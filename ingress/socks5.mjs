import dgram from 'node:dgram';
import net from 'node:net';
import {
  bridgeSockets,
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
  prepareUnixSocketPath,
} from '../tunnel.mjs';
import {
  ATYP_DOMAIN,
  ATYP_IPV4,
  ATYP_IPV6,
  CMD_EXIT_CONNECT,
  bytesToIpv4,
  bytesToIpv6,
  decodeUdpPacket,
  encodeControlRequest,
  encodeUdpAddressHeader,
  formatErrMessage,
  readControlResponse,
} from '../protocol.mjs';
import { getMode, openProxyCircuit } from '../modes/index.mjs';
import { MuxCircuitPool } from '../pool.mjs';

const SOCKS_VER = 0x05;
const AUTH_NONE = 0x00;
const AUTH_USERPASS = 0x02;
const AUTH_NO_ACCEPTABLE = 0xff;

const SOCKS_CMD_CONNECT = 0x01;
const SOCKS_CMD_UDP_ASSOCIATE = 0x03;

const REP_OK = 0x00;
const REP_GENERAL_FAILURE = 0x01;
const REP_NET_UNREACHABLE = 0x03;
const REP_HOST_UNREACHABLE = 0x04;
const REP_CONN_REFUSED = 0x05;
const REP_CMD_NOT_SUPPORTED = 0x07;
const REP_ATYP_NOT_SUPPORTED = 0x08;

const MAX_SOCKS_HANDSHAKE_BYTES = 4096;

function normalizeIp(ip) {
  if (!ip) return '';
  return ip.startsWith('::ffff:') ? ip.slice(7) : ip;
}

function isLoopbackIp(ip) {
  const clean = normalizeIp(ip);
  return clean === '127.0.0.1' || clean === '::1';
}

function buildSocksReply(rep, bindHost = '0.0.0.0', bindPort = 0) {
  const addrHdr = encodeUdpAddressHeader(bindHost, bindPort);
  return Buffer.concat([Buffer.from([SOCKS_VER, rep, 0x00]), addrHdr]);
}

function mapErrorToSocksRep(err) {
  const msg = formatErrMessage(err);
  if (/ECONNREFUSED/i.test(msg)) return REP_CONN_REFUSED;
  if (/ENETUNREACH/i.test(msg)) return REP_NET_UNREACHABLE;
  if (/EHOSTUNREACH|ENOTFOUND|EAI_AGAIN/i.test(msg)) return REP_HOST_UNREACHABLE;
  return REP_GENERAL_FAILURE;
}

class SocketByteReader {
  constructor(socket, timeoutMs = 10_000) {
    this._socket = socket;
    this._buf = Buffer.alloc(0);
    this._waiter = null;
    this._err = null;
    this._closed = false;

    this._timer = setTimeout(() => {
      this._fail(new Error('SOCKS5 handshake timeout'));
    }, timeoutMs);
    this._timer.unref?.();

    this._onData = (chunk) => {
      this._buf = Buffer.concat([this._buf, chunk]);
      if (this._buf.length > MAX_SOCKS_HANDSHAKE_BYTES) {
        this._fail(new Error('SOCKS5 handshake exceeded max size'));
        return;
      }
      this._notify();
    };
    this._onError = (err) => this._fail(err);
    this._onClose = () => this._fail(new Error('SOCKS5 client disconnected during handshake'));

    socket.on('data', this._onData);
    socket.on('error', this._onError);
    socket.on('close', this._onClose);
    socket.on('end', this._onClose);
    socket.resume();
  }

  _fail(err) {
    if (this._closed) return;
    this._err = err;
    this._cleanup();
    if (this._waiter) {
      const w = this._waiter;
      this._waiter = null;
      w.reject(err);
    }
  }

  _notify() {
    if (!this._waiter) return;
    if (this._buf.length >= this._waiter.count) {
      const w = this._waiter;
      this._waiter = null;
      const out = this._buf.subarray(0, w.count);
      this._buf = this._buf.subarray(w.count);
      w.resolve(out);
    }
  }

  readExact(count) {
    if (this._err) return Promise.reject(this._err);
    if (this._buf.length >= count) {
      const out = this._buf.subarray(0, count);
      this._buf = this._buf.subarray(count);
      return Promise.resolve(out);
    }
    return new Promise((resolve, reject) => {
      this._waiter = { count, resolve, reject };
    });
  }

  _cleanup() {
    this._closed = true;
    clearTimeout(this._timer);
    this._socket.off('data', this._onData);
    this._socket.off('error', this._onError);
    this._socket.off('close', this._onClose);
    this._socket.off('end', this._onClose);
  }

  finish() {
    this._cleanup();
    this._socket.pause();
    const rem = this._buf;
    this._buf = Buffer.alloc(0);
    return rem;
  }
}

export function createLocalSocks5Proxy(options = {}) {
  const {
    key,
    mode = 'onion',
    mux = true,
    pool = null,
    poolSize = 2,
    hops = [],
    exit,
    auth = null, // Optional { username, password }
    handshakeTimeoutMs = 10_000,
    tlsCa = undefined,
    tlsServername = undefined,
    tlsInsecure = false,
    onRequest = null,
    onSessionOpen = null,
    onError = null,
  } = options;

  getMode(mode);

  const ownsPool = !pool;
  let clientKey = null;
  let parsedHops = [];
  let parsedExit = null;

  if (!pool) {
    clientKey = loadPrivateKey(key);
    parsedHops = hops.map((h) => ({
      endpoint: h.endpoint,
      publicKey: loadAuthorizedKeys(h.publicKey),
    }));
    parsedExit = {
      endpoint: exit.endpoint,
      publicKey: loadAuthorizedKeys(exit.publicKey),
    };
  } else {
    parsedHops = pool._hops || hops;
  }

  // UDP ASSOCIATE always uses a MuxCircuitPool (created lazily if --no-mux was set for TCP)
  let muxPool = pool || (mux
    ? new MuxCircuitPool({
        key: clientKey,
        mode,
        hops: parsedHops,
        exit: parsedExit,
        poolSize,
        handshakeTimeoutMs,
        tlsCa,
        tlsServername,
        tlsInsecure,
        onSessionOpen,
      })
    : null);

  function ensureUdpPool() {
    if (!muxPool) {
      muxPool = new MuxCircuitPool({
        key: clientKey,
        mode,
        hops: parsedHops,
        exit: parsedExit,
        poolSize: 1,
        handshakeTimeoutMs,
        tlsCa,
        tlsServername,
        tlsInsecure,
        onSessionOpen,
      });
    }
    return muxPool;
  }

  const activeUdpRelays = new Set();

  const socksServer = net.createServer({ allowHalfOpen: true }, async (localSocket) => {
    localSocket.setNoDelay?.(true);
    localSocket.on('error', () => {});

    const reader = new SocketByteReader(localSocket, handshakeTimeoutMs);
    let remoteStream = null;

    try {
      // 1. Greeting
      const greetHdr = await reader.readExact(2);
      if (greetHdr[0] !== SOCKS_VER || greetHdr[1] === 0) {
        reader.finish();
        localSocket.destroy();
        return;
      }
      const methods = await reader.readExact(greetHdr[1]);

      if (auth && auth.username !== undefined) {
        if (!methods.includes(AUTH_USERPASS)) {
          reader.finish();
          localSocket.end(Buffer.from([SOCKS_VER, AUTH_NO_ACCEPTABLE]));
          return;
        }
        localSocket.write(Buffer.from([SOCKS_VER, AUTH_USERPASS]));
        const uHdr = await reader.readExact(2);
        if (uHdr[0] !== 0x01) {
          reader.finish();
          localSocket.destroy();
          return;
        }
        const uname = (await reader.readExact(uHdr[1])).toString('utf8');
        const pLen = (await reader.readExact(1))[0];
        const pass = (await reader.readExact(pLen)).toString('utf8');
        if (uname !== auth.username || pass !== (auth.password ?? '')) {
          reader.finish();
          localSocket.end(Buffer.from([0x01, 0x01]));
          return;
        }
        localSocket.write(Buffer.from([0x01, 0x00]));
      } else {
        if (!methods.includes(AUTH_NONE)) {
          reader.finish();
          localSocket.end(Buffer.from([SOCKS_VER, AUTH_NO_ACCEPTABLE]));
          return;
        }
        localSocket.write(Buffer.from([SOCKS_VER, AUTH_NONE]));
      }

      // 2. Request Header
      const reqHdr = await reader.readExact(4);
      if (reqHdr[0] !== SOCKS_VER) {
        reader.finish();
        localSocket.destroy();
        return;
      }
      const cmd = reqHdr[1];
      const atyp = reqHdr[3];

      let host;
      if (atyp === ATYP_IPV4) {
        host = bytesToIpv4(await reader.readExact(4));
      } else if (atyp === ATYP_DOMAIN) {
        const dlen = (await reader.readExact(1))[0];
        if (dlen === 0) throw new Error('Empty SOCKS5 domain');
        host = (await reader.readExact(dlen)).toString('utf8');
      } else if (atyp === ATYP_IPV6) {
        host = bytesToIpv6(await reader.readExact(16));
      } else {
        reader.finish();
        localSocket.end(buildSocksReply(REP_ATYP_NOT_SUPPORTED));
        return;
      }

      const port = (await reader.readExact(2)).readUInt16BE(0);
      const leftover = reader.finish();

      // 3A. TCP CONNECT (0x01)
      if (cmd === SOCKS_CMD_CONNECT) {
        if (!host || port < 1 || port > 65535) {
          localSocket.end(buildSocksReply(REP_GENERAL_FAILURE));
          return;
        }

        if (onRequest) {
          onRequest({
            mode,
            mux: Boolean(muxPool && mux),
            method: 'SOCKS5-CONNECT',
            host,
            port,
            hopCount: parsedHops.length,
          });
        }

        try {
          if (muxPool && mux) {
            remoteStream = await muxPool.openTargetStream(host, port);
          } else {
            const circuit = await openProxyCircuit({
              mode,
              key: clientKey,
              hops: parsedHops,
              exit: parsedExit,
              handshakeTimeoutMs,
              tlsCa,
              tlsServername,
              tlsInsecure,
            });
            remoteStream = circuit;
            circuit.write(encodeControlRequest(CMD_EXIT_CONNECT, { host, port }));
            await readControlResponse(circuit, handshakeTimeoutMs);
          }
        } catch (connErr) {
          if (onError) onError(connErr);
          if (!localSocket.destroyed) {
            localSocket.end(buildSocksReply(mapErrorToSocksRep(connErr)));
          }
          return;
        }

        if (localSocket.destroyed) {
          remoteStream.destroy();
          return;
        }

        localSocket.write(buildSocksReply(REP_OK, '0.0.0.0', 0));
        if (leftover.length > 0) {
          remoteStream.write(leftover);
        }
        localSocket.resume();
        remoteStream.resume?.();
        bridgeSockets(localSocket, remoteStream);
        return;
      }

      // 3B. UDP ASSOCIATE (0x03)
      if (cmd === SOCKS_CMD_UDP_ASSOCIATE) {
        if (onRequest) {
          onRequest({
            mode,
            mux: true,
            method: 'SOCKS5-UDP',
            host: host || '0.0.0.0',
            port,
            hopCount: parsedHops.length,
          });
        }

        const localBindIp = normalizeIp(localSocket.localAddress) || '127.0.0.1';
        const isV6 = net.isIP(localBindIp) === 6;
        const udpRelay = dgram.createSocket(isV6 ? 'udp6' : 'udp4');
        activeUdpRelays.add(udpRelay);

        let assocClosed = false;
        let udpAssoc = null;

        const closeAssociation = () => {
          if (assocClosed) return;
          assocClosed = true;
          activeUdpRelays.delete(udpRelay);
          try { udpRelay.close(); } catch {}
          if (udpAssoc) {
            udpAssoc.close();
            udpAssoc = null;
          }
          if (!localSocket.destroyed) {
            localSocket.destroy();
          }
        };

        udpRelay.on('error', () => closeAssociation());

        await new Promise((resolve, reject) => {
          udpRelay.once('error', reject);
          udpRelay.bind(0, localBindIp, () => {
            udpRelay.off('error', reject);
            resolve();
          });
        });

        const expectedClientIp = normalizeIp(localSocket.remoteAddress);
        let clientUdpPeer = (host && host !== '0.0.0.0' && host !== '::' && port > 0)
          ? { address: normalizeIp(host), port }
          : null;

        try {
          udpAssoc = await ensureUdpPool().openUdpAssociation({
            onPacket: (encodedPayload) => {
              if (assocClosed || !clientUdpPeer) return;
              const socksUdp = Buffer.allocUnsafe(3 + encodedPayload.length);
              socksUdp[0] = 0x00;
              socksUdp[1] = 0x00;
              socksUdp[2] = 0x00; // FRAG = 0
              encodedPayload.copy(socksUdp, 3);
              udpRelay.send(socksUdp, clientUdpPeer.port, clientUdpPeer.address);
            },
            onClose: () => closeAssociation(),
          });
        } catch (assocErr) {
          closeAssociation();
          if (onError) onError(assocErr);
          if (!localSocket.destroyed) {
            localSocket.end(buildSocksReply(REP_GENERAL_FAILURE));
          }
          return;
        }

        udpRelay.on('message', (msg, rinfo) => {
          if (assocClosed || msg.length < 4) return;
          // RFC 1928 §7: RSV must be 0x0000; drop fragmented packets (FRAG != 0)
          if (msg[0] !== 0x00 || msg[1] !== 0x00 || msg[2] !== 0x00) return;

          const senderIp = normalizeIp(rinfo.address);
          if (
            expectedClientIp &&
            senderIp !== expectedClientIp &&
            !(isLoopbackIp(senderIp) && isLoopbackIp(expectedClientIp))
          ) {
            return;
          }

          try {
            // Validate inner [ATYP][DST.ADDR][DST.PORT][DATA] before tunneling
            decodeUdpPacket(msg, 3);
          } catch {
            return;
          }

          clientUdpPeer = { address: rinfo.address, port: rinfo.port };
          udpAssoc.sendRaw(msg.subarray(3));
        });

        if (localSocket.destroyed) {
          closeAssociation();
          return;
        }

        const bound = udpRelay.address();
        const replyAddr = normalizeIp(bound.address);
        localSocket.write(buildSocksReply(REP_OK, replyAddr, bound.port));

        // RFC 1928: UDP association lives as long as the TCP control connection stays open
        localSocket.once('close', closeAssociation);
        localSocket.once('end', closeAssociation);
        localSocket.once('error', closeAssociation);
        localSocket.resume();
        return;
      }

      // Unsupported command (e.g. BIND)
      localSocket.end(buildSocksReply(REP_CMD_NOT_SUPPORTED));
    } catch (err) {
      reader.finish();
      if (onError) onError(err);
      if (remoteStream && !remoteStream.destroyed) {
        remoteStream.destroy();
      }
      if (!localSocket.destroyed) {
        localSocket.destroy();
      }
    }
  });

  return {
    server: socksServer,
    pool: muxPool,
    listen(...args) {
      if (args.length >= 1 && typeof args[0] === 'string') {
        const ep = parseEndpoint(args[0], '127.0.0.1');
        const cb = typeof args[1] === 'function' ? args[1] : undefined;
        if (ep.path) {
          prepareUnixSocketPath(ep.path);
          socksServer.listen(ep.path, cb);
        } else if (ep.host) {
          socksServer.listen(ep.port, ep.host, cb);
        } else {
          socksServer.listen(ep.port, cb);
        }
        return socksServer;
      }
      socksServer.listen(...args);
      return socksServer;
    },
    close(cb) {
      for (const relay of activeUdpRelays) {
        try { relay.close(); } catch {}
      }
      activeUdpRelays.clear();
      if (ownsPool && muxPool) {
        muxPool.close();
      }
      socksServer.close(cb);
    },
  };
}
