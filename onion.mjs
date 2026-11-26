import net from 'node:net';
import { URL } from 'node:url';
import {
  TunnelSocket,
  bridgeSockets,
  connect,
  createServer,
  formatEndpoint,
  loadAuthorizedKeys,
  loadPrivateKey,
  loadPublicKey,
  parseEndpoint,
  prepareUnixSocketPath,
} from './tunnel.mjs';

const CMD_EXTEND = 0x52; // 'R' — Onion relay extend (blind TCP forward to next hop)
const CMD_PTP_CHAIN = 0x50; // 'P' — Point-to-Point relay chain (decrypt & re-encrypt per hop)
const CMD_EXIT_CONNECT = 0x45; // 'E' — Exit connect to target host:port
const STATUS_OK = 0x00;
const STATUS_ERR = 0x01;
const MAX_CMD_PAYLOAD = 8192;
const MAX_CHAIN_HOPS = 32;
const MAX_HTTP_HEADER_BYTES = 32 * 1024;

// --- Wire Helpers for Control Handshakes Inside a Tunnel Layer ---

function encodeControlRequest(cmd, jsonObj) {
  const body = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  if (body.length > MAX_CMD_PAYLOAD) {
    throw new Error('Control request payload too large');
  }
  const buf = Buffer.allocUnsafe(3 + body.length);
  buf[0] = cmd;
  buf.writeUInt16BE(body.length, 1);
  body.copy(buf, 3);
  return buf;
}

function readControlRequest(stream, expectedCmdOrList, timeoutMs = 10_000) {
  const allowed = Array.isArray(expectedCmdOrList) ? expectedCmdOrList : [expectedCmdOrList];
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Timed out waiting for tunnel control header'));
    }, timeoutMs);
    timer.unref?.();

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 3 + MAX_CMD_PAYLOAD) {
        cleanup();
        reject(new Error('Control header exceeded maximum size'));
        return;
      }
      if (buf.length < 3) return;
      const cmd = buf[0];
      const len = buf.readUInt16BE(1);
      if (!allowed.includes(cmd)) {
        cleanup();
        reject(new Error(`Command 0x${cmd.toString(16)} is not permitted in this relay mode`));
        return;
      }
      if (len > MAX_CMD_PAYLOAD) {
        cleanup();
        reject(new Error('Control payload length exceeded limit'));
        return;
      }
      if (buf.length < 3 + len) return;

      const jsonSlice = buf.subarray(3, 3 + len);
      const leftover = buf.subarray(3 + len);
      cleanup();
      try {
        const parsed = JSON.parse(jsonSlice.toString('utf8'));
        resolve({ cmd, request: parsed, leftover });
      } catch {
        reject(new Error('Malformed JSON in control header'));
      }
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error('Stream closed before control header arrived'));
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('close', onClose);
      stream.off('end', onClose);
    };

    stream.on('data', onData);
    stream.on('error', onError);
    stream.on('close', onClose);
    stream.on('end', onClose);
  });
}

function sendControlOk(stream) {
  stream.write(Buffer.from([STATUS_OK]));
}

function formatErrMessage(errOrMsg) {
  if (!errOrMsg) return 'Unknown error';
  if (typeof errOrMsg === 'string') return errOrMsg;
  if (errOrMsg.message) return errOrMsg.message;
  if (Array.isArray(errOrMsg.errors) && errOrMsg.errors.length > 0) {
    return errOrMsg.errors.map((e) => e.message || e.code || String(e)).join('; ');
  }
  return errOrMsg.code || String(errOrMsg);
}

function sendControlError(stream, errOrMsg) {
  const msgBuf = Buffer.from(formatErrMessage(errOrMsg).slice(0, 500), 'utf8');
  const frame = Buffer.allocUnsafe(3 + msgBuf.length);
  frame[0] = STATUS_ERR;
  frame.writeUInt16BE(msgBuf.length, 1);
  msgBuf.copy(frame, 3);
  stream.end(frame);
}

function readControlResponse(stream, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Timed out waiting for hop control response'));
    }, timeoutMs);
    timer.unref?.();

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 1) return;

      if (buf[0] === STATUS_OK) {
        const leftover = buf.subarray(1);
        cleanup();
        if (leftover.length > 0) {
          stream.unshift(leftover);
        }
        resolve();
        return;
      }

      if (buf[0] === STATUS_ERR) {
        if (buf.length < 3) return;
        const errLen = buf.readUInt16BE(1);
        if (buf.length < 3 + errLen) return;
        const msg = buf.subarray(3, 3 + errLen).toString('utf8');
        cleanup();
        reject(new Error(`Remote hop rejected circuit: ${msg}`));
        return;
      }

      cleanup();
      reject(new Error(`Invalid control status byte: 0x${buf[0].toString(16)}`));
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error('Hop closed connection before control response'));
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('close', onClose);
      stream.off('end', onClose);
      stream.pause();
    };

    stream.on('data', onData);
    stream.on('error', onError);
    stream.on('close', onClose);
    stream.on('end', onClose);
    stream.resume();
  });
}

// --- 1. Intermediate Relay / Repeater Server (supports Onion, PTP dynamic, and PTP static --next) ---

function waitSecureConnect(tunnel) {
  return new Promise((resolve, reject) => {
    const onConnect = () => {
      tunnel.off('error', onError);
      // Prevent unhandled EventEmitter 'error' throws during async setup/teardown transitions
      tunnel.on('error', () => {});
      resolve(tunnel);
    };
    const onError = (err) => {
      tunnel.off('secureConnect', onConnect);
      reject(err);
    };
    tunnel.once('secureConnect', onConnect);
    tunnel.once('error', onError);
  });
}

export function createRelayServer(options = {}) {
  const {
    key,
    mode = options.nextHop ? 'ptp' : 'both', // 'onion' | 'ptp' | 'both'
    nextHop = null, // Optional { endpoint, publicKey } for static PTP bridge repeater
    authorizedKeys = null,
    allowAnyClient = !authorizedKeys,
    connectTimeoutMs = 8_000,
    onRelay = null,
  } = options;

  if (mode !== 'onion' && mode !== 'ptp' && mode !== 'both') {
    throw new TypeError(`Invalid relay mode "${mode}" (expected "onion", "ptp", or "both")`);
  }
  if (nextHop && mode === 'onion') {
    throw new TypeError('Static "nextHop" is only valid in "ptp" relay mode');
  }

  const relayIdentity = loadPrivateKey(key);
  const staticNext = nextHop
    ? {
        endpoint: nextHop.endpoint,
        parsedEp: parseEndpoint(nextHop.endpoint, '127.0.0.1'),
        publicKey: loadPublicKey(nextHop.publicKey),
      }
    : null;

  const allowedCmds = mode === 'onion'
    ? [CMD_EXTEND]
    : mode === 'ptp'
      ? [CMD_PTP_CHAIN]
      : [CMD_EXTEND, CMD_PTP_CHAIN];

  const server = createServer({
    key: relayIdentity,
    authorizedKeys,
    allowAnyClient,
    keepAliveMs: 30_000,
  }, async (inTunnel) => {
    // Submode A: Static PTP Repeater (--next configured on repeater; transparent hop-by-hop re-encryption)
    if (staticNext) {
      let outTunnel = null;
      try {
        if (onRelay) {
          onRelay({
            mode: 'ptp-static',
            peerFingerprint: inTunnel.peerFingerprint,
            peerComment: inTunnel.peerComment,
            nextEndpoint: formatEndpoint(staticNext.parsedEp),
          });
        }
        outTunnel = connect({
          endpoint: staticNext.endpoint,
          key: relayIdentity,
          serverPublicKey: staticNext.publicKey,
          handshakeTimeoutMs: connectTimeoutMs,
          keepAliveMs: 30_000,
        });
        await waitSecureConnect(outTunnel);
        if (inTunnel.destroyed) {
          outTunnel.destroy();
          return;
        }
        bridgeSockets(inTunnel, outTunnel);
      } catch {
        if (outTunnel && !outTunnel.destroyed) outTunnel.destroy();
        if (!inTunnel.destroyed) inTunnel.destroy();
      }
      return;
    }

    // Submode B: Dynamic Onion (CMD_EXTEND) or Dynamic PTP (CMD_PTP_CHAIN)
    let outbound = null;
    try {
      const { cmd, request, leftover } = await readControlRequest(inTunnel, allowedCmds, connectTimeoutMs);

      if (cmd === CMD_EXTEND) {
        if (!request?.next || typeof request.next !== 'string') {
          sendControlError(inTunnel, 'Missing "next" hop endpoint');
          return;
        }
        const nextEp = parseEndpoint(request.next, '127.0.0.1');
        if (onRelay) {
          onRelay({
            mode: 'onion',
            peerFingerprint: inTunnel.peerFingerprint,
            peerComment: inTunnel.peerComment,
            nextEndpoint: formatEndpoint(nextEp),
          });
        }

        const nextSock = nextEp.path
          ? net.connect({ path: nextEp.path, allowHalfOpen: true })
          : net.connect({ host: nextEp.host, port: nextEp.port, allowHalfOpen: true });
        nextSock.setNoDelay?.(true);
        outbound = nextSock;

        await new Promise((resolve, reject) => {
          const timer = setTimeout(() => {
            nextSock.destroy();
            reject(new Error(`Connect timeout to next hop ${formatEndpoint(nextEp)}`));
          }, connectTimeoutMs);
          timer.unref?.();

          nextSock.once('connect', () => {
            clearTimeout(timer);
            resolve();
          });
          nextSock.once('error', (err) => {
            clearTimeout(timer);
            reject(err);
          });
        });

        if (inTunnel.destroyed) {
          nextSock.destroy();
          return;
        }

        sendControlOk(inTunnel);
        if (leftover.length > 0) nextSock.write(leftover);
        inTunnel.resume();
        bridgeSockets(inTunnel, nextSock);
        return;
      }

      // cmd === CMD_PTP_CHAIN (decrypt from inTunnel, re-encrypt into outTunnel using this relay's key!)
      const chain = request?.chain;
      if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_CHAIN_HOPS) {
        sendControlError(inTunnel, 'Invalid PTP hop chain');
        return;
      }

      const [head, ...restChain] = chain;
      if (!head?.endpoint || typeof head.pub !== 'string') {
        sendControlError(inTunnel, 'Malformed PTP hop descriptor');
        return;
      }

      const nextEp = parseEndpoint(head.endpoint, '127.0.0.1');
      const nextPub = loadPublicKey(Buffer.from(head.pub, 'base64'));

      if (onRelay) {
        onRelay({
          mode: 'ptp',
          peerFingerprint: inTunnel.peerFingerprint,
          peerComment: inTunnel.peerComment,
          nextEndpoint: formatEndpoint(nextEp),
          remainingHops: restChain.length,
        });
      }

      const outTunnel = connect({
        endpoint: head.endpoint,
        key: relayIdentity,
        serverPublicKey: nextPub,
        handshakeTimeoutMs: connectTimeoutMs,
        keepAliveMs: 30_000,
      });
      outbound = outTunnel;
      await waitSecureConnect(outTunnel);

      if (restChain.length > 0) {
        outTunnel.write(encodeControlRequest(CMD_PTP_CHAIN, { chain: restChain }));
        await readControlResponse(outTunnel, connectTimeoutMs);
      }

      if (inTunnel.destroyed) {
        outTunnel.destroy();
        return;
      }

      sendControlOk(inTunnel);
      if (leftover.length > 0) outTunnel.write(leftover);
      inTunnel.resume();
      outTunnel.resume();
      bridgeSockets(inTunnel, outTunnel);
    } catch (err) {
      if (outbound && !outbound.destroyed) outbound.destroy();
      if (!inTunnel.destroyed) {
        try {
          sendControlError(inTunnel, err);
        } catch {
          inTunnel.destroy();
        }
      }
    }
  });

  return server;
}

// --- 2. Circuit Builders: Onion (nested E2EE) & PTP (hop-by-hop neighbor encryption) ---

export async function openOnionCircuit(options) {
  const {
    key,
    hops = [], // [{ endpoint, publicKey }] — 0..N intermediate relays
    exit, // { endpoint, publicKey } — final exit server
    handshakeTimeoutMs = 10_000,
  } = options;

  if (!key) throw new TypeError('openOnionCircuit requires client "key"');
  if (!exit?.endpoint || !exit?.publicKey) {
    throw new TypeError('openOnionCircuit requires "exit: { endpoint, publicKey }"');
  }

  const clientIdentity = loadPrivateKey(key);
  const chain = [
    ...hops.map((h) => ({ endpoint: h.endpoint, publicKey: loadPublicKey(h.publicKey) })),
    { endpoint: exit.endpoint, publicKey: loadPublicKey(exit.publicKey) },
  ];

  const layers = [];
  try {
    // Layer 0: Connect to first hop (Relay 1, or directly Exit if hops is empty)
    const first = chain[0];
    let current = connect({
      endpoint: first.endpoint,
      key: clientIdentity,
      serverPublicKey: first.publicKey,
      handshakeTimeoutMs,
      keepAliveMs: chain.length === 1 ? 30_000 : 0,
    });
    layers.push(current);
    await waitSecureConnect(current);

    // Layers 1..K: Telescope through each subsequent hop inside the existing encrypted tunnel!
    for (let i = 1; i < chain.length; i++) {
      const targetHop = chain[i];
      current.write(encodeControlRequest(CMD_EXTEND, { next: targetHop.endpoint }));
      await readControlResponse(current, handshakeTimeoutMs);

      const isInnermost = i === chain.length - 1;
      const nested = new TunnelSocket(current, {
        role: 'client',
        key: clientIdentity,
        serverPublicKey: targetHop.publicKey,
        handshakeTimeoutMs,
        keepAliveMs: isInnermost ? 30_000 : 0,
      });
      layers.push(nested);
      await waitSecureConnect(nested);
      current = nested;
    }

    return current;
  } catch (err) {
    for (let i = layers.length - 1; i >= 0; i--) {
      if (!layers[i].destroyed) layers[i].destroy();
    }
    throw err;
  }
}

export async function openPtpCircuit(options) {
  const {
    key,
    hops = [], // [{ endpoint, publicKey }] — 0..N intermediate PTP repeaters
    exit, // { endpoint, publicKey } — final exit server (or first static repeater)
    handshakeTimeoutMs = 10_000,
  } = options;

  if (!key) throw new TypeError('openPtpCircuit requires client "key"');
  if (!exit?.endpoint || !exit?.publicKey) {
    throw new TypeError('openPtpCircuit requires "exit: { endpoint, publicKey }"');
  }

  const clientIdentity = loadPrivateKey(key);
  const chain = [
    ...hops.map((h) => ({ endpoint: h.endpoint, publicKey: loadPublicKey(h.publicKey) })),
    { endpoint: exit.endpoint, publicKey: loadPublicKey(exit.publicKey) },
  ];

  const first = chain[0];
  const firstTunnel = connect({
    endpoint: first.endpoint,
    key: clientIdentity,
    serverPublicKey: first.publicKey,
    handshakeTimeoutMs,
    keepAliveMs: 30_000,
  });

  try {
    await waitSecureConnect(firstTunnel);

    if (chain.length > 1) {
      const restChain = chain.slice(1).map((h) => ({
        endpoint: h.endpoint,
        pub: h.publicKey.spkiDer.toString('base64'),
      }));
      firstTunnel.write(encodeControlRequest(CMD_PTP_CHAIN, { chain: restChain }));
      await readControlResponse(firstTunnel, handshakeTimeoutMs);
      firstTunnel.resume();
    }

    return firstTunnel;
  } catch (err) {
    if (!firstTunnel.destroyed) firstTunnel.destroy();
    throw err;
  }
}

export function openProxyCircuit(options) {
  const mode = options.mode || 'onion';
  if (mode === 'onion') return openOnionCircuit(options);
  if (mode === 'ptp') return openPtpCircuit(options);
  throw new TypeError(`Invalid proxy circuit mode "${mode}" (expected "onion" or "ptp")`);
}

// --- 3. Exit Proxy Server (terminates innermost E2EE layer & connects to target host:port) ---

export function createExitServer(options = {}) {
  const {
    key,
    authorizedKeys,
    allowAnyClient = false,
    connectTimeoutMs = 10_000,
    allowTarget = null,
    onExitRequest = null,
  } = options;

  const server = createServer({
    key,
    authorizedKeys,
    allowAnyClient,
    keepAliveMs: 30_000,
  }, async (innerTunnel) => {
    try {
      const { request, leftover } = await readControlRequest(innerTunnel, CMD_EXIT_CONNECT);
      const host = String(request?.host || '').trim();
      const port = Number(request?.port);

      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        sendControlError(innerTunnel, 'Invalid target host/port');
        return;
      }
      if (typeof allowTarget === 'function' && !allowTarget(host, port)) {
        sendControlError(innerTunnel, `Target ${host}:${port} denied by exit policy`);
        return;
      }

      if (onExitRequest) {
        onExitRequest({
          peerFingerprint: innerTunnel.peerFingerprint,
          peerComment: innerTunnel.peerComment,
          target: `${host}:${port}`,
        });
      }

      const targetSocket = net.connect({ host, port, allowHalfOpen: true });
      targetSocket.setNoDelay?.(true);
      await new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          targetSocket.destroy();
          reject(new Error(`Connect timeout to ${host}:${port}`));
        }, connectTimeoutMs);
        timer.unref?.();

        targetSocket.once('connect', () => {
          clearTimeout(timer);
          resolve();
        });
        targetSocket.once('error', (err) => {
          clearTimeout(timer);
          reject(err);
        });
      });

      if (innerTunnel.destroyed) {
        targetSocket.destroy();
        return;
      }

      sendControlOk(innerTunnel);
      if (leftover.length > 0) {
        targetSocket.write(leftover);
      }
      bridgeSockets(innerTunnel, targetSocket);
    } catch (err) {
      if (!innerTunnel.destroyed) {
        try {
          sendControlError(innerTunnel, err);
        } catch {
          innerTunnel.destroy();
        }
      }
    }
  });

  return server;
}

// --- 4. Local HTTP / HTTPS (CONNECT) Proxy Client ---

function parseHttpHeaderBlock(rawHeaderText) {
  const lines = rawHeaderText.split('\r\n');
  const requestLine = lines[0] || '';
  const match = requestLine.match(/^([A-Z]+)\s+(\S+)\s+(HTTP\/1\.[01])$/);
  if (!match) {
    throw new Error('Malformed HTTP request line');
  }
  const [, method, target, httpVersion] = match;
  const headers = lines.slice(1);
  return { method, target, httpVersion, headers };
}

function parseConnectAuthority(target) {
  if (target.startsWith('[')) {
    const close = target.indexOf(']');
    if (close === -1) throw new Error('Invalid IPv6 CONNECT authority');
    const host = target.slice(1, close);
    const port = target[close + 1] === ':' ? Number(target.slice(close + 2)) : 443;
    return { host, port };
  }
  const idx = target.lastIndexOf(':');
  if (idx === -1) return { host: target, port: 443 };
  return { host: target.slice(0, idx), port: Number(target.slice(idx + 1)) };
}

function readInitialHttpRequest(localSocket, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('HTTP client header timeout'));
    }, timeoutMs);
    timer.unref?.();

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      const headerEnd = buf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (buf.length > MAX_HTTP_HEADER_BYTES) {
          cleanup();
          reject(new Error('HTTP proxy header too large'));
        }
        return;
      }

      const rawHeader = buf.subarray(0, headerEnd).toString('latin1');
      const bodyRemainder = buf.subarray(headerEnd + 4);
      cleanup();
      resolve({ rawHeader, bodyRemainder });
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error('Local client disconnected before sending HTTP request'));
    };

    const cleanup = () => {
      clearTimeout(timer);
      localSocket.off('data', onData);
      localSocket.off('error', onError);
      localSocket.off('close', onClose);
      localSocket.off('end', onClose);
      localSocket.pause();
    };

    localSocket.on('data', onData);
    localSocket.on('error', onError);
    localSocket.on('close', onClose);
    localSocket.on('end', onClose);
  });
}

export function createLocalHttpProxy(options = {}) {
  const {
    key,
    mode = 'onion', // 'onion' | 'ptp'
    hops = [],
    exit,
    handshakeTimeoutMs = 10_000,
    onRequest = null,
    onError = null,
  } = options;

  if (mode !== 'onion' && mode !== 'ptp') {
    throw new TypeError(`Invalid client mode "${mode}" (expected "onion" or "ptp")`);
  }

  const clientKey = loadPrivateKey(key);
  const parsedHops = hops.map((h) => ({
    endpoint: h.endpoint,
    publicKey: loadPublicKey(h.publicKey),
  }));
  const parsedExit = {
    endpoint: exit.endpoint,
    publicKey: loadPublicKey(exit.publicKey),
  };

  const proxyServer = net.createServer({ allowHalfOpen: true }, async (localSocket) => {
    localSocket.setNoDelay?.(true);
    localSocket.on('error', () => {});
    let circuit = null;
    try {
      const { rawHeader, bodyRemainder } = await readInitialHttpRequest(localSocket);
      const { method, target, httpVersion, headers } = parseHttpHeaderBlock(rawHeader);

      let host;
      let port;
      let rewrittenHead = null;

      if (method === 'CONNECT') {
        ({ host, port } = parseConnectAuthority(target));
      } else {
        let parsedUrl;
        if (target.startsWith('http://')) {
          parsedUrl = new URL(target);
        } else {
          // Support transparent/origin-form requests if Host header is set
          const hostHdr = headers.find((h) => h.toLowerCase().startsWith('host:'));
          if (!hostHdr) throw new Error('HTTP proxy request requires absolute http:// URI or Host header');
          parsedUrl = new URL(`http://${hostHdr.slice(5).trim()}${target}`);
        }
        if (parsedUrl.protocol !== 'http:') {
          throw new Error(`Unsupported scheme "${parsedUrl.protocol}" (use CONNECT for HTTPS)`);
        }
        host = parsedUrl.hostname;
        port = Number(parsedUrl.port || 80);
        const originPath = (parsedUrl.pathname || '/') + (parsedUrl.search || '');

        const filteredHeaders = headers.filter((line) => {
          const lower = line.toLowerCase();
          return (
            !lower.startsWith('host:') &&
            !lower.startsWith('proxy-connection:') &&
            !lower.startsWith('proxy-authorization:') &&
            !lower.startsWith('connection:')
          );
        });
        filteredHeaders.unshift(`Host: ${parsedUrl.host}`);
        filteredHeaders.push('Connection: close');

        rewrittenHead = Buffer.from(
          `${method} ${originPath} ${httpVersion}\r\n${filteredHeaders.join('\r\n')}\r\n\r\n`,
          'latin1',
        );
      }

      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        throw new Error(`Invalid target destination: ${target}`);
      }

      if (onRequest) {
        onRequest({ mode, method, host, port, hopCount: parsedHops.length });
      }

      circuit = await openProxyCircuit({
        mode,
        key: clientKey,
        hops: parsedHops,
        exit: parsedExit,
        handshakeTimeoutMs,
      });

      circuit.write(encodeControlRequest(CMD_EXIT_CONNECT, { host, port }));
      await readControlResponse(circuit, handshakeTimeoutMs);

      if (localSocket.destroyed) {
        circuit.destroy();
        return;
      }

      if (method === 'CONNECT') {
        localSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (bodyRemainder.length > 0) {
          circuit.write(bodyRemainder);
        }
      } else {
        circuit.write(rewrittenHead);
        if (bodyRemainder.length > 0) {
          circuit.write(bodyRemainder);
        }
      }

      localSocket.resume();
      circuit.resume();
      bridgeSockets(localSocket, circuit);
    } catch (err) {
      if (onError) onError(err);
      if (circuit && !circuit.destroyed) {
        circuit.destroy();
      }
      if (!localSocket.destroyed) {
        const body = `Bad Gateway: ${err.message}\n`;
        localSocket.end(
          `HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
      }
    }
  });

  return {
    server: proxyServer,
    listen(...args) {
      if (args.length >= 1 && typeof args[0] === 'string') {
        const ep = parseEndpoint(args[0], '127.0.0.1');
        const cb = typeof args[1] === 'function' ? args[1] : undefined;
        if (ep.path) {
          prepareUnixSocketPath(ep.path);
          proxyServer.listen(ep.path, cb);
        } else {
          proxyServer.listen(ep.port, ep.host, cb);
        }
        return proxyServer;
      }
      proxyServer.listen(...args);
      return proxyServer;
    },
    close(cb) {
      proxyServer.close(cb);
    },
  };
}
