import dgram from 'node:dgram';
import dns from 'node:dns';
import net from 'node:net';
import {
  MuxSession,
  bridgeSockets,
  createServer,
} from './tunnel.mjs';
import {
  ATYP_DOMAIN,
  ATYP_IPV6,
  CMD_EXIT_CONNECT,
  CMD_EXIT_MUX,
  decodeUdpPacket,
  encodeUdpPacket,
  formatErrMessage,
  readControlRequest,
  sendControlError,
  sendControlOk,
} from './protocol.mjs';

const DNS_CACHE_TTL_MS = 30_000;
const MAX_DNS_CACHE_ENTRIES = 256;

function dialExitTarget(host, port, connectTimeoutMs) {
  return new Promise((resolve, reject) => {
    const targetSocket = net.connect({ host, port, allowHalfOpen: true });
    targetSocket.setNoDelay?.(true);

    const timer = setTimeout(() => {
      targetSocket.destroy();
      reject(new Error(`Connect timeout to ${host}:${port}`));
    }, connectTimeoutMs);
    timer.unref?.();

    targetSocket.once('connect', () => {
      clearTimeout(timer);
      resolve(targetSocket);
    });
    targetSocket.once('error', (err) => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

function createUdpAssociation(muxSession, stream, { allowTarget, udpIdleTimeoutMs, onExitRequest, peerInfo }) {
  const channelId = stream.id;
  let closed = false;
  let lastActive = Date.now();
  const dnsCache = new Map();

  const udp4 = dgram.createSocket('udp4');
  let udp6 = null;
  try {
    udp6 = dgram.createSocket('udp6');
  } catch {
    udp6 = null;
  }

  const sendBack = (msg, rinfo) => {
    if (closed || muxSession.isClosed) return;
    lastActive = Date.now();
    try {
      const addr = rinfo.address.startsWith('::ffff:') ? rinfo.address.slice(7) : rinfo.address;
      const pkt = encodeUdpPacket(addr, rinfo.port, msg);
      muxSession.sendDatagram(channelId, pkt);
    } catch {
      // Ignore malformed reply address
    }
  };

  udp4.on('message', sendBack);
  udp4.on('error', () => {});
  udp4.bind(0);

  if (udp6) {
    udp6.on('message', sendBack);
    udp6.on('error', () => {
      try { udp6.close(); } catch {}
      udp6 = null;
    });
    try {
      udp6.bind(0);
    } catch {
      udp6 = null;
    }
  }

  const idleTimer = setInterval(() => {
    if (Date.now() - lastActive > udpIdleTimeoutMs) {
      cleanup();
      if (!stream.destroyed) stream.end();
    }
  }, Math.min(30_000, Math.max(5_000, Math.floor(udpIdleTimeoutMs / 2))));
  idleTimer.unref?.();

  const cleanup = () => {
    if (closed) return;
    closed = true;
    clearInterval(idleTimer);
    dnsCache.clear();
    try { udp4.close(); } catch {}
    if (udp6) {
      try { udp6.close(); } catch {}
      udp6 = null;
    }
  };

  stream.once('close', cleanup);
  stream.once('end', cleanup);
  muxSession.once('close', cleanup);

  let loggedFirst = false;

  async function resolveHost(host, atyp) {
    if (atyp === ATYP_IPV6) return { address: host, family: 6 };
    if (atyp !== ATYP_DOMAIN) return { address: host, family: 4 };

    const cached = dnsCache.get(host);
    if (cached && cached.expiresAt > Date.now()) {
      return cached;
    }
    const records = await dns.promises.lookup(host, { all: true });
    // Prefer IPv4 when available so dual-stack domains work reliably even on IPv4-only exit VPSes
    const chosen = records.find((r) => r.family === 4) || records[0];
    if (!chosen) {
      throw new Error(`No DNS records found for ${host}`);
    }
    if (dnsCache.size >= MAX_DNS_CACHE_ENTRIES) {
      const oldestKey = dnsCache.keys().next().value;
      dnsCache.delete(oldestKey);
    }
    const entry = { address: chosen.address, family: chosen.family, expiresAt: Date.now() + DNS_CACHE_TTL_MS };
    dnsCache.set(host, entry);
    return entry;
  }

  return {
    cleanup,
    async handleDatagram(payload) {
      if (closed) return;
      let decoded;
      try {
        decoded = decodeUdpPacket(payload);
      } catch {
        return;
      }
      const { atyp, host, port, data } = decoded;
      if (!host || port < 1 || port > 65535) return;
      if (typeof allowTarget === 'function' && !allowTarget(host, port, 'udp')) {
        return;
      }

      lastActive = Date.now();
      if (!loggedFirst && onExitRequest) {
        loggedFirst = true;
        onExitRequest({
          mux: true,
          proto: 'udp',
          streamId: channelId,
          peerFingerprint: peerInfo.peerFingerprint,
          peerComment: peerInfo.peerComment,
          target: `udp://${host}:${port}`,
        });
      }

      try {
        const { address, family } = await resolveHost(host, atyp);
        if (closed) return;
        if (family === 6) {
          if (udp6) udp6.send(data, port, address);
        } else {
          udp4.send(data, port, address);
        }
      } catch {
        // Ignore transient DNS / unreachable datagram send errors
      }
    },
  };
}

export function createExitServer(options = {}) {
  const {
    key,
    authorizedKeys,
    allowAnyClient = false,
    connectTimeoutMs = 10_000,
    udpIdleTimeoutMs = 120_000,
    allowUdp = true,
    allowTarget = null,
    tunGateway = null,
    tlsCert = null,
    tlsKey = null,
    fallback = null,
    protocol = undefined,
    wsPath = undefined,
    onExitRequest = null,
  } = options;

  const server = createServer({
    key,
    authorizedKeys,
    allowAnyClient,
    tlsCert,
    tlsKey,
    fallback,
    protocol,
    wsPath,
    keepAliveMs: 30_000,
  }, async (innerTunnel) => {
    try {
      const { cmd, request, leftover } = await readControlRequest(
        innerTunnel,
        [CMD_EXIT_CONNECT, CMD_EXIT_MUX],
        connectTimeoutMs,
      );

      const peerInfo = {
        peerFingerprint: innerTunnel.peerFingerprint,
        peerComment: innerTunnel.peerComment,
      };

      // Persistent Multiplexed Session (CMD_EXIT_MUX)
      if (cmd === CMD_EXIT_MUX) {
        sendControlOk(innerTunnel);
        if (leftover.length > 0) {
          innerTunnel.unshift(leftover);
        }

        const udpAssociations = new Map(); // channelId -> assoc
        const tunBindings = new Map(); // channelId -> tunBinding

        const muxSession = new MuxSession(innerTunnel, {
          initiator: false,
          onDatagram: (channelId, payload) => {
            const tunBinding = tunBindings.get(channelId);
            if (tunBinding) {
              tunBinding.handlePacket(payload);
              return;
            }
            const udpAssoc = udpAssociations.get(channelId);
            if (udpAssoc) {
              udpAssoc.handleDatagram(payload);
            }
          },
          onStream: async (stream, metaBuf, accept, reject) => {
            let parsed;
            try {
              parsed = JSON.parse(metaBuf.toString('utf8'));
            } catch {
              reject('Malformed mux stream target metadata');
              return;
            }

            const streamType = parsed?.type || 'tcp';

            // 1) Multiplexed UDP Association
            if (streamType === 'udp') {
              if (!allowUdp) {
                reject('UDP forwarding is disabled on this exit server');
                return;
              }
              const assoc = createUdpAssociation(muxSession, stream, {
                allowTarget,
                udpIdleTimeoutMs,
                onExitRequest,
                peerInfo,
              });
              udpAssociations.set(stream.id, assoc);
              stream.once('close', () => udpAssociations.delete(stream.id));
              accept();
              return;
            }

            // 2) Multiplexed L3 TUN Channel
            if (streamType === 'tun') {
              if (!tunGateway) {
                reject('TUN gateway is not enabled on this exit server (start exit with --tun)');
                return;
              }
              try {
                const binding = tunGateway.attachClient(muxSession, stream, parsed, peerInfo);
                tunBindings.set(stream.id, binding);
                stream.once('close', () => tunBindings.delete(stream.id));
                if (onExitRequest) {
                  onExitRequest({
                    mux: true,
                    proto: 'tun',
                    streamId: stream.id,
                    peerFingerprint: peerInfo.peerFingerprint,
                    peerComment: peerInfo.peerComment,
                    target: `tun:${binding.clientIp}/${binding.prefixLen}`,
                  });
                }
                accept(JSON.stringify({
                  clientIp: binding.clientIp,
                  gatewayIp: binding.gatewayIp,
                  prefixLen: binding.prefixLen,
                  mtu: binding.mtu,
                }));
              } catch (err) {
                reject(formatErrMessage(err));
              }
              return;
            }

            // 3) Multiplexed TCP Target Stream
            const host = String(parsed?.host || '').trim();
            const port = Number(parsed?.port);
            if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
              reject('Invalid target host/port');
              return;
            }
            if (typeof allowTarget === 'function' && !allowTarget(host, port, 'tcp')) {
              reject(`Target ${host}:${port} denied by exit policy`);
              return;
            }

            if (onExitRequest) {
              onExitRequest({
                mux: true,
                proto: 'tcp',
                streamId: stream.id,
                peerFingerprint: peerInfo.peerFingerprint,
                peerComment: peerInfo.peerComment,
                target: `${host}:${port}`,
              });
            }

            try {
              const targetSocket = await dialExitTarget(host, port, connectTimeoutMs);
              if (stream.destroyed) {
                targetSocket.destroy();
                return;
              }
              accept();
              bridgeSockets(stream, targetSocket);
            } catch (err) {
              reject(formatErrMessage(err));
            }
          },
        });

        muxSession.once('close', () => {
          udpAssociations.clear();
          tunBindings.clear();
        });
        return;
      }

      // Single-stream connection (CMD_EXIT_CONNECT)
      const host = String(request?.host || '').trim();
      const port = Number(request?.port);

      if (!host || !Number.isInteger(port) || port < 1 || port > 65535) {
        sendControlError(innerTunnel, 'Invalid target host/port');
        return;
      }
      if (typeof allowTarget === 'function' && !allowTarget(host, port, 'tcp')) {
        sendControlError(innerTunnel, `Target ${host}:${port} denied by exit policy`);
        return;
      }

      if (onExitRequest) {
        onExitRequest({
          mux: false,
          proto: 'tcp',
          peerFingerprint: peerInfo.peerFingerprint,
          peerComment: peerInfo.peerComment,
          target: `${host}:${port}`,
        });
      }

      const targetSocket = await dialExitTarget(host, port, connectTimeoutMs);
      if (innerTunnel.destroyed) {
        targetSocket.destroy();
        return;
      }

      sendControlOk(innerTunnel);
      if (leftover.length > 0) {
        targetSocket.write(leftover);
      }
      innerTunnel.resume();
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

  if (tunGateway) {
    const origClose = server.close.bind(server);
    server.close = (cb) => {
      tunGateway.close(() => origClose(cb));
      return server;
    };
  }

  return server;
}
