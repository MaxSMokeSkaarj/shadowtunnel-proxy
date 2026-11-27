import net from 'node:net';
import { URL } from 'node:url';
import {
  bridgeSockets,
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
  prepareUnixSocketPath,
} from '../tunnel.mjs';
import {
  CMD_EXIT_CONNECT,
  encodeControlRequest,
  formatErrMessage,
  readControlResponse,
} from '../protocol.mjs';
import { getMode, openProxyCircuit } from '../modes/index.mjs';
import { MuxCircuitPool } from '../pool.mjs';

const MAX_HTTP_HEADER_BYTES = 32 * 1024;

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
    mode = 'onion',
    mux = true,
    pool = null,
    poolSize = 2,
    hops = [],
    exit,
    handshakeTimeoutMs = 10_000,
    tlsCa = undefined,
    tlsServername = undefined,
    tlsInsecure = false,
    onRequest = null,
    onSessionOpen = null,
    onError = null,
  } = options;

  getMode(mode); // Validate mode plugin exists

  const ownsPool = !pool && Boolean(mux);
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

  const muxPool = pool || (mux
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

  const proxyServer = net.createServer({ allowHalfOpen: true }, async (localSocket) => {
    localSocket.setNoDelay?.(true);
    localSocket.on('error', () => {});
    let remoteStream = null;
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
        onRequest({ mode, mux: Boolean(muxPool), method, host, port, hopCount: parsedHops.length });
      }

      if (muxPool) {
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

      if (localSocket.destroyed) {
        remoteStream.destroy();
        return;
      }

      if (method === 'CONNECT') {
        localSocket.write('HTTP/1.1 200 Connection Established\r\n\r\n');
        if (bodyRemainder.length > 0) {
          remoteStream.write(bodyRemainder);
        }
      } else {
        remoteStream.write(rewrittenHead);
        if (bodyRemainder.length > 0) {
          remoteStream.write(bodyRemainder);
        }
      }

      localSocket.resume();
      remoteStream.resume?.();
      bridgeSockets(localSocket, remoteStream);
    } catch (err) {
      if (onError) onError(err);
      if (remoteStream && !remoteStream.destroyed) {
        remoteStream.destroy();
      }
      if (!localSocket.destroyed) {
        const body = `Bad Gateway: ${formatErrMessage(err)}\n`;
        localSocket.end(
          `HTTP/1.1 502 Bad Gateway\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\nConnection: close\r\n\r\n${body}`,
        );
      }
    }
  });

  return {
    server: proxyServer,
    pool: muxPool,
    listen(...args) {
      if (args.length >= 1 && typeof args[0] === 'string') {
        const ep = parseEndpoint(args[0], '127.0.0.1');
        const cb = typeof args[1] === 'function' ? args[1] : undefined;
        if (ep.path) {
          prepareUnixSocketPath(ep.path);
          proxyServer.listen(ep.path, cb);
        } else if (ep.host) {
          proxyServer.listen(ep.port, ep.host, cb);
        } else {
          proxyServer.listen(ep.port, cb);
        }
        return proxyServer;
      }
      proxyServer.listen(...args);
      return proxyServer;
    },
    close(cb) {
      if (ownsPool && muxPool) muxPool.close();
      proxyServer.close(cb);
    },
  };
}
