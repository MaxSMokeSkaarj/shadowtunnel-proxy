import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { Duplex } from 'node:stream';

const WS_GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';
const MAX_WS_PAYLOAD = 256 * 1024;
const MAX_WS_WRITE_CHUNK = 32768;
const MAX_HTTP_UPGRADE_HEADER = 16 * 1024;

const DECOY_HTML = `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Welcome</title>
<style>body{font-family:system-ui,sans-serif;max-width:36rem;margin:10vh auto;padding:0 1rem;color:#222;line-height:1.5}</style>
</head>
<body><h1>Service Online</h1><p>The server is operational.</p></body>
</html>
`;

// --- Endpoint Parsing (tcp://, tls://, ws://, wss://, unix:) ---

export function parseEndpoint(spec, defaultHost = '127.0.0.1') {
  if (typeof spec === 'number') {
    if (!Number.isInteger(spec) || spec < 0 || spec > 65535) {
      throw new TypeError(`Invalid TCP port: ${spec}`);
    }
    return defaultHost ? { protocol: 'tcp', host: defaultHost, port: spec } : { protocol: 'tcp', port: spec };
  }

  if (spec && typeof spec === 'object') {
    if (spec.path) return { protocol: 'unix', path: String(spec.path) };
    if (spec.port !== undefined) {
      const protocol = spec.protocol || 'tcp';
      const h = spec.host || defaultHost;
      const out = h ? { protocol, host: h, port: Number(spec.port) } : { protocol, port: Number(spec.port) };
      if (spec.wsPath) out.wsPath = spec.wsPath;
      if (spec.servername) out.servername = spec.servername;
      return out;
    }
    throw new TypeError('Endpoint object must specify either { path } or { port, [host] }');
  }

  const str = String(spec || '').trim();
  if (!str) throw new TypeError('Empty endpoint specification');

  if (str.startsWith('unix:')) {
    const sockPath = str.slice(5);
    if (!sockPath) throw new TypeError('Empty unix socket path');
    return { protocol: 'unix', path: sockPath };
  }
  if (str.startsWith('/') || str.startsWith('./') || str.startsWith('../')) {
    return { protocol: 'unix', path: str };
  }

  // Scheme-prefixed endpoints: tcp://, tls://, ws://, wss://
  const schemeMatch = str.match(/^(tcp|tls|ws|wss):\/\/(.*)$/i);
  if (schemeMatch) {
    const protocol = schemeMatch[1].toLowerCase();
    const rest = schemeMatch[2];
    const slashIdx = rest.indexOf('/');
    const authority = slashIdx === -1 ? rest : rest.slice(0, slashIdx);
    const wsPath = slashIdx === -1 ? '/ws' : rest.slice(slashIdx);

    const defaultPort = protocol === 'tls' || protocol === 'wss' ? 443 : 80;
    const { host, port } = parseHostPort(authority, defaultHost, defaultPort);
    const out = host ? { protocol, host, port } : { protocol, port };
    if (protocol === 'ws' || protocol === 'wss') {
      out.wsPath = wsPath;
    }
    if ((protocol === 'tls' || protocol === 'wss') && host && !net.isIP(host)) {
      out.servername = host;
    }
    return out;
  }

  if (/^\d+$/.test(str)) {
    const port = Number(str);
    if (port < 0 || port > 65535) throw new TypeError(`Invalid TCP port: ${str}`);
    return defaultHost ? { protocol: 'tcp', host: defaultHost, port } : { protocol: 'tcp', port };
  }

  const { host, port } = parseHostPort(str, defaultHost, null);
  return host ? { protocol: 'tcp', host, port } : { protocol: 'tcp', port };
}

function parseHostPort(authority, defaultHost, defaultPort) {
  let host;
  let portStr;

  if (authority.startsWith('[')) {
    const closeIdx = authority.indexOf(']');
    if (closeIdx === -1) throw new TypeError(`Invalid IPv6 endpoint: ${authority}`);
    host = authority.slice(1, closeIdx);
    if (authority[closeIdx + 1] === ':') {
      portStr = authority.slice(closeIdx + 2);
    } else if (defaultPort !== null) {
      portStr = String(defaultPort);
    } else {
      throw new TypeError(`Missing port in IPv6 endpoint: ${authority}`);
    }
  } else {
    const colonIdx = authority.lastIndexOf(':');
    if (colonIdx === -1) {
      if (defaultPort === null) {
        throw new TypeError(`Invalid endpoint "${authority}" (expected host:port, :port, or /path/to.sock)`);
      }
      host = authority || defaultHost;
      portStr = String(defaultPort);
    } else {
      host = authority.slice(0, colonIdx) || defaultHost;
      portStr = authority.slice(colonIdx + 1);
    }
  }

  const port = Number(portStr);
  if (!/^\d+$/.test(portStr) || port < 0 || port > 65535) {
    throw new TypeError(`Invalid TCP port in endpoint: ${authority}`);
  }
  return { host, port };
}

export function formatEndpoint(ep) {
  if (!ep) return 'unknown';
  if (typeof ep === 'string') return `unix:${ep}`;
  if (ep.path) return `unix:${ep.path}`;
  const rawHost = ep.host || ep.address || '0.0.0.0';
  const host = rawHost.includes(':') ? `[${rawHost}]` : rawHost;
  const proto = ep.protocol && ep.protocol !== 'tcp' ? `${ep.protocol}://` : '';
  const suffix = (ep.protocol === 'ws' || ep.protocol === 'wss') && ep.wsPath ? ep.wsPath : '';
  return `${proto}${host}:${ep.port}${suffix}`;
}

export function prepareUnixSocketPath(sockPath) {
  if (!fs.existsSync(sockPath)) return;
  const stat = fs.lstatSync(sockPath);
  if (!stat.isSocket()) {
    throw new Error(`Refusing to unlink "${sockPath}": file exists and is not a Unix socket`);
  }
  fs.unlinkSync(sockPath);
}

// --- RFC 6455 WebSocket Binary Carrier Stream ---

function encodeWsFrame(opcode, payload, maskClient) {
  const len = payload.length;
  let headerLen = 2;
  if (len >= 126 && len <= 65535) headerLen += 2;
  else if (len > 65535) headerLen += 8;
  if (maskClient) headerLen += 4;

  const frame = Buffer.allocUnsafe(headerLen + len);
  frame[0] = 0x80 | (opcode & 0x0f); // FIN = 1

  const maskBit = maskClient ? 0x80 : 0x00;
  let offset = 2;
  if (len < 126) {
    frame[1] = maskBit | len;
  } else if (len <= 65535) {
    frame[1] = maskBit | 126;
    frame.writeUInt16BE(len, 2);
    offset = 4;
  } else {
    frame[1] = maskBit | 127;
    frame.writeBigUInt64BE(BigInt(len), 2);
    offset = 10;
  }

  if (maskClient) {
    const mask = crypto.randomBytes(4);
    mask.copy(frame, offset);
    offset += 4;
    for (let i = 0; i < len; i++) {
      frame[offset + i] = payload[i] ^ mask[i & 3];
    }
  } else if (len > 0) {
    payload.copy(frame, offset);
  }
  return frame;
}

export class WebSocketStream extends Duplex {
  constructor(socket, options = {}) {
    super({ allowHalfOpen: true });
    this.socket = socket;
    this.isClient = Boolean(options.isClient);
    this.connecting = Boolean(options.connecting);

    this._buf = options.initialBuffer ? Buffer.from(options.initialBuffer) : Buffer.alloc(0);
    this._closeSent = false;
    this._closeReceived = false;
    this._attached = false;

    if (!this.connecting) {
      this._attachSocket();
    }
  }

  get remoteAddress() {
    return this.socket.remoteAddress;
  }

  get remotePort() {
    return this.socket.remotePort;
  }

  setNoDelay(noDelay) {
    this.socket.setNoDelay?.(noDelay);
  }

  _completeUpgrade(leftover) {
    if (this.destroyed) return;
    if (leftover && leftover.length > 0) {
      this._buf = Buffer.concat([this._buf, leftover]);
    }
    this.connecting = false;
    this._attachSocket();
    this.emit('connect');
    if (this._buf.length > 0) {
      this._parseFrames();
    }
  }

  _attachSocket() {
    if (this._attached) return;
    this._attached = true;

    this._onData = (chunk) => {
      this._buf = this._buf.length === 0 ? chunk : Buffer.concat([this._buf, chunk]);
      this._parseFrames();
    };
    this._onError = (err) => {
      if (!this.destroyed) this.destroy(err);
    };
    this._onClose = () => {
      if (!this.destroyed) this.destroy();
    };
    this._onEnd = () => {
      if (!this._closeReceived && !this.destroyed) {
        this._closeReceived = true;
        this.push(null);
      }
    };
    this._onDrain = () => {
      this.emit('drain');
    };

    this.socket.on('data', this._onData);
    this.socket.on('error', this._onError);
    this.socket.on('close', this._onClose);
    this.socket.on('end', this._onEnd);
    this.socket.on('drain', this._onDrain);
    this.socket.resume?.();

    if (this._buf.length > 0) {
      queueMicrotask(() => {
        if (!this.destroyed) this._parseFrames();
      });
    }
  }

  _parseFrames() {
    while (!this.destroyed && this._buf.length >= 2) {
      const b0 = this._buf[0];
      const b1 = this._buf[1];
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let payloadLen = b1 & 0x7f;
      let offset = 2;

      if (payloadLen === 126) {
        if (this._buf.length < 4) return;
        payloadLen = this._buf.readUInt16BE(2);
        offset = 4;
      } else if (payloadLen === 127) {
        if (this._buf.length < 10) return;
        const bigLen = this._buf.readBigUInt64BE(2);
        if (bigLen > BigInt(MAX_WS_PAYLOAD)) {
          this.destroy(new Error('WebSocket frame exceeds maximum size'));
          return;
        }
        payloadLen = Number(bigLen);
        offset = 10;
      }

      if (payloadLen > MAX_WS_PAYLOAD) {
        this.destroy(new Error('WebSocket frame exceeds maximum size'));
        return;
      }

      const maskLen = masked ? 4 : 0;
      if (this._buf.length < offset + maskLen + payloadLen) {
        return;
      }

      const payload = Buffer.allocUnsafe(payloadLen);
      if (masked) {
        const mask = this._buf.subarray(offset, offset + 4);
        const src = this._buf.subarray(offset + 4, offset + 4 + payloadLen);
        for (let i = 0; i < payloadLen; i++) {
          payload[i] = src[i] ^ mask[i & 3];
        }
      } else if (payloadLen > 0) {
        this._buf.copy(payload, 0, offset, offset + payloadLen);
      }

      const totalConsumed = offset + maskLen + payloadLen;
      this._buf = totalConsumed === this._buf.length
        ? Buffer.alloc(0)
        : Buffer.from(this._buf.subarray(totalConsumed));

      if (opcode === 0x02 || opcode === 0x01 || opcode === 0x00) {
        if (payload.length > 0 && !this.push(payload)) {
          this.socket.pause?.();
        }
      } else if (opcode === 0x08) {
        // Close frame
        this._closeReceived = true;
        if (!this._closeSent && !this.socket.destroyed && this.socket.writable) {
          this._closeSent = true;
          this.socket.end(encodeWsFrame(0x08, Buffer.alloc(0), this.isClient));
        }
        this.push(null);
        return;
      } else if (opcode === 0x09) {
        // Ping -> Pong
        if (!this._closeSent && !this.socket.destroyed && this.socket.writable) {
          this.socket.write(encodeWsFrame(0x0a, payload, this.isClient));
        }
      }
    }
  }

  _read() {
    if (!this.destroyed && !this.socket.destroyed) {
      this.socket.resume?.();
    }
  }

  _write(chunk, encoding, callback) {
    if (this.destroyed || this.socket.destroyed) {
      callback(new Error('WebSocketStream is closed'));
      return;
    }
    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    let ok = true;
    for (let off = 0; off < buf.length; off += MAX_WS_WRITE_CHUNK) {
      const slice = buf.subarray(off, off + MAX_WS_WRITE_CHUNK);
      ok = this.socket.write(encodeWsFrame(0x02, slice, this.isClient));
    }
    if (ok) {
      callback();
    } else {
      const onDrain = () => {
        this.socket.off('close', onClose);
        callback();
      };
      const onClose = () => {
        this.socket.off('drain', onDrain);
      };
      this.socket.once('drain', onDrain);
      this.socket.once('close', onClose);
    }
  }

  _final(callback) {
    if (!this._closeSent && !this.socket.destroyed && this.socket.writable) {
      this._closeSent = true;
      this.socket.write(encodeWsFrame(0x08, Buffer.alloc(0), this.isClient));
    }
    if (this._closeReceived && !this.socket.destroyed) {
      this.socket.end(callback);
    } else {
      callback();
    }
  }

  _destroy(err, callback) {
    if (this._attached) {
      this.socket.off('data', this._onData);
      this.socket.off('error', this._onError);
      this.socket.off('close', this._onClose);
      this.socket.off('end', this._onEnd);
      this.socket.off('drain', this._onDrain);
    }
    if (!this.socket.destroyed) {
      this.socket.destroy();
    }
    this._buf = Buffer.alloc(0);
    callback(err);
  }
}

// --- Client Transport Dialer ---

function loadPemMaterial(input) {
  if (!input) return undefined;
  if (Buffer.isBuffer(input) || String(input).includes('-----BEGIN ')) return input;
  return fs.readFileSync(input);
}

export function dialTransport(ep, options = {}) {
  const proto = ep.protocol || (ep.path ? 'unix' : 'tcp');

  if (proto === 'unix') {
    const s = net.connect({ path: ep.path, allowHalfOpen: true });
    return s;
  }

  if (proto === 'tcp') {
    const s = net.connect({ host: ep.host || '127.0.0.1', port: Number(ep.port), allowHalfOpen: true });
    s.setNoDelay(true);
    return s;
  }

  if (proto === 'tls') {
    const sni = options.tlsServername || ep.servername || (!net.isIP(ep.host || '') ? ep.host : undefined);
    const tlsSock = tls.connect({
      host: ep.host || '127.0.0.1',
      port: Number(ep.port),
      servername: sni,
      ALPNProtocols: ['http/1.1'],
      rejectUnauthorized: options.tlsRejectUnauthorized ?? !options.tlsInsecure,
      ca: loadPemMaterial(options.tlsCa),
      allowHalfOpen: true,
    });
    tlsSock.setNoDelay?.(true);
    // Node tls.TLSSocket emits 'secureConnect' when TLS handshake completes; bridge 'connect' for TunnelSocket
    const wrapper = tlsSock;
    wrapper.connecting = true;
    tlsSock.once('secureConnect', () => {
      wrapper.connecting = false;
      wrapper.emit('connect');
    });
    return wrapper;
  }

  if (proto === 'ws' || proto === 'wss') {
    const host = ep.host || '127.0.0.1';
    const port = Number(ep.port);
    const wsPath = ep.wsPath || '/ws';
    const sni = options.tlsServername || ep.servername || (!net.isIP(host) ? host : undefined);
    const hostHeader = (proto === 'wss' && port === 443) || (proto === 'ws' && port === 80)
      ? (sni || host)
      : `${sni || host}:${port}`;

    const rawSock = proto === 'wss'
      ? tls.connect({
          host,
          port,
          servername: sni,
          ALPNProtocols: ['http/1.1'],
          rejectUnauthorized: options.tlsRejectUnauthorized ?? !options.tlsInsecure,
          ca: loadPemMaterial(options.tlsCa),
          allowHalfOpen: true,
        })
      : net.connect({ host, port, allowHalfOpen: true });

    rawSock.setNoDelay?.(true);
    const wsStream = new WebSocketStream(rawSock, { isClient: true, connecting: true });

    const readyEvent = proto === 'wss' ? 'secureConnect' : 'connect';
    const secKey = crypto.randomBytes(16).toString('base64');
    const expectedAccept = crypto.createHash('sha1').update(secKey + WS_GUID).digest('base64');

    let headerBuf = Buffer.alloc(0);
    const cleanupUpgrade = () => {
      rawSock.off('data', onUpgradeData);
      rawSock.off('error', onUpgradeErr);
      rawSock.off('close', onUpgradeClose);
    };
    const onUpgradeErr = (err) => {
      cleanupUpgrade();
      wsStream.destroy(err);
    };
    const onUpgradeClose = () => {
      cleanupUpgrade();
      if (wsStream.connecting && !wsStream.destroyed) {
        wsStream.destroy(new Error('Connection closed before WebSocket upgrade completed'));
      }
    };
    const onUpgradeData = (chunk) => {
      headerBuf = Buffer.concat([headerBuf, chunk]);
      const endIdx = headerBuf.indexOf('\r\n\r\n');
      if (endIdx === -1) {
        if (headerBuf.length > MAX_HTTP_UPGRADE_HEADER) {
          cleanupUpgrade();
          wsStream.destroy(new Error('WebSocket upgrade response header too large'));
        }
        return;
      }

      const headText = headerBuf.subarray(0, endIdx).toString('latin1');
      const leftover = headerBuf.subarray(endIdx + 4);
      cleanupUpgrade();

      const lines = headText.split('\r\n');
      if (!/^HTTP\/1\.[01]\s+101\b/.test(lines[0] || '')) {
        wsStream.destroy(new Error(`WebSocket upgrade rejected: ${lines[0] || 'invalid response'}`));
        return;
      }
      const acceptHdr = lines.find((l) => l.toLowerCase().startsWith('sec-websocket-accept:'));
      const actualAccept = acceptHdr ? acceptHdr.slice(acceptHdr.indexOf(':') + 1).trim() : '';
      if (actualAccept !== expectedAccept) {
        wsStream.destroy(new Error('Invalid Sec-WebSocket-Accept header'));
        return;
      }

      wsStream._completeUpgrade(leftover);
    };

    rawSock.on('error', onUpgradeErr);
    rawSock.on('close', onUpgradeClose);
    rawSock.once(readyEvent, () => {
      if (wsStream.destroyed) return;
      rawSock.on('data', onUpgradeData);
      rawSock.write(
        `GET ${wsPath} HTTP/1.1\r\n` +
        `Host: ${hostHeader}\r\n` +
        `User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Key: ${secKey}\r\n` +
        `Sec-WebSocket-Version: 13\r\n\r\n`,
      );
    });

    return wsStream;
  }

  throw new TypeError(`Unsupported transport protocol: ${proto}`);
}

// --- Server Transport Listener + Active-Probe Decoy Fallback ---

function handleProbeFallback(rawSocket, capturedBytes, fallbackEndpoint) {
  if (fallbackEndpoint) {
    const fbEp = parseEndpoint(fallbackEndpoint, '127.0.0.1');
    const fbSock = fbEp.path
      ? net.connect({ path: fbEp.path, allowHalfOpen: true })
      : net.connect({ host: fbEp.host || '127.0.0.1', port: fbEp.port, allowHalfOpen: true });
    fbSock.setNoDelay?.(true);

    fbSock.once('connect', () => {
      if (rawSocket.destroyed) {
        fbSock.destroy();
        return;
      }
      if (capturedBytes.length > 0) fbSock.write(capturedBytes);
      rawSocket.resume?.();
      rawSocket.pipe(fbSock);
      fbSock.pipe(rawSocket);
    });
    fbSock.on('error', () => {
      if (!rawSocket.destroyed) rawSocket.destroy();
    });
    rawSocket.on('error', () => {
      if (!fbSock.destroyed) fbSock.destroy();
    });
    return;
  }

  // Built-in realistic web server response for browsers / DPI probes
  const reqLine = capturedBytes.subarray(0, Math.min(capturedBytes.length, 128)).toString('latin1').split('\r\n')[0] || '';
  const isRootGet = /^(GET|HEAD)\s+\/(\?.*)?\s+HTTP\/1\.[01]$/.test(reqLine);
  const isHead = reqLine.startsWith('HEAD ');
  const status = isRootGet ? '200 OK' : '404 Not Found';
  const body = isRootGet ? DECOY_HTML : '<!DOCTYPE html><html><body><h1>404 Not Found</h1></body></html>\n';
  const dateHdr = new Date().toUTCString();

  const headers =
    `HTTP/1.1 ${status}\r\n` +
    `Server: nginx\r\n` +
    `Date: ${dateHdr}\r\n` +
    `Content-Type: text/html; charset=utf-8\r\n` +
    `Content-Length: ${Buffer.byteLength(body)}\r\n` +
    `Connection: close\r\n\r\n`;

  rawSocket.end(isHead ? headers : headers + body);
}

function looksLikeHttpRequest(buf) {
  if (buf.length < 4) return false;
  const prefix = buf.subarray(0, 4).toString('latin1');
  return (
    prefix === 'GET ' ||
    prefix === 'HEAD' ||
    prefix === 'POST' ||
    prefix === 'PUT ' ||
    prefix === 'OPT ' ||
    prefix === 'PRI '
  );
}

export function createTransportServer(options, onCarrierConnection) {
  const {
    tlsCert = null,
    tlsKey = null,
  } = options;

  const hasTlsMaterial = Boolean(tlsCert || tlsKey);

  const handleIncomingSocket = (sock) => {
    sock.setNoDelay?.(true);
    const protocol = options.protocol || (hasTlsMaterial ? 'tls' : 'tcp');
    const wsPath = options.wsPath || '/ws';
    const fallback = options.fallback || null;
    const isTls = protocol === 'tls' || protocol === 'wss' || hasTlsMaterial;
    const isWs = protocol === 'ws' || protocol === 'wss';

    if (!isWs && !isTls && !fallback) {
      onCarrierConnection(sock);
      return;
    }

    // For TLS (non-WS): peek first bytes so HTTP probes get decoy/fallback instead of binary error!
    if (!isWs) {
      let peekBuf = Buffer.alloc(0);
      const timer = setTimeout(() => {
        cleanup();
        if (!sock.destroyed) sock.destroy();
      }, 8_000);
      timer.unref?.();

      const cleanup = () => {
        clearTimeout(timer);
        sock.off('data', onPeek);
        sock.off('error', onErr);
        sock.off('close', onErr);
      };
      const onErr = () => cleanup();
      const onPeek = (chunk) => {
        peekBuf = Buffer.concat([peekBuf, chunk]);
        if (peekBuf.length < 4) return;
        cleanup();
        sock.pause();
        if (looksLikeHttpRequest(peekBuf)) {
          handleProbeFallback(sock, peekBuf, fallback);
          return;
        }
        sock.unshift(peekBuf);
        onCarrierConnection(sock);
      };
      sock.on('data', onPeek);
      sock.on('error', onErr);
      sock.on('close', onErr);
      return;
    }

    // For WS / WSS: parse HTTP Upgrade; divert anything else to decoy/fallback!
    let reqBuf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      if (!sock.destroyed) sock.destroy();
    }, 8_000);
    timer.unref?.();

    const cleanup = () => {
      clearTimeout(timer);
      sock.off('data', onData);
      sock.off('error', onErr);
      sock.off('close', onErr);
    };
    const onErr = () => cleanup();
    const onData = (chunk) => {
      reqBuf = Buffer.concat([reqBuf, chunk]);
      const headerEnd = reqBuf.indexOf('\r\n\r\n');
      if (headerEnd === -1) {
        if (reqBuf.length > MAX_HTTP_UPGRADE_HEADER) {
          cleanup();
          sock.destroy();
        }
        return;
      }

      cleanup();
      sock.pause();
      const rawHead = reqBuf.subarray(0, headerEnd).toString('latin1');
      const remainder = reqBuf.subarray(headerEnd + 4);
      const lines = rawHead.split('\r\n');
      const reqMatch = (lines[0] || '').match(/^GET\s+(\S+)\s+HTTP\/1\.1$/);

      const hdrMap = new Map();
      for (let i = 1; i < lines.length; i++) {
        const idx = lines[i].indexOf(':');
        if (idx !== -1) {
          hdrMap.set(lines[i].slice(0, idx).trim().toLowerCase(), lines[i].slice(idx + 1).trim());
        }
      }

      const reqPath = reqMatch ? reqMatch[1].split('?')[0] : '';
      const isWsUpgrade =
        reqMatch &&
        reqPath === wsPath &&
        (hdrMap.get('upgrade') || '').toLowerCase() === 'websocket' &&
        hdrMap.has('sec-websocket-key');

      if (!isWsUpgrade) {
        handleProbeFallback(sock, reqBuf, fallback);
        return;
      }

      const secKey = hdrMap.get('sec-websocket-key');
      const acceptVal = crypto.createHash('sha1').update(secKey + WS_GUID).digest('base64');
      sock.write(
        `HTTP/1.1 101 Switching Protocols\r\n` +
        `Upgrade: websocket\r\n` +
        `Connection: Upgrade\r\n` +
        `Sec-WebSocket-Accept: ${acceptVal}\r\n\r\n`,
      );

      const wsStream = new WebSocketStream(sock, {
        isClient: false,
        connecting: false,
        initialBuffer: remainder,
      });
      onCarrierConnection(wsStream);
    };

    sock.on('data', onData);
    sock.on('error', onErr);
    sock.on('close', onErr);
  };

  if (hasTlsMaterial || options.protocol === 'tls' || options.protocol === 'wss') {
    if (!tlsCert || !tlsKey) {
      throw new Error(`TLS/WSS server requires tlsCert (--tls-cert) and tlsKey (--tls-key)`);
    }
    return tls.createServer({
      cert: loadPemMaterial(tlsCert),
      key: loadPemMaterial(tlsKey),
      ALPNProtocols: ['http/1.1'],
      minVersion: 'TLSv1.2',
      allowHalfOpen: true,
    }, handleIncomingSocket);
  }

  return net.createServer({ allowHalfOpen: true }, handleIncomingSocket);
}

// --- Zero-Dependency String-Safe JSON / JSONC Config Loader ---

export function stripJsonc(text) {
  const src = String(text).replace(/^\uFEFF/, '');
  let noComments = '';
  let i = 0;
  let inString = false;

  while (i < src.length) {
    const ch = src[i];

    if (inString) {
      noComments += ch;
      if (ch === '\\' && i + 1 < src.length) {
        noComments += src[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }

    if (ch === '"') {
      inString = true;
      noComments += ch;
      i += 1;
      continue;
    }

    // Single-line // comment outside string literals (preserves "wss://..." inside strings!)
    if (ch === '/' && src[i + 1] === '/') {
      i += 2;
      while (i < src.length && src[i] !== '\n') i += 1;
      continue;
    }

    // Multi-line /* ... */ comment outside string literals (preserves newlines for error reporting)
    if (ch === '/' && src[i + 1] === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        if (src[i] === '\n') noComments += '\n';
        i += 1;
      }
      i += 2;
      continue;
    }

    noComments += ch;
    i += 1;
  }

  // Strip trailing commas before '}' or ']' outside string literals
  let clean = '';
  inString = false;
  i = 0;
  while (i < noComments.length) {
    const ch = noComments[i];
    if (inString) {
      clean += ch;
      if (ch === '\\' && i + 1 < noComments.length) {
        clean += noComments[i + 1];
        i += 2;
        continue;
      }
      if (ch === '"') inString = false;
      i += 1;
      continue;
    }
    if (ch === '"') {
      inString = true;
      clean += ch;
      i += 1;
      continue;
    }
    if (ch === ',') {
      let j = i + 1;
      while (j < noComments.length && /\s/.test(noComments[j])) j += 1;
      if (noComments[j] === '}' || noComments[j] === ']') {
        i += 1;
        continue;
      }
    }
    clean += ch;
    i += 1;
  }

  return clean;
}

export function parseJsonc(text, sourceLabel = 'config') {
  try {
    const parsed = JSON.parse(stripJsonc(text));
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('Root value must be a JSON object');
    }
    return parsed;
  } catch (err) {
    throw new Error(`Invalid JSON config in ${sourceLabel}: ${err.message}`);
  }
}

export function loadJsonConfig(configFilePath) {
  const absPath = path.resolve(configFilePath);
  if (!fs.existsSync(absPath)) {
    throw new Error(`Config file not found: ${absPath}`);
  }
  const raw = fs.readFileSync(absPath, 'utf8');
  const data = parseJsonc(raw, absPath);
  return {
    config: data,
    configPath: absPath,
    baseDir: path.dirname(absPath),
  };
}

export function resolvePathFromConfig(value, baseDir) {
  if (!value || typeof value !== 'string') return value;
  if (value.includes('-----BEGIN ')) return value;
  return path.resolve(baseDir, value);
}

export function resolveKeySpecFromConfig(value, baseDir) {
  if (!value) return value;
  if (Array.isArray(value)) {
    return value.map((item) => resolveKeySpecFromConfig(item, baseDir));
  }
  if (typeof value !== 'string') return value;
  const trimmed = value.trim();
  if (trimmed.startsWith('ed25519 ') || trimmed.includes('-----BEGIN ') || trimmed.includes('\n')) {
    return trimmed;
  }
  return path.resolve(baseDir, trimmed);
}

export function resolveEndpointFromConfig(endpoint, baseDir) {
  if (!endpoint || typeof endpoint !== 'string') return endpoint;
  const trimmed = endpoint.trim();
  if (trimmed.startsWith('./') || trimmed.startsWith('../')) {
    return path.resolve(baseDir, trimmed);
  }
  if (trimmed.startsWith('unix:./') || trimmed.startsWith('unix:../')) {
    return `unix:${path.resolve(baseDir, trimmed.slice(5))}`;
  }
  return trimmed;
}
