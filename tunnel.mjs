import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import {
  AEAD_TAG_SIZE,
  CLIENT_AUTH_SIZE,
  CLIENT_HELLO_SIZE,
  ED25519_SIG_SIZE,
  ED25519_SPKI_SIZE,
  FrameParser,
  HANDSHAKE_NONCE_SIZE,
  INNER_AUTH_SIZE,
  MAX_PLAINTEXT_SIZE,
  MSG_CLIENT_AUTH,
  MSG_CLIENT_HELLO,
  MSG_DATA,
  MSG_EOF,
  MSG_PING,
  MSG_PONG,
  MSG_SERVER_HELLO,
  MSG_SERVER_READY,
  ProtocolError,
  SERVER_HELLO_SIZE,
  SERVER_READY_SIZE,
  Transcript,
  X25519_SPKI_SIZE,
  computeFingerprint,
  computeSharedSecret,
  defaultMaxFrameSize,
  deriveCipherPair,
  encodeFrame,
  generateEphemeralKeys,
  generateIdentity,
  importEd25519PublicKey,
  importX25519PublicKey,
  loadAuthorizedKeys,
  loadPrivateKey,
  loadPublicKey,
  parseAuthorizedKeys,
  parsePublicKey,
  signClientTranscript,
  signServerTranscript,
  verifyClientTranscript,
  verifyServerTranscript,
} from './crypto.mjs';

const STATE_CLIENT_INIT = 'CLIENT_INIT';
const STATE_WAIT_CLIENT_HELLO = 'WAIT_CLIENT_HELLO';
const STATE_WAIT_SERVER_HELLO = 'WAIT_SERVER_HELLO';
const STATE_WAIT_CLIENT_AUTH = 'WAIT_CLIENT_AUTH';
const STATE_WAIT_SERVER_READY = 'WAIT_SERVER_READY';
const STATE_OPEN = 'OPEN';
const STATE_CLOSED = 'CLOSED';

export function parseEndpoint(spec, defaultHost = '127.0.0.1') {
  if (typeof spec === 'number') {
    if (!Number.isInteger(spec) || spec < 0 || spec > 65535) {
      throw new TypeError(`Invalid TCP port: ${spec}`);
    }
    return defaultHost ? { host: defaultHost, port: spec } : { port: spec };
  }
  if (spec && typeof spec === 'object') {
    if (spec.path) return { path: String(spec.path) };
    if (spec.port !== undefined) {
      const h = spec.host || defaultHost;
      return h ? { host: h, port: Number(spec.port) } : { port: Number(spec.port) };
    }
    throw new TypeError('Endpoint object must specify either { path } or { port, [host] }');
  }

  const str = String(spec || '').trim();
  if (!str) throw new TypeError('Empty endpoint specification');

  if (str.startsWith('unix:')) {
    const sockPath = str.slice(5);
    if (!sockPath) throw new TypeError('Empty unix socket path');
    return { path: sockPath };
  }
  if (str.startsWith('/') || str.startsWith('./') || str.startsWith('../')) {
    return { path: str };
  }
  if (/^\d+$/.test(str)) {
    const port = Number(str);
    if (port < 0 || port > 65535) throw new TypeError(`Invalid TCP port: ${str}`);
    return defaultHost ? { host: defaultHost, port } : { port };
  }

  let host;
  let portStr;
  if (str.startsWith('[')) {
    const closeIdx = str.indexOf(']');
    if (closeIdx === -1 || str[closeIdx + 1] !== ':') {
      throw new TypeError(`Invalid IPv6 endpoint: ${str}`);
    }
    host = str.slice(1, closeIdx);
    portStr = str.slice(closeIdx + 2);
  } else {
    const colonIdx = str.lastIndexOf(':');
    if (colonIdx === -1) {
      throw new TypeError(`Invalid endpoint "${str}" (expected host:port, :port, or /path/to.sock)`);
    }
    host = str.slice(0, colonIdx) || defaultHost;
    portStr = str.slice(colonIdx + 1);
  }

  const port = Number(portStr);
  if (!/^\d+$/.test(portStr) || port < 0 || port > 65535) {
    throw new TypeError(`Invalid TCP port in endpoint: ${str}`);
  }
  return host ? { host, port } : { port };
}

export function formatError(err) {
  if (!err) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err.message) return err.message;
  if (Array.isArray(err.errors) && err.errors.length > 0) {
    return err.errors.map((e) => e.message || e.code || String(e)).join('; ');
  }
  return err.code || String(err);
}

export function formatEndpoint(ep) {
  if (!ep) return 'unknown';
  if (typeof ep === 'string') return `unix:${ep}`;
  if (ep.path) return `unix:${ep.path}`;
  const rawHost = ep.host || ep.address || '0.0.0.0';
  const host = rawHost.includes(':') ? `[${rawHost}]` : rawHost;
  return `${host}:${ep.port}`;
}

export function prepareUnixSocketPath(sockPath) {
  if (!fs.existsSync(sockPath)) return;
  const stat = fs.lstatSync(sockPath);
  if (!stat.isSocket()) {
    throw new Error(`Refusing to unlink "${sockPath}": file exists and is not a Unix socket`);
  }
  fs.unlinkSync(sockPath);
}

export class TunnelSocket extends Duplex {
  constructor(rawSocket, options = {}) {
    super({ allowHalfOpen: options.allowHalfOpen ?? true });

    const {
      role,
      key,
      serverPublicKey,
      allowAnyServer = false,
      verifyServer = null,
      authorizedKeys,
      allowAnyClient = false,
      authorizeClient = null,
      handshakeTimeoutMs = 10_000,
      keepAliveMs = 30_000,
      keepAliveTimeoutMs = 10_000,
    } = options;

    if (role !== 'client' && role !== 'server') {
      throw new TypeError('TunnelSocket role must be "client" or "server"');
    }
    if (!key) {
      throw new TypeError('TunnelSocket requires "key" (Ed25519 private key)');
    }

    this.rawSocket = rawSocket;
    this.role = role;
    this.authorized = false;
    this.peerFingerprint = null;
    this.peerComment = '';
    this.peerPublicKey = null;
    this.peerSpkiDer = null;

    this._identity = loadPrivateKey(key);
    if (role === 'client') {
      if (!serverPublicKey && !allowAnyServer && typeof verifyServer !== 'function') {
        throw new TypeError('Client TunnelSocket requires "serverPublicKey", "verifyServer", or "allowAnyServer"');
      }
      this._expectedServer = serverPublicKey ? loadPublicKey(serverPublicKey) : null;
      this._allowAnyServer = Boolean(allowAnyServer);
      this._verifyServer = verifyServer;
      this._state = STATE_CLIENT_INIT;
    } else {
      if (!authorizedKeys && !allowAnyClient && typeof authorizeClient !== 'function') {
        throw new TypeError('Server TunnelSocket requires "authorizedKeys", "authorizeClient", or "allowAnyClient"');
      }
      this._authorizedKeys = authorizedKeys ? loadAuthorizedKeys(authorizedKeys) : null;
      this._allowAnyClient = Boolean(allowAnyClient);
      this._authorizeClient = authorizeClient;
      this._state = STATE_WAIT_CLIENT_HELLO;
    }

    this._transcript = new Transcript();
    this._eph = null;
    this._rawShared = null;
    this._hsSend = null;
    this._hsRecv = null;
    this._sendCipher = null;
    this._recvCipher = null;
    this._th2 = null;

    this._localEofSent = false;
    this._remoteEofReceived = false;
    this._pendingPostHandshake = null;
    this._cancelDrainWait = null;

    this._handshakeTimer = null;
    this._keepAliveInterval = null;
    this._pongTimer = null;
    this._keepAliveMs = keepAliveMs;
    this._keepAliveTimeoutMs = keepAliveTimeoutMs;

    this._parser = new FrameParser(
      (type, payload) => this._onFrame(type, payload),
      (type) => this._maxAllowedPayload(type),
    );

    this._bindRawSocket();

    if (handshakeTimeoutMs > 0) {
      this._handshakeTimer = setTimeout(() => {
        if (this._state !== STATE_OPEN && this._state !== STATE_CLOSED) {
          this.destroy(new ProtocolError('Handshake timed out', 'ERR_HANDSHAKE_TIMEOUT'));
        }
      }, handshakeTimeoutMs);
      this._handshakeTimer.unref?.();
    }

    if (role === 'client') {
      if (rawSocket.connecting) {
        rawSocket.once('connect', () => this._startClientHandshake());
      } else {
        queueMicrotask(() => this._startClientHandshake());
      }
    }
  }

  get remoteAddress() {
    return this.rawSocket.remoteAddress;
  }

  get remotePort() {
    return this.rawSocket.remotePort;
  }

  _maxAllowedPayload(type) {
    switch (this._state) {
      case STATE_WAIT_CLIENT_HELLO:
        return type === MSG_CLIENT_HELLO ? CLIENT_HELLO_SIZE : -1;
      case STATE_WAIT_SERVER_HELLO:
        return type === MSG_SERVER_HELLO ? SERVER_HELLO_SIZE : -1;
      case STATE_WAIT_CLIENT_AUTH:
        return type === MSG_CLIENT_AUTH ? CLIENT_AUTH_SIZE : -1;
      case STATE_WAIT_SERVER_READY:
        return type === MSG_SERVER_READY ? SERVER_READY_SIZE : -1;
      case STATE_OPEN:
        if (type === MSG_DATA || type === MSG_EOF || type === MSG_PING || type === MSG_PONG) {
          return defaultMaxFrameSize(type);
        }
        return -1;
      default:
        return -1;
    }
  }

  _bindRawSocket() {
    this._onRawData = (chunk) => {
      this._resetKeepAliveActivity();
      try {
        this._parser.push(chunk);
      } catch (err) {
        this.destroy(err);
      }
    };

    this._onRawError = (err) => {
      if (!this.destroyed) {
        if (this._localEofSent && this._remoteEofReceived) {
          this.destroy();
        } else {
          this.destroy(err);
        }
      }
    };

    this._onRawClose = () => {
      if (this.destroyed || this._state === STATE_CLOSED) return;
      if (this._state !== STATE_OPEN) {
        this.destroy(new ProtocolError('Connection closed before handshake completed', 'ERR_HANDSHAKE_ABORTED'));
      } else if (!this._remoteEofReceived) {
        this.destroy(new ProtocolError('Truncated stream: connection closed without authenticated EOF', 'ERR_TUNNEL_TRUNCATED'));
      } else {
        this.destroy();
      }
    };

    this._onRawEnd = () => {
      // Wait for close or verify EOF immediately if peer half-closed TCP without MSG_EOF
      if (!this.destroyed && this._state !== STATE_CLOSED && !this._remoteEofReceived) {
        const code = this._state === STATE_OPEN ? 'ERR_TUNNEL_TRUNCATED' : 'ERR_HANDSHAKE_ABORTED';
        const msg = this._state === STATE_OPEN
          ? 'Truncated stream: peer ended TCP stream without authenticated EOF'
          : 'Peer ended TCP stream before handshake completed';
        this.destroy(new ProtocolError(msg, code));
      }
    };

    this.rawSocket.setNoDelay?.(true);
    this.rawSocket.on('data', this._onRawData);
    this.rawSocket.on('error', this._onRawError);
    this.rawSocket.on('close', this._onRawClose);
    this.rawSocket.on('end', this._onRawEnd);
    if (typeof this.rawSocket.resume === 'function' && !this.rawSocket.connecting) {
      this.rawSocket.resume();
    }
  }

  // --- Mutual Handshake State Machine ---

  _startClientHandshake() {
    if (this.destroyed || this._state !== STATE_CLIENT_INIT) return;
    try {
      this._eph = generateEphemeralKeys();
      const cNonce = crypto.randomBytes(HANDSHAKE_NONCE_SIZE);
      const helloPayload = Buffer.concat([cNonce, this._eph.publicKeyDer], CLIENT_HELLO_SIZE);
      this._transcript.update(helloPayload);

      this._state = STATE_WAIT_SERVER_HELLO;
      this.rawSocket.write(encodeFrame(MSG_CLIENT_HELLO, helloPayload));
    } catch (err) {
      this.destroy(err);
    }
  }

  _onFrame(type, payload) {
    if (this.destroyed) return;
    switch (this._state) {
      case STATE_WAIT_CLIENT_HELLO:
        return this._handleClientHello(payload);
      case STATE_WAIT_SERVER_HELLO:
        return this._handleServerHello(payload);
      case STATE_WAIT_CLIENT_AUTH:
        return this._handleClientAuth(payload);
      case STATE_WAIT_SERVER_READY:
        return this._handleServerReady(payload);
      case STATE_OPEN:
        return this._handleOpenFrame(type, payload);
      default:
        throw new ProtocolError('Unexpected frame in current state', 'ERR_UNEXPECTED_STATE');
    }
  }

  _handleClientHello(payload) {
    if (payload.length !== CLIENT_HELLO_SIZE) {
      throw new ProtocolError('Invalid CLIENT_HELLO size', 'ERR_HANDSHAKE_FORMAT');
    }
    const cEphDer = payload.subarray(HANDSHAKE_NONCE_SIZE);
    const cEphPub = importX25519PublicKey(cEphDer);
    this._transcript.update(payload);

    this._eph = generateEphemeralKeys();
    const sNonce = crypto.randomBytes(HANDSHAKE_NONCE_SIZE);
    const serverPlain = Buffer.concat([sNonce, this._eph.publicKeyDer], HANDSHAKE_NONCE_SIZE + X25519_SPKI_SIZE);

    this._rawShared = computeSharedSecret(this._eph.privateKey, cEphPub);
    this._transcript.update(serverPlain);
    const th1 = this._transcript.digest();

    const hsPair = deriveCipherPair(this._rawShared, th1, 'hs');
    this._hsSend = hsPair.s2c;
    this._hsRecv = hsPair.c2s;

    const serverSig = signServerTranscript(th1, this._identity.spkiDer, this._identity.privateKey);
    const innerServerAuth = Buffer.concat([this._identity.spkiDer, serverSig], INNER_AUTH_SIZE);
    const encServerAuth = this._hsSend.encrypt(MSG_SERVER_HELLO, innerServerAuth);

    this._transcript.update(innerServerAuth);
    this._th2 = this._transcript.digest();

    const fullPayload = Buffer.concat([serverPlain, encServerAuth], SERVER_HELLO_SIZE);
    this._state = STATE_WAIT_CLIENT_AUTH;
    this.rawSocket.write(encodeFrame(MSG_SERVER_HELLO, fullPayload));
  }

  _handleServerHello(payload) {
    if (payload.length !== SERVER_HELLO_SIZE) {
      throw new ProtocolError('Invalid SERVER_HELLO size', 'ERR_HANDSHAKE_FORMAT');
    }
    const serverPlain = payload.subarray(0, HANDSHAKE_NONCE_SIZE + X25519_SPKI_SIZE);
    const sEphDer = serverPlain.subarray(HANDSHAKE_NONCE_SIZE);
    const encServerAuth = payload.subarray(HANDSHAKE_NONCE_SIZE + X25519_SPKI_SIZE);

    const sEphPub = importX25519PublicKey(sEphDer);
    this._rawShared = computeSharedSecret(this._eph.privateKey, sEphPub);

    this._transcript.update(serverPlain);
    const th1 = this._transcript.digest();

    const hsPair = deriveCipherPair(this._rawShared, th1, 'hs');
    this._hsSend = hsPair.c2s;
    this._hsRecv = hsPair.s2c;

    const innerServerAuth = this._hsRecv.decrypt(MSG_SERVER_HELLO, encServerAuth);
    if (innerServerAuth.length !== INNER_AUTH_SIZE) {
      throw new ProtocolError('Malformed SERVER_HELLO auth payload', 'ERR_HANDSHAKE_FORMAT');
    }

    const serverSpkiDer = innerServerAuth.subarray(0, ED25519_SPKI_SIZE);
    const serverSig = innerServerAuth.subarray(ED25519_SPKI_SIZE);

    let serverPubObj;
    let serverFp;
    let serverComment = '';

    if (this._expectedServer) {
      if (!crypto.timingSafeEqual(serverSpkiDer, this._expectedServer.spkiDer)) {
        throw new ProtocolError('Server public key mismatch', 'ERR_SERVER_IDENTITY_MISMATCH');
      }
      serverPubObj = this._expectedServer.publicKey;
      serverFp = this._expectedServer.fingerprint;
      serverComment = this._expectedServer.comment;
    } else {
      serverPubObj = importEd25519PublicKey(serverSpkiDer);
      serverFp = computeFingerprint(serverSpkiDer);
      if (typeof this._verifyServer === 'function' && !this._verifyServer(Buffer.from(serverSpkiDer), serverFp)) {
        throw new ProtocolError(`Server rejected by verifier (${serverFp})`, 'ERR_SERVER_IDENTITY_MISMATCH');
      }
    }

    if (!verifyServerTranscript(th1, serverSpkiDer, serverSig, serverPubObj)) {
      throw new ProtocolError('Server signature verification failed', 'ERR_SERVER_SIGNATURE_INVALID');
    }

    this.peerPublicKey = serverPubObj;
    this.peerSpkiDer = Buffer.from(serverSpkiDer);
    this.peerFingerprint = serverFp;
    this.peerComment = serverComment;

    this._transcript.update(innerServerAuth);
    const th2 = this._transcript.digest();

    const clientSig = signClientTranscript(th2, this._identity.spkiDer, this._identity.privateKey);
    const innerClientAuth = Buffer.concat([this._identity.spkiDer, clientSig], INNER_AUTH_SIZE);
    const encClientAuth = this._hsSend.encrypt(MSG_CLIENT_AUTH, innerClientAuth);

    this._transcript.update(innerClientAuth);
    const th3 = this._transcript.digest();
    const appPair = deriveCipherPair(this._rawShared, th3, 'app');
    this._sendCipher = appPair.c2s;
    this._recvCipher = appPair.s2c;
    this._zeroHandshakeSecrets();

    this._state = STATE_WAIT_SERVER_READY;
    this.rawSocket.write(encodeFrame(MSG_CLIENT_AUTH, encClientAuth));
  }

  _handleClientAuth(payload) {
    if (payload.length !== CLIENT_AUTH_SIZE) {
      throw new ProtocolError('Invalid CLIENT_AUTH size', 'ERR_HANDSHAKE_FORMAT');
    }
    const innerClientAuth = this._hsRecv.decrypt(MSG_CLIENT_AUTH, payload);
    if (innerClientAuth.length !== INNER_AUTH_SIZE) {
      throw new ProtocolError('Malformed CLIENT_AUTH payload', 'ERR_HANDSHAKE_FORMAT');
    }

    const clientSpkiDer = innerClientAuth.subarray(0, ED25519_SPKI_SIZE);
    const clientSig = innerClientAuth.subarray(ED25519_SPKI_SIZE);

    // Ensure valid Ed25519 SPKI and check authorization
    const clientPubObj = importEd25519PublicKey(clientSpkiDer);
    const clientFp = computeFingerprint(clientSpkiDer);
    let clientComment = '';

    if (this._authorizedKeys) {
      const authorizedEntry = this._authorizedKeys.get(clientSpkiDer.toString('hex'));
      if (!authorizedEntry) {
        throw new ProtocolError(`Unauthorized client key (${clientFp})`, 'ERR_CLIENT_UNAUTHORIZED');
      }
      clientComment = authorizedEntry.comment;
    }
    if (typeof this._authorizeClient === 'function') {
      const res = this._authorizeClient(Buffer.from(clientSpkiDer), clientFp);
      if (!res) {
        throw new ProtocolError(`Client rejected by authorizer (${clientFp})`, 'ERR_CLIENT_UNAUTHORIZED');
      }
      if (typeof res === 'string') clientComment = res;
    }

    if (!verifyClientTranscript(this._th2, clientSpkiDer, clientSig, clientPubObj)) {
      throw new ProtocolError('Client signature verification failed', 'ERR_CLIENT_SIGNATURE_INVALID');
    }

    this.peerPublicKey = clientPubObj;
    this.peerSpkiDer = Buffer.from(clientSpkiDer);
    this.peerFingerprint = clientFp;
    this.peerComment = clientComment;

    this._transcript.update(innerClientAuth);
    const th3 = this._transcript.digest();
    const appPair = deriveCipherPair(this._rawShared, th3, 'app');
    this._sendCipher = appPair.s2c;
    this._recvCipher = appPair.c2s;
    this._zeroHandshakeSecrets();

    const readyPayload = this._sendCipher.encrypt(MSG_SERVER_READY, Buffer.alloc(0));
    this.rawSocket.write(encodeFrame(MSG_SERVER_READY, readyPayload));

    this._completeHandshake('secureConnection');
  }

  _handleServerReady(payload) {
    if (payload.length !== SERVER_READY_SIZE) {
      throw new ProtocolError('Invalid SERVER_READY size', 'ERR_HANDSHAKE_FORMAT');
    }
    const plain = this._recvCipher.decrypt(MSG_SERVER_READY, payload);
    if (plain.length !== 0) {
      throw new ProtocolError('Non-empty SERVER_READY frame', 'ERR_HANDSHAKE_FORMAT');
    }
    this._completeHandshake('secureConnect');
  }

  _completeHandshake(eventName) {
    if (this._handshakeTimer) {
      clearTimeout(this._handshakeTimer);
      this._handshakeTimer = null;
    }
    this._state = STATE_OPEN;
    this.authorized = true;
    this._startKeepAlive();
    this.emit(eventName);

    if (this._pendingPostHandshake) {
      const fn = this._pendingPostHandshake;
      this._pendingPostHandshake = null;
      fn();
    }
  }

  _zeroHandshakeSecrets() {
    if (this._rawShared) {
      this._rawShared.fill(0);
      this._rawShared = null;
    }
    if (this._hsSend) {
      this._hsSend.destroy();
      this._hsSend = null;
    }
    if (this._hsRecv) {
      this._hsRecv.destroy();
      this._hsRecv = null;
    }
    this._eph = null;
    this._th2 = null;
  }

  // --- Application Data & Control Frames ---

  _handleOpenFrame(type, payload) {
    if (this._remoteEofReceived && type === MSG_DATA) {
      throw new ProtocolError('Received DATA frame after EOF', 'ERR_DATA_AFTER_EOF');
    }

    const plaintext = this._recvCipher.decrypt(type, payload);

    switch (type) {
      case MSG_DATA: {
        if (plaintext.length === 0) return;
        const canPushMore = this.push(plaintext);
        if (!canPushMore) {
          this.rawSocket.pause();
        }
        break;
      }
      case MSG_EOF: {
        if (plaintext.length !== 0) {
          throw new ProtocolError('Non-empty EOF frame', 'ERR_INVALID_EOF');
        }
        if (this._remoteEofReceived) {
          throw new ProtocolError('Duplicate EOF frame', 'ERR_DUPLICATE_EOF');
        }
        this._remoteEofReceived = true;
        this.push(null);
        this._maybeCloseRawTransport();
        break;
      }
      case MSG_PING: {
        if (!this._localEofSent && this.rawSocket.writable) {
          this._sendEncryptedFrame(MSG_PONG, plaintext);
        }
        break;
      }
      case MSG_PONG: {
        if (this._pongTimer) {
          clearTimeout(this._pongTimer);
          this._pongTimer = null;
        }
        break;
      }
      default:
        throw new ProtocolError(`Unhandled open frame type 0x${type.toString(16)}`, 'ERR_UNKNOWN_FRAME');
    }
  }

  _sendEncryptedFrame(type, plaintext) {
    const encrypted = this._sendCipher.encrypt(type, plaintext);
    return this.rawSocket.write(encodeFrame(type, encrypted));
  }

  _maybeCloseRawTransport() {
    if (this._localEofSent && this._remoteEofReceived && !this.rawSocket.destroyed) {
      this._stopKeepAlive();
      this.rawSocket.end();
    }
  }

  // --- Keepalive ---

  _startKeepAlive() {
    if (!this._keepAliveMs || this._keepAliveMs <= 0) return;
    this._keepAliveInterval = setInterval(() => {
      if (
        this._state !== STATE_OPEN ||
        this.destroyed ||
        this._pongTimer ||
        this._localEofSent ||
        this._remoteEofReceived ||
        !this.rawSocket.writable
      ) {
        return;
      }
      try {
        this._sendEncryptedFrame(MSG_PING, crypto.randomBytes(8));
        this._pongTimer = setTimeout(() => {
          if (!this.destroyed && this._state === STATE_OPEN) {
            this.destroy(new ProtocolError('Keepalive timeout', 'ERR_KEEPALIVE_TIMEOUT'));
          }
        }, this._keepAliveTimeoutMs);
        this._pongTimer.unref?.();
      } catch (err) {
        this.destroy(err);
      }
    }, this._keepAliveMs);
    this._keepAliveInterval.unref?.();
  }

  _resetKeepAliveActivity() {
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
  }

  _stopKeepAlive() {
    if (this._keepAliveInterval) {
      clearInterval(this._keepAliveInterval);
      this._keepAliveInterval = null;
    }
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
  }

  // --- Duplex Stream Implementation ---

  _read() {
    if (!this.destroyed && !this.rawSocket.destroyed) {
      this.rawSocket.resume();
    }
  }

  _write(chunk, encoding, callback) {
    if (this.destroyed) {
      callback(new Error('TunnelSocket is destroyed'));
      return;
    }
    if (this._state !== STATE_OPEN) {
      this._pendingPostHandshake = () => this._write(chunk, encoding, callback);
      return;
    }

    try {
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
      let canContinue = true;
      for (let offset = 0; offset < buf.length; offset += MAX_PLAINTEXT_SIZE) {
        const slice = buf.subarray(offset, offset + MAX_PLAINTEXT_SIZE);
        canContinue = this._sendEncryptedFrame(MSG_DATA, slice);
      }
      if (canContinue) {
        callback();
      } else {
        this._waitForRawDrain(callback);
      }
    } catch (err) {
      callback(err);
    }
  }

  _final(callback) {
    if (this.destroyed) {
      callback();
      return;
    }
    if (this._state !== STATE_OPEN) {
      this._pendingPostHandshake = () => this._final(callback);
      return;
    }

    try {
      this._localEofSent = true;
      const flushed = this._sendEncryptedFrame(MSG_EOF, Buffer.alloc(0));
      const afterFlush = () => {
        this._maybeCloseRawTransport();
        callback();
      };
      if (flushed) {
        afterFlush();
      } else {
        this._waitForRawDrain(afterFlush);
      }
    } catch (err) {
      callback(err);
    }
  }

  _waitForRawDrain(done) {
    const onDrain = () => {
      cleanup();
      done();
    };
    const onClose = () => {
      cleanup();
    };
    const cleanup = () => {
      this._cancelDrainWait = null;
      this.rawSocket.off('drain', onDrain);
      this.rawSocket.off('close', onClose);
    };
    this._cancelDrainWait = cleanup;
    this.rawSocket.on('drain', onDrain);
    this.rawSocket.on('close', onClose);
  }

  _destroy(err, callback) {
    this._state = STATE_CLOSED;
    this._pendingPostHandshake = null;
    if (this._cancelDrainWait) {
      this._cancelDrainWait();
    }
    if (this._handshakeTimer) {
      clearTimeout(this._handshakeTimer);
      this._handshakeTimer = null;
    }
    this._stopKeepAlive();
    this._parser.stop();
    this._zeroHandshakeSecrets();
    if (this._sendCipher) {
      this._sendCipher.destroy();
      this._sendCipher = null;
    }
    if (this._recvCipher) {
      this._recvCipher.destroy();
      this._recvCipher = null;
    }
    this.rawSocket.off?.('data', this._onRawData);
    this.rawSocket.off?.('error', this._onRawError);
    this.rawSocket.off?.('close', this._onRawClose);
    this.rawSocket.off?.('end', this._onRawEnd);
    if (!this.rawSocket.destroyed) {
      this.rawSocket.destroy();
    }
    callback(err);
  }
}

// --- Server & Client Factory API (similar to node:tls) ---

export class TunnelServer extends EventEmitter {
  constructor(options = {}, connectionListener) {
    super();
    if (!options.key) throw new TypeError('createServer requires "key"');
    if (!options.authorizedKeys && !options.allowAnyClient && typeof options.authorizeClient !== 'function') {
      throw new TypeError('createServer requires "authorizedKeys", "authorizeClient", or "allowAnyClient"');
    }

    // Pre-validate server key & authorizedKeys at startup
    this._identity = loadPrivateKey(options.key);
    this._authorizedKeys = options.authorizedKeys ? loadAuthorizedKeys(options.authorizedKeys) : null;
    this._options = options;
    this._unixSocketPath = null;

    if (typeof connectionListener === 'function') {
      this.on('secureConnection', connectionListener);
    }

    this.netServer = net.createServer({ allowHalfOpen: true }, (rawSocket) => {
      const tunnel = new TunnelSocket(rawSocket, {
        role: 'server',
        key: this._identity,
        authorizedKeys: this._authorizedKeys,
        allowAnyClient: options.allowAnyClient,
        authorizeClient: options.authorizeClient,
        allowHalfOpen: options.allowHalfOpen ?? true,
        handshakeTimeoutMs: options.handshakeTimeoutMs,
        keepAliveMs: options.keepAliveMs,
        keepAliveTimeoutMs: options.keepAliveTimeoutMs,
      });

      const onPreHandshakeError = (err) => {
        this.emit('clientError', err, rawSocket);
      };

      tunnel.once('error', onPreHandshakeError);
      tunnel.once('secureConnection', () => {
        tunnel.off('error', onPreHandshakeError);
        // Permanent fallback guard so removing temporary error listeners never crashes the server
        tunnel.on('error', (err) => {
          if (tunnel.listenerCount('error') === 1) {
            this.emit('clientError', err, rawSocket);
          }
        });
        this.emit('secureConnection', tunnel);
      });
    });

    this.netServer.on('listening', () => this.emit('listening'));
    this.netServer.on('error', (err) => this.emit('error', err));
    this.netServer.on('close', () => {
      this._cleanupUnixSocket();
      this.emit('close');
    });
  }

  get fingerprint() {
    return this._identity.fingerprint;
  }

  address() {
    return this.netServer.address();
  }

  listen(...args) {
    if (args.length >= 1 && (typeof args[0] === 'string' || (typeof args[0] === 'object' && args[0] !== null && !Array.isArray(args[0])))) {
      const first = args[0];
      const cb = typeof args[1] === 'function' ? args[1] : undefined;
      // Support endpoint string like ":5001" (dual-stack), "127.0.0.1:5001", "unix:/tmp/x.sock", "/tmp/x.sock"
      if (typeof first === 'string') {
        const ep = parseEndpoint(first, '');
        if (ep.path) {
          prepareUnixSocketPath(ep.path);
          this._unixSocketPath = ep.path;
          this.netServer.listen(ep.path, cb);
          return this;
        }
        if (ep.host) {
          this.netServer.listen(ep.port, ep.host, cb);
        } else {
          this.netServer.listen(ep.port, cb);
        }
        return this;
      }
      if (first.path) {
        prepareUnixSocketPath(first.path);
        this._unixSocketPath = first.path;
      }
    }
    this.netServer.listen(...args);
    return this;
  }

  close(callback) {
    this.netServer.close((err) => {
      this._cleanupUnixSocket();
      if (callback) callback(err);
    });
    return this;
  }

  _cleanupUnixSocket() {
    if (this._unixSocketPath) {
      try {
        if (fs.existsSync(this._unixSocketPath) && fs.lstatSync(this._unixSocketPath).isSocket()) {
          fs.unlinkSync(this._unixSocketPath);
        }
      } catch {
        // Ignore cleanup errors
      }
      this._unixSocketPath = null;
    }
  }
}

export function createServer(options, connectionListener) {
  return new TunnelServer(options, connectionListener);
}

export function connect(options, connectListener) {
  let connectOpts = options;
  if (typeof options.endpoint !== 'undefined') {
    const ep = parseEndpoint(options.endpoint, '127.0.0.1');
    connectOpts = { ...options, ...ep };
  }

  const rawSocket = connectOpts.path
    ? net.connect({ path: connectOpts.path, allowHalfOpen: true })
    : net.connect({
        host: connectOpts.host || '127.0.0.1',
        port: Number(connectOpts.port),
        allowHalfOpen: true,
      });

  const tunnel = new TunnelSocket(rawSocket, {
    role: 'client',
    key: connectOpts.key,
    serverPublicKey: connectOpts.serverPublicKey,
    allowAnyServer: connectOpts.allowAnyServer,
    verifyServer: connectOpts.verifyServer,
    allowHalfOpen: connectOpts.allowHalfOpen ?? true,
    handshakeTimeoutMs: connectOpts.handshakeTimeoutMs,
    keepAliveMs: connectOpts.keepAliveMs,
    keepAliveTimeoutMs: connectOpts.keepAliveTimeoutMs,
  });

  if (typeof connectListener === 'function') {
    tunnel.once('secureConnect', connectListener);
  }

  return tunnel;
}

export function bridgeSockets(streamA, streamB, onError) {
  const handleErr = (side, other) => (err) => {
    if (onError) onError(err, side);
    if (!other.destroyed) other.destroy();
  };

  streamA.on('error', handleErr('A', streamB));
  streamB.on('error', handleErr('B', streamA));

  streamA.pipe(streamB);
  streamB.pipe(streamA);
}

export {
  generateIdentity,
  loadPrivateKey,
  loadPublicKey,
  loadAuthorizedKeys,
  parsePublicKey,
  parseAuthorizedKeys,
  ProtocolError,
};
