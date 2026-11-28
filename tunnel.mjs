import crypto from 'node:crypto';
import fs from 'node:fs';
import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import {
  AEAD_TAG_SIZE,
  CLIENT_AUTH_MAX_SIZE,
  CLIENT_AUTH_SIZE,
  CLIENT_HELLO_MAX_SIZE,
  CLIENT_HELLO_SIZE,
  ED25519_SIG_SIZE,
  ED25519_SPKI_SIZE,
  FrameParser,
  HANDSHAKE_NONCE_SIZE,
  INNER_AUTH_SIZE,
  MAX_HANDSHAKE_PAD,
  MAX_PLAINTEXT_SIZE,
  MSG_CLIENT_AUTH,
  MSG_CLIENT_HELLO,
  MSG_DATA,
  MSG_EOF,
  MSG_PING,
  MSG_PONG,
  MSG_REKEY,
  MSG_SERVER_HELLO,
  MSG_SERVER_READY,
  ProtocolError,
  SERVER_HELLO_MAX_SIZE,
  SERVER_HELLO_SIZE,
  SERVER_READY_MAX_SIZE,
  SERVER_READY_SIZE,
  Transcript,
  X25519_RAW_SIZE,
  X25519_SPKI_SIZE,
  computeFingerprint,
  computeSharedSecret,
  defaultMaxFrameSize,
  deriveCipherPair,
  encodeSaltedHandshakeFrame,
  generateEphemeralKeys,
  generateIdentity,
  importEd25519PublicKey,
  importX25519PublicKey,
  importX25519RawPublicKey,
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
import {
  WebSocketStream,
  createTransportServer,
  dialTransport,
  formatEndpoint,
  loadJsonConfig,
  parseEndpoint,
  parseJsonc,
  prepareUnixSocketPath,
  resolveEndpointFromConfig,
  resolveKeySpecFromConfig,
  resolvePathFromConfig,
  stripJsonc,
} from './transport.mjs';

export {
  WebSocketStream,
  dialTransport,
  formatEndpoint,
  loadJsonConfig,
  parseEndpoint,
  parseJsonc,
  prepareUnixSocketPath,
  resolveEndpointFromConfig,
  resolveKeySpecFromConfig,
  resolvePathFromConfig,
  stripJsonc,
};

const STATE_CLIENT_INIT = 'CLIENT_INIT';
const STATE_WAIT_CLIENT_HELLO = 'WAIT_CLIENT_HELLO';
const STATE_WAIT_SERVER_HELLO = 'WAIT_SERVER_HELLO';
const STATE_WAIT_CLIENT_AUTH = 'WAIT_CLIENT_AUTH';
const STATE_WAIT_SERVER_READY = 'WAIT_SERVER_READY';
const STATE_OPEN = 'OPEN';
const STATE_CLOSED = 'CLOSED';

export function formatError(err) {
  if (!err) return 'Unknown error';
  if (typeof err === 'string') return err;
  if (err.message) return err.message;
  if (Array.isArray(err.errors) && err.errors.length > 0) {
    return err.errors.map((e) => e.message || e.code || String(e)).join('; ');
  }
  return err.code || String(err);
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
      rekeyAfterBytes = 512 * 1024 * 1024, // 512 MiB default
      rekeyIntervalMs = 30 * 60 * 1000, // 30 minutes default
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
    this.sendEpoch = 0;
    this.recvEpoch = 0;

    this._identity = loadPrivateKey(key);
    if (role === 'client') {
      if (!serverPublicKey && !allowAnyServer && typeof verifyServer !== 'function') {
        throw new TypeError('Client TunnelSocket requires "serverPublicKey", "verifyServer", or "allowAnyServer"');
      }
      this._expectedServers = serverPublicKey ? loadAuthorizedKeys(serverPublicKey) : null;
      if (this._expectedServers && this._expectedServers.size === 0) {
        throw new ProtocolError('No valid server public keys provided', 'ERR_INVALID_KEY');
      }
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
    this._lastActivityAt = Date.now();

    this._rekeyAfterBytes = rekeyAfterBytes;
    this._rekeyIntervalMs = rekeyIntervalMs;
    this._rekeyInterval = null;
    this._bytesSinceRekey = 0;
    this._rekeyWindowStart = 0;
    this._rekeyCountInWindow = 0;

    this._parser = new FrameParser(
      (type, payload, salt) => this._onFrame(type, payload, salt),
      (type) => this._maxAllowedPayload(type),
      role === 'client' ? 'salted-sh' : 'salted-ch',
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
        return type === MSG_CLIENT_HELLO ? CLIENT_HELLO_MAX_SIZE : -1;
      case STATE_WAIT_SERVER_HELLO:
        return type === MSG_SERVER_HELLO ? SERVER_HELLO_MAX_SIZE : -1;
      case STATE_WAIT_CLIENT_AUTH:
        return type === MSG_CLIENT_AUTH ? CLIENT_AUTH_MAX_SIZE : -1;
      case STATE_WAIT_SERVER_READY:
        return type === MSG_SERVER_READY ? SERVER_READY_MAX_SIZE : -1;
      case STATE_OPEN:
        if (
          type === MSG_DATA ||
          type === MSG_EOF ||
          type === MSG_PING ||
          type === MSG_PONG ||
          type === MSG_REKEY
        ) {
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
      const cSalt = crypto.randomBytes(HANDSHAKE_NONCE_SIZE);
      const pad = crypto.randomBytes(crypto.randomInt(16, MAX_HANDSHAKE_PAD - 16));
      const helloBody = Buffer.concat([this._eph.publicKeyRaw, pad]);
      this._transcript.update(Buffer.concat([cSalt, helloBody]));

      this._state = STATE_WAIT_SERVER_HELLO;
      this._lastActivityAt = Date.now();
      this.rawSocket.write(encodeSaltedHandshakeFrame('ch', MSG_CLIENT_HELLO, helloBody, cSalt));
    } catch (err) {
      this.destroy(err);
    }
  }

  _onFrame(type, payload, salt) {
    if (this.destroyed) return;
    switch (this._state) {
      case STATE_WAIT_CLIENT_HELLO:
        return this._handleClientHello(payload, salt);
      case STATE_WAIT_SERVER_HELLO:
        return this._handleServerHello(payload, salt);
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

  _handleClientHello(payload, cSalt) {
    if (payload.length < CLIENT_HELLO_SIZE || payload.length > CLIENT_HELLO_MAX_SIZE) {
      throw new ProtocolError('Invalid CLIENT_HELLO size', 'ERR_HANDSHAKE_FORMAT');
    }
    const cEphRaw = payload.subarray(0, X25519_RAW_SIZE);
    const cEphPub = importX25519RawPublicKey(cEphRaw);
    this._transcript.update(Buffer.concat([cSalt, payload]));

    this._eph = generateEphemeralKeys();
    const sSalt = crypto.randomBytes(HANDSHAKE_NONCE_SIZE);
    const sPad = crypto.randomBytes(crypto.randomInt(16, MAX_HANDSHAKE_PAD - 16));
    const serverPlain = Buffer.concat([this._eph.publicKeyRaw, sPad]);

    this._rawShared = computeSharedSecret(this._eph.privateKey, cEphPub);
    this._transcript.update(Buffer.concat([sSalt, serverPlain]));
    const th1 = this._transcript.digest();

    const hsPair = deriveCipherPair(this._rawShared, th1, 'hs');
    this._hsSend = hsPair.s2c;
    this._hsRecv = hsPair.c2s;

    const serverSig = signServerTranscript(th1, this._identity.spkiDer, this._identity.privateKey);
    const innerServerAuth = Buffer.concat([this._identity.spkiDer, serverSig], INNER_AUTH_SIZE);
    const encServerAuth = this._hsSend.encrypt(MSG_SERVER_HELLO, innerServerAuth);

    this._transcript.update(innerServerAuth);
    this._th2 = this._transcript.digest();

    const fullBody = Buffer.concat([serverPlain, encServerAuth]);
    this._state = STATE_WAIT_CLIENT_AUTH;
    this._parser.setCipher(this._hsRecv);
    this._lastActivityAt = Date.now();
    this.rawSocket.write(encodeSaltedHandshakeFrame('sh', MSG_SERVER_HELLO, fullBody, sSalt));
  }

  _handleServerHello(payload, sSalt) {
    if (payload.length < SERVER_HELLO_SIZE || payload.length > SERVER_HELLO_MAX_SIZE) {
      throw new ProtocolError('Invalid SERVER_HELLO size', 'ERR_HANDSHAKE_FORMAT');
    }
    const encAuthLen = INNER_AUTH_SIZE + AEAD_TAG_SIZE;
    const serverPlain = payload.subarray(0, payload.length - encAuthLen);
    const sEphRaw = serverPlain.subarray(0, X25519_RAW_SIZE);
    const encServerAuth = payload.subarray(payload.length - encAuthLen);

    const sEphPub = importX25519RawPublicKey(sEphRaw);
    this._rawShared = computeSharedSecret(this._eph.privateKey, sEphPub);

    this._transcript.update(Buffer.concat([sSalt, serverPlain]));
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

    if (this._expectedServers) {
      const matched = this._expectedServers.get(serverSpkiDer.toString('hex'));
      if (!matched || !crypto.timingSafeEqual(serverSpkiDer, matched.spkiDer)) {
        throw new ProtocolError('Server public key mismatch', 'ERR_SERVER_IDENTITY_MISMATCH');
      }
      serverPubObj = matched.publicKey;
      serverFp = matched.fingerprint;
      serverComment = matched.comment;
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
    const cAuthPad = crypto.randomBytes(crypto.randomInt(16, MAX_HANDSHAKE_PAD - 16));
    const innerClientAuth = Buffer.concat([this._identity.spkiDer, clientSig, cAuthPad]);
    const encClientAuthFrame = this._hsSend.encryptFrame(MSG_CLIENT_AUTH, innerClientAuth);

    this._transcript.update(innerClientAuth);
    const th3 = this._transcript.digest();
    const appPair = deriveCipherPair(this._rawShared, th3, 'app');
    this._sendCipher = appPair.c2s;
    this._recvCipher = appPair.s2c;
    this._zeroHandshakeSecrets();

    this._state = STATE_WAIT_SERVER_READY;
    this._parser.setCipher(this._recvCipher);
    this._lastActivityAt = Date.now();
    this.rawSocket.write(encClientAuthFrame);
  }

  _handleClientAuth(payload) {
    if (payload.length < CLIENT_AUTH_SIZE || payload.length > CLIENT_AUTH_MAX_SIZE) {
      throw new ProtocolError('Invalid CLIENT_AUTH size', 'ERR_HANDSHAKE_FORMAT');
    }
    const innerClientAuth = this._hsRecv.decrypt(MSG_CLIENT_AUTH, payload);
    if (innerClientAuth.length < INNER_AUTH_SIZE) {
      throw new ProtocolError('Malformed CLIENT_AUTH payload', 'ERR_HANDSHAKE_FORMAT');
    }

    const clientSpkiDer = innerClientAuth.subarray(0, ED25519_SPKI_SIZE);
    const clientSig = innerClientAuth.subarray(ED25519_SPKI_SIZE, INNER_AUTH_SIZE);

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

    this._parser.setCipher(this._recvCipher);
    const readyPad = crypto.randomBytes(crypto.randomInt(16, MAX_HANDSHAKE_PAD - 16));
    const readyFrame = this._sendCipher.encryptFrame(MSG_SERVER_READY, readyPad);
    this._lastActivityAt = Date.now();
    this.rawSocket.write(readyFrame);

    this._completeHandshake('secureConnection');
  }

  _handleServerReady(payload) {
    if (payload.length < SERVER_READY_SIZE || payload.length > SERVER_READY_MAX_SIZE) {
      throw new ProtocolError('Invalid SERVER_READY size', 'ERR_HANDSHAKE_FORMAT');
    }
    this._recvCipher.decrypt(MSG_SERVER_READY, payload);
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
          // Independent random PONG size (defeats PING == PONG echo length/RTT oracle!)
          const pongPad = crypto.randomBytes(crypto.randomInt(8, 97));
          this._sendEncryptedFrame(MSG_PONG, pongPad);
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
      case MSG_REKEY: {
        if (plaintext.length !== 1 || (plaintext[0] !== 0 && plaintext[0] !== 1)) {
          throw new ProtocolError('Malformed MSG_REKEY payload', 'ERR_INVALID_REKEY');
        }
        const requestPeerUpdate = plaintext[0] === 1;
        if (requestPeerUpdate) {
          const now = Date.now();
          if (now - this._rekeyWindowStart > 1000) {
            this._rekeyWindowStart = now;
            this._rekeyCountInWindow = 0;
          }
          if (++this._rekeyCountInWindow > 64) {
            throw new ProtocolError('Excessive MSG_REKEY rate from peer', 'ERR_REKEY_FLOOD');
          }
        }

        // Ratchet incoming cipher immediately; all subsequent frames use new epoch key
        this._recvCipher.ratchet();
        this.recvEpoch = this._recvCipher.epoch;

        if (requestPeerUpdate && !this._localEofSent && this.rawSocket.writable) {
          this._performSendRekey(false);
        }
        this.emit('rekey', { direction: 'recv', sendEpoch: this.sendEpoch, recvEpoch: this.recvEpoch });
        break;
      }
      default:
        throw new ProtocolError(`Unhandled open frame type 0x${type.toString(16)}`, 'ERR_UNKNOWN_FRAME');
    }
  }

  rekey() {
    if (this._state !== STATE_OPEN || this.destroyed || this._localEofSent || !this.rawSocket.writable) {
      return false;
    }
    this._performSendRekey(true);
    return true;
  }

  _performSendRekey(requestPeerUpdate) {
    const flagBuf = Buffer.from([requestPeerUpdate ? 1 : 0]);
    const rawFrame = this._sendCipher.encryptFrame(MSG_REKEY, flagBuf);
    this._lastActivityAt = Date.now();
    this.rawSocket.write(rawFrame);

    this._sendCipher.ratchet();
    this.sendEpoch = this._sendCipher.epoch;
    this._bytesSinceRekey = 0;
    this.emit('rekey', { direction: 'send', sendEpoch: this.sendEpoch, recvEpoch: this.recvEpoch });
  }

  _sendEncryptedFrame(type, plaintext) {
    const rawFrame = this._sendCipher.encryptFrame(type, plaintext);
    this._lastActivityAt = Date.now();
    const ok = this.rawSocket.write(rawFrame);

    if (type === MSG_DATA) {
      this._bytesSinceRekey += plaintext.length;
      if (
        this._rekeyAfterBytes > 0 &&
        this._bytesSinceRekey >= this._rekeyAfterBytes &&
        !this._localEofSent &&
        this.rawSocket.writable
      ) {
        this._performSendRekey(true);
      }
    }
    return ok;
  }

  _maybeCloseRawTransport() {
    if (this._localEofSent && this._remoteEofReceived && !this.rawSocket.destroyed) {
      this._stopKeepAlive();
      this.rawSocket.end();
    }
  }

  // --- Keepalive (idle-only, jittered, non-echoing) ---

  setKeepAlive(intervalMs) {
    this._keepAliveMs = Number(intervalMs) || 0;
    if (this._keepAliveInterval) {
      clearTimeout(this._keepAliveInterval);
      this._keepAliveInterval = null;
    }
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
    if (this._keepAliveMs > 0 && this._state === STATE_OPEN && !this.destroyed) {
      this._scheduleIdlePing();
    }
  }

  _scheduleIdlePing() {
    if (this._state !== STATE_OPEN || this.destroyed || !this._keepAliveMs || this._keepAliveMs <= 0) return;
    const jitteredDelay = Math.max(10, Math.round(this._keepAliveMs * (0.75 + Math.random() * 0.5)));
    this._keepAliveInterval = setTimeout(() => {
      if (
        this._state !== STATE_OPEN ||
        this.destroyed ||
        this._localEofSent ||
        this._remoteEofReceived ||
        !this.rawSocket.writable
      ) {
        return;
      }

      // Only transmit MSG_PING when channel has genuinely been idle (no live data traffic)
      const idleMs = Date.now() - this._lastActivityAt;
      if (idleMs < jitteredDelay * 0.75) {
        this._scheduleIdlePing();
        return;
      }

      if (!this._pongTimer) {
        try {
          const pingNoise = crypto.randomBytes(crypto.randomInt(8, 97));
          this._sendEncryptedFrame(MSG_PING, pingNoise);
          this._pongTimer = setTimeout(() => {
            if (!this.destroyed && this._state === STATE_OPEN) {
              this.destroy(new ProtocolError('Keepalive timeout', 'ERR_KEEPALIVE_TIMEOUT'));
            }
          }, this._keepAliveTimeoutMs);
          this._pongTimer.unref?.();
        } catch (err) {
          this.destroy(err);
          return;
        }
      }
      this._scheduleIdlePing();
    }, jitteredDelay);
    this._keepAliveInterval.unref?.();
  }

  _startKeepAlive() {
    if (this.role === 'client' && this._rekeyIntervalMs > 0) {
      this._rekeyInterval = setInterval(() => {
        if (
          this._state === STATE_OPEN &&
          !this.destroyed &&
          !this._localEofSent &&
          !this._remoteEofReceived &&
          this.rawSocket.writable
        ) {
          try {
            this.rekey();
          } catch (err) {
            this.destroy(err);
          }
        }
      }, this._rekeyIntervalMs);
      this._rekeyInterval.unref?.();
    }

    if (!this._keepAliveMs || this._keepAliveMs <= 0) return;
    this._scheduleIdlePing();
  }

  _resetKeepAliveActivity() {
    this._lastActivityAt = Date.now();
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
  }

  _stopKeepAlive() {
    if (this._keepAliveInterval) {
      clearTimeout(this._keepAliveInterval);
      this._keepAliveInterval = null;
    }
    if (this._pongTimer) {
      clearTimeout(this._pongTimer);
      this._pongTimer = null;
    }
    if (this._rekeyInterval) {
      clearInterval(this._rekeyInterval);
      this._rekeyInterval = null;
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
    this._transportConfig = {
      protocol: options.protocol || (options.tlsCert ? 'tls' : 'tcp'),
      wsPath: options.wsPath || '/ws',
      tlsCert: options.tlsCert || null,
      tlsKey: options.tlsKey || null,
      fallback: options.fallback || null,
    };

    if (typeof connectionListener === 'function') {
      this.on('secureConnection', connectionListener);
    }

    this.netServer = createTransportServer(this._transportConfig, (rawSocket) => {
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
        rekeyAfterBytes: options.rekeyAfterBytes,
        rekeyIntervalMs: options.rekeyIntervalMs,
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
        if (ep.protocol) this._transportConfig.protocol = ep.protocol;
        if (ep.wsPath) this._transportConfig.wsPath = ep.wsPath;
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
      if (first.protocol) this._transportConfig.protocol = first.protocol;
      if (first.wsPath) this._transportConfig.wsPath = first.wsPath;
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

  const rawSocket = dialTransport(connectOpts, connectOpts);

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
    rekeyAfterBytes: connectOpts.rekeyAfterBytes,
    rekeyIntervalMs: connectOpts.rekeyIntervalMs,
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

import { MuxSession, MuxStream } from './mux.mjs';

export {
  MuxSession,
  MuxStream,
  generateIdentity,
  loadPrivateKey,
  loadPublicKey,
  loadAuthorizedKeys,
  parsePublicKey,
  parseAuthorizedKeys,
  ProtocolError,
};
