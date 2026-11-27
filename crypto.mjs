import crypto from 'node:crypto';
import fs from 'node:fs';

export const PROTOCOL_ID = Buffer.from('socket-tunnel-v1', 'utf8');

// Frame types
export const MSG_CLIENT_HELLO = 0x01;
export const MSG_SERVER_HELLO = 0x02;
export const MSG_CLIENT_AUTH = 0x03;
export const MSG_SERVER_READY = 0x04;
export const MSG_DATA = 0x10;
export const MSG_EOF = 0x11;
export const MSG_PING = 0x12;
export const MSG_PONG = 0x13;
export const MSG_REKEY = 0x14;

// Protocol size constants
export const FRAME_HEADER_SIZE = 5; // [type:1][length:4 BE]
export const AEAD_TAG_SIZE = 16;
export const NONCE_SIZE = 12;
export const HANDSHAKE_NONCE_SIZE = 16;
export const X25519_SPKI_SIZE = 44;
export const ED25519_SPKI_SIZE = 44;
export const ED25519_SIG_SIZE = 64;

export const CLIENT_HELLO_SIZE = HANDSHAKE_NONCE_SIZE + X25519_SPKI_SIZE; // 60 min
export const INNER_AUTH_SIZE = ED25519_SPKI_SIZE + ED25519_SIG_SIZE; // 108 min
export const SERVER_HELLO_SIZE = HANDSHAKE_NONCE_SIZE + X25519_SPKI_SIZE + INNER_AUTH_SIZE + AEAD_TAG_SIZE; // 184 min
export const CLIENT_AUTH_SIZE = INNER_AUTH_SIZE + AEAD_TAG_SIZE; // 124 min
export const SERVER_READY_SIZE = AEAD_TAG_SIZE; // 16 min
export const MAX_HANDSHAKE_PAD = 256;

export const CLIENT_HELLO_MAX_SIZE = CLIENT_HELLO_SIZE + MAX_HANDSHAKE_PAD;
export const SERVER_HELLO_MAX_SIZE = SERVER_HELLO_SIZE + MAX_HANDSHAKE_PAD;
export const CLIENT_AUTH_MAX_SIZE = CLIENT_AUTH_SIZE + MAX_HANDSHAKE_PAD;
export const SERVER_READY_MAX_SIZE = SERVER_READY_SIZE + MAX_HANDSHAKE_PAD;

export const MAX_PLAINTEXT_SIZE = 65536; // 64 KiB
export const MAX_DATA_FRAME_SIZE = MAX_PLAINTEXT_SIZE + AEAD_TAG_SIZE; // 65552
export const MAX_CONTROL_FRAME_SIZE = 64 + AEAD_TAG_SIZE;
export const REKEY_FRAME_SIZE = 1 + AEAD_TAG_SIZE; // 17 bytes ([requestPeerUpdate:1] + GCM tag)
const MAX_SEQ = 0xffff_ffff_ffff_fffen;

const SERVER_SIG_CONTEXT = Buffer.from('socket-tunnel-v1/server-sig:', 'utf8');
const CLIENT_SIG_CONTEXT = Buffer.from('socket-tunnel-v1/client-sig:', 'utf8');

export class ProtocolError extends Error {
  constructor(message, code = 'ERR_TUNNEL_PROTOCOL') {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

// --- Identity & Key Utilities (Ed25519) ---

export function computeFingerprint(spkiDer) {
  const digest = crypto.createHash('sha256').update(spkiDer).digest('base64').replace(/=+$/, '');
  return `SHA256:${digest}`;
}

export function generateIdentity(comment = '') {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('ed25519');
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  const privateKeyPem = privateKey.export({ type: 'pkcs8', format: 'pem' });
  const cleanComment = comment.trim().replace(/[\r\n]+/g, ' ');
  const publicKeyLine = cleanComment
    ? `ed25519 ${spkiDer.toString('base64')} ${cleanComment}`
    : `ed25519 ${spkiDer.toString('base64')}`;

  return {
    publicKey,
    privateKey,
    spkiDer,
    privateKeyPem,
    publicKeyLine,
    fingerprint: computeFingerprint(spkiDer),
    comment: cleanComment,
  };
}

export function loadPrivateKey(input) {
  let key;
  if (input instanceof crypto.KeyObject) {
    key = input;
  } else if (input && typeof input === 'object' && input.privateKey instanceof crypto.KeyObject) {
    key = input.privateKey;
  } else {
    const raw = Buffer.isBuffer(input) || String(input).includes('BEGIN ')
      ? input
      : fs.readFileSync(input, 'utf8');
    key = crypto.createPrivateKey(raw);
  }
  if (key.type !== 'private' || key.asymmetricKeyType !== 'ed25519') {
    throw new ProtocolError(`Expected ed25519 private key, got ${key.asymmetricKeyType}`, 'ERR_INVALID_KEY_TYPE');
  }
  const publicKey = crypto.createPublicKey(key);
  const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
  return { privateKey: key, publicKey, spkiDer, fingerprint: computeFingerprint(spkiDer) };
}

export function parsePublicKey(rawInput) {
  if (rawInput instanceof crypto.KeyObject) {
    if (rawInput.type !== 'public' || rawInput.asymmetricKeyType !== 'ed25519') {
      throw new ProtocolError(`Expected ed25519 public key, got ${rawInput.asymmetricKeyType}`, 'ERR_INVALID_KEY_TYPE');
    }
    const spkiDer = rawInput.export({ type: 'spki', format: 'der' });
    return { publicKey: rawInput, spkiDer, fingerprint: computeFingerprint(spkiDer), comment: '' };
  }
  if (rawInput && typeof rawInput === 'object' && rawInput.publicKey instanceof crypto.KeyObject) {
    const entry = parsePublicKey(rawInput.publicKey);
    return { ...entry, comment: rawInput.comment || '' };
  }
  if (Buffer.isBuffer(rawInput) && rawInput.length === ED25519_SPKI_SIZE) {
    const publicKey = importEd25519PublicKey(rawInput);
    const canonicalDer = publicKey.export({ type: 'spki', format: 'der' });
    return { publicKey, spkiDer: canonicalDer, fingerprint: computeFingerprint(canonicalDer), comment: '' };
  }
  const text = (Buffer.isBuffer(rawInput) ? rawInput.toString('utf8') : String(rawInput)).trim();
  if (!text) {
    throw new ProtocolError('Empty public key', 'ERR_INVALID_KEY');
  }

  if (text.startsWith('-----BEGIN PUBLIC KEY-----')) {
    const publicKey = crypto.createPublicKey(text);
    if (publicKey.asymmetricKeyType !== 'ed25519') {
      throw new ProtocolError(`Expected ed25519 public key, got ${publicKey.asymmetricKeyType}`, 'ERR_INVALID_KEY_TYPE');
    }
    const spkiDer = publicKey.export({ type: 'spki', format: 'der' });
    return { publicKey, spkiDer, fingerprint: computeFingerprint(spkiDer), comment: '' };
  }

  const parts = text.split(/\s+/);
  if (parts.length < 2 || parts[0] !== 'ed25519') {
    throw new ProtocolError('Invalid public key format (expected "ed25519 <base64> [comment]" or PEM)', 'ERR_INVALID_KEY');
  }
  const der = Buffer.from(parts[1], 'base64');
  const publicKey = importEd25519PublicKey(der);
  const canonicalDer = publicKey.export({ type: 'spki', format: 'der' });
  const comment = parts.slice(2).join(' ');
  return {
    publicKey,
    spkiDer: canonicalDer,
    fingerprint: computeFingerprint(canonicalDer),
    comment,
  };
}

export function loadPublicKey(filePathOrKey) {
  if (typeof filePathOrKey === 'string' && !filePathOrKey.includes('BEGIN ') && !filePathOrKey.startsWith('ed25519 ')) {
    return parsePublicKey(fs.readFileSync(filePathOrKey, 'utf8'));
  }
  return parsePublicKey(filePathOrKey);
}

export function parseAuthorizedKeys(content) {
  const text = Buffer.isBuffer(content) ? content.toString('utf8') : String(content);
  const trimmed = text.trim();
  const map = new Map();
  if (!trimmed) return map;

  if (trimmed.startsWith('-----BEGIN PUBLIC KEY-----')) {
    const entry = parsePublicKey(trimmed);
    map.set(entry.spkiDer.toString('hex'), entry);
    return map;
  }

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith('#')) continue;
    const entry = parsePublicKey(line);
    map.set(entry.spkiDer.toString('hex'), entry);
  }
  return map;
}

export function loadAuthorizedKeys(filePathOrContent) {
  if (filePathOrContent instanceof Map) return filePathOrContent;
  if (
    filePathOrContent instanceof crypto.KeyObject ||
    (filePathOrContent && typeof filePathOrContent === 'object' && filePathOrContent.publicKey instanceof crypto.KeyObject) ||
    (Buffer.isBuffer(filePathOrContent) && filePathOrContent.length === ED25519_SPKI_SIZE)
  ) {
    const entry = parsePublicKey(filePathOrContent);
    const map = new Map();
    map.set(entry.spkiDer.toString('hex'), entry);
    return map;
  }
  if (Array.isArray(filePathOrContent)) {
    const map = new Map();
    for (const item of filePathOrContent) {
      for (const [k, v] of loadAuthorizedKeys(item)) {
        map.set(k, v);
      }
    }
    return map;
  }
  const str = Buffer.isBuffer(filePathOrContent) ? filePathOrContent.toString('utf8') : String(filePathOrContent);
  const content = (!str.includes('BEGIN ') && !str.startsWith('ed25519 ') && !str.includes('\n') && fs.existsSync(str))
    ? fs.readFileSync(str, 'utf8')
    : str;
  return parseAuthorizedKeys(content);
}

// --- Ephemeral ECDH (X25519) & Strict DER Imports ---

export function generateEphemeralKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  return { publicKey, privateKey, publicKeyDer };
}

export function importX25519PublicKey(der) {
  if (!Buffer.isBuffer(der) || der.length !== X25519_SPKI_SIZE) {
    throw new ProtocolError('Invalid X25519 public key length', 'ERR_HANDSHAKE_KEY');
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
  } catch {
    throw new ProtocolError('Malformed X25519 SPKI key', 'ERR_HANDSHAKE_KEY');
  }
  if (key.asymmetricKeyType !== 'x25519') {
    throw new ProtocolError('Unexpected public key algorithm (expected x25519)', 'ERR_HANDSHAKE_KEY');
  }
  return key;
}

export function importEd25519PublicKey(der) {
  if (!Buffer.isBuffer(der) || der.length !== ED25519_SPKI_SIZE) {
    throw new ProtocolError('Invalid Ed25519 public key length', 'ERR_HANDSHAKE_KEY');
  }
  let key;
  try {
    key = crypto.createPublicKey({ key: der, type: 'spki', format: 'der' });
  } catch {
    throw new ProtocolError('Malformed Ed25519 SPKI key', 'ERR_HANDSHAKE_KEY');
  }
  if (key.asymmetricKeyType !== 'ed25519') {
    throw new ProtocolError('Unexpected public key algorithm (expected ed25519)', 'ERR_HANDSHAKE_KEY');
  }
  return key;
}

export function computeSharedSecret(privateKey, peerPublicKey) {
  try {
    return crypto.diffieHellman({ privateKey, publicKey: peerPublicKey });
  } catch {
    throw new ProtocolError('ECDH key agreement failed', 'ERR_ECDH_FAILED');
  }
}

export function signServerTranscript(transcriptHash, serverSpkiDer, serverPrivateKey) {
  const msg = Buffer.concat([SERVER_SIG_CONTEXT, transcriptHash, serverSpkiDer]);
  return crypto.sign(null, msg, serverPrivateKey);
}

export function verifyServerTranscript(transcriptHash, serverSpkiDer, signature, serverPublicKey) {
  if (signature.length !== ED25519_SIG_SIZE) return false;
  const msg = Buffer.concat([SERVER_SIG_CONTEXT, transcriptHash, serverSpkiDer]);
  try {
    return crypto.verify(null, msg, serverPublicKey, signature);
  } catch {
    return false;
  }
}

export function signClientTranscript(transcriptHash, clientSpkiDer, clientPrivateKey) {
  const msg = Buffer.concat([CLIENT_SIG_CONTEXT, transcriptHash, clientSpkiDer]);
  return crypto.sign(null, msg, clientPrivateKey);
}

export function verifyClientTranscript(transcriptHash, clientSpkiDer, signature, clientPublicKey) {
  if (signature.length !== ED25519_SIG_SIZE) return false;
  const msg = Buffer.concat([CLIENT_SIG_CONTEXT, transcriptHash, clientSpkiDer]);
  try {
    return crypto.verify(null, msg, clientPublicKey, signature);
  } catch {
    return false;
  }
}

// --- Transcript & Directional AEAD CipherState ---

export class Transcript {
  constructor() {
    this._hash = crypto.createHash('sha256');
    this.update(PROTOCOL_ID);
  }

  update(buf) {
    const lenBuf = Buffer.allocUnsafe(4);
    lenBuf.writeUInt32BE(buf.length, 0);
    this._hash.update(lenBuf);
    this._hash.update(buf);
  }

  digest() {
    return this._hash.copy().digest();
  }
}

function hkdfExpand(secret, salt, info, length) {
  return Buffer.from(crypto.hkdfSync('sha256', secret, salt, info, length));
}

export function deriveCipherPair(sharedSecret, transcriptHash, phase) {
  const c2sKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v1/${phase}/c2s/key`, 32);
  const c2sIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v1/${phase}/c2s/iv`, NONCE_SIZE);
  const s2cKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v1/${phase}/s2c/key`, 32);
  const s2cIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v1/${phase}/s2c/iv`, NONCE_SIZE);

  return {
    c2s: new CipherState(c2sKey, c2sIv),
    s2c: new CipherState(s2cKey, s2cIv),
  };
}

export class CipherState {
  constructor(key, ivSalt) {
    this._key = key;
    this._ivSalt = ivSalt;
    this._seq = 0n;
    this.epoch = 0;
  }

  ratchet() {
    const nextKey = hkdfExpand(this._key, this._ivSalt, 'socket-tunnel-v1/rekey/key', 32);
    const nextIv = hkdfExpand(this._key, this._ivSalt, 'socket-tunnel-v1/rekey/iv', NONCE_SIZE);
    this._key.fill(0);
    this._ivSalt.fill(0);
    this._key = nextKey;
    this._ivSalt = nextIv;
    this._seq = 0n;
    this.epoch++;
  }

  _nextNonceAndAad(frameType) {
    if (this._seq >= MAX_SEQ) {
      throw new ProtocolError('AEAD sequence number exhausted', 'ERR_SEQ_EXHAUSTED');
    }
    const seq = this._seq++;
    const seqBuf = Buffer.allocUnsafe(8);
    seqBuf.writeBigUInt64BE(seq, 0);

    // TLS 1.3 style deterministic nonce: 96-bit salt XOR 64-bit sequence number
    const nonce = Buffer.from(this._ivSalt);
    for (let i = 0; i < 8; i++) {
      nonce[4 + i] ^= seqBuf[i];
    }

    // Bind both frameType and sequence number into GCM AAD
    const aad = Buffer.allocUnsafe(9);
    aad[0] = frameType;
    seqBuf.copy(aad, 1);

    return { nonce, aad };
  }

  encrypt(frameType, plaintext) {
    const { nonce, aad } = this._nextNonceAndAad(frameType);
    const cipher = crypto.createCipheriv('aes-256-gcm', this._key, nonce);
    cipher.setAAD(aad);
    const enc1 = cipher.update(plaintext);
    const enc2 = cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([enc1, enc2, tag], enc1.length + enc2.length + AEAD_TAG_SIZE);
  }

  decrypt(frameType, payload) {
    if (payload.length < AEAD_TAG_SIZE) {
      throw new ProtocolError('Encrypted frame too short', 'ERR_DECRYPT_FAILED');
    }
    const { nonce, aad } = this._nextNonceAndAad(frameType);
    const ciphertext = payload.subarray(0, payload.length - AEAD_TAG_SIZE);
    const tag = payload.subarray(payload.length - AEAD_TAG_SIZE);

    const decipher = crypto.createDecipheriv('aes-256-gcm', this._key, nonce);
    decipher.setAAD(aad);
    decipher.setAuthTag(tag);
    try {
      const dec1 = decipher.update(ciphertext);
      const dec2 = decipher.final();
      return dec2.length === 0 ? dec1 : Buffer.concat([dec1, dec2], dec1.length + dec2.length);
    } catch {
      throw new ProtocolError('AEAD authentication failed', 'ERR_DECRYPT_FAILED');
    }
  }

  destroy() {
    this._key.fill(0);
    this._ivSalt.fill(0);
  }
}

// --- Wire Framing & O(N) Bounded FrameParser ---

export function encodeFrame(type, payload) {
  const frame = Buffer.allocUnsafe(FRAME_HEADER_SIZE + payload.length);
  frame[0] = type;
  frame.writeUInt32BE(payload.length, 1);
  payload.copy(frame, FRAME_HEADER_SIZE);
  return frame;
}

export function defaultMaxFrameSize(type) {
  switch (type) {
    case MSG_CLIENT_HELLO: return CLIENT_HELLO_MAX_SIZE;
    case MSG_SERVER_HELLO: return SERVER_HELLO_MAX_SIZE;
    case MSG_CLIENT_AUTH: return CLIENT_AUTH_MAX_SIZE;
    case MSG_SERVER_READY: return SERVER_READY_MAX_SIZE;
    case MSG_DATA: return MAX_DATA_FRAME_SIZE;
    case MSG_EOF: return AEAD_TAG_SIZE;
    case MSG_PING:
    case MSG_PONG: return MAX_CONTROL_FRAME_SIZE;
    case MSG_REKEY: return REKEY_FRAME_SIZE;
    default: return -1;
  }
}

export class FrameParser {
  constructor(onFrame, getMaxPayloadSize = defaultMaxFrameSize) {
    this._chunks = [];
    this._totalLength = 0;
    this._onFrame = onFrame;
    this._getMaxPayloadSize = getMaxPayloadSize;
    this._stopped = false;
    this._headerScratch = Buffer.allocUnsafe(FRAME_HEADER_SIZE);
  }

  stop() {
    this._stopped = true;
    this._chunks.length = 0;
    this._totalLength = 0;
  }

  _peekHeader() {
    const first = this._chunks[0];
    if (first.length >= FRAME_HEADER_SIZE) {
      return first;
    }
    let copied = 0;
    for (const chunk of this._chunks) {
      const toCopy = Math.min(chunk.length, FRAME_HEADER_SIZE - copied);
      chunk.copy(this._headerScratch, copied, 0, toCopy);
      copied += toCopy;
      if (copied === FRAME_HEADER_SIZE) break;
    }
    return this._headerScratch;
  }

  _consumeBytes(count, targetBuffer = null) {
    let remaining = count;
    let offset = 0;
    while (remaining > 0) {
      const head = this._chunks[0];
      if (head.length <= remaining) {
        if (targetBuffer) head.copy(targetBuffer, offset);
        offset += head.length;
        remaining -= head.length;
        this._chunks.shift();
      } else {
        if (targetBuffer) head.copy(targetBuffer, offset, 0, remaining);
        this._chunks[0] = head.subarray(remaining);
        offset += remaining;
        remaining = 0;
      }
    }
    this._totalLength -= count;
  }

  push(chunk) {
    if (this._stopped || chunk.length === 0) return;
    this._chunks.push(chunk);
    this._totalLength += chunk.length;

    while (!this._stopped && this._totalLength >= FRAME_HEADER_SIZE) {
      const header = this._peekHeader();
      const type = header[0];
      const len = header.readUInt32BE(1);
      const maxLen = this._getMaxPayloadSize(type);

      if (maxLen < 0) {
        this.stop();
        throw new ProtocolError(`Unknown frame type: 0x${type.toString(16)}`, 'ERR_UNKNOWN_FRAME');
      }
      if (len > maxLen) {
        this.stop();
        throw new ProtocolError(`Frame length ${len} exceeds limit ${maxLen} for type 0x${type.toString(16)}`, 'ERR_FRAME_TOO_LARGE');
      }
      if (this._totalLength < FRAME_HEADER_SIZE + len) {
        return;
      }

      this._consumeBytes(FRAME_HEADER_SIZE, null);
      const payload = Buffer.allocUnsafe(len);
      if (len > 0) {
        this._consumeBytes(len, payload);
      }

      this._onFrame(type, payload);
    }
  }
}
