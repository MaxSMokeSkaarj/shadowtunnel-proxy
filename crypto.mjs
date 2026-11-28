import crypto from 'node:crypto';
import fs from 'node:fs';

export const PROTOCOL_ID = Buffer.from('socket-tunnel-v2.1', 'utf8');

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
export const MSG_DATA_PAD = 0x15;

// Protocol size constants
export const FRAME_HEADER_SIZE = 5; // [type:1][length:4 BE] (encrypted & bound into GCM AAD)
export const AEAD_TAG_SIZE = 16;
export const NONCE_SIZE = 12;
export const HANDSHAKE_NONCE_SIZE = 16;
export const X25519_RAW_SIZE = 32;
export const X25519_SPKI_SIZE = 44;
export const ED25519_SPKI_SIZE = 44;
export const ED25519_SIG_SIZE = 64;

// Handshake v2.1 AEAD key-slot & replay parameters
export const MAX_KEY_SLOTS = 8;
export const SH_SEED_SIZE = 32;
export const CH_TIMESTAMP_SIZE = 8;
export const CH_SLOT_PLAIN_SIZE = 1 + 2 + SH_SEED_SIZE; // [slotCount:1][bodyEncLen:2][shSeed:32] = 35B
export const CH_SLOT_WIRE_SIZE = CH_SLOT_PLAIN_SIZE + AEAD_TAG_SIZE; // 51B
export const SH_HDR_WIRE_SIZE = 2 + AEAD_TAG_SIZE; // [bodyEncLen:2] + GCM tag = 18B
export const DEFAULT_MAX_CLOCK_SKEW_SEC = 120;

const X25519_SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

// Only accepted when server explicitly sets allowUnpinnedClientHello: true (e.g. private LAN mesh discovery)
export const UNPINNED_HANDSHAKE_KEY = crypto
  .createHash('sha256')
  .update('socket-tunnel-v2.1/unpinned-discovery-key')
  .digest();

// Logical body sizes
export const CLIENT_HELLO_SIZE = CH_TIMESTAMP_SIZE + X25519_RAW_SIZE; // 40B min ([timestamp:8][cEphRaw:32])
export const INNER_AUTH_SIZE = ED25519_SPKI_SIZE + ED25519_SIG_SIZE; // 108B
export const SERVER_HELLO_SIZE = X25519_RAW_SIZE + INNER_AUTH_SIZE + AEAD_TAG_SIZE; // 156B min
export const CLIENT_AUTH_SIZE = INNER_AUTH_SIZE + AEAD_TAG_SIZE; // 124B min
export const SERVER_READY_SIZE = AEAD_TAG_SIZE; // 16B min
export const MAX_HANDSHAKE_PAD = 256;

export const CLIENT_HELLO_MAX_SIZE = CLIENT_HELLO_SIZE + MAX_HANDSHAKE_PAD;
export const SERVER_HELLO_MAX_SIZE = SERVER_HELLO_SIZE + MAX_HANDSHAKE_PAD;
export const CLIENT_AUTH_MAX_SIZE = CLIENT_AUTH_SIZE + MAX_HANDSHAKE_PAD;
export const SERVER_READY_MAX_SIZE = SERVER_READY_SIZE + MAX_HANDSHAKE_PAD;

const CH_BODY_MIN_ENC_SIZE = CLIENT_HELLO_SIZE + AEAD_TAG_SIZE; // 56B
const CH_BODY_MAX_ENC_SIZE = CLIENT_HELLO_MAX_SIZE + AEAD_TAG_SIZE; // 312B
const SH_BODY_MIN_ENC_SIZE = SERVER_HELLO_SIZE + AEAD_TAG_SIZE; // 172B
const SH_BODY_MAX_ENC_SIZE = SERVER_HELLO_MAX_SIZE + AEAD_TAG_SIZE; // 428B

export const MAX_PLAINTEXT_SIZE = 65536; // 64 KiB
export const MAX_DATA_FRAME_SIZE = MAX_PLAINTEXT_SIZE + AEAD_TAG_SIZE; // 65552
export const MAX_PADDED_DATA_FRAME_SIZE = 1 + MAX_PLAINTEXT_SIZE + 255 + AEAD_TAG_SIZE; // 65808
export const MAX_CONTROL_FRAME_SIZE = 128 + AEAD_TAG_SIZE;
export const REKEY_FRAME_SIZE = 1 + AEAD_TAG_SIZE; // 17 bytes ([requestPeerUpdate:1] + GCM tag)
const MAX_SEQ = 0xffff_ffff_ffff_fffen;

const SERVER_SIG_CONTEXT = Buffer.from('socket-tunnel-v2.1/server-sig:', 'utf8');
const CLIENT_SIG_CONTEXT = Buffer.from('socket-tunnel-v2.1/client-sig:', 'utf8');

export class ProtocolError extends Error {
  constructor(message, code = 'ERR_TUNNEL_PROTOCOL') {
    super(message);
    this.name = 'ProtocolError';
    this.code = code;
  }
}

// --- Sliding-Window O(1) Anti-Replay Filter for CLIENT_HELLO Salts ---

export class ReplayCache {
  constructor(options = {}) {
    this.windowMs = Math.max(5_000, Number(options.windowMs) || DEFAULT_MAX_CLOCK_SKEW_SEC * 2000);
    this.maxEntriesPerGen = Math.max(1_024, Number(options.maxEntriesPerGen) || 100_000);
    this._current = new Set();
    this._previous = new Set();
    this._rotatedAt = Date.now();
  }

  _maybeRotate(now) {
    const elapsed = now - this._rotatedAt;
    if (elapsed >= this.windowMs) {
      if (elapsed >= this.windowMs * 2) {
        this._previous.clear();
        this._current.clear();
      } else {
        this._previous = this._current;
        this._current = new Set();
      }
      this._rotatedAt = now;
    } else if (this._current.size >= this.maxEntriesPerGen) {
      this._previous = this._current;
      this._current = new Set();
      this._rotatedAt = now;
    }
  }

  checkAndRecord(saltBuf, now = Date.now()) {
    this._maybeRotate(now);
    const key = saltBuf.toString('base64');
    if (this._current.has(key) || this._previous.has(key)) {
      return false;
    }
    this._current.add(key);
    return true;
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

// --- Ephemeral ECDH (X25519 Raw 32B Wire Format & Strict DER Imports) ---

export function generateEphemeralKeys() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const publicKeyDer = publicKey.export({ type: 'spki', format: 'der' });
  const publicKeyRaw = Buffer.from(publicKeyDer.subarray(X25519_SPKI_PREFIX.length));
  return { publicKey, privateKey, publicKeyDer, publicKeyRaw };
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

export function importX25519RawPublicKey(raw32) {
  if (!Buffer.isBuffer(raw32) || raw32.length !== X25519_RAW_SIZE) {
    throw new ProtocolError('Invalid raw X25519 key length', 'ERR_HANDSHAKE_KEY');
  }
  const der = Buffer.concat([X25519_SPKI_PREFIX, raw32], X25519_SPKI_SIZE);
  return importX25519PublicKey(der);
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

// --- Transcript, Server-Key-Bound Handshake AEAD & Directional CipherState ---

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

function aes256GcmEncrypt(key, iv12, aad, plaintext) {
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv12);
  if (aad) cipher.setAAD(aad);
  const enc1 = cipher.update(plaintext);
  const enc2 = cipher.final();
  const tag = cipher.getAuthTag();
  return Buffer.concat([enc1, enc2, tag], enc1.length + enc2.length + AEAD_TAG_SIZE);
}

function aes256GcmDecrypt(key, iv12, aad, payload) {
  if (payload.length < AEAD_TAG_SIZE) {
    throw new ProtocolError('AEAD frame too short', 'ERR_DECRYPT_FAILED');
  }
  const ciphertext = payload.subarray(0, payload.length - AEAD_TAG_SIZE);
  const tag = payload.subarray(payload.length - AEAD_TAG_SIZE);
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, iv12);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  try {
    const dec1 = decipher.update(ciphertext);
    const dec2 = decipher.final();
    return dec2.length === 0 ? dec1 : Buffer.concat([dec1, dec2], dec1.length + dec2.length);
  } catch {
    throw new ProtocolError('AEAD authentication failed', 'ERR_DECRYPT_FAILED');
  }
}

/**
 * Encodes a v2.1 CLIENT_HELLO bound to 1..MAX_KEY_SLOTS server public keys (or UNPINNED_HANDSHAKE_KEY).
 * Wire layout: [cSalt:16] [encSlot_0:51] ... [encSlot_{K-1}:51] [encBody: 40 + padLen + 16]
 * Zero static seeds, zero plaintext headers, full AEAD authentication before server buffers or responds.
 */
export function encodeClientHelloFrame({
  serverSecrets,
  clientEphRaw,
  timestampSec = BigInt(Math.floor(Date.now() / 1000)),
  pad = crypto.randomBytes(crypto.randomInt(16, MAX_HANDSHAKE_PAD - 16)),
  cSalt = crypto.randomBytes(HANDSHAKE_NONCE_SIZE),
  shSeed = crypto.randomBytes(SH_SEED_SIZE),
}) {
  if (!Array.isArray(serverSecrets) || serverSecrets.length < 1 || serverSecrets.length > MAX_KEY_SLOTS) {
    throw new ProtocolError(`CLIENT_HELLO requires 1..${MAX_KEY_SLOTS} candidate server keys`, 'ERR_INVALID_KEY');
  }
  if (!Buffer.isBuffer(clientEphRaw) || clientEphRaw.length !== X25519_RAW_SIZE) {
    throw new ProtocolError('Invalid client X25519 raw key size', 'ERR_HANDSHAKE_KEY');
  }
  if (pad.length > MAX_HANDSHAKE_PAD) {
    throw new ProtocolError('CLIENT_HELLO padding exceeds limit', 'ERR_HANDSHAKE_FORMAT');
  }

  const timestampBuf = Buffer.allocUnsafe(CH_TIMESTAMP_SIZE);
  timestampBuf.writeBigUInt64BE(BigInt(timestampSec), 0);

  const plainBody = Buffer.concat([timestampBuf, clientEphRaw, pad], CH_TIMESTAMP_SIZE + X25519_RAW_SIZE + pad.length);
  const bodyKey = hkdfExpand(shSeed, cSalt, 'socket-tunnel-v2.1/ch-body/key', 32);
  const bodyIv = hkdfExpand(shSeed, cSalt, 'socket-tunnel-v2.1/ch-body/iv', NONCE_SIZE);
  const encBody = aes256GcmEncrypt(bodyKey, bodyIv, cSalt, plainBody);

  const slotCount = serverSecrets.length;
  const slotPlain = Buffer.allocUnsafe(CH_SLOT_PLAIN_SIZE);
  slotPlain[0] = slotCount;
  slotPlain.writeUInt16BE(encBody.length, 1);
  shSeed.copy(slotPlain, 3);

  const encSlots = serverSecrets.map((secretBuf) => {
    const slotKey = hkdfExpand(secretBuf, cSalt, 'socket-tunnel-v2.1/ch-slot/key', 32);
    const slotIv = hkdfExpand(secretBuf, cSalt, 'socket-tunnel-v2.1/ch-slot/iv', NONCE_SIZE);
    return aes256GcmEncrypt(slotKey, slotIv, cSalt, slotPlain);
  });

  const totalLen = HANDSHAKE_NONCE_SIZE + slotCount * CH_SLOT_WIRE_SIZE + encBody.length;
  const wireFrame = Buffer.concat([cSalt, ...encSlots, encBody], totalLen);
  return { wireFrame, cSalt, shSeed, timestampBuf, timestampSec: BigInt(timestampSec), pad };
}

function tryDecryptClientHelloSlot(serverSecrets, cSalt, slotIdx, encSlot) {
  for (const secretBuf of serverSecrets) {
    const slotKey = hkdfExpand(secretBuf, cSalt, 'socket-tunnel-v2.1/ch-slot/key', 32);
    const slotIv = hkdfExpand(secretBuf, cSalt, 'socket-tunnel-v2.1/ch-slot/iv', NONCE_SIZE);
    try {
      const plain = aes256GcmDecrypt(slotKey, slotIv, cSalt, encSlot);
      if (plain.length !== CH_SLOT_PLAIN_SIZE) continue;
      const slotCount = plain[0];
      const bodyEncLen = plain.readUInt16BE(1);
      if (
        slotCount < 1 ||
        slotCount > MAX_KEY_SLOTS ||
        slotIdx >= slotCount ||
        bodyEncLen < CH_BODY_MIN_ENC_SIZE ||
        bodyEncLen > CH_BODY_MAX_ENC_SIZE
      ) {
        continue;
      }
      const shSeed = Buffer.from(plain.subarray(3, 35));
      return { slotCount, bodyEncLen, shSeed };
    } catch {
      // Slot encrypted for another pinned key or invalid probe
    }
  }
  return null;
}

function decryptClientHelloBody(shSeed, cSalt, encBody) {
  const bodyKey = hkdfExpand(shSeed, cSalt, 'socket-tunnel-v2.1/ch-body/key', 32);
  const bodyIv = hkdfExpand(shSeed, cSalt, 'socket-tunnel-v2.1/ch-body/iv', NONCE_SIZE);
  const plainBody = aes256GcmDecrypt(bodyKey, bodyIv, cSalt, encBody);
  if (plainBody.length < CLIENT_HELLO_SIZE || plainBody.length > CLIENT_HELLO_MAX_SIZE) {
    throw new ProtocolError('Invalid CLIENT_HELLO body length', 'ERR_HANDSHAKE_FORMAT');
  }
  const timestampBuf = Buffer.from(plainBody.subarray(0, CH_TIMESTAMP_SIZE));
  const timestampSec = timestampBuf.readBigUInt64BE(0);
  const cEphRaw = Buffer.from(plainBody.subarray(CH_TIMESTAMP_SIZE, CH_TIMESTAMP_SIZE + X25519_RAW_SIZE));
  const pad = Buffer.from(plainBody.subarray(CH_TIMESTAMP_SIZE + X25519_RAW_SIZE));
  return { timestampBuf, timestampSec, cEphRaw, pad };
}

/**
 * Encodes a v2.1 SERVER_HELLO using shSeed established inside the authenticated CLIENT_HELLO slot.
 * Wire layout: [sSalt:16] [encLenHdr:18 (2B + 16B GCM)] [encBody: body.length + 16B GCM]
 */
export function encodeServerHelloFrame(shSeed, body, sSalt = crypto.randomBytes(HANDSHAKE_NONCE_SIZE)) {
  const bodyKey = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-body/key', 32);
  const bodyIv = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-body/iv', NONCE_SIZE);
  const encBody = aes256GcmEncrypt(bodyKey, bodyIv, sSalt, body);

  const lenPlain = Buffer.allocUnsafe(2);
  lenPlain.writeUInt16BE(encBody.length, 0);
  const hdrKey = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-hdr/key', 32);
  const hdrIv = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-hdr/iv', NONCE_SIZE);
  const encHdr = aes256GcmEncrypt(hdrKey, hdrIv, sSalt, lenPlain);

  return Buffer.concat([sSalt, encHdr, encBody], HANDSHAKE_NONCE_SIZE + SH_HDR_WIRE_SIZE + encBody.length);
}

function decryptServerHelloHeader(shSeed, sSalt, encHdr18) {
  const hdrKey = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-hdr/key', 32);
  const hdrIv = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-hdr/iv', NONCE_SIZE);
  const plain = aes256GcmDecrypt(hdrKey, hdrIv, sSalt, encHdr18);
  if (plain.length !== 2) {
    throw new ProtocolError('Malformed SERVER_HELLO header', 'ERR_HANDSHAKE_FORMAT');
  }
  return plain.readUInt16BE(0);
}

function decryptServerHelloBody(shSeed, sSalt, encBody) {
  const bodyKey = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-body/key', 32);
  const bodyIv = hkdfExpand(shSeed, sSalt, 'socket-tunnel-v2.1/sh-body/iv', NONCE_SIZE);
  return aes256GcmDecrypt(bodyKey, bodyIv, sSalt, encBody);
}

export function deriveCipherPair(sharedSecret, transcriptHash, phase) {
  const c2sKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/c2s/key`, 32);
  const c2sIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/c2s/iv`, NONCE_SIZE);
  const c2sHdrKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/c2s/hdr-key`, 32);
  const c2sHdrIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/c2s/hdr-iv`, 16);

  const s2cKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/s2c/key`, 32);
  const s2cIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/s2c/iv`, NONCE_SIZE);
  const s2cHdrKey = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/s2c/hdr-key`, 32);
  const s2cHdrIv = hkdfExpand(sharedSecret, transcriptHash, `socket-tunnel-v2.1/${phase}/s2c/hdr-iv`, 16);

  return {
    c2s: new CipherState(c2sKey, c2sIv, c2sHdrKey, c2sHdrIv),
    s2c: new CipherState(s2cKey, s2cIv, s2cHdrKey, s2cHdrIv),
  };
}

export class CipherState {
  constructor(key, ivSalt, hdrKey = null, hdrIv = null) {
    this._key = key;
    this._ivSalt = ivSalt;
    this._hdrKey = hdrKey || hkdfExpand(key, ivSalt, 'socket-tunnel-v2.1/default/hdr-key', 32);
    this._hdrIv = hdrIv || hkdfExpand(key, ivSalt, 'socket-tunnel-v2.1/default/hdr-iv', 16);
    this._hdrCipher = crypto.createCipheriv('aes-256-ctr', this._hdrKey, this._hdrIv);
    this._seq = 0n;
    this.epoch = 0;
  }

  ratchet() {
    const nextKey = hkdfExpand(this._key, this._ivSalt, 'socket-tunnel-v2.1/rekey/key', 32);
    const nextIv = hkdfExpand(this._key, this._ivSalt, 'socket-tunnel-v2.1/rekey/iv', NONCE_SIZE);
    const nextHdrKey = hkdfExpand(this._hdrKey, this._ivSalt, 'socket-tunnel-v2.1/rekey/hdr-key', 32);
    const nextHdrIv = hkdfExpand(this._hdrKey, this._ivSalt, 'socket-tunnel-v2.1/rekey/hdr-iv', 16);

    this._key.fill(0);
    this._ivSalt.fill(0);
    this._hdrKey.fill(0);
    this._hdrIv.fill(0);

    this._key = nextKey;
    this._ivSalt = nextIv;
    this._hdrKey = nextHdrKey;
    this._hdrIv = nextHdrIv;
    this._hdrCipher = crypto.createCipheriv('aes-256-ctr', this._hdrKey, this._hdrIv);
    this._seq = 0n;
    this.epoch++;
  }

  _nextNonceAndAad(frameType, payloadLength) {
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

    // Bind full 5-byte frame header ([frameType:1][payloadLength:4]) + [seq:8] into GCM AAD
    const aad = Buffer.allocUnsafe(13);
    aad[0] = frameType;
    aad.writeUInt32BE(payloadLength >>> 0, 1);
    seqBuf.copy(aad, 5);

    return { nonce, aad };
  }

  encryptHeader(frameType, payloadLength) {
    const plainHdr = Buffer.allocUnsafe(FRAME_HEADER_SIZE);
    plainHdr[0] = frameType;
    plainHdr.writeUInt32BE(payloadLength >>> 0, 1);
    return this._hdrCipher.update(plainHdr);
  }

  decryptHeader(encHdr5) {
    const plainHdr = this._hdrCipher.update(encHdr5);
    return {
      type: plainHdr[0],
      len: plainHdr.readUInt32BE(1),
    };
  }

  encrypt(frameType, plaintext) {
    const payloadLength = plaintext.length + AEAD_TAG_SIZE;
    const { nonce, aad } = this._nextNonceAndAad(frameType, payloadLength);
    const cipher = crypto.createCipheriv('aes-256-gcm', this._key, nonce);
    cipher.setAAD(aad);
    const enc1 = cipher.update(plaintext);
    const enc2 = cipher.final();
    const tag = cipher.getAuthTag();
    return Buffer.concat([enc1, enc2, tag], payloadLength);
  }

  encryptFrame(frameType, plaintext) {
    const payload = this.encrypt(frameType, plaintext);
    const encHdr = this.encryptHeader(frameType, payload.length);
    return Buffer.concat([encHdr, payload], FRAME_HEADER_SIZE + payload.length);
  }

  decrypt(frameType, payload) {
    if (payload.length < AEAD_TAG_SIZE) {
      throw new ProtocolError('Encrypted frame too short', 'ERR_DECRYPT_FAILED');
    }
    const { nonce, aad } = this._nextNonceAndAad(frameType, payload.length);
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
    this._hdrKey.fill(0);
    this._hdrIv.fill(0);
  }
}

// --- Wire Framing & Bounded AEAD-Authenticated FrameParser ---

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
    case MSG_DATA_PAD: return MAX_PADDED_DATA_FRAME_SIZE;
    case MSG_EOF: return AEAD_TAG_SIZE;
    case MSG_PING:
    case MSG_PONG: return MAX_CONTROL_FRAME_SIZE;
    case MSG_REKEY: return REKEY_FRAME_SIZE;
    default: return -1;
  }
}

export class FrameParser {
  constructor(onFrame, getMaxPayloadSize = defaultMaxFrameSize, initialMode = 'plain') {
    this._chunks = [];
    this._totalLength = 0;
    this._onFrame = onFrame;
    this._getMaxPayloadSize = getMaxPayloadSize;
    this._stopped = false;

    // Modes: 'plain' | 'client-hello' | 'server-hello' | 'cipher'
    this._mode = initialMode;
    this._cipher = null;
    this._pendingFrame = null;

    this._chSecrets = null;
    this._chCheckedSlots = 0;
    this._chMatched = null;

    this._shSeed = null;
    this._shPending = null;
  }

  setClientHelloSecrets(secretBuffers) {
    this._mode = 'client-hello';
    this._chSecrets = secretBuffers;
    this._chCheckedSlots = 0;
    this._chMatched = null;
  }

  setServerHelloSeed(shSeed) {
    this._mode = 'server-hello';
    this._shSeed = shSeed;
    this._shPending = null;
  }

  setCipher(cipherState) {
    this._mode = 'cipher';
    this._cipher = cipherState;
    this._chSecrets = null;
    this._chMatched = null;
    if (this._shSeed) {
      this._shSeed.fill(0);
      this._shSeed = null;
    }
    this._shPending = null;
  }

  stop() {
    this._stopped = true;
    this._chunks.length = 0;
    this._totalLength = 0;
    this._pendingFrame = null;
    this._cipher = null;
    this._chSecrets = null;
    this._chMatched = null;
    if (this._shSeed) {
      this._shSeed.fill(0);
      this._shSeed = null;
    }
    this._shPending = null;
  }

  _peekBytes(count) {
    if (this._chunks[0].length >= count) {
      return this._chunks[0].subarray(0, count);
    }
    const out = Buffer.allocUnsafe(count);
    let copied = 0;
    for (const chunk of this._chunks) {
      const n = Math.min(chunk.length, count - copied);
      chunk.copy(out, copied, 0, n);
      copied += n;
      if (copied === count) break;
    }
    return out;
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

    while (!this._stopped) {
      if (this._mode === 'client-hello') {
        while (!this._chMatched) {
          const neededForSlot = HANDSHAKE_NONCE_SIZE + (this._chCheckedSlots + 1) * CH_SLOT_WIRE_SIZE;
          if (this._totalLength < neededForSlot) {
            return;
          }
          const peeked = this._peekBytes(neededForSlot);
          const cSalt = peeked.subarray(0, HANDSHAKE_NONCE_SIZE);
          const slotIdx = this._chCheckedSlots;
          const slotOff = HANDSHAKE_NONCE_SIZE + slotIdx * CH_SLOT_WIRE_SIZE;
          const encSlot = peeked.subarray(slotOff, slotOff + CH_SLOT_WIRE_SIZE);

          const matched = tryDecryptClientHelloSlot(this._chSecrets, cSalt, slotIdx, encSlot);
          if (matched) {
            const prefixLen = HANDSHAKE_NONCE_SIZE + matched.slotCount * CH_SLOT_WIRE_SIZE;
            this._chMatched = {
              cSalt: Buffer.from(cSalt),
              shSeed: matched.shSeed,
              prefixLen,
              bodyEncLen: matched.bodyEncLen,
              totalWireLen: prefixLen + matched.bodyEncLen,
            };
            break;
          }

          this._chCheckedSlots += 1;
          if (this._chCheckedSlots >= MAX_KEY_SLOTS) {
            this.stop();
            throw new ProtocolError('Unauthenticated CLIENT_HELLO', 'ERR_HANDSHAKE_AUTH');
          }
        }

        const m = this._chMatched;
        if (this._totalLength < m.totalWireLen) {
          return;
        }

        this._consumeBytes(m.prefixLen, null);
        const encBody = Buffer.allocUnsafe(m.bodyEncLen);
        this._consumeBytes(m.bodyEncLen, encBody);
        this._chMatched = null;
        this._chCheckedSlots = 0;

        const parsed = decryptClientHelloBody(m.shSeed, m.cSalt, encBody);
        this._onFrame(
          MSG_CLIENT_HELLO,
          {
            cSalt: m.cSalt,
            shSeed: m.shSeed,
            timestampBuf: parsed.timestampBuf,
            timestampSec: parsed.timestampSec,
            cEphRaw: parsed.cEphRaw,
            pad: parsed.pad,
          },
          m.cSalt,
        );
        continue;
      }

      if (this._mode === 'server-hello') {
        if (!this._shPending) {
          const neededHdr = HANDSHAKE_NONCE_SIZE + SH_HDR_WIRE_SIZE;
          if (this._totalLength < neededHdr) {
            return;
          }
          const sSalt = Buffer.allocUnsafe(HANDSHAKE_NONCE_SIZE);
          const encHdr = Buffer.allocUnsafe(SH_HDR_WIRE_SIZE);
          this._consumeBytes(HANDSHAKE_NONCE_SIZE, sSalt);
          this._consumeBytes(SH_HDR_WIRE_SIZE, encHdr);

          const bodyEncLen = decryptServerHelloHeader(this._shSeed, sSalt, encHdr);
          if (bodyEncLen < SH_BODY_MIN_ENC_SIZE || bodyEncLen > SH_BODY_MAX_ENC_SIZE) {
            this.stop();
            throw new ProtocolError('Invalid SERVER_HELLO body length', 'ERR_HANDSHAKE_FORMAT');
          }
          this._shPending = { sSalt, bodyEncLen };
        }

        if (this._totalLength < this._shPending.bodyEncLen) {
          return;
        }

        const { sSalt, bodyEncLen } = this._shPending;
        this._shPending = null;
        const encBody = Buffer.allocUnsafe(bodyEncLen);
        this._consumeBytes(bodyEncLen, encBody);

        const decBody = decryptServerHelloBody(this._shSeed, sSalt, encBody);
        this._onFrame(MSG_SERVER_HELLO, decBody, sSalt);
        continue;
      }

      if (!this._pendingFrame) {
        if (this._totalLength < FRAME_HEADER_SIZE) {
          return;
        }

        let type;
        let len;
        if (this._mode === 'cipher') {
          const encHdr = Buffer.allocUnsafe(FRAME_HEADER_SIZE);
          this._consumeBytes(FRAME_HEADER_SIZE, encHdr);
          ({ type, len } = this._cipher.decryptHeader(encHdr));
        } else {
          const plainHdr = Buffer.allocUnsafe(FRAME_HEADER_SIZE);
          this._consumeBytes(FRAME_HEADER_SIZE, plainHdr);
          type = plainHdr[0];
          len = plainHdr.readUInt32BE(1);
        }

        const maxLen = this._getMaxPayloadSize(type);
        if (maxLen < 0) {
          this.stop();
          throw new ProtocolError(`Unknown frame type: 0x${type.toString(16)}`, 'ERR_UNKNOWN_FRAME');
        }
        if (len > maxLen) {
          this.stop();
          throw new ProtocolError(`Frame length ${len} exceeds limit ${maxLen} for type 0x${type.toString(16)}`, 'ERR_FRAME_TOO_LARGE');
        }

        this._pendingFrame = { type, len };
      }

      const pending = this._pendingFrame;
      if (this._totalLength < pending.len) {
        return;
      }

      const rawBody = Buffer.allocUnsafe(pending.len);
      if (pending.len > 0) {
        this._consumeBytes(pending.len, rawBody);
      }
      this._pendingFrame = null;

      this._onFrame(pending.type, rawBody, null);
    }
  }
}
