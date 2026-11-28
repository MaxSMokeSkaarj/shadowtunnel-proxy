import crypto from 'node:crypto';
import { Duplex } from 'node:stream';
import { EventEmitter } from 'node:events';
import { ProtocolError } from './crypto.mjs';

// Mux frame types
export const MUX_OPEN = 0x01;
export const MUX_OPEN_OK = 0x02;
export const MUX_OPEN_ERR = 0x03;
export const MUX_DATA = 0x04;
export const MUX_WINDOW = 0x05;
export const MUX_EOF = 0x06;
export const MUX_RST = 0x07;
export const MUX_DGRAM = 0x08;
export const MUX_GOAWAY = 0x09;

export const MUX_HEADER_SIZE = 9; // [type:1][streamId:4 BE][length:4 BE]
// 14..16 KiB jittered max data chunk prevents fixed 16456B beacons & never splits across 32 KiB WS frames
export const MIN_MUX_CHUNK_JITTER = 14336;
export const MAX_MUX_CHUNK = 16384;
export const MAX_MUX_META = 4096;
const MAX_MUX_META_WIRE = MAX_MUX_META + 256;
const META_BUCKET_BYTES = 128; // Quantize MUX_OPEN metadata into 128B buckets so host lengths never leak
export const INITIAL_STREAM_WINDOW = 262144; // 256 KiB per stream
const WINDOW_UPDATE_THRESHOLD = 131072; // 128 KiB

function packPaddedMeta(rawBuf, bucketAlign = false) {
  const realLen = rawBuf.length;
  let totalLen;
  if (bucketAlign) {
    totalLen = Math.max(META_BUCKET_BYTES, Math.ceil((2 + realLen + 8) / META_BUCKET_BYTES) * META_BUCKET_BYTES);
  } else {
    totalLen = 2 + realLen + crypto.randomInt(8, 49);
  }
  const out = Buffer.allocUnsafe(totalLen);
  out.writeUInt16BE(realLen, 0);
  if (realLen > 0) rawBuf.copy(out, 2);
  crypto.randomFillSync(out, 2 + realLen, totalLen - (2 + realLen));
  return out;
}

function unpackPaddedMeta(wireBuf) {
  if (wireBuf.length < 2) {
    throw new ProtocolError('Malformed padded mux metadata', 'ERR_MUX_PROTOCOL');
  }
  const realLen = wireBuf.readUInt16BE(0);
  if (2 + realLen > wireBuf.length) {
    throw new ProtocolError('Truncated padded mux metadata', 'ERR_MUX_PROTOCOL');
  }
  return wireBuf.subarray(2, 2 + realLen);
}

export function encodeMuxFrame(type, streamId, payload = Buffer.alloc(0)) {
  const frame = Buffer.allocUnsafe(MUX_HEADER_SIZE + payload.length);
  frame[0] = type;
  frame.writeUInt32BE(streamId >>> 0, 1);
  frame.writeUInt32BE(payload.length >>> 0, 5);
  if (payload.length > 0) {
    payload.copy(frame, MUX_HEADER_SIZE);
  }
  return frame;
}

function maxMuxPayloadSize(type) {
  switch (type) {
    case MUX_OPEN:
    case MUX_OPEN_OK:
    case MUX_OPEN_ERR:
    case MUX_RST:
      return MAX_MUX_META_WIRE;
    case MUX_DATA:
    case MUX_DGRAM:
      return 65536; // allow up to 64 KiB datagrams/IP packets
    case MUX_WINDOW:
    case MUX_EOF:
    case MUX_GOAWAY:
      return 64; // randomized control-frame padding (eliminates fixed 72B / 76B beacons)
    default:
      return -1;
  }
}

class MuxFrameParser {
  constructor(onFrame) {
    this._chunks = [];
    this._totalLength = 0;
    this._onFrame = onFrame;
    this._stopped = false;
    this._headerScratch = Buffer.allocUnsafe(MUX_HEADER_SIZE);
  }

  stop() {
    this._stopped = true;
    this._chunks.length = 0;
    this._totalLength = 0;
  }

  _peekHeader() {
    const first = this._chunks[0];
    if (first.length >= MUX_HEADER_SIZE) return first;
    let copied = 0;
    for (const chunk of this._chunks) {
      const n = Math.min(chunk.length, MUX_HEADER_SIZE - copied);
      chunk.copy(this._headerScratch, copied, 0, n);
      copied += n;
      if (copied === MUX_HEADER_SIZE) break;
    }
    return this._headerScratch;
  }

  _consumeBytes(count, target = null) {
    let remaining = count;
    let offset = 0;
    while (remaining > 0) {
      const head = this._chunks[0];
      if (head.length <= remaining) {
        if (target) head.copy(target, offset);
        offset += head.length;
        remaining -= head.length;
        this._chunks.shift();
      } else {
        if (target) head.copy(target, offset, 0, remaining);
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

    while (!this._stopped && this._totalLength >= MUX_HEADER_SIZE) {
      const hdr = this._peekHeader();
      const type = hdr[0];
      const streamId = hdr.readUInt32BE(1);
      const len = hdr.readUInt32BE(5);
      const maxLen = maxMuxPayloadSize(type);

      if (maxLen < 0) {
        this.stop();
        throw new ProtocolError(`Unknown mux frame type: 0x${type.toString(16)}`, 'ERR_MUX_PROTOCOL');
      }
      if (len > maxLen) {
        this.stop();
        throw new ProtocolError(`Mux frame length ${len} exceeds max ${maxLen}`, 'ERR_MUX_FRAME_TOO_LARGE');
      }
      if (this._totalLength < MUX_HEADER_SIZE + len) {
        return;
      }

      this._consumeBytes(MUX_HEADER_SIZE, null);
      const payload = Buffer.allocUnsafe(len);
      if (len > 0) {
        this._consumeBytes(len, payload);
      }

      this._onFrame(type, streamId, payload);
    }
  }
}

export class MuxStream extends Duplex {
  constructor(session, streamId, metadata = Buffer.alloc(0)) {
    super({ allowHalfOpen: true });
    this.session = session;
    this.id = streamId;
    this.metadata = metadata;
    this.responseMetadata = null;

    this._sendWindow = INITIAL_STREAM_WINDOW;
    this._recvInFlight = 0;
    this._unackedBytes = 0;
    this._heldBytes = 0;

    this._pendingPump = null;
    this._localEofSent = false;
    this._remoteEofReceived = false;
    this._rstReceived = false;
    this._unregistered = false;
  }

  _onData(payload) {
    if (this.destroyed) return;
    if (this._remoteEofReceived) {
      this.session._writeFrame(MUX_RST, this.id, Buffer.from('Data after EOF'));
      this._rstReceived = true;
      this.destroy(new ProtocolError('Received MUX_DATA after MUX_EOF', 'ERR_MUX_DATA_AFTER_EOF'));
      return;
    }

    this._recvInFlight += payload.length;
    if (this._recvInFlight > INITIAL_STREAM_WINDOW * 2) {
      this.session._writeFrame(MUX_RST, this.id, Buffer.from('Flow control window exceeded'));
      this._rstReceived = true;
      this.destroy(new ProtocolError('Peer exceeded mux stream flow-control window', 'ERR_MUX_FLOW_CONTROL'));
      return;
    }

    const canPushMore = this.push(payload);
    if (canPushMore) {
      this._unackedBytes += payload.length;
      this._flushWindowUpdate();
    } else {
      this._heldBytes += payload.length;
    }
  }

  _onWindow(delta) {
    if (this.destroyed || delta === 0) return;
    this._sendWindow += delta;
    this._kickPump();
  }

  _onEof() {
    if (this.destroyed || this._remoteEofReceived) return;
    this._remoteEofReceived = true;
    this.push(null);
    this._maybeCompleteCleanly();
  }

  _onRst(reasonText) {
    if (this.destroyed) return;
    this._rstReceived = true;
    const err = new ProtocolError(reasonText || 'Mux stream reset by peer', 'ERR_MUX_STREAM_RESET');
    this.destroy(err);
  }

  _onCarrierDrain() {
    this._kickPump();
  }

  _kickPump() {
    if (this._pendingPump) {
      const fn = this._pendingPump;
      this._pendingPump = null;
      fn();
    }
  }

  _flushWindowUpdate() {
    if (this.destroyed || this._remoteEofReceived || this.session.isClosed) return;
    if (this._unackedBytes >= WINDOW_UPDATE_THRESHOLD) {
      const delta = this._unackedBytes;
      this._unackedBytes = 0;
      this._recvInFlight -= delta;
      const padLen = crypto.randomInt(8, 45);
      const winBuf = Buffer.allocUnsafe(4 + padLen);
      winBuf.writeUInt32BE(delta >>> 0, 0);
      crypto.randomFillSync(winBuf, 4, padLen);
      this.session._writeFrame(MUX_WINDOW, this.id, winBuf);
    }
  }

  _read() {
    if (this._heldBytes > 0) {
      this._unackedBytes += this._heldBytes;
      this._heldBytes = 0;
      this._flushWindowUpdate();
    }
  }

  _write(chunk, encoding, callback) {
    if (this.destroyed || this.session.isClosed) {
      callback(new ProtocolError('Mux stream is closed', 'ERR_MUX_CLOSED'));
      return;
    }

    const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, encoding);
    let offset = 0;

    const pump = () => {
      if (this.destroyed || this.session.isClosed) {
        callback(new ProtocolError('Mux stream closed during write', 'ERR_MUX_CLOSED'));
        return;
      }

      while (offset < buf.length && this._sendWindow > 0 && !this.session._carrierBackpressured) {
        const remaining = buf.length - offset;
        const chunkCap = remaining > MIN_MUX_CHUNK_JITTER
          ? crypto.randomInt(MIN_MUX_CHUNK_JITTER, MAX_MUX_CHUNK + 1)
          : MAX_MUX_CHUNK;
        const len = Math.min(remaining, chunkCap, this._sendWindow);
        const slice = buf.subarray(offset, offset + len);
        this._sendWindow -= len;
        offset += len;
        this.session._writeFrame(MUX_DATA, this.id, slice);
      }

      if (offset >= buf.length) {
        if (!this.session._carrierBackpressured) {
          callback();
        } else {
          this._pendingPump = () => {
            if (this.destroyed || this.session.isClosed) {
              callback(new ProtocolError('Mux stream closed while draining', 'ERR_MUX_CLOSED'));
            } else {
              callback();
            }
          };
        }
      } else {
        this._pendingPump = pump;
      }
    };

    pump();
  }

  _final(callback) {
    if (this.destroyed || this.session.isClosed) {
      callback();
      return;
    }
    this._localEofSent = true;
    this.session._writeFrame(MUX_EOF, this.id, crypto.randomBytes(crypto.randomInt(8, 49)));
    this._maybeCompleteCleanly();
    callback();
  }

  _maybeCompleteCleanly() {
    if (this._localEofSent && this._remoteEofReceived && !this._unregistered) {
      this._unregistered = true;
      this.session._removeStream(this.id);
    }
  }

  _destroy(err, callback) {
    this._pendingPump = null;
    const cleanlyDone = this._localEofSent && this._remoteEofReceived;
    if (!cleanlyDone && !this._rstReceived && !this.session.isClosed) {
      const msg = err?.message ? Buffer.from(String(err.message).slice(0, 256), 'utf8') : Buffer.alloc(0);
      try {
        this.session._writeFrame(MUX_RST, this.id, packPaddedMeta(msg, false));
      } catch {
        // Ignore carrier write errors during teardown
      }
    }
    if (!this._unregistered) {
      this._unregistered = true;
      this.session._removeStream(this.id);
    }
    callback(err);
  }
}

export class MuxSession extends EventEmitter {
  constructor(carrier, options = {}) {
    super();
    const {
      initiator = true,
      onStream = null,
      onDatagram = null,
      openTimeoutMs = 15_000,
    } = options;

    this.carrier = carrier;
    this.initiator = Boolean(initiator);
    this.isClosed = false;
    this.goawayReceived = false;
    this._openTimeoutMs = openTimeoutMs;
    this._onStreamCallback = onStream;

    this._nextStreamId = this.initiator ? 1 : 2;
    this._streams = new Map(); // streamId -> MuxStream
    this._pendingOpens = new Map(); // streamId -> { stream, resolve, reject, timer }
    this._carrierBackpressured = false;

    if (typeof onDatagram === 'function') {
      this.on('datagram', onDatagram);
    }

    this._parser = new MuxFrameParser((type, streamId, payload) => {
      this._handleFrame(type, streamId, payload);
    });

    this._bindCarrier();
  }

  get activeStreamCount() {
    return this._streams.size + this._pendingOpens.size;
  }

  get canOpenStreams() {
    return !this.isClosed && !this.goawayReceived && !this.carrier.destroyed && this.carrier.writable;
  }

  _bindCarrier() {
    this._onData = (chunk) => {
      try {
        this._parser.push(chunk);
      } catch (err) {
        this._abortSession(err);
      }
    };

    this._onDrain = () => {
      this._carrierBackpressured = false;
      for (const stream of this._streams.values()) {
        stream._onCarrierDrain();
      }
    };

    this._onEnd = () => {
      this.goawayReceived = true;
      if (!this.carrier.destroyed && !this.carrier.writableEnded) {
        this.carrier.end();
      }
      this._handleCarrierClosed(null);
    };

    this._onError = (err) => {
      this._handleCarrierClosed(err);
    };

    this._onClose = () => {
      this._handleCarrierClosed(null);
    };

    this.carrier.on('data', this._onData);
    this.carrier.on('drain', this._onDrain);
    this.carrier.on('end', this._onEnd);
    this.carrier.on('error', this._onError);
    this.carrier.on('close', this._onClose);
    if (typeof this.carrier.resume === 'function') {
      this.carrier.resume();
    }
  }

  _writeFrame(type, streamId, payload = Buffer.alloc(0)) {
    if (this.isClosed || this.carrier.destroyed || this.carrier.writableEnded) return false;
    const ok = this.carrier.write(encodeMuxFrame(type, streamId, payload));
    if (!ok) {
      this._carrierBackpressured = true;
    }
    return ok;
  }

  _removeStream(streamId) {
    this._streams.delete(streamId);
  }

  openStream(metadata = Buffer.alloc(0), timeoutMs = this._openTimeoutMs) {
    if (!this.canOpenStreams) {
      return Promise.reject(new ProtocolError('MuxSession is closed or draining', 'ERR_MUX_CLOSED'));
    }

    const metaBuf = Buffer.isBuffer(metadata)
      ? metadata
      : Buffer.from(typeof metadata === 'string' ? metadata : JSON.stringify(metadata), 'utf8');

    if (metaBuf.length > MAX_MUX_META) {
      return Promise.reject(new RangeError(`Stream metadata exceeds ${MAX_MUX_META} bytes`));
    }

    const streamId = this._nextStreamId;
    this._nextStreamId += 2;
    if (this._nextStreamId > 0x7fff_ffff) {
      // Trigger graceful session rollover before 31-bit wraparound
      this.goawayReceived = true;
    }

    const stream = new MuxStream(this, streamId, metaBuf);
    // Prevent unhandled stream error if reset arrives right during/after open
    stream.on('error', () => {});

    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this._pendingOpens.delete(streamId);
        this._streams.delete(streamId);
        try {
          this._writeFrame(MUX_RST, streamId, packPaddedMeta(Buffer.from('Open timeout'), false));
        } catch {}
        reject(new ProtocolError('Timed out waiting for MUX_OPEN_OK', 'ERR_MUX_OPEN_TIMEOUT'));
      }, timeoutMs);
      timer.unref?.();

      this._pendingOpens.set(streamId, { stream, resolve, reject, timer });
      this._streams.set(streamId, stream);
      this._writeFrame(MUX_OPEN, streamId, packPaddedMeta(metaBuf, true));
    });
  }

  sendDatagram(channelId, payload) {
    if (this.isClosed || this.carrier.destroyed) return false;
    const buf = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
    return this._writeFrame(MUX_DGRAM, channelId >>> 0, buf);
  }

  _handleFrame(type, streamId, payload) {
    if (this.isClosed) return;

    switch (type) {
      case MUX_OPEN: {
        if (streamId === 0 || this._streams.has(streamId)) {
          this._writeFrame(MUX_OPEN_ERR, streamId, packPaddedMeta(Buffer.from('Invalid or duplicate streamId'), false));
          return;
        }
        const metaPayload = unpackPaddedMeta(payload);
        const stream = new MuxStream(this, streamId, metaPayload);
        stream.on('error', () => {});
        this._streams.set(streamId, stream);

        let settled = false;
        const accept = (respMeta = Buffer.alloc(0)) => {
          if (settled || this.isClosed) return;
          settled = true;
          const respBuf = Buffer.isBuffer(respMeta) ? respMeta : Buffer.from(String(respMeta), 'utf8');
          this._writeFrame(MUX_OPEN_OK, streamId, packPaddedMeta(respBuf, false));
        };
        const reject = (reason = 'Stream rejected') => {
          if (settled || this.isClosed) return;
          settled = true;
          stream._rstReceived = true;
          this._streams.delete(streamId);
          const errText = typeof reason === 'string' ? reason : (reason?.message || 'Stream rejected');
          this._writeFrame(MUX_OPEN_ERR, streamId, packPaddedMeta(Buffer.from(errText.slice(0, 500), 'utf8'), false));
          stream.destroy();
        };

        if (typeof this._onStreamCallback === 'function') {
          Promise.resolve(this._onStreamCallback(stream, metaPayload, accept, reject)).catch((err) => {
            reject(err?.message || 'Unhandled stream handler error');
          });
        } else if (this.listenerCount('stream') > 0) {
          accept();
          this.emit('stream', stream, metaPayload);
        } else {
          reject('No stream handler registered');
        }
        break;
      }

      case MUX_OPEN_OK: {
        const pending = this._pendingOpens.get(streamId);
        if (!pending) return;
        clearTimeout(pending.timer);
        this._pendingOpens.delete(streamId);
        pending.stream.responseMetadata = unpackPaddedMeta(payload);
        pending.resolve(pending.stream);
        break;
      }

      case MUX_OPEN_ERR: {
        const pending = this._pendingOpens.get(streamId);
        if (!pending) return;
        clearTimeout(pending.timer);
        this._pendingOpens.delete(streamId);
        pending.stream._rstReceived = true;
        this._streams.delete(streamId);
        pending.stream.destroy();
        const reason = unpackPaddedMeta(payload).toString('utf8') || 'Remote peer rejected stream';
        pending.reject(new ProtocolError(reason, 'ERR_MUX_OPEN_REJECTED'));
        break;
      }

      case MUX_DATA: {
        const stream = this._streams.get(streamId);
        if (!stream) {
          this._writeFrame(MUX_RST, streamId, packPaddedMeta(Buffer.from('Unknown stream'), false));
          return;
        }
        if (payload.length > 0) {
          stream._onData(payload);
        }
        break;
      }

      case MUX_WINDOW: {
        if (payload.length < 4) {
          throw new ProtocolError('Invalid MUX_WINDOW payload size', 'ERR_MUX_PROTOCOL');
        }
        const stream = this._streams.get(streamId);
        if (stream) {
          stream._onWindow(payload.readUInt32BE(0));
        }
        break;
      }

      case MUX_EOF: {
        const stream = this._streams.get(streamId);
        if (stream) {
          stream._onEof();
        }
        break;
      }

      case MUX_RST: {
        const errText = unpackPaddedMeta(payload).toString('utf8');
        const pending = this._pendingOpens.get(streamId);
        if (pending) {
          clearTimeout(pending.timer);
          this._pendingOpens.delete(streamId);
          pending.stream._rstReceived = true;
          this._streams.delete(streamId);
          pending.stream.destroy();
          pending.reject(new ProtocolError(errText || 'Stream reset during open', 'ERR_MUX_STREAM_RESET'));
          return;
        }
        const stream = this._streams.get(streamId);
        if (stream) {
          stream._onRst(errText);
        }
        break;
      }

      case MUX_DGRAM: {
        this.emit('datagram', streamId, payload);
        break;
      }

      case MUX_GOAWAY: {
        this.goawayReceived = true;
        this.emit('goaway');
        break;
      }
    }
  }

  _abortSession(err) {
    this._handleCarrierClosed(err);
    if (!this.carrier.destroyed) {
      this.carrier.destroy(err);
    }
  }

  _handleCarrierClosed(err) {
    if (this.isClosed) return;
    this.isClosed = true;
    this._parser.stop();

    this.carrier.off?.('data', this._onData);
    this.carrier.off?.('drain', this._onDrain);
    this.carrier.off?.('end', this._onEnd);
    this.carrier.off?.('error', this._onError);
    this.carrier.off?.('close', this._onClose);

    const closeErr = err || new ProtocolError('Mux session closed', 'ERR_MUX_CLOSED');

    for (const [, pending] of this._pendingOpens) {
      clearTimeout(pending.timer);
      pending.stream._rstReceived = true;
      pending.stream.destroy();
      pending.reject(closeErr);
    }
    this._pendingOpens.clear();

    for (const [, stream] of this._streams) {
      stream._rstReceived = true;
      if (!stream.destroyed) {
        stream.destroy(closeErr);
      }
    }
    this._streams.clear();

    if (err && this.listenerCount('error') > 0) {
      this.emit('error', err);
    }
    this.emit('close');
  }

  close() {
    if (this.isClosed) return;
    this.goawayReceived = true;
    try {
      if (!this.carrier.destroyed && !this.carrier.writableEnded) {
        this._writeFrame(MUX_GOAWAY, 0, crypto.randomBytes(crypto.randomInt(8, 33)));
        this.carrier.end();
      }
    } catch {
      // Ignore write errors on close
    }
    this._handleCarrierClosed(null);
    // Keep draining carrier until mutual MSG_EOF completes cleanly
    if (!this.carrier.destroyed) {
      this.carrier.on('data', () => {});
    }
  }
}
