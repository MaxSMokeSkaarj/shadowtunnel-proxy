import {
  MuxSession,
  loadAuthorizedKeys,
  loadPrivateKey,
} from './tunnel.mjs';
import {
  CMD_EXIT_MUX,
  encodeControlRequest,
  encodeUdpPacket,
  readControlResponse,
} from './protocol.mjs';
import { getMode, openProxyCircuit } from './modes/index.mjs';

const DEFAULT_MAX_TUN_QUEUE_BYTES = 1024 * 1024; // 1 MiB carrier queue cap against TCP-over-TCP bufferbloat

export class MuxCircuitPool {
  constructor(options) {
    const {
      key,
      mode = 'onion',
      hops = [],
      exit,
      poolSize = 2,
      handshakeTimeoutMs = 10_000,
      tlsCa = undefined,
      tlsServername = undefined,
      tlsInsecure = false,
      onSessionOpen = null,
    } = options;

    getMode(mode); // Validate mode is registered upfront

    this._key = typeof key === 'object' && key !== null && 'export' in key ? key : loadPrivateKey(key);
    this._mode = mode;
    this._hops = hops.map((h) => ({
      endpoint: h.endpoint,
      publicKey: h.publicKey instanceof Map ? h.publicKey : loadAuthorizedKeys(h.publicKey),
    }));
    this._exit = {
      endpoint: exit.endpoint,
      publicKey: exit.publicKey instanceof Map ? exit.publicKey : loadAuthorizedKeys(exit.publicKey),
    };
    this._handshakeTimeoutMs = handshakeTimeoutMs;
    this._tlsOpts = { tlsCa, tlsServername, tlsInsecure };
    this._onSessionOpen = onSessionOpen;
    this.poolSize = Math.max(1, Number(poolSize) || 1);
    this._slots = Array.from({ length: this.poolSize }, (_, index) => ({
      index,
      session: null,
      connecting: null,
    }));
    this._rr = 0;
    this._closed = false;
  }

  _connectSlot(slot) {
    if (this._closed) {
      return Promise.reject(new Error('Circuit pool is closed'));
    }
    if (slot.session && slot.session.canOpenStreams) {
      return Promise.resolve(slot.session);
    }
    if (slot.connecting) {
      return slot.connecting;
    }

    slot.connecting = (async () => {
      const circuit = await openProxyCircuit({
        mode: this._mode,
        key: this._key,
        hops: this._hops,
        exit: this._exit,
        handshakeTimeoutMs: this._handshakeTimeoutMs,
        ...this._tlsOpts,
      });

      try {
        circuit.write(encodeControlRequest(CMD_EXIT_MUX, {}));
        await readControlResponse(circuit, this._handshakeTimeoutMs);

        const dgramHandlers = new Map();
        const session = new MuxSession(circuit, {
          initiator: true,
          openTimeoutMs: this._handshakeTimeoutMs,
          onDatagram: (channelId, payload) => {
            const handler = dgramHandlers.get(channelId);
            if (handler) handler(payload);
          },
        });
        session._dgramHandlers = dgramHandlers;
        slot.session = session;
        slot.connecting = null;

        session.once('close', () => {
          dgramHandlers.clear();
          if (slot.session === session) {
            slot.session = null;
          }
        });

        if (this._onSessionOpen) {
          this._onSessionOpen({ slot: slot.index, mode: this._mode, hopCount: this._hops.length });
        }

        if (this._closed) {
          session.close();
          throw new Error('Circuit pool closed during handshake');
        }
        return session;
      } catch (err) {
        slot.connecting = null;
        if (!circuit.destroyed) circuit.destroy();
        throw err;
      }
    })();

    return slot.connecting;
  }

  _pickSlot() {
    let bestReady = null;
    let emptySlot = null;

    for (let i = 0; i < this.poolSize; i++) {
      const idx = (this._rr + i) % this.poolSize;
      const s = this._slots[idx];
      if (s.session && s.session.canOpenStreams) {
        if (!bestReady || s.session.activeStreamCount < bestReady.session.activeStreamCount) {
          bestReady = s;
        }
      } else if (!emptySlot && !s.connecting) {
        emptySlot = s;
      }
    }
    this._rr = (this._rr + 1) % this.poolSize;

    if (bestReady && bestReady.session.activeStreamCount === 0) {
      return bestReady;
    }
    if (bestReady && bestReady.session.activeStreamCount > 0 && emptySlot) {
      return emptySlot;
    }
    if (bestReady) {
      return bestReady;
    }
    return this._slots[this._rr];
  }

  async _openStreamWithRetry(metadata, preferredSlot = null) {
    const slot = preferredSlot || this._pickSlot();
    let session = await this._connectSlot(slot);
    try {
      const stream = await session.openStream(metadata, this._handshakeTimeoutMs);
      return { session, stream };
    } catch (err) {
      if (err.code === 'ERR_MUX_CLOSED' && !this._closed) {
        if (slot.session === session) slot.session = null;
        session = await this._connectSlot(slot);
        const stream = await session.openStream(metadata, this._handshakeTimeoutMs);
        return { session, stream };
      }
      throw err;
    }
  }

  async openTargetStream(host, port) {
    const { stream } = await this._openStreamWithRetry({ type: 'tcp', host, port });
    return stream;
  }

  async openUdpAssociation({ onPacket = null, onClose = null } = {}) {
    const { session, stream } = await this._openStreamWithRetry({ type: 'udp' });
    const channelId = stream.id;
    let closed = false;

    if (typeof onPacket === 'function') {
      session._dgramHandlers.set(channelId, onPacket);
    }

    const cleanup = () => {
      if (closed) return;
      closed = true;
      session._dgramHandlers.delete(channelId);
      if (typeof onClose === 'function') onClose();
    };

    stream.once('close', cleanup);
    stream.once('end', cleanup);

    return {
      channelId,
      stream,
      sendRaw(encodedUdpPayload) {
        if (closed || session.isClosed) return false;
        return session.sendDatagram(channelId, encodedUdpPayload);
      },
      send(host, port, data) {
        if (closed || session.isClosed) return false;
        return session.sendDatagram(channelId, encodeUdpPacket(host, port, data));
      },
      close() {
        cleanup();
        if (!stream.destroyed) {
          stream.end();
        }
      },
    };
  }

  async openTunChannel({
    requestedIp = null,
    maxQueueBytes = DEFAULT_MAX_TUN_QUEUE_BYTES,
    onPacket = null,
    onClose = null,
  } = {}) {
    const meta = requestedIp ? { type: 'tun', requestedIp } : { type: 'tun' };
    const { session, stream } = await this._openStreamWithRetry(meta, this._slots[0]);
    const channelId = stream.id;
    let closed = false;

    let config = {};
    if (stream.responseMetadata && stream.responseMetadata.length > 0) {
      try {
        config = JSON.parse(stream.responseMetadata.toString('utf8'));
      } catch {
        stream.destroy();
        throw new Error('Malformed TUN configuration response from exit server');
      }
    }

    if (typeof onPacket === 'function') {
      session._dgramHandlers.set(channelId, onPacket);
    }

    const cleanup = () => {
      if (closed) return;
      closed = true;
      session._dgramHandlers.delete(channelId);
      if (typeof onClose === 'function') onClose();
    };

    stream.once('close', cleanup);
    stream.once('end', cleanup);

    return {
      channelId,
      config,
      stream,
      sendPacket(ipPacket) {
        if (closed || session.isClosed) return false;
        // Drop L3 packets on severe carrier congestion rather than building multi-second TCP-over-TCP latency
        if (session.carrier.writableLength > maxQueueBytes) {
          return false;
        }
        return session.sendDatagram(channelId, ipPacket);
      },
      close() {
        cleanup();
        if (!stream.destroyed) {
          stream.end();
        }
      },
    };
  }

  close() {
    this._closed = true;
    for (const slot of this._slots) {
      if (slot.session) {
        slot.session.close();
        slot.session = null;
      }
    }
  }
}
