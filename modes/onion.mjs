import {
  TunnelSocket,
  bridgeSockets,
  connect,
  dialTransport,
  formatEndpoint,
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
} from '../tunnel.mjs';
import {
  CMD_EXTEND,
  encodeControlRequest,
  readControlResponse,
  sendControlError,
  sendControlOk,
  waitSecureConnect,
} from '../protocol.mjs';

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
    ...hops.map((h) => ({ endpoint: h.endpoint, publicKey: loadAuthorizedKeys(h.publicKey) })),
    { endpoint: exit.endpoint, publicKey: loadAuthorizedKeys(exit.publicKey) },
  ];

  const layers = [];
  try {
    const first = chain[0];
    let current = connect({
      endpoint: first.endpoint,
      key: clientIdentity,
      serverPublicKey: first.publicKey,
      handshakeTimeoutMs,
      keepAliveMs: chain.length === 1 ? 30_000 : 0,
      tlsCa: options.tlsCa,
      tlsServername: options.tlsServername,
      tlsInsecure: options.tlsInsecure,
    });
    layers.push(current);
    await waitSecureConnect(current);

    // Telescope nested TunnelSocket layers inside each preceding tunnel
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

export async function handleOnionRelay({ request, leftover, inTunnel, connectTimeoutMs, onRelay }) {
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

  const nextSock = dialTransport(nextEp, {});
  nextSock.setNoDelay?.(true);

  try {
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

    // Disable intermediate relay keepalive once extended into blind pipe (prevents hop-count echo oracle!)
    inTunnel.setKeepAlive?.(0);
    sendControlOk(inTunnel);
    if (leftover.length > 0) nextSock.write(leftover);
    inTunnel.resume();
    bridgeSockets(inTunnel, nextSock);
  } catch (err) {
    if (!nextSock.destroyed) nextSock.destroy();
    throw err;
  }
}

export const onionMode = {
  name: 'onion',
  relayCommands: [CMD_EXTEND],
  openCircuit: openOnionCircuit,
  handleRelay: handleOnionRelay,
};

export default onionMode;
