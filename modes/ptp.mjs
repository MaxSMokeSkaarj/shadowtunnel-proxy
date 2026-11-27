import {
  bridgeSockets,
  connect,
  formatEndpoint,
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
} from '../tunnel.mjs';
import {
  CMD_PTP_CHAIN,
  MAX_CHAIN_HOPS,
  encodeControlRequest,
  readControlResponse,
  sendControlError,
  sendControlOk,
  waitSecureConnect,
} from '../protocol.mjs';

export async function openPtpCircuit(options) {
  const {
    key,
    hops = [], // [{ endpoint, publicKey }] — 0..N intermediate PTP repeaters
    exit, // { endpoint, publicKey } — final exit server (or first static repeater)
    handshakeTimeoutMs = 10_000,
  } = options;

  if (!key) throw new TypeError('openPtpCircuit requires client "key"');
  if (!exit?.endpoint || !exit?.publicKey) {
    throw new TypeError('openPtpCircuit requires "exit: { endpoint, publicKey }"');
  }

  const clientIdentity = loadPrivateKey(key);
  const chain = [
    ...hops.map((h) => ({ endpoint: h.endpoint, publicKeys: loadAuthorizedKeys(h.publicKey) })),
    { endpoint: exit.endpoint, publicKeys: loadAuthorizedKeys(exit.publicKey) },
  ];

  const first = chain[0];
  const firstTunnel = connect({
    endpoint: first.endpoint,
    key: clientIdentity,
    serverPublicKey: first.publicKeys,
    handshakeTimeoutMs,
    keepAliveMs: 30_000,
    tlsCa: options.tlsCa,
    tlsServername: options.tlsServername,
    tlsInsecure: options.tlsInsecure,
  });

  try {
    await waitSecureConnect(firstTunnel);

    if (chain.length > 1) {
      const restChain = chain.slice(1).map((h) => {
        const pubs = Array.from(h.publicKeys.values()).map((entry) => entry.spkiDer.toString('base64'));
        return {
          endpoint: h.endpoint,
          pub: pubs[0],
          pubs,
        };
      });
      firstTunnel.write(encodeControlRequest(CMD_PTP_CHAIN, { chain: restChain }));
      await readControlResponse(firstTunnel, handshakeTimeoutMs);
      firstTunnel.resume();
    }

    return firstTunnel;
  } catch (err) {
    if (!firstTunnel.destroyed) firstTunnel.destroy();
    throw err;
  }
}

export async function handlePtpDynamicRelay({ request, leftover, inTunnel, relayIdentity, connectTimeoutMs, onRelay }) {
  const chain = request?.chain;
  if (!Array.isArray(chain) || chain.length < 1 || chain.length > MAX_CHAIN_HOPS) {
    sendControlError(inTunnel, 'Invalid PTP hop chain');
    return;
  }

  const [head, ...restChain] = chain;
  const rawPubs = Array.isArray(head?.pubs) && head.pubs.length > 0
    ? head.pubs
    : (typeof head?.pub === 'string' ? [head.pub] : null);

  if (!head?.endpoint || !rawPubs) {
    sendControlError(inTunnel, 'Malformed PTP hop descriptor');
    return;
  }

  const nextEp = parseEndpoint(head.endpoint, '127.0.0.1');
  const nextPub = loadAuthorizedKeys(rawPubs.map((b64) => Buffer.from(b64, 'base64')));

  if (onRelay) {
    onRelay({
      mode: 'ptp',
      peerFingerprint: inTunnel.peerFingerprint,
      peerComment: inTunnel.peerComment,
      nextEndpoint: formatEndpoint(nextEp),
      remainingHops: restChain.length,
    });
  }

  const outTunnel = connect({
    endpoint: head.endpoint,
    key: relayIdentity,
    serverPublicKey: nextPub,
    handshakeTimeoutMs: connectTimeoutMs,
    keepAliveMs: 30_000,
  });

  try {
    await waitSecureConnect(outTunnel);

    if (restChain.length > 0) {
      outTunnel.write(encodeControlRequest(CMD_PTP_CHAIN, { chain: restChain }));
      await readControlResponse(outTunnel, connectTimeoutMs);
    }

    if (inTunnel.destroyed) {
      outTunnel.destroy();
      return;
    }

    sendControlOk(inTunnel);
    if (leftover.length > 0) outTunnel.write(leftover);
    inTunnel.resume();
    outTunnel.resume();
    bridgeSockets(inTunnel, outTunnel);
  } catch (err) {
    if (!outTunnel.destroyed) outTunnel.destroy();
    throw err;
  }
}

export async function handlePtpStaticRelay({ staticNext, inTunnel, relayIdentity, connectTimeoutMs, onRelay }) {
  let outTunnel = null;
  try {
    if (onRelay) {
      onRelay({
        mode: 'ptp-static',
        peerFingerprint: inTunnel.peerFingerprint,
        peerComment: inTunnel.peerComment,
        nextEndpoint: formatEndpoint(staticNext.parsedEp),
      });
    }
    outTunnel = connect({
      endpoint: staticNext.endpoint,
      key: relayIdentity,
      serverPublicKey: staticNext.publicKey,
      handshakeTimeoutMs: connectTimeoutMs,
      keepAliveMs: 30_000,
    });
    await waitSecureConnect(outTunnel);
    if (inTunnel.destroyed) {
      outTunnel.destroy();
      return;
    }
    bridgeSockets(inTunnel, outTunnel);
  } catch {
    if (outTunnel && !outTunnel.destroyed) outTunnel.destroy();
    if (!inTunnel.destroyed) inTunnel.destroy();
  }
}

export const ptpMode = {
  name: 'ptp',
  relayCommands: [CMD_PTP_CHAIN],
  openCircuit: openPtpCircuit,
  handleRelay: handlePtpDynamicRelay,
  handleStaticRelay: handlePtpStaticRelay,
};

export default ptpMode;
