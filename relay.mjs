import {
  createServer,
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
} from './tunnel.mjs';
import {
  readControlRequest,
  sendControlError,
} from './protocol.mjs';
import {
  getMode,
  getModeByCommand,
  resolveRelayCommands,
} from './modes/index.mjs';

export function createRelayServer(options = {}) {
  const {
    key,
    mode = options.nextHop ? 'ptp' : 'both',
    nextHop = null,
    authorizedKeys = null,
    allowAnyClient = !authorizedKeys,
    connectTimeoutMs = 8_000,
    tlsCert = null,
    tlsKey = null,
    fallback = null,
    protocol = undefined,
    wsPath = undefined,
    onRelay = null,
  } = options;

  if (nextHop) {
    const plugin = getMode(mode);
    if (typeof plugin.handleStaticRelay !== 'function') {
      throw new TypeError(`Static "nextHop" is not supported in "${mode}" relay mode`);
    }
  }

  const allowedCmds = nextHop ? [] : resolveRelayCommands(mode);
  const relayIdentity = loadPrivateKey(key);
  const staticNext = nextHop
    ? {
        endpoint: nextHop.endpoint,
        parsedEp: parseEndpoint(nextHop.endpoint, '127.0.0.1'),
        publicKey: loadAuthorizedKeys(nextHop.publicKey),
      }
    : null;

  const server = createServer({
    key: relayIdentity,
    authorizedKeys,
    allowAnyClient,
    tlsCert,
    tlsKey,
    fallback,
    protocol,
    wsPath,
    keepAliveMs: 30_000,
  }, async (inTunnel) => {
    if (staticNext) {
      const plugin = getMode(mode);
      await plugin.handleStaticRelay({
        staticNext,
        inTunnel,
        relayIdentity,
        connectTimeoutMs,
        onRelay,
      });
      return;
    }

    try {
      const { cmd, request, leftover } = await readControlRequest(inTunnel, allowedCmds, connectTimeoutMs);
      const plugin = getModeByCommand(cmd);
      if (!plugin || typeof plugin.handleRelay !== 'function') {
        sendControlError(inTunnel, `Unsupported relay command 0x${cmd.toString(16)}`);
        return;
      }

      await plugin.handleRelay({
        cmd,
        request,
        leftover,
        inTunnel,
        relayIdentity,
        connectTimeoutMs,
        onRelay,
      });
    } catch (err) {
      if (!inTunnel.destroyed) {
        try {
          sendControlError(inTunnel, err);
        } catch {
          inTunnel.destroy();
        }
      }
    }
  });

  return server;
}
