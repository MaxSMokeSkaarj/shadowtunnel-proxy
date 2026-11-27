#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { formatEndpoint, formatError, generateIdentity, parseEndpoint } from './tunnel.mjs';
import {
  MuxCircuitPool,
  createExitServer,
  createExitTunGateway,
  createLocalHttpProxy,
  createLocalSocks5Proxy,
  createLocalTun,
  createRelayServer,
  extractConfigFlag,
  listModes,
  loadProxyRoleConfig,
  parseHopEntry,
} from './index.mjs';

const HELP = `Usage:
  node cli.mjs <role> [options]
  node cli.mjs -c <config.json> [cli-overrides]

Roles:
  keygen   Generate an Ed25519 identity keypair (<out>.key + <out>.pub)
  relay    Run an intermediate repeater/relay (--mode onion | ptp | both)
  exit     Run the exit proxy / UDP / TUN gateway server
  client   Run local HTTP/HTTPS, SOCKS5 (+UDP), and/or Linux TUN client

Modes:
  onion    Nested E2EE matryoshka (Client <-> Exit encrypted end-to-end; relays are blind)
  ptp      Point-to-Point hop-by-hop encryption (1 cipher layer per segment; neighbor auth)
  both     (Relay/Exit default) Accept both onion and dynamic ptp circuits on the same port

Options (common):
  -c, --config <file>      Load settings from JSON / JSONC file (CLI flags override config!)
  -q, --quiet              Suppress informational logs

Options (keygen):
  -o, --out <prefix>       Output path prefix (<prefix>.key and <prefix>.pub)
  -n, --name <comment>     Optional key label/comment
  -f, --force              Overwrite existing key files

Options (relay):
  -m, --mode <mode>        Relay mode: onion | ptp | both (default: both, or ptp if --next set)
  -l, --listen <endpoint>  Listen (:6001, ws://:6001/ws, wss://:443/secret-path)
  -k, --key <file>         Relay private key (.key)
  -a, --auth <file>        Authorized upstream keys (authorized_keys or .pub)
      --open               Allow any valid Ed25519 peer without whitelist
      --next <ep>,<pub>    Static PTP mode: always forward into fixed next hop/exit
      --tls-cert <file>    TLS certificate PEM (for tls:// or wss:// listener)
      --tls-key <file>     TLS private key PEM (for tls:// or wss:// listener)
      --fallback <ep>      Decoy HTTP backend (host:port) for browsers / DPI active probes

Options (exit):
  -m, --mode <mode>        Exit mode label: onion | ptp | both (default: both)
  -l, --listen <endpoint>  Listen (:6009, ws://:6009/ws, wss://:443/secret-path)
  -k, --key <file>         Exit private key (.key)
  -a, --auth <file>        Authorized keys (client.pub for onion, last-relay.pub for ptp)
      --open               Allow any valid Ed25519 peer without whitelist
      --no-udp             Disable multiplexed UDP forwarding on exit
      --tun <ifname>       Enable Linux L3 TUN gateway interface (e.g. st0)
      --tun-cidr <cidr>    Exit TUN gateway IP & client pool (default: 10.99.0.1/24)
      --tun-mtu <bytes>    TUN interface MTU (default: 1400)
      --nat                Auto-enable ip_forward=1 and iptables/nft MASQUERADE for TUN
      --no-tun-config      Skip ip addr/link setup (use pre-configured rootless TUN)
      --tls-cert <file>    TLS certificate PEM (for tls:// or wss:// listener)
      --tls-key <file>     TLS private key PEM (for tls:// or wss:// listener)
      --fallback <ep>      Decoy HTTP backend (host:port) for browsers / DPI active probes

Options (client):
  -m, --mode <mode>        Circuit mode: onion | ptp (default: onion)
  -l, --listen <endpoint>  Local HTTP/HTTPS proxy address (default: 127.0.0.1:8080)
      --no-http            Disable local HTTP/HTTPS proxy listener
  -s, --socks <endpoint>   Local SOCKS5 + UDP proxy address (e.g. 127.0.0.1:1080)
      --tun <ifname>       Enable Linux L3 TUN interface (e.g. st0; auto-assigns IP from exit)
      --tun-cidr <cidr>    Request a specific client TUN IP/prefix (e.g. 10.99.0.2/24)
      --tun-mtu <bytes>    Override local TUN MTU (default: negotiated from exit)
      --tun-default-route  Route system IPv4 traffic (0.0.0.0/1 + 128.0.0.0/1) via TUN
      --tun-exclude <spec> Bypass TUN via physical gateway (IP, CIDR, domain, or file; repeatable)
      --tun-route <spec>   Route specific target via TUN (IP, CIDR, domain, or file; repeatable)
      --no-tun-config      Skip ip addr/link setup (use pre-configured rootless TUN)
  -k, --key <file>         Client private key (.key)
      --hop <ep>,<pub>     Intermediate relay (supports tcp, tls://, ws://, wss://host:443/path)
  -e, --exit <ep>,<pub>    Exit server (or first static repeater when relays use --next)
      --pool <count>       Number of persistent multiplexed circuits (default: 2)
      --no-mux             Disable multiplexing for HTTP/SOCKS TCP streams
      --tls-ca <file>      Custom CA PEM for verifying entry TLS certificate
      --tls-sni <domain>   Override TLS SNI hostname on entry connection
      --tls-insecure       Skip X.509 check (Ed25519 tunnel key check still enforced!)

Examples:
  # 1) Start from JSON / JSONC config file (with optional CLI override):
  node cli.mjs -c ./client.json
  node cli.mjs -c ./client.json -m onion

  # 2) Direct CLI launch (HTTP + SOCKS5+UDP):
  node cli.mjs client -m ptp -l 127.0.0.1:8080 -s 127.0.0.1:1080 -k ./keys/client.key \\
    --hop wss://relay1.example.com:443/ws/example-path,./keys/r1.pub \\
    --exit 203.0.113.9:5001,./keys/exit.pub
`;

function die(msg) {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

function runKeygen(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      out: { type: 'string', short: 'o' },
      name: { type: 'string', short: 'n', default: '' },
      force: { type: 'boolean', short: 'f', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help || !values.out) {
    if (!values.help) {
      console.error('Usage: node cli.mjs keygen -o <prefix> [-n <comment>] [-f]\nExample: node cli.mjs keygen -o ./keys/r1 -n relay-1');
      process.exit(1);
    }
    console.log(HELP);
    return;
  }

  const privPath = `${values.out}.key`;
  const pubPath = `${values.out}.pub`;
  if (!values.force && (fs.existsSync(privPath) || fs.existsSync(pubPath))) {
    die(`Key files already exist (${privPath} / ${pubPath}). Pass -f / --force to overwrite.`);
  }

  fs.mkdirSync(path.dirname(path.resolve(privPath)), { recursive: true });
  const id = generateIdentity(values.name);
  fs.writeFileSync(privPath, id.privateKeyPem, { mode: 0o600 });
  fs.chmodSync(privPath, 0o600);
  fs.writeFileSync(pubPath, `${id.publicKeyLine}\n`, { mode: 0o644 });

  console.error(`Generated Ed25519 identity:`);
  console.error(`  Private key : ${privPath} (0600)`);
  console.error(`  Public key  : ${pubPath}`);
  console.error(`  Fingerprint : ${id.fingerprint}`);
  console.log(id.publicKeyLine);
}

function runRelay(argv, preloadedCfg = null) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', short: 'c' },
      mode: { type: 'string', short: 'm' },
      listen: { type: 'string', short: 'l' },
      key: { type: 'string', short: 'k' },
      auth: { type: 'string', short: 'a' },
      open: { type: 'boolean' },
      next: { type: 'string' },
      'tls-cert': { type: 'string' },
      'tls-key': { type: 'string' },
      fallback: { type: 'string' },
      quiet: { type: 'boolean', short: 'q' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  const cfg = preloadedCfg || (values.config ? loadProxyRoleConfig(values.config) : {});
  const listen = values.listen ?? cfg.listen;
  const key = values.key ?? cfg.key;
  const auth = values.auth ?? cfg.auth ?? null;
  const allowOpen = values.open ?? cfg.open ?? false;
  const nextHop = values.next ? parseHopEntry(values.next, null, '--next') : (cfg.next || null);
  const effectiveMode = values.mode ?? cfg.mode ?? (nextHop ? 'ptp' : 'both');
  const tlsCert = values['tls-cert'] ?? cfg.tlsCert;
  const tlsKey = values['tls-key'] ?? cfg.tlsKey;
  const fallback = values.fallback ?? cfg.fallback;
  const quiet = values.quiet ?? cfg.quiet ?? false;

  if (!listen || !key) die('relay requires -l <endpoint> and -k <relay.key>');
  if (!auth && !allowOpen) die('relay requires either -a <authorized_keys> or --open');

  const log = (...a) => { if (!quiet) console.error(...a); };

  const listenEp = parseEndpoint(listen, '');
  const server = createRelayServer({
    key,
    mode: effectiveMode,
    nextHop,
    authorizedKeys: auth,
    allowAnyClient: Boolean(allowOpen),
    protocol: listenEp.protocol,
    wsPath: listenEp.wsPath,
    tlsCert,
    tlsKey,
    fallback,
    onRelay: ({ mode, peerFingerprint, peerComment, nextEndpoint }) => {
      const who = peerComment ? `${peerComment} (${peerFingerprint})` : peerFingerprint;
      log(`[relay:${mode}] ${who} -> ${nextEndpoint}`);
    },
  });

  server.on('clientError', (err) => log(`[relay] Rejected peer: ${formatError(err)}`));
  server.listen(listen, () => {
    const modeDesc = nextHop ? `ptp-static -> ${nextHop.endpoint}` : effectiveMode;
    log(`[relay] Listening on ${formatEndpoint(server.address())} | mode=${modeDesc} | ${server.fingerprint}`);
  });

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

function runExit(argv, preloadedCfg = null) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', short: 'c' },
      mode: { type: 'string', short: 'm' },
      listen: { type: 'string', short: 'l' },
      key: { type: 'string', short: 'k' },
      auth: { type: 'string', short: 'a' },
      open: { type: 'boolean' },
      'no-udp': { type: 'boolean' },
      tun: { type: 'string' },
      'tun-cidr': { type: 'string' },
      'tun-mtu': { type: 'string' },
      nat: { type: 'boolean' },
      'no-tun-config': { type: 'boolean' },
      'tls-cert': { type: 'string' },
      'tls-key': { type: 'string' },
      fallback: { type: 'string' },
      quiet: { type: 'boolean', short: 'q' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  const cfg = preloadedCfg || (values.config ? loadProxyRoleConfig(values.config) : {});
  const mode = values.mode ?? cfg.mode ?? 'both';
  const listen = values.listen ?? cfg.listen;
  const key = values.key ?? cfg.key;
  const auth = values.auth ?? cfg.auth ?? null;
  const allowOpen = values.open ?? cfg.open ?? false;
  const allowUdp = values['no-udp'] ? false : (cfg.udp ?? true);
  const tlsCert = values['tls-cert'] ?? cfg.tlsCert;
  const tlsKey = values['tls-key'] ?? cfg.tlsKey;
  const fallback = values.fallback ?? cfg.fallback;
  const quiet = values.quiet ?? cfg.quiet ?? false;

  if (!listen || !key) die('exit requires -l <endpoint> and -k <exit.key>');
  if (!auth && !allowOpen) die('exit requires either -a <authorized_keys> or --open');
  const validExitModes = [...listModes(), 'both', 'all'];
  if (!validExitModes.includes(mode)) {
    die(`Invalid exit --mode "${mode}" (expected ${validExitModes.join(', ')})`);
  }

  const log = (...a) => { if (!quiet) console.error(...a); };

  const cfgTun = cfg.tun && cfg.tun.enabled !== false ? cfg.tun : null;
  const tunName = values.tun ?? (cfgTun ? cfgTun.name : null);
  let tunGateway = null;
  if (tunName) {
    const tunCidr = values['tun-cidr'] ?? cfgTun?.cidr ?? '10.99.0.1/24';
    const tunMtu = Number(values['tun-mtu'] ?? cfgTun?.mtu ?? 1400) || 1400;
    const tunConfigure = values['no-tun-config'] ? false : (cfgTun?.configure ?? true);
    const tunNat = values.nat ?? cfgTun?.nat ?? false;

    tunGateway = createExitTunGateway({
      ifname: tunName,
      cidr: tunCidr,
      mtu: tunMtu,
      configure: Boolean(tunConfigure),
      enableNat: Boolean(tunNat),
    });
    log(`[exit:tun] Interface ${tunGateway.name} ready (${tunGateway.gatewayIp}/${tunGateway.prefixLen}, mtu=${tunGateway.mtu}${tunNat ? ', nat=on' : ''})`);
  }

  const listenEp = parseEndpoint(listen, '');
  const server = createExitServer({
    key,
    authorizedKeys: auth,
    allowAnyClient: Boolean(allowOpen),
    allowUdp,
    tunGateway,
    protocol: listenEp.protocol,
    wsPath: listenEp.wsPath,
    tlsCert,
    tlsKey,
    fallback,
    onExitRequest: ({ mux, proto, streamId, peerFingerprint, peerComment, target }) => {
      const who = peerComment ? `${peerComment} (${peerFingerprint})` : peerFingerprint;
      const tag = mux ? `exit:${proto || 'mux'}#${streamId}` : 'exit';
      log(`[${tag}] ${who} -> ${target}`);
    },
  });

  server.on('clientError', (err) => log(`[exit] Rejected peer: ${formatError(err)}`));
  server.listen(listen, () => {
    log(`[exit] Listening on ${formatEndpoint(server.address())} | mode=${mode} | ${server.fingerprint}`);
  });

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function runClient(argv, preloadedCfg = null) {
  const { values } = parseArgs({
    args: argv,
    options: {
      config: { type: 'string', short: 'c' },
      mode: { type: 'string', short: 'm' },
      listen: { type: 'string', short: 'l' },
      'no-http': { type: 'boolean' },
      socks: { type: 'string', short: 's' },
      tun: { type: 'string' },
      'tun-cidr': { type: 'string' },
      'tun-mtu': { type: 'string' },
      'tun-default-route': { type: 'boolean' },
      'tun-exclude': { type: 'string', multiple: true },
      'tun-route': { type: 'string', multiple: true },
      'no-tun-config': { type: 'boolean' },
      key: { type: 'string', short: 'k' },
      hop: { type: 'string', multiple: true },
      exit: { type: 'string', short: 'e' },
      pool: { type: 'string' },
      'no-mux': { type: 'boolean' },
      'tls-ca': { type: 'string' },
      'tls-sni': { type: 'string' },
      'tls-insecure': { type: 'boolean' },
      quiet: { type: 'boolean', short: 'q' },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  const hasConfig = Boolean(values.config || preloadedCfg);
  const cfg = preloadedCfg || (values.config ? loadProxyRoleConfig(values.config) : {});

  const mode = values.mode ?? cfg.mode ?? 'onion';
  const key = values.key ?? cfg.key;
  const hops = (values.hop && values.hop.length > 0)
    ? values.hop.map((s) => parseHopEntry(s, null, '--hop'))
    : (cfg.hops || []);
  const exit = values.exit ? parseHopEntry(values.exit, null, '--exit') : cfg.exit;

  if (!key || !exit) {
    die('client requires -k <client.key> and --exit <endpoint>,<exit.pub> (or via -c config.json)');
  }

  const useMux = values['no-mux'] ? false : (cfg.mux ?? true);
  const poolSize = Math.max(1, Number(values.pool ?? cfg.pool ?? 2) || 2);
  const tlsCa = values['tls-ca'] ?? cfg.tlsCa;
  const tlsServername = values['tls-sni'] ?? cfg.tlsSni;
  const tlsInsecure = values['tls-insecure'] ?? cfg.tlsInsecure ?? false;
  const quiet = values.quiet ?? cfg.quiet ?? false;

  // Resolve SOCKS5 & TUN settings first so default HTTP behavior knows whether another ingress is active
  const socksListen = values.socks ?? (cfg.socks !== false ? cfg.socks : null) ?? null;
  const socksAuth = cfg.socksAuth || null;

  const cfgTun = cfg.tun && cfg.tun.enabled !== false ? cfg.tun : null;
  const tunName = values.tun ?? (cfgTun ? cfgTun.name : null);

  let httpListen = null;
  if (values['no-http']) {
    httpListen = null;
  } else if (values.listen) {
    httpListen = values.listen;
  } else if (cfg.http === false) {
    httpListen = null;
  } else if (typeof cfg.http === 'string') {
    httpListen = cfg.http;
  } else if (!hasConfig || (!socksListen && !tunName)) {
    httpListen = '127.0.0.1:8080';
  }

  const enableHttp = Boolean(httpListen);
  const enableSocks = Boolean(socksListen);
  const enableTun = Boolean(tunName);
  if (!enableHttp && !enableSocks && !enableTun) {
    die('No local ingress enabled: enable http, socks, or tun in config / CLI flags');
  }

  const log = (...a) => { if (!quiet) console.error(...a); };

  const sharedPool = (useMux || enableSocks || enableTun)
    ? new MuxCircuitPool({
        key,
        mode,
        hops,
        exit,
        poolSize,
        tlsCa,
        tlsServername,
        tlsInsecure,
        onSessionOpen: ({ slot, mode: m, hopCount }) => {
          log(`[proxy-client:${m}] Persistent mux circuit #${slot + 1} established (${hopCount} relays)`);
        },
      })
    : null;

  const closers = [];

  if (enableHttp) {
    const httpProxy = createLocalHttpProxy({
      key,
      mode,
      mux: useMux,
      pool: useMux ? sharedPool : null,
      hops,
      exit,
      tlsCa,
      tlsServername,
      tlsInsecure,
      onRequest: ({ mode: m, mux, method, host, port, hopCount }) => {
        log(`[proxy-client:${m}${mux ? ':mux' : ''}] ${method} ${host}:${port} via ${hopCount} relay(s) + exit`);
      },
      onError: (err) => log(`[proxy-client:http] Circuit error: ${formatError(err)}`),
    });

    httpProxy.listen(httpListen, () => {
      const muxInfo = useMux ? `mux-pool=${poolSize}` : 'mux=off';
      log(`[proxy-client] Local HTTP/HTTPS proxy on ${formatEndpoint(httpProxy.server.address())} | mode=${mode} | ${muxInfo} | hops=${hops.length}`);
    });
    closers.push((cb) => httpProxy.close(cb));
  }

  if (enableSocks) {
    const socksProxy = createLocalSocks5Proxy({
      key,
      mode,
      mux: useMux,
      pool: sharedPool,
      hops,
      exit,
      auth: socksAuth,
      tlsCa,
      tlsServername,
      tlsInsecure,
      onRequest: ({ mode: m, mux, method, host, port, hopCount }) => {
        log(`[proxy-client:${m}${mux ? ':mux' : ''}] ${method} ${host}:${port} via ${hopCount} relay(s) + exit`);
      },
      onError: (err) => log(`[proxy-client:socks5] Circuit error: ${formatError(err)}`),
    });

    socksProxy.listen(socksListen, () => {
      log(`[proxy-client] Local SOCKS5 (+UDP) proxy on ${formatEndpoint(socksProxy.server.address())} | mode=${mode} | hops=${hops.length}`);
    });
    closers.push((cb) => socksProxy.close(cb));
  }

  if (enableTun) {
    const tunCidr = values['tun-cidr'] ?? cfgTun?.cidr ?? null;
    const rawMtu = values['tun-mtu'] ?? cfgTun?.mtu ?? null;
    const tunMtu = rawMtu !== null && rawMtu !== undefined ? Number(rawMtu) : null;
    const tunConfigure = values['no-tun-config'] ? false : (cfgTun?.configure ?? true);
    const tunDefaultRoute = values['tun-default-route'] ?? cfgTun?.defaultRoute ?? false;
    const tunExclude = (values['tun-exclude'] && values['tun-exclude'].length > 0)
      ? values['tun-exclude']
      : (cfgTun?.exclude || []);
    const tunRoutes = (values['tun-route'] && values['tun-route'].length > 0)
      ? values['tun-route']
      : (cfgTun?.routes || []);

    const localTun = await createLocalTun({
      ifname: tunName,
      cidr: tunCidr,
      mtu: tunMtu,
      configure: Boolean(tunConfigure),
      defaultRoute: Boolean(tunDefaultRoute),
      exclude: tunExclude,
      routes: tunRoutes,
      key,
      mode,
      pool: sharedPool,
      hops,
      exit,
      tlsCa,
      tlsServername,
      tlsInsecure,
      onConnect: ({ ifname, clientIp, gatewayIp, prefixLen, mtu }) => {
        log(`[proxy-client:tun] Interface ${ifname} up (${clientIp}/${prefixLen} -> gw ${gatewayIp}, mtu=${mtu})`);
      },
      onError: (err) => log(`[proxy-client:tun] Reconnect error: ${formatError(err)}`),
    });
    closers.push((cb) => localTun.close(cb));
  }

  let stopping = false;
  const stop = () => {
    if (stopping) return;
    stopping = true;
    if (sharedPool) sharedPool.close();
    let remaining = closers.length;
    if (remaining === 0) process.exit(0);
    for (const closeFn of closers) {
      closeFn(() => {
        remaining -= 1;
        if (remaining <= 0) process.exit(0);
      });
    }
  };
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

const rawArgs = process.argv.slice(2);
if (rawArgs.length === 0 || rawArgs[0] === '-h' || rawArgs[0] === '--help' || rawArgs[0] === 'help') {
  console.log(HELP);
  process.exit(0);
}

(async () => {
  try {
    // Support roleless `node cli.mjs -c config.json [overrides]`
    if (rawArgs[0].startsWith('-')) {
      const cfgPath = extractConfigFlag(rawArgs);
      if (!cfgPath) {
        die(`Missing role or -c <config.json>`);
      }
      const preloaded = loadProxyRoleConfig(cfgPath);
      if (!preloaded.role) {
        die(`Config file "${cfgPath}" must specify "role": "client" | "relay" | "exit"`);
      }
      switch (preloaded.role) {
        case 'relay':
          runRelay(rawArgs, preloaded);
          return;
        case 'exit':
          runExit(rawArgs, preloaded);
          return;
        case 'client':
          await runClient(rawArgs, preloaded);
          return;
        default:
          die(`Unknown role "${preloaded.role}" in ${cfgPath}`);
      }
    }

    const [role, ...rest] = rawArgs;
    switch (role) {
      case 'keygen':
        runKeygen(rest);
        break;
      case 'relay':
        runRelay(rest);
        break;
      case 'exit':
        runExit(rest);
        break;
      case 'client':
        await runClient(rest);
        break;
      default:
        die(`Unknown role "${role}"`);
    }
  } catch (err) {
    die(err.message);
  }
})();
