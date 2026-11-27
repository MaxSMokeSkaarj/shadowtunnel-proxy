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
  listModes,
} from './index.mjs';

const HELP = `Usage:
  node cli.mjs <role> [options]

Roles:
  keygen   Generate an Ed25519 identity keypair (<out>.key + <out>.pub)
  relay    Run an intermediate repeater/relay (--mode onion | ptp | both)
  exit     Run the exit proxy / UDP / TUN gateway server
  client   Run local HTTP/HTTPS, SOCKS5 (+UDP), and/or Linux TUN client

Modes:
  onion    Nested E2EE matryoshka (Client <-> Exit encrypted end-to-end; relays are blind)
  ptp      Point-to-Point hop-by-hop encryption (1 cipher layer per segment; neighbor auth)
  both     (Relay/Exit default) Accept both onion and dynamic ptp circuits on the same port

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
  -q, --quiet              Suppress informational logs

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
  -q, --quiet              Suppress informational logs

Options (client):
  -m, --mode <mode>        Circuit mode: onion | ptp (default: onion)
  -l, --listen <endpoint>  Local HTTP/HTTPS proxy address (default: 127.0.0.1:8080)
      --no-http            Disable local HTTP/HTTPS proxy listener
  -s, --socks <endpoint>   Local SOCKS5 + UDP proxy address (e.g. 127.0.0.1:1080)
      --tun <ifname>       Enable Linux L3 TUN interface (e.g. st0; auto-assigns IP from exit)
      --tun-cidr <cidr>    Request a specific client TUN IP/prefix (e.g. 10.99.0.2/24)
      --tun-mtu <bytes>    Override local TUN MTU (default: negotiated from exit)
      --tun-default-route  Route system IPv4 traffic (0.0.0.0/1 + 128.0.0.0/1) via TUN
      --no-tun-config      Skip ip addr/link setup (use pre-configured rootless TUN)
  -k, --key <file>         Client private key (.key)
      --hop <ep>,<pub>     Intermediate relay (supports tcp, tls://, ws://, wss://host:443/path)
  -e, --exit <ep>,<pub>    Exit server (or first static repeater when relays use --next)
      --pool <count>       Number of persistent multiplexed circuits (default: 2)
      --no-mux             Disable multiplexing for HTTP/SOCKS TCP streams
      --tls-ca <file>      Custom CA PEM for verifying entry TLS certificate
      --tls-sni <domain>   Override TLS SNI hostname on entry connection
      --tls-insecure       Skip X.509 check (Ed25519 tunnel key check still enforced!)
  -q, --quiet              Suppress informational logs

Examples:
  # A) HTTP + SOCKS5 (TCP & UDP) simultaneously over persistent multi-hop circuits:
  node cli.mjs client -m ptp -l 127.0.0.1:8080 -s 127.0.0.1:1080 -k ./keys/client.key \\
    --hop wss://relay1.example.com:443/v1/sync,./keys/r1.pub \\
    --exit 203.0.113.9:5001,./keys/exit.pub

  # B) Full-system Linux L3 TUN VPN (ICMP, TCP, UDP, QUIC):
  sudo node cli.mjs exit   -l :5001 -k ./keys/exit.key -a ./keys/client.pub --tun st0 --nat
  sudo node cli.mjs client -k ./keys/client.key -e 203.0.113.9:5001,./keys/exit.pub \\
    --no-http --tun st0 --tun-default-route
`;

function die(msg) {
  console.error(`Error: ${msg}`);
  process.exit(1);
}

function parseHopSpec(spec, flagName) {
  const commaIdx = spec.indexOf(',');
  if (commaIdx === -1) {
    die(`Invalid ${flagName} "${spec}" (expected "<host:port>,<pubkey-file>")`);
  }
  const endpoint = spec.slice(0, commaIdx).trim();
  const publicKey = spec.slice(commaIdx + 1).trim();
  if (!endpoint || !publicKey) {
    die(`Invalid ${flagName} "${spec}" (expected "<host:port>,<pubkey-file>")`);
  }
  return { endpoint, publicKey };
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

function runRelay(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      mode: { type: 'string', short: 'm' },
      listen: { type: 'string', short: 'l' },
      key: { type: 'string', short: 'k' },
      auth: { type: 'string', short: 'a' },
      open: { type: 'boolean', default: false },
      next: { type: 'string' },
      'tls-cert': { type: 'string' },
      'tls-key': { type: 'string' },
      fallback: { type: 'string' },
      quiet: { type: 'boolean', short: 'q', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }
  if (!values.listen || !values.key) die('relay requires -l <endpoint> and -k <relay.key>');
  if (!values.auth && !values.open) die('relay requires either -a <authorized_keys> or --open');

  const nextHop = values.next ? parseHopSpec(values.next, '--next') : null;
  const effectiveMode = values.mode || (nextHop ? 'ptp' : 'both');
  const log = (...a) => { if (!values.quiet) console.error(...a); };

  const listenEp = parseEndpoint(values.listen, '');
  const server = createRelayServer({
    key: values.key,
    mode: effectiveMode,
    nextHop,
    authorizedKeys: values.auth || null,
    allowAnyClient: Boolean(values.open),
    protocol: listenEp.protocol,
    wsPath: listenEp.wsPath,
    tlsCert: values['tls-cert'],
    tlsKey: values['tls-key'],
    fallback: values.fallback,
    onRelay: ({ mode, peerFingerprint, peerComment, nextEndpoint }) => {
      const who = peerComment ? `${peerComment} (${peerFingerprint})` : peerFingerprint;
      log(`[relay:${mode}] ${who} -> ${nextEndpoint}`);
    },
  });

  server.on('clientError', (err) => log(`[relay] Rejected peer: ${formatError(err)}`));
  server.listen(values.listen, () => {
    const modeDesc = nextHop ? `ptp-static -> ${nextHop.endpoint}` : effectiveMode;
    log(`[relay] Listening on ${formatEndpoint(server.address())} | mode=${modeDesc} | ${server.fingerprint}`);
  });

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

function runExit(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      mode: { type: 'string', short: 'm', default: 'both' },
      listen: { type: 'string', short: 'l' },
      key: { type: 'string', short: 'k' },
      auth: { type: 'string', short: 'a' },
      open: { type: 'boolean', default: false },
      'no-udp': { type: 'boolean', default: false },
      tun: { type: 'string' },
      'tun-cidr': { type: 'string', default: '10.99.0.1/24' },
      'tun-mtu': { type: 'string', default: '1400' },
      nat: { type: 'boolean', default: false },
      'no-tun-config': { type: 'boolean', default: false },
      'tls-cert': { type: 'string' },
      'tls-key': { type: 'string' },
      fallback: { type: 'string' },
      quiet: { type: 'boolean', short: 'q', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }
  if (!values.listen || !values.key) die('exit requires -l <endpoint> and -k <exit.key>');
  if (!values.auth && !values.open) die('exit requires either -a <authorized_keys> or --open');
  const validExitModes = [...listModes(), 'both', 'all'];
  if (!validExitModes.includes(values.mode)) {
    die(`Invalid exit --mode "${values.mode}" (expected ${validExitModes.join(', ')})`);
  }

  const log = (...a) => { if (!values.quiet) console.error(...a); };

  let tunGateway = null;
  if (values.tun) {
    tunGateway = createExitTunGateway({
      ifname: values.tun,
      cidr: values['tun-cidr'],
      mtu: Number(values['tun-mtu']) || 1400,
      configure: !values['no-tun-config'],
      enableNat: Boolean(values.nat),
    });
    log(`[exit:tun] Interface ${tunGateway.name} ready (${tunGateway.gatewayIp}/${tunGateway.prefixLen}, mtu=${tunGateway.mtu}${values.nat ? ', nat=on' : ''})`);
  }

  const listenEp = parseEndpoint(values.listen, '');
  const server = createExitServer({
    key: values.key,
    authorizedKeys: values.auth || null,
    allowAnyClient: Boolean(values.open),
    allowUdp: !values['no-udp'],
    tunGateway,
    protocol: listenEp.protocol,
    wsPath: listenEp.wsPath,
    tlsCert: values['tls-cert'],
    tlsKey: values['tls-key'],
    fallback: values.fallback,
    onExitRequest: ({ mux, proto, streamId, peerFingerprint, peerComment, target }) => {
      const who = peerComment ? `${peerComment} (${peerFingerprint})` : peerFingerprint;
      const tag = mux ? `exit:${proto || 'mux'}#${streamId}` : 'exit';
      log(`[${tag}] ${who} -> ${target}`);
    },
  });

  server.on('clientError', (err) => log(`[exit] Rejected peer: ${formatError(err)}`));
  server.listen(values.listen, () => {
    log(`[exit] Listening on ${formatEndpoint(server.address())} | mode=${values.mode} | ${server.fingerprint}`);
  });

  const stop = () => server.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

async function runClient(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      mode: { type: 'string', short: 'm', default: 'onion' },
      listen: { type: 'string', short: 'l', default: '127.0.0.1:8080' },
      'no-http': { type: 'boolean', default: false },
      socks: { type: 'string', short: 's' },
      tun: { type: 'string' },
      'tun-cidr': { type: 'string' },
      'tun-mtu': { type: 'string' },
      'tun-default-route': { type: 'boolean', default: false },
      'no-tun-config': { type: 'boolean', default: false },
      key: { type: 'string', short: 'k' },
      hop: { type: 'string', multiple: true, default: [] },
      exit: { type: 'string', short: 'e' },
      pool: { type: 'string', default: '2' },
      'no-mux': { type: 'boolean', default: false },
      'tls-ca': { type: 'string' },
      'tls-sni': { type: 'string' },
      'tls-insecure': { type: 'boolean', default: false },
      quiet: { type: 'boolean', short: 'q', default: false },
      help: { type: 'boolean', short: 'h', default: false },
    },
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }
  if (!values.key || !values.exit) {
    die('client requires -k <client.key> and --exit <endpoint>,<exit.pub>');
  }

  const enableHttp = !values['no-http'];
  const enableSocks = Boolean(values.socks);
  const enableTun = Boolean(values.tun);
  if (!enableHttp && !enableSocks && !enableTun) {
    die('No local ingress enabled: remove --no-http, or specify --socks <ep> and/or --tun <ifname>');
  }

  const log = (...a) => { if (!values.quiet) console.error(...a); };
  const hops = values.hop.map((s) => parseHopSpec(s, '--hop'));
  const exit = parseHopSpec(values.exit, '--exit');

  const useMux = !values['no-mux'];
  const poolSize = Math.max(1, Number(values.pool) || 2);

  // Share one persistent MuxCircuitPool across HTTP, SOCKS5 (+UDP), and TUN ingresses
  const sharedPool = (useMux || enableSocks || enableTun)
    ? new MuxCircuitPool({
        key: values.key,
        mode: values.mode,
        hops,
        exit,
        poolSize,
        tlsCa: values['tls-ca'],
        tlsServername: values['tls-sni'],
        tlsInsecure: values['tls-insecure'],
        onSessionOpen: ({ slot, mode, hopCount }) => {
          log(`[proxy-client:${mode}] Persistent mux circuit #${slot + 1} established (${hopCount} relays)`);
        },
      })
    : null;

  const closers = [];

  if (enableHttp) {
    const httpProxy = createLocalHttpProxy({
      key: values.key,
      mode: values.mode,
      mux: useMux,
      pool: useMux ? sharedPool : null,
      hops,
      exit,
      tlsCa: values['tls-ca'],
      tlsServername: values['tls-sni'],
      tlsInsecure: values['tls-insecure'],
      onRequest: ({ mode, mux, method, host, port, hopCount }) => {
        log(`[proxy-client:${mode}${mux ? ':mux' : ''}] ${method} ${host}:${port} via ${hopCount} relay(s) + exit`);
      },
      onError: (err) => log(`[proxy-client:http] Circuit error: ${formatError(err)}`),
    });

    httpProxy.listen(values.listen, () => {
      const muxInfo = useMux ? `mux-pool=${poolSize}` : 'mux=off';
      log(`[proxy-client] Local HTTP/HTTPS proxy on ${formatEndpoint(httpProxy.server.address())} | mode=${values.mode} | ${muxInfo} | hops=${hops.length}`);
    });
    closers.push((cb) => httpProxy.close(cb));
  }

  if (enableSocks) {
    const socksProxy = createLocalSocks5Proxy({
      key: values.key,
      mode: values.mode,
      mux: useMux,
      pool: sharedPool,
      hops,
      exit,
      tlsCa: values['tls-ca'],
      tlsServername: values['tls-sni'],
      tlsInsecure: values['tls-insecure'],
      onRequest: ({ mode, mux, method, host, port, hopCount }) => {
        log(`[proxy-client:${mode}${mux ? ':mux' : ''}] ${method} ${host}:${port} via ${hopCount} relay(s) + exit`);
      },
      onError: (err) => log(`[proxy-client:socks5] Circuit error: ${formatError(err)}`),
    });

    socksProxy.listen(values.socks, () => {
      log(`[proxy-client] Local SOCKS5 (+UDP) proxy on ${formatEndpoint(socksProxy.server.address())} | mode=${values.mode} | hops=${hops.length}`);
    });
    closers.push((cb) => socksProxy.close(cb));
  }

  if (enableTun) {
    const localTun = await createLocalTun({
      ifname: values.tun,
      cidr: values['tun-cidr'] || null,
      mtu: values['tun-mtu'] ? Number(values['tun-mtu']) : null,
      configure: !values['no-tun-config'],
      defaultRoute: Boolean(values['tun-default-route']),
      key: values.key,
      mode: values.mode,
      pool: sharedPool,
      hops,
      exit,
      tlsCa: values['tls-ca'],
      tlsServername: values['tls-sni'],
      tlsInsecure: values['tls-insecure'],
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

const [role, ...rest] = process.argv.slice(2);
if (!role || role === '-h' || role === '--help' || role === 'help') {
  console.log(HELP);
  process.exit(0);
}

(async () => {
  try {
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
