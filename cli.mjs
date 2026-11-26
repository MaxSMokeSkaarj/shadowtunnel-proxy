#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import { parseArgs } from 'node:util';
import { formatEndpoint, formatError, generateIdentity } from './tunnel.mjs';
import {
  createExitServer,
  createLocalHttpProxy,
  createRelayServer,
} from './onion.mjs';

const HELP = `Usage:
  node cli.mjs <role> [options]

Roles:
  keygen   Generate an Ed25519 identity keypair (<out>.key + <out>.pub)
  relay    Run an intermediate repeater/relay (--mode onion | ptp | both)
  exit     Run the exit HTTP/HTTPS proxy server
  client   Run local HTTP/HTTPS proxy (--mode onion | ptp)

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
  -l, --listen <endpoint>  Listen address (e.g. :6001 or 0.0.0.0:6001)
  -k, --key <file>         Relay private key (.key)
  -a, --auth <file>        Authorized upstream keys (authorized_keys or .pub)
      --open               Allow any valid Ed25519 peer without whitelist
      --next <ep>,<pub>    Static PTP mode: always forward into fixed next hop/exit
  -q, --quiet              Suppress informational logs

Options (exit):
  -m, --mode <mode>        Exit mode label: onion | ptp | both (default: both)
  -l, --listen <endpoint>  Listen address (e.g. :6009)
  -k, --key <file>         Exit private key (.key)
  -a, --auth <file>        Authorized keys (client.pub for onion, last-relay.pub for ptp)
      --open               Allow any valid Ed25519 peer without whitelist
  -q, --quiet              Suppress informational logs

Options (client):
  -m, --mode <mode>        Circuit mode: onion | ptp (default: onion)
  -l, --listen <endpoint>  Local HTTP/HTTPS proxy address (default: 127.0.0.1:8080)
  -k, --key <file>         Client private key (.key)
      --hop <ep>,<pub>     Intermediate relay (repeatable: 0..N relays)
  -e, --exit <ep>,<pub>    Exit server (or first static repeater when relays use --next)
  -q, --quiet              Suppress informational logs

Examples:
  # A) ONION mode (relays see only ciphertext; Exit authenticates Client directly):
  node cli.mjs relay  -m onion -l 127.0.0.1:6001 -k ./keys/r1.key --open
  node cli.mjs relay  -m onion -l 127.0.0.1:6002 -k ./keys/r2.key --open
  node cli.mjs exit            -l 127.0.0.1:6009 -k ./keys/exit.key -a ./keys/client.pub
  node cli.mjs client -m onion -l 127.0.0.1:8080 -k ./keys/client.key \\
    --hop 127.0.0.1:6001,./keys/r1.pub \\
    --hop 127.0.0.1:6002,./keys/r2.pub \\
    --exit 127.0.0.1:6009,./keys/exit.pub

  # B) PTP Dynamic mode (1 cipher layer per link; each node authenticates its immediate neighbor):
  node cli.mjs relay  -m ptp -l 127.0.0.1:6001 -k ./keys/r1.key -a ./keys/client.pub
  node cli.mjs relay  -m ptp -l 127.0.0.1:6002 -k ./keys/r2.key -a ./keys/r1.pub
  node cli.mjs exit          -l 127.0.0.1:6009 -k ./keys/exit.key -a ./keys/r2.pub
  node cli.mjs client -m ptp -l 127.0.0.1:8080 -k ./keys/client.key \\
    --hop 127.0.0.1:6001,./keys/r1.pub \\
    --hop 127.0.0.1:6002,./keys/r2.pub \\
    --exit 127.0.0.1:6009,./keys/exit.pub

  # C) PTP Static Bridge mode (Client only knows Relay 1; repeaters wired via --next):
  node cli.mjs relay  -m ptp -l 127.0.0.1:6001 -k ./keys/r1.key -a ./keys/client.pub --next 127.0.0.1:6002,./keys/r2.pub
  node cli.mjs relay  -m ptp -l 127.0.0.1:6002 -k ./keys/r2.key -a ./keys/r1.pub     --next 127.0.0.1:6009,./keys/exit.pub
  node cli.mjs exit          -l 127.0.0.1:6009 -k ./keys/exit.key -a ./keys/r2.pub
  node cli.mjs client -m ptp -l 127.0.0.1:8080 -k ./keys/client.key --exit 127.0.0.1:6001,./keys/r1.pub
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

  const server = createRelayServer({
    key: values.key,
    mode: effectiveMode,
    nextHop,
    authorizedKeys: values.auth || null,
    allowAnyClient: Boolean(values.open),
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
  if (!['onion', 'ptp', 'both'].includes(values.mode)) {
    die(`Invalid exit --mode "${values.mode}" (expected onion, ptp, or both)`);
  }

  const log = (...a) => { if (!values.quiet) console.error(...a); };

  const server = createExitServer({
    key: values.key,
    authorizedKeys: values.auth || null,
    allowAnyClient: Boolean(values.open),
    onExitRequest: ({ peerFingerprint, peerComment, target }) => {
      const who = peerComment ? `${peerComment} (${peerFingerprint})` : peerFingerprint;
      log(`[exit] ${who} -> ${target}`);
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

function runClient(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      mode: { type: 'string', short: 'm', default: 'onion' },
      listen: { type: 'string', short: 'l', default: '127.0.0.1:8080' },
      key: { type: 'string', short: 'k' },
      hop: { type: 'string', multiple: true, default: [] },
      exit: { type: 'string', short: 'e' },
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

  const log = (...a) => { if (!values.quiet) console.error(...a); };
  const hops = values.hop.map((s) => parseHopSpec(s, '--hop'));
  const exit = parseHopSpec(values.exit, '--exit');

  const proxy = createLocalHttpProxy({
    key: values.key,
    mode: values.mode,
    hops,
    exit,
    onRequest: ({ mode, method, host, port, hopCount }) => {
      log(`[proxy-client:${mode}] ${method} ${host}:${port} via ${hopCount} relay(s) + exit`);
    },
    onError: (err) => {
      log(`[proxy-client] Circuit error: ${formatError(err)}`);
    },
  });

  proxy.listen(values.listen, () => {
    log(`[proxy-client] Local HTTP/HTTPS proxy on ${formatEndpoint(proxy.server.address())} | mode=${values.mode} | hops=${hops.length}`);
  });

  const stop = () => proxy.close(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

const [role, ...rest] = process.argv.slice(2);
if (!role || role === '-h' || role === '--help' || role === 'help') {
  console.log(HELP);
  process.exit(0);
}

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
      runClient(rest);
      break;
    default:
      die(`Unknown role "${role}"`);
  }
} catch (err) {
  die(err.message);
}
