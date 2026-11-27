import fs from 'node:fs';
import path from 'node:path';
import {
  loadJsonConfig,
  resolveEndpointFromConfig,
  resolveKeySpecFromConfig,
  resolvePathFromConfig,
} from './tunnel.mjs';

export function parseHopEntry(entry, baseDir = null, label = 'hop') {
  if (!entry) {
    throw new Error(`Empty ${label} specification`);
  }

  if (typeof entry === 'string') {
    const commaIdx = entry.indexOf(',');
    if (commaIdx === -1) {
      throw new Error(`Invalid ${label} "${entry}" (expected "<endpoint>,<pubkey>" or { endpoint, publicKey })`);
    }
    const endpoint = entry.slice(0, commaIdx).trim();
    const publicKey = entry.slice(commaIdx + 1).trim();
    if (!endpoint || !publicKey) {
      throw new Error(`Invalid ${label} "${entry}" (expected "<endpoint>,<pubkey>")`);
    }
    return {
      endpoint: baseDir ? resolveEndpointFromConfig(endpoint, baseDir) : endpoint,
      publicKey: baseDir ? resolveKeySpecFromConfig(publicKey, baseDir) : publicKey,
    };
  }

  if (typeof entry === 'object') {
    const endpoint = String(entry.endpoint || '').trim();
    const rawPub = entry.publicKey ?? entry.pub ?? entry.publicKeys;
    if (!endpoint || !rawPub) {
      throw new Error(`Invalid ${label} object in config: requires "endpoint" and "publicKey"`);
    }
    return {
      endpoint: baseDir ? resolveEndpointFromConfig(endpoint, baseDir) : endpoint,
      publicKey: baseDir ? resolveKeySpecFromConfig(rawPub, baseDir) : rawPub,
    };
  }

  throw new Error(`Invalid ${label} entry type: ${typeof entry}`);
}

function resolveRouteListFromConfig(spec, baseDir) {
  if (!spec) return [];
  const items = Array.isArray(spec) ? spec : [spec];
  const out = [];
  for (const raw of items) {
    const str = String(raw || '').trim();
    if (!str) continue;
    if (str.startsWith('./') || str.startsWith('../')) {
      out.push(path.resolve(baseDir, str));
      continue;
    }
    const candidate = path.resolve(baseDir, str);
    if (!str.startsWith('/') && fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
      out.push(candidate);
      continue;
    }
    out.push(str);
  }
  return out;
}

export function extractConfigFlag(argv) {
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if ((arg === '-c' || arg === '--config') && argv[i + 1]) {
      return argv[i + 1];
    }
    if (arg.startsWith('--config=')) {
      return arg.slice('--config='.length);
    }
  }
  return null;
}

export function loadProxyRoleConfig(configPath) {
  const { config, baseDir } = loadJsonConfig(configPath);
  const role = config.role ? String(config.role).trim().toLowerCase() : null;
  const tlsBlock = config.tls && typeof config.tls === 'object' ? config.tls : {};

  if (role === 'relay') {
    return {
      role: 'relay',
      mode: config.mode,
      listen: resolveEndpointFromConfig(config.listen, baseDir),
      key: resolvePathFromConfig(config.key, baseDir),
      auth: resolveKeySpecFromConfig(config.auth ?? config.authorizedKeys, baseDir),
      open: config.open !== undefined ? Boolean(config.open) : undefined,
      next: config.next ? parseHopEntry(config.next, baseDir, 'next') : null,
      tlsCert: resolvePathFromConfig(config.tlsCert ?? tlsBlock.cert, baseDir),
      tlsKey: resolvePathFromConfig(config.tlsKey ?? tlsBlock.key, baseDir),
      fallback: resolveEndpointFromConfig(config.fallback, baseDir),
      quiet: config.quiet !== undefined ? Boolean(config.quiet) : undefined,
    };
  }

  if (role === 'exit') {
    let tun = null;
    if (config.tun === true || typeof config.tun === 'string') {
      tun = {
        enabled: true,
        name: typeof config.tun === 'string' ? config.tun : 'st0',
      };
    } else if (config.tun && typeof config.tun === 'object') {
      tun = {
        enabled: config.tun.enabled !== undefined ? Boolean(config.tun.enabled) : true,
        name: config.tun.name || config.tun.ifname || 'st0',
        cidr: config.tun.cidr,
        mtu: config.tun.mtu !== undefined ? Number(config.tun.mtu) : undefined,
        nat: config.tun.nat !== undefined ? Boolean(config.tun.nat) : undefined,
        configure: config.tun.configure !== undefined ? Boolean(config.tun.configure) : undefined,
      };
    }

    return {
      role: 'exit',
      mode: config.mode,
      listen: resolveEndpointFromConfig(config.listen, baseDir),
      key: resolvePathFromConfig(config.key, baseDir),
      auth: resolveKeySpecFromConfig(config.auth ?? config.authorizedKeys, baseDir),
      open: config.open !== undefined ? Boolean(config.open) : undefined,
      udp: config.udp !== undefined ? Boolean(config.udp) : undefined,
      tun,
      tlsCert: resolvePathFromConfig(config.tlsCert ?? tlsBlock.cert, baseDir),
      tlsKey: resolvePathFromConfig(config.tlsKey ?? tlsBlock.key, baseDir),
      fallback: resolveEndpointFromConfig(config.fallback, baseDir),
      quiet: config.quiet !== undefined ? Boolean(config.quiet) : undefined,
    };
  }

  if (role === 'client' || !role) {
    // HTTP ingress: string endpoint, true (default 127.0.0.1:8080), or false/null (disabled)
    const rawHttp = config.http !== undefined ? config.http : config.listen;
    let http = undefined;
    if (rawHttp === false || rawHttp === null) {
      http = false;
    } else if (rawHttp === true) {
      http = '127.0.0.1:8080';
    } else if (typeof rawHttp === 'string' && rawHttp.trim()) {
      http = resolveEndpointFromConfig(rawHttp, baseDir);
    }

    // SOCKS5 ingress: string endpoint, { listen, auth }, or false/null
    let socks = undefined;
    let socksAuth = null;
    if (config.socks === false || config.socks === null) {
      socks = false;
    } else if (typeof config.socks === 'string' && config.socks.trim()) {
      socks = resolveEndpointFromConfig(config.socks, baseDir);
    } else if (config.socks && typeof config.socks === 'object') {
      if (config.socks.enabled !== false && config.socks.listen) {
        socks = resolveEndpointFromConfig(config.socks.listen, baseDir);
        socksAuth = config.socks.auth || null;
      } else {
        socks = false;
      }
    }

    // TUN ingress: false/null, string "st0", or { enabled, name, cidr, mtu, defaultRoute, exclude, routes, configure }
    let tun = null;
    if (config.tun === true || typeof config.tun === 'string') {
      tun = {
        enabled: true,
        name: typeof config.tun === 'string' ? config.tun : 'st0',
      };
    } else if (config.tun && typeof config.tun === 'object') {
      tun = {
        enabled: config.tun.enabled !== undefined ? Boolean(config.tun.enabled) : true,
        name: config.tun.name || config.tun.ifname || 'st0',
        cidr: config.tun.cidr || null,
        mtu: config.tun.mtu !== undefined && config.tun.mtu !== null ? Number(config.tun.mtu) : null,
        defaultRoute: config.tun.defaultRoute !== undefined ? Boolean(config.tun.defaultRoute) : false,
        configure: config.tun.configure !== undefined ? Boolean(config.tun.configure) : true,
        exclude: resolveRouteListFromConfig(config.tun.exclude, baseDir),
        routes: resolveRouteListFromConfig(config.tun.routes, baseDir),
      };
    }

    const hops = Array.isArray(config.hops)
      ? config.hops.map((h, idx) => parseHopEntry(h, baseDir, `hops[${idx}]`))
      : undefined;
    const exit = config.exit ? parseHopEntry(config.exit, baseDir, 'exit') : undefined;

    return {
      role: role || null,
      mode: config.mode,
      key: resolvePathFromConfig(config.key, baseDir),
      pool: config.pool !== undefined ? Number(config.pool) : undefined,
      mux: config.mux !== undefined ? Boolean(config.mux) : undefined,
      http,
      socks,
      socksAuth,
      tun,
      hops,
      exit,
      tlsCa: resolvePathFromConfig(config.tlsCa ?? tlsBlock.ca, baseDir),
      tlsSni: config.tlsSni ?? tlsBlock.sni,
      tlsInsecure: (config.tlsInsecure ?? tlsBlock.insecure) !== undefined
        ? Boolean(config.tlsInsecure ?? tlsBlock.insecure)
        : undefined,
      quiet: config.quiet !== undefined ? Boolean(config.quiet) : undefined,
    };
  }

  throw new Error(`Unknown role "${config.role}" in ${configPath} (expected "client", "relay", or "exit")`);
}
