import { execFileSync, spawnSync } from 'node:child_process';
import dgram from 'node:dgram';
import dns from 'node:dns';
import { EventEmitter } from 'node:events';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import {
  loadAuthorizedKeys,
  loadPrivateKey,
  parseEndpoint,
} from '../tunnel.mjs';
import { formatErrMessage, ipv4ToBytes } from '../protocol.mjs';
import { getMode } from '../modes/index.mjs';
import { MuxCircuitPool } from '../pool.mjs';

// Linux <linux/if_tun.h> constants (x86_64, arm64, arm, x86, riscv64)
const TUNSETIFF = 0x400454ca;
const IFF_TUN_NO_PI = 0x1001; // IFF_TUN (0x0001) | IFF_NO_PI (0x1000)
const DEFAULT_MAX_QUEUE_BYTES = 1024 * 1024;

export function ipv4ToUint32(ip) {
  const b = ipv4ToBytes(ip);
  return b.readUInt32BE(0);
}

export function uint32ToIpv4(u32) {
  return `${(u32 >>> 24) & 0xff}.${(u32 >>> 16) & 0xff}.${(u32 >>> 8) & 0xff}.${u32 & 0xff}`;
}

export function parseIpv4Cidr(cidrStr) {
  const [ipPart, prefixPart] = String(cidrStr).trim().split('/');
  const prefixLen = prefixPart !== undefined ? Number(prefixPart) : 24;
  if (!Number.isInteger(prefixLen) || prefixLen < 8 || prefixLen > 30) {
    throw new Error(`Invalid TUN CIDR prefix "/${prefixPart}" (expected /8../30)`);
  }
  const ipUint32 = ipv4ToUint32(ipPart);
  const maskUint32 = prefixLen === 0 ? 0 : ((0xffffffff << (32 - prefixLen)) >>> 0);
  const networkUint32 = (ipUint32 & maskUint32) >>> 0;
  const broadcastUint32 = (networkUint32 | (~maskUint32 >>> 0)) >>> 0;
  return {
    ip: uint32ToIpv4(ipUint32),
    ipUint32,
    prefixLen,
    maskUint32,
    networkUint32,
    broadcastUint32,
    subnetCidr: `${uint32ToIpv4(networkUint32)}/${prefixLen}`,
  };
}

function attachTunFdViaSystemIoctl(fd, requestedIfname) {
  if (!/^[a-zA-Z0-9_.-]{0,15}$/.test(requestedIfname)) {
    throw new Error(`Invalid TUN interface name "${requestedIfname}" (max 15 safe chars)`);
  }

  // Pass the already-opened /dev/net/tun file descriptor as fd 3 to a one-shot helper.
  // Because fork/dup2 shares the underlying kernel `struct file`, ioctl(3, TUNSETIFF)
  // binds our Node.js fd directly and exits in ~5ms with zero background child processes.
  const pyCode = [
    'import fcntl,struct,sys',
    `r=fcntl.ioctl(3,${TUNSETIFF},struct.pack("16sH",sys.argv[1].encode(),${IFF_TUN_NO_PI}))`,
    'sys.stdout.write(r[:16].split(b"\\0")[0].decode())',
  ].join(';');

  let res = spawnSync('python3', ['-c', pyCode, requestedIfname], {
    stdio: ['ignore', 'pipe', 'pipe', fd],
  });

  if (res.error && res.error.code === 'ENOENT') {
    const perlCode = [
      `my $ifr = pack("a16S", $ARGV[0], ${IFF_TUN_NO_PI});`,
      'open(my $fh, "+<&=", 3) or die $!;',
      `ioctl($fh, ${TUNSETIFF}, $ifr) or die $!;`,
      'my ($n) = unpack("Z16", $ifr); print $n;',
    ].join(' ');
    res = spawnSync('perl', ['-e', perlCode, requestedIfname], {
      stdio: ['ignore', 'pipe', 'pipe', fd],
    });
  }

  if (res.error) {
    throw new Error(`Cannot invoke python3 or perl for TUN ioctl(TUNSETIFF): ${res.error.message}`);
  }
  if (res.status !== 0) {
    const stderr = (res.stderr ? res.stderr.toString('utf8') : '').trim();
    if (/EPERM|Operation not permitted/i.test(stderr)) {
      const nameHint = requestedIfname || 'st0';
      throw new Error(
        `Permission denied opening TUN "${nameHint}" (EPERM). Run with sudo / CAP_NET_ADMIN, or pre-create once:\n` +
        `  sudo ip tuntap add dev ${nameHint} mode tun user $(whoami) && sudo ip link set ${nameHint} up`,
      );
    }
    throw new Error(`TUNSETIFF failed on "${requestedIfname}": ${stderr || `exit ${res.status}`}`);
  }

  return res.stdout.toString('utf8').trim() || requestedIfname;
}

export function openTunDevice(ifname = 'st0', options = {}) {
  if (process.platform !== 'linux') {
    throw new Error(
      `TUN mode requires Linux (/dev/net/tun), current platform is "${process.platform}". Use --socks for cross-platform TCP+UDP.`,
    );
  }

  const { onPacket = null } = options;
  const fd = fs.openSync('/dev/net/tun', 'r+');
  let actualName;
  try {
    actualName = attachTunFdViaSystemIoctl(fd, ifname);
  } catch (err) {
    try { fs.closeSync(fd); } catch {}
    throw err;
  }

  const emitter = new EventEmitter();
  let closed = false;
  let fdClosed = false;
  let reading = false;
  let wakeupIp = null;
  let closeWaiters = [];

  const finalizeFdClose = () => {
    if (fdClosed) return;
    fdClosed = true;
    try { fs.closeSync(fd); } catch {}
    const waiters = closeWaiters;
    closeWaiters = [];
    for (const fn of waiters) fn();
    emitter.emit('close');
  };

  const readBuf = Buffer.allocUnsafe(65536);
  const readLoop = () => {
    if (closed) {
      finalizeFdClose();
      return;
    }
    reading = true;
    fs.read(fd, readBuf, 0, readBuf.length, null, (err, bytesRead) => {
      reading = false;
      if (closed) {
        finalizeFdClose();
        return;
      }
      if (err) {
        if (err.code === 'EAGAIN' || err.code === 'EINTR') {
          setImmediate(readLoop);
          return;
        }
        if (emitter.listenerCount('error') > 0) {
          emitter.emit('error', err);
        }
        return;
      }
      if (bytesRead > 0) {
        const pkt = Buffer.allocUnsafe(bytesRead);
        readBuf.copy(pkt, 0, 0, bytesRead);
        if (typeof onPacket === 'function') onPacket(pkt);
        emitter.emit('packet', pkt);
      }
      readLoop();
    });
  };

  readLoop();

  return {
    name: actualName,
    fd,
    events: emitter,
    configure({ ip, prefixLen = 24, mtu = 1400 }) {
      const parsed = parseIpv4Cidr(`${ip}/${prefixLen}`);
      execFileSync('ip', ['addr', 'replace', `${parsed.ip}/${parsed.prefixLen}`, 'dev', actualName]);
      execFileSync('ip', ['link', 'set', 'dev', actualName, 'mtu', String(mtu), 'up']);
      const firstHost = (parsed.networkUint32 + 1) >>> 0;
      const lastHost = (parsed.broadcastUint32 - 1) >>> 0;
      wakeupIp = parsed.ipUint32 === firstHost ? uint32ToIpv4(lastHost) : uint32ToIpv4(firstHost);
    },
    write(packet) {
      if (closed || fdClosed || packet.length === 0) return false;
      fs.write(fd, packet, 0, packet.length, null, () => {});
      return true;
    },
    close(cb) {
      if (typeof cb === 'function') {
        if (fdClosed) {
          queueMicrotask(cb);
          return;
        }
        closeWaiters.push(cb);
      }
      if (closed) return;
      closed = true;

      if (!reading) {
        finalizeFdClose();
        return;
      }

      // Wake up kernel tun_chr_read_iter immediately by nudging a routed peer IP inside the TUN subnet
      if (wakeupIp) {
        try {
          const poke = dgram.createSocket('udp4');
          poke.send(Buffer.from([0]), 9, wakeupIp, () => {
            try { poke.close(); } catch {}
          });
        } catch {}
      }

      const timer = setTimeout(() => {
        finalizeFdClose();
      }, 60);
      timer.unref?.();
    },
  };
}

function setupLinuxExitNat(subnetCidr, tunName) {
  execFileSync('sysctl', ['-w', 'net.ipv4.ip_forward=1'], { stdio: 'ignore' });

  // Prefer native nftables first (atomic isolated table, no global /run/xtables.lock contention);
  // fall back to iptables if nft is unavailable or kernel lacks nf_tables.
  const tableName = `shadowtunnel_${tunName.replace(/[^a-zA-Z0-9_]/g, '_')}`;
  const nftScript = [
    `add table ip ${tableName}`,
    `flush table ip ${tableName}`,
    `add chain ip ${tableName} postrouting { type nat hook postrouting priority 100 ; }`,
    `add rule ip ${tableName} postrouting ip saddr ${subnetCidr} ip daddr != ${subnetCidr} masquerade`,
    `add chain ip ${tableName} forward { type filter hook forward priority 0 ; }`,
    `add rule ip ${tableName} forward iifname "${tunName}" accept`,
    `add rule ip ${tableName} forward oifname "${tunName}" accept`,
  ].join('\n');

  const nftRes = spawnSync('nft', ['-f', '-'], { input: `${nftScript}\n`, stdio: ['pipe', 'ignore', 'pipe'] });
  if (!nftRes.error && nftRes.status === 0) {
    return () => {
      spawnSync('nft', ['delete', 'table', 'ip', tableName], { stdio: 'ignore' });
    };
  }

  const cleanupTasks = [];
  const iptEnv = {
    ...process.env,
    XTABLES_LOCKFILE: process.env.XTABLES_LOCKFILE || path.join(os.tmpdir(), `xtables-${process.pid}.lock`),
  };
  const natArgs = ['-t', 'nat', 'POSTROUTING', '-s', subnetCidr, '!', '-d', subnetCidr, '-j', 'MASQUERADE'];
  if (spawnSync('iptables', ['-t', 'nat', '-C', ...natArgs.slice(2)], { stdio: 'ignore', env: iptEnv }).status !== 0) {
    execFileSync('iptables', ['-t', 'nat', '-A', ...natArgs.slice(2)], { env: iptEnv });
    cleanupTasks.push(() => {
      spawnSync('iptables', ['-t', 'nat', '-D', ...natArgs.slice(2)], { stdio: 'ignore', env: iptEnv });
    });
  }
  if (spawnSync('iptables', ['-C', 'FORWARD', '-i', tunName, '-j', 'ACCEPT'], { stdio: 'ignore', env: iptEnv }).status !== 0) {
    execFileSync('iptables', ['-I', 'FORWARD', '1', '-i', tunName, '-j', 'ACCEPT'], { env: iptEnv });
    cleanupTasks.push(() => {
      spawnSync('iptables', ['-D', 'FORWARD', '-i', tunName, '-j', 'ACCEPT'], { stdio: 'ignore', env: iptEnv });
    });
  }
  if (spawnSync('iptables', ['-C', 'FORWARD', '-o', tunName, '-j', 'ACCEPT'], { stdio: 'ignore', env: iptEnv }).status !== 0) {
    execFileSync('iptables', ['-I', 'FORWARD', '1', '-o', tunName, '-j', 'ACCEPT'], { env: iptEnv });
    cleanupTasks.push(() => {
      spawnSync('iptables', ['-D', 'FORWARD', '-o', tunName, '-j', 'ACCEPT'], { stdio: 'ignore', env: iptEnv });
    });
  }
  return () => {
    for (const fn of cleanupTasks.reverse()) {
      try { fn(); } catch {}
    }
  };
}

export function createExitTunGateway(options = {}) {
  const {
    ifname = 'st0',
    cidr = '10.99.0.1/24',
    mtu = 1400,
    configure = true,
    enableNat = false,
    maxQueueBytes = DEFAULT_MAX_QUEUE_BYTES,
  } = options;

  const parsedCidr = parseIpv4Cidr(cidr);
  const gatewayIpUint32 = parsedCidr.ipUint32;
  const gatewayIp = parsedCidr.ip;
  const prefixLen = parsedCidr.prefixLen;
  const minClientUint32 = (parsedCidr.networkUint32 + 1) >>> 0;
  // Reserve broadcast - 1 (e.g. .254) for local close wakeup poke
  const maxClientUint32 = (parsedCidr.broadcastUint32 - 2) >>> 0;

  if (maxClientUint32 <= minClientUint32) {
    throw new Error(`TUN subnet ${cidr} is too small for client IP pool (use /29 or larger, e.g. /24)`);
  }

  const clientsByIp = new Map(); // clientIpUint32 -> binding
  let nextCursor = minClientUint32;
  let cleanupNat = null;

  const tun = openTunDevice(ifname, {
    onPacket: (pkt) => {
      if (pkt.length < 20 || (pkt[0] >> 4) !== 4) return;
      const dstIpUint32 = pkt.readUInt32BE(16);
      const binding = clientsByIp.get(dstIpUint32);
      if (!binding || binding.closed || binding.session.isClosed) return;
      if (binding.session.carrier.writableLength > maxQueueBytes) return;
      binding.session.sendDatagram(binding.channelId, pkt);
    },
  });

  try {
    if (configure) {
      tun.configure({ ip: gatewayIp, prefixLen, mtu });
    }
    if (enableNat) {
      cleanupNat = setupLinuxExitNat(parsedCidr.subnetCidr, tun.name);
    }
  } catch (err) {
    tun.close();
    throw err;
  }

  function isAssignableClientIp(ipU32) {
    return (
      ipU32 >= minClientUint32 &&
      ipU32 <= maxClientUint32 &&
      ipU32 !== gatewayIpUint32
    );
  }

  function allocateClientIp(requestedIp, peerFingerprint) {
    if (requestedIp && net.isIP(requestedIp) === 4) {
      const reqU32 = ipv4ToUint32(requestedIp);
      if (isAssignableClientIp(reqU32)) {
        const existing = clientsByIp.get(reqU32);
        if (!existing || existing.closed || existing.peerFingerprint === peerFingerprint) {
          if (existing) existing.detach();
          return reqU32;
        }
      }
    }

    const total = (maxClientUint32 - minClientUint32) + 1;
    for (let i = 0; i < total; i++) {
      const candidate = minClientUint32 + ((nextCursor - minClientUint32 + i) % total);
      if (!isAssignableClientIp(candidate)) continue;
      const existing = clientsByIp.get(candidate);
      if (!existing || existing.closed) {
        nextCursor = minClientUint32 + ((candidate - minClientUint32 + 1) % total);
        return candidate;
      }
    }
    throw new Error(`TUN subnet ${parsedCidr.subnetCidr} has no free client IPs available`);
  }

  return {
    name: tun.name,
    gatewayIp,
    prefixLen,
    subnetCidr: parsedCidr.subnetCidr,
    mtu,
    attachClient(muxSession, stream, parsedMeta, peerInfo) {
      const clientIpUint32 = allocateClientIp(parsedMeta?.requestedIp, peerInfo?.peerFingerprint);
      const clientIp = uint32ToIpv4(clientIpUint32);

      const binding = {
        clientIp,
        clientIpUint32,
        gatewayIp,
        prefixLen,
        mtu,
        channelId: stream.id,
        session: muxSession,
        peerFingerprint: peerInfo?.peerFingerprint || null,
        closed: false,
        handlePacket(pkt) {
          if (this.closed || pkt.length < 20 || (pkt[0] >> 4) !== 4) return;
          // Anti-spoofing: strictly enforce client source IPv4 matches its leased TUN IP
          const srcIpUint32 = pkt.readUInt32BE(12);
          if (srcIpUint32 !== clientIpUint32) return;
          tun.write(pkt);
        },
        detach() {
          if (this.closed) return;
          this.closed = true;
          if (clientsByIp.get(clientIpUint32) === this) {
            clientsByIp.delete(clientIpUint32);
          }
        },
      };

      clientsByIp.set(clientIpUint32, binding);
      stream.once('close', () => binding.detach());
      stream.once('end', () => binding.detach());
      muxSession.once('close', () => binding.detach());

      return binding;
    },
    close(cb) {
      for (const b of clientsByIp.values()) {
        b.detach();
      }
      clientsByIp.clear();
      if (cleanupNat) {
        try { cleanupNat(); } catch {}
        cleanupNat = null;
      }
      tun.close(cb);
    },
  };
}

async function installClientDefaultRoute(tunName, gatewayIp, entryEndpoint) {
  const ep = parseEndpoint(entryEndpoint, '');
  if (!ep.host) return () => {};
  const resolved = net.isIP(ep.host) ? { address: ep.host } : await dns.promises.lookup(ep.host, { family: 4 });
  const entryIp = resolved.address;

  const cleanup = [];
  if (!entryIp.startsWith('127.')) {
    const routeOut = execFileSync('ip', ['-4', 'route', 'get', entryIp]).toString('utf8');
    const viaMatch = routeOut.match(/\bvia\s+(\S+)/);
    const devMatch = routeOut.match(/\bdev\s+(\S+)/);
    if (devMatch && devMatch[1] !== tunName) {
      const args = ['route', 'replace', `${entryIp}/32`];
      if (viaMatch) args.push('via', viaMatch[1]);
      args.push('dev', devMatch[1]);
      execFileSync('ip', args);
      cleanup.push(() => {
        spawnSync('ip', ['route', 'del', `${entryIp}/32`], { stdio: 'ignore' });
      });
    }
  }

  execFileSync('ip', ['route', 'replace', '0.0.0.0/1', 'via', gatewayIp, 'dev', tunName]);
  execFileSync('ip', ['route', 'replace', '128.0.0.0/1', 'via', gatewayIp, 'dev', tunName]);
  cleanup.push(() => {
    spawnSync('ip', ['route', 'del', '0.0.0.0/1', 'dev', tunName], { stdio: 'ignore' });
    spawnSync('ip', ['route', 'del', '128.0.0.0/1', 'dev', tunName], { stdio: 'ignore' });
  });

  return () => {
    for (const fn of cleanup.reverse()) {
      try { fn(); } catch {}
    }
  };
}

export async function createLocalTun(options = {}) {
  const {
    ifname = 'st0',
    cidr = null,
    mtu = null,
    configure = true,
    defaultRoute = false,
    key,
    mode = 'onion',
    pool = null,
    hops = [],
    exit,
    handshakeTimeoutMs = 10_000,
    maxQueueBytes = DEFAULT_MAX_QUEUE_BYTES,
    tlsCa = undefined,
    tlsServername = undefined,
    tlsInsecure = false,
    onConnect = null,
    onSessionOpen = null,
    onError = null,
  } = options;

  getMode(mode);

  let requestedIp = null;
  let staticPrefixLen = null;
  if (cidr) {
    const parsed = parseIpv4Cidr(cidr);
    requestedIp = parsed.ip;
    staticPrefixLen = parsed.prefixLen;
  }

  const ownsPool = !pool;
  const muxPool = pool || new MuxCircuitPool({
    key: loadPrivateKey(key),
    mode,
    hops: hops.map((h) => ({
      endpoint: h.endpoint,
      publicKey: loadAuthorizedKeys(h.publicKey),
    })),
    exit: {
      endpoint: exit.endpoint,
      publicKey: loadAuthorizedKeys(exit.publicKey),
    },
    poolSize: 1,
    handshakeTimeoutMs,
    tlsCa,
    tlsServername,
    tlsInsecure,
    onSessionOpen,
  });

  let activeChannel = null;
  let closed = false;
  let reconnectTimer = null;
  let cleanupRoutes = null;
  let configuredOnce = false;

  const tun = openTunDevice(ifname, {
    onPacket: (pkt) => {
      if (closed || !activeChannel) return;
      if (pkt.length < 20 || (pkt[0] >> 4) !== 4) return;
      activeChannel.sendPacket(pkt);
    },
  });

  async function establishChannel() {
    const ch = await muxPool.openTunChannel({
      requestedIp,
      maxQueueBytes,
      onPacket: (pkt) => {
        if (!closed && pkt.length >= 20 && (pkt[0] >> 4) === 4) {
          tun.write(pkt);
        }
      },
      onClose: () => {
        if (activeChannel === ch) {
          activeChannel = null;
          scheduleReconnect();
        }
      },
    });

    const assignedIp = ch.config.clientIp || requestedIp;
    const gatewayIp = ch.config.gatewayIp;
    const prefixLen = staticPrefixLen || ch.config.prefixLen || 24;
    const effectiveMtu = mtu || ch.config.mtu || 1400;

    if (!assignedIp) {
      ch.close();
      throw new Error('Exit server did not return a TUN client IP');
    }

    // Re-request the same IP across transient circuit reconnects
    requestedIp = assignedIp;
    activeChannel = ch;

    if (configure) {
      tun.configure({ ip: assignedIp, prefixLen, mtu: effectiveMtu });
    }
    if (defaultRoute && !configuredOnce && gatewayIp) {
      const entryEp = hops.length > 0 ? hops[0].endpoint : exit.endpoint;
      cleanupRoutes = await installClientDefaultRoute(tun.name, gatewayIp, entryEp);
    }
    configuredOnce = true;

    if (onConnect) {
      onConnect({
        ifname: tun.name,
        clientIp: assignedIp,
        gatewayIp,
        prefixLen,
        mtu: effectiveMtu,
      });
    }
    return {
      ifname: tun.name,
      clientIp: assignedIp,
      gatewayIp,
      prefixLen,
      mtu: effectiveMtu,
    };
  }

  function scheduleReconnect(delayMs = 500) {
    if (closed || reconnectTimer) return;
    reconnectTimer = setTimeout(async () => {
      reconnectTimer = null;
      if (closed || activeChannel) return;
      try {
        await establishChannel();
      } catch (err) {
        if (onError) onError(err);
        scheduleReconnect(Math.min(5_000, delayMs * 2));
      }
    }, delayMs);
    reconnectTimer.unref?.();
  }

  let initialInfo;
  try {
    initialInfo = await establishChannel();
  } catch (err) {
    tun.close();
    if (ownsPool) muxPool.close();
    throw new Error(`Failed to initialize TUN tunnel: ${formatErrMessage(err)}`);
  }

  return {
    ...initialInfo,
    pool: muxPool,
    close(cb) {
      closed = true;
      if (reconnectTimer) {
        clearTimeout(reconnectTimer);
        reconnectTimer = null;
      }
      if (cleanupRoutes) {
        try { cleanupRoutes(); } catch {}
        cleanupRoutes = null;
      }
      if (activeChannel) {
        activeChannel.close();
        activeChannel = null;
      }
      if (ownsPool) {
        muxPool.close();
      }
      tun.close(cb);
    },
  };
}
