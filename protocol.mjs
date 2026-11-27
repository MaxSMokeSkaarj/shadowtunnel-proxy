import net from 'node:net';

export const CMD_EXTEND = 0x52; // 'R' — Onion relay extend (blind TCP forward to next hop)
export const CMD_PTP_CHAIN = 0x50; // 'P' — Point-to-Point relay chain (decrypt & re-encrypt per hop)
export const CMD_EXIT_CONNECT = 0x45; // 'E' — Exit single-stream connect to target host:port
export const CMD_EXIT_MUX = 0x4d; // 'M' — Exit multiplexed session upgrade

export const ATYP_IPV4 = 0x01;
export const ATYP_DOMAIN = 0x03;
export const ATYP_IPV6 = 0x04;

export const STATUS_OK = 0x00;
export const STATUS_ERR = 0x01;
export const MAX_CMD_PAYLOAD = 8192;
export const MAX_CHAIN_HOPS = 32;

export function ipv4ToBytes(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) throw new Error(`Invalid IPv4 address: ${ip}`);
  const out = Buffer.allocUnsafe(4);
  for (let i = 0; i < 4; i++) {
    const n = Number(parts[i]);
    if (!Number.isInteger(n) || n < 0 || n > 255) {
      throw new Error(`Invalid IPv4 octet in ${ip}`);
    }
    out[i] = n;
  }
  return out;
}

export function bytesToIpv4(buf, offset = 0) {
  return `${buf[offset]}.${buf[offset + 1]}.${buf[offset + 2]}.${buf[offset + 3]}`;
}

export function ipv6ToBytes(ip) {
  let clean = ip.split('%')[0];
  if (clean.includes('.')) {
    const lastColon = clean.lastIndexOf(':');
    const v4Bytes = ipv4ToBytes(clean.slice(lastColon + 1));
    const hi = ((v4Bytes[0] << 8) | v4Bytes[1]).toString(16);
    const lo = ((v4Bytes[2] << 8) | v4Bytes[3]).toString(16);
    clean = `${clean.slice(0, lastColon + 1)}${hi}:${lo}`;
  }

  const halves = clean.split('::');
  if (halves.length > 2) throw new Error(`Invalid IPv6 address: ${ip}`);

  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const missing = 8 - (left.length + right.length);
  if ((halves.length === 1 && missing !== 0) || missing < 0) {
    throw new Error(`Invalid IPv6 address: ${ip}`);
  }

  const groups = [...left, ...Array(missing).fill('0'), ...right];
  const out = Buffer.allocUnsafe(16);
  for (let i = 0; i < 8; i++) {
    const val = parseInt(groups[i], 16);
    if (Number.isNaN(val) || val < 0 || val > 0xffff) {
      throw new Error(`Invalid IPv6 group in ${ip}`);
    }
    out.writeUInt16BE(val, i * 2);
  }
  return out;
}

export function bytesToIpv6(buf, offset = 0) {
  const groups = [];
  for (let i = 0; i < 8; i++) {
    groups.push(buf.readUInt16BE(offset + i * 2).toString(16));
  }
  return groups.join(':');
}

export function encodeUdpAddressHeader(host, port) {
  if (!Number.isInteger(port) || port < 0 || port > 65535) {
    throw new RangeError(`Invalid UDP port: ${port}`);
  }
  const cleanHost = host.startsWith('[') && host.endsWith(']') ? host.slice(1, -1) : host;
  const ipVer = net.isIP(cleanHost);

  if (ipVer === 4) {
    const out = Buffer.allocUnsafe(7);
    out[0] = ATYP_IPV4;
    ipv4ToBytes(cleanHost).copy(out, 1);
    out.writeUInt16BE(port, 5);
    return out;
  }

  if (ipVer === 6) {
    const out = Buffer.allocUnsafe(19);
    out[0] = ATYP_IPV6;
    ipv6ToBytes(cleanHost).copy(out, 1);
    out.writeUInt16BE(port, 17);
    return out;
  }

  const domainBuf = Buffer.from(cleanHost, 'utf8');
  if (domainBuf.length === 0 || domainBuf.length > 255) {
    throw new RangeError(`Invalid UDP domain length: ${domainBuf.length}`);
  }
  const out = Buffer.allocUnsafe(4 + domainBuf.length);
  out[0] = ATYP_DOMAIN;
  out[1] = domainBuf.length;
  domainBuf.copy(out, 2);
  out.writeUInt16BE(port, 2 + domainBuf.length);
  return out;
}

export function encodeUdpPacket(host, port, payload) {
  const hdr = encodeUdpAddressHeader(host, port);
  const data = Buffer.isBuffer(payload) ? payload : Buffer.from(payload);
  return Buffer.concat([hdr, data]);
}

export function decodeUdpPacket(buf, offset = 0) {
  if (buf.length - offset < 4) {
    throw new Error('UDP packet too short');
  }
  const atyp = buf[offset];
  if (atyp === ATYP_IPV4) {
    if (buf.length - offset < 7) throw new Error('Truncated IPv4 UDP header');
    const host = bytesToIpv4(buf, offset + 1);
    const port = buf.readUInt16BE(offset + 5);
    return { atyp, host, port, headerLength: 7, data: buf.subarray(offset + 7) };
  }
  if (atyp === ATYP_DOMAIN) {
    const len = buf[offset + 1];
    if (len === 0 || buf.length - offset < 4 + len) {
      throw new Error('Truncated domain UDP header');
    }
    const host = buf.subarray(offset + 2, offset + 2 + len).toString('utf8');
    const port = buf.readUInt16BE(offset + 2 + len);
    return { atyp, host, port, headerLength: 4 + len, data: buf.subarray(offset + 4 + len) };
  }
  if (atyp === ATYP_IPV6) {
    if (buf.length - offset < 19) throw new Error('Truncated IPv6 UDP header');
    const host = bytesToIpv6(buf, offset + 1);
    const port = buf.readUInt16BE(offset + 17);
    return { atyp, host, port, headerLength: 19, data: buf.subarray(offset + 19) };
  }
  throw new Error(`Unsupported UDP address type: 0x${atyp.toString(16)}`);
}

export function formatErrMessage(errOrMsg) {
  if (!errOrMsg) return 'Unknown error';
  if (typeof errOrMsg === 'string') return errOrMsg;
  if (errOrMsg.message) return errOrMsg.message;
  if (Array.isArray(errOrMsg.errors) && errOrMsg.errors.length > 0) {
    return errOrMsg.errors.map((e) => e.message || e.code || String(e)).join('; ');
  }
  return errOrMsg.code || String(errOrMsg);
}

export function encodeControlRequest(cmd, jsonObj) {
  const body = Buffer.from(JSON.stringify(jsonObj), 'utf8');
  if (body.length > MAX_CMD_PAYLOAD) {
    throw new Error('Control request payload too large');
  }
  const buf = Buffer.allocUnsafe(3 + body.length);
  buf[0] = cmd;
  buf.writeUInt16BE(body.length, 1);
  body.copy(buf, 3);
  return buf;
}

export function readControlRequest(stream, expectedCmdOrList, timeoutMs = 10_000) {
  const allowed = Array.isArray(expectedCmdOrList) ? expectedCmdOrList : [expectedCmdOrList];
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Timed out waiting for tunnel control header'));
    }, timeoutMs);
    timer.unref?.();

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length > 3 + MAX_CMD_PAYLOAD) {
        cleanup();
        reject(new Error('Control header exceeded maximum size'));
        return;
      }
      if (buf.length < 3) return;
      const cmd = buf[0];
      const len = buf.readUInt16BE(1);
      if (!allowed.includes(cmd)) {
        cleanup();
        reject(new Error(`Command 0x${cmd.toString(16)} is not permitted in this relay mode`));
        return;
      }
      if (len > MAX_CMD_PAYLOAD) {
        cleanup();
        reject(new Error('Control payload length exceeded limit'));
        return;
      }
      if (buf.length < 3 + len) return;

      const jsonSlice = buf.subarray(3, 3 + len);
      const leftover = buf.subarray(3 + len);
      cleanup();
      try {
        const parsed = JSON.parse(jsonSlice.toString('utf8'));
        resolve({ cmd, request: parsed, leftover });
      } catch {
        reject(new Error('Malformed JSON in control header'));
      }
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error('Stream closed before control header arrived'));
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('close', onClose);
      stream.off('end', onClose);
    };

    stream.on('data', onData);
    stream.on('error', onError);
    stream.on('close', onClose);
    stream.on('end', onClose);
  });
}

export function sendControlOk(stream) {
  stream.write(Buffer.from([STATUS_OK]));
}

export function sendControlError(stream, errOrMsg) {
  const msgBuf = Buffer.from(formatErrMessage(errOrMsg).slice(0, 500), 'utf8');
  const frame = Buffer.allocUnsafe(3 + msgBuf.length);
  frame[0] = STATUS_ERR;
  frame.writeUInt16BE(msgBuf.length, 1);
  msgBuf.copy(frame, 3);
  stream.end(frame);
}

export function readControlResponse(stream, timeoutMs = 10_000) {
  return new Promise((resolve, reject) => {
    let buf = Buffer.alloc(0);
    const timer = setTimeout(() => {
      cleanup();
      reject(new Error('Timed out waiting for hop control response'));
    }, timeoutMs);
    timer.unref?.();

    const onData = (chunk) => {
      buf = Buffer.concat([buf, chunk]);
      if (buf.length < 1) return;

      if (buf[0] === STATUS_OK) {
        const leftover = buf.subarray(1);
        cleanup();
        if (leftover.length > 0) {
          stream.unshift(leftover);
        }
        resolve();
        return;
      }

      if (buf[0] === STATUS_ERR) {
        if (buf.length < 3) return;
        const errLen = buf.readUInt16BE(1);
        if (buf.length < 3 + errLen) return;
        const msg = buf.subarray(3, 3 + errLen).toString('utf8');
        cleanup();
        reject(new Error(`Remote hop rejected circuit: ${msg}`));
        return;
      }

      cleanup();
      reject(new Error(`Invalid control status byte: 0x${buf[0].toString(16)}`));
    };

    const onError = (err) => {
      cleanup();
      reject(err);
    };

    const onClose = () => {
      cleanup();
      reject(new Error('Hop closed connection before control response'));
    };

    const cleanup = () => {
      clearTimeout(timer);
      stream.off('data', onData);
      stream.off('error', onError);
      stream.off('close', onClose);
      stream.off('end', onClose);
      stream.pause();
    };

    stream.on('data', onData);
    stream.on('error', onError);
    stream.on('close', onClose);
    stream.on('end', onClose);
    stream.resume();
  });
}

export function waitSecureConnect(tunnel) {
  return new Promise((resolve, reject) => {
    const onConnect = () => {
      tunnel.off('error', onError);
      // Prevent unhandled EventEmitter 'error' throws during async setup/teardown transitions
      tunnel.on('error', () => {});
      resolve(tunnel);
    };
    const onError = (err) => {
      tunnel.off('secureConnect', onConnect);
      reject(err);
    };
    tunnel.once('secureConnect', onConnect);
    tunnel.once('error', onError);
  });
}
