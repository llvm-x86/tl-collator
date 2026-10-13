import net from 'node:net';
import type http from 'node:http';

// Single trusted-client-IP resolver. Every per-IP decision in the collator (WS
// connection caps, routed-RPC admission, HTTP rate limits, IP intel, logs) goes
// through `resolve()`, so header trust is decided in exactly one place.

export interface TrustedProxyConfig {
  /** TRUST_PROXY=1: client-IP headers may be honored, but only from a peer in `cidrs`. */
  enabled: boolean;
  /** TRUST_PROXY_CIDRS: the reverse-proxy / CDN hop addresses (IPv4 or IPv6, optional /prefix). */
  cidrs: string[];
}

export interface ClientIpResolver {
  /** Client IP for a request: the socket peer, or a header-derived address when the peer is a trusted hop. */
  resolve(req: Pick<http.IncomingMessage, 'headers' | 'socket'>): string;
  /** True when client-IP headers on this request may be believed (peer is a configured proxy hop). */
  headersTrusted(req: Pick<http.IncomingMessage, 'socket'>): boolean;
}

interface ParsedCidr {
  addr: string;
  prefix: number;
  family: 'ipv4' | 'ipv6';
}

// Canonical textual form of an address. IPv4-mapped IPv6 (`::ffff:a.b.c.d`,
// what dual-stack sockets report) becomes `a.b.c.d`. Returns '' when the input
// is not an IP address.
export function normalizeIp(raw: string): string {
  const s = String(raw || '').trim();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  const candidate = mapped ? mapped[1] : s;
  return net.isIP(candidate) ? candidate : '';
}

function parseCidr(entry: string): ParsedCidr {
  const m = /^(.+)\/(\d{1,3})$/.exec(entry);
  const addr = m ? m[1] : entry;
  const family = net.isIP(addr);
  if (family === 0) throw new Error(`TRUST_PROXY_CIDRS: "${entry}" is not an IP address or CIDR`);
  if (family === 6 && /^::ffff:/i.test(addr)) {
    throw new Error(`TRUST_PROXY_CIDRS: "${entry}" — write IPv4 proxy hops as IPv4 (a.b.c.d), not IPv4-mapped IPv6`);
  }
  const maxPrefix = family === 4 ? 32 : 128;
  const prefix = m ? Number(m[2]) : maxPrefix;
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > maxPrefix) {
    throw new Error(`TRUST_PROXY_CIDRS: "${entry}" has an invalid prefix length`);
  }
  return { addr, prefix, family: family === 4 ? 'ipv4' : 'ipv6' };
}

/**
 * Reads TRUST_PROXY / TRUST_PROXY_CIDRS. Throws on anything ambiguous so the
 * collator refuses to start instead of silently trusting or ignoring headers.
 */
export function parseTrustedProxyConfig(env: NodeJS.ProcessEnv): TrustedProxyConfig {
  const raw = String(env.TRUST_PROXY ?? '').trim();
  if (raw !== '' && raw !== '0' && raw !== '1') {
    throw new Error(`TRUST_PROXY must be 0 or 1 (got "${raw}")`);
  }
  const enabled = raw === '1';
  const cidrs = String(env.TRUST_PROXY_CIDRS ?? '').split(/[\s,]+/).filter(Boolean);
  for (const entry of cidrs) parseCidr(entry);
  if (!enabled && cidrs.length > 0) {
    throw new Error('TRUST_PROXY_CIDRS is set but TRUST_PROXY is not 1; set TRUST_PROXY=1 or unset TRUST_PROXY_CIDRS');
  }
  if (enabled && cidrs.length === 0) {
    throw new Error('TRUST_PROXY=1 requires TRUST_PROXY_CIDRS (the reverse proxy / CDN hop addresses)');
  }
  return { enabled, cidrs };
}

export function createClientIpResolver(cfg: TrustedProxyConfig): ClientIpResolver {
  const hops = new net.BlockList();
  for (const entry of cfg.cidrs) {
    const { addr, prefix, family } = parseCidr(entry);
    hops.addSubnet(addr, prefix, family);
  }

  const isTrustedHop = (ip: string): boolean => {
    if (!cfg.enabled || !ip) return false;
    return hops.check(ip, net.isIP(ip) === 6 ? 'ipv6' : 'ipv4');
  };

  const header = (req: Pick<http.IncomingMessage, 'headers'>, name: string): string => {
    const v = req.headers[name];
    return typeof v === 'string' ? v : '';
  };

  const peerOf = (req: Pick<http.IncomingMessage, 'socket'>): string => normalizeIp(req.socket?.remoteAddress || '');

  return {
    headersTrusted(req) {
      return isTrustedHop(peerOf(req));
    },
    resolve(req) {
      const peer = peerOf(req);
      // Headers are only believed when the TCP peer is one of our proxy hops.
      if (!isTrustedHop(peer)) return peer;

      // Single-valued headers set by the immediate proxy/CDN.
      for (const name of ['cf-connecting-ip', 'x-real-ip']) {
        const ip = normalizeIp(header(req, name));
        if (ip) return ip;
      }

      // X-Forwarded-For: walk right to left past our own hops; the first
      // untrusted entry is the client. Anything malformed fails closed to the
      // peer address rather than to a client-chosen value.
      const xff = header(req, 'x-forwarded-for').split(',').map((s) => s.trim()).filter(Boolean);
      for (let i = xff.length - 1; i >= 0; i--) {
        const ip = normalizeIp(xff[i]);
        if (!ip) return peer;
        if (!isTrustedHop(ip)) return ip;
      }
      return peer;
    },
  };
}
