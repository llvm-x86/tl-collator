import { LruMap } from './lru.js';
import { fetchBoundedJson } from './boundedFetch.js';

// Round 8: a stalled or oversized IP intel answer must not hold a SUBMIT open or buffer without limit.
const IP_INTEL_TIMEOUT_MS = 3000;
const IP_INTEL_MAX_BYTES = 64 * 1024;

export interface IpIntel {
  asn?: number;
  vpn?: boolean;
}

export class IpIntelClient {
  private url: string;
  private ttlMs: number;
  private cache: LruMap<{ exp: number; v: IpIntel }>;

  constructor(opts: { url: string; ttlSec: number; max: number }) {
    this.url = opts.url;
    this.ttlMs = Math.max(0, opts.ttlSec) * 1000;
    this.cache = new LruMap(opts.max);
  }

  async lookup(ip: string): Promise<IpIntel> {
    const now = Date.now();
    const hit = this.cache.get(ip);
    if (hit && hit.exp > now) return hit.v;

    const res = await fetchBoundedJson(
      this.url,
      {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ ip }),
      },
      { timeoutMs: IP_INTEL_TIMEOUT_MS, maxBytes: IP_INTEL_MAX_BYTES },
    );
    if (!res.ok) throw new Error(`ipIntel http ${res.status}`);
    const j: any = res.body;
    const v: IpIntel = {
      asn: Number.isFinite(Number(j?.asn)) ? Number(j.asn) : undefined,
      vpn: typeof j?.vpn === 'boolean' ? j.vpn : undefined,
    };
    this.cache.set(ip, { exp: now + this.ttlMs, v });
    return v;
  }
}
