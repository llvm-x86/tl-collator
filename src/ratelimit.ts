import { LruMap } from './lru.js';

export class TokenBucket {
  private capacity: number;
  private refillPerSec: number;
  private tokens: number;
  private lastRefillMs: number;

  constructor(opts: { capacity: number; refillPerSec: number }) {
    this.capacity = Math.max(1, opts.capacity);
    this.refillPerSec = Math.max(0, opts.refillPerSec);
    this.tokens = this.capacity;
    this.lastRefillMs = Date.now();
  }

  allow(cost: number = 1): boolean {
    const now = Date.now();
    const dt = Math.max(0, now - this.lastRefillMs);
    const add = (dt / 1000) * this.refillPerSec;
    if (add > 0) {
      this.tokens = Math.min(this.capacity, this.tokens + add);
      this.lastRefillMs = now;
    }
    if (this.tokens >= cost) {
      this.tokens -= cost;
      return true;
    }
    return false;
  }
}

// Allows at most one event per `key` every `intervalMs`. Keys are bounded (LRU),
// so a flood of distinct keys cannot grow memory without limit.
export class MinIntervalGate {
  private last: LruMap<number>;

  constructor(private intervalMs: number, maxKeys: number) {
    this.last = new LruMap<number>(maxKeys);
  }

  allow(key: string, nowMs: number = Date.now()): boolean {
    const prev = this.last.get(key);
    if (prev !== undefined && nowMs - prev < this.intervalMs) return false;
    this.last.set(key, nowMs);
    return true;
  }
}

// Per-key count of outstanding (admitted, not yet released) operations, used for
// routed-RPC admission. Keys with no outstanding work are dropped, so the map
// only holds clients that currently have work in flight.
export class ConcurrencyCounter {
  private counts = new Map<string, number>();

  get(key: string): number {
    return this.counts.get(key) || 0;
  }

  acquire(key: string): void {
    this.counts.set(key, this.get(key) + 1);
  }

  release(key: string): void {
    const remaining = this.get(key) - 1;
    if (remaining > 0) this.counts.set(key, remaining);
    else this.counts.delete(key);
  }
}
