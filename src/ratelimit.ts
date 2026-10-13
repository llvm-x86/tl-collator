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


// Per-client count of outstanding (admitted, not yet released) operations.
// Routed RPCs are keyed by requester identity — `sess:<id>` for WebSocket
// sessions, `ip:<resolved client ip>` for HTTP callers — so every route shares
// one admission mechanism. Keys with no outstanding work are dropped.
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
