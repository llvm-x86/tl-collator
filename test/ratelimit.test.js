import test from 'node:test';
import assert from 'node:assert/strict';

import { ConcurrencyCounter, MinIntervalGate, TokenBucket } from '../dist/ratelimit.js';

test('ConcurrencyCounter tracks outstanding work per key and drops idle keys', () => {
  const c = new ConcurrencyCounter();
  c.acquire('ip:a');
  c.acquire('ip:a');
  c.acquire('sess:1');
  assert.equal(c.get('ip:a'), 2);
  assert.equal(c.get('sess:1'), 1);
  c.release('ip:a');
  c.release('ip:a');
  c.release('ip:a'); // extra release never goes negative
  assert.equal(c.get('ip:a'), 0);
  assert.equal(c.get('sess:1'), 1);
});

test('TokenBucket admits a burst then refuses', () => {
  const b = new TokenBucket({ capacity: 3, refillPerSec: 0 });
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), true);
  assert.equal(b.allow(1), false);
});

test('MinIntervalGate admits one event per key per interval; keys are independent', () => {
  const g = new MinIntervalGate(1000, 10);
  assert.equal(g.allow('ip:a', 0), true);
  assert.equal(g.allow('ip:a', 999), false);
  assert.equal(g.allow('ip:b', 999), true, 'a second client is not held back by the first');
  assert.equal(g.allow('ip:a', 1000), true);
});

test('MinIntervalGate is bounded: old keys are evicted rather than growing without limit', () => {
  const g = new MinIntervalGate(1000, 2);
  assert.equal(g.allow('ip:a', 0), true);
  assert.equal(g.allow('ip:b', 0), true);
  assert.equal(g.allow('ip:c', 0), true); // evicts ip:a
  assert.equal(g.allow('ip:a', 1), true, 'the oldest key is forgotten once the bound is reached');
});
