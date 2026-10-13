import test from 'node:test';
import assert from 'node:assert/strict';

import { ConcurrencyCounter, TokenBucket } from '../dist/ratelimit.js';

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
