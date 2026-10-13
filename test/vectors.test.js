import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeOrderId, stableStringify } from '../dist/canonical.js';
import { sha256Hex } from '../dist/crypto.js';
import { TapeStore } from '../dist/tape.js';

const vectorsPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'spec', 'test-vectors.json');
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

// Independent re-implementation of the wallet/smoke-script convention
// (scripts/smoke-live-flow.cjs buildOrder):
//   orderId = sha256(stableStringify(body) + traderPubKey + clientNonce)
function smokeStyleOrderId(body, traderPubKey, clientNonce) {
  const canonicalize = (v) => {
    if (Array.isArray(v)) return v.map(canonicalize);
    if (v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype) {
      const out = {};
      for (const k of Object.keys(v).sort()) out[k] = canonicalize(v[k]);
      return out;
    }
    return v;
  };
  return crypto
    .createHash('sha256')
    .update(JSON.stringify(canonicalize(body)) + traderPubKey + clientNonce, 'utf8')
    .digest('hex');
}

test('C1: spec vector orderId matches sha256(stableStringify(body)+traderPubKey+clientNonce)', () => {
  const { orderBody, traderPubKey, clientNonce, expectedOrderId } = vectors.orderTest;
  assert.equal(computeOrderId(orderBody, traderPubKey, clientNonce), expectedOrderId);
});

test('C1: canonical.ts derivation matches the smoke-script convention', () => {
  const { orderBody, traderPubKey, clientNonce } = vectors.orderTest;
  assert.equal(computeOrderId(orderBody, traderPubKey, clientNonce), smokeStyleOrderId(orderBody, traderPubKey, clientNonce));
});

test('C1: orderId is insensitive to body key order but sensitive to any content change', () => {
  const { orderBody, traderPubKey, clientNonce, expectedOrderId } = vectors.orderTest;
  const shuffled = {
    clientTs: orderBody.clientTs,
    visibility: orderBody.visibility,
    qty: orderBody.qty,
    px: orderBody.px,
    side: orderBody.side,
    market: orderBody.market,
    v: orderBody.v,
  };
  assert.equal(stableStringify(shuffled), stableStringify(orderBody));
  assert.equal(computeOrderId(shuffled, traderPubKey, clientNonce), expectedOrderId);

  // Signature-stripping attack: reuse the same orderId/sig with a tampered body.
  const tampered = { ...orderBody, px: '0.01' };
  assert.notEqual(computeOrderId(tampered, traderPubKey, clientNonce), expectedOrderId);
  const tamperedNonce = 'beef'.repeat(8);
  assert.notEqual(computeOrderId(orderBody, traderPubKey, tamperedNonce), expectedOrderId);
});

test('tape vectors: entryHash and collator sig payload hash match spec', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-vectors-'));
  const base = vectors.tapeTest.entryNoSig;
  const t = new TapeStore({
    tapePath: path.join(dir, 'tape.log'),
    idxPath: path.join(dir, 'tape.idx'),
    idxStride: 10,
    replayBatch: 10,
    collatorId: base.collatorId,
    collatorPrivKeyHex: '22'.repeat(32),
  });

  // The vector's order must itself satisfy the C1 derivation rule.
  assert.equal(
    computeOrderId(base.order.body, base.order.traderPubKey, base.order.clientNonce),
    base.order.orderId
  );

  const entryHash = t.computeEntryHash({
    v: base.v,
    collatorId: base.collatorId,
    seq: base.seq,
    prevHash: base.prevHash,
    receivedTs: base.receivedTs,
    order: base.order,
  });
  assert.equal(entryHash, vectors.tapeTest.expectedEntryHash);

  const sigPayloadHash = sha256Hex(`${base.seq}|${base.prevHash}|${base.order.orderId}|${entryHash}`);
  assert.equal(sigPayloadHash, vectors.tapeTest.expectedSigPayloadHash);
});
