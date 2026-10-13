import test from 'node:test';
import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { computeEnvelopeHash, computeOrderId, envelopeSignedFields, stableStringify } from '../dist/canonical.js';
import { sha256Hex } from '../dist/crypto.js';
import { TapeStore } from '../dist/tape.js';
import { loadValidators } from '../dist/schema.js';
import { validateOrderEnvelope } from '../dist/validate.js';

const vectorsPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'spec', 'test-vectors.json');
const vectors = JSON.parse(fs.readFileSync(vectorsPath, 'utf8'));

// Independent re-implementation of the wallet/smoke-script convention
// (scripts/smoke-live-flow.cjs buildOrder, TL-Canon v1 envelope binding):
//   orderId = sha256(stableStringify(envelope minus orderId/sigTrader))
function smokeStyleOrderId(envelope) {
  const canonicalize = (v) => {
    if (Array.isArray(v)) return v.map(canonicalize);
    if (v && typeof v === 'object' && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null)) {
      // Own-key-safe: `__proto__` must become an ordinary own key.
      const out = Object.create(null);
      for (const k of Object.keys(v).sort()) {
        Object.defineProperty(out, k, { value: canonicalize(v[k]), enumerable: true, writable: true, configurable: true });
      }
      return out;
    }
    return v;
  };
  const signed = {};
  for (const k of Object.keys(envelope)) {
    if (k === 'orderId' || k === 'sigTrader') continue;
    Object.defineProperty(signed, k, { value: envelope[k], enumerable: true, writable: true, configurable: true });
  }
  return crypto.createHash('sha256').update(JSON.stringify(canonicalize(signed)), 'utf8').digest('hex');
}

test('C1: spec vector orderId matches the envelope-hash derivation', () => {
  const { envelopeNoSig, expectedOrderId } = vectors.orderTest;
  assert.equal(computeEnvelopeHash(envelopeNoSig), expectedOrderId);
  assert.equal(computeOrderId(envelopeNoSig), expectedOrderId);
});

test('C1: canonical.ts derivation matches the smoke-script convention', () => {
  const { envelopeNoSig } = vectors.orderTest;
  assert.equal(computeEnvelopeHash(envelopeNoSig), smokeStyleOrderId(envelopeNoSig));
});

test('C1: orderId is insensitive to key order but sensitive to any content change', () => {
  const { envelopeNoSig, expectedOrderId } = vectors.orderTest;
  const shuffled = {
    clientNonce: envelopeNoSig.clientNonce,
    traderPubKey: envelopeNoSig.traderPubKey,
    body: {
      clientTs: envelopeNoSig.body.clientTs,
      visibility: envelopeNoSig.body.visibility,
      qty: envelopeNoSig.body.qty,
      px: envelopeNoSig.body.px,
      side: envelopeNoSig.body.side,
      market: envelopeNoSig.body.market,
      v: envelopeNoSig.body.v,
    },
    kind: envelopeNoSig.kind,
    v: envelopeNoSig.v,
  };
  assert.equal(stableStringify(shuffled), stableStringify(envelopeSignedFields(envelopeNoSig)));
  assert.equal(computeEnvelopeHash(shuffled), expectedOrderId);

  // Signature-stripping attack: reuse the same orderId/sig with a tampered body.
  const tampered = { ...envelopeNoSig, body: { ...envelopeNoSig.body, px: '0.01' } };
  assert.notEqual(computeEnvelopeHash(tampered), expectedOrderId);
  const tamperedNonce = 'beef'.repeat(8);
  assert.notEqual(computeEnvelopeHash({ ...envelopeNoSig, clientNonce: tamperedNonce }), expectedOrderId);
});

test('C1: kind/cancelsOrderId/replacesOrderId are bound into orderId (CANCEL/REPLACE forgery)', () => {
  const { envelopeNoSig: newEnv, expectedOrderId: newOrderId } = vectors.orderTest;
  const { envelopeNoSig: cancelEnv, expectedOrderId: cancelOrderId } = vectors.orderCancelTest;

  // The spec CANCEL vector derives cleanly and differs from its NEW sibling.
  assert.equal(computeEnvelopeHash(cancelEnv), cancelOrderId);
  assert.notEqual(cancelOrderId, newOrderId);

  // Red-team exploit: harvest (orderId, sigTrader, traderPubKey, body) from a
  // NEW order on the tape, resubmit as CANCEL/REPLACE of a victim order. The
  // recomputed envelope hash no longer matches the harvested orderId.
  const victimOrderId = 'ab'.repeat(32);
  const forgedCancel = { ...newEnv, kind: 'CANCEL', cancelsOrderId: victimOrderId };
  const forgedReplace = { ...newEnv, kind: 'REPLACE', replacesOrderId: victimOrderId };
  assert.notEqual(computeEnvelopeHash(forgedCancel), newOrderId);
  assert.notEqual(computeEnvelopeHash(forgedReplace), newOrderId);

  // Even a same-kind envelope with a different target order is unforgeable.
  assert.notEqual(
    computeEnvelopeHash({ ...cancelEnv, cancelsOrderId: 'cd'.repeat(32) }),
    cancelOrderId
  );
});

test('canonical: __proto__ keys are ordinary own keys — no hash collision, no pollution', () => {
  const base = vectors.orderTest.envelopeNoSig;
  const withProto = JSON.parse(JSON.stringify(base));
  withProto.body = JSON.parse(JSON.stringify(base.body));
  withProto.body.visibility = JSON.parse('{"kind":"PUBLIC","__proto__":{"polluted":true}}');

  // Pre-fix stableStringify dropped the __proto__ key (prototype setter),
  // making these two collide while leaving the raw objects different.
  assert.notEqual(stableStringify(base), stableStringify(withProto));
  assert.notEqual(computeEnvelopeHash(base), computeEnvelopeHash(withProto));

  // canonicalize must not pollute Object.prototype.
  stableStringify(JSON.parse('{"__proto__":{"pwned":1}}'));
  assert.equal(({}).pwned, undefined);
  assert.equal(({}).polluted, undefined);
});

test('validation: __proto__/constructor/prototype keys are rejected anywhere in the envelope', () => {
  const { envelopeNoSig } = vectors.orderTest;
  const envelope = { ...envelopeNoSig, orderId: 'ab'.repeat(32), sigTrader: '11'.repeat(64) };
  const validators = loadValidators();

  for (const key of ['__proto__', 'constructor', 'prototype']) {
    const badTop = JSON.parse(JSON.stringify(envelope));
    Object.defineProperty(badTop, key, { value: { pwned: 1 }, enumerable: true, writable: true, configurable: true });
    assert.equal(validators.validateOrderEnvelope(badTop), false, `top-level ${key} must be rejected`);
    assert.equal(validateOrderEnvelope(badTop), false, `top-level ${key} must be rejected (hand-rolled)`);

    const badNested = JSON.parse(JSON.stringify(envelope));
    badNested.body.visibility = JSON.parse(`{"kind":"PUBLIC","${key}":{"pwned":1}}`);
    assert.equal(validators.validateOrderEnvelope(badNested), false, `nested ${key} must be rejected`);
    assert.equal(validateOrderEnvelope(badNested), false, `nested ${key} must be rejected (hand-rolled)`);
  }

  // Sanity: the clean envelope still validates.
  assert.equal(validators.validateOrderEnvelope(envelope), true);
  assert.equal(validateOrderEnvelope(envelope), true);
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

  // The vector's order must itself satisfy the C1 envelope-hash derivation rule.
  assert.equal(computeEnvelopeHash(base.order), base.order.orderId);

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
