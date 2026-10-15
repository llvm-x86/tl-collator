// Characterization of the SUBMIT admission checks (src/orderAdmission.ts). The WebRTC path that
// carries SUBMIT is not reachable under the e2e wrtc stub, so these cases call admitOrder directly
// against a real TapeStore.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { admitOrder } from '../dist/orderAdmission.js';
import { computeEnvelopeHash } from '../dist/canonical.js';
import { pubKeyFromPrivKeyHex, signWithPrivKeyHex } from '../dist/crypto.js';
import { TapeStore } from '../dist/tape.js';

const TRADER_A = '11'.repeat(32);
const TRADER_B = '22'.repeat(32);
const COLLATOR = '33'.repeat(32);
const NO_POLICY = { vpnFilterMode: 'off', asnBlockMode: 'off', asnBlocklist: [], clearlistEnforce: false, clearlistFailMode: 'closed' };

// A correctly signed envelope; `fields` are part of the signed envelope, `signer` signs it.
function signed(fields = {}, signer = TRADER_A) {
  const env = {
    v: 1,
    kind: 'NEW',
    body: { v: 1, market: 'SPOT:LTC/TL', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'PUBLIC' }, clientTs: 1 },
    traderPubKey: pubKeyFromPrivKeyHex(TRADER_A),
    clientNonce: '01',
    ...fields,
  };
  if (signer !== TRADER_A) env.traderPubKey = pubKeyFromPrivKeyHex(signer);
  const orderId = computeEnvelopeHash(env);
  return { ...env, orderId, sigTrader: signWithPrivKeyHex(orderId, signer) };
}

function openTape() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-admission-'));
  const tape = new TapeStore({
    tapePath: path.join(dir, 'tape.log'),
    idxPath: path.join(dir, 'tape.idx'),
    idxStride: 4,
    replayBatch: 8,
    maxReplayEntries: 1000,
    collatorId: 'collator-test',
    collatorPrivKeyHex: COLLATOR,
  });
  return { tape, dir };
}

const meta = (remoteIp = '198.51.100.7') => ({ ...(remoteIp ? { remoteIp } : {}), firstSeenTs: 0, lastSeenTs: 0 });

// Intel stub: records lookups; `answer` is a verdict object or an Error to throw.
function intelStub(answer) {
  const calls = [];
  return {
    calls,
    lookup: async (ip) => {
      calls.push(ip);
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

function clearlistStub(answer) {
  const calls = [];
  return {
    calls,
    check: async (groupId, pubkeyHex) => {
      calls.push([groupId, pubkeyHex]);
      if (answer instanceof Error) throw answer;
      return answer;
    },
  };
}

async function refusalOf(policy, sources, m, order) {
  const r = await admitOrder(policy, sources, m, order);
  return r === null ? null : r.code;
}

test('admission: a well-formed NEW is admitted with no policy configured', async () => {
  const { tape, dir } = openTape();
  try {
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an orderId already on the tape is a DUPLICATE, checked before the signature', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed();
    assert.ok(tape.append(order));
    const tampered = { ...order, sigTrader: '00'.repeat(64) };
    const r = await admitOrder(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), tampered);
    assert.deepEqual(r, { code: 'DUPLICATE', msg: 'orderId already seen' });
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a signature by another key is bad_sig', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed({}, TRADER_B);
    const forged = { ...order, traderPubKey: pubKeyFromPrivKeyHex(TRADER_A) };
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), forged), 'bad_sig');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an orderId that is not the envelope derivation is bad_order_id', async () => {
  const { tape, dir } = openTape();
  try {
    const order = signed();
    const edited = { ...order, body: { ...order.body, qty: '2' } };
    assert.equal(await refusalOf(NO_POLICY, { tape, intel: null, clearlist: null }, meta(), edited), 'bad_order_id');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a CANCEL needs a target, a known target, and the target owner', async () => {
  const { tape, dir } = openTape();
  try {
    const sources = { tape, intel: null, clearlist: null };
    const owned = signed();
    assert.ok(tape.append(owned));
    const noTarget = signed({ kind: 'CANCEL' });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), noTarget), {
      code: 'SCHEMA_INVALID',
      msg: 'missing cancelsOrderId',
    });
    const unknown = signed({ kind: 'CANCEL', cancelsOrderId: 'ab'.repeat(32) });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), unknown), {
      code: 'UNKNOWN_ORDER',
      msg: 'cancelsOrderId not found',
    });
    const byOther = signed({ kind: 'CANCEL', cancelsOrderId: owned.orderId }, TRADER_B);
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), byOther), {
      code: 'NOT_OWNER',
      msg: 'cannot cancel other trader order',
    });
    const byOwner = signed({ kind: 'CANCEL', cancelsOrderId: owned.orderId });
    assert.equal(await admitOrder(NO_POLICY, sources, meta(), byOwner), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a REPLACE needs a target, a known target, and the target owner', async () => {
  const { tape, dir } = openTape();
  try {
    const sources = { tape, intel: null, clearlist: null };
    const owned = signed();
    assert.ok(tape.append(owned));
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE' })), {
      code: 'SCHEMA_INVALID',
      msg: 'missing replacesOrderId',
    });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: 'cd'.repeat(32) })), {
      code: 'UNKNOWN_ORDER',
      msg: 'replacesOrderId not found',
    });
    assert.deepEqual(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: owned.orderId }, TRADER_B)), {
      code: 'NOT_OWNER',
      msg: 'cannot replace other trader order',
    });
    assert.equal(await admitOrder(NO_POLICY, sources, meta(), signed({ kind: 'REPLACE', replacesOrderId: owned.orderId })), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a VPN verdict refuses only in reject mode, and records the verdict on the session', async () => {
  const { tape, dir } = openTape();
  try {
    const reject = { ...NO_POLICY, vpnFilterMode: 'reject' };
    const m = meta();
    const intel = intelStub({ vpn: true });
    assert.deepEqual(await admitOrder(reject, { tape, intel, clearlist: null }, m, signed()), {
      code: 'VPN_BLOCKED',
      msg: 'vpn traffic rejected',
    });
    assert.equal(m.vpn, true);
    assert.deepEqual(intel.calls, ['198.51.100.7']);
    const logOnly = { ...NO_POLICY, vpnFilterMode: 'log' };
    assert.equal(await admitOrder(logOnly, { tape, intel: intelStub({ vpn: true }), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: an ASN on the blocklist refuses only in reject mode', async () => {
  const { tape, dir } = openTape();
  try {
    const blockReject = { ...NO_POLICY, asnBlockMode: 'reject', asnBlocklist: [64500] };
    assert.deepEqual(await admitOrder(blockReject, { tape, intel: intelStub({ asn: 64500 }), clearlist: null }, meta(), signed()), {
      code: 'ASN_BLOCKED',
      msg: 'asn blocked',
    });
    assert.equal(await admitOrder(blockReject, { tape, intel: intelStub({ asn: 64501 }), clearlist: null }, meta(), signed()), null);
    const blockLog = { ...blockReject, asnBlockMode: 'log' };
    assert.equal(await admitOrder(blockLog, { tape, intel: intelStub({ asn: 64500 }), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: in a reject mode a failed intel lookup or a missing client IP refuses; log modes admit', async () => {
  const { tape, dir } = openTape();
  try {
    const reject = { ...NO_POLICY, vpnFilterMode: 'reject' };
    const failing = intelStub(new Error('upstream down'));
    assert.equal(
      await refusalOf(reject, { tape, intel: failing, clearlist: null }, meta(), signed()),
      'INTEL_UNAVAILABLE',
    );
    const noIp = intelStub({ vpn: false });
    assert.equal(await refusalOf(reject, { tape, intel: noIp, clearlist: null }, meta(''), signed()), 'INTEL_UNAVAILABLE');
    assert.equal(noIp.calls.length, 0);
    const logOnly = { ...NO_POLICY, vpnFilterMode: 'log' };
    assert.equal(await refusalOf(logOnly, { tape, intel: intelStub(new Error('down')), clearlist: null }, meta(), signed()), null);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('admission: a clearlist-gated order is checked with its group and trader key; closed fails closed, open admits', async () => {
  const { tape, dir } = openTape();
  try {
    const gated = { ...NO_POLICY, clearlistEnforce: true };
    const dark = signed({ body: { v: 1, market: 'SPOT:LTC/TL', side: 'BUY', px: '1', qty: '1', visibility: { kind: 'DARK', groupId: 'g1' }, clientTs: 1 } });
    const notListed = clearlistStub({ allowed: false });
    assert.deepEqual(await admitOrder(gated, { tape, intel: null, clearlist: notListed }, meta(), dark), {
      code: 'NOT_CLEARLISTED',
      msg: 'not clearlisted',
    });
    assert.deepEqual(notListed.calls, [['g1', dark.traderPubKey]]);
    assert.equal(await admitOrder(gated, { tape, intel: null, clearlist: clearlistStub({ allowed: true }) }, meta(), dark), null);
    assert.equal(
      await refusalOf(gated, { tape, intel: null, clearlist: clearlistStub(new Error('down')) }, meta(), dark),
      'CLEARLIST_DOWN',
    );
    const open = { ...gated, clearlistFailMode: 'open' };
    assert.equal(await admitOrder(open, { tape, intel: null, clearlist: clearlistStub(new Error('down')) }, meta(), dark), null);
    const probe = clearlistStub({ allowed: false });
    assert.equal(await admitOrder(gated, { tape, intel: null, clearlist: probe }, meta(), signed()), null);
    assert.equal(probe.calls.length, 0, 'a PUBLIC order is not checked against the clearlist');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
