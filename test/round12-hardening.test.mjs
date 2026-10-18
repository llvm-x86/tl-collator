// Regression probes for the round-12 findings. Each case is written to fail on the behaviour it
// guards against. Runs against dist/ (npm run build first).
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { DC_REPLAY_HIGH_WATER_BYTES, PeerSession, broadcastTapeEntry } from '../dist/peerSession.js';
import * as peerSession from '../dist/peerSession.js';
import { TapeStore } from '../dist/tape.js';

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

// A channel whose queue stays where the test puts it, so the replay parks on a full queue until
// the test drains it. Messages are recorded as the peer would parse them.
const fakeChannel = () => ({
  readyState: 'open',
  bufferedAmount: 0,
  msgs: [],
  closed: 0,
  send(data) {
    this.msgs.push(JSON.parse(data));
  },
  close() {
    this.readyState = 'closed';
    this.closed += 1;
  },
});

const orderFor = (i) => ({
  v: 1,
  kind: 'PLACE',
  orderId: i.toString(16).padStart(64, '0'),
  traderPubKey: 'ab'.repeat(33),
  clientNonce: `n${i}`,
  sigTrader: 'cd'.repeat(64),
  body: { pad: 'x'.repeat(200), i },
});

const openStore = (dir, count) => {
  const store = new TapeStore({
    tapePath: path.join(dir, 'tape.jsonl'), idxPath: path.join(dir, 'tape.idx.json'), idxStride: 50,
    replayBatch: 500, maxReplayEntries: 10000, collatorId: 'collator', collatorPrivKeyHex: '11'.repeat(32),
  });
  for (let i = 1; i <= count; i += 1) store.append(orderFor(i));
  return store;
};

const tapeSeqs = (ch) => ch.msgs.filter((m) => m.t === 'TAPE_ENTRY').map((m) => m.entry.seq);

test('R12-F1 live entries committed during a paused replay follow the replay in seq order, before TAPE_END', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-order-'));
  try {
    const store = openStore(dir, 300);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-order', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = ch;
    session.wantsTape = true;
    const served = session.serveTapeSub(ch, store, 1);
    // The replay is now parked on the full queue at seq 1.
    await sleep(30);
    for (const i of [301, 302]) broadcastTapeEntry([session], store.append(orderFor(i)));
    ch.bufferedAmount = 0;
    await served;
    const expected = Array.from({ length: 302 }, (_, k) => k + 1);
    assert.deepEqual(tapeSeqs(ch), expected, 'channel seqs are not one ascending stream');
    const end = ch.msgs[ch.msgs.length - 1];
    assert.equal(end.t, 'TAPE_END');
    assert.equal(end.lastSeq, 302, 'TAPE_END reports a tip the channel had not carried yet');
    assert.equal(ch.closed, 0);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 a newer TAPE_SUB on the same session supersedes the replay still parked on that channel', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-supersede-'));
  try {
    const store = openStore(dir, 300);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-supersede', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = ch;
    session.wantsTape = true;
    const first = session.serveTapeSub(ch, store, 1);
    await sleep(30);
    const second = session.serveTapeSub(ch, store, 1);
    ch.bufferedAmount = 0;
    await Promise.all([first, second]);
    const seqs = tapeSeqs(ch);
    assert.equal(seqs.length, 300, `delivered ${seqs.length} entries; two replays ran on one channel`);
    assert.deepEqual(seqs, Array.from({ length: 300 }, (_, k) => k + 1));
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 1, 'superseded replay sent a TAPE_END');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 live entries held past the bound close the channel and end the replay without TAPE_END', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-held-'));
  try {
    const store = openStore(dir, 20);
    const ch = fakeChannel();
    ch.bufferedAmount = 2 * DC_REPLAY_HIGH_WATER_BYTES;
    const session = new PeerSession({ id: 'f1-held', ws: { readyState: 1 }, burst: 10, ratePerSec: 1 });
    session.dc = ch;
    session.wantsTape = true;
    const served = session.serveTapeSub(ch, store, 1);
    await sleep(30);
    for (let i = 0; i <= peerSession.DC_REPLAY_MAX_HELD_ENTRIES; i += 1) {
      broadcastTapeEntry([session], store.append(orderFor(1000 + i)));
    }
    ch.bufferedAmount = 0;
    await served;
    assert.equal(ch.closed, 1, 'a replay holding unbounded live entries kept its channel');
    assert.equal(ch.msgs.filter((m) => m.t === 'TAPE_END').length, 0, 'an interrupted replay sent TAPE_END');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});

test('R12-F1 a replay delivers only the lines that existed when it began', { timeout: 20000 }, async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-r12-snapshot-'));
  try {
    const store = openStore(dir, 300);
    const seen = [];
    let appended = false;
    await store.replayFromSeq(1, (e) => {
      seen.push(e.seq);
      if (!appended) {
        appended = true;
        for (let i = 301; i <= 305; i += 1) store.append(orderFor(i));
      }
    });
    assert.deepEqual(seen, Array.from({ length: 300 }, (_, k) => k + 1), 'replay read lines appended after it began');
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
