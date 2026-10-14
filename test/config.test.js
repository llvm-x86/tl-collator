import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

import { loadConfig } from '../dist/config.js';

// loadConfig reads process.env at call time; each test gets its own DATA_DIR.
function withEnv(overrides, fn) {
  const saved = { ...process.env };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-config-test-'));
  try {
    Object.assign(process.env, { DATA_DIR: dir, TRUST_PROXY: '', TRUST_PROXY_CIDRS: '' }, overrides);
    return fn();
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

test('config: a garbage integer for an admission cap aborts startup instead of using the default', () => {
  withEnv({ CONN_MAX_PER_IP: '25six' }, () => {
    assert.throws(() => loadConfig(), /CONN_MAX_PER_IP must be an integer/);
  });
  withEnv({ PENDING_RPC_MAX_PER_SESSION: '1.5' }, () => {
    assert.throws(() => loadConfig(), /PENDING_RPC_MAX_PER_SESSION must be an integer/);
  });
});

test('config: an explicit 0 disables a cap and empty means the default', () => {
  withEnv({ CONN_MAX_PER_IP: '0', PENDING_RPC_MAX_PER_SESSION: '' }, () => {
    const cfg = loadConfig();
    assert.equal(cfg.connMaxPerIp, 0);
    assert.equal(cfg.pendingRpcMaxPerSession, 32);
  });
});

test('config: every integer env var is parsed strictly, including the ones read with `Number(x) || default`', () => {
  for (const [k, v] of [
    ['PENDING_RPC_MAX', 'ten'],
    ['TL_COLLATOR_RPC_ADVERT_TTL_MS', '45s'],
    ['CONN_IDLE_TIMEOUT_MS', '6e4'],
    ['CONN_SWEEP_INTERVAL_MS', 'x'],
    ['CONN_HANDSHAKE_GRACE_MS', '5000ms'],
    ['BITVM_COLLATERAL_PROPERTY_ID', 'one'],
    ['ASN_BLOCKLIST', '64496,AS65000'],
  ]) {
    withEnv({ [k]: v }, () => {
      assert.throws(() => loadConfig(), new RegExp(`${k} must be an integer`), `${k}=${v} must abort`);
    });
  }
});

test('config: unset, empty and explicit values for the converted integer env vars', () => {
  withEnv({ PENDING_RPC_MAX: '', CONN_IDLE_TIMEOUT_MS: '', ASN_BLOCKLIST: ' 64496 , ,65000 ' }, () => {
    const cfg = loadConfig();
    assert.equal(cfg.pendingRpcMax, 1000);
    assert.equal(cfg.connIdleTimeoutMs, 60000);
    assert.equal(cfg.connSweepIntervalMs, 15000);
    assert.equal(cfg.rpcAdvertTtlMs, 45000);
    assert.deepEqual(cfg.asnBlocklist, [64496, 65000]);
  });
  withEnv({ PENDING_RPC_MAX: '1', CONN_HANDSHAKE_GRACE_MS: '0', TL_COLLATOR_RPC_ADVERT_TTL_MS: '15000' }, () => {
    const cfg = loadConfig();
    assert.equal(cfg.pendingRpcMax, 1);
    assert.equal(cfg.connHandshakeGraceMs, 0);
    assert.equal(cfg.rpcAdvertTtlMs, 15000);
  });
});

// Out-of-range values used to be silently clamped or dropped: CONN_MAX=-1 meant
// no cap, CONN_MAX_PER_IP=-1 meant no cap, ASN_BLOCKLIST=0 dropped the entry, and
// MAX_MSG_BYTES=0 disabled the WebSocket payload check. Each must abort now.
test('config: a value outside its bounds aborts startup instead of being clamped, dropped or disabling a check', () => {
  for (const [k, v] of [
    ['CONN_MAX', '-1'],
    ['CONN_MAX_PER_IP', '-1'],
    ['PENDING_RPC_MAX_PER_SESSION', '-3'],
    ['PENDING_RPC_MAX_PER_IP', '-1'],
    ['PENDING_RPC_MAX', '0'],
    ['SUBMIT_BURST', '0'],
    ['SUBMIT_RPS', '-1'],
    ['HTTP_RPC_PER_IP_RPS', '0'],
    ['HTTP_RPC_PER_IP_BURST', '-4'],
    ['TAPE_RESYNC_MAX_ENTRIES', '0'],
    ['TAPE_INDEX_STRIDE', '0'],
    ['TAPE_REPLAY_BATCH', '0'],
    ['MAX_MSG_BYTES', '0'],
    ['MAX_MSG_BYTES', '-1'],
    ['MAX_MSG_BYTES', '3000000000'],
    ['CONN_IDLE_TIMEOUT_MS', '0'],
    ['CONN_SWEEP_INTERVAL_MS', '1'],
    ['CONN_SWEEP_INTERVAL_MS', '3000000000'],
    ['CONN_HANDSHAKE_GRACE_MS', '-1'],
    ['TL_COLLATOR_RPC_ADVERT_TTL_MS', '1'],
    ['IP_INTEL_TTL_SEC', '-5'],
    ['BITVM_COLLATERAL_PROPERTY_ID', '-1'],
    ['BITVM_COLLATERAL_PROPERTY_ID', '0'],
    ['PORT', '0'],
    ['PORT', '70000'],
    ['PORT', '-1'],
    ['SERVER_PORT', '65536'],
    ['ASN_BLOCKLIST', '0'],
    ['ASN_BLOCKLIST', '64496,0'],
    ['ASN_BLOCKLIST', '-5'],
    ['ASN_BLOCKLIST', '4294967296'],
  ]) {
    withEnv({ [k]: v }, () => {
      assert.throws(() => loadConfig(), new RegExp(`${k} must be an integer`), `${k}=${v} must abort`);
    });
  }
});

test('config: the accepted integer spellings are decimal, optionally signed, surrounding whitespace only', () => {
  withEnv({ PORT: '+8800' }, () => assert.equal(loadConfig().port, 8800));
  withEnv({ PORT: ' 8800 ' }, () => assert.equal(loadConfig().port, 8800));
  withEnv({ PORT: '   ' }, () => assert.equal(loadConfig().port, 8787));
  withEnv({ MAX_MSG_BYTES: '2147483647' }, () => assert.equal(loadConfig().maxMsgBytes, 2147483647));
  for (const v of ['0x10', '1e3', '1_000', '12 34', '٣', '9007199254740993']) {
    withEnv({ PORT: v }, () => assert.throws(() => loadConfig(), /PORT must be an integer/, `PORT=${v}`));
  }
});
