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
  withEnv({ PENDING_RPC_MAX: '0', CONN_HANDSHAKE_GRACE_MS: '0', TL_COLLATOR_RPC_ADVERT_TTL_MS: '1' }, () => {
    const cfg = loadConfig();
    assert.equal(cfg.pendingRpcMax, 1, 'a zero or tiny value is clamped to the floor, not replaced by the default');
    assert.equal(cfg.connHandshakeGraceMs, 0);
    assert.equal(cfg.rpcAdvertTtlMs, 15000);
  });
});
