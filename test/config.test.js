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
