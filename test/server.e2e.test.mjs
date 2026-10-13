// End-to-end probes against the built collator (dist/index.js). The native
// `wrtc` binding is replaced by a stub (scripts/e2e/), which is enough for the
// HTTP and WebSocket admission paths exercised here.
import test from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import WebSocket from 'ws';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const loader = path.join(root, 'scripts', 'e2e', 'wrtc-loader.mjs');

function freePort() {
  return new Promise((resolve, reject) => {
    const srv = net.createServer();
    srv.unref();
    srv.on('error', reject);
    srv.listen(0, '127.0.0.1', () => {
      const { port } = srv.address();
      srv.close(() => resolve(port));
    });
  });
}

// Starts a collator with a clean environment (no inherited proxy/limit settings).
async function startCollator(extraEnv = {}) {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-e2e-'));
  const env = { PATH: process.env.PATH, HOME: process.env.HOME || os.homedir(), DATA_DIR: dataDir, PORT: String(port), ...extraEnv };
  const child = spawn(process.execPath, ['--import', loader, 'dist/index.js'], {
    cwd: root,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  let exited = null;
  child.stderr.on('data', (d) => { stderr += d.toString(); });
  child.stdout.on('data', () => {});
  child.on('exit', (code) => { exited = code; });

  const base = `http://127.0.0.1:${port}`;
  const deadline = Date.now() + 30000;
  while (Date.now() < deadline) {
    if (exited !== null) throw new Error(`collator exited early (${exited}): ${stderr}`);
    try {
      const res = await fetch(`${base}/health`);
      if (res.ok) break;
    } catch {}
    await new Promise((r) => setTimeout(r, 150));
  }
  const stop = () => new Promise((resolve) => {
    if (exited !== null) return resolve();
    child.once('exit', () => resolve());
    child.kill('SIGTERM');
  });
  return { port, base, stop, exitCode: () => exited, stderr: () => stderr };
}

async function postRpc(base, ip) {
  const res = await fetch(`${base}/rpc/tl_getsyncstatus`, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'cf-connecting-ip': ip },
    body: '{}',
  });
  return { status: res.status, body: await res.json().catch(() => null) };
}

// Opens a WebSocket and reports whether the collator kept it (1013 = rejected).
function openWs(port, ip) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}/ws`, { headers: { 'cf-connecting-ip': ip } });
  const state = { ws, opened: false, closeCode: null };
  ws.on('error', () => {});
  ws.on('close', (code) => { state.closeCode = code; });
  state.ready = new Promise((resolve) => {
    ws.once('open', () => { state.opened = true; resolve(); });
    ws.once('close', () => resolve());
  });
  return state;
}

// Resolves with the close code if the server drops the socket within `ms`, else null.
async function closedWithin(state, ms) {
  await state.ready;
  if (state.closeCode !== null) return state.closeCode;
  await new Promise((r) => setTimeout(r, ms));
  return state.closeCode;
}

test('N3: TRUST_PROXY=1 without TRUST_PROXY_CIDRS refuses to start', { timeout: 120000 }, async () => {
  const port = await freePort();
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tl-e2e-bad-'));
  const child = spawn(process.execPath, ['--import', loader, 'dist/index.js'], {
    cwd: root,
    env: { PATH: process.env.PATH, HOME: process.env.HOME || os.homedir(), DATA_DIR: dataDir, PORT: String(port), TRUST_PROXY: '1' },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let stderr = '';
  child.stderr.on('data', (d) => { stderr += d.toString(); });
  child.stdout.on('data', () => {});
  // A collator that accepts this configuration keeps running; bound the wait.
  const code = await Promise.race([
    new Promise((resolve) => child.on('exit', resolve)),
    new Promise((resolve) => setTimeout(() => resolve('still running'), 10000)),
  ]);
  child.kill('SIGTERM');
  assert.notEqual(code, 'still running', 'collator must refuse TRUST_PROXY=1 without TRUST_PROXY_CIDRS');
  assert.notEqual(code, 0);
  assert.match(stderr, /TRUST_PROXY=1 requires TRUST_PROXY_CIDRS/);
});

test('N1: HTTP routed-RPC rate limit applies per client; spoofed headers do not reset it without a trusted hop', { timeout: 120000 }, async () => {
  const c = await startCollator({ HTTP_RPC_PER_IP_BURST: '2', HTTP_RPC_PER_IP_RPS: '1' });
  try {
    const statuses = [];
    for (const ip of ['203.0.113.1', '203.0.113.2', '203.0.113.3', '203.0.113.4']) {
      statuses.push(await postRpc(c.base, ip));
    }
    assert.notEqual(statuses[0].status, 429);
    assert.notEqual(statuses[1].status, 429);
    assert.equal(statuses[2].status, 429);
    assert.equal(statuses[2].body?.error?.code, 'RPC_RATE_LIMITED');
    assert.equal(statuses[3].status, 429);
  } finally {
    await c.stop();
  }
});

test('N3/N1: behind a trusted hop each real client keeps its own budget', { timeout: 120000 }, async () => {
  const c = await startCollator({
    TRUST_PROXY: '1',
    TRUST_PROXY_CIDRS: '127.0.0.1/32',
    HTTP_RPC_PER_IP_BURST: '2',
    HTTP_RPC_PER_IP_RPS: '1',
  });
  try {
    for (let i = 1; i <= 6; i++) {
      const r = await postRpc(c.base, `203.0.113.${i}`);
      assert.notEqual(r.status, 429, `client ${i} must not share another client's budget`);
    }
  } finally {
    await c.stop();
  }
});

test('N4: WebSocket connection cap is keyed on the resolved client IP, not the proxy socket', { timeout: 120000 }, async () => {
  // Without a trusted hop every socket is 127.0.0.1, so a second client is refused.
  const direct = await startCollator({ CONN_MAX_PER_IP: '1' });
  const openers = [];
  try {
    const a = openWs(direct.port, '203.0.113.1');
    const b = openWs(direct.port, '203.0.113.2');
    openers.push(a, b);
    assert.equal(await closedWithin(a, 300), null);
    assert.equal(await closedWithin(b, 300), 1013, 'untrusted headers must not split the per-IP budget');
  } finally {
    openers.forEach((s) => s.ws.close());
    await direct.stop();
  }

  // Behind a trusted hop the two real clients are distinct; a repeat of the first is still capped.
  const proxied = await startCollator({ CONN_MAX_PER_IP: '1', TRUST_PROXY: '1', TRUST_PROXY_CIDRS: '127.0.0.1/32' });
  const openers2 = [];
  try {
    const a = openWs(proxied.port, '203.0.113.1');
    const b = openWs(proxied.port, '203.0.113.2');
    const a2 = openWs(proxied.port, '203.0.113.1');
    openers2.push(a, b, a2);
    assert.equal(await closedWithin(a, 300), null);
    assert.equal(await closedWithin(b, 300), null);
    assert.equal(await closedWithin(a2, 300), 1013);
  } finally {
    openers2.forEach((s) => s.ws.close());
    await proxied.stop();
  }
});
