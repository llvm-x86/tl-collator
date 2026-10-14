import fs from 'node:fs';
import path from 'node:path';

import { parseTrustedProxyConfig, type TrustedProxyConfig } from './clientIp.js';

export interface Config {
  port: number;
  wsPath: string;
  dataDir: string;
  tapePath: string;
  idxPath: string;
  idxStride: number;
  replayBatch: number;
  collatorKeyPath: string;
  infraAttestationsPath: string | null;
  infraAttestationsJson: string | null;
  maxMsgBytes: number;
  submitBurst: number;
  submitRatePerSec: number;
  clearlistEnforce: boolean;
  clearlistUrl: string | null;
  clearlistFailMode: 'open' | 'closed';
  name: string | null;
  operator: string | null;
  region: string | null;
  ipLogging: 'off' | 'on';
  vpnFilterMode: 'off' | 'log' | 'reject';
  asnBlockMode: 'off' | 'log' | 'reject';
  asnBlocklist: number[];
  ipIntelUrl: string | null;
  ipIntelTtlSec: number;
  connMax: number | null;
  trustedProxy: TrustedProxyConfig;
  tapeResyncMaxEntries: number;
  httpRpcPerIpRps: number;
  httpRpcPerIpBurst: number;
  connMaxPerIp: number;
  pendingRpcMaxPerSession: number;
  pendingRpcMaxPerIp: number;
  tlsKeyPath: string | null;
  tlsCertPath: string | null;
  iceServers: RTCIceServer[];
}

// Unset or empty means the default. Anything else must be a safe integer: a
// typo such as CONN_MAX=25six aborts startup instead of silently running with
// the default.
function intEnv(k: string, d: number): number {
  const v = (process.env[k] ?? '').trim();
  if (v === '') return d;
  if (!/^[+-]?\d+$/.test(v) || !Number.isSafeInteger(Number(v))) {
    throw new Error(`${k} must be an integer (got "${process.env[k]}")`);
  }
  return Number(v);
}

export function loadConfig(): Config {
  const dataDir = process.env.DATA_DIR || './data';
  const tapePath = process.env.TAPE_PATH || path.join(dataDir, 'tape.log');
  const idxPath = process.env.TAPE_INDEX_PATH || path.join(dataDir, 'tape.idx');
  const collatorKeyPath = process.env.COLLATOR_KEY_PATH || path.join(dataDir, 'collator.key');
  const infraAttestationsPath = process.env.INFRA_ATTESTATIONS_PATH || path.join(dataDir, 'infra-attestations.json');
  const infraAttestationsJson = process.env.INFRA_ATTESTATIONS_JSON || null;
  const iceJson =
    process.env.ICE_SERVERS_JSON ||
    JSON.stringify([{ urls: ['stun:stun.l.google.com:19302', 'stun:stun1.l.google.com:19302'] }]);
  let iceServers: RTCIceServer[] = [];
  try {
    iceServers = JSON.parse(iceJson);
  } catch {
    iceServers = [{ urls: ['stun:stun.l.google.com:19302'] }];
  }

  fs.mkdirSync(dataDir, { recursive: true });

  const clearlistEnforce = String(process.env.CLEARLIST_ENFORCE || '') === '1';
  const clearlistUrl = process.env.CLEARLIST_URL || null;
  const clearlistFailMode = (process.env.CLEARLIST_FAIL_MODE === 'open' ? 'open' : 'closed') as 'open' | 'closed';

  const name = process.env.NAME || null;
  const operator = process.env.OPERATOR || null;
  const region = process.env.REGION || null;

  const ipLogging = (String(process.env.IP_LOGGING || '') === 'on' || String(process.env.IP_LOGGING || '') === '1')
    ? 'on'
    : 'off';

  const ipIntelUrl = process.env.IP_INTEL_URL || null;
  const ipIntelTtlSec = intEnv('IP_INTEL_TTL_SEC', 300);

  // If no IP intel configured, be honest: disable vpn/asn enforcement modes.
  const rawVpnMode = (process.env.VPN_FILTER_MODE || 'off').toLowerCase();
  const vpnFilterMode = (ipIntelUrl
    ? (rawVpnMode === 'reject' ? 'reject' : rawVpnMode === 'log' ? 'log' : 'off')
    : 'off') as 'off' | 'log' | 'reject';

  const rawAsnMode = (process.env.ASN_BLOCK_MODE || 'off').toLowerCase();
  const asnBlockMode = (ipIntelUrl
    ? (rawAsnMode === 'reject' ? 'reject' : rawAsnMode === 'log' ? 'log' : 'off')
    : 'off') as 'off' | 'log' | 'reject';

  const asnBlocklist = String(process.env.ASN_BLOCKLIST || '')
    .split(',')
    .map((s) => parseInt(s.trim(), 10))
    .filter((n) => Number.isFinite(n) && n > 0);

  // Support both new and old env var names.
  const submitBurst = intEnv('SUBMIT_BURST', 10);
  const submitRatePerSec = intEnv('SUBMIT_RPS', intEnv('SUBMIT_RATE_PER_SEC', 2));

  // H3b: sane default connection cap; CONN_MAX=0 explicitly disables the cap.
  const connMaxConfigured = intEnv('CONN_MAX', 256);

  // Startup-validated: a malformed or ambiguous proxy configuration aborts the
  // process instead of silently trusting or ignoring client-IP headers.
  const trustedProxy = parseTrustedProxyConfig(process.env);

  // Upper bound on tape entries a single TAPE_SUB resync may replay.
  const tapeResyncMaxEntries = Math.max(1, intEnv('TAPE_RESYNC_MAX_ENTRIES', 10000));
  // Per-client-IP token bucket for the unauthenticated HTTP RPC entry points.
  const httpRpcPerIpRps = Math.max(1, intEnv('HTTP_RPC_PER_IP_RPS', 20));
  const httpRpcPerIpBurst = Math.max(1, intEnv('HTTP_RPC_PER_IP_BURST', 40));
  // Concurrency caps: 0 disables. (Parsed here, not with `|| default`, which would
  // turn an explicit 0 back into the default.)
  const connMaxPerIp = Math.max(0, intEnv('CONN_MAX_PER_IP', 16));
  const pendingRpcMaxPerSession = Math.max(0, intEnv('PENDING_RPC_MAX_PER_SESSION', 32));
  const pendingRpcMaxPerIp = Math.max(0, intEnv('PENDING_RPC_MAX_PER_IP', 256));

  return {
    port: intEnv('PORT', intEnv('SERVER_PORT', 8787)),
    wsPath: process.env.WS_PATH || '/ws',
    dataDir,
    tapePath,
    idxPath,
    idxStride: intEnv('TAPE_INDEX_STRIDE', 1000),
    replayBatch: intEnv('TAPE_REPLAY_BATCH', 500),
    collatorKeyPath,
    infraAttestationsPath: infraAttestationsPath || null,
    infraAttestationsJson,
    maxMsgBytes: intEnv('MAX_MSG_BYTES', 1048576),
    submitBurst,
    submitRatePerSec,
    clearlistEnforce,
    clearlistUrl,
    clearlistFailMode,
    name,
    operator,
    region,
    ipLogging,
    vpnFilterMode,
    asnBlockMode,
    asnBlocklist,
    ipIntelUrl,
    ipIntelTtlSec,
    connMax: connMaxConfigured > 0 ? connMaxConfigured : null,
    trustedProxy,
    tapeResyncMaxEntries,
    httpRpcPerIpRps,
    httpRpcPerIpBurst,
    connMaxPerIp,
    pendingRpcMaxPerSession,
    pendingRpcMaxPerIp,
    tlsKeyPath: process.env.TLS_KEY_PATH || null,
    tlsCertPath: process.env.TLS_CERT_PATH || null,
    iceServers,
  };
}
