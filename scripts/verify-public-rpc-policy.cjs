#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require('node:fs');
const path = require('node:path');

const collatorPath = path.resolve(__dirname, '..', 'src', 'index.ts');
const canonicalPath = path.resolve(__dirname, '..', 'src', 'canonical.ts');
const clientIpPath = path.resolve(__dirname, '..', 'src', 'clientIp.ts');
const schemaPath = path.resolve(__dirname, '..', 'src', 'schema.ts');
const orderSchemaPath = path.resolve(__dirname, '..', 'spec', 'schemas', 'order-envelope.v1.schema.json');
// The relayer checkout is a sibling of this repo (contrib/tl-relayer when both
// are cloned side by side); TL_RELAYER_RPC_ROUTE_SOURCE overrides the location.
const relayerPath = process.env.TL_RELAYER_RPC_ROUTE_SOURCE
  || path.resolve(__dirname, '..', '..', 'tl-relayer', 'src', 'routes', 'rpc.route.ts');
const collator = fs.readFileSync(collatorPath, 'utf8');
const canonical = fs.readFileSync(canonicalPath, 'utf8');
const clientIpSrc = fs.readFileSync(clientIpPath, 'utf8');
const configSrc = fs.readFileSync(path.resolve(__dirname, '..', 'src', 'config.ts'), 'utf8');
const schemaSrc = fs.readFileSync(schemaPath, 'utf8');
const orderSchema = fs.readFileSync(orderSchemaPath, 'utf8');
if (!fs.existsSync(relayerPath)) {
  throw new Error(`relayer RPC route source not found: ${relayerPath} (set TL_RELAYER_RPC_ROUTE_SOURCE)`);
}
const relayer = fs.readFileSync(relayerPath, 'utf8');

function methodsFrom(source, name) {
  const block = source.match(new RegExp(`const ${name} = new Set\\(\\[([\\s\\S]*?)\\]\\);`));
  if (!block) throw new Error(`Missing ${name}`);
  return [...block[1].matchAll(/'([^']+)'/g)].map(([, method]) => method);
}

const collatorMethods = methodsFrom(collator, 'PUBLIC_RPC_METHODS');
const relayerMethods = methodsFrom(relayer, 'PUBLIC_RPC_METHODS');
const required = [
  'tl_getstatesnapshot',
  'tl_getsyncstatus',
  'tl_getallbalancesforaddress',
  'tl_listproperties',
  'tl_watchonly_register',
  'tl_watchonly_utxos',
  'tl_createpayload_attestation',
  'tl_createpayload_commit_tochannel',
];
const prohibited = /(?:sign|privatekey|dumpprivkey|importprivkey|walletpassphrase|loadwallet|unloadwallet|finalizepsbt|sendrawtransaction|broadcast|sendtoaddress|addmultisig)/i;

// Read-only bitcoin-family RPCs backing the documented HTTP compat routes
// (/chain/info, /address/validate/*, /address/utxo/*, /tx/decode). These MUST
// stay on the collator allowlist: with the legacy proxy disabled (H2) they
// fall through to the WebRTC-routed path, and the README documents that.
const readOnlyCompat = ['getblockchaininfo', 'validateaddress', 'listunspent', 'decoderawtransaction'];

for (const method of [...collatorMethods, ...relayerMethods]) {
  if (prohibited.test(method)) throw new Error(`Prohibited public RPC method: ${method}`);
}
for (const method of required) {
  if (!collatorMethods.includes(method) || !relayerMethods.includes(method)) {
    throw new Error(`Required public method missing: ${method}`);
  }
}
for (const method of readOnlyCompat) {
  if (!collatorMethods.includes(method)) {
    throw new Error(`Required read-only compat RPC method missing from collator: ${method}`);
  }
}

for (const needle of [
  'if (!Array.isArray(service.methods) || service.methods.length === 0) continue;',
  "code: 'RPC_ADVERTISEMENT_REJECTED'",
  'TL_COLLATOR_CORS_ORIGINS',
  'TL_COLLATOR_ENABLE_LEGACY_TL_PROXY',
  "code: 'LEGACY_TL_PROXY_DISABLED'",
  "code: 'RPC_SERVICE_FORBIDDEN'",
  "code: 'RPC_METHOD_FORBIDDEN'",
  "'tl_watchonly_register'",
  "'tl_watchonly_utxos'",
  "'/tx/buildUnsigned'",
  "'/tx/buildunsigned'",
  "'/tx/build-unsigned'",
  "proxyLegacyJson('POST', u.pathname, body)",
  // Security batch 1 (issue #1): legacy proxy master switch + faucet opt-in (H2),
  // trusted-proxy gating for client IP headers (H1), orderId binding (C1),
  // RPC_RES provider binding and pending-RPC caps (C2).
  'LEGACY_PROXY_ENABLED',
  "code: 'LEGACY_PROXY_DISABLED'",
  'LEGACY_PROXY_FAUCET',
  "code: 'LEGACY_PROXY_FAUCET_DISABLED'",
  'clientIpResolver.resolve(req)',
  'clientIpResolver.headersTrusted(req)',
  'net.isIP(ip) === 0',
  // Adversarial review fixes (batch 2): envelope-bound orderId (C1 complete),
  // endpoint allowlist regression (H2), connection fairness (H3b), TAPE_SUB
  // subscription survival, XFF rightmost hop, per-session pending RPC cap.
  'computeEnvelopeHash(order)',
  "code: 'bad_order_id'",
  "'getblockchaininfo'",
  "'validateaddress'",
  "'listunspent'",
  "'decoderawtransaction'",
  'sess.wantsTape = true;',
  "code: 'rate_limited', msg: 'TAPE_SUB resync too frequent; live feed stays subscribed'",
  'for (const key of admissionKeys) rpcAdmission.acquire(key);',
  "const tapeResyncGate = new MinIntervalGate(",
  "const admissionKeys = sessionKey ? [sessionKey, ipKey] : [ipKey];",
  "if (!httpRpcAllowed(clientIp)) {",
  "message: 'internal error'",
  'pendingRpcMaxPerSession',
  "code: 'RPC_RATE_LIMITED'",
  'tape.hasOrder(order.orderId)',
  'if (!entry) {',
  "'RPC_SESSION_OVERLOADED'",
  'releasePending(pendingKey)',
  'CONN_IDLE_TIMEOUT_MS',
  'CONN_HANDSHAKE_GRACE_MS',
  'settleRpcResponse(wm.res, sess)',
  'pending.provider !== sender',
  'pendingRpc.size >= pendingRpcMax',
]) {
  if (!collator.includes(needle)) throw new Error(`Collator policy missing: ${needle}`);
}

// canonical.ts: own-key-safe canonicalization + envelope-hash derivation.
for (const needle of [
  "new Set(['__proto__', 'constructor', 'prototype'])",
  'Object.create(null)',
  'Object.defineProperty',
  'envelope minus {orderId, sigTrader}',
  'envelopeSignedFields',
  'computeEnvelopeHash',
]) {
  if (!canonical.includes(needle)) throw new Error(`Canonical policy missing: ${needle}`);
}

// clientIp.ts: the single trusted-client-IP resolver; headers believed only from
// configured proxy hops, and proxy configuration refused at startup when ambiguous.
for (const needle of [
  'TRUST_PROXY_CIDRS',
  'TRUST_PROXY=1 requires TRUST_PROXY_CIDRS',
  'if (!isTrustedHop(peer)) return peer;',
]) {
  if (!clientIpSrc.includes(needle)) throw new Error(`Client IP policy missing: ${needle}`);
}

// config.ts: admission caps are parsed strictly (startup aborts on garbage).
for (const needle of ['intEnv(\'CONN_MAX_PER_IP\'', 'intEnv(\'PENDING_RPC_MAX_PER_SESSION\'', 'throw new Error(`${k} must be an integer']) {
  if (!configSrc.includes(needle)) throw new Error(`Config policy missing: ${needle}`);
}

// schema.ts: unsafe-key rejection before schema validation.
for (const needle of ['findCanonicalViolation', 'validateOrderEnvelope']) {
  if (!schemaSrc.includes(needle)) throw new Error(`Schema policy missing: ${needle}`);
}

// order-envelope schema: unsafe keys rejected at the JSON-Schema layer too.
for (const needle of ['"propertyNames"', '"__proto__"', '"constructor"', '"prototype"']) {
  if (!orderSchema.includes(needle)) throw new Error(`Order schema policy missing: ${needle}`);
}

for (const needle of [
  'async function handleAllocatedRpc',
  'PUBLIC_RPC_METHODS.has(normalizedMethod)',
  "'PAYLOAD_TYPE_FORBIDDEN'",
  "'RPC_METHOD_FORBIDDEN'",
  "'tl_watchonly_register'",
  "'tl_watchonly_utxos'",
]) {
  if (!relayer.includes(needle)) throw new Error(`Relayer policy missing: ${needle}`);
}

console.log(JSON.stringify({
  ok: true,
  collatorMethodCount: collatorMethods.length,
  relayerMethodCount: relayerMethods.length,
  collatorOnlyMethods: collatorMethods.filter((method) => !relayerMethods.includes(method)),
  required,
  readOnlyCompat,
}, null, 2));
