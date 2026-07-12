#!/usr/bin/env node
/* eslint-disable no-console */
const fs = require('node:fs');
const path = require('node:path');

const collatorPath = path.resolve(__dirname, '..', 'src', 'index.ts');
const relayerPath = process.env.TL_RELAYER_RPC_ROUTE_SOURCE || 'C:\\projects\\tl-relayer\\src\\routes\\rpc.route.ts';
const collator = fs.readFileSync(collatorPath, 'utf8');
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

for (const method of [...collatorMethods, ...relayerMethods]) {
  if (prohibited.test(method)) throw new Error(`Prohibited public RPC method: ${method}`);
}
for (const method of required) {
  if (!collatorMethods.includes(method) || !relayerMethods.includes(method)) {
    throw new Error(`Required public method missing: ${method}`);
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
]) {
  if (!collator.includes(needle)) throw new Error(`Collator policy missing: ${needle}`);
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
}, null, 2));
