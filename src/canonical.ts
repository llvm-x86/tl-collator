import { sha256Hex } from './crypto.js';

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && Object.getPrototypeOf(v) === Object.prototype;
}

function canonicalizeValue(v: any): any {
  if (v === null) return null;
  if (Array.isArray(v)) return v.map(canonicalizeValue);
  if (isPlainObject(v)) {
    const out: Record<string, any> = {};
    const keys = Object.keys(v).sort();
    for (const k of keys) out[k] = canonicalizeValue(v[k]);
    return out;
  }
  return v;
}

export function stableStringify(v: unknown): string {
  return JSON.stringify(canonicalizeValue(v));
}

/**
 * Order ID derivation (TL-Canon v1, see spec/schemas/tl-canon-v1.md):
 *
 *   orderId = sha256(stableStringify(body) + traderPubKey + clientNonce)
 *
 * `traderPubKey` and `clientNonce` are concatenated exactly as they appear in
 * the OrderEnvelopeV1; the digest is lowercase hex. This matches the wallet
 * client convention (scripts/smoke-live-flow.cjs buildOrder()). Enforcing it
 * server-side binds sigTrader (which signs the 32 raw bytes of orderId) to the
 * order content, so a harvested (orderId, sigTrader, traderPubKey) triple can
 * never be re-attached to a different body.
 */
export function computeOrderId(body: unknown, traderPubKey: string, clientNonce: string): string {
  return sha256Hex(stableStringify(body) + traderPubKey + clientNonce);
}
