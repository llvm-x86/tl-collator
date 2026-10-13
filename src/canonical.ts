import { sha256Hex } from './crypto.js';

// Unsafe object keys: assignment of `__proto__` on a plain object triggers the
// prototype setter (dropping the key and mutating the prototype), and
// `constructor`/`prototype` are the other classic pollution vectors. The
// canonicalizer below never interprets keys as accessors (own-key-safe), and
// the schema/validation layer rejects envelopes carrying these keys outright.
export const UNSAFE_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (!v || typeof v !== 'object') return false;
  const proto = Object.getPrototypeOf(v);
  return proto === Object.prototype || proto === null;
}

// Recursively find unsafe keys (`__proto__`/`constructor`/`prototype`).
export function findUnsafeKey(v: unknown): string | null {
  if (Array.isArray(v)) {
    for (const item of v) {
      const hit = findUnsafeKey(item);
      if (hit) return hit;
    }
    return null;
  }
  if (isPlainObject(v)) {
    for (const k of Object.keys(v)) {
      if (UNSAFE_KEYS.has(k)) return k;
      const hit = findUnsafeKey((v as Record<string, unknown>)[k]);
      if (hit) return hit;
    }
  }
  return null;
}

function canonicalizeValue(v: any): any {
  if (v === null) return null;
  if (Array.isArray(v)) return v.map(canonicalizeValue);
  if (isPlainObject(v)) {
    // Build the canonical object with a null prototype and defineProperty so
    // keys like `__proto__` become ordinary own keys instead of triggering the
    // Object.prototype setter (which silently dropped them and caused hash
    // collisions / prototype pollution).
    const out: Record<string, any> = Object.create(null);
    const keys = Object.keys(v).sort();
    for (const k of keys) {
      Object.defineProperty(out, k, {
        value: canonicalizeValue(v[k]),
        enumerable: true,
        writable: true,
        configurable: true,
      });
    }
    return out;
  }
  return v;
}

export function stableStringify(v: unknown): string {
  return JSON.stringify(canonicalizeValue(v));
}

/**
 * Signed envelope fields (TL-Canon v1, see spec/schemas/tl-canon-v1.md):
 * every own field of the OrderEnvelopeV1 except `orderId` (the digest being
 * derived) and `sigTrader` (the signature over that digest). For a well-formed
 * envelope that is `v`, `kind`, `body`, `traderPubKey`, `clientNonce`, plus
 * `cancelsOrderId` / `replacesOrderId` when present.
 */
export function envelopeSignedFields(envelope: unknown): Record<string, unknown> {
  const out: Record<string, unknown> = Object.create(null);
  if (!envelope || typeof envelope !== 'object') return out;
  for (const k of Object.keys(envelope as Record<string, unknown>)) {
    if (k === 'orderId' || k === 'sigTrader') continue;
    Object.defineProperty(out, k, {
      value: (envelope as Record<string, unknown>)[k],
      enumerable: true,
      writable: true,
      configurable: true,
    });
  }
  return out;
}

/**
 * Envelope hash (TL-Canon v1):
 *
 *   orderId = sha256(stableStringify(envelope minus {orderId, sigTrader}))
 *
 * `sigTrader` is a compact 64-byte secp256k1 signature over the 32 raw bytes of
 * `orderId`. Deriving the digest over the *whole* envelope (not just `body`)
 * binds `kind`, `cancelsOrderId` and `replacesOrderId` into the trader
 * signature, so a harvested `(orderId, sigTrader, traderPubKey, body)` from the
 * tape can never be re-submitted as a forged CANCEL/REPLACE. The digest is
 * lowercase hex.
 *
 * NOTE (BREAKING): this supersedes the batch-1 body-only derivation
 * `sha256(stableStringify(body) + traderPubKey + clientNonce)`. Clients must
 * adopt this convention (identical to scripts/smoke-live-flow.cjs buildOrder).
 */
export function computeEnvelopeHash(envelope: unknown): string {
  return sha256Hex(stableStringify(envelopeSignedFields(envelope)));
}

/**
 * Order ID derivation: `orderId` is exactly the envelope hash. Kept under the
 * historical name so client code reads naturally; the argument is now the
 * envelope (any object exposing the signed fields), not `(body, pubKey, nonce)`.
 */
export function computeOrderId(envelope: unknown): string {
  return computeEnvelopeHash(envelope);
}
