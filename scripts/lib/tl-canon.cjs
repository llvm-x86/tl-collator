'use strict';
// TL-Canon v1 serializer for the standalone scripts (smoke clients and the
// infra-attestation signer). Same rules as src/canonical.ts and
// spec/schemas/tl-canon-v1.md; spec/test-vectors.json is checked against both.
// Keys are written in Unicode code-point order by hand, because JSON.stringify
// would hoist integer-like keys ("9", "10") to the front.

const LONE_SURROGATE = /[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/;

function scalarViolation(v) {
  if (typeof v === 'number') return Number.isSafeInteger(v) ? null : 'number is not a safe integer';
  if (typeof v === 'string') return LONE_SURROGATE.test(v) ? 'string is not well-formed Unicode' : null;
  return null;
}

function compareCodePoints(a, b) {
  const x = Array.from(a, (c) => c.codePointAt(0));
  const y = Array.from(b, (c) => c.codePointAt(0));
  for (let i = 0; i < Math.min(x.length, y.length); i++) {
    if (x[i] !== y[i]) return x[i] - y[i];
  }
  return x.length - y.length;
}

function serialize(v) {
  if (v === null) return 'null';
  const t = typeof v;
  if (t === 'number' || t === 'string') {
    const problem = scalarViolation(v);
    if (problem) throw new TypeError(`TL-Canon: ${problem}`);
    return JSON.stringify(v);
  }
  if (t === 'boolean') return JSON.stringify(v);
  if (t === 'undefined' || t === 'function' || t === 'symbol') return undefined;
  if (Array.isArray(v)) return `[${Array.from(v, (item) => serialize(item) ?? 'null').join(',')}]`;
  if (v && typeof v === 'object' && (Object.getPrototypeOf(v) === Object.prototype || Object.getPrototypeOf(v) === null)) {
    const parts = [];
    for (const k of Object.keys(v).sort(compareCodePoints)) {
      const problem = scalarViolation(k);
      if (problem) throw new TypeError(`TL-Canon: key ${problem}`);
      const desc = Object.getOwnPropertyDescriptor(v, k);
      if (!desc || !('value' in desc)) continue;
      const s = serialize(desc.value);
      if (s === undefined) continue;
      parts.push(`${JSON.stringify(k)}:${s}`);
    }
    return `{${parts.join(',')}}`;
  }
  return JSON.stringify(v);
}

function stableStringify(v) {
  return serialize(v) ?? 'null';
}

module.exports = { stableStringify };
