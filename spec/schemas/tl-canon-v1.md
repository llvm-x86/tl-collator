# TL-Canon v1

Deterministic canonical JSON used for hashing/signing.

Rules:
- Objects: recursively sort keys lexicographically (`Object.keys().sort()` order).
- No whitespace: canonical JSON has no spaces/newlines.
- Arrays: preserve order.
- Numbers: only safe integers; monetary values must be strings.
- Omit keys whose value is `undefined`.
- Strings: UTF-8; hex strings should be lowercase unless specified otherwise.
- Keys are always plain own property names. Canonicalization must never
  interpret a key as an accessor: `__proto__` is serialized as an ordinary
  key (e.g. `{"__proto__":{}}` canonicalizes with that key present, never as
  a prototype mutation). Implementations built on `Object` assignment must use
  own-key-safe construction (`Object.create(null)` + `Object.defineProperty`)
  or equivalent.
- The keys `__proto__`, `constructor` and `prototype` are **rejected** by the
  schema/validation layer wherever an `OrderEnvelopeV1` is accepted.

## Order ID derivation (OrderEnvelopeV1)

`orderId` MUST be derived from the canonical envelope — every own field of the
`OrderEnvelopeV1` except `orderId` (the digest being derived) and `sigTrader`
(the signature over that digest):

```
orderId = sha256(stableStringify(envelope minus {orderId, sigTrader}))
```

- For a well-formed envelope the signed fields are `v`, `kind`, `body`,
  `traderPubKey`, `clientNonce`, plus `cancelsOrderId` / `replacesOrderId`
  when present. All of them are bound into the digest, so `kind`, `cancelsOrderId`
  and `replacesOrderId` are covered by `sigTrader` just like `body` is.
- The digest is lowercase hex (32 bytes / 64 chars).
- `sigTrader` is a compact 64-byte secp256k1 signature over the 32 raw bytes
  of `orderId`.

The collator rejects any `SUBMIT` whose `orderId` does not exactly match this
derivation (`ERR` code `bad_order_id`). This binds `sigTrader` to the complete
order intent: a harvested `(orderId, sigTrader, traderPubKey)` triple can never
be re-submitted with an attacker-chosen `body`, `kind`, `cancelsOrderId` or
`replacesOrderId` — in particular a tape-harvested `NEW` order cannot be
replayed as a forged `CANCEL`/`REPLACE` of somebody else's order. Worked
examples: `spec/test-vectors.json` → `orderTest` and `orderCancelTest`.

⚠️ **BREAKING (supersedes the earlier body-only rule):** the previous draft of
this document derived `orderId` as
`sha256(stableStringify(body) + traderPubKey + clientNonce)`, which left `kind`
and the cancel/replace target ids outside the signature. Clients must adopt the
envelope-hash derivation above (identical to `scripts/smoke-live-flow.cjs`
`buildOrder`); envelopes computed the old way are rejected with `bad_order_id`.
