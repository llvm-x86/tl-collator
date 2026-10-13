# TL-Canon v1

Deterministic canonical JSON used for hashing/signing.

Rules:
- Objects: recursively sort keys lexicographically (`Object.keys().sort()` order).
- No whitespace: canonical JSON has no spaces/newlines.
- Arrays: preserve order.
- Numbers: only safe integers; monetary values must be strings.
- Omit keys whose value is `undefined`.
- Strings: UTF-8; hex strings should be lowercase unless specified otherwise.

## Order ID derivation (OrderEnvelopeV1)

`orderId` MUST be derived from the canonical order content:

```
orderId = sha256(stableStringify(body) + traderPubKey + clientNonce)
```

- `body` is the `OrderBodyV1` object, canonicalized per the rules above.
- `traderPubKey` and `clientNonce` are concatenated verbatim (lowercase hex).
- The digest is lowercase hex (32 bytes / 64 chars).
- `sigTrader` is a compact 64-byte secp256k1 signature over the 32 raw bytes
  of `orderId`.

The collator rejects any `SUBMIT` whose `orderId` does not exactly match this
derivation (`ERR` code `bad_order_id`). This binds `sigTrader` to the order
content: a harvested `(orderId, sigTrader, traderPubKey)` triple can never be
re-submitted with an attacker-chosen `body`. Worked example:
`spec/test-vectors.json` → `orderTest`.

