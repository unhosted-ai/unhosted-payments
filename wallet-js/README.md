# @unhosted-ai/wallet-js

Payer-side helpers for [unhosted public mode](https://github.com/unhosted-ai/unhosted-payments/blob/main/design/0010-transactional-public-mode.md). Browser-friendly, no native bindings, AGPL-3.0-or-later.

A "payer" is anyone asking an unhosted daemon to do work in exchange for payment. They hold an Ed25519 keypair, build a `QuoteRequestBody`, sign it, and POST. The wire shape exactly matches the Rust `unhosted-payments-core` crate — same canonical-JSON rules, same base64 (no-pad) encoding, same field names — so the daemon's `verify_sig` round-trips without translation.

## Install

```bash
npm install @unhosted-ai/wallet-js
```

Requires Node ≥ 20 or any modern browser.

## Usage

```ts
import { generatePayerKey, requestQuote } from "@unhosted-ai/wallet-js";

// 1. Hold a key. Persist `key.secret` (32 bytes) wherever you keep
//    secrets — this is the only thing that authenticates you to the
//    daemon. Anyone with it can quote as you.
const key = await generatePayerKey();

// 2. Ask the daemon what a job would cost.
const quote = await requestQuote({
  daemonUrl: "http://127.0.0.1:7777",
  payer: { rail: "lightning", kyc: "email", country: "US" },
  requestedUnits: 1000,
  key,
});

if (quote.kind === "quote") {
  console.log(`approved: ${quote.quoted_units} units at ${quote.unit_price_micros} micros each`);
  console.log(`quote expires at ${new Date(quote.expires_at * 1000).toISOString()}`);
} else {
  console.log(`rejected: ${quote.reason}`);
}
```

## Verifying a receipt

After a job completes, the daemon returns a `SignedReceipt`. Verify it client-side before treating it as proof of work:

```ts
import { verifyReceipt, type SignedReceipt } from "@unhosted-ai/wallet-js";

const ok = await verifyReceipt(receipt);
// `ok` is true iff the sig verifies against the host_pubkey *inside*
// the signed body. That binding is what prevents receipt forgery
// where an attacker swaps the claimed signer.
```

## What this package does NOT do

- **Manage keys for you.** `generatePayerKey()` returns 32 raw secret bytes. Persisting them is your call. A real wallet has UX, storage, recovery; this is the cryptographic layer only.
- **Talk to a payment rail.** The quote is a price *commitment* — actually paying happens via Lightning / USDC / Stripe / etc. Rail adapters live elsewhere.
- **Negotiate.** The daemon's price is take-it-or-leave-it. If a peer rejects, ask another peer.

## Contract with `unhosted-payments-core`

Both sides MUST agree on:

1. **Canonical JSON**: object keys sorted recursively, no whitespace, arrays preserve order. See `canonicalJson` in `src/index.ts` and `canonical_json` in `core/src/receipt.rs`.
2. **Base64**: STANDARD_NO_PAD (no trailing `=`). The Rust side rejects padded input outright.
3. **Ed25519**: stock RFC-8032, no domain separation, no context bytes.

If you change any of these on either side without changing the other, signatures stop verifying. The test suite asserts a known canonical-JSON output (`{"a":2,"m":{"b":4,"y":3},"z":1}`) that matches the Rust test — that's the canary.

## Development

```bash
npm install
npm run build   # tsc into dist/
npm test        # node --test against src/ via tsx
```
