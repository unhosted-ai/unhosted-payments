# ADR-0010: Transactional public mode — per-payment-rail and per-country policy

Status: Draft (2026-05-16)

Companion to [unhosted-core ADR-0001 "public-mode architecture"](https://github.com/unhosted-ai/unhosted-core/blob/main/design/0001-public-mode-architecture.md) and ADR-0006 ("dual-wallet onboarding"). ADR-0001 said *that* public mode would settle; this ADR says *how* settlement is gated.

## Context

Once a peer opts in to public mode (renting idle compute to strangers), money has to move. Two facts of life shape the design:

1. **Rails are heterogeneous.** USDC-on-Base, Lightning, Stripe Connect, Apple Pay, and "manual / out-of-band" all settle differently, have different KYC requirements, and have different chargeback windows. A single "process a payment" abstraction is a lie that will leak the moment a Stripe dispute hits a host that has already paid out a layer-host peer.
2. **Compliance is per-country, not global.** A host in Singapore may be allowed to accept USDC from a payer in Germany but not from a payer in North Korea; a host in California may be barred from accepting *anything* from a payer in a sanctioned jurisdiction regardless of rail. We cannot ship one global "public mode is on" toggle.

The naive approach — "host says yes/no to a payment when it arrives" — fails because by the time a payment arrives, the job may have already been priced, queued, or even started, and reversing the quote costs the payer a confusing UX and costs the host wasted scheduler state.

## Decision

Two artifacts, both shipped from this repo (`unhosted-payments`), both consumed by the daemon (`unhosted-core`) via a thin Rust crate:

### 1. `PeerPaymentPolicy` — a pre-filter, not a payment

Every public-mode peer publishes a policy describing **what they accept**, evaluated before quoting:

```rust
pub struct PeerPaymentPolicy {
    pub accepted_rails: BTreeSet<PaymentRail>,
    pub min_kyc: KycTier,           // None | Email | IdVerified
    pub blocked_countries: BTreeSet<Country>, // ISO 3166 alpha-2
}
```

When a quote request comes in carrying a `PayerContext { rail, kyc, country }`, the host runs `policy.accepts(&payer)`. Failure modes:

- `RailNotAccepted` — the host doesn't take this rail. Cheapest signal, surfaced first.
- `KycTooLow` — payer's asserted tier is below the host's minimum.
- `CountryBlocked` — payer's country is on the host's block-list.

The policy is **coarse and explicit**. It is *not*:

- Pricing — that comes after the filter passes.
- Per-job compliance — rails do their own KYC/AML; the host's only signal is the asserted tier.
- A safety net — a buggy or misconfigured `accepted_rails` set produces `RailNotAccepted` on every request, which is the safe default.

Countries are a **block-list, not an allow-list**, because new peers must be able to serve "anyone except the jurisdictions our compliance vendor explicitly named" without enumerating 195 ISO codes.

### 2. `SignedReceipt` — the cross-trust-boundary primitive

When a job completes, the host emits a `UsageReport` (job id, host pubkey, payer pubkey, rail, units served, unit price, issued-at) and signs it with its Ed25519 identity key. The wire form is canonical JSON (object keys sorted recursively, no whitespace) — *not* RFC-8785, just a single deterministic implementation in this crate that the signer and verifier both call.

Every rail integration eventually reduces its outcome to one of these. Rail-specific adapters (Stripe webhook, Lightning preimage, USDC tx hash) are how the receipt's `units` get *paid for*; the receipt itself is what proves the work happened.

The host pubkey lives **inside** the signed body, not just in the envelope, so a verifier cannot be tricked into checking the sig against the wrong key. The payer pubkey is included for the same reason — to prevent receipt reuse across payers.

## Slicing plan

This ADR ships in slices. Each slice is shippable alone; nothing in a later slice silently breaks an earlier one.

- **Slice 1 (this commit):** `core/` crate. `PeerPaymentPolicy`, `PaymentRail`, `KycTier`, `Country`, `PayerContext`, `SignedReceipt`, `verify_receipt`. No rails wired up. 18 unit tests green.
- **Slice 2:** Daemon integration. Quote endpoint in `unhosted-core` calls `policy.accepts()`; rejected quotes return a structured error the UI can render.
- **Slice 3:** First rail. Most likely **Lightning** — small unit (sats), no chargebacks, doesn't need a KYC vendor for a v0. Adapter lives in `core/` or a sibling crate (`rails-lightning/`), TBD.
- **Slice 4:** Wallet helpers (`wallet-js/`) so the payer side can produce signed quote requests from the browser.
- **Slice 5:** USDC-on-Base via `contracts/` (Solidity escrow + receipt-anchor), once chain-side audit budget exists. This is the slice that will lag the others, which is *fine* — it's why this repo is separate from the daemon.

## Consequences

- **Pro:** Compliance work and rail integrations move on their own clock. A blocked KYC vendor review for Stripe doesn't stall Lightning.
- **Pro:** The signed-receipt primitive is small enough to audit in isolation. A reader who wants to know "does unhosted's money handling forge receipts?" reads ~200 lines of `receipt.rs`.
- **Con:** The block-list-not-allow-list choice means a new sanctions designation requires *every* public-mode peer to update their policy. We mitigate by shipping a recommended default block-list in the daemon, but the trust boundary is still "peer self-declares".
- **Con:** Canonical JSON without RFC-8785 means a second implementation (e.g., a verifier written in Go) has to either link this crate or re-implement `sort_value`. Acceptable while there is one implementation; revisit when a second one ships.

## Open questions

- **Receipt freshness window.** How far past `issued_at` is a receipt still acceptable? Verifier-side policy, but the verifier needs a sensible default. Likely 24h; deferred to slice 2.
- **Refunds.** No primitive yet. Probably a `RefundReceipt` that references a prior `SignedReceipt.job_id`; deferred until the first rail with refund semantics (Stripe) lands.
- **Multi-host jobs.** A VRAM-pooled job has one orchestrator and N layer-hosts. Does the orchestrator emit a single receipt, or one per layer-host? Leaning single, with the orchestrator settling internally — but this is the call that most needs feedback from someone who has shipped a payouts system before.
