# ADR-0011: Payment-rail integration plan

Status: Proposed (2026-05-19). Companion to [ADR-0010](./0010-transactional-public-mode.md), which defined the policy filter + signed-receipt primitives. This document is the operational plan for actually moving money through them.

## TL;DR

A `RailAdapter` trait in `unhosted-payments-core`. Five rails behind that trait, shipped in this order:

| Order | Rail | Why now / why not |
| --- | --- | --- |
| 1 | **Lightning** | Smallest unit (sats), no chargebacks, no required KYC vendor, well-documented BOLT specs, mature wallets. |
| 2 | **USDC on Base** | Programmable escrow (slice 5), low fees, USD-stable, broad wallet support. Adds the on-chain receipt anchor. |
| 3 | **USDC on Solana** | Same trust posture as Base, different chain. Reuses Solidity work poorly (different VM) — likely a later sibling crate. |
| 4 | **Stripe Connect** | The fiat path. Requires a legal entity to operate; supplies card / Apple Pay / Google Pay reach. Most regulated. |
| 5 | **Manual** | Out-of-band; host marks paid via signed admin action. Useful for one-off bespoke deals. |

Each rail is its own Rust crate behind a feature flag. The daemon links only the rails the operator wants. No rail is in the default build.

## Context

ADR-0010 gave us the rail-agnostic primitives:

- `PeerPaymentPolicy` (host accepts which rails / KYC tier / non-blocked countries)
- `SignedReceipt` (Ed25519 over canonical JSON, host-key embedded inside the signed body)
- `/v1/public-mode/quote` (payer-signed quote request, returns price stub or rejection)
- `/v1/public-mode/receipt/sign` (host signs a UsageReport with its identity key)

What's missing: the bit where money actually moves. Today every quote returns `unit_price_micros: 10` (a hard-coded stub) and no rail integration runs. This ADR plans the rail integrations.

## Patent / prior-art posture

**This section is informational. It is NOT a patent clearance. Real production deployment must include qualified counsel for the operator's jurisdiction.**

What's well-established prior art (so no one — us or anyone else — can newly patent it):

- Marketplaces that sell idle compute for tokens: Akash (AKT), Render Network (RNDR), DeepBrain Chain (DBC), Bittensor (TAO), io.net (IO), Hyperbolic, Cocoon on TON. All public since 2018–2025. The general pattern is unpatentable going forward.
- Lightning Network routing per BOLT 1–11 specifications. Open, MIT-licensed.
- USDC on Base / Solana settlements per Circle's published transfer mechanics, EIP-3009 / EIP-712 signature schemes, SPL-token transfer. All open standards.
- Ed25519 signature + canonical JSON message authentication. Decades of prior art.
- Pre-flight policy filtering of payments by rail / KYC tier / country block-list. Used by every cross-border payments processor. Not novel.

What we are deliberately NOT doing (and therefore not exposed on):

- **No payment routing optimization algorithms.** Some Lightning routing-optimization patents exist (Square / Block, others). We use BOLT-spec defaults; we do not invent new path-finding.
- **No fraud-detection ML.** Stripe, Adyen, Riskified, and others have heavy patent portfolios in this area. Our `PeerPaymentPolicy` is a static rule check (rail / KYC tier / country block-list), not adaptive ML.
- **No "one-click checkout" UX flows.** Amazon's 1-click patent has expired (US), but related quick-pay patents (Apple, Visa) remain. The payer-signed-quote flow is two steps minimum (quote → pay) by design.
- **No issued token.** Token issuance triggers a different regulatory + IP surface (Coinbase, FTX-era patent filings around order books). We don't issue.
- **No custody.** Custodial wallets are heavily patented (Coinbase, BitGo). We're non-custodial by design.
- **No biometric payment auth.** Apple, Mastercard, Visa hold large biometric-payment portfolios. We use Ed25519 signatures; the payer's device handles biometric unlock of their key locally, exactly as a hardware wallet does (and that pattern long predates current patents).

What appears to be novel about our design (worth documenting as prior art in case anyone tries to patent it later):

- **Rail-agnostic `PeerPaymentPolicy` with sanctions-default auto-merge enforced at the daemon level** — the operator cannot save a policy without comprehensively-sanctioned jurisdictions in the block-list. See [`unhosted-core/crates/unhosted-core/src/public_mode.rs`](https://github.com/unhosted-ai/unhosted-core/blob/main/crates/unhosted-core/src/public_mode.rs).
- **Signed-receipt where `host_pubkey` lives inside the signed body** — prevents an envelope swap that would let a verifier check the wrong key. See [`core/src/receipt.rs`](../core/src/receipt.rs).
- **Cross-language wire-identical canonical JSON between a Rust daemon and a TypeScript wallet** verified by a fixture test in both implementations. See [`wallet-js/test/wallet.test.ts`](../wallet-js/test/wallet.test.ts).

These three are documented here, dated to this commit, and AGPL-3.0-or-later licensed. They constitute defensive publication: anyone trying to patent them after this commit will face this ADR as cited prior art. See [`unhosted-core/IP_POSTURE.md`](https://github.com/unhosted-ai/unhosted-core/blob/main/IP_POSTURE.md) for the broader policy.

## Decision

### A common `RailAdapter` trait (Phase A)

Ships in `unhosted-payments-core`. No rail wired; the trait is the seam.

```rust
pub trait RailAdapter: Send + Sync {
    /// The rail this adapter handles.
    fn rail(&self) -> PaymentRail;

    /// Quote a price for `requested_units` units. Returns a stable
    /// quote with an expiry. Pricing is the adapter's call — it can
    /// pull from a rate oracle (Lightning), a smart contract
    /// (USDC-on-Base), or a fixed config (Manual).
    async fn quote(&self, ctx: &PayerContext, units: u64) -> Result<RailQuote, RailError>;

    /// Initiate settlement. Returns a rail-specific "payment intent"
    /// (Lightning invoice, EVM tx-to-sign, Stripe payment-intent
    /// secret, etc.) that the payer's client uses to actually pay.
    async fn intent(&self, quote: &RailQuote) -> Result<PaymentIntent, RailError>;

    /// Poll / observe settlement. Returns Settled(amount) once the
    /// rail confirms receipt, Pending if still waiting, Failed with
    /// a reason if it won't complete. Adapters that have webhooks
    /// (Stripe) wire the webhook into this same call via a state
    /// store; adapters that have chain RPCs (USDC-on-Base) poll.
    async fn observe(&self, intent: &PaymentIntent) -> Result<SettlementState, RailError>;

    /// Optional: refund hook. None means "this rail doesn't refund."
    /// Stripe will implement; Lightning won't (no chargeback by
    /// design); USDC will via the escrow contract.
    async fn refund(&self, intent: &PaymentIntent, amount: u64) -> Option<Result<RefundReceipt, RailError>> {
        None
    }
}
```

Phase A also adds:

- `RailRegistry` — singleton on the daemon, holds adapters keyed by `PaymentRail`. The quote endpoint consults `registry.get(payer.rail)?.quote(...)`.
- Adapter loading wired through Cargo features: `--features rail-lightning`, `--features rail-usdc-base`, etc. The default build has *no* rails — operators opt in to each one they want to accept.

**Shippable Phase A**: the trait + registry + a `Manual` adapter that returns a fixed-price quote and accepts an out-of-band "paid" admin signal. No external infra needed. Lets us test the rail-trait shape end-to-end.

### Phase B — Lightning rail

Sibling crate: `unhosted-payments-lightning`. Talks to either an LND node (gRPC) or a Core Lightning node (JSON-RPC) over a configured endpoint.

Operator flow:
1. Operator runs an LND or CLN node. Configures URL + macaroon in `~/.config/unhosted/lightning.toml`.
2. Operator adds `Lightning` to `PeerPaymentPolicy.accepted_rails`.
3. Daemon binary built with `--features rail-lightning`.

Payer flow:
1. Payer's wallet-js signs a quote with `rail: "lightning"`.
2. Daemon's Lightning adapter returns a `RailQuote { unit_price_micros, total_msat, expires_at }` priced from the latest BTC→USD rate (cached, default Coingecko mid).
3. Payer calls `/v1/public-mode/intent`. Adapter returns a BOLT-11 invoice.
4. Payer's wallet pays the invoice.
5. LND/CLN notifies the adapter via subscribed payment events. Adapter calls `host_identity.sign_receipt(...)` and returns the SignedReceipt.

Why this is small enough for v1:
- No chargebacks, so no dispute/refund state machine.
- No KYC vendor required (Lightning is permissionless; KYC tier is asserted not proven).
- No on-chain contract.
- Test infra is just a `regtest` LND + a local CLN — both are free / Dockerizable.

Out of scope for Phase B:
- Routing optimization (use BOLT defaults).
- Hop-count probes, route hints (let the wallet handle).
- Submarine swaps to/from on-chain.

### Phase C — USDC on Base

Sibling crate: `unhosted-payments-usdc-base`. Plus Solidity in `contracts/`.

Adds the escrow contract (slice 5 of ADR-0010):

```solidity
// SPDX-License-Identifier: AGPL-3.0-or-later
// UnhostedEscrow — minimal pay-on-receipt-verify escrow for unhosted compute.
//
// Payer deposits USDC + a quote_id. Host emits a SignedReceipt off-chain
// AND submits its hash + Ed25519 sig on-chain. Anyone can verify (Ed25519
// sig math is in EIP-7212 / RIP-7212 precompile on Base). On successful
// verify, USDC moves to host; on timeout without claim, USDC returns to payer.

contract UnhostedEscrow {
    event Deposited(bytes32 indexed quoteId, address payer, address host, uint256 amount, uint256 expiresAt);
    event Settled(bytes32 indexed quoteId, bytes32 receiptHash);
    event Refunded(bytes32 indexed quoteId);

    function deposit(bytes32 quoteId, address host, uint256 amount, uint256 ttlSeconds) external;
    function settle(bytes32 quoteId, bytes32 receiptHash, bytes calldata hostEd25519Sig) external;
    function refund(bytes32 quoteId) external; // payable to payer after expiry
}
```

Audit posture: contract is small (~150 LOC budgeted). Audit by a reputable firm (Trail of Bits, Spearbit, OpenZeppelin) is a prerequisite to mainnet deployment. Pre-audit, testnet (Base Sepolia) only.

Open questions for Phase C:
- Where the contract is deployed first (Base Sepolia testnet → 90+ days of dogfooding → mainnet).
- Whether to use Circle's CCTP for cross-chain or stay single-chain (single-chain first).
- Gas refunding: do hosts subsidize payer gas? (No — payer pays gas, same as any DApp.)

### Phase D — Stripe Connect

Sibling crate: `unhosted-payments-stripe`.

This is the fiat path: cards, Apple Pay, Google Pay, US ACH, EU SEPA. Stripe Connect handles the multi-party "platform takes a fee, host receives the rest" pattern.

**Phase D requires a legal entity to operate.** Stripe Connect platforms must be a registered business with KYC'd ownership. This is the first phase where the project *as a project* probably needs an LLC or equivalent — unless every operator self-hosts their own Stripe account and unhosted just helps them configure it (much cleaner: each operator's daemon talks to their own Stripe account, no unhosted-the-org in the middle).

Default plan: **operator-owned Stripe accounts.** Each operator configures their Stripe Connect account ID + API key locally; their daemon's Stripe adapter takes payments into that account directly. No money flows through any unhosted-the-org account. The project remains pure OSS infrastructure.

### Phase E — Manual rail

Trivial: a JSON config file declaring `paid: true` for a given `job_id`, signed by the operator's identity key. Allows out-of-band settlement (bank transfer, cash, barter) for bespoke deals between known parties. Ships in Phase A as a smoke test of the trait shape; gets refined as the other rails inform the trait.

## Per-phase compliance map

| Phase | Operator obligations the project doesn't take on |
| --- | --- |
| A (Manual) | None new beyond ADR-0010. |
| B (Lightning) | Operator's jurisdiction may treat Lightning income as virtual-asset receipt at fair market value; tax reporting is operator's call. KYC vendor not required (host's `min_kyc` is self-asserted by payer). |
| C (USDC) | EU MiCA above €1M/year may require CASP registration; UK MLRs may require FCA registration for crypto-asset exchanges. **Operator-side** obligation; project ships software. |
| D (Stripe) | Full PCI scope on the rail's side. Stripe Connect handles PCI compliance for accepted payments; operator handles their own connected account's KYC + tax. |
| E (Manual) | Pure operator responsibility. |

The project's own duties are unchanged from ADR-0010 + COMPLIANCE.md:

1. Sanctions-default block-list baked into the daemon (KP/IR/SY/CU).
2. AGPL-3.0-or-later licensing of all rail-adapter code.
3. No custody, no aggregation of operator funds, no project-issued token.
4. EAR §740.17 publicly-available source-code posture preserved.

## Threat model summary

Per-rail attacker capabilities (informal — formal threat model lands as a follow-up doc):

- **Lightning**: payer can claim "I paid" without paying (mitigated: the host's adapter only signs a receipt after LND/CLN confirms the invoice settled). Host can claim "I served" without serving (mitigated only by reputation; verifiable inference is research-grade and out of scope for v0). Routing nodes can fail (the wallet's problem; the host gets paid or doesn't).
- **USDC on Base**: same on the served-without-doing-work side. Custody risk is the smart contract's; mitigated by audit + open-source.
- **Stripe**: chargeback risk is real and one-sided. The escrow analog doesn't exist for cards. Hosts accepting Stripe should treat it as "pay now, refund possible for 60 days" and price accordingly.
- **All rails**: a host's identity key compromise lets attacker sign fraudulent receipts. Mitigated by file-system permissions (mode 0600 on `identity.toml`) and an explicit rotation procedure (see [SECURITY.md](https://github.com/unhosted-ai/unhosted-core/blob/main/SECURITY.md) — rotation procedure is planned, not yet shipped).

## Open questions (carry over from ADR-0010)

- Receipt freshness window — verifier-side default (lean: 24h).
- Multi-host receipts in VRAM-pool — single orchestrator-signed or N layer-host receipts? (Lean: single. Orchestrator settles internally with layer hosts using off-band trusted-peer accounting.)
- Refund flows beyond Stripe — none planned for Lightning (no chargeback); USDC via escrow timeout.
- LNURL / Lightning Address convenience — Phase B+ once basic Lightning works.

## Consequences

- **Pro:** Compliance and per-rail vendor risk move on their own clocks. A blocked Stripe review doesn't stall Lightning.
- **Pro:** Defensive publication of the novel patterns means no one else can corner them.
- **Pro:** The default build ships *no* rails, which keeps the daemon's regulatory surface zero. Operators who don't run public mode have no payment code in their binary.
- **Con:** Five separate rail crates is more maintenance than a unified "payments" crate. Worth it because each rail's failure modes are different enough that abstracting them is premature.
- **Con:** No central reputation system means hosts who serve poorly cannot be efficiently filtered. Will need to address in a later ADR.

## License

This document is AGPL-3.0-or-later, same as the rest of the repo. The author timestamps it via the git commit that adds it.
