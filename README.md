# unhosted-payments

Settlement layer for unhosted's public mode. When peers rent out idle compute to strangers (ADR 0001 in [unhosted-core](https://github.com/unhosted-ai/unhosted-core/blob/main/design/0001-public-mode-architecture.md)), this repo is where the money moves.

Separate from the daemon repo for three reasons:

1. **Cadence**. Compliance and rails work on a different clock than daemon engineering. A blocked KYC vendor review shouldn't pause a vram-pool release.
2. **Surface**. Payments touches more languages than the daemon's Rust — wallet helpers want TypeScript for ecosystem reach, on-chain contracts want Solidity for Base, mobile-side receipt verification might want Swift / Kotlin. Each gets its own subdir without polluting daemon dependency graphs.
3. **Trust boundary**. Sensitive code (key handling, settlement state) is reviewable in isolation. A reader auditing payments shouldn't have to skim 50k lines of daemon code to find the parts that move money.

## Status

ADR-0010 ([`design/0010-transactional-public-mode.md`](./design/0010-transactional-public-mode.md)) is the slicing plan. Five slices total.

| Slice | What ships | Status |
| --- | --- | --- |
| 1 | `core/` crate: `PeerPaymentPolicy`, `PaymentRail`, `KycTier`, `Country`, `SignedReceipt`, `verify_receipt`, `sign_receipt` | **shipped** (`unhosted-payments-core` 0.0.2) |
| 2 | Daemon integration in `unhosted-core` (`/v1/public-mode/policy`, `/inspect`, `/receipt/sign`, `/quote`) | **shipped** (in `unhosted-core` v0.0.39) |
| 3 | First rail (Lightning leading candidate) | pending |
| 4 | `wallet-js/` payer helpers | **shipped** (`@unhosted-ai/wallet-js` 0.0.1) |
| 5 | `contracts/` Solidity escrow on Base | pending |

Cross-language wire compatibility (Rust ↔ TypeScript) is verified by the wallet-js integration test, which signs a quote in Node and posts it to a running daemon.

## Layout

```
design/         ADRs and threat models
core/           Rust crate: PeerPaymentPolicy + signed-receipt verification
wallet-js/      TypeScript: payer-side helpers for browser / Node
contracts/      Solidity: escrow + receipt-anchor on Base (planned)
```

## License

AGPL-3.0-or-later, matching the daemon. Contract code, if/when it lands, will dual-license if needed for chain-side audit / verification tools.
