# unhosted-payments

Settlement layer for unhosted's public mode. When peers rent out idle compute to strangers (ADR 0001 in [unhosted-core](https://github.com/unhosted-ai/unhosted-core/blob/main/design/0001-public-mode-architecture.md)), this repo is where the money moves.

Separate from the daemon repo for three reasons:

1. **Cadence**. Compliance and rails work on a different clock than daemon engineering. A blocked KYC vendor review shouldn't pause a vram-pool release.
2. **Surface**. Payments touches more languages than the daemon's Rust — wallet helpers want TypeScript for ecosystem reach, on-chain contracts want Solidity for Base, mobile-side receipt verification might want Swift / Kotlin. Each gets its own subdir without polluting daemon dependency graphs.
3. **Trust boundary**. Sensitive code (key handling, settlement state) is reviewable in isolation. A reader auditing payments shouldn't have to skim 50k lines of daemon code to find the parts that move money.

## Status

Pre-design. No code yet. The first deliverable is ADR-0010 (sketched at [`design/0010-transactional-public-mode.md`](./design/0010-transactional-public-mode.md)) covering payment-type and country-dimension policy gating before any implementation lands.

## Planned layout

```
design/         ADRs and threat models
core/           Rust crate: PeerPaymentPolicy, settlement-state types, signed-receipt verification
wallet-js/     TypeScript: wallet-host helpers for browser / Node
contracts/      Solidity: escrow + receipt-anchor on Base (if/when we use a chain)
```

Nothing in those dirs yet — they appear as the ADR is reviewed and the first slice is approved.

## License

AGPL-3.0-or-later, matching the daemon. Contract code, if/when it lands, will dual-license if needed for chain-side audit / verification tools.
