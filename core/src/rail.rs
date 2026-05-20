//! Rail-adapter trait + registry (ADR-0011 Phase A).
//!
//! A `RailAdapter` is the seam between rail-agnostic settlement
//! primitives (`PeerPaymentPolicy`, `SignedReceipt`) and rail-specific
//! plumbing (Lightning invoices, USDC tx hashes, Stripe payment
//! intents). The unhosted-payments-core crate doesn't ship any rail
//! implementation itself — each rail lives in its own sibling crate
//! behind a Cargo feature flag, so the default daemon binary contains
//! zero rail code.
//!
//! What an adapter does, in order:
//!
//! 1. **quote** — given a payer + units, return a `RailQuote` with a
//!    rail-specific price and an expiry. Cheap; no settlement yet.
//! 2. **intent** — turn a quote into a `PaymentIntent` (Lightning
//!    invoice, EVM unsigned tx, Stripe payment-intent client secret,
//!    etc.) that the payer's client uses to actually pay.
//! 3. **observe** — poll / observe the rail until the intent settles,
//!    fails, or expires. Adapters with webhooks (Stripe) wire the
//!    webhook into the same call via a state store; adapters with
//!    chain RPCs (USDC-on-Base) poll.
//! 4. **refund** — optional. None means "this rail doesn't refund."
//!    Lightning will return None (no chargeback by design); Stripe
//!    will implement; USDC may via the escrow contract.
//!
//! Phase A ships:
//! - the trait itself,
//! - the [`Manual`] adapter (operator marks paid out-of-band), which
//!   is the lowest-spec implementation possible and acts as the
//!   trait-shape smoke test,
//! - a [`RailRegistry`] that the daemon will hold one instance of and
//!   use to dispatch quote / intent / observe calls.
//!
//! Phase B (Lightning), C (USDC-on-Base), D (Stripe) and E (a richer
//! Manual) live in sibling crates. See
//! `design/0011-payment-rail-integration-plan.md`.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use crate::{PayerContext, PaymentRail};

/// A rail-agnostic price quote. The `unit_price_micros` is in "micros
/// of the rail's native unit" — meaning satoshis for Lightning, USDC
/// cents-of-cents for USDC, etc. The unit's interpretation is the
/// rail adapter's call.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RailQuote {
    pub job_id: String,
    pub rail: PaymentRail,
    pub units: u64,
    pub unit_price_micros: u64,
    /// Total in the rail's native smallest unit (sats / wei / cents
    /// / etc). Provided so callers don't have to re-do the unit-price
    /// math at every boundary.
    pub total_native: u64,
    /// Unix seconds. After this point the quote is stale and a fresh
    /// `quote()` call must be made.
    pub expires_at: u64,
}

/// What the payer's client gets back from `intent()` — enough info
/// to actually pay. Free-form per rail; the daemon ships it through
/// to the payer without inspection.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "rail", rename_all = "snake_case")]
pub enum PaymentIntent {
    /// BOLT-11 invoice for Lightning.
    Lightning { invoice: String, expires_at: u64 },
    /// EVM-shaped intent for USDC on Base/etc. The payer's wallet
    /// constructs the actual transaction; the adapter provides the
    /// escrow-contract address, the quote-id used as a `bytes32` in
    /// the deposit, and the amount in USDC's smallest unit (6 dp).
    UsdcEvm {
        chain: String,
        escrow_contract: String,
        quote_id_hex: String,
        amount_micro_usd: u64,
        expires_at: u64,
    },
    /// Stripe Connect payment-intent client secret.
    StripeClientSecret {
        client_secret: String,
        expires_at: u64,
    },
    /// Manual rail: the adapter has already noted the quote; the
    /// payer pays out-of-band and the host marks it paid via the
    /// adapter's admin path.
    Manual {
        quote_id: String,
        host_instructions: String,
    },
}

/// What `observe()` returns. The adapter polls until it can give a
/// definitive answer; partial states (e.g. confirming) are reported
/// as `Pending` with a short reason so the caller can decide whether
/// to keep waiting.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SettlementState {
    Pending {
        reason: String,
    },
    Settled {
        amount_native: u64,
        /// Optional rail-side identifier (Lightning preimage hex,
        /// EVM tx hash, Stripe charge ID, etc.) for the operator to
        /// reconcile with on the rail side later.
        proof: Option<String>,
    },
    Failed {
        reason: String,
    },
    Expired,
}

/// What `refund()` returns when the rail does support refunds.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefundReceipt {
    pub job_id: String,
    pub amount_native: u64,
    pub proof: Option<String>,
}

/// Adapter errors. We split network / config / not-supported failure
/// modes so the daemon can decide whether to retry, surface to user,
/// or fall back to a different adapter.
#[derive(Debug, thiserror::Error)]
pub enum RailError {
    #[error("rail {0:?} is not configured on this host")]
    NotConfigured(PaymentRail),
    #[error("payer context invalid for this rail: {0}")]
    BadPayerContext(String),
    #[error("rail-side network error: {0}")]
    Network(String),
    #[error("rail-side returned an unparseable response: {0}")]
    Parse(String),
    #[error("rail does not support refunds")]
    RefundUnsupported,
    #[error("internal: {0}")]
    Internal(String),
}

/// The seam. Each rail implements this; the daemon dispatches via
/// `RailRegistry`. All methods are async because rails inherently
/// touch the network (BOLT-11 generation calls into an LND/CLN node,
/// EVM-side calls hit an RPC, Stripe hits api.stripe.com). The
/// `Manual` adapter trivially satisfies the trait synchronously.
/// Marked `#[async_trait]` (not native `async fn`) so the trait is
/// dyn-compatible — the daemon stores `Arc<dyn RailAdapter>` in a
/// HashMap and dispatches by rail at runtime. Native async-in-trait
/// (Rust 1.75+) doesn't yet support that, and the boxed-future cost
/// of async-trait is negligible for the once-per-job call shape.
#[async_trait]
pub trait RailAdapter: Send + Sync {
    fn rail(&self) -> PaymentRail;

    async fn quote(&self, ctx: &PayerContext, units: u64) -> Result<RailQuote, RailError>;

    async fn intent(&self, quote: &RailQuote) -> Result<PaymentIntent, RailError>;

    async fn observe(&self, intent: &PaymentIntent) -> Result<SettlementState, RailError>;

    /// Default: this rail doesn't refund. Stripe / USDC adapters will
    /// override with a real implementation.
    async fn refund(
        &self,
        _intent: &PaymentIntent,
        _amount: u64,
    ) -> Result<RefundReceipt, RailError> {
        Err(RailError::RefundUnsupported)
    }
}

/// The Phase-A trivial adapter. No network. Returns a fixed price
/// per unit (configured at construction) and a `Manual` payment
/// intent telling the payer to pay out-of-band. `observe()` reads
/// from an internal map that the operator marks via `mark_paid()`.
///
/// Useful for:
/// - smoke-testing the trait shape end-to-end without an LND node,
/// - one-off bespoke deals between known parties (the host trusts
///   the payer to actually transfer the funds out-of-band),
/// - integration tests of the daemon's settlement plumbing.
pub struct ManualAdapter {
    unit_price_micros: u64,
    quote_ttl_seconds: u64,
    host_instructions: String,
    paid: std::sync::Mutex<HashMap<String, u64>>,
}

impl ManualAdapter {
    pub fn new(unit_price_micros: u64, host_instructions: impl Into<String>) -> Self {
        Self {
            unit_price_micros,
            quote_ttl_seconds: 3600, // 1 hour — manual rails are slow
            host_instructions: host_instructions.into(),
            paid: std::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Operator marks an intent paid. Called after the operator
    /// confirms the out-of-band transfer (bank wire arrived, Venmo
    /// receipt, whatever). After this, `observe()` returns
    /// `Settled` for the matching quote_id.
    pub fn mark_paid(&self, quote_id: &str, amount_native: u64) {
        if let Ok(mut paid) = self.paid.lock() {
            paid.insert(quote_id.to_string(), amount_native);
        }
    }
}

#[async_trait]
impl RailAdapter for ManualAdapter {
    fn rail(&self) -> PaymentRail {
        PaymentRail::Manual
    }

    async fn quote(&self, _ctx: &PayerContext, units: u64) -> Result<RailQuote, RailError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let total = self.unit_price_micros.saturating_mul(units);
        Ok(RailQuote {
            job_id: format!("manual_{now:x}_{units}"),
            rail: PaymentRail::Manual,
            units,
            unit_price_micros: self.unit_price_micros,
            total_native: total,
            expires_at: now + self.quote_ttl_seconds,
        })
    }

    async fn intent(&self, quote: &RailQuote) -> Result<PaymentIntent, RailError> {
        Ok(PaymentIntent::Manual {
            quote_id: quote.job_id.clone(),
            host_instructions: self.host_instructions.clone(),
        })
    }

    async fn observe(&self, intent: &PaymentIntent) -> Result<SettlementState, RailError> {
        let PaymentIntent::Manual { quote_id, .. } = intent else {
            return Err(RailError::BadPayerContext(
                "ManualAdapter received a non-Manual intent".into(),
            ));
        };
        match self.paid.lock().ok().and_then(|p| p.get(quote_id).copied()) {
            Some(amount) => Ok(SettlementState::Settled {
                amount_native: amount,
                proof: None,
            }),
            None => Ok(SettlementState::Pending {
                reason: "awaiting operator confirmation".into(),
            }),
        }
    }
}

/// Holds one adapter per rail. The daemon constructs this at startup
/// based on the operator's `PeerPaymentPolicy.accepted_rails` plus
/// which Cargo features the binary was compiled with. Dispatch is
/// trivial: `registry.get(rail)?.quote(...)`.
pub struct RailRegistry {
    adapters: HashMap<PaymentRail, Arc<dyn RailAdapter>>,
}

impl Default for RailRegistry {
    fn default() -> Self {
        Self::empty()
    }
}

impl RailRegistry {
    pub fn empty() -> Self {
        Self {
            adapters: HashMap::new(),
        }
    }

    pub fn insert(&mut self, adapter: Arc<dyn RailAdapter>) {
        self.adapters.insert(adapter.rail(), adapter);
    }

    pub fn get(&self, rail: PaymentRail) -> Option<&Arc<dyn RailAdapter>> {
        self.adapters.get(&rail)
    }

    pub fn rails(&self) -> Vec<PaymentRail> {
        self.adapters.keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Country, KycTier};

    fn payer() -> PayerContext {
        PayerContext {
            rail: PaymentRail::Manual,
            kyc: KycTier::None,
            country: Country::new("US").unwrap(),
        }
    }

    #[tokio::test]
    async fn manual_adapter_quote_intent_pending() {
        let adapter = ManualAdapter::new(10_000, "wire to BIC EXAMPLEXX");
        let q = adapter.quote(&payer(), 100).await.unwrap();
        assert_eq!(q.units, 100);
        assert_eq!(q.unit_price_micros, 10_000);
        assert_eq!(q.total_native, 1_000_000);

        let intent = adapter.intent(&q).await.unwrap();
        match &intent {
            PaymentIntent::Manual {
                quote_id,
                host_instructions,
            } => {
                assert_eq!(quote_id, &q.job_id);
                assert_eq!(host_instructions, "wire to BIC EXAMPLEXX");
            }
            _ => panic!("expected Manual intent"),
        }

        let state = adapter.observe(&intent).await.unwrap();
        assert!(matches!(state, SettlementState::Pending { .. }));
    }

    #[tokio::test]
    async fn manual_adapter_mark_paid_then_observe_settled() {
        let adapter = ManualAdapter::new(10_000, "wire");
        let q = adapter.quote(&payer(), 100).await.unwrap();
        let intent = adapter.intent(&q).await.unwrap();
        adapter.mark_paid(&q.job_id, q.total_native);
        match adapter.observe(&intent).await.unwrap() {
            SettlementState::Settled { amount_native, .. } => {
                assert_eq!(amount_native, 1_000_000);
            }
            other => panic!("expected Settled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn manual_adapter_refund_is_unsupported() {
        let adapter = ManualAdapter::new(10_000, "wire");
        let q = adapter.quote(&payer(), 1).await.unwrap();
        let intent = adapter.intent(&q).await.unwrap();
        let err = adapter.refund(&intent, 10_000).await.unwrap_err();
        assert!(matches!(err, RailError::RefundUnsupported));
    }

    #[tokio::test]
    async fn registry_dispatches_by_rail() {
        let mut reg = RailRegistry::empty();
        reg.insert(Arc::new(ManualAdapter::new(5, "test")));
        assert_eq!(reg.rails(), vec![PaymentRail::Manual]);
        let got = reg.get(PaymentRail::Manual).expect("manual registered");
        let q = got.quote(&payer(), 2).await.unwrap();
        assert_eq!(q.total_native, 10);
        assert!(reg.get(PaymentRail::Lightning).is_none());
    }
}
