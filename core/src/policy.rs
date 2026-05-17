// PeerPaymentPolicy: the pre-filter a host runs before quoting a job.
//
// The policy is intentionally a coarse filter — accepted rails, a
// minimum KYC tier, and a block-list of countries. It is NOT pricing
// and it is NOT compliance: rails do their own KYC/AML, and pricing
// happens after this filter passes. The point of the filter is to
// reject obviously-incompatible quote requests cheaply, without
// burning a rail-side API call.
//
// Countries are a block-list, not an allow-list, on purpose. A new
// peer should be able to serve "anyone except FATF-grey and the
// jurisdictions our compliance vendor explicitly named" without
// having to enumerate 195 ISO codes.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::{Country, KycTier, PayerContext, PaymentRail};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerPaymentPolicy {
    pub accepted_rails: BTreeSet<PaymentRail>,
    pub min_kyc: KycTier,
    pub blocked_countries: BTreeSet<Country>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum PolicyError {
    #[error("payment rail {0:?} is not accepted by this peer")]
    RailNotAccepted(PaymentRail),
    #[error("payer kyc tier {got:?} is below required {required:?}")]
    KycTooLow { got: KycTier, required: KycTier },
    #[error("country {0} is blocked by this peer")]
    CountryBlocked(String),
}

// BTreeSet<Country> requires Ord; we derive PartialOrd/Ord manually
// because Country wraps a fixed array.
impl PartialOrd for Country {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Country {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.as_str().cmp(other.as_str())
    }
}

impl PeerPaymentPolicy {
    // Empty policy: accept nothing. Useful as a default for a peer that
    // has not opted in to public mode yet — every request will fail
    // RailNotAccepted, which is the safe default.
    pub fn closed() -> Self {
        Self {
            accepted_rails: BTreeSet::new(),
            min_kyc: KycTier::None,
            blocked_countries: BTreeSet::new(),
        }
    }

    pub fn accepts(&self, payer: &PayerContext) -> Result<(), PolicyError> {
        if !self.accepted_rails.contains(&payer.rail) {
            return Err(PolicyError::RailNotAccepted(payer.rail));
        }
        if payer.kyc < self.min_kyc {
            return Err(PolicyError::KycTooLow {
                got: payer.kyc,
                required: self.min_kyc,
            });
        }
        if self.blocked_countries.contains(&payer.country) {
            return Err(PolicyError::CountryBlocked(payer.country.as_str().to_string()));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payer(rail: PaymentRail, kyc: KycTier, country: &str) -> PayerContext {
        PayerContext {
            rail,
            kyc,
            country: Country::new(country).unwrap(),
        }
    }

    fn open_policy() -> PeerPaymentPolicy {
        PeerPaymentPolicy {
            accepted_rails: [PaymentRail::UsdcBase, PaymentRail::Lightning]
                .into_iter()
                .collect(),
            min_kyc: KycTier::Email,
            blocked_countries: [Country::new("KP").unwrap()].into_iter().collect(),
        }
    }

    #[test]
    fn closed_policy_rejects_everything() {
        let p = PeerPaymentPolicy::closed();
        let err = p.accepts(&payer(PaymentRail::UsdcBase, KycTier::IdVerified, "US"));
        assert!(matches!(err, Err(PolicyError::RailNotAccepted(_))));
    }

    #[test]
    fn rail_must_be_in_accepted_set() {
        let p = open_policy();
        assert_eq!(
            p.accepts(&payer(PaymentRail::ApplePay, KycTier::IdVerified, "US")),
            Err(PolicyError::RailNotAccepted(PaymentRail::ApplePay))
        );
    }

    #[test]
    fn kyc_above_minimum_passes() {
        let p = open_policy();
        // policy requires Email; IdVerified is higher → accepted.
        assert!(p
            .accepts(&payer(PaymentRail::UsdcBase, KycTier::IdVerified, "US"))
            .is_ok());
    }

    #[test]
    fn kyc_below_minimum_rejected() {
        let p = open_policy();
        assert_eq!(
            p.accepts(&payer(PaymentRail::UsdcBase, KycTier::None, "US")),
            Err(PolicyError::KycTooLow {
                got: KycTier::None,
                required: KycTier::Email,
            })
        );
    }

    #[test]
    fn blocked_country_rejected() {
        let p = open_policy();
        assert_eq!(
            p.accepts(&payer(PaymentRail::UsdcBase, KycTier::Email, "kp")),
            Err(PolicyError::CountryBlocked("KP".to_string()))
        );
    }

    #[test]
    fn happy_path_accepts() {
        let p = open_policy();
        assert!(p
            .accepts(&payer(PaymentRail::Lightning, KycTier::Email, "JP"))
            .is_ok());
    }

    #[test]
    fn check_order_rail_first_then_kyc_then_country() {
        // A payer that fails on all three should be reported as rail-failure,
        // because that's the cheapest signal and the most actionable
        // ("we don't take this rail" is a clear thing to surface).
        let p = PeerPaymentPolicy {
            accepted_rails: [PaymentRail::Lightning].into_iter().collect(),
            min_kyc: KycTier::IdVerified,
            blocked_countries: [Country::new("KP").unwrap()].into_iter().collect(),
        };
        assert_eq!(
            p.accepts(&payer(PaymentRail::ApplePay, KycTier::None, "KP")),
            Err(PolicyError::RailNotAccepted(PaymentRail::ApplePay))
        );
    }
}
