// unhosted-payments-core
//
// Settlement primitives for unhosted's public mode. This crate is
// intentionally rail-agnostic: it defines the shapes that the daemon,
// the wallet helpers, and the on-chain code all need to agree on, but
// no actual rail (Stripe, Lightning, USDC) is wired up here. Each rail
// gets its own crate later so a vendor-review block on one rail doesn't
// stall the others.
//
// Slice 1 ships three things:
//   - the payment-rail + KYC + country vocabulary,
//   - PeerPaymentPolicy.accepts(): the router pre-filter a host runs
//     before quoting a job,
//   - signed-receipt verification: math only, no transport.

#![forbid(unsafe_code)]

pub mod policy;
pub mod receipt;

pub use policy::{PeerPaymentPolicy, PolicyError};
pub use receipt::{verify_receipt, ReceiptError, SignedReceipt, UsageReport};

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

// The rails we plan to support. Order matters only for stable
// serialization; precedence is decided at quote time by host
// preference, not by enum order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentRail {
    UsdcBase,
    UsdcSolana,
    Lightning,
    StripeConnect,
    ApplePay,
    Manual,
}

impl PaymentRail {
    pub fn as_str(&self) -> &'static str {
        match self {
            PaymentRail::UsdcBase => "usdc_base",
            PaymentRail::UsdcSolana => "usdc_solana",
            PaymentRail::Lightning => "lightning",
            PaymentRail::StripeConnect => "stripe_connect",
            PaymentRail::ApplePay => "apple_pay",
            PaymentRail::Manual => "manual",
        }
    }
}

// Coarse KYC tiers. The host doesn't see the payer's documents — it
// sees a tier asserted by whoever ran KYC (the rail, or unhosted's own
// onramp). Tier ordering matters: a policy that requires `Email` is
// satisfied by `IdVerified`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KycTier {
    None,
    Email,
    IdVerified,
}

// ISO 3166-1 alpha-2. Stored as a fixed two-byte uppercase array so
// equality is cheap and the type can't carry garbage like "usa" or
// "United States". Construct via `Country::new`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Country([u8; 2]);

impl Country {
    pub fn new(code: &str) -> Result<Self, &'static str> {
        let bytes = code.as_bytes();
        if bytes.len() != 2 || !bytes.iter().all(|b| b.is_ascii_alphabetic()) {
            return Err("country must be ISO 3166-1 alpha-2 (two ascii letters)");
        }
        Ok(Country([
            bytes[0].to_ascii_uppercase(),
            bytes[1].to_ascii_uppercase(),
        ]))
    }

    pub fn as_str(&self) -> &str {
        // Safe: constructor guarantees ascii.
        std::str::from_utf8(&self.0).unwrap()
    }
}

impl Serialize for Country {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for Country {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        Country::new(&s).map_err(serde::de::Error::custom)
    }
}

// What the host learns about a payer at quote time. This is the input
// to `PeerPaymentPolicy::accepts`. KYC tier is asserted, not proven
// here — proof lives in whatever signed attestation accompanied the
// quote request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PayerContext {
    pub rail: PaymentRail,
    pub kyc: KycTier,
    pub country: Country,
}

// Decode a base64 (no-pad) Ed25519 public key into a VerifyingKey.
// We deliberately accept only NO_PAD form so the wire encoding is
// canonical — there's no reason to support both.
pub fn parse_pubkey(b64: &str) -> Result<VerifyingKey, KeyError> {
    let bytes = STANDARD_NO_PAD.decode(b64).map_err(|_| KeyError::Base64)?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| KeyError::Length)?;
    VerifyingKey::from_bytes(&arr).map_err(|_| KeyError::Invalid)
}

// Verify a base64 (no-pad) Ed25519 signature over the given message.
pub fn verify_sig(key: &VerifyingKey, msg: &[u8], sig_b64: &str) -> Result<(), KeyError> {
    let bytes = STANDARD_NO_PAD.decode(sig_b64).map_err(|_| KeyError::Base64)?;
    let arr: [u8; 64] = bytes.as_slice().try_into().map_err(|_| KeyError::Length)?;
    let sig = Signature::from_bytes(&arr);
    key.verify(msg, &sig).map_err(|_| KeyError::BadSignature)
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum KeyError {
    #[error("not valid base64 (no-pad)")]
    Base64,
    #[error("wrong length")]
    Length,
    #[error("not a valid ed25519 key")]
    Invalid,
    #[error("signature did not verify")]
    BadSignature,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn country_normalizes_case() {
        let c = Country::new("us").unwrap();
        assert_eq!(c.as_str(), "US");
    }

    #[test]
    fn country_rejects_garbage() {
        assert!(Country::new("USA").is_err());
        assert!(Country::new("u").is_err());
        assert!(Country::new("12").is_err());
        assert!(Country::new("").is_err());
    }

    #[test]
    fn kyc_tier_ordering() {
        assert!(KycTier::IdVerified > KycTier::Email);
        assert!(KycTier::Email > KycTier::None);
    }

    #[test]
    fn payment_rail_serializes_snake_case() {
        let j = serde_json::to_string(&PaymentRail::UsdcBase).unwrap();
        assert_eq!(j, "\"usdc_base\"");
    }

    #[test]
    fn parse_pubkey_rejects_padded_input() {
        // Standard-with-pad of 32 zero bytes ends in "=" — must be rejected.
        let padded = base64::engine::general_purpose::STANDARD.encode([0u8; 32]);
        assert!(padded.contains('='));
        assert_eq!(parse_pubkey(&padded), Err(KeyError::Base64));
    }
}
