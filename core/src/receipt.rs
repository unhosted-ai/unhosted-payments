// Signed receipts.
//
// At the end of a public-mode job the host emits a UsageReport (units
// served, on which rail, for which payer) and signs it. The payer (or
// a third-party verifier) can re-derive the canonical bytes and check
// the signature. This is the only piece of settlement state that is
// load-bearing across trust boundaries — every rail integration will
// reduce its outcome to one of these.
//
// Canonical JSON here is the bare minimum: object keys sorted
// recursively, no whitespace, serde_json's default number/string
// encoding. We don't try to be RFC-8785: as long as the signer and the
// verifier agree on the canonicalizer in this crate, signatures
// round-trip, and there's no second implementation to disagree with
// yet.

use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD_NO_PAD, Engine};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{parse_pubkey, verify_sig, KeyError, PaymentRail};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct UsageReport {
    // Job identifier, opaque to this crate — the daemon picks a ULID
    // or whatever it wants. Included in the signed body so a leaked
    // receipt can't be replayed against a different job.
    pub job_id: String,
    // The host's Ed25519 public key, base64 no-pad. Lives inside the
    // signed body so a verifier doesn't have to trust the outer
    // envelope to know who claims to have signed.
    pub host_pubkey: String,
    // The payer's identity, base64 no-pad. Same reasoning — binding
    // the receipt to a specific payer prevents reuse.
    pub payer_pubkey: String,
    pub rail: PaymentRail,
    // Granular usage. `units` is rail-agnostic (tokens, seconds, GB —
    // the unit's meaning is part of the quote, not this struct).
    pub units: u64,
    pub unit_price_micros: u64,
    // Unix seconds. Used by verifiers to reject receipts that arrive
    // far outside the negotiated window — but the policy for "how far"
    // lives in the verifier, not here.
    pub issued_at: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SignedReceipt {
    pub report: UsageReport,
    // Base64 no-pad Ed25519 signature over canonical_json(report).
    pub sig: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ReceiptError {
    #[error("host_pubkey field is not a valid ed25519 key: {0}")]
    HostKey(KeyError),
    #[error("signature did not verify against host_pubkey")]
    BadSignature,
    #[error("receipt could not be canonicalized: {0}")]
    Canonicalize(String),
    #[error("report.host_pubkey does not match the signing key")]
    HostKeyMismatch,
}

// Public so the host (signer) can compute the same bytes it will
// later sign.
pub fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ReceiptError> {
    let v = serde_json::to_value(value).map_err(|e| ReceiptError::Canonicalize(e.to_string()))?;
    let sorted = sort_value(v);
    serde_json::to_vec(&sorted).map_err(|e| ReceiptError::Canonicalize(e.to_string()))
}

fn sort_value(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut sorted: BTreeMap<String, Value> = BTreeMap::new();
            for (k, val) in map {
                sorted.insert(k, sort_value(val));
            }
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(sort_value).collect()),
        other => other,
    }
}

pub fn verify_receipt(receipt: &SignedReceipt) -> Result<(), ReceiptError> {
    let key = parse_pubkey(&receipt.report.host_pubkey).map_err(ReceiptError::HostKey)?;
    let bytes = canonical_json(&receipt.report)?;
    verify_sig(&key, &bytes, &receipt.sig).map_err(|_| ReceiptError::BadSignature)
}

/// Sign a `UsageReport` with the host's Ed25519 key and return a
/// `SignedReceipt` ready for the wire. The caller is responsible for
/// having already populated `report.host_pubkey` with the base64
/// (no-pad) of the *same* key — `sign_receipt` does not overwrite it.
/// We check the consistency before signing and return
/// `HostKeyMismatch` if the report claims a different signer than the
/// provided key, because the alternative (silently overwriting) makes
/// for a confusing wire format where the claimed pubkey doesn't
/// match what the verifier would compute from the sig.
pub fn sign_receipt(
    report: UsageReport,
    signing_key: &SigningKey,
) -> Result<SignedReceipt, ReceiptError> {
    let key_bytes = signing_key.verifying_key().to_bytes();
    let key_b64 = STANDARD_NO_PAD.encode(key_bytes);
    if report.host_pubkey != key_b64 {
        return Err(ReceiptError::HostKeyMismatch);
    }
    let bytes = canonical_json(&report)?;
    let sig = signing_key.sign(&bytes);
    Ok(SignedReceipt {
        report,
        sig: STANDARD_NO_PAD.encode(sig.to_bytes()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    fn make_signing_key() -> SigningKey {
        SigningKey::generate(&mut OsRng)
    }

    fn b64(bytes: &[u8]) -> String {
        STANDARD_NO_PAD.encode(bytes)
    }

    fn make_report(host: &SigningKey, payer: &SigningKey) -> UsageReport {
        UsageReport {
            job_id: "job_01HXYZ".to_string(),
            host_pubkey: b64(host.verifying_key().as_bytes()),
            payer_pubkey: b64(payer.verifying_key().as_bytes()),
            rail: PaymentRail::UsdcBase,
            units: 1_234,
            unit_price_micros: 50,
            issued_at: 1_715_000_000,
        }
    }

    fn sign(host: &SigningKey, report: &UsageReport) -> SignedReceipt {
        let bytes = canonical_json(report).unwrap();
        let sig = host.sign(&bytes);
        SignedReceipt {
            report: report.clone(),
            sig: b64(&sig.to_bytes()),
        }
    }

    #[test]
    fn canonical_json_is_stable_across_calls() {
        let host = make_signing_key();
        let payer = make_signing_key();
        let report = make_report(&host, &payer);
        let a = canonical_json(&report).unwrap();
        let b = canonical_json(&report).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn canonical_json_sorts_object_keys() {
        let v = serde_json::json!({ "z": 1, "a": 2, "m": { "y": 3, "b": 4 } });
        let bytes = canonical_json(&v).unwrap();
        let s = String::from_utf8(bytes).unwrap();
        // Top-level: a, m, z. Nested: b, y.
        assert_eq!(s, r#"{"a":2,"m":{"b":4,"y":3},"z":1}"#);
    }

    #[test]
    fn verify_round_trip_succeeds() {
        let host = make_signing_key();
        let payer = make_signing_key();
        let report = make_report(&host, &payer);
        let receipt = sign(&host, &report);
        assert_eq!(verify_receipt(&receipt), Ok(()));
    }

    #[test]
    fn verify_rejects_tampered_units() {
        let host = make_signing_key();
        let payer = make_signing_key();
        let report = make_report(&host, &payer);
        let mut receipt = sign(&host, &report);
        receipt.report.units += 1;
        assert_eq!(verify_receipt(&receipt), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn verify_rejects_when_host_pubkey_claim_lies() {
        // Sign with `actual`, but claim `imposter` signed it. Verifier
        // should reject — sig won't match imposter's key.
        let actual = make_signing_key();
        let imposter = make_signing_key();
        let payer = make_signing_key();
        let mut report = make_report(&actual, &payer);
        report.host_pubkey = b64(imposter.verifying_key().as_bytes());
        let bytes = canonical_json(&report).unwrap();
        let sig = actual.sign(&bytes);
        let receipt = SignedReceipt {
            report,
            sig: b64(&sig.to_bytes()),
        };
        assert_eq!(verify_receipt(&receipt), Err(ReceiptError::BadSignature));
    }

    #[test]
    fn sign_receipt_round_trips_with_verify() {
        let host = make_signing_key();
        let payer = make_signing_key();
        let report = make_report(&host, &payer);
        let receipt = sign_receipt(report, &host).unwrap();
        assert_eq!(verify_receipt(&receipt), Ok(()));
    }

    #[test]
    fn sign_receipt_rejects_pubkey_mismatch() {
        // Caller filled host_pubkey with one key but passed a
        // different signing key. We refuse rather than silently
        // overwriting — the alternative is wire receipts where the
        // claimed pubkey lies about who actually signed.
        let actual = make_signing_key();
        let imposter = make_signing_key();
        let payer = make_signing_key();
        let mut report = make_report(&actual, &payer);
        report.host_pubkey = b64(imposter.verifying_key().as_bytes());
        assert_eq!(
            sign_receipt(report, &actual),
            Err(ReceiptError::HostKeyMismatch)
        );
    }

    #[test]
    fn verify_rejects_malformed_host_pubkey() {
        let host = make_signing_key();
        let payer = make_signing_key();
        let report = make_report(&host, &payer);
        let mut receipt = sign(&host, &report);
        receipt.report.host_pubkey = "not-base64!!!".to_string();
        assert!(matches!(
            verify_receipt(&receipt),
            Err(ReceiptError::HostKey(_))
        ));
    }
}
