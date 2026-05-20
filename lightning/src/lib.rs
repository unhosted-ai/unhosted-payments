// unhosted-payments-lightning
//
// Lightning rail adapter for unhosted public-mode. Talks to an LND
// node over its REST API (port 8080 by default). LND was chosen over
// Core Lightning for this first slice because its REST surface is
// stable, well-documented, and easy to mock for tests; a CLN adapter
// can land later as a sibling impl of the same RailAdapter trait.
//
// What this crate does NOT do:
//   - No rate oracle. The operator configures `sats_per_unit`
//     directly; converting USD↔BTC is the operator's call. A
//     Coingecko-backed RateOracle ships as a follow-up slice once
//     this adapter is verified against a real LND node.
//   - No keysend / AMP / spontaneous payments. Strictly invoice-based.
//   - No path-finding or routing optimization (per ADR-0011 the
//     project deliberately does not work in that space).
//   - No refund flow. Lightning does not refund by design; the
//     RailAdapter::refund default (RefundUnsupported) is correct.
//
// Wire surface (LND REST endpoints we hit):
//   - POST /v1/invoices         — generate a BOLT-11 invoice
//   - GET  /v1/invoice/{r_hash} — look up settlement state
//
// Auth: the LND admin macaroon is sent as a hex string in the
// `Grpc-Metadata-macaroon` header. The macaroon is the only secret
// — the REST endpoint URL is operator-configurable.

#![forbid(unsafe_code)]

use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use base64::Engine;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use unhosted_payments_core::{
    PayerContext, PaymentIntent, PaymentRail, RailAdapter, RailError, RailQuote, SettlementState,
};

/// Operator-supplied configuration. Loaded by the daemon from
/// `~/.config/unhosted/lightning.toml`; the adapter itself doesn't
/// care where it comes from.
#[derive(Debug, Clone)]
pub struct LightningConfig {
    /// LND REST base URL, e.g. `https://127.0.0.1:8080`.
    pub rest_url: String,
    /// Admin macaroon as a hex string. LND prints this on `lncli
    /// printmacaroon`; the operator copies it into the config.
    pub macaroon_hex: String,
    /// Whether to skip TLS cert verification when talking to the LND
    /// REST endpoint. LND ships with self-signed certs by default;
    /// production deployments should pin the cert (TODO follow-up
    /// slice). For now this is a knob the operator sets explicitly
    /// — there's no silent default-to-insecure.
    pub tls_skip_verify: bool,
    /// Price per unit, denominated in satoshis. The operator picks
    /// this; the adapter does not consult a rate oracle in this
    /// slice. Setting this at runtime against a Coingecko mid is a
    /// follow-up that wraps this adapter; the inner adapter stays
    /// rate-oracle-free so it's deterministic for tests.
    pub sats_per_unit: u64,
    /// How long a generated invoice (and the quote that referenced
    /// it) is valid for. Capped to LND's invoice TTL — the adapter
    /// passes this straight through as the `expiry` field on the
    /// `add_invoice` call.
    pub invoice_ttl_seconds: u64,
}

impl LightningConfig {
    /// A sane default for a regtest LND on localhost. Production
    /// configs must override at least `rest_url`, `macaroon_hex`,
    /// and `tls_skip_verify`.
    pub fn regtest_localhost(sats_per_unit: u64) -> Self {
        Self {
            rest_url: "https://127.0.0.1:8080".into(),
            macaroon_hex: String::new(),
            tls_skip_verify: true,
            sats_per_unit,
            invoice_ttl_seconds: 3600,
        }
    }
}

/// The Lightning adapter. Holds the operator config + a reusable
/// reqwest client. Constructing the client up-front (instead of
/// per call) lets HTTP/2 keep-alive across the invoice-add and
/// invoice-lookup requests during one job's lifetime.
pub struct LightningAdapter {
    config: LightningConfig,
    http: Client,
}

impl LightningAdapter {
    pub fn new(config: LightningConfig) -> Result<Self, RailError> {
        let mut builder = Client::builder();
        if config.tls_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        let http = builder
            .build()
            .map_err(|e| RailError::Internal(format!("reqwest build: {e}")))?;
        Ok(Self { config, http })
    }

    /// Construct from a caller-supplied reqwest client. Used by tests
    /// to inject a wiremock-backed client; the daemon uses [`new`]
    /// which builds one internally.
    pub fn with_client(config: LightningConfig, http: Client) -> Self {
        Self { config, http }
    }

    fn macaroon_header(&self) -> &str {
        &self.config.macaroon_hex
    }

    fn invoices_url(&self) -> String {
        format!("{}/v1/invoices", self.config.rest_url.trim_end_matches('/'))
    }

    fn invoice_lookup_url(&self, r_hash_hex: &str) -> String {
        // LND REST takes the r_hash as URL-safe base64, *not* hex.
        // Convert before constructing the path.
        let r_hash_bytes = hex::decode(r_hash_hex).unwrap_or_default();
        let r_hash_b64 =
            base64::engine::general_purpose::URL_SAFE.encode(r_hash_bytes);
        format!(
            "{}/v1/invoice/{}",
            self.config.rest_url.trim_end_matches('/'),
            r_hash_b64
        )
    }
}

#[derive(Serialize)]
struct AddInvoiceRequest {
    /// Memo is stored on the invoice and shown to the payer in
    /// their wallet. We put the unhosted job id so the payer's
    /// wallet shows something meaningful, not just "Lightning".
    memo: String,
    value: u64,
    expiry: u64,
}

#[derive(Deserialize)]
struct AddInvoiceResponse {
    /// BOLT-11 string ("lnbc...").
    payment_request: String,
    /// 32-byte preimage hash; LND returns it as base64 here. We
    /// re-encode to hex for our own bookkeeping (the rest of the
    /// adapter speaks hex; LND's invoice-lookup endpoint speaks
    /// URL-safe base64, which we translate at the boundary).
    r_hash: String,
}

#[derive(Deserialize)]
struct LookupInvoiceResponse {
    /// `OPEN`, `SETTLED`, `CANCELED`, `ACCEPTED`. Strings, not enums,
    /// per LND's REST shape.
    state: String,
    /// Total amount paid in satoshis (i64 in the wire format —
    /// always non-negative in practice).
    #[serde(default)]
    amt_paid_sat: i64,
    /// Hex-encoded preimage; present once `state == SETTLED`. We
    /// pass it through as the receipt proof.
    #[serde(default)]
    r_preimage: String,
}

#[async_trait]
impl RailAdapter for LightningAdapter {
    fn rail(&self) -> PaymentRail {
        PaymentRail::Lightning
    }

    async fn quote(&self, _ctx: &PayerContext, units: u64) -> Result<RailQuote, RailError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let total = self.config.sats_per_unit.saturating_mul(units);
        Ok(RailQuote {
            // LND assigns invoice IDs internally; we use our own
            // namespace so a quote can reference an invoice that
            // hasn't been generated yet. `intent()` is what triggers
            // the actual `add_invoice` call.
            job_id: format!("ln_{now:x}_{units}"),
            rail: PaymentRail::Lightning,
            units,
            unit_price_micros: self.config.sats_per_unit, // sats not micros — adapter convention
            total_native: total,
            expires_at: now + self.config.invoice_ttl_seconds,
        })
    }

    async fn intent(&self, quote: &RailQuote) -> Result<PaymentIntent, RailError> {
        if quote.rail != PaymentRail::Lightning {
            return Err(RailError::BadPayerContext(format!(
                "expected Lightning quote, got {:?}",
                quote.rail
            )));
        }
        let req = AddInvoiceRequest {
            memo: format!("unhosted job {}", quote.job_id),
            value: quote.total_native,
            expiry: self.config.invoice_ttl_seconds,
        };
        let resp = self
            .http
            .post(self.invoices_url())
            .header("Grpc-Metadata-macaroon", self.macaroon_header())
            .json(&req)
            .send()
            .await
            .map_err(|e| RailError::Network(format!("add_invoice: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(RailError::Network(format!(
                "add_invoice: {status} body={body}"
            )));
        }
        let parsed: AddInvoiceResponse = resp
            .json()
            .await
            .map_err(|e| RailError::Parse(format!("add_invoice response: {e}")))?;

        // Log the r_hash as a hex breadcrumb. The
        // `PaymentIntent::Lightning` variant deliberately doesn't
        // carry it — observe() recovers it from the BOLT-11's
        // payment_hash tagged field, so there's exactly one source
        // of truth and no chance for it to drift between intent and
        // observe.
        if let Ok(r_hash_bytes) =
            base64::engine::general_purpose::STANDARD.decode(parsed.r_hash.as_bytes())
        {
            tracing::debug!(r_hash = %hex::encode(r_hash_bytes), "lightning: invoice created");
        }
        Ok(PaymentIntent::Lightning {
            invoice: parsed.payment_request,
            expires_at: quote.expires_at,
        })
    }

    async fn observe(&self, intent: &PaymentIntent) -> Result<SettlementState, RailError> {
        let PaymentIntent::Lightning { invoice, .. } = intent else {
            return Err(RailError::BadPayerContext(
                "LightningAdapter received a non-Lightning intent".into(),
            ));
        };
        // Extract the payment_hash from the BOLT-11. We don't pull
        // in a full BOLT-11 parser for this — the payment_hash is a
        // 32-byte tagged field at a known offset. For Phase B we use
        // a minimal parser that handles the common case; an
        // unparseable invoice surfaces as a deterministic Parse error.
        let r_hash_hex = bolt11_payment_hash_hex(invoice)
            .ok_or_else(|| RailError::Parse("could not extract payment_hash from BOLT-11".into()))?;
        let resp = self
            .http
            .get(self.invoice_lookup_url(&r_hash_hex))
            .header("Grpc-Metadata-macaroon", self.macaroon_header())
            .send()
            .await
            .map_err(|e| RailError::Network(format!("lookup_invoice: {e}")))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(RailError::Network(format!(
                "lookup_invoice: {status} body={body}"
            )));
        }
        let parsed: LookupInvoiceResponse = resp
            .json()
            .await
            .map_err(|e| RailError::Parse(format!("lookup_invoice response: {e}")))?;
        Ok(match parsed.state.as_str() {
            "SETTLED" => SettlementState::Settled {
                amount_native: parsed.amt_paid_sat.max(0) as u64,
                proof: if parsed.r_preimage.is_empty() {
                    None
                } else {
                    // r_preimage from LND is base64. Re-encode to hex
                    // for the SignedReceipt; that matches the rest of
                    // the adapter's hex convention.
                    base64::engine::general_purpose::STANDARD
                        .decode(parsed.r_preimage.as_bytes())
                        .ok()
                        .map(hex::encode)
                },
            },
            "CANCELED" => SettlementState::Failed {
                reason: "invoice canceled".into(),
            },
            "OPEN" | "ACCEPTED" => SettlementState::Pending {
                reason: parsed.state.to_lowercase(),
            },
            other => SettlementState::Pending {
                reason: format!("unknown lnd state: {other}"),
            },
        })
    }
}

/// Minimal BOLT-11 payment-hash extractor. A full bech32 + tagged-
/// field parser is overkill for the one field we need here, but we
/// still have to do the bech32 decode + walk the tagged TLV stream.
/// Returns None if the invoice is malformed.
///
/// We intentionally avoid pulling in a heavyweight Lightning crate
/// (rust-lightning, lightning-invoice, etc.) — they're huge, pull
/// in bitcoin-the-crate, and the adapter only needs one field.
fn bolt11_payment_hash_hex(invoice: &str) -> Option<String> {
    // bech32 decode. The HRP is `lnbc{amount}{multiplier}` for
    // mainnet, `lntb...` for testnet, `lnbcrt...` for regtest. We
    // accept any HRP that starts with `ln` so the adapter works on
    // all networks without special-casing.
    let invoice = invoice.trim();
    let separator = invoice.rfind('1')?;
    let hrp = &invoice[..separator];
    let data = &invoice[separator + 1..];
    if !hrp.to_ascii_lowercase().starts_with("ln") {
        return None;
    }
    // bech32 charset → 5-bit values.
    const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
    let mut five_bit: Vec<u8> = Vec::with_capacity(data.len());
    for ch in data.bytes() {
        let v = CHARSET
            .iter()
            .position(|&c| c == ch.to_ascii_lowercase())?;
        five_bit.push(v as u8);
    }
    // Drop the 6-byte checksum at the end.
    if five_bit.len() < 6 {
        return None;
    }
    let payload = &five_bit[..five_bit.len() - 6];
    if payload.len() < 7 {
        return None;
    }
    // Skip the 7-byte timestamp at the start (35 bits = 7 * 5).
    let mut cur = 7;
    while cur < payload.len() {
        // Tagged field: 1-byte tag, 2-byte length (big-endian 5-bit
        // values = 10 bits total), `length` 5-bit values of data.
        if cur + 3 > payload.len() {
            return None;
        }
        let tag = payload[cur];
        let len = ((payload[cur + 1] as usize) << 5) | (payload[cur + 2] as usize);
        cur += 3;
        if cur + len > payload.len() {
            return None;
        }
        // Tag 'p' (which is bech32-character 1) is the payment_hash.
        if tag == 1 {
            // 52 5-bit values = 260 bits = 32 bytes + 4 padding bits.
            if len != 52 {
                return None;
            }
            let mut bytes = [0u8; 32];
            convert_bits_5_to_8(&payload[cur..cur + 52], &mut bytes)?;
            return Some(hex::encode(bytes));
        }
        cur += len;
    }
    None
}

/// 5-bit -> 8-bit regroup. BOLT-11 payment-hash is exactly 32 bytes,
/// so we hard-code the output size and assert.
fn convert_bits_5_to_8(input: &[u8], out: &mut [u8; 32]) -> Option<()> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let mut idx = 0;
    for &v in input {
        if v >= 32 {
            return None;
        }
        acc = (acc << 5) | (v as u32);
        bits += 5;
        while bits >= 8 {
            bits -= 8;
            if idx >= 32 {
                return None;
            }
            out[idx] = ((acc >> bits) & 0xff) as u8;
            idx += 1;
        }
    }
    // Final 4 padding bits must be zero per BOLT-11.
    if idx != 32 {
        return None;
    }
    Some(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use unhosted_payments_core::{Country, KycTier};
    use wiremock::matchers::{header, method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    fn payer() -> PayerContext {
        PayerContext {
            rail: PaymentRail::Lightning,
            kyc: KycTier::None,
            country: Country::new("US").unwrap(),
        }
    }

    fn config_for(url: &str) -> LightningConfig {
        LightningConfig {
            rest_url: url.into(),
            macaroon_hex: "deadbeef".into(),
            tls_skip_verify: false,
            sats_per_unit: 7,
            invoice_ttl_seconds: 600,
        }
    }

    #[tokio::test]
    async fn quote_uses_sats_per_unit_from_config() {
        let adapter = LightningAdapter::new(config_for("http://unused.example")).unwrap();
        let q = adapter.quote(&payer(), 13).await.unwrap();
        assert_eq!(q.rail, PaymentRail::Lightning);
        assert_eq!(q.units, 13);
        assert_eq!(q.unit_price_micros, 7);
        assert_eq!(q.total_native, 7 * 13);
    }

    #[tokio::test]
    async fn intent_posts_add_invoice_and_returns_bolt11() {
        let server = MockServer::start().await;
        // LND returns r_hash as base64 — pick 32 bytes of pattern.
        let r_hash_bytes = [0xABu8; 32];
        let r_hash_b64 =
            base64::engine::general_purpose::STANDARD.encode(r_hash_bytes);
        let body = serde_json::json!({
            "payment_request": "lnbcrt1ptest",
            "r_hash": r_hash_b64,
        });
        Mock::given(method("POST"))
            .and(path("/v1/invoices"))
            .and(header("Grpc-Metadata-macaroon", "deadbeef"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let adapter = LightningAdapter::new(config_for(&server.uri())).unwrap();
        let q = adapter.quote(&payer(), 5).await.unwrap();
        let intent = adapter.intent(&q).await.unwrap();
        match intent {
            PaymentIntent::Lightning { invoice, .. } => assert_eq!(invoice, "lnbcrt1ptest"),
            other => panic!("expected Lightning intent, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn intent_rejects_wrong_rail_quote() {
        let adapter = LightningAdapter::new(config_for("http://unused.example")).unwrap();
        let bad_quote = RailQuote {
            job_id: "x".into(),
            rail: PaymentRail::Manual,
            units: 1,
            unit_price_micros: 1,
            total_native: 1,
            expires_at: 0,
        };
        let err = adapter.intent(&bad_quote).await.unwrap_err();
        assert!(matches!(err, RailError::BadPayerContext(_)));
    }

    #[tokio::test]
    async fn observe_settled_returns_amount_and_proof() {
        let server = MockServer::start().await;
        let preimage_bytes = [0x11u8; 32];
        let preimage_b64 =
            base64::engine::general_purpose::STANDARD.encode(preimage_bytes);
        let body = serde_json::json!({
            "state": "SETTLED",
            "amt_paid_sat": 35,
            "r_preimage": preimage_b64,
        });
        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/invoice/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;

        let adapter = LightningAdapter::new(config_for(&server.uri())).unwrap();
        let intent = PaymentIntent::Lightning {
            invoice: sample_invoice_with_known_hash(),
            expires_at: 0,
        };
        match adapter.observe(&intent).await.unwrap() {
            SettlementState::Settled { amount_native, proof } => {
                assert_eq!(amount_native, 35);
                assert_eq!(proof, Some(hex::encode([0x11u8; 32])));
            }
            other => panic!("expected Settled, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn observe_open_returns_pending() {
        let server = MockServer::start().await;
        let body = serde_json::json!({ "state": "OPEN" });
        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/invoice/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let adapter = LightningAdapter::new(config_for(&server.uri())).unwrap();
        let intent = PaymentIntent::Lightning {
            invoice: sample_invoice_with_known_hash(),
            expires_at: 0,
        };
        assert!(matches!(
            adapter.observe(&intent).await.unwrap(),
            SettlementState::Pending { .. }
        ));
    }

    #[tokio::test]
    async fn observe_canceled_returns_failed() {
        let server = MockServer::start().await;
        let body = serde_json::json!({ "state": "CANCELED" });
        Mock::given(method("GET"))
            .and(path_regex(r"^/v1/invoice/.+$"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .mount(&server)
            .await;
        let adapter = LightningAdapter::new(config_for(&server.uri())).unwrap();
        let intent = PaymentIntent::Lightning {
            invoice: sample_invoice_with_known_hash(),
            expires_at: 0,
        };
        assert!(matches!(
            adapter.observe(&intent).await.unwrap(),
            SettlementState::Failed { .. }
        ));
    }

    #[test]
    fn bolt11_parser_extracts_payment_hash_from_test_vector() {
        // BOLT-11 test vector "Please send $3 for a cup of coffee":
        // payment_hash = 0001020304050607080900010203040506070809000102030405060708090102
        let inv = sample_invoice_with_known_hash();
        let hash = bolt11_payment_hash_hex(&inv).expect("parser must extract");
        assert_eq!(
            hash,
            "0001020304050607080900010203040506070809000102030405060708090102"
        );
    }

    #[test]
    fn refund_is_unsupported() {
        // Compile-time check via the default trait impl. We just call
        // it; Lightning doesn't refund, ever.
        let adapter = LightningAdapter::new(config_for("http://unused.example")).unwrap();
        let intent = PaymentIntent::Lightning {
            invoice: sample_invoice_with_known_hash(),
            expires_at: 0,
        };
        let fut = adapter.refund(&intent, 1);
        // We need a runtime to drive the future; reuse the test's.
        let err = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(fut)
            .unwrap_err();
        assert!(matches!(err, RailError::RefundUnsupported));
    }

    /// BOLT-11 test vector: "Please send $3 for a cup of coffee".
    /// Taken verbatim from the BOLT-11 spec test-vectors file. The
    /// payment_hash field decodes to
    /// 0001020304050607080900010203040506070809000102030405060708090102.
    fn sample_invoice_with_known_hash() -> String {
        "lnbc2500u1pvjluezpp5qqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqqqsyqcyq5rqwzqfqypqdq5xysxxatsyp3k7enxv4jsxqzpufppj3a24vwu6r8ejrss3axul8rxldph2q7z9kmrgvr7xlaqm47apw3d48zm203kzcq357a4ls9al2ea73r8jcceyjtya6fu5wzzpe50zrge6ulk4nvjcpxlekvmxl".into()
    }
}
