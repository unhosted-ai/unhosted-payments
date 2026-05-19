// @unhosted-ai/wallet-js
//
// Payer-side helpers for unhosted public mode. A payer holds an
// Ed25519 keypair and uses it to sign quote requests against an
// unhosted daemon. The daemon's wire shape lives in the Rust crate
// `unhosted-payments-core`; this TypeScript module reproduces the
// canonical-JSON + Ed25519 contract bit-for-bit so the daemon's
// `verify_sig` call succeeds.
//
// Crypto: @noble/ed25519 (audited, browser-friendly, no native
// bindings). Base64 uses the "no-pad" form to match the Rust side —
// both ends MUST use STANDARD_NO_PAD or signatures won't round-trip.

import * as ed from "@noble/ed25519";
import { sha512 } from "@noble/hashes/sha2";

// @noble/ed25519 ships without a hash backend so it stays under 4KB.
// Wire up sha512 once at module load — without this, signAsync /
// verifyAsync throw. The signature `(...msgs) => sha512(concat(msgs))`
// matches what noble-ed25519 expects.
ed.etc.sha512Sync = (...msgs: Uint8Array[]) => {
  if (msgs.length === 1) return sha512(msgs[0]);
  let total = 0;
  for (const m of msgs) total += m.length;
  const buf = new Uint8Array(total);
  let off = 0;
  for (const m of msgs) {
    buf.set(m, off);
    off += m.length;
  }
  return sha512(buf);
};

// ─── types — must mirror unhosted-payments-core ─────────────────────────

export type PaymentRail =
  | "lightning"
  | "usdc_base"
  | "usdc_solana"
  | "stripe_connect"
  | "apple_pay"
  | "manual";

export type KycTier = "none" | "email" | "id_verified";

export interface PayerContext {
  rail: PaymentRail;
  kyc: KycTier;
  /** ISO 3166-1 alpha-2, uppercase. */
  country: string;
}

export interface QuoteRequestBody {
  payer: PayerContext;
  /** Base64 no-pad of the payer's Ed25519 public key. */
  payer_pubkey: string;
  requested_units: number;
}

export interface QuoteRequest {
  body: QuoteRequestBody;
  /** Base64 no-pad of the Ed25519 signature over canonical_json(body). */
  sig: string;
}

export interface Quote {
  kind: "quote";
  job_id: string;
  host_pubkey: string;
  unit_price_micros: number;
  quoted_units: number;
  /** Unix seconds. After this point the payer must re-quote. */
  expires_at: number;
}

export interface QuoteRejected {
  kind: "rejected";
  reason: string;
}

export type QuoteResponse = Quote | QuoteRejected;

// ─── canonical-json — must match Rust receipt.rs::canonical_json ────────
//
// Rules:
//   - object keys sorted (recursively),
//   - no whitespace,
//   - JSON.stringify's default number/string encoding (which matches
//     serde_json's defaults for the value shapes we use).
//
// We DON'T support undefined values — JSON.stringify drops them, and
// the Rust side has no equivalent, so by the time we canonicalize the
// caller has already chosen what to ship.

function sortValue(v: unknown): unknown {
  if (v === null || typeof v !== "object") return v;
  if (Array.isArray(v)) return v.map(sortValue);
  const sorted: Record<string, unknown> = {};
  for (const k of Object.keys(v as Record<string, unknown>).sort()) {
    sorted[k] = sortValue((v as Record<string, unknown>)[k]);
  }
  return sorted;
}

export function canonicalJson(value: unknown): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(sortValue(value)));
}

// ─── base64 no-pad ───────────────────────────────────────────────────────

function toBase64NoPad(bytes: Uint8Array): string {
  // Browser + Node both have btoa; we go via a binary string. For
  // larger inputs (>10KB) we'd want a chunked impl, but every payload
  // here is 32-or-64 byte keys/sigs.
  let s = "";
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  const b64 = typeof btoa === "function"
    ? btoa(s)
    : Buffer.from(bytes).toString("base64");
  return b64.replace(/=+$/, "");
}

function fromBase64NoPad(b64: string): Uint8Array {
  // Re-pad so the decoder doesn't choke.
  const pad = b64.length % 4 === 0 ? "" : "=".repeat(4 - (b64.length % 4));
  const s = typeof atob === "function"
    ? atob(b64 + pad)
    : Buffer.from(b64 + pad, "base64").toString("binary");
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}

// ─── keys ────────────────────────────────────────────────────────────────

export interface PayerKey {
  /** 32-byte Ed25519 secret. Hold this carefully — anyone with it can
   *  sign quote requests as you. */
  secret: Uint8Array;
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** Base64 no-pad form of the public key, ready to drop into
   *  QuoteRequestBody.payer_pubkey. */
  publicKeyB64: string;
}

export async function generatePayerKey(): Promise<PayerKey> {
  const secret = ed.utils.randomPrivateKey();
  const publicKey = await ed.getPublicKeyAsync(secret);
  return {
    secret,
    publicKey,
    publicKeyB64: toBase64NoPad(publicKey),
  };
}

export async function payerKeyFromSecret(secret: Uint8Array): Promise<PayerKey> {
  if (secret.length !== 32) {
    throw new Error("Ed25519 secret must be exactly 32 bytes");
  }
  const publicKey = await ed.getPublicKeyAsync(secret);
  return {
    secret,
    publicKey,
    publicKeyB64: toBase64NoPad(publicKey),
  };
}

// ─── quote ───────────────────────────────────────────────────────────────

export interface RequestQuoteOptions {
  daemonUrl: string;
  payer: PayerContext;
  requestedUnits: number;
  key: PayerKey;
  /** Optional fetch override (so callers can plug in a custom
   *  implementation — e.g. a tunneled fetch through a relay).
   *  Defaults to global fetch. */
  fetch?: typeof fetch;
}

export async function buildSignedQuoteRequest(
  opts: Omit<RequestQuoteOptions, "daemonUrl" | "fetch">,
): Promise<QuoteRequest> {
  const body: QuoteRequestBody = {
    payer: opts.payer,
    payer_pubkey: opts.key.publicKeyB64,
    requested_units: opts.requestedUnits,
  };
  const canon = canonicalJson(body);
  const sig = await ed.signAsync(canon, opts.key.secret);
  return { body, sig: toBase64NoPad(sig) };
}

export async function requestQuote(
  opts: RequestQuoteOptions,
): Promise<QuoteResponse> {
  const envelope = await buildSignedQuoteRequest(opts);
  const f = opts.fetch ?? fetch;
  const r = await f(`${stripTrailingSlash(opts.daemonUrl)}/v1/public-mode/quote`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(envelope),
  });
  if (!r.ok) {
    throw new Error(`quote request failed: ${r.status} ${r.statusText}`);
  }
  return (await r.json()) as QuoteResponse;
}

function stripTrailingSlash(s: string): string {
  return s.endsWith("/") ? s.slice(0, -1) : s;
}

// ─── verify (for round-tripping a SignedReceipt the daemon returned) ────
// We only verify, not sign — receipts come from the host's identity,
// not the payer's. Same canonical-JSON contract as the Rust core.

export interface UsageReport {
  job_id: string;
  host_pubkey: string;
  payer_pubkey: string;
  rail: PaymentRail;
  units: number;
  unit_price_micros: number;
  issued_at: number;
}

export interface SignedReceipt {
  report: UsageReport;
  sig: string;
}

export async function verifyReceipt(receipt: SignedReceipt): Promise<boolean> {
  let hostKey: Uint8Array;
  try {
    hostKey = fromBase64NoPad(receipt.report.host_pubkey);
  } catch {
    return false;
  }
  if (hostKey.length !== 32) return false;
  const canon = canonicalJson(receipt.report);
  let sig: Uint8Array;
  try {
    sig = fromBase64NoPad(receipt.sig);
  } catch {
    return false;
  }
  if (sig.length !== 64) return false;
  try {
    return await ed.verifyAsync(sig, canon, hostKey);
  } catch {
    return false;
  }
}

// Exports for testing only.
export const __test = { sortValue, toBase64NoPad, fromBase64NoPad };
