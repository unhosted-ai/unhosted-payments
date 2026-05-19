import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  __test,
  buildSignedQuoteRequest,
  canonicalJson,
  generatePayerKey,
  payerKeyFromSecret,
  verifyReceipt,
  type SignedReceipt,
} from "../src/index.js";

const { toBase64NoPad, fromBase64NoPad } = __test;

describe("canonicalJson", () => {
  it("sorts object keys (matches Rust core test)", () => {
    // This is the exact assertion from receipt.rs::canonical_json_sorts_object_keys.
    // If this drifts, the daemon will reject every signed envelope we produce.
    const bytes = canonicalJson({ z: 1, a: 2, m: { y: 3, b: 4 } });
    assert.equal(new TextDecoder().decode(bytes), '{"a":2,"m":{"b":4,"y":3},"z":1}');
  });

  it("is stable across repeated calls on the same input", () => {
    const input = { rail: "lightning", units: 42, kyc: "email" };
    const a = canonicalJson(input);
    const b = canonicalJson(input);
    assert.deepEqual(a, b);
  });

  it("recurses into nested arrays without sorting them", () => {
    // Arrays preserve order; only object keys sort.
    const bytes = canonicalJson({ list: [{ b: 1, a: 2 }, { d: 3, c: 4 }] });
    assert.equal(
      new TextDecoder().decode(bytes),
      '{"list":[{"a":2,"b":1},{"c":4,"d":3}]}',
    );
  });
});

describe("base64 no-pad", () => {
  it("round-trips arbitrary bytes", () => {
    const bytes = new Uint8Array([0, 1, 2, 250, 200, 30, 31]);
    const enc = toBase64NoPad(bytes);
    assert.ok(!enc.includes("="), "no padding");
    const dec = fromBase64NoPad(enc);
    assert.deepEqual(dec, bytes);
  });

  it("decodes a known fixed-length pubkey", () => {
    // 32 zero bytes — what Rust core's parse_pubkey_rejects_padded_input
    // builds. We must accept the no-pad form.
    const zeros = new Uint8Array(32);
    const enc = toBase64NoPad(zeros);
    const dec = fromBase64NoPad(enc);
    assert.equal(dec.length, 32);
    assert.deepEqual(dec, zeros);
  });
});

describe("keys", () => {
  it("generates a fresh keypair on every call", async () => {
    const a = await generatePayerKey();
    const b = await generatePayerKey();
    assert.notDeepEqual(a.secret, b.secret);
    assert.equal(a.secret.length, 32);
    assert.equal(a.publicKey.length, 32);
    assert.ok(a.publicKeyB64.length > 0);
    assert.ok(!a.publicKeyB64.includes("="));
  });

  it("derives the same public key from the same secret", async () => {
    const k1 = await generatePayerKey();
    const k2 = await payerKeyFromSecret(k1.secret);
    assert.deepEqual(k1.publicKey, k2.publicKey);
    assert.equal(k1.publicKeyB64, k2.publicKeyB64);
  });

  it("rejects a wrong-length secret", async () => {
    await assert.rejects(() => payerKeyFromSecret(new Uint8Array(31)));
    await assert.rejects(() => payerKeyFromSecret(new Uint8Array(33)));
  });
});

describe("buildSignedQuoteRequest", () => {
  it("produces an envelope where sig verifies against payer_pubkey", async () => {
    // This is the property the daemon checks before doing anything
    // else. If it ever breaks, the daemon will 401 every quote and
    // the failure mode in prod is silent (just 401s, no useful log).
    const key = await generatePayerKey();
    const env = await buildSignedQuoteRequest({
      payer: { rail: "lightning", kyc: "email", country: "US" },
      requestedUnits: 1234,
      key,
    });
    assert.equal(env.body.payer_pubkey, key.publicKeyB64);

    // Reproduce the daemon's verify step.
    const canon = canonicalJson(env.body);
    const sig = fromBase64NoPad(env.sig);
    assert.equal(sig.length, 64);
    // Verify via verifyReceipt would be type-wrong; use the lib directly.
    const ed = await import("@noble/ed25519");
    const ok = await ed.verifyAsync(sig, canon, key.publicKey);
    assert.ok(ok, "signature must verify against payer_pubkey");
  });

  it("uses snake_case keys (matches the Rust struct field names)", async () => {
    const key = await generatePayerKey();
    const env = await buildSignedQuoteRequest({
      payer: { rail: "usdc_base", kyc: "id_verified", country: "JP" },
      requestedUnits: 100,
      key,
    });
    assert.ok("payer_pubkey" in env.body);
    assert.ok("requested_units" in env.body);
    assert.equal(env.body.requested_units, 100);
  });
});

describe("verifyReceipt", () => {
  it("accepts a self-signed receipt round-trip", async () => {
    // Pretend to be a host: generate a key, build a UsageReport with
    // host_pubkey set, sign it, then verify.
    const ed = await import("@noble/ed25519");
    const host = await generatePayerKey();
    const payer = await generatePayerKey();
    const report = {
      job_id: "job_test",
      host_pubkey: host.publicKeyB64,
      payer_pubkey: payer.publicKeyB64,
      rail: "lightning" as const,
      units: 100,
      unit_price_micros: 10,
      issued_at: 1715000000,
    };
    const canon = canonicalJson(report);
    const sig = await ed.signAsync(canon, host.secret);
    const receipt: SignedReceipt = { report, sig: toBase64NoPad(sig) };
    assert.ok(await verifyReceipt(receipt));
  });

  it("rejects a tampered receipt", async () => {
    const ed = await import("@noble/ed25519");
    const host = await generatePayerKey();
    const payer = await generatePayerKey();
    const report = {
      job_id: "job_test",
      host_pubkey: host.publicKeyB64,
      payer_pubkey: payer.publicKeyB64,
      rail: "lightning" as const,
      units: 100,
      unit_price_micros: 10,
      issued_at: 1715000000,
    };
    const sig = await ed.signAsync(canonicalJson(report), host.secret);
    const receipt: SignedReceipt = {
      report: { ...report, units: 101 },
      sig: toBase64NoPad(sig),
    };
    assert.equal(await verifyReceipt(receipt), false);
  });

  it("rejects a malformed host_pubkey", async () => {
    const receipt: SignedReceipt = {
      report: {
        job_id: "job_test",
        host_pubkey: "not-base64!!!",
        payer_pubkey: "AAAA",
        rail: "lightning",
        units: 100,
        unit_price_micros: 10,
        issued_at: 1715000000,
      },
      sig: "AAAA",
    };
    assert.equal(await verifyReceipt(receipt), false);
  });
});
