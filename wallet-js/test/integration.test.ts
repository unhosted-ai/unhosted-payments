// Integration smoke test: sign a quote envelope in TS and post it to
// a real unhosted daemon. Skipped unless UNHOSTED_DAEMON_URL is set —
// CI shouldn't try to talk to a daemon that isn't there.
//
// To run locally:
//   UNHOSTED_DAEMON_URL=http://127.0.0.1:7787 npx tsx --test test/integration.test.ts

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { generatePayerKey, requestQuote } from "../src/index.js";

const daemonUrl = process.env.UNHOSTED_DAEMON_URL;

describe("integration: wallet-js ↔ daemon", { skip: !daemonUrl }, () => {
  it("a daemon-accepting policy returns a quote", async () => {
    // The daemon at $UNHOSTED_DAEMON_URL must already be configured
    // to accept lightning + email + US — i.e. PUT a matching policy
    // before running this test.
    const key = await generatePayerKey();
    const resp = await requestQuote({
      daemonUrl: daemonUrl!,
      payer: { rail: "lightning", kyc: "email", country: "US" },
      requestedUnits: 250,
      key,
    });
    if (resp.kind === "rejected") {
      // Surface the reason — usually "rail not accepted" if the test
      // operator forgot to enable lightning in the daemon's policy.
      assert.fail(`daemon rejected: ${resp.reason}`);
    }
    assert.equal(resp.kind, "quote");
    assert.equal(resp.quoted_units, 250);
    assert.ok(resp.unit_price_micros > 0);
    assert.ok(resp.host_pubkey.length > 0);
    assert.ok(resp.expires_at > Math.floor(Date.now() / 1000));
  });
});
