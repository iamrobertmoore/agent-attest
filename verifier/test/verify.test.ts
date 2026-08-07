/**
 * Tests for the Confidential Space verifier.
 *
 * The primary fixture is a real attestation token captured from this project's
 * own Confidential Space VM by `tools/attestation-vm/run.sh token`, together
 * with the metadata that run recorded. Generate it with:
 *
 *   cd tools/attestation-vm && ./run.sh setup && ./run.sh build \
 *     && ./run.sh launch && ./run.sh token
 *
 * The fixture is deliberately not committed as a pre-baked artefact from
 * somewhere else. A verifier whose test corpus comes from a third party proves
 * less than one you can regenerate end to end from a documented command, and
 * regenerating it is the same path a reviewer would take to reproduce the
 * result themselves.
 *
 * Attestation tokens live for one hour, so once captured the fixture is
 * permanently expired. That is not a problem: the interesting assertions are
 * mostly about the verifier saying "no" for the right reasons, with the
 * time-based checks evaluated against an injected clock and reported as a
 * caveat on the result.
 */

import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

import { verifyAttestation } from "../src/verify.js";
import { rootCaDer } from "../src/root.js";
import type { Check } from "../src/types.js";

const here = dirname(fileURLToPath(import.meta.url));
const FIXTURES = join(here, "fixtures");

/**
 * Fail loudly rather than skipping. A verifier test suite that silently passes
 * with no token to verify is worse than one that does not run, because it
 * reports green while proving nothing.
 */
function requireFixture(name: string): string {
  const path = join(FIXTURES, name);
  if (!existsSync(path)) {
    throw new Error(
      `Missing fixture ${name}. Capture one from this project's own Confidential ` +
        `Space VM with: cd tools/attestation-vm && ./run.sh setup && ./run.sh build ` +
        `&& ./run.sh launch && ./run.sh token`,
    );
  }
  return readFileSync(path, "utf8").trim();
}

const liveToken = requireFixture("live_attestation.jwt");

/** Written alongside the token by `run.sh token`. */
const meta = JSON.parse(requireFixture("live_attestation.meta.json")) as {
  nonce: string;
  imageId: string;
  issuedAt: string;
  expiresAt: string;
};

/** Instant at which the captured token was still live, for inspection-mode tests. */
const WHEN_LIVE = new Date(meta.issuedAt);

/** Nonce carried by the captured token. */
const FIXTURE_NONCE = meta.nonce;
const FIXTURE_IMAGE_ID = meta.imageId;

function check(checks: Check[], id: string): Check {
  const c = checks.find((x) => x.id === id);
  assert.ok(c, `expected a check with id "${id}"`);
  return c!;
}

describe("A real Confidential Space token", () => {
  test("the cryptographic chain is genuine", async () => {
    const r = await verifyAttestation(liveToken, { now: WHEN_LIVE });

    assert.equal(check(r.checks, "token.structure").ok, true);
    assert.equal(check(r.checks, "header.alg").ok, true);
    assert.equal(check(r.checks, "header.x5c").ok, true);
    assert.equal(check(r.checks, "chain.parse").ok, true);
    assert.equal(check(r.checks, "chain.build").ok, true);
    assert.equal(check(r.checks, "chain.signatures").ok, true);
    assert.equal(check(r.checks, "leaf.algorithm").ok, true);
    assert.equal(check(r.checks, "token.signature").ok, true);
    assert.equal(check(r.checks, "claim.iss").ok, true);
  });

  test("the presented root is byte-identical to the pinned Google root", async () => {
    const r = await verifyAttestation(liveToken, { now: WHEN_LIVE });
    assert.equal(check(r.checks, "root.pin").ok, true);
  });

  test("it is rejected against the real clock, for three independent reasons", async () => {
    const r = await verifyAttestation(liveToken, {
      expectedNonce: FIXTURE_NONCE,
      allowedImageIds: [FIXTURE_IMAGE_ID],
    });

    assert.equal(r.verified, false);

    // 1. the token itself expired 2025-10-28
    assert.equal(check(r.checks, "claim.exp").ok, false);
    // 2. the leaf certificate expired 2025-12-25
    assert.equal(check(r.checks, "chain.lifetimes").ok, false);
    // 3. it is a debug image
    assert.equal(check(r.checks, "policy.dbgstat").ok, false);

    // ...and the cryptography is still fine throughout, which is the point:
    // the failures are policy and freshness, not forgery.
    assert.equal(check(r.checks, "token.signature").ok, true);
    assert.equal(check(r.checks, "root.pin").ok, true);
  });

  test("dbgstat is reported as a policy failure, not a cryptographic one", async () => {
    const r = await verifyAttestation(liveToken, { now: WHEN_LIVE });
    const c = check(r.checks, "policy.dbgstat");
    assert.equal(c.ok, false);
    assert.equal(c.severity, "policy");
    assert.match(c.detail, /debug/i);
  });

  test("eat_nonce arrives as a bare string and is normalised", async () => {
    // A real token carries eat_nonce as a string, not an array. Code that
    // assumes an array breaks here, which is why this test exists.
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      expectedNonce: FIXTURE_NONCE,
    });
    assert.equal(check(r.checks, "policy.eat_nonce").ok, true);
    assert.equal(typeof r.claims?.eat_nonce, "string");
  });

  test("a wrong nonce is caught", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      expectedNonce: "0".repeat(64),
    });
    assert.equal(check(r.checks, "policy.eat_nonce").ok, false);
  });

  test("image_id is read from submods.container, not the top level", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      allowedImageIds: [FIXTURE_IMAGE_ID],
    });
    assert.equal(check(r.checks, "policy.image_id").ok, true);
    assert.equal((r.claims as any).image_id, undefined);
    assert.equal(r.claims?.submods?.container?.image_id, FIXTURE_IMAGE_ID);
  });

  test("an unlisted image_id is rejected", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      allowedImageIds: ["sha256:" + "0".repeat(64)],
    });
    assert.equal(check(r.checks, "policy.image_id").ok, false);
  });

  test("it passes everything when debug images are explicitly permitted", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      expectedNonce: FIXTURE_NONCE,
      allowedImageIds: [FIXTURE_IMAGE_ID],
      requireProductionDebugStatus: false,
    });
    const failures = r.checks.filter((c) => !c.ok);
    assert.deepEqual(failures.map((c) => c.id), [], "expected no failing checks");
    assert.equal(r.verified, true);
  });
});

describe("fail-closed behaviour", () => {
  test("omitting the nonce drops the result to unverified", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      allowedImageIds: [FIXTURE_IMAGE_ID],
      requireProductionDebugStatus: false,
    });
    assert.equal(r.verified, false);
    const c = check(r.checks, "policy.eat_nonce");
    assert.equal(c.ok, false);
    assert.equal(c.skipped, true);
  });

  test("omitting the image allowlist drops the result to unverified", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      expectedNonce: FIXTURE_NONCE,
      requireProductionDebugStatus: false,
    });
    assert.equal(r.verified, false);
    assert.equal(check(r.checks, "policy.image_id").skipped, true);
  });

  test("caveats are attached even to a fully passing result", async () => {
    const r = await verifyAttestation(liveToken, {
      now: WHEN_LIVE,
      expectedNonce: FIXTURE_NONCE,
      allowedImageIds: [FIXTURE_IMAGE_ID],
      requireProductionDebugStatus: false,
    });
    assert.equal(r.verified, true);
    assert.ok(r.caveats.length >= 4);
    assert.ok(r.caveats.some((c) => /[Rr]evocation/.test(c)));
    assert.ok(r.caveats.some((c) => /served this JavaScript/.test(c)));
  });
});

describe("hostile input", () => {
  test("garbage is rejected without throwing", async () => {
    for (const bad of ["", "not-a-jwt", "a.b", "a.b.c.d", "..", "eyJ.eyJ."]) {
      const r = await verifyAttestation(bad);
      assert.equal(r.verified, false, `expected "${bad}" to be rejected`);
    }
  });

  test("a self-signed chain with an attacker's own root is rejected at the pin", async () => {
    // The attack this defends against: an attacker mints leaf, intermediate AND
    // root themselves. Every signature in the chain verifies perfectly, because
    // they control every key. Only the pin catches it.
    const forged = readFileSync(join(FIXTURES, "forged.jwt"), "utf8").trim();
    const r = await verifyAttestation(forged, { now: WHEN_LIVE });

    assert.equal(check(r.checks, "root.pin").ok, false, "the pin must reject the forged root");
    assert.equal(r.verified, false);

    // The forged chain is internally consistent — which is precisely why
    // "the signatures all verify" is not, by itself, worth anything.
    assert.equal(check(r.checks, "chain.signatures").ok, true);
    assert.equal(check(r.checks, "token.signature").ok, true);
  });

  test("swapping alg to none is rejected", async () => {
    const [, payload, sig] = liveToken.split(".");
    const hdr = Buffer.from(JSON.stringify({ alg: "none", x5c: [] })).toString("base64url");
    const r = await verifyAttestation(`${hdr}.${payload}.${sig}`);
    assert.equal(check(r.checks, "header.alg").ok, false);
    assert.equal(r.verified, false);
  });
});

describe("the pinned root", () => {
  test("decodes to a 1548-byte DER certificate", () => {
    const der = rootCaDer();
    assert.equal(der.length, 1548);
    assert.equal(der[0], 0x30); // SEQUENCE
  });
});
