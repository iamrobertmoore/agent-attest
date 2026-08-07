#!/usr/bin/env node
/**
 * Promote a freshly captured attestation token into the committed test fixture.
 *
 *   ./run.sh token            # writes attestation-vm/token.jwt and .last-nonce
 *   node tools/promote-fixture.mjs
 *
 * Writes verifier/test/fixtures/live_attestation.jwt and .meta.json, deriving the
 * metadata from the token itself rather than asking a human to copy values across.
 * Every number in the meta file is read out of the token, so the fixture cannot drift
 * from the thing it describes.
 *
 * The token is committed on purpose. It is this project's own, it expires an hour after
 * issue so it grants nothing, and committing it means `npm test` passes and the demo
 * shows a real verification on a fresh clone with no GCP account. What must never be
 * committed is somebody else's token.
 */

import { readFileSync, writeFileSync, existsSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const repo = join(here, "..");
const tokenPath = join(here, "attestation-vm", "token.jwt");
const noncePath = join(here, "attestation-vm", ".last-nonce");
const fixtures = join(repo, "verifier", "test", "fixtures");

function die(msg) {
  console.error(`promote-fixture: ${msg}`);
  process.exit(1);
}

if (!existsSync(tokenPath)) {
  die(`no token at ${tokenPath}. Run ./run.sh token first.`);
}

const token = readFileSync(tokenPath, "utf8").trim();
const parts = token.split(".");
if (parts.length !== 3) die(`token is not a compact JWS (${parts.length} segments).`);

const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
const claims = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));

if (!Array.isArray(header.x5c)) {
  die(
    `token has no x5c header, so it is an OIDC-variant token, not a PKI one. ` +
      `The verifier implements the offline PKI path only. Re-request with ` +
      `token_type: "PKI".`,
  );
}

const imageId = claims?.submods?.container?.image_id;
if (typeof imageId !== "string" || !imageId.startsWith("sha256:")) {
  die(`token carries no usable submods.container.image_id.`);
}

const nonceFromClaims = Array.isArray(claims.eat_nonce) ? claims.eat_nonce[0] : claims.eat_nonce;
const nonceFromFile = existsSync(noncePath) ? readFileSync(noncePath, "utf8").trim() : null;
if (nonceFromFile && nonceFromClaims && nonceFromFile !== nonceFromClaims) {
  die(
    `nonce mismatch. .last-nonce says ${nonceFromFile} but the token carries ` +
      `${nonceFromClaims}. This token is from a different run than the recorded nonce, ` +
      `which means one of them is stale. Re-capture rather than guessing.`,
  );
}

const meta = {
  _comment: [
    "A real Google Confidential Space attestation token, captured from this project's",
    "own production VM by tools/attestation-vm. Committed so the test suite runs and",
    "the demo shows a passing verification on a fresh clone, with no GCP account.",
    "",
    "Attestation tokens live for one hour, so this one is permanently expired and",
    "verifying it against the current clock correctly fails on freshness. The tests set",
    "the evaluation time to the moment of issue and the verifier reports that as a",
    "caveat on the result. That is inspection, not a green tick arranged for ourselves.",
    "",
    "Regenerate: ./run.sh setup && ./run.sh build && ./run.sh launch && ./run.sh token",
    "            && node tools/promote-fixture.mjs",
  ],
  nonce: nonceFromClaims ?? nonceFromFile,
  imageId,
  issuedAt: new Date(claims.iat * 1000).toISOString(),
  expiresAt: new Date(claims.exp * 1000).toISOString(),
  hwmodel: claims.hwmodel ?? null,
  swname: claims.swname ?? null,
  dbgstat: claims.dbgstat ?? null,
  audience: claims.aud ?? null,
};

writeFileSync(join(fixtures, "live_attestation.jwt"), token + "\n");
writeFileSync(join(fixtures, "live_attestation.meta.json"), JSON.stringify(meta, null, 2) + "\n");

console.log(`promoted fixture:
  image_id  ${meta.imageId}
  hwmodel   ${meta.hwmodel}
  dbgstat   ${meta.dbgstat}
  issued    ${meta.issuedAt}
  expires   ${meta.expiresAt}
  x5c depth ${header.x5c.length}

Now run: cd verifier && npm test`);

if (meta.dbgstat !== "disabled-since-boot") {
  console.warn(
    `\nWARNING: dbgstat is "${meta.dbgstat}", not "disabled-since-boot". This is a debug ` +
      `image, and the verifier rejects those by default because an operator can attach to ` +
      `the running workload and read its memory. Re-capture from --image-family=confidential-space.`,
  );
}
