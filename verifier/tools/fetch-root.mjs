#!/usr/bin/env node
/**
 * Re-derive the pinned root certificate in src/root.ts.
 *
 * This exists so anyone can check our trust anchor rather than take it on faith.
 * It runs at build time only — the verifier itself never touches the network.
 *
 *   node tools/fetch-root.mjs           # verify the current pin still matches
 *   node tools/fetch-root.mjs --emit    # print a fresh src/root.ts body
 *
 * Exits non-zero if what Google serves today differs from what we have pinned,
 * which is exactly the condition a human should look at rather than auto-apply.
 */

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const DISCOVERY =
  "https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root";

const EXPECTED_SHA256 =
  "148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39";
const EXPECTED_SHA1 = "B95120742C24E3AA34042E1C3BA3AAD28B212321";

const emit = process.argv.includes("--emit");

/** Google serves these as content-type: text/html. Do not sniff; parse by shape. */
async function fetchText(url) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return await res.text();
}

function pemToDer(pem) {
  const b64 = pem
    .replace(/-----BEGIN CERTIFICATE-----/, "")
    .replace(/-----END CERTIFICATE-----/, "")
    .replace(/\s+/g, "");
  return Buffer.from(b64, "base64");
}

function fp(der, alg) {
  return createHash(alg).update(der).digest("hex").toUpperCase();
}

const discovery = await fetchText(DISCOVERY);
let rootCaUri;
try {
  rootCaUri = JSON.parse(discovery).root_ca_uri;
} catch {
  throw new Error(
    `Discovery endpoint did not return JSON. Got:\n${discovery.slice(0, 200)}`,
  );
}
if (!rootCaUri) throw new Error("Discovery JSON had no root_ca_uri field.");

console.log(`discovery : ${DISCOVERY}`);
console.log(`root_ca_uri: ${rootCaUri}`);

const pem = await fetchText(rootCaUri);
if (!pem.includes("-----BEGIN CERTIFICATE-----")) {
  throw new Error(`Expected a PEM certificate, got:\n${pem.slice(0, 200)}`);
}

const der = pemToDer(pem);
const sha256 = fp(der, "sha256");
const sha1 = fp(der, "sha1");

console.log(`DER bytes : ${der.length}`);
console.log(`SHA-256   : ${sha256}`);
console.log(`SHA-1     : ${sha1}`);

let failed = false;
if (sha256 !== EXPECTED_SHA256) {
  console.error(`\nMISMATCH: SHA-256 differs from the pinned value.`);
  console.error(`  pinned : ${EXPECTED_SHA256}`);
  console.error(`  served : ${sha256}`);
  console.error(
    `\nDo not update the pin automatically. Google's Confidential Space root is valid\n` +
      `until 2034-01-16, so a change today warrants investigation, not a commit.`,
  );
  failed = true;
}
if (sha1 !== EXPECTED_SHA1) {
  console.error(`\nNote: SHA-1 also differs (${sha1}).`);
  failed = true;
}

// Cross-check against what is actually embedded in the source, not just the constant.
try {
  const here = dirname(fileURLToPath(import.meta.url));
  const src = readFileSync(join(here, "..", "src", "root.ts"), "utf8");
  // Scope to the ROOT_CA_DER_B64 declaration only. A looser regex also matches
  // the hex fingerprint constants, which silently inflates the decoded length.
  const decl = src.match(/ROOT_CA_DER_B64\s*=\s*([\s\S]*?);/);
  const embedded = decl
    ? [...decl[1].matchAll(/"([A-Za-z0-9+/=]+)"/g)].map((m) => m[1]).join("")
    : "";
  if (embedded) {
    const embeddedDer = Buffer.from(embedded, "base64");
    const same = embeddedDer.equals(der);
    console.log(
      `embedded  : ${embeddedDer.length} bytes, ${same ? "IDENTICAL to served" : "DIFFERS from served"}`,
    );
    if (!same) failed = true;
  }
} catch (e) {
  console.error(`Could not read src/root.ts: ${e.message}`);
}

if (emit) {
  const b64 = der.toString("base64");
  const lines = b64.match(/.{1,100}/g).map((l) => `  "${l}" +`);
  lines[lines.length - 1] = lines[lines.length - 1].replace(/ \+$/, ";");
  console.log("\n// ---- paste into src/root.ts ----\nexport const ROOT_CA_DER_B64 =");
  console.log(lines.join("\n"));
}

if (failed) process.exit(1);
console.log("\nOK — pinned root matches what Google serves today.");
