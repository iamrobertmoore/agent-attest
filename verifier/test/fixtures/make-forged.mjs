#!/usr/bin/env node
/**
 * Generate `forged.jwt` — the attack the root pin exists to stop.
 *
 * We mint our own root, our own intermediate and our own leaf, chain them
 * correctly, and sign a payload that claims to be a pristine production
 * Confidential Space token: secboot true, dbgstat disabled-since-boot,
 * hwmodel GCP_AMD_SEV, the right issuer, a live expiry.
 *
 * Every signature in the resulting chain verifies. The chain builds to depth 3.
 * The algorithms are correct. A verifier that validates the x5c chain on its own
 * terms will report this token as perfectly good.
 *
 * The only thing wrong with it is that the root is ours, not Google's — which
 * is why `root.pin` is the check that carries the whole design.
 *
 *   node test/fixtures/make-forged.mjs
 */

import "reflect-metadata";
import * as x509 from "@peculiar/x509";
import { SignJWT, importPKCS8 } from "jose";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

x509.cryptoProvider.set(globalThis.crypto);

const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) };

async function keypair() {
  return await crypto.subtle.generateKey(alg, true, ["sign", "verify"]);
}

async function toPkcs8Pem(key) {
  const der = await crypto.subtle.exportKey("pkcs8", key);
  const b64 = Buffer.from(der).toString("base64").match(/.{1,64}/g).join("\n");
  return `-----BEGIN PRIVATE KEY-----\n${b64}\n-----END PRIVATE KEY-----\n`;
}

const NOW = new Date("2025-10-28T16:00:00Z");
const LATER = new Date("2027-10-28T16:00:00Z");

// --- attacker's root, deliberately mimicking Google's subject line ----------
const rootKeys = await keypair();
const root = await x509.X509CertificateGenerator.createSelfSigned({
  serialNumber: "01",
  name: "C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=Confidential Space Root CA",
  notBefore: NOW,
  notAfter: LATER,
  signingAlgorithm: alg,
  keys: rootKeys,
  extensions: [
    new x509.BasicConstraintsExtension(true, 2, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ],
});

// --- attacker's intermediate -----------------------------------------------
const interKeys = await keypair();
const inter = await x509.X509CertificateGenerator.create({
  serialNumber: "02",
  subject: "C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=Confidential Space Intermediate CA",
  issuer: root.subject,
  notBefore: NOW,
  notAfter: LATER,
  signingAlgorithm: alg,
  publicKey: interKeys.publicKey,
  signingKey: rootKeys.privateKey,
  extensions: [
    new x509.BasicConstraintsExtension(true, 1, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.keyCertSign | x509.KeyUsageFlags.cRLSign, true),
  ],
});

// --- attacker's leaf --------------------------------------------------------
const leafKeys = await keypair();
const leaf = await x509.X509CertificateGenerator.create({
  serialNumber: "03",
  subject: "C=US, ST=California, L=Mountain View, O=Google LLC, OU=Google Cloud, CN=Confidential Space Leaf Certificate",
  issuer: inter.subject,
  notBefore: NOW,
  notAfter: LATER,
  signingAlgorithm: alg,
  publicKey: leafKeys.publicKey,
  signingKey: interKeys.privateKey,
  extensions: [
    new x509.BasicConstraintsExtension(false, undefined, true),
    new x509.KeyUsagesExtension(x509.KeyUsageFlags.digitalSignature, true),
  ],
});

const x5c = [leaf, inter, root].map((c) =>
  Buffer.from(c.rawData).toString("base64"),
);

// --- a token that claims to be everything you would want -------------------
const privPem = await toPkcs8Pem(leafKeys.privateKey);
const signKey = await importPKCS8(privPem, "RS256");

const jwt = await new SignJWT({
  eat_nonce: "2d42069907c0408f5b8ad156a48fd9b9da4cb77b8ab43667287569d7e44b549e",
  eat_profile: "https://cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims",
  secboot: true,
  oemid: 11129,
  hwmodel: "GCP_AMD_SEV",
  swname: "CONFIDENTIAL_SPACE",
  swversion: ["20251020"],
  dbgstat: "disabled-since-boot",
  submods: {
    container: {
      image_id: "sha256:732d2328d06950198ffbd35b5eb55ec95ae700d05bddfa56fa0bc4c43ed1ce97",
      image_reference: "us-central1-docker.pkg.dev/example-project/agents/worker:1.0.0",
      restart_policy: "Never",
    },
  },
})
  .setProtectedHeader({ alg: "RS256", x5c })
  .setIssuer("https://confidentialcomputing.googleapis.com")
  .setAudience("https://sts.google.com")
  .setIssuedAt(Math.floor(NOW.getTime() / 1000))
  .setNotBefore(Math.floor(NOW.getTime() / 1000))
  .setExpirationTime(Math.floor(LATER.getTime() / 1000))
  .sign(signKey);

const out = join(dirname(fileURLToPath(import.meta.url)), "forged.jwt");
writeFileSync(out, jwt + "\n");
console.log(`wrote ${out} (${jwt.length} chars)`);
console.log("This token is internally perfect and completely worthless. That is the lesson.");
