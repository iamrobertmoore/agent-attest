/**
 * Browser-native verification of Google Confidential Space attestation tokens.
 *
 * Runs entirely on WebCrypto. No WASM, no Node built-ins, no network at
 * verification time. Works in a browser, in Node 18+, and in Workers.
 *
 * DESIGN NOTES
 * ------------
 *
 * 1. Every check runs. We do not short-circuit on first failure.
 *    A verifier that stops at the first problem tells you one thing is wrong.
 *    A verifier that reports all six tells you what kind of thing you are
 *    looking at. That matters when the answer is "no" — which, for an
 *    attestation verifier, is the interesting case.
 *
 * 2. Fail-closed. `verified` is true only when every check ran and passed.
 *    A check that could not be evaluated counts as a failure, never as a pass.
 *
 * 3. The root is pinned at build time (see root.ts). x5c is attacker-controlled
 *    input. Building a chain out of x5c and then trusting it because the maths
 *    works is the single most common way to get this wrong: an attacker
 *    supplies leaf, intermediate AND root, all three signed consistently by a
 *    key they own, and every signature verifies perfectly. Step `root.pin` is
 *    the check that makes the rest of the chain mean anything.
 */

import "reflect-metadata"; // required by @peculiar/x509's DI container (tsyringe)
import * as x509 from "@peculiar/x509";
import { decodeProtectedHeader, compactVerify, importX509 } from "jose";

import { rootCaDer, ROOT_SHA256_FINGERPRINT } from "./root.js";
import {
  TEE_HW_MODELS,
  NON_TEE_HW_MODELS,
  type AttestationClaims,
  type Check,
  type CheckSeverity,
  type VerificationResult,
  type VerifyOptions,
} from "./types.js";

x509.cryptoProvider.set(globalThis.crypto);

const DEFAULT_ISSUER = "https://confidentialcomputing.googleapis.com";
const DEFAULT_CLOCK_TOLERANCE_SEC = 30;

/** Accumulates check results in evaluation order. */
class Checklist {
  readonly items: Check[] = [];

  pass(id: string, title: string, detail: string, severity: CheckSeverity = "cryptographic") {
    this.items.push({ id, title, ok: true, detail, severity });
  }

  fail(id: string, title: string, detail: string, severity: CheckSeverity = "cryptographic") {
    this.items.push({ id, title, ok: false, detail, severity });
  }

  /** Record a check that could not be evaluated. Counts as a failure. */
  skip(id: string, title: string, reason: string, severity: CheckSeverity = "cryptographic") {
    this.items.push({ id, title, ok: false, detail: reason, severity, skipped: true });
  }

  assert(
    cond: boolean,
    id: string,
    title: string,
    okDetail: string,
    failDetail: string,
    severity: CheckSeverity = "cryptographic",
  ): boolean {
    if (cond) this.pass(id, title, okDetail, severity);
    else this.fail(id, title, failDetail, severity);
    return cond;
  }
}

function hex(buf: ArrayBuffer): string {
  return [...new Uint8Array(buf)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
  return diff === 0;
}

/**
 * eat_nonce may be a bare string or an array of strings.
 * A real production token carries a bare string, so code that assumes an array
 * silently breaks on exactly the input it most needs to handle.
 */
function normaliseNonce(value: unknown): string[] | null {
  if (typeof value === "string") return [value];
  if (Array.isArray(value) && value.every((v) => typeof v === "string")) return value as string[];
  return null;
}

function fmt(d: Date): string {
  return d.toISOString().replace(".000", "");
}

/**
 * Verify a Confidential Space attestation token.
 *
 * Never throws for a bad token — a malformed or hostile token is a normal
 * result, not an exceptional one, and callers should be handling it as data.
 * Throwing would also tempt callers into a try/catch that treats "threw" and
 * "returned unverified" differently, which is how fail-open bugs get written.
 */
export async function verifyAttestation(
  token: string,
  options: VerifyOptions = {},
): Promise<VerificationResult> {
  const cl = new Checklist();
  const caveats: string[] = [];

  const realNow = new Date();
  const now = options.now ?? realNow;
  const tolerance = options.clockToleranceSec ?? DEFAULT_CLOCK_TOLERANCE_SEC;
  const expectedIssuer = options.expectedIssuer ?? DEFAULT_ISSUER;
  const allowedHwModels = options.allowedHwModels ?? TEE_HW_MODELS;
  const requireProd = options.requireProductionDebugStatus ?? true;

  if (options.now) {
    caveats.push(
      `Time-based checks were evaluated against an injected clock (${fmt(now)}), not the ` +
        `real time (${fmt(realNow)}). This is an inspection mode for examining historic ` +
        `tokens. A result produced this way must never be treated as a live attestation.`,
    );
  }

  // ---------------------------------------------------------------- structure
  const parts = token.trim().split(".");
  if (
    !cl.assert(
      parts.length === 3 && parts.every((p) => p.length > 0),
      "token.structure",
      "Token is a well-formed compact JWS",
      `Three non-empty segments.`,
      `Expected 3 non-empty dot-separated segments, got ${parts.length}.`,
    )
  ) {
    return finish(cl, caveats, undefined, now);
  }

  let header: ReturnType<typeof decodeProtectedHeader>;
  try {
    header = decodeProtectedHeader(token);
  } catch (e) {
    cl.fail("token.header", "Protected header decodes", `Could not decode: ${String(e)}`);
    return finish(cl, caveats, undefined, now);
  }
  cl.pass("token.header", "Protected header decodes", `alg=${header.alg}, kid=${header.kid ?? "none"}.`);

  // RS256 is RSASSA-PKCS1-v1_5 + SHA-256, a mandatory WebCrypto algorithm.
  // Asserting it up front also closes the `alg: "none"` and algorithm-confusion families.
  cl.assert(
    header.alg === "RS256",
    "header.alg",
    "Signature algorithm is RS256",
    `alg=RS256.`,
    `Expected alg=RS256, got ${String(header.alg)}. Refusing to continue with an unexpected algorithm.`,
  );

  const x5c = header.x5c;
  if (
    !cl.assert(
      Array.isArray(x5c) && x5c.length === 3,
      "header.x5c",
      "Certificate chain present with expected depth",
      `x5c contains 3 certificates (leaf, intermediate, root).`,
      Array.isArray(x5c)
        ? `Expected exactly 3 certificates in x5c, got ${x5c.length}. Confidential Space PKI ` +
            `tokens always have a fixed depth of 3. Note that JWKS-style tokens carry no x5c ` +
            `at all; this verifier implements the offline PKI path only.`
        : `No x5c header. This verifier implements the offline PKI path, which requires the ` +
            `certificate chain to be carried in the token.`,
    )
  ) {
    return finish(cl, caveats, undefined, now);
  }

  // ------------------------------------------------------------- chain parse
  // RFC 7515 §4.1.6: x5c entries are standard base64 DER, NOT base64url.
  let certs: x509.X509Certificate[];
  try {
    certs = (x5c as string[]).map((b64) => new x509.X509Certificate(b64));
  } catch (e) {
    cl.fail("chain.parse", "Certificates parse as X.509", `Failed to parse: ${String(e)}`);
    return finish(cl, caveats, undefined, now);
  }
  const [leaf, intermediate, presentedRoot] = certs;
  cl.pass(
    "chain.parse",
    "Certificates parse as X.509",
    `leaf="${leaf.subjectName.getField("CN")[0] ?? "?"}", ` +
      `intermediate="${intermediate.subjectName.getField("CN")[0] ?? "?"}", ` +
      `root="${presentedRoot.subjectName.getField("CN")[0] ?? "?"}".`,
  );

  // ------------------------------------------------------- THE CRITICAL CHECK
  const pinned = options.rootDerOverride ?? rootCaDer();
  if (options.rootDerOverride) {
    caveats.push(
      "The build-time root pin was overridden by the caller. The result is only as " +
        "trustworthy as the root that was supplied.",
    );
  }
  const rootMatches = bytesEqual(new Uint8Array(presentedRoot.rawData), pinned);
  cl.assert(
    rootMatches,
    "root.pin",
    "Presented root is byte-identical to the pinned Google root",
    `Matches the pinned Confidential Space Root CA ` +
      `(SHA-256 ${ROOT_SHA256_FINGERPRINT.slice(0, 16)}…).`,
    `The root certificate in x5c[2] is NOT the pinned Google Confidential Space Root CA. ` +
      `x5c is supplied by whoever sent the token, so a chain that validates against a root ` +
      `taken from x5c proves nothing. This is the check that anchors every signature below it.`,
  );

  // --------------------------------------------------------------- chain build
  let chain: x509.X509Certificate[] = [];
  try {
    const builder = new x509.X509ChainBuilder({ certificates: [intermediate, presentedRoot] });
    chain = await builder.build(leaf);
    cl.assert(
      chain.length === 3,
      "chain.build",
      "Chain builds to expected depth",
      `Built leaf → intermediate → root.`,
      `Chain built to depth ${chain.length}, expected 3.`,
    );
  } catch (e) {
    cl.fail("chain.build", "Chain builds to expected depth", `Chain building failed: ${String(e)}`);
  }

  // --------------------------------------------------------- link signatures
  if (chain.length === 3) {
    let allLinksOk = true;
    const linkDetails: string[] = [];
    for (let i = 0; i < chain.length - 1; i++) {
      let ok = false;
      try {
        ok = await chain[i].verify({ publicKey: chain[i + 1].publicKey, signatureOnly: true });
      } catch {
        ok = false;
      }
      allLinksOk &&= ok;
      linkDetails.push(
        `${chain[i].subjectName.getField("CN")[0] ?? "?"} ← ${
          chain[i + 1].subjectName.getField("CN")[0] ?? "?"
        }: ${ok ? "ok" : "FAILED"}`,
      );
    }
    cl.assert(
      allLinksOk,
      "chain.signatures",
      "Every link in the chain is correctly signed by its issuer",
      linkDetails.join("; ") + ".",
      linkDetails.join("; ") + ".",
    );
  } else {
    cl.skip(
      "chain.signatures",
      "Every link in the chain is correctly signed by its issuer",
      "Not evaluated, the chain did not build.",
    );
  }

  // ------------------------------------------------------------- lifetimes
  // Checked separately from signatures (signatureOnly:true above) so an expired
  // certificate is reported as expiry rather than as a cryptographic failure.
  {
    const expired = certs.filter((c) => now < c.notBefore || now > c.notAfter);
    cl.assert(
      expired.length === 0,
      "chain.lifetimes",
      "Every certificate is within its validity period",
      certs
        .map((c) => `${c.subjectName.getField("CN")[0] ?? "?"} valid to ${fmt(c.notAfter)}`)
        .join("; ") + ".",
      expired
        .map(
          (c) =>
            `${c.subjectName.getField("CN")[0] ?? "?"} was valid ${fmt(c.notBefore)} .. ` +
            `${fmt(c.notAfter)}, outside the evaluation time ${fmt(now)}`,
        )
        .join("; ") + ".",
      "freshness",
    );
  }

  // -------------------------------------------------------- leaf key algorithm
  {
    const alg = leaf.publicKey.algorithm as { name?: string };
    const sig = leaf.signatureAlgorithm as { name?: string; hash?: { name?: string } };
    const ok = alg.name === "RSASSA-PKCS1-v1_5" && sig.hash?.name === "SHA-256";
    cl.assert(
      ok,
      "leaf.algorithm",
      "Leaf key is RSASSA-PKCS1-v1_5 / SHA-256",
      `${alg.name} with ${sig.hash?.name}.`,
      `Expected RSASSA-PKCS1-v1_5 / SHA-256, got ${alg.name} / ${sig.hash?.name}.`,
    );
  }

  // ------------------------------------------------------- token signature
  let claims: AttestationClaims | undefined;
  try {
    const key = await importX509(leaf.toString("pem"), "RS256");
    const { payload } = await compactVerify(token, key, { algorithms: ["RS256"] });
    claims = JSON.parse(new TextDecoder().decode(payload)) as AttestationClaims;
    cl.pass(
      "token.signature",
      "Token signature verifies against the leaf certificate",
      `RS256 signature valid.`,
    );
  } catch (e) {
    cl.fail(
      "token.signature",
      "Token signature verifies against the leaf certificate",
      `Signature verification failed: ${String(e)}`,
    );
    return finish(cl, caveats, claims, now);
  }

  // ------------------------------------------------------------ time claims
  {
    const nowSec = Math.floor(now.getTime() / 1000);
    if (typeof claims.exp === "number") {
      cl.assert(
        nowSec <= claims.exp + tolerance,
        "claim.exp",
        "Token has not expired",
        `Expires ${fmt(new Date(claims.exp * 1000))}.`,
        `Token expired ${fmt(new Date(claims.exp * 1000))}; evaluated at ${fmt(now)}. ` +
          `The chain and signature are unaffected by this, an expired attestation was a ` +
          `true statement about a real machine when it was issued.`,
        "freshness",
      );
    } else {
      cl.skip("claim.exp", "Token has not expired", "No exp claim present.", "freshness");
    }

    if (typeof claims.nbf === "number") {
      cl.assert(
        nowSec >= claims.nbf - tolerance,
        "claim.nbf",
        "Token is already valid",
        `Valid from ${fmt(new Date(claims.nbf * 1000))}.`,
        `Token not valid until ${fmt(new Date(claims.nbf * 1000))}.`,
        "freshness",
      );
    }
  }

  // ------------------------------------------------------------ issuer / aud
  cl.assert(
    claims.iss === expectedIssuer,
    "claim.iss",
    "Issuer is Google Cloud Attestation",
    `iss=${claims.iss}.`,
    `Expected iss=${expectedIssuer}, got ${String(claims.iss)}.`,
  );

  if (options.expectedAudience !== undefined) {
    const auds = Array.isArray(claims.aud) ? claims.aud : claims.aud ? [claims.aud] : [];
    cl.assert(
      auds.includes(options.expectedAudience),
      "claim.aud",
      "Audience matches",
      `aud=${auds.join(", ")}.`,
      `Expected aud to include "${options.expectedAudience}", got ${auds.join(", ") || "none"}.`,
    );
  }

  // ------------------------------------------------------------ policy claims
  cl.assert(
    claims.secboot === true,
    "policy.secboot",
    "Secure Boot was enabled",
    `secboot=true.`,
    `Expected secboot=true, got ${String(claims.secboot)}.`,
    "policy",
  );

  if (requireProd) {
    cl.assert(
      claims.dbgstat === "disabled-since-boot",
      "policy.dbgstat",
      "Machine is a production image, not a debug image",
      `dbgstat=disabled-since-boot.`,
      `dbgstat=${String(claims.dbgstat)}. A debug image lets an operator attach to the ` +
        `workload and read its memory, so nothing sent to it is confidential. Debug images ` +
        `are right for development and must never be accepted in production.`,
      "policy",
    );
  } else {
    caveats.push(
      "Debug images were explicitly permitted by the caller. On a debug image an operator " +
        "can inspect workload memory, so confidentiality is not established.",
    );
  }

  {
    const hw = String(claims.hwmodel);
    const isNonTee = (NON_TEE_HW_MODELS as readonly string[]).includes(hw);
    cl.assert(
      allowedHwModels.includes(hw),
      "policy.hwmodel",
      "Hardware is an accepted confidential-computing platform",
      `hwmodel=${hw}.`,
      isNonTee
        ? `hwmodel=${hw}, which is not a TEE. A Shielded VM has verified boot and vTPM ` +
            `integrity monitoring but no memory encryption, so the hypervisor can read guest ` +
            `memory. Rejecting.`
        : `hwmodel=${hw} is not in the accepted set (${allowedHwModels.join(", ")}).`,
      "policy",
    );
  }

  cl.assert(
    claims.swname === "CONFIDENTIAL_SPACE",
    "policy.swname",
    "Workload is running under Confidential Space",
    `swname=CONFIDENTIAL_SPACE.`,
    `Expected swname=CONFIDENTIAL_SPACE, got ${String(claims.swname)}. A value of "GCE" means ` +
      `an ordinary VM image, which does not enforce the Confidential Space workload model.`,
    "policy",
  );

  // ------------------------------------------------------------- image_id
  // Nested under submods.container — NOT a top-level claim.
  {
    const imageId = claims.submods?.container?.image_id;
    const imageRef = claims.submods?.container?.image_reference;
    if (!options.allowedImageIds || options.allowedImageIds.length === 0) {
      cl.skip(
        "policy.image_id",
        "Workload image is on the allowlist",
        `No image allowlist supplied, so this token is not bound to any particular code. ` +
          `The token would attest that some workload ran in a genuine TEE, but not which one, ` +
          `which is not a useful security property. Observed image_id: ${String(imageId)}.`,
        "policy",
      );
    } else {
      cl.assert(
        typeof imageId === "string" && options.allowedImageIds.includes(imageId),
        "policy.image_id",
        "Workload image is on the allowlist",
        `image_id=${String(imageId)}.`,
        `image_id=${String(imageId)} is not on the allowlist.`,
        "policy",
      );
    }
    if (imageRef) {
      caveats.push(
        `The token also carries image_reference="${imageRef}". That is a mutable registry tag ` +
          `and must never be used for a trust decision; only image_id (an immutable digest) is ` +
          `pinned here.`,
      );
    }
  }

  // ------------------------------------------------------------- eat_nonce
  {
    const nonces = normaliseNonce(claims.eat_nonce);
    if (nonces === null) {
      cl.fail(
        "policy.eat_nonce",
        "Nonce binds the token to this verification",
        `eat_nonce is absent or malformed (${JSON.stringify(claims.eat_nonce)}). Expected a ` +
          `string or an array of strings.`,
        "policy",
      );
    } else if (nonces.length !== 1) {
      cl.fail(
        "policy.eat_nonce",
        "Nonce binds the token to this verification",
        `Expected exactly one nonce, got ${nonces.length}. Google permits up to 6; this ` +
          `verifier requires exactly one so that "the challenge was answered" is unambiguous.`,
        "policy",
      );
    } else if (options.expectedNonce === undefined) {
      cl.skip(
        "policy.eat_nonce",
        "Nonce binds the token to this verification",
        `No expected nonce supplied, so this token is not bound to your request. Without a ` +
          `nonce comparison an old token replayed by anyone would pass every other check. ` +
          `Observed nonce: ${nonces[0]}.`,
        "policy",
      );
    } else {
      const enc = new TextEncoder();
      const ok = bytesEqual(enc.encode(nonces[0]), enc.encode(options.expectedNonce));
      cl.assert(
        ok,
        "policy.eat_nonce",
        "Nonce binds the token to this verification",
        `Nonce matches the issued challenge.`,
        `Nonce mismatch. Expected "${options.expectedNonce}", token carries "${nonces[0]}".`,
        "policy",
      );
    }
  }

  return finish(cl, caveats, claims, now);
}

/** Assemble the result and attach the standing caveats. */
function finish(
  cl: Checklist,
  caveats: string[],
  claims: AttestationClaims | undefined,
  now: Date,
): VerificationResult {
  return {
    // Fail-closed. Empty checklist is not a pass.
    verified: cl.items.length > 0 && cl.items.every((c) => c.ok),
    checks: cl.items,
    claims,
    caveats: [...caveats, ...STANDING_CAVEATS],
    evaluatedAt: now.toISOString(),
  };
}

/**
 * Limitations that hold even when every check passes.
 *
 * These are attached to every result, including successful ones, deliberately.
 * The failure mode of attestation tooling is not that it verifies incorrectly;
 * it is that a green tick gets read as a stronger claim than it is.
 */
export const STANDING_CAVEATS: readonly string[] = [
  "Revocation is not checked. The leaf certificate carries no CRL distribution point, and " +
    "the intermediate's CRL is hosted on storage.googleapis.com without CORS headers, so a " +
    "browser cannot fetch it. With ~60-day leaf lifetimes and a hard root pin, the residual " +
    "exposure is a revoked intermediate, which is rare, but it is not zero, and this " +
    "verifier does not detect it.",

  "This proves properties of the machine and the image, not the correctness of the code " +
    "inside that image. A TEE running buggy or malicious code produces a perfectly valid " +
    "attestation. The image_id check tells you which code ran; it does not tell you that " +
    "code is trustworthy.",

  "Verification in the browser removes the need to trust the server that runs the workload. " +
    "It does not remove the need to trust the server that served this JavaScript. If an " +
    "attacker can change the verifier itself, they can make it print whatever they like. " +
    "Subresource Integrity and a pinned, versioned bundle raise that bar; they do not " +
    "eliminate it. There is currently no general defence against a persistent server " +
    "attacker in a plain web page.",

  "A passing result describes the machine at the moment the token was issued. It says " +
    "nothing about the state of that machine now.",
];
