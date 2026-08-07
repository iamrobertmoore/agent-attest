/**
 * Google Confidential Space Root CA — pinned at build time.
 *
 * THIS IS THE TRUST ANCHOR. Everything else in the verifier is downstream of it.
 *
 * How this was obtained (reproduce with `npm run fetch-root`):
 *
 *   1. GET https://confidentialcomputing.googleapis.com/.well-known/attestation-pki-root
 *      → returns JSON, NOT a certificate:
 *        { "root_ca_uri": ".../.well-known/confidential_space_root.crt" }
 *      (note: the response is served as content-type text/html — do not sniff)
 *   2. GET that URI → PEM certificate, 2150 bytes, 1548 bytes of DER
 *   3. Verify both fingerprints below before embedding.
 *
 * Certificate details, verified 2026-07-31:
 *   Subject == Issuer  CN=Confidential Space Root CA, O=Google LLC, OU=Google Cloud
 *   Self-signed, CA:TRUE, keyCertSign|cRLSign
 *   Valid  2024-01-19T22:10:50Z .. 2034-01-16T22:10:49Z
 *   RSA 4096
 *
 * WHY THIS IS EMBEDDED AND NEVER FETCHED AT RUNTIME
 * -------------------------------------------------
 * Two independent reasons, and either alone is sufficient:
 *
 *   (a) Security. A root fetched at verification time is not a trust anchor — it is
 *       just another piece of network input. An attacker who can serve you the root
 *       can serve you a root they own, and every signature below it will then verify
 *       perfectly. The anchor has to be fixed at build time or it isn't an anchor.
 *
 *   (b) It would not work anyway. Neither Google endpoint sends an
 *       access-control-allow-origin header, so a browser fetch is CORS-blocked.
 *
 * The SHA-256 value is what the verifier asserts. SHA-1 is recorded only because
 * Google's own documentation quotes it, so a reader checking our work against their
 * docs can confirm we are pinning the same certificate. We do not compare against it.
 */

/** SHA-256 fingerprint of the DER below. This is the value we assert. */
export const ROOT_SHA256_FINGERPRINT =
  "148B293821BB0C6A317F413C8BA475814091CB22D49B9E3C94198DB8E8F86C39";

/**
 * SHA-1 fingerprint, for cross-referencing against Google's published docs only.
 * Never used as a security check — SHA-1 is not collision-resistant.
 */
export const ROOT_SHA1_FINGERPRINT_DOCS_ONLY =
  "B95120742C24E3AA34042E1C3BA3AAD28B212321";

/** Base64-encoded DER of the root certificate. */
export const ROOT_CA_DER_B64 =
  "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";

/** Decode the pinned root to raw DER bytes. */
export function rootCaDer(): Uint8Array {
  const bin = atob(ROOT_CA_DER_B64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
