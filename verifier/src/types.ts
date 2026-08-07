/**
 * Types for Google Confidential Space attestation verification.
 *
 * Claim names and nesting follow Google's token-claims reference:
 * https://docs.cloud.google.com/confidential-computing/confidential-space/docs/reference/token-claims
 */

/** Hardware models that are genuinely a TEE. */
export const TEE_HW_MODELS = [
  "GCP_AMD_SEV",
  "GCP_AMD_SEV_ES",
  "GCP_INTEL_TDX",
] as const;

/**
 * GCP_SHIELDED_VM is a valid value of the `hwmodel` claim but is NOT a TEE.
 * A Shielded VM has verified boot and vTPM integrity monitoring; it does not
 * have memory encryption and the hypervisor can read guest memory. Accepting it
 * would mean accepting a machine whose operator can read the data you sent it.
 * It is excluded from TEE_HW_MODELS deliberately, and named here so the omission
 * reads as a decision rather than an oversight.
 */
export const NON_TEE_HW_MODELS = ["GCP_SHIELDED_VM"] as const;

export type TeeHwModel = (typeof TEE_HW_MODELS)[number];

/** Subset of the token payload this verifier reasons about. */
export interface AttestationClaims {
  iss?: string;
  aud?: string | string[];
  sub?: string;
  iat?: number;
  nbf?: number;
  exp?: number;

  /** Bare string OR array of strings. Real production tokens use a bare string. */
  eat_nonce?: string | string[];
  eat_profile?: string;

  /** Secure Boot state. Google's docs say this is always true. */
  secboot?: boolean;
  /** "disabled-since-boot" on production images, "enabled" on debug images. */
  dbgstat?: string;
  /** See TEE_HW_MODELS / NON_TEE_HW_MODELS. */
  hwmodel?: string;
  /** "CONFIDENTIAL_SPACE" or "GCE". */
  swname?: string;
  swversion?: string[];
  /** Google's IANA Private Enterprise Number: 11129. */
  oemid?: number;

  submods?: {
    container?: {
      /** sha256:... The immutable content digest. This is what admission records. */
      image_id?: string;
      /** A mutable registry tag. Never make a trust decision on this. */
      image_reference?: string;
      image_digest?: string;
      restart_policy?: string;
      env?: Record<string, string>;
      args?: string[];
    };
    confidential_space?: {
      support_attributes?: string[];
      monitoring_enabled?: unknown;
    };
    gce?: Record<string, unknown>;
    /**
     * NOTE: submods.nvidia_gpu.gpus[].hwmodel is a DIFFERENT claim that happens
     * to share a name with the top-level hwmodel. Its only value is
     * GCP_NVIDIA_H100. Do not conflate the two.
     */
    nvidia_gpu?: Record<string, unknown>;
  };

  google_service_accounts?: string[];
  [k: string]: unknown;
}

/**
 * Why a check failing matters. The three are genuinely different claims and must not
 * be collapsed — the response to each is different.
 */
export type CheckSeverity =
  /**
   * Cryptographic or structural: signatures, the certificate chain, the root pin.
   * Failure means the token proves nothing at all and should be treated as hostile
   * input.
   */
  | "cryptographic"
  /**
   * Time. The token and its chain are genuine; they are simply outside their validity
   * window. This is emphatically NOT a forgery — an expired attestation was a true
   * statement about a real machine when it was issued, and saying "the cryptography
   * failed" about it is both wrong and alarming in the wrong direction.
   */
  | "freshness"
  /**
   * Policy. The token is authentic and current, but describes a machine or an image
   * we chose not to accept. This is the interesting failure in practice: forging
   * Google's chain is hard, pointing a genuine enclave at different code is easy.
   */
  | "policy";

export interface Check {
  id: string;
  title: string;
  ok: boolean;
  /** Human-readable outcome — shown to the user, so write it for a human. */
  detail: string;
  severity: CheckSeverity;
  /** True when an earlier failure made this check impossible to evaluate. */
  skipped?: boolean;
}

export interface VerificationResult {
  /** Fail-closed: true only if every check ran and every check passed. */
  verified: boolean;
  checks: Check[];
  /** Present once the token parses, even if verification later fails. */
  claims?: AttestationClaims;
  /** Things this result does NOT prove. Always populated, even on success. */
  caveats: string[];
  /** Instant the verification was evaluated against. */
  evaluatedAt: string;
}

export interface VerifyOptions {
  /**
   * The challenge you issued. Compared against eat_nonce.
   * If omitted, the nonce check is reported as not evaluated and the overall
   * result is NOT verified — a token with no nonce binding is a replay waiting
   * to happen, so we refuse to call it verified rather than quietly passing.
   */
  expectedNonce?: string;

  /**
   * Allowlist of acceptable submods.container.image_id values (sha256:...).
   * This is the check that binds "some TEE" to "the code I expect".
   * Omitting it is allowed for exploration but drops the result to unverified.
   */
  allowedImageIds?: string[];

  /** Defaults to TEE_HW_MODELS. */
  allowedHwModels?: readonly string[];

  /** Require dbgstat === "disabled-since-boot". Default true. */
  requireProductionDebugStatus?: boolean;

  /** Default "https://confidentialcomputing.googleapis.com". */
  expectedIssuer?: string;

  /** Optional. Checked only when supplied. */
  expectedAudience?: string;

  /** Seconds of leeway on exp/nbf/iat. Default 30. */
  clockToleranceSec?: number;

  /**
   * Evaluate time-based checks against this instant instead of now.
   * Provided so expired sample tokens can be inspected in a demo. It does not
   * suppress the failure — the expiry check still reports honestly against the
   * real clock as well.
   */
  now?: Date;

  /** Override the pinned root. Testing only; never do this in production. */
  rootDerOverride?: Uint8Array;
}
