export { verifyAttestation, STANDING_CAVEATS } from "./verify.js";
export {
  TEE_HW_MODELS,
  NON_TEE_HW_MODELS,
  type AttestationClaims,
  type Check,
  type CheckSeverity,
  type VerificationResult,
  type VerifyOptions,
} from "./types.js";
export {
  checkRegistryBinding,
  readRegistryBinding,
  readAdmissionRecord,
  imageDigestFromClaims,
  platformFromClaims,
  REGISTRY_CAVEATS,
  FIRESTORE_HOST,
  AGENTS_COLLECTION,
  DEFAULT_FRESHNESS_WINDOW_SEC,
  type RegistryOptions,
  type RegistryBinding,
  type AdmissionRecord,
} from "./registry.js";
export {
  ROOT_SHA256_FINGERPRINT,
  ROOT_SHA1_FINGERPRINT_DOCS_ONLY,
  ROOT_CA_DER_B64,
  rootCaDer,
} from "./root.js";
