/**
 * Bind a Confidential Space attestation token to an agent's admission record.
 *
 * THIS IS THE PART THAT MAKES THE ATTESTATION MEAN SOMETHING.
 *
 * verify.ts answers: "is this a genuine Google Confidential Space token, and does the
 * machine it describes meet my policy?" That is necessary and not sufficient. It
 * establishes that *some* code ran in *a* real TEE. It cannot tell you that the code is
 * the code this agent was admitted to the registry under.
 *
 * agent-attest records that separately, in Firestore, at the moment of admission. The
 * attestation token carries the same facts in its claims. This module joins them.
 *
 * THE JOIN
 * --------
 * Two claims carry everything the decision needs:
 *
 *   imageDigest = submods.container.image_id     (immutable content digest)
 *   platform    = hwmodel                        (which TEE the workload ran on)
 *
 * And the admission record holds exactly those, written by the control plane at the
 * moment it called services.create on Google's Agent Registry.
 *
 * WHY THE RECORD IS READ OVER THE PUBLIC FIRESTORE REST API
 * ---------------------------------------------------------
 * Admission records are deliberately world-readable. The entire argument of this project
 * is that approval should be checkable rather than asserted, and a record only you can
 * read is an assertion. Publishing them costs nothing (they contain digests and verdicts,
 * never tokens or credentials) and it buys the property that matters: anyone can
 * recompute the admission decision, in a browser, offline against the pinned Google root,
 * without an account and without asking this service to be honest about it.
 *
 * That is also why there is no SDK dependency here. One `fetch` against the REST API
 * keeps this module usable unchanged in the browser, in the Cloud Run control plane, and
 * in the gateway authorization extension. Three call sites, one implementation, no
 * chance of them disagreeing.
 *
 * WHAT `verified` DOES NOT MEAN
 * -----------------------------
 * See REGISTRY_CAVEATS at the bottom. It is not decoration. Every result this module
 * produces carries them, including the passing ones.
 */

import type { AttestationClaims, Check } from "./types.js";

/** Firestore REST endpoint. Documents are read unauthenticated; see the note above. */
export const FIRESTORE_HOST = "https://firestore.googleapis.com/v1";

/** Collection holding one admission record per agent. */
export const AGENTS_COLLECTION = "agents";

/**
 * How stale an agent's last good attestation may be before the gateway stops honouring
 * its admission.
 *
 * Agents re-attest on a heartbeat. This window is the exposure: the maximum time an
 * agent that has stopped being what it claimed can still be routed to. Shorter is safer
 * and costs one Firestore write per agent per heartbeat, which is nothing. 300 seconds
 * against a 60 second heartbeat tolerates four consecutive missed heartbeats before an
 * agent is treated as unattested, which is enough to survive a redeploy without
 * flapping.
 *
 * Note this is a policy default, not a security boundary discovered by measurement. It
 * is stated here so a reader can disagree with the number rather than having to find it.
 */
export const DEFAULT_FRESHNESS_WINDOW_SEC = 300;

export interface RegistryOptions {
  /** GCP project holding the Firestore database. */
  projectId: string;
  /** Agent to check the attestation against. Firestore document id. */
  agentId: string;
  /** Defaults to "(default)". */
  databaseId?: string;
  /** Defaults to DEFAULT_FRESHNESS_WINDOW_SEC. */
  freshnessWindowSec?: number;
  /** Evaluate freshness against this instant instead of now. Inspection mode. */
  now?: Date;
  /** Injected for testing. Defaults to globalThis.fetch. */
  fetchImpl?: typeof fetch;
  /** Defaults to FIRESTORE_HOST. */
  firestoreHost?: string;
}

export interface AdmissionRecord {
  agentId: string;
  /** Resource name in Google's Agent Registry, projects/*&#47;locations/*&#47;services/*. */
  registryService: string;
  /** sha256:... the agent was admitted under. */
  imageDigest: string;
  /** hwmodel the agent was admitted under. */
  platform: string;
  admitted: boolean;
  revoked: boolean;
  revokedReason: string | null;
  admittedAt: string | null;
  /** Last time this agent produced an attestation that verified. */
  lastAttestedAt: string | null;
  /** Digest carried by that last good attestation. */
  lastAttestedDigest: string | null;
}

export interface RegistryBinding extends AdmissionRecord {
  /** Digest carried by the token being checked right now. */
  presentedDigest: string;
  /** Platform carried by the token being checked right now. */
  presentedPlatform: string;
  /** Presented digest equals the admitted digest. */
  digestMatches: boolean;
  /** Presented platform equals the admitted platform. */
  platformMatches: boolean;
  /** Seconds since lastAttestedAt, or null if the agent has never attested. */
  attestationAgeSec: number | null;
  /** attestationAgeSec is inside the freshness window. */
  fresh: boolean;
}

/** Immutable content digest. This is the value admission pins. */
export function imageDigestFromClaims(claims: AttestationClaims): string {
  const id = claims.submods?.container?.image_id;
  if (typeof id !== "string" || !id.startsWith("sha256:")) {
    throw new Error(
      `submods.container.image_id missing or not a sha256 digest (got ${String(id)}). ` +
        `Note image_reference is a mutable tag and is never a substitute.`,
    );
  }
  return id;
}

/** Which TEE the workload ran on. */
export function platformFromClaims(claims: AttestationClaims): string {
  const hw = claims.hwmodel;
  if (typeof hw !== "string" || hw.length === 0) {
    throw new Error(`hwmodel claim missing or empty (got ${String(hw)}).`);
  }
  return hw;
}

/**
 * Firestore wraps every field in a type tag: {"stringValue": "x"}, {"booleanValue": true}.
 * Unwrap only the types admission records actually use, and return undefined for anything
 * else rather than guessing. A silent coercion here would turn a schema change into a
 * wrong trust decision instead of a loud failure.
 */
function unwrap(v: unknown): string | boolean | null | undefined {
  if (v === null || typeof v !== "object") return undefined;
  const f = v as Record<string, unknown>;
  if ("stringValue" in f) return String(f.stringValue);
  if ("booleanValue" in f) return Boolean(f.booleanValue);
  if ("timestampValue" in f) return String(f.timestampValue);
  if ("nullValue" in f) return null;
  return undefined;
}

function str(fields: Record<string, unknown>, key: string): string | null {
  const v = unwrap(fields[key]);
  return typeof v === "string" ? v : null;
}

function bool(fields: Record<string, unknown>, key: string): boolean {
  return unwrap(fields[key]) === true;
}

/**
 * Read an agent's admission record.
 *
 * Throws only on transport or schema failure, which are genuinely exceptional. A missing
 * agent is not exceptional and is returned as admitted: false, because "this agent was
 * never admitted" and "this agent was admitted and then revoked" must both be expressible
 * as data that a caller has to handle.
 */
export async function readAdmissionRecord(
  options: RegistryOptions,
): Promise<AdmissionRecord | null> {
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;
  const host = options.firestoreHost ?? FIRESTORE_HOST;
  const db = options.databaseId ?? "(default)";
  const url =
    `${host}/projects/${encodeURIComponent(options.projectId)}` +
    `/databases/${encodeURIComponent(db)}/documents` +
    `/${AGENTS_COLLECTION}/${encodeURIComponent(options.agentId)}`;

  const res = await fetchImpl(url, { headers: { accept: "application/json" } });
  if (res.status === 404) return null;
  if (!res.ok) {
    throw new Error(`Firestore read failed: HTTP ${res.status} ${res.statusText} for ${url}`);
  }

  const doc = (await res.json()) as { fields?: Record<string, unknown> };
  const f = doc.fields;
  if (!f) throw new Error(`Firestore document for ${options.agentId} has no fields.`);

  const imageDigest = str(f, "imageDigest");
  const platform = str(f, "platform");
  if (!imageDigest || !platform) {
    throw new Error(
      `Admission record for ${options.agentId} is missing imageDigest or platform. ` +
        `Refusing to evaluate a record whose shape is not what this code expects.`,
    );
  }

  return {
    agentId: options.agentId,
    registryService: str(f, "registryService") ?? "",
    imageDigest,
    platform,
    admitted: bool(f, "admitted"),
    revoked: bool(f, "revoked"),
    revokedReason: str(f, "revokedReason"),
    admittedAt: str(f, "admittedAt"),
    lastAttestedAt: str(f, "lastAttestedAt"),
    lastAttestedDigest: str(f, "lastAttestedDigest"),
  };
}

/** Join a live token's claims against the stored admission record. */
export async function readRegistryBinding(
  claims: AttestationClaims,
  options: RegistryOptions,
): Promise<RegistryBinding | null> {
  const record = await readAdmissionRecord(options);
  if (!record) return null;

  const presentedDigest = imageDigestFromClaims(claims);
  const presentedPlatform = platformFromClaims(claims);
  const now = options.now ?? new Date();
  const windowSec = options.freshnessWindowSec ?? DEFAULT_FRESHNESS_WINDOW_SEC;

  const attestationAgeSec = record.lastAttestedAt
    ? Math.floor((now.getTime() - new Date(record.lastAttestedAt).getTime()) / 1000)
    : null;

  return {
    ...record,
    presentedDigest,
    presentedPlatform,
    digestMatches: presentedDigest === record.imageDigest,
    platformMatches: presentedPlatform === record.platform,
    attestationAgeSec,
    fresh: attestationAgeSec !== null && attestationAgeSec <= windowSec,
  };
}

/**
 * The admission checks, in the same Check shape verify.ts produces, so a caller can
 * concatenate the two lists and render one honest verdict.
 *
 * Every failure here is severity "policy", never "cryptographic". The token can be
 * perfectly genuine and still describe an agent nobody admitted. Collapsing those into
 * one alarming category is how people learn to ignore the alarm.
 */
export async function checkRegistryBinding(
  claims: AttestationClaims,
  options: RegistryOptions,
): Promise<Check[]> {
  const checks: Check[] = [];
  const add = (id: string, title: string, ok: boolean, detail: string): void => {
    checks.push({ id, title, ok, detail, severity: "policy" });
  };

  let binding: RegistryBinding | null;
  try {
    binding = await readRegistryBinding(claims, options);
  } catch (e) {
    add(
      "admission.read",
      "Admission record is readable",
      false,
      `Could not read the admission record: ${String(e)}. Failing closed: an agent whose ` +
        `admission cannot be established is not admitted.`,
    );
    return checks;
  }

  if (!binding) {
    add(
      "admission.exists",
      "Agent has an admission record",
      false,
      `No admission record for "${options.agentId}". This agent was never admitted, which ` +
        `is a different thing from having been admitted and revoked.`,
    );
    return checks;
  }

  add(
    "admission.exists",
    "Agent has an admission record",
    true,
    `Admitted ${binding.admittedAt ?? "at an unrecorded time"} against registry service ` +
      `${binding.registryService || "(none recorded)"}.`,
  );

  add(
    "admission.admitted",
    "Admission is in force",
    binding.admitted && !binding.revoked,
    binding.revoked
      ? `Revoked: ${binding.revokedReason ?? "no reason recorded"}.`
      : binding.admitted
        ? `Admitted and not revoked.`
        : `Record exists but admitted is false.`,
  );

  add(
    "admission.digest",
    "Running image matches the admitted image",
    binding.digestMatches,
    binding.digestMatches
      ? `Presented ${binding.presentedDigest}, which is the digest this agent was admitted ` +
        `under.`
      : `Presented ${binding.presentedDigest} but this agent was admitted as ` +
        `${binding.imageDigest}. The identity is unchanged and the registry entry is ` +
        `unchanged. The code is not.`,
  );

  add(
    "admission.platform",
    "Running platform matches the admitted platform",
    binding.platformMatches,
    binding.platformMatches
      ? `Presented ${binding.presentedPlatform}.`
      : `Presented ${binding.presentedPlatform} but this agent was admitted on ` +
        `${binding.platform}. A weaker TEE than the one approved is still a change of ` +
        `security posture.`,
  );

  const windowSec = options.freshnessWindowSec ?? DEFAULT_FRESHNESS_WINDOW_SEC;
  add(
    "admission.freshness",
    "Agent has attested recently",
    binding.fresh,
    binding.attestationAgeSec === null
      ? `This agent has never produced a verifying attestation since admission.`
      : binding.fresh
        ? `Last good attestation ${binding.attestationAgeSec}s ago, inside the ${windowSec}s ` +
          `window.`
        : `Last good attestation ${binding.attestationAgeSec}s ago, outside the ${windowSec}s ` +
          `window. The agent may be fine and simply unreachable. Treated as not admitted ` +
          `either way, because the alternative is honouring an admission nobody can confirm.`,
  );

  return checks;
}

export const REGISTRY_CAVEATS: readonly string[] = [
  "The record says this digest was attested and admitted. It does not say the code is " +
    "correct, safe, or does what the agent claims. Whoever operates the control plane " +
    "decides what gets admitted, and the record is an assertion by that operator joined " +
    "to a cryptographic proof of what ran, not an audit of the code itself.",

  "The record is read over the Firestore REST API. You are trusting Firestore to report " +
    "the document honestly, and trusting the control plane not to have written a record " +
    "it should not have. The attestation half of the decision needs no such trust: it is " +
    "verified offline against a root pinned at build time, so a lying registry can " +
    "withhold or fabricate an admission but cannot forge the proof of what code ran.",

  "Admission state is read at check time. An agent admitted when you looked can be " +
    "revoked a second later, and the freshness window means an agent that stopped being " +
    "what it claimed remains routable until its next missed heartbeat.",

  "Attestation describes the workload image and the platform. It says nothing about what " +
    "the workload does with the data it receives, nor about the model weights or prompts " +
    "it loads at runtime from somewhere else. Pinning the image pins the code, not the " +
    "behaviour.",
];
