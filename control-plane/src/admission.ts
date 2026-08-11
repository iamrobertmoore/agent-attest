/**
 * The admission decision.
 *
 * Two operations, and the difference between them is the whole design:
 *
 *   apply()     an agent presents an attestation and asks to be admitted. The digest it
 *               presents becomes the digest it is pinned to, forever.
 *   heartbeat() an admitted agent proves it is STILL running that digest.
 *
 * apply() is the only path that calls services.create on Google's Agent Registry, and it
 * cannot be reached without a verification that passed. heartbeat() can never change the
 * pinned digest, only refresh the timestamp. Those two invariants are what the gateway's
 * per-request check ultimately rests on, so they are enforced here rather than assumed.
 *
 * FAIL CLOSED, EVERYWHERE
 * -----------------------
 * Every error path in this file ends in "not admitted". There is no branch where an
 * exception, a timeout or an unreadable record results in an agent being trusted. That
 * sounds obvious and is exactly the property that quietly disappears from systems like
 * this, usually via a try/catch written to stop an alert firing.
 */

import { randomBytes, createHash } from "node:crypto";
import { Firestore, Timestamp, FieldValue } from "@google-cloud/firestore";
import {
  verifyAttestation,
  TEE_HW_MODELS,
  type AttestationClaims,
  type Check,
} from "@agent-attest/confidential-space-verifier";
import { registerAttestedAgent } from "./agent-registry.js";

const db = new Firestore();

/** Nonces live briefly and are single use. A replayed attestation is not an attestation. */
const NONCE_TTL_SEC = 300;

export interface AdmissionPolicy {
  allowedHwModels: readonly string[];
  requireProductionDebugStatus: boolean;
  freshnessWindowSec: number;
}

export const DEFAULT_POLICY: AdmissionPolicy = {
  allowedHwModels: TEE_HW_MODELS,
  requireProductionDebugStatus: true,
  freshnessWindowSec: 300,
};

function sha256(s: string): string {
  return createHash("sha256").update(s).digest("hex");
}

/**
 * The digests an operator has approved for admission.
 *
 * Stored rather than hardcoded so the demo can show one being added and an agent
 * becoming admissible, and one being removed and an agent becoming inadmissible, without
 * redeploying the control plane.
 *
 * Note these are Docker CONFIG digests, which is what Confidential Space reports as
 * submods.container.image_id, and NOT the manifest digest that `docker push` prints.
 * They differ, and confusing them yields an allowlist that never matches anything.
 * `docker inspect --format='{{.Id}}'` gives the right one.
 */
async function loadAllowedDigests(): Promise<string[]> {
  const snap = await db.collection("policies").doc("admission").get();
  if (!snap.exists) return [];
  const data = snap.data() as { allowedImageDigests?: unknown };
  const list = data.allowedImageDigests;
  if (!Array.isArray(list)) return [];
  return list.filter(
    (d): d is string => typeof d === "string" && d.startsWith("sha256:"),
  );
}

/**
 * Issue a challenge.
 *
 * The nonce is stored, not merely signed, because it has to be consumable exactly once
 * and a stateless token cannot express that. 32 bytes from the CSPRNG, base64url, which
 * is what the Confidential Space token service accepts in `nonces`.
 */
export async function issueChallenge(agentId: string): Promise<{ nonce: string; expiresAt: Date }> {
  const nonce = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + NONCE_TTL_SEC * 1000);
  await db.collection("nonces").doc(sha256(nonce)).set({
    agentId,
    issuedAt: Timestamp.now(),
    expiresAt: Timestamp.fromDate(expiresAt),
    consumed: false,
  });
  return { nonce, expiresAt };
}

/**
 * Consume a nonce, atomically. Returns the agent it was issued to, or null.
 *
 * A transaction rather than read-then-write, because two concurrent presentations of the
 * same token is precisely the case this is here to stop, and that is the case where the
 * non-atomic version passes both.
 */
async function consumeNonce(nonce: string): Promise<string | null> {
  const ref = db.collection("nonces").doc(sha256(nonce));
  return db.runTransaction(async (tx) => {
    const snap = await tx.get(ref);
    if (!snap.exists) return null;
    const d = snap.data() as { agentId: string; expiresAt: Timestamp; consumed: boolean };
    if (d.consumed) return null;
    if (d.expiresAt.toDate().getTime() < Date.now()) return null;
    tx.update(ref, { consumed: true, consumedAt: Timestamp.now() });
    return d.agentId;
  });
}

export interface VerdictSummary {
  verified: boolean;
  checks: { id: string; ok: boolean; severity: string }[];
  caveats: string[];
}

function summarise(checks: Check[], verified: boolean, caveats: string[]): VerdictSummary {
  return {
    verified,
    checks: checks.map((c) => ({ id: c.id, ok: c.ok, severity: c.severity })),
    caveats,
  };
}

function launchPolicyFrom(claims: AttestationClaims): Record<string, unknown> {
  const c = claims.submods?.container;
  return {
    restartPolicy: c?.restart_policy ?? null,
    imageReference: c?.image_reference ?? null,
    supportAttributes: claims.submods?.confidential_space?.support_attributes ?? null,
  };
}

export interface ApplyInput {
  agentId: string;
  token: string;
  nonce: string;
  displayName: string;
  description: string;
  role: string;
  url: string;
  projectId: string;
  location: string;
  agentCard?: Record<string, unknown>;
}

export type ApplyResult =
  | { admitted: true; registryService: string; imageDigest: string; verdict: VerdictSummary }
  | { admitted: false; reason: string; verdict?: VerdictSummary };

/**
 * Admit an agent, or refuse and say why.
 *
 * Order matters and is not arbitrary: consume the nonce first, so a replayed token is
 * rejected before any work is done on it; verify before touching the registry, so a
 * failed verification cannot leave a half-registered agent behind; and write the
 * admission record only after services.create has succeeded, so the record never claims
 * a registry entry that does not exist.
 */
export async function apply(input: ApplyInput): Promise<ApplyResult> {
  const issuedTo = await consumeNonce(input.nonce);
  if (issuedTo === null) {
    return { admitted: false, reason: "Nonce is unknown, expired, or already used." };
  }
  if (issuedTo !== input.agentId) {
    return {
      admitted: false,
      reason: `Nonce was issued to "${issuedTo}" but presented for "${input.agentId}".`,
    };
  }

  const existing = await db.collection("agents").doc(input.agentId).get();
  if (existing.exists) {
    return {
      admitted: false,
      reason:
        `Agent "${input.agentId}" already has an admission record. Re-admitting would ` +
        `silently repin it to a new digest, which is the exact substitution this system ` +
        `exists to prevent. Revoke it explicitly first.`,
    };
  }

  // THE DIGEST ALLOWLIST IS THE APPROVAL.
  //
  // An earlier version verified without allowedImageIds, on the reasoning that the
  // digest an agent presents at admission becomes the digest it is pinned to. The
  // verifier refused to call that verified, correctly: with no allowlist, admission is
  // trust-on-first-use, and anyone able to launch a Confidential Space workload could
  // admit themselves. The attestation would prove what code ran; nobody would have said
  // that code was allowed to run.
  //
  // So approval is an operator decision about a digest, made in advance and recorded in
  // policies/admission. Attestation then proves the running code IS that digest. Those
  // are two different claims and the system needs both: the allowlist without
  // attestation is a database row, and attestation without the allowlist is a
  // stranger asserting their own legitimacy.
  const allowedImageIds = await loadAllowedDigests();
  if (allowedImageIds.length === 0) {
    return {
      admitted: false,
      reason:
        "No approved image digests in policies/admission. Refusing to admit anything " +
        "rather than falling back to trusting whatever digest was presented.",
    };
  }

  const result = await verifyAttestation(input.token, {
    expectedNonce: input.nonce,
    allowedHwModels: DEFAULT_POLICY.allowedHwModels,
    requireProductionDebugStatus: DEFAULT_POLICY.requireProductionDebugStatus,
    allowedImageIds,
  });
  const verdict = summarise(result.checks, result.verified, [...result.caveats]);

  if (!result.verified || !result.claims) {
    const failed = result.checks.filter((c) => !c.ok).map((c) => c.id);
    return {
      admitted: false,
      reason: `Attestation did not verify. Failed checks: ${failed.join(", ") || "unknown"}.`,
      verdict,
    };
  }

  const imageDigest = result.claims.submods?.container?.image_id;
  const platform = result.claims.hwmodel;
  if (typeof imageDigest !== "string" || !imageDigest.startsWith("sha256:") || !platform) {
    return {
      admitted: false,
      reason: "Token verified but carries no usable image_id or hwmodel.",
      verdict,
    };
  }

  const registered = await registerAttestedAgent(
    {
      projectId: input.projectId,
      location: input.location,
      serviceId: input.agentId,
      displayName: input.displayName,
      description: input.description,
      url: input.url,
      ...(input.agentCard ? { agentCard: input.agentCard } : {}),
    },
    { imageDigest, verifiedAt: new Date() },
  );

  await db
    .collection("agents")
    .doc(input.agentId)
    .set({
      registryService: registered.name,
      displayName: input.displayName,
      role: input.role,
      imageDigest,
      platform,
      swname: result.claims.swname ?? null,
      dbgstat: result.claims.dbgstat ?? null,
      launchPolicy: launchPolicyFrom(result.claims),
      admitted: true,
      admittedAt: Timestamp.now(),
      admittedBy: process.env.K_SERVICE ?? "local",
      admissionTokenSha256: sha256(input.token),
      revoked: false,
      revokedAt: null,
      revokedReason: null,
      lastAttestedAt: Timestamp.now(),
      lastAttestedDigest: imageDigest,
      attestationFailures: 0,
    });

  await recordAttestation(input.agentId, imageDigest, true, verdict, input.token, input.nonce);
  return { admitted: true, registryService: registered.name, imageDigest, verdict };
}

async function recordAttestation(
  agentId: string,
  digest: string | null,
  verified: boolean,
  verdict: VerdictSummary,
  token: string,
  nonce: string,
): Promise<void> {
  await db.collection("agents").doc(agentId).collection("attestations").add({
    at: Timestamp.now(),
    digest,
    verified,
    checks: verdict.checks,
    tokenSha256: sha256(token),
    nonceSha256: sha256(nonce),
  });
}

export type HeartbeatResult =
  | { ok: true; digest: string }
  | { ok: false; reason: string; revoked: boolean };

/**
 * An admitted agent proving it is still what it was.
 *
 * This can refresh `lastAttestedAt` and it can revoke. It can never repin `imageDigest`.
 * If it could, an attacker who could reach this endpoint would be able to launder new
 * code into an existing admission, and every downstream check would keep passing.
 */
export async function heartbeat(
  agentId: string,
  token: string,
  nonce: string,
): Promise<HeartbeatResult> {
  const issuedTo = await consumeNonce(nonce);
  if (issuedTo !== agentId) {
    return { ok: false, reason: "Nonce unknown, expired, reused, or issued to another agent.", revoked: false };
  }

  const ref = db.collection("agents").doc(agentId);
  const snap = await ref.get();
  if (!snap.exists) return { ok: false, reason: "No admission record.", revoked: false };
  const record = snap.data() as { imageDigest: string; revoked: boolean };
  if (record.revoked) return { ok: false, reason: "Already revoked.", revoked: true };

  const result = await verifyAttestation(token, {
    expectedNonce: nonce,
    allowedHwModels: DEFAULT_POLICY.allowedHwModels,
    requireProductionDebugStatus: DEFAULT_POLICY.requireProductionDebugStatus,
    allowedImageIds: [record.imageDigest],
  });
  const verdict = summarise(result.checks, result.verified, [...result.caveats]);
  const presented = result.claims?.submods?.container?.image_id ?? null;

  await recordAttestation(agentId, presented, result.verified, verdict, token, nonce);

  if (!result.verified) {
    const drifted = presented !== null && presented !== record.imageDigest;
    await ref.update({
      attestationFailures: FieldValue.increment(1),
      ...(drifted
        ? {
            revoked: true,
            revokedAt: Timestamp.now(),
            revokedReason:
              `Presented ${presented} but was admitted as ${record.imageDigest}. The ` +
              `identity is unchanged and the registry entry is unchanged. The code is not.`,
          }
        : {}),
    });
    return {
      ok: false,
      reason: drifted
        ? `Digest drift: presented ${presented}, admitted ${record.imageDigest}.`
        : `Attestation failed: ${result.checks.filter((c) => !c.ok).map((c) => c.id).join(", ")}.`,
      revoked: drifted,
    };
  }

  await ref.update({
    lastAttestedAt: Timestamp.now(),
    lastAttestedDigest: record.imageDigest,
    attestationFailures: 0,
  });
  return { ok: true, digest: record.imageDigest };
}

export async function revoke(agentId: string, reason: string): Promise<void> {
  await db.collection("agents").doc(agentId).update({
    revoked: true,
    revokedAt: Timestamp.now(),
    revokedReason: reason,
  });
}
