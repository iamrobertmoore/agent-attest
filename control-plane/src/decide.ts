/**
 * The authorization decision, as a pure function of the admission record.
 *
 * Deliberately transport-free. Nothing in this file knows about gRPC, Envoy, Service
 * Extensions or HTTP. That separation is not tidiness for its own sake: it means the
 * same decision runs behind a real Agent Gateway authorization extension and behind a
 * plain HTTP proxy, and the two cannot drift apart and start disagreeing about who is
 * allowed to talk to whom. It also means this half is unit-testable without standing up
 * a load balancer.
 *
 * WHAT THIS CHECK CAN AND CANNOT DO
 * ---------------------------------
 * A Confidential Space attestation token is minted by the workload itself, from the
 * launcher socket, on request. The gateway cannot compel a fresh attestation on every
 * call, and the caller is not the agent, so no token is available at this point.
 *
 * So the per-request decision is NOT "re-attest the target now". It is:
 *
 *   was this agent admitted, is that admission still in force, and has the agent proved
 *   recently enough that it is still running the code it was admitted under?
 *
 * The digest comparison happens at heartbeat time, in the control plane, where a token
 * genuinely is available. This function consumes that work. Being precise about the
 * split matters, because "the gateway re-checks the running measurement on every
 * request" is a claim that would be false if stated without it.
 *
 * The exposure is the freshness window, and it is bounded by a property of the platform
 * rather than by trust: on Confidential Space an image cannot be swapped in place. New
 * code means a new VM, and the new VM's first heartbeat carries a different image_id.
 * Drift surfaces on the next beat rather than needing to be hunted for.
 */

import {
  readAdmissionRecord,
  DEFAULT_FRESHNESS_WINDOW_SEC,
  type AdmissionRecord,
} from "@agent-attest/confidential-space-verifier";

export type DenyReason =
  | "no_record"
  | "not_admitted"
  | "revoked"
  | "never_attested"
  | "stale_attestation"
  | "digest_drift"
  | "lookup_failed";

export interface Decision {
  allow: boolean;
  reason: DenyReason | "ok";
  /** Written for a human reading a log line at 3am, not for a machine. */
  detail: string;
  agentId: string;
  record?: AdmissionRecord;
  attestationAgeSec?: number;
}

export interface DecideOptions {
  projectId: string;
  databaseId?: string;
  freshnessWindowSec?: number;
  now?: Date;
  fetchImpl?: typeof fetch;
}

function deny(agentId: string, reason: DenyReason, detail: string, extra?: Partial<Decision>): Decision {
  return { allow: false, reason, detail, agentId, ...extra };
}

/**
 * Decide whether traffic to `agentId` is allowed.
 *
 * Every failure path returns deny. There is no branch, including an unreachable
 * Firestore, where this returns allow. Fail-open is the natural shape for an
 * availability-minded engineer and it is the wrong shape here: an authorization
 * extension that permits traffic when it cannot reach its own policy store is an
 * authorization extension an attacker can disable by attacking the policy store.
 */
export async function decide(agentId: string, options: DecideOptions): Promise<Decision> {
  const windowSec = options.freshnessWindowSec ?? DEFAULT_FRESHNESS_WINDOW_SEC;
  const now = options.now ?? new Date();

  let record: AdmissionRecord | null;
  try {
    record = await readAdmissionRecord({
      projectId: options.projectId,
      agentId,
      ...(options.databaseId ? { databaseId: options.databaseId } : {}),
      ...(options.fetchImpl ? { fetchImpl: options.fetchImpl } : {}),
    });
  } catch (e) {
    return deny(
      agentId,
      "lookup_failed",
      `Could not read the admission record: ${String(e)}. Denying, because an ` +
        `authorization extension that allows traffic when it cannot reach its policy ` +
        `store can be switched off by attacking the policy store.`,
    );
  }

  if (!record) {
    return deny(
      agentId,
      "no_record",
      `No admission record for "${agentId}". This agent was never admitted, which is a ` +
        `different thing from having been admitted and revoked, and the two are worth ` +
        `distinguishing in an incident.`,
    );
  }

  if (record.revoked) {
    return deny(agentId, "revoked", `Admission revoked: ${record.revokedReason ?? "no reason recorded"}.`, {
      record,
    });
  }

  if (!record.admitted) {
    return deny(agentId, "not_admitted", `Record exists but admitted is false.`, { record });
  }

  if (!record.lastAttestedAt) {
    return deny(
      agentId,
      "never_attested",
      `Admitted but has never produced a verifying attestation since.`,
      { record },
    );
  }

  const ageSec = Math.floor((now.getTime() - new Date(record.lastAttestedAt).getTime()) / 1000);

  // Belt and braces. The control plane revokes on drift at heartbeat time, so reaching
  // this branch means either a heartbeat has not landed yet or something wrote the
  // record that should not have. Both are reasons to stop, not to reason about it.
  if (record.lastAttestedDigest && record.lastAttestedDigest !== record.imageDigest) {
    return deny(
      agentId,
      "digest_drift",
      `Last attestation carried ${record.lastAttestedDigest} but this agent was admitted ` +
        `as ${record.imageDigest}. The identity is unchanged and the registry entry is ` +
        `unchanged. The code is not.`,
      { record, attestationAgeSec: ageSec },
    );
  }

  if (ageSec > windowSec) {
    return deny(
      agentId,
      "stale_attestation",
      `Last good attestation ${ageSec}s ago, outside the ${windowSec}s window. The agent ` +
        `may be perfectly healthy and merely unable to reach the control plane. Denied ` +
        `either way, because the alternative is honouring an admission nobody can confirm.`,
      { record, attestationAgeSec: ageSec },
    );
  }

  return {
    allow: true,
    reason: "ok",
    detail: `Admitted as ${record.imageDigest}, attested ${ageSec}s ago.`,
    agentId,
    record,
    attestationAgeSec: ageSec,
  };
}
