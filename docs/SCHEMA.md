# Firestore schema

Admission records are **world-readable by design**. The argument of this project is that
approval should be checkable rather than asserted, and a record only the control plane can
read is an assertion. The records contain digests, timestamps and verdicts. They never
contain attestation tokens, credentials or nonces that are still live.

Write access belongs to exactly one principal: the admission controller's service account.

```
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /agents/{agentId} {
      allow read: if true;
      allow write: if false;          // control plane writes with admin credentials
      match /attestations/{id} {
        allow read: if true;
        allow write: if false;
      }
    }
    match /policies/{policyId} {
      allow read: if true;
      allow write: if false;
    }
  }
}
```

---

## `agents/{agentId}`

One document per agent. Read by the verifier, the gateway authorization extension and any
browser that wants to check the control plane's work.

| Field | Type | Notes |
|---|---|---|
| `registryService` | string | `projects/*/locations/*/services/*` in Google's Agent Registry. The link back to the real product. |
| `displayName` | string | |
| `role` | string | `orchestrator` \| `surveyor` \| `assessor` \| `executor` |
| `imageDigest` | string | `sha256:...` from `submods.container.image_id`. **The value admission pins.** |
| `platform` | string | `hwmodel`. One of `GCP_AMD_SEV`, `GCP_AMD_SEV_ES`, `GCP_INTEL_TDX`. |
| `swname` | string | Expected `CONFIDENTIAL_SPACE`. |
| `dbgstat` | string | Expected `disabled-since-boot`. A debug image is rejected at admission. |
| `launchPolicy` | map | Recorded so policy drift is visible, not just image drift. |
| `admitted` | bool | |
| `admittedAt` | timestamp | |
| `admittedBy` | string | Control plane service account. |
| `admissionTokenSha256` | string | Hash of the admitting token. **Never the token.** |
| `revoked` | bool | |
| `revokedAt` | timestamp \| null | |
| `revokedReason` | string \| null | |
| `lastAttestedAt` | timestamp | Updated on every verifying heartbeat. Drives freshness. |
| `lastAttestedDigest` | string | Digest carried by that heartbeat. |
| `attestationFailures` | int | Consecutive failures. Reconciler revokes past a threshold. |

`imageDigest` is the digest at admission and never changes. `lastAttestedDigest` is what the
agent most recently proved it was running. **When those two diverge, that is the whole
event this project exists to catch.**

Note `submods.container.image_reference` is a mutable registry tag and is recorded for
humans only. It is never compared. `types.ts` carries the same warning at the type.

## `agents/{agentId}/attestations/{autoId}`

Append-only. Every heartbeat, passing or failing.

| Field | Type |
|---|---|
| `at` | timestamp |
| `digest` | string |
| `verified` | bool |
| `checks` | array of `{ id, ok, severity }` |
| `tokenSha256` | string |
| `nonce` | string |

This is the audit trail the Fleet track asks for under Telemetry, and it is what makes an
incident reconstructable after the fact. Each entry also emits an OpenTelemetry span.

## `policies/{policyId}`

The admission policy the controller enforces, stored rather than hardcoded so the demo can
show it being tightened.

| Field | Type |
|---|---|
| `allowedHwModels` | array of string |
| `requireProductionDebugStatus` | bool |
| `freshnessWindowSec` | int |
| `requiredLaunchPolicy` | map |

---

## Freshness and the heartbeat

Agents re-attest every **60 seconds**. The freshness window is **300 seconds**, so four
consecutive missed heartbeats are tolerated before an agent is treated as unattested. That
survives a redeploy without flapping.

The window is the exposure. It is the longest an agent that has stopped being what it
claimed can still be routed to. Two things bound the risk in practice:

1. On Confidential Space an image cannot be swapped in place. Changing the workload means
   destroying and recreating the VM, and the new instance's first heartbeat carries a
   different `image_id`, so the divergence surfaces on the next beat rather than needing to
   be detected.
2. A background reconciler independently re-attests every admitted agent and sets `revoked`
   on divergence, so the gateway check degrades to a boolean read.

The residual is stated plainly in `REGISTRY_CAVEATS` and belongs in the write-up: an agent
that drifts inside the window remains routable until its next missed heartbeat. Shortening
the window costs only Firestore writes.
