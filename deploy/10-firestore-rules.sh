#!/usr/bin/env bash
# Admission records are world-READABLE and control-plane-write-only.
#
# The readability is deliberate and it is the argument of the project: an approval only
# the control plane can read is an assertion, and the whole point is that approval should
# be checkable. The records contain digests, timestamps and verdicts. They never contain
# attestation tokens, credentials, or nonces that are still live.
set -euo pipefail
PROJECT="${PROJECT:-agent-attest-2026}"
cd "$(dirname "$0")"

cat > /tmp/firestore.rules <<'RULES'
rules_version = '2';
service cloud.firestore {
  match /databases/{db}/documents {
    match /agents/{agentId} {
      allow read: if true;
      allow write: if false;
      match /attestations/{id} {
        allow read: if true;
        allow write: if false;
      }
    }
    match /policies/{policyId} {
      allow read: if true;
      allow write: if false;
    }
    // Nonces are single-use challenges. Readable by nobody: publishing an unconsumed
    // challenge would hand an attacker the one input they cannot otherwise obtain.
    match /nonces/{n} {
      allow read, write: if false;
    }
  }
}
RULES

cat > /tmp/firebase.json <<'JSON'
{ "firestore": { "rules": "/tmp/firestore.rules" } }
JSON

echo "Rules written to /tmp/firestore.rules"
echo "Apply with either:"
echo "  npx -y firebase-tools deploy --only firestore:rules --project ${PROJECT} --config /tmp/firebase.json"
echo "or paste them into the console: Firestore > Rules"
