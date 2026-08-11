#!/usr/bin/env bash
# One-time project setup: APIs, Firestore, service accounts, IAM.
# Idempotent. Safe to re-run.
set -euo pipefail

PROJECT="${PROJECT:-agent-attest-2026}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-agent-attest}"

# Manual Agent Registry registration is NOT supported in the `us` or `eu` MULTI-regions.
# us-central1 is a named region, so this is fine, but the constraint is why every
# resource here is pinned to one region rather than left to default.
echo "== project ${PROJECT}, region ${REGION}"
gcloud config set project "${PROJECT}" >/dev/null

echo "== APIs"
gcloud services enable \
  run.googleapis.com \
  firestore.googleapis.com \
  artifactregistry.googleapis.com \
  cloudasset.googleapis.com \
  aiplatform.googleapis.com \
  agentregistry.googleapis.com \
  cloudbuild.googleapis.com \
  iamcredentials.googleapis.com

echo "== Firestore (native mode)"
gcloud firestore databases create --location="${REGION}" 2>/dev/null \
  || echo "   already exists"

echo "== Artifact Registry"
gcloud artifacts repositories create "${REPO}" \
  --repository-format=docker --location="${REGION}" 2>/dev/null \
  || echo "   already exists"

# --- service accounts -------------------------------------------------------
# One per role, with the smallest grant each can do its job with. The separation is
# the product: it is what makes "no agent holds two of these powers" a fact about the
# project rather than a claim in a README.

make_sa () {
  gcloud iam service-accounts create "$1" --display-name="$2" 2>/dev/null \
    || echo "   sa $1 already exists"
}

echo "== service accounts"
make_sa agent-attest-control  "agent-attest control plane"
make_sa agent-attest-authz    "agent-attest gateway authorization extension"
make_sa agent-attest-surveyor "Surveyor: broad read, zero write"
make_sa agent-attest-assessor "Assessor: no cloud access at all"
make_sa agent-attest-executor "Executor: one narrow mutation"
make_sa agent-attest-warden   "Warden: orchestrator, no estate access"

grant () {
  gcloud projects add-iam-policy-binding "${PROJECT}" \
    --member="serviceAccount:$1@${PROJECT}.iam.gserviceaccount.com" \
    --role="$2" --condition=None >/dev/null
  echo "   $1 -> $2"
}

echo "== IAM"
# The control plane is the ONLY principal that may write to Agent Registry. Everything
# in this build rests on that being true, so it is granted in exactly one place.
grant agent-attest-control  roles/agentregistry.admin
grant agent-attest-control  roles/datastore.user
grant agent-attest-control  roles/logging.logWriter

grant agent-attest-authz    roles/run.invoker
grant agent-attest-authz    roles/logging.logWriter

# Surveyor: broad read, and deliberately no write of any kind.
grant agent-attest-surveyor roles/cloudasset.viewer
grant agent-attest-surveyor roles/browser
grant agent-attest-surveyor roles/aiplatform.user
grant agent-attest-surveyor roles/run.invoker
grant agent-attest-surveyor roles/confidentialcomputing.workloadUser
grant agent-attest-surveyor roles/logging.logWriter

# Assessor: aiplatform.user so it can call Gemini, and nothing else. It cannot read
# the estate, which is the point: its opinion is bounded by having no way to check it.
grant agent-attest-assessor roles/aiplatform.user
grant agent-attest-assessor roles/run.invoker
grant agent-attest-assessor roles/confidentialcomputing.workloadUser
grant agent-attest-assessor roles/logging.logWriter

# Executor: the only mutating principal. compute.storageAdmin lets it delete a disk
# and nothing else. NOT compute.admin, which would let it delete instances too.
grant agent-attest-executor roles/compute.storageAdmin
grant agent-attest-executor roles/aiplatform.user
grant agent-attest-executor roles/run.invoker
grant agent-attest-executor roles/confidentialcomputing.workloadUser
grant agent-attest-executor roles/logging.logWriter

# Warden: reasons and delegates. No estate access at all.
grant agent-attest-warden   roles/aiplatform.user
grant agent-attest-warden   roles/run.invoker
grant agent-attest-warden   roles/confidentialcomputing.workloadUser
grant agent-attest-warden   roles/logging.logWriter

echo
echo "Bootstrap done."
echo "Next: deploy/10-firestore-rules.sh, then deploy/20-control-plane.sh"
