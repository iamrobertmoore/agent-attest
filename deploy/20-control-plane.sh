#!/usr/bin/env bash
# Build and deploy the admission controller to Cloud Run.
set -euo pipefail

PROJECT="${PROJECT:-agent-attest-2026}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-agent-attest}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/control-plane:latest"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "== building ${IMAGE}"
# Built from the repo root: the Dockerfile copies both verifier/ and control-plane/,
# because the control plane depends on the verifier by path. One verifier, one
# implementation, no vendored copy that can drift.
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -f "${ROOT}/control-plane/Dockerfile" -t "${IMAGE}" "${ROOT}"
docker push "${IMAGE}"

echo "== deploying"
# --no-allow-unauthenticated is not optional. This service holds the only
# agentregistry.services.create permission in the project. Admission is gated on
# attestation, but authentication and attestation answer different questions and the
# service needs both: one says who is calling, the other says what code is running.
#
# --min-instances=1 because the gateway authorization extension calls this on the
# request path with a 1s budget and fails CLOSED, once the policy binding exists. A cold
# start would deny live traffic.
gcloud run deploy agent-attest-control \
  --image="${IMAGE}" \
  --region="${REGION}" \
  --service-account="agent-attest-control@${PROJECT}.iam.gserviceaccount.com" \
  --no-allow-unauthenticated \
  --min-instances=1 \
  --max-instances=4 \
  --memory=512Mi \
  --set-env-vars="PROJECT_ID=${PROJECT},LOCATION=${REGION}"

# shellcheck source=deploy/lib-url.sh
. "$(dirname "$0")/lib-url.sh"
echo "== resolving a URL that actually answers"
URL="$(resolve_control_plane_url agent-attest-control "${REGION}" "${PROJECT}")"
echo
echo "CONTROL_PLANE_URL=${URL}"
echo "   verified: GET /healthz returned 200"
