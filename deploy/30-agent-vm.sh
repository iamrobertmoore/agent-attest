#!/usr/bin/env bash
# Build the fleet image and launch one agent as a Confidential Space workload.
#
#   ./deploy/30-agent-vm.sh surveyor
#   ./deploy/30-agent-vm.sh assessor
#
# Every agent runs the same image. Which one it becomes is decided by the AGENT env var
# at launch, so all four share a digest. That matters for the demo: it means a changed
# measurement can only mean the IMAGE changed, never merely that a different agent is
# running.
set -euo pipefail

AGENT="${1:-}"
case "$AGENT" in
  warden|surveyor|assessor|executor) ;;
  *) echo "usage: $0 {warden|surveyor|assessor|executor}"; exit 2 ;;
esac

PROJECT="${PROJECT:-agent-attest-2026}"
REGION="${REGION:-us-central1}"
REPO="${REPO:-agent-attest}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/fleet:latest"
VM="agent-attest-${AGENT}"
SA="agent-attest-${AGENT}@${PROJECT}.iam.gserviceaccount.com"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

# shellcheck source=deploy/lib-url.sh
. "$(dirname "$0")/lib-url.sh"
# Resolved and PROVEN before launching a VM. The agent fails closed on a bad URL, and
# the resulting log line says "cannot attest", which points at the TEE rather than at
# the typo that actually caused it.
CONTROL_PLANE_URL="${CONTROL_PLANE_URL:-$(resolve_control_plane_url agent-attest-control "${REGION}" "${PROJECT}")}"
[ -n "${CONTROL_PLANE_URL}" ] || { echo "control plane URL could not be resolved"; exit 1; }
echo "== control plane: ${CONTROL_PLANE_URL}"

if [ "${SKIP_BUILD:-}" != "true" ]; then
  echo "== building ${IMAGE}"
  # --platform linux/amd64 explicitly: Confidential Space is amd64 only, and an arm64
  # image built on an Apple Silicon laptop launches, fails to exec, and the VM stops
  # before writing anything useful anywhere.
  docker build --platform linux/amd64 -f "${ROOT}/agents/Dockerfile" -t "${IMAGE}" "${ROOT}/agents"
  docker push "${IMAGE}"
fi

# Allow the agent's service account to invoke the control plane. Least privilege, per
# agent, rather than one shared identity: the admission record records who applied.
gcloud run services add-iam-policy-binding agent-attest-control \
  --region="${REGION}" --project="${PROJECT}" \
  --member="serviceAccount:${SA}" --role=roles/run.invoker >/dev/null
gcloud artifacts repositories add-iam-policy-binding "${REPO}" \
  --location="${REGION}" --project="${PROJECT}" \
  --member="serviceAccount:${SA}" --role=roles/artifactregistry.reader >/dev/null 2>&1 || true

gcloud --quiet compute instances delete "${VM}" --project="${PROJECT}" \
  --zone="$(cat "${ROOT}/deploy/.zone-${AGENT}" 2>/dev/null || echo us-central1-c)" 2>/dev/null || true

launched=0
for z in us-central1-c us-central1-a us-central1-b us-central1-f; do
  echo "== launching ${VM} in ${z}"
  if gcloud --quiet compute instances create "${VM}" \
      --project="${PROJECT}" --zone="${z}" \
      --machine-type=n2d-standard-2 \
      --confidential-compute-type=SEV \
      --min-cpu-platform="AMD Milan" \
      --maintenance-policy=MIGRATE \
      --shielded-secure-boot \
      --scopes=cloud-platform \
      --service-account="${SA}" \
      --image-project=confidential-space-images \
      --image-family=confidential-space \
      --metadata="^~^tee-image-reference=${IMAGE}~tee-container-log-redirect=true~tee-env-AGENT=${AGENT}~tee-env-CONTROL_PLANE_URL=${CONTROL_PLANE_URL}~tee-env-TARGET_PROJECT_ID=${PROJECT}~tee-env-GATEWAY_HOST=${GATEWAY_HOST:-invalid.local}~tee-env-EXECUTOR_ARMED=${EXECUTOR_ARMED:-false}~tee-env-GOOGLE_CLOUD_PROJECT=${PROJECT}~tee-env-GOOGLE_CLOUD_LOCATION=${REGION}~tee-env-GOOGLE_GENAI_USE_VERTEXAI=TRUE"
  then
    echo "${z}" > "${ROOT}/deploy/.zone-${AGENT}"
    launched=1
    break
  fi
  echo "   no capacity in ${z}, trying the next zone"
done
[ "${launched}" = "1" ] || { echo "no capacity in any zone"; exit 1; }

cat <<NEXT

Launched. The workload pulls the image, applies for admission, then serves.
That takes two or three minutes.

Watch it:
  gcloud logging read 'resource.type="gce_instance" AND labels."compute.googleapis.com/resource_name"="${VM}"' \\
    --project ${PROJECT} --limit 40 --freshness=10m --format='value(textPayload)'

Confirm it reached Google's Agent Registry:
  gcloud alpha agent-registry services list --location=${REGION} --project=${PROJECT} 2>/dev/null \\
    || curl -s -H "Authorization: Bearer \$(gcloud auth print-access-token)" \\
       "https://agentregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/services" | head -60

Confirm the admission record, unauthenticated, as anyone could:
  curl -s "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/agents/${AGENT}" | head -40

Tear down:
  gcloud compute instances delete ${VM} --zone=\$(cat deploy/.zone-${AGENT}) --project=${PROJECT}
NEXT
