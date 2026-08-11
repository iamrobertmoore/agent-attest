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
  # Three flags, all load-bearing.
  #
  # --platform linux/amd64: Confidential Space is amd64 only. An arm64 image from an
  #   Apple Silicon laptop launches, fails to exec, and stops the VM before writing
  #   anything useful anywhere.
  #
  # --provenance=false --sbom=false: buildx attaches a provenance attestation by default,
  #   which turns the result into a multi-manifest INDEX rather than a plain image. The
  #   Confidential Space launcher wants a single-platform image and silently fails to
  #   resolve an index, which presents as a VM that boots, logs nothing, and does nothing.
  #   The build log gives it away: "exporting attestation manifest" then "exporting
  #   manifest list".
  docker build --platform linux/amd64 --provenance=false --sbom=false \
    -f "${ROOT}/agents/Dockerfile" -t "${IMAGE}" "${ROOT}/agents"
  docker push "${IMAGE}"

  # Refuse to launch a VM against an image the launcher cannot resolve. Checking costs a
  # second; not checking costs a VM cycle and a confusing silence.
  echo "== confirming it is a plain single-platform image"
  mediatype="$(docker manifest inspect "${IMAGE}" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mediaType",""))' 2>/dev/null || true)"
  echo "   mediaType: ${mediatype:-unknown}"
  case "${mediatype}" in
    *manifest.list*|*image.index*)
      echo "   ERROR: this is a manifest list, not a single image."
      echo "   Confidential Space will not resolve it. Rebuild with --provenance=false --sbom=false."
      exit 1 ;;
    *) echo "   single image, good" ;;
  esac

  # Boot it locally before spending a VM on it.
  #
  # A Confidential Space VM that fails at startup tells you almost nothing: it reports
  # RUNNING, then TERMINATED, and the logs never leave the machine because the container
  # died before the launcher attached anything to it. Every failure looks like silence.
  #
  # Twenty seconds here replaces a four-minute cycle that ends in no information. This
  # is how the missing sse-starlette dependency was eventually found, after three VMs.
  # Every tee-env- we pass must appear in the image's allow_env_override label, or the
  # launcher refuses the workload and reports "Workload completed", which reads like
  # success. Checking here turns a four-minute silent failure into a one-line message.
  echo "== checking launch policy allows every env var we pass"
  allowed="$(docker inspect --format '{{ index .Config.Labels "tee.launch_policy.allow_env_override" }}' "${IMAGE}" 2>/dev/null || true)"
  echo "   image allows: ${allowed}"
  missing=""
  for v in AGENT CONTROL_PLANE_URL TARGET_PROJECT_ID GATEWAY_HOST EXECUTOR_ARMED \
           GOOGLE_CLOUD_PROJECT GOOGLE_CLOUD_LOCATION GOOGLE_GENAI_USE_VERTEXAI; do
    case ",${allowed}," in *",${v},"*) ;; *) missing="${missing} ${v}" ;; esac
  done
  if [ -n "${missing}" ]; then
    echo "   ERROR: launch would pass env vars the image does not permit:${missing}"
    echo "   Add them to tee.launch_policy.allow_env_override in agents/Dockerfile."
    exit 1
  fi
  echo "   all permitted"

  # Approve this digest for admission.
  #
  # This is the operator saying "this exact code may join the fleet". It is a separate
  # act from the attestation, which proves the running code IS this digest. The system
  # needs both: an allowlist alone is a database row, and an attestation alone is a
  # stranger asserting their own legitimacy.
  #
  # image_id in the attestation is the Docker CONFIG digest, which is what
  # `docker inspect --format={{.Id}}` returns and what the build log prints as
  # "exporting config sha256:...". It is NOT the manifest digest `docker push` prints.
  # They differ, and using the wrong one gives an allowlist that never matches.
  # Read the CONFIG blob digest out of the manifest.
  #
  # `docker inspect --format={{.Id}}` is NOT it. On Docker Desktop's containerd image
  # store that returns the MANIFEST digest, the same value `docker push` prints, and it
  # does not match image_id. Both are sha256 and both look plausible in a log line, which
  # is what makes this worth doing explicitly rather than conveniently.
  #
  # Confirmed against a real token: a capture whose build logged
  # "exporting config sha256:6d9033aa..." produced image_id sha256:6d9033aa..., while
  # its push printed a completely different manifest digest.
  CONFIG_DIGEST="$(docker manifest inspect "${IMAGE}" \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["config"]["digest"])')"
  case "${CONFIG_DIGEST}" in
    sha256:*) ;;
    *) echo "   ERROR: could not read a config digest (got '${CONFIG_DIGEST}')"; exit 1 ;;
  esac
  echo "== approving digest for admission"
  echo "   ${CONFIG_DIGEST}"
  curl -s -X PATCH \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    "https://firestore.googleapis.com/v1/projects/${PROJECT}/databases/(default)/documents/policies/admission?updateMask.fieldPaths=allowedImageDigests" \
    -d "{\"fields\":{\"allowedImageDigests\":{\"arrayValue\":{\"values\":[{\"stringValue\":\"${CONFIG_DIGEST}\"}]}}}}" \
    > /tmp/agent-attest-policy.json
  if grep -q '"error"' /tmp/agent-attest-policy.json; then
    echo "   ERROR writing the admission policy:"
    cat /tmp/agent-attest-policy.json
    exit 1
  fi
  echo "   approved"

  echo "== booting the image locally to check it starts at all"
  if ! docker run --rm --platform linux/amd64 \
        -e AGENT="${AGENT}" -e SKIP_ATTESTATION=true \
        -e TARGET_PROJECT_ID="${PROJECT}" \
        -e GATEWAY_HOST=example.invalid \
        -e CONTROL_PLANE_URL=https://example.invalid \
        "${IMAGE}" > /tmp/agent-attest-smoke.log 2>&1 &
  then :; fi
  smoke_pid=$!
  sleep 25
  kill "${smoke_pid}" 2>/dev/null || true
  if grep -qE "Application startup complete|Uvicorn running" /tmp/agent-attest-smoke.log; then
    echo "   started cleanly"
  else
    echo "   ERROR: the container did not reach a running server. Last lines:"
    tail -25 /tmp/agent-attest-smoke.log | sed 's/^/     /'
    echo
    echo "   Full log: /tmp/agent-attest-smoke.log"
    echo "   Not launching a VM against an image that cannot start."
    exit 1
  fi
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
