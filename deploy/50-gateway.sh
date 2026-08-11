#!/usr/bin/env bash
# Stand up Agent Gateway and bind the authorization extension.
#
# WHAT THIS IS FOR
# Without a gateway, "revoked" is a fact in a database. With one, a revoked agent is
# unreachable: Agent Gateway calls our extension before every request and refuses to route
# when the answer is no. That is the difference between bookkeeping and enforcement.
#
# WHY IT IS THE FIDDLY PART
# Agent Gateway custom extensions are not like ordinary Service Extensions. The docs
# require `service` to be an FQDN resolvable by Cloud DNS, on HTTP/2 with TLS on port 443,
# with the endpoints inside the VPC. A public Cloud Run URL is not the documented path.
# So the callout needs: a VPC, a proxy-only subnet, a serverless NEG, an internal
# Application Load Balancer, a certificate, and a private DNS zone pointing at it.
#
# The docs also note the extension "doesn't validate the server certificate", which is
# why VPC containment is doing the security work and a self-signed cert is acceptable
# here. That is worth knowing rather than assuming; it is the reason this is tractable.
#
# Every step is idempotent. Stop at the first failure and read it: this is the part of the
# build most likely to hit a permission or preview gate, and the error text is the signal.
set -euo pipefail

PROJECT="${PROJECT:-agent-attest-2026}"
REGION="${REGION:-us-central1}"
NET="${NET:-agent-attest-net}"
SUBNET="${SUBNET:-agent-attest-subnet}"
PROXY_SUBNET="${PROXY_SUBNET:-agent-attest-proxy-only}"
DNS_ZONE="${DNS_ZONE:-agent-attest-internal}"
DNS_NAME="${DNS_NAME:-agent-attest.internal.}"
AUTHZ_HOST="authz.agent-attest.internal"
REPO="${REPO:-agent-attest}"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/gateway-ext:latest"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

step () { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok ()   { echo "   $*"; }

step "APIs"
gcloud services enable --project="${PROJECT}" \
  networkservices.googleapis.com networksecurity.googleapis.com \
  compute.googleapis.com dns.googleapis.com certificatemanager.googleapis.com \
  agentregistry.googleapis.com modelarmor.googleapis.com 2>&1 | tail -1

step "VPC and subnets"
gcloud compute networks create "${NET}" --project="${PROJECT}" \
  --subnet-mode=custom 2>/dev/null || ok "network exists"
gcloud compute networks subnets create "${SUBNET}" --project="${PROJECT}" \
  --network="${NET}" --region="${REGION}" --range=10.10.0.0/24 2>/dev/null \
  || ok "subnet exists"
# The proxy-only subnet is required by every regional internal ALB in a region, and it is
# reserved for the load balancer's own proxies. It is not for workloads.
gcloud compute networks subnets create "${PROXY_SUBNET}" --project="${PROJECT}" \
  --network="${NET}" --region="${REGION}" --range=10.10.128.0/23 \
  --purpose=REGIONAL_MANAGED_PROXY --role=ACTIVE 2>/dev/null || ok "proxy subnet exists"

step "Deploy the authorization extension to Cloud Run"
docker build --platform linux/amd64 --provenance=false --sbom=false \
  -f "${ROOT}/gateway-ext/Dockerfile" -t "${IMAGE}" "${ROOT}/gateway-ext"
docker push "${IMAGE}"
CONTROL_PLANE_URL="https://agent-attest-control-$(gcloud projects describe "${PROJECT}" \
  --format='value(projectNumber)').${REGION}.run.app"
# h2c: the callout speaks plaintext gRPC and the load balancer in front terminates TLS.
gcloud run deploy agent-attest-authz \
  --project="${PROJECT}" --region="${REGION}" --image="${IMAGE}" \
  --service-account="agent-attest-authz@${PROJECT}.iam.gserviceaccount.com" \
  --allow-unauthenticated --use-http2 --port=8443 --min-instances=1 \
  --set-env-vars="CONTROL_PLANE_URL=${CONTROL_PLANE_URL}"

step "Serverless NEG and internal load balancer"
gcloud compute network-endpoint-groups create agent-attest-authz-neg \
  --project="${PROJECT}" --region="${REGION}" \
  --network-endpoint-type=serverless --cloud-run-service=agent-attest-authz 2>/dev/null \
  || ok "NEG exists"
gcloud compute backend-services create agent-attest-authz-be \
  --project="${PROJECT}" --region="${REGION}" \
  --load-balancing-scheme=INTERNAL_MANAGED --protocol=HTTP2 2>/dev/null || ok "backend exists"
gcloud compute backend-services add-backend agent-attest-authz-be \
  --project="${PROJECT}" --region="${REGION}" \
  --network-endpoint-group=agent-attest-authz-neg \
  --network-endpoint-group-region="${REGION}" 2>/dev/null || ok "backend attached"

step "Certificate for the internal ALB"
# Self-signed is acceptable BECAUSE the docs state the extension does not validate the
# server certificate, and the endpoint is confined to the VPC. Using a real cert here
# would imply a verification step that does not happen.
if ! gcloud compute ssl-certificates describe agent-attest-authz-cert \
     --project="${PROJECT}" --region="${REGION}" >/dev/null 2>&1; then
  TMP="$(mktemp -d)"
  openssl req -x509 -newkey rsa:2048 -nodes -days 365 \
    -keyout "${TMP}/k.pem" -out "${TMP}/c.pem" \
    -subj "/CN=${AUTHZ_HOST}" -addext "subjectAltName=DNS:${AUTHZ_HOST}" 2>/dev/null
  gcloud compute ssl-certificates create agent-attest-authz-cert \
    --project="${PROJECT}" --region="${REGION}" \
    --certificate="${TMP}/c.pem" --private-key="${TMP}/k.pem"
  rm -rf "${TMP}"
else ok "certificate exists"; fi

gcloud compute url-maps create agent-attest-authz-urlmap \
  --project="${PROJECT}" --region="${REGION}" \
  --default-service=agent-attest-authz-be 2>/dev/null || ok "url map exists"
gcloud compute target-https-proxies create agent-attest-authz-proxy \
  --project="${PROJECT}" --region="${REGION}" \
  --url-map=agent-attest-authz-urlmap \
  --ssl-certificates=agent-attest-authz-cert 2>/dev/null || ok "proxy exists"
gcloud compute forwarding-rules create agent-attest-authz-fr \
  --project="${PROJECT}" --region="${REGION}" \
  --load-balancing-scheme=INTERNAL_MANAGED --network="${NET}" --subnet="${SUBNET}" \
  --target-https-proxy=agent-attest-authz-proxy \
  --target-https-proxy-region="${REGION}" --ports=443 2>/dev/null || ok "forwarding rule exists"

ILB_IP="$(gcloud compute forwarding-rules describe agent-attest-authz-fr \
  --project="${PROJECT}" --region="${REGION}" --format='value(IPAddress)')"
ok "internal LB at ${ILB_IP}"

step "Private DNS"
gcloud dns managed-zones create "${DNS_ZONE}" --project="${PROJECT}" \
  --dns-name="${DNS_NAME}" --visibility=private --networks="${NET}" \
  --description="agent-attest internal" 2>/dev/null || ok "zone exists"
gcloud dns record-sets create "${AUTHZ_HOST}." --project="${PROJECT}" \
  --zone="${DNS_ZONE}" --type=A --ttl=60 --rrdatas="${ILB_IP}" 2>/dev/null \
  || gcloud dns record-sets update "${AUTHZ_HOST}." --project="${PROJECT}" \
     --zone="${DNS_ZONE}" --type=A --ttl=60 --rrdatas="${ILB_IP}"
ok "${AUTHZ_HOST} -> ${ILB_IP}"

step "Authorization extension"
cat > /tmp/authz-extension.yaml <<YAML
name: agent-attest-authz
service: ${AUTHZ_HOST}
failOpen: false
timeout: 1s
wireFormat: EXT_AUTHZ_GRPC
YAML
echo "   failOpen: false  (Google's own samples set this true; see docs/GATEWAY.md)"
gcloud beta service-extensions authz-extensions import agent-attest-authz \
  --project="${PROJECT}" --source=/tmp/authz-extension.yaml --location="${REGION}"

step "Agent Gateway"
# There is no `create` verb. `gcloud beta network-services agent-gateways` offers only
# delete, describe, export, import and list, so a gateway is created declaratively by
# importing a YAML document. Google's own docs show `create` in prose, which is how the
# earlier version of this script came to call a command that does not exist.
if gcloud beta network-services agent-gateways describe agent-attest-gw \
     --project="${PROJECT}" --location="${REGION}" >/dev/null 2>&1; then
  ok "gateway already exists"
else
  # Schema recovered from the import validator's own error output, which dumps the full
  # JSON schema. Top-level `network` / `subnetwork` are rejected (additionalProperties
  # false); the network lives under networkConfig, and `protocols` is required.
  #
  # NOTE THE ENUM: protocols accepts only MCP or PROTOCOL_UNSPECIFIED. There is no A2A
  # value. See docs/GATEWAY.md.
  cat > /tmp/agent-gateway.yaml <<YAML
name: agent-attest-gw
protocols:
  - MCP
googleManaged: {}
registries:
  - //agentregistry.googleapis.com/projects/${PROJECT}/locations/${REGION}
YAML
  echo "   importing (errors shown in full, on purpose)"
  gcloud beta network-services agent-gateways import agent-attest-gw \
    --project="${PROJECT}" --location="${REGION}" --source=/tmp/agent-gateway.yaml || {
      cat <<'HINT'

   Gateway import failed, so the policy binding below cannot work.

   Check the schema this gcloud build expects:
     gcloud beta network-services agent-gateways import --help
   And, if any gateway exists anywhere to copy the shape from:
     gcloud beta network-services agent-gateways export NAME --location=REGION

   If Agent Gateway cannot be created on this account, nothing else is wasted. The
   authzExtension is a real resource, and the decision it serves is POST /authorize on
   the control plane, which already works. See docs/GATEWAY.md.
HINT
      exit 1
    }
fi

step "Bind the policy to the gateway"
cat > /tmp/authz-policy.yaml <<YAML
name: agent-attest-policy
target:
  resources:
    - "projects/${PROJECT}/locations/${REGION}/agentGateways/agent-attest-gw"
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/${PROJECT}/locations/${REGION}/authzExtensions/agent-attest-authz"
YAML
echo "   policyProfile: REQUEST_AUTHZ  (CONTENT_AUTHZ cannot be made fail-closed)"

# A googleManaged gateway is provisioned asynchronously in a Google-run tenant project.
# The AgentGateway resource exists and is describable immediately, but binding a policy
# to it fails until that provisioning finishes:
#
#   "agent gateway ... is not yet provisioned in the tenant project"
#
# Resource created is not the same as resource ready, and nothing in the create response
# distinguishes the two. So retry rather than treat the first attempt as the answer.
bound=0
for attempt in $(seq 1 12); do
  if gcloud beta network-security authz-policies import agent-attest-policy \
       --project="${PROJECT}" --source=/tmp/authz-policy.yaml --location="${REGION}" 2>/tmp/aa-authz-err; then
    bound=1
    break
  fi
  if grep -q "not yet provisioned" /tmp/aa-authz-err; then
    echo "   tenant project still provisioning, waiting 60s (attempt ${attempt}/12)"
    sleep 60
  else
    echo "   binding failed for a reason other than provisioning:"
    cat /tmp/aa-authz-err
    exit 1
  fi
done
[ "${bound}" = "1" ] || { echo "   still not provisioned after 12 minutes; retry later"; exit 1; }
echo "   policy bound"

step "Done"
cat <<NEXT
Gateway:   projects/${PROJECT}/locations/${REGION}/agentGateways/agent-attest-gw
Extension: ${AUTHZ_HOST} -> ${ILB_IP} -> Cloud Run agent-attest-authz -> /authorize

Test the decision path directly, without the gateway:
  gcloud run services proxy agent-attest-control --region=${REGION} --project=${PROJECT} --port=8080 &
  curl -s -X POST localhost:8080/authorize -H 'content-type: application/json' \\
    -d '{"agentId":"surveyor"}'

A revoked agent returns allow:false with the reason. That is the exact payload the
extension turns into a gRPC PERMISSION_DENIED.
NEXT
