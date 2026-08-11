#!/usr/bin/env bash
# Patch interfaces[].url on existing Agent Registry entries.
#
# The URL is written once, at admission. Agents admitted before PUBLIC_URL was wired
# carry http://localhost:8080, which is honest but wrong: the agent is reachable through
# the gateway, not on its own loopback. Re-admitting to fix a cosmetic field would mean
# revoking and re-approving, which is a much bigger hammer than the problem deserves.
set -euo pipefail
PROJECT="${PROJECT:-agent-attest-2026}"
REGION="${REGION:-us-central1}"
GATEWAY_HOST="${GATEWAY_HOST:-agents.agent-attest.internal}"

for AGENT in warden surveyor assessor executor; do
  URL="https://${AGENT}.${GATEWAY_HOST}"
  code=$(curl -s -o /tmp/aa-patch.json -w '%{http_code}' -X PATCH \
    -H "Authorization: Bearer $(gcloud auth print-access-token)" \
    -H "Content-Type: application/json" \
    "https://agentregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/services/${AGENT}?updateMask=interfaces" \
    -d "{\"interfaces\":[{\"url\":\"${URL}\",\"protocolBinding\":\"HTTP_JSON\"}]}")
  printf '%-10s -> %s  (HTTP %s)\n' "${AGENT}" "${URL}" "${code}"
done

echo
echo "Verify:"
echo "  curl -s -H \"Authorization: Bearer \$(gcloud auth print-access-token)\" \\"
echo "    https://agentregistry.googleapis.com/v1/projects/${PROJECT}/locations/${REGION}/services"
