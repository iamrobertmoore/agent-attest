# Resolve the control plane's URL, and prove it actually answers.
#
# gcloud can report more than one hostname for a Cloud Run service, and not all of them
# route. Taking status.url on faith produced a Google edge 404 that looks exactly like an
# application 404 unless you notice the response is HTML. Everything downstream of this
# value fails closed, so a wrong URL here would surface as "attestation refused" three
# hops away and send us hunting in the wrong place entirely.
#
# So: try every hostname gcloud knows about, keep the first that answers, and fail loudly
# if none do.
resolve_control_plane_url () {
  local service="${1:-agent-attest-control}" region="${2:-us-central1}" project="${3:-agent-attest-2026}"
  local token candidates url code
  token="$(gcloud auth print-identity-token 2>/dev/null || true)"
  candidates="$(gcloud run services describe "${service}" --region="${region}" --project="${project}" \
      --format='value(status.url,status.urls)' 2>/dev/null | tr ';,\t' '\n' | grep '^https://' | sort -u)"

  for url in ${candidates}; do
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
             -H "Authorization: Bearer ${token}" "${url}/healthz" || true)"
    if [ "${code}" = "200" ]; then
      echo "${url}"
      return 0
    fi
    echo "   ${url} -> HTTP ${code}" >&2
  done

  echo "Could not find a working URL for ${service}. Tried:" >&2
  echo "${candidates}" >&2
  return 1
}
