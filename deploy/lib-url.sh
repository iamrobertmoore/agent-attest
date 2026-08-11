# Resolve the control plane's URL.
#
# THREE TRAPS, ALL OF WHICH COST TIME
#
# 1. A private Cloud Run service answers unauthorised callers with 404, not 403, so that
#    private services do not leak their existence. A wrong-URL failure and a no-access
#    failure are therefore indistinguishable from outside.
#
# 2. `status.url` can hold a stale legacy hostname that resolves but 404s at the Google
#    frontend. `gcloud run services list` DISPLAYS the routable hostname in its table,
#    but `--format='value(status.url)'` returns the stale one, so scripting the list
#    command does not help. `gcloud run services proxy` also reads status.url, which is
#    why even a correctly authenticated proxy can 404 against a healthy service.
#
# 3. `gcloud auth print-identity-token --audiences=` requires a service account and
#    refuses a user account outright, so a human cannot mint a token Cloud Run accepts.
#
# Rather than interrogate gcloud, construct the canonical hostname. Cloud Run's current
# format is deterministic: https://SERVICE-PROJECTNUMBER.REGION.run.app. Deriving it is
# more reliable than asking, because it cannot return a stale value.
resolve_control_plane_url () {
  local service="${1:-agent-attest-control}" region="${2:-us-central1}" project="${3:-agent-attest-2026}"
  local number url

  # An explicit override always wins, for the case where Google changes the format again.
  if [ -n "${CONTROL_PLANE_URL_OVERRIDE:-}" ]; then
    echo "${CONTROL_PLANE_URL_OVERRIDE}"
    return 0
  fi

  number="$(gcloud projects describe "${project}" --format='value(projectNumber)' 2>/dev/null)"
  if [ -z "${number}" ]; then
    echo "could not read the project number for ${project}" >&2
    return 1
  fi

  url="https://${service}-${number}.${region}.run.app"

  # Confirm the service exists at all. We cannot confirm it answers, because that needs
  # a token this account cannot mint; the agents authenticate from inside the VM via the
  # metadata server, which can.
  if ! gcloud run services describe "${service}" --region="${region}" --project="${project}" \
        --format='value(status.conditions[0].status)' 2>/dev/null | grep -q True; then
    echo "   warning: ${service} is not reporting Ready in ${region}" >&2
  fi

  echo "${url}"
}
