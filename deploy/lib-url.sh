# Resolve the control plane's URL, and prove it actually answers.
#
# TWO TRAPS, BOTH OF WHICH COST TIME THE FIRST TIME
#
# 1. gcloud reports more than one hostname. `status.url` gave a legacy-format host that
#    does not route, while `gcloud run services list` gave the canonical one. Taking
#    either on faith is a coin flip, so both are tried.
#
# 2. A private Cloud Run service answers an unauthorised caller with 404, not 403. That
#    is deliberate on Google's part, so that private services do not leak their existence
#    by responding differently to "wrong URL" and "no access". It is also indistinguishable
#    from a genuinely wrong hostname, which is exactly the confusion it caused here: a
#    Ready service with RoutesReady true, returning a Google frontend 404 on every URL.
#
#    The fix for the caller is an ID token audienced to the SERVICE, not to gcloud. A
#    token from `gcloud auth print-identity-token` with no --audiences carries gcloud's
#    own client ID as its audience and Cloud Run rejects it.
#
# Everything downstream of this value fails closed, so a wrong URL here surfaces two hops
# later as "cannot attest" inside a VM, which points at the TEE rather than at the URL.
# Worth the care.
resolve_control_plane_url () {
  local service="${1:-agent-attest-control}" region="${2:-us-central1}" project="${3:-agent-attest-2026}"
  local candidates url code token

  # ORDER MATTERS, and must not be left to sort(1).
  #
  # `gcloud run services list` reports the hostname that actually routes. `describe`
  # can report a stale legacy host in status.url that resolves but 404s at the Google
  # frontend, and gcloud's own `run services proxy` uses that stale value, so even a
  # correctly authenticated proxy fails against it.
  #
  # An earlier version piped both through `sort -u`, which happened to put the right one
  # first only because a digit sorts before a letter. Deduplicate while preserving order
  # instead, so the correct URL is first by intent rather than by luck.
  candidates="$(
    {
      gcloud run services list --region="${region}" --project="${project}" \
        --filter="metadata.name=${service}" --format='value(status.url)' 2>/dev/null
      gcloud run services describe "${service}" --region="${region}" --project="${project}" \
        --format='value(status.url,status.urls)' 2>/dev/null | tr ';,\t' '\n'
    } | grep '^https://' | awk '!seen[$0]++'
  )"

  if [ -z "${candidates}" ]; then
    echo "No URL found for ${service} in ${region}. Is it deployed?" >&2
    return 1
  fi

  # An audience-scoped ID token is the only kind Cloud Run accepts, and
  # `gcloud auth print-identity-token --audiences=` REQUIRES a service account:
  # a user account is refused outright with "Invalid account type for --audiences".
  #
  # So when a human runs this, the health check cannot succeed even against a perfectly
  # good URL. Attempting it anyway and failing closed would block the deploy on a check
  # that is structurally impossible for the person running it, which is worse than not
  # checking. We probe when we can, and fall back to gcloud's canonical URL when we
  # cannot, saying which happened.
  for url in ${candidates}; do
    token="$(gcloud auth print-identity-token --audiences="${url}" 2>/dev/null || true)"
    if [ -z "${token}" ]; then
      continue
    fi
    code="$(curl -s -o /dev/null -w '%{http_code}' -m 10 \
             -H "Authorization: Bearer ${token}" "${url}/healthz" || true)"
    case "${code}" in
      200) echo "${url}"; return 0 ;;
      403) echo "   ${url} -> 403 (URL correct, caller lacks run.invoker)" >&2 ;;
      404) echo "   ${url} -> 404 (wrong host, OR correct host and unauthorised)" >&2 ;;
      *)   echo "   ${url} -> HTTP ${code}" >&2 ;;
    esac
  done

  # Fall back to the first candidate, which comes from `gcloud run services list` and is
  # the hostname gcloud itself considers canonical.
  url="$(echo "${candidates}" | head -n1)"
  cat >&2 <<HINT
   could not verify from this account (audience-scoped ID tokens need a service account)
   using gcloud's canonical URL unverified: ${url}
   to check it by hand:
     gcloud run services proxy ${service} --region=${region} --project=${project} --port=8080 &
     curl http://localhost:8080/healthz
HINT
  echo "${url}"
}
