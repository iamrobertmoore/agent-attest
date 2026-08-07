#!/usr/bin/env bash
#
# Capture a real Google Confidential Space attestation token, end to end.
#
#   ./run.sh preflight    check the account is capable before spending anything
#   ./run.sh setup        APIs, service account, roles, registry, bucket
#   ./run.sh build        build and push the workload image
#   ./run.sh launch       create the Confidential Space VM
#   ./run.sh token        fetch the captured token
#   ./run.sh teardown     delete everything that costs money
#
# Run them in that order. `preflight` is not optional: it catches the two account-level
# problems that cannot be fixed once you are mid-run.
#
# Cost is a few pence. An n2d-standard-2 is about $0.09/hour and the VM lives for
# minutes. `teardown` removes it.

set -euo pipefail

PROJECT="${ATTEST_PROJECT:-}"
ZONE="${ATTEST_ZONE:-us-central1-a}"
REGION="${ZONE%-*}"
SA_NAME="agent-attest-tee"
REPO="agent-attest"
IMAGE="capture-token"
VM="agent-attest-attest"
BUCKET="${ATTEST_BUCKET:-}"

die() { echo "ERROR: $*" >&2; exit 1; }
say() { printf '\n\033[1m%s\033[0m\n' "$*"; }

# macOS does not ship GNU `timeout`. It is `gtimeout` if you have coreutils from
# Homebrew, and absent otherwise. An earlier version assumed `timeout` existed, so on a
# Mac every wrapped call died with "command not found" and the checks reported "unknown"
# rather than failing visibly. Worse than no check at all, because it looked like it ran.
#
# Detect once. If neither is available, run the command directly: --quiet is what
# actually prevents the hang, and the timeout was only ever a second line of defence.
if command -v timeout >/dev/null 2>&1; then
  TIMEOUT_CMD="timeout"
elif command -v gtimeout >/dev/null 2>&1; then
  TIMEOUT_CMD="gtimeout"
else
  TIMEOUT_CMD=""
fi

# _t <seconds> <command...>
_t() {
  local secs="$1"; shift
  if [ -n "$TIMEOUT_CMD" ]; then
    "$TIMEOUT_CMD" "$secs" "$@"
  else
    "$@"
  fi
}

# Every gcloud call goes through here. --quiet answers the invisible install prompts
# that made this hang in the first place.
gc() { _t 90 gcloud --quiet "$@"; }

[ -n "$PROJECT" ] || die "set ATTEST_PROJECT to your GCP project id"
case "$PROJECT" in
  your-project-id|your-actual-project-id|YOUR_PROJECT_ID|PROJECT_ID)
    die "ATTEST_PROJECT is still the placeholder text: '$PROJECT'

       Use your real project id. Find it on the Project info card at
       https://console.cloud.google.com/home/dashboard
       It usually has digits appended, like agent-attest-504509.

         export ATTEST_PROJECT=agent-attest-504509" ;;
esac
SA="${SA_NAME}@${PROJECT}.iam.gserviceaccount.com"
[ -n "$BUCKET" ] || BUCKET="${PROJECT}-agent-attest-tokens"
IMAGE_URI="${REGION}-docker.pkg.dev/${PROJECT}/${REPO}/${IMAGE}:latest"

# ---------------------------------------------------------------- preflight

preflight() {
  NEEDS_SETUP=0
  QUOTA_BAD=0
  say "1. Billing account type"
  local ba
  # `gcloud beta` needs the beta component. If it is missing, gcloud prompts to install
  # it, so check up front and say so rather than appearing to freeze.
  if ! gcloud beta --help >/dev/null 2>&1; then
    echo "   the gcloud 'beta' component is not installed, so I cannot read the billing"
    echo "   account automatically. Install it with:"
    echo "       gcloud components install beta"
    echo "   or just check by eye at https://console.cloud.google.com/billing"
    ba=""
  else
    ba=$(gc beta billing projects describe "$PROJECT" \
          --format='value(billingAccountName)' 2>/dev/null || true)
  fi
  if [ -z "$ba" ]; then
    echo "   could not confirm a billing account for $PROJECT."
    echo "   Check at https://console.cloud.google.com/billing/linkedaccount?project=$PROJECT"
    echo "   Continuing, since the later steps will fail clearly if it really is missing."
    ba="unknown"
  fi
  if [ "$ba" != "unknown" ]; then
    local open masked
    open=$(gc beta billing accounts describe "${ba##*/}" --format='value(open)' 2>/dev/null || echo "")
    masked=$(gc beta billing accounts describe "${ba##*/}" --format='value(displayName)' 2>/dev/null || echo "?")
    echo "   linked to: $masked (open=$open)"
  fi
  cat <<'NOTE'
   NOTE: gcloud does not expose "is this a Free Trial account" directly. Check in the
   console at Billing > Overview. If it says "Free trial", upgrade before going further:
   a Free Trial account CANNOT request quota increases, and if N2D quota in your region
   is zero there is no way through except upgrading. Upgrading keeps your remaining
   credit and is not itself a charge.
NOTE

  say "2. N2D CPU quota in $REGION"
  # N2D_CPUS is its own pool, separate from CPUS. Having general CPU headroom tells you
  # nothing about whether an N2D instance will start.
  #
  # Asked for as JSON and parsed here, rather than with a gcloud projection. The
  # projection syntax I tried first was invalid, and gcloud reports that by printing an
  # error to stdout, which my code then treated as the quota value and declared OK. A
  # check that turns its own failure into a pass is worse than no check.
  local quota_json n2d
  quota_json=$(gc compute regions describe "$REGION" --project "$PROJECT" --format=json 2>&1) || true

  if printf '%s' "$quota_json" | grep -qi "has not been used\|is disabled\|SERVICE_DISABLED"; then
    echo "   cannot read it yet: the Compute Engine API is not enabled on this project."
    echo "   That is expected on a new project. './run.sh setup' turns it on, then"
    echo "   re-run preflight to see the real number."
    NEEDS_SETUP=1
  else
    n2d=$(printf '%s' "$quota_json" | python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
for q in d.get("quotas", []):
    if q.get("metric") == "N2D_CPUS":
        print(int(q.get("limit", 0)), int(q.get("usage", 0)))
        break
' 2>/dev/null || true)

    if [ -z "$n2d" ]; then
      echo "   could not read the quota. Check by eye at"
      echo "   https://console.cloud.google.com/iam-admin/quotas?project=$PROJECT"
      echo "   filter for N2D_CPUS. You need a limit of at least 2 in $REGION."
    else
      local limit used free
      limit=$(printf '%s' "$n2d" | cut -d' ' -f1)
      used=$(printf '%s' "$n2d" | cut -d' ' -f2)
      free=$(( limit - used ))
      echo "   N2D_CPUS limit $limit, in use $used, free $free"
      if [ "$free" -lt 2 ]; then
        echo "   NOT ENOUGH. You need 2 free."
        echo "   Request an increase at https://console.cloud.google.com/iam-admin/quotas?project=$PROJECT"
        echo "   (filter N2D_CPUS, tick $REGION, Edit Quotas, ask for 8), or try another"
        echo "   region with: export ATTEST_ZONE=us-west1-b"
        QUOTA_BAD=1
      else
        echo "   enough to launch"
      fi
    fi
  fi

  say "3. Confidential Space image family is reachable"
  gc compute images describe-from-family confidential-space \
    --project confidential-space-images --format='value(name)' \
    || echo "   could not read it. Usually means the Compute Engine API is not on yet; 'setup' enables it."

  say "4. A network exists in $PROJECT"
  if ! gc compute networks describe default --project "$PROJECT" >/dev/null 2>&1; then
    echo "   no 'default' network. A fresh project has none until Compute Engine is"
    echo "   enabled. 'setup' will create one."
  else
    echo "   default network present"
  fi

  say "Preflight finished"
  echo "Project: $PROJECT   Zone: $ZONE"
  if [ -n "$TIMEOUT_CMD" ]; then
    echo "Timeout helper: $TIMEOUT_CMD"
  else
    echo "Timeout helper: none installed, running gcloud without one. Fine."
  fi
  if [ "${NEEDS_SETUP:-0}" = "1" ]; then
    echo
    echo "Several checks could not run because the Compute Engine API is off, which is"
    echo "normal for a new project. Do this:"
    echo "    ./run.sh setup        # enables the APIs"
    echo "    ./run.sh preflight    # now the quota numbers are real"
  elif [ "${QUOTA_BAD:-0}" = "1" ]; then
    echo
    echo "Sort the N2D quota out before launching. Everything else looks fine."
  else
    echo
    echo "All clear. Next:  ./run.sh build"
  fi
}

# ---------------------------------------------------------------- setup

setup() {
  say "Enabling APIs"
  _t 300 gcloud --quiet services enable \
    compute.googleapis.com \
    confidentialcomputing.googleapis.com \
    artifactregistry.googleapis.com \
    storage.googleapis.com \
    logging.googleapis.com \
    --project "$PROJECT"

  if ! gc compute networks describe default --project "$PROJECT" >/dev/null 2>&1; then
    say "Creating the default network"
    gc compute networks create default --subnet-mode=auto --project "$PROJECT"
  fi

  say "Service account"
  gc iam service-accounts create "$SA_NAME" \
    --display-name="agent-attest Confidential Space workload" \
    --project "$PROJECT" 2>/dev/null || echo "   already exists"

  say "Roles"
  # workloadUser: lets the workload ask for an attestation token at all.
  # logWriter:    without it, log redirect produces nothing even with the image label.
  # artifactregistry.reader: lets the VM pull the workload image.
  for role in \
    roles/confidentialcomputing.workloadUser \
    roles/logging.logWriter \
    roles/artifactregistry.reader
  do
    gc projects add-iam-policy-binding "$PROJECT" \
      --member="serviceAccount:${SA}" --role="$role" \
      --condition=None >/dev/null
    echo "   $role"
  done

  say "Artifact Registry"
  gc artifacts repositories create "$REPO" \
    --repository-format=docker --location="$REGION" \
    --description="agent-attest attestation workload" \
    --project "$PROJECT" 2>/dev/null || echo "   already exists"

  say "Bucket for the captured token"
  gc storage buckets create "gs://${BUCKET}" \
    --location="$REGION" --project "$PROJECT" 2>/dev/null || echo "   already exists"
  gc storage buckets add-iam-policy-binding "gs://${BUCKET}" \
    --member="serviceAccount:${SA}" --role=roles/storage.objectAdmin >/dev/null
  echo "   ${SA} can write to it"

  say "Setup done. Image will be $IMAGE_URI"
}

# ---------------------------------------------------------------- build

build() {
  say "Building and pushing $IMAGE_URI"
  gcloud --quiet auth configure-docker "${REGION}-docker.pkg.dev"
  # --provenance=false --sbom=false matter here.
  #
  # buildx attaches a provenance attestation by default, which turns the result into a
  # multi-manifest index rather than a plain image. The build log gives it away:
  # "exporting attestation manifest" followed by "exporting manifest list". The
  # Confidential Space launcher wants a single-platform image and can fail to resolve
  # an index, in a way that produces no useful error.
  docker build --platform linux/amd64 --provenance=false --sbom=false -t "$IMAGE_URI" .
  docker push "$IMAGE_URI"

  say "Confirming the image is a plain single-platform image"
  local mediatype
  mediatype=$(docker manifest inspect "$IMAGE_URI" 2>/dev/null \
    | python3 -c 'import json,sys; print(json.load(sys.stdin).get("mediaType","?"))' 2>/dev/null || echo "?")
  echo "   mediaType: $mediatype"
  case "$mediatype" in
    *manifest.list*|*image.index*)
      echo "   WARNING: this is a manifest list, not a single image. Confidential Space"
      echo "   may not resolve it. Rebuild with --provenance=false --sbom=false." ;;
    *) echo "   single image, good" ;;
  esac

  say "Confirming the launch policy labels survived the build"
  # Worth checking rather than assuming. A missing log_redirect label is invisible
  # until the run has already failed.
  local labels
  labels=$(docker inspect "$IMAGE_URI" --format '{{json .Config.Labels}}')
  echo "   $labels"
  case "$labels" in
    *log_redirect*) echo "   log_redirect present" ;;
    *) die "log_redirect label missing. Production VM would produce no output." ;;
  esac
}

# ---------------------------------------------------------------- launch

launch() {
  local nonce="${ATTEST_NONCE:-}"
  if [ -z "$nonce" ]; then
    # 32 random bytes, base64url, no padding. 43 characters, inside the 10 to 74 the
    # docs allow. Google's own pages disagree on that range, so we sit in the
    # intersection of the two.
    nonce=$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')
  fi
  echo "$nonce" > .last-nonce
  say "Nonce for this run: $nonce   (saved to .last-nonce)"

  # Capacity for a given machine type is per zone and moves around during the day.
  # ZONE_RESOURCE_POOL_EXHAUSTED is not a configuration problem and not something you
  # can fix by waiting at the keyboard, so try elsewhere rather than stopping.
  #
  # Zones listed here all support N2D with AMD SEV. The ones in your configured region
  # come first, because N2D quota is granted per region and you already have it there.
  # Crossing into another region needs quota there too, which usually exists by default
  # but is worth knowing if the later ones also fail.
  local zones="$ZONE"
  local base_region="${ZONE%-*}"
  for z in "${base_region}-a" "${base_region}-b" "${base_region}-c" "${base_region}-f" \
           us-west1-b us-east1-c us-east4-b europe-west1-b europe-west4-a; do
    case " $zones " in *" $z "*) ;; *) zones="$zones $z" ;; esac
  done

  local attempt=0 launched=0
  for z in $zones; do
    attempt=$((attempt + 1))
    say "Attempt $attempt: creating the VM in $z"

    gc compute instances delete "$VM" --zone "$z" --project "$PROJECT" 2>/dev/null || true

    # --image-family=confidential-space, NOT confidential-space-debug. The debug image
    # reports dbgstat "enabled", which our verifier rejects, and rejecting it is right:
    # on a debug image an operator can attach and read the workload's memory.
    if _t 300 gcloud --quiet compute instances create "$VM" \
      --project "$PROJECT" \
      --zone "$z" \
      --machine-type="${ATTEST_MACHINE:-n2d-standard-2}" \
      --confidential-compute-type=SEV \
      --min-cpu-platform="AMD Milan" \
      --maintenance-policy=MIGRATE \
      --shielded-secure-boot \
      --scopes=cloud-platform \
      --service-account="$SA" \
      --image-project=confidential-space-images \
      --image-family=confidential-space \
      --metadata="^~^tee-image-reference=${IMAGE_URI}~tee-container-log-redirect=true~tee-restart-policy=Never~tee-env-ATTEST_BUCKET=${BUCKET}~tee-env-ATTEST_NONCE=${nonce}~tee-env-ATTEST_AUDIENCE=agent-attest-demo" 2>&1 | tee /tmp/agent-attest-launch.log
    then
      echo "$z" > .last-zone
      launched=1
      say "Created in $z"
      break
    fi

    if grep -q "ZONE_RESOURCE_POOL_EXHAUSTED\|does not have enough resources" /tmp/agent-attest-launch.log; then
      echo "   no capacity in $z right now. Trying the next zone."
      continue
    fi
    if grep -qi "Quota .*exceeded\|QUOTA_EXCEEDED" /tmp/agent-attest-launch.log; then
      echo "   quota problem in ${z%-*}. You have N2D quota in $base_region but perhaps"
      echo "   not here. Trying the next zone."
      continue
    fi
    # Anything else is a real error and retrying elsewhere will not help.
    die "creation failed for a reason that is not capacity or quota. See the output above."
  done

  if [ "$launched" != "1" ]; then
    die "every zone we tried was out of n2d-standard-2 capacity.

       This happens, and it passes. Options:
         - wait 20 minutes and run ./run.sh launch again
         - try a machine type with more spare capacity:
             ATTEST_MACHINE=n2d-standard-4 ./run.sh launch
         - pick a zone by hand:
             ATTEST_ZONE=europe-west4-b ./run.sh launch"
  fi

  say "The workload takes a couple of minutes to pull and run"
  echo "Watch it:"
  echo "  gcloud logging read 'logName:confidential-space-launcher' --project $PROJECT --limit 40 --freshness=10m"
  echo
  echo "Then: ./run.sh token"
}

# ---------------------------------------------------------------- logs

logs() {
  local z="$ZONE"
  [ -f .last-zone ] && z=$(cat .last-zone)

  say "Instance status"
  gc compute instances describe "$VM" --zone "$z" --project "$PROJECT" \
    --format="value(name,status,machineType.basename(),zone.basename())" 2>/dev/null \
    || echo "   no instance called $VM in $z. It may have finished and stopped, which is normal."

  say "Launcher logs (noise filtered, newest last)"
  # Read newest-first and reverse for display.
  #
  # Reading oldest-first with a limit filled the whole window with launcher startup
  # chatter: three hundred protobuf registration warnings, all on the same timestamp,
  # emitted before the workload runs at all. The interesting part is always the end of
  # the run, so take the end.
  #
  # The protobuf warnings are a known quirk of the launcher's own dependencies and say
  # nothing about your workload, so they are filtered out. Everything else is kept.
  _t 120 gcloud --quiet logging read \
    'logName:confidential-space-launcher' \
    --project "$PROJECT" --limit 400 --freshness=6h \
    --order=desc --format=json 2>/dev/null \
  | python3 -c '
import json, sys

NOISE = (
    "WARNING: proto:",
    "previously from:",
    "currently from:",
    "See https://protobuf.dev",
)

try:
    entries = json.load(sys.stdin)
except Exception:
    print("   could not parse the log response")
    sys.exit(0)

if not entries:
    print("   no launcher entries. The VM may not have reached the workload.")
    sys.exit(0)

lines, dropped = [], 0
for e in reversed(entries):          # newest-first in, oldest-first out
    ts = (e.get("timestamp") or "")[11:19]
    msg = e.get("textPayload")
    if msg is None:
        jp = e.get("jsonPayload") or {}
        msg = jp.get("MESSAGE") or jp.get("message") or json.dumps(jp)
    for line in str(msg).rstrip().split(chr(10)):
        if any(n in line for n in NOISE):
            dropped += 1
            continue
        lines.append("   %s  %s" % (ts, line))

if dropped:
    print("   (%d lines of launcher protobuf warnings hidden)" % dropped)
if not lines:
    print("   nothing but startup noise. The workload produced no output at all,")
    print("   which usually means the image failed to start rather than failed to run.")
for line in lines[-120:]:
    print(line)
' || echo "   could not read logs"

  say "Serial console, last 60 lines"
  # Useful when the launcher logged nothing, because boot problems show up here even
  # when the workload never ran.
  local serial
  serial=$(gc compute instances get-serial-port-output "$VM" --zone "$z" --project "$PROJECT" 2>&1) || true
  if printf '%s' "$serial" | grep -qi "ERROR\|not found\|was not found"; then
    echo "   could not read it:"
    printf '%s\n' "$serial" | head -4 | sed 's/^/     /'
  else
    printf '%s\n' "$serial" | tail -60 | sed 's/^/   /'
  fi

  say "Bucket contents"
  local listing
  listing=$(gc storage ls "gs://${BUCKET}/" 2>&1 || true)
  if [ -z "$listing" ]; then
    echo "   empty. The workload either never ran, or could not write."
    echo "   Its write uses the VM service account, which needs storage.objectAdmin on"
    echo "   the bucket. Check with:"
    echo "     gcloud storage buckets get-iam-policy gs://${BUCKET} --project $PROJECT"
  else
    printf '%s\n' "$listing" | sed 's/^/   /'
  fi
}

# ---------------------------------------------------------------- token

token() {
  say "Looking in gs://${BUCKET}/token.jwt"
  if gcloud storage cp "gs://${BUCKET}/token.jwt" ./token.jwt --project "$PROJECT" 2>/dev/null; then
    echo "   saved to ./token.jwt ($(wc -c < ./token.jwt) bytes)"
    gc storage cat "gs://${BUCKET}/token.meta.txt" --project "$PROJECT" 2>/dev/null || true
  else
    echo "   not there yet. Falling back to Cloud Logging."
    # Same payload-shape problem as the logs command had: these entries carry
    # jsonPayload, so a textPayload projection returns blank lines and the token
    # appears to be missing when it is actually right there.
    _t 120 gcloud --quiet logging read 'logName:confidential-space-launcher' \
      --project "$PROJECT" --limit 400 --freshness=2h --order=desc --format=json 2>/dev/null \
    | python3 -c '
import json, sys
try:
    entries = json.load(sys.stdin)
except Exception:
    sys.exit(0)
out, capture = [], False
for e in reversed(entries):
    msg = e.get("textPayload")
    if msg is None:
        jp = e.get("jsonPayload") or {}
        msg = jp.get("MESSAGE") or jp.get("message") or ""
    for line in str(msg).split(chr(10)):
        line = line.strip()
        if "ATTEST-TOKEN-BEGIN" in line:
            capture = True; continue
        if "ATTEST-TOKEN-END" in line:
            capture = False; continue
        if capture and line:
            out.append(line)
sys.stdout.write("".join(out))
' > ./token.jwt
    if [ -s ./token.jwt ]; then
      echo "   recovered from logs, saved to ./token.jwt"
    else
      rm -f ./token.jwt
      die "no token yet. Give it another minute, then check the launcher logs."
    fi
  fi

  say "What the token says"
  python3 - <<'PY'
import base64, json
tok = open("token.jwt").read().strip()
h, p, _ = tok.split(".")
d = lambda s: json.loads(base64.urlsafe_b64decode(s + "=" * (-len(s) % 4)))
H, P = d(h), d(p)
print(f"  alg      {H.get('alg')}")
print(f"  x5c      {len(H.get('x5c', []))} certificates" if H.get("x5c") else "  x5c      MISSING, this is an OIDC token not a PKI one")
print(f"  hwmodel  {P.get('hwmodel')}")
print(f"  swname   {P.get('swname')}")
print(f"  dbgstat  {P.get('dbgstat')}")
print(f"  secboot  {P.get('secboot')}")
print(f"  nonce    {P.get('eat_nonce')}")
print(f"  image_id {P.get('submods',{}).get('container',{}).get('image_id')}")
PY

  cat <<'NEXT'

Next:
  1. Paste ./token.jwt into the agent-attest page.
  2. Set the nonce field to the value in .last-nonce.
  3. Put the image_id above in the allowed image IDs field.
  4. To get the on-chain check green too, register that image_id as a code hash on
     your own the registry extension. Until then registry.codeHash will fail, correctly.
  5. ./run.sh teardown
NEXT
}

# ---------------------------------------------------------------- teardown

teardown() {
  # Sweep every zone rather than trusting .last-zone.
  #
  # An interrupted launch can leave an instance behind in a zone the script never got
  # round to recording, and an instance you have forgotten about is the only way this
  # exercise costs real money. Ask the API where it actually is.
  say "Looking for any instance called $VM, anywhere in the project"
  local found
  found=$(gc compute instances list --project "$PROJECT" \
            --filter="name=($VM)" --format="value(name,zone.basename(),status)" 2>/dev/null || true)

  if [ -z "$found" ]; then
    echo "   none found. Nothing is running."
  else
    printf '%s\n' "$found" | sed 's/^/   /'
    printf '%s\n' "$found" | while read -r name zone status; do
      [ -n "$zone" ] || continue
      echo
      echo "   deleting $name in $zone"
      gc compute instances delete "$name" --zone "$zone" --project "$PROJECT" 2>&1 \
        | sed 's/^/     /' || echo "     could not delete, remove it by hand"
    done
  fi

  rm -f .last-zone

  say "Confirming"
  local left
  left=$(gc compute instances list --project "$PROJECT" --filter="name=($VM)" \
           --format="value(name)" 2>/dev/null || true)
  if [ -z "$left" ]; then
    echo "   nothing left running. You are not being billed for compute."
  else
    echo "   still there: $left"
    echo "   delete by hand at https://console.cloud.google.com/compute/instances?project=$PROJECT"
  fi

  echo
  echo "Left in place, costing approximately nothing:"
  echo "  the Artifact Registry image, the token bucket, the service account."
  echo "  Your captured token is safe in gs://${BUCKET}/token.jwt and in ./token.jwt"
}

case "${1:-}" in
  preflight) preflight ;;
  logs)      logs ;;
  setup)     setup ;;
  build)     build ;;
  launch)    launch ;;
  token)     token ;;
  teardown)  teardown ;;
  *) sed -n '2,20p' "$0" | sed 's/^# \?//' ;;
esac
