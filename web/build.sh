#!/usr/bin/env bash
# Bundle the verifier for the browser and stage the sample fixture.
#
# The same source that runs in the Cloud Run control plane is bundled here unchanged.
# That is the point of the page: a judge recomputes the control plane's verdict with the
# control plane's own code, rather than a second implementation written to agree with it.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="${ROOT}/web/dist"

rm -rf "${OUT}" && mkdir -p "${OUT}/sample"
cp "${ROOT}/web/index.html" "${OUT}/index.html"
cp "${ROOT}/verifier/test/fixtures/live_attestation.jwt" "${OUT}/sample/"
cp "${ROOT}/verifier/test/fixtures/live_attestation.meta.json" "${OUT}/sample/"

cd "${ROOT}/verifier"
[ -d node_modules ] || npm install --no-audit --no-fund
npx esbuild src/index.ts --bundle --format=esm --minify \
  --outfile="${OUT}/verifier.js"

echo
ls -l "${OUT}/verifier.js"
echo "gzipped: $(gzip -c "${OUT}/verifier.js" | wc -c) bytes"
echo
cat <<NEXT

Serve it:
  cd ${OUT} && python3 -m http.server 3000

Then open http://localhost:3000 and click "Load the committed sample".

python3 rather than npx: it is already installed, needs no confirmation prompt, and logs
every request, which is what you want when a page looks blank.
NEXT
