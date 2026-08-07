# Workload image for capturing a real Confidential Space attestation token.
#
# The three LABELs below are launch policies read by the Confidential Space launcher.
# They are not decoration. Two of them are the difference between a working run and a
# VM that boots, does its job, stops, and leaves you nothing at all.

FROM golang:1.24-bookworm AS build
WORKDIR /src
COPY go.mod ./
COPY main.go ./
# No module dependencies on purpose: the container talks to the launcher socket, the
# metadata server and the storage JSON API over plain net/http. Fewer moving parts in
# the thing whose hash we are about to pin on-chain, and a smaller image to attest.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/capture-token .

# NOT :nonroot.
#
# The launcher exposes its attestation endpoint on a Unix socket at
# /run/container_launcher/teeserver.sock, and that socket is root-owned. A container
# running as uid 65532, which is what the :nonroot tag gives you, cannot open it:
#
#   dial unix /run/container_launcher/teeserver.sock: connect: permission denied
#
# Nothing in the Confidential Space documentation mentions this, and :nonroot is the
# tag you would reach for by habit. Google's own samples run as root.
#
# Running as root inside the workload is not the risk it would be elsewhere. The
# container is the whole of what the VM does, the machine is torn down after one run,
# and the isolation that matters here is the hardware boundary rather than the user
# boundary inside it.
FROM gcr.io/distroless/static-debian12

# THE ONE THAT COSTS YOU A RUN.
#
# tee.launch_policy.log_redirect defaults to "debugonly", meaning stdout and stderr are
# discarded on a production image. Combined with a production VM stopping the instant
# the workload exits, and a VM being impossible to re-run in place, forgetting this
# means creating a new instance to find out you learned nothing.
LABEL "tee.launch_policy.log_redirect"="always"

# tee-env-* metadata is silently ignored unless the variable is named here. Silently:
# no warning, no error, the variable simply is not set and the workload uses defaults.
LABEL "tee.launch_policy.allow_env_override"="ATTEST_AUDIENCE,ATTEST_NONCE,ATTEST_BUCKET"

# The launcher requires an ENTRYPOINT. An image with only CMD fails to start with a
# confusing message about Args being shorter than Cmd. This is enforced in the launcher
# and not mentioned in the documentation.
COPY --from=build /out/capture-token /capture-token
ENTRYPOINT ["/capture-token"]
