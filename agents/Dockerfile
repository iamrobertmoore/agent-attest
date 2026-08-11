# One image, four agents. AGENT selects which at runtime, so all four share a digest
# and the demo can prove that swapping the image is what changes the measurement,
# rather than which agent happens to be running.
FROM python:3.12-slim

# NOT distroless:nonroot, and NOT a non-root USER. uid 65532 cannot open the root-owned
# Confidential Space launcher socket at /run/container_launcher/teeserver.sock, and the
# failure looks like a generic permission error three layers away from the cause.
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY . ./

# Without this label a production Confidential Space VM silently discards stdout.
# tee.launch_policy.log_redirect defaults to debugonly, and passing
# tee-container-log-redirect=true at launch does nothing unless the image carries it.
LABEL "tee.launch_policy.log_redirect"="always"
# The launch policy allowlist. An env var passed at launch that is NOT named here is
# refused by the launcher, which then kills the workload and logs "Workload completed",
# wording that reads like success. The real line is above it:
#   "env var {X} is not allowed to be overridden on this image"
#
# This is a security control, not a nuisance: it stops whoever creates the VM from
# altering the behaviour of an image someone else approved. Which is the same problem
# agent-attest exists to solve, one layer down, so it deserves respect rather than a
# wildcard.
#
# Vertex needs GOOGLE_CLOUD_PROJECT, GOOGLE_CLOUD_LOCATION and GOOGLE_GENAI_USE_VERTEXAI,
# so they are declared explicitly.
LABEL "tee.launch_policy.allow_env_override"="AGENT,PORT,PUBLIC_URL,CONTROL_PLANE_URL,GATEWAY_HOST,TARGET_PROJECT_ID,EXECUTOR_ARMED,MODEL,GOOGLE_CLOUD_PROJECT,GOOGLE_CLOUD_LOCATION,GOOGLE_GENAI_USE_VERTEXAI"

ENV PORT=8080
EXPOSE 8080
CMD ["python", "serve.py"]
