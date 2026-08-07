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
LABEL "tee.launch_policy.allow_env_override"="AGENT,PORT,PUBLIC_URL,CONTROL_PLANE_URL,GATEWAY_HOST,TARGET_PROJECT_ID,EXECUTOR_ARMED,MODEL"

ENV PORT=8080
EXPOSE 8080
CMD ["python", "serve.py"]
