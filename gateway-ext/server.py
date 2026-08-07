"""
Agent Gateway authorization extension.

A protocol adapter and nothing else. It speaks Envoy's ext_authz v3 to the gateway,
turns a CheckRequest into an agent id, asks the control plane, and turns the answer
back into an ALLOW or a DENY. It holds no policy.

WHY PYTHON, IN AN OTHERWISE TYPESCRIPT REPO
-------------------------------------------
Google ships callout SDKs for Python, Go and Java, and only the Python one implements
ext_authz (`AuthorizationServicer`); the Go and Java SDKs are ext_proc only. There is no
Node SDK. Hand-rolling the proto generation, H2C and health-check plumbing in Node for a
fail-closed security control on a deadline is the kind of decision that looks clever for
two days and then costs a week.

So the language boundary follows the SDK boundary, and the decision stays in one place
behind /authorize rather than being reimplemented here. Two implementations of "is this
agent allowed" would eventually disagree, and the day they disagreed is the day one of
them would be wrong in the permissive direction.

WIRE FORMAT
-----------
envoy.service.auth.v3.Authorization/Check, selected with wireFormat: EXT_AUTHZ_GRPC on
the AuthzExtension. That is regional-only, which suits us: everything here lives in one
region on purpose.

POLICY PROFILE: REQUEST_AUTHZ, DELIBERATELY
-------------------------------------------
Not CONTENT_AUTHZ. Google's docs state that under CONTENT_AUTHZ with
FULL_DUPLEX_STREAMED, "the proxy fail-opens up to the first chunk of body data being
processed" and that connection and header failures fail open REGARDLESS of the failOpen
setting. Only REQUEST_AUTHZ gives a clean fail-closed guarantee, and a fail-closed
guarantee is the entire product here. We do not need to inspect bodies, so there is
nothing to trade away.

See docs/GATEWAY.md for the failOpen finding, which is worth reading before copying any
sample config from Google's documentation.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.error
import urllib.request
from concurrent import futures
from typing import Optional

import grpc
from envoy.service.auth.v3 import external_auth_pb2, external_auth_pb2_grpc
from envoy.type.v3 import http_status_pb2
from google.rpc import code_pb2, status_pb2

CONTROL_PLANE_URL = os.environ["CONTROL_PLANE_URL"].rstrip("/")
LISTEN_PORT = int(os.environ.get("PORT", "8443"))
# The AuthzExtension timeout must be 10..10000ms. Ours is set to 1s, so the upstream
# call gets 800ms and we still have room to answer rather than being cut off mid-flight.
CONTROL_PLANE_TIMEOUT_SEC = float(os.environ.get("CONTROL_PLANE_TIMEOUT_SEC", "0.8"))

log = logging.getLogger("authz")


def _headers(req: external_auth_pb2.CheckRequest) -> dict[str, str]:
    """Envoy puts the useful value in raw_value; the `value` field is ignored."""
    out: dict[str, str] = {}
    for k, v in req.attributes.request.http.headers.items():
        out[k.lower()] = v
    hm = req.attributes.request.http.header_map
    for h in hm.headers:
        raw = h.raw_value.decode("utf-8", "replace") if h.raw_value else h.value
        out[h.key.lower()] = raw
    return out


def target_agent_id(req: external_auth_pb2.CheckRequest) -> Optional[str]:
    """
    Work out which agent is being called.

    There is no documented field carrying the target's Agent Registry resource name.
    Google's attributes give the caller's identity richly (connection.client_cert_spiffe_id)
    and the target only through routing: host, path, backend_service_name. So the mapping
    from route to agent is ours to define, and it is defined here rather than inferred
    in three places.

    Convention: each agent is fronted by a host of the form <agentId>.<suffix>, so the
    first label of :authority is the agent id. An explicit x-agent-attest-agent header
    wins when present, which is what makes the thing testable with curl.

    Stated as a known limitation rather than hidden: if Google later surfaces the target
    resource name as an attribute, this function is the single place that changes.
    """
    hdrs = _headers(req)
    explicit = hdrs.get("x-agent-attest-agent")
    if explicit:
        return explicit.strip()

    authority = hdrs.get(":authority") or req.attributes.request.http.host
    if not authority:
        return None
    host = authority.split(":")[0]
    label = host.split(".")[0].strip()
    return label or None


def caller_spiffe_id(req: external_auth_pb2.CheckRequest) -> Optional[str]:
    """
    The calling agent's mTLS identity, as Agent Gateway sees it.

    Logged rather than enforced on. It is the right identifier for "which agent made this
    hop", and pairing it with the target's admission state is what makes an inter-agent
    audit trail reconstructable. It proves where the caller runs, not what code it runs,
    which is the whole reason this extension exists.
    """
    return req.attributes.source.principal or None


def _allow() -> external_auth_pb2.CheckResponse:
    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(code=code_pb2.OK),
        ok_response=external_auth_pb2.OkHttpResponse(),
    )


def _deny(reason: str, detail: str) -> external_auth_pb2.CheckResponse:
    body = json.dumps({"error": "not_admitted", "reason": reason, "detail": detail})
    return external_auth_pb2.CheckResponse(
        status=status_pb2.Status(code=code_pb2.PERMISSION_DENIED),
        denied_response=external_auth_pb2.DeniedHttpResponse(
            status=http_status_pb2.HttpStatus(code=http_status_pb2.Forbidden),
            body=body,
        ),
    )


class Authorization(external_auth_pb2_grpc.AuthorizationServicer):
    def Check(self, request, context):  # noqa: N802 - name fixed by the proto
        agent_id = target_agent_id(request)
        caller = caller_spiffe_id(request)

        if not agent_id:
            # Cannot identify the target, so cannot establish that it was admitted.
            # Deny. An unidentifiable target is not a reason to relax.
            log.warning("deny: could not derive target agent id (caller=%s)", caller)
            return _deny(
                "unidentifiable_target",
                "Could not determine which agent this request is addressed to.",
            )

        try:
            req = urllib.request.Request(
                f"{CONTROL_PLANE_URL}/authorize",
                data=json.dumps({"agentId": agent_id}).encode(),
                headers={"content-type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=CONTROL_PLANE_TIMEOUT_SEC) as resp:
                decision = json.loads(resp.read())
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as e:
            # FAIL CLOSED. An authorization extension that permits traffic when it cannot
            # reach its policy store can be switched off by attacking the policy store.
            # This is also why failOpen must be false on the AuthzExtension: this branch
            # only runs if we are reachable and the control plane is not.
            log.error("deny: control plane unreachable for %s: %s", agent_id, e)
            return _deny("control_plane_unreachable", f"Policy lookup failed: {e}")

        if decision.get("allow") is True:
            log.info(
                "allow: %s (%s) caller=%s", agent_id, decision.get("detail", ""), caller
            )
            return _allow()

        log.warning(
            "deny: %s reason=%s detail=%s caller=%s",
            agent_id,
            decision.get("reason"),
            decision.get("detail"),
            caller,
        )
        return _deny(str(decision.get("reason", "denied")), str(decision.get("detail", "")))


def serve() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    server = grpc.server(futures.ThreadPoolExecutor(max_workers=16))
    external_auth_pb2_grpc.add_AuthorizationServicer_to_server(Authorization(), server)

    # Cloud Run terminates TLS itself and requires a plaintext h2c listener, so no
    # credentials here. Behind an internal ALB with the FQDN path that Agent Gateway
    # documents, this must instead be add_secure_port with a real certificate: the docs
    # say "Without TLS, connections to the extension server fail". See docs/GATEWAY.md.
    server.add_insecure_port(f"0.0.0.0:{LISTEN_PORT}")
    server.start()
    log.info("authz extension listening on %s -> %s", LISTEN_PORT, CONTROL_PLANE_URL)
    server.wait_for_termination()


if __name__ == "__main__":
    serve()
