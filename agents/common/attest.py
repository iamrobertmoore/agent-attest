"""
The half of agent-attest that lives inside the agent.

Every agent in the fleet runs this. It does two things: applies for admission once at
startup, and then proves on a heartbeat that it is still running the code it was admitted
under. Everything else in the system, up to and including the gateway's per-request
decision, is downstream of these two calls actually happening.

HOW A WORKLOAD GETS ITS OWN ATTESTATION
---------------------------------------
Confidential Space runs a launcher alongside the workload and exposes it on a Unix socket
inside the VM. POST to it and the TEE mints a token describing the machine and the exact
image running on it. The workload cannot lie in that token: it does not sign it, the
platform does, and the claims come from measurements the workload has no access to.

Two things this file inherits from six rounds of debugging on the capture tooling:

  1. `token_type: "PKI"` is not optional. Without it you get the OIDC variant, which has a
     `kid` and no `x5c` and can only be checked by fetching Google's JWKS over the
     network. Our verifier implements the offline PKI path, so an OIDC token is not
     merely inconvenient, it is uncheckable by the thing that has to check it.

  2. The image must not run as `distroless:nonroot`. uid 65532 cannot open the
     root-owned launcher socket, so every call here fails with a permission error that
     looks nothing like the actual cause.

WHY THE NONCE COMES FROM THE CONTROL PLANE
------------------------------------------
The agent does not choose its own challenge. It asks the control plane for one, and the
control plane consumes it exactly once. An agent that picked its own nonce could replay a
token it captured while healthy for as long as the token lived, which is precisely the
window an attacker who swapped the image would want.
"""

from __future__ import annotations

import http.client
import json
import logging
import os
import socket
import threading
import time
from typing import Any, Optional
from urllib import error as urlerror
from urllib import request as urlrequest

LAUNCHER_SOCKET = "/run/container_launcher/teeserver.sock"
TOKEN_PATH = "/v1/token"

CONTROL_PLANE_URL = os.environ.get("CONTROL_PLANE_URL", "").rstrip("/")
AGENT_ID = os.environ.get("AGENT_ID", "")
AUDIENCE = os.environ.get("ATTEST_AUDIENCE", "agent-attest")

#: Must be comfortably inside the control plane's freshness window (300s), so that a
#: single failed beat is survivable without the agent being treated as unattested.
HEARTBEAT_INTERVAL_SEC = int(os.environ.get("HEARTBEAT_INTERVAL_SEC", "60"))

log = logging.getLogger("attest")


class AttestationUnavailable(RuntimeError):
    """Raised when the launcher socket cannot produce a token."""


class _UnixHTTPConnection(http.client.HTTPConnection):
    """http.client over a Unix socket. The host in the URL is ignored."""

    def __init__(self, socket_path: str, timeout: float = 10.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:  # type: ignore[override]
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


def fetch_attestation_token(nonce: str, audience: str = AUDIENCE) -> str:
    """Ask the launcher for a PKI attestation token bound to `nonce`."""
    body = json.dumps(
        {"audience": audience, "nonces": [nonce], "token_type": "PKI"}
    )
    conn = _UnixHTTPConnection(LAUNCHER_SOCKET)
    try:
        conn.request("POST", TOKEN_PATH, body=body, headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        raw = resp.read().decode("utf-8").strip()
        if resp.status != 200:
            raise AttestationUnavailable(
                f"launcher returned HTTP {resp.status}: {raw[:200]}"
            )
    except FileNotFoundError as e:
        raise AttestationUnavailable(
            f"no launcher socket at {LAUNCHER_SOCKET}. This process is not running as a "
            f"Confidential Space workload."
        ) from e
    except PermissionError as e:
        raise AttestationUnavailable(
            f"permission denied opening {LAUNCHER_SOCKET}. The socket is root-owned, so "
            f"this is almost certainly a distroless:nonroot base image running as uid "
            f"65532. Use a base image that runs as root."
        ) from e
    finally:
        conn.close()

    # Fail loudly here rather than letting the control plane reject it later. A token
    # with no x5c cannot be verified by the offline path at all, and the error it
    # produces three hops away describes a symptom rather than this cause.
    header_b64 = raw.split(".")[0]
    header_b64 += "=" * (-len(header_b64) % 4)
    import base64

    header = json.loads(base64.urlsafe_b64decode(header_b64))
    if "x5c" not in header:
        raise AttestationUnavailable(
            f'launcher returned an OIDC-variant token (alg={header.get("alg")}, '
            f'kid={header.get("kid")}). token_type: "PKI" did not take effect.'
        )
    return raw


def _post(path: str, payload: dict[str, Any], timeout: float = 15.0) -> dict[str, Any]:
    if not CONTROL_PLANE_URL:
        raise RuntimeError("CONTROL_PLANE_URL is not set.")
    req = urlrequest.Request(
        f"{CONTROL_PLANE_URL}{path}",
        data=json.dumps(payload).encode(),
        headers={"content-type": "application/json"},
        method="POST",
    )
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read())
    except urlerror.HTTPError as e:
        # The control plane answers a refusal with 403 and a JSON body explaining why.
        # That body is the useful part, so read it rather than raising on the status.
        try:
            return json.loads(e.read())
        except Exception:
            raise


def _challenge(agent_id: str) -> str:
    return str(_post("/admission/challenge", {"agentId": agent_id})["nonce"])


def apply_for_admission(
    agent_id: str,
    display_name: str,
    description: str,
    role: str,
    url: str,
    agent_card: Optional[dict[str, Any]] = None,
) -> dict[str, Any]:
    """
    Apply once, at startup.

    Idempotent from the caller's point of view but NOT from the system's: the control
    plane refuses a second application for an agent that already has a record, because
    re-admitting would silently repin it to whatever digest applied second. If this
    returns admitted: false with that reason, the agent is already admitted and should
    carry on to heartbeats.
    """
    nonce = _challenge(agent_id)
    token = fetch_attestation_token(nonce)
    payload: dict[str, Any] = {
        "agentId": agent_id,
        "token": token,
        "nonce": nonce,
        "displayName": display_name,
        "description": description,
        "role": role,
        "url": url,
    }
    if agent_card is not None:
        payload["agentCard"] = agent_card
    return _post("/admission/apply", payload)


def send_heartbeat(agent_id: str) -> dict[str, Any]:
    """Prove, once, that this workload is still the code it was admitted under."""
    nonce = _challenge(agent_id)
    token = fetch_attestation_token(nonce)
    return _post("/attest/heartbeat", {"agentId": agent_id, "token": token, "nonce": nonce})


def start_heartbeat(agent_id: str = "", interval_sec: int = HEARTBEAT_INTERVAL_SEC) -> threading.Thread:
    """
    Run heartbeats forever on a daemon thread.

    A daemon thread on purpose. If the agent is shutting down, the right outcome is that
    heartbeats stop and the admission goes stale, which the gateway then treats as not
    admitted. A non-daemon thread would keep a dying agent looking alive.

    Failures are logged and retried rather than raised. A missed beat is not fatal: the
    freshness window tolerates four of them. What must never happen is the agent crashing
    on a transient control-plane blip and taking the workload down with it, because a
    restart on Confidential Space means a new VM and a new admission.
    """
    aid = agent_id or AGENT_ID
    if not aid:
        raise RuntimeError("AGENT_ID is not set and no agent_id was passed.")

    def loop() -> None:
        while True:
            try:
                result = send_heartbeat(aid)
                if result.get("ok"):
                    log.debug("heartbeat ok: %s", result.get("digest"))
                else:
                    # Reaching here usually means the digest no longer matches, and the
                    # control plane has already revoked. Log it at error level: this is
                    # the event the whole system exists to produce.
                    log.error(
                        "heartbeat REFUSED: %s (revoked=%s)",
                        result.get("reason"),
                        result.get("revoked"),
                    )
            except AttestationUnavailable as e:
                log.error("cannot attest: %s", e)
            except Exception as e:  # noqa: BLE001 - a heartbeat must never kill the agent
                log.warning("heartbeat failed, will retry: %s", e)
            time.sleep(interval_sec)

    t = threading.Thread(target=loop, name="attest-heartbeat", daemon=True)
    t.start()
    log.info("heartbeat started for %s every %ss", aid, interval_sec)
    return t
