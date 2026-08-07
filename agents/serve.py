"""
Serve one agent over A2A, as a Confidential Space workload.

    AGENT=surveyor python serve.py

Order matters and is the point of the file. Admission happens BEFORE the server starts
listening. An agent that served traffic first and attested afterwards would have a window,
however short, in which it was reachable without having proved anything, and the length of
that window would depend on how fast the control plane happened to answer.
"""

from __future__ import annotations

import importlib
import logging
import os
import sys

from google.adk.a2a.utils.agent_to_a2a import to_a2a

from common import attest

logging.basicConfig(level=logging.INFO, format="%(levelname)s %(name)s %(message)s")
log = logging.getLogger("serve")

AGENT = os.environ.get("AGENT", "")
PORT = int(os.environ.get("PORT", "8080"))
PUBLIC_URL = os.environ.get("PUBLIC_URL", "")

ROLES = {
    "warden": "orchestrator",
    "surveyor": "surveyor",
    "assessor": "assessor",
    "executor": "executor",
}

if AGENT not in ROLES:
    sys.exit(f"AGENT must be one of {sorted(ROLES)}, got {AGENT!r}")

module = importlib.import_module(f"{AGENT}.agent")
root_agent = module.root_agent

if os.environ.get("SKIP_ATTESTATION", "").lower() == "true":
    # Local development only. Loud on purpose: the whole product is that this step is
    # not optional, and a quiet flag that skips it would eventually be set in the demo.
    log.warning(
        "SKIP_ATTESTATION is set. This agent is NOT proving what code it is running. "
        "It will be refused by the gateway, which is the correct outcome."
    )
else:
    result = attest.apply_for_admission(
        agent_id=AGENT,
        display_name=root_agent.name,
        description=root_agent.description or "",
        role=ROLES[AGENT],
        url=PUBLIC_URL or f"http://localhost:{PORT}",
    )
    if result.get("admitted"):
        log.info("admitted as %s", result.get("imageDigest"))
    elif "already has an admission record" in str(result.get("reason", "")):
        log.info("already admitted, continuing to heartbeats")
    else:
        # Fail closed at startup too. An agent that could not be admitted should not
        # serve, rather than serve and be refused one hop later: failing here produces a
        # readable error in one place instead of an unexplained 403 in someone else's log.
        sys.exit(f"refused admission: {result.get('reason')} {result.get('verdict', '')}")

    attest.start_heartbeat(AGENT)

a2a_app = to_a2a(root_agent, port=PORT)

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(a2a_app, host="0.0.0.0", port=PORT)
