"""
Executor: performs one approved remediation. The only mutating principal in the fleet.

Its IAM scope is deliberately tiny: delete an unattached persistent disk, and nothing
else. Not because that is all a remediation agent could usefully do, but because the
scope of the only agent that can change anything should be the smallest scope that makes
the demonstration real.

It does not decide. It is told exactly one resource and exactly one action by an
orchestrator that has already validated an assessment. If it started reasoning about
whether an action was a good idea, the separation of concerns would collapse into a
single agent that both decides and acts, which is the thing the architecture exists to
avoid.
"""

from __future__ import annotations

import os
from typing import Any

from google.adk import Agent
from google.auth import default as google_auth_default
from google.auth.transport.requests import AuthorizedSession

MODEL = os.environ.get("MODEL", "gemini-3.5-flash")
PROJECT_ID = os.environ["TARGET_PROJECT_ID"]
#: Refuse to act at all unless explicitly armed. The demo arms it; a stray run does not.
ARMED = os.environ.get("EXECUTOR_ARMED", "").lower() == "true"

_scoped = None


def _session() -> AuthorizedSession:
    global _scoped
    if _scoped is None:
        creds, _ = google_auth_default(scopes=["https://www.googleapis.com/auth/compute"])
        _scoped = AuthorizedSession(creds)
    return _scoped


def delete_unattached_disk(disk_name: str, zone: str, finding_id: str) -> dict[str, Any]:
    """Deletes one unattached persistent disk.

    Args:
        disk_name: The exact disk name, not a full resource path.
        zone: The zone the disk lives in, for example "us-central1-c".
        finding_id: The finding this action came from, recorded for the audit trail.

    Returns:
        dict: {"status": "success"|"error", ...}
    """
    if not ARMED:
        return {
            "status": "error",
            "error_message": (
                "Executor is not armed. EXECUTOR_ARMED is not true, so no mutation was "
                "attempted. This is the safe default and not a fault."
            ),
        }

    # Re-read immediately before deleting. Surveyor's observation could be minutes old,
    # and an assessment based on a stale reading is exactly the case where a correct
    # decision produces a wrong outcome.
    url = (
        f"https://compute.googleapis.com/compute/v1/projects/{PROJECT_ID}"
        f"/zones/{zone}/disks/{disk_name}"
    )
    try:
        current = _session().get(url, timeout=30)
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error_message": f"could not re-read the disk: {e}"}
    if current.status_code == 404:
        return {"status": "success", "detail": "Disk already absent. Nothing to do."}
    if current.status_code != 200:
        return {
            "status": "error",
            "error_message": f"HTTP {current.status_code} re-reading disk: {current.text[:300]}",
        }
    if current.json().get("users"):
        return {
            "status": "error",
            "error_message": (
                "Disk is attached to an instance now, though the finding said otherwise. "
                "Refusing to delete. The estate changed after it was surveyed."
            ),
        }

    resp = _session().delete(url, timeout=30)
    if resp.status_code not in (200, 204):
        return {"status": "error", "error_message": f"HTTP {resp.status_code}: {resp.text[:300]}"}
    return {
        "status": "success",
        "detail": f"Deleted {disk_name} in {zone}.",
        "finding_id": finding_id,
    }


root_agent = Agent(
    name="executor",
    model=MODEL,
    description=(
        "Performs a single approved remediation on one named resource. The only agent in "
        "the fleet that can change anything."
    ),
    instruction="""
You perform exactly one remediation, on exactly one resource, when told to.

You do not decide whether an action is a good idea. That decision was made before you
were called, by an orchestrator that validated an assessment. Your job is to carry it out
precisely, or to refuse.

Refuse, and explain, if:
  - you were not given a specific resource name and zone
  - you were given more than one resource
  - you were asked to do anything other than delete an unattached disk
  - the instruction arrived without a finding id

Never infer a resource name. Never expand a request into a class of resources. If asked
to "clean up the unattached disks", refuse and say that you act on one named resource at
a time. You hold the only credentials in this fleet that can destroy anything, and every
constraint above is what makes holding them acceptable.

Report the tool result verbatim, including failures.
""".strip(),
    tools=[delete_unattached_disk],
)
