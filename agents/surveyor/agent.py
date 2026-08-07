"""
Surveyor: inventories the estate. Broad read, zero write.

The breadth of its read scope is exactly why it must never be able to write. An agent
that can enumerate every resource in a project is the most useful possible reconnaissance
tool, so the only safe version of it is one that cannot act on what it finds.

It also does not judge. Severity and blast radius belong to Assessor, which cannot see
the estate. Splitting "what exists" from "what it means" means neither agent alone is
enough to cause harm.
"""

from __future__ import annotations

import os
from typing import Any

from google.adk import Agent
from google.auth import default as google_auth_default
from google.auth.transport.requests import AuthorizedSession

MODEL = os.environ.get("MODEL", "gemini-3.5-flash")
PROJECT_ID = os.environ["TARGET_PROJECT_ID"]

_scoped = None


def _session() -> AuthorizedSession:
    global _scoped
    if _scoped is None:
        creds, _ = google_auth_default(
            scopes=["https://www.googleapis.com/auth/cloud-platform.read-only"]
        )
        _scoped = AuthorizedSession(creds)
    return _scoped


def find_unattached_disks() -> dict[str, Any]:
    """Finds persistent disks that are not attached to any instance.

    These are the clearest example of pure waste: billed monthly, attached to nothing.
    They are still not safe to delete without an assessment, because an unattached disk
    is sometimes a deliberate snapshot source or a detached volume awaiting migration.

    Returns:
        dict: {"status": "success", "findings": [...], "count": n}
    """
    url = f"https://cloudasset.googleapis.com/v1/projects/{PROJECT_ID}/assets"
    try:
        resp = _session().get(
            url,
            params={
                "assetTypes": "compute.googleapis.com/Disk",
                "contentType": "RESOURCE",
                "pageSize": 100,
            },
            timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error_message": f"asset inventory unreachable: {e}"}
    if resp.status_code != 200:
        return {"status": "error", "error_message": f"HTTP {resp.status_code}: {resp.text[:300]}"}

    findings = []
    for a in resp.json().get("assets", []):
        data = a.get("resource", {}).get("data", {})
        if data.get("users"):
            continue
        name = a.get("name", "")
        findings.append(
            {
                # Stable and derived from the resource name, so Assessor can cite it back
                # and Warden can tell whether it has seen this finding before.
                "id": name.rsplit("/", 1)[-1] + "@unattached-disk",
                "name": name,
                "sizeGb": data.get("sizeGb"),
                "created": data.get("creationTimestamp"),
                "zone": (data.get("zone") or "").rsplit("/", 1)[-1],
                "observation": "Disk has no attached instances.",
            }
        )
    return {"status": "success", "findings": findings, "count": len(findings)}


def find_public_buckets() -> dict[str, Any]:
    """Finds storage buckets whose IAM policy grants access to allUsers or allAuthenticatedUsers.

    Returns:
        dict: {"status": "success", "findings": [...], "count": n}
    """
    url = f"https://cloudasset.googleapis.com/v1/projects/{PROJECT_ID}/assets"
    try:
        resp = _session().get(
            url,
            params={
                "assetTypes": "storage.googleapis.com/Bucket",
                "contentType": "IAM_POLICY",
                "pageSize": 100,
            },
            timeout=30,
        )
    except Exception as e:  # noqa: BLE001
        return {"status": "error", "error_message": f"asset inventory unreachable: {e}"}
    if resp.status_code != 200:
        return {"status": "error", "error_message": f"HTTP {resp.status_code}: {resp.text[:300]}"}

    public = {"allUsers", "allAuthenticatedUsers"}
    findings = []
    for a in resp.json().get("assets", []):
        bindings = a.get("iamPolicy", {}).get("bindings", [])
        exposed = [
            {"role": b.get("role"), "member": m}
            for b in bindings
            for m in b.get("members", [])
            if m in public
        ]
        if not exposed:
            continue
        name = a.get("name", "")
        findings.append(
            {
                "id": name.rsplit("/", 1)[-1] + "@public-bucket",
                "name": name,
                "exposed_to": exposed,
                "observation": "Bucket IAM policy grants access to an all-users principal.",
            }
        )
    return {"status": "success", "findings": findings, "count": len(findings)}


root_agent = Agent(
    name="surveyor",
    model=MODEL,
    description="Read-only inventory of the cloud estate. Returns structured findings.",
    instruction="""
You inventory a cloud estate and report what you find. You do not judge, rank, or
recommend, and you never speculate about whether something is safe to remove. Another
agent does that, and it is deliberately kept ignorant of everything except what you hand
it, so anything you leave out is information nobody downstream will have.

Report findings exactly as the tools return them, including every id verbatim. The ids
are how the rest of the fleet refers to these resources, so altering or abbreviating one
breaks the chain.

If a tool returns an error, say so plainly and return no findings for it. Never invent a
finding and never fill a gap with a plausible example. A fabricated resource id will be
passed to an agent that reasons about deleting things.
""".strip(),
    tools=[find_unattached_disks, find_public_buckets],
)
