# agent-attest

**Google's Agent Registry knows where an agent runs. It does not know what runs there.**

An agent joins the registry because someone with the right IAM role deployed it. Agent
Identity then issues that agent a SPIFFE ID *"mapped directly to the resource URI where the
agent is hosted"*. Redeploy entirely different code to the same resource URI and you get the
identical SPIFFE ID, the identical IAM authority, and an unchanged registry entry. Nothing
in the platform notices.

agent-attest makes admission provable. An agent runs as a workload on Google Confidential
Space and applies to the registry by presenting its attestation token. The token is verified
**offline**, against a Google root certificate pinned at build time, and only then is the
agent registered. The digest it was admitted under is recorded, and an Agent Gateway
authorization extension re-checks that digest on every request between every agent in the
fleet.

> source code → reproducible build → image digest → attested by Confidential Space →
> verified offline in the browser → admitted to Google's Agent Registry → re-checked at the
> gateway on every hop

This extends Google's platform rather than replacing it. Registration goes into the real
Agent Registry (`agentregistry.googleapis.com`). Enforcement runs as a real Agent Gateway
authorization extension. The contribution is the admission step in between.

## Status

Under construction for the All Things Agentic Hackathon.

## Architecture

![architecture](docs/architecture.svg)

## Layout

| Path | What |
|---|---|
| `verifier/` | Confidential Space attestation verification. Pure WebCrypto, offline PKI (`x5c`) path, no backend, runs unchanged in a browser and in Node. 65,751 bytes gzipped, measured by `web/build.sh`. |
| `control-plane/` | Admission controller. Verifies, calls `services.create`, writes the admission record. |
| `gateway-ext/` | Agent Gateway authorization extension. The gRPC callout that allows or denies. |
| `agents/` | The demo fleet: orchestrator plus specialised workers. |
| `tools/attestation-vm/` | Scripts a Confidential Space VM from nothing to a real attestation token. |
| `docs/` | Schema and architecture. |

## One verifier, two surfaces

`verifier/` has no DOM dependency and no Node-only dependency. The same code runs in the
admission controller and in a browser page, so the control plane's verdict can be
independently recomputed by anyone, client-side, against the pinned root. Most governance
systems ask you to trust the control plane's answer. This one lets you check it.

## Honest limitations

Carried in the code as `STANDING_CAVEATS` and `REGISTRY_CAVEATS`, and surfaced on every
result including the passing ones. In short:

- Attestation proves what image ran. It does not prove the code is correct or safe.
- Pinning the image pins the code, not the behaviour. It says nothing about model weights or
  prompts loaded at runtime from elsewhere.
- Admission is read at check time, and the freshness window means an agent that stops being
  what it claimed stays routable until its next missed heartbeat.
- A lying registry can withhold or fabricate an admission. It cannot forge the proof of what
  code ran, because that half is verified offline against a pinned root.

## Spin-up

See `docs/` (in progress).

## Prior work

The verifier began as the Confidential Space verifier from my earlier project
[glassbox](https://github.com/iamrobertmoore/glassbox) and is reused here under MIT with the
registry binding rewritten. The attestation capture tooling has the same origin.

## Licence

MIT. See `LICENSE`.

## Verify it yourself

`web/` is a single page that bundles the verifier and runs it client-side. Paste an
attestation token and it recomputes the same verdict the control plane reached, against a
Google root certificate pinned at build time, with no account and no trust in our servers.
The admission records it joins against are world-readable in Firestore for the same
reason: an approval only we can read is an assertion.

```bash
./web/build.sh
npx -y serve web/dist
```

The bundle is the control plane's own verifier source, unchanged. That is the point. A
second implementation written to agree with the first would prove only that we can write
two things that agree.
