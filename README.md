# agent-attest

**Google's Agent Registry knows where an agent runs. It doesn't know what code runs there.**

Try it: **[agent-attest.pages.dev](https://agent-attest.pages.dev)** ·
**[4 min demo](https://www.youtube.com/watch?v=mD6cvaFkFEc)**

An agent gets into the registry because somebody with the right IAM role deployed it. Agent
Identity then gives that agent a SPIFFE ID which Google's docs describe as "mapped directly
to the resource URI where the agent is hosted". So redeploy completely different code to the
same resource URI and you get the same SPIFFE ID, the same IAM authority, and a registry
entry that hasn't changed. Nothing in the platform notices.

agent-attest fixes that. Agents run as workloads on Google Confidential Space and have to
present an attestation token to get in. That token is checked offline, against a Google root
certificate pinned into the binary at build time, before the agent is registered. The digest
it was admitted under gets recorded, and every 60 seconds the agent has to prove it's still
running that same digest.

> source → reproducible build → image digest → attested by the TEE → verified offline
> against a pinned root → approved digest → admitted → re-proved every 60 seconds

This builds on Google's platform rather than replacing it. Registration goes into the real
Agent Registry (`agentregistry.googleapis.com`). Enforcement is a real Agent Gateway
authorization extension. The bit I added is the admission step in between.

## Architecture

![architecture](docs/architecture.svg)

## Status

| Part | State |
|---|---|
| Offline Confidential Space attestation verifier, 20 checks | **Live.** 17 tests against a real production token from a TEE in this project. |
| Admission into Google's Agent Registry | **Live.** Four agents registered because an attestation checked out. |
| Heartbeat re-attestation, revocation on drift | **Live.** Caught in about 60 seconds, end to end. |
| Browser verification page | **Live** at [agent-attest.pages.dev](https://agent-attest.pages.dev). |
| ADK fleet on Confidential Space | **Live.** Orchestrator plus three specialised workers. |
| Agent Gateway authorization extension | **Registered.** Real `authzExtension` resource, checked against Envoy `ext_authz` v3. |
| Gateway policy binding | **Blocked.** Tenant provisioning never completed, and the protocol enum has no A2A. See [docs/GATEWAY.md](docs/GATEWAY.md). |

## Layout

| Path | What's in it |
|---|---|
| `verifier/` | Confidential Space attestation verification. Pure WebCrypto, offline PKI (`x5c`) path, no backend. Runs unchanged in a browser and in Node. 65,751 bytes gzipped, measured by `web/build.sh`. |
| `control-plane/` | Admission controller. Verifies, calls `services.create`, writes the admission record. |
| `gateway-ext/` | Agent Gateway authorization extension. The gRPC callout that allows or denies. |
| `agents/` | The fleet: Warden, Surveyor, Assessor, Executor. |
| `web/` | The verification page. |
| `deploy/` | Numbered scripts, run in order. |
| `tools/attestation-vm/` | Takes a Confidential Space VM from nothing to a real attestation token. |
| `docs/` | Schema, gateway notes, architecture diagram. |

## One verifier, two places

`verifier/` has no DOM dependency and no Node-only dependency, so the same code runs in the
Cloud Run control plane and in a browser. That means you can recompute the control plane's
verdict yourself, client-side, against the pinned root, without an account and without
trusting my servers.

There's no second browser implementation. Two implementations that agree would only prove I
can write two things that agree.

## Spin-up

You'll need: a Google Cloud project with billing enabled, `gcloud`, Docker, and Node 20+.
Confidential Space needs AMD SEV capable hardware (the n2d family), so pick a region that
has it.

```bash
git clone https://github.com/iamrobertmoore/agent-attest
cd agent-attest
export PROJECT=your-project-id
```

**1. Bootstrap.** APIs, Firestore, six service accounts with deliberately non-overlapping
IAM grants.

```bash
./deploy/00-bootstrap.sh
```

**2. Firestore rules.** Admission records are world-readable on purpose; the control plane
writes with admin credentials, which bypass rules.

```bash
./deploy/10-firestore-rules.sh   # prints the rules and how to apply them
```

**3. Control plane.** Deploys to Cloud Run as the only principal in the project holding
`agentregistry.services.create`.

```bash
./deploy/20-control-plane.sh
```

**4. Launch an agent.** Builds the fleet image, approves its digest, and launches it on
Confidential Space. Before it spends a VM it checks the image is single-platform, diffs
every env var against the launch policy, and boots the container locally.

```bash
./deploy/30-agent-vm.sh surveyor
for a in assessor warden executor; do SKIP_BUILD=true ./deploy/30-agent-vm.sh $a; sleep 20; done
```

**5. Check it worked.** No credentials needed for the second one.

```bash
curl -s -H "Authorization: Bearer $(gcloud auth print-access-token)" \
  "https://agentregistry.googleapis.com/v1/projects/$PROJECT/locations/us-central1/services"

curl -s "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/agents/surveyor"
```

**6. See it catch a change.** Redeploys one agent with different code, under the same name
and identity, never approved. Takes about 90 seconds.

```bash
./deploy/40-drift-demo.sh assessor
```

**Optional: the gateway.** VPC, internal load balancer, private DNS, authorization
extension, gateway. Read [docs/GATEWAY.md](docs/GATEWAY.md) first, it explains what does and
doesn't work.

```bash
./deploy/50-gateway.sh
```

**Run the tests:**

```bash
cd verifier && npm install && npm test    # 17 tests against a real TEE token
```

**Build the page locally:**

```bash
./web/build.sh
cd web/dist && python3 -m http.server 3000
```

**Tear down** so you stop paying for VMs:

```bash
for a in surveyor assessor warden executor; do
  gcloud compute instances delete agent-attest-$a --zone=$(cat deploy/.zone-$a) --quiet
done
```

## What this doesn't do

These are in the code as `STANDING_CAVEATS` and `REGISTRY_CAVEATS`, and they get printed
with every result including the ones that pass.

- Attestation proves which image ran. It doesn't prove the code is any good. A TEE running
  malicious code produces a perfectly valid attestation.
- Pinning an image pins the code, not the behaviour. Nothing here covers model weights or
  prompts pulled in at runtime from somewhere else.
- Revocation isn't checked. The leaf has no CRL distribution point, and the intermediate's
  CRL is served without CORS headers so a browser can't fetch it. With 60-day leaves and a
  hard root pin the residual risk is a revoked intermediate. Rare, not zero.
- The gateway doesn't re-attest per request, because only the workload can mint a token and
  the caller isn't the workload. It checks admission, revocation and freshness. The digest
  comparison happens on the heartbeat, so an agent that drifts inside the 300-second window
  stays reachable until it misses a beat.
- Verifying in your browser means you don't have to trust the server running the workload.
  You do still have to trust whoever served you the JavaScript.

## Prior work

The verifier started as the Confidential Space verifier from an earlier project of mine,
[glassbox](https://github.com/iamrobertmoore/glassbox), reused here under MIT with the
registry binding rewritten from an on-chain lookup to Firestore. The attestation capture
tooling has the same origin.

## Licence

MIT. See `LICENSE`.
