# Agent Gateway enforcement

How the per-request half works, and the two things about it that are worth arguing over.

---

## Shape

```
caller ──► Agent Gateway ──ext_authz gRPC──► gateway-ext (Python)
                                                  │  POST /authorize
                                                  ▼
                                            control-plane (Node)
                                                  │  Firestore REST
                                                  ▼
                                            admission record
```

The callout is a protocol adapter with no policy in it. The decision lives beside the
verifier and the admission record, behind `POST /authorize`, so there is exactly one
implementation of "is this agent allowed". Two implementations would eventually disagree,
and the day they disagreed one of them would be wrong in the permissive direction.

The language boundary follows Google's SDK boundary. Google ships callout SDKs for
Python, Go and Java; only the Python one implements `ext_authz`
(`AuthorizationServicer`), the other two are `ext_proc` only, and there is no Node SDK.
Hand-rolling proto generation, H2C and health-check plumbing in Node for a fail-closed
security control on a deadline is a decision that looks clever for two days.

## What the per-request check actually checks

Not "re-attest the target now". The gateway cannot compel a fresh attestation: a
Confidential Space token is minted by the workload itself from the launcher socket, and
the caller is not the workload. So per request the question is:

> was this agent admitted, is that admission still in force, and has it proved recently
> enough that it is still running the code it was admitted under?

The digest comparison happens at heartbeat time, in the control plane, where a token
genuinely is available. Being precise about this matters, because "the gateway re-checks
the running measurement on every request" would be an overclaim if said without it.

## Two findings worth stating in the write-up

### 1. Google's own Agent Gateway samples ship `failOpen: true`

`failOpen` defaults to `false`, and the reference is unambiguous about what that means:
*"If the extension times out or fails, request processing stops... a generic 500 error is
returned to the client."* That is the correct default for an authorization control.

Every Agent Gateway authz sample in Google's documentation nonetheless sets
`failOpen: true`. Copy-paste one and the control degrades to a suggestion: anything that
makes the callout unreachable also makes it irrelevant, which is a property an attacker
can arrange. We set it explicitly to `false` and say so.

This is worth reporting to Google as a documentation issue rather than a pull request,
since there may be a reason the samples are permissive that is not visible from outside.
**Re-verify before submission.** Sponsor docs get fixed, and a claim that was true when
written and false a week later reads badly in a public README the sponsor will read.

### 2. `CONTENT_AUTHZ` cannot be made fail-closed

Under `CONTENT_AUTHZ` with `FULL_DUPLEX_STREAMED`, the docs say *"The proxy fail-opens up
to the first chunk of body data being processed"*, and connection and header failures
fail open **regardless of `failOpen`**. Only `REQUEST_AUTHZ` gives a clean fail-closed
guarantee.

We use `REQUEST_AUTHZ`. We do not need to inspect bodies, so there is nothing to trade
away, but the choice is deliberate rather than incidental and the alternative would have
silently undermined the whole design.

## Deriving the target agent

There is no documented attribute carrying the target's Agent Registry resource name.
Google's attributes describe the **caller** richly, via
`connection.client_cert_spiffe_id`, and the **target** only through routing: `host`,
`path`, `backend_service_name`.

So the route-to-agent mapping is ours to define. Convention: each agent is fronted by a
host `<agentId>.<suffix>`, and an explicit `x-agent-attest-agent` header overrides it so
the thing is testable with curl. It lives in one function, `target_agent_id`, which is
the single place that changes if Google later surfaces the target as an attribute.

The caller's SPIFFE ID is logged rather than enforced on. It is the right identifier for
"which agent made this hop", and pairing it with the target's admission state is what
makes an inter-agent audit trail reconstructable. It proves where the caller runs, not
what code runs there, which is the reason this extension exists at all.

## Deployment, and the part that is genuinely awkward

Ordinary Service Extensions accept a serverless NEG pointing at Cloud Run, with the
caveat that the service *"must listen on a plaintext gRPC port"* and *"allow
unauthenticated access"*.

**Agent Gateway custom extensions are documented differently.** `service` must be an FQDN
resolvable by Cloud DNS, on HTTP/2 with TLS on port 443, with the resolved endpoints
inside the VPC and DNS peering between the gateway project and that VPC. The docs also
note the extension *"doesn't validate the server certificate"*, which is why the VPC
containment is doing the work.

That is a real infrastructure lift: VPC, internal Application Load Balancer, serverless
NEG, private DNS zone, peering. It is the single largest schedule risk in the build and
the reason the plan carries a hard checkpoint before it.

Other constraints worth having in one place:

| Constraint | Value |
|---|---|
| `wireFormat` | `EXT_AUTHZ_GRPC`, regional only |
| `policyProfile` | `REQUEST_AUTHZ` |
| `failOpen` | `false`, explicitly |
| `timeout` | 10 to 10000 ms. Ours 1s, upstream call budgeted 800ms. |
| Max gRPC response | 128 kB |
| LB scheme | `INTERNAL_MANAGED` or `EXTERNAL_MANAGED`, same region, same project as the forwarding rule |
| IAM | `agentGateway.use` to attach policies |

A doc inconsistency to check against the live gateway: the same page uses both
`.../agentGateways/NAME` and `.../gateways/NAME` in different samples.

## Config

```yaml
# authz-extension.yaml
name: agent-attest-authz
service: authz.agent-attest.internal      # FQDN in the peered VPC
failOpen: false                            # NOT the value in Google's samples
timeout: 1s
wireFormat: EXT_AUTHZ_GRPC
```

```yaml
# authz-policy.yaml
name: agent-attest-policy
target:
  resources:
    - "projects/agent-attest-2026/locations/us-central1/agentGateways/AGENT_GATEWAY"
policyProfile: REQUEST_AUTHZ
action: CUSTOM
customProvider:
  authzExtension:
    resources:
      - "projects/agent-attest-2026/locations/us-central1/authzExtensions/agent-attest-authz"
```

```bash
gcloud beta service-extensions authz-extensions import agent-attest-authz \
  --source=authz-extension.yaml --location=us-central1
gcloud network-security authz-policies import agent-attest-policy \
  --source=authz-policy.yaml --location=us-central1
```

## Fallback

If the VPC and DNS path cannot be made to work in the time available, the same
`/authorize` endpoint sits behind a plain HTTP reverse proxy on Cloud Run and the
enforcement logic is byte-identical, because the callout never held any of it. The
write-up then names this exact surface as what it binds to. That is the pre-planned
scale-back and it costs one honest paragraph.

## Platform gotcha: a private Cloud Run service 404s, it does not 403

Worth writing down because it cost time and it will recur.

A Cloud Run service deployed `--no-allow-unauthenticated` answers an unauthorised caller
with **404 from the Google frontend**, not 403. That is deliberate information hiding: a
private service that answered differently for "wrong URL" and "no access" would leak its
own existence to anyone who could guess a hostname.

The cost is that the two cases are indistinguishable from the outside. A service showing
`Ready: True` and `RoutesReady: True` returning a frontend 404 on every hostname looks
exactly like a routing problem and is usually an IAM problem.

Two things make it worse together:

- `gcloud run services describe --format='value(status.url)'` can return a legacy-format
  hostname that does not route, while `gcloud run services list` returns the canonical
  one. So there genuinely are wrong hostnames in circulation.
- `gcloud auth print-identity-token` with no `--audiences` mints a token audienced to
  gcloud's own OAuth client, which Cloud Run rejects. So even the right hostname 404s.

`deploy/lib-url.sh` handles all of it: tries every hostname gcloud knows, mints an
audience-scoped token per candidate, and distinguishes 403 (right URL, wrong caller) from
404 in its output.
