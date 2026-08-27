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

The callout is just a protocol adapter. There's no policy in it. The decision lives beside the
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
genuinely is available. I'm being fussy about this because "the gateway re-checks the running measurement on
every request" would be an overclaim without the qualifier.

## Two findings worth stating in the write-up

### 1. Google's own Agent Gateway samples ship `failOpen: true`

`failOpen` defaults to `false`, and the reference is unambiguous about what that means:
*"If the extension times out or fails, request processing stops... a generic 500 error is
returned to the client."* That is the correct default for an authorization control.

Every Agent Gateway authz sample in Google's documentation nonetheless sets
`failOpen: true`. Copy-paste one and the control degrades to a suggestion: anything that
makes the callout unreachable also makes it irrelevant, which is a property an attacker
can arrange. I set it explicitly to `false` and say so.

This is worth reporting to Google as a documentation issue rather than a pull request,
since there may be a reason the samples are permissive that is not visible from outside.
**Re-verify before submission.** Sponsor docs get fixed, and a claim that was true when
written and false a week later reads badly in a public README the sponsor will read.

### 2. `CONTENT_AUTHZ` cannot be made fail-closed

Under `CONTENT_AUTHZ` with `FULL_DUPLEX_STREAMED`, the docs say *"The proxy fail-opens up
to the first chunk of body data being processed"*, and connection and header failures
fail open **regardless of `failOpen`**. Only `REQUEST_AUTHZ` gives a clean fail-closed
guarantee.

I use `REQUEST_AUTHZ`. I don't need to inspect bodies so nothing is lost, but it's a
choice I made on purpose, and the other option would have quietly undermined the design.

## Deriving the target agent

There is no documented attribute carrying the target's Agent Registry resource name.
Google's attributes describe the **caller** richly, via
`connection.client_cert_spiffe_id`, and the **target** only through routing: `host`,
`path`, `backend_service_name`.

So the route-to-agent mapping is mine to define. Convention: each agent is fronted by a
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

That's a lot of infrastructure: VPC, internal Application Load Balancer, serverless NEG,
private DNS zone, peering. It was the biggest schedule risk in the whole build.

Other constraints worth having in one place:

| Constraint | Value |
|---|---|
| `wireFormat` | `EXT_AUTHZ_GRPC`, regional only |
| `policyProfile` | `REQUEST_AUTHZ` |
| `failOpen` | `false`, explicitly |
| `timeout` | 10 to 10000 ms. Mine 1s, upstream call budgeted 800ms. |
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

Writing this down because it cost me time and it'll happen again.

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
  one. So there genuinely are wrong hostnames in circulation. **`gcloud run services
  proxy` reads `status.url`**, so even a correctly authenticated proxy 404s against a
  service whose `status.url` is stale. That is worth knowing before concluding an app is
  broken: a proxy failure is not evidence about the container.
- `gcloud auth print-identity-token` with no `--audiences` mints a token audienced to
  gcloud's own OAuth client, which Cloud Run rejects. So even the right hostname 404s.

`deploy/lib-url.sh` handles all of it: tries every hostname gcloud knows, mints an
audience-scoped token per candidate, and distinguishes 403 (right URL, wrong caller) from
404 in its output.

## Platform finding: Agent Registry interface URLs are globally unique

Not stated in the reference for `Service.interfaces[]`, and worth knowing because the
failure is invisible if you are not looking for it.

Registering a second service with an interface URL already claimed by another fails with:

```
The request was invalid: generic::invalid_argument:
Interface URL 'http://localhost:8080' is already in use by another service.
```

Two things make this expensive to diagnose.

First, `services.create` returns a **long-running operation**, and the uniqueness check
happens asynchronously. The HTTP call returns 200 with an operation name. A client that
takes the 200 as success sees nothing wrong at all.

Second, the first registration succeeds. If a fleet shares an image and a default port,
agent one is admitted and agents two, three and four are silently rejected, which looks
like a race or a quota problem rather than a constraint on a field nobody thinks of as a
key.

That is exactly what happened here: three agents held admission records asserting registry
entries that did not exist, because the control plane never polled the operation. The
control plane now polls to `done` and treats a failed operation as a failed registration,
and each agent registers its own gateway-fronted URL.

Worth reporting to Google: documenting the uniqueness constraint on `interfaces[].url`
would have made this a one-line fix instead of an afternoon.

## Platform finding: Agent Gateway does not speak A2A

The `agent-gateways import` validator rejects an incomplete document by printing its full
JSON schema, which is the most useful error message in the entire platform. It contains:

```
'protocols': {'description': 'List of protocols supported by an Agent Gateway',
              'items': {'enum': ['MCP', 'PROTOCOL_UNSPECIFIED'],
                        'type': 'string'},
              'type': 'array'},
```

**Two values, and neither is A2A.**

This matters for anything built the way the Fortified Enterprise Fleet track describes.
ADK's own inter-agent transport is A2A: `RemoteA2aAgent` on the calling side, `to_a2a()`
on the serving side, agent cards at `/.well-known/`. That is the documented way to build a
fleet where agents delegate to each other over the network.

Agent Gateway governs MCP traffic. So at the time of writing, the gateway cannot sit in
front of agent-to-agent calls in an ADK fleet, only in front of MCP tool and server calls.
The track text pairs "Agent Gateway (for unified routing and policy enforcement)" with
building "a scalable network of institutional agents", and those two things do not yet
meet.

Also worth noting from the same schema dump, since none of it appears in the prose docs:

- top-level `network` and `subnetwork` are rejected; `additionalProperties` is false and
  networking belongs under `networkConfig`
- `googleManaged` versus `selfManaged` is a required choice of posture: a Google-run proxy
  in a tenant project, or attachment to an existing Application Load Balancer or Secure
  Web Proxy
- `registries` binds a gateway to Agent Registry with the unusual
  `//agentregistry.googleapis.com/projects/{p}/locations/{l}` form

**What this means for agent-attest.** The enforcement design does not change. The
authorization extension is a real registered resource, it speaks Envoy `ext_authz` v3, and
the decision it serves is the same `POST /authorize` the control plane already answers. If
the gateway can be created for MCP it demonstrates the binding; if A2A support arrives, the
same extension applies to inter-agent hops with no code change, because the callout holds
no policy of its own.

The honest claim is therefore: the extension is registered and exercised, and the gateway
binding covers the protocol Google currently supports.

## Platform note: created is not the same as ready

A `googleManaged` Agent Gateway is provisioned asynchronously in a Google-run tenant
project. `agent-gateways import` returns a complete resource, with a name, an etag and
timestamps, and `describe` finds it straight away. Binding an authorization policy to it
nonetheless fails:

```
Failed to update tenant configuration for AgentGateway:
generic::cancelled: agent gateway "agent-attest-gw" is not yet provisioned in the tenant project
```

Nothing in the create response distinguishes created from ready. There is no state field
to poll, so the only signal is the error text from the operation that needs it.

**And it does not resolve.** The gateway was created at 14:38 and the same error was still
returned at 18:49, over four hours later. That is not a provisioning delay, and there is no
way from outside to tell whether tenant provisioning is queued, failed, or requires
something this project does not have, because the resource reports no state at all.

## Where this leaves enforcement, stated plainly

What exists as real resources on the project:

| Resource | State |
|---|---|
| `authzExtensions/agent-attest-authz` | Created. `wireFormat: EXT_AUTHZ_GRPC`, `failOpen` at its safe default. |
| `agentGateways/agent-attest-gw` | Created. `protocols: [MCP]`, bound to Agent Registry. |
| VPC, proxy-only subnet, internal ALB, certificate, private DNS | Created. `authz.agent-attest.internal` resolves to `10.10.0.2`. |
| `gateway-ext` on Cloud Run | Deployed. Verified against Envoy's real `ext_authz` v3 protos. |
| `authzPolicies/agent-attest-policy` | **Not bound.** Blocked on tenant provisioning that did not complete. |

**The binding would not have governed this fleet anyway.** Agent Gateway's `protocols`
enum is MCP only. ADK agents talk A2A. So even a successfully bound policy would sit in
front of MCP tool traffic and never see an inter-agent hop. The two findings compound: the
gateway cannot be provisioned here, and if it were, it would not cover the transport an
ADK fleet actually uses.

That makes the fallback the correct architecture today rather than a consolation. The
authorization decision is served by `POST /authorize` on the control plane, the callout is
a protocol adapter with no policy of its own, and the decision is identical either way.
When Agent Gateway supports A2A, binding it requires no code change, because there is no
policy in the callout to move.

**Do not claim the gateway enforces anything in the submission.** Claim what is true: the
extension is a registered Google resource, the decision path is live and demonstrable, and
the binding is blocked by a platform limitation that is documented here with its exact
error text.
