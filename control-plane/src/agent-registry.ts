/**
 * The thin client for Google's Agent Registry.
 *
 * Deliberately thin. This project's contribution is the admission decision, not a
 * reimplementation of the sponsor's product, and every call here is one the platform
 * already documents.
 *
 * WHAT THE REGISTRY WILL AND WILL NOT STORE
 * -----------------------------------------
 * The writable resource is `Service`. Its complete field list is name, displayName,
 * description, interfaces[], registryResource, createTime, updateTime, and exactly one of
 * agentSpec / mcpServerSpec / endpointSpec. There is no state, no approvalState, no
 * lifecycleStage, and no labels or annotations map.
 *
 * That is the gap this project exists to fill, so it is worth being precise about it:
 * there is nowhere in the Agent Registry data model to record that an agent was admitted,
 * why, or against what measurement. The read-only `Agent` resource has an `attributes`
 * map, but it is output-only and system-populated with reserved keys, so a third party
 * cannot write a verdict into it either.
 *
 * The consequence is architectural rather than incidental. The admission record has to
 * live alongside the registry entry rather than inside it, and the two are joined by
 * `registryService`. If Google later adds an approval state, this is the seam where it
 * would bind, and the write-up should say so.
 *
 * Region note: manual registration is not supported in the `us` or `eu` MULTI-regions.
 * A named region such as us-central1, or `global`, is required.
 */

import { GoogleAuth } from "google-auth-library";

const auth = new GoogleAuth({
  scopes: ["https://www.googleapis.com/auth/cloud-platform"],
});

export const AGENT_REGISTRY_HOST = "https://agentregistry.googleapis.com/v1";

export interface RegisterAgentInput {
  projectId: string;
  location: string;
  /** Becomes the serviceId, and the last segment of the resource name. */
  serviceId: string;
  displayName: string;
  description: string;
  /** Where the agent actually answers. */
  url: string;
  /** A2A agent card, or an empty object for NO_SPEC. Capped at 10KB by the API. */
  agentCard?: Record<string, unknown>;
}

export interface RegisteredService {
  /** projects/{p}/locations/{l}/services/{s} */
  name: string;
}

async function authedFetch(url: string, init: RequestInit = {}): Promise<Response> {
  const client = await auth.getClient();
  const token = await client.getAccessToken();
  if (!token.token) throw new Error("Could not obtain an access token for Agent Registry.");
  return fetch(url, {
    ...init,
    headers: {
      ...(init.headers ?? {}),
      authorization: `Bearer ${token.token}`,
      "content-type": "application/json",
    },
  });
}

/**
 * Create the Service. Returns once the long-running Operation is accepted, not once it
 * has completed; callers that need the finished resource should poll.
 *
 * This function is deliberately NOT exported to any HTTP handler directly. The only path
 * that reaches it runs an attestation verification first. That is the entire point, and
 * keeping the call private to this module is what makes the invariant reviewable rather
 * than merely intended.
 */
async function createService(input: RegisterAgentInput): Promise<RegisteredService> {
  const parent = `projects/${input.projectId}/locations/${input.location}`;
  const url =
    `${AGENT_REGISTRY_HOST}/${parent}/services` +
    `?serviceId=${encodeURIComponent(input.serviceId)}`;

  const body = {
    displayName: input.displayName,
    description: input.description,
    interfaces: [{ url: input.url, protocolBinding: "HTTP_JSON" }],
    agentSpec: input.agentCard
      ? { type: "A2A_AGENT_CARD", content: input.agentCard }
      : { type: "NO_SPEC" },
  };

  const res = await authedFetch(url, { method: "POST", body: JSON.stringify(body) });
  if (!res.ok) {
    const detail = await res.text();
    throw new Error(
      `Agent Registry services.create failed: HTTP ${res.status} ${res.statusText}. ${detail}`,
    );
  }

  // services.create returns a LONG-RUNNING OPERATION, and accepting it is not the same
  // as the service existing.
  //
  // An earlier version returned here on the strength of a 200 and a resource name from
  // the operation metadata. Three agents were then recorded in Firestore as admitted
  // while their Agent Registry entries did not exist, because the operation had failed
  // asynchronously and nothing was watching. The admission record claimed a registry
  // entry that was never created, which is precisely the kind of quiet divergence this
  // project exists to prevent, sitting inside the project itself.
  //
  // So: poll to completion, and treat a failed operation as a failed registration.
  const op = (await res.json()) as {
    name?: string;
    done?: boolean;
    error?: { message?: string };
    metadata?: { target?: string };
    response?: { name?: string };
  };

  const expected = `${parent}/services/${input.serviceId}`;
  if (op.done) {
    if (op.error) throw new Error(`Agent Registry create failed: ${op.error.message}`);
    return { name: op.response?.name ?? expected };
  }
  if (!op.name) {
    throw new Error("Agent Registry returned neither a completed result nor an operation name.");
  }

  // ~20s budget. Registration is a startup-path call, not a request-path one, so waiting
  // is cheap; being wrong about whether it succeeded is not.
  for (let i = 0; i < 20; i++) {
    await new Promise((r) => setTimeout(r, 1000));
    const poll = await authedFetch(`${AGENT_REGISTRY_HOST}/${op.name}`);
    if (!poll.ok) continue;
    const state = (await poll.json()) as {
      done?: boolean;
      error?: { message?: string };
      response?: { name?: string };
    };
    if (!state.done) continue;
    if (state.error) {
      throw new Error(`Agent Registry create failed: ${state.error.message}`);
    }
    return { name: state.response?.name ?? expected };
  }

  throw new Error(
    `Agent Registry create did not complete within 20s (operation ${op.name}). ` +
      `Refusing to record an admission that claims a registry entry which may not exist.`,
  );
}

/**
 * Register an agent. The only exported way to reach services.create.
 *
 * The `attested` argument is not used to build the request, because there is no field in
 * the Agent Registry data model to put it in. It is required anyway, so that the type
 * system refuses to let a caller register an agent it has not verified. An unused
 * parameter is a cheap way to make a policy structural instead of documentary.
 */
export async function registerAttestedAgent(
  input: RegisterAgentInput,
  attested: { imageDigest: string; verifiedAt: Date },
): Promise<RegisteredService> {
  if (!attested.imageDigest.startsWith("sha256:")) {
    throw new Error(
      `Refusing to register ${input.serviceId}: admission digest is not a sha256 digest.`,
    );
  }
  return createService(input);
}

export async function deleteService(name: string): Promise<void> {
  const res = await authedFetch(`${AGENT_REGISTRY_HOST}/${name}`, { method: "DELETE" });
  if (!res.ok && res.status !== 404) {
    throw new Error(`Agent Registry delete failed: HTTP ${res.status} ${await res.text()}`);
  }
}
