/**
 * HTTP surface for the admission controller.
 *
 * Node's own http module, no framework. There are six routes and none of them need
 * middleware, so a framework would add a dependency tree to the one service in this
 * system that most wants a small one: this is the only principal holding
 * agentregistry.services.create.
 */

import { createServer, type IncomingMessage, type ServerResponse } from "node:http";
import { apply, heartbeat, issueChallenge, revoke, DEFAULT_POLICY } from "./admission.js";
import { decide } from "./decide.js";

const PORT = Number(process.env.PORT ?? 8080);
const PROJECT_ID = process.env.GOOGLE_CLOUD_PROJECT ?? process.env.PROJECT_ID ?? "";
const LOCATION = process.env.LOCATION ?? "us-central1";

if (!PROJECT_ID) {
  throw new Error("PROJECT_ID or GOOGLE_CLOUD_PROJECT must be set.");
}

/** 256 KB. An attestation token is a few KB; anything near this cap is not one. */
const MAX_BODY_BYTES = 256 * 1024;

async function readJson(req: IncomingMessage): Promise<Record<string, unknown>> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of req) {
    total += (chunk as Buffer).length;
    if (total > MAX_BODY_BYTES) throw new Error("Request body too large.");
    chunks.push(chunk as Buffer);
  }
  if (total === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
}

function send(res: ServerResponse, status: number, body: unknown): void {
  const payload = JSON.stringify(body, null, 2);
  res.writeHead(status, {
    "content-type": "application/json",
    "content-length": Buffer.byteLength(payload),
  });
  res.end(payload);
}

function str(body: Record<string, unknown>, key: string): string {
  const v = body[key];
  if (typeof v !== "string" || v.length === 0) {
    throw new Error(`Field "${key}" is required and must be a non-empty string.`);
  }
  return v;
}

const routes: Record<
  string,
  (body: Record<string, unknown>) => Promise<{ status: number; body: unknown }>
> = {
  "POST /admission/challenge": async (body) => {
    const { nonce, expiresAt } = await issueChallenge(str(body, "agentId"));
    return { status: 200, body: { nonce, expiresAt: expiresAt.toISOString() } };
  },

  "POST /admission/apply": async (body) => {
    const result = await apply({
      agentId: str(body, "agentId"),
      token: str(body, "token"),
      nonce: str(body, "nonce"),
      displayName: str(body, "displayName"),
      description: str(body, "description"),
      role: str(body, "role"),
      url: str(body, "url"),
      projectId: PROJECT_ID,
      location: LOCATION,
      ...(body.agentCard ? { agentCard: body.agentCard as Record<string, unknown> } : {}),
    });
    // 403 rather than 400 on refusal: the request was well formed, the answer is no.
    return { status: result.admitted ? 201 : 403, body: result };
  },

  "POST /attest/heartbeat": async (body) => {
    const result = await heartbeat(str(body, "agentId"), str(body, "token"), str(body, "nonce"));
    return { status: result.ok ? 200 : 403, body: result };
  },

  "POST /admission/revoke": async (body) => {
    await revoke(str(body, "agentId"), str(body, "reason"));
    return { status: 200, body: { revoked: true } };
  },

  /**
   * The authorization decision the gateway callout delegates to.
   *
   * It lives here rather than in the callout because the decision depends on the
   * verifier and the admission record, and Google ships no Node SDK for the ext_authz
   * wire protocol. Splitting it this way keeps exactly one implementation of "is this
   * agent allowed" while letting the protocol adapter be written in the one language
   * Google actually provides an ext_authz SDK for.
   *
   * The adapter is deliberately dumb. It translates a CheckRequest into an agentId and
   * a Decision into an ALLOW or a DENY, and holds no policy of its own.
   */
  "POST /authorize": async (body) => {
    const decision = await decide(str(body, "agentId"), {
      projectId: PROJECT_ID,
      ...(typeof body.freshnessWindowSec === "number"
        ? { freshnessWindowSec: body.freshnessWindowSec }
        : {}),
    });
    // Always HTTP 200. The allow/deny lives in the body, so a transport failure and a
    // deny are never confusable by the caller. The callout fails closed on transport
    // errors of its own accord.
    return { status: 200, body: decision };
  },
};

const server = createServer((req, res) => {
  void (async () => {
    const path = (req.url ?? "/").split("?")[0] ?? "/";
    const key = `${req.method} ${path}`;

    if (key === "GET /healthz") return send(res, 200, { ok: true });
    if (key === "GET /policy") return send(res, 200, DEFAULT_POLICY);

    const handler = routes[key];
    if (!handler) return send(res, 404, { error: `No route for ${key}` });

    try {
      const body = await readJson(req);
      const { status, body: out } = await handler(body);
      send(res, status, out);
    } catch (e) {
      // Fail closed and say so. A 500 from this service means "not admitted", never
      // "probably fine". Callers must not have to infer that from a status code.
      const message = e instanceof Error ? e.message : String(e);
      console.error(`[admission] ${key} failed:`, message);
      send(res, 500, { admitted: false, ok: false, error: message });
    }
  })();
});

server.listen(PORT, () => {
  console.log(
    `[admission] listening on ${PORT}, project=${PROJECT_ID}, location=${LOCATION}`,
  );
});
