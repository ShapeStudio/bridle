#!/usr/bin/env node
/**
 * A toy coordination server for the demo — the smallest thing docs/PROTOCOL.md
 * permits. One org, bearer tokens, and an append-only JSONL event log projected
 * into memory on boot: kill it mid-demo, start it again, nothing is lost.
 *
 * It exists so `npm run demo` needs no cloud, and doubles as proof that the
 * protocol document is enough to write a server from. It is not the hosted
 * server and not hardened for anything beyond localhost.
 *
 * Events are metadata only: names, verbs, sizes, timestamps, verdicts and the
 * ciphertext it is queueing anyway. A payload never appears here — it cannot;
 * the server never holds one.
 */
import { createServer } from "node:http";
import { appendFileSync, readFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname } from "node:path";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { verifyEnvelope, payloadBytes } from "../packages/core/dist/src/index.js";

const arg = (n) => {
  const i = process.argv.indexOf(`--${n}`);
  return i >= 0 ? process.argv[i + 1] : undefined;
};
const PORT = Number(arg("port") ?? 8799);
const STATE = arg("state") ?? "demo-state/coord/events.jsonl";
mkdirSync(dirname(STATE), { recursive: true });

const hashToken = (t) => createHash("sha256").update(t).digest("hex");

// ---- the event log IS the storage model -----------------------------------
const events = [];
let orgId;
const nodes = new Map(); // name -> { name, key, sealKey, tokenHash }
const tokens = new Map(); // tokenHash -> name
const invites = new Map(); // code -> used
const queue = new Map(); // envelope id -> { envelope, to, verdict? }

/** Projects one event into memory. Unknown types and fields are tolerated — old logs replay. */
function project(ev) {
  events.push(ev);
  switch (ev.t) {
    case "org.created": orgId = ev.orgId; break;
    case "invite.created": invites.set(ev.code, false); break;
    case "invite.used": invites.set(ev.code, true); break;
    case "node.registered":
      nodes.set(ev.name, { name: ev.name, key: ev.key, sealKey: ev.sealKey, tokenHash: ev.tokenHash });
      tokens.set(ev.tokenHash, ev.name);
      break;
    case "envelope.queued": queue.set(ev.id, { envelope: ev.envelope, to: ev.to }); break;
    case "verdict.recorded": { const q = queue.get(ev.id); if (q) q.verdict = ev.verdict; break; }
    // envelope.fetched projects to nothing: the queue drains on ack, not on a look
  }
}

function append(ev) {
  const line = { t: ev.t, at: new Date().toISOString(), orgId, ...ev };
  appendFileSync(STATE, JSON.stringify(line) + "\n");
  project(line);
}

if (existsSync(STATE)) {
  for (const line of readFileSync(STATE, "utf8").split("\n").filter(Boolean)) project(JSON.parse(line));
}
if (!orgId) {
  orgId = randomUUID();
  append({ t: "org.created", orgId, name: "default" });
  const boot = process.env.BRIDLE_BOOTSTRAP_INVITE;
  if (boot) append({ t: "invite.created", code: boot, by: "bootstrap" });
}

// ---- HTTP ------------------------------------------------------------------
const json = (res, status, body) => {
  const buf = Buffer.from(JSON.stringify(body), "utf8");
  res.writeHead(status, { "content-type": "application/json", "content-length": buf.length });
  res.end(buf);
};
const newInvite = () => (randomBytes(4).toString("hex").toUpperCase().match(/.{4}/g) ?? []).join("-");

createServer(async (req, res) => {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  let body = {};
  try { body = chunks.length ? JSON.parse(Buffer.concat(chunks).toString("utf8")) : {}; } catch { /* -> 400 below */ }

  const bearer = (req.headers.authorization ?? "").replace(/^Bearer\s+/i, "");
  const me = bearer ? tokens.get(hashToken(bearer)) : undefined;
  const route = `${req.method} ${new URL(req.url, "http://x").pathname}`;

  if (route === "GET /health") return json(res, 200, { ok: true, orgs: 1, nodes: nodes.size });

  if (route === "POST /v1/register") {
    const { name, key, sealKey, invite } = body;
    if (!name || !key || !sealKey || !invite) return json(res, 400, { error: "name, key, sealKey and invite are required" });
    if (invites.get(invite) !== false) return json(res, 403, { error: "invite is unknown or already used" });
    if (nodes.has(name)) return json(res, 409, { error: `a node named "${name}" already exists` });
    const token = randomBytes(32).toString("base64url");
    append({ t: "invite.used", code: invite, by: name });
    append({ t: "node.registered", name, key, sealKey, tokenHash: hashToken(token) });
    return json(res, 200, { name, token });
  }

  if (!me) return json(res, 401, { error: "missing or unknown token" });

  switch (route) {
    case "POST /v1/invite": {
      const code = newInvite();
      append({ t: "invite.created", code, by: me });
      return json(res, 200, { code });
    }
    case "GET /v1/peers":
      return json(res, 200, { peers: [...nodes.values()].map(({ name, key, sealKey }) => ({ name, key, sealKey })) });
    case "POST /v1/envelope": {
      const env = body.envelope;
      if (!env) return json(res, 400, { error: "no envelope" });
      if (env.from !== me) return json(res, 403, { error: "from must be the authenticated node" });
      if (env.fromKey !== nodes.get(me)?.key) return json(res, 403, { error: "fromKey is not this node's registered key" });
      if (env.payload || !env.sealed) return json(res, 400, { error: "refusing an unsealed envelope" });
      if (!verifyEnvelope(env)) return json(res, 400, { error: "bad signature" });
      if (!nodes.has(env.to)) return json(res, 404, { error: `no node named "${env.to}"` });
      // Routing metadata only, plus the ciphertext this queue exists to hold.
      append({
        t: "envelope.queued", id: env.id, from: env.from, to: env.to,
        verb: env.verb, bytes: payloadBytes(env), ...(env.ref ? { ref: env.ref } : {}), envelope: env,
      });
      return json(res, 202, { id: env.id });
    }
    case "GET /v1/inbox": {
      const waiting = [...queue.values()].filter((q) => q.to === me && !q.verdict);
      for (const q of waiting) append({ t: "envelope.fetched", id: q.envelope.id, by: me });
      return json(res, 200, { envelopes: waiting.map((q) => q.envelope) });
    }
    case "POST /v1/ack": {
      const q = queue.get(body.id);
      if (!q || q.to !== me) return json(res, 404, { error: "no such envelope" });
      append({
        t: "verdict.recorded", id: body.id, by: me, verdict: body.verdict,
        ...(body.reason ? { reason: body.reason } : {}),
        ...(typeof body.heldMs === "number" ? { heldMs: body.heldMs } : {}),
      });
      return json(res, 200, { ok: true });
    }
    case "GET /v1/audit":
      return json(res, 200, { events });
    default:
      return json(res, 404, { error: "not found" });
  }
}).listen(PORT, "127.0.0.1", () => {
  console.log(`demo coord on http://127.0.0.1:${PORT}, log at ${STATE}`);
});
