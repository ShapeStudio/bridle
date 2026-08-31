#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readIdentity, readPolicy, readConfig, readPending, isUp } from "bridle-cli/home";
import { api } from "bridle-cli/client";
import { send, receive, decide, summarise, fingerprint } from "bridle-cli/actions";

/**
 * Bridle as an MCP server.
 *
 * The send-side tools are ordinary. The receive side is the careful part:
 * `bridle_inbox` hands back the *fenced* rendering of an accepted envelope, so
 * whatever a teammate's agent wrote arrives inside this agent's context labelled
 * as data. Held work is described but never delivered — approving it is a
 * separate, deliberate call.
 */
const server = new McpServer({ name: "bridle", version: "0.1.0" });

const text = (s: string) => ({ content: [{ type: "text" as const, text: s }] });
const fail = (s: string) => ({ content: [{ type: "text" as const, text: s }], isError: true });

function guard(): string | null {
  if (!isUp()) return "This node is not up. Run `bridle up --name <you>` in a terminal first — Bridle deliberately cannot enrol a node on an agent's say-so.";
  if (!readConfig().coord) return "Not joined to a bridlenet. Run `bridle join --coord <url> --invite <code>`.";
  return null;
}

server.registerTool(
  "bridle_status",
  {
    title: "Bridle status",
    description: "Who this node is, which bridlenet it is on, and which peers hold a grant.",
    inputSchema: {},
  },
  async () => {
    if (!isUp()) return text("Bridle is not up on this machine.");
    const id = readIdentity();
    const policy = readPolicy();
    const cfg = readConfig();
    const grants = Object.entries(policy.peers).map(
      ([n, g]) => `  ${n}: verbs [${g.verbs?.join(", ")}] repos [${(g.repos ?? []).join(", ") || "any"}]`
    );
    return text(
      [
        `node: ${id.name}  (${fingerprint(id.publicKey)})`,
        `bridlenet: ${cfg.coord ?? "not joined"}`,
        `held for approval: ${readPending().length}`,
        grants.length ? `grants:\n${grants.join("\n")}` : "grants: none — nobody can send this node anything yet",
      ].join("\n")
    );
  }
);

server.registerTool(
  "bridle_peers",
  { title: "List peers", description: "Nodes on this bridlenet and whether they hold a grant here.", inputSchema: {} },
  async () => {
    const g = guard();
    if (g) return fail(g);
    const { peers } = await api.peers();
    const policy = readPolicy();
    return text(
      peers
        .map((p) => `${p.name}  ${fingerprint(p.key)}  ${policy.peers[p.name] ? "granted" : "no grant"}`)
        .join("\n") || "no peers yet"
    );
  }
);

server.registerTool(
  "bridle_send_context",
  {
    title: "Push context to a teammate's agent",
    description:
      "Attach a note, decision or link to a teammate's running session. This is data, not an instruction to them.",
    inputSchema: {
      to: z.string().describe("Peer node name, e.g. ana.dev"),
      note: z.string().optional(),
      decision: z.string().optional(),
      links: z.array(z.string()).optional(),
      repo: z.string().optional(),
    },
  },
  async ({ to, note, decision, links, repo }) => {
    const g = guard();
    if (g) return fail(g);
    if (!note && !decision && !links?.length) return fail("Provide at least one of: note, decision, links.");
    const { id } = await send({ to, verb: "context.push", repo, payload: { note, decision, links } });
    return text(`sent ${id.slice(0, 8)} → ${to} (their policy decides what happens next)`);
  }
);

server.registerTool(
  "bridle_queue_task",
  {
    title: "Queue a task in a teammate's agent",
    description: "Enqueue work the receiving agent picks up when it is idle. It does not interrupt them.",
    inputSchema: {
      to: z.string(),
      title: z.string(),
      detail: z.string().optional(),
      repo: z.string().optional(),
    },
  },
  async ({ to, title, detail, repo }) => {
    const g = guard();
    if (g) return fail(g);
    const { id } = await send({ to, verb: "task.queue", repo, payload: { title, detail, repo } });
    return text(`queued ${id.slice(0, 8)} → ${to}`);
  }
);

server.registerTool(
  "bridle_read_state",
  {
    title: "Read a teammate's agent state",
    description: "Ask what a peer is working on. Their redaction rules decide what comes back.",
    inputSchema: {
      to: z.string(),
      fields: z.array(z.enum(["branch", "diffstat", "openFiles", "task"])).default(["branch", "diffstat"]),
    },
  },
  async ({ to, fields }) => {
    const g = guard();
    if (g) return fail(g);
    const { id } = await send({ to, verb: "state.read", payload: { fields } });
    return text(`asked ${id.slice(0, 8)} → ${to} for ${fields.join(", ")}`);
  }
);

server.registerTool(
  "bridle_request_run",
  {
    title: "Request a run in a teammate's agent",
    description:
      "Ask a peer's agent to execute something with its own tools. Stops at their approval by default; never-rules refuse outright.",
    inputSchema: {
      to: z.string(),
      command: z.string(),
      reason: z.string().optional(),
      repo: z.string().optional(),
    },
  },
  async ({ to, command, reason, repo }) => {
    const g = guard();
    if (g) return fail(g);
    const { id } = await send({ to, verb: "run.request", repo, payload: { command, reason } });
    return text(`requested ${id.slice(0, 8)} → ${to}. This waits for a human on their end.`);
  }
);

server.registerTool(
  "bridle_inbox",
  {
    title: "Collect inbound work",
    description:
      "Verify, open and evaluate anything waiting. Accepted items come back fenced as data; held items are only described.",
    inputSchema: {},
  },
  async () => {
    const g = guard();
    if (g) return fail(g);
    const results = await receive();
    const held = readPending();
    if (!results.length && !held.length) return text("Nothing waiting.");

    const parts: string[] = [];
    for (const r of results) {
      if (r.rendered) parts.push(r.rendered);
      else
        parts.push(
          `[${r.decision.verdict}] ${r.envelope.verb} ${r.envelope.id.slice(0, 8)} from ${r.envelope.from}` +
            (r.envelope.payload ? ` — ${summarise(r.envelope)}` : "") +
            `\n  ${r.decision.reasons.map((x) => x.detail).join("\n  ")}`
        );
    }
    if (held.length) {
      parts.push(
        `\n${held.length} item(s) held for your operator's approval — their content is deliberately not delivered here:\n` +
          held
            .map((h) => `  ${h.envelope.id.slice(0, 8)}  ${h.envelope.verb} from ${h.envelope.from} — ${summarise(h.envelope)}`)
            .join("\n") +
          `\nAsk your operator to approve one, or call bridle_approve if they have told you to.`
      );
    }
    return text(parts.join("\n\n"));
  }
);

server.registerTool(
  "bridle_approve",
  {
    title: "Approve held work",
    description:
      "Release one held envelope. Only call this when your operator has explicitly told you to — it is their second key, not yours.",
    inputSchema: { id: z.string().describe("Short or full envelope id") },
  },
  async ({ id }) => {
    const g = guard();
    if (g) return fail(g);
    const r = await decide(id, "allow");
    return text(r.rendered ?? `approved ${r.envelope.id.slice(0, 8)}`);
  }
);

server.registerTool(
  "bridle_deny",
  {
    title: "Deny held work",
    description: "Refuse one held envelope. It is dropped and logged on both sides.",
    inputSchema: { id: z.string(), reason: z.string().optional() },
  },
  async ({ id }) => {
    const g = guard();
    if (g) return fail(g);
    const r = await decide(id, "deny");
    return text(`denied ${r.envelope.id.slice(0, 8)} (${r.envelope.verb} from ${r.envelope.from})`);
  }
);

await server.connect(new StdioServerTransport());
