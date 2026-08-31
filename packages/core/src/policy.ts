import { parse as parseYaml } from "yaml";
import { VERBS, payloadBytes, type ContextPush, type Envelope, type Verb, type Verdict } from "./envelope.js";
import { redactDeep } from "./redact.js";

export interface PeerGrant {
  /** The peer's Ed25519 public key, base64. Without it, nothing from them is trusted. */
  key?: string;
  repos?: string[];
  verbs?: Verb[];
  /** Per-peer override of the default verdict for a verb. */
  overrides?: Partial<Record<Verb, Verdict>>;
}

export interface Policy {
  version: 1;
  node: string;
  defaults: Record<Verb, Verdict>;
  never: { commands: string[] };
  limits: { payloadBytes: number; askAbovePayloadBytes: number };
  peers: Record<string, PeerGrant>;
}

export interface Reason {
  code: string;
  detail: string;
  verdict: Verdict;
}

export interface Decision {
  verdict: Verdict;
  reasons: Reason[];
  /** The payload as it should actually be handed to the agent. */
  payload: unknown;
  redacted: string[];
}

/**
 * Defaults are deliberately boring: the three read-ish verbs pass, and anything
 * that executes stops for a human. Everything here is overridable per repo/team,
 * but you have to say so out loud.
 */
export const DEFAULT_POLICY: Policy = {
  version: 1,
  node: "unnamed",
  defaults: {
    "context.push": "allow",
    "task.queue": "allow",
    "state.read": "allow",
    "run.request": "ask",
  },
  never: {
    commands: [
      "git push",
      "npm publish",
      "yarn publish",
      "pnpm publish",
      "vercel deploy",
      "rm -rf",
      "sudo",
      "curl | sh",
      "chmod 777",
      "aws s3 rm",
      "terraform apply",
      "kubectl delete",
      "DROP TABLE",
    ],
  },
  limits: { payloadBytes: 2 * 1024 * 1024, askAbovePayloadBytes: 256 * 1024 },
  peers: {},
};

export function parsePolicy(source: string): Policy {
  const raw = (parseYaml(source) ?? {}) as Record<string, any>;
  if (raw.version !== undefined && raw.version !== 1) {
    throw new Error(`unsupported policy version: ${String(raw.version)}`);
  }
  const defaults = { ...DEFAULT_POLICY.defaults };
  for (const [k, v] of Object.entries(raw.defaults ?? {})) {
    if (!VERBS.includes(k as Verb)) throw new Error(`unknown verb in defaults: ${k}`);
    if (!["allow", "ask", "deny"].includes(v as string)) throw new Error(`bad verdict for ${k}: ${String(v)}`);
    defaults[k as Verb] = v as Verdict;
  }
  const peers: Record<string, PeerGrant> = {};
  for (const [name, grant] of Object.entries((raw.peers ?? {}) as Record<string, any>)) {
    const g = grant ?? {};
    if (g.verbs) {
      for (const v of g.verbs) if (!VERBS.includes(v)) throw new Error(`unknown verb in grant for ${name}: ${v}`);
    }
    peers[name] = {
      key: g.key,
      repos: g.repos ?? [],
      verbs: g.verbs ?? [],
      overrides: g.overrides ?? {},
    };
  }
  return {
    version: 1,
    node: raw.node ?? DEFAULT_POLICY.node,
    defaults,
    never: { commands: raw.never?.commands ?? [...DEFAULT_POLICY.never.commands] },
    limits: {
      payloadBytes: raw.limits?.payload_bytes ?? DEFAULT_POLICY.limits.payloadBytes,
      askAbovePayloadBytes: raw.limits?.ask_above_payload_bytes ?? DEFAULT_POLICY.limits.askAbovePayloadBytes,
    },
    peers,
  };
}

const RANK: Record<Verdict, number> = { allow: 0, ask: 1, deny: 2 };
const worse = (a: Verdict, b: Verdict): Verdict => (RANK[b] > RANK[a] ? b : a);

/** Normalises a command so `git   push` and `GIT PUSH` can't slip past a pattern. */
function normaliseCommand(cmd: string): string {
  return cmd.toLowerCase().replace(/\s+/g, " ").trim();
}

/**
 * Evaluate an inbound envelope against this node's policy.
 *
 * Deny always wins over ask, and ask always wins over allow — so adding a rule
 * can only ever make the outcome stricter, never looser.
 */
export function evaluate(
  env: Envelope,
  policy: Policy,
  opts: {
    signatureOk?: boolean;
    /**
     * True when this envelope answers something *we* sent, and came from the
     * exact node and key we sent it to. Asking someone to do work implies
     * permission for them to tell you how it went — otherwise every handoff
     * would need a reciprocal grant before you could hear back.
     */
    impliedReply?: boolean;
  } = {}
): Decision {
  const reasons: Reason[] = [];
  let verdict: Verdict = "allow";
  const add = (code: string, detail: string, v: Verdict) => {
    reasons.push({ code, detail, verdict: v });
    verdict = worse(verdict, v);
  };

  if (opts.signatureOk === false) {
    add("bad-signature", "Signature did not verify against the granted key for this peer.", "deny");
  }

  const isStatusReply =
    opts.impliedReply === true &&
    env.verb === "context.push" &&
    typeof (env.payload as ContextPush | undefined)?.status === "string";

  const peer = policy.peers[env.from];
  if (!peer && isStatusReply) {
    // No grant, but this reports on work we asked for. Accept the status and
    // nothing else: the payload is still redacted and size-limited below.
    add("reply-to-your-request", `Reports on ${env.ref} — work this node handed to "${env.from}".`, "allow");
    const { value: replyPayload, found: replyFound } = redactDeep(env.payload);
    if (replyFound.length > 0) {
      add("secrets-redacted", `Redacted before delivery: ${replyFound.join(", ")}.`, "ask");
    }
    return { verdict, reasons, payload: replyPayload, redacted: replyFound };
  }
  if (!peer) {
    add("no-bridle", `No bridle with "${env.from}". Both ends must opt in before anything crosses.`, "deny");
    return { verdict, reasons, payload: env.payload, redacted: [] };
  }
  if (peer.key && env.fromKey !== peer.key) {
    add("key-mismatch", `The key on this envelope is not the one granted to "${env.from}".`, "deny");
  }

  if (peer.verbs && peer.verbs.length > 0 && !peer.verbs.includes(env.verb)) {
    add("verb-outside-grant", `"${env.from}" holds ${peer.verbs.join(", ")} — not ${env.verb}.`, "deny");
  }

  if (env.scope.repo && peer.repos && peer.repos.length > 0 && !peer.repos.includes(env.scope.repo)) {
    add("repo-outside-grant", `Grant covers ${peer.repos.join(", ")}, not ${env.scope.repo}.`, "deny");
  }

  if (env.verb === "run.request") {
    const cmd = normaliseCommand((env.payload as { command: string }).command);
    for (const pattern of policy.never.commands) {
      if (cmd.includes(normaliseCommand(pattern))) {
        add("never-verb", `Matches a never-rule (“${pattern}”). No grant can permit this.`, "deny");
        break;
      }
    }
  }

  const bytes = payloadBytes(env);
  if (bytes > policy.limits.payloadBytes) {
    add("payload-too-large", `Payload is ${bytes} bytes, over the ${policy.limits.payloadBytes} limit.`, "deny");
  } else if (bytes > policy.limits.askAbovePayloadBytes) {
    add("payload-large", `Payload is ${bytes} bytes — above the auto-accept threshold.`, "ask");
  }

  const { value: payload, found } = redactDeep(env.payload);
  if (found.length > 0) {
    add("secrets-redacted", `Redacted before delivery: ${found.join(", ")}.`, "ask");
  }

  const base = peer.overrides?.[env.verb] ?? policy.defaults[env.verb];
  add("default", `Default for ${env.verb} on this node is ${base}.`, base);

  return { verdict, reasons, payload, redacted: found };
}

export function policyToYaml(policy: Policy): string {
  const lines: string[] = [
    "# bridle.policy.yaml — this node's ACL. Deny wins over ask; ask wins over allow.",
    "version: 1",
    `node: ${policy.node}`,
    "",
    "defaults:",
    ...VERBS.map((v) => `  ${v}: ${policy.defaults[v]}`),
    "",
    "limits:",
    `  payload_bytes: ${policy.limits.payloadBytes}`,
    `  ask_above_payload_bytes: ${policy.limits.askAbovePayloadBytes}`,
    "",
    "# Commands no grant can ever permit.",
    "never:",
    "  commands:",
    ...policy.never.commands.map((c) => `    - ${JSON.stringify(c)}`),
    "",
    "# Nothing crosses from a peer that is not listed here.",
    "peers:",
  ];
  const names = Object.keys(policy.peers);
  if (names.length === 0) lines.push("  {}");
  for (const name of names) {
    const p = policy.peers[name]!;
    lines.push(`  ${name}:`);
    if (p.key) lines.push(`    key: ${JSON.stringify(p.key)}`);
    lines.push(`    repos: [${(p.repos ?? []).map((r) => JSON.stringify(r)).join(", ")}]`);
    lines.push(`    verbs: [${(p.verbs ?? []).join(", ")}]`);
    if (p.overrides && Object.keys(p.overrides).length) {
      lines.push("    overrides:");
      for (const [v, d] of Object.entries(p.overrides)) lines.push(`      ${v}: ${d}`);
    }
  }
  return lines.join("\n") + "\n";
}
