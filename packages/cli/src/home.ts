import { readFileSync, writeFileSync, appendFileSync, existsSync, mkdirSync, chmodSync, readdirSync, renameSync } from "node:fs";
import { homedir } from "node:os";
import { createHash } from "node:crypto";
import { join, resolve, dirname, basename } from "node:path";
import {
  generateIdentity, parsePolicy, policyToYaml, DEFAULT_POLICY,
  type Identity, type Policy, type Envelope, type Decision, type TaskStatus,
} from "bridle-core";

export interface Config {
  coord?: string;
  token?: string;
}

/** An envelope that passed verification but stopped at `ask`. */
export interface Pending {
  envelope: Envelope;
  decision: Decision;
  heldAt: string;
}

/**
 * Where this node's identity lives.
 *
 * Bridle connects *sessions*, not computers. Two agents working side by side in
 * different repos on one machine are two different participants — they should
 * have different keys, different policies and different names, and one should be
 * able to hand work to the other. Keying everything off ~/.bridle made them the
 * same node, so a handoff between them silently went nowhere.
 *
 * So the home is derived from the workspace: the nearest enclosing git
 * repository, or the working directory if there is not one. BRIDLE_HOME still
 * wins when set, for CI and for anyone who wants to place it themselves.
 */
export function workspaceRoot(from: string = process.cwd()): string {
  let dir = resolve(from);
  for (;;) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) return resolve(from); // no repo above us — use the cwd itself
    dir = parent;
  }
}

/**
 * A stable directory name for a workspace. The basename makes it legible; the
 * path digest keeps two checkouts of the same repo from colliding.
 */
export function workspaceSlug(root: string = workspaceRoot()): string {
  const base = basename(root).toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "workspace";
  return `${base}-${createHash("sha256").update(root).digest("hex").slice(0, 8)}`;
}

export const bridleHome = (): string =>
  process.env.BRIDLE_HOME ?? join(homedir(), ".bridle", "nodes", workspaceSlug());

/** Suggested node name for a fresh workspace, e.g. marko.shape-website. */
export function defaultNodeName(root: string = workspaceRoot()): string {
  const user = (process.env.USER ?? "node").toLowerCase().replace(/[^a-z0-9]/g, "") || "node";
  const repo = basename(root).toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "workspace";
  return `${user}.${repo}`.slice(0, 63);
}

const p = (f: string) => join(bridleHome(), f);
export const paths = {
  identity: () => p("identity.json"),
  config: () => p("config.json"),
  policy: () => p("bridle.policy.yaml"),
  pending: () => p("pending.json"),
  delivered: () => p("delivered.jsonl"),
  outbox: () => p("outbox.json"),
  received: () => p("received.json"),
};

/** The pre-workspace layout: identity files directly inside ~/.bridle. */
export function legacyHome(): string {
  return join(homedir(), ".bridle");
}
export function hasLegacyNode(): boolean {
  return existsSync(join(legacyHome(), "identity.json"));
}

/** Every node this machine holds, so `bridle nodes` can list them. */
export function localNodes(): { home: string; name: string; coord?: string }[] {
  const root = join(homedir(), ".bridle", "nodes");
  if (!existsSync(root)) return [];
  return readdirSync(root)
    .map((slug) => join(root, slug))
    .filter((home) => existsSync(join(home, "identity.json")))
    .map((home) => ({
      home,
      name: (JSON.parse(readFileSync(join(home, "identity.json"), "utf8")) as Identity).name,
      coord: existsSync(join(home, "config.json"))
        ? (JSON.parse(readFileSync(join(home, "config.json"), "utf8")) as Config).coord
        : undefined,
    }));
}

export function isUp(): boolean {
  return existsSync(paths.identity());
}

/**
 * Moves a pre-workspace ~/.bridle node into the workspace layout.
 *
 * Without this, everyone who had already run `bridle up` would find their node
 * apparently gone — the identity is still on disk, just no longer where the tool
 * looks. Adopting it keeps the existing keys, token and grants working.
 */
export function adoptLegacyNode(): { from: string; to: string } | null {
  if (process.env.BRIDLE_HOME || !hasLegacyNode() || isUp()) return null;
  const to = bridleHome();
  mkdirSync(to, { recursive: true });
  for (const f of ["identity.json", "config.json", "bridle.policy.yaml", "pending.json", "delivered.jsonl"]) {
    const src = join(legacyHome(), f);
    if (existsSync(src)) renameSync(src, join(to, f));
  }
  return { from: legacyHome(), to };
}

/** `bridle up` — this end opting in. Nothing is reachable before this exists. */
export function up(name: string): { identity: Identity; policy: Policy; created: boolean } {
  mkdirSync(bridleHome(), { recursive: true });
  if (isUp()) {
    return { identity: readIdentity(), policy: readPolicy(), created: false };
  }
  const identity = generateIdentity(name);
  writeFileSync(paths.identity(), JSON.stringify(identity, null, 2), { mode: 0o600 });
  chmodSync(paths.identity(), 0o600);
  const policy: Policy = { ...DEFAULT_POLICY, node: name, peers: {} };
  writeFileSync(paths.policy(), policyToYaml(policy), "utf8");
  writeConfig({});
  writePending([]);
  return { identity, policy, created: true };
}

export function readIdentity(): Identity {
  if (!isUp()) throw new Error("this node is not up — run `bridle up --name <you>` first");
  return JSON.parse(readFileSync(paths.identity(), "utf8")) as Identity;
}

export function readPolicy(): Policy {
  return parsePolicy(readFileSync(paths.policy(), "utf8"));
}

/**
 * Writes the policy, atomically, and records what changed and who asked.
 *
 * Twice in one afternoon a policy file acquired an entry nobody wrote — a node
 * granting itself, and a repo scope that no version of this code has ever been
 * able to produce. Neither reproduced. A policy quietly gaining a permission is
 * the worst failure this tool has, so rather than keep guessing: every write now
 * leaves a line in policy.log with the argv that caused it, and lands via
 * rename so a torn write cannot survive.
 */
export function writePolicy(policy: Policy): void {
  let before: Policy | null = null;
  try {
    before = readPolicy();
  } catch {
    /* first write for this node */
  }

  const summarise = (p: Policy | null) =>
    p ? Object.entries(p.peers).map(([n, g]) => `${n}[${(g.verbs ?? []).join("|")}]{${(g.repos ?? []).join("|")}}`).sort().join(" ") : "";
  const from = summarise(before);
  const to = summarise(policy);

  if (from !== to) {
    const line = JSON.stringify({
      at: new Date().toISOString(),
      pid: process.pid,
      argv: process.argv.slice(2),
      cwd: process.cwd(),
      from,
      to,
    });
    try {
      appendFileSync(join(bridleHome(), "policy.log"), line + "\n", "utf8");
    } catch {
      /* never let auditing block the write itself */
    }
  }

  // Atomic: a crash or a concurrent writer cannot leave a half-parsed policy.
  const tmp = paths.policy() + `.${process.pid}.tmp`;
  writeFileSync(tmp, policyToYaml(policy), "utf8");
  renameSync(tmp, paths.policy());
}

export function readConfig(): Config {
  const f = paths.config();
  return existsSync(f) ? (JSON.parse(readFileSync(f, "utf8")) as Config) : {};
}
export function writeConfig(c: Config): void {
  writeFileSync(paths.config(), JSON.stringify(c, null, 2), { mode: 0o600 });
}

/** Work this node handed to someone else, and the last thing they said about it. */
export interface OutboxEntry {
  id: string;
  to: string;
  /** The key we sent to. A reply must come from this exact key to count. */
  toKey: string;
  verb: string;
  summary: string;
  sentAt: string;
  status?: TaskStatus;
  note?: string;
  updatedAt?: string;
}

/** Work handed to this node, so it knows what a report would be about. */
export interface ReceivedEntry {
  id: string;
  from: string;
  verb: string;
  summary: string;
  at: string;
}

const readJson = <T>(file: string, fallback: T): T =>
  existsSync(file) ? (JSON.parse(readFileSync(file, "utf8")) as T) : fallback;

export const readOutbox = (): Record<string, OutboxEntry> => readJson(paths.outbox(), {});
export const writeOutbox = (o: Record<string, OutboxEntry>): void =>
  writeFileSync(paths.outbox(), JSON.stringify(o, null, 2), "utf8");

export const readReceived = (): Record<string, ReceivedEntry> => readJson(paths.received(), {});
export const writeReceived = (r: Record<string, ReceivedEntry>): void =>
  writeFileSync(paths.received(), JSON.stringify(r, null, 2), "utf8");

export function readPending(): Pending[] {
  const f = paths.pending();
  return existsSync(f) ? (JSON.parse(readFileSync(f, "utf8")) as Pending[]) : [];
}
export function writePending(list: Pending[]): void {
  writeFileSync(paths.pending(), JSON.stringify(list, null, 2), "utf8");
}

/** The local half of the audit trail. The coord keeps its own; they should agree. */
export function recordDelivered(entry: unknown): void {
  const line = JSON.stringify({ at: new Date().toISOString(), ...(entry as object) }) + "\n";
  const f = paths.delivered();
  if (!existsSync(f)) writeFileSync(f, "", "utf8");
  writeFileSync(f, readFileSync(f, "utf8") + line, "utf8");
}
