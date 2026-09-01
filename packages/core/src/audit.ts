import { payloadBytes, type Envelope, type TaskStatus, type Verb, type Verdict } from "./envelope.js";
import type { Decision, PeerGrant, Policy, Reason } from "./policy.js";

/**
 * The audit trail's vocabulary, and the arithmetic behind it.
 *
 * Everything in an entry is metadata the local policy engine or the relay's
 * routing layer already sees: verbs, names, sizes, timestamps, verdicts and the
 * reasons for them. Payload content never appears here — the builders work from
 * an envelope's routing fields and the decision about it, never from what it
 * carries — so a trail can be kept, shipped and replayed without weakening the
 * seal on anything it describes.
 */

/** How a run.request execution ended, as far as a status report makes that observable. */
export const RUN_OUTCOMES = ["passed", "failed", "reverted"] as const;
export type RunOutcome = (typeof RUN_OUTCOMES)[number];

/**
 * One line of the audit trail. Older logs recorded only
 * `{ at, id, from, verb, verdict }` — every later field is optional so those
 * lines still project, unchanged, alongside new ones.
 */
export interface AuditEntry {
  /** When the entry was recorded. */
  at: string;
  /** The envelope this entry is about. */
  id: string;
  verb: Verb;
  from: string;
  to?: string;
  repo?: string;
  /** The envelope this one answered, for report entries. */
  ref?: string;
  /** The grant the evaluation ran under — the peer name it is filed by. */
  grant?: string;
  verdict: Verdict;
  /** The policy engine's reasons, verbatim. Codes and rule details, never payload. */
  reasons?: Reason[];
  /** Size of what crossed — ciphertext or its plaintext, both visible locally. */
  bytes?: number;
  /** Names of secret *types* the redactor stripped, e.g. "github-token". */
  redacted?: string[];
  /** Who settled it: the policy alone, or an operator turning the second key. */
  decidedBy?: "policy" | "operator";
  /** The operator's stated reason for an approve or a deny. */
  reason?: string;
  /** When the envelope was held for a human, and when one decided. */
  heldAt?: string;
  decidedAt?: string;
  /** decidedAt minus heldAt — how long the sender waited on a person. */
  waitedMs?: number;
  /** For run.request handoffs that reported back: how it went, and how long. */
  outcome?: RunOutcome;
  runMs?: number;
}

/** How long a held envelope waited for a human. Clock skew cannot make it negative. */
export function timeToApproval(heldAt: string, decidedAt: string): number {
  return Math.max(0, Date.parse(decidedAt) - Date.parse(heldAt));
}

/** An entry for a verdict the policy engine just reached on an inbound envelope. */
export function auditPolicyDecision(
  env: Envelope,
  decision: Decision,
  opts: { at?: string; heldAt?: string } = {}
): AuditEntry {
  const at = opts.at ?? new Date().toISOString();
  const entry: AuditEntry = {
    at,
    id: env.id,
    verb: env.verb,
    from: env.from,
    to: env.to,
    verdict: decision.verdict,
    decidedBy: "policy",
    reasons: decision.reasons,
    bytes: payloadBytes(env),
  };
  if (env.scope.repo) entry.repo = env.scope.repo;
  if (env.ref) entry.ref = env.ref;
  if (decision.grant) entry.grant = decision.grant;
  if (decision.redacted.length) entry.redacted = decision.redacted;
  if (decision.verdict === "ask") entry.heldAt = opts.heldAt ?? at;
  return entry;
}

/** The operator's half: a held envelope approved or denied, and how long that took. */
export function auditOperatorDecision(
  env: Envelope,
  verdict: "allow" | "deny",
  opts: { heldAt: string; at?: string; reason?: string; grant?: string }
): AuditEntry {
  const at = opts.at ?? new Date().toISOString();
  const entry: AuditEntry = {
    at,
    id: env.id,
    verb: env.verb,
    from: env.from,
    to: env.to,
    verdict,
    decidedBy: "operator",
    heldAt: opts.heldAt,
    decidedAt: at,
    waitedMs: timeToApproval(opts.heldAt, at),
  };
  if (env.scope.repo) entry.repo = env.scope.repo;
  if (env.ref) entry.ref = env.ref;
  if (opts.grant) entry.grant = opts.grant;
  if (opts.reason) entry.reason = opts.reason;
  return entry;
}

/**
 * What a status report makes observable about a run: done means it passed,
 * blocked means it failed. A run still in flight has no outcome yet, and
 * "reverted" waits on a protocol revision that can carry it.
 */
export function runOutcomeFromStatus(status: TaskStatus): RunOutcome | undefined {
  return status === "done" ? "passed" : status === "blocked" ? "failed" : undefined;
}

/**
 * An entry for a run.request that reported back — outcome plus wall-clock
 * duration from handing it over to hearing how it went. Returns nothing while
 * the run is still in flight.
 */
export function auditRunOutcome(opts: {
  id: string;
  from: string;
  to: string;
  status: TaskStatus;
  startedAt: string;
  reportedAt: string;
  at?: string;
  repo?: string;
}): AuditEntry | undefined {
  const outcome = runOutcomeFromStatus(opts.status);
  if (!outcome) return undefined;
  const entry: AuditEntry = {
    at: opts.at ?? new Date().toISOString(),
    id: opts.id,
    verb: "run.request",
    from: opts.from,
    to: opts.to,
    verdict: "allow", // it only ran because it was allowed
    outcome,
    runMs: timeToApproval(opts.startedAt, opts.reportedAt),
  };
  if (opts.repo) entry.repo = opts.repo;
  return entry;
}

/**
 * Parses one line of an audit log, tolerantly. A line an older version wrote —
 * or one a human mangled — projects with its missing fields simply absent;
 * a line that is not an entry at all returns null rather than throwing mid-file.
 */
export function parseAuditLine(line: string): AuditEntry | null {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  if (typeof raw !== "object" || raw === null) return null;
  const e = raw as Record<string, unknown>;
  for (const field of ["at", "id", "verb", "from", "verdict"] as const) {
    if (typeof e[field] !== "string") return null;
  }
  return e as unknown as AuditEntry;
}

/** Mean and worst time-to-approval, per person kept waiting. */
export function approvalTimes(
  entries: AuditEntry[]
): Record<string, { count: number; meanMs: number; maxMs: number }> {
  const out: Record<string, { count: number; meanMs: number; maxMs: number }> = {};
  for (const e of entries) {
    if (e.decidedBy !== "operator" || typeof e.waitedMs !== "number") continue;
    const s = (out[e.from] ??= { count: 0, meanMs: 0, maxMs: 0 });
    s.meanMs = (s.meanMs * s.count + e.waitedMs) / (s.count + 1);
    s.count += 1;
    s.maxMs = Math.max(s.maxMs, e.waitedMs);
  }
  return out;
}

/** Per-grant usage, keyed by peer name. Timestamps and counts — nothing about what crossed. */
export interface GrantUse {
  lastUsedAt: string;
  uses: number;
}
export type GrantUsageMap = Record<string, GrantUse>;

/**
 * Stamps a grant as having just admitted an envelope. Returns a new map; an
 * out-of-order stamp bumps the count but can never move last-used backwards.
 */
export function stampGrantUse(usage: GrantUsageMap, peer: string, at: string): GrantUsageMap {
  const prev = usage[peer];
  return {
    ...usage,
    [peer]: {
      lastUsedAt: prev && prev.lastUsedAt > at ? prev.lastUsedAt : at,
      uses: (prev?.uses ?? 0) + 1,
    },
  };
}

/** One grant's standing: what it permits, when it last admitted anything, and whether it is dead weight. */
export interface GrantStanding {
  peer: string;
  grant: PeerGrant;
  lastUsedAt?: string;
  uses: number;
  unused: boolean;
}

/**
 * Every grant in the policy against its recorded usage. A grant is unused when
 * nothing has ever come in under it — or, given `unusedAfterMs`, when nothing
 * has for that long. Unused grants are standing permissions nobody is spending;
 * they exist to be revoked.
 */
export function grantStandings(
  policy: Policy,
  usage: GrantUsageMap,
  opts: { asOf?: string; unusedAfterMs?: number } = {}
): GrantStanding[] {
  const asOf = Date.parse(opts.asOf ?? new Date().toISOString());
  return Object.entries(policy.peers).map(([peer, grant]) => {
    const use = usage[peer];
    const stale =
      opts.unusedAfterMs !== undefined && use !== undefined
        ? asOf - Date.parse(use.lastUsedAt) > opts.unusedAfterMs
        : false;
    return {
      peer,
      grant,
      lastUsedAt: use?.lastUsedAt,
      uses: use?.uses ?? 0,
      unused: use === undefined || stale,
    };
  });
}

/** Just the prune list: grants nothing has come in under. */
export function unusedGrants(
  policy: Policy,
  usage: GrantUsageMap,
  opts: { asOf?: string; unusedAfterMs?: number } = {}
): GrantStanding[] {
  return grantStandings(policy, usage, opts).filter((s) => s.unused);
}
