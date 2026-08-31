import { randomUUID, createHash } from "node:crypto";
import type { SealedBox } from "./seal.js";

/**
 * The four verbs. This list is closed on purpose: a protocol that can express
 * anything is a protocol you cannot write a policy for.
 */
export const VERBS = ["context.push", "task.queue", "state.read", "run.request"] as const;
export type Verb = (typeof VERBS)[number];

export type Verdict = "allow" | "ask" | "deny";

/** Where a piece of handed-off work has got to. */
export const TASK_STATUSES = ["accepted", "working", "done", "blocked"] as const;
export type TaskStatus = (typeof TASK_STATUSES)[number];

export interface ContextPush {
  note?: string;
  decision?: string;
  /** Present when this push reports on work someone handed you. */
  status?: TaskStatus;
  files?: { path: string; sha256: string; bytes: number; content?: string }[];
  links?: string[];
}
export interface TaskQueue {
  title: string;
  detail?: string;
  repo?: string;
}
export interface StateRead {
  fields: ("branch" | "diffstat" | "openFiles" | "task")[];
}
export interface RunRequest {
  command: string;
  cwd?: string;
  reason?: string;
}

export type Payload = ContextPush | TaskQueue | StateRead | RunRequest;

export interface Envelope {
  /** Protocol version. Bumped only for breaking envelope changes. */
  v: 1;
  id: string;
  ts: string;
  verb: Verb;
  /** Sending node name, e.g. "marko.dev". */
  from: string;
  /** Sender's Ed25519 public key, base64. Carried so a receiver can verify offline. */
  fromKey: string;
  /** Receiving node name. */
  to: string;
  scope: { repo?: string; tools?: string[] };
  /**
   * The envelope this one answers. Set when reporting back on work someone
   * handed you, so the sender can correlate a reply with what they asked for.
   */
  ref?: string;
  /** Present before sealing and after opening. Never on the wire. */
  payload?: Payload;
  /** What actually crosses the relay. The relay cannot open this. */
  sealed?: SealedBox;
  /** Base64 Ed25519 signature over the canonical form of every field above. */
  sig?: string;
}

/**
 * Deterministic serialisation for signing. Keys are sorted at every level so
 * two implementations in two languages agree byte-for-byte.
 */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value) ?? "null";
  if (Array.isArray(value)) return "[" + value.map(canonical).join(",") + "]";
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).filter((k) => obj[k] !== undefined).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonical(obj[k])).join(",") + "}";
}

/** The exact bytes that get signed: the envelope minus its own signature. */
export function signingBytes(env: Envelope): Buffer {
  const { sig: _drop, ...rest } = env;
  return Buffer.from(canonical(rest), "utf8");
}

export function envelopeDigest(env: Envelope): string {
  return createHash("sha256").update(signingBytes(env)).digest("hex");
}

export interface DraftEnvelope {
  ref?: string;
  verb: Verb;
  from: string;
  fromKey: string;
  to: string;
  payload: Payload;
  scope?: { repo?: string; tools?: string[] };
  /** Injectable for tests; defaults to now. */
  ts?: string;
  id?: string;
}

export function createEnvelope(draft: DraftEnvelope): Envelope {
  return {
    v: 1,
    id: draft.id ?? randomUUID(),
    ts: draft.ts ?? new Date().toISOString(),
    verb: draft.verb,
    from: draft.from,
    fromKey: draft.fromKey,
    to: draft.to,
    scope: draft.scope ?? {},
    ...(draft.ref ? { ref: draft.ref } : {}),
    payload: draft.payload,
  };
}

export class EnvelopeError extends Error {}

const NAME_RE = /^[a-z0-9][a-z0-9._-]{1,62}$/i;

/**
 * Structural validation. This runs before anything else touches an envelope —
 * a malformed envelope is rejected, never "best-effort" interpreted.
 */
export function validateEnvelope(input: unknown): Envelope {
  if (typeof input !== "object" || input === null) throw new EnvelopeError("envelope must be an object");
  const e = input as Record<string, unknown>;

  if (e.v !== 1) throw new EnvelopeError(`unsupported envelope version: ${String(e.v)}`);
  for (const field of ["id", "ts", "from", "fromKey", "to"] as const) {
    if (typeof e[field] !== "string" || !(e[field] as string).length) {
      throw new EnvelopeError(`missing or invalid field: ${field}`);
    }
  }
  if (!VERBS.includes(e.verb as Verb)) throw new EnvelopeError(`unknown verb: ${String(e.verb)}`);
  if (!NAME_RE.test(e.from as string)) throw new EnvelopeError("invalid sender name");
  if (!NAME_RE.test(e.to as string)) throw new EnvelopeError("invalid recipient name");
  if (Number.isNaN(Date.parse(e.ts as string))) throw new EnvelopeError("invalid timestamp");
  if (e.ref !== undefined && (typeof e.ref !== "string" || !e.ref.length)) {
    throw new EnvelopeError("ref must be an envelope id");
  }
  if (typeof e.scope !== "object" || e.scope === null) throw new EnvelopeError("scope must be an object");

  const hasPayload = typeof e.payload === "object" && e.payload !== null;
  const hasSealed = typeof e.sealed === "object" && e.sealed !== null;
  if (!hasPayload && !hasSealed) throw new EnvelopeError("envelope carries neither a payload nor a sealed box");
  if (hasPayload && hasSealed) throw new EnvelopeError("envelope carries both a payload and a sealed box");
  if (hasSealed) {
    for (const f of ["epk", "iv", "ct", "tag"] as const) {
      if (typeof (e.sealed as Record<string, unknown>)[f] !== "string") {
        throw new EnvelopeError(`sealed box is missing ${f}`);
      }
    }
  }
  if (hasPayload) validatePayload(e.verb as Verb, e.payload as Record<string, unknown>);
  return e as unknown as Envelope;
}

export function validatePayload(verb: Verb, p: Record<string, unknown>): void {
  const str = (v: unknown) => typeof v === "string";
  switch (verb) {
    case "context.push":
      if (p.note !== undefined && !str(p.note)) throw new EnvelopeError("context.push.note must be a string");
      if (p.decision !== undefined && !str(p.decision)) throw new EnvelopeError("context.push.decision must be a string");
      if (p.files !== undefined && !Array.isArray(p.files)) throw new EnvelopeError("context.push.files must be an array");
      if (p.links !== undefined && !Array.isArray(p.links)) throw new EnvelopeError("context.push.links must be an array");
      if (p.status !== undefined && !TASK_STATUSES.includes(p.status as TaskStatus)) {
        throw new EnvelopeError(`unknown status: ${String(p.status)}`);
      }
      if (
        p.note === undefined && p.decision === undefined && p.files === undefined &&
        p.links === undefined && p.status === undefined
      ) {
        throw new EnvelopeError("context.push needs at least one of: note, decision, files, links, status");
      }
      return;
    case "task.queue":
      if (!str(p.title) || !(p.title as string).trim()) throw new EnvelopeError("task.queue.title is required");
      return;
    case "state.read": {
      if (!Array.isArray(p.fields) || p.fields.length === 0) throw new EnvelopeError("state.read.fields is required");
      const allowed = new Set(["branch", "diffstat", "openFiles", "task"]);
      for (const f of p.fields) if (!allowed.has(f as string)) throw new EnvelopeError(`unknown state field: ${String(f)}`);
      return;
    }
    case "run.request":
      if (!str(p.command) || !(p.command as string).trim()) throw new EnvelopeError("run.request.command is required");
      return;
  }
}

/** Size of what is actually carried — ciphertext while sealed, plaintext once open. */
export function payloadBytes(env: Envelope): number {
  if (env.sealed) return Buffer.from(env.sealed.ct, "base64").byteLength;
  return Buffer.byteLength(canonical(env.payload), "utf8");
}
