import { readFileSync } from "node:fs";
import { basename } from "node:path";
import { createHash } from "node:crypto";
import {
  createEnvelope, sealEnvelope, signEnvelope, openEnvelope, verifyFrom,
  evaluate, renderForAgent, summarise, fingerprint,
  auditPolicyDecision, auditOperatorDecision, auditRunOutcome, timeToApproval,
  type Envelope, type Payload, type Verb, type Decision, type TaskStatus,
} from "bridle-core";
import { api } from "./client.js";
import {
  readIdentity, readPolicy, writePolicy, readPending, writePending, recordDelivered,
  readOutbox, writeOutbox, readReceived, writeReceived, markGrantUsed,
} from "./home.js";

export interface SendOptions {
  to: string;
  verb: Verb;
  payload: Payload;
  repo?: string;
  /** The envelope this answers, when reporting back on work someone sent. */
  ref?: string;
}

/** Build → seal → sign → hand to the relay. In that order, always. */
export async function send(opts: SendOptions): Promise<{ id: string }> {
  const identity = readIdentity();
  const { peers } = await api.peers();
  const peer = peers.find((p) => p.name === opts.to);
  if (!peer) throw new Error(`no node named "${opts.to}" in this bridlenet`);

  const draft = createEnvelope({
    ...(opts.ref ? { ref: opts.ref } : {}),
    verb: opts.verb,
    from: identity.name,
    fromKey: identity.publicKey,
    to: opts.to,
    payload: opts.payload,
    scope: opts.repo ? { repo: opts.repo } : {},
  });
  const signed = signEnvelope(sealEnvelope(draft, peer.sealKey), identity);
  await api.send(signed);

  // Remember what we handed over, and to which key. A reply only counts if it
  // comes back from that exact key, referencing that exact envelope.
  const outbox = readOutbox();
  outbox[signed.id] = {
    id: signed.id,
    to: opts.to,
    toKey: peer.key,
    verb: opts.verb,
    summary: summarise({ ...draft, payload: opts.payload } as Envelope),
    sentAt: signed.ts,
  };
  writeOutbox(outbox);

  return { id: signed.id };
}

/** Report back on work someone handed this node. */
export async function report(
  shortId: string,
  status: TaskStatus,
  note?: string
): Promise<{ id: string; to: string; about: string }> {
  const received = readReceived();
  const entry = Object.values(received).find((r) => r.id.startsWith(shortId));
  if (!entry) throw new Error(`nothing received with an id starting "${shortId}" — try \`bridle work\``);

  const { id } = await send({
    to: entry.from,
    verb: "context.push",
    ref: entry.id,
    payload: note ? { status, note } : { status },
  });

  // Reporting on a run.request closes the loop on this side too: our trail
  // records how the run came out and how long we sat on it.
  if (entry.verb === "run.request") {
    const outcome = auditRunOutcome({
      id: entry.id,
      from: entry.from,
      to: readIdentity().name,
      status,
      startedAt: entry.at,
      reportedAt: new Date().toISOString(),
    });
    if (outcome) recordDelivered(outcome);
  }
  return { id, to: entry.from, about: entry.summary };
}

export function fileToAttachment(path: string): NonNullable<Parameters<typeof buildContext>[0]["files"]>[number] {
  const content = readFileSync(path, "utf8");
  return {
    path: basename(path),
    sha256: createHash("sha256").update(content).digest("hex"),
    bytes: Buffer.byteLength(content, "utf8"),
    content,
  };
}

export function buildContext(input: {
  note?: string;
  decision?: string;
  files?: { path: string; sha256: string; bytes: number; content?: string }[];
  links?: string[];
}): Payload {
  return input as Payload;
}

export interface Processed {
  envelope: Envelope;
  decision: Decision;
  rendered?: string;
  error?: string;
}

/**
 * Run the inbox through the full receive path: verify the signature against the
 * key we granted, open the seal, re-validate, then evaluate this node's policy.
 *
 * `collect` is the difference between looking and taking. Reading your own queue
 * used to acknowledge every envelope in it, so an operator glancing at what was
 * waiting silently consumed their agent's work — and an ack is recorded on both
 * sides, so there was nothing to undo. Peeking now changes nothing at all: no
 * acks, no pending file, no delivery log.
 */
async function processInbox(collect: boolean): Promise<Processed[]> {
  const identity = readIdentity();
  const policy = readPolicy();
  const { envelopes } = await api.inbox();
  const out: Processed[] = [];
  const pending = readPending();
  const ack = async (id: string, verdict: string, reason?: string) => {
    if (collect) await api.ack(id, verdict, reason);
  };

  for (const sealedEnv of envelopes) {
    // Already held for a human — leave it alone rather than re-listing it on
    // every poll. `bridle pending` is where held work lives.
    if (pending.some((p) => p.envelope.id === sealedEnv.id)) continue;

    // A reply to work we handed over verifies against the key we sent to,
    // even when that peer holds no grant here.
    const outbox = readOutbox();
    const answers = sealedEnv.ref ? outbox[sealedEnv.ref] : undefined;
    const impliedReply = Boolean(answers && answers.to === sealedEnv.from && answers.toKey === sealedEnv.fromKey);

    const grantedKey = policy.peers[sealedEnv.from]?.key ?? (impliedReply ? answers!.toKey : undefined);
    const v = verifyFrom(sealedEnv, grantedKey);
    if (!v.ok) {
      const decision: Decision = { verdict: "deny", reasons: [{ code: "unverified", detail: v.reason!, verdict: "deny" }], payload: {}, redacted: [] };
      await ack(sealedEnv.id, "deny", v.reason);
      if (collect) recordDelivered(auditPolicyDecision(sealedEnv, decision));
      out.push({ envelope: sealedEnv, decision, error: v.reason });
      continue;
    }

    let opened: Envelope;
    try {
      opened = openEnvelope(sealedEnv, { publicKey: identity.sealPublicKey, privateKey: identity.sealPrivateKey });
    } catch (err) {
      const decision: Decision = { verdict: "deny", reasons: [{ code: "unsealable", detail: (err as Error).message, verdict: "deny" }], payload: {}, redacted: [] };
      await ack(sealedEnv.id, "deny", (err as Error).message);
      if (collect) recordDelivered(auditPolicyDecision(sealedEnv, decision));
      out.push({ envelope: sealedEnv, decision, error: (err as Error).message });
      continue;
    }

    const decision = evaluate(opened, policy, { signatureOk: true, impliedReply });

    if (decision.verdict === "deny") {
      await ack(opened.id, "deny", decision.reasons.find((r) => r.verdict === "deny")?.code);
      if (collect) recordDelivered(auditPolicyDecision(opened, decision));
      out.push({ envelope: opened, decision });
      continue;
    }
    if (decision.verdict === "ask") {
      if (collect && !pending.some((p) => p.envelope.id === opened.id)) {
        const heldAt = new Date().toISOString();
        pending.push({ envelope: opened, decision, heldAt });
        recordDelivered(auditPolicyDecision(opened, decision, { heldAt }));
      }
      out.push({ envelope: opened, decision });
      continue;
    }

    if (collect) {
      recordDelivered(auditPolicyDecision(opened, decision));
      if (decision.grant) markGrantUsed(decision.grant);
      deliver(opened, identity.name);
      await api.ack(opened.id, "allow");
    }
    out.push({ envelope: opened, decision, rendered: renderForAgent(opened, decision) });
  }

  if (collect) writePending(pending);
  return out;
}

/**
 * Files an accepted envelope where its follow-up lives: a status report folds
 * into the outbox entry it answers — closing the run.request loop with an
 * outcome and a duration — and anything else lands in `bridle work`. Shared by
 * the collect path and by approvals, so held work is deliverable too.
 */
function deliver(opened: Envelope, selfName: string): void {
  const status = (opened.payload as { status?: TaskStatus; note?: string } | undefined)?.status;
  const box = readOutbox();
  const answers = opened.ref ? box[opened.ref] : undefined;
  const isReply = Boolean(answers && answers.to === opened.from && answers.toKey === opened.fromKey);

  if (isReply && status && answers) {
    // Fold the report into the record of what we asked for.
    answers.status = status;
    answers.note = (opened.payload as { note?: string }).note;
    answers.updatedAt = opened.ts;
    writeOutbox(box);

    if (answers.verb === "run.request") {
      const outcome = auditRunOutcome({
        id: answers.id,
        from: selfName,
        to: answers.to,
        status,
        startedAt: answers.sentAt,
        reportedAt: opened.ts,
      });
      if (outcome) recordDelivered(outcome);
    }
    return;
  }

  const inbound = readReceived();
  inbound[opened.id] = {
    id: opened.id,
    from: opened.from,
    verb: opened.verb,
    summary: summarise(opened),
    at: opened.ts,
  };
  writeReceived(inbound);
}

/** Look at what is waiting. Changes nothing, on either side. */
export const peek = (): Promise<Processed[]> => processInbox(false);

/** Take delivery: evaluate, hold what needs a human, acknowledge the rest. */
export const collect = (): Promise<Processed[]> => processInbox(true);

/** @deprecated use `collect` — kept so existing callers keep working. */
export const receive = collect;

/**
 * The second key. Nothing held at `ask` moves without this.
 *
 * The trail records who waited and for how long — held-at to decided-at — and
 * the reason the operator gave, so an approval is accountable and a denial is
 * explicable months later.
 */
export async function decide(id: string, verdict: "allow" | "deny", reason?: string): Promise<Processed> {
  const pending = readPending();
  const idx = pending.findIndex((p) => p.envelope.id.startsWith(id));
  if (idx === -1) throw new Error(`nothing pending with id starting "${id}"`);
  const held = pending[idx]!;
  pending.splice(idx, 1);
  writePending(pending);

  const decidedAt = new Date().toISOString();
  const heldAt = held.heldAt ?? decidedAt; // pending files predating heldAt still decide cleanly
  await api.ack(held.envelope.id, verdict, reason ?? "operator", timeToApproval(heldAt, decidedAt));
  recordDelivered(
    auditOperatorDecision(held.envelope, verdict, { heldAt, at: decidedAt, reason, grant: held.decision.grant })
  );

  if (verdict === "allow") {
    // Approval is the moment the grant actually admitted something, and the
    // moment the work becomes real here — file it so it can be reported on.
    if (held.decision.grant) markGrantUsed(held.decision.grant, decidedAt);
    deliver(held.envelope, readIdentity().name);
  }

  return {
    envelope: held.envelope,
    decision: { ...held.decision, verdict },
    rendered: verdict === "allow" ? renderForAgent(held.envelope, held.decision) : undefined,
  };
}

export async function grant(peer: string, opts: { repos?: string[]; verbs?: Verb[] }): Promise<void> {
  const policy = readPolicy();
  // A node granting itself is meaningless, and a policy file quietly holding a
  // self-grant is the kind of state nobody can explain later. Refuse it outright.
  if (peer === readIdentity().name) {
    throw new Error(`"${peer}" is this node — a node cannot grant itself`);
  }
  const { peers } = await api.peers();
  const known = peers.find((p) => p.name === peer);
  if (!known) throw new Error(`no node named "${peer}" in this bridlenet`);
  policy.peers[peer] = {
    key: known.key,
    repos: opts.repos ?? policy.peers[peer]?.repos ?? [],
    verbs: opts.verbs ?? policy.peers[peer]?.verbs ?? ["context.push", "task.queue"],
    overrides: policy.peers[peer]?.overrides ?? {},
  };
  writePolicy(policy);
}

export function revoke(peer: string): void {
  const policy = readPolicy();
  if (!policy.peers[peer]) throw new Error(`no grant for "${peer}"`);
  delete policy.peers[peer];
  writePolicy(policy);
}

export { summarise, fingerprint };
