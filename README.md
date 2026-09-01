# Bridle

**Tailscale for agents.** An open protocol that lets your coding agent hand work to a
teammate's agent — push context, queue a task, request a run — where both ends have opted
in and every action passes the receiving side's policy before it lands.

> A bridle steers a horse without breaking it, and handing someone the reins is exactly the
> move this is for. *Unbridled* is the failure mode: one agent reaching into another with
> nothing in between.

Status: **pre-release**, spec v0.1. The protocol is small and the code is meant to be read
before it is trusted.

---

## The shape of it

| Tailscale | Bridle |
|---|---|
| `tailscale up` on every device | `bridle up` in every agent session — **both ends, always** |
| tailnet | bridlenet |
| node key, device approval | Ed25519 identity, approved by its own operator |
| ACL policy file | `bridle.policy.yaml` |
| coordination server | Bridle Cloud, or your own |
| Headscale | write your own — the protocol is specified in `docs/PROTOCOL.md` |

## The four verbs

The list is closed on purpose. A protocol that can express anything is one you cannot write
a policy for.

| verb | what it does | default |
|---|---|---|
| `context.push` | attach a note, file, link or decision to a running session | allow |
| `task.queue` | enqueue work the receiving agent picks up when idle | allow |
| `state.read` | read what the agent is working on, redacted by policy | allow |
| `run.request` | ask the agent to execute now, with its own tools | **ask** |

## Try it

```bash
npm install && npm run build && npm test
npm run demo

# to get the `bridle` command on your PATH (the bin lives in the cli package,
# not at the root — `npm link` from the root links nothing usable)
cd packages/cli && npm link
```

`npm test` covers the trust-critical half: canonical form, signatures, the impostor case,
sealing, replay, policy precedence, redaction, and that a payload cannot escape the render
fence. No coordination server needed — none of it depends on one.

## Use it

```bash
# on each machine — this is the opt-in, and there is no way around it
bridle up                        # authorises in a browser, no invite code needed
bridle up --offline              # keys + policy only, join later
bridle join --coord https://your-coord --invite ABCD-EF01   # your own server

# your teammate decides what you may send them
bridle grant marko.dev --repo pai-frontend --verbs context.push,task.queue

# then
bridle send ana.dev --decision "keep RLS on for the wa_ tables" --repo pai-frontend
bridle queue ana.dev --title "retry migration" --repo pai-frontend
bridle ask   ana.dev --command "pnpm test --filter api"   # stops at her approval

bridle inbox        # verify, open, evaluate
bridle pending      # what is waiting on you, and for how long
bridle approve 81df --reason "staging only"   # the second key, on the record

bridle audit          # this node's trail: verdicts, reasons, waits, run outcomes
bridle audit --grants # which grants are earning their keep — revoke the ones that are not
```

An agent drives the same CLI. Anything with a shell — a coding agent, a headless
run in CI — hands work across by running `bridle send` the way it runs `git`. That
is the whole integration surface; there is no per-vendor client to install.

## What makes it safe

**Both ends opt in.** A bridle does not exist until both operators have run `bridle up` and
the receiving side has granted a scope. There is no directory, no discovery, no
reachable-by-default, and no admin who can open one for you.

**An envelope, not a prompt.** Actions are typed, signed JSON. When accepted work is handed
to the receiving agent it is fenced inside a block whose delimiter carries a random nonce, so
no content inside it can close the fence and continue as instructions. The header says, in
the agent's own context, that everything inside is data written by someone else.

**The relay cannot read your work.** Payloads are sealed to the recipient's X25519 key
(ECDH → HKDF-SHA256 → AES-256-GCM, with the envelope id bound in as additional data, so a
sealed box cannot be replayed inside a different envelope). The coordination server verifies
signatures and routes by name. It never sees a payload — which is what makes self-hosting a
real choice rather than a slogan.

**Deny beats ask beats allow.** Adding a policy rule can only ever make the outcome stricter.
Never-rules outrank explicit grants: if `git push` is in `never`, no grant permits it.

**Identity is checked, not claimed.** A valid signature is not enough — the key must be the
one you granted a scope to. Otherwise anyone could sign as anyone by bringing their own key.

**Replayable audit.** The coordination server's state *is* an append-only event log; the
projection is rebuilt from it on boot. Each node keeps its own, richer half: every verdict with
the reasons behind it, which grant admitted what and when each grant last admitted anything
(`bridle audit --grants` names the ones worth revoking), how long every approval kept the sender
waiting and what the operator said, and how a `run.request` came out. All of it is metadata —
verbs, names, sizes, timestamps, verdicts. Payload content never enters either log, so the
trail can be kept and replayed without weakening the seal on anything it describes.

**Orgs never leak into each other.** Every node, invite, queue and audit entry is keyed by org.
Node names are unique only *within* an org, so two teams can both have a `marko.dev`. Sending to
a name that exists only in another org returns the same 404 as a name that exists nowhere — the
error must not confirm what lives elsewhere on the server. Which org a node joins is decided
entirely by the invite it was given; a node cannot ask for one.

### What is not true yet

- There is no production open-source coordination server. `docs/PROTOCOL.md` specifies one
  completely — `npm run demo` spawns a toy server written from that document alone
  (`scripts/demo-coord.mjs`) — and the security of the protocol does not rest on it: payloads
  are sealed to the recipient and policy runs on the receiving machine. A hardened one is
  currently your job or Bridle Cloud's.
- There is no relay for agents that cannot reach the coordination server directly.
- **Twice during development a policy file gained an entry that no version of this code can
  produce** — a node granting itself, and a repo scope appearing when none was passed. Neither
  reproduced. Self-grants are now refused outright, policy writes are atomic, and every write
  logs the argv that caused it, so a third occurrence would be attributable. The mechanism is
  still unknown, and on a tool whose entire job is deciding what is permitted, that is worth
  saying out loud rather than discovering later.
- The receive pipeline in `packages/cli/src/actions.ts` has no tests. The 63 cover the parts
  where being wrong is unrecoverable — envelopes, signatures, sealing, policy, the render
  fence — and the CLI orchestration around them is currently covered only by use.
- The MCP server is not shipping in v0. It builds and answers a tools/list handshake, but it
  has no tests and is not part of the supported surface.
- The Postgres backend has no integration test against a live database — the unit suite covers
  the JSONL backend only, so the two could drift.
- `state.read` defines the wire format but has no collector wired to a real editor session.
- Delivery is poll-based (`bridle inbox`). Live push is not implemented.
- The redaction pass is a safety net, not a guarantee. Policy refusing a field by name is the
  guarantee; regexes are what catch the rest.

## Layout

```
packages/core     envelope, identity, sealing, policy, redaction, rendering  (44 tests)
packages/coord    the control plane: org-scoped, two storage backends           (18 tests)
packages/cli      bridle — up, join, grant, send, inbox, approve
packages/mcp      an MCP server over the same nine capabilities — built, smoke-tested,
                  and deliberately not part of v0. The CLI has to be the thing that works
                  first; MCP is a convenience on top of it, not the way in.
apps/dashboard    Bridle Cloud: social sign-in, device approval, activity
```

Storage is behind one interface with two implementations: an append-only JSONL log for
self-hosting a single process, and Postgres for the hosted deployment, where a serverless
invocation cannot afford to replay history on every cold start. See `docs/cloud-setup.md`.

## Licence

 and  — the half that holds your keys and enforces your policy —
are **Apache-2.0**. They have to be readable, or none of the security claims above can be
checked by the person relying on them.

The coordination server and dashboard are **not** open source.

That is defensible only because of where the trust actually sits. A coordination server routes
by name and holds sealed boxes; it cannot read a payload, cannot forge an envelope, and cannot
grant itself a scope on your node. Policy is evaluated on your machine against a file it never
sees. So the half you have to trust is the half you can read, and `docs/PROTOCOL.md` specifies
the other half completely enough to replace.
