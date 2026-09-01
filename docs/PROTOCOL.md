# The Bridle protocol, v0.1

Enough to write your own coordination server, or your own client, without reading ours.

The client half — envelopes, signing, sealing, policy — is Apache-2.0 in this repository.
The coordination server we operate is not open source. This document exists so that does not
matter: it is a relay with an address book, and the security of the protocol does not depend
on it behaving.

---

## What the coordination server is trusted with

Almost nothing, deliberately.

It **can**: route by node name, verify signatures, refuse an envelope, and hold one until the
recipient collects it. It **cannot**: read a payload, forge an envelope, or grant itself a
scope on anyone's node.

Payloads are sealed to the recipient's X25519 key before the envelope is signed, so a relay
holds ciphertext. Policy is evaluated on the receiving machine against a file the server never
sees. A hostile coordination server can deny service and learn who talks to whom; it cannot
read the work or put words in anyone's mouth.

That is the property that makes running your own optional rather than necessary.

## Envelope

```jsonc
{
  "v": 1,
  "id": "uuid-v4",
  "ts": "2026-08-31T09:00:00.000Z",
  "verb": "context.push",          // or task.queue | state.read | run.request
  "from": "marko.dev",
  "fromKey": "<base64 SPKI Ed25519>",
  "to": "ana.dev",
  "scope": { "repo": "pai-frontend" },
  "ref": "uuid-of-the-envelope-this-answers",   // optional
  "sealed": { "epk": "…", "iv": "…", "ct": "…", "tag": "…" },
  "sig": "<base64 Ed25519>"
}
```

Node names match `^[a-z0-9][a-z0-9._-]{1,62}$` and are unique **within an org**, not globally.

### Canonical form

Signing and verification depend on both sides serialising identically. Sort object keys at
every level, drop `undefined`, no whitespace:

```
canonical({b:1, a:2})        →  {"a":2,"b":1}
canonical({x:[{b:1, a:2}]})  →  {"x":[{"a":2,"b":1}]}
```

The signature covers the canonical form of the envelope **minus `sig`** — including `sealed`,
so a relay cannot swap ciphertext between envelopes.

### Sealing

X25519 ECDH with an ephemeral sender key → HKDF-SHA256 → AES-256-GCM.

- salt: `epk || "|" || recipientSealPublicKey`
- info: `"bridle/seal/v1|" || envelope.id`
- AAD: `envelope.id`

Binding the id means a sealed box lifted into a different envelope fails to open rather than
opening wrong. **Seal before signing**, never after.

### Verbs

| verb | payload | default |
|---|---|---|
| `context.push` | `{ note?, decision?, files?, links?, status? }` | allow |
| `task.queue` | `{ title, detail?, repo? }` | allow |
| `state.read` | `{ fields: [branch\|diffstat\|openFiles\|task] }` | allow |
| `run.request` | `{ command, cwd?, reason? }` | **ask** |

The set is closed. A protocol that can express anything is one you cannot write a policy for.

## Receiving

In this order, and the order matters:

1. **Verify the signature against the key you granted** — not the key in the envelope. A valid
   signature from an unexpected key is an impostor, not a peer.
2. **Open the seal**, then re-validate the payload. Decrypting is not evidence of well-formedness.
3. **Evaluate policy.** Deny beats ask beats allow, so a rule can only ever make the outcome
   stricter. Never-rules outrank explicit grants.
4. **Render as data.** Fence the payload in a delimiter carrying a random nonce, under a header
   saying it is data from another person. Anything less and a note that reads like an
   instruction becomes one.

A reply — an envelope whose `ref` names something you sent, from the exact key you sent it to,
carrying only a status — is implicitly permitted. Asking someone to do work implies permission
to hear how it went, and nothing further.

## What a coordination server must do

```
POST /v1/register        { name, key, sealKey, invite } → { name, token }
POST /v1/invite          → { code }                       (auth)
GET  /v1/peers           → { peers: [{ name, key, sealKey }] }
POST /v1/envelope        { envelope } → 202               (auth)
GET  /v1/inbox           → { envelopes }                  (auth)
POST /v1/ack             { id, verdict, reason?, heldMs? }  (auth)
GET  /v1/audit           → { events }                     (auth)
GET  /health             → { ok, orgs, nodes }
```

Bearer token auth. Point a client at yours with `bridle join --coord https://your-host`.

Rules a conforming server must not break:

- Refuse an envelope whose `from` is not the authenticated node, or whose `fromKey` is not that
  node's registered key.
- Refuse an unsealed envelope.
- Scope every read to the caller's org. Return the same 404 for a node in another org as for one
  that does not exist — an error must not be usable to probe what lives on the server.
- An invite decides which org a node joins. There must be no way to name an org directly.

## Audit

Both halves of the trail are **metadata only**: verbs, names, sizes, timestamps, verdicts and
the reasons behind them. That is the whole budget. A server records what its routing layer
already sees — an envelope queued, fetched, acked; the verdict and reason the receiving node
chose to report; `heldMs` when a human's approval settled it. Payload content, sealed or
opened, must never enter an event. The log stays replayable precisely because it never holds
anything worth stealing.

The receiving node keeps the richer half locally, because only it can: which grant admitted an
envelope, how long a held item waited for its operator and why they decided as they did, how a
`run.request` reported back (passed, failed, reverted) and how long it ran, and when each grant
last admitted anything — a grant that never does is a standing permission waiting to be revoked.
On an ack, `verdict` is `allow`, `ask` or `deny`; `reason` is a short code or the operator's own
words, never payload. Both fields are optional on the wire and a server must tolerate their
absence — logs written by older nodes still have to replay.
