#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { spawn } from "node:child_process";
import {
  readIdentity, readPolicy, readConfig, writeConfig, up, isUp, readPending, paths,
  bridleHome, workspaceRoot, defaultNodeName, adoptLegacyNode, localNodes,
  readOutbox, readReceived, readDelivered, readGrantUsage,
} from "./home.js";
import { api, device, DEFAULT_COORD } from "./client.js";
import { send, peek, collect, decide, grant, revoke, report, buildContext, fileToAttachment, summarise, fingerprint } from "./actions.js";
import { grantStandings, approvalTimes, type Verb } from "bridle-core";

const argv = process.argv.slice(2);
const cmd = argv[0];
const rest = argv.slice(1);

const flag = (n: string): string | undefined => {
  const i = rest.indexOf(`--${n}`);
  return i >= 0 ? rest[i + 1] : undefined;
};
const has = (n: string) => rest.includes(`--${n}`);
const positional = rest.filter((a, i) => !a.startsWith("--") && !(i > 0 && rest[i - 1]?.startsWith("--")));

const dim = (s: string) => `\x1b[2m${s}\x1b[0m`;
const bold = (s: string) => `\x1b[1m${s}\x1b[0m`;
const tone = (v: string) =>
  v === "allow" ? `\x1b[32m${v}\x1b[0m` : v === "ask" ? `\x1b[33m${v}\x1b[0m` : `\x1b[31m${v}\x1b[0m`;

/** Durations for humans: 90000 → "1m 30s". Audit output, not arithmetic. */
const fmtMs = (ms: number): string => {
  if (ms < 1000) return "<1s";
  const s = Math.round(ms / 1000);
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return s % 60 ? `${m}m ${s % 60}s` : `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return m % 60 ? `${h}h ${m % 60}m` : `${h}h`;
  return `${Math.floor(h / 24)}d`;
};

const HELP = `
${bold("bridle")} — hand work to a teammate's agent, under their policy.

  bridle up [--name <you>]                     enable this workspace and authorise it
                                               (one node per repo, not per machine)
  bridle up --offline                          keys + policy only, join later
  bridle join --coord <url> --invite <code>    join a bridlenet
  bridle share [--name <them>]                 everything a teammate needs, in one paste
  bridle invite                                just the raw invite code
  bridle peers                                 who else is on this bridlenet
  bridle grant <peer> --repo <r> --verbs a,b   let a peer send you specific things
  bridle revoke <peer>                         withdraw a grant

  bridle send <peer> --note "..." [--file f] [--decision "..."] [--repo r]
  bridle queue <peer> --title "..." [--detail "..."] [--repo r]
  bridle state <peer> --fields branch,diffstat
  bridle ask <peer> --command "pnpm test"

  bridle work                                  what you have been handed
  bridle done <id> [--note "..."]              tell the sender it is finished
  bridle working <id> | bridle blocked <id>    tell them where it got to
  bridle tasks                                 what you handed out, and what came back

  bridle inbox                                 look at what is waiting, change nothing
  bridle inbox --collect [--deliver]           take delivery: evaluate and acknowledge
  bridle pending                               work held for your approval, and for how long
  bridle approve <id> [--reason "..."]         the second key — the reason lands in the audit trail
  bridle deny <id> [--reason "..."]
  bridle access                                who you have opened this node to
  bridle set-coord <url>                       move this node to another coordination server
  bridle nodes                                 every node on this machine
  bridle audit                                 this node's trail: verdicts, reasons, waits, run outcomes
  bridle audit --grants                        grant usage — unused grants are there to be revoked
  bridle audit --coord                         the coordination server's half; the two should agree
  bridle status | bridle policy
`;

async function main(): Promise<void> {
  switch (cmd) {
    case "up": {
      const moved = adoptLegacyNode();
      if (moved) console.log(dim(`moved your existing node into ${moved.to}`));
      const name = flag("name") ?? readConfigName() ?? defaultNodeName();
      const { identity, created } = up(name);
      console.log(created ? `${bold("bridle is up")} as ${identity.name}` : `already up as ${identity.name}`);
      console.log(`  fingerprint  ${fingerprint(identity.publicKey)}`);
      console.log(`  workspace    ${workspaceRoot()}`);
      console.log(`  home         ${bridleHome()}`);

      if (readConfig().token) {
        console.log(`  bridlenet    ${readConfig().coord}`);
        return;
      }
      if (has("offline")) {
        console.log(dim("\nNothing can reach this node until you join a bridlenet and grant a scope."));
        return;
      }

      // No credential yet: authorise this device in a browser. `bridle join`
      // with an invite code remains the path for self-hosted coordination.
      const coord = flag("coord") ?? DEFAULT_COORD;
      const req = await device.start(coord, {
        name: identity.name,
        key: identity.publicKey,
        sealKey: identity.sealPublicKey,
      });
      console.log(`\n  To authorise this node, open:\n    ${bold(req.verificationUri)}`);
      console.log(`  and enter the code:\n    ${bold(req.userCode)}\n`);
      openBrowser(`${req.verificationUri}?code=${encodeURIComponent(req.userCode)}`);
      process.stdout.write(dim("  waiting for approval"));

      const deadline = Date.now() + req.expiresIn * 1000;
      for (;;) {
        if (Date.now() > deadline) throw new Error("timed out waiting for approval");
        await sleep(req.interval * 1000);
        const r = await device.poll(coord, req.deviceCode);
        if (r.status === "approved") {
          writeConfig({ coord, token: r.token });
          process.stdout.write("\n");
          console.log(`\n${bold("authorised")} as ${r.name}`);
          console.log(dim("Peers still cannot send you anything until you grant them a scope."));
          console.log(`\nBring in a teammate:  ${bold("bridle share")}`);
          return;
        }
        process.stdout.write(dim("."));
      }
    }

    case "join": {
      const coord = flag("coord");
      const invite = flag("invite");
      const name = flag("name");
      if (!coord || !invite) throw new Error("--coord and --invite are required");
      if (!isUp()) {
        if (!name) throw new Error("--name is required (this node is not up yet)");
        up(name);
      }
      const identity = readIdentity();
      const { token } = await api.register(coord, {
        name: identity.name,
        key: identity.publicKey,
        sealKey: identity.sealPublicKey,
        invite,
      });
      writeConfig({ coord, token });
      console.log(`${bold("joined")} ${coord} as ${identity.name}`);
      console.log(dim("Peers still cannot send you anything until you `bridle grant` them."));
      return;
    }

    case "invite": {
      const { code } = await api.invite();
      console.log(code);
      console.log(dim("Hand this to one teammate. It works once. `bridle share` prints the full instructions."));
      return;
    }

    // Everything a teammate needs, in one paste. Minting the invite here rather
    // than during `up` means codes exist only when somebody actually asks to
    // share — an unused invite is a credential lying around.
    case "share": {
      const identity = readIdentity();
      const cfg = readConfig();
      if (!cfg.coord) throw new Error("join a bridlenet first — run `bridle up`");
      const { code } = await api.invite();
      const them = flag("name") ?? "<their-name>";

      console.log(`\n${bold("Send this to one teammate.")} The invite works once.\n`);
      console.log(dim("────────────────────────────────────────────────────────"));
      console.log(`You're joining ${bold(readPolicy().node)}'s bridlenet on Bridle.\n`);
      console.log("1. Install");
      console.log(dim("   npm install -g bridle-cli\n"));
      console.log("2. Join");
      console.log(dim(`   bridle join --coord ${cfg.coord} --invite ${code} --name ${them}\n`));
      console.log("3. Hand me something");
      console.log(dim(`   bridle send ${identity.name} --note "..."`));
      console.log(dim(`   bridle queue ${identity.name} --title "..."\n`));
      console.log(dim("   `bridle peers` shows who else is on the mesh."));
      console.log(dim("────────────────────────────────────────────────────────"));
      console.log(`\nThen, on your side once they have joined:`);
      console.log(`   ${bold(`bridle grant ${them} --verbs context.push,task.queue`)}`);
      console.log(dim("Nothing they send arrives until you do. That is the point.\n"));
      return;
    }

    case "peers": {
      const { peers } = await api.peers();
      const policy = readPolicy();
      for (const p of peers) {
        const g = policy.peers[p.name];
        const state = g ? `granted ${g.verbs?.join(",") || "—"}` : dim("no grant");
        console.log(`${p.name.padEnd(18)} ${dim(fingerprint(p.key))}  ${state}`);
      }
      return;
    }

    case "grant": {
      const peer = positional[0];
      if (!peer) throw new Error("usage: bridle grant <peer> --repo <r> --verbs a,b");
      const verbs = flag("verbs")?.split(",").map((v) => v.trim() as Verb);
      const repos = flag("repo")?.split(",").map((r) => r.trim());
      await grant(peer, { repos, verbs });
      const g = readPolicy().peers[peer]!;
      console.log(`granted ${bold(peer)} → verbs [${g.verbs?.join(", ")}] repos [${g.repos?.join(", ") || "any"}]`);
      return;
    }

    case "revoke": {
      const peer = positional[0];
      if (!peer) throw new Error("usage: bridle revoke <peer>");
      revoke(peer);
      console.log(`revoked ${peer}`);
      return;
    }

    case "send": {
      const to = positional[0];
      if (!to) throw new Error("usage: bridle send <peer> --note ...");
      const files = flag("file") ? [fileToAttachment(flag("file")!)] : undefined;
      const { id } = await send({
        to,
        verb: "context.push",
        repo: flag("repo"),
        payload: buildContext({
          note: flag("note"),
          decision: flag("decision"),
          files,
          links: flag("link") ? [flag("link")!] : undefined,
        }),
      });
      console.log(`sent ${dim(id.slice(0, 8))} → ${to}`);
      return;
    }

    case "queue": {
      const to = positional[0];
      if (!to) throw new Error("usage: bridle queue <peer> --title ...");
      const title = flag("title");
      if (!title) throw new Error("--title is required");
      const { id } = await send({
        to, verb: "task.queue", repo: flag("repo"),
        payload: { title, detail: flag("detail"), repo: flag("repo") },
      });
      console.log(`queued ${dim(id.slice(0, 8))} → ${to}`);
      return;
    }

    case "state": {
      const to = positional[0];
      const fields = (flag("fields") ?? "branch,diffstat").split(",") as ("branch" | "diffstat" | "openFiles" | "task")[];
      if (!to) throw new Error("usage: bridle state <peer> --fields branch,diffstat");
      const { id } = await send({ to, verb: "state.read", repo: flag("repo"), payload: { fields } });
      console.log(`asked ${dim(id.slice(0, 8))} → ${to}`);
      return;
    }

    case "ask": {
      const to = positional[0];
      const command = flag("command");
      if (!to || !command) throw new Error('usage: bridle ask <peer> --command "pnpm test"');
      const { id } = await send({
        to, verb: "run.request", repo: flag("repo"),
        payload: { command, cwd: flag("cwd"), reason: flag("reason") },
      });
      console.log(`requested ${dim(id.slice(0, 8))} → ${to}`);
      console.log(dim("run.request stops at their approval by default."));
      return;
    }

    case "inbox": {
      // Looking is not taking. --collect (or --deliver) is what acknowledges.
      const taking = has("collect") || has("deliver");
      const results = taking ? await collect() : await peek();
      if (!results.length) {
        console.log(dim("nothing waiting"));
        return;
      }
      for (const r of results) {
        const { envelope: e, decision: d } = r;
        console.log(`${tone(d.verdict).padEnd(16)} ${bold(e.verb)}  ${dim(e.id.slice(0, 8))}  from ${e.from}`);
        if (e.payload) console.log(`  ${summarise(e)}`);
        for (const reason of d.reasons) {
          if (reason.verdict !== "allow" || d.verdict === "allow") console.log(dim(`  · ${reason.detail}`));
        }
        if (d.verdict === "ask" && taking) console.log(dim(`  → bridle approve ${e.id.slice(0, 8)}`));
        if (r.rendered && has("deliver")) console.log("\n" + r.rendered + "\n");
      }
      if (!taking) {
        console.log(dim(`\nnothing was collected — this was a look. run \`bridle inbox --collect\` to take delivery.`));
      }
      return;
    }

    // Report back on work someone handed you. The sender sees it against the
    // thing they asked for, so a handoff stops being fire-and-forget.
    case "done":
    case "working":
    case "blocked": {
      const id = positional[0];
      if (!id) throw new Error(`usage: bridle ${cmd} <id> [--note "..."]`);
      const r = await report(id, cmd, flag("note"));
      console.log(`${tone(cmd === "blocked" ? "deny" : cmd === "done" ? "allow" : "ask")} ${bold(cmd)} → ${r.to}`);
      console.log(dim(`  about: ${r.about}`));
      return;
    }

    /** What this node has been handed and can report on. */
    case "work": {
      const inbound = Object.values(readReceived()).sort((a, b) => b.at.localeCompare(a.at));
      if (!inbound.length) { console.log(dim("nothing has been handed to this node yet")); return; }
      for (const w of inbound) {
        console.log(`${dim(w.id.slice(0, 8))}  ${bold(w.verb)}  from ${w.from}`);
        console.log(`  ${w.summary}`);
        console.log(dim(`  → bridle done ${w.id.slice(0, 8)} --note "..."`));
      }
      return;
    }

    /** What this node handed out, and what came back. */
    case "tasks": {
      const out = Object.values(readOutbox()).sort((a, b) => b.sentAt.localeCompare(a.sentAt));
      if (!out.length) { console.log(dim("you have not handed anything over yet")); return; }
      for (const t of out) {
        const state = t.status
          ? tone(t.status === "done" ? "allow" : t.status === "blocked" ? "deny" : "ask")
          : dim("no word yet");
        console.log(`${dim(t.id.slice(0, 8))}  ${t.to.padEnd(26)} ${state}`);
        console.log(`  ${t.summary}`);
        if (t.note) console.log(dim(`  “${t.note}”`));
      }
      return;
    }

    case "pending": {
      const held = readPending();
      if (!held.length) { console.log(dim("nothing held")); return; }
      for (const h of held) {
        const waiting = h.heldAt ? `  ${dim(`waiting ${fmtMs(Date.now() - Date.parse(h.heldAt))}`)}` : "";
        console.log(`${tone("ask").padEnd(16)} ${bold(h.envelope.verb)}  ${dim(h.envelope.id.slice(0, 8))}  from ${h.envelope.from}${waiting}`);
        console.log(`  ${summarise(h.envelope)}`);
        for (const r of h.decision.reasons) console.log(dim(`  · ${r.detail}`));
      }
      return;
    }

    case "approve":
    case "deny": {
      const id = positional[0];
      if (!id) throw new Error(`usage: bridle ${cmd} <id> [--reason "..."]`);
      const reason = flag("reason");
      const r = await decide(id, cmd === "approve" ? "allow" : "deny", reason);
      console.log(`${tone(cmd === "approve" ? "allow" : "deny")} ${r.envelope.verb} from ${r.envelope.from}`);
      if (reason) console.log(dim(`  reason: ${reason}`));
      if (r.rendered) console.log("\n" + r.rendered + "\n");
      return;
    }

    case "status": {
      if (!isUp()) {
        console.log("bridle is not up here. Run `bridle up --name <you>`.");
        return;
      }
      const identity = readIdentity();
      const policy = readPolicy();
      const cfg = readConfig();
      const pending = readPending();
      console.log(`${bold(identity.name)}  ${dim(fingerprint(identity.publicKey))}`);
      console.log(`  workspace   ${workspaceRoot()}`);
      console.log(`  bridlenet   ${cfg.coord ?? dim("not joined")}`);
      console.log(`  grants      ${Object.keys(policy.peers).length}`);
      console.log(`  pending     ${pending.length}`);
      for (const [name, g] of Object.entries(policy.peers)) {
        console.log(`    ${name.padEnd(16)} ${g.verbs?.join(", ")}  ${dim((g.repos ?? []).join(", ") || "any repo")}`);
      }
      return;
    }

    /**
     * Everything this node has opened up, in one place. Grants are held by the
     * receiver, so this is the only place the whole picture exists — the
     * coordination server never sees a policy.
     */
    /**
     * Move an already-joined node to a different coordination server.
     *
     * A joined node remembers the coord it joined rather than following the
     * client's default, so upgrading the CLI can never silently relocate
     * somebody's node. That is the right default and it means moving one is an
     * explicit act — this is it.
     */
    case "set-coord": {
      const url = positional[0];
      if (!url) throw new Error("usage: bridle set-coord https://api.bridle.network");
      let parsed: URL;
      try {
        parsed = new URL(url);
      } catch {
        throw new Error(`"${url}" is not a URL`);
      }
      if (parsed.protocol !== "https:" && parsed.hostname !== "127.0.0.1" && parsed.hostname !== "localhost") {
        throw new Error("refusing a plaintext coordination server — envelopes are sealed, but tokens are not");
      }
      const cfg = readConfig();
      const before = cfg.coord;
      writeConfig({ ...cfg, coord: parsed.origin });
      console.log(`${bold(readIdentity().name)} now talks to ${parsed.origin}`);
      if (before) console.log(dim(`  was ${before}`));
      console.log(dim("Your token travels with you only if both hostnames are the same server."));
      return;
    }

    case "access": {
      const policy = readPolicy();
      const identity = readIdentity();
      const outbox = Object.values(readOutbox());

      console.log(`${bold(identity.name)} ${dim("— what this node has opened up")}\n`);

      const peers = Object.entries(policy.peers);
      console.log(`${bold("Granted")} ${dim("· who may send this node what")}`);
      if (!peers.length) console.log(dim("  nobody — nothing can reach this node"));
      for (const [name, g] of peers) {
        const repos = (g.repos ?? []).join(", ") || "any repo";
        console.log(`  ${name.padEnd(28)} ${(g.verbs ?? []).join(", ")}`);
        console.log(dim(`  ${" ".repeat(28)} ${repos}`));
      }

      // Handing work over opens a narrow return path automatically: they may
      // report on that envelope, and nothing else.
      const open = new Map<string, number>();
      for (const t of outbox) if (!t.status) open.set(t.to, (open.get(t.to) ?? 0) + 1);
      console.log(`\n${bold("Reply channels")} ${dim("· open because you handed them work")}`);
      if (!open.size) console.log(dim("  none outstanding"));
      for (const [to, n] of open) {
        console.log(`  ${to.padEnd(28)} ${n} awaiting a report`);
        console.log(dim(`  ${" ".repeat(28)} may send a status on those only`));
      }

      console.log(`\n${dim(`policy file: ${paths.policy()}`)}`);
      console.log(dim("revoke with: bridle revoke <peer>"));
      return;
    }

    case "nodes": {
      const all = localNodes();
      if (!all.length) { console.log(dim("no nodes on this machine yet")); return; }
      for (const n of all) {
        const here = n.home === bridleHome() ? bold(" ← this workspace") : "";
        console.log(`${n.name.padEnd(24)} ${dim(n.coord ?? "not joined")}${here}`);
        console.log(dim(`  ${n.home}`));
      }
      return;
    }

    case "policy":
      console.log(`# ${paths.policy()}`);
      console.log(readFileSync(paths.policy(), "utf8"));
      return;

    /**
     * The local half of the audit trail: every verdict this node reached, who
     * waited on whom for how long, and how run.requests came out. `--grants`
     * turns it around — which standing permissions are earning their keep.
     * `--coord` fetches the server's half; the two should agree.
     */
    case "audit": {
      if (has("coord")) {
        const { events } = await api.audit();
        for (const e of events) {
          console.log(`${dim(String(e.at))}  ${String(e.t).padEnd(18)} ${JSON.stringify(e).slice(0, 120)}`);
        }
        return;
      }

      if (has("grants")) {
        const standings = grantStandings(readPolicy(), readGrantUsage());
        if (!standings.length) { console.log(dim("no grants — nothing can reach this node")); return; }
        console.log(`${bold("Grants")} ${dim("· stamped each time an envelope is admitted under one")}`);
        for (const s of standings) {
          const use = s.lastUsedAt ? `used ${s.uses}×, last ${s.lastUsedAt}` : "never used";
          console.log(`  ${s.peer.padEnd(24)} ${((s.grant.verbs ?? []).join(", ") || "—").padEnd(38)} ${s.unused ? `\x1b[33m${use}\x1b[0m` : dim(use)}`);
        }
        const unused = standings.filter((s) => s.unused);
        if (unused.length) {
          console.log(`\n${bold("Unused")} ${dim("· standing permissions nobody is spending")}`);
          for (const s of unused) console.log(dim(`  bridle revoke ${s.peer}`));
        }
        return;
      }

      const entries = readDelivered();
      if (!entries.length) { console.log(dim("nothing in the local audit trail yet")); return; }
      for (const e of entries) {
        const route = e.to ? `${e.from} → ${e.to}` : `from ${e.from}`;
        console.log(`${dim(e.at)}  ${tone(e.verdict).padEnd(16)} ${bold(e.verb)}  ${dim(e.id.slice(0, 8))}  ${route}`);
        const detail: string[] = [];
        if (e.grant) detail.push(`grant ${e.grant}`);
        if (e.decidedBy === "operator") {
          detail.push(`${e.verdict === "allow" ? "approved" : "denied"} by operator after ${fmtMs(e.waitedMs ?? 0)}`);
        } else if (e.verdict === "deny") {
          const why = e.reasons?.find((r) => r.verdict === "deny");
          if (why) detail.push(why.detail);
        } else if (e.verdict === "ask") {
          detail.push("held for approval");
        } else if (!e.grant && !e.outcome && e.reasons?.length) {
          // Allowed with no grant at all — the reply channel. Say so.
          detail.push(e.reasons[0]!.detail);
        }
        if (e.reason) detail.push(`“${e.reason}”`);
        if (e.outcome) detail.push(`run ${e.outcome} after ${fmtMs(e.runMs ?? 0)}`);
        if (e.redacted?.length) detail.push(`redacted: ${e.redacted.join(", ")}`);
        if (detail.length) console.log(dim(`  · ${detail.join("  ·  ")}`));
      }

      const waits = approvalTimes(entries);
      const names = Object.keys(waits);
      if (names.length) {
        console.log(`\n${bold("Time to approval")} ${dim("· per person kept waiting")}`);
        for (const name of names) {
          const w = waits[name]!;
          console.log(`  ${name.padEnd(24)} ${w.count} decided · mean ${fmtMs(w.meanMs)} · worst ${fmtMs(w.maxMs)}`);
        }
      }
      return;
    }

    default:
      console.log(HELP);
      if (cmd && cmd !== "help" && cmd !== "--help") process.exitCode = 1;
  }
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

function openBrowser(url: string): void {
  const cmd = process.platform === "darwin" ? "open" : process.platform === "win32" ? "start" : "xdg-open";
  try {
    spawn(cmd, [url], { stdio: "ignore", detached: true }).unref();
  } catch {
    /* the URL is printed above; opening a browser is a convenience, not a requirement */
  }
}

function readConfigName(): string | undefined {
  try {
    return readIdentity().name;
  } catch {
    return undefined;
  }
}

main().catch((err: Error) => {
  console.error(`\x1b[31merror\x1b[0m ${err.message}`);
  process.exitCode = 1;
});
