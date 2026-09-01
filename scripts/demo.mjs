#!/usr/bin/env node
/**
 * End-to-end demo: a real coord process, three nodes, every verdict path — and
 * the audit trail that captures each one: verdicts and their reasons, which
 * grant admitted what, how long approvals took, how a run.request came out,
 * and the grant nobody ever used.
 *
 * Runs entirely in ./demo-state and never touches your real ~/.bridle.
 * The coord it spawns is scripts/demo-coord.mjs — a toy server written from
 * docs/PROTOCOL.md alone. Build first: `npm run build`.
 */
import { rmSync, mkdirSync, readFileSync } from "node:fs";
import { execFileSync, spawn } from "node:child_process";
import { setTimeout as sleep } from "node:timers/promises";

const ROOT = new URL("..", import.meta.url).pathname;
const STATE = `${ROOT}demo-state`;
rmSync(STATE, { recursive: true, force: true });
mkdirSync(STATE, { recursive: true });

const PORT = 8799;
const BOOT = "DEMO-INVITE-0001";
const COORD = `http://127.0.0.1:${PORT}`;

// The coord must be its own process: the CLI calls below are synchronous and
// would otherwise block the very event loop the server needs to reply on.
const coord = spawn("node", [`${ROOT}scripts/demo-coord.mjs`, "--port", String(PORT), "--state", `${STATE}/coord/events.jsonl`], {
  env: { ...process.env, BRIDLE_BOOTSTRAP_INVITE: BOOT },
  stdio: "ignore",
});

for (let i = 0; i < 60; i++) {
  try {
    const r = await fetch(`${COORD}/health`);
    if (r.ok) break;
  } catch { /* not up yet */ }
  await sleep(100);
}

const bridle = (home, ...args) => {
  try {
    return execFileSync("node", [`${ROOT}packages/cli/dist/src/bin.js`, ...args], {
      env: { ...process.env, BRIDLE_HOME: `${STATE}/${home}` },
      encoding: "utf8",
    }).trimEnd();
  } catch (e) {
    return ((e.stdout ?? "") + (e.stderr ?? "")).trimEnd();
  }
};

const step = (t) => console.log(`\n\x1b[1m▸ ${t}\x1b[0m`);
const show = (out) => out && console.log(out.split("\n").map((l) => "  " + l).join("\n"));
const heldId = (home) => JSON.parse(readFileSync(`${STATE}/${home}/pending.json`, "utf8"))[0].envelope.id.slice(0, 8);

step("Both ends opt in — each runs `bridle up` and joins the bridlenet");
show(bridle("marko", "join", "--coord", COORD, "--invite", BOOT, "--name", "marko.dev"));
const invite = bridle("marko", "invite").split("\n")[0];
show(bridle("ana", "join", "--coord", COORD, "--invite", invite, "--name", "ana.dev"));
const invite2 = bridle("ana", "invite").split("\n")[0];
show(bridle("cara", "join", "--coord", COORD, "--invite", invite2, "--name", "cara.dev"));

step("Before any grant, nothing crosses — and the refusal is on the record");
show(bridle("marko", "send", "ana.dev", "--note", "first contact", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));

step("Ana grants marko context + task on one repo — and cara, who will never use hers");
show(bridle("ana", "grant", "marko.dev", "--repo", "pai-frontend", "--verbs", "context.push,task.queue"));
show(bridle("ana", "grant", "cara.dev", "--verbs", "task.queue"));

step("Now a context.push lands, stamped against the grant that admitted it");
show(bridle("marko", "send", "ana.dev", "--decision", "keep RLS on for the wa_ tables", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));

step("A repo outside the grant is denied");
show(bridle("marko", "send", "ana.dev", "--note", "unrelated", "--repo", "shape-erp"));
show(bridle("ana", "inbox", "--collect"));

step("A verb outside the grant is denied");
show(bridle("marko", "ask", "ana.dev", "--command", "pnpm test", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));

step("Ana widens the grant to run.request — it stops at ask, not allow");
show(bridle("ana", "grant", "marko.dev", "--repo", "pai-frontend", "--verbs", "context.push,task.queue,run.request"));
show(bridle("marko", "ask", "ana.dev", "--command", "pnpm test --filter api", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));

step("A never-command is refused even though run.request is granted");
show(bridle("marko", "ask", "ana.dev", "--command", "git push origin main", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));

step("Held work shows how long the sender has been waiting");
await sleep(1200);
show(bridle("ana", "pending"));

step("Ana turns the second key, with a reason — approved work arrives fenced as DATA");
const run = heldId("ana");
show(bridle("ana", "approve", run, "--reason", "staging only — fine"));

step("The approved run is now hers to report on; the sender hears how it went");
show(bridle("ana", "work"));
show(bridle("ana", "done", run, "--note", "4 suites green"));
show(bridle("marko", "inbox", "--collect"));
show(bridle("marko", "tasks"));

step("A payload carrying a secret is redacted and held — Ana denies it, on the record");
show(bridle("marko", "send", "ana.dev", "--note", "use ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa to test", "--repo", "pai-frontend"));
show(bridle("ana", "inbox", "--collect"));
show(bridle("ana", "deny", heldId("ana"), "--reason", "tokens do not ride along — rotate it"));

step("Ana's audit trail: every verdict, its reason, the grant, the waits");
show(bridle("ana", "audit"));

step("Marko's half closes the loop: the run he asked for, its outcome, its duration");
show(bridle("marko", "audit"));

step("Grant usage — the grant nobody spends is there to be revoked");
show(bridle("ana", "audit", "--grants"));

step("The coordination server's half — metadata only, and it should agree");
show(bridle("ana", "audit", "--coord"));

coord.kill();
console.log("\n\x1b[32m✔ demo complete\x1b[0m\n");
process.exit(0);
