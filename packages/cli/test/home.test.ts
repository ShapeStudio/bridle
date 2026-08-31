import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { workspaceRoot, workspaceSlug, defaultNodeName } from "../src/home.js";

describe("a node belongs to a workspace, not a machine", () => {
  test("finds the enclosing git repository from a nested directory", () => {
    const root = mkdtempSync(join(tmpdir(), "ws-"));
    mkdirSync(join(root, ".git"));
    mkdirSync(join(root, "apps", "web"), { recursive: true });
    assert.equal(workspaceRoot(join(root, "apps", "web")), root);
    rmSync(root, { recursive: true, force: true });
  });

  test("falls back to the directory itself outside a repository", () => {
    const dir = mkdtempSync(join(tmpdir(), "plain-"));
    assert.equal(workspaceRoot(dir), dir);
    rmSync(dir, { recursive: true, force: true });
  });

  // The whole point: two repos side by side are two participants.
  test("two workspaces get different homes", () => {
    const a = mkdtempSync(join(tmpdir(), "ws-a-"));
    const b = mkdtempSync(join(tmpdir(), "ws-b-"));
    assert.notEqual(workspaceSlug(a), workspaceSlug(b));
    rmSync(a, { recursive: true, force: true });
    rmSync(b, { recursive: true, force: true });
  });

  // Two checkouts of the same repo must not collide just because the basename matches.
  test("same basename in different places still differs", () => {
    const one = join(tmpdir(), "alpha", "shape-website");
    const two = join(tmpdir(), "beta", "shape-website");
    assert.notEqual(workspaceSlug(one), workspaceSlug(two));
    assert.ok(workspaceSlug(one).startsWith("shape-website-"), "stays legible");
  });

  test("the slug is stable for a given path", () => {
    const dir = join(tmpdir(), "stable-repo");
    assert.equal(workspaceSlug(dir), workspaceSlug(dir));
  });

  test("the suggested name pairs the user with the repo", () => {
    const name = defaultNodeName(join(tmpdir(), "shape-website"));
    assert.match(name, /^[a-z0-9][a-z0-9._-]{1,62}$/, "must satisfy the protocol's name rule");
    assert.ok(name.endsWith(".shape-website"));
  });

  test("a messy directory name still yields a legal node name", () => {
    const name = defaultNodeName(join(tmpdir(), "My Repo (v2)!"));
    assert.match(name, /^[a-z0-9][a-z0-9._-]{1,62}$/);
  });
});

describe("grants", () => {
  // A node granting itself does nothing, and a policy holding one is state that
  // cannot be accounted for afterwards. It should be impossible, not just unused.
  test("a node cannot grant itself", async () => {
    const home = mkdtempSync(join(tmpdir(), "self-"));
    process.env.BRIDLE_HOME = home;
    const { up } = await import("../src/home.js");
    const { grant } = await import("../src/actions.js");
    up("solo.dev");
    await assert.rejects(() => grant("solo.dev", { verbs: ["context.push"] }), /cannot grant itself/);
    delete process.env.BRIDLE_HOME;
    rmSync(home, { recursive: true, force: true });
  });
});

describe("policy writes", () => {
  // The regression guard for the scope that appeared from nowhere: granting
  // without --repo must mean "any repo", never the workspace's name.
  test("a grant with no repo flag scopes to no repo at all", async () => {
    const home = mkdtempSync(join(tmpdir(), "scope-"));
    process.env.BRIDLE_HOME = home;
    const { up, readPolicy, writePolicy } = await import("../src/home.js");
    up("scoped.dev");
    const policy = readPolicy();
    policy.peers["someone"] = { key: "k", repos: [], verbs: ["context.push"], overrides: {} };
    writePolicy(policy);
    assert.deepEqual(readPolicy().peers["someone"]?.repos, []);
    delete process.env.BRIDLE_HOME;
    rmSync(home, { recursive: true, force: true });
  });

  test("every change to the peer set is recorded with the argv that caused it", async () => {
    const home = mkdtempSync(join(tmpdir(), "audit-"));
    process.env.BRIDLE_HOME = home;
    const { up, readPolicy, writePolicy } = await import("../src/home.js");
    up("audited.dev");
    const policy = readPolicy();
    policy.peers["ghost"] = { key: "k", repos: ["surprise"], verbs: ["task.queue"], overrides: {} };
    writePolicy(policy);

    const log = readFileSync(join(home, "policy.log"), "utf8").trim().split("\n").map((l) => JSON.parse(l));
    const last = log.at(-1);
    assert.match(last.to, /ghost\[task\.queue\]\{surprise\}/, "records what the peer set became");
    assert.ok(Array.isArray(last.argv), "records the command responsible");
    delete process.env.BRIDLE_HOME;
    rmSync(home, { recursive: true, force: true });
  });
});
