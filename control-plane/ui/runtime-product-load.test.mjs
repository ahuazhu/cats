import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  loadAll,
  runtimeCatView,
  runtimeDiskView,
  setRuntimeProductLoadingShell,
} from "./runtime-product-load.mjs";

test("workspace switch removes stale rows while the next Workspace pages are paused", async () => {
  const catsTable = { innerHTML: "<tr><td>Cat A</td></tr>" };
  const disksTable = { innerHTML: "<tr><td>Disk A</td></tr>" };
  const shell = {
    attributes: new Map(),
    setAttribute(name, value) { this.attributes.set(name, value); },
    removeAttribute(name) { this.attributes.delete(name); },
  };
  const controls = [{ disabled: false }, { disabled: false }];
  const root = {
    querySelector(selector) {
      return new Map([
        ["#app-shell", shell],
        ["#cats-table", catsTable],
        ["#disks-table", disksTable],
      ]).get(selector) || null;
    },
    querySelectorAll() { return controls; },
  };

  let releaseB;
  const pausedB = new Promise((resolve) => { releaseB = resolve; });
  const loadB = loadAll({
    workspaceId: "ws_B",
    signal: new AbortController().signal,
    requestPage: async () => {
      await pausedB;
      return [];
    },
  });

  // This is the synchronous boundary after selecting B while both B
  // collection requests remain unresolved.
  setRuntimeProductLoadingShell(root, true);

  assert.equal(catsTable.innerHTML, "");
  assert.equal(disksTable.innerHTML, "");
  assert.equal(shell.attributes.get("aria-busy"), "true");
  assert.ok(controls.every((control) => control.disabled));

  releaseB();
  await loadB;
  setRuntimeProductLoadingShell(root, false);
  assert.equal(shell.attributes.has("aria-busy"), false);
  assert.ok(controls.every((control) => !control.disabled));
});

test("loadAll captures one workspace and calls the exact semantic collection paths", async () => {
  const requested = [];
  const collections = new Map([
    ["/v1/workspaces/ws_A/cats", [{ cat_id: "cat_01" }, { cat_id: "cat_02" }]],
    ["/v1/workspaces/ws_A/disks", [{ disk_id: "disk_01" }, { disk_id: "disk_02" }]],
  ]);
  const controller = new AbortController();

  const result = await loadAll({
    workspaceId: "ws_A",
    signal: controller.signal,
    requestPage: async (path, options) => {
      requested.push(path);
      assert.equal(options.signal, controller.signal);
      return collections.get(path);
    },
  });

  assert.deepEqual(result, {
    workspaceId: "ws_A",
    cats: [{ cat_id: "cat_01" }, { cat_id: "cat_02" }],
    disks: [{ disk_id: "disk_01" }, { disk_id: "disk_02" }],
  });
  assert.deepEqual(new Set(requested), new Set(collections.keys()));
});

test("aborting workspace A prevents its delayed collections from completing after B", async () => {
  const aController = new AbortController();
  let releaseA;
  const aPage = new Promise((resolve) => { releaseA = resolve; });
  const loadA = loadAll({
    workspaceId: "ws_A",
    signal: aController.signal,
    requestPage: async (_path, { signal }) => {
      await aPage;
      if (signal.aborted) throw new DOMException("aborted", "AbortError");
      return [{ id: "from_A" }];
    },
  });

  aController.abort();
  const loadB = loadAll({
    workspaceId: "ws_B",
    signal: new AbortController().signal,
    requestPage: async () => [{ id: "from_B" }],
  });
  releaseA();

  await assert.rejects(loadA, (error) => error.name === "AbortError");
  assert.deepEqual(await loadB, {
    workspaceId: "ws_B",
    cats: [{ id: "from_B" }],
    disks: [{ id: "from_B" }],
  });
});

test("semantic Cat and Disk views map directly into the shipped console rows", () => {
  assert.deepEqual(runtimeCatView({
    cat_id: "cat_01",
    workspace_id: "ws_A",
    cat_slug: "app",
    state: "running",
    current_action: null,
    node_id: "node_01",
    node_name: "metal-1",
    cpu: 2,
    memory_bytes: 2147483648,
    boot_image: "sha256:abc",
    mounts: [],
    last_error: null,
    created_at_unix_ms: 1700000000123,
    updated_at_unix_ms: 1700000000456,
    destroyed_at_unix_ms: null,
  }), {
    cat_id: "cat_01",
    workspace_id: "ws_A",
    cat_slug: "app",
    state: "running",
    current_action: null,
    node_id: "node_01",
    node_name: "metal-1",
    cpu: 2,
    memory_bytes: 2147483648,
    boot_image: "sha256:abc",
    mounts: [],
    last_error: null,
    created_at_unix_ms: 1700000000123,
    updated_at_unix_ms: 1700000000456,
    destroyed_at_unix_ms: null,
    id: "cat_01",
    name: "app",
    spec: { cpus: 2, memory_mib: 2048 },
    desired_state: "running",
    observed_state: "running",
    created_at_unix: 1700000000,
    auto_suspend: false,
    expires_at_unix: null,
  });
  assert.deepEqual(runtimeDiskView({
    disk_id: "disk_01",
    workspace_id: "ws_A",
    disk_slug: "data",
    size_bytes: 107374182400,
    status: "normal",
    binding: { cat_id: "cat_01", cat_slug: "app", mount_path: "/data" },
    created_at_unix_ms: 1700000000123,
    deleted_at_unix_ms: null,
  }), {
    disk_id: "disk_01",
    workspace_id: "ws_A",
    disk_slug: "data",
    size_bytes: 107374182400,
    status: "normal",
    binding: { cat_id: "cat_01", cat_slug: "app", mount_path: "/data" },
    created_at_unix_ms: 1700000000123,
    deleted_at_unix_ms: null,
    id: "disk_01",
    name: "data",
    kind: "persistent",
    state: "bound",
    bound_cat_id: "cat_01",
    created_at_unix: 1700000000,
  });
});

test("semantic Cat transition names are readable", () => {
  assert.equal(runtimeCatView({ current_action: "create" }).observed_state, "creating");
  assert.equal(runtimeCatView({ state: "cold", current_action: "run" }).observed_state, "starting");
  assert.equal(runtimeCatView({ current_action: "cold" }).observed_state, "cooling");
});

test("release user console exposes create and read controls without retired mutations", async () => {
  const [script, markup] = await Promise.all([
    readFile(new URL("./user.js", import.meta.url), "utf8"),
    readFile(new URL("./user.html", import.meta.url), "utf8"),
  ]);
  for (const retired of [
    "data-cat-action",
    "data-disk-action",
    "/actions/",
    "#exec-form",
  ]) {
    assert.equal(script.includes(retired), false, `release script retains ${retired}`);
  }
  assert.match(markup, /id="create-cat-button"/);
  assert.match(markup, /id="create-disk-button"/);
  assert.match(markup, /data-view="cats">/);
  assert.match(markup, /data-view="disks">/);
  assert.doesNotMatch(markup, /<dialog id="create-disk-dialog"[^>]* hidden/);
  assert.doesNotMatch(markup, /id="exec-dialog"/);
});
