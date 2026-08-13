import assert from "node:assert/strict";
import test from "node:test";

import {
  loadAll,
  runtimeProductActionAllowed,
  setRuntimeProductLoadingShell,
} from "./runtime-product-load.mjs";

test("workspace switch removes stale Cat actions while the next Workspace pages are paused", async () => {
  const catsTable = { innerHTML: '<button data-cat-action="start" data-workspace-id="ws_A">start</button>' };
  const disksTable = { innerHTML: '<button data-disk-action="delete" data-workspace-id="ws_A">delete</button>' };
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
      return { items: [], next_cursor: null };
    },
  });

  // This is the synchronous boundary after selecting B while both B
  // collection requests remain unresolved.
  setRuntimeProductLoadingShell(root, true);

  assert.equal(catsTable.innerHTML, "");
  assert.equal(disksTable.innerHTML, "");
  assert.equal(shell.attributes.get("aria-busy"), "true");
  assert.ok(controls.every((control) => control.disabled));

  let mutationRequests = 0;
  const staleAButton = { dataset: { workspaceId: "ws_A" } };
  if (runtimeProductActionAllowed({
    button: staleAButton,
    activeWorkspaceId: "ws_B",
    loadingWorkspaceId: "ws_B",
  })) {
    mutationRequests += 1;
  }
  assert.equal(mutationRequests, 0, "a detached A action must not issue a request under B");

  releaseB();
  await loadB;
  setRuntimeProductLoadingShell(root, false);
  assert.equal(shell.attributes.has("aria-busy"), false);
  assert.ok(controls.every((control) => !control.disabled));
});

test("loadAll captures one workspace and fetches every Cat and Disk page", async () => {
  const requested = [];
  const pages = new Map([
    ["/v1/workspaces/ws_A/cats?limit=100", { items: [{ id: "cat_01" }], next_cursor: "cat_next" }],
    ["/v1/workspaces/ws_A/cats?limit=100&cursor=cat_next", { items: [{ id: "cat_02" }], next_cursor: null }],
    ["/v1/workspaces/ws_A/disks?limit=100", { items: [{ id: "disk_01" }], next_cursor: "disk_next" }],
    ["/v1/workspaces/ws_A/disks?limit=100&cursor=disk_next", { items: [{ id: "disk_02" }], next_cursor: null }],
  ]);
  const controller = new AbortController();

  const result = await loadAll({
    workspaceId: "ws_A",
    signal: controller.signal,
    requestPage: async (path, options) => {
      requested.push(path);
      assert.equal(options.signal, controller.signal);
      return pages.get(path);
    },
  });

  assert.deepEqual(result, {
    workspaceId: "ws_A",
    cats: [{ id: "cat_01" }, { id: "cat_02" }],
    disks: [{ id: "disk_01" }, { id: "disk_02" }],
  });
  assert.deepEqual(new Set(requested), new Set(pages.keys()));
});

test("aborting workspace A prevents its delayed pagination from completing after B", async () => {
  const aController = new AbortController();
  let releaseA;
  const aPage = new Promise((resolve) => { releaseA = resolve; });
  const loadA = loadAll({
    workspaceId: "ws_A",
    signal: aController.signal,
    requestPage: async (_path, { signal }) => {
      await aPage;
      if (signal.aborted) throw new DOMException("aborted", "AbortError");
      return { items: [{ id: "from_A" }], next_cursor: null };
    },
  });

  aController.abort();
  const loadB = loadAll({
    workspaceId: "ws_B",
    signal: new AbortController().signal,
    requestPage: async () => ({ items: [{ id: "from_B" }], next_cursor: null }),
  });
  releaseA();

  await assert.rejects(loadA, (error) => error.name === "AbortError");
  assert.deepEqual(await loadB, {
    workspaceId: "ws_B",
    cats: [{ id: "from_B" }],
    disks: [{ id: "from_B" }],
  });
});
