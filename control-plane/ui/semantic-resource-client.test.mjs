import assert from "node:assert/strict";
import test from "node:test";

import {
  assertSemanticConsoleRequestSupported,
  buildSemanticCatCreateRequest,
  buildSemanticDiskCreateRequest,
  buildSemanticDiskSnapshotCreateRequest,
  buildSemanticDiskSnapshotDestroyRequest,
  buildSemanticDiskSnapshotRestoreRequest,
  catCollectionPath,
  createSemanticCat,
  createSemanticDisk,
  createSemanticDiskSnapshot,
  destroySemanticDiskSnapshot,
  diskCollectionPath,
  diskSnapshotCollectionPath,
  diskSnapshotItemPath,
  restoreSemanticDiskSnapshot,
  diskSnapshotActionPath,
} from "./semantic-resource-client.mjs";

test("semantic builders emit only the current scenario-identity DTOs", () => {
  assert.deepEqual(buildSemanticCatCreateRequest({
    name: "app",
    vcpus: 2,
    memoryMib: 2048,
  }), {
    cat_slug: "app",
    cpu: 2,
    memory_bytes: 2147483648,
    mounts: [],
  });
  assert.deepEqual(buildSemanticDiskCreateRequest({ name: "data-disk", sizeGib: 100 }), {
    disk_slug: "data-disk",
    size_bytes: 107374182400,
  });
  assert.deepEqual(buildSemanticDiskSnapshotCreateRequest({ disk: "data-disk", name: "before-upgrade" }), {
    snapshot_slug: "before-upgrade",
    disk_slug: "data-disk",
  });
  assert.deepEqual(buildSemanticDiskSnapshotDestroyRequest({ expectedSnapshotId: "snapshot_01" }), {
    expected_snapshot_id: "snapshot_01",
  });
  assert.deepEqual(buildSemanticDiskSnapshotRestoreRequest({
    expectedSnapshotId: "snapshot_01",
    expectedGeneration: 42,
  }), {
    expected_snapshot_id: "snapshot_01",
    expected_generation: 42,
  });
  assert.equal(catCollectionPath("ws_01"), "/v1/workspaces/ws_01/cats");
  assert.equal(diskCollectionPath("ws_01"), "/v1/workspaces/ws_01/disks");
  assert.equal(
    diskSnapshotCollectionPath("ws_01"),
    "/v1/workspaces/ws_01/snapshots",
  );
  assert.equal(
    diskSnapshotItemPath("ws_01", "before-upgrade"),
    "/v1/workspaces/ws_01/snapshots/before-upgrade",
  );
  assert.equal(
    diskSnapshotActionPath("ws_01", "before-upgrade", "restore"),
    "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/restore",
  );
});

test("DiskSnapshot paths reject mutable-looking or non-canonical resource keys", () => {
  for (const callback of [
    () => diskSnapshotCollectionPath("ws/01"),
    () => diskSnapshotItemPath("ws_01", "before/upgrade"),
    () => diskSnapshotActionPath("ws_01", "snapshot", "clone"),
    () => buildSemanticDiskSnapshotCreateRequest({ disk: "Data", name: "before-upgrade" }),
    () => buildSemanticDiskSnapshotCreateRequest({ disk: "data", name: "before upgrade" }),
    () => buildSemanticDiskSnapshotDestroyRequest({ expectedSnapshotId: "other_01" }),
    () => buildSemanticDiskSnapshotRestoreRequest({
      expectedSnapshotId: "snapshot_01",
      expectedGeneration: -1,
    }),
  ]) {
    assert.throws(callback);
  }
});

function snapshotView(overrides = {}) {
  return {
    snapshot_id: "snapshot_01",
    workspace_id: "ws_01",
    snapshot_slug: "before-upgrade",
    disk_id: "disk_01",
    disk_slug: "data",
    size_bytes: 10737418240,
    status: "normal",
    captured_generation: 42,
    created_at_unix_ms: 1,
    deleted_at_unix_ms: null,
    ...overrides,
  };
}

test("DiskSnapshot create binds both user-selected slugs without an Idempotency-Key", async () => {
  const sent = [];
  const response = await createSemanticDiskSnapshot({
    immutableWorkspaceId: "ws_01",
    request: { snapshot_slug: "before-upgrade", disk_slug: "data" },
    send: async (path, options) => {
      sent.push({ path, options });
      return {
        status: 201,
        contentType: "application/json",
        contentEncoding: "",
        value: {
          status: "ok",
          code: "snapshot_created",
          snapshot: snapshotView(),
          disk_head_generation: 42,
        },
      };
    },
  });
  assert.equal(response.snapshot.snapshot_id, "snapshot_01");
  assert.deepEqual(sent, [{
    path: "/v1/workspaces/ws_01/snapshots",
    options: {
      method: "POST",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ snapshot_slug: "before-upgrade", disk_slug: "data" }),
    },
  }]);
  assert.equal("Idempotency-Key" in sent[0].options.headers, false);
});

test("DiskSnapshot restore carries the latest target-disk generation", async () => {
  let sent;
  const response = await restoreSemanticDiskSnapshot({
    immutableWorkspaceId: "ws_01",
    snapshot: "before-upgrade",
    snapshotId: "snapshot_01",
    disk: "data",
    expectedGeneration: 77,
    send: async (path, options) => {
      sent = { path, options };
      return {
        status: 200,
        contentType: "application/json",
        contentEncoding: "",
        value: {
          status: "ok",
          code: "snapshot_restored",
          snapshot: snapshotView(),
          disk_head_generation: 78,
        },
      };
    },
  });
  assert.equal(response.code, "snapshot_restored");
  assert.equal(sent.path, "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/restore");
  assert.deepEqual(JSON.parse(sent.options.body), {
    expected_snapshot_id: "snapshot_01",
    expected_generation: 77,
  });
  assert.equal("Idempotency-Key" in sent.options.headers, false);
});

test("DiskSnapshot destroy carries the exact occurrence and accepts its already-deleted tombstone", async () => {
  let sent;
  await destroySemanticDiskSnapshot({
    immutableWorkspaceId: "ws_01",
    snapshot: "before-upgrade",
    snapshotId: "snapshot_01",
    send: async (path, options) => {
      sent = { path, options };
      return {
        status: 200,
        contentType: "application/json",
        contentEncoding: "",
        value: {
          status: "already_done",
          code: "already_deleted",
          snapshot: snapshotView({ status: "deleted", deleted_at_unix_ms: 2 }),
          disk_head_generation: 42,
        },
      };
    },
  });
  assert.equal(sent.path, "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/destroy");
  assert.deepEqual(sent.options, {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ expected_snapshot_id: "snapshot_01" }),
  });
});

test("DiskSnapshot actions reject responses rebound to another resource", async () => {
  await assert.rejects(restoreSemanticDiskSnapshot({
    immutableWorkspaceId: "ws_01",
    snapshot: "before-upgrade",
    snapshotId: "snapshot_01",
    disk: "data",
    expectedGeneration: 77,
    send: async () => ({
      status: 200,
      contentType: "application/json",
      contentEncoding: "",
      value: {
        status: "ok",
        code: "snapshot_restored",
        snapshot: snapshotView({ disk_slug: "other" }),
        disk_head_generation: 78,
      },
    }),
  }), /semantic identity binding/);

  await assert.rejects(destroySemanticDiskSnapshot({
    immutableWorkspaceId: "ws_01",
    snapshot: "before-upgrade",
    snapshotId: "snapshot_01",
    send: async () => ({
      status: 200,
      contentType: "application/json",
      contentEncoding: "",
      value: {
        status: "ok",
        code: "snapshot_destroyed",
        snapshot: snapshotView({
          snapshot_id: "snapshot_02",
          status: "deleted",
          deleted_at_unix_ms: 2,
        }),
        disk_head_generation: 42,
      },
    }),
  }), /semantic identity binding/);
});

test("semantic Cat create sends no request identifier and accepts exact retry identity", async () => {
  const sent = [];
  const request = buildSemanticCatCreateRequest({
    name: "app",
    vcpus: 2,
    memoryMib: 1024,
  });
  const response = await createSemanticCat({
    immutableWorkspaceId: "ws_01",
    request,
    send: async (path, options) => {
      sent.push({ path, options });
      return {
        status: 200,
        contentType: "application/json",
        contentEncoding: "",
        value: {
          status: "already_exists",
          code: "already_exists",
          cat: { cat_id: "cat_01", workspace_id: "ws_01", cat_slug: "app" },
        },
      };
    },
  });
  assert.equal(response.code, "already_exists");
  assert.deepEqual(sent, [{
    path: "/v1/workspaces/ws_01/cats",
    options: {
      method: "POST",
      redirect: "error",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
    },
  }]);
  assert.equal("Idempotency-Key" in sent[0].options.headers, false);
});

test("semantic PersistentDisk create binds the returned slug and Workspace", async () => {
  const request = buildSemanticDiskCreateRequest({ name: "data", sizeGib: 10 });
  const response = await createSemanticDisk({
    immutableWorkspaceId: "ws_01",
    request,
    send: async () => ({
      status: 201,
      contentType: "application/json",
      contentEncoding: "",
      value: {
        status: "ok",
        code: "disk_created",
        disk: {
          disk_id: "disk_01",
          workspace_id: "ws_01",
          disk_slug: "data",
          size_bytes: 10737418240,
        },
      },
    }),
  });
  assert.equal(response.disk.disk_slug, "data");
});

test("semantic client rejects query pagination and retired console surfaces locally", () => {
  for (const [method, path] of [
    ["GET", "/v1/workspaces/ws_01/cats"],
    ["POST", "/v1/workspaces/ws_01/cats"],
    ["GET", "/v1/workspaces/ws_01/disks"],
    ["POST", "/v1/workspaces/ws_01/disks"],
    ["GET", "/v1/workspaces/ws_01/snapshots"],
    ["POST", "/v1/workspaces/ws_01/snapshots"],
    ["GET", "/v1/workspaces/ws_01/snapshots/before-upgrade"],
    ["POST", "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/destroy"],
    ["POST", "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/restore"],
  ]) {
    assert.doesNotThrow(() => assertSemanticConsoleRequestSupported(path, method));
  }
  for (const [method, path] of [
    ["GET", "/v1/workspaces/ws_01/cats?limit=100"],
    ["GET", "/v1/workspaces/ws_01/disks?cursor=next"],
    ["GET", "/v1/workspaces/ws_01/snapshots?cursor=next"],
    ["POST", "/v1/workspaces/ws_01/snapshots/before-upgrade"],
    ["DELETE", "/v1/workspaces/ws_01/snapshots/before-upgrade"],
    ["GET", "/v1/workspaces/ws_01/snapshots/before-upgrade/actions/restore"],
    ["POST", "/v1/workspaces/ws_01/cats/app/actions/run"],
    ["GET", "/v1/workspaces/ws_01/operations"],
    ["GET", "/v1/admin/nodes"],
  ]) {
    assert.throws(
      () => assertSemanticConsoleRequestSupported(path, method),
      /no request was sent/,
      `${method} ${path}`,
    );
  }
});

test("semantic create rejects a response bound to another slug", async () => {
  const request = buildSemanticCatCreateRequest({
    name: "app",
    vcpus: 1,
    memoryMib: 512,
  });
  await assert.rejects(createSemanticCat({
    immutableWorkspaceId: "ws_01",
    request,
    send: async () => ({
      status: 201,
      contentType: "application/json",
      contentEncoding: "",
      value: {
        status: "ok",
        code: "cat_created",
        cat: { cat_id: "cat_01", workspace_id: "ws_01", cat_slug: "other" },
      },
    }),
  }), /semantic identity binding/);
});
