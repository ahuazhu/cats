import assert from "node:assert/strict";
import test from "node:test";

import {
  assertSemanticConsoleRequestSupported,
  buildSemanticCatCreateRequest,
  buildSemanticDiskCreateRequest,
  catCollectionPath,
  createSemanticCat,
  createSemanticDisk,
  diskCollectionPath,
} from "./semantic-resource-client.mjs";

const DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

test("semantic builders emit only the current scenario-identity DTOs", () => {
  assert.deepEqual(buildSemanticCatCreateRequest({
    name: "app",
    bootImage: DIGEST,
    vcpus: 2,
    memoryMib: 2048,
  }), {
    cat_slug: "app",
    cpu: 2,
    memory_bytes: 2147483648,
    boot_image: DIGEST,
    mounts: [],
  });
  assert.deepEqual(buildSemanticDiskCreateRequest({ name: "data-disk", sizeGib: 100 }), {
    disk_slug: "data-disk",
    size_bytes: 107374182400,
  });
  assert.equal(catCollectionPath("ws_01"), "/v1/workspaces/ws_01/cats");
  assert.equal(diskCollectionPath("ws_01"), "/v1/workspaces/ws_01/disks");
});

test("semantic Cat create sends no request identifier and accepts exact retry identity", async () => {
  const sent = [];
  const request = buildSemanticCatCreateRequest({
    name: "app",
    bootImage: DIGEST,
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
  ]) {
    assert.doesNotThrow(() => assertSemanticConsoleRequestSupported(path, method));
  }
  for (const [method, path] of [
    ["GET", "/v1/workspaces/ws_01/cats?limit=100"],
    ["GET", "/v1/workspaces/ws_01/disks?cursor=next"],
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
    bootImage: DIGEST,
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
