import assert from "node:assert/strict";
import test from "node:test";

import {
  assertRuntimeCutoverClientRequestSupported,
  buildCatCreateV2Request,
  catCreateV2Path,
  listPendingCatCreateV2,
  parseCatCreateV2AcceptedResponse,
  parseCatCreateV2AcceptedResponseBody,
  sendDurableCatCreateV2,
} from "./cat-create-v2.mjs";

const DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

class MemoryStorage {
  #values = new Map();

  get length() {
    return this.#values.size;
  }

  key(index) {
    return Array.from(this.#values.keys())[index] ?? null;
  }

  getItem(key) {
    return this.#values.get(String(key)) ?? null;
  }

  setItem(key, value) {
    this.#values.set(String(key), String(value));
  }

  removeItem(key) {
    this.#values.delete(String(key));
  }
}

class MemoryLocks {
  #active = new Set();

  async request(name, options, callback) {
    assert.deepEqual(options, { mode: "exclusive", ifAvailable: true });
    if (this.#active.has(name)) return callback(null);
    this.#active.add(name);
    try {
      return await callback({ name, mode: "exclusive" });
    } finally {
      this.#active.delete(name);
    }
  }
}

function requestBody(vcpus = 2) {
  return JSON.stringify(buildCatCreateV2Request({
    name: "app",
    bootImageDigest: DIGEST,
    vcpus,
    memoryMib: 2048,
    rootGib: 4,
    durability: "strict",
  }));
}

function accepted(body = '{"cat_id":"cat_01","operation_id":"op_01"}') {
  return {
    status: 202,
    contentType: "application/json",
    contentEncoding: "",
    body,
  };
}

test("builder emits only the frozen six-field Cat-create body", () => {
  const body = buildCatCreateV2Request({
    name: "app",
    bootImageDigest: DIGEST,
    vcpus: 2,
    memoryMib: 2048,
    rootGib: 4,
    durability: "strict",
  });
  assert.equal(
    JSON.stringify(body),
    `{"name":"app","boot_image_digest":"${DIGEST}","vcpus":2,"memory_bytes":2147483648,"root_size_bytes":4294967296,"durability":"strict"}`,
  );
  assert.equal("image" in body, false);
  assert.equal("auto_suspend" in body, false);
  assert.equal("disk" in body, false);
});

test("accepted response is flat and exact", () => {
  assert.deepEqual(
    parseCatCreateV2AcceptedResponse({ cat_id: "cat_01", operation_id: "op_01" }),
    { cat_id: "cat_01", operation_id: "op_01" },
  );
  assert.throws(() => parseCatCreateV2AcceptedResponse({
    cat: { id: "cat_01" },
    operation: { id: "op_01" },
  }));
  assert.throws(() => parseCatCreateV2AcceptedResponse({
    cat_id: "cat_01",
    operation_id: "op_01",
    legacy: true,
  }));
  assert.deepEqual(
    parseCatCreateV2AcceptedResponseBody('{"cat_id":"cat_01","operation_id":"op_01"}'),
    { cat_id: "cat_01", operation_id: "op_01" },
  );
  assert.throws(() => parseCatCreateV2AcceptedResponseBody(
    '{"cat_id":"cat_01","cat_id":"cat_02","operation_id":"op_01"}',
  ));
});

test("closed legacy authority paths fail locally while exact create remains allowed", () => {
  assert.doesNotThrow(() => assertRuntimeCutoverClientRequestSupported(
    "/v1/workspaces/ws_01/cats",
    "POST",
  ));
  for (const [method, path] of [
    ["GET", "/v1/workspaces/ws_01/cats"],
    ["POST", "/v1/workspaces//cats"],
    ["GET", "/v1/workspaces/ws_01/cats/cat_01"],
    ["POST", "/v1/workspaces/ws_01/cats/cat_01/actions/start"],
    ["POST", "/v1/workspaces/ws_01/cats/cat_01/endpoints"],
    ["GET", "/v1/workspaces/ws_01/disks"],
    ["GET", "/v1/workspaces/ws_01/operations"],
    ["GET", "/v1/operations/op_01"],
    ["GET", "/v1/admin/monitoring"],
    ["GET", "/v1/admin/nodes"],
    ["POST", "/v1/admin/nodes/node_01/actions/drain"],
  ]) {
    assert.throws(
      () => assertRuntimeCutoverClientRequestSupported(path, method),
      /no request was sent/,
      `${method} ${path}`,
    );
  }
});

test("commit then lost response replays exact path, body, and key after page restart", async () => {
  const storage = new MemoryStorage();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const body = requestBody();
  const requests = [];
  const cats = new Map();
  const operations = new Map();
  let dropCommittedResponse = true;
  const server = async (requestPath, options) => {
    assert.equal(
      listPendingCatCreateV2({ storage, workspaceId }).length,
      1,
      "exact recovery state must exist before transport",
    );
    requests.push({ path: requestPath, body: options.body, key: options.headers["Idempotency-Key"] });
    let result = operations.get(options.headers["Idempotency-Key"]);
    if (!result) {
      result = accepted();
      operations.set(options.headers["Idempotency-Key"], result);
      cats.set("cat_01", { id: "cat_01", name: "app" });
    }
    if (dropCommittedResponse) {
      dropCommittedResponse = false;
      throw new Error("connection closed after commit");
    }
    return result;
  };

  await assert.rejects(
    sendDurableCatCreateV2({
      storage,
      lockManager: new MemoryLocks(),
      workspaceId,
      path,
      requestBody: body,
      send: server,
      idempotencyKeyFactory: () => "page-restart-key",
    }),
    /remains pending/,
  );
  assert.equal(listPendingCatCreateV2({ storage, workspaceId }).length, 1);

  let rendered;
  const replayed = await sendDurableCatCreateV2({
    storage,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: body,
    send: server,
    onAccepted: (value) => { rendered = value; },
    idempotencyKeyFactory: () => { throw new Error("replay generated a new key"); },
  });
  assert.deepEqual(replayed, { cat_id: "cat_01", operation_id: "op_01" });
  assert.deepEqual(rendered, replayed);
  assert.equal(cats.size, 1);
  assert.equal(operations.size, 1);
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1], requests[0]);
  assert.equal(requests[0].path, path);
  assert.equal(requests[0].body, body);
  assert.equal(listPendingCatCreateV2({ storage, workspaceId }).length, 0);
});

test("different request conflicts with pending intent before transport", async () => {
  const storage = new MemoryStorage();
  const locks = new MemoryLocks();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let sends = 0;
  await assert.rejects(sendDurableCatCreateV2({
    storage,
    lockManager: locks,
    workspaceId,
    path,
    requestBody: requestBody(2),
    send: async () => {
      sends += 1;
      throw new Error("ambiguous transport");
    },
    idempotencyKeyFactory: () => "pending-key",
  }), /remains pending/);
  await assert.rejects(sendDurableCatCreateV2({
    storage,
    lockManager: locks,
    workspaceId,
    path,
    requestBody: requestBody(3),
    send: async () => { sends += 1; },
    idempotencyKeyFactory: () => "different-key",
  }), /different exact body.*no request was sent/);
  assert.equal(sends, 1);
  assert.equal(listPendingCatCreateV2({ storage, workspaceId }).length, 1);
});

test("exact deterministic name conflict clears pending while ambiguous status retains it", async () => {
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const terminalStorage = new MemoryStorage();
  const nameConflict = new Error("already exists");
  Object.assign(nameConflict, {
    status: 409,
    code: "already_exists",
    contentType: "application/json",
    contentEncoding: "",
    body: '{"code":"already_exists","message":"cat name already exists"}',
  });
  await assert.rejects(sendDurableCatCreateV2({
    storage: terminalStorage,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => { throw nameConflict; },
    idempotencyKeyFactory: () => "terminal-key",
  }), /already exists/);
  assert.equal(listPendingCatCreateV2({ storage: terminalStorage, workspaceId }).length, 0);

  const ambiguousStorage = new MemoryStorage();
  await assert.rejects(sendDurableCatCreateV2({
    storage: ambiguousStorage,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => ({
      status: 503,
      contentType: "application/json",
      contentEncoding: "",
      body: '{"code":"unavailable","message":"retry"}',
    }),
    idempotencyKeyFactory: () => "ambiguous-key",
  }), /remains pending/);
  assert.equal(listPendingCatCreateV2({ storage: ambiguousStorage, workspaceId }).length, 1);

  const malformedAcceptedStorage = new MemoryStorage();
  await assert.rejects(sendDurableCatCreateV2({
    storage: malformedAcceptedStorage,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => accepted('{"cat":{"id":"cat_01"},"operation":{"id":"op_01"}}'),
    idempotencyKeyFactory: () => "malformed-accepted-key",
  }), /remains pending/);
  assert.equal(
    listPendingCatCreateV2({ storage: malformedAcceptedStorage, workspaceId }).length,
    1,
  );
});

test("cross-page concurrent submit fails locally and emits only one request", async () => {
  const storage = new MemoryStorage();
  const locks = new MemoryLocks();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  let sends = 0;
  const first = sendDurableCatCreateV2({
    storage,
    lockManager: locks,
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => {
      sends += 1;
      await held;
      return accepted();
    },
    idempotencyKeyFactory: () => "concurrent-key",
  });
  await new Promise((resolve) => setImmediate(resolve));
  await assert.rejects(sendDurableCatCreateV2({
    storage,
    lockManager: locks,
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => { sends += 1; return accepted(); },
    idempotencyKeyFactory: () => "duplicate-key",
  }), /already active.*no duplicate request was sent/);
  release();
  await first;
  assert.equal(sends, 1);
});
