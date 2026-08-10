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

class MemoryDurablePendingStore {
  #values = new Map();

  #transactions = Promise.resolve();

  #nextInsertBarrier = null;

  #nextInsertError = null;

  delayNextInsertUntil(barrier) {
    let started;
    const startedPromise = new Promise((resolve) => { started = resolve; });
    this.#nextInsertBarrier = { barrier, started };
    return startedPromise;
  }

  abortNextInsert(error) {
    this.#nextInsertError = error;
  }

  replaceRaw(key, raw) {
    const existing = this.#values.get(key);
    assert.ok(existing, `missing pending key ${key}`);
    this.#values.set(key, { ...existing, raw });
  }

  async #writeTransaction(action) {
    const running = this.#transactions.then(action, action);
    this.#transactions = running.then(() => {}, () => {});
    return running;
  }

  async load(key) {
    await this.#transactions;
    return this.#values.get(key)?.raw ?? null;
  }

  async insertWithinWorkspaceLimit({ workspaceId, key, raw, maximum }) {
    return this.#writeTransaction(async () => {
      const existing = this.#values.get(key);
      if (existing) return { kind: "existing", raw: existing.raw };
      const count = Array.from(this.#values.values())
        .filter((value) => value.workspaceId === workspaceId)
        .length;
      if (count >= maximum) return { kind: "limit" };
      const pendingBarrier = this.#nextInsertBarrier;
      this.#nextInsertBarrier = null;
      if (pendingBarrier) {
        pendingBarrier.started();
        await pendingBarrier.barrier;
      }
      const insertError = this.#nextInsertError;
      this.#nextInsertError = null;
      if (insertError) throw insertError;
      this.#values.set(key, { workspaceId, raw });
      return { kind: "inserted", raw };
    });
  }

  async deleteIfExact(key, expectedRaw) {
    return this.#writeTransaction(async () => {
      const existing = this.#values.get(key);
      if (!existing) return "absent";
      if (existing.raw !== expectedRaw) return "changed";
      this.#values.delete(key);
      return "deleted";
    });
  }

  async listWorkspace(workspaceId, maximum) {
    await this.#transactions;
    return Array.from(this.#values.entries())
      .filter(([, value]) => value.workspaceId === workspaceId)
      .sort(([left], [right]) => left.localeCompare(right))
      .slice(0, maximum)
      .map(([key, value]) => ({ key, raw: value.raw }));
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

class PausedCallbackLocks {
  #releaseCallback;

  #requested;

  constructor() {
    this.requested = new Promise((resolve) => { this.#requested = resolve; });
    this.callbackBarrier = new Promise((resolve) => { this.#releaseCallback = resolve; });
  }

  release() {
    this.#releaseCallback();
  }

  async request(name, options, callback) {
    assert.deepEqual(options, { mode: "exclusive", ifAvailable: true });
    this.#requested();
    await this.callbackBarrier;
    return callback({ name, mode: "exclusive" });
  }
}

function requestBody(vcpus = 2, name = "app") {
  return JSON.stringify(buildCatCreateV2Request({
    name,
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
  const pendingStore = new MemoryDurablePendingStore();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const body = requestBody();
  const requests = [];
  const cats = new Map();
  const operations = new Map();
  let dropCommittedResponse = true;
  const server = async (requestPath, options) => {
    assert.equal(
      (await listPendingCatCreateV2({ pendingStore, workspaceId })).length,
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
      pendingStore,
      lockManager: new MemoryLocks(),
      workspaceId,
      path,
      requestBody: body,
      send: server,
      idempotencyKeyFactory: () => "page-restart-key",
    }),
    /remains pending/,
  );
  const [pending] = await listPendingCatCreateV2({ pendingStore, workspaceId });
  assert.ok(pending);
  assert.deepEqual(Reflect.ownKeys(pending.expectedPending), []);

  let rendered;
  const replayed = await sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path: pending.path,
    requestBody: pending.requestBody,
    send: server,
    onAccepted: (value) => { rendered = value; },
    idempotencyKeyFactory: () => { throw new Error("replay generated a new key"); },
    expectedPending: pending.expectedPending,
  });
  assert.deepEqual(replayed, { cat_id: "cat_01", operation_id: "op_01" });
  assert.deepEqual(rendered, replayed);
  assert.equal(cats.size, 1);
  assert.equal(operations.size, 1);
  assert.equal(requests.length, 2);
  assert.deepEqual(requests[1], requests[0]);
  assert.equal(requests[0].path, path);
  assert.equal(requests[0].body, body);
  assert.equal((await listPendingCatCreateV2({ pendingStore, workspaceId })).length, 0);
});

test("different request conflicts with pending intent before transport", async () => {
  const pendingStore = new MemoryDurablePendingStore();
  const locks = new MemoryLocks();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let sends = 0;
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore,
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
    pendingStore,
    lockManager: locks,
    workspaceId,
    path,
    requestBody: requestBody(3),
    send: async () => { sends += 1; },
    idempotencyKeyFactory: () => "different-key",
  }), /different exact body.*no request was sent/);
  assert.equal(sends, 1);
  assert.equal((await listPendingCatCreateV2({ pendingStore, workspaceId })).length, 1);
});

test("exact deterministic name conflict clears pending while ambiguous status retains it", async () => {
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const terminalStore = new MemoryDurablePendingStore();
  const nameConflict = new Error("already exists");
  Object.assign(nameConflict, {
    status: 409,
    code: "already_exists",
    contentType: "application/json",
    contentEncoding: "",
    body: '{"code":"already_exists","message":"cat name already exists"}',
  });
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore: terminalStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => { throw nameConflict; },
    idempotencyKeyFactory: () => "terminal-key",
  }), /already exists/);
  assert.equal(
    (await listPendingCatCreateV2({ pendingStore: terminalStore, workspaceId })).length,
    0,
  );

  const ambiguousStore = new MemoryDurablePendingStore();
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore: ambiguousStore,
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
  assert.equal(
    (await listPendingCatCreateV2({ pendingStore: ambiguousStore, workspaceId })).length,
    1,
  );

  const malformedAcceptedStore = new MemoryDurablePendingStore();
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore: malformedAcceptedStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => accepted('{"cat":{"id":"cat_01"},"operation":{"id":"op_01"}}'),
    idempotencyKeyFactory: () => "malformed-accepted-key",
  }), /remains pending/);
  assert.equal(
    (await listPendingCatCreateV2({
      pendingStore: malformedAcceptedStore,
      workspaceId,
    })).length,
    1,
  );
});

test("cross-page concurrent submit fails locally and emits only one request", async () => {
  const pendingStore = new MemoryDurablePendingStore();
  const locks = new MemoryLocks();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  let sends = 0;
  const first = sendDurableCatCreateV2({
    pendingStore,
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
    pendingStore,
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

test("transport waits for the durable commit barrier and an aborted commit sends nothing", async () => {
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const pendingStore = new MemoryDurablePendingStore();
  let releaseCommit;
  const commitBarrier = new Promise((resolve) => { releaseCommit = resolve; });
  const insertStarted = pendingStore.delayNextInsertUntil(commitBarrier);
  let sends = 0;
  const creating = sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => {
      sends += 1;
      return accepted();
    },
    idempotencyKeyFactory: () => "durable-barrier-key",
  });
  await insertStarted;
  assert.equal(sends, 0, "transport ran before the durable transaction completed");
  releaseCommit();
  await creating;
  assert.equal(sends, 1);

  const abortedStore = new MemoryDurablePendingStore();
  abortedStore.abortNextInsert(new Error("injected strict transaction abort"));
  let abortedSends = 0;
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore: abortedStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => { abortedSends += 1; return accepted(); },
    idempotencyKeyFactory: () => "aborted-key",
  }), /injected strict transaction abort/);
  assert.equal(abortedSends, 0);
  assert.equal(
    (await listPendingCatCreateV2({ pendingStore: abortedStore, workspaceId })).length,
    0,
  );
});

test("missing strict browser storage capability fails before transport", async () => {
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let sends = 0;
  await assert.rejects(sendDurableCatCreateV2({
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: requestBody(),
    send: async () => { sends += 1; return accepted(); },
    idempotencyKeyFactory: () => "must-not-be-persisted",
  }), /strict browser durable storage is unavailable.*no Cat-create request was sent/);
  assert.equal(sends, 0);
});

test("paused replay snapshot skips after another page clears instead of minting K2", async () => {
  const pendingStore = new MemoryDurablePendingStore();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const body = requestBody();
  const keys = [];
  let first = true;
  const server = async (_requestPath, options) => {
    keys.push(options.headers["Idempotency-Key"]);
    if (first) {
      first = false;
      throw new Error("ambiguous response");
    }
    return accepted();
  };
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: body,
    send: server,
    idempotencyKeyFactory: () => "K1",
  }), /remains pending/);
  const [paused] = await listPendingCatCreateV2({ pendingStore, workspaceId });
  const [active] = await listPendingCatCreateV2({ pendingStore, workspaceId });

  const pausedLocks = new PausedCallbackLocks();
  let staleSends = 0;
  const staleReplay = sendDurableCatCreateV2({
    pendingStore,
    lockManager: pausedLocks,
    workspaceId,
    path: paused.path,
    requestBody: paused.requestBody,
    send: async () => { staleSends += 1; return accepted(); },
    idempotencyKeyFactory: () => { throw new Error("stale replay minted K2"); },
    expectedPending: paused.expectedPending,
  });
  await pausedLocks.requested;

  await sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path: active.path,
    requestBody: active.requestBody,
    send: server,
    expectedPending: active.expectedPending,
  });
  pausedLocks.release();
  const skipped = await staleReplay;
  assert.equal(skipped, null);
  assert.equal(staleSends, 0);
  assert.deepEqual(keys, ["K1", "K1"]);
  assert.equal((await listPendingCatCreateV2({ pendingStore, workspaceId })).length, 0);
});

test("changed replay token fails closed before transport", async () => {
  const pendingStore = new MemoryDurablePendingStore();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  const body = requestBody();
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path,
    requestBody: body,
    send: async () => { throw new Error("ambiguous"); },
    idempotencyKeyFactory: () => "original-key",
  }), /remains pending/);
  const [pending] = await listPendingCatCreateV2({ pendingStore, workspaceId });
  const [entry] = await pendingStore.listWorkspace(workspaceId, 1);
  const changed = JSON.parse(entry.raw);
  changed.idempotency_key = "changed-key";
  pendingStore.replaceRaw(entry.key, JSON.stringify(changed));
  let sends = 0;
  await assert.rejects(sendDurableCatCreateV2({
    pendingStore,
    lockManager: new MemoryLocks(),
    workspaceId,
    path: pending.path,
    requestBody: pending.requestBody,
    send: async () => { sends += 1; return accepted(); },
    expectedPending: pending.expectedPending,
  }), /changed after recovery enumeration.*no request was sent/);
  assert.equal(sends, 0);
});

test("workspace limit rejects the 33rd concurrent fresh request but permits exact replay at 32", async () => {
  const pendingStore = new MemoryDurablePendingStore();
  const locks = new MemoryLocks();
  const workspaceId = "ws_01";
  const path = catCreateV2Path(workspaceId);
  let sends = 0;
  const attempts = Array.from({ length: 33 }, (_, index) => {
    const name = `app-${String(index).padStart(2, "0")}`;
    return sendDurableCatCreateV2({
      pendingStore,
      lockManager: locks,
      workspaceId,
      path,
      requestBody: requestBody(2, name),
      send: async () => {
        sends += 1;
        throw new Error("ambiguous outage");
      },
      idempotencyKeyFactory: () => `limit-key-${index}`,
    });
  });
  const results = await Promise.allSettled(attempts);
  assert.equal(results.filter((result) => result.status === "rejected").length, 33);
  assert.equal(
    results.filter((result) => result.reason.message.includes("too many pending")).length,
    1,
  );
  assert.equal(sends, 32);
  const pending = await listPendingCatCreateV2({ pendingStore, workspaceId });
  assert.equal(pending.length, 32);

  const replayed = await sendDurableCatCreateV2({
    pendingStore,
    lockManager: locks,
    workspaceId,
    path: pending[0].path,
    requestBody: pending[0].requestBody,
    send: async () => {
      sends += 1;
      return accepted();
    },
    idempotencyKeyFactory: () => { throw new Error("exact replay minted a key at the limit"); },
    expectedPending: pending[0].expectedPending,
  });
  assert.deepEqual(replayed, { cat_id: "cat_01", operation_id: "op_01" });
  assert.equal(sends, 33);
  assert.equal(
    (await listPendingCatCreateV2({ pendingStore, workspaceId })).length,
    31,
  );
});
