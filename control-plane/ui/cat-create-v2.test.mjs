import assert from "node:assert/strict";
import test from "node:test";

import {
  assertRuntimeCutoverClientRequestSupported,
  buildCatCreateV2Request,
  parseCatCreateV2AcceptedResponse,
  parseCatCreateV2AcceptedResponseBody,
} from "./cat-create-v2.mjs";

const DIGEST = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

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
