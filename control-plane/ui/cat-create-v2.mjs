const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const CAT_NAME = /^[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_ROOT_SIZE_BYTES = 1_099_511_627_776;
const JSON_CONTENT_TYPE = "application/json";
const PENDING_PREFIX = "cats.cat-create-v2.pending.v1:";
const MAX_PENDING_PER_WORKSPACE = 32;
const NAME_CONFLICT_BODY = '{"code":"already_exists","message":"cat name already exists"}';

function positiveSafeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return parsed;
}

// Build the exact six-field frozen Cat-create v2 request.
export function buildCatCreateV2Request({
  name,
  bootImageDigest,
  vcpus,
  memoryMib,
  rootGib,
  durability,
}) {
  const normalizedName = String(name).trim();
  const digest = String(bootImageDigest).trim();
  if (!CAT_NAME.test(normalizedName)) throw new Error("invalid Cat name");
  if (!SHA256.test(digest)) throw new Error("invalid boot image digest");
  const memoryBytes = positiveSafeInteger(Number(memoryMib) * (1024 ** 2), "memory_bytes");
  const rootSizeBytes = positiveSafeInteger(Number(rootGib) * (1024 ** 3), "root_size_bytes");
  if (rootSizeBytes > MAX_ROOT_SIZE_BYTES) throw new Error("root_size_bytes is too large");
  if (durability !== "strict" && durability !== "relaxed") {
    throw new Error("invalid durability");
  }
  return validateCatCreateV2Request({
    name: normalizedName,
    boot_image_digest: digest,
    vcpus: positiveSafeInteger(vcpus, "vcpus"),
    memory_bytes: memoryBytes,
    root_size_bytes: rootSizeBytes,
    durability,
  });
}

function validateCatCreateV2Request(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid Cat-create request");
  }
  const keys = Object.keys(value);
  const expected = [
    "name",
    "boot_image_digest",
    "vcpus",
    "memory_bytes",
    "root_size_bytes",
    "durability",
  ];
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("invalid Cat-create request fields");
  }
  if (
    typeof value.name !== "string"
    || typeof value.boot_image_digest !== "string"
    || !CAT_NAME.test(value.name)
    || !SHA256.test(value.boot_image_digest)
  ) {
    throw new Error("invalid Cat-create request identity");
  }
  if (!Number.isSafeInteger(value.vcpus) || value.vcpus <= 0) {
    throw new Error("vcpus must be a positive safe integer");
  }
  if (!Number.isSafeInteger(value.memory_bytes) || value.memory_bytes <= 0) {
    throw new Error("memory_bytes must be a positive safe integer");
  }
  if (!Number.isSafeInteger(value.root_size_bytes) || value.root_size_bytes <= 0) {
    throw new Error("root_size_bytes must be a positive safe integer");
  }
  const rootSizeBytes = value.root_size_bytes;
  if (rootSizeBytes > MAX_ROOT_SIZE_BYTES) throw new Error("root_size_bytes is too large");
  if (typeof value.durability !== "string"
    || (value.durability !== "strict" && value.durability !== "relaxed")) {
    throw new Error("invalid durability");
  }
  return value;
}

export function parseCatCreateV2RequestBody(body) {
  let value;
  try {
    value = JSON.parse(body);
  } catch (_) {
    throw new Error("invalid Cat-create request JSON");
  }
  const request = validateCatCreateV2Request(value);
  if (JSON.stringify(request) !== body) {
    throw new Error("Cat-create request is not canonical");
  }
  return request;
}

export function catCreateV2Path(workspaceId) {
  if (typeof workspaceId !== "string") throw new Error("invalid immutable Workspace ID");
  const canonicalWorkspaceId = workspaceId;
  if (!ID.test(canonicalWorkspaceId)) throw new Error("invalid immutable Workspace ID");
  return `/v1/workspaces/${canonicalWorkspaceId}/cats`;
}

// Parse the exact flat `202 Accepted` response, rejecting legacy envelopes.
export function parseCatCreateV2AcceptedResponse(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid Cat-create accepted response");
  }
  const keys = Object.keys(value).sort();
  if (keys.length !== 2 || keys[0] !== "cat_id" || keys[1] !== "operation_id") {
    throw new Error("invalid Cat-create accepted response");
  }
  if (
    typeof value.cat_id !== "string"
    || typeof value.operation_id !== "string"
    || !ID.test(value.cat_id)
    || !ID.test(value.operation_id)
  ) {
    throw new Error("invalid Cat-create accepted response IDs");
  }
  return { cat_id: value.cat_id, operation_id: value.operation_id };
}

export function parseCatCreateV2AcceptedResponseBody(body) {
  let value;
  try {
    value = JSON.parse(body);
  } catch (_) {
    throw new Error("invalid Cat-create accepted response JSON");
  }
  const accepted = parseCatCreateV2AcceptedResponse(value);
  if (JSON.stringify(accepted) !== body) {
    throw new Error("Cat-create accepted response is not canonical");
  }
  return accepted;
}

// Fail locally for every production route whose legacy authority is closed.
// The sole resource exception is the exact Cat-create collection POST.
export function assertRuntimeCutoverClientRequestSupported(path, method = "GET") {
  const normalizedMethod = String(method).toUpperCase();
  const catCollection = /^\/v1\/workspaces\/[^/?]+\/cats$/;
  if (catCollection.test(path) && normalizedMethod === "POST") return;
  const retiredWorkspaceSurface = /^\/v1\/workspaces\/[^/]*\/(?:cats|disks|operations)(?:[/?]|$)/;
  const retiredGlobalOperation = /^\/v1\/operations(?:[/?]|$)/;
  const retiredFleetSurface = /^\/v1\/admin\/(?:nodes|monitoring)(?:[/?]|$)/;
  if (
    retiredWorkspaceSurface.test(path)
    || retiredGlobalOperation.test(path)
    || retiredFleetSurface.test(path)
  ) {
    throw new Error("This feature is unavailable during the signed runtime cutover; no request was sent.");
  }
}

function pendingStorageKey(workspaceId, name) {
  return `${PENDING_PREFIX}${encodeURIComponent(workspaceId)}:${encodeURIComponent(name)}`;
}

function pendingLockName(workspaceId, name) {
  return `cats-cat-create-v2:${encodeURIComponent(workspaceId)}:${encodeURIComponent(name)}`;
}

function validateIdempotencyKey(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    throw new Error("invalid Cat-create Idempotency-Key");
  }
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) throw new Error("invalid Cat-create Idempotency-Key");
  }
  return value;
}

function defaultIdempotencyKey() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  if (!globalThis.crypto?.getRandomValues) {
    throw new Error("secure browser randomness is unavailable; no Cat-create request was sent");
  }
  const bytes = globalThis.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const hex = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function exactPendingRecord(raw, expectedKey = "") {
  let record;
  try {
    record = JSON.parse(raw);
  } catch (_) {
    throw new Error("pending Cat-create state is not valid JSON; no request was sent");
  }
  if (!record || typeof record !== "object" || Array.isArray(record)) {
    throw new Error("pending Cat-create state is invalid; no request was sent");
  }
  const keys = Object.keys(record);
  const expectedKeys = [
    "version",
    "authenticated_workspace_id",
    "method",
    "path",
    "content_type",
    "idempotency_key",
    "request_body",
  ];
  if (
    keys.length !== expectedKeys.length
    || keys.some((key, index) => key !== expectedKeys[index])
    || JSON.stringify(record) !== raw
  ) {
    throw new Error("pending Cat-create state is not canonical; no request was sent");
  }
  if (record.version !== 1 || record.method !== "POST" || record.content_type !== JSON_CONTENT_TYPE) {
    throw new Error("pending Cat-create state changed its HTTP binding; no request was sent");
  }
  const request = parseCatCreateV2RequestBody(record.request_body);
  if (
    record.path !== catCreateV2Path(record.authenticated_workspace_id)
    || !ID.test(record.authenticated_workspace_id)
  ) {
    throw new Error("pending Cat-create state changed its path binding; no request was sent");
  }
  validateIdempotencyKey(record.idempotency_key);
  const storageKey = pendingStorageKey(record.authenticated_workspace_id, request.name);
  if (expectedKey && storageKey !== expectedKey) {
    throw new Error("pending Cat-create state changed its storage binding; no request was sent");
  }
  return { record, request, storageKey };
}

function storageGet(storage, key) {
  let value;
  try {
    value = storage.getItem(key);
  } catch (error) {
    throw new Error(`browser durable storage is unavailable: ${error.message}; no Cat-create request was sent`);
  }
  return value;
}

function persistNewPending(storage, key, record) {
  const raw = JSON.stringify(record);
  try {
    storage.setItem(key, raw);
  } catch (error) {
    throw new Error(`could not durably save Cat-create recovery state: ${error.message}; no request was sent`);
  }
  if (storageGet(storage, key) !== raw) {
    throw new Error("browser did not retain exact Cat-create recovery state; no request was sent");
  }
  return exactPendingRecord(raw, key).record;
}

function clearPending(storage, key, expected) {
  const current = storageGet(storage, key);
  if (current === null) return;
  const loaded = exactPendingRecord(current, key).record;
  if (JSON.stringify(loaded) !== JSON.stringify(expected)) {
    throw new Error("pending Cat-create state changed before terminal cleanup");
  }
  try {
    storage.removeItem(key);
  } catch (error) {
    throw new Error(`could not clear terminal Cat-create recovery state: ${error.message}`);
  }
  if (storageGet(storage, key) !== null) {
    throw new Error("browser did not clear terminal Cat-create recovery state");
  }
}

function preparePending(storage, workspaceId, path, requestBody, idempotencyKeyFactory) {
  const request = parseCatCreateV2RequestBody(requestBody);
  const canonicalPath = catCreateV2Path(workspaceId);
  if (path !== canonicalPath) throw new Error("Cat-create path is not canonical; no request was sent");
  assertRuntimeCutoverClientRequestSupported(path, "POST");
  const key = pendingStorageKey(workspaceId, request.name);
  const existingRaw = storageGet(storage, key);
  if (existingRaw !== null) {
    const existing = exactPendingRecord(existingRaw, key).record;
    if (
      existing.authenticated_workspace_id !== workspaceId
      || existing.path !== path
      || existing.request_body !== requestBody
    ) {
      throw new Error(
        "an unresolved Cat-create request for this Workspace and Cat name has a different exact body; no request was sent",
      );
    }
    return { key, record: existing };
  }
  const record = {
    version: 1,
    authenticated_workspace_id: workspaceId,
    method: "POST",
    path,
    content_type: JSON_CONTENT_TYPE,
    idempotency_key: validateIdempotencyKey(idempotencyKeyFactory()),
    request_body: requestBody,
  };
  return { key, record: persistNewPending(storage, key, record) };
}

function isExactNameConflict(error) {
  return error?.status === 409
    && error?.contentType === JSON_CONTENT_TYPE
    && !error?.contentEncoding
    && error?.body === NAME_CONFLICT_BODY;
}

function pendingFailure(error) {
  const failure = new Error(
    `${error?.message || String(error)}; the exact Cat-create request remains pending and will be replayed with the same Idempotency-Key`,
    { cause: error },
  );
  failure.name = error?.name || "Error";
  failure.status = error?.status || 0;
  failure.code = error?.code || "";
  failure.catCreatePending = true;
  return failure;
}

/**
 * Save and send one exact Cat-create request under a same-origin Web Lock.
 * `localStorage` is browser-persistent recovery state, not a defense against
 * malicious local users or scripts already executing in this origin.
 */
export async function sendDurableCatCreateV2({
  storage = globalThis.localStorage,
  lockManager = globalThis.navigator?.locks,
  workspaceId,
  path,
  requestBody,
  send,
  onAccepted = () => {},
  idempotencyKeyFactory = defaultIdempotencyKey,
}) {
  const request = parseCatCreateV2RequestBody(requestBody);
  if (!lockManager?.request) {
    throw new Error("browser cross-page locking is unavailable; no Cat-create request was sent");
  }
  if (typeof send !== "function") throw new Error("Cat-create transport is unavailable");
  const lockName = pendingLockName(workspaceId, request.name);
  return lockManager.request(
    lockName,
    { mode: "exclusive", ifAvailable: true },
    async (lock) => {
      if (!lock) {
        throw new Error("this Cat-create request is already active in another page; no duplicate request was sent");
      }
      const { key, record } = preparePending(
        storage,
        workspaceId,
        path,
        requestBody,
        idempotencyKeyFactory,
      );
      let response;
      try {
        response = await send(record.path, {
          method: record.method,
          redirect: "error",
          headers: {
            "Content-Type": record.content_type,
            "Idempotency-Key": record.idempotency_key,
          },
          body: record.request_body,
        });
      } catch (error) {
        if (isExactNameConflict(error)) {
          clearPending(storage, key, record);
          throw error;
        }
        throw pendingFailure(error);
      }
      if (
        response?.status !== 202
        || response?.contentType !== JSON_CONTENT_TYPE
        || response?.contentEncoding
      ) {
        throw pendingFailure(new Error(
          `Cat create returned a non-terminal HTTP response; expected exact 202 application/json`,
        ));
      }
      let accepted;
      try {
        accepted = parseCatCreateV2AcceptedResponseBody(response.body);
      } catch (error) {
        throw pendingFailure(error);
      }
      // Let the page render the durable Cat/Operation identity before clearing
      // recovery state. If rendering throws or the page dies, reload replays.
      try {
        await onAccepted(accepted);
      } catch (error) {
        throw pendingFailure(error);
      }
      clearPending(storage, key, record);
      return accepted;
    },
  );
}

export function listPendingCatCreateV2({ storage = globalThis.localStorage, workspaceId }) {
  catCreateV2Path(workspaceId);
  const prefix = `${PENDING_PREFIX}${encodeURIComponent(workspaceId)}:`;
  const keys = [];
  let length;
  try {
    length = storage.length;
    for (let index = 0; index < length; index += 1) {
      const key = storage.key(index);
      if (key?.startsWith(prefix)) keys.push(key);
    }
  } catch (error) {
    throw new Error(`browser durable storage is unavailable: ${error.message}`);
  }
  if (keys.length > MAX_PENDING_PER_WORKSPACE) {
    throw new Error("too many pending Cat-create requests; automatic replay stopped");
  }
  keys.sort();
  return keys.map((key) => {
    const raw = storageGet(storage, key);
    if (raw === null) return null;
    const { record } = exactPendingRecord(raw, key);
    if (record.authenticated_workspace_id !== workspaceId) {
      throw new Error("pending Cat-create state crossed its Workspace boundary");
    }
    return { path: record.path, requestBody: record.request_body };
  }).filter(Boolean);
}
