import {
  assertRuntimeCutoverClientRequestSupported,
  IndexedDbPendingStore,
  validatePendingStore,
} from "./cat-create-v2.mjs";

const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const PRODUCT_DISK_ID = /^disk_[0-9a-f]{32}$/;
const VOLUME_ID = /^vol_[0-9a-f]{32}$/;
const JSON_CONTENT_TYPE = "application/json";
const MAX_VOLUME_BYTES = 1_099_511_627_776;
const PENDING_PREFIX = "cats.persistent-disk-create-v1.pending.v1:";
const PENDING_DATABASE = "cats-persistent-disk-create-v1-authority-v1";
const MAX_PENDING_PER_WORKSPACE = 32;
const NAME_CONFLICT_BODY = '{"code":"already_exists","message":"disk name already exists"}';

function positiveSafeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return parsed;
}

function validateDurability(value) {
  if (value !== "strict" && value !== "relaxed") {
    throw new Error("invalid PersistentDisk durability");
  }
  return value;
}

function validatePersistentDiskCreateV1Request(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw new Error("invalid PersistentDisk-create request");
  }
  const expected = ["durability", "name", "size_bytes"];
  const keys = Object.keys(value);
  if (keys.length !== expected.length || keys.some((key, index) => key !== expected[index])) {
    throw new Error("invalid PersistentDisk-create request fields");
  }
  if (typeof value.name !== "string" || !ID.test(value.name)) {
    throw new Error("invalid PersistentDisk name");
  }
  validateDurability(value.durability);
  positiveSafeInteger(value.size_bytes, "size_bytes");
  if (value.size_bytes > MAX_VOLUME_BYTES) {
    throw new Error("size_bytes is too large");
  }
  return value;
}

// Build the exact closed PersistentDiskCreateV1Request. The user console has
// no durability selector, so its explicit and fail-closed product default is
// Strict; callers that supply a value must still choose a frozen enum member.
export function buildPersistentDiskCreateV1Request({
  name,
  sizeGib,
  durability = "strict",
}) {
  const normalizedName = String(name ?? "").trim();
  const sizeBytes = positiveSafeInteger(Number(sizeGib) * (1024 ** 3), "size_bytes");
  return validatePersistentDiskCreateV1Request({
    durability: validateDurability(durability),
    name: normalizedName,
    size_bytes: sizeBytes,
  });
}

export function parsePersistentDiskCreateV1RequestBody(body) {
  let value;
  try {
    value = JSON.parse(body);
  } catch (_) {
    throw new Error("invalid PersistentDisk-create request JSON");
  }
  const request = validatePersistentDiskCreateV1Request(value);
  if (JSON.stringify(request) !== body) {
    throw new Error("PersistentDisk-create request is not canonical");
  }
  return request;
}

export function persistentDiskCreateV1Path(workspaceId) {
  if (typeof workspaceId !== "string" || !ID.test(workspaceId)) {
    throw new Error("invalid immutable Workspace ID");
  }
  return `/v1/workspaces/${workspaceId}/disks`;
}

function parseCreatedResponseBody(body, expected) {
  let disk;
  try {
    disk = JSON.parse(body);
  } catch (_) {
    throw new Error("invalid PersistentDisk-create response JSON");
  }
  if (!disk || typeof disk !== "object" || Array.isArray(disk)) {
    throw new Error("invalid PersistentDisk-create response");
  }
  const fields = [
    "id",
    "workspace_id",
    "name",
    "kind",
    "size_bytes",
    "state",
    "durability",
    "volume_id",
    "created_at_unix",
  ];
  const keys = Object.keys(disk);
  if (
    keys.length !== fields.length
    || keys.some((key, index) => key !== fields[index])
    || JSON.stringify(disk) !== body
  ) {
    throw new Error("PersistentDisk-create response is not canonical");
  }
  if (
    !PRODUCT_DISK_ID.test(disk.id)
    || !VOLUME_ID.test(disk.volume_id)
    || disk.workspace_id !== expected.workspaceId
    || disk.name !== expected.request.name
    || disk.kind !== "persistent"
    || disk.size_bytes !== expected.request.size_bytes
    || disk.state !== "available"
    || disk.durability !== expected.request.durability
    || !Number.isSafeInteger(disk.created_at_unix)
    || disk.created_at_unix < 0
  ) {
    throw new Error("PersistentDisk-create response changed its exact request binding");
  }
  return disk;
}

function pendingStorageKey(workspaceId, name) {
  return `${PENDING_PREFIX}${encodeURIComponent(workspaceId)}:${encodeURIComponent(name)}`;
}

function pendingLockName(workspaceId, name) {
  return `cats-persistent-disk-create-v1:${encodeURIComponent(workspaceId)}:${encodeURIComponent(name)}`;
}

function validateIdempotencyKey(value) {
  if (typeof value !== "string" || value.length < 1 || value.length > 512) {
    throw new Error("invalid PersistentDisk-create Idempotency-Key");
  }
  for (const character of value) {
    const code = character.charCodeAt(0);
    if (code < 0x20 || code > 0x7e) {
      throw new Error("invalid PersistentDisk-create Idempotency-Key");
    }
  }
  return value;
}

function defaultIdempotencyKey() {
  if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
  throw new Error(
    "secure browser randomness is unavailable; no PersistentDisk-create request was sent",
  );
}

function exactPendingRecord(raw, expectedKey = "") {
  let record;
  try {
    record = JSON.parse(raw);
  } catch (_) {
    throw new Error("pending PersistentDisk-create state is not valid JSON; no request was sent");
  }
  const fields = [
    "version",
    "authenticated_workspace_id",
    "method",
    "path",
    "content_type",
    "idempotency_key",
    "request_body",
  ];
  const keys = record && typeof record === "object" && !Array.isArray(record)
    ? Object.keys(record)
    : [];
  if (
    keys.length !== fields.length
    || keys.some((key, index) => key !== fields[index])
    || JSON.stringify(record) !== raw
  ) {
    throw new Error("pending PersistentDisk-create state is not canonical; no request was sent");
  }
  const request = parsePersistentDiskCreateV1RequestBody(record.request_body);
  if (
    record.version !== 1
    || record.method !== "POST"
    || record.content_type !== JSON_CONTENT_TYPE
    || record.path !== persistentDiskCreateV1Path(record.authenticated_workspace_id)
  ) {
    throw new Error("pending PersistentDisk-create state changed its HTTP binding; no request was sent");
  }
  validateIdempotencyKey(record.idempotency_key);
  const key = pendingStorageKey(record.authenticated_workspace_id, request.name);
  if (expectedKey && key !== expectedKey) {
    throw new Error("pending PersistentDisk-create state changed its storage binding; no request was sent");
  }
  return { key, record, request };
}

function exactBinding(record, workspaceId, path, requestBody) {
  if (
    record.authenticated_workspace_id !== workspaceId
    || record.path !== path
    || record.request_body !== requestBody
  ) {
    throw new Error(
      "an unresolved PersistentDisk-create request has a different exact body; no request was sent",
    );
  }
}

let defaultStore;

function defaultPendingStore() {
  if (!globalThis.indexedDB || !globalThis.IDBKeyRange) {
    throw new Error(
      "strict browser durable storage is unavailable; no PersistentDisk-create request was sent",
    );
  }
  if (!defaultStore) {
    defaultStore = new IndexedDbPendingStore(globalThis.indexedDB, globalThis.IDBKeyRange, {
      databaseName: PENDING_DATABASE,
      pendingPrefix: PENDING_PREFIX,
      operationLabel: "PersistentDisk-create",
    });
  }
  return defaultStore;
}

async function prepareFresh(store, workspaceId, path, requestBody, request, keyFactory) {
  const key = pendingStorageKey(workspaceId, request.name);
  const existingRaw = await store.load(key);
  if (existingRaw !== null) {
    const existing = exactPendingRecord(existingRaw, key).record;
    exactBinding(existing, workspaceId, path, requestBody);
    return { key, raw: existingRaw, record: existing };
  }
  const record = {
    version: 1,
    authenticated_workspace_id: workspaceId,
    method: "POST",
    path,
    content_type: JSON_CONTENT_TYPE,
    idempotency_key: validateIdempotencyKey(keyFactory()),
    request_body: requestBody,
  };
  const raw = JSON.stringify(record);
  exactPendingRecord(raw, key);
  const result = await store.insertWithinWorkspaceLimit({
    workspaceId,
    key,
    raw,
    maximum: MAX_PENDING_PER_WORKSPACE,
  });
  if (result.kind === "limit") {
    throw new Error("too many pending PersistentDisk-create requests; no new request was sent");
  }
  if (result.kind !== "inserted" && result.kind !== "existing") {
    throw new Error("browser durable storage returned an invalid insert result");
  }
  const prepared = exactPendingRecord(result.raw, key);
  exactBinding(prepared.record, workspaceId, path, requestBody);
  return { key, raw: result.raw, record: prepared.record };
}

const replayBindings = new WeakMap();

class PendingReplayToken {
  constructor(key, raw) {
    replayBindings.set(this, Object.freeze({ key, raw }));
    Object.freeze(this);
  }
}

function replayBinding(token, workspaceId, path, requestBody) {
  const binding = replayBindings.get(token);
  if (!(token instanceof PendingReplayToken) || !binding) {
    throw new Error("pending PersistentDisk-create replay token is invalid; no request was sent");
  }
  const { record } = exactPendingRecord(binding.raw, binding.key);
  exactBinding(record, workspaceId, path, requestBody);
  return { ...binding, record };
}

async function clearPending(store, prepared) {
  const outcome = await store.deleteIfExact(prepared.key, prepared.raw);
  if (outcome === "changed") {
    throw new Error("pending PersistentDisk-create state changed before terminal cleanup");
  }
  if (outcome !== "deleted" && outcome !== "absent") {
    throw new Error("browser durable storage returned an invalid cleanup result");
  }
}

function pendingFailure(error) {
  return new Error(
    `${error?.message || String(error)}; the exact PersistentDisk-create request remains pending and will be replayed with the same Idempotency-Key`,
    { cause: error },
  );
}

export async function sendDurablePersistentDiskCreateV1({
  pendingStore,
  lockManager = globalThis.navigator?.locks,
  workspaceId,
  path,
  requestBody,
  send,
  onCreated = () => {},
  idempotencyKeyFactory = defaultIdempotencyKey,
  expectedPending,
}) {
  const request = parsePersistentDiskCreateV1RequestBody(requestBody);
  const canonicalPath = persistentDiskCreateV1Path(workspaceId);
  if (path !== canonicalPath) {
    throw new Error("PersistentDisk-create path is not canonical; no request was sent");
  }
  assertRuntimeCutoverClientRequestSupported(path, "POST");
  if (!lockManager?.request) {
    throw new Error("browser cross-page locking is unavailable; no PersistentDisk-create request was sent");
  }
  if (typeof send !== "function") throw new Error("PersistentDisk-create transport is unavailable");
  const store = validatePendingStore(pendingStore || defaultPendingStore());
  return lockManager.request(
    pendingLockName(workspaceId, request.name),
    { mode: "exclusive", ifAvailable: true },
    async (lock) => {
      if (!lock) {
        throw new Error("this PersistentDisk-create request is active in another page; no duplicate request was sent");
      }
      let prepared;
      if (expectedPending !== undefined) {
        prepared = replayBinding(expectedPending, workspaceId, path, requestBody);
        const current = await store.load(prepared.key);
        if (current === null) return null;
        if (current !== prepared.raw) {
          throw new Error("pending PersistentDisk-create state changed after recovery enumeration; no request was sent");
        }
      } else {
        prepared = await prepareFresh(
          store,
          workspaceId,
          path,
          requestBody,
          request,
          idempotencyKeyFactory,
        );
      }
      let response;
      try {
        response = await send(prepared.record.path, {
          method: "POST",
          redirect: "error",
          headers: {
            "Content-Type": JSON_CONTENT_TYPE,
            "Idempotency-Key": prepared.record.idempotency_key,
          },
          body: prepared.record.request_body,
        });
      } catch (error) {
        if (
          error?.status === 409
          && error?.contentType === JSON_CONTENT_TYPE
          && !error?.contentEncoding
          && error?.body === NAME_CONFLICT_BODY
        ) {
          await clearPending(store, prepared);
          throw error;
        }
        throw pendingFailure(error);
      }
      if (
        response?.status !== 201
        || response?.contentType !== JSON_CONTENT_TYPE
        || response?.contentEncoding
      ) {
        throw pendingFailure(new Error(
          "PersistentDisk create returned a non-terminal HTTP response; expected exact 201 application/json",
        ));
      }
      let disk;
      try {
        disk = parseCreatedResponseBody(response.body, { workspaceId, request });
        await onCreated(disk);
      } catch (error) {
        throw pendingFailure(error);
      }
      await clearPending(store, prepared);
      return disk;
    },
  );
}

export async function listPendingPersistentDiskCreateV1({ pendingStore, workspaceId }) {
  persistentDiskCreateV1Path(workspaceId);
  const store = validatePendingStore(pendingStore || defaultPendingStore());
  const entries = await store.listWorkspace(workspaceId, MAX_PENDING_PER_WORKSPACE + 1);
  if (entries.length > MAX_PENDING_PER_WORKSPACE) {
    throw new Error("too many pending PersistentDisk-create requests; automatic replay stopped");
  }
  return entries.map(({ key, raw }) => {
    const { record } = exactPendingRecord(raw, key);
    if (record.authenticated_workspace_id !== workspaceId) {
      throw new Error("pending PersistentDisk-create state crossed its Workspace boundary");
    }
    return {
      path: record.path,
      requestBody: record.request_body,
      expectedPending: new PendingReplayToken(key, raw),
    };
  });
}
