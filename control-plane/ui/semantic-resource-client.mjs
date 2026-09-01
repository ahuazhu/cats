const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const JSON_CONTENT_TYPE = "application/json";
const MAX_VOLUME_BYTES = 1_099_511_627_776;

function positiveSafeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
  }
  return parsed;
}

function nonnegativeSafeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
  return parsed;
}

function resourceSlug(value, label) {
  const slug = String(value ?? "").trim();
  if (!SLUG.test(slug)) {
    throw new Error(`${label} must be 1..=63 lowercase letters, digits, or interior hyphens`);
  }
  return slug;
}

function workspaceId(value) {
  if (typeof value !== "string" || !ID.test(value)) {
    throw new Error("invalid immutable Workspace ID");
  }
  return value;
}

function snapshotId(value) {
  if (
    typeof value !== "string"
    || !ID.test(value)
    || !value.startsWith("snapshot_")
    || value === "snapshot_"
  ) {
    throw new Error("invalid immutable DiskSnapshot ID");
  }
  return value;
}

export function catCollectionPath(value) {
  return `/v1/workspaces/${workspaceId(value)}/cats`;
}

export function diskCollectionPath(value) {
  return `/v1/workspaces/${workspaceId(value)}/disks`;
}

export function diskSnapshotCollectionPath(immutableWorkspaceId) {
  return `/v1/workspaces/${workspaceId(immutableWorkspaceId)}/snapshots`;
}

export function diskSnapshotItemPath(immutableWorkspaceId, snapshot) {
  return `${diskSnapshotCollectionPath(immutableWorkspaceId)}/${resourceSlug(snapshot, "DiskSnapshot name")}`;
}

export function diskSnapshotActionPath(immutableWorkspaceId, snapshot, action) {
  const supportedAction = String(action);
  if (!new Set(["destroy", "restore"]).has(supportedAction)) {
    throw new Error("unsupported DiskSnapshot action");
  }
  return `${diskSnapshotItemPath(immutableWorkspaceId, snapshot)}/actions/${supportedAction}`;
}

export function buildSemanticCatCreateRequest({ name, vcpus, memoryMib }) {
  return {
    cat_slug: resourceSlug(name, "Cat name"),
    cpu: positiveSafeInteger(vcpus, "cpu"),
    memory_bytes: positiveSafeInteger(Number(memoryMib) * (1024 ** 2), "memory_bytes"),
    mounts: [],
  };
}

export function buildSemanticDiskCreateRequest({ name, sizeGib }) {
  const sizeBytes = positiveSafeInteger(Number(sizeGib) * (1024 ** 3), "size_bytes");
  if (sizeBytes > MAX_VOLUME_BYTES) throw new Error("size_bytes is too large");
  return {
    disk_slug: resourceSlug(name, "PersistentDisk name"),
    size_bytes: sizeBytes,
  };
}

export function buildSemanticDiskSnapshotCreateRequest({ disk, name }) {
  return {
    snapshot_slug: resourceSlug(name, "DiskSnapshot name"),
    disk_slug: resourceSlug(disk, "PersistentDisk name"),
  };
}

export function buildSemanticDiskSnapshotDestroyRequest({ expectedSnapshotId }) {
  return { expected_snapshot_id: snapshotId(expectedSnapshotId) };
}

export function buildSemanticDiskSnapshotRestoreRequest({
  expectedSnapshotId,
  expectedGeneration,
}) {
  return {
    expected_snapshot_id: snapshotId(expectedSnapshotId),
    expected_generation: nonnegativeSafeInteger(expectedGeneration, "expected_generation"),
  };
}

function validateTransport(response, kind) {
  if (
    !response
    || ![200, 201].includes(response.status)
    || response.contentType !== JSON_CONTENT_TYPE
    || response.contentEncoding
  ) {
    throw new Error(`${kind} create returned an invalid terminal response`);
  }
  if (!response.value || typeof response.value !== "object" || Array.isArray(response.value)) {
    throw new Error(`${kind} create returned an invalid response body`);
  }
  return response.value;
}

export async function createSemanticCat({ immutableWorkspaceId, request, send }) {
  if (typeof send !== "function") throw new Error("Cat create transport is unavailable");
  const path = catCollectionPath(immutableWorkspaceId);
  const expected = buildSemanticCatCreateRequest({
    name: request?.cat_slug,
    vcpus: request?.cpu,
    memoryMib: Number(request?.memory_bytes) / (1024 ** 2),
  });
  const response = validateTransport(await send(path, {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": JSON_CONTENT_TYPE },
    body: JSON.stringify(expected),
  }), "Cat");
  if (
    !response.cat
    || response.cat.workspace_id !== immutableWorkspaceId
    || response.cat.cat_slug !== expected.cat_slug
    || !ID.test(response.cat.cat_id || "")
    || !["cat_created", "already_exists"].includes(response.code)
  ) {
    throw new Error("Cat create response changed its semantic identity binding");
  }
  return response;
}

export async function createSemanticDisk({ immutableWorkspaceId, request, send }) {
  if (typeof send !== "function") throw new Error("PersistentDisk create transport is unavailable");
  const path = diskCollectionPath(immutableWorkspaceId);
  const expected = buildSemanticDiskCreateRequest({
    name: request?.disk_slug,
    sizeGib: Number(request?.size_bytes) / (1024 ** 3),
  });
  const response = validateTransport(await send(path, {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": JSON_CONTENT_TYPE },
    body: JSON.stringify(expected),
  }), "PersistentDisk");
  if (
    !response.disk
    || response.disk.workspace_id !== immutableWorkspaceId
    || response.disk.disk_slug !== expected.disk_slug
    || !ID.test(response.disk.disk_id || "")
    || !["disk_created", "already_exists"].includes(response.code)
  ) {
    throw new Error("PersistentDisk create response changed its semantic identity binding");
  }
  return response;
}

function validateDiskSnapshot(snapshot, {
  immutableWorkspaceId,
  snapshotSlug,
  snapshotId: expectedSnapshotId,
  diskSlug,
} = {}) {
  if (
    !snapshot
    || typeof snapshot !== "object"
    || Array.isArray(snapshot)
    || !ID.test(snapshot.snapshot_id || "")
    || !ID.test(snapshot.disk_id || "")
    || snapshot.workspace_id !== immutableWorkspaceId
    || snapshot.snapshot_slug !== snapshotSlug
    || (expectedSnapshotId !== undefined && snapshot.snapshot_id !== expectedSnapshotId)
    || (diskSlug !== undefined && snapshot.disk_slug !== diskSlug)
    || !SLUG.test(snapshot.disk_slug || "")
    || !["normal", "deleted"].includes(snapshot.status)
    || !Number.isSafeInteger(snapshot.captured_generation)
    || snapshot.captured_generation < 0
  ) {
    throw new Error("DiskSnapshot response changed its semantic identity binding");
  }
  return snapshot;
}

function validateDiskSnapshotResponse(transport, expected, codes, operation) {
  const response = validateTransport(transport, `DiskSnapshot ${operation}`);
  if (!codes.includes(response.code)) {
    throw new Error(`DiskSnapshot ${operation} returned an invalid semantic result`);
  }
  validateDiskSnapshot(response.snapshot, expected);
  return response;
}

export async function createSemanticDiskSnapshot({ immutableWorkspaceId, request, send }) {
  if (typeof send !== "function") throw new Error("DiskSnapshot create transport is unavailable");
  const expected = buildSemanticDiskSnapshotCreateRequest({
    disk: request?.disk_slug,
    name: request?.snapshot_slug,
  });
  const response = await send(diskSnapshotCollectionPath(immutableWorkspaceId), {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": JSON_CONTENT_TYPE },
    body: JSON.stringify(expected),
  });
  const validated = validateDiskSnapshotResponse(response, {
    immutableWorkspaceId,
    snapshotSlug: expected.snapshot_slug,
    diskSlug: expected.disk_slug,
  }, ["snapshot_created", "already_exists"], "create");
  if (
    validated.snapshot.status !== "normal"
    || !Number.isSafeInteger(validated.disk_head_generation)
    || validated.disk_head_generation !== validated.snapshot.captured_generation
  ) {
    throw new Error("DiskSnapshot create returned an invalid captured generation");
  }
  return validated;
}

export async function destroySemanticDiskSnapshot({
  immutableWorkspaceId,
  snapshot,
  snapshotId: immutableSnapshotId,
  send,
}) {
  if (typeof send !== "function") throw new Error("DiskSnapshot destroy transport is unavailable");
  const snapshotSlug = resourceSlug(snapshot, "DiskSnapshot name");
  const expected = buildSemanticDiskSnapshotDestroyRequest({
    expectedSnapshotId: immutableSnapshotId,
  });
  const response = await send(diskSnapshotActionPath(immutableWorkspaceId, snapshotSlug, "destroy"), {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": JSON_CONTENT_TYPE },
    body: JSON.stringify(expected),
  });
  const validated = validateDiskSnapshotResponse(response, {
    immutableWorkspaceId,
    snapshotSlug,
    snapshotId: expected.expected_snapshot_id,
  }, ["snapshot_destroyed", "already_deleted"], "destroy");
  if (validated.snapshot.status !== "deleted") {
    throw new Error("DiskSnapshot destroy did not return a tombstone");
  }
  return validated;
}

export async function restoreSemanticDiskSnapshot({
  immutableWorkspaceId,
  snapshot,
  snapshotId: immutableSnapshotId,
  disk,
  expectedGeneration,
  send,
}) {
  if (typeof send !== "function") throw new Error("DiskSnapshot restore transport is unavailable");
  const snapshotSlug = resourceSlug(snapshot, "DiskSnapshot name");
  const diskSlug = resourceSlug(disk, "PersistentDisk name");
  const expected = buildSemanticDiskSnapshotRestoreRequest({
    expectedSnapshotId: immutableSnapshotId,
    expectedGeneration,
  });
  const response = await send(diskSnapshotActionPath(immutableWorkspaceId, snapshotSlug, "restore"), {
    method: "POST",
    redirect: "error",
    headers: { "Content-Type": JSON_CONTENT_TYPE },
    body: JSON.stringify(expected),
  });
  const validated = validateDiskSnapshotResponse(response, {
    immutableWorkspaceId,
    snapshotSlug,
    snapshotId: expected.expected_snapshot_id,
    diskSlug,
  }, ["snapshot_restored", "already_restored"], "restore");
  if (
    validated.snapshot.status !== "normal"
    || !Number.isSafeInteger(validated.disk_head_generation)
    || validated.disk_head_generation !== expected.expected_generation + 1
  ) {
    throw new Error("DiskSnapshot restore returned an invalid resulting generation");
  }
  return validated;
}

// Fail locally for product surfaces that are intentionally not exposed by the
// current console. Every admitted route is an exact synchronous resource
// endpoint; query pagination and legacy asynchronous Operation routes stay
// closed.
export function assertSemanticConsoleRequestSupported(path, method = "GET") {
  const normalizedMethod = String(method).toUpperCase();
  const catCollection = /^\/v1\/workspaces\/[^/?]+\/cats$/;
  const diskCollection = /^\/v1\/workspaces\/[^/?]+\/disks$/;
  if ((normalizedMethod === "GET" || normalizedMethod === "POST")
    && (catCollection.test(path) || diskCollection.test(path))) return;
  const exactCatRead = /^\/v1\/workspaces\/[^/?]+\/cats\/[^/?]+$/;
  const exactDiskRead = /^\/v1\/workspaces\/[^/?]+\/disks\/[^/?]+$/;
  if (normalizedMethod === "GET" && (exactCatRead.test(path) || exactDiskRead.test(path))) return;
  const diskSnapshotCollection = /^\/v1\/workspaces\/[^/?]+\/snapshots$/;
  if ((normalizedMethod === "GET" || normalizedMethod === "POST")
    && diskSnapshotCollection.test(path)) return;
  const diskSnapshotItem = /^\/v1\/workspaces\/[^/?]+\/snapshots\/[^/?]+$/;
  if (normalizedMethod === "GET" && diskSnapshotItem.test(path)) return;
  const diskSnapshotAction = /^\/v1\/workspaces\/[^/?]+\/snapshots\/[^/?]+\/actions\/(?:destroy|restore)$/;
  if (normalizedMethod === "POST" && diskSnapshotAction.test(path)) return;
  const closedSurface = /^\/v1\/(?:workspaces\/[^/]*\/(?:cats|disks|snapshots|operations)|operations|admin\/(?:nodes|monitoring))(?:[/?]|$)/;
  if (closedSurface.test(path)) {
    throw new Error("This feature is unavailable in the current console; no request was sent.");
  }
}
