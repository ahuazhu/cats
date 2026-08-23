const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const SLUG = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const JSON_CONTENT_TYPE = "application/json";
const MAX_VOLUME_BYTES = 1_099_511_627_776;

function positiveSafeInteger(value, field) {
  const parsed = Number(value);
  if (!Number.isSafeInteger(parsed) || parsed <= 0) {
    throw new Error(`${field} must be a positive safe integer`);
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

export function catCollectionPath(value) {
  return `/v1/workspaces/${workspaceId(value)}/cats`;
}

export function diskCollectionPath(value) {
  return `/v1/workspaces/${workspaceId(value)}/disks`;
}

export function buildSemanticCatCreateRequest({ name, bootImage, vcpus, memoryMib }) {
  const image = String(bootImage ?? "").trim();
  if (!SHA256.test(image)) throw new Error("invalid boot image digest");
  return {
    cat_slug: resourceSlug(name, "Cat name"),
    cpu: positiveSafeInteger(vcpus, "cpu"),
    memory_bytes: positiveSafeInteger(Number(memoryMib) * (1024 ** 2), "memory_bytes"),
    boot_image: image,
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
    bootImage: request?.boot_image,
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

// Fail locally for product surfaces that are intentionally not exposed by the
// current console. The exact semantic Cat/Disk collection reads and creates
// are the only user resource requests made by this release UI.
export function assertSemanticConsoleRequestSupported(path, method = "GET") {
  const normalizedMethod = String(method).toUpperCase();
  const catCollection = /^\/v1\/workspaces\/[^/?]+\/cats$/;
  const diskCollection = /^\/v1\/workspaces\/[^/?]+\/disks$/;
  if ((normalizedMethod === "GET" || normalizedMethod === "POST")
    && (catCollection.test(path) || diskCollection.test(path))) return;
  const exactCatRead = /^\/v1\/workspaces\/[^/?]+\/cats\/[^/?]+$/;
  const exactDiskRead = /^\/v1\/workspaces\/[^/?]+\/disks\/[^/?]+$/;
  if (normalizedMethod === "GET" && (exactCatRead.test(path) || exactDiskRead.test(path))) return;
  const closedSurface = /^\/v1\/(?:workspaces\/[^/]*\/(?:cats|disks|operations)|operations|admin\/(?:nodes|monitoring))(?:[/?]|$)/;
  if (closedSurface.test(path)) {
    throw new Error("This feature is unavailable in the current console; no request was sent.");
  }
}
