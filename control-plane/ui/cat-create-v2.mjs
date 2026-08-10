const ID = /^[A-Za-z0-9._:-]{1,128}$/;
const CAT_NAME = /^[a-z0-9](?:[a-z0-9-]{0,28}[a-z0-9])?$/;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const MAX_ROOT_SIZE_BYTES = 1_099_511_627_776;

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
  return {
    name: normalizedName,
    boot_image_digest: digest,
    vcpus: positiveSafeInteger(vcpus, "vcpus"),
    memory_bytes: memoryBytes,
    root_size_bytes: rootSizeBytes,
    durability,
  };
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
  if (!ID.test(value.cat_id) || !ID.test(value.operation_id)) {
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
