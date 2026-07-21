#!/usr/bin/env bash
set -euo pipefail

VIRTUAL_SIZE_GB="${VIRTUAL_SIZE_GB:-4}"
CHUNK_SIZE_MB="${CHUNK_SIZE_MB:-1}"
FILE_COUNT="${FILE_COUNT:-10000}"
STATE_DIR="${STATE_DIR:-/state}"
SOCKET_PATH="/run/lazy-ext4-demo.sock"
MOUNT_PATH="/mnt/demo-ext4"
VIRTUAL_SIZE_BYTES=$((VIRTUAL_SIZE_GB * 1024 * 1024 * 1024))
CHUNK_SIZE_BYTES=$((CHUNK_SIZE_MB * 1024 * 1024))
NBD_DEVICE=""
NBDKIT_PID=""

say() {
  echo
  echo "==> $*"
}

cleanup() {
  set +e
  if mountpoint -q "$MOUNT_PATH"; then
    umount "$MOUNT_PATH"
  fi
  if [[ -n "$NBD_DEVICE" ]]; then
    nbd-client -d "$NBD_DEVICE" >/dev/null 2>&1 || true
  fi
  if [[ -n "$NBDKIT_PID" ]]; then
    kill "$NBDKIT_PID" >/dev/null 2>&1 || true
    wait "$NBDKIT_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
}
trap cleanup EXIT INT TERM

find_free_nbd() {
  local device name
  for device in /dev/nbd{0..15}; do
    [[ -b "$device" ]] || continue
    name="${device##*/}"
    if [[ ! -e "/sys/class/block/$name/pid" ]]; then
      echo "$device"
      return 0
    fi
  done
  return 1
}

start_backend() {
  rm -f "$SOCKET_PATH"
  rm -f "$STATE_DIR/stats.json"
  nbdkit --foreground --unix "$SOCKET_PATH" \
    python /opt/lazy-ext4-demo/lazy_chunk_plugin.py \
    state="$STATE_DIR" \
    size="$VIRTUAL_SIZE_BYTES" \
    chunk_size="$CHUNK_SIZE_BYTES" \
    >"$STATE_DIR/nbdkit.log" 2>&1 &
  NBDKIT_PID=$!
  for _ in {1..100}; do
    [[ -S "$SOCKET_PATH" ]] && break
    sleep 0.05
  done
  [[ -S "$SOCKET_PATH" ]] || {
    cat "$STATE_DIR/nbdkit.log"
    echo "nbdkit socket did not appear" >&2
    exit 1
  }

  NBD_DEVICE="$(find_free_nbd)" || {
    echo "no free /dev/nbd device" >&2
    exit 1
  }
  nbd-client -unix "$SOCKET_PATH" "$NBD_DEVICE" >/dev/null
}

stop_backend() {
  if mountpoint -q "$MOUNT_PATH"; then
    umount "$MOUNT_PATH"
  fi
  if [[ -n "$NBD_DEVICE" ]]; then
    blockdev --flushbufs "$NBD_DEVICE" || true
    nbd-client -d "$NBD_DEVICE" >/dev/null
    NBD_DEVICE=""
  fi
  if [[ -n "$NBDKIT_PID" ]]; then
    kill "$NBDKIT_PID"
    wait "$NBDKIT_PID" || true
    NBDKIT_PID=""
  fi
  rm -f "$SOCKET_PATH"
}

tree_digest() {
  python3 - "$MOUNT_PATH/repo" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
digest = hashlib.sha256()
for directory, _, files in os.walk(root):
    files.sort()
    for name in files:
        path = os.path.join(directory, name)
        relative = os.path.relpath(path, root).encode()
        digest.update(len(relative).to_bytes(4, "big"))
        digest.update(relative)
        with open(path, "rb") as stream:
            while True:
                data = stream.read(128 * 1024)
                if not data:
                    break
                digest.update(data)
print(digest.hexdigest())
PY
}

validate_evidence() {
  python3 - "$STATE_DIR" <<'PY'
import json
import os
import sys

state = sys.argv[1]
with open(os.path.join(state, "HEAD.json"), "r", encoding="utf-8") as stream:
    head = json.load(stream)
with open(os.path.join(state, "manifests", head["manifest"]), "r", encoding="utf-8") as stream:
    manifest = json.load(stream)
with open(os.path.join(state, "stats.json"), "r", encoding="utf-8") as stream:
    stats = json.load(stream)

total_chunks = manifest["virtual_size"] // manifest["chunk_size"]
mapped_chunks = len(manifest["chunks"])
objects_dir = os.path.join(state, "objects")
object_bytes = sum(
    os.path.getsize(os.path.join(objects_dir, name))
    for name in os.listdir(objects_dir)
    if name.endswith(".chunk")
)

assert mapped_chunks < total_chunks, (mapped_chunks, total_chunks)
assert object_bytes < manifest["virtual_size"], (object_bytes, manifest["virtual_size"])
assert stats["cache_misses"] > 0, stats
assert stats["object_bytes_downloaded"] > 0, stats
print(
    "validated "
    f"mapped={mapped_chunks}/{total_chunks} "
    f"object_bytes={object_bytes}/{manifest['virtual_size']} "
    f"cold_misses={stats['cache_misses']} "
    f"cold_bytes={stats['object_bytes_downloaded']}"
)
PY
}

create_workload() {
  python3 - "$MOUNT_PATH/repo" "$FILE_COUNT" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
count = int(sys.argv[2])
os.makedirs(root, exist_ok=True)
for index in range(count):
    directory = os.path.join(root, f"dir-{index % 256:03d}")
    os.makedirs(directory, exist_ok=True)
    seed = f"sprite-file-{index:08d}".encode()
    body = (seed + b":" + hashlib.sha256(seed).hexdigest().encode() + b"\n")
    with open(os.path.join(directory, f"file-{index:08d}.txt"), "wb") as stream:
        stream.write(body)
PY
}

say "Initialize a sparse ${VIRTUAL_SIZE_GB}GiB logical disk (${CHUNK_SIZE_MB}MiB chunks)"
mkdir -p "$STATE_DIR" "$MOUNT_PATH"
python3 /opt/lazy-ext4-demo/chunkctl.py --state "$STATE_DIR" init \
  --size "$VIRTUAL_SIZE_BYTES" --chunk-size "$CHUNK_SIZE_BYTES"

say "Expose the chunk backend as a real Linux NBD block device"
start_backend
echo "device=$NBD_DEVICE"

say "Format and mount unmodified ext4"
mkfs.ext4 -F -q -m 0 -E lazy_itable_init=1,lazy_journal_init=1 "$NBD_DEVICE"
mount -o noatime "$NBD_DEVICE" "$MOUNT_PATH"

say "Create ${FILE_COUNT} small files through ext4"
create_workload
ORIGINAL_DIGEST="$(tree_digest)"
echo "tree_digest_before=$ORIGINAL_DIGEST"
sync
stop_backend

say "Commit dirty cache chunks to the object directory and manifest"
python3 /opt/lazy-ext4-demo/chunkctl.py --state "$STATE_DIR" commit \
  --size "$VIRTUAL_SIZE_BYTES" --chunk-size "$CHUNK_SIZE_BYTES"
python3 /opt/lazy-ext4-demo/chunkctl.py --state "$STATE_DIR" report \
  --size "$VIRTUAL_SIZE_BYTES" --chunk-size "$CHUNK_SIZE_BYTES"

say "Delete the complete local NVMe-like cache"
python3 /opt/lazy-ext4-demo/chunkctl.py --state "$STATE_DIR" clear-cache \
  --size "$VIRTUAL_SIZE_BYTES" --chunk-size "$CHUNK_SIZE_BYTES"

say "Cold-start from only manifest + object chunks"
start_backend
mount -o ro,noload "$NBD_DEVICE" "$MOUNT_PATH"
RESTORED_DIGEST="$(tree_digest)"
echo "tree_digest_after=$RESTORED_DIGEST"
sync
stop_backend

say "Cold-read backend statistics"
python3 /opt/lazy-ext4-demo/chunkctl.py --state "$STATE_DIR" report \
  --size "$VIRTUAL_SIZE_BYTES" --chunk-size "$CHUNK_SIZE_BYTES"

if [[ "$ORIGINAL_DIGEST" != "$RESTORED_DIGEST" ]]; then
  echo "ERROR: restored ext4 content differs" >&2
  exit 1
fi
validate_evidence

say "PASS"
echo "Unmodified ext4 mounted twice; the second mount started with an empty cache."
echo "The tree digest matched, and backend_stats shows object bytes fetched lazily."
