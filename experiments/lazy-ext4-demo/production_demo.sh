#!/usr/bin/env bash
set -euo pipefail

VIRTUAL_SIZE_GB="${VIRTUAL_SIZE_GB:-4}"
CHUNK_SIZE_MB="${CHUNK_SIZE_MB:-4}"
FILE_COUNT="${FILE_COUNT:-10000}"
BASE_DIR="${BASE_DIR:-/state}"
VIRTUAL_SIZE_BYTES=$((VIRTUAL_SIZE_GB * 1024 * 1024 * 1024))
CHUNK_SIZE_BYTES=$((CHUNK_SIZE_MB * 1024 * 1024))

LOCAL_DIR="$BASE_DIR/nvme"
OBJECT_BUCKET="$BASE_DIR/object-store"
JFS_CACHE="$BASE_DIR/juicefs-cache"
JFS_MOUNT="/mnt/juicefs"
REMOTE_DIR="$JFS_MOUNT/volumes/system-disk"
EXT4_MOUNT="/mnt/demo-ext4"
META="sqlite3://$BASE_DIR/juicefs-meta.db"
SOCKET_PATH="/run/lazy-ext4-production.sock"
NBD_DEVICE=""
NBDKIT_PID=""

say() {
  echo
  echo "==> $*"
}

cleanup() {
  set +e
  if mountpoint -q "$EXT4_MOUNT"; then
    umount "$EXT4_MOUNT"
  fi
  if [[ -n "$NBD_DEVICE" ]]; then
    nbd-client -d "$NBD_DEVICE" >/dev/null 2>&1 || true
  fi
  if [[ -n "$NBDKIT_PID" ]]; then
    kill "$NBDKIT_PID" >/dev/null 2>&1 || true
    wait "$NBDKIT_PID" >/dev/null 2>&1 || true
  fi
  rm -f "$SOCKET_PATH"
  if mountpoint -q "$JFS_MOUNT"; then
    juicefs umount "$JFS_MOUNT" >/dev/null 2>&1 || umount "$JFS_MOUNT"
  fi
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

start_juicefs() {
  mkdir -p "$JFS_MOUNT" "$JFS_CACHE"
  juicefs mount "$META" "$JFS_MOUNT" -d \
    --cache-dir "$JFS_CACHE" \
    --cache-size 256 \
    --backup-meta 0 \
    --no-usage-report \
    --log "$BASE_DIR/juicefs.log" >/dev/null
  for _ in {1..100}; do
    mountpoint -q "$JFS_MOUNT" && return 0
    sleep 0.05
  done
  echo "JuiceFS mount did not become ready" >&2
  exit 1
}

stop_juicefs() {
  if mountpoint -q "$JFS_MOUNT"; then
    juicefs umount "$JFS_MOUNT" >/dev/null
  fi
}

start_backend() {
  local cache_dir="$1"
  local strict="$2"
  rm -f "$SOCKET_PATH"
  rm -f "$cache_dir/stats.json"
  mkdir -p "$cache_dir"
  nbdkit --foreground --unix "$SOCKET_PATH" \
    python /opt/lazy-ext4-demo/lazy_chunk_plugin.py \
    local="$cache_dir" \
    remote="$REMOTE_DIR" \
    size="$VIRTUAL_SIZE_BYTES" \
    chunk_size="$CHUNK_SIZE_BYTES" \
    commit_on_flush="$strict" \
    >"$BASE_DIR/nbdkit.log" 2>&1 &
  NBDKIT_PID=$!
  for _ in {1..100}; do
    [[ -S "$SOCKET_PATH" ]] && break
    sleep 0.05
  done
  [[ -S "$SOCKET_PATH" ]] || {
    cat "$BASE_DIR/nbdkit.log"
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
  if mountpoint -q "$EXT4_MOUNT"; then
    umount "$EXT4_MOUNT"
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

chunkctl() {
  python3 /opt/lazy-ext4-demo/chunkctl.py \
    --local "$LOCAL_DIR" \
    --remote "$REMOTE_DIR" \
    "$@" \
    --size "$VIRTUAL_SIZE_BYTES" \
    --chunk-size "$CHUNK_SIZE_BYTES"
}

generation() {
  chunkctl report --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["generation"])'
}

dirty_count() {
  chunkctl report --json | python3 -c 'import json,sys; print(json.load(sys.stdin)["dirty_chunk_count"])'
}

validate_backend_stats() {
  local mode="$1"
  python3 - "$LOCAL_DIR/stats.json" "$mode" <<'PY'
import json
import sys

path, mode = sys.argv[1:]
with open(path, "r", encoding="utf-8") as stream:
    stats = json.load(stream)
if mode == "strict":
    assert stats["remote_commits"] > 0, stats
    assert stats["remote_commit_dirty_chunks"] > 0, stats
    assert stats["dirty_chunks_current"] == 0, stats
elif mode == "cold":
    assert stats["cache_misses"] > 0, stats
    assert stats["object_bytes_downloaded"] > 0, stats
    assert stats["write_requests"] == 0, stats
else:
    raise AssertionError(mode)
print(f"validated_{mode}_backend_stats=" + json.dumps(stats, sort_keys=True))
PY
}

tree_digest() {
  python3 - "$EXT4_MOUNT/repo" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
digest = hashlib.sha256()
for directory, directories, files in os.walk(root):
    directories.sort()
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

create_workload() {
  python3 - "$EXT4_MOUNT/repo" "$FILE_COUNT" <<'PY'
import hashlib
import os
import sys

root = sys.argv[1]
count = int(sys.argv[2])
os.makedirs(root, exist_ok=True)
for index in range(count):
    directory = os.path.join(root, f"dir-{index % 256:03d}")
    os.makedirs(directory, exist_ok=True)
    seed = f"production-file-{index:08d}".encode()
    body = seed + b":" + hashlib.sha256(seed).hexdigest().encode() + b"\n"
    with open(os.path.join(directory, f"file-{index:08d}.txt"), "wb") as stream:
        stream.write(body)
PY
}

expect_crash() {
  local point="$1"
  local status
  set +e
  chunkctl commit --crash-at "$point"
  status=$?
  set -e
  if [[ "$status" -ne 86 ]]; then
    echo "expected crash exit 86 at $point, got $status" >&2
    exit 1
  fi
}

probe_file() {
  local probe_local="$1"
  local expected="$2"
  local path="$3"
  start_backend "$probe_local" false
  mount -o ro,noload "$NBD_DEVICE" "$EXT4_MOUNT"
  if [[ "$expected" == present ]]; then
    test -f "$EXT4_MOUNT/$path"
  else
    test ! -e "$EXT4_MOUNT/$path"
  fi
  stop_backend
}

mkdir -p "$BASE_DIR" "$OBJECT_BUCKET" "$LOCAL_DIR" "$EXT4_MOUNT"

say "Format and mount a real JuiceFS remote store"
juicefs version
juicefs format --force "$META" cat-production-demo \
  --storage file \
  --bucket "$OBJECT_BUCKET" \
  --trash-days 0 >/dev/null
start_juicefs
mkdir -p "$REMOTE_DIR"
chunkctl init

say "Strict durability: ext4 FLUSH publishes chunks, a manifest, then HEAD"
start_backend "$LOCAL_DIR" true
echo "device=$NBD_DEVICE"
mkfs.ext4 -F -q -m 0 -E lazy_itable_init=1,lazy_journal_init=1 "$NBD_DEVICE"
mount -o noatime "$NBD_DEVICE" "$EXT4_MOUNT"
create_workload
sync
ORIGINAL_DIGEST="$(tree_digest)"
echo "tree_digest_before=$ORIGINAL_DIGEST"
stop_backend
chunkctl verify
chunkctl report
if [[ "$(dirty_count)" -ne 0 ]]; then
  echo "strict FLUSH left dirty chunks" >&2
  exit 1
fi
validate_backend_stats strict

say "Delete local NVMe and JuiceFS client caches, then cold-recover ext4"
stop_juicefs
rm -rf "$LOCAL_DIR" "$JFS_CACHE"
mkdir -p "$LOCAL_DIR"
start_juicefs
start_backend "$LOCAL_DIR" true
mount -o ro,noload "$NBD_DEVICE" "$EXT4_MOUNT"
COLD_DIGEST="$(tree_digest)"
echo "tree_digest_after=$COLD_DIGEST"
stop_backend
if [[ "$ORIGINAL_DIGEST" != "$COLD_DIGEST" ]]; then
  echo "cold-restored ext4 tree differs" >&2
  exit 1
fi
chunkctl report
validate_backend_stats cold

say "Crash before HEAD: an orphan manifest must not become visible"
start_backend "$LOCAL_DIR" false
mount -o noatime "$NBD_DEVICE" "$EXT4_MOUNT"
printf 'manifest crash boundary\n' >"$EXT4_MOUNT/repo/after-manifest.txt"
sync
stop_backend
GEN_BEFORE_MANIFEST="$(generation)"
expect_crash after-manifest
GEN_AFTER_MANIFEST_CRASH="$(generation)"
if [[ "$GEN_BEFORE_MANIFEST" != "$GEN_AFTER_MANIFEST_CRASH" ]]; then
  echo "HEAD changed during after-manifest crash" >&2
  exit 1
fi
probe_file "$BASE_DIR/probe-before-head" absent repo/after-manifest.txt
chunkctl commit
probe_file "$BASE_DIR/probe-after-head" present repo/after-manifest.txt

say "Crash after HEAD: new data is visible and retry only clears dirty markers"
start_backend "$LOCAL_DIR" false
mount -o noatime "$NBD_DEVICE" "$EXT4_MOUNT"
printf 'head published\n' >"$EXT4_MOUNT/repo/after-head.txt"
sync
stop_backend
GEN_BEFORE_HEAD="$(generation)"
expect_crash after-head
GEN_AFTER_HEAD_CRASH="$(generation)"
if [[ "$GEN_AFTER_HEAD_CRASH" -ne $((GEN_BEFORE_HEAD + 1)) ]]; then
  echo "HEAD did not publish exactly one generation" >&2
  exit 1
fi
if [[ "$(dirty_count)" -eq 0 ]]; then
  echo "after-head crash unexpectedly cleared dirty markers" >&2
  exit 1
fi
probe_file "$BASE_DIR/probe-after-head-crash" present repo/after-head.txt
chunkctl commit
if [[ "$(generation)" != "$GEN_AFTER_HEAD_CRASH" ]] || [[ "$(dirty_count)" -ne 0 ]]; then
  echo "after-head retry was not idempotent" >&2
  exit 1
fi

say "Final integrity verification"
chunkctl verify
chunkctl report
python3 - "$LOCAL_DIR/stats.json" "$OBJECT_BUCKET" <<'PY'
import json
import os
import sys

stats_path, bucket = sys.argv[1:]
bucket_bytes = sum(
    os.path.getsize(os.path.join(directory, name))
    for directory, _, files in os.walk(bucket)
    for name in files
)
stats = {}
if os.path.exists(stats_path):
    with open(stats_path, "r", encoding="utf-8") as stream:
        stats = json.load(stream)
print(f"juicefs_object_backend_bytes={bucket_bytes}")
assert bucket_bytes > 0, bucket_bytes
print("last_probe_backend_stats=" + json.dumps(stats, sort_keys=True))
PY

say "PASS"
echo "Verified real JuiceFS persistence, strict FLUSH durability, cold lazy recovery,"
echo "pre-HEAD rollback, and post-HEAD idempotent crash recovery."
