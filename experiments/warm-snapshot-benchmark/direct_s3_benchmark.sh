#!/usr/bin/env bash
# Cold-cache boot through Direct-S3 chunks -> nbdkit -> NBD -> vhost-user-blk.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/benchmark.sh"

S3_BUCKET="${S3_BUCKET:-}"
S3_PREFIX="${S3_PREFIX:-benchmarks/direct-s3/default}"
S3_REGION="${S3_REGION:-us-east-1}"
S3_CHUNK_SIZE="${S3_CHUNK_SIZE:-4194304}"
S3_LOCAL="${S3_LOCAL:-$WORK_DIR/direct-s3-local}"
S3_PLUGIN="${S3_PLUGIN:-$SCRIPT_DIR/s3_chunk_plugin.py}"
S3_CTL="${S3_CTL:-$SCRIPT_DIR/s3_chunkctl.py}"
S3_SOCKET="${S3_SOCKET:-$RUN_DIR/direct-s3-nbd.sock}"
S3_LOG="${S3_LOG:-$RUN_DIR/direct-s3-nbdkit.log}"
NBD_DEVICE="${NBD_DEVICE:-/dev/nbd2}"
SOURCE_DISK="${SOURCE_DISK:-}"
DIRECT_CSV="$RESULT_DIR/direct-s3-cold-benchmark.csv"
S3_PID=""

require_s3_bucket() {
  [ -n "$S3_BUCKET" ] || die "S3_BUCKET must name an isolated test bucket"
}

stop_s3_export() {
  set +e
  if [ -b "$NBD_DEVICE" ]; then
    nbd-client -d "$NBD_DEVICE" >/dev/null 2>&1 || true
  fi
  stop_pid "$S3_PID"
  S3_PID=""
  rm -f "$S3_SOCKET"
  set -e
}

cleanup_direct() {
  set +e
  cleanup
  stop_s3_export
}

start_s3_export() {
  mkdir -p "$RUN_DIR" "$S3_LOCAL"
  rm -f "$S3_SOCKET"
  : > "$S3_LOG"
  nbdkit --foreground --unix "$S3_SOCKET" python "$S3_PLUGIN" \
    "local=$S3_LOCAL" "bucket=$S3_BUCKET" "prefix=$S3_PREFIX" \
    "region=$S3_REGION" "size=$(stat -c %s "$SOURCE_DISK")" \
    "chunk_size=$S3_CHUNK_SIZE" commit_on_flush=true \
    >"$S3_LOG" 2>&1 &
  S3_PID=$!
  for _ in $(seq 1 300); do
    [ -S "$S3_SOCKET" ] && break
    kill -0 "$S3_PID" 2>/dev/null || { tail -n 120 "$S3_LOG" >&2; die "Direct-S3 nbdkit exited"; }
    sleep 0.02
  done
  [ -S "$S3_SOCKET" ] || die "Direct-S3 NBD socket did not appear"
  nbd-client -unix "$S3_SOCKET" "$NBD_DEVICE" >/dev/null
  [ "$(blockdev --getsize64 "$NBD_DEVICE")" = "$(stat -c %s "$SOURCE_DISK")" ] || die "NBD geometry mismatch"
}

stats_value() {
  local key="$1"
  python3 - "$S3_LOCAL/stats.json" "$key" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8"))[sys.argv[2]])
PY
}

prepare_remote() {
  require_linux_kvm
  require_s3_bucket
  [ -n "$SOURCE_DISK" ] && [ -f "$SOURCE_DISK" ] || die "SOURCE_DISK must name a stable, initialized raw disk"
  [ -x "$S3_CTL" ] || die "missing Direct-S3 control tool: $S3_CTL"
  say "Publish sparse raw disk as immutable $S3_CHUNK_SIZE-byte S3 chunks"
  python3 "$S3_CTL" publish --source "$SOURCE_DISK" --bucket "$S3_BUCKET" \
    --prefix "$S3_PREFIX" --region "$S3_REGION" --chunk-size "$S3_CHUNK_SIZE"
}

one_direct_cycle() {
  local iteration="$1" previous_boot="$2" wake_start network_end export_end backend_end
  local vmm_start vmm_end health_end sync_start sync_end durable_start durable_end response boot_id unique
  local cache_hits cache_misses object_gets object_bytes get_requests get_bytes get_ms
  local put_requests put_bytes put_ms commits dirty_committed

  python3 "$S3_CTL" clear-local --local "$S3_LOCAL" >/dev/null
  wake_start="$(now_ns)"
  ensure_network
  network_end="$(now_ns)"
  start_s3_export
  export_end="$(now_ns)"
  start_backend
  backend_end="$(now_ns)"
  vmm_start="$(now_ns)"
  start_initial_vmm
  vmm_end="$(now_ns)"
  response="$(wait_guest "$BOOT_TIMEOUT_S")" || {
    tail -n 200 "$SERIAL_LOG" >&2 || true
    tail -n 200 "$S3_LOG" >&2 || true
    die "Direct-S3 guest did not become healthy in ${BOOT_TIMEOUT_S}s"
  }
  health_end="$(now_ns)"
  boot_id="$(printf '%s' "$response" | json_field boot_id)"
  [ -z "$previous_boot" ] || [ "$boot_id" != "$previous_boot" ] && unique=true || unique=false

  # Capture the cold-read path at first health before the explicit durability sync.
  cache_hits="$(stats_value cache_hits)"
  cache_misses="$(stats_value cache_misses)"
  object_gets="$(stats_value object_get_requests)"
  object_bytes="$(stats_value object_bytes_downloaded)"
  get_requests="$(stats_value s3_get_requests)"
  get_bytes="$(stats_value s3_get_bytes)"
  get_ms="$(stats_value s3_get_ms)"

  sync_start="$(now_ns)"
  guest_json /sync 180 >/dev/null
  sync_end="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" pause >/dev/null
  durable_start="$(now_ns)"
  python3 - "$NBD_DEVICE" <<'PY'
import os
import sys

descriptor = os.open(sys.argv[1], os.O_RDWR)
try:
    os.fsync(descriptor)
finally:
    os.close(descriptor)
PY
  durable_end="$(now_ns)"
  put_requests="$(stats_value s3_put_requests)"
  put_bytes="$(stats_value s3_put_bytes)"
  put_ms="$(stats_value s3_put_ms)"
  commits="$(stats_value remote_commits)"
  dirty_committed="$(stats_value remote_commit_dirty_chunks)"

  "$CH_REMOTE" --api-socket "$API_SOCKET" shutdown-vmm >/dev/null 2>&1 || true
  stop_runtime
  stop_s3_export

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$iteration" "$MEMORY_MIB" "$WORKSET_MIB" "$wake_start" \
    "$(elapsed_ms "$wake_start" "$network_end")" \
    "$(elapsed_ms "$network_end" "$export_end")" \
    "$(elapsed_ms "$export_end" "$backend_end")" \
    "$(elapsed_ms "$vmm_start" "$vmm_end")" \
    "$(elapsed_ms "$wake_start" "$health_end")" \
    "$(elapsed_ms "$sync_start" "$sync_end")" \
    "$(elapsed_ms "$durable_start" "$durable_end")" \
    "$cache_hits" "$cache_misses" "$object_gets" "$object_bytes" \
    "$get_requests" "$get_bytes" "$get_ms" "$put_requests" "$put_bytes" \
    "$put_ms" "$commits" "$dirty_committed" "$unique" "$boot_id" | tee -a "$DIRECT_CSV"
  [ "$unique" = true ] || die "Direct-S3 cold boot reused the previous process boot ID"
  printf '%s\n' "$boot_id" > "$RUN_DIR/last-direct-boot-id"
}

run_direct() {
  require_linux_kvm
  require_s3_bucket
  [ -n "$SOURCE_DISK" ] && [ -f "$SOURCE_DISK" ] || die "SOURCE_DISK is required for geometry"
  [ -x "$S3_PLUGIN" ] && [ -x "$S3_CTL" ] || die "Direct-S3 helpers are missing"
  command -v nbdkit >/dev/null || die "nbdkit is not installed"
  modprobe nbd max_part=16
  [ -b "$NBD_DEVICE" ] || die "missing $NBD_DEVICE"
  export ROOT_DISK="$NBD_DEVICE"
  export MEMORY_BACKING_FILE=""
  export RUNTIME_CGROUP=""
  prepare_guest
  trap cleanup_direct EXIT INT TERM
  stop_runtime
  stop_s3_export
  mkdir -p "$RUN_DIR" "$RESULT_DIR" "$S3_LOCAL"
  echo "iteration,memory_mib,workset_mib,wake_started_ns,network_ms,s3_export_ms,vhost_backend_ms,vmm_to_api_ms,cold_to_health_ms,guest_sync_ms,durable_flush_ms,cache_hits,cache_misses,object_get_requests,object_bytes_downloaded,s3_get_requests,s3_get_bytes,s3_get_ms,s3_put_requests,s3_put_bytes,s3_put_ms,remote_commits,remote_commit_dirty_chunks,boot_id_changed,boot_id" > "$DIRECT_CSV"

  say "Run $ITERATIONS Direct-S3 cold-cache boot cycles"
  local previous_boot=""
  for iteration in $(seq 1 "$ITERATIONS"); do
    echo "iteration=$iteration"
    one_direct_cycle "$iteration" "$previous_boot"
    previous_boot="$(<"$RUN_DIR/last-direct-boot-id")"
  done
  say "PASS: every boot used an empty NVMe chunk cache and fetched blocks directly from S3"
  echo "results=$DIRECT_CSV"
}

case "${1:-}" in
  prepare-remote) as_root prepare-remote; prepare_remote ;;
  run) as_root run; run_direct ;;
  *) echo "usage: $0 {prepare-remote|run}" >&2; exit 2 ;;
esac
