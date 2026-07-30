#!/usr/bin/env bash
set -euo pipefail

: "${CATS_BENCH_DEVICE:?set CATS_BENCH_DEVICE to the inspected local NVMe device}"
: "${CATS_BENCH_MOUNT:?set CATS_BENCH_MOUNT to a dedicated mount point}"
: "${CATS_BENCH_BINARY_S3_URI:?set CATS_BENCH_BINARY_S3_URI}"
: "${CATS_BENCH_RESULT_S3_URI:?set CATS_BENCH_RESULT_S3_URI}"

samples="${CATS_BENCH_SAMPLES:-500}"
expected_sha256="${CATS_BENCH_BINARY_SHA256:-}"
run_name="${CATS_BENCH_RUN_NAME:-relaxed-tail-$(date -u +%Y%m%dT%H%M%SZ)}"
run_dir="${CATS_BENCH_MOUNT}/${run_name}"
iostat_pid=""
mounted_here=0

stop_iostat() {
  if [[ -n "$iostat_pid" ]]; then
    kill "$iostat_pid" 2>/dev/null || true
    wait "$iostat_pid" 2>/dev/null || true
    iostat_pid=""
  fi
}

cleanup() {
  stop_iostat
  cd /
  if [[ "$mounted_here" == 1 ]]; then
    umount "$CATS_BENCH_MOUNT" || true
  fi
}
trap cleanup EXIT

existing_target="$(findmnt -nr -S "$CATS_BENCH_DEVICE" -o TARGET || true)"
if [[ -n "$existing_target" && "$existing_target" != "$CATS_BENCH_MOUNT" ]]; then
  echo "$CATS_BENCH_DEVICE is already mounted at $existing_target" >&2
  exit 1
fi
if [[ -z "$existing_target" ]]; then
  mkdir -p "$CATS_BENCH_MOUNT"
  mount -o noatime "$CATS_BENCH_DEVICE" "$CATS_BENCH_MOUNT"
  mounted_here=1
fi

mkdir -p "$run_dir/tmp"
aws s3 cp "$CATS_BENCH_BINARY_S3_URI" "$run_dir/commit_cost" --only-show-errors
chmod 0755 "$run_dir/commit_cost"

actual_sha256="$(sha256sum "$run_dir/commit_cost" | awk '{print $1}')"
if [[ -n "$expected_sha256" && "$actual_sha256" != "$expected_sha256" ]]; then
  echo "benchmark binary checksum mismatch" >&2
  exit 1
fi

{
  echo "started_at=$(date -Ins)"
  echo "hostname=$(hostname)"
  echo "samples=$samples"
  echo "binary_sha256=$actual_sha256"
  uname -a
  lscpu
  findmnt -T "$run_dir" -o TARGET,SOURCE,FSTYPE,OPTIONS
  df -hT "$run_dir"
  cat /proc/loadavg
  pgrep -fc cats-blockd || true
  pgrep -fc cloud-hypervisor || true
} >"$run_dir/environment-before.txt"

if command -v iostat >/dev/null; then
  iostat -xz 1 >"$run_dir/iostat.log" &
  iostat_pid=$!
fi

set +e
TMPDIR="$run_dir/tmp" \
  CATS_BENCH_SAMPLES="$samples" \
  CATS_BENCH_CSV="$run_dir/raw-samples.csv" \
  "$run_dir/commit_cost" \
    relaxed_local_ack_and_remote_publish_cost_are_separate \
    --ignored --nocapture >"$run_dir/stdout.log" 2>&1
benchmark_status=$?
set -e

stop_iostat
{
  echo "finished_at=$(date -Ins)"
  echo "benchmark_status=$benchmark_status"
  cat /proc/loadavg
  pgrep -fc cats-blockd || true
  pgrep -fc cloud-hypervisor || true
} >"$run_dir/environment-after.txt"

(
  cd "$run_dir"
  sha256sum raw-samples.csv stdout.log environment-before.txt \
    environment-after.txt iostat.log >SHA256SUMS
)

aws s3 cp "$run_dir/" "$CATS_BENCH_RESULT_S3_URI" \
  --recursive --exclude commit_cost --exclude 'tmp/*' --only-show-errors
cat "$run_dir/stdout.log"
exit "$benchmark_status"
