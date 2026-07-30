#!/usr/bin/env bash
set -euo pipefail

: "${CATS_SOAK_RUN_ID:?set a unique run id}"
: "${CATS_SOAK_SOURCE_S3_URI:?set the exact source archive URI}"
: "${CATS_SOAK_SOURCE_SHA256:?set the source archive SHA-256}"
: "${CATS_SOAK_RESULT_S3_URI:?set the run-scoped result directory URI}"
: "${CATS_SOAK_EXPECTED_STATE_SOURCE:?set the inspected Cats state mount source}"

case "$CATS_SOAK_RUN_ID" in
  *[!A-Za-z0-9_-]* | "") echo "unsafe CATS_SOAK_RUN_ID" >&2; exit 2 ;;
esac
case "$CATS_SOAK_RESULT_S3_URI" in
  */"$CATS_SOAK_RUN_ID"/results/) ;;
  *) echo "result URI must end in /$CATS_SOAK_RUN_ID/results/" >&2; exit 2 ;;
esac

run_root="/var/lib/cats/soak-runs/$CATS_SOAK_RUN_ID"
output_dir="$run_root/results"
state_dir="$run_root/state"
socket_dir="/tmp/cats-soak-$CATS_SOAK_RUN_ID"
build_root="${CATS_SOAK_BUILD_ROOT:-/var/tmp/cats-soak-build-$CATS_SOAK_RUN_ID}"
source_dir="$build_root/source"
archive="$build_root/source.tar.gz"
target_dir="$build_root/target"
cargo_home="$build_root/cargo"
rustup_home="$build_root/rustup"
guest_bench="$build_root/cats-fsync-bench"
rustup_init="$build_root/rustup-init"
settle_seconds="${CATS_SOAK_SETTLE_SECONDS:-30}"
run_log="$output_dir/run.log"
status=1

case "$settle_seconds" in
  *[!0-9]* | "") echo "unsafe CATS_SOAK_SETTLE_SECONDS" >&2; exit 2 ;;
esac

mkdir -p "$run_root" "$source_dir" "$output_dir" "$state_dir" "$socket_dir" "$build_root"
state_source="$(findmnt -nr -T /var/lib/cats -o SOURCE)"
build_source="$(findmnt -nr -T "$build_root" -o SOURCE)"
if [[ "$state_source" == "$build_source" ]]; then
  echo "build root and Cats state resolve to the same filesystem: $state_source" >&2
  exit 2
fi

finish() {
  status=$?
  set +e
  {
    echo "finished_at=$(date -Ins)"
    echo "exit_status=$status"
    echo "mount=$(findmnt -nr -T /var/lib/cats -o SOURCE,FSTYPE,OPTIONS)"
    echo "worker_active=$(systemctl is-active cats-worker)"
    echo "blockd_processes=$(pgrep -fc cats-blockd || true)"
    echo "vmm_processes=$(pgrep -fc cloud-hypervisor || true)"
    echo "active_nbd=$(for p in /sys/class/block/nbd*/size; do [ -r "$p" ] && [ "$(cat "$p")" -gt 0 ] && basename "$(dirname "$p")"; done | sort | tr '\n' ' ')"
    echo "load=$(cat /proc/loadavg)"
  } >"$output_dir/environment-after.txt"
  (
    cd "$output_dir" || exit
    find . -type f ! -name SHA256SUMS -print0 |
      sort -z |
      xargs -0 sha256sum >SHA256SUMS
  )
  aws s3 cp "$output_dir/" "$CATS_SOAK_RESULT_S3_URI" \
    --recursive --only-show-errors
  exit "$status"
}
trap finish EXIT

{
  echo "started_at=$(date -Ins)"
  echo "run_id=$CATS_SOAK_RUN_ID"
  echo "hostname=$(hostname)"
  echo "kernel=$(uname -srmo)"
  echo "cpus=$(nproc)"
  echo "build_source=$build_source"
  echo "mount=$(findmnt -nr -T /var/lib/cats -o SOURCE,FSTYPE,OPTIONS)"
  echo "worker_active=$(systemctl is-active cats-worker)"
  echo "blockd_processes=$(pgrep -fc cats-blockd || true)"
  echo "vmm_processes=$(pgrep -fc cloud-hypervisor || true)"
  echo "active_nbd=$(for p in /sys/class/block/nbd*/size; do [ -r "$p" ] && [ "$(cat "$p")" -gt 0 ] && basename "$(dirname "$p")"; done | sort | tr '\n' ' ')"
  echo "load=$(cat /proc/loadavg)"
  df -hT /var/lib/cats
} >"$output_dir/environment-before.txt"

test "$(findmnt -nr -T /var/lib/cats -o SOURCE)" = "$CATS_SOAK_EXPECTED_STATE_SOURCE"
test "$(systemctl is-active cats-worker)" = "active"
test -r /dev/kvm

aws s3 cp "$CATS_SOAK_SOURCE_S3_URI" "$archive" --only-show-errors
actual_sha256="$(sha256sum "$archive" | awk '{print $1}')"
test "$actual_sha256" = "$CATS_SOAK_SOURCE_SHA256"
tar -xzf "$archive" -C "$source_dir"

curl -fsSL --retry 5 --retry-delay 2 \
  https://static.rust-lang.org/rustup/dist/x86_64-unknown-linux-gnu/rustup-init \
  -o "$rustup_init"
chmod 0755 "$rustup_init"
RUSTUP_HOME="$rustup_home" CARGO_HOME="$cargo_home" \
  "$rustup_init" -y --no-modify-path --profile minimal \
  --default-toolchain 1.97.1

export RUSTUP_HOME="$rustup_home"
export CARGO_HOME="$cargo_home"
export PATH="$cargo_home/bin:$PATH"
export CARGO_TARGET_DIR="$target_dir"

# The file is root-only and contains production service credentials. Source it
# without printing it; the runner only passes the existing PostgreSQL URL to
# the adapter and uses the node instance role for its run-scoped S3 prefix.
set -a
# shellcheck disable=SC1091
source /etc/cats/worker.env
set +a

cd "$source_dir"
rustc --version >"$output_dir/toolchain.txt"
cargo --version >>"$output_dir/toolchain.txt"
git rev-parse HEAD 2>/dev/null >>"$output_dir/toolchain.txt" || true

nice -n 10 ionice -c 2 -n 7 \
  cargo build --release -j 8 -p cats-blockd-daemon \
  >"$output_dir/build-blockd.log" 2>&1
nice -n 10 ionice -c 2 -n 7 \
  cargo test --release -j 8 -p cats-e2e --test metal_vhost_soak --no-run \
  >"$output_dir/build-soak.log" 2>&1
gcc -std=c11 -Wall -Wextra -Werror -O2 \
  experiments/vhost-user-soak-20260730/guest-fsync-bench.c \
  -o "$guest_bench"

# ADR-0022 failure semantics run on this Linux/NVMe host before the real-remote
# Guest soak. These use deterministic fault adapters; the next phase supplies
# the real S3/PostgreSQL latency distribution.
nice -n 10 ionice -c 2 -n 7 \
  cargo test --release -j 8 -p cats-blockd relaxed -- --nocapture \
  >"$output_dir/blockd-relaxed-tests.log" 2>&1
nice -n 10 ionice -c 2 -n 7 \
  cargo test --release -j 8 -p cats-node-agent --test runtime_lifecycle relaxed \
  -- --nocapture \
  >"$output_dir/node-relaxed-lifecycle-tests.log" 2>&1

# The old A/B built roughly 14 GiB of Cargo artifacts on the same NVMe as
# ChunkStore and then ran vhost-user first. Flush those writes and give the
# separate state device a quiet boundary before collecting latency samples.
sync
sleep "$settle_seconds"
{
  echo "settled_at=$(date -Ins)"
  echo "settle_seconds=$settle_seconds"
  echo "state_source=$state_source"
  echo "build_source=$build_source"
  awk '$1 == "Dirty:" || $1 == "Writeback:" { print tolower($1) "=" $2 " " $3 }' \
    /proc/meminfo
} >"$output_dir/benchmark-boundary.txt"

export CATS_SOAK_STATE_DIR="$state_dir"
export CATS_SOAK_OUTPUT_DIR="$output_dir"
export CATS_SOAK_SOCKET_DIR="$socket_dir"
export CATS_SOAK_BLOCKD_BIN="$target_dir/release/cats-blockd"
export CATS_SOAK_GUEST_AGENT_BIN="/opt/cats/bin/cats-guest-agent"
export CATS_SOAK_GUEST_BENCH_BIN="$guest_bench"
export CATS_SOAK_CH_BIN="/opt/cats/bin/cloud-hypervisor"
export CATS_SOAK_KERNEL="/opt/cats/guest/vmlinuz"
export CATS_SOAK_INITRAMFS="/opt/cats/guest/initramfs.img"
export CATS_SOAK_SEED_IMAGE="/opt/cats/guest/rootfs.ext4"
export CATS_SOAK_POSTGRES_CA="/etc/cats/rds-ca.pem"
export CATS_SOAK_S3_PREFIX="cats-soak/$CATS_SOAK_RUN_ID"
export RUST_LOG="cats_node_agent=info,cats_blockd=info"

nice -n 5 ionice -c 2 -n 5 \
  cargo test --release -j 8 -p cats-e2e --test metal_vhost_soak \
  metal_vhost_user_soak -- --ignored --nocapture --test-threads=1 \
  2>&1 | tee "$run_log"

status=0
