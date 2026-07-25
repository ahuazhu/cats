#!/usr/bin/env bash
# Reproduce the evidence in this directory: vhost-user-blk acceptance tests plus
# the NBD-versus-vhost-user frontend cost benchmark.
#
# Needs Linux (vhost-user uses eventfd, memfd and SCM_RIGHTS). It does NOT need
# KVM, a VMM or root: the harness in blockd/tests/vhu_frontend is the VMM half of
# the protocol. On macOS the script re-executes itself in a Linux container.
#
#   ./run.sh                # acceptance tests + benchmark, writes raw/
#   CATS_BENCH_REPEATS=1 ./run.sh   # quicker benchmark pass
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
rel="${here#"$repo"/}"
image="${CATS_RUST_IMAGE:-rust:1.97-bookworm}"
repeats="${CATS_BENCH_REPEATS:-5}"

if [ "$(uname -s)" != "Linux" ]; then
  case "$(uname -m)" in
    arm64 | aarch64) platform=linux/arm64 ;;
    x86_64) platform=linux/amd64 ;;
    *)
      echo "unsupported host architecture $(uname -m)" >&2
      exit 1
      ;;
  esac
  echo "== not Linux: re-running in $image ($platform)"
  # Build artifacts go into a Docker volume, not the bind mount: a shared
  # macOS filesystem is both slow and flaky for the thousands of small writes a
  # cargo build makes.
  exec docker run --rm --platform "$platform" \
    -v "$repo":/work -w /work \
    -v cats-cargo-registry:/usr/local/cargo/registry \
    -v cats-target-linux:/target \
    -e CATS_TARGET_DIR=/target \
    -e CATS_BENCH_REPEATS="$repeats" \
    "$image" "/work/$rel/run.sh"
fi

target_dir="${CATS_TARGET_DIR:-$repo/target-linux/$(uname -m)}"
raw="$here/raw"
mkdir -p "$raw"

{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -srm)"
  echo "cpus: $(nproc)"
  echo "memory_kb: $(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  echo "rustc: $(rustc --version)"
  echo "kvm: $([ -e /dev/kvm ] && echo present || echo absent)"
  echo "container: $([ -f /.dockerenv ] && echo yes || echo no)"
  echo "cpu_model: $(awk -F': ' '/model name|Processor|CPU implementer/ {print $2; exit}' /proc/cpuinfo)"
  echo "git_commit: $(git -C "$repo" rev-parse --short HEAD 2>/dev/null || echo unknown)"
} >"$raw/environment.txt"
echo "== environment"
cat "$raw/environment.txt"

echo "== acceptance tests (debug build, assertions on)"
cargo test -p cats-blockd --target-dir "$target_dir" \
  --test vhost_user_blk -- --nocapture 2>&1 | tee "$raw/acceptance-tests.log"

echo "== whole-crate tests: both frontends over the same engine"
cargo test -p cats-blockd --target-dir "$target_dir" 2>&1 |
  tee "$raw/blockd-crate-tests.log"

echo "== frontend cost benchmark (release, $repeats repeats per point)"
CATS_BENCH_CSV="$raw/frontend-cost.csv" CATS_BENCH_REPEATS="$repeats" \
  cargo test --release -p cats-blockd --target-dir "$target_dir" \
  --test vhost_user_bench frontend_cost -- --ignored --nocapture --test-threads=1 2>&1 |
  tee "$raw/frontend-cost.log"

echo "== queue depth scaling (vhost-user only)"
cargo test --release -p cats-blockd --target-dir "$target_dir" \
  --test vhost_user_bench queue_depth -- --ignored --nocapture --test-threads=1 2>&1 |
  tee "$raw/queue-depth.log"

echo "== harness notification cost (poll versus spin)"
cargo test --release -p cats-blockd --target-dir "$target_dir" \
  --test vhost_user_bench notification_cost -- --ignored --nocapture --test-threads=1 2>&1 |
  tee "$raw/notification-cost.log"

echo "== done; evidence in $raw"
