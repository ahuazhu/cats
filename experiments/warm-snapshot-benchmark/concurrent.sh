#!/usr/bin/env bash
# Run multiple independent one-cycle Warm benchmarks concurrently. Immutable
# binaries and base images are shared through ASSET_DIR; every worker gets its
# own root disk, seed, snapshot, API sockets, bridge, tap, and subnet.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BENCHMARK="${BENCHMARK:-$SCRIPT_DIR/benchmark.sh}"
ASSET_DIR="${ASSET_DIR:-/var/lib/cats-warm-bench}"
BASE_WORK_DIR="${BASE_WORK_DIR:-/var/lib/cats-warm-concurrent}"
CAT_COUNT="${CAT_COUNT:-10}"
MEMORY_MIB="${MEMORY_MIB:-512}"
WORKSET_MIB="${WORKSET_MIB:-64}"
PREFAULT_TIMEOUT_S="${PREFAULT_TIMEOUT_S:-300}"
WAKE_TIMEOUT_S="${WAKE_TIMEOUT_S:-15}"
BARRIER_TIMEOUT_S="${BARRIER_TIMEOUT_S:-600}"

die() { echo "ERROR: $*" >&2; exit 1; }

if [ "${EUID:-$(id -u)}" -ne 0 ]; then
  exec sudo --preserve-env=BENCHMARK,ASSET_DIR,BASE_WORK_DIR,CAT_COUNT,MEMORY_MIB,WORKSET_MIB,PREFAULT_TIMEOUT_S,WAKE_TIMEOUT_S,BARRIER_TIMEOUT_S \
    "$0" "$@"
fi

case "$CAT_COUNT" in
  ''|*[!0-9]*) die "CAT_COUNT must be an integer" ;;
esac
[ "$CAT_COUNT" -ge 1 ] && [ "$CAT_COUNT" -le 50 ] || die "CAT_COUNT must be between 1 and 50"
[ -x "$BENCHMARK" ] || die "benchmark not executable: $BENCHMARK"
[ -x "$ASSET_DIR/bin/cloud-hypervisor" ] || die "shared assets are not prepared: $ASSET_DIR"

mkdir -p "$BASE_WORK_DIR"
barrier_dir="$BASE_WORK_DIR/barrier"
mkdir -p "$barrier_dir"
rm -f "$barrier_dir/go" "$barrier_dir"/*.ready
declare -a pids=() workers=()

for worker in $(seq 1 "$CAT_COUNT"); do
  printf -v worker_name 'cat-%02d' "$worker"
  printf -v bridge 'cwb%02d' "$worker"
  printf -v tap 'cwt%02d' "$worker"
  printf -v mac '02:ca:75:10:00:%02x' "$worker"
  worker_dir="$BASE_WORK_DIR/$worker_name"
  mkdir -p "$worker_dir"
  workers+=("$worker_name")

  env \
    WORK_DIR="$worker_dir" \
    ASSET_DIR="$ASSET_DIR" \
    MEMORY_MIB="$MEMORY_MIB" \
    WORKSET_MIB="$WORKSET_MIB" \
    ITERATIONS=1 \
    PREFAULT_TIMEOUT_S="$PREFAULT_TIMEOUT_S" \
    WAKE_TIMEOUT_S="$WAKE_TIMEOUT_S" \
    WAKE_BARRIER_DIR="$barrier_dir" \
    WAKE_WORKER_ID="$worker_name" \
    HOST_IP="10.250.$worker.1" \
    GUEST_IP="10.250.$worker.2" \
    BRIDGE="$bridge" \
    TAP="$tap" \
    MAC="$mac" \
    "$BENCHMARK" run >"$worker_dir/benchmark.log" 2>&1 &
  pids+=("$!")
done

deadline=$((SECONDS + BARRIER_TIMEOUT_S))
while [ "$SECONDS" -lt "$deadline" ]; do
  ready_count="$(find "$barrier_dir" -maxdepth 1 -name '*.ready' -type f | wc -l)"
  [ "$ready_count" -eq "$CAT_COUNT" ] && break
  for pid in "${pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      : > "$barrier_dir/go"
      die "a worker exited before the wake barrier was ready"
    fi
  done
  sleep 0.05
done

ready_count="$(find "$barrier_dir" -maxdepth 1 -name '*.ready' -type f | wc -l)"
if [ "$ready_count" -ne "$CAT_COUNT" ]; then
  : > "$barrier_dir/go"
  die "wake barrier timed out with $ready_count/$CAT_COUNT workers ready"
fi
: > "$barrier_dir/go"

failures=0
for index in "${!pids[@]}"; do
  if ! wait "${pids[$index]}"; then
    echo "worker failed: ${workers[$index]} (see $BASE_WORK_DIR/${workers[$index]}/benchmark.log)" >&2
    failures=$((failures + 1))
  fi
done

[ "$failures" -eq 0 ] || die "$failures/$CAT_COUNT workers failed"

python3 - "$BASE_WORK_DIR" "$CAT_COUNT" <<'PY'
import csv
import pathlib
import statistics
import sys

base = pathlib.Path(sys.argv[1])
expected = int(sys.argv[2])
rows = []
for path in sorted(base.glob("cat-*/results/warm-benchmark.csv")):
    with path.open(newline="") as handle:
        row = next(csv.DictReader(handle))
    row = {"worker": path.parts[-3], **row}
    rows.append(row)

if len(rows) != expected:
    raise SystemExit(f"expected {expected} results, found {len(rows)}")

output = base / "concurrent-summary.csv"
with output.open("w", newline="") as handle:
    writer = csv.DictWriter(handle, fieldnames=rows[0].keys())
    writer.writeheader()
    writer.writerows(rows)

print("\n==> Concurrent summary")
wake_starts = [int(row["wake_started_ns"]) for row in rows]
print(f"workers                  {len(rows)}")
print(f"wake_start_spread_ms     {(max(wake_starts) - min(wake_starts)) / 1_000_000:.3f}")
for key in ("snapshot_ms", "wake_to_health_ms", "touch_wall_ms", "full_memory_ready_ms"):
    values = sorted(float(row[key]) for row in rows)
    print(f"{key:24s} p50={statistics.median(values):9.3f} ms  max={max(values):9.3f} ms")
print(f"warm_runtime_rss_kib     max={max(int(row['warm_runtime_rss_kib']) for row in rows)} KiB")
print(f"boot_id_preserved        {sum(row['boot_id_preserved'] == 'true' for row in rows)}/{len(rows)}")
print(f"results                  {output}")
PY
