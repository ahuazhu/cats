#!/usr/bin/env bash
# Concurrent capacity on real metal: how many Cats can be brought up at once, and
# what the per-Cat latency distribution looks like.
#
# Three phases per run:
#   1. cold create  -- N Cats created concurrently from nothing
#   2. warm         -- all N snapshotted (vm.snapshot + VMM exit)
#   3. warm restore -- all N resumed concurrently; this is what the node's
#                      concurrent-wake admission gate (ADR-0002 §8) bounds
#
#   experiments/metal-cluster-20260726/concurrent-start.sh <label> <count>
set -uo pipefail

label=${1:?usage: concurrent-start.sh <label> <count>}
count=${2:?usage: concurrent-start.sh <label> <count>}
prefix=${CATS_BENCH_PREFIX:-conc}

export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [ -z "${CATS_TOKEN:-}" ] && [ -r /etc/cats/cats.env ]; then
  CATS_TOKEN=$(sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env | tail -1)
  export CATS_TOKEN
fi
cli=${CATS:-/opt/cats/bin/cats}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

names=()
for i in $(seq 1 "$count"); do names+=("$prefix-$i"); done

echo "== cleanup" >&2
for n in "${names[@]}"; do $cli destroy "$n" >/dev/null 2>&1 & done
wait

# Each Cat's phase timings land in its own file so the parent can summarise.
phase() { # phase-name command...
  local name=$1
  shift
  local started
  started=$(date +%s%3N)
  # Keep each command's output: a failure at high concurrency is the point of
  # the run, so its message has to survive.
  "$@" >"$work/out-$name" 2>&1
  local rc=$?
  echo "$(($(date +%s%3N) - started)) $rc" >>"$work/$name"
  if [ "$rc" -ne 0 ]; then
    echo "# FAILURE $name rc=$rc: $(tr '\n' ' ' <"$work/out-$name" | cut -c1-300)" >&2
  fi
}

summarise() { # phase label
  python3 - "$work" "$1" "$2" "$count" <<'PY'
import glob, os, statistics, sys
work, phase, label, count = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
values, failures = [], 0
for path in glob.glob(os.path.join(work, f"{phase}-*")):
    with open(path) as handle:
        for line in handle:
            ms, rc = line.split()
            values.append(int(ms))
            failures += 1 if rc != "0" else 0
if not values:
    print(f"{label},{phase},{count},0,,,,,{failures}")
    raise SystemExit
values.sort()
pick = lambda p: values[min(len(values) - 1, int(round((len(values) - 1) * p)))]
print(f"{label},{phase},{count},{len(values)},{min(values)},{pick(0.5)},{pick(0.95)},{max(values)},{failures}")
PY
}

# A phase is only finished when the fleet actually reached the target state; the
# CLI's per-operation wait can expire long before that under saturation, and
# starting the next phase on a backlog produces meaningless numbers.
settle() { # target-substring
  local target=$1 deadline=$((SECONDS + ${CATS_SETTLE_SECONDS:-600})) seen
  while [ $SECONDS -lt $deadline ]; do
    seen=$($cli ls 2>/dev/null | grep -c "^$prefix-.*$target")
    [ "$seen" -ge "$count" ] && { echo "# settled: $seen/$count $target after $((SECONDS))s" >&2; return 0; }
    sleep 2
  done
  echo "# NOT SETTLED: $seen/$count $target after ${CATS_SETTLE_SECONDS:-600}s" >&2
  return 1
}

phases=${CATS_PHASES:-create,warm,restore}
has_phase() { case ",$phases," in *",$1,"*) return 0 ;; *) return 1 ;; esac; }

echo "label,phase,requested,completed,min_ms,p50_ms,p95_ms,max_ms,failures"

# ---- phase 1: concurrent cold create -------------------------------------
if has_phase create; then
batch_started=$(date +%s%3N)
for n in "${names[@]}"; do
  phase "create-$n" $cli create "$n" --root-size 2GiB --cpus 2 --memory 1GiB --no-auto-suspend &
done
wait
create_batch_ms=$(($(date +%s%3N) - batch_started))
summarise create "$label"

settle "observed=running"
settled_create_ms=$(($(date +%s%3N) - batch_started))
running=$($cli ls 2>/dev/null | grep -c "^$prefix-.*observed=running")
echo "# $label: $running/$count running; create batch wall ${create_batch_ms} ms, settled at ${settled_create_ms} ms" >&2
fi

# ---- phase 2: warm (snapshot + VMM exit) ---------------------------------
if has_phase warm; then
batch_started=$(date +%s%3N)
for n in "${names[@]}"; do phase "warm-$n" $cli warm "$n" & done
wait
settle "observed=warm"
warm_batch_ms=$(($(date +%s%3N) - batch_started))
summarise warm "$label"
fi

# ---- phase 3: concurrent warm restore ------------------------------------
if has_phase restore; then
batch_started=$(date +%s%3N)
for n in "${names[@]}"; do phase "restore-$n" $cli resume "$n" & done
wait
settle "observed=running"
restore_batch_ms=$(($(date +%s%3N) - batch_started))
summarise restore "$label"
fi

echo "# $label: batch walls create=${create_batch_ms:-n/a} warm=${warm_batch_ms:-n/a} restore=${restore_batch_ms:-n/a} ms (settled)" >&2
echo "# $label: wake gate telemetry:" >&2
$cli admin nodes 2>/dev/null | sed 's/^/#   /' >&2

echo "== cleanup" >&2
for n in "${names[@]}"; do $cli destroy "$n" >/dev/null 2>&1 & done
wait
