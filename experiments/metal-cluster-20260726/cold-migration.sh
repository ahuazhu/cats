#!/usr/bin/env bash
# Cross-node Cold migration on real metal: a Cat that ran on node A comes back on
# node B from the durable object store, with nothing but S3 + PostgreSQL between
# them.
#
# Run ON the control-plane node of a two-node metal cluster (both nodes must
# share one object store and one storage-meta; SQLite/file adapters are per-host
# and cannot migrate).
#
#   experiments/metal-cluster-20260726/cold-migration.sh <from-node-id> <to-node-id>
set -uo pipefail

from=${1:?usage: cold-migration.sh <from-node-id> <to-node-id>}
to=${2:?usage: cold-migration.sh <from-node-id> <to-node-id>}
cat_name=${CATS_MIGRATION_CAT:-migrate-probe}
payload="cold-migration-payload-$(date +%s)"

export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [ -z "${CATS_TOKEN:-}" ]; then
  # No [ -r ] test: cats.env is root-only 0600, so the test fails for a normal
  # user even though the read below is sudo. That silently left CATS_TOKEN empty
  # and every measurement in the run failed with "not logged in".
  CATS_TOKEN=$(sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env | tail -1)
  export CATS_TOKEN
fi
cli=${CATS:-/opt/cats/bin/cats}

pass=0
fail=0
ok() { pass=$((pass + 1)); echo "  PASS  $1"; }
bad() { fail=$((fail + 1)); echo "  FAIL  $1" >&2; }
check() { case "$3" in *"$2"*) ok "$1" ;; *) bad "$1 (wanted '$2', got '$3')" ;; esac; }
node_of() { $cli ls 2>/dev/null | awk -v c="$cat_name" '$1==c{for(i=1;i<=NF;i++) if ($i ~ /^node=/) {sub("node=","",$i); print $i}}'; }
boot_id() { $cli exec "$cat_name" -- cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d ' \r\n'; }

echo "== cleanup"
$cli destroy "$cat_name" >/dev/null 2>&1
$cli admin node uncordon "$from" >/dev/null 2>&1
$cli admin node uncordon "$to" >/dev/null 2>&1

echo "== 1. place the Cat on $from and make data durable"
$cli admin node cordon "$to" >/dev/null 2>&1
out=$($cli create "$cat_name" --root-size 2GiB --cpus 2 --memory 1GiB --no-auto-suspend 2>&1)
check "create converges to running" "observed=running" "$out"
placed=$(node_of)
check "placed on the source node" "$from" "$placed"
boot_before=$(boot_id)
[ -n "$boot_before" ] && ok "source boot id is present" || bad "no boot id on the source node"
$cli exec "$cat_name" -- sh -c "echo $payload > /migrated.txt && sync" >/dev/null 2>&1
check "durable write on the source node" "$payload" "$($cli exec "$cat_name" -- cat /migrated.txt 2>&1)"
$cli admin node uncordon "$to" >/dev/null 2>&1

echo "== 2. stop the Cat (Cold) and cordon $from so it cannot be placed back"
out=$($cli stop "$cat_name" 2>&1)
check "stop converges to cold" "observed=cold" "$out"
$cli admin node cordon "$from" >/dev/null 2>&1
check "source node is cordoned" "cordoned" "$($cli admin node get "$from" 2>&1)"

echo "== 3. start again: the scheduler must pick $to, with an empty local cache"
started_ms=$(date +%s%3N)
out=$($cli start "$cat_name" 2>&1)
elapsed_ms=$(($(date +%s%3N) - started_ms))
check "start converges to running" "observed=running" "$out"
landed=$(node_of)
check "migrated to the destination node" "$to" "$landed"
boot_after=$(boot_id)
[ -n "$boot_after" ] && ok "destination boot id is present" || bad "no boot id after migration"
if [ -n "$boot_before" ] && [ "$boot_before" != "$boot_after" ]; then
  ok "cold migration is a fresh boot (new boot id)"
else
  bad "boot id did not change across a cold migration"
fi
check "durable data survived the migration" "$payload" "$($cli exec "$cat_name" -- cat /migrated.txt 2>&1)"
echo "  INFO  cold migration $from -> $to took ${elapsed_ms} ms (single sample, empty destination cache)"

echo "== 4. the destination can write and flush too"
$cli exec "$cat_name" -- sh -c "echo after-migration >> /migrated.txt && sync" >/dev/null 2>&1
check "post-migration write" "after-migration" "$($cli exec "$cat_name" -- cat /migrated.txt 2>&1)"

echo "== cleanup"
$cli destroy "$cat_name" >/dev/null 2>&1
$cli admin node uncordon "$from" >/dev/null 2>&1

echo
echo "cold migration: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
