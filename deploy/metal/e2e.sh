#!/usr/bin/env bash
# Real-microVM acceptance run on a metal host (run after install.sh).
# Drives the cats CLI against the local stack and asserts the ADR-0002
# lifecycle oracles with a REAL kernel boot id.
set -uo pipefail

CATS=${CATS:-/opt/cats/bin/cats}
export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
CAT=metal-e2e

pass=0; fail=0
ok()   { pass=$((pass+1)); echo "  PASS  $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL  $1" >&2; }
check() { # check <desc> <expected-substr> <actual>
  case "$3" in *"$2"*) ok "$1";; *) bad "$1 (wanted '$2', got '$3')";; esac
}

boot_id() { $CATS exec $CAT -- cat /proc/sys/kernel/random/boot_id 2>/dev/null | tr -d ' \n'; }

echo "== cleanup from previous runs =="
$CATS destroy $CAT >/dev/null 2>&1

echo "== 1. cold create -> real VM boots =="
out=$($CATS create $CAT --root-size 512MiB --cpus 1 --memory 512MiB 2>&1)
check "create converges to running" "observed=running" "$out"

guest_kver=$($CATS exec $CAT -- uname -r 2>/dev/null | tr -d ' \n')
host_kver=$(uname -r)
check "guest runs the direct-boot kernel" "$host_kver" "$guest_kver"

boot1=$(boot_id)
[ -n "$boot1" ] && ok "guest reports a kernel boot_id ($boot1)" || bad "no boot_id"

echo "== 2. durable write through the real ext4 root =="
$CATS exec $CAT -- sh -c 'echo metal-persistent-data > /data.txt && sync' >/dev/null 2>&1 \
  && ok "wrote /data.txt + sync" || bad "guest write failed"

echo "== 3. suspend/resume (vm.pause/resume): same boot =="
out=$($CATS suspend $CAT 2>&1);  check "suspend" "observed=suspended" "$out"
out=$($CATS resume $CAT 2>&1);   check "resume"  "observed=running"   "$out"
check "boot_id preserved across suspend/resume" "$boot1" "$(boot_id)"

echo "== 4. warm (vm.snapshot + full exit) / restore: same boot =="
out=$($CATS warm $CAT 2>&1);     check "warm"    "observed=warm"      "$out"
# Match the VMM executable itself. cats-noded's arguments contain both the
# cloud-hypervisor path and (in this test deployment) an S3 bucket containing
# "metal-e2e", so a loose `pgrep -f` produces a false positive.
if pgrep -f '^/usr/local/bin/cloud-hypervisor( |$)' >/dev/null 2>&1; then bad "VMM still resident while Warm"; else ok "no resident VMM while Warm"; fi
out=$($CATS resume $CAT 2>&1);   check "restore" "observed=running"   "$out"
check "boot_id preserved across warm/restore" "$boot1" "$(boot_id)"
check "file survives warm" "metal-persistent-data" "$($CATS exec $CAT -- cat /data.txt 2>/dev/null)"

echo "== 5. stop/start: fresh boot, durable data intact =="
out=$($CATS stop $CAT 2>&1);     check "stop"    "observed=cold"      "$out"
out=$($CATS start $CAT 2>&1);    check "start"   "observed=running"   "$out"
boot2=$(boot_id)
if [ -n "$boot2" ] && [ "$boot2" != "$boot1" ]; then ok "cold start is a fresh boot"; else bad "boot_id did not change on cold start ($boot2)"; fi
check "flushed data survives cold restart" "metal-persistent-data" "$($CATS exec $CAT -- cat /data.txt 2>/dev/null)"

echo "== 6. destroy =="
out=$($CATS destroy $CAT 2>&1);  check "destroy" "destroyed" "$out"

echo
echo "metal e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
