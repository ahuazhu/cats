#!/usr/bin/env bash
# Real-microVM acceptance run on a metal host (run after install.sh).
# Drives the cats CLI against the local stack and asserts the ADR-0002
# lifecycle oracles with a REAL kernel boot id.
set -uo pipefail

CATS=${CATS:-/opt/cats/bin/cats}
export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
# The CLI requires a bearer token (ADR-0008). Reuse the fleet admin token from
# the deployment config so an acceptance run needs no interactive `cats login`.
if [[ -z ${CATS_TOKEN:-} ]] && [[ -r /etc/cats/cats.env ]]; then
  CATS_TOKEN=$(sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env | tail -1)
  export CATS_TOKEN
fi
[[ -n ${CATS_TOKEN:-} ]] || { echo "set CATS_TOKEN (or CATS_ADMIN_TOKEN in /etc/cats/cats.env)" >&2; exit 1; }
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
cold_create_started_ms=$(date +%s%3N)
out=$($CATS create $CAT --root-size 1GiB --cpus 1 --memory 512MiB ${CATS_CREATE_ARGS:-} 2>&1)
cold_create_ms=$(( $(date +%s%3N) - cold_create_started_ms ))
check "create converges to running" "observed=running" "$out"
echo "  INFO  create-to-running ${cold_create_ms} ms (single sample; includes scheduling and root seeding)"

guest_kver=$($CATS exec $CAT -- uname -r 2>/dev/null | tr -d ' \n')
host_kver=$(uname -r)
check "guest runs the direct-boot kernel" "$host_kver" "$guest_kver"

guest_os=$($CATS exec $CAT -- sh -c '. /etc/os-release && echo "$PRETTY_NAME"' 2>/dev/null)
check "guest userland is Ubuntu 24.04" "Ubuntu 24.04" "$guest_os"

guest_tools=$($CATS exec $CAT -- sh -c 'command -v apt-get curl git' 2>/dev/null)
check "guest includes apt, curl and git" "/usr/bin/git" "$guest_tools"

guest_pid1=$($CATS exec $CAT -- cat /proc/1/comm 2>/dev/null | tr -d ' \n')
check "guest uses the optimized reaping PID 1" "tini" "$guest_pid1"
guest_agent=$($CATS exec $CAT -- pgrep -f '^/usr/bin/cats-guest-agent( |$)' 2>/dev/null)
[ -n "$guest_agent" ] && ok "Guest Agent is running" || bad "Guest Agent is not running"

guest_network=$($CATS exec $CAT -- sh -c \
  'getent ahostsv4 github.com >/dev/null && curl -fsSI --max-time 10 https://github.com | head -n 1' \
  2>/dev/null)
check "guest DNS and HTTPS egress work" "200" "$guest_network"

root_bytes=$($CATS exec $CAT -- sh -c "df -B1 --output=size / | tail -1" 2>/dev/null | tr -d ' ')
if [ "${root_bytes:-0}" -ge 900000000 ]; then
  ok "guest ext4 root grew to the requested size"
else
  bad "guest ext4 root did not grow (reported ${root_bytes:-unknown} bytes)"
fi

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
cold_start_started_ms=$(date +%s%3N)
out=$($CATS start $CAT 2>&1);    check "start"   "observed=running"   "$out"
cold_start_ms=$(( $(date +%s%3N) - cold_start_started_ms ))
echo "  INFO  cold-to-running ${cold_start_ms} ms (single sample; warm remote/root cache state)"
boot2=$(boot_id)
if [ -n "$boot2" ] && [ "$boot2" != "$boot1" ]; then ok "cold start is a fresh boot"; else bad "boot_id did not change on cold start ($boot2)"; fi
check "flushed data survives cold restart" "metal-persistent-data" "$($CATS exec $CAT -- cat /data.txt 2>/dev/null)"

echo "== 6. destroy =="
out=$($CATS destroy $CAT 2>&1);  check "destroy" "destroyed" "$out"

echo
echo "metal e2e: $pass passed, $fail failed"
[ "$fail" -eq 0 ]
