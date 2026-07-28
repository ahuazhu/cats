#!/usr/bin/env bash
# Does a Warm cycle advance the guest's clocks the way a Suspended cycle does?
#
# Suspended is a same-host pause: measured, all three clocks kept running, so an
# in-process scheduler notices its missed deadline by itself. Warm is different in
# kind -- snapshot, VMM exit, then restore into a NEW VMM process -- and CH's own
# taxonomy says so:
#
#   SameHostResume   "the clock kept running, nothing to advance"
#   SnapshotRestore  "advance to current wall time"
#
# "Advance to current wall time" is explicit about the wall clock and silent about
# CLOCK_MONOTONIC, which is what every runtime's timer deadline actually uses. That
# gap is what this measures, and it decides the design: if monotonic is restored to
# its snapshot value, an app CANNOT self-discover a deadline it missed while Warm,
# and the platform's missed-list becomes load-bearing rather than a convenience.
#
# Warm is also the state that matters most: auto-tier demotes Suspended -> Warm
# after 10 minutes, so any schedule with a period over ~10 minutes wakes from Warm,
# not from Suspended.
set -euo pipefail

WORK=${WORK:-/opt/warmexp}
GUEST=/opt/cats/guest
CH=${CH:-/usr/local/bin/cloud-hypervisor}
RESULTS="$WORK/results"
MEM_MIB=512
VCPUS=2
# Each dwell must comfortably exceed the probe's 45s deadline so the deadline
# falls INSIDE the window and its post-restore behaviour is observable.
DWELLS=(120 60)

say() { printf '\n=== %s\n' "$*" >&2; }
note() { printf -- '--- %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$GUEST/vmlinuz" ] || die "no guest kernel at $GUEST"
mkdir -p "$WORK" "$RESULTS"

ROOTFS="$WORK/probe-rootfs.ext4"
build_rootfs() {
  if [ -f "$ROOTFS" ]; then note "probe rootfs exists"; return; fi
  say "Derive probe rootfs from the Cats golden root (read-only source)"
  cp --sparse=always "$GUEST/rootfs.ext4" "$ROOTFS.tmp"
  truncate -s 900M "$ROOTFS.tmp"
  e2fsck -fy "$ROOTFS.tmp" >/dev/null 2>&1 || true
  resize2fs "$ROOTFS.tmp" >/dev/null
  local mnt="$WORK/mnt"; mkdir -p "$mnt"
  mount -o loop "$ROOTFS.tmp" "$mnt"
  install -m 0755 "$(dirname "$0")/clockprobe.py" "$mnt/usr/bin/clockprobe"
  grep -q clockprobe "$mnt/usr/bin/cats-init" || \
    sed -i 's|^exec /usr/bin/tini|/usr/bin/clockprobe \&\nexec /usr/bin/tini|' "$mnt/usr/bin/cats-init"
  grep -q clockprobe "$mnt/usr/bin/cats-init" || die "failed to patch cats-init"
  umount "$mnt"
  e2fsck -fy "$ROOTFS.tmp" >/dev/null 2>&1 || true
  mv "$ROOTFS.tmp" "$ROOTFS"
}

CH_PID=""; API=""
ch_api() {
  local method="$1" path="$2" body="${3:-}"
  if [ -n "$body" ]; then
    curl -fsS --unix-socket "$API" -X "$method" -H 'Content-Type: application/json' \
      -d "$body" "http://localhost/api/v1/$path"
  else
    curl -fsS --unix-socket "$API" -X "$method" "http://localhost/api/v1/$path"
  fi
}

wait_probe() {
  local serial="$1" deadline=$((SECONDS + 120))
  while ! grep -q "^CLKPROBE," "$serial" 2>/dev/null; do
    kill -0 "$CH_PID" 2>/dev/null || die "guest died: $(tail -20 "$serial" 2>/dev/null)"
    [ "$SECONDS" -lt "$deadline" ] || die "probe never started: $(tail -25 "$serial" 2>/dev/null)"
    sleep 1
  done
}

EVENTS="$RESULTS/host-events.csv"

# One full Warm cycle: boot -> pause -> snapshot -> VMM exit -> dwell -> restore
# into a fresh VMM process.
warm_cycle() {
  local dwell="$1"
  local tag="warm-${dwell}s"
  local disk="$WORK/root-$tag.ext4"
  local snap="$WORK/snap-$tag"
  local serial_a="$RESULTS/serial-$tag-before.log"
  local serial_b="$RESULTS/serial-$tag-after.log"
  rm -rf "$snap" "$disk" "$serial_a" "$serial_b"; mkdir -p "$snap"
  cp --sparse=always "$ROOTFS" "$disk"

  say "Warm cycle, dwell ${dwell}s"
  API="$WORK/api-$tag-a.sock"; rm -f "$API"
  # Anonymous guest RAM so the snapshot self-contains memory (a file-backed zone
  # is deliberately skipped during snapshot copy).
  "$CH" --api-socket "$API" --cpus "boot=$VCPUS" --memory "size=${MEM_MIB}M" \
    --kernel "$GUEST/vmlinuz" --initramfs "$GUEST/initramfs.img" \
    --cmdline "console=ttyS0 root=/dev/vda rw" \
    --disk "path=$disk,image_type=raw" \
    --serial "file=$serial_a" --console off \
    >"$WORK/ch-$tag-a.log" 2>&1 &
  CH_PID=$!
  local d=$((SECONDS + 40))
  while [ ! -S "$API" ]; do
    kill -0 "$CH_PID" 2>/dev/null || die "CH died: $(tail -5 "$WORK/ch-$tag-a.log")"
    [ "$SECONDS" -lt "$d" ] || die "api socket never appeared"
    sleep 0.2
  done
  wait_probe "$serial_a"
  note "probe live; letting it settle 30s so the rate loop has a cadence"
  sleep 30

  echo "pause,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  ch_api PUT vm.pause >/dev/null
  sleep 1
  echo "snapshot_begin,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  ch_api PUT vm.snapshot "{\"destination_url\":\"file://$snap\"}" >/dev/null
  echo "snapshot_done,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  ch_api PUT vmm.shutdown >/dev/null 2>&1 || true
  local dd=$((SECONDS + 20))
  while kill -0 "$CH_PID" 2>/dev/null && [ "$SECONDS" -lt "$dd" ]; do sleep 1; done
  kill -9 "$CH_PID" 2>/dev/null || true; CH_PID=""
  echo "vmm_exited,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  note "VMM exited (this is Warm). Snapshot: $(du -sh "$snap" | cut -f1). Dwelling ${dwell}s"

  sleep "$dwell"

  echo "restore_call,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  API="$WORK/api-$tag-b.sock"; rm -f "$API"
  # Restore needs a fresh VMM with no VM configured yet.
  "$CH" --api-socket "$API" >"$WORK/ch-$tag-b.log" 2>&1 &
  CH_PID=$!
  d=$((SECONDS + 30))
  while [ ! -S "$API" ]; do
    kill -0 "$CH_PID" 2>/dev/null || die "restore CH died: $(tail -5 "$WORK/ch-$tag-b.log")"
    [ "$SECONDS" -lt "$d" ] || die "restore api socket never appeared"
    sleep 0.2
  done
  # The snapshot carries the device config, including the serial file path, so
  # point it at a fresh file to keep before/after halves cleanly separated.
  cp "$serial_a" "$serial_a.frozen"
  ch_api PUT vm.restore "{\"source_url\":\"file://$snap\"}" >/dev/null \
    || die "restore failed: $(tail -20 "$WORK/ch-$tag-b.log")"
  echo "restore_returned,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  ch_api PUT vm.resume >/dev/null 2>&1 || note "resume after restore returned non-OK (may already be running)"
  echo "resumed,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"

  note "restored; observing 90s"
  sleep 90
  # The restored VM keeps writing to the snapshot's configured serial path.
  cp "$serial_a" "$serial_b" 2>/dev/null || true
  echo "observed,$(date +%s.%N),$dwell,$tag" >>"$EVENTS"
  note "after-restore samples in this cycle: $(grep -c '^CLKPROBE,' "$serial_b" 2>/dev/null || echo 0) total lines"
  kill -9 "$CH_PID" 2>/dev/null || true; CH_PID=""
  rm -f "$disk"
}

cleanup() { [ -n "$CH_PID" ] && kill -9 "$CH_PID" 2>/dev/null; true; }
trap cleanup EXIT

main() {
  build_rootfs
  echo "event,host_unix_s,dwell_seconds,tag" >"$EVENTS"
  local w
  for w in "${DWELLS[@]}"; do warm_cycle "$w"; done
  say "Results in $RESULTS"; ls -l "$RESULTS" >&2
}

main "$@"
