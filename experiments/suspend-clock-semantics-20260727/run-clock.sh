#!/usr/bin/env bash
# What does a Cats pause/resume do to the guest's clocks?
#
# Cats' Suspended is "CH pause + MADV_PAGEOUT". The page-out only moves memory;
# the clock behaviour comes entirely from CH's pause/resume, and node-agent does
# no clock handling of its own (its resume is a bare PUT /api/v1/vm.resume). So
# driving CH directly answers the question faithfully while leaving the live
# cats-noded deployment on this box untouched.
#
# CH v53 documents the intent in hypervisor::ClockRestoreMode:
#   SameHostResume  -- "the clock kept running, nothing to advance"
#   SnapshotRestore -- "advance to current wall time"
# This measures whether same-host pause/resume actually behaves that way, and
# what it means for a scheduler parked on a monotonic deadline.
set -euo pipefail

WORK=${WORK:-/opt/clockexp}
GUEST=/opt/cats/guest
CH=${CH:-/usr/local/bin/cloud-hypervisor}
RESULTS="$WORK/results"

# Distinct from anything cats-noded uses (it is on 10.240.0.0/16) and no --net at
# all, so there is no bridge or tap to collide over.
MEM_MIB=512
VCPUS=2

# Pause durations to sweep, seconds. 45s deadline in the probe lands inside the
# first window, so that window must be comfortably longer than 45s.
PAUSES=(90 30 240)

say() { printf '\n=== %s\n' "$*" >&2; }
note() { printf -- '--- %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "run as root"
[ -f "$GUEST/vmlinuz" ] || die "no guest kernel at $GUEST"

mkdir -p "$WORK" "$RESULTS"

# ---------------------------------------------------------------- guest rootfs

ROOTFS="$WORK/probe-rootfs.ext4"
build_rootfs() {
  if [ -f "$ROOTFS" ]; then note "probe rootfs exists"; return; fi
  say "Derive a probe rootfs from the Cats golden root (read-only source)"
  cp --sparse=always "$GUEST/rootfs.ext4" "$ROOTFS.tmp"
  # Room for nothing much -- the probe is one python file and python3 is already
  # in the golden root's manifest.
  truncate -s 900M "$ROOTFS.tmp"
  e2fsck -fy "$ROOTFS.tmp" >/dev/null 2>&1 || true
  resize2fs "$ROOTFS.tmp" >/dev/null

  local mnt="$WORK/mnt"; mkdir -p "$mnt"
  mount -o loop "$ROOTFS.tmp" "$mnt"
  install -m 0755 "$(dirname "$0")/clockprobe.py" "$mnt/usr/bin/clockprobe"
  command -v python3 >/dev/null && true
  [ -x "$mnt/usr/bin/python3" ] || note "WARNING: no python3 in the guest rootfs"

  # Launch the probe just before cats-init hands off to the Guest Agent: the
  # probe inherits cats-init's stdout, which is the serial console, so the host
  # reads results straight out of the serial log.
  grep -q clockprobe "$mnt/usr/bin/cats-init" || \
    sed -i 's|^exec /usr/bin/tini|/usr/bin/clockprobe \&\nexec /usr/bin/tini|' \
      "$mnt/usr/bin/cats-init"
  grep -q clockprobe "$mnt/usr/bin/cats-init" || die "failed to patch cats-init"
  grep -n -B1 -A1 clockprobe "$mnt/usr/bin/cats-init" >&2

  umount "$mnt"
  e2fsck -fy "$ROOTFS.tmp" >/dev/null 2>&1 || true
  mv "$ROOTFS.tmp" "$ROOTFS"
  note "probe rootfs ready"
}

# ------------------------------------------------------------------ VM control

CH_PID=""; API=""; SERIAL=""
ch_api() { curl -fsS --unix-socket "$API" -X "$1" "http://localhost/api/v1/$2" ; }

boot() {
  local label="$1"
  API="$WORK/api-$label.sock"; SERIAL="$RESULTS/serial-$label.log"
  rm -f "$API" "$SERIAL" "$WORK/vsock-$label.sock"
  local disk="$WORK/root-$label.ext4"
  cp --sparse=always "$ROOTFS" "$disk"

  "$CH" \
    --api-socket "$API" \
    --cpus "boot=$VCPUS" \
    --memory "size=${MEM_MIB}M" \
    --kernel "$GUEST/vmlinuz" \
    --initramfs "$GUEST/initramfs.img" \
    --cmdline "console=ttyS0 root=/dev/vda rw" \
    --disk "path=$disk,image_type=raw" \
    --vsock "cid=3,socket=$WORK/vsock-$label.sock" \
    --serial "file=$SERIAL" \
    --console off \
    >"$WORK/ch-$label.log" 2>&1 &
  CH_PID=$!

  local deadline=$((SECONDS + 40))
  while [ ! -S "$API" ]; do
    kill -0 "$CH_PID" 2>/dev/null || die "CH died: $(tail -5 "$WORK/ch-$label.log")"
    [ "$SECONDS" -lt "$deadline" ] || die "api socket never appeared"
    sleep 0.2
  done
  # Wait for the probe to actually be emitting before doing anything to the VM.
  deadline=$((SECONDS + 90))
  while ! grep -q "^CLKPROBE," "$SERIAL" 2>/dev/null; do
    kill -0 "$CH_PID" 2>/dev/null || die "guest died: $(tail -20 "$SERIAL")"
    [ "$SECONDS" -lt "$deadline" ] || die "probe never started; serial: $(tail -25 "$SERIAL")"
    sleep 1
  done
  note "$label: probe emitting after $((SECONDS))s"
}

teardown() {
  [ -n "$CH_PID" ] && kill -0 "$CH_PID" 2>/dev/null && { kill -9 "$CH_PID" 2>/dev/null; wait "$CH_PID" 2>/dev/null; }
  CH_PID=""
}
trap teardown EXIT

# ------------------------------------------------------------------ the sweep

# Records host-side truth about when each pause/resume happened, so the guest's
# view can be checked against it rather than against itself.
EVENTS="$RESULTS/host-events.csv"

phase_pause_sweep() {
  say "Pause/resume sweep: ${PAUSES[*]} seconds"
  echo "event,host_unix_s,pause_seconds,note" >"$EVENTS"
  boot sweep
  echo "boot_probe_live,$(date +%s.%N),0," >>"$EVENTS"

  # Let the fixed-rate loop settle into its cadence and the sampler build a
  # baseline before the first pause.
  sleep 25

  local p
  for p in "${PAUSES[@]}"; do
    note "pausing for ${p}s"
    echo "pause_begin,$(date +%s.%N),$p," >>"$EVENTS"
    ch_api PUT vm.pause >/dev/null
    sleep "$p"
    echo "resume_call,$(date +%s.%N),$p," >>"$EVENTS"
    ch_api PUT vm.resume >/dev/null
    echo "resume_returned,$(date +%s.%N),$p," >>"$EVENTS"
    # Long enough after resume for the deadline thread and any catch-up burst to
    # show, and for the fixed-rate loop to return to its normal cadence.
    sleep 60
    echo "settled,$(date +%s.%N),$p," >>"$EVENTS"
  done

  note "sweep done; $(grep -c '^CLKPROBE,' "$SERIAL") clock samples"
  teardown
}

# A fresh boot has no memory of a deadline it missed while it did not exist.
# Confirms the Cold path and that a fresh guest gets a correct wall clock.
phase_cold_boot() {
  say "Cold boot: does a fresh guest know it missed anything?"
  local host_before host_after
  host_before="$(date +%s.%N)"
  boot cold
  host_after="$(date +%s.%N)"
  echo "cold_boot,$host_before,0,host_time_before_boot" >>"$EVENTS"
  echo "cold_probe_live,$host_after,0,host_time_when_probe_live" >>"$EVENTS"
  sleep 30
  teardown
}

main() {
  build_rootfs
  phase_pause_sweep
  phase_cold_boot
  say "Results in $RESULTS"
  ls -l "$RESULTS" >&2
}

main "$@"
