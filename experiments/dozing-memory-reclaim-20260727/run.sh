#!/usr/bin/env bash
# Dozing: how low can a *running* guest's host memory footprint go?
#
# Cats' Suspended state reclaims memory by pausing the VM and calling
# process_madvise(MADV_PAGEOUT). That works but stops the guest clock, so
# in-process schedulers (@Scheduled, setInterval, time.Ticker) never fire.
# This experiment measures the alternative: leave the guest running and reclaim
# its memory anyway, so those timers keep working with no application change.
#
# The guest is Cats' own image (deploy/metal/build-guest-image.sh), not a stock
# cloud image. That matters three ways: the guest kernel is the host kernel, so
# free page reporting / memory.reclaim / MGLRU are exactly the ones production
# would use; PID 1 is cats-init rather than systemd+snapd+cloud-init, so the
# floor is the real product floor and not one inflated by things users never
# run; and it boots directly from vmlinuz+initramfs, with no firmware chain.
#
# Usage: sudo ./run.sh [setup|ladder|haltpoll|soak|all]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
WORK_DIR="${WORK_DIR:-/opt/cats-dozing}"
ASSET_DIR="$WORK_DIR/assets"
RUN_DIR="$WORK_DIR/run"
RESULT_DIR="${RESULT_DIR:-$SCRIPT_DIR/results}"
RAW_DIR="$RESULT_DIR/raw"

CH_VERSION="${CH_VERSION:-v53.0}"
CH_BIN="$ASSET_DIR/bin/cloud-hypervisor"
CH_REMOTE="$ASSET_DIR/bin/ch-remote"

# Cats guest artifacts, built by the repo's own script.
GUEST_OUT="${GUEST_OUT:-/opt/cats/guest}"
GUEST_KERNEL="$GUEST_OUT/vmlinuz"
GUEST_INITRAMFS="$GUEST_OUT/initramfs.img"
GOLDEN_ROOTFS="$GUEST_OUT/rootfs.ext4"
PROBE_ROOTFS="$ASSET_DIR/probe-rootfs.ext4"
PROBE_ROOTFS_MB="${PROBE_ROOTFS_MB:-2560}"
GUEST_CMDLINE="${GUEST_CMDLINE:-console=ttyS0}"

MEMORY_MIB="${MEMORY_MIB:-1024}"
BOOT_VCPUS="${BOOT_VCPUS:-2}"
JVM_XMX="${JVM_XMX:-384m}"

BRIDGE="${BRIDGE:-czb0}"
TAP="${TAP:-czbtap0}"
# cats-init derives the guest address from the last four MAC bytes and the
# gateway from address-1, so the MAC encodes 192.168.251.2 with gateway .1.
MAC="02:ca:c0:a8:fb:02"
HOST_IP="192.168.251.1"
GUEST_IP="192.168.251.2"
PREFIX=30
APP_PORT=8080

SETTLE_S="${SETTLE_S:-90}"
MEASURE_S="${MEASURE_S:-360}"
SAMPLE_INTERVAL_S="${SAMPLE_INTERVAL_S:-5}"
BOOT_TIMEOUT_S="${BOOT_TIMEOUT_S:-240}"

CH_PID=""
API_SOCKET=""
CURRENT_CGROUP=""
BACKING_FILE=""
ROOT_DISK=""

say() { printf '\n=== %s\n' "$*" >&2; }
note() { printf -- '--- %s\n' "$*" >&2; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- host setup

setup_host_packages() {
  say "Host packages"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y -qq --no-install-recommends \
    ca-certificates curl jq python3 qemu-utils openjdk-21-jdk-headless maven \
    busybox-static cpio zstd e2fsprogs debootstrap musl-tools \
    iproute2 iptables build-essential pkg-config libssl-dev >/dev/null
  mkdir -p "$ASSET_DIR/bin" "$RUN_DIR" "$RESULT_DIR" "$RAW_DIR"
}

setup_ch() {
  say "cloud-hypervisor $CH_VERSION"
  [ -x "$CH_BIN" ] || { curl -fsSL --retry 3 -o "$CH_BIN" \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static"; chmod +x "$CH_BIN"; }
  [ -x "$CH_REMOTE" ] || { curl -fsSL --retry 3 -o "$CH_REMOTE" \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/ch-remote-static"; chmod +x "$CH_REMOTE"; }
  "$CH_BIN" --version >&2
  "$CH_BIN" --help 2>&1 | grep -q -- '--balloon' || die "this CH build has no --balloon"
}

build_guest_artifacts() {
  if [ -f "$GUEST_KERNEL" ] && [ -f "$GUEST_INITRAMFS" ] && [ -f "$GOLDEN_ROOTFS" ]; then
    note "Cats guest artifacts already built"
    return
  fi
  say "Build Cats guest image (repo script, real artifacts)"
  if ! command -v cargo >/dev/null 2>&1; then
    note "installing rust toolchain for the musl guest agent"
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --default-toolchain stable --profile minimal >/dev/null
  fi
  export PATH="$HOME/.cargo/bin:/root/.cargo/bin:$PATH"
  OUT="$GUEST_OUT" bash "$REPO/deploy/metal/build-guest-image.sh" >&2
  ls -l "$GUEST_OUT" >&2
}

build_app() {
  say "Build Spring Boot probe"
  local jar="$ASSET_DIR/dozing-probe.jar"
  if [ ! -f "$jar" ]; then
    ( cd "$SCRIPT_DIR/app" && mvn -q -B -DskipTests package )
    cp "$SCRIPT_DIR/app/target/dozing-probe.jar" "$jar"
  fi
  ls -l "$jar" >&2
}

# Take Cats' golden rootfs and add exactly what the probe needs: a JRE, the
# Spring Boot jar, python3 for the timer sampler, and one line in cats-init to
# launch the app. Everything else stays as production ships it.
build_probe_rootfs() {
  if [ -f "$PROBE_ROOTFS" ]; then
    note "probe rootfs already built"
    return
  fi
  say "Derive probe rootfs from the Cats golden rootfs"
  local mnt="$RUN_DIR/rootmnt"
  mkdir -p "$mnt"
  cp --sparse=always "$GOLDEN_ROOTFS" "$PROBE_ROOTFS.tmp"
  truncate -s "${PROBE_ROOTFS_MB}M" "$PROBE_ROOTFS.tmp"
  e2fsck -fy "$PROBE_ROOTFS.tmp" >/dev/null 2>&1 || true
  resize2fs "$PROBE_ROOTFS.tmp" >/dev/null
  mount -o loop "$PROBE_ROOTFS.tmp" "$mnt"

  mount -t proc proc "$mnt/proc"
  mount -t sysfs sysfs "$mnt/sys"
  mount --bind /dev "$mnt/dev"
  cp /etc/resolv.conf "$mnt/etc/resolv.conf"
  chroot "$mnt" /bin/sh -euc '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq --no-install-recommends openjdk-21-jre-headless python3-minimal
    apt-get clean
    rm -rf /var/lib/apt/lists/*
  ' >&2

  install -m 0755 /dev/stdin "$mnt/usr/bin/dozing-start" <<EOF
#!/bin/sh
# Started by cats-init after the network is configured.
#
# Xms is deliberately far below Xmx and the heap free ratios are tightened:
# pinning Xms=Xmx commits and touches the whole heap up front and the collector
# then never returns it, which would make the measured floor a property of this
# flag rather than of the reclaim mechanism under test.
mkdir -p /var/log/dozing

# Join a cgroup BEFORE exec'ing the JVM. cgroup v2 does not move existing
# memory charges when a task migrates, so a process moved into a cgroup after
# it has already allocated stays charged to the old one and memory.high there
# has nothing to act on. Charges only land here if the process starts here.
# The Cats guest image mounts no cgroup2 at all, so this does it too.
mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup 2>/dev/null
mkdir -p /sys/fs/cgroup/dozing
echo +memory > /sys/fs/cgroup/cgroup.subtree_control 2>/dev/null
echo \$\$ > /sys/fs/cgroup/dozing/cgroup.procs 2>/dev/null

exec /usr/bin/java -Xms64m -Xmx$JVM_XMX -XX:+UseSerialGC \\
  -XX:MinHeapFreeRatio=10 -XX:MaxHeapFreeRatio=30 \\
  -jar /opt/dozing-probe.jar > /var/log/dozing/app.log 2>&1
EOF
  mkdir -p "$mnt/opt"
  cp "$ASSET_DIR/dozing-probe.jar" "$mnt/opt/dozing-probe.jar"
  cp "$SCRIPT_DIR/guest/timer_sampler.py" "$mnt/opt/timer_sampler.py"
  chmod +x "$mnt/opt/timer_sampler.py"

  # Launch the probe just before cats-init hands off to the Guest Agent, so the
  # network is already up and the Agent still becomes PID 1's exec target.
  grep -q dozing-start "$mnt/usr/bin/cats-init" || \
    sed -i 's|^exec /usr/bin/tini|/usr/bin/dozing-start \&\nexec /usr/bin/tini|' \
      "$mnt/usr/bin/cats-init"
  grep -n -B2 -A1 dozing-start "$mnt/usr/bin/cats-init" >&2 \
    || die "failed to patch cats-init"

  umount "$mnt/dev" "$mnt/proc" "$mnt/sys"
  umount "$mnt"
  e2fsck -fy "$PROBE_ROOTFS.tmp" >/dev/null 2>&1 || true
  mv "$PROBE_ROOTFS.tmp" "$PROBE_ROOTFS"
  note "probe rootfs ready: $(du -h "$PROBE_ROOTFS" | cut -f1)"
}

setup_network() {
  ip link show "$BRIDGE" >/dev/null 2>&1 || ip link add "$BRIDGE" type bridge
  ip addr replace "$HOST_IP/$PREFIX" dev "$BRIDGE"
  ip link set "$BRIDGE" up
  ip link del "$TAP" 2>/dev/null || true
  ip tuntap add dev "$TAP" mode tap
  ip link set "$TAP" master "$BRIDGE"
  ip link set "$TAP" up
}

teardown_network() {
  ip link del "$TAP" 2>/dev/null || true
  ip link del "$BRIDGE" 2>/dev/null || true
}

host_facts() {
  say "Host facts"
  {
    echo "date_utc=$(date -u +%FT%TZ)"
    echo "instance_type=$(curl -fsS --max-time 2 -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' \
      -X PUT http://169.254.169.254/latest/api/token 2>/dev/null \
      | { read -r t; curl -fsS --max-time 2 -H "X-aws-ec2-metadata-token: $t" \
          http://169.254.169.254/latest/meta-data/instance-type 2>/dev/null; } || echo unknown)"
    echo "host_kernel=$(uname -r)"
    echo "guest_kernel=$(uname -r)  # cats guest image reuses the host kernel"
    echo "ch_version=$("$CH_BIN" --version 2>&1 | head -1)"
    echo "nproc=$(nproc)"
    echo "memtotal_kib=$(awk '/MemTotal/{print $2}' /proc/meminfo)"
    echo "halt_poll_ns=$(cat /sys/module/kvm/parameters/halt_poll_ns 2>/dev/null || echo na)"
    echo "mglru_host=$(cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null || echo unavailable)"
    echo "thp=$(cat /sys/kernel/mm/transparent_hugepage/enabled 2>/dev/null || echo na)"
    echo "cgroup_version=$(stat -fc %T /sys/fs/cgroup)"
    echo "host_swap_kib=$(awk '/SwapTotal/{print $2}' /proc/meminfo)"
    echo "guest_mem_mib=$MEMORY_MIB"
    echo "guest_vcpus=$BOOT_VCPUS"
    echo "jvm_xmx=$JVM_XMX"
    echo "block_backend=virtio-blk file (NOT vhost-user: see report caveats)"
    echo "work_dir_fs=$(findmnt -no SOURCE,FSTYPE --target "$WORK_DIR" | tr '\n' ' ')"
  } | tee "$RESULT_DIR/host-facts.txt" >&2
}

# ------------------------------------------------------------------- VM control

# $1 label, $2 extra CH args (may be empty)
boot_vm() {
  local label="$1" extra="$2"
  API_SOCKET="$RUN_DIR/api-$label.sock"
  rm -f "$API_SOCKET" "$RUN_DIR/vsock-$label.sock"

  local args=(
    --api-socket "$API_SOCKET"
    --cpus "boot=$BOOT_VCPUS"
    --kernel "$GUEST_KERNEL"
    --initramfs "$GUEST_INITRAMFS"
    --cmdline "$GUEST_CMDLINE"
    # image_type must be explicit: CH v53 auto-detects raw and then disables
    # sector 0 writes, which makes the guest's ext4 superblock write fail and
    # the root mount abort. Production uses vhost-user-blk and never hits this.
    --disk "path=$ROOT_DISK,image_type=raw"
    --net "tap=$TAP,mac=$MAC"
    --vsock "cid=3,socket=$RUN_DIR/vsock-$label.sock"
    --serial "file=$RUN_DIR/serial-$label.log"
    --console off
  )
  if [ -n "$BACKING_FILE" ]; then
    truncate -s "${MEMORY_MIB}M" "$BACKING_FILE"
    args+=(--memory "size=0")
    args+=(--memory-zone "id=cats-ram,size=${MEMORY_MIB}M,file=$BACKING_FILE,shared=on")
  else
    args+=(--memory "size=${MEMORY_MIB}M")
  fi
  # shellcheck disable=SC2206
  [ -n "$extra" ] && args+=($extra)

  note "cloud-hypervisor ${args[*]}"
  # No setsid: it forks, so $! would be the wrong pid for every /proc lookup.
  "$CH_BIN" "${args[@]}" >"$RUN_DIR/ch-$label.log" 2>&1 &
  CH_PID=$!

  local deadline=$((SECONDS + 30))
  while [ ! -S "$API_SOCKET" ]; do
    kill -0 "$CH_PID" 2>/dev/null || die "CH died: $(tail -5 "$RUN_DIR/ch-$label.log")"
    [ "$SECONDS" -lt "$deadline" ] || die "api socket never appeared"
    sleep 0.2
  done
}

place_in_cgroup() {
  local name="$1"
  echo "+memory +cpu" >/sys/fs/cgroup/cgroup.subtree_control 2>/dev/null || true
  CURRENT_CGROUP="/sys/fs/cgroup/$name"
  rmdir "$CURRENT_CGROUP" 2>/dev/null || true
  mkdir -p "$CURRENT_CGROUP"
  [ -f "$CURRENT_CGROUP/memory.high" ] || die "memory controller not delegated"
  echo "$CH_PID" >"$CURRENT_CGROUP/cgroup.procs"
  echo 1 >"$CURRENT_CGROUP/cgroup.pressure" 2>/dev/null || true
}

wait_app_ready() {
  local start=$SECONDS
  while :; do
    if curl -fsS --max-time 2 "http://$GUEST_IP:$APP_PORT/ready" >/dev/null 2>&1; then
      note "app ready in $((SECONDS - start))s"
      return 0
    fi
    kill -0 "$CH_PID" 2>/dev/null \
      || die "VM died before the app came up: $(tail -20 "$RUN_DIR/serial-"*.log | tail -20)"
    [ $((SECONDS - start)) -lt "$BOOT_TIMEOUT_S" ] \
      || die "app never ready; serial: $(tail -30 "$RUN_DIR/serial-"*.log | tail -30)"
    sleep 2
  done
}

# Run a command inside the guest through the probe's /exec endpoint. Avoids
# installing an SSH server, which would be resident during every measurement.
guest_exec() {
  local cmd="$1"
  curl -fsS --max-time 90 -G --data-urlencode "cmd=$cmd" \
    "http://$GUEST_IP:$APP_PORT/exec" 2>/dev/null \
    | python3 -c 'import json,sys
try: print(json.load(sys.stdin).get("output",""))
except Exception: print("")'
}

teardown_vm() {
  if [ -n "$CH_PID" ] && kill -0 "$CH_PID" 2>/dev/null; then
    "$CH_REMOTE" --api-socket "$API_SOCKET" power-button >/dev/null 2>&1 || true
    local deadline=$((SECONDS + 15))
    while kill -0 "$CH_PID" 2>/dev/null && [ "$SECONDS" -lt "$deadline" ]; do sleep 1; done
    kill -9 "$CH_PID" 2>/dev/null || true
    wait "$CH_PID" 2>/dev/null || true
  fi
  CH_PID=""
  [ -n "$CURRENT_CGROUP" ] && [ -d "$CURRENT_CGROUP" ] && rmdir "$CURRENT_CGROUP" 2>/dev/null || true
  CURRENT_CGROUP=""
}

cleanup() { teardown_vm; }
trap cleanup EXIT

# ------------------------------------------------------------------ sampling

mapping_kib() {
  python3 - "$1" "$2" <<'PY'
import os, sys
pid, target = sys.argv[1], os.path.realpath(sys.argv[2])
rss = pss = 0
matched = False
try:
    with open(f"/proc/{pid}/smaps", encoding="utf-8") as stream:
        for line in stream:
            head = line.split()
            if head and "-" in head[0] and len(head) >= 6:
                matched = os.path.realpath(head[5]) == target
            elif matched and line.startswith("Rss:"):
                rss += int(line.split()[1])
            elif matched and line.startswith("Pss:"):
                pss += int(line.split()[1])
except FileNotFoundError:
    pass
print(f"{rss} {pss}")
PY
}

cgroup_field() {
  local file="$1" key="$2"
  [ -r "$CURRENT_CGROUP/$file" ] || { echo 0; return; }
  if [ -z "$key" ]; then cat "$CURRENT_CGROUP/$file"; else
    awk -v k="$key" '$1==k {print $2; f=1} END{if(!f) print 0}' "$CURRENT_CGROUP/$file"
  fi
}

# memory.stat has no bare pgsteal/pgscan key, only pgsteal_kswapd and friends.
cgroup_field_prefix_sum() {
  local file="$1" prefix="$2"
  [ -r "$CURRENT_CGROUP/$file" ] || { echo 0; return; }
  awk -v p="$prefix" 'index($1,p)==1 {s+=$2} END{print s+0}' "$CURRENT_CGROUP/$file"
}

SAMPLE_COLUMNS="rung,elapsed_s,vmm_rss_kib,zone_rss_kib,zone_pss_kib,backing_alloc_kib,cg_current_kib,cg_high,refault_file,refault_anon,pgsteal,pgscan,cpu_usec,psi_cpu_total,jvm_rss_kib,jvm_swap_kib,heap_used_kib,guest_memfree_kib,guest_memavail_kib,guest_cached_kib,guest_anon_kib,guest_slab_kib,guest_swapfree_kib,fixed_fires,cron_fires"

sample_once() {
  local rung="$1" elapsed="$2"
  local zone_rss=0 zone_pss=0 vmm_rss=0 backing_alloc=0
  if [ -n "$BACKING_FILE" ] && [ -e "$BACKING_FILE" ]; then
    read -r zone_rss zone_pss < <(mapping_kib "$CH_PID" "$BACKING_FILE")
    backing_alloc=$(( $(stat -c %b "$BACKING_FILE") * $(stat -c %B "$BACKING_FILE") / 1024 ))
  fi
  vmm_rss="$(awk '/^VmRSS/{print $2}' "/proc/$CH_PID/status" 2>/dev/null || echo 0)"

  local cg_current cg_high refault_file refault_anon pgsteal pgscan cpu_usec psi
  cg_current=$(( $(cgroup_field memory.current "") / 1024 ))
  cg_high="$(cgroup_field memory.high "")"
  refault_file="$(cgroup_field memory.stat workingset_refault_file)"
  refault_anon="$(cgroup_field memory.stat workingset_refault_anon)"
  pgsteal="$(cgroup_field_prefix_sum memory.stat pgsteal)"
  pgscan="$(cgroup_field_prefix_sum memory.stat pgscan)"
  cpu_usec="$(cgroup_field cpu.stat usage_usec)"
  psi="$(awk '/^some/{for(i=1;i<=NF;i++) if($i ~ /^total=/){sub("total=","",$i); print $i}}' \
        "$CURRENT_CGROUP/cpu.pressure" 2>/dev/null || echo 0)"

  local g
  g="$(curl -fsS --max-time 3 "http://$GUEST_IP:$APP_PORT/stats" 2>/dev/null \
      | python3 -c '
import json,sys
try: d=json.load(sys.stdin)
except Exception: d={}
keys=["jvm_rss_kib","jvm_swap_kib","heap_used_kib","guest_memfree_kib","guest_memavailable_kib",
      "guest_cached_kib","guest_anonpages_kib","guest_slab_kib","guest_swapfree_kib",
      "fixed_rate_fires","cron_fires"]
print(",".join(str(d.get(k,-1)) for k in keys))' 2>/dev/null || echo "-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1")"
  [ -n "$g" ] || g="-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$rung" "$elapsed" "$vmm_rss" "$zone_rss" "$zone_pss" "$backing_alloc" \
    "$cg_current" "$cg_high" "$refault_file" "$refault_anon" "$pgsteal" "$pgscan" \
    "$cpu_usec" "$psi" "$g"
}

measure_rung() {
  local rung="$1" seconds="$2"
  local csv="$RAW_DIR/$rung.csv"
  echo "$SAMPLE_COLUMNS" >"$csv"
  local start=$SECONDS
  while [ $((SECONDS - start)) -lt "$seconds" ]; do
    sample_once "$rung" "$((SECONDS - start))" >>"$csv" || note "sample failed, continuing"
    sleep "$SAMPLE_INTERVAL_S"
  done
  note "$rung: $(( $(wc -l <"$csv") - 1 )) samples; last row:"
  tail -1 "$csv" >&2
}

warm_app() {
  # A just-booted JVM is not the thing users pay for. Load classes, serve
  # requests, churn heap, and populate guest page cache first.
  curl -fsS --max-time 120 "http://$GUEST_IP:$APP_PORT/touch?mib=256" >/dev/null || true
  curl -fsS --max-time 120 "http://$GUEST_IP:$APP_PORT/hold?mib=64" >/dev/null || true
  for _ in $(seq 1 50); do
    curl -fsS --max-time 5 "http://$GUEST_IP:$APP_PORT/actuator/health" >/dev/null 2>&1 || true
  done
  guest_exec 'cat /opt/dozing-probe.jar /usr/lib/jvm/*/lib/modules > /dev/null 2>&1; echo warmed' >/dev/null
}

collect_guest_artifacts() {
  local rung="$1"
  curl -fsS --max-time 10 "http://$GUEST_IP:$APP_PORT/fires" \
    -o "$RAW_DIR/$rung-fires.csv" 2>/dev/null || note "no fire log for $rung"
  guest_exec 'dmesg | tail -120' >"$RAW_DIR/$rung-guest-dmesg.txt" 2>/dev/null || true
  guest_exec 'cat /proc/meminfo; echo ---; cat /proc/vmstat' \
    >"$RAW_DIR/$rung-guest-mem.txt" 2>/dev/null || true
}

# ------------------------------------------------------------------ the ladder

run_rung() {
  local rung="$1" extra="$2" hook="${3:-}"
  say "Rung $rung"
  ROOT_DISK="$RUN_DIR/root-$rung.ext4"
  BACKING_FILE="$RUN_DIR/backing-$rung.mem"
  rm -f "$ROOT_DISK" "$BACKING_FILE"
  cp --sparse=always "$PROBE_ROOTFS" "$ROOT_DISK"

  boot_vm "$rung" "$extra"
  place_in_cgroup "cats-dozing-$rung"
  wait_app_ready
  warm_app
  note "settling ${SETTLE_S}s so JIT and startup churn stop moving the numbers"
  sleep "$SETTLE_S"

  # Each rung carries its own pre-mechanism control, so no comparison ever
  # crosses two different boots.
  sample_once "$rung" -1 >>"$RESULT_DIR/pre-config.csv"
  if [ -n "$hook" ]; then note "applying $hook"; "$hook"; fi

  measure_rung "$rung" "${RUNG_MEASURE_S:-$MEASURE_S}"
  collect_guest_artifacts "$rung"
  teardown_vm
  rm -f "$ROOT_DISK" "$BACKING_FILE"
}

hook_host_high() {
  # 25% of guest RAM: enough to force continuous reclaim. memory.high, never
  # memory.max -- max would OOM-kill the VMM instead of applying pressure.
  local target=$(( MEMORY_MIB * 1024 * 1024 / 4 ))
  echo "$target" >"$CURRENT_CGROUP/memory.high"
  note "host memory.high=$target"
}

hook_guest_pressure() {
  # The guest kernel has the LRU information the host lacks, so accuracy comes
  # from asking it to reclaim rather than guessing host-side.
  #
  # The JVM must first be moved into a non-root cgroup: cgroup v2's root has no
  # memory.high / memory.reclaim at all, and the Cats guest image has no systemd
  # to have placed the process in a slice, so without this every pressure write
  # silently goes nowhere.
  curl -fsS --max-time 30 "http://$GUEST_IP:$APP_PORT/gc" >/dev/null 2>&1 || true
  guest_exec 'set -x
    # The Cats guest image does not mount cgroup2 (cats-init mounts only proc,
    # sysfs, devpts and tmpfs), so every guest-side pressure knob is missing
    # until it is mounted. This is a real gap in the image, not just a test
    # detail: asking the guest to reclaim is where the accuracy comes from.
    mountpoint -q /sys/fs/cgroup || mount -t cgroup2 none /sys/fs/cgroup || echo "CGROUP2 MOUNT FAILED"
    cat /sys/fs/cgroup/cgroup.controllers 2>/dev/null || echo "no controllers file"
    mkdir -p /sys/fs/cgroup/dozing
    echo "+memory" > /sys/fs/cgroup/cgroup.subtree_control 2>&1 || echo "SUBTREE FAILED"
    echo "jvm already started inside the cgroup by dozing-start"
    echo "jvm cgroup procs: $(cat /sys/fs/cgroup/dozing/cgroup.procs 2>/dev/null | tr "\\n" " ")"
    echo "jvm cgroup current: $(cat /sys/fs/cgroup/dozing/memory.current 2>/dev/null || echo NONE)"
    echo "--- before"; grep -E "MemFree|Cached|AnonPages|SwapFree" /proc/meminfo
    # Step the limit down rather than slamming it: a single aggressive value
    # sends the JVM straight into swap thrash instead of steady reclaim.
    for lim in 320M 256M 192M; do
      echo $lim > /sys/fs/cgroup/dozing/memory.high 2>&1 || echo "HIGH FAILED at $lim"
      echo 64M > /sys/fs/cgroup/dozing/memory.reclaim 2>&1 || echo "reclaim failed at $lim"
      sleep 3
    done
    sync; echo 3 > /proc/sys/vm/drop_caches
    sleep 3
    echo "--- after"; grep -E "MemFree|Cached|AnonPages|SwapFree" /proc/meminfo
    echo "jvm cgroup current: $(cat /sys/fs/cgroup/dozing/memory.current 2>/dev/null || echo NONE)"
    echo "jvm cgroup stat: $(grep -E \"^(anon|file|slab) \" /sys/fs/cgroup/dozing/memory.stat 2>/dev/null | tr \"\\n\" \" \")"' \
    | tee -a "$RESULT_DIR/guest-pressure.log" >&2
  # Give free page reporting time to hand the freed blocks back to the host.
  sleep 20
}

hook_guest_pressure_swap() {
  guest_exec 'if ! swapon --show 2>/dev/null | grep -q swapfile; then
      fallocate -l 512M /swapfile && chmod 600 /swapfile && mkswap -q /swapfile && swapon /swapfile
    fi
    swapon --show 2>/dev/null || cat /proc/swaps
    echo 100 > /proc/sys/vm/swappiness' | tee -a "$RESULT_DIR/guest-pressure.log" >&2
  hook_guest_pressure
}

hook_mglru() {
  echo y >/sys/kernel/mm/lru_gen/enabled 2>/dev/null || note "host MGLRU unavailable"
  guest_exec 'cat /sys/kernel/mm/lru_gen/enabled 2>/dev/null || echo "guest MGLRU unavailable"' >&2
  hook_guest_pressure_swap
}

hook_suspend_pageout() {
  # The existing Suspended path, measured in this same run so the ladder has an
  # in-run reference rather than a cross-machine comparison.
  local before after
  read -r before _ < <(mapping_kib "$CH_PID" "$BACKING_FILE")
  "$CH_REMOTE" --api-socket "$API_SOCKET" pause >/dev/null
  sleep 2
  python3 "$REPO/experiments/warm-snapshot-benchmark/process_madvise_file.py" \
    "$CH_PID" "$BACKING_FILE" pageout >&2 || note "pageout helper failed"
  sleep 3
  read -r after _ < <(mapping_kib "$CH_PID" "$BACKING_FILE")
  note "Suspended reference: zone rss ${before} -> ${after} KiB"
  { echo "before_kib=$before"; echo "after_kib=$after"; } >"$RESULT_DIR/suspended-reference.txt"
}

phase_ladder() {
  echo "$SAMPLE_COLUMNS" >"$RESULT_DIR/pre-config.csv"
  local balloon="--balloon size=0,free_page_reporting=on"

  run_rung R0_baseline            ""          ""
  run_rung R1_host_high           ""          hook_host_high
  run_rung R2_fpr                 "$balloon"  ""
  run_rung R3_fpr_guest_pressure  "$balloon"  hook_guest_pressure
  run_rung R4_fpr_guest_swap      "$balloon"  hook_guest_pressure_swap
  run_rung R5_all_plus_host_high  "$balloon"  "hook_all"
  RUNG_MEASURE_S=90 run_rung S_suspended "" hook_suspend_pageout
  unset RUNG_MEASURE_S
}

hook_all() { hook_guest_pressure_swap; hook_host_high; }

# Second ladder: the first run's guest-pressure rungs silently no-opped because
# cgroup v2's root has no memory.reclaim and the JVM had a pinned, fully
# committed heap. Both are fixed; these rungs are the real measurement of
# "reclaim a running guest by asking the guest".
# The guest-side pressure rungs. Order matters: hook_guest_pressure on its own
# has no swap to push anon pages to, so memory.high throttling freezes the JVM
# (that is what killed R9 in the recorded run). Keep the swap variants.
phase_ladder3() {
  local balloon="--balloon size=0,free_page_reporting=on"
  RUNG_MEASURE_S=240 run_rung R9_cgroup_at_launch      "$balloon" hook_guest_pressure_swap
  RUNG_MEASURE_S=240 run_rung R10_cgroup_launch_swap   "$balloon" hook_guest_pressure_swap
  RUNG_MEASURE_S=240 run_rung R11_everything           "$balloon" hook_all
  unset RUNG_MEASURE_S
}

# Suspended, but entered from an already-reclaimed guest: this is the
# combination Cats would actually ship if Dozing became the pre-Suspend state.
hook_suspend_after_pressure() {
  hook_guest_pressure_swap
  hook_suspend_pageout
}


# The soak showed the guest freeing hundreds of MiB that never came back to the
# host. page_reporting_order defaults to pageblock order (9 == 2 MiB), so only
# large contiguous free blocks are reported, and heavy reclaim leaves the free
# list fragmented. This phase tests that explanation directly by lowering the
# order mid-run and watching host residency.
phase_fpr_order() {
  say "Free page reporting granularity sweep"
  ROOT_DISK="$RUN_DIR/root-fprorder.ext4"
  BACKING_FILE="$RUN_DIR/backing-fprorder.mem"
  rm -f "$ROOT_DISK" "$BACKING_FILE"
  cp --sparse=always "$PROBE_ROOTFS" "$ROOT_DISK"
  boot_vm fprorder "--balloon size=0,free_page_reporting=on"
  place_in_cgroup "cats-dozing-fprorder"
  wait_app_ready
  warm_app
  sleep 30
  hook_guest_pressure_swap || true

  local csv="$RAW_DIR/fpr-order.csv"
  echo "phase,$SAMPLE_COLUMNS" >"$csv"
  local i
  for i in 1 2 3 4 5 6; do
    echo "order9,$(sample_once order9 $((i*10)))" >>"$csv"; sleep 10
  done
  guest_exec 'echo 0 > /sys/module/page_reporting/parameters/page_reporting_order 2>&1 \
    && echo "order set to $(cat /sys/module/page_reporting/parameters/page_reporting_order)" \
    || echo "ORDER WRITE FAILED"
    # Reporting only runs when free pages cross a watermark, so nudge the guest
    # into freeing something to trigger a reporting cycle at the new order.
    python3 -c "b=bytearray(200*1024*1024)" 2>/dev/null || true
    sync' | tee -a "$RESULT_DIR/guest-pressure.log" >&2
  sleep 15
  for i in 1 2 3 4 5 6 7 8 9; do
    echo "order0,$(sample_once order0 $((i*10)))" >>"$csv"; sleep 10
  done
  note "fpr-order results:"; column -s, -t "$csv" 2>/dev/null | awk 'NR==1||NR%3==1' | cut -c1-140 >&2 || tail -5 "$csv" >&2
  collect_guest_artifacts fprorder
  teardown_vm
  rm -f "$ROOT_DISK" "$BACKING_FILE"
}

# --------------------------------------------------------------- halt polling

phase_haltpoll() {
  say "halt_poll_ns cost sweep"
  local csv="$RAW_DIR/haltpoll.csv"
  echo "halt_poll_ns,nominal_wakeups_per_s,guest_ctxsw_per_s,vmm_cpu_usec_per_s,vmm_cpu_pct_of_core" >"$csv"
  local original
  original="$(cat /sys/module/kvm/parameters/halt_poll_ns)"
  note "original halt_poll_ns=$original"

  local hp wps
  for hp in "$original" 0; do
    echo "$hp" >/sys/module/kvm/parameters/halt_poll_ns
    for wps in 0 100 500 1000; do
      ROOT_DISK="$RUN_DIR/root-hp.ext4"
      BACKING_FILE=""
      rm -f "$ROOT_DISK"
      cp --sparse=always "$PROBE_ROOTFS" "$ROOT_DISK"
      boot_vm "hp-$hp-$wps" ""
      place_in_cgroup "cats-dozing-hp"
      wait_app_ready
      if [ "$wps" -gt 0 ]; then
        # Wakeup frequency, not utilisation, is what drives halt-poll cost.
        local interval
        interval="$(awk -v w="$wps" 'BEGIN{printf "%.6f", 1.0/w}')"
        guest_exec "nohup python3 -c 'import time
while True: time.sleep($interval)' >/dev/null 2>&1 & echo started" >/dev/null
        sleep 5
      fi
      sleep 15
      local t0 t1 c0 c1
      t0="$(cgroup_field cpu.stat usage_usec)"
      c0="$(guest_exec 'awk "/^ctxt/{print \$2}" /proc/stat' | tr -d '[:space:]')"
      sleep 30
      t1="$(cgroup_field cpu.stat usage_usec)"
      c1="$(guest_exec 'awk "/^ctxt/{print \$2}" /proc/stat' | tr -d '[:space:]')"
      local usec_per_s ctxsw_per_s pct
      usec_per_s=$(( (t1 - t0) / 30 ))
      ctxsw_per_s=$(( ( ${c1:-0} - ${c0:-0} ) / 30 ))
      # A whole core is 1e6 usec/s, so this is percent-of-one-core burned by a
      # guest doing no business work at all.
      pct="$(awk -v u="$usec_per_s" 'BEGIN{printf "%.2f", 100*u/1000000}')"
      echo "$hp,$wps,$ctxsw_per_s,$usec_per_s,$pct" >>"$csv"
      note "halt_poll_ns=$hp nominal=$wps/s ctxsw=$ctxsw_per_s/s -> ${pct}% of a core"
      teardown_vm
      rm -f "$ROOT_DISK"
    done
  done
  echo "$original" >/sys/module/kvm/parameters/halt_poll_ns
  note "restored halt_poll_ns=$original"
}

# ---------------------------------------------------------------------- soak

phase_soak() {
  local seconds="${SOAK_S:-2400}"
  say "Soak ${seconds}s under the deepest reclaim config"
  ROOT_DISK="$RUN_DIR/root-soak.ext4"
  BACKING_FILE="$RUN_DIR/backing-soak.mem"
  rm -f "$ROOT_DISK" "$BACKING_FILE"
  cp --sparse=always "$PROBE_ROOTFS" "$ROOT_DISK"
  boot_vm soak "--balloon size=0,free_page_reporting=on"
  place_in_cgroup "cats-dozing-soak"
  wait_app_ready
  warm_app
  hook_all
  guest_exec "nohup python3 /opt/timer_sampler.py --out /var/log/dozing/timers.csv \
    --seconds $seconds --interval 1 --label soak >/dev/null 2>&1 & echo sampler started" >/dev/null
  measure_rung soak "$seconds"
  collect_guest_artifacts soak
  guest_exec 'cat /var/log/dozing/timers.csv' >"$RAW_DIR/soak-timers.csv" 2>/dev/null || true
  guest_exec 'dmesg | grep -Ei "rcu|soft lockup|hung task|clocksource|watchdog|oom|stall" || echo "no pathologies found"' \
    >"$RESULT_DIR/soak-dmesg-findings.txt" 2>&1 || true
  teardown_vm
}

# ----------------------------------------------------------------------- main

phase_setup() {
  setup_host_packages
  setup_ch
  build_guest_artifacts
  build_app
  build_probe_rootfs
  host_facts
  setup_network
}

main() {
  [ "$(id -u)" -eq 0 ] || die "run as root"
  mkdir -p "$RESULT_DIR" "$RAW_DIR" "$RUN_DIR"
  case "${1:-all}" in
    setup)    phase_setup ;;
    ladder)   phase_setup; phase_ladder ;;
    ladder3)  phase_setup; phase_ladder3 ;;
    fprorder) phase_setup; phase_fpr_order ;;
    haltpoll) phase_setup; phase_haltpoll ;;
    soak)     phase_setup; phase_soak ;;
    all)      phase_setup; phase_ladder; phase_ladder3; phase_fpr_order; phase_haltpoll; phase_soak ;;
    *) die "unknown phase: $1" ;;
  esac
  say "Done. Results in $RESULT_DIR"
}

main "$@"
