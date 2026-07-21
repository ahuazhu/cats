#!/usr/bin/env bash
# Measure a Cats-style Warm transition on a real KVM host:
#
#   running -> CH snapshot -> VMM/backend/tap exit -> local NVMe only
#           -> restart backend/tap -> CH ondemand restore -> resume
#
# The guest runs a small HTTP service with an in-memory boot ID and a configurable
# touched working set. A successful restore must return the same boot ID.
set -euo pipefail

BENCHMARK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

CH_VERSION="${CH_VERSION:-v53.0}"
WORK_DIR="${WORK_DIR:-/var/lib/cats-warm-bench}"
ASSET_DIR="${ASSET_DIR:-$WORK_DIR}"
MEMORY_MIB="${MEMORY_MIB:-1024}"
WORKSET_MIB="${WORKSET_MIB:-128}"
SERVICE_NETWORK_TARGET="${SERVICE_NETWORK_TARGET:-network-online.target}"
SERVICE_BOOT_MODE="${SERVICE_BOOT_MODE:-normal}"
GUEST_KERNEL="${GUEST_KERNEL:-}"
GUEST_INITRAMFS="${GUEST_INITRAMFS:-}"
GUEST_CMDLINE="${GUEST_CMDLINE:-root=LABEL=cloudimg-rootfs ro console=ttyS0}"
ITERATIONS="${ITERATIONS:-5}"
GUEST_IP="${GUEST_IP:-192.168.249.2}"
HOST_IP="${HOST_IP:-192.168.249.1}"
PREFIX="${PREFIX:-24}"
BRIDGE="${BRIDGE:-cwb0}"
TAP="${TAP:-cwbtap0}"
MAC="${MAC:-02:ca:75:00:00:02}"
HTTP_PORT="${HTTP_PORT:-8000}"
BOOT_TIMEOUT_S="${BOOT_TIMEOUT_S:-180}"
WAKE_TIMEOUT_S="${WAKE_TIMEOUT_S:-15}"
PREFAULT_TIMEOUT_S="${PREFAULT_TIMEOUT_S:-300}"
WAKE_BARRIER_DIR="${WAKE_BARRIER_DIR:-}"
WAKE_WORKER_ID="${WAKE_WORKER_ID:-}"
MEMORY_BACKING_FILE="${MEMORY_BACKING_FILE:-}"
RUNTIME_CGROUP="${RUNTIME_CGROUP:-}"
RUNTIME_EXEC="${RUNTIME_EXEC:-$BENCHMARK_DIR/runtime_exec.py}"

BIN_DIR="$ASSET_DIR/bin"
SRC_DIR="$ASSET_DIR/src"
IMAGE_DIR="$ASSET_DIR/images"
RUN_DIR="$WORK_DIR/run"
RESULT_DIR="$WORK_DIR/results"
SNAPSHOT_DIR="$WORK_DIR/snapshot"
CH_BIN="$BIN_DIR/cloud-hypervisor"
CH_REMOTE="$BIN_DIR/ch-remote"
VHOST_BLK="$BIN_DIR/vhost_user_block"
FIRMWARE="$IMAGE_DIR/hypervisor-fw"
BASE_DISK="$IMAGE_DIR/jammy-base.raw"
ROOT_DISK="${ROOT_DISK:-$RUN_DIR/jammy-working.raw}"
SEED_DISK="$RUN_DIR/seed.img"
API_SOCKET="$RUN_DIR/cloud-hypervisor.sock"
VHOST_SOCKET="$RUN_DIR/vhost-user-blk.sock"
CH_LOG="$RUN_DIR/cloud-hypervisor.log"
VHOST_LOG="$RUN_DIR/vhost-user-blk.log"
SERIAL_LOG="$RUN_DIR/serial.log"
CSV="$RESULT_DIR/warm-benchmark.csv"

CH_PID=""
VHOST_PID=""

say() { printf '\n==> %s\n' "$*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
now_ns() { date +%s%N; }
elapsed_ms() { awk -v start="$1" -v end="$2" 'BEGIN { printf "%.3f", (end-start)/1000000 }'; }

require_linux_kvm() {
  [ "$(uname -s)" = Linux ] || die "requires Linux; current host is $(uname -s)"
  [ "$(uname -m)" = x86_64 ] || die "this benchmark currently requires x86_64"
  [ -e /dev/kvm ] || die "missing /dev/kvm (Docker Desktop on macOS cannot run this benchmark)"
  [ -r /dev/kvm ] && [ -w /dev/kvm ] || die "/dev/kvm is not readable/writable; run with sudo"
}

as_root() {
  if [ "${EUID:-$(id -u)}" -ne 0 ]; then
    exec sudo --preserve-env=CH_VERSION,WORK_DIR,ASSET_DIR,MEMORY_MIB,WORKSET_MIB,SERVICE_NETWORK_TARGET,SERVICE_BOOT_MODE,GUEST_KERNEL,GUEST_INITRAMFS,GUEST_CMDLINE,ITERATIONS,GUEST_IP,HOST_IP,PREFIX,BRIDGE,TAP,MAC,HTTP_PORT,BOOT_TIMEOUT_S,WAKE_TIMEOUT_S,PREFAULT_TIMEOUT_S,WAKE_BARRIER_DIR,WAKE_WORKER_ID,MEMORY_BACKING_FILE,ROOT_DISK,RUNTIME_CGROUP,RUNTIME_EXEC \
      "$0" "$@"
  fi
}

download_release_asset() {
  local asset="$1" destination="$2" url
  url="$(curl -fsSL "https://api.github.com/repos/cloud-hypervisor/cloud-hypervisor/releases/tags/$CH_VERSION" \
    | python3 -c 'import json,sys; n=sys.argv[1]; a=json.load(sys.stdin).get("assets", []); print(next((x["browser_download_url"] for x in a if x["name"]==n), ""))' "$asset")"
  [ -n "$url" ] || die "release asset $asset not found for $CH_VERSION"
  curl -fL --retry 3 -o "$destination" "$url"
  chmod +x "$destination"
}

prepare_dependencies() {
  say "Install build and image tooling"
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y
  apt-get install -y --no-install-recommends \
    ca-certificates curl git jq python3 qemu-utils cloud-image-utils \
    build-essential pkg-config libseccomp-dev libcap-ng-dev clang

  if ! command -v cargo >/dev/null 2>&1; then
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
    export PATH="/root/.cargo/bin:$PATH"
  fi
}

prepare_binaries() {
  mkdir -p "$BIN_DIR" "$SRC_DIR" "$IMAGE_DIR" "$RUN_DIR" "$RESULT_DIR"
  say "Download Cloud Hypervisor $CH_VERSION"
  [ -x "$CH_BIN" ] || download_release_asset cloud-hypervisor-static "$CH_BIN"
  [ -x "$CH_REMOTE" ] || download_release_asset ch-remote-static "$CH_REMOTE"

  if [ ! -x "$VHOST_BLK" ]; then
    say "Build the in-tree vhost-user-blk reference backend"
    export PATH="/root/.cargo/bin:$PATH"
    local source="$SRC_DIR/cloud-hypervisor-$CH_VERSION"
    if [ ! -d "$source/.git" ]; then
      rm -rf "$source"
      git clone --depth 1 --branch "$CH_VERSION" \
        https://github.com/cloud-hypervisor/cloud-hypervisor.git "$source"
    fi
    cargo build --manifest-path "$source/Cargo.toml" --release --package vhost_user_block
    install -m 0755 "$source/target/release/vhost_user_block" "$VHOST_BLK"
  fi

  if [ ! -f "$FIRMWARE" ]; then
    say "Download rust-hypervisor-firmware"
    local fw_url
    fw_url="$(curl -fsSL https://api.github.com/repos/cloud-hypervisor/rust-hypervisor-firmware/releases/latest \
      | python3 -c 'import json,sys; a=json.load(sys.stdin).get("assets", []); print(next((x["browser_download_url"] for x in a if x["name"]=="hypervisor-fw"), ""))')"
    [ -n "$fw_url" ] || die "hypervisor-fw release asset not found"
    curl -fL --retry 3 -o "$FIRMWARE" "$fw_url"
  fi

  "$CH_BIN" --version
  "$VHOST_BLK" --version
}

prepare_guest() {
  mkdir -p "$IMAGE_DIR" "$RUN_DIR"
  if [ ! -f "$BASE_DISK" ]; then
    say "Download and convert Ubuntu 22.04 cloud image"
    curl -fL --retry 3 -o "$IMAGE_DIR/jammy.img" \
      https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-amd64.img
    qemu-img convert -p -O raw "$IMAGE_DIR/jammy.img" "$BASE_DISK"
    qemu-img resize "$BASE_DISK" 4G
  fi

  say "Build cloud-init seed with an in-memory working-set service"
  local server_b64 service_b64 service_unit_ordering service_install_target
  server_b64="$(cat <<'PY' | base64 -w0
import json
import os
import subprocess
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

process_entry_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
size = int(os.environ.get("WORKSET_MIB", "128")) * 1024 * 1024
allocation_start_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
memory = bytearray(size)
for offset in range(0, size, 4096):
    memory[offset] = (offset // 4096) & 0xff
allocation_end_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)

boot_id = str(uuid.uuid4())
started_ns = time.time_ns()
request_count = 0

def boot_timing():
    now_boottime_ns = time.clock_gettime_ns(time.CLOCK_BOOTTIME)
    return {
        "process_entry_boottime_ms": round(process_entry_boottime_ns / 1_000_000, 3),
        "allocation_start_boottime_ms": round(allocation_start_boottime_ns / 1_000_000, 3),
        "allocation_end_boottime_ms": round(allocation_end_boottime_ns / 1_000_000, 3),
        "workset_init_ms": round((allocation_end_boottime_ns - allocation_start_boottime_ns) / 1_000_000, 3),
        "guest_uptime_ms": round(now_boottime_ns / 1_000_000, 3),
    }

def command_output(command):
    result = subprocess.run(command, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10, check=False)
    return {"exit_code": result.returncode, "output": result.stdout.strip()}

class Handler(BaseHTTPRequestHandler):
    def reply(self, payload):
        body = json.dumps(payload, separators=(",", ":")).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        global request_count
        request_count += 1
        if self.path == "/profile":
            payload = {
                "ok": True,
                "boot_id": boot_id,
                **boot_timing(),
                "systemd_time": command_output(["systemd-analyze", "time", "--no-pager"]),
                "critical_chain": command_output([
                    "systemd-analyze", "critical-chain", "cats-warm-server.service", "--no-pager"
                ]),
                "blame": command_output(["systemd-analyze", "blame", "--no-pager"]),
                "active_jobs": command_output(["systemctl", "list-jobs", "--no-pager"]),
                "unit_timestamps": command_output([
                    "systemctl", "show", "--no-pager",
                    "--property=Id,ActiveState,SubState,InactiveExitTimestampMonotonic,"
                    "ActiveEnterTimestampMonotonic,ExecMainStartTimestampMonotonic,"
                    "ExecMainExitTimestampMonotonic",
                    "systemd-networkd.service",
                    "systemd-networkd-wait-online.service",
                    "cloud-init-local.service",
                    "cloud-init.service",
                    "cloud-config.service",
                    "cloud-final.service",
                    "cats-warm-server.service",
                ]),
                "boot_journal": command_output([
                    "journalctl", "-b", "--no-pager", "-o", "short-monotonic",
                    "-u", "systemd-networkd.service",
                    "-u", "systemd-networkd-wait-online.service",
                    "-u", "cloud-init-local.service",
                    "-u", "cloud-init.service",
                    "-u", "cats-warm-server.service",
                ]),
            }
            self.reply(payload)
            return
        if self.path == "/sync":
            os.sync()
            self.reply({"ok": True, "boot_id": boot_id})
            return
        if self.path == "/touch":
            begin = time.perf_counter_ns()
            checksum = 0
            for offset in range(0, len(memory), 4096):
                checksum = (checksum + memory[offset]) & 0xffffffff
            self.reply({
                "ok": True,
                "boot_id": boot_id,
                "workset_mib": size // 1024 // 1024,
                "touch_ms": round((time.perf_counter_ns() - begin) / 1_000_000, 3),
                "checksum": checksum,
            })
            return
        self.reply({
            "ok": True,
            "boot_id": boot_id,
            "started_ns": started_ns,
            "requests": request_count,
            "workset_mib": size // 1024 // 1024,
            **boot_timing(),
        })

    def log_message(self, fmt, *args):
        return

ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()
PY
)"
  if [ "$SERVICE_BOOT_MODE" = earliest ]; then
    service_unit_ordering="DefaultDependencies=no
After=local-fs.target
Before=cloud-init.service"
    service_install_target="sysinit.target"
  elif [ "$SERVICE_BOOT_MODE" = early ]; then
    service_unit_ordering="DefaultDependencies=no
After=local-fs.target systemd-networkd.service
Before=cloud-init.service"
    service_install_target="sysinit.target"
  else
    service_unit_ordering="After=$SERVICE_NETWORK_TARGET
Wants=$SERVICE_NETWORK_TARGET"
    service_install_target="multi-user.target"
  fi
  service_b64="$(cat <<EOF | base64 -w0
[Unit]
Description=Cats Warm Snapshot Benchmark Guest Service
$service_unit_ordering

[Service]
Type=simple
Environment=WORKSET_MIB=$WORKSET_MIB
ExecStart=/usr/bin/python3 /usr/local/bin/cats-warm-server.py
Restart=always

[Install]
WantedBy=$service_install_target
EOF
)"

  cat > "$RUN_DIR/user-data" <<EOF
#cloud-config
growpart:
  mode: auto
resize_rootfs: true
write_files:
  - path: /usr/local/bin/cats-warm-server.py
    permissions: '0755'
    encoding: b64
    content: $server_b64
  - path: /etc/systemd/system/cats-warm-server.service
    permissions: '0644'
    encoding: b64
    content: $service_b64
runcmd:
  - [ systemctl, daemon-reload ]
  - [ systemctl, enable, --now, cats-warm-server.service ]
EOF
  cat > "$RUN_DIR/meta-data" <<'EOF'
instance-id: cats-warm-benchmark-v1
local-hostname: cats-warm-benchmark
EOF
  cat > "$RUN_DIR/network-config" <<EOF
version: 2
ethernets:
  eth0:
    match:
      macaddress: "$MAC"
    set-name: eth0
    addresses:
      - "$GUEST_IP/$PREFIX"
EOF
  rm -f "$SEED_DISK"
  cloud-localds --network-config="$RUN_DIR/network-config" \
    "$SEED_DISK" "$RUN_DIR/user-data" "$RUN_DIR/meta-data"
}

prepare() {
  require_linux_kvm
  prepare_dependencies
  prepare_binaries
  prepare_guest
  say "Prepared $WORK_DIR"
}

pid_rss_kib() {
  local pid="${1:-}"
  [ -n "$pid" ] && [ -r "/proc/$pid/status" ] || { echo 0; return; }
  awk '/^VmRSS:/ {print $2; found=1} END {if (!found) print 0}' "/proc/$pid/status"
}

runtime_rss_kib() {
  local total=0 value
  for pid in "$CH_PID" "$VHOST_PID"; do
    value="$(pid_rss_kib "$pid")"
    total=$((total + value))
  done
  echo "$total"
}

stop_pid() {
  local pid="${1:-}"
  [ -n "$pid" ] || return 0
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 50); do
      kill -0 "$pid" 2>/dev/null || break
      [ "$(awk '{print $3}' "/proc/$pid/stat" 2>/dev/null || true)" = Z ] && break
      sleep 0.1
    done
    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
  fi
}

stop_runtime() {
  stop_pid "$CH_PID"
  stop_pid "$VHOST_PID"
  CH_PID=""
  VHOST_PID=""
  rm -f "$API_SOCKET" "$VHOST_SOCKET"
  ip link del "$TAP" 2>/dev/null || true
  ip link del "$BRIDGE" 2>/dev/null || true
}

cleanup() {
  set +e
  stop_runtime
}

ensure_network() {
  if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    ip link add "$BRIDGE" type bridge
  fi
  ip addr replace "$HOST_IP/$PREFIX" dev "$BRIDGE"
  ip link set "$BRIDGE" up
  ip link del "$TAP" 2>/dev/null || true
  ip tuntap add dev "$TAP" mode tap
  ip link set "$TAP" master "$BRIDGE"
  ip link set "$TAP" up
}

launch_runtime() {
  if [ -n "$RUNTIME_CGROUP" ]; then
    [ -x "$RUNTIME_EXEC" ] || die "missing cgroup exec helper: $RUNTIME_EXEC"
    exec python3 "$RUNTIME_EXEC" "$RUNTIME_CGROUP" "$@"
  fi
  exec "$@"
}

start_backend() {
  rm -f "$VHOST_SOCKET"
  : > "$VHOST_LOG"
  launch_runtime "$VHOST_BLK" --block-backend \
    "path=$ROOT_DISK,socket=$VHOST_SOCKET,num_queues=1,queue_size=128,readonly=false,direct=false,poll_queue=false" \
    >"$VHOST_LOG" 2>&1 &
  VHOST_PID=$!
  for _ in $(seq 1 100); do
    [ -S "$VHOST_SOCKET" ] && return 0
    kill -0 "$VHOST_PID" 2>/dev/null || { tail -n 100 "$VHOST_LOG" >&2; die "vhost-user-blk exited"; }
    sleep 0.02
  done
  die "vhost-user-blk socket did not appear"
}

wait_api() {
  local deadline=$((SECONDS + WAKE_TIMEOUT_S))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if [ -S "$API_SOCKET" ] && "$CH_REMOTE" --api-socket "$API_SOCKET" info >/dev/null 2>&1; then
      return 0
    fi
    kill -0 "$CH_PID" 2>/dev/null || { tail -n 120 "$CH_LOG" >&2; die "Cloud Hypervisor exited"; }
    sleep 0.02
  done
  tail -n 120 "$CH_LOG" >&2 || true
  die "Cloud Hypervisor API was not ready in ${WAKE_TIMEOUT_S}s"
}

start_initial_vmm() {
  local -a memory_args boot_args
  if [ -n "$MEMORY_BACKING_FILE" ]; then
    mkdir -p "$(dirname "$MEMORY_BACKING_FILE")"
    [ -e "$MEMORY_BACKING_FILE" ] || truncate -s "${MEMORY_MIB}M" "$MEMORY_BACKING_FILE"
    memory_args=(
      --memory "size=0"
      --memory-zone "id=cats-ram,size=${MEMORY_MIB}M,file=$MEMORY_BACKING_FILE,shared=on,prefault=on"
    )
  else
    memory_args=(--memory "size=${MEMORY_MIB}M,shared=on")
  fi

  if [ -n "$GUEST_KERNEL" ]; then
    [ -f "$GUEST_KERNEL" ] || die "guest kernel not found: $GUEST_KERNEL"
    boot_args=(--kernel "$GUEST_KERNEL" --cmdline "$GUEST_CMDLINE")
    if [ -n "$GUEST_INITRAMFS" ]; then
      [ -f "$GUEST_INITRAMFS" ] || die "guest initramfs not found: $GUEST_INITRAMFS"
      boot_args+=(--initramfs "$GUEST_INITRAMFS")
    fi
  else
    boot_args=(--kernel "$FIRMWARE")
  fi

  rm -f "$API_SOCKET"
  : > "$CH_LOG"
  launch_runtime "$CH_BIN" \
    -v \
    --api-socket "$API_SOCKET" \
    --cpus boot=2 \
    "${memory_args[@]}" \
    "${boot_args[@]}" \
    --disk "vhost_user=true,socket=$VHOST_SOCKET,num_queues=1,queue_size=128" "path=$SEED_DISK" \
    --net "tap=$TAP,mac=$MAC" \
    --serial "file=$SERIAL_LOG" --console off --seccomp false \
    >"$CH_LOG" 2>&1 &
  CH_PID=$!
  wait_api
}

start_restored_vmm() {
  rm -f "$API_SOCKET"
  : > "$CH_LOG"
  launch_runtime "$CH_BIN" \
    -v \
    --api-socket "$API_SOCKET" \
    --restore "source_url=file://$SNAPSHOT_DIR,memory_restore_mode=ondemand" \
    >"$CH_LOG" 2>&1 &
  CH_PID=$!
  wait_api
}

guest_json() {
  local path="${1:-/health}"
  local timeout="${2:-2}"
  curl -fsS --connect-timeout 0.2 --max-time "$timeout" "http://$GUEST_IP:$HTTP_PORT$path"
}

wait_guest() {
  local timeout="$1" response
  local deadline=$((SECONDS + timeout))
  while [ "$SECONDS" -lt "$deadline" ]; do
    response="$(guest_json /health 2>/dev/null || true)"
    if printf '%s' "$response" | python3 -c 'import json,sys; raise SystemExit(0 if json.load(sys.stdin).get("ok") else 1)' 2>/dev/null; then
      printf '%s' "$response"
      return 0
    fi
    sleep 0.02
  done
  return 1
}

wait_restore_complete() {
  local deadline=$((SECONDS + PREFAULT_TIMEOUT_S))
  while [ "$SECONDS" -lt "$deadline" ]; do
    if grep -Fq "UFFD handler: prefault done" "$CH_LOG"; then
      return 0
    fi
    kill -0 "$CH_PID" 2>/dev/null || { tail -n 120 "$CH_LOG" >&2; die "Cloud Hypervisor exited during background prefault"; }
    sleep 0.02
  done
  tail -n 120 "$CH_LOG" >&2 || true
  die "on-demand restore did not finish background prefault in ${PREFAULT_TIMEOUT_S}s"
}

json_field() {
  python3 -c 'import json,sys; print(json.load(sys.stdin)[sys.argv[1]])' "$1"
}

drop_snapshot_cache() {
  sync
  python3 - "$SNAPSHOT_DIR" <<'PY'
import os
import pathlib
import sys

for path in pathlib.Path(sys.argv[1]).iterdir():
    if not path.is_file():
        continue
    with path.open("rb") as handle:
        os.posix_fadvise(handle.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
PY
}

snapshot_apparent_bytes() {
  find "$SNAPSHOT_DIR" -type f -printf '%s\n' | awk '{s+=$1} END {print s+0}'
}

snapshot_allocated_bytes() {
  find "$SNAPSHOT_DIR" -type f -printf '%b\n' | awk '{s+=$1*512} END {print s+0}'
}

write_csv_header() {
  mkdir -p "$RESULT_DIR"
  echo "iteration,memory_mib,workset_mib,before_rss_kib,pause_ms,snapshot_ms,shutdown_ms,warm_runtime_rss_kib,snapshot_apparent_bytes,snapshot_allocated_bytes,wake_started_ns,network_backend_ms,restore_to_api_ms,resume_api_ms,wake_to_health_ms,touch_wall_ms,touch_guest_ms,full_memory_ready_ms,after_rss_kib,full_ready_rss_kib,boot_id_preserved" > "$CSV"
}

wait_wake_barrier() {
  [ -n "$WAKE_BARRIER_DIR" ] || return 0
  [ -n "$WAKE_WORKER_ID" ] || die "WAKE_WORKER_ID is required with WAKE_BARRIER_DIR"
  mkdir -p "$WAKE_BARRIER_DIR"
  : > "$WAKE_BARRIER_DIR/$WAKE_WORKER_ID.ready"
  while [ ! -e "$WAKE_BARRIER_DIR/go" ]; do
    sleep 0.01
  done
}

one_cycle() {
  local iteration="$1" before_json before_boot after_json after_boot
  local before_rss pause_start pause_end snapshot_start snapshot_end shutdown_start shutdown_end
  local warm_rss apparent allocated wake_start prep_end restore_start restore_end resume_start resume_end health_end
  local touch_start touch_end touch_json touch_guest prefault_end after_rss full_ready_rss preserved

  # os.sync() may take several seconds on an EBS-backed guest disk. It is a
  # pre-snapshot durability barrier, not part of the measured wake path.
  before_json="$(guest_json /sync 30)"
  before_boot="$(printf '%s' "$before_json" | json_field boot_id)"
  before_rss="$(runtime_rss_kib)"

  rm -rf "$SNAPSHOT_DIR"
  mkdir -p "$SNAPSHOT_DIR"

  pause_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" pause >/dev/null
  pause_end="$(now_ns)"

  snapshot_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" snapshot "file://$SNAPSHOT_DIR" >/dev/null
  snapshot_end="$(now_ns)"

  shutdown_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" shutdown-vmm >/dev/null 2>&1 || true
  stop_pid "$CH_PID"
  CH_PID=""
  stop_pid "$VHOST_PID"
  VHOST_PID=""
  rm -f "$API_SOCKET" "$VHOST_SOCKET"
  ip link del "$TAP" 2>/dev/null || true
  shutdown_end="$(now_ns)"

  drop_snapshot_cache
  warm_rss="$(runtime_rss_kib)"
  apparent="$(snapshot_apparent_bytes)"
  allocated="$(snapshot_allocated_bytes)"

  wait_wake_barrier
  wake_start="$(now_ns)"
  ensure_network
  start_backend
  prep_end="$(now_ns)"

  restore_start="$(now_ns)"
  start_restored_vmm
  restore_end="$(now_ns)"

  resume_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" resume >/dev/null
  resume_end="$(now_ns)"

  after_json="$(wait_guest "$WAKE_TIMEOUT_S")" || {
    tail -n 120 "$CH_LOG" >&2 || true
    tail -n 120 "$VHOST_LOG" >&2 || true
    die "guest did not become healthy after restore"
  }
  health_end="$(now_ns)"
  after_boot="$(printf '%s' "$after_json" | json_field boot_id)"
  if [ "$before_boot" = "$after_boot" ]; then preserved=true; else preserved=false; fi

  touch_start="$(now_ns)"
  # This endpoint intentionally faults the full working set back in. On a
  # cold EBS/object-backed snapshot that can legitimately take much longer
  # than a health request, and its wall time is one of the measured results.
  touch_json="$(guest_json /touch 120)"
  touch_end="$(now_ns)"
  touch_guest="$(printf '%s' "$touch_json" | json_field touch_ms)"
  after_rss="$(runtime_rss_kib)"

  # Cloud Hypervisor v53 prefaults untouched pages in the background. Until
  # this completes, v53 intentionally rejects another snapshot or migration.
  wait_restore_complete
  prefault_end="$(now_ns)"
  full_ready_rss="$(runtime_rss_kib)"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$iteration" "$MEMORY_MIB" "$WORKSET_MIB" "$before_rss" \
    "$(elapsed_ms "$pause_start" "$pause_end")" \
    "$(elapsed_ms "$snapshot_start" "$snapshot_end")" \
    "$(elapsed_ms "$shutdown_start" "$shutdown_end")" \
    "$warm_rss" "$apparent" "$allocated" "$wake_start" \
    "$(elapsed_ms "$wake_start" "$prep_end")" \
    "$(elapsed_ms "$restore_start" "$restore_end")" \
    "$(elapsed_ms "$resume_start" "$resume_end")" \
    "$(elapsed_ms "$wake_start" "$health_end")" \
    "$(elapsed_ms "$touch_start" "$touch_end")" "$touch_guest" \
    "$(elapsed_ms "$wake_start" "$prefault_end")" "$after_rss" "$full_ready_rss" "$preserved" \
    | tee -a "$CSV"

  [ "$preserved" = true ] || die "boot ID changed; memory state was not preserved"
}

summarize() {
  python3 - "$CSV" <<'PY'
import csv
import statistics
import sys

rows = list(csv.DictReader(open(sys.argv[1], newline="")))
metrics = [
    "snapshot_ms",
    "shutdown_ms",
    "network_backend_ms",
    "restore_to_api_ms",
    "resume_api_ms",
    "wake_to_health_ms",
    "touch_wall_ms",
    "full_memory_ready_ms",
]
print("\n==> Summary")
for key in metrics:
    values = sorted(float(row[key]) for row in rows)
    p50 = statistics.median(values)
    p95 = values[max(0, int(len(values) * 0.95 + 0.999999) - 1)]
    print(f"{key:24s} p50={p50:9.3f} ms  p95={p95:9.3f} ms")
print(f"warm_runtime_rss_kib     max={max(int(r['warm_runtime_rss_kib']) for r in rows)} KiB")
print(f"full_ready_rss_kib       max={max(int(r['full_ready_rss_kib']) for r in rows)} KiB")
print(f"snapshot_allocated_bytes max={max(int(r['snapshot_allocated_bytes']) for r in rows)} bytes")
print(f"boot_id_preserved        {sum(r['boot_id_preserved']=='true' for r in rows)}/{len(rows)}")
PY
}

run_benchmark() {
  require_linux_kvm
  [ -x "$CH_BIN" ] || die "run '$0 prepare' first"
  [ -x "$CH_REMOTE" ] || die "run '$0 prepare' first"
  [ -x "$VHOST_BLK" ] || die "run '$0 prepare' first"
  [ -f "$BASE_DISK" ] || die "run '$0 prepare' first"

  # Rebuild the seed for the requested WORKSET_MIB and start from a pristine
  # cloud image. Reusing a previously booted image would make cloud-init skip
  # the new benchmark service configuration.
  prepare_guest
  rm -f "$ROOT_DISK"
  cp --reflink=auto --sparse=always "$BASE_DISK" "$ROOT_DISK"

  trap cleanup EXIT INT TERM
  stop_runtime
  mkdir -p "$RUN_DIR" "$RESULT_DIR"
  write_csv_header

  say "Boot ${MEMORY_MIB}MiB guest with ${WORKSET_MIB}MiB touched working set"
  ensure_network
  start_backend
  start_initial_vmm
  local initial_json
  initial_json="$(wait_guest "$BOOT_TIMEOUT_S")" || {
    tail -n 200 "$SERIAL_LOG" >&2 || true
    die "guest service was not ready in ${BOOT_TIMEOUT_S}s"
  }
  echo "guest=$initial_json"
  guest_json /touch 120 >/dev/null

  say "Run $ITERATIONS Warm snapshot/exit/ondemand-restore cycles"
  for iteration in $(seq 1 "$ITERATIONS"); do
    echo "iteration=$iteration"
    one_cycle "$iteration"
  done
  summarize
  say "PASS: process memory survived every VMM exit and lazy restore"
  echo "results=$CSV"
}

if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  case "${1:-}" in
    prepare) as_root prepare; prepare ;;
    run) as_root run; run_benchmark ;;
    all) as_root all; prepare; run_benchmark ;;
    clean-runtime) as_root clean-runtime; cleanup ;;
    *) echo "usage: $0 {prepare|run|all|clean-runtime}" >&2; exit 2 ;;
  esac
fi
