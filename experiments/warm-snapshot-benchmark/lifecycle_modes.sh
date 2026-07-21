#!/usr/bin/env bash
# Compare a true guest cold boot with same-host pause + NVMe page-out.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/benchmark.sh"

PAGEOUT_HELPER="${PAGEOUT_HELPER:-$SCRIPT_DIR/process_madvise_file.py}"
COLD_CSV="$RESULT_DIR/cold-benchmark.csv"
PAGEOUT_CSV="$RESULT_DIR/pageout-benchmark.csv"
PAGEOUT_CGROUP=""

drop_file_cache() {
  sync
  python3 - "$@" <<'PY'
import os
import sys

for name in sys.argv[1:]:
    with open(name, "rb") as stream:
        os.posix_fadvise(stream.fileno(), 0, 0, os.POSIX_FADV_DONTNEED)
PY
}

mapping_rss_kib() {
  local pid="$1" target="$2"
  python3 - "$pid" "$target" <<'PY'
import os
import sys

pid, target = sys.argv[1], os.path.realpath(sys.argv[2])
total = 0
matched = False
with open(f"/proc/{pid}/smaps", encoding="utf-8") as stream:
    for line in stream:
        if "-" in line.split(maxsplit=1)[0] and len(line.split()) >= 5:
            fields = line.rstrip().split(maxsplit=5)
            matched = len(fields) == 6 and os.path.realpath(fields[5]) == target
        elif matched and line.startswith("Rss:"):
            total += int(line.split()[1])
print(total)
PY
}

runtime_mapping_rss_kib() {
  local total=0 pid value
  for pid in "$CH_PID" "$VHOST_PID"; do
    [ -n "$pid" ] || continue
    value="$(mapping_rss_kib "$pid" "$MEMORY_BACKING_FILE")"
    total=$((total + value))
  done
  echo "$total"
}

advise_runtime_mapping() {
  local action="$1" pid value
  for pid in "$CH_PID" "$VHOST_PID"; do
    [ -n "$pid" ] || continue
    value="$(mapping_rss_kib "$pid" "$MEMORY_BACKING_FILE")"
    [ "$value" -gt 0 ] || continue
    python3 "$PAGEOUT_HELPER" "$pid" "$MEMORY_BACKING_FILE" "$action"
  done
}

percent_reclaimed() {
  awk -v before="$1" -v after="$2" 'BEGIN { if (before <= 0) print "0.000"; else printf "%.3f", 100 * (before-after) / before }'
}

setup_pageout_cgroup() {
  PAGEOUT_CGROUP="/sys/fs/cgroup/cats-pageout-benchmark-$$"
  mkdir "$PAGEOUT_CGROUP"
  export RUNTIME_CGROUP="$PAGEOUT_CGROUP"
}

cgroup_memory_bytes() {
  [ -n "$PAGEOUT_CGROUP" ] && [ -r "$PAGEOUT_CGROUP/memory.current" ] || { echo 0; return; }
  cat "$PAGEOUT_CGROUP/memory.current"
}

reclaim_runtime_cgroup() {
  local target_bytes=$(((MEMORY_MIB + 256) * 1024 * 1024))
  # memory.reclaim may return EAGAIN after partial progress. memory.current is
  # the authoritative measured result, so retain the progress and continue.
  printf '%s\n' "$target_bytes" > "$PAGEOUT_CGROUP/memory.reclaim" 2>/dev/null || true
}

cleanup_lifecycle() {
  set +e
  cleanup
  if [ -n "$PAGEOUT_CGROUP" ] && [ -d "$PAGEOUT_CGROUP" ]; then
    rmdir "$PAGEOUT_CGROUP" 2>/dev/null || true
  fi
}

summarize_csv() {
  local csv="$1" mode="$2"
  python3 - "$csv" "$mode" <<'PY'
import csv
import statistics
import sys

rows = list(csv.DictReader(open(sys.argv[1], newline="")))
mode = sys.argv[2]
print("\n==> Summary")
if mode == "cold":
    keys = ("shutdown_ms", "network_backend_ms", "vmm_to_api_ms", "cold_to_health_ms")
else:
    keys = ("pause_ms", "pageout_ms", "resume_api_ms", "wake_to_health_ms", "touch_wall_ms")
for key in keys:
    values = sorted(float(row[key]) for row in rows)
    p95 = values[max(0, int(len(values) * 0.95 + 0.999999) - 1)]
    print(f"{key:24s} p50={statistics.median(values):9.3f} ms  p95={p95:9.3f} ms")
if mode == "cold":
    print(f"boot_id_changed          {sum(r['boot_id_changed']=='true' for r in rows)}/{len(rows)}")
else:
    print(f"suspended_rss_kib        p50={statistics.median(int(r['suspended_rss_kib']) for r in rows):.0f}")
    print(f"reclaimed_pct            p50={statistics.median(float(r['reclaimed_pct']) for r in rows):.3f}%")
    print(f"boot_id_preserved        {sum(r['boot_id_preserved']=='true' for r in rows)}/{len(rows)}")
PY
}

cold_cycle() {
  local iteration="$1" before_json before_boot after_json after_boot
  local shutdown_start shutdown_end wake_start backend_end vmm_start vmm_end health_end
  local touch_start touch_end after_rss changed profile_json
  local process_entry_ms workset_init_ms guest_uptime_ms

  before_json="$(guest_json /sync 30)"
  before_boot="$(printf '%s' "$before_json" | json_field boot_id)"

  shutdown_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" shutdown-vmm >/dev/null 2>&1 || true
  stop_pid "$CH_PID"
  CH_PID=""
  stop_pid "$VHOST_PID"
  VHOST_PID=""
  rm -f "$API_SOCKET" "$VHOST_SOCKET"
  ip link del "$TAP" 2>/dev/null || true
  ip link del "$BRIDGE" 2>/dev/null || true
  shutdown_end="$(now_ns)"

  drop_file_cache "$ROOT_DISK" "$SEED_DISK"
  wake_start="$(now_ns)"
  ensure_network
  start_backend
  backend_end="$(now_ns)"
  vmm_start="$(now_ns)"
  start_initial_vmm
  vmm_end="$(now_ns)"
  after_json="$(wait_guest "$BOOT_TIMEOUT_S")" || die "guest did not cold boot in ${BOOT_TIMEOUT_S}s"
  health_end="$(now_ns)"
  after_boot="$(printf '%s' "$after_json" | json_field boot_id)"
  process_entry_ms="$(printf '%s' "$after_json" | json_field process_entry_boottime_ms)"
  workset_init_ms="$(printf '%s' "$after_json" | json_field workset_init_ms)"
  guest_uptime_ms="$(printf '%s' "$after_json" | json_field guest_uptime_ms)"
  [ "$before_boot" != "$after_boot" ] && changed=true || changed=false

  touch_start="$(now_ns)"
  guest_json /touch 120 >/dev/null
  touch_end="$(now_ns)"
  after_rss="$(runtime_rss_kib)"

  # Capture systemd's own kernel/userspace split without putting this slower
  # diagnostic request on the measured cold-to-health path.
  sleep 1
  profile_json="$(guest_json /profile 30)"
  printf '%s\n' "$profile_json" > "$RESULT_DIR/cold-profile-$iteration.json"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$iteration" "$MEMORY_MIB" "$WORKSET_MIB" \
    "$(elapsed_ms "$shutdown_start" "$shutdown_end")" 0 "$wake_start" \
    "$(elapsed_ms "$wake_start" "$backend_end")" \
    "$(elapsed_ms "$vmm_start" "$vmm_end")" \
    "$(elapsed_ms "$wake_start" "$health_end")" \
    "$process_entry_ms" "$workset_init_ms" "$guest_uptime_ms" \
    "$(elapsed_ms "$touch_start" "$touch_end")" \
    "$after_rss" "$changed" "$after_boot" | tee -a "$COLD_CSV"
  [ "$changed" = true ] || die "cold boot unexpectedly preserved the process boot ID"
}

run_cold() {
  require_linux_kvm
  [ -x "$CH_BIN" ] && [ -x "$VHOST_BLK" ] && [ -f "$BASE_DISK" ] || die "run benchmark.sh prepare first"
  MEMORY_BACKING_FILE=""
  prepare_guest
  rm -f "$ROOT_DISK"
  cp --reflink=auto --sparse=always "$BASE_DISK" "$ROOT_DISK"
  trap cleanup EXIT INT TERM
  stop_runtime
  mkdir -p "$RUN_DIR" "$RESULT_DIR"
  echo "iteration,memory_mib,workset_mib,shutdown_ms,cold_runtime_rss_kib,wake_started_ns,network_backend_ms,vmm_to_api_ms,cold_to_health_ms,process_entry_boottime_ms,workset_init_ms,guest_uptime_at_health_ms,touch_wall_ms,after_rss_kib,boot_id_changed,after_boot_id" > "$COLD_CSV"

  say "Prime the persistent root disk and cloud-init before measured cold boots"
  ensure_network
  start_backend
  start_initial_vmm
  wait_guest "$BOOT_TIMEOUT_S" >/dev/null || die "initial guest boot failed"
  guest_json /touch 120 >/dev/null

  say "Run $ITERATIONS cold guest boot cycles"
  for iteration in $(seq 1 "$ITERATIONS"); do
    echo "iteration=$iteration"
    cold_cycle "$iteration"
  done
  summarize_csv "$COLD_CSV" cold
  say "PASS: every cycle started a new guest kernel/userspace and process boot ID"
  echo "results=$COLD_CSV"
}

pageout_cycle() {
  local iteration="$1" before_json before_boot after_json after_boot
  local pause_start pause_end pageout_start pageout_end wake_start resume_end health_end
  local touch_start touch_end touch_json touch_guest before_rss before_map suspended_rss suspended_map
  local after_rss after_map preserved advice before_cgroup suspended_cgroup after_cgroup

  before_json="$(guest_json /sync 30)"
  before_boot="$(printf '%s' "$before_json" | json_field boot_id)"
  pause_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" pause >/dev/null
  pause_end="$(now_ns)"

  # Normalize every iteration to a resident memory-zone before measuring reclaim.
  advise_runtime_mapping populate >/dev/null
  before_rss="$(runtime_rss_kib)"
  before_map="$(runtime_mapping_rss_kib)"
  before_cgroup="$(cgroup_memory_bytes)"
  pageout_start="$(now_ns)"
  advice="$(advise_runtime_mapping pageout)"
  reclaim_runtime_cgroup
  pageout_end="$(now_ns)"
  suspended_rss="$(runtime_rss_kib)"
  suspended_map="$(runtime_mapping_rss_kib)"
  suspended_cgroup="$(cgroup_memory_bytes)"
  echo "pageout=$advice before_mapping_rss_kib=$before_map suspended_mapping_rss_kib=$suspended_map before_cgroup_bytes=$before_cgroup suspended_cgroup_bytes=$suspended_cgroup"

  wake_start="$(now_ns)"
  "$CH_REMOTE" --api-socket "$API_SOCKET" resume >/dev/null
  resume_end="$(now_ns)"
  after_json="$(wait_guest "$WAKE_TIMEOUT_S")" || die "guest did not become healthy after page-out resume"
  health_end="$(now_ns)"
  after_boot="$(printf '%s' "$after_json" | json_field boot_id)"
  [ "$before_boot" = "$after_boot" ] && preserved=true || preserved=false

  touch_start="$(now_ns)"
  touch_json="$(guest_json /touch 120)"
  touch_end="$(now_ns)"
  touch_guest="$(printf '%s' "$touch_json" | json_field touch_ms)"
  after_rss="$(runtime_rss_kib)"
  after_map="$(runtime_mapping_rss_kib)"
  after_cgroup="$(cgroup_memory_bytes)"

  printf '%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s\n' \
    "$iteration" "$MEMORY_MIB" "$WORKSET_MIB" "$before_rss" "$before_map" \
    "$before_cgroup" \
    "$(elapsed_ms "$pause_start" "$pause_end")" \
    "$(elapsed_ms "$pageout_start" "$pageout_end")" \
    "$suspended_rss" "$suspended_map" "$suspended_cgroup" \
    "$(percent_reclaimed "$before_cgroup" "$suspended_cgroup")" \
    "$wake_start" "$(elapsed_ms "$wake_start" "$resume_end")" \
    "$(elapsed_ms "$wake_start" "$health_end")" \
    "$(elapsed_ms "$touch_start" "$touch_end")" "$touch_guest" \
    "$after_rss" "$after_map" "$after_cgroup" "$preserved" | tee -a "$PAGEOUT_CSV"
  [ "$preserved" = true ] || die "page-out resume changed the process boot ID"
}

run_pageout() {
  require_linux_kvm
  [ -x "$CH_BIN" ] && [ -x "$VHOST_BLK" ] && [ -f "$BASE_DISK" ] || die "run benchmark.sh prepare first"
  [ -x "$PAGEOUT_HELPER" ] || die "missing helper: $PAGEOUT_HELPER"
  MEMORY_BACKING_FILE="${MEMORY_BACKING_FILE:-$WORK_DIR/pageout/guest-ram.bin}"
  prepare_guest
  rm -f "$ROOT_DISK" "$MEMORY_BACKING_FILE"
  mkdir -p "$(dirname "$MEMORY_BACKING_FILE")"
  truncate -s "${MEMORY_MIB}M" "$MEMORY_BACKING_FILE"
  cp --reflink=auto --sparse=always "$BASE_DISK" "$ROOT_DISK"
  trap cleanup_lifecycle EXIT INT TERM
  stop_runtime
  mkdir -p "$RUN_DIR" "$RESULT_DIR"
  echo "iteration,memory_mib,workset_mib,before_rss_kib,before_mapping_rss_kib,before_cgroup_bytes,pause_ms,pageout_ms,suspended_rss_kib,suspended_mapping_rss_kib,suspended_cgroup_bytes,reclaimed_pct,wake_started_ns,resume_api_ms,wake_to_health_ms,touch_wall_ms,touch_guest_ms,after_rss_kib,after_mapping_rss_kib,after_cgroup_bytes,boot_id_preserved" > "$PAGEOUT_CSV"

  say "Boot with ${MEMORY_MIB}MiB file-backed Guest RAM on local NVMe"
  setup_pageout_cgroup
  ensure_network
  start_backend
  start_initial_vmm
  wait_guest "$BOOT_TIMEOUT_S" >/dev/null || die "initial guest boot failed"
  guest_json /touch 120 >/dev/null

  say "Run $ITERATIONS pause + MADV_PAGEOUT + resume cycles"
  for iteration in $(seq 1 "$ITERATIONS"); do
    echo "iteration=$iteration"
    pageout_cycle "$iteration"
  done
  summarize_csv "$PAGEOUT_CSV" pageout
  say "PASS: the same process state survived every pause and NVMe page-out"
  echo "results=$PAGEOUT_CSV"
}

case "${1:-}" in
  cold) as_root cold; run_cold ;;
  pageout) as_root pageout; run_pageout ;;
  *) echo "usage: $0 {cold|pageout}" >&2; exit 2 ;;
esac
