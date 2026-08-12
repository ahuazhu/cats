#!/bin/sh
# Shared process-lifetime lock and readiness boundary for worker deployments.

CATS_WORKER_DEPLOYMENT_LOCK_PATH=/run/lock/cats/worker-deployment.lock
CATS_WORKER_DEPLOYMENT_LOCK_FD=9
CATS_WORKER_DEPLOYMENT_HELPER=/opt/cats/bin/worker-deployment-transaction
CATS_WORKER_DEPLOYMENT_WATCHDOG=cats-worker-deployment-watchdog.service

# Production has no environment-controlled fault injection. Linux contract
# tests replace this no-op only in a private copy.
cats_worker_deployment_crash_probe() { :; }

cats_require_worker_deployment_lock() {
  local descriptor lock_identity fd_identity
  descriptor=${CATS_WORKER_DEPLOYMENT_LOCK_FD:-}
  case "$descriptor" in
    ''|*[!0-9]*)
      echo "worker mutation requires the Host deployment lock descriptor" >&2
      return 1
      ;;
  esac
  [ -e "/proc/self/fd/$descriptor" ] || return 1
  lock_identity=$(stat -Lc '%d:%i' "$CATS_WORKER_DEPLOYMENT_LOCK_PATH") || return 1
  fd_identity=$(stat -Lc '%d:%i' "/proc/self/fd/$descriptor") || return 1
  [ "$lock_identity" = "$fd_identity" ] || return 1
  [ "$(stat -Lc '%u:%g:%a:%h' "$CATS_WORKER_DEPLOYMENT_LOCK_PATH")" = \
      '0:0:600:1' ] || return 1
  flock -n "$descriptor"
}

cats_acquire_worker_deployment_lock() {
  # `/run/lock` is shared with the whole Host. Only manage Cats' dedicated
  # child; `install -d -m` must never chmod the shared parent.
  install -d -o root -g root -m 0700 "$(dirname "$CATS_WORKER_DEPLOYMENT_LOCK_PATH")"
  if [ ! -e "$CATS_WORKER_DEPLOYMENT_LOCK_PATH" ] && [ ! -L "$CATS_WORKER_DEPLOYMENT_LOCK_PATH" ]; then
    (umask 077; set -o noclobber; : > "$CATS_WORKER_DEPLOYMENT_LOCK_PATH") 2>/dev/null || true
  fi
  [ -f "$CATS_WORKER_DEPLOYMENT_LOCK_PATH" ] && [ ! -L "$CATS_WORKER_DEPLOYMENT_LOCK_PATH" ] || {
    echo "worker deployment lock is not a regular file" >&2
    return 1
  }
  [ "$(stat -Lc '%u:%g:%a:%h' "$CATS_WORKER_DEPLOYMENT_LOCK_PATH")" = \
      '0:0:600:1' ] || {
    echo "worker deployment lock violates root:root/0600/single-link contract" >&2
    return 1
  }
  [ ! -e "/proc/$$/fd/$CATS_WORKER_DEPLOYMENT_LOCK_FD" ] || {
    echo "reserved worker deployment descriptor is already occupied" >&2
    return 1
  }
  exec 9>>"$CATS_WORKER_DEPLOYMENT_LOCK_PATH"
  export CATS_WORKER_DEPLOYMENT_LOCK_FD
  flock "$CATS_WORKER_DEPLOYMENT_LOCK_FD"
  cats_require_worker_deployment_lock
}

cats_systemd_property() {
  local service property value
  service=$1
  property=$2
  value=$(systemctl show "$service" "--property=$property" --value) || {
    echo "cannot query $service $property" >&2
    return 1
  }
  [ -n "$value" ] || {
    echo "$service returned an empty $property" >&2
    return 1
  }
  printf '%s\n' "$value"
}

cats_require_node_service_stopped() {
  local service load_state active_state
  service=$1
  load_state=$(cats_systemd_property "$service" LoadState) || return 1
  active_state=$(cats_systemd_property "$service" ActiveState) || return 1
  case "$load_state:$active_state" in
    loaded:inactive|loaded:failed|not-found:inactive|masked:inactive|masked:failed) return 0 ;;
  esac
  echo "$service is not provably stopped ($load_state/$active_state)" >&2
  return 1
}

cats_process_start_ticks() {
  local pid stat_line suffix
  pid=$1
  case "$pid" in ''|0|*[!0-9]*) return 1 ;; esac
  [ -r "/proc/$pid/stat" ] || return 1
  IFS= read -r stat_line < "/proc/$pid/stat" || return 1
  suffix=${stat_line##*) }
  set -- $suffix
  [ "$#" -ge 20 ] || return 1
  case "${20}" in ''|0|*[!0-9]*) return 1 ;; esac
  printf '%s\n' "${20}"
}

cats_process_identity_matches() {
  local actual
  actual=$(cats_process_start_ticks "$1") || return 1
  [ "$actual" = "$2" ]
}

cats_candidate_main_identity() {
  local service main_pid main_start
  service=$1
  main_pid=$(cats_systemd_property "$service" MainPID) || return 1
  case "$main_pid" in ''|0|*[!0-9]*) return 1 ;; esac
  main_start=$(cats_process_start_ticks "$main_pid") || return 1
  printf '%s:%s\n' "$main_pid" "$main_start"
}

cats_require_node_service_active() {
  local service load_state active_state
  service=$1
  load_state=$(cats_systemd_property "$service" LoadState) || return 1
  active_state=$(cats_systemd_property "$service" ActiveState) || return 1
  [ "$load_state:$active_state" = loaded:active ] || {
    echo "$service is not active ($load_state/$active_state)" >&2
    return 1
  }
}

cats_stop_node_service() {
  local service load_state
  service=$1
  if ! systemctl stop "$service"; then
    load_state=$(cats_systemd_property "$service" LoadState) || return 1
    [ "$load_state" = not-found ] || {
      echo "failed to stop loaded service $service" >&2
      return 1
    }
  fi
  cats_require_node_service_stopped "$service"
}

cats_retire_legacy_gateway() {
  local unit_file wants_link binary_file service load_state
  unit_file=$1
  wants_link=$2
  binary_file=$3
  service=cats-gatewayd.service

  case "$unit_file:$wants_link:$binary_file" in
    */cats-gatewayd.service:*/multi-user.target.wants/cats-gatewayd.service:*/bin/cats-gatewayd) ;;
    *)
      echo "refusing to remove unexpected legacy Gateway paths" >&2
      return 1
      ;;
  esac

  if ! systemctl disable "$service"; then
    load_state=$(cats_systemd_property "$service" LoadState) || return 1
    [ "$load_state" = not-found ] || {
      echo "failed to disable loaded service $service" >&2
      return 1
    }
  fi
  cats_stop_node_service "$service" || return 1
  # Keep the proof adjacent to deletion: a successful `systemctl stop` alone
  # does not guarantee that the unit reached an inactive state.
  cats_require_node_service_stopped "$service" || return 1
  rm -f -- "$unit_file" "$wants_link" "$binary_file"
}

cats_worker_metering_root() {
  local service cgroup_mount service_cgroup service_slice
  service=$1
  cgroup_mount=$(findmnt --noheadings --first-only --types cgroup2 --output TARGET) || return 1
  [ -n "$cgroup_mount" ] || return 1
  service_cgroup=$(systemctl show "$service" --property=ControlGroup --value) || return 1
  if [ -z "$service_cgroup" ]; then
    service_slice=$(systemctl show "$service" --property=Slice --value) || return 1
    service_slice=${service_slice:-system.slice}
    service_cgroup="/$service_slice/$service.service"
  fi
  case "$service_cgroup" in /*) ;; *) return 1 ;; esac
  printf '%s%s/metering\n' "$cgroup_mount" "$service_cgroup"
}

cats_gate_node_service() {
  local service unit_file_state
  service=$1
  systemctl mask --runtime "$service" || return 1
  unit_file_state=$(cats_systemd_property "$service" UnitFileState) || return 1
  case "$unit_file_state" in
    masked|masked-runtime) ;;
    *)
      echo "$service did not enter a masked state ($unit_file_state)" >&2
      return 1
      ;;
  esac
  cats_stop_node_service "$service"
}

cats_ungate_node_service() {
  local service unit_file_state
  service=$1
  systemctl unmask --runtime "$service" || return 1
  unit_file_state=$(cats_systemd_property "$service" UnitFileState) || return 1
  case "$unit_file_state" in
    masked|masked-runtime)
      echo "$service remained masked after removing its runtime gate" >&2
      return 1
      ;;
  esac
}

cats_begin_candidate_lifetime() {
  local service installer owner_pid owner_start token
  service=$1
  installer=$2
  cats_require_worker_deployment_lock || return 1
  cats_require_node_service_stopped "$service" || return 1
  [ -x "$CATS_WORKER_DEPLOYMENT_HELPER" ] || return 1
  [ -x "$installer" ] || return 1
  owner_pid=$$
  owner_start=$(cats_process_start_ticks "$owner_pid") || return 1
  token=$(openssl rand -hex 32) || return 1
  case "$token" in
    *[!0-9a-f]*|'') return 1 ;;
  esac
  [ "${#token}" -eq 64 ] || return 1

  # A previous collected transient unit may remain in systemd's failed-unit
  # cache. Under the Host lock it cannot represent a live deployment owner.
  systemctl stop "$CATS_WORKER_DEPLOYMENT_WATCHDOG" >/dev/null 2>&1 || true
  systemctl reset-failed "$CATS_WORKER_DEPLOYMENT_WATCHDOG" >/dev/null 2>&1 || true
  systemd-run --quiet --collect \
    --unit="$CATS_WORKER_DEPLOYMENT_WATCHDOG" \
    --property=Type=exec --property=Restart=on-failure -- \
    "$CATS_WORKER_DEPLOYMENT_HELPER" __watchdog \
    "$service" "$installer" "$owner_pid" "$owner_start" "$token" || return 1
  systemctl is-active --quiet "$CATS_WORKER_DEPLOYMENT_WATCHDOG" || return 1
  "$installer" authorize-start "$token" "$owner_pid" "$owner_start" || return 1

  CATS_WORKER_CANDIDATE_TOKEN=$token
  CATS_WORKER_CANDIDATE_OWNER_PID=$owner_pid
  CATS_WORKER_CANDIDATE_OWNER_START=$owner_start
  export CATS_WORKER_CANDIDATE_TOKEN CATS_WORKER_CANDIDATE_OWNER_PID \
    CATS_WORKER_CANDIDATE_OWNER_START
}

cats_bind_candidate_main() {
  local service installer identity
  service=$1
  installer=$2
  [ -n "${CATS_WORKER_CANDIDATE_TOKEN:-}" ] || return 1
  identity=$(cats_candidate_main_identity "$service") || return 1
  CATS_WORKER_CANDIDATE_MAIN_PID=${identity%%:*}
  CATS_WORKER_CANDIDATE_MAIN_START=${identity#*:}
  "$installer" bind-start "$CATS_WORKER_CANDIDATE_TOKEN" \
    "$CATS_WORKER_CANDIDATE_MAIN_PID" "$CATS_WORKER_CANDIDATE_MAIN_START" || return 1
  export CATS_WORKER_CANDIDATE_MAIN_PID CATS_WORKER_CANDIDATE_MAIN_START
}

cats_wait_for_registered_node() {
  local service=$1 url=${2:-http://127.0.0.1:7301/healthz} deadline identity
  [ -n "${CATS_WORKER_CANDIDATE_MAIN_PID:-}" \
      ] && [ -n "${CATS_WORKER_CANDIDATE_MAIN_START:-}" ] || return 1
  deadline=$(($(date +%s) + 60))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    identity=$(cats_candidate_main_identity "$service" 2>/dev/null || true)
    if [ "$identity" = "$CATS_WORKER_CANDIDATE_MAIN_PID:$CATS_WORKER_CANDIDATE_MAIN_START" ] \
        && cats_require_node_service_active "$service" \
        && curl --fail --silent --show-error --max-time 1 "$url" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "$service did not establish registration-backed local readiness" >&2
  return 1
}

cats_commit_candidate() {
  local installer=$1
  [ -n "${CATS_WORKER_CANDIDATE_TOKEN:-}" \
      ] && [ -n "${CATS_WORKER_CANDIDATE_MAIN_PID:-}" \
      ] && [ -n "${CATS_WORKER_CANDIDATE_MAIN_START:-}" ] || return 1
  "$installer" commit "$CATS_WORKER_CANDIDATE_TOKEN" \
    "$CATS_WORKER_CANDIDATE_MAIN_PID" "$CATS_WORKER_CANDIDATE_MAIN_START"
}

cats_worker_deployment_watchdog() {
  local service installer owner_pid owner_start token check_status
  service=$1
  installer=$2
  owner_pid=$3
  owner_start=$4
  token=$5

  while cats_process_identity_matches "$owner_pid" "$owner_start"; do
    CATS_NODE_SERVICE_NAME=$service \
      "$installer" watchdog-check "$token" "$owner_pid" "$owner_start" \
      >/dev/null 2>&1
    check_status=$?
    [ "$check_status" -ne 10 ] || return 0
    sleep 0.1
  done

  # The systemd manager, rather than the outer shell, created this process, so
  # it does not inherit descriptor 9. After parent death, acquire the exact
  # Host lock before changing either the worker or the activation journal.
  unset CATS_WORKER_DEPLOYMENT_LOCK_FD
  CATS_WORKER_DEPLOYMENT_LOCK_FD=9
  cats_acquire_worker_deployment_lock || return 1
  CATS_NODE_SERVICE_NAME=$service \
    "$installer" watchdog-check "$token" "$owner_pid" "$owner_start" \
    >/dev/null 2>&1
  check_status=$?
  [ "$check_status" -ne 10 ] || return 0
  systemctl mask --runtime "$service" || return 1
  cats_stop_node_service "$service" || return 1
  CATS_NODE_SERVICE_NAME=$service "$installer" rollback
}

if [ "${1:-}" = __watchdog ]; then
  [ "$#" -eq 6 ] || exit 2
  shift
  cats_worker_deployment_watchdog "$@"
  exit $?
fi
