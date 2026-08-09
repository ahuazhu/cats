#!/bin/sh
# Shared process-lifetime lock and readiness boundary for worker deployments.

CATS_WORKER_DEPLOYMENT_LOCK_PATH=/run/lock/cats/worker-deployment.lock
CATS_WORKER_DEPLOYMENT_LOCK_FD=9

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
    loaded:inactive|loaded:failed|not-found:inactive) return 0 ;;
  esac
  echo "$service is not provably stopped ($load_state/$active_state)" >&2
  return 1
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

cats_wait_for_registered_node() {
  local service=$1 url=${2:-http://127.0.0.1:7301/healthz} deadline
  deadline=$(($(date +%s) + 60))
  while [ "$(date +%s)" -lt "$deadline" ]; do
    if cats_require_node_service_active "$service" \
        && curl --fail --silent --show-error --max-time 1 "$url" >/dev/null; then
      return 0
    fi
    sleep 1
  done
  echo "$service did not establish registration-backed local readiness" >&2
  return 1
}
