#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

: "${CATS_SOURCE_PROVENANCE_ROOT:?missing source provenance root}"
: "${CATS_SOURCE_PROVENANCE_HEAD:?missing source provenance head}"
: "${CATS_SOURCE_PROVENANCE_DIRTY:?missing source provenance dirty bit}"
: "${CATS_SOURCE_PROVENANCE_FINGERPRINT:?missing source provenance fingerprint}"

LINUX_PLATFORM="${CATS_LINUX_PLATFORM:-linux/arm64}"
LINUX_TARGET_VOLUME="${CATS_LINUX_TARGET_VOLUME:-cats-target-linux}"
LINUX_JOBS="${CATS_LINUX_JOBS:-2}"
LINUX_CLEANUP_BUDGET_SECONDS="${CATS_LINUX_CLEANUP_BUDGET_SECONDS:-40}"
if [[ ! "$LINUX_CLEANUP_BUDGET_SECONDS" =~ ^[0-9]+$ ]] \
  || ((LINUX_CLEANUP_BUDGET_SECONDS < 5 || LINUX_CLEANUP_BUDGET_SECONDS > 120)); then
  echo "CATS_LINUX_CLEANUP_BUDGET_SECONDS must be between 5 and 120" >&2
  exit 1
fi
LINUX_RUN_TOKEN="$(LC_ALL=C od -An -N16 -tx1 /dev/urandom | tr -d '[:space:]')"
[[ "$LINUX_RUN_TOKEN" =~ ^[0-9a-f]{32}$ ]] || {
  echo "cannot generate the Linux gate resource capability" >&2
  exit 1
}

LINUX_OWNER_KEY="io.cats.quality.linux.owner"
LINUX_OWNER_LABEL="$LINUX_OWNER_KEY=$LINUX_RUN_TOKEN"
LINUX_NETWORK="cats-linux-net-$LINUX_RUN_TOKEN"
LINUX_PG="cats-linux-pg-$LINUX_RUN_TOKEN"
LINUX_WORKSPACE_GATE="cats-linux-workspace-gate-$LINUX_RUN_TOKEN"
LINUX_SYSTEMD_GATE="cats-linux-systemd-gate-$LINUX_RUN_TOKEN"
LINUX_NETWORK_INTENDED=false
LINUX_PG_INTENDED=false
LINUX_WORKSPACE_INTENDED=false
LINUX_SYSTEMD_INTENDED=false
LINUX_OWNER_CONFLICT=false
LINUX_ACTIVE_DOCKER_PID=""
LINUX_ACTIVE_DOCKER_KIND=""
LINUX_ACTIVE_DOCKER_STATUS=0
LINUX_CREATE_SETTLEMENT_UNKNOWN=false
LINUX_CREATE_PENDING=false
LINUX_CREATE_RESOURCE_KIND=""
LINUX_CREATE_EXPECTED_NAME=""
LINUX_CREATE_MODE=""
LINUX_CREATE_ARGUMENTS=()
LINUX_DEFERRED_SIGNAL_STATUS=0
LINUX_CLEANUP_ACTIVE=false
LINUX_CAPTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cats-linux-gate.XXXXXXXX")"
LINUX_DOCKER_STDOUT="$LINUX_CAPTURE_DIR/docker.stdout"
LINUX_DOCKER_STDERR="$LINUX_CAPTURE_DIR/docker.stderr"
LINUX_SYSTEMD_IIDFILE="$LINUX_CAPTURE_DIR/systemd-image.iid"
LINUX_SYSTEMD_IMAGE_ID=""
LINUX_SOURCE_FINGERPRINT_KEY="io.cats.quality.source-fingerprint"
LINUX_PROBE_PRESENT=false
LINUX_PROBE_ID=""
LINUX_CLEANUP_DEADLINE=0

# The bind-mounted worktree may carry a .git file whose host-only gitdir is not
# mounted into a nested Linux quality container. Hash only the inherited,
# validated provenance root from a fresh non-repository directory so target
# isolation never depends on reopening repository metadata.
LINUX_TARGET_NAMESPACE="$(
  printf '%s\0' "$CATS_SOURCE_PROVENANCE_ROOT" \
    | env -u GIT_DIR -u GIT_WORK_TREE -u GIT_COMMON_DIR \
      GIT_OPTIONAL_LOCKS=0 \
      GIT_CEILING_DIRECTORIES="$(dirname "$LINUX_CAPTURE_DIR")" \
      git -C "$LINUX_CAPTURE_DIR" hash-object --stdin --no-filters
)"
[[ "$LINUX_TARGET_NAMESPACE" =~ ^[0-9a-f]{40}$ \
  || "$LINUX_TARGET_NAMESPACE" =~ ^[0-9a-f]{64}$ ]] || {
  echo "cannot derive the Linux target namespace from source provenance" >&2
  exit 1
}
LINUX_TARGET_DIRECTORY="/target/worktrees/$LINUX_TARGET_NAMESPACE"

terminate_active_docker() {
  local attempt
  local pid="$LINUX_ACTIVE_DOCKER_PID"
  [[ -n "$pid" ]] || return 0
  kill -TERM "$pid" 2>/dev/null || true
  for ((attempt = 0; attempt < 10; attempt++)); do
    kill -0 "$pid" 2>/dev/null || break
    if ((LINUX_CLEANUP_DEADLINE > 0 && SECONDS >= LINUX_CLEANUP_DEADLINE)); then
      break
    fi
    sleep 0.1
  done
  if kill -0 "$pid" 2>/dev/null; then
    kill -KILL "$pid" 2>/dev/null || true
  fi
  wait "$pid" 2>/dev/null || true
  LINUX_ACTIVE_DOCKER_PID=""
  LINUX_ACTIVE_DOCKER_KIND=""
}

reap_active_docker() {
  local pid="$LINUX_ACTIVE_DOCKER_PID"
  [[ -n "$pid" ]] || return 0
  if wait "$pid"; then
    LINUX_ACTIVE_DOCKER_STATUS=0
  else
    LINUX_ACTIVE_DOCKER_STATUS=$?
  fi
  LINUX_ACTIVE_DOCKER_PID=""
  LINUX_ACTIVE_DOCKER_KIND=""
}

defer_linux_gate_signal() {
  local status="$1"
  if ((LINUX_DEFERRED_SIGNAL_STATUS == 0)); then
    LINUX_DEFERRED_SIGNAL_STATUS="$status"
  fi
}

restore_linux_gate_signal_traps() {
  if [[ "$LINUX_CLEANUP_ACTIVE" == true ]]; then
    trap '' INT TERM
  else
    trap 'linux_gate_signal 130' INT
    trap 'linux_gate_signal 143' TERM
  fi
}

# Fork and publication of LINUX_ACTIVE_DOCKER_PID are one signal-safe handoff.
# A signal in that tiny interval is deferred until the parent can account for
# the exact Docker client it just started.
start_docker_cli() {
  local mode="$1"
  local kind="$2"
  local defer_signals=true
  local restore_job_control=false
  shift 2
  : >"$LINUX_DOCKER_STDOUT"
  : >"$LINUX_DOCKER_STDERR"
  LINUX_ACTIVE_DOCKER_KIND="$kind"
  LINUX_ACTIVE_DOCKER_STATUS=0
  LINUX_DEFERRED_SIGNAL_STATUS=0
  if [[ "$LINUX_CLEANUP_ACTIVE" == true ]]; then
    defer_signals=false
  else
    trap 'defer_linux_gate_signal 130' INT
    trap 'defer_linux_gate_signal 143' TERM
  fi
  if [[ "$kind" == create && "$-" != *m* ]]; then
    # Put each create client in its own process group before restoring the
    # parent's traps. This protects it when a supervisor signals the entire
    # gate process group, including the fork-before-child-trap window.
    set -m
    restore_job_control=true
  fi
  if [[ "$kind" == create && "$mode" == capture ]]; then
    # A terminal or CI supervisor may signal this shell's entire process
    # group. Keep the create client alive until it receives the daemon result;
    # the bounded settlement path can still terminate it with SIGKILL.
    (
      trap '' INT TERM
      exec docker "$@"
    ) >"$LINUX_DOCKER_STDOUT" 2>"$LINUX_DOCKER_STDERR" &
  elif [[ "$kind" == create ]]; then
    (
      trap '' INT TERM
      exec docker "$@"
    ) &
  elif [[ "$mode" == capture ]]; then
    docker "$@" >"$LINUX_DOCKER_STDOUT" 2>"$LINUX_DOCKER_STDERR" &
  else
    docker "$@" &
  fi
  LINUX_ACTIVE_DOCKER_PID=$!
  if [[ "$restore_job_control" == true ]]; then
    set +m
  fi
  restore_linux_gate_signal_traps
  if [[ "$defer_signals" == true ]] && ((LINUX_DEFERRED_SIGNAL_STATUS != 0)); then
    linux_gate_signal "$LINUX_DEFERRED_SIGNAL_STATUS"
  fi
}

clear_pending_create() {
  LINUX_CREATE_PENDING=false
  LINUX_CREATE_RESOURCE_KIND=""
  LINUX_CREATE_EXPECTED_NAME=""
  LINUX_CREATE_MODE=""
  LINUX_CREATE_ARGUMENTS=()
}

wait_active_create_result() {
  local pid="$LINUX_ACTIVE_DOCKER_PID"
  local status
  [[ -n "$pid" && "$LINUX_ACTIVE_DOCKER_KIND" == create ]] || return 1
  while kill -0 "$pid" 2>/dev/null; do
    if ((LINUX_CLEANUP_DEADLINE > 0 && SECONDS >= LINUX_CLEANUP_DEADLINE)); then
      echo "Docker create request did not settle before the Linux cleanup deadline" >&2
      LINUX_CREATE_SETTLEMENT_UNKNOWN=true
      terminate_active_docker
      return 1
    fi
    sleep 0.1
  done
  reap_active_docker
  status="$LINUX_ACTIVE_DOCKER_STATUS"
  return "$status"
}

abandon_foreign_intent() {
  local resource_kind="$1"
  local expected_name="$2"
  if [[ "$resource_kind" == network && "$expected_name" == "$LINUX_NETWORK" ]]; then
    LINUX_NETWORK_INTENDED=false
  elif [[ "$resource_kind" == container && "$expected_name" == "$LINUX_PG" ]]; then
    LINUX_PG_INTENDED=false
  elif [[ "$resource_kind" == container && "$expected_name" == "$LINUX_WORKSPACE_GATE" ]]; then
    LINUX_WORKSPACE_INTENDED=false
  elif [[ "$resource_kind" == container && "$expected_name" == "$LINUX_SYSTEMD_GATE" ]]; then
    LINUX_SYSTEMD_INTENDED=false
  fi
}

reconcile_pending_create() {
  while [[ "$LINUX_CREATE_PENDING" == true ]] \
    && ((SECONDS < LINUX_CLEANUP_DEADLINE)); do
    if [[ "$LINUX_CREATE_RESOURCE_KIND" == container ]]; then
      if probe_owned_container "$LINUX_CREATE_EXPECTED_NAME"; then
        if [[ "$LINUX_PROBE_PRESENT" == true ]]; then
          clear_pending_create
          return 0
        fi
      elif [[ "$LINUX_OWNER_CONFLICT" == true ]]; then
        clear_pending_create
        return 1
      fi
    elif [[ "$LINUX_CREATE_RESOURCE_KIND" == network ]]; then
      if probe_owned_network "$LINUX_CREATE_EXPECTED_NAME"; then
        if [[ "$LINUX_PROBE_PRESENT" == true ]]; then
          clear_pending_create
          return 0
        fi
      elif [[ "$LINUX_OWNER_CONFLICT" == true ]]; then
        clear_pending_create
        return 1
      fi
    else
      echo "Linux gate lost the pending Docker create resource identity" >&2
      LINUX_CREATE_SETTLEMENT_UNKNOWN=true
      return 1
    fi

    start_docker_cli "$LINUX_CREATE_MODE" create "${LINUX_CREATE_ARGUMENTS[@]}"
    wait_active_create_result || true
    # Inspect even after success, because the exact name/owner object is the
    # cleanup authority. A non-zero result can mean response loss, so retry the
    # same request until that object or an exact foreign collision is visible.
    sleep 0.1
  done

  echo "Docker create request did not settle before the Linux cleanup deadline" >&2
  LINUX_CREATE_SETTLEMENT_UNKNOWN=true
  if [[ "$LINUX_ACTIVE_DOCKER_KIND" == create ]]; then
    terminate_active_docker
  fi
  return 1
}

# A create request is causally settled only after a successful daemon response
# or an exact same-name ownership observation. Client exit alone is not a
# receipt: transport failure may race a later daemon-side create.
settle_active_create() {
  if [[ "$LINUX_ACTIVE_DOCKER_KIND" == create ]]; then
    wait_active_create_result || true
  fi
  [[ "$LINUX_CREATE_PENDING" == true ]] || return 0
  reconcile_pending_create
}

# Every Docker CLI call is asynchronous from this shell. `steps` is a
# wall-clock bound in tenths of a second. Only create calls are allowed to
# outlive a signal/ordinary operation timeout, because their daemon response
# is the receipt which closes the late-create authority.
docker_cli_operation() {
  local kind="$1"
  local mode="$2"
  local steps="$3"
  local attempt
  local status
  shift 3
  start_docker_cli "$mode" "$kind" "$@"
  for ((attempt = 0; attempt < steps; attempt++)); do
    kill -0 "$LINUX_ACTIVE_DOCKER_PID" 2>/dev/null || break
    sleep 0.1
  done
  if kill -0 "$LINUX_ACTIVE_DOCKER_PID" 2>/dev/null; then
    echo "Docker CLI exceeded its Linux gate deadline: docker $*" >&2
    if [[ "$kind" == create ]]; then
      if ((LINUX_CLEANUP_DEADLINE == 0)); then
        LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))
      fi
      settle_active_create || true
    else
      terminate_active_docker
    fi
    return 124
  fi
  reap_active_docker
  status="$LINUX_ACTIVE_DOCKER_STATUS"
  if [[ "$kind" == create ]]; then
    if ((LINUX_CLEANUP_DEADLINE == 0)); then
      LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))
    fi
    if reconcile_pending_create; then
      if [[ "$LINUX_CLEANUP_ACTIVE" == false ]]; then
        LINUX_CLEANUP_DEADLINE=0
      fi
      return 0
    fi
    if [[ "$status" -eq 0 ]]; then
      return 1
    fi
  fi
  return "$status"
}

docker_cli() {
  docker_cli_operation interruptible "$@"
}

report_docker_capture_failure() {
  if [[ -s "$LINUX_DOCKER_STDOUT" ]]; then
    echo "==> captured Docker stdout" >&2
    cat "$LINUX_DOCKER_STDOUT" >&2
  fi
  if [[ -s "$LINUX_DOCKER_STDERR" ]]; then
    echo "==> captured Docker stderr" >&2
    cat "$LINUX_DOCKER_STDERR" >&2
  fi
}

docker_create_cli() {
  local resource_kind="$1"
  local expected_name="$2"
  local mode="$3"
  local steps="$4"
  shift 4
  [[ "$LINUX_CREATE_PENDING" == false ]] || {
    echo "Linux gate attempted overlapping Docker create requests" >&2
    return 1
  }
  LINUX_CREATE_RESOURCE_KIND="$resource_kind"
  LINUX_CREATE_EXPECTED_NAME="$expected_name"
  LINUX_CREATE_MODE="$mode"
  LINUX_CREATE_ARGUMENTS=("$@")
  LINUX_CREATE_PENDING=true
  docker_cli_operation create "$mode" "$steps" "$@"
}

# Cleanup is one bounded settlement operation, not a sequence of independent
# per-command timeouts. Keep a five-second margin under the advertised
# 45-second wall bound for Bash 3.2's integer `SECONDS` granularity and host
# scheduling, and cap every Docker client to the remaining shared budget.
cleanup_docker_cli() {
  local mode="$1"
  local requested_steps="$2"
  local remaining_seconds
  local remaining_steps
  shift 2
  # Reserve one final second for killing and reaping a Docker client which
  # ignores TERM. That grace period is part of this one shared deadline, not
  # an additional timeout granted after it expires.
  remaining_seconds=$((LINUX_CLEANUP_DEADLINE - SECONDS - 1))
  if ((remaining_seconds <= 0)); then
    return 124
  fi
  remaining_steps=$((remaining_seconds * 10))
  if ((requested_steps > remaining_steps)); then
    requested_steps=$remaining_steps
  fi
  docker_cli "$mode" "$requested_steps" "$@"
}

probe_owned_container() {
  local expected_name="$1"
  local id
  local inspection
  local -a ids=()
  LINUX_PROBE_PRESENT=false
  LINUX_PROBE_ID=""
  cleanup_docker_cli capture 50 container ls --all --quiet --no-trunc \
    --filter "name=^/${expected_name}$" || return 1
  # macOS ships Bash 3.2, so keep this gate independent of Bash 4's
  # `mapfile`. The redirection (rather than a pipe) also keeps `ids` in this
  # shell, where the ownership decision is made.
  while IFS= read -r id; do
    if [[ -n "$id" ]]; then
      ids[${#ids[@]}]="$id"
    fi
  done <"$LINUX_DOCKER_STDOUT"
  if [[ "${#ids[@]}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${#ids[@]}" -ne 1 ]]; then
    echo "Linux gate container name is not unique: $expected_name" >&2
    LINUX_OWNER_CONFLICT=true
    return 1
  fi
  id="${ids[0]}"
  cleanup_docker_cli capture 50 container inspect \
    --format "{{.Id}}|{{.Name}}|{{index .Config.Labels \"$LINUX_OWNER_KEY\"}}" \
    "$id" || return 1
  IFS= read -r inspection <"$LINUX_DOCKER_STDOUT" || true
  if [[ "$inspection" != "$id|/$expected_name|$LINUX_RUN_TOKEN" ]]; then
    echo "refusing to remove foreign Linux gate container $expected_name ($inspection)" >&2
    LINUX_OWNER_CONFLICT=true
    abandon_foreign_intent container "$expected_name"
    return 1
  fi
  LINUX_PROBE_PRESENT=true
  LINUX_PROBE_ID="$id"
}

probe_owned_network() {
  local expected_name="$1"
  local id
  local inspection
  local -a ids=()
  LINUX_PROBE_PRESENT=false
  LINUX_PROBE_ID=""
  cleanup_docker_cli capture 50 network ls --quiet --no-trunc \
    --filter "name=^${expected_name}$" || return 1
  while IFS= read -r id; do
    if [[ -n "$id" ]]; then
      ids[${#ids[@]}]="$id"
    fi
  done <"$LINUX_DOCKER_STDOUT"
  if [[ "${#ids[@]}" -eq 0 ]]; then
    return 0
  fi
  if [[ "${#ids[@]}" -ne 1 ]]; then
    echo "Linux gate network name is not unique: $expected_name" >&2
    LINUX_OWNER_CONFLICT=true
    return 1
  fi
  id="${ids[0]}"
  cleanup_docker_cli capture 50 network inspect \
    --format "{{.Id}}|{{.Name}}|{{index .Labels \"$LINUX_OWNER_KEY\"}}" \
    "$id" || return 1
  IFS= read -r inspection <"$LINUX_DOCKER_STDOUT" || true
  if [[ "$inspection" != "$id|$expected_name|$LINUX_RUN_TOKEN" ]]; then
    echo "refusing to remove foreign Linux gate network $expected_name ($inspection)" >&2
    LINUX_OWNER_CONFLICT=true
    abandon_foreign_intent network "$expected_name"
    return 1
  fi
  LINUX_PROBE_PRESENT=true
  LINUX_PROBE_ID="$id"
}

remove_owned_container() {
  local intended="$1"
  local expected_name="$2"
  local graceful="$3"
  local id
  [[ "$intended" == true ]] || return 0
  probe_owned_container "$expected_name" || return 1
  [[ "$LINUX_PROBE_PRESENT" == true ]] || return 0
  id="$LINUX_PROBE_ID"
  if [[ "$graceful" == true ]]; then
    cleanup_docker_cli capture 250 stop --time 20 "$id" || true
  fi
  # `postgres:16` declares an anonymous data volume. Remove anonymous volumes
  # with their already owner-verified immutable container ID; Docker preserves
  # the explicitly named Cargo/target cache volumes mounted by the other two
  # containers.
  cleanup_docker_cli capture 50 rm --force --volumes "$id" || true
}

remove_owned_network() {
  local intended="$1"
  local expected_name="$2"
  local id
  [[ "$intended" == true ]] || return 0
  probe_owned_network "$expected_name" || return 1
  [[ "$LINUX_PROBE_PRESENT" == true ]] || return 0
  id="$LINUX_PROBE_ID"
  cleanup_docker_cli capture 50 network rm "$id" || true
}

all_intended_resources_absent() {
  local all_absent=true
  if [[ "$LINUX_SYSTEMD_INTENDED" == true ]]; then
    probe_owned_container "$LINUX_SYSTEMD_GATE" || all_absent=false
    [[ "$LINUX_PROBE_PRESENT" == false ]] || all_absent=false
  fi
  if [[ "$LINUX_WORKSPACE_INTENDED" == true ]]; then
    probe_owned_container "$LINUX_WORKSPACE_GATE" || all_absent=false
    [[ "$LINUX_PROBE_PRESENT" == false ]] || all_absent=false
  fi
  if [[ "$LINUX_PG_INTENDED" == true ]]; then
    probe_owned_container "$LINUX_PG" || all_absent=false
    [[ "$LINUX_PROBE_PRESENT" == false ]] || all_absent=false
  fi
  if [[ "$LINUX_NETWORK_INTENDED" == true ]]; then
    probe_owned_network "$LINUX_NETWORK" || all_absent=false
    [[ "$LINUX_PROBE_PRESENT" == false ]] || all_absent=false
  fi
  [[ "$all_absent" == true ]]
}

cleanup_linux_gate() {
  local cleanup_status=1
  LINUX_CLEANUP_ACTIVE=true
  trap '' INT TERM
  if ((LINUX_CLEANUP_DEADLINE == 0)); then
    LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))
  fi
  if [[ "$LINUX_ACTIVE_DOCKER_KIND" == create ]]; then
    settle_active_create || true
  else
    terminate_active_docker
    if [[ "$LINUX_CREATE_PENDING" == true ]]; then
      reconcile_pending_create || true
    fi
  fi
  while ((SECONDS < LINUX_CLEANUP_DEADLINE)); do
    remove_owned_container "$LINUX_SYSTEMD_INTENDED" "$LINUX_SYSTEMD_GATE" true || true
    remove_owned_container "$LINUX_WORKSPACE_INTENDED" "$LINUX_WORKSPACE_GATE" false || true
    remove_owned_container "$LINUX_PG_INTENDED" "$LINUX_PG" false || true
    remove_owned_network "$LINUX_NETWORK_INTENDED" "$LINUX_NETWORK" || true
    if all_intended_resources_absent; then
      cleanup_status=0
      break
    fi
    sleep 0.25
  done
  # Final explicit probes are sufficient only because every create request is
  # already settled. An unknown create result can never be converted into
  # success by an absence observation.
  if [[ "$cleanup_status" -eq 0 ]] && ! all_intended_resources_absent; then
    cleanup_status=1
  fi
  if [[ "$LINUX_CREATE_SETTLEMENT_UNKNOWN" == true ]]; then
    echo "Linux gate has an unsettled Docker create result" >&2
    cleanup_status=1
  fi
  if [[ "$LINUX_OWNER_CONFLICT" == true ]]; then
    cleanup_status=1
  fi
  if [[ "$cleanup_status" -ne 0 ]]; then
    echo "Linux gate resources did not converge to exact absence" >&2
  fi
  return "$cleanup_status"
}

linux_gate_on_exit() {
  local run_status=$?
  local cleanup_status=0
  trap - EXIT
  cleanup_linux_gate || cleanup_status=$?
  rm -rf -- "$LINUX_CAPTURE_DIR"
  if [[ "$run_status" -ne 0 ]]; then
    exit "$run_status"
  fi
  exit "$cleanup_status"
}

linux_gate_signal() {
  local status="$1"
  trap '' INT TERM
  LINUX_CLEANUP_ACTIVE=true
  if ((LINUX_CLEANUP_DEADLINE == 0)); then
    LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))
  fi
  if [[ "$LINUX_ACTIVE_DOCKER_KIND" == create ]]; then
    settle_active_create || true
  else
    terminate_active_docker
    if [[ "$LINUX_CREATE_PENDING" == true ]]; then
      reconcile_pending_create || true
    fi
  fi
  exit "$status"
}

trap linux_gate_on_exit EXIT
trap 'linux_gate_signal 130' INT
trap 'linux_gate_signal 143' TERM

main() {
  local attempt
  local blockd_installed=false
  local collected_failures=""
  local collected_status=0
  local expected_node_privileged_inventory="$LINUX_CAPTURE_DIR/node-privileged.expected"
  local expected_root_control_inventory="$LINUX_CAPTURE_DIR/root-control.expected"
  local image_inspection=""
  local iidfile_expected=""
  local iidfile_expected_lf=""
  local listed_test=""
  local observed_node_privileged_inventory="$LINUX_CAPTURE_DIR/node-privileged.observed"
  local observed_root_control_inventory="$LINUX_CAPTURE_DIR/root-control.observed"
  local observed=""
  local node_privileged_inventory_ready=false
  local root_control_inventory_ready=false
  local status=0
  local systemd_ready=false
  local workspace_gate_status=0

  collect_gate_failure() {
    local label="$1"
    local failure_status="$2"
    collected_status=1
    collected_failures="$collected_failures $label(exit=$failure_status)"
    echo "==> Linux quality stage failed: $label (exit $failure_status)" >&2
  }

  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the Linux quality gate" >&2
    return 1
  }

  # Intent and the unforgeable owner capability precede every create. A lost
  # CLI response is settled before cleanup observes absence. Container create
  # and start are separate so an interrupted start has no late-create power.
  LINUX_NETWORK_INTENDED=true
  docker_create_cli network "$LINUX_NETWORK" capture 100 \
    network create --label "$LINUX_OWNER_LABEL" "$LINUX_NETWORK" \
    || return $?
  LINUX_PG_INTENDED=true
  docker_create_cli container "$LINUX_PG" capture 300 \
    create --name "$LINUX_PG" --label "$LINUX_OWNER_LABEL" \
    --network "$LINUX_NETWORK" -e POSTGRES_PASSWORD=cats postgres:16 || return $?
  docker_cli capture 300 start "$LINUX_PG" || return $?

  # The workspace-wide gate remains unprivileged.
  LINUX_WORKSPACE_INTENDED=true
  if docker_create_cli container "$LINUX_WORKSPACE_GATE" capture 72000 \
    create --name "$LINUX_WORKSPACE_GATE" \
    --label "$LINUX_OWNER_LABEL" --platform "$LINUX_PLATFORM" \
    --ulimit nofile=65536:65536 \
    -e CARGO_BUILD_JOBS="$LINUX_JOBS" \
    -e CATS_TEST_POSTGRES_URL="postgres://postgres:cats@${LINUX_PG}:5432/postgres" \
    -e CATS_SOURCE_PROVENANCE_ROOT="$CATS_SOURCE_PROVENANCE_ROOT" \
    -e CATS_SOURCE_PROVENANCE_HEAD="$CATS_SOURCE_PROVENANCE_HEAD" \
    -e CATS_SOURCE_PROVENANCE_DIRTY="$CATS_SOURCE_PROVENANCE_DIRTY" \
    -e CATS_SOURCE_PROVENANCE_FINGERPRINT="$CATS_SOURCE_PROVENANCE_FINGERPRINT" \
    -e CATS_LINUX_TARGET_DIRECTORY="$LINUX_TARGET_DIRECTORY" \
    --network "$LINUX_NETWORK" \
    -v "$REPO_ROOT:/work" -w /work \
    -v cats-cargo-registry:/usr/local/cargo/registry \
    -v "$LINUX_TARGET_VOLUME:/target" \
    rust:1.97.1-bookworm \
    sh -ceu 'if ! apt-get update -qq \
             || ! apt-get install -qy --no-install-recommends e2fsprogs jq zstd \
             || ! rustup component add clippy rustfmt; then
             exit 125
           fi
           linux_status=0
           linux_build_ready=false
           linux_failures=""
           run_linux_stage() {
             stage_name="$1"
             shift
             if "$@"; then
               if [ "$stage_name" = build ]; then
                 linux_build_ready=true
               fi
               echo "==> Linux quality stage passed: $stage_name"
             else
               stage_status=$?
               linux_status=1
               linux_failures="$linux_failures $stage_name(exit=$stage_status)"
               echo "==> Linux quality stage failed: $stage_name (exit $stage_status)" >&2
             fi
           }
           run_linux_stage skills ./scripts/quality.sh skills
           run_linux_stage fmt cargo fmt --all -- --check
           run_linux_stage check cargo check --workspace --all-targets --locked --keep-going --target-dir "$CATS_LINUX_TARGET_DIRECTORY"
           run_linux_stage build cargo build --workspace --locked --keep-going --target-dir "$CATS_LINUX_TARGET_DIRECTORY"
           run_linux_stage clippy cargo clippy --workspace --all-targets --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY" -- -D warnings
           run_linux_stage tests cargo test --workspace --locked --no-fail-fast --target-dir "$CATS_LINUX_TARGET_DIRECTORY" -- --test-threads=4
           run_linux_stage rustdoc env RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY"
           if [ "$linux_status" -ne 0 ]; then
             echo "==> Linux quality stage failures:$linux_failures" >&2
           fi
           if [ "$linux_build_ready" != true ]; then
             exit 2
           fi
           exit "$linux_status"' \
    ; then
    if docker_cli inherit 72000 start --attach "$LINUX_WORKSPACE_GATE"; then
      :
    else
      workspace_gate_status=$?
      if [[ "$workspace_gate_status" -eq 1 ]]; then
        # The workspace process reserves exit 1 for collected independent
        # failures after a successful current-source build. Preserve that
        # failure for the final summary while still exercising the privileged
        # groups against those exact artifacts. Exit 2 or setup failures do
        # not prove a usable build and therefore stop dependent execution.
        collect_gate_failure workspace "$workspace_gate_status"
      else
        status="$workspace_gate_status"
      fi
    fi
  else
    status=$?
  fi

  # ProvisionRootImage restart inventory must query a real system manager.
  # Build the small PID-1 image after the unprivileged workspace gate, bind it
  # to this exact source fingerprint, and consume only Docker's immutable image
  # receipt. A tag is deliberately not part of the create authority. The image
  # is content-addressed build cache, not a run-owned resource: concurrent runs
  # may share it, so cleanup must remove only the owner-labeled container and
  # leave cache reclamation to Docker.
  if [[ "$status" -eq 0 ]]; then
    if docker_cli inherit 36000 build \
      --platform "$LINUX_PLATFORM" \
      --iidfile "$LINUX_SYSTEMD_IIDFILE" \
      --build-arg \
        "CATS_SOURCE_PROVENANCE_FINGERPRINT=$CATS_SOURCE_PROVENANCE_FINGERPRINT" \
      --file "$REPO_ROOT/scripts/linux-systemd.Dockerfile" \
      "$REPO_ROOT/scripts"; then
      LINUX_SYSTEMD_IMAGE_ID="$(LC_ALL=C cat "$LINUX_SYSTEMD_IIDFILE")"
      iidfile_expected="$LINUX_CAPTURE_DIR/systemd-image.expected"
      iidfile_expected_lf="$LINUX_CAPTURE_DIR/systemd-image.expected-lf"
      printf '%s' "$LINUX_SYSTEMD_IMAGE_ID" >"$iidfile_expected"
      printf '%s\n' "$LINUX_SYSTEMD_IMAGE_ID" >"$iidfile_expected_lf"
      if [[ ! "$LINUX_SYSTEMD_IMAGE_ID" =~ ^sha256:[0-9a-f]{64}$ \
        ]] || { ! cmp -s "$LINUX_SYSTEMD_IIDFILE" "$iidfile_expected" \
        && ! cmp -s "$LINUX_SYSTEMD_IIDFILE" "$iidfile_expected_lf"; }; then
        echo "focused Linux Runtime E2E received an invalid Docker image receipt" >&2
        status=1
      fi
    else
      status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    if docker_cli capture 50 image inspect \
      --format \
        "{{.Id}}|{{index .Config.Labels \"$LINUX_SOURCE_FINGERPRINT_KEY\"}}" \
      "$LINUX_SYSTEMD_IMAGE_ID"; then
      IFS= read -r image_inspection <"$LINUX_DOCKER_STDOUT" || true
      if [[ "$image_inspection" \
        != "$LINUX_SYSTEMD_IMAGE_ID|$CATS_SOURCE_PROVENANCE_FINGERPRINT" ]]; then
        echo "focused Linux Runtime E2E image provenance does not match the source" >&2
        status=1
      fi
    else
      status=$?
      report_docker_capture_failure
    fi
  fi

  # Privilege is confined to this owner-labeled container and exact ignored
  # inventories. Its source bind is read-only, while the target volume reuses
  # the workspace gate's already-built Linux artifacts. Create and start stay
  # separate so an interrupted start has no late-create authority.
  if [[ "$status" -eq 0 ]]; then
    LINUX_SYSTEMD_INTENDED=true
    if docker_create_cli container "$LINUX_SYSTEMD_GATE" capture 300 \
      create --name "$LINUX_SYSTEMD_GATE" \
      --label "$LINUX_OWNER_LABEL" --platform "$LINUX_PLATFORM" \
      --privileged --cgroupns=private --cgroup-parent system.slice \
      --tmpfs /run:exec --tmpfs /run/lock -e container=docker \
      -e CARGO_BUILD_JOBS="$LINUX_JOBS" \
      -e CATS_TEST_POSTGRES_URL="postgres://postgres:cats@${LINUX_PG}:5432/postgres" \
      --network "$LINUX_NETWORK" \
      --mount "type=bind,source=$REPO_ROOT,target=/work,readonly" -w /work \
      -v cats-cargo-registry:/usr/local/cargo/registry \
      -v "$LINUX_TARGET_VOLUME:/target" \
      "$LINUX_SYSTEMD_IMAGE_ID" /lib/systemd/systemd \
      && docker_cli capture 300 start "$LINUX_SYSTEMD_GATE"; then
      :
    else
      status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    for ((attempt = 0; attempt < 120; attempt++)); do
      observed=""
      if docker_cli capture 50 exec "$LINUX_SYSTEMD_GATE" cat /proc/1/comm; then
        IFS= read -r observed <"$LINUX_DOCKER_STDOUT" || true
      fi
      [[ "$observed" == systemd ]] || { sleep 0.25; continue; }
      if docker_cli capture 50 exec "$LINUX_SYSTEMD_GATE" cat /proc/1/cgroup; then
        IFS= read -r observed <"$LINUX_DOCKER_STDOUT" || true
      fi
      [[ "$observed" == "0::/init.scope" ]] || { sleep 0.25; continue; }
      if docker_cli capture 50 exec "$LINUX_SYSTEMD_GATE" \
        systemctl is-system-running --quiet; then
        systemd_ready=true
        break
      fi
      sleep 0.25
    done
    if [[ "$systemd_ready" != true ]]; then
      echo "focused Linux Runtime E2E did not obtain a real systemd PID 1" >&2
      docker_cli inherit 100 logs "$LINUX_SYSTEMD_GATE" || true
      status=1
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    # Exercise the installed topology under the same real PID 1 used by the
    # focused Runtime test. The production-named Agent service and the
    # production-shaped per-Cat service are siblings in system.slice. A real
    # Agent stop/restart must preserve the exact Cat PID/start/cgroup so the
    # successor Agent can validate and adopt that physical candidate.
    if docker_cli inherit 300 exec "$LINUX_SYSTEMD_GATE" \
      sh -ceu 'agent_unit=cats-noded.service
        cat_unit=cats-serving-11111111111111111111111111111111.service
        agent_script=/run/cats-n5-agent-fixture.sh
        agent_unit_path=/run/systemd/system/$agent_unit
        ready=/run/cats-n5-agent-fixture.ready
        adopted=/run/cats-n5-agent-fixture.adopted
        expected=/run/cats-n5-cat-sibling.expected
        cleanup_fixture() {
          systemctl stop "$agent_unit" >/dev/null 2>&1 || true
          systemctl stop "$cat_unit" >/dev/null 2>&1 || true
          rm -f "$agent_unit_path" "$agent_script" "$ready" "$adopted" "$expected"
          systemctl daemon-reload >/dev/null 2>&1 || true
          systemctl reset-failed "$agent_unit" "$cat_unit" >/dev/null 2>&1 || true
        }
        trap cleanup_fixture EXIT
        cleanup_fixture
        {
          printf "%s\n" "#!/bin/sh"
          printf "%s\n" "set -eu"
          printf "%s\n" "cat_unit=$cat_unit"
          printf "%s\n" "ready=$ready"
          printf "%s\n" "adopted=$adopted"
          printf "%s\n" "expected=$expected"
          printf "%s\n" "if systemctl is-active --quiet \"\$cat_unit\"; then"
          printf "%s\n" "  read -r expected_pid expected_ticks expected_cgroup < \"\$expected\""
          printf "%s\n" "  current_pid=\$(systemctl show --property=MainPID --value \"\$cat_unit\")"
          printf "%s\n" "  test \"\$current_pid\" = \"\$expected_pid\""
          printf "%s\n" "  current_ticks=\$(cut -d \" \" -f 22 \"/proc/\$current_pid/stat\")"
          printf "%s\n" "  test \"\$current_ticks\" = \"\$expected_ticks\""
          printf "%s\n" "  current_cgroup=\$(cut -d : -f 3 \"/proc/\$current_pid/cgroup\")"
          printf "%s\n" "  test \"\$current_cgroup\" = \"\$expected_cgroup\""
          printf "%s\n" "  test \"\$(systemctl show --property=ControlGroup --value \"\$cat_unit\")\" = \"\$expected_cgroup\""
          printf "%s\n" "  test \"\$(systemctl show --property=KillMode --value \"\$cat_unit\")\" = control-group"
          printf "%s\n" "  test \"\$(systemctl show --property=Restart --value \"\$cat_unit\")\" = no"
          printf "%s\n" "  touch \"\$adopted\""
          printf "%s\n" "else"
          printf "%s\n" "  systemd-run --quiet --collect --unit=\"\$cat_unit\" --slice=system.slice --property=Type=exec --property=KillMode=control-group --property=Restart=no --property=UMask=0077 --property=TimeoutStopSec=2s /bin/sleep infinity"
          printf "%s\n" "fi"
          printf "%s\n" "touch \"\$ready\""
          printf "%s\n" "exec /bin/sleep infinity"
        } >"$agent_script"
        chmod 0755 "$agent_script"
        {
          printf "%s\n" "[Unit]"
          printf "%s\n" "Description=Cats node agent N5 PID1 fixture"
          printf "%s\n" "[Service]"
          printf "%s\n" "Type=exec"
          printf "%s\n" "KillMode=control-group"
          printf "%s\n" "ExecStart=$agent_script"
          printf "%s\n" "Restart=always"
          printf "%s\n" "RestartSec=1"
        } >"$agent_unit_path"
        systemctl daemon-reload
        systemctl start "$agent_unit"
        fixture_ready=false
        for _ in $(seq 1 120); do
          if test -f "$ready" \
            && test "$(systemctl is-active "$agent_unit")" = active \
            && test "$(systemctl is-active "$cat_unit")" = active; then
            fixture_ready=true
            break
          fi
          sleep 0.05
        done
        test "$fixture_ready" = true
        test "$(systemctl show --property=KillMode --value "$agent_unit")" = control-group
        agent_pid_before=$(systemctl show --property=MainPID --value "$agent_unit")
        cat_pid=$(systemctl show --property=MainPID --value "$cat_unit")
        test "$agent_pid_before" -gt 1
        test "$cat_pid" -gt 1
        test "$agent_pid_before" -ne "$cat_pid"
        cat_start_ticks_before=$(cut -d " " -f 22 "/proc/$cat_pid/stat")
        cat_control_group_before=$(cut -d : -f 3 "/proc/$cat_pid/cgroup")
        test -n "$cat_start_ticks_before"
        test "$cat_control_group_before" = "/system.slice/$cat_unit"
        printf "%s %s %s\n" "$cat_pid" "$cat_start_ticks_before" "$cat_control_group_before" >"$expected"

        systemctl stop "$agent_unit"
        test "$(systemctl is-active "$agent_unit")" = inactive
        test ! -e "/proc/$agent_pid_before/stat"
        test -e "/proc/$cat_pid/stat"
        cat_start_ticks_after_stop=$(cut -d " " -f 22 "/proc/$cat_pid/stat")
        cat_control_group_after_stop=$(cut -d : -f 3 "/proc/$cat_pid/cgroup")
        test "$cat_start_ticks_after_stop" = "$cat_start_ticks_before"
        test "$cat_control_group_after_stop" = "$cat_control_group_before"

        rm -f "$ready" "$adopted"
        systemctl restart "$agent_unit"
        fixture_adopted=false
        for _ in $(seq 1 120); do
          if test -f "$ready" && test -f "$adopted" \
            && test "$(systemctl is-active "$agent_unit")" = active; then
            fixture_adopted=true
            break
          fi
          sleep 0.05
        done
        test "$fixture_adopted" = true
        cat_pid_after_restart=$(systemctl show --property=MainPID --value "$cat_unit")
        cat_start_ticks_after_restart=$(cut -d " " -f 22 "/proc/$cat_pid_after_restart/stat")
        cat_control_group_after_restart=$(cut -d : -f 3 "/proc/$cat_pid_after_restart/cgroup")
        test "$cat_pid_after_restart" = "$cat_pid"
        test "$cat_start_ticks_after_restart" = "$cat_start_ticks_before"
        test "$cat_control_group_after_restart" = "$cat_control_group_before"
        test "$(systemctl show --property=ControlGroup --value "$cat_unit")" = "$cat_control_group_after_restart"
        test "$(systemctl show --property=KillMode --value "$cat_unit")" = control-group
        test "$(systemctl show --property=Restart --value "$cat_unit")" = no

        systemctl stop "$cat_unit"
        cat_stopped=false
        for _ in $(seq 1 120); do
          if test ! -e "/proc/$cat_pid/stat"; then
            cat_stopped=true
            break
          fi
          sleep 0.05
        done
        test "$cat_stopped" = true
        trap - EXIT
        cleanup_fixture'; then
      :
    else
      collect_gate_failure systemd-topology "$?"
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    if docker_cli inherit 300 exec "$LINUX_SYSTEMD_GATE" \
      sh -ceu 'source_binary="$1/debug/cats-blockd"
        target_binary=/opt/cats/bin/cats-blockd
        test -f "$source_binary"
        test -x "$source_binary"
        test ! -L "$source_binary"
        install -D -m 0755 "$source_binary" "$target_binary"
        test -f "$target_binary"
        test -x "$target_binary"
        test ! -L "$target_binary"
        cmp -s "$source_binary" "$target_binary"' sh "$LINUX_TARGET_DIRECTORY"; then
      blockd_installed=true
    else
      collect_gate_failure blockd-install "$?"
    fi
  fi
  if [[ "$status" -eq 0 && "$blockd_installed" == true ]]; then
    # These real-binary tests intentionally exercise the installed
    # /run/cats/blockd-v1 namespace. The native qualification builder and the
    # workspace-wide Linux container are unprivileged, so keep the tests
    # ignored there and run their exact closed inventory only inside this one
    # owner-labeled PID-1 container. Calibrate Cargo's zero-test-success
    # behavior before trusting the privileged run.
    printf '%s\n' \
      'control_only_rejects_frontends_and_serves_only_the_typed_effect: test' \
      'every_provision_publication_crash_window_recovers_by_authority_or_exact_replay: test' \
      'first_lf_framing_enforces_prefix_crlf_and_payload_cap_before_effect: test' \
      'receiver_responds_at_first_lf_without_waiting_for_half_close_or_running_tail: test' \
      'stalled_connection_times_out_without_starving_the_next_request: test' \
      >"$expected_root_control_inventory"
    if docker_cli capture 12600 exec "$LINUX_SYSTEMD_GATE" \
      timeout --signal=TERM --kill-after=30s 20m \
      cargo test -p cats-blockd-daemon --test root_provision_control --locked \
        --target-dir "$LINUX_TARGET_DIRECTORY" \
        -- --ignored --list; then
      : >"$observed_root_control_inventory"
      while IFS= read -r listed_test; do
        case "$listed_test" in
          *": test") printf '%s\n' "$listed_test" >>"$observed_root_control_inventory" ;;
        esac
      done <"$LINUX_DOCKER_STDOUT"
      if ! cmp -s "$expected_root_control_inventory" "$observed_root_control_inventory"; then
        echo "privileged blockd root-control test inventory was not the exact known positive" >&2
        collect_gate_failure root-control-inventory 1
      else
        root_control_inventory_ready=true
      fi
    else
      workspace_gate_status=$?
      report_docker_capture_failure
      collect_gate_failure root-control-inventory "$workspace_gate_status"
    fi
  fi
  if [[ "$status" -eq 0 && "$root_control_inventory_ready" == true ]]; then
    if docker_cli inherit 12600 exec "$LINUX_SYSTEMD_GATE" \
      timeout --signal=TERM --kill-after=30s 20m \
      cargo test -p cats-blockd-daemon --test root_provision_control --locked --no-fail-fast \
        --target-dir "$LINUX_TARGET_DIRECTORY" \
        -- --ignored --test-threads=1 --nocapture; then
      :
    else
      collect_gate_failure root-control-tests "$?"
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    # Rust's test filter exits successfully even when it selects zero tests.
    # Calibrate the privileged Node probe against the exact current physical
    # network inventory before trusting the run. These tests need a private
    # network namespace, CAP_NET_ADMIN and /dev/net/tun; the unprivileged
    # workspace container intentionally cannot execute them.
    # The fresh systemd image may initialize Rust components before Cargo can
    # reuse the workspace target, so both inventory and execution are bounded.
    printf '%s\n' \
      'ch::tests::real_linux_pending_tap_rejects_name_replacement_at_every_configuration_boundary: test' \
      'ch::tests::real_linux_scoped_tap_is_published_and_exact_in_a_private_network_namespace: test' \
      | LC_ALL=C sort >"$expected_node_privileged_inventory"
    if docker_cli capture 12600 exec "$LINUX_SYSTEMD_GATE" \
      timeout --signal=TERM --kill-after=30s 20m \
      cargo test -p cats-node-agent --lib --all-features --locked \
        --target-dir "$LINUX_TARGET_DIRECTORY" \
        ch::tests::real_linux_ \
        -- --ignored --list; then
      : >"$observed_node_privileged_inventory"
      while IFS= read -r listed_test; do
        case "$listed_test" in
          *": test") printf '%s\n' "$listed_test" >>"$observed_node_privileged_inventory" ;;
        esac
      done <"$LINUX_DOCKER_STDOUT"
      LC_ALL=C sort -o "$observed_node_privileged_inventory" \
        "$observed_node_privileged_inventory"
      if ! cmp -s "$expected_node_privileged_inventory" \
        "$observed_node_privileged_inventory"; then
        echo "privileged Node test inventory was not the exact known positive" >&2
        report_docker_capture_failure
        collect_gate_failure node-privileged-inventory 1
      else
        node_privileged_inventory_ready=true
      fi
    else
      workspace_gate_status=$?
      report_docker_capture_failure
      collect_gate_failure node-privileged-inventory "$workspace_gate_status"
    fi
  fi
  if [[ "$status" -eq 0 && "$node_privileged_inventory_ready" == true ]]; then
    if docker_cli inherit 12600 exec "$LINUX_SYSTEMD_GATE" \
      timeout --signal=TERM --kill-after=30s 20m \
      cargo test -p cats-node-agent --lib --all-features --locked --no-fail-fast \
        --target-dir "$LINUX_TARGET_DIRECTORY" \
        ch::tests::real_linux_ \
        -- --ignored --test-threads=1 --nocapture; then
      :
    else
      collect_gate_failure node-privileged-tests "$?"
    fi
  fi

  if [[ "$status" -eq 0 && "$collected_status" -ne 0 ]]; then
    echo "==> Linux quality stage failures:$collected_failures" >&2
    status="$collected_status"
  fi
  return "$status"
}

main
