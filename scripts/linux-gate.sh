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
LINUX_DEFERRED_SIGNAL_STATUS=0
LINUX_CLEANUP_ACTIVE=false
LINUX_CAPTURE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cats-linux-gate.XXXXXXXX")"
LINUX_DOCKER_STDOUT="$LINUX_CAPTURE_DIR/docker.stdout"
LINUX_DOCKER_STDERR="$LINUX_CAPTURE_DIR/docker.stderr"
LINUX_PROBE_PRESENT=false
LINUX_PROBE_ID=""
LINUX_CLEANUP_DEADLINE=0

source_git() {
  GIT_OPTIONAL_LOCKS=0 git \
    -c safe.directory="$REPO_ROOT" \
    -c core.hooksPath=/dev/null \
    -c core.fsmonitor=false \
    -C "$REPO_ROOT" \
    "$@"
}

LINUX_TARGET_NAMESPACE="$(
  printf '%s\0' "$CATS_SOURCE_PROVENANCE_ROOT" | source_git hash-object --stdin
)"
LINUX_TARGET_DIRECTORY="/target/worktrees/$LINUX_TARGET_NAMESPACE"
LINUX_PLATFORM_NAMESPACE="$(
  printf '%s\0' "$LINUX_PLATFORM" | source_git hash-object --stdin
)"
LINUX_SYSTEMD_IMAGE="cats-linux-systemd-gate:${LINUX_TARGET_NAMESPACE}-${LINUX_PLATFORM_NAMESPACE}"

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
  if [[ "$mode" == capture ]]; then
    docker "$@" >"$LINUX_DOCKER_STDOUT" 2>"$LINUX_DOCKER_STDERR" &
  else
    docker "$@" &
  fi
  LINUX_ACTIVE_DOCKER_PID=$!
  restore_linux_gate_signal_traps
  if [[ "$defer_signals" == true ]] && ((LINUX_DEFERRED_SIGNAL_STATUS != 0)); then
    linux_gate_signal "$LINUX_DEFERRED_SIGNAL_STATUS"
  fi
}

# A create request is causally settled only after its CLI receives the daemon
# result. Killing that client first would make a later daemon-side create
# indistinguishable from absence. The shared cleanup deadline is the only
# bound; expiry records an explicit unknown state that cleanup cannot bless.
settle_active_create() {
  local pid="$LINUX_ACTIVE_DOCKER_PID"
  [[ -n "$pid" && "$LINUX_ACTIVE_DOCKER_KIND" == create ]] || return 0
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
  return "$status"
}

docker_cli() {
  docker_cli_operation interruptible "$@"
}

docker_create_cli() {
  docker_cli_operation create "$@"
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
  cleanup_docker_cli capture 50 rm -f "$id" || true
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
  fi
  while ((SECONDS < LINUX_CLEANUP_DEADLINE)); do
    if [[ "$LINUX_OWNER_CONFLICT" == true ]]; then
      break
    fi
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
  if ((LINUX_CLEANUP_DEADLINE == 0)); then
    LINUX_CLEANUP_DEADLINE=$((SECONDS + LINUX_CLEANUP_BUDGET_SECONDS))
  fi
  if [[ "$LINUX_ACTIVE_DOCKER_KIND" == create ]]; then
    settle_active_create || true
  else
    terminate_active_docker
  fi
  exit "$status"
}

trap linux_gate_on_exit EXIT
trap 'linux_gate_signal 130' INT
trap 'linux_gate_signal 143' TERM

main() {
  local attempt
  local status=0
  local systemd_ready=false
  local observed

  command -v docker >/dev/null 2>&1 || {
    echo "docker is required for the Linux quality gate" >&2
    return 1
  }

  # Intent and the unforgeable owner capability precede every create. A lost
  # CLI response is settled before cleanup observes absence. Container create
  # and start are separate so an interrupted start has no late-create power.
  LINUX_NETWORK_INTENDED=true
  docker_create_cli capture 100 network create --label "$LINUX_OWNER_LABEL" "$LINUX_NETWORK" \
    || return $?
  LINUX_PG_INTENDED=true
  docker_create_cli capture 300 create --name "$LINUX_PG" --label "$LINUX_OWNER_LABEL" \
    --network "$LINUX_NETWORK" -e POSTGRES_PASSWORD=cats postgres:16 || return $?
  docker_cli capture 300 start "$LINUX_PG" || return $?

  # The workspace-wide gate remains unprivileged. It builds every workspace
  # binary before tests so the focused systemd stage consumes the same exact
  # Linux cats-blockd artifact without a second Cargo build lock.
  LINUX_WORKSPACE_INTENDED=true
  if docker_create_cli capture 72000 create --name "$LINUX_WORKSPACE_GATE" \
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
    sh -c 'apt-get update -qq &&
           apt-get install -qy --no-install-recommends e2fsprogs jq &&
           rustup component add clippy rustfmt &&
           ./scripts/quality.sh skills &&
           cargo fmt --all -- --check &&
           cargo check --workspace --all-targets --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY" &&
           cargo build --workspace --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY" &&
           cargo clippy --workspace --all-targets --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY" -- -D warnings &&
           cargo test --workspace --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY" -- --test-threads=4 &&
           RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked --target-dir "$CATS_LINUX_TARGET_DIRECTORY"' \
    && docker_cli inherit 72000 start --attach "$LINUX_WORKSPACE_GATE"; then
    :
  else
    status=$?
  fi

  # ProvisionRootImage restart inventory must query a real system manager.
  # The privilege is confined to one private-cgroup container and one exact,
  # ignored test. Source remains read-only.
  if [[ "$status" -eq 0 ]]; then
    if docker_cli inherit 36000 build \
      --platform "$LINUX_PLATFORM" \
      --file "$REPO_ROOT/scripts/linux-systemd.Dockerfile" \
      --tag "$LINUX_SYSTEMD_IMAGE" "$REPO_ROOT/scripts"; then
      :
    else
      status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    LINUX_SYSTEMD_INTENDED=true
    if docker_create_cli capture 300 create --name "$LINUX_SYSTEMD_GATE" \
      --label "$LINUX_OWNER_LABEL" --platform "$LINUX_PLATFORM" \
      --privileged --cgroupns=private --cgroup-parent system.slice \
      --tmpfs /run --tmpfs /run/lock -e container=docker \
      -e CARGO_BUILD_JOBS="$LINUX_JOBS" \
      -e CATS_TEST_POSTGRES_URL="postgres://postgres:cats@${LINUX_PG}:5432/postgres" \
      --network "$LINUX_NETWORK" \
      --mount "type=bind,source=$REPO_ROOT,target=/work,readonly" -w /work \
      -v cats-cargo-registry:/usr/local/cargo/registry \
      -v "$LINUX_TARGET_VOLUME:/target" \
      "$LINUX_SYSTEMD_IMAGE" /lib/systemd/systemd \
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
      :
    else
      status=$?
    fi
  fi
  if [[ "$status" -eq 0 ]]; then
    if docker_cli inherit 12600 exec "$LINUX_SYSTEMD_GATE" \
      timeout --signal=TERM --kill-after=30s 20m \
      cargo test -p cats-node-agent --lib --locked \
        --target-dir "$LINUX_TARGET_DIRECTORY" \
        runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_reconcile_one_created_cat_across_restart \
        -- --ignored --exact --nocapture; then
      :
    else
      status=$?
    fi
  fi
  return "$status"
}

main
