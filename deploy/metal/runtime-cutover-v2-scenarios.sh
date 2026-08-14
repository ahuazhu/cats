#!/usr/bin/env bash
# Production-v2 scenarios for runtime-cutover-e2e.sh. This script only drives
# an already-installed release. It never provisions, installs or starts a
# long-lived service, and it never treats a focused test as live proof.
set -euo pipefail

readonly BLOCKED=78
readonly ACTION=${1:?missing scenario action}
readonly CASE_ID=${2:?missing scenario case id}
readonly BLOCK_PATH=${3:?missing scenario block path}
readonly CASE_DIR=${4:?missing scenario case directory}

fail() {
  printf 'runtime cutover v2 driver: %s\n' "$*" >&2
  exit 64
}

blocked() {
  local reason=$1 receipt=$CASE_DIR/blocked-receipt.json temporary
  temporary=$(mktemp "$CASE_DIR/.blocked.json.XXXXXX")
  jq -S -c -n \
    --arg case_id "$CASE_ID" \
    --arg block_path "$BLOCK_PATH" \
    --arg reason "$reason" \
    '{version:1,status:"blocked",case_id:$case_id,block_path:$block_path,reason:$reason}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$receipt"
  printf 'BLOCKED_RECEIPT '
  jq -S -c . "$receipt"
  exit "$BLOCKED"
}

required() {
  local name=$1 value=${!1:-}
  [[ -n $value ]] || fail "$name is required"
  printf '%s' "$value"
}

qualification_node_id() {
  local value
  value=$(required CATS_E3_QUALIFICATION_NODE_ID)
  canonical_id CATS_E3_QUALIFICATION_NODE_ID "$value"
  printf '%s' "$value"
}

# The runner supplies only a private staged token file. Capture its path in a
# non-exported readonly shell variable, then remove even the path from the
# environment inherited by probes, systemd and diagnostics.
TOKEN_FILE=${CATS_E3_TOKEN_FILE:-}
[[ $TOKEN_FILE == /* && -f $TOKEN_FILE && ! -L $TOKEN_FILE ]] || \
  fail "staged control token file is required"
export -n TOKEN_FILE
unset CATS_E3_TOKEN_FILE
readonly TOKEN_FILE

read_token() {
  local value
  value=$(<"$TOKEN_FILE")
  [[ -n $value && $value != *$'\n'* && $value != *$'\r'* ]] || \
    fail "staged control token must be one nonempty header-safe line"
  printf '%s' "$value"
}
AUTHORIZATION_TEMP=
CURL_JSON_STATUS=
QUALIFICATION_WATCHER_PID=
cleanup_authorization_temp() {
  if [[ -n $QUALIFICATION_WATCHER_PID ]]; then
    kill "$QUALIFICATION_WATCHER_PID" 2>/dev/null || true
    wait "$QUALIFICATION_WATCHER_PID" 2>/dev/null || true
    QUALIFICATION_WATCHER_PID=
  fi
  if [[ -n $AUTHORIZATION_TEMP ]]; then
    rm -f "$AUTHORIZATION_TEMP"
    AUTHORIZATION_TEMP=
  fi
}
trap cleanup_authorization_temp EXIT

canonical_id() {
  [[ $2 =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "$1 is not a canonical runtime ID"
}

nonsecret_path() {
  local name=$1 value
  value=$(required "$name")
  [[ $value == /* && -f $value && ! -L $value ]] || fail "$name must be an absolute regular non-symlink file"
  printf '%s' "$value"
}

binary() {
  local label=$1 environment_label name value
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  name=CATS_E3_BINARY_${environment_label}
  value=${!name:-}
  [[ $value == /* && -f $value && -x $value && ! -L $value ]] || fail "validated --binary $label is required"
  printf '%s' "$value"
}

binary_sha256() {
  local label=$1 environment_label name value
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  name=CATS_E3_BINARY_${environment_label}_SHA256
  value=${!name:-}
  [[ $value =~ ^[0-9a-f]{64}$ ]] || fail "validated --binary hash for $label is required"
  printf '%s' "$value"
}

config() {
  local label=$1 environment_label name value
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  name=CATS_E3_CONFIG_${environment_label}
  value=${!name:-}
  [[ $value == /* && -f $value && ! -L $value ]] || fail "validated --config $label is required"
  printf '%s' "$value"
}

json_field() {
  local path=$1 expression=$2
  jq -er "$expression" "$path"
}

atomic_json() {
  local destination=$1 source=$2 temporary
  temporary=$(mktemp "$CASE_DIR/.${destination}.XXXXXX")
  jq -S -c . "$source" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$CASE_DIR/$destination"
}

run_cats() {
  local executable token
  executable=$(binary cats)
  token=$(read_token)
  CATS_TOKEN=$token "$executable" "$@"
}

curl_json() {
  local method=$1 url=$2 output=$3 expected_status=$4
  shift 4
  local curl_bin auth_header response_headers status content_types encodings curl_status size token
  curl_bin=$(binary curl)
  auth_header=$(mktemp "$CASE_DIR/.authorization.XXXXXX")
  AUTHORIZATION_TEMP=$auth_header
  response_headers=$(mktemp "$CASE_DIR/.response-headers.XXXXXX")
  chmod 0600 "$auth_header" "$response_headers"
  token=$(read_token)
  printf 'authorization: Bearer %s\n' "$token" >"$auth_header"
  unset token
  set +e
  status=$("$curl_bin" --silent --show-error \
    --proto '=https' --tlsv1.2 --max-time 30 --max-filesize 1048576 \
    --request "$method" \
    --header "@$auth_header" \
    --header 'accept: application/json' \
    --header 'accept-encoding: identity' \
    --dump-header "$response_headers" --write-out '%{http_code}' \
    "$@" --output "$output" "$url")
  curl_status=$?
  set -e
  rm -f "$auth_header"
  AUTHORIZATION_TEMP=
  if [[ $curl_status -ne 0 ]]; then
    CURL_JSON_STATUS=
    rm -f "$response_headers" "$output"
    return 75
  fi
  [[ $status =~ ^[0-9]{3}$ ]] || {
    rm -f "$response_headers" "$output"
    fail "$method returned an invalid HTTP status"
  }
  size=$(wc -c <"$output")
  [[ $size -le 1048576 ]] || {
    rm -f "$response_headers" "$output"
    fail "$method response exceeds the closed byte bound"
  }
  case ",$expected_status," in
    *",$status,"*) ;;
    *)
      rm -f "$response_headers"
      fail "$method returned HTTP $status, expected $expected_status"
      ;;
  esac
  CURL_JSON_STATUS=$status
  content_types=$(awk 'BEGIN{IGNORECASE=1} /^Content-Type:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$response_headers")
  encodings=$(awk 'BEGIN{IGNORECASE=1} /^Content-Encoding:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$response_headers")
  rm -f "$response_headers"
  [[ $content_types == application/json ]] || fail "$method response Content-Type is not one exact application/json"
  [[ -z $encodings || $encodings == identity ]] || fail "$method response Content-Encoding is not absent or identity"
  jq -e . "$output" >/dev/null || fail "$method response is not JSON"
}

control_origin() {
  local origin
  origin=$(required CATS_E3_CONTROL_ORIGIN)
  [[ $origin =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || fail "CATS_E3_CONTROL_ORIGIN must be one canonical HTTPS origin"
  printf '%s' "$origin"
}

operation_wait() {
  local operation_id=$1 expected_target=$2 origin workspace response
  origin=$(control_origin)
  workspace=$(required CATS_E3_WORKSPACE_ID)
  canonical_id CATS_E3_WORKSPACE_ID "$workspace"
  canonical_id operation_id "$operation_id"
  response=$CASE_DIR/operation-$operation_id.json
  run_cats --api-url "$origin" --workspace "$workspace" --json \
    operation wait "$operation_id" >"$response"
  jq -e \
    --arg operation "$operation_id" --arg workspace "$workspace" --arg target "$expected_target" \
    '.operation_id == $operation and .workspace_id == $workspace and .phase == "succeeded"
      and .target == $target and .terminal.kind == "succeeded"
      and .terminal.result.observed_target == $target' \
    "$response" >/dev/null || fail "canonical Operation does not prove exact $expected_target settlement"
  jq -S -c \
    '{version:1,operation_id,workspace_id,target,phase,
      terminal:{kind:.terminal.kind,observed_target:.terminal.result.observed_target}}' \
    "$response" >"$CASE_DIR/operation-receipt.source.json"
  atomic_json operation-receipt.json "$CASE_DIR/operation-receipt.source.json"
  rm -f "$CASE_DIR/operation-receipt.source.json"
}

product_mutation() {
  local method=$1 path=$2 key=$3 expected_target=$4 body=${5:-}
  local origin response replay operation_id replay_operation_id converged request_status attempt
  origin=$(control_origin)
  response=$CASE_DIR/mutation-response.json
  replay=$CASE_DIR/mutation-replay.json
  request_status=75
  for attempt in 1 2; do
    set +e
    if [[ -n $body ]]; then
      curl_json "$method" "$origin$path" "$response" 200,202 \
        --header "idempotency-key: $key" \
        --header 'content-type: application/json' \
        --data-binary "@$body"
    else
      curl_json "$method" "$origin$path" "$response" 200,202 \
        --header "idempotency-key: $key"
    fi
    request_status=$?
    set -e
    [[ $request_status -eq 75 ]] || break
  done
  [[ $request_status -eq 0 ]] || fail "product mutation response remained ambiguous after one exact idempotent replay"
  jq -S -c \
    '{version:1,operation_id:(.operation_id // null),
      desired_revision:(.desired_revision // null),converged:(.converged // null)}' \
    "$response" >"$CASE_DIR/mutation-receipt.source.json"
  atomic_json mutation-receipt.json "$CASE_DIR/mutation-receipt.source.json"
  rm -f "$CASE_DIR/mutation-receipt.source.json"
  operation_id=$(jq -er '.operation_id // empty' "$response" 2>/dev/null || true)
  if [[ -n $operation_id ]]; then
    if [[ -n $body ]]; then
      curl_json "$method" "$origin$path" "$replay" 200,202 \
        --header "idempotency-key: $key" \
        --header 'content-type: application/json' \
        --data-binary "@$body" || fail "idempotent mutation replay was ambiguous"
    else
      curl_json "$method" "$origin$path" "$replay" 200,202 \
        --header "idempotency-key: $key" || fail "idempotent mutation replay was ambiguous"
    fi
    replay_operation_id=$(jq -er '.operation_id // empty' "$replay" 2>/dev/null || true)
    [[ $replay_operation_id == "$operation_id" ]] || fail "idempotent replay returned another Operation"
    jq -S -c -n --arg operation_id "$operation_id" \
      '{version:1,idempotent_replay:true,operation_id:$operation_id}' \
      >"$CASE_DIR/idempotent-replay.source.json"
    atomic_json idempotent-replay-receipt.json "$CASE_DIR/idempotent-replay.source.json"
    rm -f "$CASE_DIR/idempotent-replay.source.json"
    operation_wait "$operation_id" "$expected_target"
    return
  fi
  converged=$(jq -er '.converged // false' "$response" 2>/dev/null || true)
  [[ $converged == true ]] || fail "product mutation returned neither operation_id nor converged=true"
}

fleet_verify_to() {
  local destination=$1 key_ring args node
  key_ring=$(config route-key-ring)
  args=(--api-url "$(control_origin)" --json admin fleet-verify
    --key-ring "$key_ring" --release-commit "$CATS_E3_EXACT_COMMIT"
    --timeout-seconds 120 --poll-interval-ms 500)
  IFS=, read -r -a nodes <<<"$(required CATS_E3_EXPECTED_NODES)"
  [[ ${#nodes[@]} -gt 0 ]] || fail "CATS_E3_EXPECTED_NODES is empty"
  for node in "${nodes[@]}"; do
    canonical_id expected_node "$node"
    args+=(--expected-node "$node")
  done
  run_cats "${args[@]}" >"$destination"
}

raw_fleet_snapshot_to() {
  local destination=$1
  curl_json GET "$(control_origin)/v1/admin/runtime/fleet-verification" "$destination" 200 || return $?
  jq -e --arg commit "$CATS_E3_EXACT_COMMIT" '
    .version == 1 and .control_release_commit_sha == $commit
    and (.nodes | type == "array" and length > 0)' "$destination" >/dev/null
}

run_fleet_verify() {
  fleet_verify_to "$CASE_DIR/fleet-verification.json"
  fleet_safe_summary "$CASE_DIR/fleet-verification.json" \
    >"$CASE_DIR/fleet-verification-receipt.source.json"
  atomic_json fleet-verification-receipt.json \
    "$CASE_DIR/fleet-verification-receipt.source.json"
  rm -f "$CASE_DIR/fleet-verification-receipt.source.json"
  printf 'FLEET_VERIFY_RECEIPT exact_commit=%s sha256=%s\n' "$CATS_E3_EXACT_COMMIT" \
    "$(sha256sum "$CASE_DIR/fleet-verification-receipt.json" | awk '{print $1}')"
}

fleet_safe_summary() {
  local source=$1
  jq -S -c --arg block_path "$BLOCK_PATH" '
    {version:1,release_commit_sha:.release_commit_sha,block_path:$block_path,
     desired_runtime_count:.snapshot.desired_runtime_count,
     current_runtime_observation_count:.snapshot.current_runtime_observation_count,
     nodes:[.snapshot.nodes[] | {node_id,
       complete_inventory:.inventory.complete_inventory,
       assigned_desired_count:.inventory.assigned_desired_count,
       runtime_count:.inventory.runtime_count,residue_count:.inventory.residue_count,
       lifecycle_open_count:.inventory.lifecycle_open_count,
       route_active_count:.inventory.route_active_count,
       route_closed_count:.inventory.route_closed_count,
       active_guard_count:.inventory.active_guard_count,
       cancellation_pending_count:.inventory.cancellation_pending_count,
       quarantined_condition_count:.inventory.quarantined_condition_count}]}' "$source"
}

write_runtime_cat_id() {
  local cat=$1 state temporary
  state=$(nonsecret_path CATS_E3_RUNTIME_STATE)
  temporary=$(mktemp "${state%/*}/.runtime-state.json.XXXXXX")
  jq -S -c --arg cat_id "$cat" '.cat_id = $cat_id' "$state" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$state"
}

run_create() {
  local output cat_id operation_id expected_name expected_node placement_snapshot
  expected_name=$(required CATS_E3_CAT_NAME)
  output=$CASE_DIR/create-response.json
  run_cats --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" --json \
    create "$expected_name" \
    --boot-image-digest "$(required CATS_E3_BOOT_IMAGE_DIGEST)" \
    --cpus "${CATS_E3_CPUS:-1}" --memory "${CATS_E3_MEMORY:-512MiB}" \
    --root-size "${CATS_E3_ROOT_SIZE:-1GiB}" --durability strict >"$output"
  cat_id=$(json_field "$output" '.cat_id')
  operation_id=$(json_field "$output" '.operation_id')
  canonical_id cat_id "$cat_id"
  canonical_id operation_id "$operation_id"
  write_runtime_cat_id "$cat_id"
  operation_wait "$operation_id" running
  run_cats --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" --json \
    get "$cat_id" >"$CASE_DIR/cat-running.json"
  jq -e --arg cat "$cat_id" \
    '.id == $cat and .desired.target == "running" and .observed.stable_state == "running" and (.observed.conditions | index("ready") != null)' \
    "$CASE_DIR/cat-running.json" >/dev/null || fail "Cat did not converge to exact Running/Ready"
  expected_node=$(qualification_node_id)
  placement_snapshot=$CASE_DIR/create-placement-snapshot.json
  run_probe snapshot --cat-id "$cat_id" >"$placement_snapshot"
  jq -e --arg cat "$cat_id" --arg node "$expected_node" \
    '.version == 1 and .cat_id == $cat and .node_id == $node' \
    "$placement_snapshot" >/dev/null || \
    fail "created Cat was not placed on the exact qualification Node"
  jq -S -c \
    '{version:1,cat_id:.id,desired_target:.desired.target,
      observed_stable_state:.observed.stable_state,conditions:.observed.conditions}' \
    "$CASE_DIR/cat-running.json" >"$CASE_DIR/cat-running-receipt.source.json"
  atomic_json cat-running-receipt.json "$CASE_DIR/cat-running-receipt.source.json"
  jq -S -c '{version:1,cat_id,node_id,runtime_incarnation,root_block_frontend}' \
    "$placement_snapshot" >"$CASE_DIR/create-placement-receipt.source.json"
  atomic_json create-placement-receipt.json \
    "$CASE_DIR/create-placement-receipt.source.json"
  rm -f "$CASE_DIR/cat-running-receipt.source.json"
  rm -f "$CASE_DIR/create-placement-receipt.source.json"
}

cat_id() {
  local state value
  state=$(nonsecret_path CATS_E3_RUNTIME_STATE)
  jq -e \
    --arg commit "$CATS_E3_EXACT_COMMIT" --arg block_path "$BLOCK_PATH" --arg run_id "$CATS_E3_RUN_ID" \
    '.version == 1 and .exact_commit == $commit and .block_path == $block_path and .run_id == $run_id' \
    "$state" >/dev/null || fail "runtime state coordinates do not match this exact run"
  value=$(json_field "$state" '.cat_id')
  canonical_id runtime_state_cat_id "$value"
  printf '%s' "$value"
}

run_control_startup() {
  local curl_bin origin health
  curl_bin=$(binary curl)
  origin=$(control_origin)
  health=$CASE_DIR/healthz
  "$curl_bin" --fail --silent --show-error --proto '=https' --tlsv1.2 \
    --max-time 10 --max-filesize 4096 --header 'accept-encoding: identity' \
    --output "$health" "$origin/healthz"
  jq -S -c -n \
    --arg exact_commit "$CATS_E3_EXACT_COMMIT" \
    --arg sha256 "$(sha256sum "$health" | awk '{print $1}')" \
    '{version:1,health_reachable:true,exact_commit:$exact_commit,response_sha256:$sha256}' \
    >"$CASE_DIR/health-release-receipt.source.json"
  atomic_json health-release-receipt.json "$CASE_DIR/health-release-receipt.source.json"
  rm -f "$CASE_DIR/health-release-receipt.source.json"
  # Health alone is not release identity. The canonical fleet command decodes
  # Control's exact release commit and the current full inventory.
  run_fleet_verify
}

run_probe() {
  local executable
  executable=$(binary runtime-e3-probe)
  "$executable" "$@"
}

run_guest_write() {
  local cat source expected_node
  cat=$(cat_id)
  expected_node=$(qualification_node_id)
  source=$CASE_DIR/durable-write-flush.source.json
  run_probe guest-sync --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" >"$source"
  jq -e \
    --arg cat "$cat" --arg node "$expected_node" --arg run_id "$CATS_E3_RUN_ID" \
    '.version == 1 and .cat_id == $cat and .run_id == $run_id
      and .node_id == $node
      and .strict_flush_remote_durable == true
      and .after_remote_generation > .before_remote_generation' \
    "$source" >/dev/null || fail "Guest write receipt lacks exact Strict remote proof"
  atomic_json durable-write-flush-receipt.json "$source"
  rm -f "$source"
}

install_route_workload() {
  local cat workload workload_sha256 source expected_node
  cat=$1
  expected_node=$(qualification_node_id)
  workload=$(binary e3-guest-workload)
  workload_sha256=$(binary_sha256 e3-guest-workload)
  source=$CASE_DIR/workload-install.source.json
  run_probe install-workload --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" \
    --workload "$workload" --workload-sha256 "$workload_sha256" --port 8080 >"$source"
  jq -e --arg cat "$cat" --arg node "$expected_node" --arg run_id "$CATS_E3_RUN_ID" \
    --arg workload_sha256 "$workload_sha256" \
    '.version == 1 and .cat_id == $cat and .node_id == $node and .run_id == $run_id
      and .port == 8080 and .workload_sha256 == $workload_sha256
      and .guest_reread_sha256 == $workload_sha256
      and .guest_file_fsynced == true
      and (.unit_main_pid | type == "string" and test("^[1-9][0-9]*$"))
      and (.path | type == "string" and startswith("/run/cats/"))
      and .unit_main_executable == .path
      and .installed == true' \
    "$source" >/dev/null || fail "Guest workload install receipt is not exact"
  atomic_json workload-install-receipt.json "$source"
  rm -f "$source"
}

probe_public_route() {
  local origin source attempt route_status
  origin=${CATS_E3_PUBLIC_ORIGIN:-https://$(required CATS_E3_ENDPOINT_HOSTNAME)}
  [[ $origin == "https://$(required CATS_E3_ENDPOINT_HOSTNAME)" ]] || \
    fail "CATS_E3_PUBLIC_ORIGIN must be the exact deployed endpoint origin"
  source=$CASE_DIR/public-route.source.json
  attempt=0
  route_status=1
  while [[ $attempt -lt 12 ]]; do
    attempt=$((attempt + 1))
    set +e
    run_probe public-route --origin "$origin" --run-id "$CATS_E3_RUN_ID" >"$source"
    route_status=$?
    set -e
    [[ $route_status -eq 0 ]] && break
    sleep 1
  done
  [[ $route_status -eq 0 ]] || fail "public endpoint did not reach the run-bound Guest workload"
  jq -e --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" \
    '.version == 1 and .origin == $origin and .run_id == $run_id
      and .http_guest_body == true and .websocket_guest_echo == true' \
    "$source" >/dev/null || fail "public route receipt lacks live Guest HTTP and WebSocket proof"
  atomic_json public-route-receipt.json "$source"
  rm -f "$source"
}

run_route() {
  local workspace cat body
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  install_route_workload "$cat"
  body=$CASE_DIR/endpoint-bind.json
  jq -S -c -n \
    --arg name "$(required CATS_E3_ENDPOINT_NAME)" \
    --arg hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" \
    '{name:$name,hostname:$hostname,target_port:8080}' >"$body"
  product_mutation POST "/v1/workspaces/$workspace/cats/$cat/endpoints" \
    "e3-$CATS_E3_RUN_ID-endpoint-$BLOCK_PATH" running "$body"
  probe_public_route
}

run_restart() {
  local cat systemctl_bin service installed_noded before after
  local before_fleet after_fleet before_invocation after_invocation before_pid after_pid
  local node_id expected_node before_agent_instance before_agent_epoch
  local attempt cat_state ready raw_status source
  cat=$(cat_id)
  systemctl_bin=$(binary systemctl)
  service=$(required CATS_E3_WORKER_SERVICE)
  [[ $service == cats-worker.service ]] || fail "installer receipt did not select exact cats-worker.service"
  installed_noded=$(nonsecret_path CATS_E3_INSTALLED_NODED_PATH)
  before=$CASE_DIR/restart-before.json
  after=$CASE_DIR/restart-after.json
  before_fleet=$CASE_DIR/restart-fleet-before.json
  after_fleet=$CASE_DIR/restart-fleet-after.json
  run_probe snapshot --cat-id "$cat" >"$before"
  node_id=$(json_field "$before" '.node_id')
  canonical_id checkpoint_node_id "$node_id"
  expected_node=$(qualification_node_id)
  [[ $node_id == "$expected_node" ]] || fail "runtime is not on the exact qualification Node"
  raw_fleet_snapshot_to "$before_fleet" || fail "pre-restart raw fleet snapshot is unavailable"
  jq -e --arg node "$node_id" '
    .desired_runtime_count == 1 and .current_runtime_observation_count == 1
    and ([.nodes[] | select(.node_id == $node)] | length == 1)
    and ([.nodes[] | select(.node_id == $node)][0] as $n
      | $n.session != null and $n.inventory != null
      and $n.inventory.complete_inventory == true
      and $n.inventory.assigned_desired_count == 1
      and $n.inventory.runtime_count == 1
      and $n.inventory.residue_count == 0
      and $n.inventory.source_session.node_id == $n.session.node_id
      and $n.inventory.source_session.node_boot_id == $n.session.node_boot_id
      and $n.inventory.source_session.agent_instance_id == $n.session.agent_instance_id
      and $n.inventory.source_session.agent_session_epoch == $n.session.agent_session_epoch
      and $n.inventory.attestation.agent_session_epoch == $n.session.agent_session_epoch)' \
    "$before_fleet" >/dev/null || fail "pre-restart inventory is not session-bound and complete"
  before_agent_instance=$(json_field "$before_fleet" ".nodes[] | select(.node_id == \"$node_id\") | .session.agent_instance_id")
  before_agent_epoch=$(json_field "$before_fleet" ".nodes[] | select(.node_id == \"$node_id\") | .session.agent_session_epoch")
  jq -S -c --arg node "$node_id" '
    [.nodes[] | select(.node_id == $node)][0] as $n
    | {version:1,node_id:$node,
       agent_instance_id:$n.session.agent_instance_id,
       agent_epoch:$n.session.agent_session_epoch,
       node_boot_id:$n.session.node_boot_id,
       lease_deadline_unix_ms:$n.session.lease_deadline_unix_ms,
       inventory_observation_id:$n.inventory.source_observation_id,
       inventory_complete:$n.inventory.complete_inventory,
       inventory_runtime_count:$n.inventory.runtime_count,
       inventory_residue_count:$n.inventory.residue_count,
       inventory_route_active_count:$n.inventory.route_active_count}' \
    "$before_fleet" >"$CASE_DIR/restart-fleet-before-receipt.source.json"
  atomic_json restart-fleet-before-receipt.json \
    "$CASE_DIR/restart-fleet-before-receipt.source.json"
  rm -f "$CASE_DIR/restart-fleet-before-receipt.source.json"
  before_invocation=$("$systemctl_bin" show --property=InvocationID --value "$service")
  [[ $before_invocation =~ ^[0-9a-f]{32}$ ]] || fail "Agent has no exact pre-restart InvocationID"
  before_pid=$("$systemctl_bin" show --property=MainPID --value "$service")
  [[ $before_pid =~ ^[1-9][0-9]*$ ]] || fail "cats-worker has no live pre-restart MainPID"
  [[ /proc/$before_pid/exe -ef $installed_noded ]] || \
    fail "cats-worker pre-restart MainPID is not the installed cats-noded"
  "$systemctl_bin" restart "$service"
  cat_state=$CASE_DIR/cat-after-restart.json
  attempt=0
  ready=false
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    if "$systemctl_bin" is-active --quiet "$service"; then
      after_pid=$("$systemctl_bin" show --property=MainPID --value "$service")
      if [[ $after_pid =~ ^[1-9][0-9]*$ && $after_pid != "$before_pid" ]]; then
        if [[ /proc/$after_pid/exe -ef $installed_noded ]]; then
          set +e
          raw_fleet_snapshot_to "$after_fleet"
          raw_status=$?
          set -e
          if [[ $raw_status -eq 0 ]] && jq -e -n \
            --arg node "$node_id" --arg before_instance "$before_agent_instance" \
            --argjson before_epoch "$before_agent_epoch" \
            --slurpfile before "$before_fleet" --slurpfile after "$after_fleet" '
            $after[0].desired_runtime_count == 1
            and $after[0].current_runtime_observation_count == 1
            and ([$after[0].nodes[] | select(.node_id == $node)] | length == 1)
            and ([$after[0].nodes[] | select(.node_id == $node)][0] as $a
              | [$before[0].nodes[] | select(.node_id == $node)][0] as $b
              | $a.session.agent_instance_id != $before_instance
              and $a.session.agent_session_epoch > $before_epoch
              and $a.session.node_boot_id == $b.session.node_boot_id
              and $a.session.lease_deadline_unix_ms > $after[0].evaluated_at_unix_ms
              and $a.inventory.complete_inventory == true
              and $a.inventory.assigned_desired_count == 1
              and $a.inventory.runtime_count == 1
              and $a.inventory.residue_count == 0
              and $a.inventory.source_session.node_id == $a.session.node_id
              and $a.inventory.source_session.node_boot_id == $a.session.node_boot_id
              and $a.inventory.source_session.agent_instance_id == $a.session.agent_instance_id
              and $a.inventory.source_session.agent_session_epoch == $a.session.agent_session_epoch
              and $a.inventory.attestation.agent_session_epoch == $a.session.agent_session_epoch
              and ($a.inventory.source_observation_id | type == "string" and length == 32)
              and $a.inventory.source_observation_id != $b.inventory.source_observation_id
              and $a.inventory.attestation.accepted_at_unix_ms <= $after[0].evaluated_at_unix_ms
              and $after[0].evaluated_at_unix_ms < ($a.inventory.attestation.accepted_at_unix_ms + 60000)
              and $a.inventory.route_active_count > 0
              and $a.inventory.active_guard_count == 0)' >/dev/null; then
            ready=true
            break
          fi
        fi
      fi
    fi
    sleep 0.5
  done
  [[ $ready == true ]] || fail "Agent restart did not produce a new session-bound complete inventory and active route gate"
  after_invocation=$("$systemctl_bin" show --property=InvocationID --value "$service")
  [[ $after_invocation =~ ^[0-9a-f]{32}$ && $after_invocation != "$before_invocation" ]] || \
    fail "systemctl restart did not create a fresh Agent invocation"
  run_cats --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" \
    --json get "$cat" >"$cat_state"
  jq -e '.desired.target == "running" and .observed.stable_state == "running"
    and (.observed.conditions | index("ready") != null)' "$cat_state" >/dev/null || \
    fail "new AgentSession did not produce a current Running/Ready Cat observation"
  run_probe snapshot --cat-id "$cat" >"$after"
  jq -e -n --arg node "$expected_node" --slurpfile before "$before" --slurpfile after "$after" \
    '$before[0].cat_id == $after[0].cat_id
      and $before[0].node_id == $node and $after[0].node_id == $node
      and $before[0].runtime_incarnation == $after[0].runtime_incarnation
      and $before[0].guest_boot_id == $after[0].guest_boot_id
      and $before[0].root_volume_id == $after[0].root_volume_id
      and $before[0].root_attachment_id == $after[0].root_attachment_id
      and $before[0].root_attachment_epoch == $after[0].root_attachment_epoch
      and $before[0].root_remote_head == $after[0].root_remote_head
      and $after[0].active_route_gate_count > 0
      and $after[0].strict_remote_durable == true' >/dev/null || \
    fail "Agent restart did not adopt the exact retained Running runtime"
  jq -S -c --arg node "$node_id" '
    [.nodes[] | select(.node_id == $node)][0] as $n
    | {version:1,node_id:$node,
       agent_instance_id:$n.session.agent_instance_id,
       agent_epoch:$n.session.agent_session_epoch,
       node_boot_id:$n.session.node_boot_id,
       lease_deadline_unix_ms:$n.session.lease_deadline_unix_ms,
       inventory_observation_id:$n.inventory.source_observation_id,
       inventory_complete:$n.inventory.complete_inventory,
       inventory_runtime_count:$n.inventory.runtime_count,
       inventory_residue_count:$n.inventory.residue_count,
       inventory_route_active_count:$n.inventory.route_active_count}' \
    "$after_fleet" >"$CASE_DIR/restart-fleet-after-receipt.source.json"
  atomic_json restart-fleet-after-receipt.json \
    "$CASE_DIR/restart-fleet-after-receipt.source.json"
  rm -f "$CASE_DIR/restart-fleet-after-receipt.source.json"
  source=$CASE_DIR/restart-guest-sync.source.json
  run_probe guest-sync --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" >"$source"
  jq -e --arg cat "$cat" --arg node "$expected_node" --arg run_id "$CATS_E3_RUN_ID" '
    .version == 1 and .cat_id == $cat and .node_id == $node and .run_id == $run_id
    and .strict_flush_remote_durable == true
    and .after_remote_generation > .before_remote_generation' "$source" >/dev/null || \
    fail "post-restart Guest write lacks exact Strict remote proof"
  atomic_json restart-guest-sync-receipt.json "$source"
  rm -f "$source"
  probe_public_route
  jq -S -c -n \
    --arg cat_id "$cat" --arg before_invocation "$before_invocation" \
    --arg after_invocation "$after_invocation" \
    --arg service "$service" --arg installed_noded "$installed_noded" \
    --arg before_pid "$before_pid" --arg after_pid "$after_pid" \
    --slurpfile before "$before" --slurpfile after "$after" \
    --slurpfile before_fleet "$before_fleet" --slurpfile after_fleet "$after_fleet" \
    '{version:1,cat_id:$cat_id,systemctl_restart:true,
      service:$service,installed_noded:$installed_noded,
      before_main_pid:$before_pid,after_main_pid:$after_pid,
      before_invocation_id:$before_invocation,after_invocation_id:$after_invocation,
      before_agent_instance_id:([$before_fleet[0].nodes[] | select(.node_id == $before[0].node_id)][0].session.agent_instance_id),
      before_agent_epoch:([$before_fleet[0].nodes[] | select(.node_id == $before[0].node_id)][0].session.agent_session_epoch),
      before_node_boot_id:([$before_fleet[0].nodes[] | select(.node_id == $before[0].node_id)][0].session.node_boot_id),
      after_agent_instance_id:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].session.agent_instance_id),
      after_agent_epoch:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].session.agent_session_epoch),
      after_node_boot_id:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].session.node_boot_id),
      after_inventory_observation_id:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].inventory.source_observation_id),
      after_inventory_complete:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].inventory.complete_inventory),
      after_route_active_count:([$after_fleet[0].nodes[] | select(.node_id == $after[0].node_id)][0].inventory.route_active_count),
      retained_runtime_incarnation:$after[0].runtime_incarnation,
      retained_guest_boot_id:$after[0].guest_boot_id,
      retained_root_remote_head:$after[0].root_remote_head,
      active_route_gate_count:$after[0].active_route_gate_count,
      post_restart_guest_sync:true,post_restart_public_http_ws:true,
      strict_remote_durable:$after[0].strict_remote_durable}' \
    >"$CASE_DIR/restart-adoption-receipt.source.json"
  atomic_json restart-adoption-receipt.json "$CASE_DIR/restart-adoption-receipt.source.json"
  rm -f "$CASE_DIR/restart-adoption-receipt.source.json"
}

qualification_operation_wait() {
  local operation_id=$1 expected_target=$2 output=$3 workspace
  workspace=$(required CATS_E3_WORKSPACE_ID)
  canonical_id qualification_operation_id "$operation_id"
  run_cats --api-url "$(control_origin)" --workspace "$workspace" --json \
    operation wait "$operation_id" >"$output"
  jq -e --arg operation "$operation_id" --arg workspace "$workspace" \
    --arg target "$expected_target" '
    .operation_id == $operation and .workspace_id == $workspace
    and .phase == "succeeded" and .target == $target
    and .terminal.kind == "succeeded"
    and .terminal.result.observed_target == $target' "$output" >/dev/null || \
    fail "qualification Operation lacks exact $expected_target settlement"
}

qualification_mutation_begin() {
  local method=$1 path=$2 key=$3 body=$4 response=$5 replay=$6
  local origin status attempt operation replay_operation revision replay_revision
  origin=$(control_origin)
  status=75
  for attempt in 1 2; do
    set +e
    if [[ -n $body ]]; then
      curl_json "$method" "$origin$path" "$response" 202 \
        --header "idempotency-key: $key" \
        --header 'content-type: application/json' --data-binary "@$body"
    else
      curl_json "$method" "$origin$path" "$response" 202 \
        --header "idempotency-key: $key"
    fi
    status=$?
    set -e
    [[ $status -eq 75 ]] || break
  done
  [[ $status -eq 0 ]] || fail "qualification mutation remained ambiguous after exact replay"
  operation=$(jq -er '.operation_id' "$response")
  revision=$(jq -er '.desired_revision' "$response")
  canonical_id qualification_operation_id "$operation"
  [[ $revision =~ ^[1-9][0-9]*$ ]] || fail "qualification mutation revision is invalid"
  if [[ -n $body ]]; then
    curl_json "$method" "$origin$path" "$replay" 202 \
      --header "idempotency-key: $key" \
      --header 'content-type: application/json' --data-binary "@$body" || \
      fail "qualification mutation replay was ambiguous"
  else
    curl_json "$method" "$origin$path" "$replay" 202 \
      --header "idempotency-key: $key" || \
      fail "qualification mutation replay was ambiguous"
  fi
  replay_operation=$(jq -er '.operation_id' "$replay")
  replay_revision=$(jq -er '.desired_revision' "$replay")
  [[ $replay_operation == "$operation" && $replay_revision == "$revision" ]] || \
    fail "qualification mutation replay changed Operation or Desired revision"
  printf '%s' "$operation"
}

qualification_mutation_wait() {
  local method=$1 path=$2 key=$3 target=$4 body=$5 prefix=$6
  local response replay operation result
  response=$CASE_DIR/$prefix-response.json
  replay=$CASE_DIR/$prefix-replay.json
  result=$CASE_DIR/$prefix-operation.json
  operation=$(qualification_mutation_begin \
    "$method" "$path" "$key" "$body" "$response" "$replay")
  qualification_operation_wait "$operation" "$target" "$result"
  rm -f "$response" "$replay" "$result"
}

run_volume_init_matrix() {
  local workspace cat expected_node root_snapshot disk_create disk_name disk_id volume_id
  local mount_path attach_body watcher watcher_pid start_response start_replay start_operation
  local start_result initialization before_fleet after_fleet before_snapshot after_snapshot
  local systemctl_bin service before_epoch after_epoch attempt ready raw_status
  local strict_sync cold_absence final_fleet receipt_source delete_response delete_replay
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  expected_node=$(qualification_node_id)
  mount_path=${CATS_E3_PERSISTENT_MOUNT_PATH:-/mnt/cats-e3-persistent}
  [[ $mount_path == /* && $mount_path != / && $mount_path != *$'\n'* ]] || \
    fail "Persistent qualification mount path is not absolute non-root"

  root_snapshot=$CASE_DIR/persistent-root-frontend.json
  run_probe snapshot --cat-id "$cat" >"$root_snapshot"
  jq -e --arg cat "$cat" --arg node "$expected_node" --arg block_path "$BLOCK_PATH" '
    .version == 1 and .cat_id == $cat and .node_id == $node
    and .root_block_frontend == $block_path and .strict_remote_durable == true' \
    "$root_snapshot" >/dev/null || \
    fail "installed Running checkpoint does not use the selected block frontend"
  rm -f "$root_snapshot"

  qualification_mutation_wait POST \
    "/v1/workspaces/$workspace/cats/$cat/actions/stop" \
    "e3-$CATS_E3_RUN_ID-persistent-pre-stop-$BLOCK_PATH" cold '' persistent-pre-stop

  disk_name="e3-persistent-$CATS_E3_RUN_ID"
  disk_create=$CASE_DIR/persistent-disk-create.json
  run_cats --api-url "$(control_origin)" --workspace "$workspace" --json \
    disk create "$disk_name" --size "${CATS_E3_PERSISTENT_SIZE:-1GiB}" \
    --durability strict >"$disk_create"
  jq -e --arg workspace "$workspace" --arg name "$disk_name" '
    .workspace_id == $workspace and .name == $name and .kind == "persistent"
    and .state == "available" and .durability == "strict"
    and (.id | type == "string" and startswith("disk_"))
    and (.volume_id | type == "string" and startswith("vol_"))' \
    "$disk_create" >/dev/null || fail "PersistentDisk create response is not exact"
  disk_id=$(json_field "$disk_create" '.id')
  volume_id=$(json_field "$disk_create" '.volume_id')
  canonical_id persistent_disk_id "$disk_id"
  canonical_id persistent_volume_id "$volume_id"

  attach_body=$CASE_DIR/persistent-attach-body.json
  jq -S -c -n --arg cat_id "$cat" --arg mount_path "$mount_path" \
    '{cat_id:$cat_id,mount_path:$mount_path}' >"$attach_body"
  qualification_mutation_wait POST \
    "/v1/workspaces/$workspace/disks/$disk_id/actions/attach" \
    "e3-$CATS_E3_RUN_ID-persistent-attach-$BLOCK_PATH" cold "$attach_body" persistent-attach

  watcher=$CASE_DIR/persistent-initialization-watch.json
  run_probe watch-persistent-initialization --cat-id "$cat" --disk-id "$disk_id" \
    --volume-id "$volume_id" --mount-path "$mount_path" --run-id "$CATS_E3_RUN_ID" \
    --timeout-seconds 300 >"$watcher" &
  watcher_pid=$!
  QUALIFICATION_WATCHER_PID=$watcher_pid
  start_response=$CASE_DIR/persistent-start-response.json
  start_replay=$CASE_DIR/persistent-start-replay.json
  start_result=$CASE_DIR/persistent-start-operation.json
  start_operation=$(qualification_mutation_begin POST \
    "/v1/workspaces/$workspace/cats/$cat/actions/start" \
    "e3-$CATS_E3_RUN_ID-persistent-start-$BLOCK_PATH" '' \
    "$start_response" "$start_replay")
  qualification_operation_wait "$start_operation" running "$start_result"
  if ! wait "$watcher_pid"; then
    QUALIFICATION_WATCHER_PID=
    fail "Persistent initialization watcher did not prove first-format recovery"
  fi
  QUALIFICATION_WATCHER_PID=
  rm -f "$start_response" "$start_replay" "$start_result"
  initialization=$watcher
  jq -e --arg cat "$cat" --arg disk "$disk_id" --arg volume "$volume_id" \
    --arg node "$expected_node" --arg mount "$mount_path" --arg block_path "$BLOCK_PATH" '
    .version == 1 and .cat_id == $cat and .disk_id == $disk and .volume_id == $volume
    and (.volume_intent_id | type == "string" and length > 0)
    and (.attachment_id | type == "string" and length > 0)
    and (.attachment_epoch | type == "number" and . > 0)
    and (.guest_device.serial | type == "string" and length > 0)
    and (.guest_device.slot | type == "string" and length > 0)
    and (.filesystem_uuid | type == "string" and length > 0)
    and .mount_path == $mount
    and (.expected_blank_head | type == "string" and length > 0)
    and (.initialized_head | type == "string" and length > 0)
    and .initialized_head != .expected_blank_head
    and .first_format.ambiguous_response_discovered == true
    and .first_format.mkfs_invocations == 1
    and .first_format.fault_action == "drop_validated_format_response_once"
    and .first_format.consumed == true
    and (.first_format.artifact_sha256 | test("^[0-9a-f]{64}$"))
    and .ready.node_id == $node and .ready.block_frontend == $block_path
    and .ready.filesystem_uuid == .filesystem_uuid and .ready.mount_path == $mount
    and .ready.mounted_set_complete == true and .ready.strict_remote_durable == true' \
    "$initialization" >/dev/null || fail "Persistent first-format/A22/Ready proof is not exact"

  before_fleet=$CASE_DIR/persistent-restart-fleet-before.json
  after_fleet=$CASE_DIR/persistent-restart-fleet-after.json
  before_snapshot=$CASE_DIR/persistent-restart-before.json
  after_snapshot=$CASE_DIR/persistent-restart-after.json
  raw_fleet_snapshot_to "$before_fleet" || fail "pre-restart Persistent fleet snapshot unavailable"
  run_probe persistent-snapshot --cat-id "$cat" --disk-id "$disk_id" \
    --volume-id "$volume_id" --mount-path "$mount_path" >"$before_snapshot"
  jq -e --arg node "$expected_node" '
    ([.nodes[] | select(.node_id == $node)] | length == 1)
    and ([.nodes[] | select(.node_id == $node)][0] as $n
      | $n.inventory.complete_inventory == true
      and $n.inventory.source_session.agent_session_epoch == $n.session.agent_session_epoch
      and $n.inventory.attestation.agent_session_epoch == $n.session.agent_session_epoch
      and $n.inventory.residue_count == 0 and $n.inventory.active_guard_count == 0)' \
    "$before_fleet" >/dev/null || fail "pre-restart full inventory is not exact"
  before_epoch=$(json_field "$before_fleet" ".nodes[] | select(.node_id == \"$expected_node\") | .session.agent_session_epoch")
  [[ $before_epoch =~ ^[1-9][0-9]*$ ]] || fail "pre-restart AgentSession epoch is invalid"
  systemctl_bin=$(binary systemctl)
  service=$(required CATS_E3_WORKER_SERVICE)
  [[ $service == cats-worker.service ]] || fail "Persistent restart service is not cats-worker.service"
  "$systemctl_bin" restart "$service"
  attempt=0
  ready=false
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    set +e
    raw_fleet_snapshot_to "$after_fleet"
    raw_status=$?
    set -e
    if [[ $raw_status -eq 0 ]] && jq -e --arg node "$expected_node" \
      --argjson before "$before_epoch" '
      ([.nodes[] | select(.node_id == $node)] | length == 1)
      and ([.nodes[] | select(.node_id == $node)][0] as $n
        | $n.session.agent_session_epoch > $before
        and $n.inventory.complete_inventory == true
        and $n.inventory.source_session.agent_session_epoch == $n.session.agent_session_epoch
        and $n.inventory.attestation.agent_session_epoch == $n.session.agent_session_epoch
        and $n.inventory.residue_count == 0 and $n.inventory.active_guard_count == 0)' \
      "$after_fleet" >/dev/null; then
      set +e
      run_probe persistent-snapshot --cat-id "$cat" --disk-id "$disk_id" \
        --volume-id "$volume_id" --mount-path "$mount_path" >"$after_snapshot"
      raw_status=$?
      set -e
      if [[ $raw_status -eq 0 ]]; then
        ready=true
        break
      fi
    fi
    sleep 0.5
  done
  [[ $ready == true ]] || fail "Agent restart did not adopt exact Persistent runtime"
  after_epoch=$(json_field "$after_fleet" ".nodes[] | select(.node_id == \"$expected_node\") | .session.agent_session_epoch")
  jq -e -n --slurpfile initial "$initialization" --slurpfile before "$before_snapshot" \
    --slurpfile after "$after_snapshot" '
    $before[0].runtime_incarnation == $initial[0].ready.runtime_incarnation
    and $after[0].runtime_incarnation == $before[0].runtime_incarnation
    and $before[0].guest_boot_id == $initial[0].ready.guest_boot_id
    and $after[0].guest_boot_id == $before[0].guest_boot_id
    and $after[0].attachment_id == $before[0].attachment_id
    and $after[0].attachment_epoch == $before[0].attachment_epoch
    and $after[0].filesystem_uuid == $before[0].filesystem_uuid
    and $after[0].mount_path == $before[0].mount_path
    and $after[0].mounted_set_complete == true
    and $after[0].strict_remote_durable == true' >/dev/null || \
    fail "restart changed Persistent runtime/boot/attachment/filesystem/mount identity"

  strict_sync=$CASE_DIR/persistent-strict-sync.json
  run_probe persistent-sync --cat-id "$cat" --disk-id "$disk_id" \
    --volume-id "$volume_id" --mount-path "$mount_path" --run-id "$CATS_E3_RUN_ID" \
    >"$strict_sync"
  jq -e --arg disk "$disk_id" --arg volume "$volume_id" '
    .version == 1 and .disk_id == $disk and .volume_id == $volume
    and .remote_durable == true and .after_remote_generation > .before_remote_generation
    and (.before_head | type == "string" and length > 0)
    and (.after_head | type == "string" and length > 0)
    and .after_head != .before_head' \
    "$strict_sync" >/dev/null || fail "Persistent Strict FLUSH did not advance remote head"

  qualification_mutation_wait POST \
    "/v1/workspaces/$workspace/cats/$cat/actions/stop" \
    "e3-$CATS_E3_RUN_ID-persistent-stop-$BLOCK_PATH" cold '' persistent-stop
  qualification_mutation_wait POST \
    "/v1/workspaces/$workspace/disks/$disk_id/actions/detach" \
    "e3-$CATS_E3_RUN_ID-persistent-detach-$BLOCK_PATH" cold "$attach_body" persistent-detach

  cold_absence=$CASE_DIR/persistent-cold-absence.json
  run_probe persistent-cold-absence --cat-id "$cat" --disk-id "$disk_id" \
    --volume-id "$volume_id" --mount-path "$mount_path" >"$cold_absence"
  jq -e --arg cat "$cat" --arg node "$expected_node" --arg disk "$disk_id" \
    --arg volume "$volume_id" '
    .version == 1 and .cat_id == $cat and .node_id == $node
    and .disk_id == $disk and .volume_id == $volume and .stable_cold == true
    and .desired_volume_absent == true and .device_absent == true and .mount_absent == true' \
    "$cold_absence" >/dev/null || fail "detached Persistent resources remain in Cold checkpoint"
  final_fleet=$CASE_DIR/persistent-final-fleet.json
  raw_fleet_snapshot_to "$final_fleet" || fail "post-detach fleet snapshot unavailable"
  jq -e --arg node "$expected_node" --argjson restart_epoch "$after_epoch" '
    ([.nodes[] | select(.node_id == $node)] | length == 1)
    and ([.nodes[] | select(.node_id == $node)][0] as $n
      | $n.session.agent_session_epoch >= $restart_epoch
      and $n.inventory.complete_inventory == true
      and $n.inventory.lifecycle_open_count == 0
      and $n.inventory.route_active_count == 0
      and $n.inventory.active_guard_count == 0
      and $n.inventory.residue_count == 0)' "$final_fleet" >/dev/null || \
    fail "post-detach full inventory is not complete, closed and residue-free"

  receipt_source=$CASE_DIR/persistent-disk-receipt.source.json
  jq -S -c -n --arg workspace "$workspace" --arg cat "$cat" --arg node "$expected_node" \
    --arg disk "$disk_id" --arg volume "$volume_id" --arg block_path "$BLOCK_PATH" \
    --argjson before_epoch "$before_epoch" --argjson after_epoch "$after_epoch" \
    --slurpfile init "$initialization" --slurpfile before "$before_snapshot" \
    --slurpfile after "$after_snapshot" --slurpfile flush "$strict_sync" \
    --slurpfile absent "$cold_absence" --slurpfile fleet "$final_fleet" '
    ([$fleet[0].nodes[] | select(.node_id == $node)][0]) as $final
    | {version:1,proof:"persistent_disk_attach_initialize_restart_detach",
       block_path:$block_path,workspace_id:$workspace,cat_id:$cat,node_id:$node,
       disk_id:$disk,volume_id:$volume,
       volume_intent_id:$init[0].volume_intent_id,
       attachment_id:$init[0].attachment_id,
       attachment_epoch:$init[0].attachment_epoch,
       guest_device:$init[0].guest_device,
       filesystem_uuid:$init[0].filesystem_uuid,mount_path:$init[0].mount_path,
       expected_blank_head:$init[0].expected_blank_head,
       initialized_head:$init[0].initialized_head,
       first_format:$init[0].first_format,
       ready:{runtime_incarnation:$init[0].ready.runtime_incarnation,
         guest_boot_id:$init[0].ready.guest_boot_id,
         device_path:$init[0].ready.device_path,mounted_set_complete:true},
       restart:{before_agent_session_epoch:$before_epoch,
         after_agent_session_epoch:$after_epoch,
         retained_runtime_incarnation:$after[0].runtime_incarnation,
         retained_guest_boot_id:$after[0].guest_boot_id,
         filesystem_uuid:$after[0].filesystem_uuid,mount_path:$after[0].mount_path},
       strict_flush:{before_head:$flush[0].before_head,after_head:$flush[0].after_head,
         remote_durable:$flush[0].remote_durable},
       detach:{desired_volume_absent:$absent[0].desired_volume_absent,
         authority_unowned:true,device_absent:$absent[0].device_absent,
         mount_absent:$absent[0].mount_absent},
       final_inventory:{node_id:$node,agent_session_epoch:$final.session.agent_session_epoch,
         complete:$final.inventory.complete_inventory,gates_closed:true,
         active_guard_count:$final.inventory.active_guard_count,
         residue_count:$final.inventory.residue_count}}' >"$receipt_source"
  jq -e --arg block_path "$BLOCK_PATH" --arg workspace "$workspace" --arg cat "$cat" \
    --arg node "$expected_node" --arg disk "$disk_id" --arg volume "$volume_id" '
    keys == ["attachment_epoch","attachment_id","block_path","cat_id","detach","disk_id",
      "expected_blank_head","filesystem_uuid","final_inventory","first_format","guest_device",
      "initialized_head","mount_path","node_id","proof","ready","restart","strict_flush",
      "version","volume_id","volume_intent_id","workspace_id"]
    and .version == 1 and .proof == "persistent_disk_attach_initialize_restart_detach"
    and .block_path == $block_path and .workspace_id == $workspace and .cat_id == $cat
    and .node_id == $node and .disk_id == $disk and .volume_id == $volume
    and (.volume_intent_id | type == "string" and length > 0)
    and (.attachment_id | type == "string" and length > 0)
    and (.attachment_epoch | type == "number" and . > 0 and floor == .)
    and (.guest_device | keys == ["serial","slot"])
    and (.guest_device.serial | type == "string" and length > 0)
    and (.guest_device.slot | type == "string" and length > 0)
    and (.filesystem_uuid | type == "string" and length > 0)
    and (.mount_path | type == "string" and startswith("/") and . != "/")
    and (.expected_blank_head | type == "string" and length > 0)
    and (.initialized_head | type == "string" and length > 0)
    and .initialized_head != .expected_blank_head
    and (.first_format | keys == ["ambiguous_response_discovered","artifact_sha256",
      "consumed","fault_action","mkfs_invocations"])
    and .first_format == {ambiguous_response_discovered:true,
      artifact_sha256:.first_format.artifact_sha256,consumed:true,
      fault_action:"drop_validated_format_response_once",mkfs_invocations:1}
    and (.first_format.artifact_sha256 | test("^[0-9a-f]{64}$"))
    and (.ready | keys == ["device_path","guest_boot_id","mounted_set_complete",
      "runtime_incarnation"])
    and (.ready.runtime_incarnation | type == "string" and length > 0)
    and (.ready.guest_boot_id | type == "string" and length > 0)
    and (.ready.device_path | type == "string" and startswith("/"))
    and .ready.mounted_set_complete == true
    and (.restart | keys == ["after_agent_session_epoch","before_agent_session_epoch",
      "filesystem_uuid","mount_path","retained_guest_boot_id","retained_runtime_incarnation"])
    and .restart.after_agent_session_epoch > .restart.before_agent_session_epoch
    and .restart.retained_runtime_incarnation == .ready.runtime_incarnation
    and .restart.retained_guest_boot_id == .ready.guest_boot_id
    and .restart.filesystem_uuid == .filesystem_uuid and .restart.mount_path == .mount_path
    and (.strict_flush | keys == ["after_head","before_head","remote_durable"])
    and (.strict_flush.before_head | type == "string" and length > 0)
    and (.strict_flush.after_head | type == "string" and length > 0)
    and .strict_flush.after_head != .strict_flush.before_head
    and .strict_flush.remote_durable == true
    and .detach == {authority_unowned:true,desired_volume_absent:true,
      device_absent:true,mount_absent:true}
    and (.final_inventory | keys == ["active_guard_count","agent_session_epoch","complete",
      "gates_closed","node_id","residue_count"])
    and .final_inventory.node_id == $node and .final_inventory.complete == true
    and .final_inventory.gates_closed == true and .final_inventory.active_guard_count == 0
    and .final_inventory.residue_count == 0
    and .final_inventory.agent_session_epoch >= .restart.after_agent_session_epoch' \
    "$receipt_source" >/dev/null || fail "Persistent receipt is outside its frozen closed schema"
  atomic_json persistent-disk-receipt.json "$receipt_source"

  delete_response=$CASE_DIR/persistent-delete-response.json
  delete_replay=$CASE_DIR/persistent-delete-replay.json
  curl_json DELETE "$(control_origin)/v1/workspaces/$workspace/disks/$disk_id" \
    "$delete_response" 202 --header "idempotency-key: e3-$CATS_E3_RUN_ID-persistent-delete-$BLOCK_PATH" || \
    fail "detached qualification Disk delete was ambiguous"
  curl_json DELETE "$(control_origin)/v1/workspaces/$workspace/disks/$disk_id" \
    "$delete_replay" 202 --header "idempotency-key: e3-$CATS_E3_RUN_ID-persistent-delete-$BLOCK_PATH" || \
    fail "detached qualification Disk delete replay was ambiguous"
  cmp -s "$delete_response" "$delete_replay" || fail "Disk delete replay changed result"

  # Restore the numbered suite's Cat to Running only after the exact detached
  # Cold receipt has been sealed; later usage and delete cases retain ownership.
  qualification_mutation_wait POST \
    "/v1/workspaces/$workspace/cats/$cat/actions/start" \
    "e3-$CATS_E3_RUN_ID-persistent-restore-$BLOCK_PATH" running '' persistent-restore
  rm -f "$disk_create" "$attach_body" "$initialization" "$before_fleet" "$after_fleet" \
    "$before_snapshot" "$after_snapshot" "$strict_sync" "$cold_absence" "$final_fleet" \
    "$receipt_source" "$delete_response" "$delete_replay"
}

usage_report_to() {
  local destination=$1 workspace=$2 cat=$3 from_ms=$4 to_ms=$5
  curl_json GET \
    "$(control_origin)/v1/workspaces/$workspace/billing/usage?from_ms=$from_ms&to_ms=$to_ms&cat_id=$cat&detail=true" \
    "$destination" 200 || return $?
  jq -e --arg workspace "$workspace" '
    .workspace_id == $workspace and .status == "provisional"
    and (.details | type == "array")' "$destination" >/dev/null || \
    fail "usage projection is not the canonical workspace report"
}

usage_source_keys_to() {
  local report=$1 destination=$2 cat=$3
  jq -c --arg cat "$cat" '
    [.details[]
      | select(.attributed_cat_id == $cat
        and (.source_id | type == "string"
          and startswith("node/") and endswith("/cat/" + $cat))
        and (.source_epoch | type == "string" and length > 0)
        and (.metric == "cpu_usec" or .metric == "memory_byte_millis"))
      | {source_id,source_epoch}]
    | sort_by([.source_id,.source_epoch])
    | unique_by([.source_id,.source_epoch])' "$report" >"$destination"
}

discover_usage_source_terminal() {
  local source_id=$1 source_epoch=$2 destination=$3 request attempt request_status
  request=$CASE_DIR/usage-source-terminal-discover.request.json
  jq -c -n --arg source_id "$source_id" --arg source_epoch "$source_epoch" \
    '{source_id:$source_id,source_epoch:$source_epoch}' >"$request"
  for attempt in 1 2; do
    set +e
    curl_json POST \
      "$(control_origin)/v1/admin/usage/source-terminal/discover" \
      "$destination" 200,404 \
      --header 'content-type: application/json' --data-binary "@$request"
    request_status=$?
    set -e
    [[ $request_status -eq 75 ]] && continue
    [[ $request_status -eq 0 ]] || fail "source terminal discovery failed"
    case "$CURL_JSON_STATUS" in
      200)
        jq -e --arg source_id "$source_id" --arg source_epoch "$source_epoch" '
          (keys == ["cat_id","contract_version","final_events",
            "final_observed_at_unix_ms","final_sequence","source_binding",
            "source_epoch","source_id"])
          and .contract_version == 1
          and .source_id == $source_id and .source_epoch == $source_epoch
          and (.cat_id | type == "string" and length > 0)
          and (.source_binding | keys == ["agent_epoch","agent_instance_id",
            "desired_revision","node_boot_id","node_id","runtime_incarnation"])
          and (.final_sequence | type == "number" and . >= 0 and floor == .)
          and (.final_observed_at_unix_ms | type == "number" and . >= 0 and floor == .)
          and (.final_events | type == "array" and length == 2)
          and ([.final_events[].metric] == ["cpu_usec","memory_byte_millis"])
          and all(.final_events[];
            keys == ["archive","cumulative_quantity","event_id","metric"]
            and (.event_id | type == "string" and length > 0)
            and (.cumulative_quantity | type == "number" and . >= 0 and floor == .)
            and (.archive | keys == ["archive_bucket","archive_key","archive_sha256",
              "sequence_number","shard_id","stream_name"])
            and (.archive.sequence_number | test("^(0|[1-9][0-9]{0,77})$"))
            and (.archive.archive_sha256 | test("^sha256:[0-9a-f]{64}$"))))' \
          "$destination" >/dev/null || fail "source terminal receipt has a foreign shape"
        rm -f "$request"
        return 0
        ;;
      404)
        rm -f "$destination" "$request"
        return 1
        ;;
      *) fail "source terminal discovery returned an unexpected status" ;;
    esac
  done
  rm -f "$request"
  return 75
}

run_usage_source_terminals() {
  local cat workspace from_ms to_ms report keys previous_keys receipt_dir sources_work
  local attempt stable all_terminal index source_id source_epoch receipt receipt_sha256
  local sources_json source_set_sha256 selected_source_id selected_source_epoch
  local selected_index selected_receipt live_source aggregate_source ready
  cat=$(cat_id)
  workspace=$(required CATS_E3_WORKSPACE_ID)
  from_ms=$(required CATS_E3_RUN_STARTED_AT_UNIX_MS)
  [[ $from_ms =~ ^[1-9][0-9]{12}$ ]] || fail "run start is not canonical Unix milliseconds"
  to_ms=$(( $(date +%s) * 1000 + 60000 ))
  report=$CASE_DIR/usage-run-window.json
  keys=$CASE_DIR/usage-source-keys.json
  previous_keys=$CASE_DIR/usage-source-keys.previous.json
  receipt_dir=$CASE_DIR/source-terminal-receipts
  sources_work=$CASE_DIR/usage-terminal-sources.jsonl
  mkdir -m 0700 "$receipt_dir"
  : >"$sources_work"

  # Product deletion and the framework EndQualification/Closed hook have
  # already drained every Usage writer. Poll only previously produced records
  # from this exact run window; do not manufacture a post-delete sample.
  stable=0
  ready=false
  attempt=0
  while [[ $attempt -lt 120 ]]; do
    attempt=$((attempt + 1))
    to_ms=$(( $(date +%s) * 1000 + 60000 ))
    if ! usage_report_to "$report" "$workspace" "$cat" "$from_ms" "$to_ms"; then
      sleep 2
      continue
    fi
    usage_source_keys_to "$report" "$keys" "$cat"
    if [[ $(jq 'length' "$keys") -eq 0 ]]; then
      stable=0
      sleep 2
      continue
    fi
    : >"$sources_work"
    all_terminal=true
    index=0
    while IFS=$'\t' read -r source_id source_epoch; do
      receipt=$receipt_dir/source-$index.json
      if ! discover_usage_source_terminal "$source_id" "$source_epoch" "$receipt"; then
        all_terminal=false
        break
      fi
      receipt_sha256=sha256:$(sha256sum "$receipt" | awk '{print $1}')
      jq -c -n --arg source_id "$source_id" --arg source_epoch "$source_epoch" \
        --arg receipt_sha256 "$receipt_sha256" \
        '{source_id:$source_id,source_epoch:$source_epoch,receipt_sha256:$receipt_sha256}' \
        >>"$sources_work"
      index=$((index + 1))
    done < <(jq -r '.[] | [.source_id,.source_epoch] | @tsv' "$keys")
    if [[ $all_terminal == true && -f $previous_keys ]] && cmp -s "$keys" "$previous_keys"; then
      stable=$((stable + 1))
    else
      stable=0
    fi
    cp "$keys" "$previous_keys"
    if [[ $all_terminal == true && $stable -ge 2 ]]; then
      ready=true
      break
    fi
    sleep 2
  done
  [[ $ready == true ]] || \
    fail "run-bound Usage source set did not become stably terminal"

  # Select one already-produced complete nonzero pair for the live-delivery
  # receipt. The source terminal artifact below must close this exact pair.
  live_source=$CASE_DIR/usage-live-delivery-receipt.source.json
  jq -c --arg workspace "$workspace" --arg cat "$cat" --arg run_id "$CATS_E3_RUN_ID" \
    --argjson from_ms "$from_ms" --argjson to_ms "$to_ms" '
    [.details[]
      | select(.attributed_cat_id == $cat
        and (.source_id | startswith("node/") and endswith("/cat/" + $cat))
        and (.source_epoch | type == "string" and length > 0)
        and (.metric == "cpu_usec" or .metric == "memory_byte_millis")
        and (.quantity | test("^(0|[1-9][0-9]*)$")))]
    | sort_by([.source_id,.source_epoch,.end_sequence,.metric])
    | group_by([.source_id,.source_epoch,.end_sequence])
    | map(select(length == 2
        and ([.[].metric] | sort) == ["cpu_usec","memory_byte_millis"]
        and any(.[]; .quantity != "0")))
    | sort_by([.[0].interval_end_unix_ms,.[0].source_id,.[0].source_epoch,.[0].end_sequence])
    | last as $pair
    | if $pair == null then error("no complete nonzero run-bound meter pair") else
      {version:1,proof:"sampler_spool_signed_ingest_projection",
       run_id:$run_id,run_window_from_unix_ms:$from_ms,run_window_to_unix_ms:$to_ms,
       workspace_id:$workspace,cat_id:$cat,source_id:$pair[0].source_id,
       source_epoch:$pair[0].source_epoch,end_sequence:$pair[0].end_sequence,
       interval_end_unix_ms:$pair[0].interval_end_unix_ms,
       metrics:[$pair[] | {metric,quantity,unit}],
       durable_spool_on_delivery_path:true,exact_current_agent_binding_required:true,
       spool_absence_used_as_authority:false,source_terminal_receipt_proved:true}
      end' "$report" >"$live_source" || \
    fail "run window has no previously produced complete nonzero Usage pair"
  selected_source_id=$(jq -er '.source_id' "$live_source")
  selected_source_epoch=$(jq -er '.source_epoch' "$live_source")
  selected_index=$(jq -er --arg source_id "$selected_source_id" --arg source_epoch "$selected_source_epoch" '
    to_entries[] | select(.value.source_id == $source_id and .value.source_epoch == $source_epoch)
    | .key' "$keys")
  [[ $selected_index =~ ^[0-9]+$ ]] || fail "live Usage pair is outside the terminal source set"
  selected_receipt=$receipt_dir/source-$selected_index.json
  receipt_sha256=sha256:$(sha256sum "$selected_receipt" | awk '{print $1}')
  jq --arg receipt_sha256 "$receipt_sha256" \
    '. + {source_terminal_receipt_sha256:$receipt_sha256}' "$live_source" \
    >"$CASE_DIR/usage-live-delivery-receipt.bound.json"
  atomic_json usage-live-delivery-receipt.json \
    "$CASE_DIR/usage-live-delivery-receipt.bound.json"

  sources_json=$(jq -s -c '
    sort_by([.source_id,.source_epoch])
    | map({source_id:.source_id,source_epoch:.source_epoch,receipt_sha256:.receipt_sha256})' \
    "$sources_work")
  source_set_sha256=sha256:$(printf '%s' "$sources_json" | sha256sum | awk '{print $1}')
  aggregate_source=$CASE_DIR/usage-source-terminal-receipts.source.json
  jq -S -c -n \
    --arg block_path "$BLOCK_PATH" \
    --arg cat_id "$cat" \
    --arg qualification_catalog_sha256 "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
    --arg release_commit "$CATS_E3_EXACT_COMMIT" \
    --arg run_id "$CATS_E3_RUN_ID" \
    --argjson run_window_from_unix_ms "$from_ms" \
    --argjson run_window_to_unix_ms "$to_ms" \
    --arg source_set_sha256 "$source_set_sha256" \
    --argjson sources "$sources_json" \
    --arg worker_bundle_sha256 "sha256:$(required CATS_E3_WORKER_BUNDLE_SHA256)" \
    --arg workspace_id "$workspace" '
    {block_path:$block_path,cat_id:$cat_id,
     kind:"cats.usage-source-terminal-receipts.v1",
     qualification_catalog_sha256:$qualification_catalog_sha256,
     release_commit:$release_commit,run_id:$run_id,
     run_window_from_unix_ms:$run_window_from_unix_ms,
     run_window_to_unix_ms:$run_window_to_unix_ms,
     source_set_sha256:$source_set_sha256,sources:$sources,version:1,
     worker_bundle_sha256:$worker_bundle_sha256,workspace_id:$workspace_id}' \
    >"$aggregate_source"
  atomic_json usage-source-terminal-receipts.json "$aggregate_source"

  rm -rf "$receipt_dir"
  rm -f "$sources_work" "$previous_keys" \
    "$CASE_DIR/usage-live-delivery-receipt.bound.json" \
    "$aggregate_source" "$live_source" "$report" "$keys"
  printf 'USAGE_SOURCE_TERMINAL_RECEIPTS source_count=%s source_set_sha256=%s\n' \
    "$(jq 'length' <<<"$sources_json")" "$source_set_sha256"
}

run_delete() {
  local workspace cat
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  product_mutation DELETE "/v1/workspaces/$workspace/cats/$cat" \
    "e3-$CATS_E3_RUN_ID-delete-$BLOCK_PATH" deleted
  run_fleet_verify
}

run_case() {
  case "$CASE_ID" in
    control-startup-schema) run_control_startup ;;
    node-registration-full-inventory) run_fleet_verify ;;
    cat-create-running) run_create ;;
    durable-write-flush) run_guest_write ;;
    route-http-ws) run_route ;;
    agent-restart-adoption) run_restart ;;
    volume-init-matrix) run_volume_init_matrix ;;
    usage-source-terminal-receipts) run_usage_source_terminals ;;
    delete-cleanup) run_delete ;;
    *) fail "unknown scenario case $CASE_ID" ;;
  esac
}

diagnostics() {
  local journalctl_bin service
  journalctl_bin=$(binary journalctl)
  service=$(required CATS_E3_WORKER_SERVICE)
  [[ $service == cats-worker.service ]] || fail "diagnostics service is not installer-bound"
  "$journalctl_bin" --no-pager --output=short-monotonic --lines=200 --unit "$service" || true
}

cleanup() {
  local policy source cat expected_node
  policy=observation_only
  if [[ $CASE_ID == route-http-ws ]]; then
    policy=retained_run_bound_guest_workload_for_agent_restart
  elif [[ $CASE_ID == agent-restart-adoption ]]; then
    cat=$(cat_id)
    expected_node=$(qualification_node_id)
    source=$CASE_DIR/workload-remove.source.json
    run_probe remove-workload --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" >"$source"
    jq -e --arg cat "$cat" --arg node "$expected_node" --arg run_id "$CATS_E3_RUN_ID" \
      '.version == 1 and .cat_id == $cat and .node_id == $node and .run_id == $run_id and .removed == true' \
      "$source" >/dev/null || fail "Guest workload cleanup receipt is not exact"
    atomic_json workload-remove-receipt.json "$source"
    rm -f "$source"
    policy=removed_run_bound_guest_workload_after_restart_reprobe
  elif [[ $CASE_ID == usage-source-terminal-receipts ]]; then
    policy=source_terminal_read_only_no_product_mutation
  fi
  # Product teardown remains the numbered delete-cleanup case. No failure path
  # guesses physical ownership or issues an extra destructive transition.
  jq -S -c -n --arg case_id "$CASE_ID" --arg policy "$policy" \
    '{version:1,case_id:$case_id,cleanup_status:"succeeded",policy:$policy}' \
    >"$CASE_DIR/cleanup-receipt.source.json"
  atomic_json cleanup-receipt.json "$CASE_DIR/cleanup-receipt.source.json"
  rm -f "$CASE_DIR/cleanup-receipt.source.json"
  printf 'cleanup policy: %s; delete-cleanup owns product teardown\n' "$policy"
}

inventory() {
  fleet_verify_to "$CASE_DIR/final-fleet-verification.json"
  fleet_safe_summary "$CASE_DIR/final-fleet-verification.json"
}

case "$ACTION" in
  run) run_case ;;
  diagnostics) diagnostics ;;
  cleanup) cleanup ;;
  inventory) inventory ;;
  *) fail "unknown driver action $ACTION" ;;
esac
