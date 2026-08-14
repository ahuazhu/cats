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
  local reason=$1 receipt=$CASE_DIR/blocked.json temporary
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

run_focused() {
  local binary_label=$1 exact_test=$2 ignored=${3:-false} executable receipt temporary status
  executable=$(binary "$binary_label")
  receipt=$CASE_DIR/focused-${binary_label}.json
  set +e
  if [[ $ignored == true ]]; then
    "$executable" --exact "$exact_test" --ignored --nocapture
  else
    "$executable" --exact "$exact_test" --nocapture
  fi
  status=$?
  set -e
  temporary=$(mktemp "$CASE_DIR/.focused-${binary_label}.json.XXXXXX")
  jq -S -c -n \
    --arg binary_label "$binary_label" \
    --arg exact_test "$exact_test" \
    --arg exact_commit "$CATS_E3_EXACT_COMMIT" \
    --argjson exit_code "$status" \
    '{version:1,binary_label:$binary_label,exact_test:$exact_test,exact_commit:$exact_commit,exit_code:$exit_code}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$receipt"
  printf 'FOCUSED_RECEIPT binary_label=%s exact_test=%s exact_commit=%s exit_code=%s\n' \
    "$binary_label" "$exact_test" "$CATS_E3_EXACT_COMMIT" "$status"
  [[ $status -eq 0 ]] || return "$status"
}

curl_json() {
  local method=$1 url=$2 output=$3 expected_status=$4
  shift 4
  local curl_bin token auth_header response_headers status content_types encodings
  curl_bin=$(binary curl)
  token=$(required CATS_TOKEN)
  [[ $token != *$'\n'* && $token != *$'\r'* ]] || fail "CATS_TOKEN must be one header-safe line"
  auth_header=$(mktemp "$CASE_DIR/.authorization.XXXXXX")
  response_headers=$(mktemp "$CASE_DIR/.response-headers.XXXXXX")
  chmod 0600 "$auth_header" "$response_headers"
  printf 'Authorization: Bearer %s\n' "$token" >"$auth_header"
  status=$("$curl_bin" --fail-with-body --silent --show-error \
    --proto '=https' --tlsv1.2 --max-time 30 \
    --request "$method" \
    --header "@$auth_header" \
    --header 'Accept: application/json' \
    --header 'Accept-Encoding: identity' \
    --dump-header "$response_headers" --write-out '%{http_code}' \
    "$@" --output "$output" "$url")
  case ",$expected_status," in
    *",$status,"*) ;;
    *) fail "$method returned HTTP $status, expected $expected_status" ;;
  esac
  content_types=$(awk 'BEGIN{IGNORECASE=1} /^Content-Type:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$response_headers")
  [[ $content_types == application/json ]] || fail "$method response Content-Type is not one exact application/json"
  encodings=$(awk 'BEGIN{IGNORECASE=1} /^Content-Encoding:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$response_headers")
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
  local operation_id=$1 expected_target=$2 origin workspace response phase target
  origin=$(control_origin)
  workspace=$(required CATS_E3_WORKSPACE_ID)
  canonical_id CATS_E3_WORKSPACE_ID "$workspace"
  canonical_id operation_id "$operation_id"
  response=$CASE_DIR/operation-$operation_id.json
  local attempt=0
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    curl_json GET "$origin/v1/workspaces/$workspace/operations/$operation_id" "$response" 200
    phase=$(json_field "$response" '.phase')
    case "$phase" in
      pending) sleep 0.5 ;;
      succeeded)
        target=$(json_field "$response" '.terminal.result.observed_target')
        [[ $target == "$expected_target" ]] || fail "operation $operation_id settled at $target, expected $expected_target"
        atomic_json operation-receipt.json "$response"
        return 0
        ;;
      failed|superseded) fail "operation $operation_id settled as $phase" ;;
      *) fail "operation $operation_id returned an unknown phase" ;;
    esac
  done
  fail "operation $operation_id did not settle before the subordinate deadline"
}

product_mutation() {
  local method=$1 path=$2 key=$3 expected_target=$4 body=${5:-} origin response operation_id converged
  origin=$(control_origin)
  response=$CASE_DIR/mutation-response.json
  if [[ -n $body ]]; then
    curl_json "$method" "$origin$path" "$response" 200,202 \
      --header "Idempotency-Key: $key" \
      --header 'Content-Type: application/json' \
      --data-binary "@$body"
  else
    curl_json "$method" "$origin$path" "$response" 200,202 \
      --header "Idempotency-Key: $key"
  fi
  atomic_json mutation-receipt.json "$response"
  operation_id=$(jq -er '.operation_id // empty' "$response" 2>/dev/null || true)
  if [[ -n $operation_id ]]; then
    operation_wait "$operation_id" "$expected_target"
    return
  fi
  converged=$(jq -er '.converged // false' "$response" 2>/dev/null || true)
  [[ $converged == true ]] || fail "product mutation returned neither operation_id nor converged=true"
}

fleet_verify_to() {
  local destination=$1 cats key_ring args node
  cats=$(binary cats)
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
  "$cats" "${args[@]}" >"$destination"
}

run_fleet_verify() {
  fleet_verify_to "$CASE_DIR/fleet-verification.json"
  atomic_json fleet-verification-receipt.json "$CASE_DIR/fleet-verification.json"
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
  local cats output cat_id operation_id expected_name
  cats=$(binary cats)
  expected_name=$(required CATS_E3_CAT_NAME)
  output=$CASE_DIR/create-response.json
  "$cats" --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" --json \
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
  "$cats" --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" --json \
    get "$cat_id" >"$CASE_DIR/cat-running.json"
  jq -e --arg cat "$cat_id" \
    '.id == $cat and .desired.target == "running" and .observed.stable_state == "running" and (.observed.conditions | index("ready") != null)' \
    "$CASE_DIR/cat-running.json" >/dev/null || fail "Cat did not converge to exact Running/Ready"
  atomic_json cat-running-receipt.json "$CASE_DIR/cat-running.json"
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
  local curl_bin origin
  curl_bin=$(binary curl)
  origin=$(control_origin)
  "$curl_bin" --fail --silent --show-error --proto '=https' --tlsv1.2 --max-time 10 \
    --output /dev/null "$origin/healthz"
  printf 'exact release %s schema startup health reachable\n' "$CATS_E3_EXACT_COMMIT"
}

run_guest_write() {
  cat_id >/dev/null
  blocked 'this release has no installed production GuestClient write+sync and Strict remote-proof subordinate command'
}

run_route() {
  local workspace cat body
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  body=$CASE_DIR/endpoint-bind.json
  jq -S -c -n \
    --arg name "$(required CATS_E3_ENDPOINT_NAME)" \
    --arg hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" \
    '{name:$name,hostname:$hostname,target_port:8080}' >"$body"
  product_mutation POST "/v1/workspaces/$workspace/cats/$cat/endpoints" \
    "e3-$CATS_E3_RUN_ID-endpoint-$BLOCK_PATH" running "$body"
  if [[ -z ${CATS_E3_BINARY_ROUTE_G5_HTTP:-} || -z ${CATS_E3_BINARY_ROUTE_G5_WS:-} ]]; then
    blocked 'endpoint bind settled, but this release has no installed G5 HTTP and WebSocket focused test binaries'
  fi
  run_focused route-g5-http public_http_bytes_cross_one_route_lookup_and_one_node_tunnel
  run_focused route-g5-ws websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel
  blocked 'endpoint bind and G5 calibration passed, but no installed production public HTTP+WebSocket Guest workload harness exists'
}

run_restart() {
  cat_id >/dev/null
  if [[ -z ${CATS_E3_BINARY_NODE_AGENT_TESTS:-} ]]; then
    blocked 'N6 exact native-x86 node-agent test binary is absent from this release manifest'
  fi
  run_focused node-agent-tests \
    runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_adopts_serving_relaxed_pending_pack_across_restart \
    true
}

run_usage_final() {
  cat_id >/dev/null
  blocked 'E9 immutable archive to exact projection terminal receipt is not runnable in this release'
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
    usage-final-terminal-receipt) run_usage_final ;;
    delete-cleanup) run_delete ;;
    *) fail "unknown scenario case $CASE_ID" ;;
  esac
}

diagnostics() {
  local journalctl_bin service
  journalctl_bin=$(binary journalctl)
  service=$(required CATS_E3_NODE_SERVICE)
  "$journalctl_bin" --no-pager --output=short-monotonic --lines=200 --unit "$service" || true
}

cleanup() {
  # Destructive cleanup is itself the final delete-cleanup scenario. Earlier
  # cases do not guess authority or delete physical state after a failure.
  printf 'cleanup policy: observation only; delete-cleanup owns product teardown\n'
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
