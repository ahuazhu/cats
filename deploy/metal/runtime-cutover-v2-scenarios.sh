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

# Keep the bearer token in this driver only. Every authorized child receives
# it through one command-scoped environment assignment; focused tests,
# diagnostics, systemctl and qualification probes never inherit it.
TOKEN=${CATS_TOKEN:-}
[[ -n $TOKEN && $TOKEN != *$'\n'* && $TOKEN != *$'\r'* ]] || \
  fail "CATS_TOKEN must be one nonempty header-safe line"
unset CATS_TOKEN
readonly TOKEN
AUTHORIZATION_TEMP=
cleanup_authorization_temp() {
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
  local executable
  executable=$(binary cats)
  CATS_TOKEN=$TOKEN "$executable" "$@"
}

run_focused() {
  local binary_label=$1 exact_test=$2 ignored=${3:-false}
  local executable receipt temporary status listing matches
  executable=$(binary "$binary_label")
  receipt=$CASE_DIR/focused-${binary_label}.json
  listing=$(mktemp "$CASE_DIR/.focused-${binary_label}.list.XXXXXX")
  set +e
  "$executable" --list --format terse >"$listing" 2>&1
  status=$?
  set -e
  [[ $status -eq 0 && $(wc -c <"$listing") -le 1048576 ]] || {
    rm -f "$listing"
    fail "$binary_label could not produce one bounded libtest catalog"
  }
  matches=$(awk -F': ' -v expected="$exact_test" \
    '$1 == expected && $2 == "test" { count += 1 } END { print count + 0 }' "$listing")
  rm -f "$listing"
  [[ $matches -eq 1 ]] || fail "$binary_label catalog contains $matches matches for exact test $exact_test"
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
    '{version:1,binary_label:$binary_label,exact_test:$exact_test,exact_commit:$exact_commit,catalog_matches:1,exit_code:$exit_code,live_proof:false}' \
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
  local curl_bin auth_header response_headers status content_types encodings curl_status size
  curl_bin=$(binary curl)
  auth_header=$(mktemp "$CASE_DIR/.authorization.XXXXXX")
  AUTHORIZATION_TEMP=$auth_header
  response_headers=$(mktemp "$CASE_DIR/.response-headers.XXXXXX")
  chmod 0600 "$auth_header" "$response_headers"
  printf 'authorization: Bearer %s\n' "$TOKEN" >"$auth_header"
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
  local output cat_id operation_id expected_name
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
  jq -S -c \
    '{version:1,cat_id:.id,desired_target:.desired.target,
      observed_stable_state:.observed.stable_state,conditions:.observed.conditions}' \
    "$CASE_DIR/cat-running.json" >"$CASE_DIR/cat-running-receipt.source.json"
  atomic_json cat-running-receipt.json "$CASE_DIR/cat-running-receipt.source.json"
  rm -f "$CASE_DIR/cat-running-receipt.source.json"
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
  local cat source
  cat=$(cat_id)
  source=$CASE_DIR/durable-write-flush.source.json
  run_probe guest-sync --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" >"$source"
  jq -e \
    --arg cat "$cat" --arg run_id "$CATS_E3_RUN_ID" \
    '.version == 1 and .cat_id == $cat and .run_id == $run_id
      and .strict_flush_remote_durable == true
      and .after_remote_generation > .before_remote_generation' \
    "$source" >/dev/null || fail "Guest write receipt lacks exact Strict remote proof"
  atomic_json durable-write-flush-receipt.json "$source"
  rm -f "$source"
}

run_route() {
  local workspace cat body workload workload_sha256 origin source attempt route_status
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  workload=$(binary e3-guest-workload)
  workload_sha256=$(binary_sha256 e3-guest-workload)
  source=$CASE_DIR/workload-install.source.json
  run_probe install-workload --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" \
    --workload "$workload" --workload-sha256 "$workload_sha256" --port 8080 >"$source"
  jq -e --arg cat "$cat" --arg run_id "$CATS_E3_RUN_ID" \
    --arg workload_sha256 "$workload_sha256" \
    '.version == 1 and .cat_id == $cat and .run_id == $run_id
      and .port == 8080 and .workload_sha256 == $workload_sha256
      and .installed == true' \
    "$source" >/dev/null || fail "Guest workload install receipt is not exact"
  atomic_json workload-install-receipt.json "$source"
  rm -f "$source"
  body=$CASE_DIR/endpoint-bind.json
  jq -S -c -n \
    --arg name "$(required CATS_E3_ENDPOINT_NAME)" \
    --arg hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" \
    '{name:$name,hostname:$hostname,target_port:8080}' >"$body"
  product_mutation POST "/v1/workspaces/$workspace/cats/$cat/endpoints" \
    "e3-$CATS_E3_RUN_ID-endpoint-$BLOCK_PATH" running "$body"
  # These focused tests calibrate the bridge but are explicitly not live proof.
  run_focused route-g5-http public_http_bytes_cross_one_route_lookup_and_one_node_tunnel
  run_focused route-g5-ws websocket_upgrade_and_frames_remain_raw_on_the_one_admitted_tunnel
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

run_restart() {
  local cat systemctl_bin service before after before_invocation after_invocation
  local attempt cat_state ready
  cat=$(cat_id)
  systemctl_bin=$(binary systemctl)
  service=$(required CATS_E3_NODE_SERVICE)
  [[ $service =~ ^[A-Za-z0-9_.@-]+\.service$ ]] || fail "CATS_E3_NODE_SERVICE is not canonical"
  before=$CASE_DIR/restart-before.json
  after=$CASE_DIR/restart-after.json
  run_probe snapshot --cat-id "$cat" >"$before"
  before_invocation=$("$systemctl_bin" show --property=InvocationID --value "$service")
  [[ $before_invocation =~ ^[0-9a-f]{32}$ ]] || fail "Agent has no exact pre-restart InvocationID"
  "$systemctl_bin" restart "$service"
  cat_state=$CASE_DIR/cat-after-restart.json
  attempt=0
  ready=false
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    if "$systemctl_bin" is-active --quiet "$service" &&
      run_cats --api-url "$(control_origin)" --workspace "$(required CATS_E3_WORKSPACE_ID)" \
        --json get "$cat" >"$cat_state" 2>/dev/null &&
      jq -e '.desired.target == "running" and .observed.stable_state == "running"
        and (.observed.conditions | index("ready") != null)' "$cat_state" >/dev/null; then
      ready=true
      break
    fi
    sleep 0.5
  done
  [[ $ready == true ]] || fail "Agent restart did not return the Cat to exact Running/Ready"
  after_invocation=$("$systemctl_bin" show --property=InvocationID --value "$service")
  [[ $after_invocation =~ ^[0-9a-f]{32}$ && $after_invocation != "$before_invocation" ]] || \
    fail "systemctl restart did not create a fresh Agent invocation"
  run_probe snapshot --cat-id "$cat" >"$after"
  jq -e -n --slurpfile before "$before" --slurpfile after "$after" \
    '$before[0].cat_id == $after[0].cat_id
      and $before[0].runtime_incarnation == $after[0].runtime_incarnation
      and $before[0].guest_boot_id == $after[0].guest_boot_id
      and $before[0].root_volume_id == $after[0].root_volume_id
      and $before[0].root_attachment_id == $after[0].root_attachment_id
      and $before[0].root_attachment_epoch == $after[0].root_attachment_epoch
      and $before[0].root_remote_head == $after[0].root_remote_head
      and $after[0].strict_remote_durable == true' >/dev/null || \
    fail "Agent restart did not adopt the exact retained Running runtime"
  run_focused node-agent-tests \
    runtime_cutover::cross_component_e2e::postgres_control_and_production_cutover_adopts_serving_relaxed_pending_pack_across_restart \
    true
  jq -S -c -n \
    --arg cat_id "$cat" --arg before_invocation "$before_invocation" \
    --arg after_invocation "$after_invocation" \
    --slurpfile before "$before" --slurpfile after "$after" \
    '{version:1,cat_id:$cat_id,systemctl_restart:true,
      before_invocation_id:$before_invocation,after_invocation_id:$after_invocation,
      retained_runtime_incarnation:$after[0].runtime_incarnation,
      retained_guest_boot_id:$after[0].guest_boot_id,
      retained_root_remote_head:$after[0].root_remote_head,
      strict_remote_durable:$after[0].strict_remote_durable}' \
    >"$CASE_DIR/restart-adoption-receipt.source.json"
  atomic_json restart-adoption-receipt.json "$CASE_DIR/restart-adoption-receipt.source.json"
  rm -f "$CASE_DIR/restart-adoption-receipt.source.json"
}

run_volume_init_matrix() {
  local cat snapshot flush source v5_run_id exact_test
  cat=$(cat_id)
  case "$BLOCK_PATH" in
    kernel-nbd)
      exact_test=runtime::reconciliation::clean_slate_probes::tests::full_scanner_seals_exact_root_and_persistent_kernel_nbd_mount_set
      ;;
    vhost-user)
      exact_test=runtime::reconciliation::clean_slate_probes::tests::full_scanner_seals_exact_root_and_persistent_vhost_mount_set
      ;;
    *) fail "unknown selected block path $BLOCK_PATH" ;;
  esac
  # This existing shared fixture covers first init, the lost-mkfs-response
  # crash boundary, exact ext4 UUID adoption, drain/commit, remount/restart
  # inventory and Guest mounted-set readiness. It remains subordinate to the
  # installed Strict-FLUSH proof below and is never presented as live proof.
  run_focused node-agent-tests "$exact_test"
  snapshot=$CASE_DIR/volume-matrix-snapshot.json
  flush=$CASE_DIR/volume-matrix-flush.json
  v5_run_id=v5-${CATS_E3_RUN_ID:0:61}
  run_probe snapshot --cat-id "$cat" >"$snapshot"
  run_probe guest-sync --cat-id "$cat" --run-id "$v5_run_id" >"$flush"
  jq -e --arg cat "$cat" \
    '.cat_id == $cat and .strict_remote_durable == true' "$snapshot" >/dev/null || \
    fail "selected live block path lacks exact Running mount readiness"
  jq -e --arg cat "$cat" \
    '.cat_id == $cat and .strict_flush_remote_durable == true
      and .after_remote_generation > .before_remote_generation' "$flush" >/dev/null || \
    fail "selected live block path lacks Strict FLUSH proof"
  source=$CASE_DIR/volume-init-matrix-receipt.source.json
  jq -S -c -n --arg cat_id "$cat" --arg block_path "$BLOCK_PATH" \
    --slurpfile snapshot "$snapshot" --slurpfile flush "$flush" \
    '{version:1,cat_id:$cat_id,block_path:$block_path,
      shared_matrix_exact_match:true,live_mount_ready:true,
      runtime_incarnation:$snapshot[0].runtime_incarnation,
      guest_boot_id:$snapshot[0].guest_boot_id,
      root_remote_head:$snapshot[0].root_remote_head,
      strict_flush_remote_durable:$flush[0].strict_flush_remote_durable,
      strict_flush_generation:$flush[0].after_remote_generation}' >"$source"
  atomic_json volume-init-matrix-receipt.json "$source"
  rm -f "$source"
}

run_usage_final() {
  local cat workspace from_ms to_ms before before_sequence after source attempt query_status ready
  cat=$(cat_id)
  workspace=$(required CATS_E3_WORKSPACE_ID)
  from_ms=$(( $(date +%s) * 1000 - 3600000 ))
  before=$CASE_DIR/usage-before.json
  to_ms=$(( $(date +%s) * 1000 + 60000 ))
  curl_json GET \
    "$(control_origin)/v1/workspaces/$workspace/billing/usage?from_ms=$from_ms&to_ms=$to_ms&cat_id=$cat&detail=true" \
    "$before" 200
  jq -e --arg workspace "$workspace" \
    '.workspace_id == $workspace and .status == "provisional" and (.details | type == "array")' \
    "$before" >/dev/null || fail "baseline usage projection is not the canonical workspace report"
  before_sequence=$(jq -r --arg cat "$cat" '
    [.details[] | select(.attributed_cat_id == $cat) | .end_sequence] | max // -1' \
    "$before")
  [[ $before_sequence =~ ^-?[0-9]+$ ]] || fail "baseline usage sequence is not an integer"

  after=$CASE_DIR/usage-after.json
  attempt=0
  query_status=1
  ready=false
  while [[ $attempt -lt 45 ]]; do
    attempt=$((attempt + 1))
    to_ms=$(( $(date +%s) * 1000 + 60000 ))
    set +e
    curl_json GET \
      "$(control_origin)/v1/workspaces/$workspace/billing/usage?from_ms=$from_ms&to_ms=$to_ms&cat_id=$cat&detail=true" \
      "$after" 200
    query_status=$?
    set -e
    if [[ $query_status -eq 0 ]] && jq -e \
      --arg workspace "$workspace" --arg cat "$cat" --argjson before "$before_sequence" '
      .workspace_id == $workspace and .status == "provisional"
      and ([.details[]
        | select(.attributed_cat_id == $cat
          and (.source_id | startswith("node/") and endswith("/cat/" + $cat))
          and (.source_epoch | test("^[0-9a-f]{32}$"))
          and (.metric == "cpu_usec" or .metric == "memory_byte_millis")
          and (.quantity | test("^(0|[1-9][0-9]*)$")))]
        | group_by([.source_id,.source_epoch,.end_sequence])
        | any(.[];
            length == 2
            and ([.[].metric] | sort) == ["cpu_usec","memory_byte_millis"]
            and (.[0].end_sequence > $before)
            and any(.[]; .quantity != "0")))' \
      "$after" >/dev/null; then
      ready=true
      break
    fi
    sleep 2
  done
  [[ $ready == true ]] || fail "live usage projection did not advance one complete Cat meter pair"
  source=$CASE_DIR/usage-live-delivery-receipt.source.json
  jq -S -c --arg workspace "$workspace" --arg cat "$cat" \
    --argjson before "$before_sequence" '
    [.details[]
      | select(.attributed_cat_id == $cat
        and (.source_id | startswith("node/") and endswith("/cat/" + $cat))
        and (.source_epoch | test("^[0-9a-f]{32}$"))
        and (.metric == "cpu_usec" or .metric == "memory_byte_millis"))]
      | group_by([.source_id,.source_epoch,.end_sequence])
      | map(select(length == 2
          and ([.[].metric] | sort) == ["cpu_usec","memory_byte_millis"]
          and .[0].end_sequence > $before
          and any(.[]; .quantity != "0")))
      | sort_by(.[0].end_sequence)
      | last as $pair
    | {version:1,proof:"sampler_spool_signed_ingest_projection",
        workspace_id:$workspace,cat_id:$cat,source_id:$pair[0].source_id,
        source_epoch:$pair[0].source_epoch,before_end_sequence:$before,
        after_end_sequence:$pair[0].end_sequence,
        interval_end_unix_ms:$pair[0].interval_end_unix_ms,
        metrics:[$pair[] | {metric,quantity,unit}],
        durable_spool_on_delivery_path:true,
        exact_current_agent_binding_required:true,
        projector_delivery_eventual:true,
        spool_absence_used_as_authority:false,
        terminal_archive_projector_receipt_proved:false}' \
    "$after" >"$source"
  atomic_json usage-live-delivery-receipt.json "$source"
  rm -f "$source" "$before" "$after"
  blocked 'E9 live sampler/spool/signed ingest passed; accepted terminal archive/projector receipt remains unavailable'
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
  local policy source cat
  policy=observation_only
  if [[ $CASE_ID == route-http-ws ]]; then
    cat=$(cat_id)
    source=$CASE_DIR/workload-remove.source.json
    run_probe remove-workload --cat-id "$cat" --run-id "$CATS_E3_RUN_ID" >"$source"
    jq -e --arg cat "$cat" --arg run_id "$CATS_E3_RUN_ID" \
      '.version == 1 and .cat_id == $cat and .run_id == $run_id and .removed == true' \
      "$source" >/dev/null || fail "Guest workload cleanup receipt is not exact"
    atomic_json workload-remove-receipt.json "$source"
    rm -f "$source"
    policy=removed_run_bound_guest_workload
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
