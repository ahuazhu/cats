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
readonly ROTATION_JOURNAL=$CASE_DIR/route-v2-rotation-journal.v1
ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS=

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

atomic_json_path() {
  local destination=$1 source=$2 directory temporary
  [[ $destination == "$CASE_DIR/"* ]] || fail "atomic JSON destination is outside the case directory"
  directory=${destination%/*}
  [[ -d $directory && ! -L $directory && -O $directory ]] || \
    fail "atomic JSON parent is not an owner-controlled directory"
  temporary=$(mktemp "$directory/.${destination##*/}.XXXXXX")
  jq -S -c . "$source" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$destination"
  durable_case_file "$destination"
}

file_link_count() {
  local path=$1 count
  if count=$(stat -c '%h' "$path" 2>/dev/null); then
    :
  elif count=$(stat -f '%l' "$path" 2>/dev/null); then
    :
  else
    fail "could not read file link count: $path"
  fi
  [[ $count =~ ^[1-9][0-9]*$ ]] || fail "file link count is invalid"
  printf '%s' "$count"
}

recover_interrupted_adoption() {
  local destination=$1 directory link_count candidate
  local same_inode_links=()
  directory=${destination%/*}
  [[ -f $destination && ! -L $destination && -O $destination ]] || \
    fail "adopted destination is not an owner-controlled regular file"
  link_count=$(file_link_count "$destination")
  if [[ $link_count == 2 ]]; then
    shopt -s nullglob
    for candidate in "$directory/.${destination##*/}."*; do
      if [[ -f $candidate && ! -L $candidate && -O $candidate && \
        $candidate -ef $destination ]]; then
        same_inode_links+=("$candidate")
      fi
    done
    shopt -u nullglob
    ((${#same_inode_links[@]} == 1)) || \
      fail "interrupted no-replace adoption has no unique private temporary link"
    rm -f "${same_inode_links[0]}"
    sync -f "$directory"
    link_count=$(file_link_count "$destination")
  fi
  [[ $link_count == 1 ]] || fail "adopted destination is not single-link"
}

prepare_rotation_journal() {
  local mode
  if [[ ! -e $ROTATION_JOURNAL ]]; then
    mkdir -m 0700 "$ROTATION_JOURNAL"
    sync -f "$CASE_DIR"
  fi
  [[ -d $ROTATION_JOURNAL && ! -L $ROTATION_JOURNAL && -O $ROTATION_JOURNAL ]] || \
    fail "Route rotation journal is not an owner-controlled directory"
  mode=$(stat -c '%a' "$ROTATION_JOURNAL")
  [[ $mode == 700 ]] || fail "Route rotation journal must have exact mode 0700"
}

durable_case_file() {
  local path=$1
  [[ $path == "$CASE_DIR/"* && -f $path && ! -L $path && -O $path ]] || \
    fail "Route rotation journal entry is not an owner-controlled regular file"
  [[ $(file_link_count "$path") == 1 ]] || \
    fail "Route rotation journal entry is not single-link"
  chmod 0600 "$path"
  sync -f "$path"
  sync -f "${path%/*}"
}

adopt_rotation_file() {
  local source=$1 destination=$2 temporary
  [[ $source == "$ROTATION_JOURNAL/"* && $destination == "$ROTATION_JOURNAL/"* ]] || \
    fail "Route rotation adoption escaped the private journal"
  [[ -f $source && ! -L $source && -O $source ]] || \
    fail "Route rotation adoption source is unsafe"
  [[ $(file_link_count "$source") == 1 ]] || \
    fail "Route rotation adoption source is not single-link"
  if [[ -e $destination ]]; then
    recover_interrupted_adoption "$destination"
    cmp -s "$source" "$destination" || \
      fail "adopted Route rotation bytes changed across resume"
    return
  fi
  temporary=$(mktemp "$ROTATION_JOURNAL/.${destination##*/}.XXXXXX")
  cp "$source" "$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary"
  if ln "$temporary" "$destination" 2>/dev/null; then
    rm -f "$temporary"
    durable_case_file "$destination"
    return
  fi
  rm -f "$temporary"
  recover_interrupted_adoption "$destination"
  cmp -s "$source" "$destination" || \
    fail "adopted Route rotation bytes changed across resume"
}

adopt_case_file() {
  local source=$1 destination=$2 directory temporary
  [[ $source == "$CASE_DIR/"* && $destination == "$CASE_DIR/"* ]] || \
    fail "durable case adoption escaped the case directory"
  [[ -f $source && ! -L $source && -O $source ]] || \
    fail "durable case adoption source is unsafe"
  [[ $(file_link_count "$source") == 1 ]] || \
    fail "durable case adoption source is not single-link"
  directory=${destination%/*}
  [[ -d $directory && ! -L $directory && -O $directory ]] || \
    fail "durable case adoption parent is unsafe"
  if [[ -e $destination ]]; then
    recover_interrupted_adoption "$destination"
    cmp -s "$source" "$destination" || \
      fail "durable case bytes changed across exact replay"
    return
  fi
  temporary=$(mktemp "$directory/.${destination##*/}.XXXXXX")
  cp "$source" "$temporary"
  chmod 0600 "$temporary"
  sync -f "$temporary"
  if ln "$temporary" "$destination" 2>/dev/null; then
    rm -f "$temporary"
    durable_case_file "$destination"
    return
  fi
  rm -f "$temporary"
  recover_interrupted_adoption "$destination"
  cmp -s "$source" "$destination" || \
    fail "durable case bytes changed across exact replay"
}

publish_json_idempotent_path() {
  local destination=$1 source=$2 canonical
  canonical=$(mktemp "${destination%/*}/.${destination##*/}.canonical.XXXXXX")
  jq -S -c . "$source" >"$canonical"
  chmod 0600 "$canonical"
  adopt_case_file "$canonical" "$destination"
  rm -f "$canonical"
}

initialize_rotation_journal() {
  local transcript=$CASE_DIR/route-v2-rotation-disable-live-delivery.transcript.log
  local phases=$ROTATION_JOURNAL/rotation-phase-receipts.json temporary expected_header
  prepare_rotation_journal
  if [[ -z $ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS ]]; then
    ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS=$(( $(date +%s) + 1740 ))
  fi
  expected_header="version=1 kind=route_v2_rotation_transcript_v1 case_id=$CASE_ID qualification_run_id=$CATS_E3_RUN_ID source_commit_sha=$CATS_E3_EXACT_COMMIT"
  if [[ -e $transcript ]]; then
    [[ -f $transcript && ! -L $transcript && -O $transcript ]] || \
      fail "Route rotation transcript is not an owner-controlled regular file"
    [[ $(sed -n '1p' "$transcript") == "$expected_header" ]] || \
      fail "Route rotation transcript belongs to another run"
    [[ $(grep -c '^terminal_marker=route_v2_rotation_disable_recovered_active_http_ws$' "$transcript" || true) -le 1 ]] || \
      fail "Route rotation transcript repeats its terminal marker"
  else
    temporary=$(mktemp "$CASE_DIR/.route-v2-rotation-transcript.XXXXXX")
    printf '%s\n' "$expected_header" >"$temporary"
    chmod 0600 "$temporary"
    mv "$temporary" "$transcript"
    durable_case_file "$transcript"
  fi
  if [[ -e $phases ]]; then
    [[ -f $phases && ! -L $phases && -O $phases ]] || \
      fail "Route rotation phase aggregate is not an owner-controlled regular file"
    jq -e -S -c . "$phases" >"$ROTATION_JOURNAL/.phase-prefix.canonical"
    cmp -s "$phases" "$ROTATION_JOURNAL/.phase-prefix.canonical" || \
      fail "Route rotation phase aggregate is not canonical JSON"
    rm -f "$ROTATION_JOURNAL/.phase-prefix.canonical"
  else
    printf '[]\n' >"$phases"
    durable_case_file "$phases"
  fi
}

rotation_require_budget() {
  local minimum_seconds=$1 now remaining
  [[ $ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS =~ ^[0-9]+$ ]] || \
    fail "Route rotation invocation deadline is unavailable"
  now=$(date +%s)
  remaining=$((ROTATION_INVOCATION_DEADLINE_UNIX_SECONDS - now))
  (( remaining >= minimum_seconds )) || \
    fail "Route rotation invocation exhausted its forward-recovery budget"
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
  auth_header=$(mktemp "${TOKEN_FILE%/*}/.authorization.XXXXXX")
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

sha256_wire() {
  printf 'sha256:%s' "$(sha256sum "$1" | awk '{print $1}')"
}

rotation_input() {
  config "$1"
}

protected_rotation_operator_key() {
  local path=$1 parent mode uid gid links size parent_mode parent_uid parent_gid
  parent=${path%/*}
  read -r mode uid gid links size < <(stat -c '%a %u %g %h %s' "$path")
  read -r parent_mode parent_uid parent_gid < <(stat -c '%a %u %g' "$parent")
  [[ -f $path && ! -L $path && $mode == 600 && $uid == 0 && $gid == 0 && $links == 1 ]] || \
    fail "Route rotation operator key must be one root:root 0600 single-link regular file"
  [[ $size =~ ^[1-9][0-9]*$ ]] && (( size <= 65536 )) || \
    fail "Route rotation operator key exceeds its closed byte bound"
  [[ -d $parent && ! -L $parent && $parent_mode == 700 && $parent_uid == 0 && $parent_gid == 0 ]] || \
    fail "Route rotation operator key parent must be exact root:root 0700"
}

validate_rotation_recovery_inputs() {
  local trust bundle operator_key transport ca canonical
  local rotation_origin rotation_server inbox_server authority port
  local phase receipt_url expected_url_sha actual_url_sha remainder
  trust=$(rotation_input route-rotation-operator-trust)
  bundle=$(rotation_input route-rotation-command-bundle)
  operator_key=$(rotation_input route-rotation-operator-key)
  transport=$(rotation_input route-rotation-recovery)
  ca=$(rotation_input route-rotation-server-ca)
  canonical=$CASE_DIR/rotation-recovery-transport.canonical.json
  jq -S -c . "$transport" >"$canonical"
  cmp -s "$transport" "$canonical" || fail "Route rotation recovery transport is not sorted canonical JSON"
  rm -f "$canonical"
  jq -e \
    --arg case_id "$CASE_ID" \
    --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg catalog "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg trust_sha "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256)" \
    --arg ca_sha "$(sha256_wire "$ca")" '
    . as $root
    | (keys == ["authority_id","case_id","immutability_mode","kind","phases",
        "qualification_catalog_sha256","qualification_run_id","receipt_inbox_server_name",
        "rotation_operator_trust_sha256","rotation_origin","rotation_server_name",
        "route_deployment_id","server_ca_bundle_sha256","source_commit_sha","version"])
      and .version == 1
      and .kind == "route_v2_rotation_recovery_transport_v1"
      and .immutability_mode == "create_only_no_delete_v1"
      and .case_id == $case_id and .qualification_run_id == $run_id
      and .source_commit_sha == $commit
      and .qualification_catalog_sha256 == $catalog
      and .authority_id == $authority and .route_deployment_id == $deployment
      and .rotation_operator_trust_sha256 == $trust_sha
      and .server_ca_bundle_sha256 == $ca_sha
      and (.rotation_origin | test("^https://[a-z0-9][a-z0-9.-]*[a-z0-9](:[1-9][0-9]{0,4})?$"))
      and (.rotation_origin == ("https://" + $root.rotation_server_name)
        or (.rotation_origin | startswith("https://" + $root.rotation_server_name + ":")))
      and (.receipt_inbox_server_name | test("^[a-z0-9][a-z0-9.-]*[a-z0-9]$"))
      and (.phases | type == "array" and length == 7)
      and ([.phases[].phase] == ["publish_overlap","switch_active","publish_new_only",
        "retire","disable","publish_recovery","activate"])
      and ([.phases[].signer_revision] == [2,3,4,5,6,7,8])
      and all(.phases[];
        (keys == ["phase","plan_validation_receipt_sha256","receipt_url",
          "receipt_url_sha256","saved_plan_sha256","signer_revision"])
        and (.saved_plan_sha256 | test("^sha256:[0-9a-f]{64}$"))
        and (.plan_validation_receipt_sha256 | test("^sha256:[0-9a-f]{64}$"))
        and (.receipt_url | test("^https://[A-Za-z0-9./:_-]+$"))
        and ((.receipt_url | startswith("https://" + $root.receipt_inbox_server_name + "/"))
          or (.receipt_url | startswith("https://" + $root.receipt_inbox_server_name + ":")))
        and (.receipt_url_sha256 | test("^sha256:[0-9a-f]{64}$")))' \
    "$transport" >/dev/null || fail "Route rotation recovery transport does not bind this exact run"
  jq -e \
    --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg trust_sha "$(sha256_wire "$trust")" '
    .version == 1 and .case_id == $case_id
    and .qualification_run_id == $run_id and .source_commit_sha == $commit
    and .rotation_operator_authority_id == $authority
    and .route_deployment_id == $deployment
    and .rotation_operator_trust_sha256 == $trust_sha
    and ([.commands[].phase] == ["publish_overlap","switch_active","publish_new_only",
      "retire","disable","publish_recovery","activate"])
    and ([.commands[].signer_revision] == [2,3,4,5,6,7,8])
    and ([.control_rollouts[].signer_revision] == [2,3,4,5,6,7,8])' \
    "$bundle" >/dev/null || fail "Route rotation command bundle does not bind this exact run"
  [[ $(sha256_wire "$trust") == "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256)" ]] || \
    fail "Route rotation trust digest differs from runner authority"
  [[ -s $operator_key && -s $ca ]] || fail "Route rotation key or server CA is empty"
  protected_rotation_operator_key "$operator_key"
  rotation_origin=$(jq -er '.rotation_origin' "$transport")
  rotation_server=$(jq -er '.rotation_server_name' "$transport")
  inbox_server=$(jq -er '.receipt_inbox_server_name' "$transport")
  authority=${rotation_origin#https://}
  [[ $authority == "$rotation_server" || $authority == "$rotation_server":* ]] || \
    fail "Route rotation origin does not select the exact server identity"
  if [[ $authority == *:* ]]; then
    port=${authority##*:}
    [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$port <= 65535 )) || \
      fail "Route rotation origin has an invalid HTTPS port"
  fi
  while IFS=$'\t' read -r phase receipt_url expected_url_sha; do
    [[ -n $phase && -n $receipt_url && -n $expected_url_sha ]] || \
      fail "Route rotation recovery transport has an incomplete phase coordinate"
    actual_url_sha="sha256:$(printf '%s' "$receipt_url" | sha256sum | awk '{print $1}')"
    [[ $actual_url_sha == "$expected_url_sha" ]] || \
      fail "Route rotation recovery transport has a mismatched URL digest for $phase"
    remainder=${receipt_url#https://}
    authority=${remainder%%/*}
    [[ $remainder != "$authority" && $authority != *'@'* ]] || \
      fail "Route rotation recovery transport has a malformed receipt URL"
    [[ $authority == "$inbox_server" || $authority == "$inbox_server":* ]] || \
      fail "Route rotation receipt URL does not select the exact inbox identity"
    if [[ $authority == *:* ]]; then
      port=${authority##*:}
      [[ $port =~ ^[1-9][0-9]{0,4}$ ]] && (( 10#$port <= 65535 )) || \
        fail "Route rotation receipt URL has an invalid HTTPS port"
    fi
  done < <(jq -r '.phases[] | [.phase,.receipt_url,.receipt_url_sha256] | @tsv' "$transport")
}

rotation_transport_field() {
  jq -er "$1" "$(rotation_input route-rotation-recovery)"
}

curl_secret_url() {
  local method=$1 url=$2 output=$3 expected=$4
  shift 4
  local curl_bin ca url_config headers errors status curl_status size content_types encodings
  curl_bin=$(binary curl)
  ca=$(rotation_input route-rotation-server-ca)
  url_config=$(mktemp "$CASE_DIR/.curl-url.XXXXXX")
  headers=$(mktemp "$CASE_DIR/.rotation-headers.XXXXXX")
  errors=$(mktemp "$CASE_DIR/.rotation-curl-errors.XXXXXX")
  chmod 0600 "$url_config" "$headers" "$errors"
  [[ $url != *'"'* && $url != *'\'* && $url != *$'\n'* && $url != *$'\r'* ]] || \
    fail "recovery transport URL is not config-safe"
  printf 'url = "%s"\n' "$url" >"$url_config"
  set +e
  status=$(HTTPS_PROXY= HTTP_PROXY= ALL_PROXY= NO_PROXY='*' \
    https_proxy= http_proxy= all_proxy= no_proxy='*' \
    "$curl_bin" --disable --silent --show-error --config "$url_config" \
    --proto '=https' --tlsv1.3 --http1.1 --max-time 30 --max-filesize 1048576 \
    --noproxy '*' --max-redirs 0 \
    --cacert "$ca" --request "$method" \
    --header 'accept: application/json' --header 'accept-encoding: identity' \
    --dump-header "$headers" --write-out '%{http_code}' \
    "$@" --output "$output" 2>"$errors")
  curl_status=$?
  set -e
  rm -f "$url_config" "$errors"
  if [[ $curl_status -ne 0 || ! $status =~ ^[0-9]{3}$ ]]; then
    rm -f "$headers" "$output"
    return 75
  fi
  size=$(wc -c <"$output")
  if [[ $size -gt 1048576 ]]; then
    rm -f "$headers" "$output"
    fail "recovery HTTPS response exceeds the closed byte bound"
  fi
  case ",$expected," in
    *",$status,"*) ;;
    *)
      rm -f "$headers" "$output"
      return 76
      ;;
  esac
  if [[ $status == 200 || $status == 409 ]]; then
    content_types=$(awk 'BEGIN{IGNORECASE=1} /^Content-Type:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$headers")
    encodings=$(awk 'BEGIN{IGNORECASE=1} /^Content-Encoding:/{sub(/\r$/,""); sub(/^[^:]*:[[:space:]]*/,""); print}' "$headers")
    [[ $content_types == application/json ]] || {
      rm -f "$headers" "$output"
      fail "recovery HTTPS response Content-Type is not exact application/json"
    }
    [[ -z $encodings || $encodings == identity ]] || {
      rm -f "$headers" "$output"
      fail "recovery HTTPS response encoding is not identity"
    }
  fi
  rm -f "$headers"
  printf '%s' "$status"
}

rotation_json_request() {
  local method=$1 path=$2 output=$3 expected=$4 origin status
  shift 4
  origin=$(rotation_transport_field '.rotation_origin')
  status=$(curl_secret_url "$method" "$origin$path" "$output" "$expected" "$@") || return $?
  [[ $status == 200 ]] || return 76
  jq -e . "$output" >/dev/null || fail "Route rotation response is not JSON"
}

operation_wait() {
  local operation_id=$1 expected_target=$2 artifact_dir=${3:-$CASE_DIR} prefix=${4:-}
  local origin workspace response response_probe receipt_source receipt
  origin=$(control_origin)
  workspace=$(required CATS_E3_WORKSPACE_ID)
  canonical_id CATS_E3_WORKSPACE_ID "$workspace"
  canonical_id operation_id "$operation_id"
  [[ $artifact_dir == "$CASE_DIR" || $artifact_dir == "$CASE_DIR/"* ]] || \
    fail "Operation artifacts are outside the case directory"
  response=$artifact_dir/${prefix}operation-$operation_id.json
  response_probe=$(mktemp "$artifact_dir/.${prefix}operation-$operation_id.probe.XXXXXX")
  run_cats --api-url "$origin" --workspace "$workspace" --json \
    operation wait "$operation_id" >"$response_probe"
  adopt_case_file "$response_probe" "$response"
  rm -f "$response_probe"
  jq -e \
    --arg operation "$operation_id" --arg workspace "$workspace" --arg target "$expected_target" \
    '.operation_id == $operation and .workspace_id == $workspace and .phase == "succeeded"
      and .target == $target and .terminal.kind == "succeeded"
      and .terminal.result.observed_target == $target' \
    "$response" >/dev/null || fail "canonical Operation does not prove exact $expected_target settlement"
  receipt_source=$artifact_dir/.${prefix}operation-receipt.source.json
  receipt=$artifact_dir/${prefix}operation-receipt.json
  jq -S -c \
    '{version:1,operation_id,workspace_id,target,phase,
      terminal:{kind:.terminal.kind,observed_target:.terminal.result.observed_target}}' \
    "$response" >"$receipt_source"
  publish_json_idempotent_path "$receipt" "$receipt_source"
  rm -f "$receipt_source"
}

product_mutation() {
  local method=$1 path=$2 key=$3 expected_target=$4 body=${5:-}
  local artifact_dir=${6:-$CASE_DIR} prefix=${7:-}
  local origin response response_probe replay replay_probe
  local receipt_source receipt replay_source replay_receipt
  local operation_id replay_operation_id converged request_status attempt
  origin=$(control_origin)
  [[ $artifact_dir == "$CASE_DIR" || $artifact_dir == "$CASE_DIR/"* ]] || \
    fail "mutation artifacts are outside the case directory"
  response=$artifact_dir/${prefix}mutation-response.json
  replay=$artifact_dir/${prefix}mutation-replay.json
  receipt_source=$artifact_dir/.${prefix}mutation-receipt.source.json
  receipt=$artifact_dir/${prefix}mutation-receipt.json
  replay_source=$artifact_dir/.${prefix}idempotent-replay.source.json
  replay_receipt=$artifact_dir/${prefix}idempotent-replay-receipt.json
  response_probe=$(mktemp "$artifact_dir/.${prefix}mutation-response.probe.XXXXXX")
  request_status=75
  for attempt in 1 2; do
    set +e
    if [[ -n $body ]]; then
      curl_json "$method" "$origin$path" "$response_probe" 200,202 \
        --header "idempotency-key: $key" \
        --header 'content-type: application/json' \
        --data-binary "@$body"
    else
      curl_json "$method" "$origin$path" "$response_probe" 200,202 \
        --header "idempotency-key: $key"
    fi
    request_status=$?
    set -e
    [[ $request_status -eq 75 ]] || break
  done
  [[ $request_status -eq 0 ]] || fail "product mutation response remained ambiguous after one exact idempotent replay"
  adopt_case_file "$response_probe" "$response"
  rm -f "$response_probe"
  jq -S -c \
    '{version:1,operation_id:(.operation_id // null),
      desired_revision:(.desired_revision // null),converged:(.converged // null)}' \
    "$response" >"$receipt_source"
  publish_json_idempotent_path "$receipt" "$receipt_source"
  rm -f "$receipt_source"
  operation_id=$(jq -er '.operation_id // empty' "$response" 2>/dev/null || true)
  if [[ -n $operation_id ]]; then
    replay_probe=$(mktemp "$artifact_dir/.${prefix}mutation-replay.probe.XXXXXX")
    if [[ -n $body ]]; then
      curl_json "$method" "$origin$path" "$replay_probe" 200,202 \
        --header "idempotency-key: $key" \
        --header 'content-type: application/json' \
        --data-binary "@$body" || fail "idempotent mutation replay was ambiguous"
    else
      curl_json "$method" "$origin$path" "$replay_probe" 200,202 \
        --header "idempotency-key: $key" || fail "idempotent mutation replay was ambiguous"
    fi
    adopt_case_file "$replay_probe" "$replay"
    rm -f "$replay_probe"
    replay_operation_id=$(jq -er '.operation_id // empty' "$replay" 2>/dev/null || true)
    [[ $replay_operation_id == "$operation_id" ]] || fail "idempotent replay returned another Operation"
    cmp -s "$response" "$replay" || \
      fail "idempotent replay changed the exact mutation response bytes"
    jq -S -c -n --arg operation_id "$operation_id" \
      '{version:1,idempotent_replay:true,operation_id:$operation_id}' \
      >"$replay_source"
    publish_json_idempotent_path "$replay_receipt" "$replay_source"
    rm -f "$replay_source"
    operation_wait "$operation_id" "$expected_target" "$artifact_dir" "$prefix"
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
  local cat=$1 state
  state=$(nonsecret_path CATS_E3_RUNTIME_STATE)
  python3 - "$state" "$cat" "$CATS_E3_EXACT_COMMIT" "$BLOCK_PATH" \
    "$CATS_E3_RUN_ID" <<'PY' || fail "runtime Cat identity is unsafe or changed across resume"
import json
import os
import re
import stat
import sys
import tempfile


path, cat_id, exact_commit, block_path, run_id = sys.argv[1:]
id_pattern = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")
if id_pattern.fullmatch(cat_id) is None:
    raise SystemExit(1)
directory = os.path.dirname(path)
name = os.path.basename(path)
directory_fd = os.open(
    directory,
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0),
)
descriptor = -1
temporary_fd = -1
temporary_path = None


def identity(value):
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


try:
    descriptor = os.open(
        name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=directory_fd,
    )
    before = os.fstat(descriptor)
    effective_uid = os.geteuid()
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_uid != effective_uid
        or (effective_uid == 0 and before.st_gid != 0)
        or before.st_nlink != 1
        or stat.S_IMODE(before.st_mode) != 0o600
        or not 1 <= before.st_size <= 65_536
    ):
        raise SystemExit(1)
    raw = b""
    while len(raw) < before.st_size:
        chunk = os.read(descriptor, before.st_size - len(raw))
        if not chunk:
            raise SystemExit(1)
        raw += chunk
    if os.read(descriptor, 1) or identity(os.fstat(descriptor)) != identity(before):
        raise SystemExit(1)
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as error:
        raise SystemExit(1) from error
    canonical = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    if (
        raw != canonical
        or not isinstance(value, dict)
        or set(value)
        != {"block_path", "cat_id", "exact_commit", "run_id", "version"}
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["exact_commit"] != exact_commit
        or value["block_path"] != block_path
        or value["run_id"] != run_id
        or (
            value["cat_id"] is not None
            and (
                not isinstance(value["cat_id"], str)
                or id_pattern.fullmatch(value["cat_id"]) is None
            )
        )
    ):
        raise SystemExit(1)
    if value["cat_id"] is not None:
        if value["cat_id"] != cat_id:
            raise SystemExit(1)
        raise SystemExit(0)

    value["cat_id"] = cat_id
    replacement = (
        json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")
    temporary_fd, temporary_path = tempfile.mkstemp(
        prefix=f".{name}.", dir=directory
    )
    os.fchmod(temporary_fd, 0o600)
    offset = 0
    while offset < len(replacement):
        count = os.write(temporary_fd, replacement[offset:])
        if count <= 0:
            raise SystemExit(1)
        offset += count
    os.fsync(temporary_fd)
    os.close(temporary_fd)
    temporary_fd = -1
    if identity(os.stat(name, dir_fd=directory_fd, follow_symlinks=False)) != identity(before):
        raise SystemExit(1)
    os.rename(
        os.path.basename(temporary_path),
        name,
        src_dir_fd=directory_fd,
        dst_dir_fd=directory_fd,
    )
    temporary_path = None
    os.fsync(directory_fd)
finally:
    if descriptor >= 0:
        os.close(descriptor)
    if temporary_fd >= 0:
        os.close(temporary_fd)
    if temporary_path is not None:
        try:
            os.unlink(os.path.basename(temporary_path), dir_fd=directory_fd)
            os.fsync(directory_fd)
        except FileNotFoundError:
            pass
    os.close(directory_fd)
PY
}

create_response_private_file() {
  python3 - "$1" <<'PY'
import os
import stat
import sys


path = sys.argv[1]
try:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
except OSError:
    raise SystemExit(1)
try:
    value = os.fstat(descriptor)
    if (
        not stat.S_ISREG(value.st_mode)
        or value.st_uid != os.geteuid()
        or (os.geteuid() == 0 and value.st_gid != 0)
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) != 0o600
        or value.st_size > 65_536
    ):
        raise SystemExit(1)
finally:
    os.close(descriptor)
PY
}

create_response_is_accepted() {
  local path=$1
  create_response_private_file "$path" || return 1
  [[ -s $path ]] || return 1
  jq -e '
    keys == ["cat_id","operation_id"]
    and (.cat_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"))
    and (.operation_id | type == "string" and test("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"))' \
    "$path" >/dev/null 2>&1
}

create_response_is_no_pending() {
  local path=$1
  create_response_private_file "$path" || return 1
  jq -e 'keys == ["pending_cat_create"] and .pending_cat_create == false' \
    "$path" >/dev/null 2>&1
}

publish_create_response() {
  local source=$1 destination=$2 directory source_canonical destination_canonical
  directory=${destination%/*}
  [[ $source == "$CASE_DIR/".create-response.json.* && \
    $destination == "$CASE_DIR/create-response.json" ]] || \
    fail "Cat create response adoption escaped its exact private names"
  create_response_is_accepted "$source" || \
    fail "Cat create response temp is not one complete accepted identity"
  sync -f "$source" || fail "sync complete Cat create response temp"
  if [[ -e $destination || -L $destination ]]; then
    if [[ $source -ef $destination ]]; then
      recover_interrupted_adoption "$destination"
      create_response_is_accepted "$destination" || \
        fail "recovered Cat create response is unsafe"
      return
    fi
    recover_interrupted_adoption "$destination"
    source_canonical=$(jq -S -c . "$source")
    destination_canonical=$(jq -S -c . "$destination")
    [[ $source_canonical == "$destination_canonical" ]] || \
      fail "Cat create accepted identity changed across exact recovery"
    rm -f "$source"
    sync -f "$directory"
    return
  fi
  if ln "$source" "$destination" 2>/dev/null; then
    sync -f "$directory" || fail "sync no-replace Cat create response publication"
    rm -f "$source"
    sync -f "$directory" || fail "sync Cat create response temp removal"
  else
    recover_interrupted_adoption "$destination"
    source_canonical=$(jq -S -c . "$source")
    destination_canonical=$(jq -S -c . "$destination")
    [[ $source_canonical == "$destination_canonical" ]] || \
      fail "concurrent Cat create response publication changed accepted identity"
    rm -f "$source"
    sync -f "$directory"
  fi
  recover_interrupted_adoption "$destination"
  create_response_is_accepted "$destination" || \
    fail "published Cat create response is unsafe"
}

run_cat_create_to() {
  local destination=$1 existing_only=$2 expected_name=$3 args
  args=(--api-url "$(control_origin)" \
    --workspace "$(required CATS_E3_WORKSPACE_ID)" --json \
    create "$expected_name" \
    --boot-image-digest "$(required CATS_E3_BOOT_IMAGE_DIGEST)" \
    --cpus "${CATS_E3_CPUS:-1}" --memory "${CATS_E3_MEMORY:-512MiB}" \
    --root-size "${CATS_E3_ROOT_SIZE:-1GiB}" --durability strict)
  if [[ $existing_only == true ]]; then
    args+=(--existing-pending-only)
  fi
  (umask 077; run_cats "${args[@]}" >"$destination")
}

resolve_cat_create_cli_journal() {
  local output=$1 expected_name=$2 replay replay_canonical output_canonical
  local replay_temps=()
  shopt -s nullglob
  replay_temps=("$CASE_DIR"/.create-response-replay.*)
  shopt -u nullglob
  for replay in "${replay_temps[@]}"; do
    create_response_private_file "$replay" || \
      fail "interrupted Cat create replay temp is unsafe"
    rm -f "$replay"
  done
  ((${#replay_temps[@]} == 0)) || sync -f "$CASE_DIR"
  replay=$(mktemp "$CASE_DIR/.create-response-replay.XXXXXX")
  chmod 0600 "$replay"
  if ! run_cat_create_to "$replay" true "$expected_name"; then
    rm -f "$replay"
    sync -f "$CASE_DIR"
    return 1
  fi
  sync -f "$replay" || fail "sync Cat create exact-replay response"
  if create_response_is_no_pending "$replay"; then
    :
  elif create_response_is_accepted "$replay"; then
    replay_canonical=$(jq -S -c . "$replay")
    output_canonical=$(jq -S -c . "$output")
    [[ $replay_canonical == "$output_canonical" ]] || \
      fail "durable CLI journal replay returned another accepted Cat identity"
  else
    fail "existing-only Cat create returned neither accepted identity nor typed absence"
  fi
  rm -f "$replay"
  sync -f "$CASE_DIR"
}

fixture_kill_before_runtime_cat_state() {
  [[ ${CATS_E3_FIXTURE_MODE:-} == enabled && \
    ${CATS_E3_FIXTURE_CAT_CREATE_CRASH_POINT:-} == before-runtime-state ]] || return 0
  local once=${CATS_E3_FIXTURE_KILL_ONCE_FILE:-} pid=${CATS_E3_FIXTURE_SCENARIO_PID:-}
  [[ $once == /* && $pid =~ ^[1-9][0-9]*$ ]] || return 125
  if [[ ! -e $once ]]; then
    (umask 077; printf '%s\n' killed >"$once")
    sync -f "${once%/*}"
    kill -KILL "$pid"
  fi
}

run_create() {
  local output response_temp cat_id operation_id expected_name expected_node placement_snapshot
  local runtime_cat_id response_canonical output_canonical
  local response_temps=()
  expected_name=$(required CATS_E3_CAT_NAME)
  output=$CASE_DIR/create-response.json
  runtime_cat_id=$(jq -er '.cat_id // empty' "$(nonsecret_path CATS_E3_RUNTIME_STATE)" \
    2>/dev/null || true)
  if [[ -n $runtime_cat_id ]]; then
    canonical_id runtime_state_cat_id "$runtime_cat_id"
    [[ -e $output || -L $output ]] || \
      fail "durable Cat identity has no adjacent create response"
  fi
  if [[ -e $output || -L $output ]]; then
    recover_interrupted_adoption "$output"
    create_response_is_accepted "$output" || \
      fail "durable Cat create response is unsafe"
    shopt -s nullglob
    response_temps=("$CASE_DIR"/.create-response.json.*)
    shopt -u nullglob
    for response_temp in "${response_temps[@]}"; do
      create_response_private_file "$response_temp" || \
        fail "interrupted Cat create response temp is unsafe"
      if create_response_is_accepted "$response_temp"; then
        response_canonical=$(jq -S -c . "$response_temp")
        output_canonical=$(jq -S -c . "$output")
        [[ $response_canonical == "$output_canonical" ]] || \
          fail "interrupted Cat create response temp conflicts with durable identity"
      fi
      rm -f "$response_temp"
    done
    ((${#response_temps[@]} == 0)) || sync -f "$CASE_DIR"
    resolve_cat_create_cli_journal "$output" "$expected_name" || \
      fail "could not resolve the exact durable Cat create CLI journal"
  else
    shopt -s nullglob
    response_temps=("$CASE_DIR"/.create-response.json.*)
    shopt -u nullglob
    ((${#response_temps[@]} <= 1)) || \
      fail "Cat create has multiple interrupted response temps"
    if ((${#response_temps[@]} == 1)); then
      response_temp=${response_temps[0]}
      create_response_private_file "$response_temp" || \
        fail "interrupted Cat create response temp is unsafe"
      if create_response_is_accepted "$response_temp"; then
        publish_create_response "$response_temp" "$output"
        resolve_cat_create_cli_journal "$output" "$expected_name" || \
          fail "could not resolve the exact durable Cat create CLI journal"
      else
        if run_cat_create_to "$response_temp" true "$expected_name"; then
          sync -f "$response_temp" || fail "sync exact Cat create replay response"
        else
          fail "exact pending Cat create replay remained ambiguous"
        fi
        if create_response_is_no_pending "$response_temp"; then
          rm -f "$response_temp"
          sync -f "$CASE_DIR"
          response_temp=$(mktemp "$CASE_DIR/.create-response.json.XXXXXX")
          chmod 0600 "$response_temp"
          run_cat_create_to "$response_temp" false "$expected_name" || \
            fail "Cat create did not reach one durable accepted identity"
          sync -f "$response_temp"
        fi
        create_response_is_accepted "$response_temp" || \
          fail "exact Cat create replay did not return one accepted identity"
        publish_create_response "$response_temp" "$output"
      fi
    else
      response_temp=$(mktemp "$CASE_DIR/.create-response.json.XXXXXX")
      chmod 0600 "$response_temp"
      run_cat_create_to "$response_temp" false "$expected_name" || \
        fail "Cat create did not reach one durable accepted identity"
      sync -f "$response_temp"
      create_response_is_accepted "$response_temp" || \
        fail "Cat create returned no complete accepted identity"
      publish_create_response "$response_temp" "$output"
    fi
  fi
  create_response_is_accepted "$output" || fail "durable Cat create response is unsafe"
  cat_id=$(json_field "$output" '.cat_id')
  operation_id=$(json_field "$output" '.operation_id')
  canonical_id cat_id "$cat_id"
  canonical_id operation_id "$operation_id"
  [[ -z $runtime_cat_id || $runtime_cat_id == "$cat_id" ]] || \
    fail "durable Cat identity differs from the accepted create response"
  fixture_kill_before_runtime_cat_state
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
  local destination=${1:-$CASE_DIR/public-route-receipt.json}
  local origin source attempt route_status
  origin=${CATS_E3_PUBLIC_ORIGIN:-https://$(required CATS_E3_ENDPOINT_HOSTNAME)}
  [[ $origin == "https://$(required CATS_E3_ENDPOINT_HOSTNAME)" ]] || \
    fail "CATS_E3_PUBLIC_ORIGIN must be the exact deployed endpoint origin"
  [[ $destination == "$CASE_DIR/"* ]] || fail "public Route receipt is outside the case directory"
  if [[ -e $destination ]]; then
    jq -e --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" '
      .version == 1 and .origin == $origin and .run_id == $run_id
      and .http_guest_body == true and .websocket_guest_echo == true' \
      "$destination" >/dev/null || fail "durable public Route receipt changed across resume"
    return
  fi
  source=${destination%/*}/.${destination##*/}.source
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
  publish_json_idempotent_path "$destination" "$source"
  rm -f "$source"
}

rotation_transcript() {
  local phase=$1 event=$2 detail=$3
  local transcript=$CASE_DIR/route-v2-rotation-disable-live-delivery.transcript.log temporary
  [[ $phase =~ ^[a-z0-9_]+$ && $event =~ ^[a-z0-9_]+$ && $detail =~ ^[A-Za-z0-9_:.-]+$ ]] || \
    fail "Route rotation transcript event is not bounded text"
  temporary=$(mktemp "$CASE_DIR/.route-v2-rotation-transcript.XXXXXX")
  cat "$transcript" >"$temporary"
  printf 'phase=%s event=%s detail=%s\n' "$phase" "$event" "$detail" >>"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$transcript"
  durable_case_file "$transcript"
}

rotation_phase_revision() {
  jq -er --arg phase "$1" '.commands[] | select(.phase == $phase) | .signer_revision' \
    "$(rotation_input route-rotation-command-bundle)"
}

rotation_phase_ring_version() {
  jq -er --arg phase "$1" '.commands[] | select(.phase == $phase) | .ring_version' \
    "$(rotation_input route-rotation-command-bundle)"
}

rotation_phase_rollout_field() {
  local phase=$1 expression=$2 revision
  revision=$(rotation_phase_revision "$phase")
  jq -er --argjson revision "$revision" \
    ".control_rollouts[] | select(.signer_revision == \$revision) | $expression" \
    "$(rotation_input route-rotation-command-bundle)"
}

sign_rotation_attempt() {
  local phase=$1 attempt=$2 pending=$3 signing=$4 cats_bin authority_command_sha replayed signing_probe
  replayed=false
  [[ ! -e $pending ]] || replayed=true
  cats_bin=$(binary cats)
  signing_probe=$(mktemp "$ROTATION_JOURNAL/.$phase.attempt-$attempt.signing.probe.XXXXXX")
  "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
    sign-prepared-rotation-phase \
    --trust "$(rotation_input route-rotation-operator-trust)" \
    --operator-private-key "$(rotation_input route-rotation-operator-key)" \
    --command-bundle "$(rotation_input route-rotation-command-bundle)" \
    --phase "$phase" --output "$pending" >"$signing_probe"
  adopt_rotation_file "$signing_probe" "$signing"
  rm -f "$signing_probe"
  authority_command_sha=$(jq -er --arg phase "$phase" \
    '.commands[] | select(.phase == $phase) | .exact_authority_command_sha256' \
    "$(rotation_input route-rotation-command-bundle)")
  jq -e --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg phase "$phase" --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg authority_command_sha "$authority_command_sha" \
    --arg signed_command_sha "$(sha256_wire "$pending")" \
    --arg pending_path "$pending" \
    --argjson revision "$(rotation_phase_revision "$phase")" \
    --argjson ring "$(rotation_phase_ring_version "$phase")" '
    .version == 1 and .case_id == $case_id and .qualification_run_id == $run_id
    and .phase == $phase and .release_commit_sha == $commit
    and .authority_id == $authority and .route_deployment_id == $deployment
    and .signer_revision == $revision and .ring_version == $ring
    and (.command_id | test("^[0-9a-f]{32}$"))
    and .exact_authority_command_sha256 == $authority_command_sha
    and .exact_signed_command_sha256 == $signed_command_sha
    and .pending_command_path == $pending_path
    and (.issued_at_unix_ms | type == "number" and . > 0)
    and (.expires_at_unix_ms - .issued_at_unix_ms == 300000)' \
    "$signing" >/dev/null || fail "fresh Route rotation command signing receipt is not exact"
  durable_case_file "$pending"
  if [[ $replayed == true ]]; then
    rotation_transcript "$phase" signed_replay "attempt_$attempt"
  else
    rotation_transcript "$phase" signed_fresh "attempt_$attempt"
  fi
}

post_rotation_attempt() {
  local phase=$1 pending=$2 response=$3 response_probe status transport_try command_id command_sha request_status
  command_id=$(jq -er '.payload.command_id' "$pending")
  command_sha=$(sha256_wire "$pending")
  response_probe=$(mktemp "$ROTATION_JOURNAL/.$phase.store-response.probe.XXXXXX")
  status=
  for transport_try in 1 2 3 4 5; do
    set +e
    status=$(curl_secret_url POST \
      "$(rotation_transport_field '.rotation_origin')/v1/internal/route-v2/signing-authority-commands" \
      "$response_probe" 200,409 \
      --header 'content-type: application/json' --data-binary "@$pending")
    request_status=$?
    set -e
    [[ $request_status -eq 0 ]] && break
    sleep 1
  done
  [[ $status == 200 || $status == 409 ]] || fail "signed Route rotation command remained ambiguous"
  adopt_rotation_file "$response_probe" "$response"
  rm -f "$response_probe"
  if [[ $status == 409 ]] && jq -e '
    keys == ["code","message"]
    and .code == "command_outside_execution_window"
    and .message == "Route v2 rotation command is outside its execution window"' \
    "$response" >/dev/null; then
    # The Store checks this outcome under the same exclusive authority lock
    # after proving command_id absence. A later attempt may therefore use a
    # fresh ID without creating two effects.
    printf '%s' expired_uncommitted
    return
  fi
  jq -e --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg commit "$CATS_E3_EXACT_COMMIT" --arg command_id "$command_id" \
    --arg command_sha "$command_sha" '
    .version == 1 and .authority_id == $authority and .release_commit_sha == $commit
    and .command_id == $command_id and .exact_command_sha256 == $command_sha
    and (.committed_at_unix_ms | type == "number" and . > 0)
    and (.result.outcome == "applied"
      or .result.outcome == "authority_precondition_failed")' \
    "$response" >/dev/null || fail "Route rotation Store receipt is not exact"
  if [[ $status == 200 && $(jq -er '.result.outcome' "$response") == applied ]]; then
    printf '%s' applied
  elif [[ $status == 409 && $(jq -er '.result.outcome' "$response") == authority_precondition_failed ]]; then
    printf '%s' precondition_failed
  else
    fail "Route rotation receipt status and outcome disagree"
  fi
}

wait_rotation_store_precondition() {
  local phase=$1 observed destination expected_ring_digest expected_kids expected_ring_version
  local expected_signer expected_signer_revision attempt status ready require_closed probe projection
  case "$phase" in
    switch_active) observed=publish_overlap; require_closed=false ;;
    retire) observed=publish_new_only; require_closed=false ;;
    activate) observed=publish_recovery; require_closed=true ;;
    *) return ;;
  esac
  destination=$ROTATION_JOURNAL/$phase.precondition-fleet.json
  expected_ring_digest=$(rotation_phase_rollout_field "$observed" '.public_key_ring_digest')
  expected_ring_version=$(rotation_phase_ring_version "$observed")
  expected_signer_revision=$(rotation_phase_revision "$observed")
  expected_kids=$(jq -c --arg phase "$observed" '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor_ring.keys | map(.kid)' \
    "$(rotation_input route-rotation-command-bundle)")
  expected_signer=$(jq -c --arg phase "$observed" '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor.signer' \
    "$(rotation_input route-rotation-command-bundle)")
  if [[ -e $destination ]]; then
    projection=$(mktemp "$ROTATION_JOURNAL/.$phase.precondition-projection.XXXXXX")
    write_rotation_store_precondition_projection "$phase" "$projection"
    rm -f "$projection"
    rotation_transcript "$phase" resumed_store_precondition "ring_$expected_ring_version"
    return
  fi
  probe=$(mktemp "$ROTATION_JOURNAL/.$phase.precondition-fleet.probe.XXXXXX")
  ready=false
  attempt=0
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 45
    set +e
    raw_fleet_snapshot_to "$probe"
    status=$?
    set -e
    if [[ $status -eq 0 ]] && jq -e \
      --argjson ring_version "$expected_ring_version" \
      --argjson signer_revision "$expected_signer_revision" \
      --arg ring_digest "$expected_ring_digest" --argjson kids "$expected_kids" \
      --argjson signer "$expected_signer" \
      --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
      --argjson require_closed "$require_closed" \
      --arg nodes "$(required CATS_E3_EXPECTED_NODES)" '
      . as $root | ($nodes | split(",")) as $expected
      | .route_signing_authority.deployment_id == $deployment
      and .route_signing_authority.signer_revision == $signer_revision
      and .route_signing_authority.active_kid == ($signer.active_kid // null)
      and .route_signing_authority.public_key_ring_version == $ring_version
      and .route_signing_authority.public_key_ring_digest == $ring_digest
      and ([.nodes[].node_id] | sort) == ($expected | sort)
      and all(.nodes[];
        .session != null and .inventory != null and .inventory.complete_inventory == true
        and .inventory.source_session.node_id == .session.node_id
        and .inventory.source_session.node_boot_id == .session.node_boot_id
        and .inventory.source_session.agent_instance_id == .session.agent_instance_id
        and .inventory.source_session.agent_session_epoch == .session.agent_session_epoch
        and .inventory.attestation.accepted_at_unix_ms <= $root.evaluated_at_unix_ms
        and $root.evaluated_at_unix_ms < (.inventory.attestation.accepted_at_unix_ms + 60000)
        and .inventory.key_ring_version == $ring_version
        and .inventory.key_ring_digest == $ring_digest
        and .inventory.loaded_kids == $kids
        and (if $require_closed then
          .inventory.route_active_count == 0 and .inventory.active_guard_count == 0
          and .inventory.residue_count == 0
          and .inventory.cancellation_pending_count == 0
          and .inventory.quarantined_condition_count == 0
        else true end))
      and (if $require_closed then ([.nodes[].inventory.route_closed_count] | add) == 1
        else true end)' "$probe" >/dev/null; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ $ready == true ]] || fail "Route rotation Store precondition did not become observable before signing"
  adopt_rotation_file "$probe" "$destination"
  rm -f "$probe"
  rotation_transcript "$phase" store_precondition_observed "ring_$expected_ring_version"
}

write_rotation_store_precondition_projection() {
  local phase=$1 output=$2 observed condition fleet require_closed
  local ring_digest ring_version signer_revision kids signer fleet_sha
  case "$phase" in
    switch_active)
      observed=publish_overlap
      condition=all_schedulable_nodes_ack_ring
      fleet=$ROTATION_JOURNAL/switch_active.precondition-fleet.json
      require_closed=false
      ;;
    retire)
      observed=publish_new_only
      condition=all_schedulable_nodes_ack_ring
      fleet=$ROTATION_JOURNAL/retire.precondition-fleet.json
      require_closed=false
      ;;
    publish_recovery)
      observed=disable
      condition=all_provisioned_nodes_closed_or_fenced
      fleet=$ROTATION_JOURNAL/rotation-disabled-fleet.json
      require_closed=true
      ;;
    activate)
      observed=publish_recovery
      condition=all_provisioned_nodes_closed_or_fenced_and_ack_ring
      fleet=$ROTATION_JOURNAL/activate.precondition-fleet.json
      require_closed=true
      ;;
    *)
      printf 'null\n' >"$output"
      return
      ;;
  esac
  [[ -f $fleet && ! -L $fleet && -O $fleet ]] || \
    fail "Route rotation Store precondition Fleet snapshot is missing or unsafe"
  ring_digest=$(rotation_phase_rollout_field "$observed" '.public_key_ring_digest')
  ring_version=$(rotation_phase_ring_version "$observed")
  signer_revision=$(rotation_phase_revision "$observed")
  kids=$(jq -c --arg phase "$observed" '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor_ring.keys | map(.kid)' \
    "$(rotation_input route-rotation-command-bundle)")
  signer=$(jq -c --arg phase "$observed" '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor.signer' \
    "$(rotation_input route-rotation-command-bundle)")
  fleet_sha=$(sha256_wire "$fleet")
  jq -S -c -n \
    --arg observed_phase "$observed" --arg required_condition "$condition" \
    --arg fleet_sha256 "$fleet_sha" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --argjson signer_revision "$signer_revision" --argjson signer "$signer" \
    --argjson ring_version "$ring_version" --arg ring_digest "$ring_digest" \
    --argjson kids "$kids" --argjson require_closed "$require_closed" \
    --arg nodes "$(required CATS_E3_EXPECTED_NODES)" --slurpfile fleet "$fleet" '
    def projected_nodes($snapshot):
      [$snapshot.nodes[] |
        {node_id,binding:{node_id:.session.node_id,node_boot_id:.session.node_boot_id,
           agent_instance_id:.session.agent_instance_id,
           agent_epoch:.session.agent_session_epoch},
         inventory:{source_observation_id:.inventory.source_observation_id,
           source_heartbeat_sequence:.inventory.source_heartbeat_sequence,
           source_binding:{node_id:.inventory.source_session.node_id,
             node_boot_id:.inventory.source_session.node_boot_id,
             agent_instance_id:.inventory.source_session.agent_instance_id,
             agent_epoch:.inventory.source_session.agent_session_epoch},
           attestation_accepted_at_unix_ms:.inventory.attestation.accepted_at_unix_ms,
           complete_inventory:.inventory.complete_inventory,
           key_ring_version:.inventory.key_ring_version,
           key_ring_digest:.inventory.key_ring_digest,loaded_kids:.inventory.loaded_kids,
           route_active_count:.inventory.route_active_count,
           route_closed_count:.inventory.route_closed_count,
           active_guard_count:.inventory.active_guard_count,
           residue_count:.inventory.residue_count,
           cancellation_pending_count:.inventory.cancellation_pending_count,
           quarantined_condition_count:.inventory.quarantined_condition_count}}]
      | sort_by(.node_id);
    ($nodes | split(",") | sort) as $expected
    | projected_nodes($fleet[0]) as $projected
    | {version:1,observed_phase:$observed_phase,required_condition:$required_condition,
       fleet_sha256:$fleet_sha256,evaluated_at_unix_ms:$fleet[0].evaluated_at_unix_ms,
       signing_authority:$fleet[0].route_signing_authority,
       expected_nodes:$expected,nodes:$projected,
       expected_signer_revision:$signer_revision,
       expected_active_kid:($signer.active_kid // null),
       expected_ring_version:$ring_version,expected_ring_digest:$ring_digest,
       expected_loaded_kids:$kids,require_closed:$require_closed,
       satisfied:
         ($fleet[0].route_signing_authority.deployment_id == $deployment
          and $fleet[0].route_signing_authority.signer_revision == $signer_revision
          and $fleet[0].route_signing_authority.active_kid == ($signer.active_kid // null)
          and $fleet[0].route_signing_authority.public_key_ring_version == $ring_version
          and $fleet[0].route_signing_authority.public_key_ring_digest == $ring_digest
          and ($projected | map(.node_id)) == $expected
          and all($projected[];
            .binding == .inventory.source_binding
            and .inventory.complete_inventory == true
            and .inventory.attestation_accepted_at_unix_ms <= $fleet[0].evaluated_at_unix_ms
            and $fleet[0].evaluated_at_unix_ms
              < (.inventory.attestation_accepted_at_unix_ms + 60000)
            and .inventory.key_ring_version == $ring_version
            and .inventory.key_ring_digest == $ring_digest
            and .inventory.loaded_kids == $kids
            and (if $require_closed then
              .inventory.route_active_count == 0 and .inventory.active_guard_count == 0
              and .inventory.residue_count == 0
              and .inventory.cancellation_pending_count == 0
              and .inventory.quarantined_condition_count == 0
            else true end))
          and (if $require_closed
            then ([$projected[].inventory.route_closed_count] | add) == 1
            else true end))}' >"$output"
  jq -e '.satisfied == true' "$output" >/dev/null || \
    fail "Route rotation Store precondition projection is not independently closed"
}

advance_rotation_phase() {
  local phase=$1 attempt pending signing response outcome revision ring_version
  revision=$(rotation_phase_revision "$phase")
  ring_version=$(rotation_phase_ring_version "$phase")
  attempt=0
  while [[ $attempt -lt 360 ]]; do
    attempt=$((attempt + 1))
    pending=$ROTATION_JOURNAL/$phase.attempt-$attempt.command.json
    signing=$ROTATION_JOURNAL/$phase.attempt-$attempt.signing-receipt.json
    response=$ROTATION_JOURNAL/$phase.attempt-$attempt.store-receipt.json
    if [[ ! -e $pending ]]; then
      wait_rotation_store_precondition "$phase"
    fi
    rotation_require_budget 45
    sign_rotation_attempt "$phase" "$attempt" "$pending" "$signing"
    outcome=$(post_rotation_attempt "$phase" "$pending" "$response")
    if [[ $outcome == applied ]]; then
      jq -e --argjson revision "$revision" --argjson ring "$ring_version" '
        .result.signer_revision == $revision
        and .result.public_key_ring_version == $ring' "$response" >/dev/null || \
        fail "Route rotation Store applied another successor"
      adopt_rotation_file "$pending" "$ROTATION_JOURNAL/$phase.signed-command.json"
      adopt_rotation_file "$signing" "$ROTATION_JOURNAL/$phase.signing-receipt.json"
      adopt_rotation_file "$response" "$ROTATION_JOURNAL/$phase.store-receipt.json"
      rotation_transcript "$phase" store_applied "attempt_$attempt"
      return
    fi
    [[ $outcome == precondition_failed || $outcome == expired_uncommitted ]] || \
      fail "Route rotation phase returned a non-retryable Store result"
    rotation_transcript "$phase" "$outcome" "attempt_$attempt"
    sleep 1
  done
  fail "Route rotation phase did not satisfy its bounded Store precondition"
}

wait_rotation_retention() {
  local committed_ms target_seconds now_seconds attempt
  committed_ms=$(jq -er '.committed_at_unix_ms' "$ROTATION_JOURNAL/switch_active.store-receipt.json")
  target_seconds=$(( (committed_ms + 305000) / 1000 + 1 ))
  attempt=0
  while [[ $attempt -lt 420 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 45
    now_seconds=$(date +%s)
    if [[ $now_seconds -gt $target_seconds ]]; then
      rotation_transcript publish_new_only retention_elapsed "strictly_after_switch_plus_305s"
      return
    fi
    sleep 1
  done
  fail "worker clock did not reach the bounded Route rotation retention deadline"
}

future_rotation_receipts_absent() {
  local phase=$1 transport current_index future_url future_phase probe status fetch_status
  transport=$(rotation_input route-rotation-recovery)
  current_index=$(jq -er --arg phase "$phase" \
    '.phases | map(.phase) | index($phase)' "$transport")
  while IFS=$'\t' read -r future_phase future_url; do
    [[ -n $future_phase && -n $future_url ]] || continue
    probe=$ROTATION_JOURNAL/.future-$future_phase.probe
    rotation_require_budget 45
    set +e
    status=$(curl_secret_url GET "$future_url" "$probe" 200,404)
    fetch_status=$?
    set -e
    rm -f "$probe"
    [[ $fetch_status -eq 0 ]] || return 75
    [[ $status == 404 ]] || fail "a future rollout receipt appeared before its Store phase"
  done < <(jq -r --argjson index "$current_index" \
    '.phases[($index + 1):][] | [.phase,.receipt_url] | @tsv' "$transport")
}

fetch_rotation_apply_receipt() {
  local phase=$1 transport url expected_url_sha actual_url_sha saved_plan_sha
  local receipt second probe status fetch_status attempt cats_bin verification report
  local verification_probe_dir verification_probe report_probe
  transport=$(rotation_input route-rotation-recovery)
  url=$(jq -er --arg phase "$phase" '.phases[] | select(.phase == $phase) | .receipt_url' "$transport")
  expected_url_sha=$(jq -er --arg phase "$phase" \
    '.phases[] | select(.phase == $phase) | .receipt_url_sha256' "$transport")
  actual_url_sha="sha256:$(printf '%s' "$url" | sha256sum | awk '{print $1}')"
  [[ $actual_url_sha == "$expected_url_sha" ]] || fail "rollout receipt URL digest differs from descriptor"
  saved_plan_sha=$(jq -er --arg phase "$phase" \
    '.phases[] | select(.phase == $phase) | .saved_plan_sha256' "$transport")
  receipt=$ROTATION_JOURNAL/$phase.apply-receipt.signed.json
  second=$ROTATION_JOURNAL/.$phase.apply-receipt.second
  probe=$ROTATION_JOURNAL/.$phase.apply-receipt.probe
  attempt=0
  while [[ $attempt -lt 600 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 45
    if ! future_rotation_receipts_absent "$phase"; then
      sleep 1
      continue
    fi
    set +e
    status=$(curl_secret_url GET "$url" "$probe" 200,404)
    fetch_status=$?
    set -e
    if [[ $fetch_status -ne 0 ]]; then
      rm -f "$probe"
      sleep 1
      continue
    fi
    if [[ $status == 404 ]]; then
      rm -f "$probe"
      sleep 1
      continue
    fi
    [[ $(wc -c <"$probe") -le 32768 ]] || fail "signed rollout receipt exceeds its wire bound"
    jq -e . "$probe" >/dev/null || fail "signed rollout receipt is not JSON"
    set +e
    status=$(curl_secret_url GET "$url" "$second" 200)
    fetch_status=$?
    set -e
    [[ $fetch_status -eq 0 && $status == 200 ]] || fail "signed rollout receipt could not be re-read immutably"
    cmp -s "$probe" "$second" || fail "same rollout phase returned different receipt bytes"
    rm -f "$second"
    adopt_rotation_file "$probe" "$receipt"
    rm -f "$probe"
    verification=$ROTATION_JOURNAL/$phase.apply-verification.json
    report=$ROTATION_JOURNAL/$phase.apply-verification-report.json
    verification_probe_dir=$(mktemp -d "$ROTATION_JOURNAL/.$phase.apply-verification.XXXXXX")
    chmod 0700 "$verification_probe_dir"
    verification_probe=$verification_probe_dir/output.json
    report_probe=$verification_probe_dir/report.json
    cats_bin=$(binary cats)
    "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
      verify-control-rollout-apply-receipt \
      --trust "$(rotation_input route-rotation-operator-trust)" \
      --command-bundle "$(rotation_input route-rotation-command-bundle)" \
      --phase "$phase" \
      --qualification-catalog-sha256 "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
      --saved-plan-sha256 "$saved_plan_sha" \
      --receipt "$receipt" --output "$verification_probe" >"$report_probe"
    jq -e -n --slurpfile verification "$verification_probe" --slurpfile report "$report_probe" \
      '$verification == $report' >/dev/null || fail "rollout receipt verifier report differs from durable output"
    jq -e --arg cats_sha256 "sha256:$(binary_sha256 cats)" \
      '.receipt_signer_executable_sha256 == $cats_sha256' "$verification_probe" >/dev/null || \
      fail "rollout receipt signer is not the exact qualification Cats executable"
    adopt_rotation_file "$verification_probe" "$verification"
    adopt_rotation_file "$report_probe" "$report"
    rm -f "$verification_probe" "$report_probe"
    rmdir "$verification_probe_dir"
    rotation_transcript "$phase" apply_receipt_verified "url_digest_$expected_url_sha"
    return
  done
  fail "deployment controller did not publish the bounded rollout receipt"
}

verify_rotation_current_after_rollout() {
  local phase=$1 revision discovery discovery_probe verification report cats_bin
  local verification_probe_dir verification_probe report_probe
  revision=$(rotation_phase_revision "$phase")
  discovery=$ROTATION_JOURNAL/$phase.current-discovery.json
  discovery_probe=$(mktemp "$ROTATION_JOURNAL/.$phase.current-discovery.probe.XXXXXX")
  rotation_json_request GET \
    /v1/internal/route-v2/signing-authority-current "$discovery_probe" 200 || \
    fail "Route rotation current discovery is unavailable after rollout receipt"
  adopt_rotation_file "$discovery_probe" "$discovery"
  rm -f "$discovery_probe"
  verification=$ROTATION_JOURNAL/$phase.current-verification.json
  report=$ROTATION_JOURNAL/$phase.current-verification-report.json
  verification_probe_dir=$(mktemp -d "$ROTATION_JOURNAL/.$phase.current-verification.XXXXXX")
  chmod 0700 "$verification_probe_dir"
  verification_probe=$verification_probe_dir/output.json
  report_probe=$verification_probe_dir/report.json
  cats_bin=$(binary cats)
  "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
    verify-prepared-rotation-current \
    --trust "$(rotation_input route-rotation-operator-trust)" \
    --command-bundle "$(rotation_input route-rotation-command-bundle)" \
    --signer-revision "$revision" --discovery "$discovery" \
    --output "$verification_probe" >"$report_probe"
  jq -e -n --slurpfile verification "$verification_probe" --slurpfile report "$report_probe" \
    '$verification == $report' >/dev/null || fail "current-binding verifier report differs from durable output"
  [[ $(jq -er '.postcondition_discovery_sha256' "$ROTATION_JOURNAL/$phase.apply-verification.json") == \
    "$(sha256_wire "$discovery")" ]] || \
    fail "rollout receipt postcondition differs from worker current discovery"
  adopt_rotation_file "$verification_probe" "$verification"
  adopt_rotation_file "$report_probe" "$report"
  rm -f "$verification_probe" "$report_probe"
  rmdir "$verification_probe_dir"
  rotation_transcript "$phase" current_process_verified "signer_revision_$revision"
}

write_rotation_phase_summary() {
  local phase=$1 summary=$2 transport url_sha saved_plan_sha precondition
  transport=$(rotation_input route-rotation-recovery)
  url_sha=$(jq -er --arg phase "$phase" \
    '.phases[] | select(.phase == $phase) | .receipt_url_sha256' "$transport")
  saved_plan_sha=$(jq -er --arg phase "$phase" \
    '.phases[] | select(.phase == $phase) | .saved_plan_sha256' "$transport")
  precondition=$(mktemp "$ROTATION_JOURNAL/.$phase.store-precondition.XXXXXX")
  write_rotation_store_precondition_projection "$phase" "$precondition"
  jq -S -c -n \
    --arg phase "$phase" \
    --argjson signer_revision "$(rotation_phase_revision "$phase")" \
    --argjson ring_version "$(rotation_phase_ring_version "$phase")" \
    --arg saved_plan_sha256 "$saved_plan_sha" \
    --arg receipt_url_sha256 "$url_sha" \
    --arg signed_command_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.signed-command.json")" \
    --arg store_command_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.store-receipt.json")" \
    --arg signed_apply_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.apply-receipt.signed.json")" \
    --arg apply_verification_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.apply-verification.json")" \
    --arg current_discovery_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.current-discovery.json")" \
    --arg current_verification_sha256 "$(sha256_wire "$ROTATION_JOURNAL/$phase.current-verification.json")" \
    --slurpfile signing "$ROTATION_JOURNAL/$phase.signing-receipt.json" \
    --slurpfile store "$ROTATION_JOURNAL/$phase.store-receipt.json" \
    --slurpfile apply "$ROTATION_JOURNAL/$phase.apply-verification.json" \
    --slurpfile current "$ROTATION_JOURNAL/$phase.current-verification.json" \
    --slurpfile precondition "$precondition" \
    '{phase:$phase,signer_revision:$signer_revision,ring_version:$ring_version,
      command_id:$signing[0].command_id,
      issued_at_unix_ms:$signing[0].issued_at_unix_ms,
      expires_at_unix_ms:$signing[0].expires_at_unix_ms,
      authority_command_sha256:$signing[0].exact_authority_command_sha256,
      signed_command_sha256:$signed_command_sha256,
      store_command_receipt_sha256:$store_command_receipt_sha256,
      store_outcome:$store[0].result.outcome,
      committed_at_unix_ms:$store[0].committed_at_unix_ms,
      store_precondition:$precondition[0],
      saved_plan_sha256:$saved_plan_sha256,receipt_url_sha256:$receipt_url_sha256,
      signed_apply_receipt_sha256:$signed_apply_receipt_sha256,
      apply_verification_sha256:$apply_verification_sha256,
      terraform_show_json_sha256:$apply[0].terraform_show_json_sha256,
      plan_validation_receipt_sha256:$apply[0].plan_validation_receipt_sha256,
      terraform_executable_sha256:$apply[0].terraform_executable_sha256,
      deployment_operator_executable_sha256:$apply[0].deployment_operator_executable_sha256,
      saved_plan_validator_executable_sha256:$apply[0].saved_plan_validator_executable_sha256,
      receipt_signer_executable_sha256:$apply[0].receipt_signer_executable_sha256,
      apply_outcome:$apply[0].apply_outcome,
      terraform_apply_stdout_sha256:$apply[0].terraform_apply_stdout_sha256,
      terraform_apply_stderr_sha256:$apply[0].terraform_apply_stderr_sha256,
      postcondition_discovery_sha256:$apply[0].postcondition_discovery_sha256,
      current_discovery_sha256:$current_discovery_sha256,
      current_verification_sha256:$current_verification_sha256,
      signer_state:$current[0].signer_state,active_kid:$current[0].active_kid,
      public_key_ring_digest:$current[0].public_key_ring_digest,
      database_current:$current[0].database_current,process_ready:$current[0].process_ready,
      terminal_marker:$apply[0].terminal_marker}' >"$summary"
  rm -f "$precondition"
}

verify_completed_rotation_phase() {
  local phase=$1 signing pending expected_summary report cats_bin saved_plan_sha artifact
  local verification_probe_dir verification_probe
  for artifact in signed-command signing-receipt store-receipt apply-receipt.signed \
    apply-verification apply-verification-report current-discovery current-verification \
    current-verification-report phase-receipt; do
    [[ -f $ROTATION_JOURNAL/$phase.$artifact.json && ! -L $ROTATION_JOURNAL/$phase.$artifact.json ]] || \
      fail "completed Route rotation phase $phase is missing $artifact"
  done
  signing=$ROTATION_JOURNAL/$phase.signing-receipt.json
  pending=$(jq -er '.pending_command_path' "$signing")
  [[ $pending == "$ROTATION_JOURNAL/"* && -f $pending && ! -L $pending ]] || \
    fail "completed Route rotation phase points outside its durable pending journal"
  cmp -s "$pending" "$ROTATION_JOURNAL/$phase.signed-command.json" || \
    fail "completed Route rotation signed command differs from its durable pending bytes"
  report=$ROTATION_JOURNAL/.$phase.signing-reverify.json
  cats_bin=$(binary cats)
  "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
    sign-prepared-rotation-phase \
    --trust "$(rotation_input route-rotation-operator-trust)" \
    --operator-private-key "$(rotation_input route-rotation-operator-key)" \
    --command-bundle "$(rotation_input route-rotation-command-bundle)" \
    --phase "$phase" --output "$pending" >"$report"
  cmp -s "$report" "$signing" || \
    fail "completed Route rotation signing receipt no longer verifies"
  rm -f "$report"
  jq -e --argjson revision "$(rotation_phase_revision "$phase")" \
    --argjson ring "$(rotation_phase_ring_version "$phase")" \
    --arg command_sha "$(sha256_wire "$ROTATION_JOURNAL/$phase.signed-command.json")" '
    .result.outcome == "applied" and .result.signer_revision == $revision
    and .result.public_key_ring_version == $ring
    and .exact_command_sha256 == $command_sha' \
    "$ROTATION_JOURNAL/$phase.store-receipt.json" >/dev/null || \
    fail "completed Route rotation Store receipt is not exact"
  saved_plan_sha=$(jq -er --arg phase "$phase" \
    '.phases[] | select(.phase == $phase) | .saved_plan_sha256' \
    "$(rotation_input route-rotation-recovery)")
  report=$ROTATION_JOURNAL/.$phase.apply-reverify.json
  verification_probe_dir=$(mktemp -d "$ROTATION_JOURNAL/.$phase.apply-reverify.XXXXXX")
  chmod 0700 "$verification_probe_dir"
  verification_probe=$verification_probe_dir/output.json
  "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
    verify-control-rollout-apply-receipt \
    --trust "$(rotation_input route-rotation-operator-trust)" \
    --command-bundle "$(rotation_input route-rotation-command-bundle)" \
    --phase "$phase" \
    --qualification-catalog-sha256 "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
    --saved-plan-sha256 "$saved_plan_sha" \
    --receipt "$ROTATION_JOURNAL/$phase.apply-receipt.signed.json" \
    --output "$verification_probe" >"$report"
  cmp -s "$verification_probe" "$ROTATION_JOURNAL/$phase.apply-verification.json" || \
    fail "completed Route rotation apply verification bytes changed"
  cmp -s "$report" "$ROTATION_JOURNAL/$phase.apply-verification-report.json" || \
    fail "completed Route rotation apply receipt no longer verifies"
  rm -f "$report" "$verification_probe"
  rmdir "$verification_probe_dir"
  report=$ROTATION_JOURNAL/.$phase.current-reverify.json
  verification_probe_dir=$(mktemp -d "$ROTATION_JOURNAL/.$phase.current-reverify.XXXXXX")
  chmod 0700 "$verification_probe_dir"
  verification_probe=$verification_probe_dir/output.json
  "$cats_bin" --json admin runtime-provisioner route-v2-r1 \
    verify-prepared-rotation-current \
    --trust "$(rotation_input route-rotation-operator-trust)" \
    --command-bundle "$(rotation_input route-rotation-command-bundle)" \
    --signer-revision "$(rotation_phase_revision "$phase")" \
    --discovery "$ROTATION_JOURNAL/$phase.current-discovery.json" \
    --output "$verification_probe" >"$report"
  cmp -s "$verification_probe" "$ROTATION_JOURNAL/$phase.current-verification.json" || \
    fail "completed Route rotation current verification bytes changed"
  cmp -s "$report" "$ROTATION_JOURNAL/$phase.current-verification-report.json" || \
    fail "completed Route rotation current receipt no longer verifies"
  rm -f "$report" "$verification_probe"
  rmdir "$verification_probe_dir"
  expected_summary=$(mktemp "$ROTATION_JOURNAL/.$phase.phase-summary.XXXXXX")
  write_rotation_phase_summary "$phase" "$expected_summary"
  cmp -s "$expected_summary" "$ROTATION_JOURNAL/$phase.phase-receipt.json" || \
    fail "completed Route rotation phase summary differs from its closed artifacts"
  rm -f "$expected_summary"
}

validate_rotation_phase_prefix() {
  local aggregate=$ROTATION_JOURNAL/rotation-phase-receipts.json count index phase
  local phases=(publish_overlap switch_active publish_new_only retire disable publish_recovery activate)
  jq -e --argjson expected '["publish_overlap","switch_active","publish_new_only","retire","disable","publish_recovery","activate"]' '
    type == "array" and length <= 7
    and (length as $count | [.[].phase] == $expected[0:$count])' \
    "$aggregate" >/dev/null || fail "Route rotation completed phases are not one exact prefix"
  count=$(jq -er 'length' "$aggregate")
  for ((index=0; index<count; index++)); do
    phase=${phases[$index]}
    verify_completed_rotation_phase "$phase"
    jq -e -n --argjson index "$index" \
      --slurpfile aggregate "$aggregate" \
      --slurpfile phase "$ROTATION_JOURNAL/$phase.phase-receipt.json" \
      '$aggregate[0][$index] == $phase[0]' >/dev/null || \
      fail "Route rotation phase aggregate diverges at $phase"
  done
}

rotation_incomplete_phase_has_pending_command() {
  local count phase path
  local phases=(publish_overlap switch_active publish_new_only retire disable publish_recovery activate)
  local pending=()
  count=$(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json")
  (( count < ${#phases[@]} )) || return 1
  phase=${phases[$count]}
  shopt -s nullglob
  pending=("$ROTATION_JOURNAL/$phase".attempt-*.command.json)
  shopt -u nullglob
  ((${#pending[@]} > 0)) || return 1
  for path in "${pending[@]}"; do
    [[ -f $path && ! -L $path && -O $path ]] || \
      fail "incomplete Route rotation pending command is unsafe"
  done
}

discover_rotation_resume_state() {
  local discovery=$ROTATION_JOURNAL/resume-current-latest.json
  local revision count completed_revision next_revision database_current process_ready
  rotation_json_request GET \
    /v1/internal/route-v2/signing-authority-current "$discovery" 200 || \
    fail "Route rotation exact-current discovery is unavailable during resume"
  durable_case_file "$discovery"
  jq -e \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg trust "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256)" '
    keys == ["authority_id","database_current","loaded_active_kid",
      "loaded_public_key_ring_digest","loaded_public_key_ring_version",
      "loaded_signer_reference_sha256","loaded_signer_revision","loaded_signer_state",
      "process_ready","release_commit_sha","rotation_operator_trust_sha256",
      "route_deployment_id","version"]
    and .version == 1 and .authority_id == $authority
    and .route_deployment_id == $deployment and .release_commit_sha == $commit
    and .rotation_operator_trust_sha256 == $trust
    and (.loaded_signer_revision | type == "number" and . >= 1 and . <= 8 and floor == .)
    and (.loaded_public_key_ring_version | type == "number" and . >= 1 and floor == .)
    and (.loaded_signer_reference_sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.loaded_public_key_ring_digest | test("^sha256:[0-9a-f]{64}$"))
    and (.database_current | type == "boolean") and (.process_ready | type == "boolean")' \
    "$discovery" >/dev/null || fail "Route rotation exact-current discovery is not closed"
  revision=$(jq -er '.loaded_signer_revision' "$discovery")
  database_current=$(jq -r '.database_current' "$discovery")
  process_ready=$(jq -r '.process_ready' "$discovery")
  count=$(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json")
  completed_revision=$((count + 1))
  next_revision=$((completed_revision + 1))
  (( revision == completed_revision || (count < 7 && revision == next_revision) )) || \
    fail "Route rotation live process is ahead of or behind the durable phase prefix"
  if (( revision == 1 )); then
    jq -e '
      .loaded_signer_state == "active" and (.loaded_active_kid | type == "string" and length > 0)
      and .loaded_public_key_ring_version == 1' \
      "$discovery" >/dev/null || fail "initial Route rotation process is not exact-current Active"
  else
    jq -e --argjson revision "$revision" \
      --slurpfile bundle "$(rotation_input route-rotation-command-bundle)" '
      ($bundle[0].commands[] | select(.signer_revision == $revision)) as $entry
      | ($entry.exact_authority_command_json | fromjson | .successor) as $successor
      | ($bundle[0].control_rollouts[] | select(.signer_revision == $revision)) as $rollout
      | .loaded_signer_reference_sha256 == $rollout.signer_reference_sha256
        and .loaded_signer_state == $successor.signer.state
        and .loaded_active_kid == (if $successor.signer.state == "active"
          then $successor.signer.active_kid else null end)
        and .loaded_public_key_ring_version == $entry.ring_version
        and .loaded_public_key_ring_digest == $rollout.public_key_ring_digest' \
      "$discovery" >/dev/null || fail "Route rotation live process differs from the prepared lineage"
  fi
  if [[ $database_current == true ]]; then
    if (( revision == 1 )); then
      [[ $process_ready == true ]] || fail "current initial Route rotation process is not ready"
    else
      jq -e --argjson revision "$revision" \
        --slurpfile bundle "$(rotation_input route-rotation-command-bundle)" '
        ($bundle[0].commands[] | select(.signer_revision == $revision)
          | .exact_authority_command_json | fromjson | .successor.signer.state) as $state
        | .process_ready == ($state == "active")' "$discovery" >/dev/null || \
        fail "current Route rotation process readiness differs from signer state"
    fi
  else
    # The only admissible stale process is the predecessor of an already
    # durable, incomplete adjacent command. This is the crash window after its
    # Store COMMIT and before the reviewed rollout/current receipt. It may
    # exact-replay that pending command, but cannot mint the following phase.
    [[ $process_ready == false && $revision -eq $completed_revision ]] || \
      fail "non-current Route rotation process is not the durable predecessor"
    rotation_incomplete_phase_has_pending_command || \
      fail "non-current Route rotation process has no durable adjacent command to resolve"
  fi
  rotation_transcript setup resume_current "signer_revision_$revision"
}

append_rotation_phase_receipt() {
  local phase=$1 summary=$ROTATION_JOURNAL/$phase.phase-receipt.json
  local expected_summary temporary count expected_phase
  local phases=(publish_overlap switch_active publish_new_only retire disable publish_recovery activate)
  validate_rotation_phase_prefix
  count=$(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json")
  expected_phase=${phases[$count]:-}
  [[ $phase == "$expected_phase" ]] || fail "Route rotation phase completion is not adjacent"
  expected_summary=$(mktemp "$ROTATION_JOURNAL/.$phase.phase-summary.XXXXXX")
  write_rotation_phase_summary "$phase" "$expected_summary"
  if [[ -e $summary ]]; then
    cmp -s "$expected_summary" "$summary" || \
      fail "Route rotation phase summary changed across resume"
    rm -f "$expected_summary"
  else
    adopt_rotation_file "$expected_summary" "$summary"
    rm -f "$expected_summary"
  fi
  temporary=$(mktemp "$ROTATION_JOURNAL/.rotation-phase-receipts.XXXXXX")
  jq -S -c --slurpfile current "$ROTATION_JOURNAL/rotation-phase-receipts.json" \
    --slurpfile addition "$summary" -n '$current[0] + [$addition[0]]' >"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$ROTATION_JOURNAL/rotation-phase-receipts.json"
  durable_case_file "$ROTATION_JOURNAL/rotation-phase-receipts.json"
}

settle_rotation_phase() {
  local phase=$1 count index
  local phases=(publish_overlap switch_active publish_new_only retire disable publish_recovery activate)
  validate_rotation_phase_prefix
  count=$(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json")
  for index in "${!phases[@]}"; do
    if [[ ${phases[$index]} == "$phase" ]]; then
      if (( index < count )); then
        rotation_transcript "$phase" resumed_completed "durable_prefix"
        return
      fi
      (( index == count )) || fail "Route rotation attempted a non-adjacent phase"
      break
    fi
  done
  advance_rotation_phase "$phase"
  fetch_rotation_apply_receipt "$phase"
  verify_rotation_current_after_rollout "$phase"
  append_rotation_phase_receipt "$phase"
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

disabled_public_route_observation_is_exact() {
  local observation=$1 origin=$2
  jq -e --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" '
    keys == ["body_sha256","content_encoding_absent","content_type","http_status",
      "kind","origin","path","retry_after_seconds","run_id","terminal_marker",
      "tls_reachable","version"]
    and .version == 1 and .kind == "route_v2_public_admission_closed_v1"
    and .origin == $origin and .path == ("/e3/" + $run_id) and .run_id == $run_id
    and .tls_reachable == true and .http_status == 503
    and .content_type == "text/plain" and .retry_after_seconds == 1
    and .content_encoding_absent == true
    and .body_sha256 == "sha256:3993919ba29fc397f3bbc6bf5d814e9caa9f184b557eb9c5fd7a59d45a2ac609"
    and .terminal_marker == "public_ingress_reachable_route_v2_closed"' \
    "$observation" >/dev/null
}

initialize_disabled_public_route_probe_state() {
  local origin=$1 state=$ROTATION_JOURNAL/disabled-public-route-probe-state.json source
  source=$ROTATION_JOURNAL/.disabled-public-route-probe-state.source.json
  if [[ ! -e $state ]]; then
    jq -S -c -n \
      '{version:1,next_attempt_index:1,in_flight_attempt:null,observations:[]}' >"$source"
    atomic_json_path "$state" "$source"
    rm -f "$source"
  fi
  jq -e --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" '
    . as $root
    | keys == ["in_flight_attempt","next_attempt_index","observations","version"]
    and .version == 1
    and (.next_attempt_index | type == "number" and . >= 1 and . <= 100000 and floor == .)
    and (.in_flight_attempt == null
      or (.in_flight_attempt | type == "number" and . >= 1 and floor == .))
    and (.observations | type == "array" and length <= 3)
    and all(.observations[];
      keys == ["attempt_index","receipt"]
      and (.attempt_index | type == "number" and . >= 1 and floor == .)
      and (.receipt | keys) == ["body_sha256","content_encoding_absent","content_type",
        "http_status","kind","origin","path","retry_after_seconds","run_id",
        "terminal_marker","tls_reachable","version"]
      and .receipt.version == 1
      and .receipt.kind == "route_v2_public_admission_closed_v1"
      and .receipt.origin == $origin and .receipt.path == ("/e3/" + $run_id)
      and .receipt.run_id == $run_id and .receipt.tls_reachable == true
      and .receipt.http_status == 503 and .receipt.content_type == "text/plain"
      and .receipt.retry_after_seconds == 1
      and .receipt.content_encoding_absent == true
      and .receipt.body_sha256 == "sha256:3993919ba29fc397f3bbc6bf5d814e9caa9f184b557eb9c5fd7a59d45a2ac609"
      and .receipt.terminal_marker == "public_ingress_reachable_route_v2_closed")
    and all(.observations[]; .attempt_index < $root.next_attempt_index)
    and ($root.in_flight_attempt == null
      or $root.in_flight_attempt == ($root.next_attempt_index - 1))
    and ([.observations[].receipt] | unique | length) <= 1
    and (($root.observations | length) < 2
      or all(range(1; $root.observations | length); . as $index
        | $root.observations[$index].attempt_index
          == ($root.observations[$index - 1].attempt_index + 1)))' \
    "$state" >/dev/null || fail "durable disabled public Route probe prefix is malformed"
  if [[ $(jq -r '.in_flight_attempt' "$state") != null ]]; then
    # A process death anywhere between beginning the request and durably
    # classifying its response makes adjacency unknowable. Discard the whole
    # candidate prefix before another observation; never count across it.
    jq -S -c '.in_flight_attempt = null | .observations = []' "$state" >"$source"
    atomic_json_path "$state" "$source"
    rm -f "$source"
    rotation_transcript disable unknown_probe_reset "crash_safe_prefix_reset"
  fi
}

prove_rotation_disable_observed() {
  local origin source receipt state state_source aggregate_source
  local attempt status consecutive attempt_index
  origin=$CATS_E3_PUBLIC_ORIGIN
  [[ -n $origin ]] || origin=https://$(required CATS_E3_ENDPOINT_HOSTNAME)
  source=$ROTATION_JOURNAL/.disabled-public-route.probe.json
  receipt=$ROTATION_JOURNAL/disabled-public-route.json
  state=$ROTATION_JOURNAL/disabled-public-route-probe-state.json
  state_source=$ROTATION_JOURNAL/.disabled-public-route-probe-state.source.json
  aggregate_source=$ROTATION_JOURNAL/.disabled-public-route.source.json
  initialize_disabled_public_route_probe_state "$origin"
  if [[ -e $receipt ]]; then
    jq -e --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" \
      --slurpfile state "$state" '
      keys == ["kind","observation_count","observations","origin","path","run_id",
        "terminal_marker","version"]
      and .version == 1 and .kind == "route_v2_public_admission_closed_sequence_v1"
      and .origin == $origin and .path == ("/e3/" + $run_id) and .run_id == $run_id
      and .observation_count == 3 and (.observations | length) == 3
      and .observations == $state[0].observations
      and $state[0].in_flight_attempt == null
      and ($state[0].observations | length) == 3
      and .terminal_marker == "three_consecutive_public_ingress_reachable_route_v2_closed"' \
      "$receipt" >/dev/null || fail "durable disabled public Route proof is malformed"
    rotation_transcript disable resumed_public_route_closed "durable_three_exact_503"
    return
  fi
  consecutive=$(jq -er '.observations | length' "$state")
  attempt=0
  while [[ $attempt -lt 30 && $consecutive -lt 3 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 30
    attempt_index=$(jq -er '.next_attempt_index' "$state")
    jq -S -c --argjson attempt "$attempt_index" '
      .in_flight_attempt = $attempt | .next_attempt_index = ($attempt + 1)' \
      "$state" >"$state_source"
    atomic_json_path "$state" "$state_source"
    rm -f "$state_source"
    set +e
    run_probe public-route-closed --origin "$origin" --run-id "$CATS_E3_RUN_ID" >"$source"
    status=$?
    set -e
    if [[ $status -eq 0 ]] && disabled_public_route_observation_is_exact "$source" "$origin"; then
      jq -S -c --slurpfile observation "$source" '
        .in_flight_attempt as $attempt
        | .in_flight_attempt = null
        | .observations =
            (if ((.observations | length) == 0
              or all(.observations[]; .receipt == $observation[0]))
             then .observations + [{attempt_index:$attempt,receipt:$observation[0]}]
             else [{attempt_index:$attempt,receipt:$observation[0]}]
             end)' "$state" >"$state_source"
      atomic_json_path "$state" "$state_source"
      rm -f "$state_source" "$source"
      consecutive=$(jq -er '.observations | length' "$state")
      [[ $consecutive -ge 3 ]] && break
    else
      jq -S -c '.in_flight_attempt = null | .observations = []' \
        "$state" >"$state_source"
      atomic_json_path "$state" "$state_source"
      rm -f "$state_source" "$source"
      consecutive=0
    fi
    sleep 1
  done
  [[ $consecutive -ge 3 ]] || fail "disabled signer did not close the calibrated public route"
  jq -S -c --arg origin "$origin" --arg run_id "$CATS_E3_RUN_ID" '
    {version:1,kind:"route_v2_public_admission_closed_sequence_v1",
     origin:$origin,path:("/e3/" + $run_id),run_id:$run_id,
     observation_count:(.observations | length),observations,
     terminal_marker:"three_consecutive_public_ingress_reachable_route_v2_closed"}' \
    "$state" >"$aggregate_source"
  publish_json_idempotent_path "$receipt" "$aggregate_source"
  rm -f "$aggregate_source"
  rotation_transcript disable public_route_closed "three_exact_503_probes"
}

rotation_disabled_fleet_is_exact() {
  local destination=$1 expected_ring_digest expected_kids
  expected_ring_digest=$(rotation_phase_rollout_field disable '.public_key_ring_digest')
  expected_kids=$(jq -c --arg phase disable '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor_ring.keys | map(.kid)' \
    "$(rotation_input route-rotation-command-bundle)")
  [[ $expected_kids == '[]' ]] || fail "disable phase does not carry the exact empty public ring"
  jq -e \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg ring_digest "$expected_ring_digest" --argjson kids "$expected_kids" \
    --arg nodes "$(required CATS_E3_EXPECTED_NODES)" '
    . as $root | ($nodes | split(",")) as $expected
    | .route_signing_authority.deployment_id == $deployment
    and .route_signing_authority.signer_revision == 6
    and .route_signing_authority.active_kid == null
    and .route_signing_authority.public_key_ring_version == 4
    and .route_signing_authority.public_key_ring_digest == $ring_digest
    and ([.nodes[].node_id] | sort) == ($expected | sort)
    and all(.nodes[];
      .session != null and .inventory != null and .inventory.complete_inventory == true
      and .inventory.source_session.node_id == .session.node_id
      and .inventory.source_session.node_boot_id == .session.node_boot_id
      and .inventory.source_session.agent_instance_id == .session.agent_instance_id
      and .inventory.source_session.agent_session_epoch == .session.agent_session_epoch
      and .inventory.attestation.accepted_at_unix_ms <= $root.evaluated_at_unix_ms
      and $root.evaluated_at_unix_ms < (.inventory.attestation.accepted_at_unix_ms + 60000)
      and .inventory.key_ring_version == 4
      and .inventory.key_ring_digest == $ring_digest
      and .inventory.loaded_kids == $kids
      and .inventory.route_active_count == 0
      and .inventory.active_guard_count == 0
      and .inventory.residue_count == 0
      and .inventory.cancellation_pending_count == 0
      and .inventory.quarantined_condition_count == 0)
    and ([.nodes[].inventory.route_closed_count] | add) == 1' "$destination" >/dev/null
}

wait_rotation_disabled_fleet() {
  local destination=$ROTATION_JOURNAL/rotation-disabled-fleet.json attempt status ready probe
  if [[ -e $destination ]]; then
    rotation_disabled_fleet_is_exact "$destination" || \
      fail "durable disabled Fleet proof is malformed"
    rotation_transcript disable resumed_disabled_fleet "durable_empty_ring"
    return
  fi
  probe=$(mktemp "$ROTATION_JOURNAL/.rotation-disabled-fleet.probe.XXXXXX")
  ready=false
  attempt=0
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 30
    set +e
    raw_fleet_snapshot_to "$probe"
    status=$?
    set -e
    if [[ $status -eq 0 ]] && rotation_disabled_fleet_is_exact "$probe"; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ $ready == true ]] || fail "all Nodes did not prove fresh empty-ring Closed state with zero guards"
  adopt_rotation_file "$probe" "$destination"
  rm -f "$probe"
  rotation_transcript disable disabled_fleet_verified "empty_ring_closed_guard_zero"
}

read_current_endpoints() {
  local destination=$1 workspace cat origin
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  origin=$(control_origin)
  curl_json GET "$origin/v1/workspaces/$workspace/cats/$cat/endpoints" \
    "$destination" 200 || fail "current Endpoint observation is unavailable"
  jq -e --arg cat "$cat" '
    keys == ["cat_id","complete","desired_revision","items","version"]
    and .version == 1 and .cat_id == $cat and .complete == true
    and (.desired_revision | type == "number" and . >= 1 and floor == .)
    and (.items | type == "array" and length <= 256)
    and (.items == (.items | sort_by(.endpoint_id)))
    and all(.items[];
      keys == ["endpoint_id","hostname","name","protocol","route_epoch",
        "target_port","version","wake_policy"]
      and .version == 1
      and (.endpoint_id | type == "string" and test("^[A-Za-z0-9._:-]{1,128}$"))
      and (.name | type == "string" and test("^[A-Za-z0-9._:-]{1,128}$"))
      and (.hostname | type == "string" and length >= 1 and length <= 253)
      and .target_port == 8080 and .protocol == "http" and .wake_policy == "disabled"
      and (.route_epoch | type == "number" and . >= 1 and floor == .))' \
    "$destination" >/dev/null || fail "current Endpoint observation is not the closed V1 DTO"
}

replace_endpoint_with_fresh_lineage() {
  local workspace cat before live after_unbind after_bind lineage old_id old_name old_hostname
  local old_revision unbound_revision fresh_name fresh_id fresh_hostname fresh_revision run_digest body
  local unbind_operation_id bind_operation_id source
  workspace=$(required CATS_E3_WORKSPACE_ID)
  cat=$(cat_id)
  before=$ROTATION_JOURNAL/fresh-endpoint-before.json
  live=$ROTATION_JOURNAL/.fresh-endpoint-current.json
  after_unbind=$ROTATION_JOURNAL/fresh-endpoint-after-unbind.json
  after_bind=$ROTATION_JOURNAL/fresh-endpoint-after-bind.json
  lineage=$ROTATION_JOURNAL/fresh-endpoint-lineage.json
  if [[ ! -e $before ]]; then
    read_current_endpoints "$live"
    jq -e --arg name "$(required CATS_E3_ENDPOINT_NAME)" \
      --arg hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" '
      (.items | length) == 1
      and .items[0].name == $name and .items[0].hostname == $hostname
      and .items[0].target_port == 8080' "$live" >/dev/null || \
      fail "initial Endpoint observation does not contain the calibrated binding"
    adopt_rotation_file "$live" "$before"
  fi
  jq -e --arg name "$(required CATS_E3_ENDPOINT_NAME)" \
    --arg hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" '
    (.items | length) == 1 and .items[0].name == $name
    and .items[0].hostname == $hostname and .items[0].target_port == 8080' \
    "$before" >/dev/null || fail "durable old Endpoint binding is not exact"
  old_id=$(jq -er '.items[0].endpoint_id' "$before")
  old_name=$(jq -er '.items[0].name' "$before")
  old_hostname=$(jq -er '.items[0].hostname' "$before")
  old_revision=$(jq -er '.desired_revision' "$before")
  canonical_id old_endpoint_id "$old_id"
  canonical_id old_endpoint_name "$old_name"

  run_digest=$(printf '%s' "$CASE_ID:$CATS_E3_RUN_ID" | sha256sum | awk '{print $1}')
  fresh_name=g3-${run_digest:0:24}
  canonical_id fresh_endpoint_name "$fresh_name"
  [[ $fresh_name != "$old_name" ]] || fail "fresh Endpoint name reuses the retained binding name"

  read_current_endpoints "$live"
  jq -e --arg old_id "$old_id" --arg old_name "$old_name" \
    --arg hostname "$old_hostname" --arg fresh_name "$fresh_name" \
    --argjson old_revision "$old_revision" '
    ((.desired_revision == $old_revision and (.items | length) == 1
      and .items[0].endpoint_id == $old_id and .items[0].name == $old_name)
    or (.desired_revision == ($old_revision + 1) and (.items | length) == 0)
    or (.desired_revision == ($old_revision + 2) and (.items | length) == 1
      and .items[0].endpoint_id != $old_id and .items[0].name == $fresh_name
      and .items[0].hostname == $hostname and .items[0].route_epoch == 1))' \
    "$live" >/dev/null || fail "Endpoint recovery found a foreign or non-adjacent current Desired"

  product_mutation DELETE "/v1/workspaces/$workspace/cats/$cat/endpoints/$old_id" \
    "g3-${run_digest:0:20}-unbind" running "" "$ROTATION_JOURNAL" "fresh-endpoint-unbind-"
  jq -e --argjson expected_revision "$((old_revision + 1))" '
    keys == ["desired_revision","operation_id"]
    and .desired_revision == $expected_revision
    and (.operation_id | type == "string" and length > 0)' \
    "$ROTATION_JOURNAL/fresh-endpoint-unbind-mutation-response.json" >/dev/null || \
    fail "Endpoint unbind response is not the closed adjacent mutation DTO"
  unbind_operation_id=$(jq -er '.operation_id' \
    "$ROTATION_JOURNAL/fresh-endpoint-unbind-mutation-receipt.json")
  jq -e --argjson expected_revision "$((old_revision + 1))" '
    keys == ["converged","desired_revision","operation_id","version"]
    and .version == 1 and .desired_revision == $expected_revision
    and (.operation_id | type == "string" and length > 0)' \
    "$ROTATION_JOURNAL/fresh-endpoint-unbind-mutation-receipt.json" >/dev/null || \
    fail "Endpoint unbind mutation did not return the exact adjacent Desired revision"
  if [[ ! -e $after_unbind ]]; then
    read_current_endpoints "$live"
    jq -e --argjson old_revision "$old_revision" \
      '.desired_revision == ($old_revision + 1) and (.items | length) == 0' \
      "$live" >/dev/null || fail "old Endpoint remains in the current Desired projection"
    adopt_rotation_file "$live" "$after_unbind"
  fi
  jq -e --argjson old_revision "$old_revision" \
    '.desired_revision == ($old_revision + 1) and (.items | length) == 0' \
    "$after_unbind" >/dev/null || fail "old Endpoint remains in the current Desired projection"
  unbound_revision=$(jq -er '.desired_revision' "$after_unbind")

  body=$ROTATION_JOURNAL/fresh-endpoint-bind.json
  source=$ROTATION_JOURNAL/.fresh-endpoint-bind.source.json
  jq -S -c -n --arg name "$fresh_name" --arg hostname "$old_hostname" \
    '{name:$name,hostname:$hostname,target_port:8080}' >"$source"
  if [[ -e $body ]]; then
    cmp -s "$source" "$body" || fail "fresh Endpoint request changed across resume"
    rm -f "$source"
  else
    adopt_rotation_file "$source" "$body"
    rm -f "$source"
  fi
  product_mutation POST "/v1/workspaces/$workspace/cats/$cat/endpoints" \
    "g3-${run_digest:0:20}-bind" running "$body" "$ROTATION_JOURNAL" "fresh-endpoint-bind-"
  jq -e --argjson expected_revision "$((unbound_revision + 1))" '
    keys == ["desired_revision","operation_id"]
    and .desired_revision == $expected_revision
    and (.operation_id | type == "string" and length > 0)' \
    "$ROTATION_JOURNAL/fresh-endpoint-bind-mutation-response.json" >/dev/null || \
    fail "Endpoint bind response is not the closed adjacent mutation DTO"
  bind_operation_id=$(jq -er '.operation_id' \
    "$ROTATION_JOURNAL/fresh-endpoint-bind-mutation-receipt.json")
  jq -e --argjson expected_revision "$((unbound_revision + 1))" '
    keys == ["converged","desired_revision","operation_id","version"]
    and .version == 1 and .desired_revision == $expected_revision
    and (.operation_id | type == "string" and length > 0)' \
    "$ROTATION_JOURNAL/fresh-endpoint-bind-mutation-receipt.json" >/dev/null || \
    fail "Endpoint bind mutation did not return the exact adjacent Desired revision"
  read_current_endpoints "$live"
  jq -e --arg old_id "$old_id" --arg old_name "$old_name" \
    --arg name "$fresh_name" --arg hostname "$old_hostname" \
    --argjson unbound_revision "$unbound_revision" '
    .desired_revision == ($unbound_revision + 1) and (.items | length) == 1
    and all(.items[]; .endpoint_id != $old_id and .name != $old_name)
    and .items[0].name == $name and .items[0].hostname == $hostname
    and .items[0].target_port == 8080 and .items[0].route_epoch == 1' \
    "$live" >/dev/null || fail "fresh Endpoint binding did not establish a new epoch-one lineage"
  if [[ -e $after_bind ]]; then
    cmp -s "$live" "$after_bind" || fail "fresh Endpoint current projection changed across resume"
  else
    adopt_rotation_file "$live" "$after_bind"
  fi
  fresh_id=$(jq -er '.items[0].endpoint_id' "$after_bind")
  fresh_hostname=$(jq -er '.items[0].hostname' "$after_bind")
  fresh_revision=$(jq -er '.desired_revision' "$after_bind")
  canonical_id fresh_endpoint_id "$fresh_id"
  [[ $fresh_id != "$old_id" && $fresh_hostname == "$(required CATS_E3_ENDPOINT_HOSTNAME)" ]] || \
    fail "fresh Endpoint identity or hostname is not exact"
  jq -e --arg workspace "$workspace" --arg cat "$cat" \
    --arg operation "$unbind_operation_id" \
    --argjson unbound_revision "$(jq -er '.desired_revision' "$after_unbind")" '
    keys == ["cat_id","created_at_unix_ms","desired_revision","desired_spec_digest",
      "operation_id","phase","placement","target","terminal","updated_at_unix_ms",
      "version","workspace_id"]
    and .version == 1 and .operation_id == $operation
    and .workspace_id == $workspace and .cat_id == $cat
    and .desired_revision == $unbound_revision and .phase == "succeeded"
    and .target == "running"
    and (.terminal | keys) == ["completed_at_unix_ms","kind","result"]
    and (.terminal.result | keys) == ["agent_session_epoch","heartbeat_sequence",
      "node_id","observation_id","observed_target","runtime_incarnation"]
    and .terminal.kind == "succeeded" and .terminal.result.observed_target == "running"
    and (.terminal.result.observation_id | type == "string")' \
    "$ROTATION_JOURNAL/fresh-endpoint-unbind-operation-$unbind_operation_id.json" >/dev/null || \
    fail "Endpoint unbind Operation does not settle the observed empty Desired revision"
  jq -e --arg workspace "$workspace" --arg cat "$cat" \
    --arg operation "$bind_operation_id" \
    --argjson fresh_revision "$fresh_revision" '
    keys == ["cat_id","created_at_unix_ms","desired_revision","desired_spec_digest",
      "operation_id","phase","placement","target","terminal","updated_at_unix_ms",
      "version","workspace_id"]
    and .version == 1 and .operation_id == $operation
    and .workspace_id == $workspace and .cat_id == $cat
    and .desired_revision == $fresh_revision and .phase == "succeeded"
    and .target == "running"
    and (.terminal | keys) == ["completed_at_unix_ms","kind","result"]
    and (.terminal.result | keys) == ["agent_session_epoch","heartbeat_sequence",
      "node_id","observation_id","observed_target","runtime_incarnation"]
    and .terminal.kind == "succeeded" and .terminal.result.observed_target == "running"
    and (.terminal.result.observation_id | type == "string")
    and (.terminal.result.node_id | type == "string")
    and (.terminal.result.agent_session_epoch | type == "number" and . >= 1)
    and (.terminal.result.heartbeat_sequence | type == "number" and . >= 1)' \
    "$ROTATION_JOURNAL/fresh-endpoint-bind-operation-$bind_operation_id.json" >/dev/null || \
    fail "Endpoint bind Operation does not settle the fresh Desired revision"

  source=$ROTATION_JOURNAL/.fresh-endpoint-lineage.source.json
  jq -S -c -n \
    --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg old_collection_sha256 "$(sha256_wire "$before")" \
    --arg unbound_collection_sha256 "$(sha256_wire "$after_unbind")" \
    --arg fresh_collection_sha256 "$(sha256_wire "$after_bind")" \
    --arg unbind_mutation_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-unbind-mutation-receipt.json")" \
    --arg unbind_replay_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-unbind-idempotent-replay-receipt.json")" \
    --arg unbind_operation_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-unbind-operation-receipt.json")" \
    --arg unbind_operation_full_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-unbind-operation-$unbind_operation_id.json")" \
    --arg bind_mutation_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-bind-mutation-receipt.json")" \
    --arg bind_replay_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-bind-idempotent-replay-receipt.json")" \
    --arg bind_operation_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-bind-operation-receipt.json")" \
    --arg bind_operation_full_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-bind-operation-$bind_operation_id.json")" \
    --argjson old_revision "$old_revision" --argjson fresh_revision "$fresh_revision" \
    --slurpfile before "$before" --slurpfile after "$after_bind" \
    --slurpfile unbind_operation "$ROTATION_JOURNAL/fresh-endpoint-unbind-operation-$unbind_operation_id.json" \
    --slurpfile bind_operation "$ROTATION_JOURNAL/fresh-endpoint-bind-operation-$bind_operation_id.json" '
    {version:1,kind:"route_v2_fresh_endpoint_lineage_v1",case_id:$case_id,
     qualification_run_id:$run_id,source_commit_sha:$commit,
     old_desired_revision:$old_revision,old_endpoint:$before[0].items[0],
     old_collection_sha256:$old_collection_sha256,
     unbind:{mutation_receipt_sha256:$unbind_mutation_sha256,
       replay_receipt_sha256:$unbind_replay_sha256,
       operation_receipt_sha256:$unbind_operation_sha256,
       full_operation_receipt_sha256:$unbind_operation_full_sha256,
       operation_id:$unbind_operation[0].operation_id,
       settled_observation_id:$unbind_operation[0].terminal.result.observation_id,
       empty_current_collection_sha256:$unbound_collection_sha256},
     fresh_desired_revision:$fresh_revision,fresh_endpoint:$after[0].items[0],
     bind:{mutation_receipt_sha256:$bind_mutation_sha256,
       replay_receipt_sha256:$bind_replay_sha256,
       operation_receipt_sha256:$bind_operation_sha256,
       full_operation_receipt_sha256:$bind_operation_full_sha256,
       operation_id:$bind_operation[0].operation_id,
       settled_observation_id:$bind_operation[0].terminal.result.observation_id,
       settled_node_id:$bind_operation[0].terminal.result.node_id,
       settled_agent_epoch:$bind_operation[0].terminal.result.agent_session_epoch,
       settled_heartbeat_sequence:$bind_operation[0].terminal.result.heartbeat_sequence,
       current_collection_sha256:$fresh_collection_sha256},
     terminal_marker:"old_endpoint_unbound_fresh_epoch_one_bound"}' \
    >"$source"
  if [[ -e $lineage ]]; then
    cmp -s "$source" "$lineage" || fail "fresh Endpoint lineage changed across resume"
    rm -f "$source"
  else
    adopt_rotation_file "$source" "$lineage"
    rm -f "$source"
  fi
  rotation_transcript activate fresh_endpoint_lineage "unbind_old_bind_fresh_epoch_one"
}

probe_fresh_endpoint_after_rotation() {
  local current=$ROTATION_JOURNAL/fresh-endpoint-before-probe.json
  local probe
  probe=$(mktemp "$ROTATION_JOURNAL/.fresh-endpoint-before-probe.XXXXXX")
  read_current_endpoints "$probe"
  adopt_rotation_file "$probe" "$current"
  rm -f "$probe"
  jq -e -n --slurpfile lineage "$ROTATION_JOURNAL/fresh-endpoint-lineage.json" \
    --slurpfile current "$current" '
    ($current[0].items | length) == 1
    and $current[0].items[0] == $lineage[0].fresh_endpoint
    and $current[0].desired_revision == $lineage[0].fresh_desired_revision' >/dev/null || \
    fail "fresh Endpoint lineage changed before the live HTTP/WebSocket probe"
  probe_public_route "$ROTATION_JOURNAL/fresh-endpoint-public-route.json"
  rotation_transcript activate fresh_endpoint_live "node_ack_then_http_ws"
}

rotation_terminal_fleet_is_exact() {
  local destination=$1
  local expected_ring_digest expected_kids bind_node bind_epoch bind_heartbeat
  expected_ring_digest=$(rotation_phase_rollout_field publish_recovery '.public_key_ring_digest')
  expected_kids=$(jq -c --arg phase publish_recovery '
    .commands[] | select(.phase == $phase)
    | .exact_authority_command_json | fromjson | .successor_ring.keys | map(.kid)' \
    "$(rotation_input route-rotation-command-bundle)")
  bind_node=$(jq -er '.bind.settled_node_id' "$ROTATION_JOURNAL/fresh-endpoint-lineage.json")
  bind_epoch=$(jq -er '.bind.settled_agent_epoch' "$ROTATION_JOURNAL/fresh-endpoint-lineage.json")
  bind_heartbeat=$(jq -er '.bind.settled_heartbeat_sequence' "$ROTATION_JOURNAL/fresh-endpoint-lineage.json")
  canonical_id fresh_endpoint_settlement_node "$bind_node"
  jq -e \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg ring_digest "$expected_ring_digest" --argjson kids "$expected_kids" \
    --arg bind_node "$bind_node" --argjson bind_epoch "$bind_epoch" \
    --argjson bind_heartbeat "$bind_heartbeat" \
    --arg nodes "$(required CATS_E3_EXPECTED_NODES)" '
    . as $root | ($nodes | split(",")) as $expected
    | .route_signing_authority.deployment_id == $deployment
    and .route_signing_authority.signer_revision == 8
    and .route_signing_authority.active_kid == $kids[0]
    and .route_signing_authority.public_key_ring_version == 5
    and .route_signing_authority.public_key_ring_digest == $ring_digest
    and ([.nodes[].node_id] | sort) == ($expected | sort)
    and ([.nodes[] | select(.node_id == $bind_node)] | length) == 1
    and ([.nodes[] | select(.node_id == $bind_node)][0] as $bound
      | $bound.session.agent_session_epoch == $bind_epoch
      and $bound.inventory.source_heartbeat_sequence >= $bind_heartbeat)
    and all(.nodes[];
      .session != null and .inventory != null and .inventory.complete_inventory == true
      and .inventory.source_session.node_id == .session.node_id
      and .inventory.source_session.node_boot_id == .session.node_boot_id
      and .inventory.source_session.agent_instance_id == .session.agent_instance_id
      and .inventory.source_session.agent_session_epoch == .session.agent_session_epoch
      and .inventory.attestation.accepted_at_unix_ms <= $root.evaluated_at_unix_ms
      and $root.evaluated_at_unix_ms < (.inventory.attestation.accepted_at_unix_ms + 60000)
      and .inventory.key_ring_version == 5
      and .inventory.key_ring_digest == $ring_digest
      and .inventory.loaded_kids == $kids
      and .inventory.active_guard_count == 0
      and .inventory.residue_count == 0
      and .inventory.cancellation_pending_count == 0
      and .inventory.quarantined_condition_count == 0)
    and ([.nodes[].inventory.route_active_count] | add) == 1
    and ([.nodes[].inventory.route_closed_count] | add) == 0' \
    "$destination" >/dev/null
}

terminal_rotation_fleet() {
  local destination=$ROTATION_JOURNAL/rotation-terminal-fleet.json attempt status ready probe
  if [[ -e $destination ]]; then
    rotation_terminal_fleet_is_exact "$destination" || \
      fail "durable terminal Fleet proof is malformed"
    rotation_transcript activate resumed_terminal_fleet "ring_5_active"
    return
  fi
  probe=$(mktemp "$ROTATION_JOURNAL/.rotation-terminal-fleet.probe.XXXXXX")
  ready=false
  attempt=0
  while [[ $attempt -lt 240 ]]; do
    attempt=$((attempt + 1))
    rotation_require_budget 30
    set +e
    raw_fleet_snapshot_to "$probe"
    status=$?
    set -e
    if [[ $status -eq 0 ]] && rotation_terminal_fleet_is_exact "$probe"; then
      ready=true
      break
    fi
    sleep 1
  done
  [[ $ready == true ]] || fail "terminal Fleet did not acknowledge the recovery ring and fresh route"
  adopt_rotation_file "$probe" "$destination"
  rm -f "$probe"
  rotation_transcript activate terminal_fleet_verified "ring_5_active"
}

build_rotation_node_acks() {
  local output=$CASE_DIR/route-v2-rotation-disable-live-delivery.node-acks.json
  local source=$ROTATION_JOURNAL/route-v2-rotation-node-acks.source.json
  local bundle fleet expected_nodes
  bundle=$(rotation_input route-rotation-command-bundle)
  fleet=$ROTATION_JOURNAL/rotation-terminal-fleet.json
  expected_nodes=$(printf '%s' "$(required CATS_E3_EXPECTED_NODES)" | jq -R 'split(",")')
  jq -S -c -n \
    --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --argjson expected_nodes "$expected_nodes" \
    --arg disabled_fleet_sha256 "$(sha256_wire "$ROTATION_JOURNAL/rotation-disabled-fleet.json")" \
    --arg final_fleet_sha256 "$(sha256_wire "$fleet")" \
    --arg switch_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/switch_active.store-receipt.json")" \
    --arg retire_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/retire.store-receipt.json")" \
    --arg recovery_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/publish_recovery.store-receipt.json")" \
    --arg activate_receipt_sha256 "$(sha256_wire "$ROTATION_JOURNAL/activate.store-receipt.json")" \
    --slurpfile bundle "$bundle" --slurpfile fleet "$fleet" \
    --slurpfile phases "$ROTATION_JOURNAL/rotation-phase-receipts.json" \
    --slurpfile disabled_fleet "$ROTATION_JOURNAL/rotation-disabled-fleet.json" \
    --slurpfile switch_receipt "$ROTATION_JOURNAL/switch_active.store-receipt.json" \
    --slurpfile retire_receipt "$ROTATION_JOURNAL/retire.store-receipt.json" \
    --slurpfile recovery_receipt "$ROTATION_JOURNAL/publish_recovery.store-receipt.json" \
    --slurpfile activate_receipt "$ROTATION_JOURNAL/activate.store-receipt.json" '
    def command($phase):
      $bundle[0].commands[] | select(.phase == $phase)
      | . + {decoded:(.exact_authority_command_json | fromjson)};
    def rollout($phase):
      command($phase).signer_revision as $revision
      | $bundle[0].control_rollouts[] | select(.signer_revision == $revision);
    def checkpoint($observed; $settled; $condition; $receipt_sha256; $receipt):
      command($observed) as $command
      | rollout($observed) as $rollout
      | ($phases[0][] | select(.phase == $settled) | .store_precondition) as $precondition
      | {observed_phase:$observed,signer_revision:$command.signer_revision,
         ring_version:$command.ring_version,
         ring_digest:$rollout.public_key_ring_digest,
         loaded_kids:($command.decoded.successor_ring.keys | map(.kid)),
         settled_by_phase:$settled,required_store_precondition:$condition,
         settled_by_store_receipt_sha256:$receipt_sha256,
         settled_at_unix_ms:$receipt[0].committed_at_unix_ms,
         precondition:$precondition,
         store_precondition_satisfied:
           ($precondition != null and $precondition.satisfied == true
            and $precondition.observed_phase == $observed
            and $precondition.required_condition == $condition
            and $precondition.expected_signer_revision == $command.signer_revision
            and $precondition.expected_ring_version == $command.ring_version
            and $precondition.expected_ring_digest == $rollout.public_key_ring_digest
            and $precondition.expected_loaded_kids
              == ($command.decoded.successor_ring.keys | map(.kid)))};
    def projected_nodes($snapshot):
      [$snapshot.nodes[] |
        {node_id,binding:{node_id:.session.node_id,node_boot_id:.session.node_boot_id,
           agent_instance_id:.session.agent_instance_id,
           agent_epoch:.session.agent_session_epoch},
         inventory:{source_observation_id:.inventory.source_observation_id,
           source_heartbeat_sequence:.inventory.source_heartbeat_sequence,
           source_binding:{node_id:.inventory.source_session.node_id,
             node_boot_id:.inventory.source_session.node_boot_id,
             agent_instance_id:.inventory.source_session.agent_instance_id,
             agent_epoch:.inventory.source_session.agent_session_epoch},
           attestation_accepted_at_unix_ms:.inventory.attestation.accepted_at_unix_ms,
           complete_inventory:.inventory.complete_inventory,
           key_ring_version:.inventory.key_ring_version,
           key_ring_digest:.inventory.key_ring_digest,loaded_kids:.inventory.loaded_kids,
           route_active_count:.inventory.route_active_count,
           route_closed_count:.inventory.route_closed_count,
           active_guard_count:.inventory.active_guard_count,
           residue_count:.inventory.residue_count,
           cancellation_pending_count:.inventory.cancellation_pending_count,
           quarantined_condition_count:.inventory.quarantined_condition_count}}]
      | sort_by(.node_id);
    ($expected_nodes | sort) as $expected
    | projected_nodes($disabled_fleet[0]) as $disabled_nodes
    | projected_nodes($fleet[0]) as $terminal_nodes
    | (rollout("disable")) as $disabled_rollout
    | (rollout("publish_recovery")) as $terminal_rollout
    | (command("publish_recovery").decoded.successor_ring.keys | map(.kid)) as $terminal_kids
    | {version:1,kind:"route_v2_node_ring_ack_set_v1",case_id:$case_id,
     qualification_run_id:$run_id,source_commit_sha:$commit,
     route_deployment_id:$deployment,expected_nodes:$expected,
     disabled_fleet_sha256:$disabled_fleet_sha256,
     disabled_evaluated_at_unix_ms:$disabled_fleet[0].evaluated_at_unix_ms,
     disabled_nodes:$disabled_nodes,
     disabled_all_nodes_closed_or_fenced:
       (($disabled_nodes | map(.node_id)) == $expected
        and all($disabled_nodes[];
          .binding == .inventory.source_binding
          and .inventory.complete_inventory == true
          and .inventory.attestation_accepted_at_unix_ms <= $disabled_fleet[0].evaluated_at_unix_ms
          and $disabled_fleet[0].evaluated_at_unix_ms
            < (.inventory.attestation_accepted_at_unix_ms + 60000)
          and .inventory.key_ring_version == 4
          and .inventory.key_ring_digest == $disabled_rollout.public_key_ring_digest
          and .inventory.loaded_kids == [] and .inventory.route_active_count == 0
          and .inventory.active_guard_count == 0 and .inventory.residue_count == 0
          and .inventory.cancellation_pending_count == 0
          and .inventory.quarantined_condition_count == 0)
        and ([$disabled_nodes[].inventory.route_closed_count] | add) == 1),
     checkpoints:[
       checkpoint("publish_overlap";"switch_active";"all_schedulable_nodes_ack_ring";
         $switch_receipt_sha256;$switch_receipt),
       checkpoint("publish_new_only";"retire";"all_schedulable_nodes_ack_ring";
         $retire_receipt_sha256;$retire_receipt),
       checkpoint("disable";"publish_recovery";"all_provisioned_nodes_closed_or_fenced";
         $recovery_receipt_sha256;$recovery_receipt),
       checkpoint("publish_recovery";"activate";
         "all_provisioned_nodes_closed_or_fenced_and_ack_ring";
         $activate_receipt_sha256;$activate_receipt)
     ],
     terminal_fleet_sha256:$final_fleet_sha256,
     terminal_evaluated_at_unix_ms:$fleet[0].evaluated_at_unix_ms,
     terminal_signing_authority:$fleet[0].route_signing_authority,
     terminal_nodes:$terminal_nodes,
     all_nodes_acknowledged:
       (($terminal_nodes | map(.node_id)) == $expected
        and all($terminal_nodes[];
          .binding == .inventory.source_binding
          and .inventory.complete_inventory == true
          and .inventory.attestation_accepted_at_unix_ms <= $fleet[0].evaluated_at_unix_ms
          and $fleet[0].evaluated_at_unix_ms
            < (.inventory.attestation_accepted_at_unix_ms + 60000)
          and .inventory.key_ring_version == 5
          and .inventory.key_ring_digest == $terminal_rollout.public_key_ring_digest
          and .inventory.loaded_kids == $terminal_kids
          and .inventory.residue_count == 0
          and .inventory.cancellation_pending_count == 0
          and .inventory.quarantined_condition_count == 0)
        and ([$terminal_nodes[].inventory.route_active_count] | add) == 1
        and ([$terminal_nodes[].inventory.route_closed_count] | add) == 0),
     all_active_guards_zero:all($terminal_nodes[]; .inventory.active_guard_count == 0),
     terminal_marker:"recovery_ring_acked_and_active_routes_reopened"}' >"$source"
  jq -e '
    .disabled_all_nodes_closed_or_fenced == true
    and all(.checkpoints[];
      .store_precondition_satisfied == true and .precondition.satisfied == true)
    and .all_nodes_acknowledged == true and .all_active_guards_zero == true' \
    "$source" >/dev/null || fail "Route rotation Node ACK projection is not independently closed"
  publish_json_idempotent_path "$output" "$source"
  rm -f "$source"
}

build_rotation_terminal_receipt() {
  local output=$CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json
  local source=$ROTATION_JOURNAL/route-v2-rotation-terminal-receipt.source.json
  local transcript=$CASE_DIR/route-v2-rotation-disable-live-delivery.transcript.log
  jq -S -c -n \
    --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg catalog "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg trust_sha "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256)" \
    --arg command_bundle_sha256 "$(sha256_wire "$(rotation_input route-rotation-command-bundle)")" \
    --arg recovery_transport_sha256 "$(sha256_wire "$(rotation_input route-rotation-recovery)")" \
    --arg node_acks_sha256 "$(sha256_wire "$CASE_DIR/route-v2-rotation-disable-live-delivery.node-acks.json")" \
    --arg transcript_sha256 "$(sha256_wire "$transcript")" \
    --arg disabled_fleet_sha256 "$(sha256_wire "$ROTATION_JOURNAL/rotation-disabled-fleet.json")" \
    --arg disabled_route_sha256 "$(sha256_wire "$ROTATION_JOURNAL/disabled-public-route.json")" \
    --arg baseline_route_sha256 "$(sha256_wire "$ROTATION_JOURNAL/rotation-baseline-public-route.json")" \
    --arg endpoint_lineage_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-lineage.json")" \
    --arg endpoint_probe_collection_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-before-probe.json")" \
    --arg public_route_sha256 "$(sha256_wire "$ROTATION_JOURNAL/fresh-endpoint-public-route.json")" \
    --arg terminal_fleet_sha256 "$(sha256_wire "$ROTATION_JOURNAL/rotation-terminal-fleet.json")" \
    --slurpfile phases "$ROTATION_JOURNAL/rotation-phase-receipts.json" \
    --slurpfile node_acks "$CASE_DIR/route-v2-rotation-disable-live-delivery.node-acks.json" \
    --slurpfile disabled_fleet "$ROTATION_JOURNAL/rotation-disabled-fleet.json" \
    --slurpfile disabled_route "$ROTATION_JOURNAL/disabled-public-route.json" \
    --slurpfile terminal_fleet "$ROTATION_JOURNAL/rotation-terminal-fleet.json" \
    --slurpfile endpoint_lineage "$ROTATION_JOURNAL/fresh-endpoint-lineage.json" \
    --slurpfile final_route "$ROTATION_JOURNAL/fresh-endpoint-public-route.json" '
    {version:1,kind:"route_v2_rotation_terminal_receipt_v1",case_id:$case_id,
     qualification_run_id:$run_id,source_commit_sha:$commit,
     qualification_catalog_sha256:$catalog,authority_id:$authority,
     route_deployment_id:$deployment,rotation_operator_trust_sha256:$trust_sha,
     command_bundle_sha256:$command_bundle_sha256,
     recovery_transport_sha256:$recovery_transport_sha256,
     phase_receipts:$phases[0],
     disabled_checkpoint:{signer_revision:6,ring_version:4,signer_state:"disabled",
       loaded_kids:[],public_route_closed:
         ($disabled_route[0].terminal_marker
           == "three_consecutive_public_ingress_reachable_route_v2_closed"),
       public_route_closed_observation_count:$disabled_route[0].observation_count,
       disabled_public_route_sha256:$disabled_route_sha256,
       all_nodes_closed_or_fenced:$node_acks[0].disabled_all_nodes_closed_or_fenced,
       active_guard_count:([$disabled_fleet[0].nodes[].inventory.active_guard_count] | add),
       disabled_fleet_sha256:$disabled_fleet_sha256,
       disable_store_receipt_sha256:$phases[0][4].store_command_receipt_sha256,
       closed_fleet_settlement_store_receipt_sha256:$phases[0][5].store_command_receipt_sha256},
     recovery_checkpoint:{signer_revision:8,ring_version:5,signer_state:"active",
       active_kid:$terminal_fleet[0].route_signing_authority.active_kid,
       database_current:$phases[0][6].database_current,
       process_ready:$phases[0][6].process_ready,
       all_nodes_acknowledged:$node_acks[0].all_nodes_acknowledged,
       all_active_guards_zero:$node_acks[0].all_active_guards_zero,
       terminal_fleet_sha256:$terminal_fleet_sha256},
     fresh_endpoint:{mechanism:"unbind_old_bind_fresh_endpoint",
       calibrated_baseline_public_route_sha256:$baseline_route_sha256,
       lineage_receipt_sha256:$endpoint_lineage_sha256,
       old_endpoint:$endpoint_lineage[0].old_endpoint,
       unbind:$endpoint_lineage[0].unbind,
       fresh_endpoint:$endpoint_lineage[0].fresh_endpoint,
       bind:$endpoint_lineage[0].bind,
       pre_probe_collection_sha256:$endpoint_probe_collection_sha256,
       public_route_receipt_sha256:$public_route_sha256,
       http_guest_body:$final_route[0].http_guest_body,
       websocket_guest_echo:$final_route[0].websocket_guest_echo},
     node_acks_sha256:$node_acks_sha256,transcript_sha256:$transcript_sha256,
     terminal_marker:"route_v2_rotation_disable_recovered_active_http_ws"}' >"$source"
  jq -e '
    (.phase_receipts | length) == 7
    and .disabled_checkpoint.public_route_closed == true
    and .disabled_checkpoint.public_route_closed_observation_count == 3
    and .disabled_checkpoint.all_nodes_closed_or_fenced == true
    and .recovery_checkpoint.database_current == true
    and .recovery_checkpoint.process_ready == true
    and .recovery_checkpoint.all_nodes_acknowledged == true
    and .recovery_checkpoint.all_active_guards_zero == true
    and .fresh_endpoint.http_guest_body == true
    and .fresh_endpoint.websocket_guest_echo == true
    and .terminal_marker == "route_v2_rotation_disable_recovered_active_http_ws"' \
    "$source" >/dev/null || fail "Route rotation terminal receipt is not a closed success"
  publish_json_idempotent_path "$output" "$source"
  rm -f "$source"
}

validate_rotation_terminal_evidence() {
  local receipt=$CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json
  local node_acks=$CASE_DIR/route-v2-rotation-disable-live-delivery.node-acks.json
  local transcript=$CASE_DIR/route-v2-rotation-disable-live-delivery.transcript.log
  local evidence filename expected_nodes run_digest fresh_name
  local top_evidence=()
  expected_nodes=$(printf '%s' "$(required CATS_E3_EXPECTED_NODES)" | jq -R 'split(",") | sort')
  run_digest=$(printf '%s' "$CASE_ID:$CATS_E3_RUN_ID" | sha256sum | awk '{print $1}')
  fresh_name=g3-${run_digest:0:24}
  for evidence in "$receipt" "$node_acks" "$transcript"; do
    [[ -f $evidence && ! -L $evidence && -O $evidence ]] || \
      fail "Route rotation terminal evidence is missing or unsafe"
  done
  [[ $(grep -c '^terminal_marker=route_v2_rotation_disable_recovered_active_http_ws$' "$transcript" || true) -eq 1 ]] || \
    fail "Route rotation transcript has no single terminal marker"
  jq -e \
    --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg catalog "$(required CATS_E3_QUALIFICATION_CATALOG_SHA256)" \
    --arg authority "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID)" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --arg trust "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256)" \
    --arg command_bundle_sha "$(sha256_wire "$(rotation_input route-rotation-command-bundle)")" \
    --arg recovery_transport_sha "$(sha256_wire "$(rotation_input route-rotation-recovery)")" \
    --arg endpoint_name "$(required CATS_E3_ENDPOINT_NAME)" \
    --arg endpoint_hostname "$(required CATS_E3_ENDPOINT_HOSTNAME)" \
    --arg fresh_name "$fresh_name" \
    --arg node_acks_sha "$(sha256_wire "$node_acks")" \
    --arg transcript_sha "$(sha256_wire "$transcript")" '
    .version == 1 and .kind == "route_v2_rotation_terminal_receipt_v1"
    and .case_id == $case_id and .qualification_run_id == $run_id
    and .source_commit_sha == $commit and .qualification_catalog_sha256 == $catalog
    and .authority_id == $authority and .route_deployment_id == $deployment
    and .rotation_operator_trust_sha256 == $trust
    and .command_bundle_sha256 == $command_bundle_sha
    and .recovery_transport_sha256 == $recovery_transport_sha
    and (.phase_receipts | length) == 7
    and .disabled_checkpoint.public_route_closed == true
    and .disabled_checkpoint.public_route_closed_observation_count == 3
    and .disabled_checkpoint.all_nodes_closed_or_fenced == true
    and .recovery_checkpoint.database_current == true
    and .recovery_checkpoint.process_ready == true
    and .recovery_checkpoint.all_nodes_acknowledged == true
    and .recovery_checkpoint.all_active_guards_zero == true
    and .fresh_endpoint.old_endpoint.name == $endpoint_name
    and .fresh_endpoint.old_endpoint.hostname == $endpoint_hostname
    and .fresh_endpoint.fresh_endpoint.name == $fresh_name
    and .fresh_endpoint.fresh_endpoint.hostname == $endpoint_hostname
    and .fresh_endpoint.fresh_endpoint.route_epoch == 1
    and .fresh_endpoint.fresh_endpoint.endpoint_id
      != .fresh_endpoint.old_endpoint.endpoint_id
    and .fresh_endpoint.http_guest_body == true
    and .fresh_endpoint.websocket_guest_echo == true
    and .node_acks_sha256 == $node_acks_sha and .transcript_sha256 == $transcript_sha
    and .terminal_marker == "route_v2_rotation_disable_recovered_active_http_ws"' \
    "$receipt" >/dev/null || fail "Route rotation terminal receipt changed across resume"
  jq -e --arg case_id "$CASE_ID" --arg run_id "$CATS_E3_RUN_ID" \
    --arg commit "$CATS_E3_EXACT_COMMIT" \
    --arg deployment "$(required CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID)" \
    --argjson expected_nodes "$expected_nodes" '
    .version == 1 and .kind == "route_v2_node_ring_ack_set_v1"
    and .case_id == $case_id and .qualification_run_id == $run_id
    and .source_commit_sha == $commit
    and .route_deployment_id == $deployment
    and .expected_nodes == $expected_nodes
    and .disabled_all_nodes_closed_or_fenced == true
    and all(.checkpoints[];
      .store_precondition_satisfied == true and .precondition.satisfied == true)
    and .all_nodes_acknowledged == true and .all_active_guards_zero == true
    and .terminal_signing_authority.deployment_id == $deployment
    and .terminal_signing_authority.signer_revision == 8
    and .terminal_marker == "recovery_ring_acked_and_active_routes_reopened"' \
    "$node_acks" >/dev/null || fail "Route rotation Node ACK evidence changed across resume"
  shopt -s nullglob
  top_evidence=("$CASE_DIR"/*receipt*.json "$CASE_DIR"/*.node-acks.json "$CASE_DIR"/*.transcript.log)
  shopt -u nullglob
  for evidence in "${top_evidence[@]}"; do
    filename=${evidence##*/}
    case "$filename" in
      route-v2-rotation-disable-live-delivery.receipt.json | \
      route-v2-rotation-disable-live-delivery.node-acks.json | \
      route-v2-rotation-disable-live-delivery.transcript.log | \
      cleanup-receipt.json) ;;
      *) fail "Route rotation top-level evidence contains a non-canonical WIP artifact" ;;
    esac
  done
}

ensure_rotation_baseline() {
  local baseline=$ROTATION_JOURNAL/rotation-baseline-public-route.json count revision
  if [[ -e $baseline ]]; then
    jq -e --arg origin "${CATS_E3_PUBLIC_ORIGIN:-https://$(required CATS_E3_ENDPOINT_HOSTNAME)}" \
      --arg run_id "$CATS_E3_RUN_ID" '
      .version == 1 and .origin == $origin and .run_id == $run_id
      and .http_guest_body == true and .websocket_guest_echo == true' \
      "$baseline" >/dev/null || fail "durable Route rotation baseline is not the run-bound HTTP/WebSocket proof"
    return
  fi
  count=$(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json")
  revision=$(jq -er '.loaded_signer_revision' "$ROTATION_JOURNAL/resume-current-latest.json")
  (( count == 0 && revision == 1 )) || \
    fail "Route rotation mutation began without a durable positive public baseline"
  probe_public_route "$baseline"
  rotation_transcript setup calibrated_public_route "http_ws_positive"
}

append_rotation_terminal_marker() {
  local transcript=$CASE_DIR/route-v2-rotation-disable-live-delivery.transcript.log temporary count
  count=$(grep -c '^terminal_marker=route_v2_rotation_disable_recovered_active_http_ws$' "$transcript" || true)
  (( count <= 1 )) || fail "Route rotation transcript repeats its terminal marker"
  if (( count == 1 )) && \
    [[ $(tail -n 1 "$transcript") == terminal_marker=route_v2_rotation_disable_recovered_active_http_ws ]]; then
    return
  fi
  temporary=$(mktemp "$CASE_DIR/.route-v2-rotation-transcript.XXXXXX")
  sed '/^terminal_marker=route_v2_rotation_disable_recovered_active_http_ws$/d' \
    "$transcript" >"$temporary"
  printf '%s\n' 'terminal_marker=route_v2_rotation_disable_recovered_active_http_ws' >>"$temporary"
  chmod 0600 "$temporary"
  mv "$temporary" "$transcript"
  durable_case_file "$transcript"
}

run_route_rotation_recovery() {
  validate_rotation_recovery_inputs
  initialize_rotation_journal
  if [[ -e $CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json ]]; then
    validate_rotation_terminal_evidence
    printf 'ROUTE_V2_ROTATION_TERMINAL_RECEIPT sha256=%s\n' \
      "$(sha256sum "$CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json" | awk '{print $1}')"
    return
  fi
  validate_rotation_phase_prefix
  discover_rotation_resume_state
  rotation_transcript setup validated "release_run_catalog_trust_transport"
  ensure_rotation_baseline

  settle_rotation_phase publish_overlap
  settle_rotation_phase switch_active
  wait_rotation_retention
  settle_rotation_phase publish_new_only
  settle_rotation_phase retire
  settle_rotation_phase disable
  prove_rotation_disable_observed
  wait_rotation_disabled_fleet
  settle_rotation_phase publish_recovery
  settle_rotation_phase activate

  replace_endpoint_with_fresh_lineage
  terminal_rotation_fleet
  probe_fresh_endpoint_after_rotation
  rotation_transcript terminal completed "recovered_active_http_ws"
  append_rotation_terminal_marker
  build_rotation_node_acks
  build_rotation_terminal_receipt
  validate_rotation_terminal_evidence
  printf 'ROUTE_V2_ROTATION_TERMINAL_RECEIPT sha256=%s\n' \
    "$(sha256sum "$CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json" | awk '{print $1}')"
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
  if [[ ! -e $receipt_dir && ! -L $receipt_dir ]]; then
    mkdir -m 0700 "$receipt_dir"
    sync -f "$CASE_DIR"
  fi
  [[ -d $receipt_dir && ! -L $receipt_dir && -O $receipt_dir && \
    $(stat -c '%a' "$receipt_dir") == 700 ]] || \
    fail "Usage source terminal receipt directory is not protected resume state"
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
    route-v2-rotation-disable-live-delivery) run_route_rotation_recovery ;;
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

rotation_mutation_started() {
  local pending=()
  [[ -d $ROTATION_JOURNAL && ! -L $ROTATION_JOURNAL ]] || return 1
  if [[ -f $ROTATION_JOURNAL/rotation-phase-receipts.json ]] && \
    [[ $(jq -er 'length' "$ROTATION_JOURNAL/rotation-phase-receipts.json") -gt 0 ]]; then
    return 0
  fi
  shopt -s nullglob
  pending=("$ROTATION_JOURNAL"/*.attempt-*.command.json)
  shopt -u nullglob
  ((${#pending[@]} > 0))
}

cleanup() {
  local policy source cat expected_node
  policy=observation_only
  if [[ $CASE_ID == route-v2-rotation-disable-live-delivery ]]; then
    if [[ -e $CASE_DIR/route-v2-rotation-disable-live-delivery.receipt.json ]] || \
      rotation_mutation_started; then
      # There is no rollback authority. Resolve every durable pending command,
      # then continue the accepted adjacent lineage through r8, a fresh
      # Endpoint epoch and full Node acknowledgement.
      run_route_rotation_recovery
      validate_rotation_terminal_evidence
      policy=forward_recovered_active_fresh_endpoint_for_agent_restart
    else
      policy=no_route_rotation_mutation_observed
    fi
  elif [[ $CASE_ID == route-http-ws ]]; then
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
  durable_case_file "$CASE_DIR/cleanup-receipt.json"
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
