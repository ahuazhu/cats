#!/usr/bin/env bash
# Deterministic evidence orchestrator for an already-provisioned qualification
# host inside the runbook's bounded schedulable/ingress window. It never
# provisions infrastructure, applies Terraform, or installs a long-lived service.
set -euo pipefail

# Testable boundary after all production authority checks and stable staging.
# Executing this file always enters the root-only main path below; sourcing it
# only exposes this deterministic case/evidence loop to repository tests.
cats_e3_run_cases_post_preflight() {
  atomic_copy() {
    local source=$1 destination=$2 temporary
    temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
    cp "$source" "$temporary"
    chmod 0600 "$temporary"
    mv -f "$temporary" "$output_dir/$destination"
  }

  run_filtered() {
    local action=$1 case_id=$2 deadline=$3 destination=$4 case_dir=$5
    local statuses command_status filter_status
    set +e
    "$timeout_bin" --signal=TERM --kill-after=5 "$deadline" \
      "$scenario_driver" "$action" "$case_id" "$block_path" "$case_dir" 2>&1 \
      | "$filter" --mode text --max-bytes 16384 >"$destination"
    statuses=("${PIPESTATUS[@]}")
    set -e
    command_status=${statuses[0]:-125}
    filter_status=${statuses[1]:-125}
    if [[ $filter_status -ne 0 ]]; then
      printf '%s\n' '[evidence filter failed closed]' >"$destination"
      return 125
    fi
    return "$command_status"
  }

  append_summary() {
    local case_id=$1 phase=$2 source=$3 bounded
    printf '=== %s %s ===\n' "$case_id" "$phase" >>"$journal_work"
    cat "$source" >>"$journal_work"
    printf '\n' >>"$journal_work"
    bounded=$scratch/component-journal-summary.bounded
    "$filter" --mode text --max-bytes 131072 <"$journal_work" >"$bounded" || \
      printf '%s\n' '[evidence filter failed closed]' >"$bounded"
    mv -f "$bounded" "$journal_work"
    atomic_copy "$journal_work" component-journal-summary.txt
  }

  persist_case_evidence() {
    local case_id=$1 case_dir=$2 required_evidence=$3 exact_set_required=$4
    local candidate filename kind filtered entry digest size actual_json expected_json
    local candidates=() actual_names=() evidence_names=()
    expected_json=$(jq -c '[.[].filename] | sort' <<<"$required_evidence") || return 125
    shopt -s nullglob
    candidates=("$case_dir"/*)
    shopt -u nullglob
    for candidate in "${candidates[@]}"; do
      [[ -f $candidate && ! -L $candidate ]] || continue
      filename=${candidate##*/}
      case "$filename" in
        *receipt*.json|*.node-acks.json|*.transcript.log) actual_names+=("$filename") ;;
        *)
          if jq -e --arg filename "$filename" \
            'any(.[]; .filename == $filename)' <<<"$required_evidence" >/dev/null; then
            actual_names+=("$filename")
          fi
          ;;
      esac
    done

    if [[ $exact_set_required == true ]]; then
      if [[ ${#actual_names[@]} -eq 0 ]]; then
        actual_json='[]'
      else
        actual_json=$(printf '%s\n' "${actual_names[@]}" | LC_ALL=C sort | jq -Rsc 'split("\n")[:-1]') || return 125
      fi
      [[ $actual_json == "$expected_json" ]] || return 125
      while IFS= read -r filename; do
        evidence_names+=("$filename")
      done < <(jq -r '.[].filename' <<<"$required_evidence")
    else
      evidence_names=("${actual_names[@]}")
    fi

    for filename in "${evidence_names[@]}"; do
      candidate=$case_dir/$filename
      [[ -f $candidate && ! -L $candidate ]] || return 125
      if [[ $exact_set_required == true ]]; then
        kind=$(jq -r --arg filename "$filename" \
          '.[] | select(.filename == $filename) | .kind' <<<"$required_evidence") || return 125
      else
        case "$filename" in
          *.json) kind=json ;;
          *.log) kind=text ;;
          *) return 125 ;;
        esac
      fi
      filtered=$(mktemp "$scratch/.case-evidence.XXXXXX")
      case "$kind" in
        json)
          if ! "$filter" --mode inventory --max-bytes 1048576 <"$candidate" >"$filtered"; then
            rm -f "$filtered"
            return 125
          fi
          ;;
        text)
          if ! "$filter" --mode text --max-bytes 131072 <"$candidate" >"$filtered"; then
            rm -f "$filtered"
            return 125
          fi
          ;;
        *)
          rm -f "$filtered"
          return 125
          ;;
      esac
      digest=$(sha256sum "$filtered" | awk '{print $1}')
      size=$(wc -c <"$filtered" | tr -d ' ')
      entry=$(mktemp "$scratch/.case-evidence-entry.XXXXXX")
      if [[ $kind == json ]]; then
        if ! jq -S -c -n --arg case_id "$case_id" --arg filename "$filename" \
          --arg kind "$kind" --arg sha256 "sha256:$digest" --argjson size_bytes "$size" \
          --slurpfile content "$filtered" \
          '{case_id:$case_id,filename:$filename,kind:$kind,sha256:$sha256,
            size_bytes:$size_bytes,content:$content[0]}' >"$entry"; then
          rm -f "$filtered" "$entry"
          return 125
        fi
      elif ! jq -S -c -n --arg case_id "$case_id" --arg filename "$filename" \
        --arg kind "$kind" --arg sha256 "sha256:$digest" --argjson size_bytes "$size" \
        --rawfile content "$filtered" \
        '{case_id:$case_id,filename:$filename,kind:$kind,sha256:$sha256,
          size_bytes:$size_bytes,content:$content}' >"$entry"; then
        rm -f "$filtered" "$entry"
        return 125
      fi
      cat "$entry" >>"$evidence_work"
      rm -f "$filtered" "$entry"
    done
    atomic_copy "$evidence_work" case-evidence.jsonl
  }

  failed_cases=0
  blocked_cases=0
  passed_cases=0
  for index in "${!case_ids[@]}"; do
    case_id=${case_ids[$index]}
    deadline=${case_deadlines[$index]}
    expected_outcome=${case_expected_outcomes[$index]}
    required_evidence=${case_required_evidence[$index]}
    case_dir=$scratch/case-$case_id
    mkdir -m 0700 "$case_dir"
    run_summary=$case_dir/run-summary.txt
    cleanup_summary=$case_dir/cleanup-summary.txt
    diagnostic_summary=$case_dir/diagnostic-summary.txt
    case_started=$(date +%s)

    if run_filtered run "$case_id" "$deadline" "$run_summary" "$case_dir"; then
      run_code=0
    else
      run_code=$?
    fi
    append_summary "$case_id" run "$run_summary"

    diagnostic_code=0
    if [[ $run_code -ne 0 ]]; then
      if run_filtered diagnostics "$case_id" 30 "$diagnostic_summary" "$case_dir"; then
        diagnostic_code=0
      else
        diagnostic_code=$?
      fi
      append_summary "$case_id" diagnostics "$diagnostic_summary"
    fi

    if run_filtered cleanup "$case_id" 60 "$cleanup_summary" "$case_dir"; then
      cleanup_code=0
    else
      cleanup_code=$?
    fi
    append_summary "$case_id" cleanup "$cleanup_summary"

    exact_set_required=false
    if [[ $run_code -eq 0 && $cleanup_code -eq 0 ]]; then
      exact_set_required=true
    fi
    if persist_case_evidence "$case_id" "$case_dir" "$required_evidence" "$exact_set_required"; then
      evidence_code=0
    else
      evidence_code=$?
    fi

    case_ended=$(date +%s)
    observed_outcome=passed
    if [[ $cleanup_code -ne 0 || $evidence_code -ne 0 ]]; then
      observed_outcome=failed
    elif [[ $run_code -eq 124 ]]; then
      observed_outcome=timed_out
    elif [[ $run_code -eq 78 ]]; then
      if [[ -f $case_dir/blocked-receipt.json ]] && jq -e \
        --arg case_id "$case_id" --arg block_path "$block_path" \
        '.version == 1 and .status == "blocked" and .case_id == $case_id
          and .block_path == $block_path and (.reason | type == "string" and length > 0)' \
        "$case_dir/blocked-receipt.json" >/dev/null; then
        observed_outcome=blocked
      else
        observed_outcome=failed
        evidence_code=125
      fi
    elif [[ $run_code -ne 0 ]]; then
      observed_outcome=failed
    fi
    expected_kind=$(jq -r '.kind' <<<"$expected_outcome") || return 125
    outcome_matches=false
    status=failed
    if [[ $observed_outcome == "$expected_kind" ]]; then
      outcome_matches=true
      status=passed
      passed_cases=$((passed_cases + 1))
    else
      failed_cases=$((failed_cases + 1))
      [[ $observed_outcome != blocked ]] || blocked_cases=$((blocked_cases + 1))
    fi
    jq -S -c -n \
      --arg case_id "$case_id" \
      --arg status "$status" \
      --arg observed_outcome "$observed_outcome" \
      --argjson expected_outcome "$expected_outcome" \
      --argjson outcome_matches "$outcome_matches" \
      --argjson deadline_seconds "$deadline" \
      --argjson started_at_unix_seconds "$case_started" \
      --argjson ended_at_unix_seconds "$case_ended" \
      --argjson run_exit_code "$run_code" \
      --argjson diagnostic_exit_code "$diagnostic_code" \
      --argjson cleanup_exit_code "$cleanup_code" \
      --argjson evidence_exit_code "$evidence_code" \
      '{case_id:$case_id,status:$status,observed_outcome:$observed_outcome,
        expected_outcome:$expected_outcome,outcome_matches:$outcome_matches,
        deadline_seconds:$deadline_seconds,started_at_unix_seconds:$started_at_unix_seconds,
        ended_at_unix_seconds:$ended_at_unix_seconds,run_exit_code:$run_exit_code,
        diagnostic_exit_code:$diagnostic_exit_code,cleanup_exit_code:$cleanup_exit_code,
        evidence_exit_code:$evidence_exit_code}' \
      >>"$results_work"
    atomic_copy "$results_work" scenario-results.jsonl
  done

  inventory_work=$scratch/final-inventory.json
  set +e
  "$timeout_bin" --signal=TERM --kill-after=5 180 \
    "$scenario_driver" inventory final "$block_path" "$scratch" 2>/dev/null \
    | "$filter" --mode inventory --max-bytes 1048576 >"$inventory_work"
  inventory_statuses=("${PIPESTATUS[@]}")
  set -e
  inventory_command_status=${inventory_statuses[0]:-125}
  inventory_filter_status=${inventory_statuses[1]:-125}
  if [[ $inventory_command_status -ne 0 || $inventory_filter_status -ne 0 ]]; then
    failed_cases=$((failed_cases + 1))
    printf '%s\n' '{"status":"unavailable"}' >"$inventory_work"
    printf '%s\n' '[final inventory command or evidence filter failed closed]' >"$scratch/inventory-diagnostic.txt"
    append_summary final-inventory diagnostics "$scratch/inventory-diagnostic.txt"
  fi
  atomic_copy "$inventory_work" final-inventory.json
}

cats_e3_clear_ambient() {
  local environment_name
  while IFS='=' read -r environment_name _; do
    case "$environment_name" in
      CATS_TOKEN|CATS_E3_*) unset "$environment_name" ;;
    esac
  done < <(env)
}

cats_e3_export_qualification_environment() {
  export CATS_E3_WORKER_SERVICE=cats-worker.service
  export CATS_E3_INSTALLED_NODED_PATH=$installed_noded_path
  export CATS_E3_TOKEN_FILE=$token_file
  export CATS_E3_CONTROL_ORIGIN=$control_origin
  export CATS_E3_WORKSPACE_ID=$workspace_id
  export CATS_E3_QUALIFICATION_NODE_ID=$qualification_node
  export CATS_E3_CAT_NAME=$cat_name
  export CATS_E3_BOOT_IMAGE_DIGEST=$boot_image_digest
  export CATS_E3_ENDPOINT_NAME=$endpoint_name
  export CATS_E3_ENDPOINT_HOSTNAME=$endpoint_hostname
  export CATS_E3_PUBLIC_ORIGIN=https://$endpoint_hostname
  printf -v CATS_E3_EXPECTED_NODES '%s,' "${expected_nodes[@]}"
  CATS_E3_EXPECTED_NODES=${CATS_E3_EXPECTED_NODES%,}
  export CATS_E3_EXPECTED_NODES
  export CATS_E3_ROUTE_ROTATION_OPERATOR_AUTHORITY_ID=$route_rotation_operator_authority_id
  export CATS_E3_ROUTE_ROTATION_OPERATOR_ROUTE_DEPLOYMENT_ID=$route_rotation_operator_route_deployment_id
  export CATS_E3_ROUTE_ROTATION_OPERATOR_TRUST_SHA256=$route_rotation_operator_trust_sha256
}

cats_e3_environment_labels_are_unique() {
  local reserve_sha256=$1 entry label environment_label derived_name seen
  shift
  [[ $reserve_sha256 == true || $reserve_sha256 == false ]] || return 1
  seen='|'
  for entry in "$@"; do
    label=${entry%%=*}
    [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || return 1
    environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
    derived_name=$environment_label
    case "$seen" in *"|$derived_name|"*) return 1 ;; esac
    seen+="$derived_name|"
    if [[ $reserve_sha256 == true ]]; then
      derived_name=${environment_label}_SHA256
      case "$seen" in *"|$derived_name|"*) return 1 ;; esac
      seen+="$derived_name|"
    fi
  done
}

cats_e3_private_stage=
cats_e3_cleanup_private_stage() {
  local status=$?
  trap - EXIT INT TERM
  if [[ -n $cats_e3_private_stage ]]; then
    rm -f -- "$cats_e3_private_stage/control-token" || status=125
    rmdir -- "$cats_e3_private_stage" || status=125
    cats_e3_private_stage=
  fi
  exit "$status"
}

cats_e3_prepare_private_stage() {
  local parent=$1
  [[ -z $cats_e3_private_stage && $parent == /* && -d $parent && ! -L $parent ]] || return 1
  cats_e3_private_stage=$(mktemp -d "$parent/.cats-e3-secrets.XXXXXX") || return 1
  trap cats_e3_cleanup_private_stage EXIT
  trap 'exit 130' INT
  trap 'exit 143' TERM
  chmod 0700 "$cats_e3_private_stage"
}

if [[ ${BASH_SOURCE[0]} != "$0" ]]; then
  return 0
fi

usage() {
  cat >&2 <<'EOF'
usage: runtime-cutover-e2e.sh \
  --exact-commit <40 lowercase hex> \
  --block-path <kernel-nbd|vhost-user> \
  --run-id <stable-id> \
  --output-dir </absolute/new/directory> \
  --build-receipt </absolute/build-receipt.json> \
  --release-manifest </absolute/release-manifest.json> \
  --release-manifest-sha256 <sha256:64hex> \
  --installer-receipt </absolute/installer-receipt.json> \
  --token-file </absolute/root-only/control-token> \
  --control-origin <canonical-https-origin> \
  --workspace-id <runtime-id> \
  --expected-node <runtime-id> [--expected-node ...] \
  --qualification-node <one-expected-node-id> \
  --cat-name <bounded-name> \
  --boot-image-digest <sha256:64hex> \
  --endpoint-name <bounded-name> \
  --endpoint-hostname <lowercase-dns-name> \
  --guest-kernel <nonsecret-release-string> \
  --binary <label=/absolute/path> [--binary ...] \
  --config <label=/absolute/path> [--config ...] \
  --key-fingerprint <label=sha256:64hex> [--key-fingerprint ...] \
  --scenario-driver </absolute/repo-owned/executable>
EOF
  exit 64
}

fail() {
  printf 'runtime cutover e2e: %s\n' "$*" >&2
  exit 64
}

exact_commit=
block_path=
run_id=
output_dir=
build_receipt=
release_manifest=
release_manifest_sha256=
installer_receipt=
token_file=
control_origin=
workspace_id=
qualification_node=
cat_name=
boot_image_digest=
endpoint_name=
endpoint_hostname=
guest_kernel=
scenario_driver=
expected_nodes=()
binary_entries=()
config_entries=()
key_fingerprint_entries=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exact-commit|--block-path|--run-id|--output-dir|--build-receipt|--release-manifest|--release-manifest-sha256|--installer-receipt|--token-file|--control-origin|--workspace-id|--qualification-node|--cat-name|--boot-image-digest|--endpoint-name|--endpoint-hostname|--guest-kernel|--scenario-driver)
      [[ $# -ge 2 ]] || usage
      name=${1#--}
      name=${name//-/_}
      printf -v "$name" '%s' "$2"
      shift 2
      ;;
    --expected-node)
      [[ $# -ge 2 ]] || usage
      expected_nodes+=("$2")
      shift 2
      ;;
    --binary)
      [[ $# -ge 2 ]] || usage
      binary_entries+=("$2")
      shift 2
      ;;
    --config)
      [[ $# -ge 2 ]] || usage
      config_entries+=("$2")
      shift 2
      ;;
    --key-fingerprint)
      [[ $# -ge 2 ]] || usage
      key_fingerprint_entries+=("$2")
      shift 2
      ;;
    -h|--help) usage ;;
    *) usage ;;
  esac
done

[[ $exact_commit =~ ^[0-9a-f]{40}$ ]] || fail "--exact-commit must be one 40-character lowercase commit ID, not a branch or tag"
case "$block_path" in kernel-nbd|vhost-user) ;; *) fail "--block-path must be kernel-nbd or vhost-user" ;; esac
[[ $run_id =~ ^[a-z0-9][a-z0-9._-]{0,63}$ ]] || fail "--run-id is not canonical"
[[ $output_dir == /* ]] || fail "--output-dir must be an absolute output path"
[[ -n $build_receipt && $build_receipt == /* ]] || fail "--build-receipt must be absolute"
[[ -n $release_manifest && $release_manifest == /* ]] || fail "--release-manifest must be absolute"
[[ $release_manifest_sha256 =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--release-manifest-sha256 must be one independently approved sha256 digest"
[[ $installer_receipt == /opt/cats/release/worker-installation-receipt.v1.json ]] || \
  fail "--installer-receipt must be the canonical production installation receipt"
[[ $token_file == /* ]] || fail "--token-file must be absolute"
[[ $control_origin =~ ^https://[A-Za-z0-9.-]+(:[0-9]+)?$ ]] || \
  fail "--control-origin must be one canonical HTTPS origin"
for coordinate in workspace_id qualification_node cat_name endpoint_name; do
  value=${!coordinate}
  [[ $value =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "--${coordinate//_/-} is not canonical"
done
[[ $boot_image_digest =~ ^sha256:[0-9a-f]{64}$ ]] || \
  fail "--boot-image-digest must be one SHA-256 digest"
[[ $endpoint_hostname =~ ^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$ ]] || \
  fail "--endpoint-hostname is not one bounded lowercase DNS name"
[[ ${#expected_nodes[@]} -gt 0 ]] || fail "at least one --expected-node is required"
seen_expected_nodes='|'
qualification_node_matches=0
for node in "${expected_nodes[@]}"; do
  [[ $node =~ ^[A-Za-z0-9._:-]{1,128}$ ]] || fail "--expected-node is not canonical"
  case "$seen_expected_nodes" in *"|$node|"*) fail "--expected-node $node is repeated" ;; esac
  seen_expected_nodes+="$node|"
  [[ $node != "$qualification_node" ]] || qualification_node_matches=$((qualification_node_matches + 1))
done
[[ $qualification_node_matches -eq 1 ]] || \
  fail "--qualification-node must equal exactly one --expected-node"
[[ $guest_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || fail "--guest-kernel is not a bounded nonsecret release string"
[[ -n $scenario_driver && $scenario_driver == /* ]] || fail "--scenario-driver must be absolute"
[[ ${#binary_entries[@]} -gt 0 ]] || fail "at least one --binary is required"
[[ ${#config_entries[@]} -gt 0 ]] || fail "at least one --config is required"
[[ ${#key_fingerprint_entries[@]} -gt 0 ]] || fail "at least one --key-fingerprint is required"
cats_e3_environment_labels_are_unique true "${binary_entries[@]}" || \
  fail "binary labels collide after environment normalization"
cats_e3_environment_labels_are_unique false "${config_entries[@]}" || \
  fail "config labels collide after environment normalization"
[[ $EUID -eq 0 ]] || fail "production E3 qualification must run as root"

for command_name in git jq python3 sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

# The scenario driver may execute only binaries/configs named by this exact
# invocation.  Do not let a caller's ambient environment smuggle an unrecorded
# executable or config past the manifest-backed --binary/--config boundary.
cats_e3_clear_ambient

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$script_dir/../.." && pwd -P)
filter=$script_dir/runtime-cutover-evidence-filter.py
runner=$script_dir/runtime-cutover-e2e.sh
qualification_catalog=$script_dir/runtime-cutover-e2e-catalog.v1.json

canonical_existing() {
  local path=$1
  [[ $path == /* && -e $path && ! -L $path ]] || return 1
  python3 - "$path" <<'PY'
import os
import sys
print(os.path.realpath(sys.argv[1]))
PY
}

canonical_output() {
  local requested=$1 parent base
  parent=${requested%/*}
  base=${requested##*/}
  [[ -n $parent && -n $base && $base != . && $base != .. ]] || return 1
  [[ -d $parent && ! -L $parent ]] || return 1
  parent=$(cd "$parent" && pwd -P) || return 1
  printf '%s/%s\n' "$parent" "$base"
}

build_receipt=$(canonical_existing "$build_receipt") || fail "build receipt must be a regular non-symlink file"
release_manifest=$(canonical_existing "$release_manifest") || fail "release manifest must be a regular non-symlink file"
installer_receipt=$(canonical_existing "$installer_receipt") || fail "installer receipt must be a regular non-symlink file"
token_file=$(canonical_existing "$token_file") || fail "token file must be a regular non-symlink file"
[[ $installer_receipt == /opt/cats/release/worker-installation-receipt.v1.json ]] || \
  fail "installer receipt path must resolve to the canonical production path"
scenario_driver=$(canonical_existing "$scenario_driver") || fail "scenario driver must be a regular non-symlink file"
qualification_catalog=$(canonical_existing "$qualification_catalog") || \
  fail "qualification catalog must be the fixed regular non-symlink repository file"
output_dir=$(canonical_output "$output_dir") || fail "absolute output parent must already exist and be a real directory"
[[ ! -e $output_dir && ! -L $output_dir ]] || fail "output directory already exists; refusing to overwrite evidence"

[[ $(git -C "$repo" rev-parse HEAD) == "$exact_commit" ]] || fail "checkout HEAD does not equal the exact commit"
[[ $(git -C "$repo" rev-parse "${exact_commit}^{commit}") == "$exact_commit" ]] || fail "exact commit is not a commit object"

verify_exact_repo_blob() {
  local path=$1 relative expected_blob actual_blob
  case "$path" in "$repo"/*) ;; *) fail "runner authority inputs must be repo-owned" ;; esac
  relative=${path#"$repo"/}
  expected_blob=$(git -C "$repo" rev-parse "${exact_commit}:${relative}" 2>/dev/null) || fail "$relative is not tracked by the exact commit"
  actual_blob=$(git -C "$repo" hash-object "$path")
  [[ $actual_blob == "$expected_blob" ]] || fail "$relative differs from the exact commit"
  [[ -f $path && ! -L $path ]] || fail "$relative must be a regular non-symlink file"
}

verify_exact_repo_file() {
  local path=$1
  verify_exact_repo_blob "$path"
  [[ -f $path && -x $path && ! -L $path ]] || fail "$path must be an executable regular file"
}

verify_exact_repo_file "$runner"
verify_exact_repo_file "$filter"
verify_exact_repo_file "$scenario_driver"
verify_exact_repo_blob "$qualification_catalog"

python3 - "$qualification_catalog" <<'PY' || fail "qualification catalog is not canonical or violates its closed schema"
import json
from pathlib import Path
import re
import sys


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey
        value[key] = item
    return value


raw = Path(sys.argv[1]).read_bytes()
if not 1 <= len(raw) <= 65536:
    raise SystemExit(1)
try:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey):
    raise SystemExit(1)
canonical = (json.dumps(value, ensure_ascii=True, indent=2, sort_keys=True) + "\n").encode()
if raw != canonical or not isinstance(value, dict):
    raise SystemExit(1)
if set(value) != {"cases", "framework_required_evidence", "version"} or value["version"] != 1:
    raise SystemExit(1)

filename_pattern = re.compile(r"[a-z0-9][a-z0-9._-]{0,127}\Z")
case_pattern = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")


def validate_evidence(items):
    if not isinstance(items, list) or not items or len(items) > 32:
        raise SystemExit(1)
    names = []
    for item in items:
        if not isinstance(item, dict) or set(item) != {"filename", "kind"}:
            raise SystemExit(1)
        filename = item["filename"]
        if not isinstance(filename, str) or filename_pattern.fullmatch(filename) is None:
            raise SystemExit(1)
        if filename in {".", ".."} or item["kind"] not in {"json", "text"}:
            raise SystemExit(1)
        if item["kind"] == "json" and not filename.endswith(".json"):
            raise SystemExit(1)
        if item["kind"] == "text" and not filename.endswith(".log"):
            raise SystemExit(1)
        names.append(filename)
    if len(names) != len(set(names)):
        raise SystemExit(1)
    return set(names)


framework_names = validate_evidence(value["framework_required_evidence"])
if value["framework_required_evidence"] != [
    {"filename": "cleanup-receipt.json", "kind": "json"}
]:
    raise SystemExit(1)
cases = value["cases"]
if not isinstance(cases, list) or not cases:
    raise SystemExit(1)
expected_cases = {
    "control-startup-schema",
    "node-registration-full-inventory",
    "cat-create-running",
    "durable-write-flush",
    "route-http-ws",
    "route-v2-rotation-disable-live-delivery",
    "agent-restart-adoption",
    "volume-init-matrix",
    "usage-final-terminal-receipt",
    "v3-aws-host-fence-authority",
    "delete-cleanup",
}
case_ids = []
for case in cases:
    if not isinstance(case, dict) or set(case) != {
        "case_id",
        "deadline_seconds",
        "expected_outcome",
        "required_evidence",
    }:
        raise SystemExit(1)
    case_id = case["case_id"]
    if not isinstance(case_id, str) or case_pattern.fullmatch(case_id) is None:
        raise SystemExit(1)
    deadline = case["deadline_seconds"]
    if type(deadline) is not int or not 1 <= deadline <= 3600:
        raise SystemExit(1)
    if case["expected_outcome"] != {"kind": "passed"}:
        raise SystemExit(1)
    if validate_evidence(case["required_evidence"]) & framework_names:
        raise SystemExit(1)
    case_ids.append(case_id)
if len(case_ids) != len(set(case_ids)) or set(case_ids) != expected_cases:
    raise SystemExit(1)
PY

qualification_catalog_sha256=$(sha256sum "$qualification_catalog" | awk '{print $1}')
qualification_catalog_size=$(wc -c <"$qualification_catalog" | tr -d ' ')

[[ $(wc -c <"$build_receipt") -le 1048576 ]] || fail "build receipt is too large"
[[ $(wc -c <"$release_manifest") -le 1048576 ]] || fail "release manifest is too large"
[[ $(wc -c <"$installer_receipt") -le 1048576 ]] || fail "installer receipt is too large"
jq -e --arg commit "$exact_commit" \
  '.source_sha == $commit and .exit_status == 0 and .output_frozen == true' \
  "$build_receipt" >/dev/null || fail "build receipt does not prove a successful frozen build of the exact commit"
jq -e --arg commit "$exact_commit" \
  --arg catalog_sha256 "sha256:$qualification_catalog_sha256" \
  --argjson catalog_size "$qualification_catalog_size" \
  '.version == 1 and .source.commit == $commit
    and (.artifacts.worker.bundle_sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.artifacts.worker.members | type == "object" and length > 0)
    and .build_inputs.files.qualification_catalog
      == {sha256:$catalog_sha256,size_bytes:$catalog_size}' \
  "$release_manifest" >/dev/null || fail "release manifest does not bind the exact commit"
approved_release_manifest_sha256=${release_manifest_sha256#sha256:}
[[ $(sha256sum "$release_manifest" | awk '{print $1}') == "$approved_release_manifest_sha256" ]] || \
  fail "release manifest differs from the independently approved sha256"
jq -e '
  (keys == ["host_tools","members","service","version","worker_bundle_sha256"])
  and .version == 1 and .service == "cats-worker.service"
  and (.worker_bundle_sha256 | test("^sha256:[0-9a-f]{64}$"))
  and (.members | keys) == ["cats","cats-blockd","cats-e3-guest-workload","cats-guest-agent","cats-noded","cats-route-v2-node-r1-validator","cats-runtime-e3-probe","cats-usage-schema-v16-verifier","cats-usage-terminal-receipt-verifier","cats-vmm-launcher"]
  and (.host_tools | keys) == ["curl","journalctl","systemctl","timeout"]
  and all(.members[];
    (keys == ["path","sha256","size_bytes"])
    and (.path | type == "string" and startswith("/"))
    and (.sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.size_bytes | type == "number" and . > 0 and floor == .))
  and all(.host_tools[];
    (keys == ["path","sha256","size_bytes"])
    and (.path | type == "string" and startswith("/"))
    and (.sha256 | test("^sha256:[0-9a-f]{64}$"))
    and (.size_bytes | type == "number" and . > 0 and floor == .))' \
  "$installer_receipt" >/dev/null || fail "installer receipt has the wrong closed shape"
python3 - "$installer_receipt" <<'PY' || fail "installer receipt or its parent is not protected production evidence"
import os
import stat
import sys
value = os.stat(sys.argv[1], follow_symlinks=False)
parent = os.stat(os.path.dirname(sys.argv[1]), follow_symlinks=False)
assert stat.S_ISREG(value.st_mode)
assert value.st_uid == 0
assert value.st_gid == 0
assert value.st_nlink == 1
assert stat.S_IMODE(value.st_mode) in (0o600, 0o644)
assert stat.S_ISDIR(parent.st_mode)
assert parent.st_uid == 0
assert parent.st_gid == 0
assert stat.S_IMODE(parent.st_mode) & 0o022 == 0
PY
protected_token_file() {
  python3 - "$1" <<'PY'
import os
import stat
import sys
value = os.stat(sys.argv[1], follow_symlinks=False)
parent = os.stat(os.path.dirname(sys.argv[1]), follow_symlinks=False)
assert stat.S_ISREG(value.st_mode)
assert value.st_uid == 0
assert value.st_gid == 0
assert value.st_nlink == 1
assert stat.S_IMODE(value.st_mode) == 0o600
assert 0 < value.st_size <= 16384
assert stat.S_ISDIR(parent.st_mode)
assert parent.st_uid == 0
assert parent.st_gid == 0
assert stat.S_IMODE(parent.st_mode) & 0o022 == 0
raw = open(sys.argv[1], "rb").read()
if raw.endswith(b"\n"):
    raw = raw[:-1]
assert raw and b"\n" not in raw and b"\r" not in raw and b"\0" not in raw
PY
}
protected_token_file "$token_file" || fail "token file or its parent is not protected root-only input"
manifest_worker_bundle_sha256=$(jq -er '.artifacts.worker.bundle_sha256' "$release_manifest")
installer_worker_bundle_sha256=$(jq -er '.worker_bundle_sha256' "$installer_receipt")
[[ $installer_worker_bundle_sha256 == "$manifest_worker_bundle_sha256" ]] || \
  fail "installer receipt is not bound to the approved worker bundle"

schema_version=$(git -C "$repo" show "${exact_commit}:storage/src/authority.rs" |
  sed -nE 's/^pub const AUTHORITY_RELEASE_SCHEMA_VERSION: i64 = ([0-9]+);$/\1/p')
[[ $schema_version =~ ^[1-9][0-9]*$ ]] || fail "exact source does not expose one authority schema version"

mkdir -m 0700 "$output_dir"
scratch=$output_dir/.scratch
mkdir -m 0700 "$scratch"
stage=$scratch/stage
mkdir -m 0700 "$stage" "$stage/binaries" "$stage/configs"
results_work=$scratch/scenario-results.jsonl
journal_work=$scratch/component-journal-summary.txt
catalog_work=$scratch/scenario-catalog.jsonl
binaries_work=$scratch/binaries.jsonl
configs_work=$scratch/configs.jsonl
fingerprints_work=$scratch/key-fingerprints.jsonl
evidence_work=$scratch/case-evidence.jsonl
: >"$results_work"
: >"$journal_work"
: >"$catalog_work"
: >"$binaries_work"
: >"$configs_work"
: >"$fingerprints_work"
: >"$evidence_work"

original_labels=()
original_paths=()
original_digests=()

remember_original() {
  original_labels+=("$1")
  original_paths+=("$2")
  original_digests+=("$3")
}

stage_input() {
  local label=$1 source=$2 destination=$3 mode=$4 expected=$5 before after
  before=$(sha256sum "$source" | awk '{print $1}')
  [[ $before == "$expected" ]] || fail "$label changed before its stable-stage copy"
  cp "$source" "$destination"
  chmod "$mode" "$destination"
  after=$(sha256sum "$destination" | awk '{print $1}')
  [[ $after == "$expected" ]] || fail "stable-stage copy changed $label"
  remember_original "$label" "$source" "$expected"
}

atomic_copy() {
  local source=$1 destination=$2 temporary
  temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
  cp "$source" "$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/$destination"
}

atomic_text() {
  local destination=$1 value=$2 temporary
  temporary=$(mktemp "$output_dir/.${destination}.XXXXXX")
  printf '%s' "$value" >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/$destination"
}

scenario_driver_original=$scenario_driver
qualification_catalog_original=$qualification_catalog
filter_original=$filter
runner_authority_sha256=$(sha256sum "$runner" | awk '{print $1}')
filter_authority_sha256=$(sha256sum "$filter" | awk '{print $1}')
scenario_driver_authority_sha256=$(sha256sum "$scenario_driver" | awk '{print $1}')
qualification_catalog_authority_sha256=$(sha256sum "$qualification_catalog" | awk '{print $1}')
build_receipt_authority_sha256=$(sha256sum "$build_receipt" | awk '{print $1}')
installer_receipt_authority_sha256=$(sha256sum "$installer_receipt" | awk '{print $1}')
token_file_original=$token_file
token_file_authority_sha256=$(sha256sum "$token_file" | awk '{print $1}')
verify_exact_repo_file "$runner"
verify_exact_repo_file "$filter"
verify_exact_repo_file "$scenario_driver"
stage_input runner "$runner" "$stage/runtime-cutover-e2e.sh" 0700 "$runner_authority_sha256"
stage_input evidence-filter "$filter" "$stage/runtime-cutover-evidence-filter.py" 0700 "$filter_authority_sha256"
stage_input scenario-driver "$scenario_driver" "$stage/runtime-cutover-v2-scenarios.sh" 0700 "$scenario_driver_authority_sha256"
stage_input qualification-catalog "$qualification_catalog" "$stage/qualification-catalog.v1.json" 0600 "$qualification_catalog_authority_sha256"
stage_input build-receipt "$build_receipt" "$stage/build-receipt.json" 0600 "$build_receipt_authority_sha256"
stage_input release-manifest "$release_manifest" "$stage/release-manifest.json" 0600 "$approved_release_manifest_sha256"
stage_input installer-receipt "$installer_receipt" "$stage/installer-receipt.json" 0600 "$installer_receipt_authority_sha256"
cats_e3_prepare_private_stage "${token_file_original%/*}" || \
  fail "create root-only private token stage"
token_file=$cats_e3_private_stage/control-token
token_before=$(sha256sum "$token_file_original" | awk '{print $1}')
[[ $token_before == "$token_file_authority_sha256" ]] || fail "token changed before its private stable-stage copy"
cp "$token_file_original" "$token_file"
chmod 0600 "$token_file"
[[ $(sha256sum "$token_file" | awk '{print $1}') == "$token_file_authority_sha256" ]] || \
  fail "private stable-stage copy changed token"
verify_staged_repo_file() {
  local original=$1 staged=$2 relative expected_blob actual_blob
  relative=${original#"$repo"/}
  expected_blob=$(git -C "$repo" rev-parse "${exact_commit}:${relative}") || \
    fail "$relative has no exact-commit blob"
  actual_blob=$(git -C "$repo" hash-object "$staged")
  [[ $actual_blob == "$expected_blob" ]] || fail "stable-stage $relative differs from the exact commit"
}
verify_staged_repo_file "$runner" "$stage/runtime-cutover-e2e.sh"
verify_staged_repo_file "$filter" "$stage/runtime-cutover-evidence-filter.py"
verify_staged_repo_file "$scenario_driver" "$stage/runtime-cutover-v2-scenarios.sh"
verify_staged_repo_file "$qualification_catalog" "$stage/qualification-catalog.v1.json"
filter=$stage/runtime-cutover-evidence-filter.py
scenario_driver=$stage/runtime-cutover-v2-scenarios.sh
qualification_catalog=$stage/qualification-catalog.v1.json

jq -e --arg commit "$exact_commit" \
  '.source_sha == $commit and .exit_status == 0 and .output_frozen == true' \
  "$stage/build-receipt.json" >/dev/null || fail "staged build receipt changed authority"
jq -e --arg commit "$exact_commit" \
  --arg catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
  --argjson catalog_size "$qualification_catalog_size" \
  '.version == 1 and .source.commit == $commit
    and .build_inputs.files.qualification_catalog
      == {sha256:$catalog_sha256,size_bytes:$catalog_size}' \
  "$stage/release-manifest.json" >/dev/null || fail "staged release manifest changed authority"
jq -e '
  (keys == ["host_tools","members","service","version","worker_bundle_sha256"])
  and .version == 1 and .service == "cats-worker.service"' \
  "$stage/installer-receipt.json" >/dev/null || fail "staged installer receipt changed authority"

jq -e -n --slurpfile manifest "$stage/release-manifest.json" \
  --slurpfile receipt "$stage/installer-receipt.json" \
  '($manifest[0].artifacts.worker.members | keys) == ($receipt[0].members | keys)
    and all($manifest[0].artifacts.worker.members | to_entries[];
      . as $member
      | $member.value.sha256 == $receipt[0].members[$member.key].sha256
        and $member.value.size_bytes == $receipt[0].members[$member.key].size_bytes)' \
  >/dev/null || fail "installer receipt members differ from the approved worker manifest"

seen_binary_labels='|'
seen_binary_environment_labels='|'
installed_noded_path=
timeout_bin=
timeout_bin_original=
for entry in "${binary_entries[@]}"; do
  label=${entry%%=*}
  path=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "binary label is not canonical"
  case "$seen_binary_labels" in *"|$label|"*) fail "binary label $label is repeated" ;; esac
  seen_binary_labels+="$label|"
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  case "$seen_binary_environment_labels" in
    *"|$environment_label|"*) fail "binary label $label collides after environment normalization" ;;
  esac
  seen_binary_environment_labels+="$environment_label|"
  [[ $path != *@sha256:* ]] || fail "binary $label digest must come from the approved manifest and installer receipt"
  canonical=$(canonical_existing "$path") || fail "binary $label must name a regular non-symlink file"
  [[ -f $canonical && -x $canonical ]] || fail "binary $label is not executable"
  artifact_name=${canonical##*/}
  authority=$(jq -er --arg name "$artifact_name" '
    if .members[$name] != null then "worker-member"
    elif .host_tools[$name] != null then "installer-host-tool"
    else empty end' "$stage/installer-receipt.json") || \
    fail "binary $label is absent from the installer receipt"
  case "$authority" in
    worker-member)
      expected_path=$(jq -er --arg name "$artifact_name" '.members[$name].path' "$stage/installer-receipt.json")
      expected_sha256=$(jq -er --arg name "$artifact_name" '.members[$name].sha256' "$stage/installer-receipt.json")
      expected_size=$(jq -er --arg name "$artifact_name" '.members[$name].size_bytes' "$stage/installer-receipt.json")
      manifest_sha256=$(jq -er --arg name "$artifact_name" '.artifacts.worker.members[$name].sha256' "$stage/release-manifest.json")
      manifest_size=$(jq -er --arg name "$artifact_name" '.artifacts.worker.members[$name].size_bytes' "$stage/release-manifest.json")
      [[ $expected_sha256 == "$manifest_sha256" && $expected_size == "$manifest_size" ]] || \
        fail "installed worker member $artifact_name differs from the approved manifest"
      ;;
    installer-host-tool)
      expected_path=$(jq -er --arg name "$artifact_name" '.host_tools[$name].path' "$stage/installer-receipt.json")
      expected_sha256=$(jq -er --arg name "$artifact_name" '.host_tools[$name].sha256' "$stage/installer-receipt.json")
      expected_size=$(jq -er --arg name "$artifact_name" '.host_tools[$name].size_bytes' "$stage/installer-receipt.json")
      ;;
    *) fail "binary $label has no closed installer authority" ;;
  esac
  [[ $expected_path == /* && $expected_sha256 =~ ^sha256:[0-9a-f]{64}$ && $expected_size =~ ^[1-9][0-9]*$ ]] || \
    fail "installer receipt entry for $artifact_name is invalid"
  canonical_expected=$(canonical_existing "$expected_path") || \
    fail "installer receipt path for $artifact_name is not a real regular file"
  [[ $canonical == "$canonical_expected" ]] || fail "binary $label path differs from the installer receipt"
  digest=$(sha256sum "$canonical" | awk '{print $1}')
  size=$(wc -c <"$canonical" | tr -d ' ')
  [[ sha256:$digest == "$expected_sha256" && $size == "$expected_size" ]] || \
    fail "binary $label bytes differ from the installer receipt"
  staged=$stage/binaries/$label
  stage_input "binary:$label" "$canonical" "$staged" 0700 "$digest"
  jq -S -c -n --arg label "$label" --arg artifact_name "$artifact_name" \
    --arg authority "$authority" --arg path "$canonical" --arg staged_path "$staged" \
    --arg sha256 "$digest" --argjson size_bytes "$size" \
    '{label:$label,artifact_name:$artifact_name,authority:$authority,path:$path,
      staged_path:$staged_path,sha256:$sha256,size_bytes:$size_bytes}' >>"$binaries_work"
  printf -v "CATS_E3_BINARY_${environment_label}" '%s' "$staged"
  export "CATS_E3_BINARY_${environment_label}"
  printf -v "CATS_E3_BINARY_${environment_label}_SHA256" '%s' "$digest"
  export "CATS_E3_BINARY_${environment_label}_SHA256"
  if [[ $artifact_name == cats-noded ]]; then
    installed_noded_path=$canonical
  fi
  if [[ $label == timeout ]]; then
    [[ $artifact_name == timeout && $authority == installer-host-tool ]] || \
      fail "--binary timeout must be the installer-recorded Host timeout"
    timeout_bin=$staged
    timeout_bin_original=$canonical
    timeout_bin_sha256=$digest
  fi
done
for required_binding in \
  cats=cats \
  runtime-e3-probe=cats-runtime-e3-probe \
  e3-guest-workload=cats-e3-guest-workload \
  curl=curl \
  systemctl=systemctl \
  journalctl=journalctl \
  timeout=timeout; do
  required_label=${required_binding%%=*}
  required_artifact=${required_binding#*=}
  jq -e --arg label "$required_label" --arg artifact "$required_artifact" \
    'select(.label == $label and .artifact_name == $artifact)' "$binaries_work" >/dev/null || \
    fail "--binary $required_label must bind installer-recorded $required_artifact"
done
[[ -n $installed_noded_path ]] || fail "the installed cats-noded worker member must be an explicit --binary"
[[ -n $timeout_bin ]] || fail "--binary timeout is required"

seen_config_labels='|'
seen_config_environment_labels='|'
route_rotation_operator_authority_id=
route_rotation_operator_route_deployment_id=
route_rotation_operator_trust_sha256=
for entry in "${config_entries[@]}"; do
  label=${entry%%=*}
  path=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "config label is not canonical"
  case "$seen_config_labels" in *"|$label|"*) fail "config label $label is repeated" ;; esac
  seen_config_labels+="$label|"
  environment_label=$(printf '%s' "$label" | tr '[:lower:]-' '[:upper:]_')
  case "$seen_config_environment_labels" in
    *"|$environment_label|"*) fail "config label $label collides after environment normalization" ;;
  esac
  seen_config_environment_labels+="$environment_label|"
  canonical=$(canonical_existing "$path") || fail "config $label must name a regular non-symlink file"
  [[ -f $canonical ]] || fail "config $label is not a regular file"
  digest=$(sha256sum "$canonical" | awk '{print $1}')
  size=$(wc -c <"$canonical" | tr -d ' ')
  if [[ $label == route-rotation-operator-trust ]]; then
    [[ $path == /etc/cats/route-v2/rotation-operator-trust.v1.json && $canonical == "$path" ]] || \
      fail "route-rotation-operator-trust must use the canonical installed path"
    if ! route_rotation_operator_coordinates=$(python3 - "$canonical" "$exact_commit" <<'PY'
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey
        value[key] = item
    return value


path = Path(sys.argv[1])
exact_commit = sys.argv[2]
raw = path.read_bytes()
if not 1 <= len(raw) <= 16384:
    raise SystemExit(1)
try:
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
except (UnicodeDecodeError, json.JSONDecodeError, DuplicateKey):
    raise SystemExit(1)
if not isinstance(value, dict) or list(value) != [
    "version",
    "authority_id",
    "route_deployment_id",
    "release_commit_sha",
    "threshold",
    "credentials",
]:
    raise SystemExit(1)
canonical = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
if (
    raw != canonical
    or type(value["version"]) is not int
    or value["version"] != 1
    or value["release_commit_sha"] != exact_commit
):
    raise SystemExit(1)
id_pattern = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
digest_pattern = re.compile(r"sha256:[0-9a-f]{64}\Z")
base64url_pattern = re.compile(r"[A-Za-z0-9_-]+\Z")
if (
    not isinstance(value["authority_id"], str)
    or id_pattern.fullmatch(value["authority_id"]) is None
    or not isinstance(value["route_deployment_id"], str)
    or id_pattern.fullmatch(value["route_deployment_id"]) is None
):
    raise SystemExit(1)
credentials = value["credentials"]
threshold = value["threshold"]
if (
    not isinstance(credentials, list)
    or not 1 <= len(credentials) <= 8
    or type(threshold) is not int
    or not 1 <= threshold <= len(credentials)
):
    raise SystemExit(1)
credential_ids = []
spki_digests = set()
ed25519_spki_prefix = bytes.fromhex("302a300506032b6570032100")
for credential in credentials:
    if not isinstance(credential, dict) or list(credential) != [
        "credential_id",
        "public_key_spki",
        "public_key_spki_sha256",
    ]:
        raise SystemExit(1)
    credential_id = credential["credential_id"]
    public_key_spki = credential["public_key_spki"]
    public_key_spki_sha256 = credential["public_key_spki_sha256"]
    if (
        not isinstance(credential_id, str)
        or id_pattern.fullmatch(credential_id) is None
        or not isinstance(public_key_spki, str)
        or base64url_pattern.fullmatch(public_key_spki) is None
        or not isinstance(public_key_spki_sha256, str)
        or digest_pattern.fullmatch(public_key_spki_sha256) is None
    ):
        raise SystemExit(1)
    try:
        padding = "=" * ((4 - len(public_key_spki) % 4) % 4)
        spki = base64.b64decode(public_key_spki + padding, altchars=b"-_", validate=True)
    except (ValueError, base64.binascii.Error):
        raise SystemExit(1)
    if len(spki) != 44 or not spki.startswith(ed25519_spki_prefix):
        raise SystemExit(1)
    if "sha256:" + hashlib.sha256(spki).hexdigest() != public_key_spki_sha256:
        raise SystemExit(1)
    credential_ids.append(credential_id)
    spki_digests.add(public_key_spki_sha256)
if credential_ids != sorted(set(credential_ids)) or len(spki_digests) != len(credentials):
    raise SystemExit(1)
metadata = os.stat(path, follow_symlinks=False)
parent = os.stat(path.parent, follow_symlinks=False)
if (
    not stat.S_ISREG(metadata.st_mode)
    or metadata.st_uid != 0
    or metadata.st_gid != 0
    or metadata.st_nlink != 1
    or stat.S_IMODE(metadata.st_mode) != 0o644
    or not stat.S_ISDIR(parent.st_mode)
    or parent.st_uid != 0
    or parent.st_gid != 0
    or stat.S_IMODE(parent.st_mode) != 0o700
):
    raise SystemExit(1)
print(value["authority_id"] + "\t" + value["route_deployment_id"])
PY
    ); then
      fail "route-rotation-operator-trust is not the exact canonical release trust"
    fi
    IFS=$'\t' read -r route_rotation_operator_authority_id \
      route_rotation_operator_route_deployment_id <<<"$route_rotation_operator_coordinates"
    [[ -n $route_rotation_operator_authority_id && -n $route_rotation_operator_route_deployment_id ]] || \
      fail "route-rotation-operator-trust does not expose exact coordinates"
    route_rotation_operator_trust_sha256=sha256:$digest
  fi
  staged=$stage/configs/$label
  stage_input "config:$label" "$canonical" "$staged" 0600 "$digest"
  jq -S -c -n --arg label "$label" --arg path "$canonical" --arg staged_path "$staged" \
    --arg sha256 "$digest" --argjson size_bytes "$size" \
    '{label:$label,path:$path,staged_path:$staged_path,sha256:$sha256,size_bytes:$size_bytes}' >>"$configs_work"
  printf -v "CATS_E3_CONFIG_${environment_label}" '%s' "$staged"
  export "CATS_E3_CONFIG_${environment_label}"
done

for required_config in \
  qualification-ingress-open-plan \
  qualification-ingress-close-plan \
  route-rotation-operator-trust \
  usage-terminal-targets; do
  jq -e --arg label "$required_config" 'select(.label == $label)' "$configs_work" >/dev/null || \
    fail "--config $required_config is required by the production qualification contract"
done

usage_terminal_targets=$stage/configs/usage-terminal-targets
jq -e '
  (keys == ["fresh_target","old_target","shards","version"])
  and .version == 1
  and ([.old_target,.fresh_target] | all(.;
    keys == ["archive_bucket_arn","archive_bucket_name","aws_account_id","aws_region",
      "checkpoint_table_arn","checkpoint_table_name","stream_arn","stream_name","usage_schema"]
    and all(.[]; type == "string" and length > 0)))
  and (.shards | type == "array" and length > 0)
  and all(.shards[];
    keys == ["explicit_hash_key","shard_id"]
    and (.shard_id | test("^shardId-[0-9]{12}$"))
    and (.explicit_hash_key | test("^(0|[1-9][0-9]{0,38})$")))
  and ([.shards[].shard_id] == ([.shards[].shard_id] | sort | unique))' \
  "$usage_terminal_targets" >/dev/null || \
  fail "--config usage-terminal-targets has the wrong closed E9 target shape"

cats_e3_export_qualification_environment
seen_key_fingerprint_labels='|'
for entry in "${key_fingerprint_entries[@]}"; do
  label=${entry%%=*}
  fingerprint=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "key fingerprint label is not canonical"
  case "$seen_key_fingerprint_labels" in
    *"|$label|"*) fail "key fingerprint label $label is repeated" ;;
  esac
  seen_key_fingerprint_labels+="$label|"
  [[ $fingerprint =~ ^sha256:[0-9a-f]{64}$ ]] || fail "key fingerprint must be a nonsecret sha256 value"
  jq -S -c -n --arg label "$label" --arg fingerprint "$fingerprint" \
    '{label:$label,fingerprint:$fingerprint}' >>"$fingerprints_work"
done

case_ids=()
case_deadlines=()
case_expected_outcomes=()
case_required_evidence=()
while IFS= read -r case_record; do
  case_ids+=("$(jq -r '.case_id' <<<"$case_record")")
  case_deadlines+=("$(jq -r '.deadline_seconds' <<<"$case_record")")
  case_expected_outcomes+=("$(jq -c '.expected_outcome' <<<"$case_record")")
  case_required_evidence+=("$(jq -c '.required_evidence' <<<"$case_record")")
  printf '%s\n' "$case_record" >>"$catalog_work"
done < <(jq -S -c '
  .framework_required_evidence as $framework
  | .cases[]
  | .required_evidence = (.required_evidence + $framework)' "$qualification_catalog")
[[ ${#case_ids[@]} -gt 0 ]] || fail "qualification catalog contains no cases"
expected_nodes_work=$scratch/expected-nodes.json
printf '%s\n' "${expected_nodes[@]}" | jq -Rsc 'split("\n")[:-1]' >"$expected_nodes_work"

started_at_unix_seconds=$(date +%s)
host_kernel=$(uname -r)
[[ $host_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || fail "Host kernel release is not a bounded nonsecret string"
build_receipt_sha256=$(sha256sum "$build_receipt" | awk '{print $1}')
release_manifest_sha256=$(sha256sum "$release_manifest" | awk '{print $1}')
installer_receipt_sha256=$(sha256sum "$installer_receipt" | awk '{print $1}')
scenario_driver_sha256=$(sha256sum "$scenario_driver" | awk '{print $1}')
scenario_catalog_sha256=$(sha256sum "$catalog_work" | awk '{print $1}')

write_manifest() {
  local state=$1 exit_value=$2 ended=$3 temporary case_evidence_sha256 case_evidence_count
  case_evidence_sha256=$(sha256sum "$evidence_work" | awk '{print $1}')
  case_evidence_count=$(wc -l <"$evidence_work" | tr -d ' ')
  temporary=$(mktemp "$output_dir/.manifest.json.XXXXXX")
  jq -S -c -n \
    --arg state "$state" \
    --arg exact_commit "$exact_commit" \
    --arg block_path "$block_path" \
    --arg run_id "$run_id" \
    --arg host_kernel "$host_kernel" \
    --arg guest_kernel "$guest_kernel" \
    --argjson schema_version "$schema_version" \
    --arg build_receipt "$build_receipt" \
    --arg build_receipt_sha256 "$build_receipt_sha256" \
    --arg release_manifest "$release_manifest" \
    --arg release_manifest_sha256 "$release_manifest_sha256" \
    --arg approved_release_manifest_sha256 "$approved_release_manifest_sha256" \
    --arg installer_receipt "$installer_receipt" \
    --arg installer_receipt_sha256 "$installer_receipt_sha256" \
    --arg worker_bundle_sha256 "$manifest_worker_bundle_sha256" \
    --arg control_origin "$control_origin" \
    --arg workspace_id "$workspace_id" \
    --arg qualification_node "$qualification_node" \
    --arg cat_name "$cat_name" \
    --arg boot_image_digest "$boot_image_digest" \
    --arg endpoint_name "$endpoint_name" \
    --arg endpoint_hostname "$endpoint_hostname" \
    --arg scenario_driver "$scenario_driver_original" \
    --arg scenario_driver_sha256 "$scenario_driver_sha256" \
    --arg qualification_catalog "$qualification_catalog_original" \
    --arg qualification_catalog_sha256 "sha256:$qualification_catalog_authority_sha256" \
    --argjson qualification_catalog_size_bytes "$qualification_catalog_size" \
    --arg timeout_binary "$timeout_bin_original" \
    --arg timeout_binary_sha256 "$timeout_bin_sha256" \
    --arg scenario_catalog_sha256 "$scenario_catalog_sha256" \
    --arg case_evidence_sha256 "sha256:$case_evidence_sha256" \
    --argjson case_evidence_count "$case_evidence_count" \
    --arg route_rotation_operator_authority_id "$route_rotation_operator_authority_id" \
    --arg route_rotation_operator_route_deployment_id "$route_rotation_operator_route_deployment_id" \
    --arg route_rotation_operator_trust_sha256 "$route_rotation_operator_trust_sha256" \
    --argjson started_at_unix_seconds "$started_at_unix_seconds" \
    --argjson ended_at_unix_seconds "$ended" \
    --argjson exit_code "$exit_value" \
    --slurpfile binaries "$binaries_work" \
    --slurpfile configs "$configs_work" \
    --slurpfile key_fingerprints "$fingerprints_work" \
    --slurpfile expected_nodes "$expected_nodes_work" \
    --slurpfile scenarios "$catalog_work" \
    '{version:1,state:$state,exact_commit:$exact_commit,block_path:$block_path,
      run_id:$run_id,schema_version:$schema_version,kernels:{host:$host_kernel,guest:$guest_kernel},
      build_receipt:{path:$build_receipt,sha256:$build_receipt_sha256},
      release_manifest:{path:$release_manifest,sha256:$release_manifest_sha256,
        approved_sha256:$approved_release_manifest_sha256},
      installer_receipt:{path:$installer_receipt,sha256:$installer_receipt_sha256,
        worker_bundle_sha256:$worker_bundle_sha256},
      scenario_driver:{path:$scenario_driver,sha256:$scenario_driver_sha256},
      qualification_catalog:{path:$qualification_catalog,sha256:$qualification_catalog_sha256,
        size_bytes:$qualification_catalog_size_bytes},
      route_v2_rotation_operator:{config_label:"route-rotation-operator-trust",
        authority_id:$route_rotation_operator_authority_id,
        route_deployment_id:$route_rotation_operator_route_deployment_id,
        trust_sha256:$route_rotation_operator_trust_sha256},
      case_evidence:{sha256:$case_evidence_sha256,count:$case_evidence_count},
      timeout_binary:{path:$timeout_binary,sha256:$timeout_binary_sha256},
      qualification:{control_origin:$control_origin,workspace_id:$workspace_id,
        expected_nodes:$expected_nodes[0],qualification_node_id:$qualification_node,
        cat_name:$cat_name,boot_image_digest:$boot_image_digest,endpoint_name:$endpoint_name,
        endpoint_hostname:$endpoint_hostname,public_origin:("https://" + $endpoint_hostname)},
      scenario_catalog_sha256:$scenario_catalog_sha256,binaries:$binaries,configs:$configs,
      key_fingerprints:$key_fingerprints,scenarios:$scenarios,
      started_at_unix_seconds:$started_at_unix_seconds,
      ended_at_unix_seconds:$ended_at_unix_seconds,exit_code:$exit_code}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/manifest.json"
}

write_manifest running -1 0
atomic_copy "$results_work" scenario-results.jsonl
atomic_copy "$journal_work" component-journal-summary.txt
atomic_copy "$evidence_work" case-evidence.jsonl
atomic_copy "$qualification_catalog" qualification-catalog.v1.json

export CATS_E3_EXACT_COMMIT=$exact_commit
export CATS_E3_BLOCK_PATH=$block_path
export CATS_E3_RUN_ID=$run_id
export CATS_E3_OUTPUT_DIR=$output_dir
export CATS_E3_RUNTIME_STATE=$output_dir/runtime-state.json
export CATS_E3_RUN_STARTED_AT_UNIX_MS=$((started_at_unix_seconds * 1000))
export CATS_E3_WORKER_BUNDLE_SHA256=${manifest_worker_bundle_sha256#sha256:}

jq -S -c -n \
  --arg exact_commit "$exact_commit" --arg block_path "$block_path" --arg run_id "$run_id" \
  '{version:1,exact_commit:$exact_commit,block_path:$block_path,run_id:$run_id,cat_id:null}' \
  >"$scratch/runtime-state.initial.json"
atomic_copy "$scratch/runtime-state.initial.json" runtime-state.json

cats_e3_run_cases_post_preflight

input_rehash_work=$scratch/input-rehash-diagnostic.txt
: >"$input_rehash_work"
for index in "${!original_paths[@]}"; do
  original=${original_paths[$index]}
  expected=${original_digests[$index]}
  actual=unavailable
  if [[ -f $original && ! -L $original ]]; then
    actual=$(sha256sum "$original" | awk '{print $1}')
  fi
  if [[ $actual != "$expected" ]]; then
    printf 'stable input changed label=%s expected_sha256=%s actual_sha256=%s\n' \
      "${original_labels[$index]}" "$expected" "$actual" >>"$input_rehash_work"
  fi
done
if [[ -s $input_rehash_work ]]; then
  failed_cases=$((failed_cases + 1))
  append_summary stable-inputs diagnostics "$input_rehash_work"
fi

coordinate_recheck=$scratch/qualification-coordinate-diagnostic.txt
: >"$coordinate_recheck"
[[ ${CATS_E3_CONTROL_ORIGIN:-} == "$control_origin" ]] || printf '%s\n' 'control origin changed' >>"$coordinate_recheck"
[[ ${CATS_E3_WORKSPACE_ID:-} == "$workspace_id" ]] || printf '%s\n' 'workspace ID changed' >>"$coordinate_recheck"
[[ ${CATS_E3_EXPECTED_NODES:-} == "$(IFS=,; printf '%s' "${expected_nodes[*]}")" ]] || \
  printf '%s\n' 'expected Node set changed' >>"$coordinate_recheck"
[[ ${CATS_E3_QUALIFICATION_NODE_ID:-} == "$qualification_node" ]] || \
  printf '%s\n' 'qualification Node changed' >>"$coordinate_recheck"
[[ ${CATS_E3_CAT_NAME:-} == "$cat_name" ]] || printf '%s\n' 'Cat name changed' >>"$coordinate_recheck"
[[ ${CATS_E3_BOOT_IMAGE_DIGEST:-} == "$boot_image_digest" ]] || \
  printf '%s\n' 'boot image digest changed' >>"$coordinate_recheck"
[[ ${CATS_E3_ENDPOINT_NAME:-} == "$endpoint_name" ]] || printf '%s\n' 'Endpoint name changed' >>"$coordinate_recheck"
[[ ${CATS_E3_ENDPOINT_HOSTNAME:-} == "$endpoint_hostname" ]] || \
  printf '%s\n' 'Endpoint hostname changed' >>"$coordinate_recheck"
[[ ${CATS_E3_PUBLIC_ORIGIN:-} == "https://$endpoint_hostname" ]] || \
  printf '%s\n' 'public origin changed' >>"$coordinate_recheck"
[[ -f $token_file_original && ! -L $token_file_original ]] && \
  protected_token_file "$token_file_original" >/dev/null 2>&1 && \
  [[ $(sha256sum "$token_file_original" | awk '{print $1}') == "$token_file_authority_sha256" ]] || \
  printf '%s\n' 'root-only token input changed' >>"$coordinate_recheck"
if [[ -s $coordinate_recheck ]]; then
  failed_cases=$((failed_cases + 1))
  append_summary qualification-coordinates diagnostics "$coordinate_recheck"
fi

final_exit=0
final_state=passed
if [[ $failed_cases -ne 0 || $blocked_cases -ne 0 ]]; then
  final_exit=1
  final_state=failed
fi
atomic_text exit-code "$final_exit"$'\n'
ended_at_unix_seconds=$(date +%s)
write_manifest "$final_state" "$final_exit" "$ended_at_unix_seconds"

rm -rf "$scratch"
checksums_tmp=$(mktemp "$output_dir/.SHA256SUMS.XXXXXX")
(
  cd "$output_dir"
  LC_ALL=C sha256sum \
    component-journal-summary.txt \
    case-evidence.jsonl \
    exit-code \
    final-inventory.json \
    manifest.json \
    qualification-catalog.v1.json \
    runtime-state.json \
    scenario-results.jsonl
) >"$checksums_tmp"
chmod 0600 "$checksums_tmp"
mv -f "$checksums_tmp" "$output_dir/SHA256SUMS"

exit "$final_exit"
