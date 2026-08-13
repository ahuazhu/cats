#!/usr/bin/env bash
# Deterministic evidence orchestrator for an already-provisioned, cordoned
# runtime-cutover qualification host. It never provisions infrastructure,
# applies Terraform, or installs a long-lived service.
set -euo pipefail

usage() {
  cat >&2 <<'EOF'
usage: runtime-cutover-e2e.sh \
  --exact-commit <40 lowercase hex> \
  --block-path <kernel-nbd|vhost-user> \
  --run-id <stable-id> \
  --output-dir </absolute/new/directory> \
  --build-receipt </absolute/build-receipt.json> \
  --release-manifest </absolute/release-manifest.json> \
  --guest-kernel <nonsecret-release-string> \
  --binary <label=/absolute/path@sha256:64hex> [--binary ...] \
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
guest_kernel=
scenario_driver=
binary_entries=()
config_entries=()
key_fingerprint_entries=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    --exact-commit|--block-path|--run-id|--output-dir|--build-receipt|--release-manifest|--guest-kernel|--scenario-driver)
      [[ $# -ge 2 ]] || usage
      name=${1#--}
      name=${name//-/_}
      printf -v "$name" '%s' "$2"
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
[[ $guest_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || fail "--guest-kernel is not a bounded nonsecret release string"
[[ -n $scenario_driver && $scenario_driver == /* ]] || fail "--scenario-driver must be absolute"
[[ ${#binary_entries[@]} -gt 0 ]] || fail "at least one --binary is required"
[[ ${#config_entries[@]} -gt 0 ]] || fail "at least one --config is required"
[[ ${#key_fingerprint_entries[@]} -gt 0 ]] || fail "at least one --key-fingerprint is required"

for command_name in git jq python3 sha256sum; do
  command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done

script_dir=$(cd "$(dirname "$0")" && pwd -P)
repo=$(cd "$script_dir/../.." && pwd -P)
filter=$script_dir/runtime-cutover-evidence-filter.py
runner=$script_dir/runtime-cutover-e2e.sh

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
scenario_driver=$(canonical_existing "$scenario_driver") || fail "scenario driver must be a regular non-symlink file"
output_dir=$(canonical_output "$output_dir") || fail "absolute output parent must already exist and be a real directory"
[[ ! -e $output_dir && ! -L $output_dir ]] || fail "output directory already exists; refusing to overwrite evidence"

[[ $(git -C "$repo" rev-parse HEAD) == "$exact_commit" ]] || fail "checkout HEAD does not equal the exact commit"
[[ $(git -C "$repo" rev-parse "${exact_commit}^{commit}") == "$exact_commit" ]] || fail "exact commit is not a commit object"

verify_exact_repo_file() {
  local path=$1 relative expected_blob actual_blob
  case "$path" in "$repo"/*) ;; *) fail "scenario and evidence executables must be repo-owned" ;; esac
  relative=${path#"$repo"/}
  expected_blob=$(git -C "$repo" rev-parse "${exact_commit}:${relative}" 2>/dev/null) || fail "$relative is not tracked by the exact commit"
  actual_blob=$(git -C "$repo" hash-object "$path")
  [[ $actual_blob == "$expected_blob" ]] || fail "$relative differs from the exact commit"
  [[ -f $path && -x $path && ! -L $path ]] || fail "$relative must be an executable regular file"
}

verify_exact_repo_file "$runner"
verify_exact_repo_file "$filter"
verify_exact_repo_file "$scenario_driver"

[[ $(wc -c <"$build_receipt") -le 1048576 ]] || fail "build receipt is too large"
[[ $(wc -c <"$release_manifest") -le 1048576 ]] || fail "release manifest is too large"
jq -e --arg commit "$exact_commit" \
  '.source_sha == $commit and .exit_status == 0 and .output_frozen == true' \
  "$build_receipt" >/dev/null || fail "build receipt does not prove a successful frozen build of the exact commit"
jq -e --arg commit "$exact_commit" \
  '.version == 1 and .source.commit == $commit' \
  "$release_manifest" >/dev/null || fail "release manifest does not bind the exact commit"

schema_version=$(sed -nE 's/^pub const AUTHORITY_RELEASE_SCHEMA_VERSION: i64 = ([0-9]+);$/\1/p' "$repo/storage/src/authority.rs")
[[ $schema_version =~ ^[1-9][0-9]*$ ]] || fail "exact source does not expose one authority schema version"

timeout_bin=${CATS_E3_TIMEOUT_BIN:-}
if [[ -z $timeout_bin ]]; then
  timeout_bin=$(command -v timeout || true)
fi
[[ -n $timeout_bin ]] || fail "GNU timeout is required on the qualification host"
timeout_bin=$(canonical_existing "$timeout_bin") || fail "timeout command must be an absolute non-symlink executable"
[[ -x $timeout_bin && -f $timeout_bin ]] || fail "timeout command is not executable"

mkdir -m 0700 "$output_dir"
scratch=$output_dir/.scratch
mkdir -m 0700 "$scratch"
results_work=$scratch/scenario-results.jsonl
journal_work=$scratch/component-journal-summary.txt
catalog_work=$scratch/scenario-catalog.jsonl
binaries_work=$scratch/binaries.jsonl
configs_work=$scratch/configs.jsonl
fingerprints_work=$scratch/key-fingerprints.jsonl
: >"$results_work"
: >"$journal_work"
: >"$catalog_work"
: >"$binaries_work"
: >"$configs_work"
: >"$fingerprints_work"

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

record_hashed_entries() {
  local kind=$1 output=$2 entry label path canonical digest expected size
  shift 2
  for entry in "$@"; do
    label=${entry%%=*}
    path=${entry#*=}
    [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "$kind label is not canonical"
    expected=
    if [[ $kind == binary ]]; then
      expected=${path##*@sha256:}
      [[ $path != "$expected" && $expected =~ ^[0-9a-f]{64}$ ]] || fail "binary $label requires an expected sha256"
      path=${path%@sha256:*}
    fi
    canonical=$(canonical_existing "$path") || fail "$kind $label must name a regular non-symlink file"
    [[ -f $canonical ]] || fail "$kind $label is not a regular file"
    if [[ $kind == binary && ! -x $canonical ]]; then
      fail "binary $label is not executable"
    fi
    digest=$(sha256sum "$canonical" | awk '{print $1}')
    if [[ $kind == binary && $digest != "$expected" ]]; then
      fail "binary $label differs from its exact expected sha256"
    fi
    size=$(wc -c <"$canonical" | tr -d ' ')
    jq -S -c -n --arg label "$label" --arg path "$canonical" --arg sha256 "$digest" --arg expected_sha256 "$expected" --argjson size_bytes "$size" \
      '{label:$label,path:$path,sha256:$sha256,size_bytes:$size_bytes} + (if $expected_sha256 == "" then {} else {expected_sha256:$expected_sha256} end)' >>"$output"
  done
}

record_hashed_entries binary "$binaries_work" "${binary_entries[@]}"
record_hashed_entries config "$configs_work" "${config_entries[@]}"
for entry in "${key_fingerprint_entries[@]}"; do
  label=${entry%%=*}
  fingerprint=${entry#*=}
  [[ $label != "$entry" && $label =~ ^[a-z][a-z0-9_-]{0,31}$ ]] || fail "key fingerprint label is not canonical"
  [[ $fingerprint =~ ^sha256:[0-9a-f]{64}$ ]] || fail "key fingerprint must be a nonsecret sha256 value"
  jq -S -c -n --arg label "$label" --arg fingerprint "$fingerprint" \
    '{label:$label,fingerprint:$fingerprint}' >>"$fingerprints_work"
done

case_ids=(
  control-startup-schema
  node-registration-full-inventory
  cat-create-running
  durable-write-flush
  route-http-ws
  agent-restart-adoption
  usage-final-terminal-receipt
  delete-cleanup
)
case_deadlines=(120 180 600 300 300 600 300 600)
case_postconditions=(
  'exact schema starts and rejects every other schema'
  'current AgentSession owns one complete full-inventory attestation with gates Closed'
  'production Desired converges through the physical executor to stable Running'
  'Guest write and successful FLUSH reach the selected durability postcondition'
  'HTTP and WebSocket traverse Gateway, Control resolve, Node guard and Guest'
  'Agent restart adopts exact runtime and retained pending data without gate resurrection'
  'Final usage is durably archived, projected and acknowledged before teardown'
  'delete reaches exact physical cleanup with no residue or writer'
)

for index in "${!case_ids[@]}"; do
  jq -S -c -n \
    --arg case_id "${case_ids[$index]}" \
    --argjson deadline_seconds "${case_deadlines[$index]}" \
    --arg expected_postcondition "${case_postconditions[$index]}" \
    '{case_id:$case_id,deadline_seconds:$deadline_seconds,expected_postcondition:$expected_postcondition,cleanup_required:true}' \
    >>"$catalog_work"
done

started_at_unix_seconds=$(date +%s)
host_kernel=$(uname -r)
[[ $host_kernel =~ ^[A-Za-z0-9][A-Za-z0-9._+:-]{0,127}$ ]] || fail "Host kernel release is not a bounded nonsecret string"
build_receipt_sha256=$(sha256sum "$build_receipt" | awk '{print $1}')
release_manifest_sha256=$(sha256sum "$release_manifest" | awk '{print $1}')
scenario_driver_sha256=$(sha256sum "$scenario_driver" | awk '{print $1}')
scenario_catalog_sha256=$(sha256sum "$catalog_work" | awk '{print $1}')

write_manifest() {
  local state=$1 exit_value=$2 ended=$3 temporary
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
    --arg scenario_driver "$scenario_driver" \
    --arg scenario_driver_sha256 "$scenario_driver_sha256" \
    --arg scenario_catalog_sha256 "$scenario_catalog_sha256" \
    --argjson started_at_unix_seconds "$started_at_unix_seconds" \
    --argjson ended_at_unix_seconds "$ended" \
    --argjson exit_code "$exit_value" \
    --slurpfile binaries "$binaries_work" \
    --slurpfile configs "$configs_work" \
    --slurpfile key_fingerprints "$fingerprints_work" \
    --slurpfile scenarios "$catalog_work" \
    '{version:1,state:$state,exact_commit:$exact_commit,block_path:$block_path,run_id:$run_id,schema_version:$schema_version,kernels:{host:$host_kernel,guest:$guest_kernel},build_receipt:{path:$build_receipt,sha256:$build_receipt_sha256},release_manifest:{path:$release_manifest,sha256:$release_manifest_sha256},scenario_driver:{path:$scenario_driver,sha256:$scenario_driver_sha256},scenario_catalog_sha256:$scenario_catalog_sha256,binaries:$binaries,configs:$configs,key_fingerprints:$key_fingerprints,scenarios:$scenarios,started_at_unix_seconds:$started_at_unix_seconds,ended_at_unix_seconds:$ended_at_unix_seconds,exit_code:$exit_code}' \
    >"$temporary"
  chmod 0600 "$temporary"
  mv -f "$temporary" "$output_dir/manifest.json"
}

write_manifest running -1 0
atomic_copy "$results_work" scenario-results.jsonl
atomic_copy "$journal_work" component-journal-summary.txt

export CATS_E3_EXACT_COMMIT=$exact_commit
export CATS_E3_BLOCK_PATH=$block_path
export CATS_E3_RUN_ID=$run_id
export CATS_E3_OUTPUT_DIR=$output_dir

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

failed_cases=0
for index in "${!case_ids[@]}"; do
  case_id=${case_ids[$index]}
  deadline=${case_deadlines[$index]}
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

  case_ended=$(date +%s)
  status=passed
  if [[ $run_code -ne 0 || $cleanup_code -ne 0 ]]; then
    status=failed
    failed_cases=$((failed_cases + 1))
  fi
  if [[ $run_code -eq 124 ]]; then
    status=timed_out
  fi
  jq -S -c -n \
    --arg case_id "$case_id" \
    --arg status "$status" \
    --arg expected_postcondition "${case_postconditions[$index]}" \
    --argjson deadline_seconds "$deadline" \
    --argjson started_at_unix_seconds "$case_started" \
    --argjson ended_at_unix_seconds "$case_ended" \
    --argjson run_exit_code "$run_code" \
    --argjson diagnostic_exit_code "$diagnostic_code" \
    --argjson cleanup_exit_code "$cleanup_code" \
    '{case_id:$case_id,status:$status,deadline_seconds:$deadline_seconds,expected_postcondition:$expected_postcondition,started_at_unix_seconds:$started_at_unix_seconds,ended_at_unix_seconds:$ended_at_unix_seconds,run_exit_code:$run_exit_code,diagnostic_exit_code:$diagnostic_exit_code,cleanup_exit_code:$cleanup_exit_code}' \
    >>"$results_work"
  atomic_copy "$results_work" scenario-results.jsonl
done

inventory_work=$scratch/final-inventory.json
set +e
"$timeout_bin" --signal=TERM --kill-after=5 60 \
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

final_exit=0
final_state=passed
if [[ $failed_cases -ne 0 ]]; then
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
    exit-code \
    final-inventory.json \
    manifest.json \
    scenario-results.jsonl
) >"$checksums_tmp"
chmod 0600 "$checksums_tmp"
mv -f "$checksums_tmp" "$output_dir/SHA256SUMS"

exit "$final_exit"
