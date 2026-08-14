#!/usr/bin/env bash
set -euo pipefail

[[ ${CATS_E3_FIXTURE_MODE:-} == enabled ]] || {
  echo "the runtime cutover scenario fixture is test-only" >&2
  exit 64
}

action=${1:?missing fixture action}
case_id=${2:-none}
block_path=${3:-none}
case_dir=${4:-none}
trace=${CATS_E3_FIXTURE_TRACE:?missing fixture trace}
catalog=${CATS_E3_FIXTURE_CATALOG:?missing fixture qualification catalog}

write_catalog_evidence() {
  local scope=$1 filename kind sensitive_written=false
  while IFS=$'\t' read -r filename kind; do
    [[ -n $filename && -n $kind ]] || continue
    if [[ $kind == json ]]; then
      if [[ $scope == case && ${CATS_E3_FIXTURE_SENSITIVE_RECEIPT_CASE:-} == "$case_id" \
        && $sensitive_written == false ]]; then
        printf '%s\n' '{"agent_session":"must-be-rejected"}' >"$case_dir/$filename"
        sensitive_written=true
      else
        jq -S -c -n --arg case_id "$case_id" --arg filename "$filename" \
          '{version:1,case_id:$case_id,evidence:$filename}' >"$case_dir/$filename"
      fi
    elif [[ $kind == text ]]; then
      printf 'fixture evidence for %s: %s\n' "$case_id" "$filename" >"$case_dir/$filename"
    else
      exit 64
    fi
  done < <(
    if [[ $scope == case ]]; then
      jq -r --arg case_id "$case_id" \
        '.cases[] | select(.case_id == $case_id) | .required_evidence[] | [.filename,.kind] | @tsv' \
        "$catalog"
    else
      jq -r '.framework_required_evidence[] | [.filename,.kind] | @tsv' "$catalog"
    fi
  )
}

printf '%s|%s|%s\n' "$action" "$case_id" "$block_path" >>"$trace"

case "$action" in
  run)
    printf 'fixture ran %s through %s\n' "$case_id" "$block_path"
    case ",${CATS_E3_FIXTURE_BLOCK_CASES:-}," in
      *",$case_id,"*)
        jq -S -c -n --arg case_id "$case_id" --arg block_path "$block_path" \
          '{version:1,status:"blocked",case_id:$case_id,block_path:$block_path,reason:"fixture typed block"}' \
          >"$case_dir/blocked-receipt.json"
        exit 78
        ;;
    esac
    write_catalog_evidence case
    if [[ ${CATS_E3_FIXTURE_EXTRA_EVIDENCE_CASE:-} == "$case_id" ]]; then
      jq -S -c -n --arg case_id "$case_id" \
        '{version:1,case_id:$case_id,unexpected:true}' >"$case_dir/extra-receipt.json"
    fi
    if [[ ${CATS_E3_FIXTURE_SECRETS:-false} == true ]]; then
      printf 'Authorization: Bearer fixture-token-must-not-survive\n'
      printf 'password=fixture-password-must-not-survive\n'
      for ((line = 0; line < 3000; line++)); do
        printf 'bounded-safe-diagnostic-%04d\n' "$line"
      done
    fi
    if [[ ${CATS_E3_FIXTURE_FAIL_CASE:-} == "$case_id" ]]; then
      exit 23
    fi
    ;;
  cleanup)
    printf 'fixture cleanup %s\n' "$case_id"
    write_catalog_evidence framework
    ;;
  diagnostics)
    printf 'diagnostic for %s\n' "$case_id"
    printf '%s\n' '-----BEGIN PRIVATE KEY-----'
    printf '%s\n' 'fixture-private-key-must-not-survive'
    printf '%s\n' '-----END PRIVATE KEY-----'
    ;;
  inventory)
    if [[ ${CATS_E3_FIXTURE_SENSITIVE_INVENTORY:-false} == true ]]; then
      printf '%s\n' '{"token":"fixture-token-must-not-survive"}'
    else
      printf '%s\n' '{"complete_inventory":true,"gates":"closed","residue":[],"runtimes":[]}'
    fi
    ;;
  *)
    echo "unknown fixture action: $action" >&2
    exit 64
    ;;
esac
