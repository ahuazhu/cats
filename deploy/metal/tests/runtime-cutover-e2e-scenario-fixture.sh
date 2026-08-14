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
    if [[ ${CATS_E3_FIXTURE_SENSITIVE_RECEIPT_CASE:-} == "$case_id" ]]; then
      printf '%s\n' '{"agent_session":"must-be-rejected"}' >"$case_dir/sensitive-receipt.json"
    else
      jq -S -c -n --arg case_id "$case_id" \
        '{version:1,case_id:$case_id,evidence:"fixture"}' >"$case_dir/fixture-receipt.json"
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
