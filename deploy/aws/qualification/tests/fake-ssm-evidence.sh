#!/usr/bin/env bash
set -euo pipefail
journal=${Q124_SSM_EVIDENCE_JOURNAL:?}
case ${1:-} in
  publish-intent)
    [[ ${Q124_SSM_EVIDENCE_FAIL:-0} != 1 ]] || exit 1
    jq -cn --arg instance "$2" --arg nonce "$3" --arg mode "$4" --arg manifest "$5" --argjson delivery "$6" --argjson not_after "$7" \
      '{kind:"intent",instance_id:$instance,nonce:$nonce,mode:$mode,manifest_sha256:$manifest,delivery_deadline_epoch:$delivery,not_after_epoch:$not_after}' >>"$journal"
    ;;
  publish-command)
    [[ ${Q124_SSM_COMMAND_EVIDENCE_FAIL:-0} != 1 ]] || exit 1
    jq -cn --arg instance "$2" --arg command "$3" --arg mode "$4" --arg manifest "$5" --arg nonce "$6" \
      '{kind:"command",instance_id:$instance,command_id:$command,nonce:$nonce,mode:$mode,manifest_sha256:$manifest}' >>"$journal"
    ;;
  list)
    [[ -f $journal ]] && cat "$journal"
    ;;
  *) exit 2 ;;
esac
