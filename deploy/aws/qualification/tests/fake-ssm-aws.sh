#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --region && ${2:-} == "$Q124_REGION" ]] || exit 2
printf 'outer-aws %s\n' "$*" >>"$Q124_BOOTSTRAP_AWS_LOG"
shift 2
[[ ${1:-} == ssm ]] || exit 3
action=${2:-}
state=${Q124_SSM_FAKE_STATE:?}
command_id=0124abcd-0000-0000-0000-000000000124

update_state() {
  local filter=$1 next=$state.next
  "$Q124_REAL_JQ" "$filter" "$state" >"$next" && mv "$next" "$state"
}

case $action in
  send-command)
    shift 2
    parameters= timeout=
    args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
      [[ ${args[$i]} == --parameters ]] && parameters=${args[$((i + 1))]#file://}
      [[ ${args[$i]} == --timeout-seconds ]] && timeout=${args[$((i + 1))]}
    done
    [[ -f $parameters ]] || exit 4
    execution=$Q124_SSM_EXECUTION_TIMEOUT_SECONDS
    if [[ $timeout == 60 ]]; then execution=60; else [[ $timeout == "$Q124_SSM_DELIVERY_TIMEOUT_SECONDS" ]] || exit 4; fi
    "$Q124_REAL_JQ" -e --arg execution "$execution" \
      '(.commands | length) == 1 and .executionTimeout == [$execution]' "$parameters" >/dev/null || exit 5
    "$Q124_REAL_JQ" -er '.commands[0]' "$parameters" >"$Q124_CAPTURED_COMMAND"
    rc=0
    if [[ ${Q124_SSM_SKIP_EXECUTE:-0} != 1 ]]; then
      set +e
      env PATH="$Q124_SSM_REMOTE_PATH" bash "$Q124_CAPTURED_COMMAND" >"$Q124_SSM_STDOUT" 2>"$Q124_SSM_STDERR"
      rc=$?
      set -e
    fi
    "$Q124_REAL_JQ" -n --argjson rc "$rc" '{poll:0,cancel_poll:0,cancelled:false,rc:$rc}' >"$state"
    printf '%s\n' "$command_id"
    ;;
  get-command-invocation)
    [[ " $* " == *" --command-id $command_id "* && " $* " == *" --instance-id $Q124_INSTANCE_ID "* ]] || exit 6
    if ! grep -q "$command_id" "$Q124_SSM_EVIDENCE_JOURNAL" &&
       [[ ${Q124_ALLOW_UNJOURNALED_COMMAND:-0} != 1 ]] &&
       ! grep -q 'guard=absent nonce=' "$Q124_CAPTURED_COMMAND"; then
      printf 'command was polled before durable evidence\n' >&2
      exit 9
    fi
    [[ -z ${Q124_SSM_GET_DELAY_SECONDS:-} ]] || sleep "$Q124_SSM_GET_DELAY_SECONDS"
    poll=$("$Q124_REAL_JQ" -r '.poll' "$state")
    if (( poll < ${Q124_SSM_NOT_FOUND_POLLS:-0} )); then
      update_state '.poll += 1'
      printf 'InvocationDoesNotExist\n' >&2
      exit 255
    fi
    [[ ${Q124_SSM_LOOKUP_ERROR:-0} != 1 ]] || { printf 'AccessDenied\n' >&2; exit 255; }
    if [[ $("$Q124_REAL_JQ" -r '.cancelled' "$state") == true ]]; then
      cancel_poll=$("$Q124_REAL_JQ" -r '.cancel_poll' "$state")
      status=Cancelling
      (( cancel_poll >= ${Q124_SSM_CANCEL_PENDING_POLLS:-1} )) && status=Cancelled
      update_state '.cancel_poll += 1'
    else
      sequence=${Q124_SSM_STATUS_SEQUENCE:-Pending,InProgress,RESULT}
      IFS=, read -r -a statuses <<<"$sequence"
      index=$((poll - ${Q124_SSM_NOT_FOUND_POLLS:-0}))
      (( index < ${#statuses[@]} )) || index=$((${#statuses[@]} - 1))
      status=${statuses[$index]}
      update_state '.poll += 1'
      if [[ $status == RESULT ]]; then
        rc=$("$Q124_REAL_JQ" -r '.rc' "$state")
        if (( rc == 0 )); then status=Success; else status=Failed; fi
      fi
    fi
    rc=$("$Q124_REAL_JQ" -r '.rc' "$state")
    "$Q124_REAL_JQ" -n --arg status "$status" --argjson rc "$rc" \
      --rawfile stdout "$Q124_SSM_STDOUT" --rawfile stderr "$Q124_SSM_STDERR" \
      '{Status:$status,StatusDetails:$status,ResponseCode:$rc,StandardOutputContent:$stdout,StandardErrorContent:$stderr}'
    ;;
  cancel-command)
    [[ " $* " == *" --command-id $command_id "* && " $* " == *" --instance-ids $Q124_INSTANCE_ID "* ]] || exit 7
    update_state '.cancelled = true'
    printf '{"Command":{"CommandId":"%s"}}\n' "$command_id"
    ;;
  *) exit 8 ;;
esac
