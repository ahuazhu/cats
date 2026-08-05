#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == --region && ${2:-} == "$Q124_REGION" ]] || exit 2
printf 'outer-aws %s\n' "$*" >>"$Q124_BOOTSTRAP_AWS_LOG"
shift 2
[[ ${1:-} == ssm ]] || exit 3
action=${2:-}
case $action in
  send-command)
    shift 2
    parameters=
    while (($#)); do
      if [[ $1 == --parameters ]]; then parameters=${2#file://}; break; fi
      shift
    done
    [[ -f $parameters ]] || exit 4
    "$Q124_REAL_JQ" -er '.commands | select(length == 1) | .[0]' "$parameters" >"$Q124_CAPTURED_COMMAND"
    set +e
    env PATH="$Q124_SSM_REMOTE_PATH" bash "$Q124_CAPTURED_COMMAND" >"$Q124_SSM_STDOUT" 2>"$Q124_SSM_STDERR"
    rc=$?
    set -e
    printf '%s\n' "$rc" >"$Q124_SSM_RC"
    printf '0124abcd-0000-0000-0000-000000000124\n'
    ;;
  wait) exit 0 ;;
  get-command-invocation)
    rc=$(<"$Q124_SSM_RC")
    "$Q124_REAL_JQ" -n --argjson rc "$rc" \
      --rawfile stdout "$Q124_SSM_STDOUT" --rawfile stderr "$Q124_SSM_STDERR" \
      '{Status:(if $rc == 0 then "Success" else "Failed" end),StatusDetails:(if $rc == 0 then "Success" else "Failed" end),ResponseCode:$rc,StandardOutputContent:$stdout,StandardErrorContent:$stderr}'
    ;;
  *) exit 5 ;;
esac
