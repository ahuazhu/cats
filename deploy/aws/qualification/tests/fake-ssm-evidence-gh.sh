#!/usr/bin/env bash
set -euo pipefail
store=${Q124_SSM_GH_STORE:?}
[[ ${1:-} == api ]] || exit 2
if [[ ${2:-} == "repos/${GITHUB_REPOSITORY}/issues/124/comments" ]]; then
  [[ ${3:-} == -f && ${4:-} == body=* ]] || exit 3
  body=${4#body=}
  jq -n --arg body "$body" '{body:$body}' >>"$store"
  printf '{"id":124}\n'
elif [[ ${2:-} == --paginate && ${3:-} == "repos/${GITHUB_REPOSITORY}/issues/124/comments?per_page=100" && ${4:-} == --slurp ]]; then
  if [[ ${Q124_SSM_GH_MALFORMED:-0} == 1 ]]; then
    printf '%s\n' '[[{"body":"<!-- cats-q124-ssm-command:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa:bad -->\nq124-ssm-command-base64: %%%"}]]'
  else
    jq -s '[.]' "$store"
  fi
else
  exit 4
fi
