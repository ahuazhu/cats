#!/usr/bin/env bash
set -euo pipefail
store=${Q124_LAUNCH_EVIDENCE_STORE:?}
[[ ${1:-} == api ]]
shift
if [[ ${1:-} == --paginate ]]; then
  cat "$store"
  exit 0
fi
body=
while (($#)); do
  if [[ $1 == -f && ${2:-} == body=* ]]; then body=${2#body=}; shift 2; else shift; fi
done
[[ -n $body ]]
next=$store.next
jq --arg body "$body" '. + [{body:$body}]' "$store" >"$next" && mv "$next" "$store"
