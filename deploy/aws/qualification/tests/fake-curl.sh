#!/usr/bin/env bash
set -euo pipefail
output= method=GET url=
args=("$@")
while (($#)); do
  case $1 in
    --output) output=$2; shift 2 ;;
    --request) method=$2; shift 2 ;;
    http*) url=$1; shift ;;
    *) shift ;;
  esac
done
printf '%s\n' "${args[*]}" >>"$Q124_CURL_LOG"
[[ -n $output && -n $url ]] || exit 2
path=${url#https://$Q124_CONTROL_AUTHORITY}
status=200
body='{}'
case "$method $path" in
  'GET /v1/admin/nodes/metal-source')
    body='{"node":{"id":"metal-source","state":"ready"},"assigned_cats":0,"orphan_cats":0}'
    ;;
  'GET /v1/admin/nodes/q124-node')
    if [[ -e $Q124_CONTROL_FAKE_STATE ]]; then
      status=404
    elif [[ ${Q124_CONTROL_SCENARIO:-lost} == nonempty ]]; then
      body='{"node":{"id":"q124-node","state":"cordoned"},"assigned_cats":1,"orphan_cats":0}'
    else
      body='{"node":{"id":"q124-node","state":"lost"},"assigned_cats":0,"orphan_cats":0}'
    fi
    ;;
  'GET /v1/admin/nodes/q124-node/cats')
    if [[ ${Q124_CONTROL_SCENARIO:-lost} == wrong-scope ]]; then
      body='{"items":[{"cat":{"id":"cat-1","node_id":"q124-node","workspace_id":"ws-other","name":"other"}}]}'
    else
      body='{"items":[]}'
    fi
    ;;
  'DELETE /v1/admin/nodes/q124-node')
    : >"$Q124_CONTROL_FAKE_STATE"
    [[ ${Q124_CONTROL_SCENARIO:-lost} == delete-race ]] && status=404 || status=204
    ;;
  *) status=404 ;;
esac
printf '%s\n' "$body" >"$output"
printf '%s' "$status"
