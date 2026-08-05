#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <namespace> <pod-name> <pod-uid>" >&2
  exit 64
fi

namespace=$1
pod_name=$2
pod_uid=$3
dns_label='^[a-z0-9]([-a-z0-9]*[a-z0-9])?$'
uid_pattern='^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$'

[[ "$namespace" == "cats" ]] || {
  echo "refusing to evict outside the cats namespace" >&2
  exit 65
}
[[ ${#pod_name} -le 63 && "$pod_name" =~ $dns_label ]] || {
  echo "invalid Pod name" >&2
  exit 65
}
[[ "$pod_uid" =~ $uid_pattern ]] || {
  echo "invalid Pod UID" >&2
  exit 65
}

eviction="$(
  jq -cn --arg namespace "$namespace" --arg name "$pod_name" --arg uid "$pod_uid" '
    {
      apiVersion: "policy/v1",
      kind: "Eviction",
      metadata: {namespace: $namespace, name: $name},
      deleteOptions: {
        propagationPolicy: "Background",
        preconditions: {uid: $uid}
      }
    }
  '
)"

# The API server atomically checks both the PDB admission policy and this UID
# precondition. A same-name replacement cannot be evicted after the caller's
# GET, and a concurrent disruption cannot bypass the PDB checked above.
printf '%s\n' "$eviction" |
  kubectl --namespace "$namespace" create \
    --raw "/api/v1/namespaces/${namespace}/pods/${pod_name}/eviction" \
    --filename - >/dev/null
printf 'evicted pod/%s with UID precondition\n' "$pod_name"
