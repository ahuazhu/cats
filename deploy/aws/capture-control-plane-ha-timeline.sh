#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <kubeconfig> <evidence-dir> <maximum-seconds>" >&2
  exit 64
fi

kubeconfig=$1
evidence_dir=$2
maximum_seconds=$3
positive_integer='^[1-9][0-9]*$'
[[ -f "$kubeconfig" ]] || {
  echo "kubeconfig does not exist" >&2
  exit 66
}
[[ "$maximum_seconds" =~ $positive_integer ]] && (( maximum_seconds <= 300 )) || {
  echo "maximum-seconds must be an integer between 1 and 300" >&2
  exit 65
}
command -v kubectl >/dev/null 2>&1 || {
  echo "kubectl is required" >&2
  exit 69
}
command -v jq >/dev/null 2>&1 || {
  echo "jq is required" >&2
  exit 69
}

mkdir -p "$evidence_dir"
pods_evidence="$evidence_dir/kubernetes-pods.ndjson"
slices_evidence="$evidence_dir/kubernetes-endpointslices.ndjson"
ready_file="$evidence_dir/kubernetes-timeline.ready"
pods_pipe="$evidence_dir/.pods-watch.pipe"
slices_pipe="$evidence_dir/.endpointslices-watch.pipe"
for path in "$pods_evidence" "$slices_evidence" "$ready_file" "$pods_pipe" "$slices_pipe"; do
  [[ ! -e "$path" ]] || {
    echo "refusing to mix Kubernetes timeline evidence with existing path: $path" >&2
    exit 73
  }
done

kube=(
  kubectl
  --kubeconfig "$kubeconfig"
  --namespace cats
  --request-timeout="${maximum_seconds}s"
)
pod_selector='app.kubernetes.io/name=cats-controld'
slice_selector='kubernetes.io/service-name=cats-controld'
pods_filter='def pod_record($event): {
  captured_at: (now | todateiso8601),
  resource: "Pod",
  event_type: $event,
  name: .metadata.name,
  uid: .metadata.uid,
  resource_version: .metadata.resourceVersion,
  deletion_timestamp: .metadata.deletionTimestamp,
  phase: .status.phase,
  pod_ip: .status.podIP,
  host_ip: .status.hostIP,
  node: .spec.nodeName,
  conditions: [(.status.conditions // [])[] | {
    type, status, reason, last_transition_time: .lastTransitionTime
  }],
  containers: [(.status.containerStatuses // [])[] | {
    name, ready, restart_count: .restartCount,
    state: ((.state // {}) | keys | first)
  }]
};'
slices_filter='def slice_record($event): {
  captured_at: (now | todateiso8601),
  resource: "EndpointSlice",
  event_type: $event,
  name: .metadata.name,
  uid: .metadata.uid,
  resource_version: .metadata.resourceVersion,
  deletion_timestamp: .metadata.deletionTimestamp,
  address_type: .addressType,
  endpoints: [(.endpoints // [])[] | {
    addresses,
    conditions,
    target_name: .targetRef.name,
    target_uid: .targetRef.uid,
    node: .nodeName,
    zone
  }]
};'

# Calibrate both read-only selectors before trusting a quiet watch. The HA
# precondition already requires two Ready Pods; an empty result here means the
# collector is broken or looking at the wrong resource, not that nothing
# happened during the disruption.
pods_initial="$("${kube[@]}" get pods --selector "$pod_selector" --output=json)"
jq -e '(.items | length) >= 2' <<<"$pods_initial" >/dev/null || {
  echo "the control-plane Pod selector did not return the redundant deployment" >&2
  exit 1
}
slices_initial="$("${kube[@]}" get endpointslices --selector "$slice_selector" --output=json)"
jq -e '(.items | length) >= 1 and ([.items[].endpoints[]?] | length) >= 2' \
  <<<"$slices_initial" >/dev/null || {
  echo "the control-plane EndpointSlice selector did not return two endpoints" >&2
  exit 1
}

jq -c "$pods_filter .items[] | pod_record(\"INITIAL\")" \
  <<<"$pods_initial" >"$pods_evidence"
jq -c "$slices_filter .items[] | slice_record(\"INITIAL\")" \
  <<<"$slices_initial" >"$slices_evidence"
unset pods_initial slices_initial

mkfifo "$pods_pipe" "$slices_pipe"
child_pids=()
cleaned=0

bound_evidence() {
  local file=$1
  local resource=$2
  local lines
  local bounded
  lines=$(wc -l <"$file" | tr -d ' ')
  (( lines <= 2000 )) && return 0
  bounded="$file.bounded"
  sed -n '1,2000p' "$file" >"$bounded"
  jq -cn --arg resource "$resource" --argjson omitted "$((lines - 2000))" \
    '{captured_at:(now|todateiso8601), resource:$resource, event_type:"TRUNCATED", omitted_events:$omitted}' \
    >>"$bounded"
  mv "$bounded" "$file"
}

cleanup() {
  local pid
  (( cleaned == 0 )) || return 0
  cleaned=1
  for pid in "${child_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${child_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  rm -f "$pods_pipe" "$slices_pipe" "$ready_file"
  bound_evidence "$pods_evidence" Pod
  bound_evidence "$slices_evidence" EndpointSlice
}

stop_cleanly() {
  cleanup
  exit 0
}
trap cleanup EXIT
trap stop_cleanly TERM INT

"${kube[@]}" get pods \
  --selector "$pod_selector" \
  --watch-only --output-watch-events \
  --output=json >"$pods_pipe" &
child_pids+=("$!")
jq --unbuffered -c "$pods_filter . as \$watch | .object | pod_record(\$watch.type)" \
  <"$pods_pipe" >>"$pods_evidence" &
pods_jq_pid=$!
child_pids+=("$pods_jq_pid")

"${kube[@]}" get endpointslices \
  --selector "$slice_selector" \
  --watch-only --output-watch-events \
  --output=json >"$slices_pipe" &
child_pids+=("$!")
jq --unbuffered -c "$slices_filter . as \$watch | .object | slice_record(\$watch.type)" \
  <"$slices_pipe" >>"$slices_evidence" &
slices_jq_pid=$!
child_pids+=("$slices_jq_pid")

for pid in "${child_pids[@]}"; do
  kill -0 "$pid" 2>/dev/null || {
    echo "Kubernetes timeline watcher exited before becoming ready" >&2
    exit 1
  }
done
printf 'ready_at=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >"$ready_file"

# A watcher exiting before the orchestrator asks us to stop is evidence loss.
# Polling also lets TERM run promptly while avoiding an uninterruptible wait on
# one child. The API request timeout provides a second, independent bound.
while :; do
  for pid in "${child_pids[@]}"; do
    if ! kill -0 "$pid" 2>/dev/null; then
      wait "$pid" 2>/dev/null || true
      echo "Kubernetes timeline watcher ended before disruption evidence collection stopped" >&2
      exit 1
    fi
  done
  sleep 0.1
done
