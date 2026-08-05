#!/usr/bin/env bash
set -euo pipefail

if (( $# != 3 )); then
  echo "usage: $0 <kubeconfig> <namespace> <pod-name>" >&2
  exit 64
fi

kubeconfig=$1
namespace=$2
probe=$3
kubectl_args=(
  --kubeconfig "$kubeconfig"
  --namespace "$namespace"
)

cleanup() {
  kubectl "${kubectl_args[@]}" \
    delete pod "$probe" --ignore-not-found --wait=false \
    >/dev/null 2>&1 || true
}
trap cleanup EXIT

# A previous attempt with the same run ID must not turn creation failure into
# an ambiguous database result. The name is unique per workflow attempt, but
# deleting first also makes a manually rerun step deterministic.
kubectl "${kubectl_args[@]}" \
  delete pod "$probe" --ignore-not-found \
  >/dev/null 2>&1 || true

set +e
create_output="$(
  kubectl "${kubectl_args[@]}" \
    run "$probe" \
    --restart=Never \
    --image=postgres:16 \
    --overrides='{
      "spec": {
        "containers": [{
          "name": "psql",
          "image": "postgres:16",
          "command": ["sh", "-c",
            "psql \"$CATS_POSTGRES_URL\" -v ON_ERROR_STOP=1 -tA -c \"SELECT version FROM control_schema_version\" 2>&1"],
          "envFrom": [{"secretRef": {"name": "cats-runtime"}}]
        }]
      }
    }' 2>&1
)"
create_status=$?
set -e
if (( create_status != 0 )); then
  printf '%s\n' "$create_output"
  exit "$create_status"
fi

# Do not use `kubectl run --attach`: if its initial attach races container
# creation, kubectl falls back to streaming logs and can replay the same output.
# Waiting for a terminal Pod and reading its logs exactly once preserves the
# distinction between one schema row and duplicate/corrupt rows.
deadline=$((SECONDS + 180))
phase=""
while :; do
  set +e
  phase_output="$(
    kubectl "${kubectl_args[@]}" \
      get pod "$probe" --output=jsonpath='{.status.phase}' 2>&1
  )"
  phase_status=$?
  set -e
  if (( phase_status != 0 )); then
    printf '%s\n' "$phase_output"
    exit "$phase_status"
  fi

  phase=$phase_output
  case "$phase" in
    Succeeded | Failed)
      break
      ;;
  esac
  if (( SECONDS >= deadline )); then
    echo "schema probe Pod did not terminate within 180 seconds (phase: ${phase:-unknown})"
    exit 124
  fi
  sleep 2
done

set +e
query_output="$(
  kubectl "${kubectl_args[@]}" \
    logs "$probe" --container=psql 2>&1
)"
logs_status=$?
exit_code_output="$(
  kubectl "${kubectl_args[@]}" \
    get pod "$probe" \
    --output=jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' \
    2>&1
)"
exit_code_status=$?
set -e

if (( logs_status != 0 )); then
  printf '%s\n' "$query_output"
  exit "$logs_status"
fi
if (( exit_code_status != 0 )); then
  printf '%s\n' "$exit_code_output"
  exit "$exit_code_status"
fi
if [[ ! "$exit_code_output" =~ ^[0-9]+$ ]] || (( exit_code_output > 255 )); then
  echo "schema probe Pod reached $phase without a valid container exit code: $exit_code_output"
  exit 1
fi

printf '%s\n' "$query_output"
exit "$exit_code_output"
