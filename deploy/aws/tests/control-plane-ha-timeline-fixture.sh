#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
capture="$repo_root/deploy/aws/capture-control-plane-ha-timeline.sh"
fake_kubectl="$repo_root/deploy/aws/tests/fake-timeline-kubectl.sh"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/cats-ha-timeline-fixture.XXXXXX")
capture_pid=""

cleanup() {
  if [[ -n "$capture_pid" ]] && kill -0 "$capture_pid" 2>/dev/null; then
    kill "$capture_pid" 2>/dev/null || true
    wait "$capture_pid" 2>/dev/null || true
  fi
  rm -r "$fixture_root"
}
trap cleanup EXIT

mkdir -p "$fixture_root/bin" "$fixture_root/state/live" "$fixture_root/evidence"
ln -s "$fake_kubectl" "$fixture_root/bin/kubectl"
: >"$fixture_root/kubeconfig"

FAKE_KUBECTL_STATE="$fixture_root/state" \
PATH="$fixture_root/bin:$PATH" \
  "$capture" "$fixture_root/kubeconfig" "$fixture_root/evidence" 10 \
  >"$fixture_root/stdout" 2>"$fixture_root/stderr" &
capture_pid=$!

for _ in $(seq 1 100); do
  [[ -s "$fixture_root/evidence/kubernetes-timeline.ready" ]] && break
  kill -0 "$capture_pid" 2>/dev/null || {
    echo "timeline collector exited before readiness" >&2
    sed -n '1,80p' "$fixture_root/stderr" >&2
    exit 1
  }
  sleep 0.02
done
[[ -s "$fixture_root/evidence/kubernetes-timeline.ready" ]] || {
  echo "timeline collector never became ready" >&2
  exit 1
}

sleep 0.1
kill "$capture_pid"
wait "$capture_pid"
capture_pid=""

for file in \
  "$fixture_root/evidence/kubernetes-pods.ndjson" \
  "$fixture_root/evidence/kubernetes-endpointslices.ndjson"
do
  [[ -s "$file" ]] || {
    echo "timeline evidence file is empty: $file" >&2
    exit 1
  }
  jq -e . "$file" >/dev/null
  grep -Fq '"event_type":"INITIAL"' "$file"
  grep -Fq '"event_type":"MODIFIED"' "$file"
  if grep -Fq 'MUST_NOT_ESCAPE' "$file"; then
    echo "unsanitized Kubernetes object field escaped into evidence" >&2
    exit 1
  fi
done

if compgen -G "$fixture_root/state/live/*" >/dev/null; then
  echo "fake kubectl process leaked after collector shutdown" >&2
  exit 1
fi
if compgen -G "$fixture_root/evidence/.*.pipe" >/dev/null; then
  echo "timeline collector FIFO leaked after shutdown" >&2
  exit 1
fi

echo "control-plane HA Kubernetes timeline fixture passed"
