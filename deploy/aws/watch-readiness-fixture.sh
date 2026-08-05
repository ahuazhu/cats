#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 2 || "$1" != "--waiter" ]]; then
  echo "usage: $0 --waiter PATH" >&2
  exit 2
fi
waiter="$2"
if [[ ! -x "$waiter" ]]; then
  echo "waiter is not executable: $waiter" >&2
  exit 2
fi

fixture_dir="$(mktemp -d "${TMPDIR:-/tmp}/cats-watch-readiness.XXXXXX")"
fixture_pids=()
stop_fixture_processes() {
  local pid
  for pid in "${fixture_pids[@]}"; do
    if kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${fixture_pids[@]}"; do
    wait "$pid" 2>/dev/null || true
  done
  fixture_pids=()
}
cleanup_fixture() {
  stop_fixture_processes
  rm -rf -- "$fixture_dir"
}
trap cleanup_fixture EXIT

pods="$fixture_dir/pods.jsonl"
endpoints="$fixture_dir/endpoints.jsonl"
(
  sleep 0.2
  printf '%s\n' '{"type":"ADDED","object":{"kind":"Pod"}}' > "$pods"
  sleep 2
) &
pods_pid=$!
fixture_pids+=("$pods_pid")
(
  sleep 0.4
  printf '%s\n' '{"type":"ADDED","object":{"kind":"EndpointSlice"}}' > "$endpoints"
  sleep 2
) &
endpoints_pid=$!
fixture_pids+=("$endpoints_pid")
"$waiter" 2 "$pods_pid" "$pods" "$endpoints_pid" "$endpoints"
echo "delayed streams: ready"
stop_fixture_processes

dead_path="$fixture_dir/dead.jsonl"
silent_path="$fixture_dir/silent.jsonl"
(
  exit 0
) &
dead_pid=$!
wait "$dead_pid"
(
  sleep 3
) &
silent_pid=$!
fixture_pids+=("$silent_pid")
if "$waiter" 2 "$dead_pid" "$dead_path" "$silent_pid" "$silent_path" \
  > "$fixture_dir/early.stdout" 2> "$fixture_dir/early.stderr"
then
  echo "an exited watcher was accepted" >&2
  exit 1
fi
if [[ "$(<"$fixture_dir/early.stderr")" != *"exited before"* ]]; then
  echo "early-exit diagnostic is missing" >&2
  exit 1
fi
echo "early watcher exit: rejected"
stop_fixture_processes

(
  sleep 3
) &
pods_pid=$!
fixture_pids+=("$pods_pid")
(
  sleep 3
) &
endpoints_pid=$!
fixture_pids+=("$endpoints_pid")
if "$waiter" 1 "$pods_pid" "$pods.silent" "$endpoints_pid" "$endpoints.silent" \
  > "$fixture_dir/timeout.stdout" 2> "$fixture_dir/timeout.stderr"
then
  echo "silent watchers bypassed the readiness timeout" >&2
  exit 1
fi
if [[ "$(<"$fixture_dir/timeout.stderr")" != *"produced no initial event within 1s"* ]]; then
  echo "timeout diagnostic is missing" >&2
  exit 1
fi
for pid in "$pods_pid" "$endpoints_pid"; do
  if ! kill -0 "$pid" 2>/dev/null; then
    echo "waiter terminated a live watcher on timeout" >&2
    exit 1
  fi
done
echo "silent watcher timeout: rejected"
