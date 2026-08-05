#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 TIMEOUT_SECONDS PID PATH [PID PATH ...]" >&2
  exit 2
}

if (( $# < 3 || ($# - 1) % 2 != 0 )); then
  usage
fi

timeout_seconds="$1"
shift
if [[ ! "$timeout_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "timeout must be a positive integer number of seconds" >&2
  exit 2
fi

pairs=("$@")
stream_count=$(( ${#pairs[@]} / 2 ))
for ((index = 0; index < ${#pairs[@]}; index += 2)); do
  pid="${pairs[index]}"
  path="${pairs[index + 1]}"
  if [[ ! "$pid" =~ ^[1-9][0-9]*$ || -z "$path" ]]; then
    echo "each evidence stream requires a numeric PID and non-empty path" >&2
    exit 2
  fi
done

deadline=$((SECONDS + timeout_seconds))
while true; do
  ready_count=0
  for ((index = 0; index < ${#pairs[@]}; index += 2)); do
    pid="${pairs[index]}"
    path="${pairs[index + 1]}"
    if ! kill -0 "$pid" 2>/dev/null; then
      echo "evidence stream process $pid exited before $(basename "$path") became ready" >&2
      exit 1
    fi
    if [[ -s "$path" ]]; then
      ready_count=$((ready_count + 1))
    fi
  done

  if (( ready_count == stream_count )); then
    exit 0
  fi
  if (( SECONDS >= deadline )); then
    for ((index = 0; index < ${#pairs[@]}; index += 2)); do
      path="${pairs[index + 1]}"
      if [[ ! -s "$path" ]]; then
        echo "evidence stream $(basename "$path") produced no initial event within ${timeout_seconds}s" >&2
      fi
    done
    exit 1
  fi
  sleep 0.1
done
