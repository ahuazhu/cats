#!/usr/bin/env bash
set -euo pipefail

: "${FAKE_CURL_STATE:?FAKE_CURL_STATE is required}"
attempt=${CATS_FAKE_PROBE_ATTEMPT:-0}
header_file=""
delay_ms=${FAKE_CURL_DELAY_MS:-10}
exit_code=0
http_code=200

while (( $# > 0 )); do
  case "$1" in
    --dump-header)
      header_file=$2
      shift 2
      ;;
    --write-out | --output | --connect-timeout | --max-time)
      shift 2
      ;;
    --fail | --silent)
      shift
      ;;
    https://cats.run/healthz)
      shift
      ;;
    *)
      echo "fake curl received an unexpected argument: $1" >&2
      exit 64
      ;;
  esac
done

mkdir -p "$FAKE_CURL_STATE/live"
lock="$FAKE_CURL_STATE/lock"
while ! mkdir "$lock" 2>/dev/null; do
  sleep 0.001
done
active=$(<"$FAKE_CURL_STATE/active")
active=$((active + 1))
echo "$active" >"$FAKE_CURL_STATE/active"
maximum=$(<"$FAKE_CURL_STATE/max_active")
if (( active > maximum )); then
  echo "$active" >"$FAKE_CURL_STATE/max_active"
fi
rm -r "$lock"

live_marker="$FAKE_CURL_STATE/live/$BASHPID"
: >"$live_marker"
started_ms=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
printf '%s\t%s\t%s\n' "$attempt" "$BASHPID" "$started_ms" >>"$FAKE_CURL_STATE/starts.tsv"

cleanup() {
  ended_ms=$(python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)')
  printf '%s\t%s\t%s\n' "$attempt" "$BASHPID" "$ended_ms" >>"$FAKE_CURL_STATE/ends.tsv"
  rm -f "$live_marker"
  while ! mkdir "$lock" 2>/dev/null; do
    sleep 0.001
  done
  active=$(<"$FAKE_CURL_STATE/active")
  echo "$((active - 1))" >"$FAKE_CURL_STATE/active"
  rm -r "$lock"
}
trap cleanup EXIT

if [[ ${FAKE_CURL_SLOW_ATTEMPT:-} == "$attempt" ]]; then
  delay_ms=${FAKE_CURL_SLOW_MS:-300}
  exit_code=28
  http_code=000
fi
if [[ -n ${FAKE_CURL_HANG_MS:-} ]]; then
  delay_ms=$FAKE_CURL_HANG_MS
  exit_code=28
  http_code=000
fi

python3 -c 'import sys, time; time.sleep(int(sys.argv[1]) / 1000)' "$delay_ms"
if [[ -n "$header_file" ]]; then
  printf 'HTTP/1.1 %s Fake\r\nServer: awselb/2.0\r\nX-Amzn-Trace-Id: Root=fake-%s\r\nSet-Cookie: must-not-escape=yes\r\n\r\n' \
    "$http_code" "$attempt" >"$header_file"
fi
printf '%s|192.0.2.10|0.001|0.002|0.010' "$http_code"
exit "$exit_code"
