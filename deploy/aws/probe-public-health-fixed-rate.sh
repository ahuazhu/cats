#!/usr/bin/env bash
set -euo pipefail

if (( $# != 7 )); then
  echo "usage: $0 <url> <attempts> <interval-ms> <max-concurrency> <request-timeout-seconds> <total-timeout-ms> <evidence-dir>" >&2
  exit 64
fi

url=$1
attempts=$2
interval_ms=$3
max_concurrency=$4
request_timeout_seconds=$5
total_timeout_ms=$6
evidence_dir=$7

positive_integer='^[1-9][0-9]*$'
positive_number='^([0-9]+([.][0-9]+)?|[.][0-9]+)$'
[[ "$url" == "https://cats.run/healthz" ]] || {
  echo "refusing to probe any URL except the public Cats health endpoint" >&2
  exit 65
}
[[ "$attempts" =~ $positive_integer ]] || {
  echo "attempts must be a positive integer" >&2
  exit 65
}
[[ "$interval_ms" =~ $positive_integer ]] || {
  echo "interval-ms must be a positive integer" >&2
  exit 65
}
[[ "$max_concurrency" =~ $positive_integer ]] || {
  echo "max-concurrency must be a positive integer" >&2
  exit 65
}
[[ "$request_timeout_seconds" =~ $positive_number ]] || {
  echo "request-timeout-seconds must be positive" >&2
  exit 65
}
[[ "$total_timeout_ms" =~ $positive_integer ]] || {
  echo "total-timeout-ms must be a positive integer" >&2
  exit 65
}
command -v curl >/dev/null 2>&1 || {
  echo "curl is required" >&2
  exit 69
}
command -v python3 >/dev/null 2>&1 || {
  echo "python3 is required for monotonic fixed-rate scheduling" >&2
  exit 69
}

attempt_dir="$evidence_dir/public-health-attempts"
mkdir -p "$attempt_dir"
if compgen -G "$attempt_dir/*.tsv" >/dev/null; then
  echo "refusing to mix public probe evidence with existing attempt files" >&2
  exit 73
fi

monotonic_ms() {
  python3 -c 'import time; print(time.monotonic_ns() // 1_000_000)'
}

sleep_until_ms() {
  python3 -c '
import sys
import time
target_ms = int(sys.argv[1])
delay = target_ms / 1000 - time.monotonic()
if delay > 0:
    time.sleep(delay)
' "$1"
}

utc_now() {
  date -u +%Y-%m-%dT%H:%M:%SZ
}

header_value() {
  local header_name=$1
  local header_file=$2
  awk -v wanted="$header_name" '
    BEGIN { IGNORECASE = 1 }
    {
      sub(/\r$/, "")
      separator = index($0, ":")
      if (separator == 0) next
      name = substr($0, 1, separator - 1)
      if (tolower(name) != tolower(wanted)) next
      value = substr($0, separator + 1)
      sub(/^[[:space:]]+/, "", value)
      gsub(/[\t\r\n]/, " ", value)
      print substr(value, 1, 200)
      exit
    }
  ' "$header_file"
}

run_start_ms=$(monotonic_ms)
run_start_utc=$(utc_now)
deadline_ms=$((run_start_ms + total_timeout_ms))
active_pids=()
max_observed_workers=0
total_timed_out=0

probe_once() {
  local attempt=$1
  local scheduled_offset_ms=$2
  local sequence
  local header_file
  local metrics_file
  local record_file
  local started_ms
  local ended_ms
  local started_offset_ms
  local ended_offset_ms
  local started_utc
  local ended_utc
  local curl_pid=""
  local curl_exit=0
  local metrics
  local http_code=000
  local remote_ip=""
  local time_connect=0
  local time_starttransfer=0
  local time_total=0
  local server=""
  local trace=""
  local cloudfront=""
  local via=""

  sequence=$(printf '%04d' "$attempt")
  header_file="$attempt_dir/$sequence.headers"
  metrics_file="$attempt_dir/$sequence.metrics"
  record_file="$attempt_dir/$sequence.tsv"
  started_ms=$(monotonic_ms)
  started_offset_ms=$((started_ms - run_start_ms))
  started_utc=$(utc_now)

  stop_curl() {
    if [[ -n "$curl_pid" ]] && kill -0 "$curl_pid" 2>/dev/null; then
      kill "$curl_pid" 2>/dev/null || true
      wait "$curl_pid" 2>/dev/null || true
    fi
  }
  trap stop_curl TERM INT

  CATS_FAKE_PROBE_ATTEMPT="$attempt" curl \
    --fail --silent \
    --connect-timeout 2 --max-time "$request_timeout_seconds" \
    --dump-header "$header_file" \
    --output /dev/null \
    --write-out '%{http_code}|%{remote_ip}|%{time_connect}|%{time_starttransfer}|%{time_total}' \
    "$url" >"$metrics_file" 2>/dev/null &
  curl_pid=$!
  set +e
  wait "$curl_pid"
  curl_exit=$?
  set -e
  curl_pid=""
  trap - TERM INT

  ended_ms=$(monotonic_ms)
  ended_offset_ms=$((ended_ms - run_start_ms))
  ended_utc=$(utc_now)
  metrics=$(tr -d '\r\n' <"$metrics_file" 2>/dev/null || true)
  IFS='|' read -r http_code remote_ip time_connect time_starttransfer time_total <<<"$metrics"
  http_code=${http_code:-000}
  remote_ip=${remote_ip:-}
  time_connect=${time_connect:-0}
  time_starttransfer=${time_starttransfer:-0}
  time_total=${time_total:-0}
  if [[ -s "$header_file" ]]; then
    server=$(header_value server "$header_file")
    trace=$(header_value x-amzn-trace-id "$header_file")
    cloudfront=$(header_value x-amz-cf-id "$header_file")
    via=$(header_value via "$header_file")
  fi
  rm -f "$header_file" "$metrics_file"

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$attempt" "$scheduled_offset_ms" "$started_offset_ms" "$ended_offset_ms" \
    "$started_utc" "$ended_utc" "$curl_exit" "$http_code" "$remote_ip" \
    "$time_connect" "$time_starttransfer" "$time_total" \
    "$server" "$trace" "$cloudfront" "$via" >"$record_file"
}

cleanup_workers() {
  local pid
  for pid in "${active_pids[@]}"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill "$pid" 2>/dev/null || true
    fi
  done
  for pid in "${active_pids[@]}"; do
    [[ -n "$pid" ]] && wait "$pid" 2>/dev/null || true
  done
  active_pids=()
}
trap cleanup_workers EXIT
trap 'cleanup_workers; exit 143' TERM
trap 'cleanup_workers; exit 130' INT

reap_workers() {
  local still_running=()
  local pid
  for pid in "${active_pids[@]}"; do
    [[ -n "$pid" ]] || continue
    if kill -0 "$pid" 2>/dev/null; then
      still_running+=("$pid")
    else
      wait "$pid" 2>/dev/null || true
    fi
  done
  active_pids=("${still_running[@]}")
}

wait_for_worker_slot() {
  local now
  while (( ${#active_pids[@]} >= max_concurrency )); do
    reap_workers
    (( ${#active_pids[@]} < max_concurrency )) && return 0
    now=$(monotonic_ms)
    if (( now >= deadline_ms )); then
      return 124
    fi
    sleep 0.01
  done
}

for attempt in $(seq 1 "$attempts"); do
  scheduled_offset_ms=$(((attempt - 1) * interval_ms))
  scheduled_ms=$((run_start_ms + scheduled_offset_ms))
  (( scheduled_ms < deadline_ms )) || {
    total_timed_out=1
    break
  }
  sleep_until_ms "$scheduled_ms"
  reap_workers
  if ! wait_for_worker_slot; then
    total_timed_out=1
    break
  fi
  probe_once "$attempt" "$scheduled_offset_ms" &
  active_pids+=("$!")
  if (( ${#active_pids[@]} > max_observed_workers )); then
    max_observed_workers=${#active_pids[@]}
  fi
done

while (( ${#active_pids[@]} > 0 )); do
  reap_workers
  (( ${#active_pids[@]} == 0 )) && break
  now=$(monotonic_ms)
  if (( now >= deadline_ms )); then
    total_timed_out=1
    cleanup_workers
    break
  fi
  sleep 0.01
done
trap - EXIT TERM INT

evidence_file="$evidence_dir/public-health.tsv"
summary_file="$evidence_dir/public-health-summary.txt"
printf '%s\n' $'attempt\tscheduled_offset_ms\tstarted_offset_ms\tended_offset_ms\tstarted_utc\tended_utc\tcurl_exit\thttp_code\tremote_ip\ttime_connect\ttime_starttransfer\ttime_total\tserver\tx_amzn_trace_id\tx_amz_cf_id\tvia' >"$evidence_file"
incomplete=0
for attempt in $(seq 1 "$attempts"); do
  sequence=$(printf '%04d' "$attempt")
  record_file="$attempt_dir/$sequence.tsv"
  if [[ -s "$record_file" ]]; then
    cat "$record_file" >>"$evidence_file"
  else
    incomplete=$((incomplete + 1))
    scheduled_offset_ms=$(((attempt - 1) * interval_ms))
    printf '%s\t%s\t\t\t\t\t124\t000\t\t0\t0\t0\t\t\t\t\n' \
      "$attempt" "$scheduled_offset_ms" >>"$evidence_file"
  fi
done

failures=$(awk -F '\t' 'NR > 1 && ($7 != 0 || $8 !~ /^2[0-9][0-9]$/) { count++ } END { print count + 0 }' "$evidence_file")
run_end_ms=$(monotonic_ms)
run_end_utc=$(utc_now)
{
  echo "run_start_utc=$run_start_utc"
  echo "run_end_utc=$run_end_utc"
  echo "elapsed_ms=$((run_end_ms - run_start_ms))"
  echo "attempts=$attempts"
  echo "failures=$failures"
  echo "incomplete=$incomplete"
  echo "interval_ms=$interval_ms"
  echo "max_concurrency=$max_concurrency"
  echo "max_observed_workers=$max_observed_workers"
  echo "request_timeout_seconds=$request_timeout_seconds"
  echo "total_timeout_ms=$total_timeout_ms"
  echo "total_timed_out=$total_timed_out"
} >"$summary_file"

if (( failures > 0 || incomplete > 0 || total_timed_out != 0 )); then
  echo "public control-plane health probe failures (first 40):" >&2
  awk -F '\t' 'NR == 1 || (NR > 1 && ($7 != 0 || $8 !~ /^2[0-9][0-9]$/))' \
    "$evidence_file" | sed -n '1,41p' >&2
  exit 1
fi

echo "All $attempts fixed-rate public health probes succeeded."
