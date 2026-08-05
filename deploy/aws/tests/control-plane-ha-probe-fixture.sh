#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)
probe="$repo_root/deploy/aws/probe-public-health-fixed-rate.sh"
fake_curl="$repo_root/deploy/aws/tests/fake-health-curl.sh"
fixture_root=$(mktemp -d "${TMPDIR:-/tmp}/cats-ha-probe-fixture.XXXXXX")

cleanup() {
  rm -r "$fixture_root"
}
trap cleanup EXIT

new_state() {
  local name=$1
  local state="$fixture_root/$name"
  mkdir -p "$state/bin" "$state/live" "$state/evidence"
  ln -s "$fake_curl" "$state/bin/curl"
  echo 0 >"$state/active"
  echo 0 >"$state/max_active"
  : >"$state/starts.tsv"
  : >"$state/ends.tsv"
  printf '%s\n' "$state"
}

assert_no_live_fake_curl() {
  local state=$1
  [[ $(<"$state/active") == 0 ]] || {
    echo "fake curl active count leaked after scheduler exit" >&2
    exit 1
  }
  if compgen -G "$state/live/*" >/dev/null; then
    echo "fake curl process marker leaked after scheduler exit" >&2
    exit 1
  fi
}

# Known negative: the old serial loop cannot start the next sample while one
# curl consumes its timeout. Calibrate the timestamps against the fast first
# call, then require the third start to be delayed by the slow second call.
serial_state=$(new_state serial)
for attempt in $(seq 1 6); do
  CATS_FAKE_PROBE_ATTEMPT=$attempt \
    FAKE_CURL_STATE=$serial_state \
    FAKE_CURL_SLOW_ATTEMPT=2 \
    FAKE_CURL_SLOW_MS=300 \
    PATH="$serial_state/bin:$PATH" \
    curl --fail --silent --connect-timeout 2 --max-time 0.3 \
      --dump-header "$serial_state/header" --output /dev/null \
      --write-out '%{http_code}' https://cats.run/healthz \
      >/dev/null 2>&1 || true
  sleep 0.05
done
serial_first=$(awk -F '\t' '$1 == 1 { print $3 }' "$serial_state/starts.tsv")
serial_second=$(awk -F '\t' '$1 == 2 { print $3 }' "$serial_state/starts.tsv")
serial_third=$(awk -F '\t' '$1 == 3 { print $3 }' "$serial_state/starts.tsv")
serial_second_end=$(awk -F '\t' '$1 == 2 { print $3 }' "$serial_state/ends.tsv")
[[ -n "$serial_first" && -n "$serial_second" && -n "$serial_third" && -n "$serial_second_end" ]] || {
  echo "serial negative control did not emit calibrated timestamps" >&2
  exit 1
}
(( serial_third >= serial_second_end )) || {
  echo "old serial probe did not demonstrate its timeout blind window" >&2
  exit 1
}
assert_no_live_fake_curl "$serial_state"

# Positive: attempt 2 consumes 300 ms, while attempts 3+ remain anchored to
# their 50 ms schedule. The scheduler must report the failed curl, continue
# sampling, never exceed three workers, and retain only allowlisted headers.
fixed_state=$(new_state fixed)
set +e
FAKE_CURL_STATE=$fixed_state \
FAKE_CURL_SLOW_ATTEMPT=2 \
FAKE_CURL_SLOW_MS=300 \
PATH="$fixed_state/bin:$PATH" \
  "$probe" https://cats.run/healthz 8 50 3 0.3 1200 "$fixed_state/evidence" \
  >"$fixed_state/stdout" 2>"$fixed_state/stderr"
fixed_status=$?
set -e
(( fixed_status != 0 )) || {
  echo "fixed-rate probe hid the controlled curl timeout" >&2
  exit 1
}
fixed_second=$(awk -F '\t' '$1 == 2 { print $3 }' "$fixed_state/starts.tsv")
fixed_third=$(awk -F '\t' '$1 == 3 { print $3 }' "$fixed_state/starts.tsv")
fixed_second_end=$(awk -F '\t' '$1 == 2 { print $3 }' "$fixed_state/ends.tsv")
[[ -n "$fixed_second" && -n "$fixed_third" && -n "$fixed_second_end" ]] || {
  echo "fixed-rate probe did not continue after the slow request" >&2
  exit 1
}
(( fixed_third < fixed_second_end )) || {
  echo "fixed-rate probe recreated the serial timeout blind window" >&2
  exit 1
}
fixed_max=$(<"$fixed_state/max_active")
(( fixed_max >= 2 && fixed_max <= 3 )) || {
  echo "fixed-rate probe concurrency was not bounded: $fixed_max" >&2
  exit 1
}
grep -Fq $'2\t50' "$fixed_state/evidence/public-health.tsv"
grep -Fq 'awselb/2.0' "$fixed_state/evidence/public-health.tsv"
grep -Fq 'Root=fake-' "$fixed_state/evidence/public-health.tsv"
if grep -Fq 'must-not-escape' "$fixed_state/evidence/public-health.tsv"; then
  echo "non-allowlisted response header escaped into evidence" >&2
  exit 1
fi
assert_no_live_fake_curl "$fixed_state"

# Success control: without an injected failure every scheduled request is
# present, the aggregate verdict is green, and cleanup still reaches zero.
success_state=$(new_state success)
FAKE_CURL_STATE=$success_state \
PATH="$success_state/bin:$PATH" \
  "$probe" https://cats.run/healthz 6 30 2 0.3 800 "$success_state/evidence" \
  >"$success_state/stdout" 2>"$success_state/stderr"
grep -Fxq 'attempts=6' "$success_state/evidence/public-health-summary.txt"
grep -Fxq 'failures=0' "$success_state/evidence/public-health-summary.txt"
grep -Fxq 'incomplete=0' "$success_state/evidence/public-health-summary.txt"
[[ $(wc -l <"$success_state/evidence/public-health.tsv" | tr -d ' ') == 7 ]]
success_max=$(<"$success_state/max_active")
(( success_max <= 2 )) || {
  echo "successful fixed-rate probe exceeded its concurrency bound: $success_max" >&2
  exit 1
}
assert_no_live_fake_curl "$success_state"

# Cleanup control: curls outlive the global deadline and must all be killed and
# waited. No fake-curl marker or active count may remain afterward.
timeout_state=$(new_state total-timeout)
set +e
FAKE_CURL_STATE=$timeout_state \
FAKE_CURL_HANG_MS=2000 \
PATH="$timeout_state/bin:$PATH" \
  "$probe" https://cats.run/healthz 20 20 2 3 250 "$timeout_state/evidence" \
  >"$timeout_state/stdout" 2>"$timeout_state/stderr"
timeout_status=$?
set -e
(( timeout_status != 0 )) || {
  echo "fixed-rate probe ignored its total timeout" >&2
  exit 1
}
grep -Fxq 'total_timed_out=1' "$timeout_state/evidence/public-health-summary.txt"
timeout_max=$(<"$timeout_state/max_active")
(( timeout_max <= 2 )) || {
  echo "total-timeout path exceeded its concurrency bound: $timeout_max" >&2
  exit 1
}
assert_no_live_fake_curl "$timeout_state"

echo "control-plane HA fixed-rate probe fixture passed"
