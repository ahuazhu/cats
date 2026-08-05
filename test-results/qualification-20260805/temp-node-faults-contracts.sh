#!/usr/bin/env bash
set -euo pipefail

# Non-networking v2 evidence contract.  Covers every scenario/trial window and
# calibrated negatives for scope, freshness, observer, and evidence reuse.

HARNESS="${1:-test-results/qualification-20260805/temp-node-faults.sh}"
BASE="$(dirname "${HARNESS}")"
STRICT="${BASE}/temp-node-faults.strict.fixture.json"
RELAXED="${BASE}/temp-node-faults.relaxed.fixture.json"
LEGACY_DUAL="${BASE}/temp-node-faults.fixture.json"
MANIFEST="${BASE}/temp-node-faults.provisioning.fixture.json"
for file in "${HARNESS}" "${STRICT}" "${RELAXED}" "${LEGACY_DUAL}" "${MANIFEST}"; do [[ -f "${file}" ]]; done
ROOT="$(mktemp -d /tmp/q124-fault-contracts.XXXXXX)"
trap 'rm -rf "${ROOT}"' EXIT HUP INT TERM

run_fixture() {
  local run_id="$1" scenario="$2" trial="$3" snapshot="$4"; shift 4
  env "$@" CATS_FAULT_MODE=fixture CATS_FAULT_SCENARIO="${scenario}" CATS_FAULT_TRIAL="${trial}" \
    CATS_FAULT_ALLOW_COMBINED=true CATS_FAULT_RUN_ID="${run_id}" CATS_FAULT_RESULT_ROOT="${ROOT}" \
    TEMP_INSTANCE_ID=i-0123456789abcdef0 NODE_ID=q124-20260805000000-abcdef \
    CATS_OWNERSHIP_SNAPSHOT="${snapshot}" CATS_PROVISIONING_MANIFEST="${MANIFEST}" \
    "${HARNESS}"
}

positive=0
while read -r scenario trial durability; do
  snapshot="${STRICT}"; [[ "${durability}" == strict ]] || snapshot="${RELAXED}"
  run_fixture "positive-${trial}" "${scenario}" "${trial}" "${snapshot}" >/dev/null
  jq -e --arg scenario "${scenario}" --arg trial "${trial}" '
    .scenario == $scenario and .trial == $trial and .schema_version == 2
  ' "${ROOT}/positive-${trial}/${trial}/provenance.json" >/dev/null
  positive=$((positive + 1))
done <<'MATRIX'
db db-running strict
db db-cold-start strict
s3 s3-strict strict
s3 s3-relaxed relaxed
control-plane control-plane-running strict
db-s3 db-s3-strict strict
db-s3 db-s3-relaxed relaxed
db-control-plane db-control-plane-strict strict
db-control-plane db-control-plane-relaxed relaxed
s3-control-plane s3-control-plane-strict strict
s3-control-plane s3-control-plane-relaxed relaxed
all-3 all-3-strict strict
all-3 all-3-relaxed relaxed
MATRIX
[[ "${positive}" == 13 ]]
printf 'scenario-trial-matrix\tPASS\twindows=%s\n' "${positive}"

expect_reject() {
  local name="$1" scenario="$2" trial="$3" snapshot="$4"; shift 4
  set +e
  run_fixture "negative-${name}" "${scenario}" "${trial}" "${snapshot}" "$@" \
    >"${ROOT}/${name}.log" 2>&1
  local rc=$?
  set -e
  [[ "${rc}" -ne 0 ]] || { printf 'negative unexpectedly passed: %s\n' "${name}" >&2; return 1; }
  printf '%s\tPASS\n' "${name}"
}

expect_reject legacy-dual-cat db db-running "${LEGACY_DUAL}"
expect_reject trial-durability-mismatch s3 s3-relaxed "${STRICT}"
expect_reject stale-ownership db db-running "${STRICT}" CATS_FAULT_REQUIRE_FRESH_OWNERSHIP=true
expect_reject observer-api-disconnect control-plane control-plane-running "${STRICT}" CATS_FIXTURE_OBSERVER_MISSING=true
expect_reject observer-invalid control-plane control-plane-running "${STRICT}" CATS_FIXTURE_OBSERVER_FAIL=true
expect_reject previous-window-evidence-reuse db db-running "${STRICT}" CATS_FIXTURE_WINDOW_REUSE=true
expect_reject false-oracle db db-running "${STRICT}" CATS_FIXTURE_ORACLE_FAIL=true
expect_reject state-cat-scope-mismatch db db-running "${STRICT}" CATS_FIXTURE_CAT_SET_MISMATCH=true
expect_reject state-window-nonce-reuse db db-running "${STRICT}" CATS_FIXTURE_STATE_NONCE_REUSE=true
expect_reject oracle-window-nonce-reuse db db-running "${STRICT}" CATS_FIXTURE_ORACLE_NONCE_REUSE=true
expect_reject invalid-phase-order db db-running "${STRICT}" CATS_FIXTURE_TIMESTAMP_ORDER_FAIL=true
expect_reject preexisting-lost-not-causal control-plane control-plane-running "${STRICT}" CATS_FIXTURE_OBSERVER_PREEXISTING_LOST=true

live_root="${ROOT}/live-must-not-exist"
set +e
env CATS_FAULT_MODE=live CATS_FAULT_SCENARIO=db CATS_FAULT_TRIAL=db-running \
  CATS_FAULT_RUN_ID=live-zero-mutation CATS_FAULT_RESULT_ROOT="${live_root}" \
  TEMP_INSTANCE_ID=i-0123456789abcdef0 NODE_ID=q124-20260805000000-abcdef \
  CATS_OWNERSHIP_SNAPSHOT="${STRICT}" CATS_PROVISIONING_MANIFEST="${MANIFEST}" \
  "${HARNESS}" >"${ROOT}/live-zero-mutation.log" 2>&1
live_rc=$?
set -e
[[ "${live_rc}" -ne 0 && ! -e "${live_root}" ]]
grep -Fq 'DO NOT LIVE: worker admin authority was removed' "${ROOT}/live-zero-mutation.log"
printf 'incomplete-external-control-zero-mutation\tPASS\n'

printf 'result=PASS positive_windows=13 calibrated_negatives=13\n'
