#!/usr/bin/env bash
set -euo pipefail

MATRIX="${1:-test-results/qualification-20260805/temp-node-fault-matrix.sh}"
BASE="$(dirname "${MATRIX}")"
ROOT="$(mktemp -d /tmp/q124-matrix-contract.XXXXXX)"
trap 'rm -rf "${ROOT}"' EXIT HUP INT TERM
FAKE="${ROOT}/fake-harness"

cat >"${FAKE}" <<'FAKE'
#!/usr/bin/env bash
set -euo pipefail
printf '%s\t%s\t%s\t%s\n' "${CATS_FAULT_SCENARIO}" "${CATS_FAULT_TRIAL}" \
  "${CATS_FAULT_RUN_ID}" "${CATS_FAULT_WINDOW_NONCE}" >>"${Q124_MATRIX_CALLS}"
source="${Q124_STRICT_FIXTURE}"
case "${CATS_FAULT_TRIAL}" in *-relaxed) source="${Q124_RELAXED_FIXTURE}" ;; esac
cp "${source}" "${CATS_OWNERSHIP_SNAPSHOT}"
FAKE
chmod 0700 "${FAKE}"
mkdir "${ROOT}/ownership" "${ROOT}/results"

Q124_MATRIX_CALLS="${ROOT}/calls.tsv" \
Q124_STRICT_FIXTURE="${BASE}/temp-node-faults.strict.fixture.json" \
Q124_RELAXED_FIXTURE="${BASE}/temp-node-faults.relaxed.fixture.json" \
CATS_FAULT_HARNESS="${FAKE}" CATS_FAULT_MATRIX_RUN_ID=matrix-contract-124 \
CATS_FAULT_OWNERSHIP_ROOT="${ROOT}/ownership" CATS_FAULT_RESULT_ROOT="${ROOT}/results" \
TEMP_INSTANCE_ID=i-0123456789abcdef0 NODE_ID=q124-20260805000000-abcdef \
CATS_FAULT_STRICT_CAT_ID=cat_matrix_strict CATS_FAULT_STRICT_CAT_NAME=q124-matrix-strict \
CATS_FAULT_RELAXED_CAT_ID=cat_matrix_relaxed CATS_FAULT_RELAXED_CAT_NAME=q124-matrix-relaxed \
CATS_PROVISIONING_MANIFEST="${BASE}/temp-node-faults.provisioning.fixture.json" \
CATS_FAULT_MATRIX_CONFIRM=RUN_Q124_MATRIX_i-0123456789abcdef0_q124-20260805000000-abcdef \
Q124_MATRIX_CALLS="${ROOT}/calls.tsv" Q124_STRICT_FIXTURE="${BASE}/temp-node-faults.strict.fixture.json" \
Q124_RELAXED_FIXTURE="${BASE}/temp-node-faults.relaxed.fixture.json" \
"${MATRIX}" >/dev/null

[[ "$(wc -l <"${ROOT}/calls.tsv" | tr -d ' ')" == 13 ]]
jq -e '
  .result == "passed" and (.windows|length) == 13 and
  [.windows[].ordinal] == [range(1;14)] and
  ([.windows[].window_nonce] | unique | length) == 13 and
  all(.windows[]; .result == "passed" and (.ownership_sha256|test("^[0-9a-f]{64}$")))
' "${ROOT}/results/matrix-contract-124-matrix.json" >/dev/null

printf 'matrix-real-orchestrator\tPASS\twindows=13\n'
