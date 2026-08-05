#!/usr/bin/env bash
set -euo pipefail

# Serial live orchestrator for all 13 q124 dependency-fault trials.  Every
# window first runs prepare-trial on the exact temporary Node, obtains a new
# ownership snapshot, and only then starts that one fault window.  A failure
# stops the matrix before any later window can mutate host firewall state.

HARNESS="${CATS_FAULT_HARNESS:-$(cd "$(dirname "$0")" && pwd)/temp-node-faults.sh}"
BASE_RUN_ID="${CATS_FAULT_MATRIX_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 3)}"
OWNERSHIP_ROOT="${CATS_FAULT_OWNERSHIP_ROOT:?}"
RESULT_ROOT="${CATS_FAULT_RESULT_ROOT:?}"
TEMP_INSTANCE_ID="${TEMP_INSTANCE_ID:?}"
NODE_ID="${NODE_ID:?}"
STRICT_CAT_ID="${CATS_FAULT_STRICT_CAT_ID:?}"
STRICT_CAT_NAME="${CATS_FAULT_STRICT_CAT_NAME:?}"
RELAXED_CAT_ID="${CATS_FAULT_RELAXED_CAT_ID:?}"
RELAXED_CAT_NAME="${CATS_FAULT_RELAXED_CAT_NAME:?}"
MANIFEST="${CATS_PROVISIONING_MANIFEST:?}"
MATRIX_CONFIRM="${CATS_FAULT_MATRIX_CONFIRM:-}"

die() { printf 'error: %s\n' "$*" >&2; exit 2; }
[[ -x "${HARNESS}" && -f "${MANIFEST}" ]] || die "reviewed harness/manifest missing"
[[ "${BASE_RUN_ID}" =~ ^[A-Za-z0-9._-]{8,40}$ ]] || die "unsafe matrix run ID"
[[ "${TEMP_INSTANCE_ID}" =~ ^i-[0-9a-f]{17}$ ]] || die "invalid exact instance ID"
[[ "${NODE_ID}" =~ ^q124-[a-z0-9-]{8,55}$ ]] || die "invalid exact Node ID"
[[ "${STRICT_CAT_ID}" =~ ^cat_[A-Za-z0-9_-]+$ && "${RELAXED_CAT_ID}" =~ ^cat_[A-Za-z0-9_-]+$ ]] ||
  die "invalid exact Cat IDs"
[[ "${STRICT_CAT_ID}" != "${RELAXED_CAT_ID}" ]] || die "strict and relaxed trials require distinct Cats"
[[ "${STRICT_CAT_NAME}" =~ ^q124-[a-z0-9][a-z0-9-]{0,57}$ &&
   "${RELAXED_CAT_NAME}" =~ ^q124-[a-z0-9][a-z0-9-]{0,57}$ ]] || die "invalid exact Cat names"
[[ "${MATRIX_CONFIRM}" == "RUN_Q124_MATRIX_${TEMP_INSTANCE_ID}_${NODE_ID}" ]] ||
  die "live matrix requires CATS_FAULT_MATRIX_CONFIRM=RUN_Q124_MATRIX_${TEMP_INSTANCE_ID}_${NODE_ID}"
mkdir -p "${OWNERSHIP_ROOT}" "${RESULT_ROOT}"
[[ -d "${OWNERSHIP_ROOT}" && -d "${RESULT_ROOT}" ]] || die "evidence roots unavailable"
MATRIX_EVIDENCE="${RESULT_ROOT}/${BASE_RUN_ID}-matrix.json"
[[ ! -e "${MATRIX_EVIDENCE}" ]] || die "matrix evidence already exists"

jq -n --arg run "${BASE_RUN_ID}" --arg instance "${TEMP_INSTANCE_ID}" --arg node "${NODE_ID}" \
  '{schema_version:2,matrix_run_id:$run,temp_instance_id:$instance,node_id:$node,
    mode:"serial-fresh-ownership",started_at:(now|todateiso8601),windows:[]}' >"${MATRIX_EVIDENCE}"
chmod 0600 "${MATRIX_EVIDENCE}"

index=0
while read -r scenario trial durability; do
  index=$((index + 1))
  window_run="${BASE_RUN_ID}-$(printf '%02d' "${index}")"
  ownership="${OWNERSHIP_ROOT}/${window_run}-${trial}.json"
  [[ ! -e "${ownership}" ]] || die "ownership output already exists for ${trial}"
  cat_id="${STRICT_CAT_ID}"; cat_name="${STRICT_CAT_NAME}"
  if [[ "${durability}" == relaxed ]]; then cat_id="${RELAXED_CAT_ID}"; cat_name="${RELAXED_CAT_NAME}"; fi
  started="$(date -u +%FT%TZ)"
  set +e
  CATS_FAULT_MODE=live CATS_FAULT_SCENARIO="${scenario}" CATS_FAULT_TRIAL="${trial}" \
    CATS_FAULT_PREPARE_TRIAL=true CATS_FAULT_TARGET_CAT_ID="${cat_id}" CATS_FAULT_TARGET_CAT_NAME="${cat_name}" \
    CATS_FAULT_ALLOW_COMBINED=true CATS_FAULT_RUN_ID="${window_run}" \
    CATS_FAULT_CONFIRM="RUN_Q124_FAULT_${TEMP_INSTANCE_ID}_${NODE_ID}_${scenario}" \
    CATS_FAULT_RESULT_ROOT="${RESULT_ROOT}" CATS_OWNERSHIP_SNAPSHOT="${ownership}" \
    CATS_PROVISIONING_MANIFEST="${MANIFEST}" TEMP_INSTANCE_ID="${TEMP_INSTANCE_ID}" NODE_ID="${NODE_ID}" \
    "${HARNESS}"
  rc=$?
  set -e
  completed="$(date -u +%FT%TZ)"
  ownership_sha=""; [[ ! -f "${ownership}" ]] || ownership_sha="$(sha256sum "${ownership}" | awk '{print $1}')"
  jq --arg scenario "${scenario}" --arg trial "${trial}" --arg durability "${durability}" \
    --arg run "${window_run}" --arg started "${started}" --arg completed "${completed}" \
    --arg ownership "${ownership}" --arg sha "${ownership_sha}" --argjson rc "${rc}" \
    '.windows += [{ordinal:(.windows|length)+1,scenario:$scenario,trial:$trial,durability:$durability,
      window_run_id:$run,started_at:$started,completed_at:$completed,ownership_snapshot:$ownership,
      ownership_sha256:$sha,result:(if $rc == 0 then "passed" else "failed" end),rc:$rc}]' \
    "${MATRIX_EVIDENCE}" >"${MATRIX_EVIDENCE}.next"
  mv "${MATRIX_EVIDENCE}.next" "${MATRIX_EVIDENCE}"
  (( rc == 0 )) || die "matrix stopped after failed trial ${trial}; no later fault window was started"
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

jq '.completed_at=(now|todateiso8601) |
  if (.windows|length) == 13 and all(.windows[]; .result == "passed" and (.ownership_sha256|test("^[0-9a-f]{64}$")))
  then .result="passed" else error("incomplete matrix") end' "${MATRIX_EVIDENCE}" >"${MATRIX_EVIDENCE}.next"
mv "${MATRIX_EVIDENCE}.next" "${MATRIX_EVIDENCE}"
printf 'result=PASS matrix_windows=13 evidence=%s\n' "${MATRIX_EVIDENCE}"
