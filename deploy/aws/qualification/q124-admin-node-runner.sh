#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Independent-runner administrator adapter for Issue 124. This file is never
# installed on a Cats worker. It accepts only exact q124 Node scope, keeps the
# transient global capability in RUNNER_TEMP, and emits only validated JSON.

API_ORIGIN="https://cats.run"
WORKSPACE_ID="ws_788c5bfc3931"

die() { printf 'error: %s\n' "$*" >&2; exit 2; }

cat_scope_valid() {
  local cat_id="$1" cat_name="$2"
  [[ -z "${cat_id}" && -z "${cat_name}" ]] ||
    [[ "${cat_id}" =~ ^cat_[A-Za-z0-9_-]+$ && "${cat_name}" =~ ^q124-[a-z0-9-]+$ ]]
}

assignment_expectation_valid() {
  local expectation="$1" cat_id="$2"
  case "${expectation}" in
    empty) return 0 ;;
    exact-one|empty-or-exact) [[ -n "${cat_id}" ]] ;;
    *) return 1 ;;
  esac
}

if [[ "${1:-}" == --validate-scope-fixtures ]]; then
  cat_scope_valid '' ''
  cat_scope_valid cat_fixture q124-fixture
  ! cat_scope_valid '' q124-fixture
  ! cat_scope_valid cat_fixture ''
  assignment_expectation_valid empty ''
  assignment_expectation_valid empty cat_fixture
  assignment_expectation_valid exact-one cat_fixture
  assignment_expectation_valid empty-or-exact cat_fixture
  ! assignment_expectation_valid exact-one ''
  ! assignment_expectation_valid empty-or-exact ''
  ! assignment_expectation_valid arbitrary cat_fixture
  printf 'adapter_scope_fixture=PASS empty=true paired=true name_only_rejected=true id_only_rejected=true expectations=true\n'
  exit 0
fi

[[ "${GITHUB_ACTIONS:-}" == true && "${GITHUB_REF:-}" == refs/heads/main &&
   "${GITHUB_REPOSITORY:-}" == ahuazhu/cats ]] ||
  die "administrator adapter must run on the independent main-branch Actions runner"
[[ "$#" == 2 ]] || die "usage: q124-admin-node-runner.sh get|cats|cordon|uncordon q124-NODE"
ACTION="$1"
NODE_ID="$2"
case "${ACTION}" in get|cats|cordon|uncordon) ;; *) die "unsupported admin action" ;; esac
[[ "${NODE_ID}" =~ ^q124-[a-z0-9][a-z0-9-]{7,54}$ ]] || die "invalid q124 Node ID"
[[ "${CATS_HA_HOOK_WORKSPACE_ID:-}" == "${WORKSPACE_ID}" ]] || die "invalid workspace scope"
WINDOW_NONCE="${CATS_HA_WINDOW_NONCE:-}"
[[ "${WINDOW_NONCE}" =~ ^[0-9a-f]{32}$ ]] || die "missing 128-bit runner window nonce"
CAT_ID="${CATS_HA_HOOK_CAT_ID:-}"
CAT_NAME="${CATS_HA_HOOK_CAT_NAME:-}"
cat_scope_valid "${CAT_ID}" "${CAT_NAME}" || die "invalid q124 Cat scope"
ASSIGNMENT_EXPECTATION="${CATS_HA_HOOK_ASSIGNMENT_EXPECTATION:-}"
assignment_expectation_valid "${ASSIGNMENT_EXPECTATION}" "${CAT_ID}" ||
  die "invalid exact assignment expectation"
for command in curl jq stat mktemp; do command -v "${command}" >/dev/null || die "missing ${command}"; done

RUNNER_ROOT="${RUNNER_TEMP:?}"
TOKEN_FILE="${Q124_RUNNER_ADMIN_TOKEN_FILE:?}"
[[ "${RUNNER_ROOT}" =~ ^/[-A-Za-z0-9._/]+$ && "${RUNNER_ROOT}" != *..* ]] || die "unsafe runner temp path"
[[ "${TOKEN_FILE}" == "${RUNNER_ROOT}/q124-admin-token" ]] || die "token must use the exact runner-temporary path"
[[ -f "${TOKEN_FILE}" && ! -L "${TOKEN_FILE}" ]] || die "missing regular ephemeral admin token file"
if token_stat="$(stat -c '%u %a' "${TOKEN_FILE}" 2>/dev/null)"; then
  :
elif token_stat="$(stat -f '%u %Lp' "${TOKEN_FILE}" 2>/dev/null)"; then
  :
else
  die "cannot inspect ephemeral admin token ownership/mode"
fi
read -r token_uid token_mode <<<"${token_stat}"
[[ "${token_uid}" == "$(id -u)" && "${token_mode}" == 600 ]] || die "unsafe ephemeral admin token ownership/mode"
IFS= read -r ADMIN_TOKEN <"${TOKEN_FILE}"
[[ "${ADMIN_TOKEN}" =~ ^[A-Za-z0-9._~-]+$ ]] &&
  (( ${#ADMIN_TOKEN} >= 32 && ${#ADMIN_TOKEN} <= 512 )) || die "invalid admin token format"
STATE_ROOT="$(mktemp -d "${RUNNER_ROOT}/q124-admin-node.XXXXXX")"
cleanup() { rm -rf "${STATE_ROOT}"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

request() {
  local method="$1" path="$2" output="$3" status
  : >"${output}"; chmod 0600 "${output}"
  status="$(printf 'header = "Authorization: Bearer %s"\n' "${ADMIN_TOKEN}" |
    curl --config - --silent --show-error --max-time 30 --request "${method}" \
      --header 'accept: application/json' --header 'content-length: 0' \
      --output "${output}" --write-out '%{http_code}' "${API_ORIGIN}${path}" 2>/dev/null)" || status=000
  [[ "${status}" == 200 ]] && jq -e . "${output}" >/dev/null 2>&1
}

assignment_file_valid() {
  local file="$1"
  jq -e --arg node "${NODE_ID}" --arg ws "${WORKSPACE_ID}" \
    --arg cat_id "${CAT_ID}" --arg cat_name "${CAT_NAME}" \
    --arg expectation "${ASSIGNMENT_EXPECTATION}" '
      (keys | sort) == ["items"] and (.items | type == "array") and
      (if $expectation == "empty" then
         (.items | length == 0)
       elif $expectation == "exact-one" then
         (.items | length == 1)
       else
         (.items | length <= 1)
       end) and
      all(.items[];
        .cat.node_id == $node and .cat.workspace_id == $ws and
        .cat.id == $cat_id and .cat.name == $cat_name)
    ' "${file}" >/dev/null
}

capture_assignment() {
  local output="$1"
  request GET "/v1/admin/nodes/${NODE_ID}/cats" "${output}" &&
    assignment_file_valid "${output}"
}

summary_valid() {
  local file="$1" expected_state="$2"
  jq -e --arg node "${NODE_ID}" --arg state "${expected_state}" \
    --arg expectation "${ASSIGNMENT_EXPECTATION}" '
      .node.id == $node and .node.state == $state and
      .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024 and
      (.assigned_cats | type == "number") and (.assigned_cpus | type == "number") and
      (.assigned_memory_mib | type == "number") and .orphan_cats == 0 and
      (if $expectation == "empty" then .assigned_cats == 0
       elif $expectation == "exact-one" then .assigned_cats == 1
       else (.assigned_cats == 0 or .assigned_cats == 1)
       end)
    ' "${file}" >/dev/null
}

recover_uncordon() {
  local response="${STATE_ROOT}/recovery-cordon.json" summary="${STATE_ROOT}/recovery-summary.json"
  request POST "/v1/admin/nodes/${NODE_ID}/actions/cordon" "${response}" &&
    request GET "/v1/admin/nodes/${NODE_ID}" "${summary}" &&
    jq -e --arg node "${NODE_ID}" '
      .node.id == $node and .node.state == "cordoned" and
      .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024 and
      (.assigned_cats | type == "number") and .orphan_cats == 0
    ' "${summary}" >/dev/null
}

cats_file="${STATE_ROOT}/cats-before.json"
capture_assignment "${cats_file}" || die "cannot prove exact Node assignment scope"

if [[ "${ACTION}" == cats ]]; then jq -c '.items' "${cats_file}"; exit 0; fi
response="${STATE_ROOT}/response.json"
case "${ACTION}" in
  get) request GET "/v1/admin/nodes/${NODE_ID}" "${response}" || die "Node read failed" ;;
  cordon)
    request POST "/v1/admin/nodes/${NODE_ID}/actions/cordon" "${response}" ||
      die "Node cordon failed"
    ;;
  uncordon)
    if ! request POST "/v1/admin/nodes/${NODE_ID}/actions/uncordon" "${response}"; then
      recover_uncordon || true
      die "Node uncordon failed and was conservatively re-cordoned"
    fi
    ;;
esac
expected_state=""
case "${ACTION}" in
  get) expected_state="$(jq -er '.node.state | select(. == "cordoned" or . == "ready" or . == "lost")' "${response}")" ||
    die "invalid exact NodeSummary response" ;;
  cordon) expected_state=cordoned ;;
  uncordon) expected_state=ready ;;
esac
if ! summary_valid "${response}" "${expected_state}"; then
  [[ "${ACTION}" != uncordon ]] || recover_uncordon || true
  die "invalid exact NodeSummary response"
fi
if [[ "${ACTION}" == cordon || "${ACTION}" == uncordon ]]; then
  cats_after="${STATE_ROOT}/cats-after.json"
  if ! capture_assignment "${cats_after}"; then
    [[ "${ACTION}" != uncordon ]] || recover_uncordon || true
    die "Node assignment changed across ${ACTION}; Node left Cordoned when recovery succeeded"
  fi
fi
jq -c . "${response}"
