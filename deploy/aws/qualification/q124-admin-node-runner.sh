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

if [[ "${1:-}" == --validate-scope-fixtures ]]; then
  cat_scope_valid '' ''
  cat_scope_valid cat_fixture q124-fixture
  ! cat_scope_valid '' q124-fixture
  ! cat_scope_valid cat_fixture ''
  printf 'adapter_scope_fixture=PASS empty=true paired=true name_only_rejected=true id_only_rejected=true\n'
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
for command in curl jq stat mktemp; do command -v "${command}" >/dev/null || die "missing ${command}"; done

RUNNER_ROOT="${RUNNER_TEMP:?}"
TOKEN_FILE="${Q124_RUNNER_ADMIN_TOKEN_FILE:?}"
[[ "${RUNNER_ROOT}" =~ ^/[-A-Za-z0-9._/]+$ && "${RUNNER_ROOT}" != *..* ]] || die "unsafe runner temp path"
[[ "${TOKEN_FILE}" == "${RUNNER_ROOT}/q124-admin-token" ]] || die "token must use the exact runner-temporary path"
[[ -f "${TOKEN_FILE}" && ! -L "${TOKEN_FILE}" ]] || die "missing regular ephemeral admin token file"
read -r token_uid token_mode < <(stat -c '%u %a' "${TOKEN_FILE}")
[[ "${token_uid}" == "$(id -u)" && "${token_mode}" == 600 ]] || die "unsafe ephemeral admin token ownership/mode"
IFS= read -r ADMIN_TOKEN <"${TOKEN_FILE}"
[[ "${ADMIN_TOKEN}" =~ ^[A-Za-z0-9._~-]{32,512}$ ]] || die "invalid admin token format"
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

cats_file="${STATE_ROOT}/cats.json"
request GET "/v1/admin/nodes/${NODE_ID}/cats" "${cats_file}" || die "cannot prove exact Node assignment scope"
jq -e --arg node "${NODE_ID}" --arg ws "${WORKSPACE_ID}" \
  --arg cat_id "${CAT_ID}" --arg cat_name "${CAT_NAME}" '
    (keys | sort) == ["items"] and (.items | type == "array" and length <= 1) and
    all(.items[];
      .cat.node_id == $node and .cat.workspace_id == $ws and
      (.cat.id | test("^cat_[A-Za-z0-9_-]+$")) and (.cat.name | startswith("q124-")) and
      (($cat_id == "" and $cat_name == "") or
       (.cat.id == $cat_id and .cat.name == $cat_name)))
  ' "${cats_file}" >/dev/null || die "Node assignment escaped exact q124 scope"

if [[ "${ACTION}" == cats ]]; then jq -c '.items' "${cats_file}"; exit 0; fi
response="${STATE_ROOT}/response.json"
case "${ACTION}" in
  get) request GET "/v1/admin/nodes/${NODE_ID}" "${response}" || die "Node read failed" ;;
  cordon|uncordon)
    request POST "/v1/admin/nodes/${NODE_ID}/actions/${ACTION}" "${response}" ||
      die "Node ${ACTION} failed"
    ;;
esac
jq -e --arg node "${NODE_ID}" '
  .node.id == $node and .node.capacity.cpus == 1 and .node.capacity.memory_mib == 1024 and
  (.assigned_cats | type == "number") and (.assigned_cpus | type == "number") and
  (.assigned_memory_mib | type == "number") and (.orphan_cats | type == "number")
' "${response}" >/dev/null || die "invalid exact NodeSummary response"
jq -c . "${response}"
