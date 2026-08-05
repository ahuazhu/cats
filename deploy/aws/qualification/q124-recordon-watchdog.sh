#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

# Runs on an independent GitHub-hosted recovery runner, never on the Cats
# worker.  The production admin token is read from a mode-0600 ephemeral file,
# sent only on curl's config stdin, and removed by the workflow cleanup step.

NODE_ID="${Q124_WATCHDOG_NODE_ID:?}"
WORKSPACE_ID="${Q124_WATCHDOG_WORKSPACE_ID:?}"
NONCE="${Q124_WATCHDOG_NONCE:?}"
TOKEN_FILE="${Q124_WATCHDOG_TOKEN_FILE:?}"
REPOSITORY="${GITHUB_REPOSITORY:?}"
RUN_ID="${GITHUB_RUN_ID:?}"
API_ORIGIN="${Q124_WATCHDOG_API_ORIGIN:-https://cats.run}"
NO_ACTIVITY_SECONDS="${Q124_WATCHDOG_NO_ACTIVITY_SECONDS:-300}"
RECOVERY_WINDOW_SECONDS="${Q124_WATCHDOG_RECOVERY_WINDOW_SECONDS:-210}"
HARD_DEADLINE_SECONDS="${Q124_WATCHDOG_HARD_DEADLINE_SECONDS:-900}"
RETRY_SECONDS="${Q124_WATCHDOG_RETRY_SECONDS:-5}"
CONTRACT_MODE="${Q124_WATCHDOG_CONTRACT_MODE:-false}"
STATE_ROOT="$(mktemp -d "${RUNNER_TEMP:?}/q124-recordon.XXXXXX")"
ARMED_MARKER="<!-- cats-q124-recordon:${NONCE}:armed -->"

cleanup() { rm -rf "${STATE_ROOT}"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
die() { printf 'q124-recordon-watchdog: %s\n' "$*" >&2; exit 2; }

[[ "${GITHUB_REF:-}" == refs/heads/main ]] || die 'watchdog must run from main'
[[ "${WORKSPACE_ID}" == ws_788c5bfc3931 ]] || die 'invalid qualification workspace'
[[ "${NODE_ID}" =~ ^q124-[a-z0-9][a-z0-9-]{7,54}$ ]] || die 'invalid exact q124 Node ID'
[[ "${NONCE}" =~ ^[0-9a-f]{32}$ ]] || die 'invalid 128-bit nonce'
[[ "${REPOSITORY}" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ && "${RUN_ID}" =~ ^[0-9]+$ ]] || die 'invalid GitHub identity'
if [[ "${CONTRACT_MODE}" == true ]]; then
  [[ "${API_ORIGIN}" == https://fixture.invalid ]] || die 'contract mode requires fixture origin'
else
  [[ "${CONTRACT_MODE}" == false && "${API_ORIGIN}" == https://cats.run ]] || die 'invalid API origin'
fi
for value in "${NO_ACTIVITY_SECONDS}" "${RECOVERY_WINDOW_SECONDS}" "${HARD_DEADLINE_SECONDS}" "${RETRY_SECONDS}"; do
  [[ "${value}" =~ ^[0-9]+$ ]] || die 'invalid watchdog duration'
done
if [[ "${CONTRACT_MODE}" == true ]]; then
  (( NO_ACTIVITY_SECONDS >= 1 && RECOVERY_WINDOW_SECONDS >= 1 && HARD_DEADLINE_SECONDS >= 4 )) || die 'invalid contract durations'
else
  (( NO_ACTIVITY_SECONDS >= 120 && NO_ACTIVITY_SECONDS <= 600 )) || die 'invalid no-activity window'
  (( RECOVERY_WINDOW_SECONDS >= 30 && RECOVERY_WINDOW_SECONDS <= 300 )) || die 'invalid recovery window'
  (( HARD_DEADLINE_SECONDS >= 300 && HARD_DEADLINE_SECONDS <= 1200 )) || die 'invalid hard deadline'
fi
(( HARD_DEADLINE_SECONDS > NO_ACTIVITY_SECONDS && HARD_DEADLINE_SECONDS > RECOVERY_WINDOW_SECONDS )) || die 'invalid deadline ordering'
(( RETRY_SECONDS >= 1 && RETRY_SECONDS <= 15 )) || die 'invalid retry interval'

[[ "${TOKEN_FILE}" == "${RUNNER_TEMP}/q124-admin-token" ]] || die 'admin token must use the exact runner-temporary path'
[[ -f "${TOKEN_FILE}" && ! -L "${TOKEN_FILE}" ]] || die 'missing ephemeral admin token file'
read -r token_uid token_mode < <(stat -c '%u %a' "${TOKEN_FILE}")
[[ "${token_uid}" == "$(id -u)" && "${token_mode}" == 600 ]] || die 'unsafe ephemeral admin token ownership/mode'
IFS= read -r ADMIN_TOKEN <"${TOKEN_FILE}"
[[ "${ADMIN_TOKEN}" =~ ^[A-Za-z0-9._~-]{32,512}$ ]] || die 'invalid admin token format'

request() {
  local method="$1" path="$2" output="$3" status
  : >"${output}"; chmod 0600 "${output}"
  status="$(printf 'header = "Authorization: Bearer %s"\n' "${ADMIN_TOKEN}" |
    curl --config - --silent --show-error --max-time 15 --request "${method}" \
      --header 'accept: application/json' --header 'content-length: 0' \
      --output "${output}" --write-out '%{http_code}' "${API_ORIGIN}${path}" 2>/dev/null)" || status=000
  [[ "${status}" == 200 ]] && jq -e . "${output}" >/dev/null 2>&1
}

observe_exact_node() {
  local cats="${STATE_ROOT}/cats.json" summary="${STATE_ROOT}/node.json"
  request GET "/v1/admin/nodes/${NODE_ID}/cats" "${cats}" || return 1
  jq -e --arg node "${NODE_ID}" --arg ws "${WORKSPACE_ID}" '
    (keys | sort) == ["items"] and (.items | type == "array" and length <= 1) and
    all(.items[]; .cat.node_id == $node and .cat.workspace_id == $ws and
      (.cat.id | test("^cat_[A-Za-z0-9_-]+$")) and
      (.cat.name | test("^q124-[a-z0-9][a-z0-9-]{0,57}$")))
  ' "${cats}" >/dev/null || return 64
  request GET "/v1/admin/nodes/${NODE_ID}" "${summary}" || return 1
  jq -er --arg node "${NODE_ID}" '
    select(.node.id == $node and (.node.state == "cordoned" or .node.state == "ready" or .node.state == "lost") and
      (.assigned_cats|type == "number" and . <= 1) and .orphan_cats == 0) | .node.state
  ' "${summary}"
}

cordon_exact_node() {
  local cats="${STATE_ROOT}/cordon-cats.json" response="${STATE_ROOT}/cordon.json" state rc=0
  state="$(observe_exact_node)" || rc=$?
  (( rc == 0 )) || return "${rc}"
  [[ "${state}" != cordoned ]] || return 0
  request POST "/v1/admin/nodes/${NODE_ID}/actions/cordon" "${response}" || return 1
  state="$(observe_exact_node)" || return $?
  [[ "${state}" == cordoned ]]
}

post_status() {
  local status="$1" body
  body="${ARMED_MARKER}
q124-recordon-watchdog status=${status} node=${NODE_ID} workspace=${WORKSPACE_ID} run_id=${RUN_ID}"
  gh api "repos/${REPOSITORY}/issues/124/comments" -f body="${body}" >/dev/null
}

# Positive calibration and scope proof happen before the durable armed marker.
initial_state="$(observe_exact_node)" || die 'cannot prove exact Node scope before arming'
[[ "${initial_state}" == cordoned ]] || die 'Node must be authoritatively Cordoned before arming'
post_status armed || die 'cannot publish durable armed marker'
printf 'watchdog_armed=PASS node=%s nonce=%s run_id=%s\n' "${NODE_ID}" "${NONCE}" "${RUN_ID}"

started_epoch="$(date +%s)"; no_activity_deadline=$((started_epoch + NO_ACTIVITY_SECONDS))
hard_deadline=$((started_epoch + HARD_DEADLINE_SECONDS)); recovery_deadline=0; activity=false
while (( $(date +%s) < hard_deadline )); do
  now="$(date +%s)"; state_rc=0; state="$(observe_exact_node)" || state_rc=$?
  if (( state_rc == 64 )); then
    post_status scope-violation >/dev/null 2>&1 || true
    die 'Node assignment escaped exact q124 scope; no mutation attempted'
  fi
  if [[ "${activity}" == false ]]; then
    if (( state_rc != 0 )) || [[ "${state:-}" == ready || "${state:-}" == lost ]]; then
      activity=true; recovery_deadline=$((now + RECOVERY_WINDOW_SECONDS))
      printf 'watchdog_activity=OBSERVED node=%s\n' "${NODE_ID}"
    elif (( now >= no_activity_deadline )); then
      [[ "${state}" == cordoned ]] || die 'unexpected state at no-activity deadline'
      post_status no-uncordon >/dev/null 2>&1 || true
      printf 'watchdog_result=PASS state=cordoned reason=no-uncordon\n'
      exit 0
    fi
  fi
  if [[ "${activity}" == true ]]; then
    if (( state_rc == 0 )) && [[ "${state}" == cordoned ]]; then
      post_status recovered >/dev/null 2>&1 || true
      printf 'watchdog_result=PASS state=cordoned reason=observed\n'
      exit 0
    fi
    if (( now >= recovery_deadline )); then
      if cordon_exact_node; then
        post_status recovered >/dev/null 2>&1 || true
        printf 'watchdog_result=PASS state=cordoned reason=forced\n'
        exit 0
      fi
    fi
  fi
  sleep "${RETRY_SECONDS}"
done
post_status hard-deadline >/dev/null 2>&1 || true
printf 'q124-recordon-watchdog: hard deadline reached without authoritative Cordoned\n' >&2
exit 70
