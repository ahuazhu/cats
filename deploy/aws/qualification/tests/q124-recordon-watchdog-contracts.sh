#!/usr/bin/env bash
set -euo pipefail

WATCHDOG="${1:-deploy/aws/qualification/q124-recordon-watchdog.sh}"
WORKFLOW="$(dirname "$(dirname "$(dirname "$(dirname "${WATCHDOG}")")")")/.github/workflows/q124-recordon-watchdog.yml"
[[ -f "${WORKFLOW}" ]]
ROOT="$(mktemp -d /tmp/q124-recordon-contract.XXXXXX)"
BIN="${ROOT}/bin"; STATE="${ROOT}/state"; TOKEN="${ROOT}/q124-admin-token"
mkdir "${BIN}" "${STATE}"
trap 'rm -rf "${ROOT}"' EXIT HUP INT TERM
SECRET=admin_capability_must_never_appear_0123456789
printf '%s\n' "${SECRET}" >"${TOKEN}"; chmod 0600 "${TOKEN}"
printf cordoned >"${STATE}/node-state"

cat >"${BIN}/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
method=GET output= url=
printf '%q ' "$@" >>"${MOCK_STATE}/curl-argv.log"; printf '\n' >>"${MOCK_STATE}/curl-argv.log"
cat >/dev/null
while (($#)); do
  case "$1" in --request) shift; method="$1" ;; --output) shift; output="$1" ;; http*) url="$1" ;; esac
  shift
done
if [[ -f "${MOCK_STATE}/api-down" ]]; then exit 7; fi
case "${url}" in
  */cats)
    printf '%s\n' '{"items":[{"cat":{"id":"cat_contract","name":"q124-contract","workspace_id":"ws_788c5bfc3931","node_id":"q124-20260805000000-abcdef"}}]}' >"${output}"
    ;;
  */actions/cordon)
    printf cordoned >"${MOCK_STATE}/node-state"
    printf '%s\n' '{"node":{"id":"q124-20260805000000-abcdef","state":"cordoned"},"assigned_cats":1,"orphan_cats":0}' >"${output}"
    ;;
  *)
    state="$(<"${MOCK_STATE}/node-state")"
    printf '{"node":{"id":"q124-20260805000000-abcdef","state":"%s"},"assigned_cats":1,"orphan_cats":0}\n' "${state}" >"${output}"
    ;;
esac
printf 200
MOCK

cat >"${BIN}/gh" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
body=
while (($#)); do [[ "$1" != -f ]] || { shift; body="${1#body=}"; }; shift || true; done
sleep "${MOCK_GH_DELAY_SECONDS:-0}"
printf '%s\n' "${body}" >>"${MOCK_STATE}/github-comments.log"
MOCK
chmod 0700 "${BIN}"/*

common_env=(env PATH="${BIN}:/usr/bin:/bin" MOCK_STATE="${STATE}" RUNNER_TEMP="${ROOT}" \
  GITHUB_REPOSITORY=owner/cats GITHUB_RUN_ID=4242 GITHUB_REF=refs/heads/main \
  Q124_WATCHDOG_CONTRACT_MODE=true Q124_WATCHDOG_API_ORIGIN=https://fixture.invalid \
  Q124_WATCHDOG_WORKSPACE_ID=ws_788c5bfc3931 Q124_WATCHDOG_NODE_ID=q124-20260805000000-abcdef \
  Q124_WATCHDOG_NONCE=0123456789abcdef0123456789abcdef Q124_WATCHDOG_TOKEN_FILE="${TOKEN}" \
  Q124_WATCHDOG_NO_ACTIVITY_SECONDS=2 Q124_WATCHDOG_RECOVERY_WINDOW_SECONDS=2 \
  Q124_WATCHDOG_HARD_DEADLINE_SECONDS=8 Q124_WATCHDOG_RETRY_SECONDS=1)

expect_reject() {
  local name="$1"; shift
  set +e; "$@" >"${ROOT}/${name}.log" 2>&1; rc=$?; set -e
  [[ "${rc}" -ne 0 ]] || { echo "negative unexpectedly passed: ${name}" >&2; exit 1; }
  printf '%s\tPASS\n' "${name}"
}
expect_reject wrong-workspace env "${common_env[@]:1}" Q124_WATCHDOG_WORKSPACE_ID=ws_wrong "${WATCHDOG}"
expect_reject foreign-node env "${common_env[@]:1}" Q124_WATCHDOG_NODE_ID=prod-worker "${WATCHDOG}"
expect_reject invalid-nonce env "${common_env[@]:1}" Q124_WATCHDOG_NONCE=abcd "${WATCHDOG}"
printf '%s\n' "${SECRET}" >"${ROOT}/wrong-token-path"; chmod 0600 "${ROOT}/wrong-token-path"
expect_reject wrong-token-path env "${common_env[@]:1}" Q124_WATCHDOG_TOKEN_FILE="${ROOT}/wrong-token-path" "${WATCHDOG}"
chmod 0644 "${TOKEN}"
expect_reject unsafe-token-mode "${common_env[@]}" "${WATCHDOG}"
chmod 0600 "${TOKEN}"

# Before dispatch or before the armed marker, the parent is forbidden to
# uncordon; killing it therefore leaves the baseline Cordoned.
(sleep 30) & parent_pid=$!; kill -KILL "${parent_pid}"; set +e; wait "${parent_pid}"; set -e
[[ "$(<"${STATE}/node-state")" == cordoned ]]
printf 'parent-kill-before-dispatch\tPASS\n'
rm -f "${STATE}/github-comments.log"
env "${common_env[@]:1}" MOCK_GH_DELAY_SECONDS=1 "${WATCHDOG}" >"${ROOT}/prearmed.log" 2>&1 & prearmed_pid=$!
(sleep 30) & parent_pid=$!; kill -KILL "${parent_pid}"; set +e; wait "${parent_pid}"; set -e
[[ "$(<"${STATE}/node-state")" == cordoned ]]
wait "${prearmed_pid}"
printf 'parent-kill-dispatched-before-armed\tPASS\n'

# The recovery process is independent of the parent process.  Killing a parent
# after the durable armed marker cannot kill this process or prevent re-cordon.
rm -f "${STATE}/github-comments.log"
"${common_env[@]}" "${WATCHDOG}" >"${ROOT}/watchdog.log" 2>&1 & watchdog_pid=$!
for _ in $(seq 1 100); do grep -q 'status=armed' "${STATE}/github-comments.log" 2>/dev/null && break; sleep 0.05; done
grep -q 'status=armed' "${STATE}/github-comments.log"
(sleep 30) & parent_pid=$!; kill -KILL "${parent_pid}"; set +e; wait "${parent_pid}"; set -e
printf 'parent-kill-after-armed\tPASS\n'
printf ready >"${STATE}/node-state"
(sleep 30) & parent_pid=$!; kill -KILL "${parent_pid}"; set +e; wait "${parent_pid}"; set -e
printf 'parent-kill-after-uncordon\tPASS\n'
for _ in $(seq 1 100); do grep -q 'watchdog_activity=OBSERVED' "${ROOT}/watchdog.log" 2>/dev/null && break; sleep 0.05; done
touch "${STATE}/api-down"; sleep 2; rm "${STATE}/api-down"
wait "${watchdog_pid}"
[[ "$(<"${STATE}/node-state")" == cordoned ]]
grep -q 'watchdog_result=PASS state=cordoned reason=forced' "${ROOT}/watchdog.log"
printf 'independent-runner-api-retry-recordon\tPASS\n'
(sleep 30) & parent_pid=$!; kill -KILL "${parent_pid}"; set +e; wait "${parent_pid}"; set -e
[[ "$(<"${STATE}/node-state")" == cordoned ]]
printf 'parent-kill-after-injection\tPASS\n'

# The capability is never in argv, comments, stdout/stderr, an artifact, or a
# systemd unit (the external design creates no systemd unit at all).
! grep -R -Fq "${SECRET}" "${STATE}" "${ROOT}/watchdog.log"
! rg -n 'systemd-run|systemctl' "${WATCHDOG}" >/dev/null
[[ ! -e "${ROOT}"/q124-recordon.* ]]
printf 'capability-non-disclosure\tPASS\n'

rg -q '^name: Q124 exact-Node re-cordon watchdog$' "${WORKFLOW}"
rg -q 'role-to-assume:.*AWS_ROLE_ARN' "${WORKFLOW}"
rg -q 'get secret cats-runtime' "${WORKFLOW}"
rg -q 'CATS_ADMIN_TOKEN.*@base64d' "${WORKFLOW}"
rg -q '::add-mask::' "${WORKFLOW}"
rg -q 'rm -f.*q124-admin-token' "${WORKFLOW}"
! rg -q 'upload-artifact|admin_token:[[:space:]]*$|CATS_ADMIN_TOKEN:[[:space:]]*\$\{\{ inputs' "${WORKFLOW}"
printf 'workflow-capability-lifecycle\tPASS\n'

printf 'result=PASS input_negatives=5 kill_points=5 recovery=1 disclosure=1 workflow=1\n'
