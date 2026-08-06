#!/usr/bin/env bash
set -euo pipefail

ADAPTER="${1:-deploy/aws/qualification/q124-admin-node-runner.sh}"
ROOT="$(mktemp -d /tmp/q124-admin-runner-contract.XXXXXX)"
BIN="${ROOT}/bin"; STATE="${ROOT}/state"; TOKEN="${ROOT}/q124-admin-token"
SECRET=runner_admin_capability_must_not_escape_0123456789
mkdir "${BIN}" "${STATE}"
trap 'rm -rf "${ROOT}"' EXIT HUP INT TERM
printf '%s\n' "${SECRET}" >"${TOKEN}"; chmod 0600 "${TOKEN}"
printf exact >"${STATE}/scope"
printf cordoned >"${STATE}/node-state"
printf normal >"${STATE}/behavior"

cat >"${BIN}/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
method=GET output= url=
cat >/dev/null
printf '%q ' "$@" >>"${MOCK_STATE}/curl-argv.log"; printf '\n' >>"${MOCK_STATE}/curl-argv.log"
while (($#)); do
  case "$1" in
    --request) shift; method="$1" ;;
    --output) shift; output="$1" ;;
    http*) url="$1" ;;
    --config|--header|--write-out|--max-time) shift ;;
  esac
  shift
done
printf '%s %s\n' "${method}" "${url}" >>"${MOCK_STATE}/requests.log"
scope="$(<"${MOCK_STATE}/scope")"
assigned=0
case "${scope}" in exact|q124-foreign) assigned=1 ;; esac
case "${url}" in
  */cats)
    if [[ "${scope}" == foreign ]]; then
      body='{"items":[{"cat":{"id":"cat_foreign","name":"user-cat","workspace_id":"ws_foreign","node_id":"q124-20260805000000-abcdef"}}]}'
    elif [[ "${scope}" == q124-foreign ]]; then
      body='{"items":[{"cat":{"id":"cat_other","name":"q124-other","workspace_id":"ws_788c5bfc3931","node_id":"q124-20260805000000-abcdef"}}]}'
    elif [[ "${scope}" == exact ]]; then
      body='{"items":[{"cat":{"id":"cat_fixture","name":"q124-fixture","workspace_id":"ws_788c5bfc3931","node_id":"q124-20260805000000-abcdef"}}]}'
    else body='{"items":[]}'
    fi
    ;;
  */actions/uncordon)
    printf ready >"${MOCK_STATE}/node-state"
    if [[ "$(<"${MOCK_STATE}/behavior")" == race-after-uncordon ]]; then
      printf q124-foreign >"${MOCK_STATE}/scope"; assigned=1
    fi
    body="{\"node\":{\"id\":\"q124-20260805000000-abcdef\",\"state\":\"ready\",\"capacity\":{\"cpus\":1,\"memory_mib\":1024}},\"assigned_cats\":${assigned},\"assigned_cpus\":${assigned},\"assigned_memory_mib\":$((assigned * 1024)),\"orphan_cats\":0}"
    ;;
  */actions/cordon)
    printf cordoned >"${MOCK_STATE}/node-state"
    body="{\"node\":{\"id\":\"q124-20260805000000-abcdef\",\"state\":\"cordoned\",\"capacity\":{\"cpus\":1,\"memory_mib\":1024}},\"assigned_cats\":${assigned},\"assigned_cpus\":${assigned},\"assigned_memory_mib\":$((assigned * 1024)),\"orphan_cats\":0}"
    ;;
  *)
    state="$(<"${MOCK_STATE}/node-state")"
    body="{\"node\":{\"id\":\"q124-20260805000000-abcdef\",\"state\":\"${state}\",\"capacity\":{\"cpus\":1,\"memory_mib\":1024}},\"assigned_cats\":${assigned},\"assigned_cpus\":${assigned},\"assigned_memory_mib\":$((assigned * 1024)),\"orphan_cats\":0}"
    ;;
esac
printf '%s' "${body}" >"${output}"
if [[ "$(<"${MOCK_STATE}/behavior")" == ambiguous-uncordon && "${url}" == */actions/uncordon ]]; then
  printf 500
  exit 0
fi
printf 200
MOCK
chmod 0700 "${BIN}/curl"

base_env=(PATH="${BIN}:/usr/bin:/bin" MOCK_STATE="${STATE}" GITHUB_ACTIONS=true
  GITHUB_REF=refs/heads/main GITHUB_REPOSITORY=ahuazhu/cats RUNNER_TEMP="${ROOT}"
  Q124_RUNNER_ADMIN_TOKEN_FILE="${TOKEN}" CATS_HA_WINDOW_NONCE=0123456789abcdef0123456789abcdef
  CATS_HA_HOOK_WORKSPACE_ID=ws_788c5bfc3931 CATS_HA_HOOK_CAT_ID=cat_fixture
  CATS_HA_HOOK_CAT_NAME=q124-fixture CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=exact-one)

expect_reject() {
  local name="$1"; shift
  set +e; "$@" >"${ROOT}/${name}.out" 2>"${ROOT}/${name}.err"; rc=$?; set -e
  [[ "${rc}" -ne 0 ]] || { echo "negative unexpectedly passed: ${name}" >&2; exit 1; }
  printf '%s\tPASS\n' "${name}"
}

expect_reject non-actions env "${base_env[@]}" GITHUB_ACTIONS=false "${ADAPTER}" get q124-20260805000000-abcdef
expect_reject wrong-ref env "${base_env[@]}" GITHUB_REF=refs/heads/feature "${ADAPTER}" get q124-20260805000000-abcdef
expect_reject invalid-nonce env "${base_env[@]}" CATS_HA_WINDOW_NONCE=abcd "${ADAPTER}" get q124-20260805000000-abcdef
expect_reject missing-expectation env "${base_env[@]}" CATS_HA_HOOK_ASSIGNMENT_EXPECTATION= "${ADAPTER}" get q124-20260805000000-abcdef
expect_reject impossible-exact-scope env "${base_env[@]}" CATS_HA_HOOK_CAT_ID= CATS_HA_HOOK_CAT_NAME= \
  CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=exact-one "${ADAPTER}" get q124-20260805000000-abcdef
printf '%s\n' "${SECRET}" >"${ROOT}/wrong-token-path"; chmod 0600 "${ROOT}/wrong-token-path"
expect_reject wrong-token-path env "${base_env[@]}" Q124_RUNNER_ADMIN_TOKEN_FILE="${ROOT}/wrong-token-path" "${ADAPTER}" get q124-20260805000000-abcdef
chmod 0644 "${TOKEN}"
expect_reject unsafe-token-mode env "${base_env[@]}" "${ADAPTER}" get q124-20260805000000-abcdef
chmod 0600 "${TOKEN}"

for action in get cats cordon; do
  env "${base_env[@]}" "${ADAPTER}" "${action}" q124-20260805000000-abcdef >"${ROOT}/${action}.json"
  jq -e . "${ROOT}/${action}.json" >/dev/null
  printf 'runner-%s\tPASS\n' "${action}"
done
printf empty >"${STATE}/scope"; printf cordoned >"${STATE}/node-state"
env "${base_env[@]}" CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=empty "${ADAPTER}" uncordon \
  q124-20260805000000-abcdef >"${ROOT}/uncordon.json"
jq -e '.node.state == "ready" and .assigned_cats == 0' "${ROOT}/uncordon.json" >/dev/null
printf 'runner-uncordon\tPASS\n'

printf foreign >"${STATE}/scope"
before="$(wc -l <"${STATE}/curl-argv.log")"
expect_reject foreign-assignment env "${base_env[@]}" "${ADAPTER}" cordon q124-20260805000000-abcdef
after="$(wc -l <"${STATE}/curl-argv.log")"
[[ "$((after - before))" == 1 ]]

# Empty scope means exactly zero assignments. A same-workspace q124 Cat that
# wins before the adapter's fresh check must prevent any uncordon call.
printf q124-foreign >"${STATE}/scope"; printf cordoned >"${STATE}/node-state"
before="$(rg -c '/actions/uncordon' "${STATE}/requests.log" || true)"
expect_reject empty-scope-q124-race env "${base_env[@]}" CATS_HA_HOOK_CAT_ID= \
  CATS_HA_HOOK_CAT_NAME= CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=empty \
  "${ADAPTER}" uncordon q124-20260805000000-abcdef
after="$(rg -c '/actions/uncordon' "${STATE}/requests.log" || true)"
[[ "${after}" == "${before}" && "$(<"${STATE}/node-state")" == cordoned ]]
printf 'empty-scope-foreign-placement\tPASS\n'

# A placement that appears after the precheck is detected by the response or
# postcheck. The adapter must make an exact re-cordon attempt before failing.
printf race-empty >"${STATE}/scope"; printf race-after-uncordon >"${STATE}/behavior"
printf cordoned >"${STATE}/node-state"
before_uncordon="$(rg -c '/actions/uncordon' "${STATE}/requests.log" || true)"
before_cordon="$(rg -c '/actions/cordon' "${STATE}/requests.log" || true)"
expect_reject postcheck-q124-race env "${base_env[@]}" CATS_HA_HOOK_CAT_ID= \
  CATS_HA_HOOK_CAT_NAME= CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=empty \
  "${ADAPTER}" uncordon q124-20260805000000-abcdef
after_uncordon="$(rg -c '/actions/uncordon' "${STATE}/requests.log" || true)"
after_cordon="$(rg -c '/actions/cordon' "${STATE}/requests.log" || true)"
[[ "$((after_uncordon - before_uncordon))" == 1 && "$((after_cordon - before_cordon))" == 1 ]]
[[ "$(<"${STATE}/node-state")" == cordoned ]]
printf 'postcheck-race-recordon\tPASS\n'

# A lost uncordon response may have been applied. Recovery must still issue a
# re-cordon and leave the fixture authoritatively Cordoned.
printf empty >"${STATE}/scope"; printf ambiguous-uncordon >"${STATE}/behavior"
printf cordoned >"${STATE}/node-state"
before_cordon="$(rg -c '/actions/cordon' "${STATE}/requests.log" || true)"
expect_reject ambiguous-uncordon-recordon env "${base_env[@]}" \
  CATS_HA_HOOK_ASSIGNMENT_EXPECTATION=empty "${ADAPTER}" uncordon q124-20260805000000-abcdef
after_cordon="$(rg -c '/actions/cordon' "${STATE}/requests.log" || true)"
[[ "$((after_cordon - before_cordon))" == 1 && "$(<"${STATE}/node-state")" == cordoned ]]
printf 'ambiguous-uncordon-recordon\tPASS\n'

! grep -R -Fq "${SECRET}" "${STATE}" "${ROOT}"/*.json "${ROOT}"/*.out "${ROOT}"/*.err
! rg -n '/etc/cats/qualification-124|systemd-run|systemctl' "${ADAPTER}" >/dev/null
printf 'capability-non-disclosure\tPASS\n'
printf 'result=PASS input_negatives=8 actions=4 scope=4 disclosure=1\n'
