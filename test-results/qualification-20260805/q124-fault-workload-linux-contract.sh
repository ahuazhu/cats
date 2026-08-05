#!/usr/bin/env bash
set -euo pipefail

# Deterministic, non-networking contract for the reviewed q124 workload hook.
# Run only as root in a disposable Linux container.

[[ "$(uname -s)" == Linux && "${EUID}" == 0 ]] || {
  printf 'error: disposable root Linux container required\n' >&2; exit 2;
}
for command in bash jq sha256sum python3 stat; do command -v "${command}" >/dev/null; done

HOOK="${1:-test-results/qualification-20260805/live-hooks/q124-fault-workload}"
[[ -x "${HOOK}" ]]
CONTRACT_ROOT="$(mktemp -d /tmp/q124-workload-contract.XXXXXX)"
MOCK_BIN="${CONTRACT_ROOT}/bin"
MOCK_STATE="${CONTRACT_ROOT}/state"
mkdir -p "${MOCK_BIN}" "${MOCK_STATE}"

[[ ! -e /etc/cats/qualification-124/admin-token && ! -e /etc/cats/worker.env ]]
cleanup() {
  rm -rf "${CONTRACT_ROOT}" /etc/cats/qualification-124
  rm -f /etc/cats/worker.env /run/q124-contract-*-prepare.json /run/q124-contract-observer*
  rm -rf /run/cats-q124-workload-contract-*
}
trap cleanup EXIT HUP INT TERM

mkdir -p /etc/cats/qualification-124
printf '%s\n' 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' >/etc/cats/qualification-124/admin-token
printf '%s\n' 'CATS_AUTH_TOKEN=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' >/etc/cats/worker.env
chmod 0600 /etc/cats/qualification-124/admin-token /etc/cats/worker.env
cat >/etc/cats/qualification-124/fault-targets.json <<'JSON'
{"schema_version":1,"db_host":"fixture.cluster.us-east-1.rds.amazonaws.com","db_port":5432,
 "s3_host":"s3.us-east-1.amazonaws.com","s3_port":443,
 "control_plane_host":"cats.run","control_plane_port":443,
 "node_listen_ip":"10.0.0.124","node_listen_port":7301,
 "fault_duration_seconds":5,"control_plane_lease_timeout_seconds":5}
JSON
chmod 0600 /etc/cats/qualification-124/fault-targets.json

cat >"${MOCK_BIN}/curl" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
output=""; method=GET; url=""
while (($#)); do
  case "$1" in
    --output) shift; output="$1" ;;
    --request) shift; method="$1" ;;
    http://*|https://*) url="$1" ;;
    --config|--header|--data-binary|--write-out|--max-time|--resolve) shift ;;
  esac
  shift
done
[[ -n "${output}" && -n "${url}" ]]
printf '%s %s\n' "${method}" "${url}" >>"${MOCK_STATE}/curl.log"
status=200
if [[ "${MOCK_OBSERVER_API_FAIL:-false}" == true ]]; then
  status=000; body='{}'
elif [[ "${MOCK_OBSERVER:-false}" == true ]]; then
  case "${url}" in
    */v1/admin/nodes/q124-20260805000000-abcdef/cats)
      body='{"items":[{"cat":{"id":"cat_observer_target","name":"q124-observer-target","workspace_id":"ws_788c5bfc3931","node_id":"q124-20260805000000-abcdef","generation":17,"observed_state":"running"}}]}' ;;
    */v1/admin/nodes/q124-20260805000000-abcdef)
      count_file="${MOCK_STATE}/observer-node-count"; count=0
      [[ ! -f "${count_file}" ]] || count="$(<"${count_file}")"; count=$((count + 1)); printf '%s' "${count}" >"${count_file}"
      state=cordoned; (( count != 2 )) || state=lost
      body="{\"node\":{\"id\":\"q124-20260805000000-abcdef\",\"state\":\"${state}\",\"capacity\":{\"cpus\":1,\"memory_mib\":1024}},\"assigned_cats\":1,\"orphan_cats\":0}" ;;
    *) status=404; body='{}' ;;
  esac
else case "${url}" in
  */v1/admin/nodes/q124-20260805000000-abcdef/cats) body='{"items":[]}' ;;
  */v1/admin/nodes/q124-20260805000000-abcdef/actions/uncordon)
    body='{"node":{"id":"q124-20260805000000-abcdef","state":"ready"}}' ;;
  */v1/admin/nodes/q124-20260805000000-abcdef/actions/cordon)
    if [[ "${MOCK_PREPARE_CORDON_FAIL:-false}" == true ]]; then status=500; body='{}'
    else body='{"node":{"id":"q124-20260805000000-abcdef","state":"cordoned"}}'; fi ;;
  */v1/admin/nodes/q124-20260805000000-abcdef)
    body='{"node":{"id":"q124-20260805000000-abcdef","state":"cordoned","capacity":{"cpus":1,"memory_mib":1024}},"assigned_cats":0,"orphan_cats":0}' ;;
  */v1/workspaces/ws_788c5bfc3931/cats/cat_prepare_target/actions/start)
    body='{"operation":{"id":"op_prepare_target","phase":"pending"}}'; status=202 ;;
  */v1/workspaces/ws_788c5bfc3931/cats/cat_prepare_target)
    count_file="${MOCK_STATE}/cat-count"; count=0
    [[ ! -f "${count_file}" ]] || count="$(<"${count_file}")"; count=$((count + 1)); printf '%s' "${count}" >"${count_file}"
    if (( count == 1 )); then
      body='{"id":"cat_prepare_target","name":"q124-prepare-target","workspace_id":"ws_788c5bfc3931","observed_state":"cold","node_id":null,"root_disk_id":"disk_prepare_target"}'
    else
      body='{"id":"cat_prepare_target","name":"q124-prepare-target","workspace_id":"ws_788c5bfc3931","desired_state":"running","observed_state":"running","node_id":"q124-wrong-placement","root_disk_id":"disk_prepare_target"}'
    fi ;;
  */v1/workspaces/ws_788c5bfc3931/disks/disk_prepare_target)
    body='{"id":"disk_prepare_target","workspace_id":"ws_788c5bfc3931","durability":"strict","bound_cat_id":"cat_prepare_target","volume_id":"vol_prepare_target"}' ;;
  *) status=404; body='{}' ;;
esac
fi
printf '%s' "${body}" >"${output}"
printf '%s' "${status}"
MOCK
chmod 0700 "${MOCK_BIN}/curl"

run_prepare_failure() {
  local run_id="$1"
  env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_STATE="${MOCK_STATE}" \
    MOCK_PREPARE_CORDON_FAIL="${MOCK_PREPARE_CORDON_FAIL:-false}" Q124_RUN_ID="${run_id}" \
    "${HOOK}" prepare-trial --scenario db --trial db-running \
    --workspace-id ws_788c5bfc3931 --node-id q124-20260805000000-abcdef \
    --cat-id cat_prepare_target --cat-name q124-prepare-target --instance-id i-0123456789abcdef0 \
    --output "/run/q124-${run_id}-prepare.json"
}

set +e; run_prepare_failure contract-placement >"${CONTRACT_ROOT}/placement.log" 2>&1; placement_rc=$?; set -e
[[ "${placement_rc}" -ne 0 ]]
[[ -s "${MOCK_STATE}/curl.log" ]] || { cat "${CONTRACT_ROOT}/placement.log" >&2; exit 1; }
mapfile -t actions < <(awk '$2 ~ /actions\/(uncordon|cordon)$/ {print $2}' "${MOCK_STATE}/curl.log")
[[ "${#actions[@]}" == 2 && "${actions[0]}" == */uncordon && "${actions[1]}" == */cordon ]]
printf 'prepare-placement-return-recordon\tPASS\n'

rm -rf "${MOCK_STATE}"; mkdir -p "${MOCK_STATE}"
set +e; MOCK_PREPARE_CORDON_FAIL=true run_prepare_failure contract-recordon-fail \
  >"${CONTRACT_ROOT}/recordon-fail.log" 2>&1; recordon_rc=$?; set -e
[[ "${recordon_rc}" == 70 ]]
grep -q '/actions/cordon$' "${MOCK_STATE}/curl.log"
printf 'prepare-recordon-failure-closed\tPASS\n'

rm -rf "${MOCK_STATE}"; mkdir -p "${MOCK_STATE}"
env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_STATE="${MOCK_STATE}" MOCK_OBSERVER=true \
  Q124_RUN_ID=contract-observer "${HOOK}" observe-window --scenario control-plane \
  --trial control-plane-running --workspace-id ws_788c5bfc3931 --node-id q124-20260805000000-abcdef \
  --cat-id cat_observer_target --timeout-seconds 5 --ready-file /run/q124-contract-observer.ready \
  --output /run/q124-contract-observer.json
jq -e '.schema_version == 2 and .source == "external-control-plane-observer" and
  .window_id == "contract-observer" and .checks.node_lost_observed == true and
  .checks.node_recovered_cordoned == true' /run/q124-contract-observer.json >/dev/null
printf 'external-observer-positive\tPASS\n'

rm -rf "${MOCK_STATE}"; mkdir -p "${MOCK_STATE}"
set +e
env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_STATE="${MOCK_STATE}" MOCK_OBSERVER_API_FAIL=true \
  Q124_RUN_ID=contract-observer-api-fail "${HOOK}" observe-window --scenario control-plane \
  --trial control-plane-running --workspace-id ws_788c5bfc3931 --node-id q124-20260805000000-abcdef \
  --cat-id cat_observer_target --timeout-seconds 1 --ready-file /run/q124-contract-observer-api-fail.ready \
  --output /run/q124-contract-observer-api-fail.json >/dev/null 2>&1
observer_fail_rc=$?
set -e
[[ "${observer_fail_rc}" -ne 0 && ! -e /run/q124-contract-observer-api-fail.ready ]]
printf 'external-observer-api-disconnect-failure-closed\tPASS\n'
printf 'result=PASS workload_hook_contracts=4\n'
