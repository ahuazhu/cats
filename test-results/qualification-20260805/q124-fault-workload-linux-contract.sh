#!/usr/bin/env bash
set -euo pipefail

# Deterministic, non-networking capability-boundary contract for the q124
# worker hook. Run only as root in a disposable Linux container.

[[ "$(uname -s)" == Linux && "${EUID}" == 0 ]] || {
  printf 'error: disposable root Linux container required\n' >&2; exit 2;
}
for command in bash jq sha256sum python3 stat rg; do command -v "${command}" >/dev/null; done

HOOK="${1:-test-results/qualification-20260805/live-hooks/q124-fault-workload}"
[[ -x "${HOOK}" ]]
CONTRACT_ROOT="$(mktemp -d /tmp/q124-workload-contract.XXXXXX)"
MOCK_BIN="${CONTRACT_ROOT}/bin"
MOCK_STATE="${CONTRACT_ROOT}/state"
ADMIN_SENTINEL=admin_capability_must_not_reach_worker_0123456789
SERVICE_SENTINEL=local_node_service_capability_0123456789abcdef
mkdir -p "${MOCK_BIN}" "${MOCK_STATE}"

[[ ! -e /etc/cats/qualification-124/admin-token && ! -e /etc/cats/worker.env ]]
cleanup() {
  rm -rf "${CONTRACT_ROOT}" /etc/cats/qualification-124
  rm -f /etc/cats/worker.env
  rm -rf /run/cats-q124-workload-contract-*
}
trap cleanup EXIT HUP INT TERM

mkdir -p /etc/cats/qualification-124
# A legacy path is deliberately present as a tripwire. The worker must never
# open it; production's immutable guard rejects it before the hook starts.
printf '%s\n' "${ADMIN_SENTINEL}" >/etc/cats/qualification-124/admin-token
chmod 0600 /etc/cats/qualification-124/admin-token
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
output= url=
printf '%q ' "$@" >>"${MOCK_STATE}/curl-argv.log"; printf '\n' >>"${MOCK_STATE}/curl-argv.log"
while (($#)); do
  case "$1" in
    --output) shift; output="$1" ;;
    http://*|https://*) url="$1" ;;
    --header|--write-out|--max-time|--resolve|--request) shift ;;
  esac
  shift
done
[[ -n "${output}" && "${url}" == https://cats.run/healthz ]]
if [[ "${MOCK_HEALTH_FAIL:-false}" == true ]]; then exit 7; fi
printf ok >"${output}"
printf 200
MOCK
chmod 0700 "${MOCK_BIN}/curl"

common=(env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_STATE="${MOCK_STATE}"
  Q124_RUN_ID=contract-worker-boundary Q124_WINDOW_NONCE=0123456789abcdef0123456789abcdef
  "${HOOK}" probe --scenario control-plane --trial control-plane-running
  --workspace-id ws_788c5bfc3931 --node-id q124-20260805000000-abcdef
  --address 192.0.2.124 --port 443)

"${common[@]}"
[[ ! -e /etc/cats/worker.env ]]
[[ "$(wc -l <"${MOCK_STATE}/curl-argv.log")" == 1 ]]
grep -Fq 'https://cats.run/healthz' "${MOCK_STATE}/curl-argv.log"
! grep -Fq "${ADMIN_SENTINEL}" "${MOCK_STATE}/curl-argv.log"
! grep -Fq "${SERVICE_SENTINEL}" "${MOCK_STATE}/curl-argv.log"
printf 'public-health-probe-no-capability\tPASS\n'

set +e; MOCK_HEALTH_FAIL=true "${common[@]}" >/dev/null 2>&1; health_rc=$?; set -e
[[ "${health_rc}" -ne 0 ]]
printf 'public-health-disconnect-failure-closed\tPASS\n'

# Former administrator entry points remain unavailable even if an old global
# token file is accidentally left on the worker.
before_curl="$(wc -l <"${MOCK_STATE}/curl-argv.log")"
for action in get cats cordon uncordon ensure-cordoned prepare-trial observe-window; do
  set +e
  env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_STATE="${MOCK_STATE}" \
    Q124_RUN_ID="contract-reject-${action}" Q124_WINDOW_NONCE=0123456789abcdef0123456789abcdef \
    "${HOOK}" "${action}" --scenario control-plane --trial control-plane-running \
      --workspace-id ws_788c5bfc3931 --node-id q124-20260805000000-abcdef \
      >/dev/null 2>&1
  action_rc=$?
  set -e
  [[ "${action_rc}" -ne 0 ]]
done
[[ "$(wc -l <"${MOCK_STATE}/curl-argv.log")" == "${before_curl}" ]]
printf 'legacy-admin-entrypoints-rejected\tPASS\n'

# Static boundary: no global administrator capability, admin endpoint, control
# mutation, systemd watchdog, or arbitrary remote Node-agent origin remains.
! rg -n 'ADMIN_TOKEN|TOKEN_FILE|/v1/admin/|/actions/(cordon|uncordon|start|stop|sync)' "${HOOK}" >/dev/null
! rg -n 'systemd-run|systemctl' "${HOOK}" >/dev/null
[[ "$(rg -c 'NODE_AGENT_ORIGIN="http://127[.]0[.]0[.]1:7301"' "${HOOK}")" == 1 ]]
[[ "$(rg -c '"\$\{NODE_AGENT_ORIGIN\}\$\{path\}"' "${HOOK}")" == 1 ]]
! grep -R -Fq "${ADMIN_SENTINEL}" "${CONTRACT_ROOT}"
! grep -R -Fq "${SERVICE_SENTINEL}" "${CONTRACT_ROOT}"
printf 'worker-capability-boundary\tPASS\n'

printf 'result=PASS workload_hook_contracts=4\n'
