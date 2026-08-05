#!/usr/bin/env bash
set -euo pipefail

# Linux-only, non-networking mock acceptance for the embedded remote helper.
# Run as root in a disposable container. No AWS command is present.

[[ "$(uname -s)" == Linux ]] || { echo "Linux is required" >&2; exit 2; }
[[ "${EUID}" == 0 ]] || { echo "root in a disposable container is required" >&2; exit 2; }
for command in jq sha256sum flock gzip openssl; do command -v "${command}" >/dev/null; done

HARNESS="${1:-test-results/qualification-20260805/temp-node-faults.sh}"
[[ -f "${HARNESS}" ]]
TEST_ROOT="$(mktemp -d /tmp/cats-q124-fault-linux-mock.XXXXXX)"
MOCK_BIN="${TEST_ROOT}/bin"
MOCK_ROOT="${TEST_ROOT}/state"
REMOTE="${TEST_ROOT}/remote.sh"
CONFIG="${TEST_ROOT}/fault-targets.json"
HOOK="${TEST_ROOT}/q124-fault-workload"
mkdir -p "${MOCK_BIN}" "${MOCK_ROOT}"
trap 'rm -rf "${TEST_ROOT}"' EXIT

awk '/^  cat <<'"'"'Q124_REMOTE'"'"'$/ {copy=1; next} copy && /^Q124_REMOTE$/ {exit} copy {print}' \
  "${HARNESS}" >"${REMOTE}"
chmod 0700 "${REMOTE}"

cat >"${CONFIG}" <<'JSON'
{"schema_version":1,"db_host":"fixture.cluster.us-east-1.rds.amazonaws.com","db_port":5432,
 "s3_host":"s3.us-east-1.amazonaws.com","s3_port":443,
 "control_plane_host":"api.cats.run","control_plane_port":443,
 "node_listen_ip":"10.0.0.124","node_listen_port":7301,
 "fault_duration_seconds":5,"control_plane_lease_timeout_seconds":5}
JSON
chmod 0600 "${CONFIG}"

cat >"${MOCK_BIN}/xtables-mock" <<'MOCK'
#!/usr/bin/env bash
set -u
name="$(basename "$0")"
family=4
[[ "${name}" != ip6tables && "${name}" != ip6tables-save ]] || family=6
state="${MOCK_ROOT}/rules${family}"
count_file="${MOCK_ROOT}/xtables-count"
mkdir -p "${MOCK_ROOT}"; touch "${state}"

if [[ "${name}" == *-save ]]; then
  if [[ -f "${MOCK_ROOT}/fail-save-next" ]]; then
    rm -f "${MOCK_ROOT}/fail-save-next"
    exit 4
  fi
  cat "${state}"
  exit 0
fi

count=0; [[ ! -f "${count_file}" ]] || count="$(<"${count_file}")"
count=$((count + 1)); printf '%s' "${count}" >"${count_file}"
if [[ -n "${MOCK_XTABLES_FAIL_AT:-}" && "${count}" == "${MOCK_XTABLES_FAIL_AT}" ]]; then exit 4; fi

args=" $* "
if [[ "${args}" == *" -N "* ]]; then
  chain="${*: -1}"
  grep -Fq ":${chain} " "${state}" && exit 1
  printf ':%s - [0:0]\n' "${chain}" >>"${state}"
elif [[ "${args}" == *" -I OUTPUT "* ]]; then
  comment=""; chain="${*: -1}"
  while (($#)); do [[ "$1" != --comment ]] || { shift; comment="$1"; }; shift || true; done
  printf -- '-A OUTPUT -m comment --comment "%s" -j %s\n' "${comment}" "${chain}" >>"${state}"
elif [[ "${args}" == *" -I INPUT "* ]]; then
  comment=""; chain="${*: -1}"
  while (($#)); do [[ "$1" != --comment ]] || { shift; comment="$1"; }; shift || true; done
  printf -- '-A INPUT -m comment --comment "%s" -j %s\n' "${comment}" "${chain}" >>"${state}"
elif [[ "${args}" == *" -A "* ]]; then
  chain=""; comment=""; destination=""; port=""
  while (($#)); do
    case "$1" in
      -A) shift; chain="$1" ;;
      -d) shift; destination="$1" ;;
      --dport) shift; port="$1" ;;
      --comment) shift; comment="$1" ;;
    esac
    shift || true
  done
  printf -- '-A %s -d %s --dport %s -m comment --comment "%s" -j REJECT\n' \
    "${chain}" "${destination:--}" "${port}" "${comment}" >>"${state}"
elif [[ "${args}" == *" -D OUTPUT "* || "${args}" == *" -D INPUT "* ]]; then
  builtin=OUTPUT; [[ "${args}" != *" -D INPUT "* ]] || builtin=INPUT
  chain="${*: -1}"
  awk -v needle="-A ${builtin} " -v chain="-j ${chain}" \
    'BEGIN{done=0} !done && index($0,needle)==1 && index($0,chain)>0 {done=1;next} {print}' \
    "${state}" >"${state}.new" && mv "${state}.new" "${state}"
elif [[ "${args}" == *" -F "* ]]; then
  chain="${*: -1}"
  awk -v needle="-A ${chain} " 'index($0,needle)!=1' "${state}" >"${state}.new" && mv "${state}.new" "${state}"
elif [[ "${args}" == *" -X "* ]]; then
  chain="${*: -1}"
  awk -v needle=":${chain} " 'index($0,needle)!=1' "${state}" >"${state}.new" && mv "${state}.new" "${state}"
elif [[ "${args}" == *" -nvxL "* ]]; then
  chain="${*: -1}"
  grep -Fq ":${chain} " "${state}" || exit 1
  packet_file="${MOCK_ROOT}/packets-${family}-${chain}"
  packets=0; [[ ! -f "${packet_file}" ]] || packets="$(<"${packet_file}")"
  printf 'Chain %s (0 references)\n pkts bytes target prot opt in out source destination\n%s 0 REJECT tcp -- * * 0.0.0.0/0 0.0.0.0/0\n' "${chain}" "${packets}"
fi
MOCK
chmod 0700 "${MOCK_BIN}/xtables-mock"
for name in iptables iptables-save ip6tables ip6tables-save; do ln -s xtables-mock "${MOCK_BIN}/${name}"; done

cat >"${MOCK_BIN}/timeout" <<'MOCK'
#!/usr/bin/env bash
address="${@: -2:1}"; port="${@: -1}"; blocked=0
for state in "${MOCK_ROOT}"/rules4 "${MOCK_ROOT}"/rules6; do
  [[ -f "${state}" ]] || continue; family="${state##*rules}"
  while IFS= read -r chain; do
    [[ -n "${chain}" ]] || continue
    packet_file="${MOCK_ROOT}/packets-${family}-${chain}"
    packets=0; [[ ! -f "${packet_file}" ]] || packets="$(<"${packet_file}")"
    printf '%s' "$((packets + 1))" >"${packet_file}"; blocked=1
  done < <(awk -v address="${address}" -v port="${port}" '
    $1=="-A" && $0 ~ ("--dport " port " ") && ($0 ~ ("-d " address "/") || $0 ~ "-d - ") {print $2}
  ' "${state}")
done
(( blocked == 0 ))
MOCK

cat >"${MOCK_BIN}/getent" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  ahostsv4)
    case "$2" in
      *.rds.amazonaws.com) address=192.0.2.124 ;;
      s3.*.amazonaws.com|*.s3.*.amazonaws.com) address=192.0.2.125 ;;
      *) address=192.0.2.126 ;;
    esac
    printf '%s STREAM %s\n' "${address}" "$2"
    ;;
  ahostsv6)
    case "$2" in
      *.rds.amazonaws.com) address=2001:db8::124 ;;
      s3.*.amazonaws.com|*.s3.*.amazonaws.com) address=2001:db8::125 ;;
      *) address=2001:db8::126 ;;
    esac
    [[ "${MOCK_IPV6_EMPTY:-false}" == true ]] || printf '%s STREAM %s\n' "${address}" "$2"
    ;;
esac
MOCK

cat >"${MOCK_BIN}/ip" <<'MOCK'
#!/usr/bin/env bash
case " $* " in
  *" -6 route show default "*) [[ "${MOCK_IPV6_ROUTABLE:-false}" == true ]] && echo 'default via 2001:db8::1 dev eth0' ;;
  *" -4 route get "*|*" -6 route get "*) echo 'mock route' ;;
  *" -4 -o addr show scope global "*) echo '2: eth0 inet 10.0.0.124/24 scope global eth0' ;;
esac
MOCK

cat >"${MOCK_BIN}/systemd-run" <<'MOCK'
#!/usr/bin/env bash
unit=""; previous=""
for arg in "$@"; do [[ "${previous}" != --unit ]] || unit="${arg}"; previous="${arg}"; done
[[ -n "${unit}" ]] || { for arg in "$@"; do [[ "${arg}" != --unit=* ]] || unit="${arg#--unit=}"; done; }
cleanup="${*: -1}"
touch "${MOCK_ROOT}/${unit}.timer"
(
  exec 9>&- 2>/dev/null || true
  sleep "${MOCK_WATCHDOG_DELAY_SECONDS:-15}"
  [[ ! -f "${MOCK_ROOT}/${unit}.timer" ]] || bash "${cleanup}" >/dev/null 2>&1 || true
) &
exit 0
MOCK

cat >"${MOCK_BIN}/systemctl" <<'MOCK'
#!/usr/bin/env bash
case "$1" in
  is-active) unit="${*: -1}"; [[ -f "${MOCK_ROOT}/${unit}" ]] ;;
  stop) rm -f "${MOCK_ROOT}/$2" ;;
  reset-failed) exit 0 ;;
esac
MOCK
chmod 0700 "${MOCK_BIN}/timeout" "${MOCK_BIN}/getent" "${MOCK_BIN}/ip" \
  "${MOCK_BIN}/systemd-run" "${MOCK_BIN}/systemctl"

cat >"${HOOK}" <<'MOCK'
#!/usr/bin/env bash
set -euo pipefail
command="$1"; shift
scenario=""; phase=""; output=""; node=""; instance=""; address=""; port=""
restored=""; remaining=""
while (($#)); do
  case "$1" in
    --scenario) shift; scenario="$1" ;; --phase) shift; phase="$1" ;;
    --output) shift; output="$1" ;; --node-id) shift; node="$1" ;;
    --instance-id) shift; instance="$1" ;;
    --address) shift; address="$1" ;; --port) shift; port="$1" ;;
    --restored-dependency) shift; restored="$1" ;;
    --remaining-dependencies) shift; remaining="$1" ;;
    --dependency|--dependencies|--recovery-order) shift ;;
  esac
  shift
done
now="$(date -u +%FT%TZ)"
case "${command}" in
  ensure-cordoned)
    jq -n --arg node "${node}" --arg now "${now}" '{schema_version:1,operation_id:"op_mock_cordon",
      kind:"ensure_node_cordoned",phase:"succeeded",node_id:$node,started_at:$now,
      completed_at:$now,log_ref:"journal://q124/mock/cordon"}' >"${output}"
    ;;
  snapshot)
    jq -n --arg instance "${instance}" --arg node "${node}" --arg now "${now}" \
      --arg test_sha "${Q124_TEST_SHA}" --arg scenario "${scenario}" '
      {schema_version:1,captured_at:$now,temp_instance_id:$instance,node_id:$node,node_state:"Cordoned",
       workspace_id:"ws_788c5bfc3931",workspace:"default/qual-124-20260805",
       tags:{Issue:"124",CatsNodeId:$node,Purpose:"qualification-124"},orphans:0,
       assigned_cats:(if ($scenario | contains("s3")) then
         [{cat_id:"cat_mock_strict",name:"q124-mock-strict",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"strict"},
          {cat_id:"cat_mock_relaxed",name:"q124-mock-relaxed",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"relaxed"}]
         else [{cat_id:"cat_mock_q124",name:"q124-mock-cat",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"strict"}] end),
       test_sha:$test_sha,dependency_endpoints:{db_host:"fixture.cluster.us-east-1.rds.amazonaws.com",
         s3_host:"s3.us-east-1.amazonaws.com",control_plane_host:"api.cats.run",node_listen_ip:"10.0.0.124"}}' >"${output}"
    if [[ "${MOCK_SECRET_EXTRA:-false}" == true ]]; then
      jq '.password="should-have-been-rejected"' "${output}" >"${output}.bad" && mv "${output}.bad" "${output}"
    fi
    ;;
  probe)
    blocked=0
    for state in "${MOCK_ROOT}"/rules4 "${MOCK_ROOT}"/rules6; do
      [[ -f "${state}" ]] || continue; family="${state##*rules}"
      while IFS= read -r chain; do
        [[ -n "${chain}" ]] || continue; packet_file="${MOCK_ROOT}/packets-${family}-${chain}"
        packets=0; [[ ! -f "${packet_file}" ]] || packets="$(<"${packet_file}")"
        printf '%s' "$((packets + 1))" >"${packet_file}"; blocked=1
      done < <(awk -v address="${address}" -v port="${port}" '
        $1=="-A" && $0 ~ ("--dport " port " ") && $0 ~ ("-d " address "/") {print $2}
      ' "${state}")
    done
    (( blocked == 0 ))
    ;;
  state)
    digest="sha256:mock"
    if [[ "${MOCK_LARGE_EVIDENCE:-false}" == true ]]; then
      [[ -f "${MOCK_ROOT}/large-digest" ]] || openssl rand -hex 12000 >"${MOCK_ROOT}/large-digest"
      digest="sha256:$(<"${MOCK_ROOT}/large-digest")"
    fi
    jq -n --arg scenario "${scenario}" --arg phase "${phase}" --arg node "${node}" --arg now "${now}" \
      --arg digest "${digest}" '
      def cat($id;$name;$durability;$digest):
        {cat_id:$id,cat_name:$name,durability:$durability,desired_state:"running",
         observed_state:(if $phase=="during" then "unknown" else "running" end),generation:7,node_id:$node,
         operation_ids:["op_mock_fault"],watermark:{local:11,remote:11,unpublished:0},disk_epoch:3,digest:$digest};
      {schema_version:1,captured_at:$now,phase:$phase,scenario:$scenario,
       workspace_id:"ws_788c5bfc3931",node_id:$node,
       cats:(if ($scenario | contains("s3")) then
         [cat("cat_mock_strict";"q124-mock-strict";"strict";($digest + "-strict")),
          cat("cat_mock_relaxed";"q124-mock-relaxed";"relaxed";($digest + "-relaxed"))]
         else [cat("cat_mock_q124";"q124-mock-cat";"strict";$digest)] end),
       raw_operations:[{operation_id:"op_mock_fault",kind:"mock_fault",phase:"succeeded",started_at:$now,completed_at:$now,log_ref:"journal://q124/mock/op"}],
       log_refs:["journal://q124/mock/state"]}' >"${output}"
    ;;
  exercise)
    for state in "${MOCK_ROOT}"/rules4 "${MOCK_ROOT}"/rules6; do
      [[ -f "${state}" ]] || continue; family="${state##*rules}"
      while IFS= read -r chain; do
        [[ -n "${chain}" ]] || continue; packet_file="${MOCK_ROOT}/packets-${family}-${chain}"
        packets=0; [[ ! -f "${packet_file}" ]] || packets="$(<"${packet_file}")"
        printf '%s' "$((packets + 3))" >"${packet_file}"
      done < <(awk '$1=="-A" && $0 ~ /-j REJECT/ {print $2}' "${state}" | sort -u)
    done
    [[ "${MOCK_ARM_SAVE_FAILURE:-false}" != true || "${phase}" != isolated ]] || touch "${MOCK_ROOT}/fail-save-next"
    [[ "${MOCK_PAUSE_EXERCISE:-false}" != true || "${phase}" != isolated ]] || { touch "${MOCK_ROOT}/exercise-paused"; sleep "${MOCK_PAUSE_SECONDS:-3}"; }
    if [[ "${phase}" == partial-recovery ]]; then
      if [[ -n "${remaining}" ]]; then remaining_json="$(printf '%s' "${remaining}" | jq -R 'split(",")')"; else remaining_json='[]'; fi
      jq -n --arg scenario "${scenario}" --arg dep "${restored}" --argjson remaining "${remaining_json}" --arg now "${now}" '
        {schema_version:1,scenario:$scenario,phase:"partial-recovery",restored_dependency:$dep,
         remaining_dependencies:$remaining,started_at:$now,completed_at:$now,
         checks:{restored_dependency_positive:true,remaining_dependencies_negative:true,false_success_absent:true,
           digest_preserved:true,generation_preserved:true,disk_epoch_preserved:true},
         raw_operations:[{operation_id:"op_mock_partial_recovery",kind:"mock_partial_recovery",phase:"succeeded",
           started_at:$now,completed_at:$now,log_ref:"journal://q124/mock/partial-recovery"}],
         log_refs:["journal://q124/mock/partial-recovery"]}' >"${output}"
      exit 0
    elif [[ "${scenario}" == db && "${phase}" == isolated ]]; then
      checks='{"running_exec_observed":true,"metadata_cas_false_success_absent":true,"sync_false_success_absent":true,"cold_false_success_absent":true,"start_retry_or_failure_observed":true,"new_start_retry_or_failure_observed":true,"corruption_absent":true}'
    elif [[ "${scenario}" == db ]]; then checks='{"dependency_reconnected":true,"pending_operations_converged":true,"digest_verified":true}'
    elif [[ "${scenario}" == db-s3 && "${phase}" == isolated ]]; then checks='{"simultaneous_window_confirmed":true,"db_false_success_absent":true,"s3_strict_false_success_absent":true,"s3_relaxed_false_success_absent":true,"digests_unchanged":true}'
    elif [[ "${scenario}" == db-s3 ]]; then checks='{"recovery_order_exact":true,"db_reconnected":true,"s3_converged":true,"final_digests_verified":true,"generation_preserved":true,"disk_epoch_preserved":true}'
    elif [[ "${scenario}" == db-control-plane && "${phase}" == isolated ]]; then checks='{"simultaneous_window_confirmed":true,"db_false_success_absent":true,"node_lost_without_fence":true,"generation_replacement_absent":true,"epoch_replacement_absent":true,"digest_unchanged":true}'
    elif [[ "${scenario}" == db-control-plane ]]; then checks='{"recovery_order_exact":true,"control_plane_same_identity":true,"db_reconnected":true,"final_digest_verified":true,"generation_preserved":true,"disk_epoch_preserved":true}'
    elif [[ "${scenario}" == s3-control-plane && "${phase}" == isolated ]]; then checks='{"simultaneous_window_confirmed":true,"s3_strict_false_success_absent":true,"s3_relaxed_false_success_absent":true,"node_lost_without_fence":true,"generation_replacement_absent":true,"epoch_replacement_absent":true,"digests_unchanged":true}'
    elif [[ "${scenario}" == s3-control-plane ]]; then checks='{"recovery_order_exact":true,"control_plane_same_identity":true,"s3_converged":true,"final_digests_verified":true,"generation_preserved":true,"disk_epoch_preserved":true}'
    elif [[ "${scenario}" == all-3 && "${phase}" == isolated ]]; then checks='{"simultaneous_window_confirmed":true,"db_false_success_absent":true,"s3_strict_false_success_absent":true,"s3_relaxed_false_success_absent":true,"node_lost_without_fence":true,"generation_replacement_absent":true,"epoch_replacement_absent":true,"digests_unchanged":true}'
    elif [[ "${scenario}" == all-3 ]]; then checks='{"recovery_order_exact":true,"control_plane_same_identity":true,"db_reconnected":true,"s3_converged":true,"final_digests_verified":true,"generation_preserved":true,"disk_epoch_preserved":true}'
    else exit 2; fi
    jq -n --arg scenario "${scenario}" --arg phase "${phase}" --arg now "${now}" --argjson checks "${checks}" '
      {schema_version:1,scenario:$scenario,phase:$phase,started_at:$now,completed_at:$now,checks:$checks,
       raw_operations:[{operation_id:"op_mock_fault",kind:"mock_exercise",phase:"succeeded",started_at:$now,completed_at:$now,log_ref:"journal://q124/mock/exercise"}],
       log_refs:["journal://q124/mock/oracle"]}' >"${output}"
    ;;
  assert) ;;
esac
MOCK
chmod 0700 "${HOOK}"

run_remote() {
  local run_id="$1" scenario="${2:-db}"
  shift
  if (($#)); then shift; fi
  local -a remote_env
  local cat_set_sha
  (($# == 0))
  cat_set_sha="$(jq -Sc --arg scenario "${scenario}" --arg node q124-20260805000000-abcdef -n '
    if ($scenario | contains("s3")) then
      [{cat_id:"cat_mock_strict",name:"q124-mock-strict",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"strict"},
       {cat_id:"cat_mock_relaxed",name:"q124-mock-relaxed",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"relaxed"}]
    else [{cat_id:"cat_mock_q124",name:"q124-mock-cat",workspace_id:"ws_788c5bfc3931",node_id:$node,durability:"strict"}] end |
    sort_by(.cat_id)' | sha256sum | awk '{print $1}')"
  printf '%s' "${cat_set_sha}" >"${MOCK_ROOT}/expected-cat-set-sha"
  remote_env=(env PATH="${MOCK_BIN}:/usr/sbin:/usr/bin:/sbin:/bin" MOCK_ROOT="${MOCK_ROOT}" \
    MOCK_XTABLES_FAIL_AT="${MOCK_XTABLES_FAIL_AT:-}" MOCK_IPV6_ROUTABLE="${MOCK_IPV6_ROUTABLE:-false}" \
    MOCK_IPV6_EMPTY="${MOCK_IPV6_EMPTY:-false}" MOCK_SECRET_EXTRA="${MOCK_SECRET_EXTRA:-false}" \
    MOCK_ARM_SAVE_FAILURE="${MOCK_ARM_SAVE_FAILURE:-false}" MOCK_PAUSE_EXERCISE="${MOCK_PAUSE_EXERCISE:-false}" \
    MOCK_PAUSE_SECONDS="${MOCK_PAUSE_SECONDS:-3}" \
    MOCK_LARGE_EVIDENCE="${MOCK_LARGE_EVIDENCE:-false}" \
    MOCK_WATCHDOG_DELAY_SECONDS="${MOCK_WATCHDOG_DELAY_SECONDS:-15}" \
    Q124_RUN_ID="${run_id}" Q124_SCENARIO="${scenario}" Q124_INSTANCE_ID=i-0123456789abcdef0 \
    Q124_NODE_ID=q124-20260805000000-abcdef Q124_WORKSPACE_ID=ws_788c5bfc3931 \
    Q124_CONFIG_REF="${CONFIG}" Q124_HOOK_REF="${HOOK}" \
    Q124_TEST_SHA=1111111111111111111111111111111111111111 \
    Q124_CONFIG_SHA256="$(sha256sum "${CONFIG}" | awk '{print $1}')" \
    Q124_HOOK_SHA256="$(sha256sum "${HOOK}" | awk '{print $1}')" \
    Q124_HARNESS_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    Q124_HELPER_SHA256="$(sha256sum "${REMOTE}" | awk '{print $1}')" \
    Q124_CAT_SET_SHA256="${cat_set_sha}" \
    "${REMOTE}")
  if [[ "${MOCK_EXEC_REMOTE:-false}" == true ]]; then exec "${remote_env[@]}"; else "${remote_env[@]}"; fi
}

reset_mock() {
  rm -rf "${MOCK_ROOT}" /run/cats-q124-fault-mock-* 2>/dev/null || true
  mkdir -p "${MOCK_ROOT}"
}

pass=0
case_result() { printf '%s\t%s\n' "$1" "$2"; pass=$((pass + 1)); }
wait_for_file() {
  local file="$1"
  for _ in $(seq 1 200); do [[ -f "${file}" ]] && return 0; sleep 0.05; done
  return 1
}
assert_rules_absent() {
  if grep -Rq 'cats-q124-' "${MOCK_ROOT}"/rules* 2>/dev/null; then return 1; fi
}

reset_mock
run_remote mock-happy >"${TEST_ROOT}/happy.log" 2>&1 || { cat "${TEST_ROOT}/happy.log" >&2; exit 1; }
assert_rules_absent
sed -n 's/^Q124_STATE_AFTER=//p' "${TEST_ROOT}/happy.log" | openssl base64 -d -A | gzip -d |
  jq -e '.schema_version == 1 and .phase == "after"' >/dev/null
case_result happy PASS

reset_mock
set +e; MOCK_XTABLES_FAIL_AT=2 run_remote mock-partial >"${TEST_ROOT}/partial.log" 2>&1; rc=$?; set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
case_result partial-create PASS

reset_mock
set +e; MOCK_ARM_SAVE_FAILURE=true run_remote mock-save-fail >"${TEST_ROOT}/save-fail.log" 2>&1; rc=$?; set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
grep -q 'iptables-save-failed' /run/cats-q124-fault-mock-save-fail/cleanup-errors.log || {
  cat "${TEST_ROOT}/save-fail.log" >&2; exit 1;
}
grep -q '^Q124_RESULT functional_rc=0 cleanup_rc=70$' "${TEST_ROOT}/save-fail.log"
case_result save-failure-ledger PASS

reset_mock
MOCK_PAUSE_EXERCISE=true MOCK_EXEC_REMOTE=true run_remote mock-term >"${TEST_ROOT}/term.log" 2>&1 & pid=$!
wait_for_file "${MOCK_ROOT}/exercise-paused" || { cat "${TEST_ROOT}/term.log" >&2; exit 1; }
kill -TERM "${pid}"; set +e; wait "${pid}"; set -e
assert_rules_absent
case_result term-trap PASS

reset_mock
MOCK_PAUSE_EXERCISE=true MOCK_ARM_SAVE_FAILURE=true MOCK_WATCHDOG_DELAY_SECONDS=1 \
  MOCK_EXEC_REMOTE=true run_remote mock-kill >"${TEST_ROOT}/kill.log" 2>&1 & pid=$!
wait_for_file "${MOCK_ROOT}/exercise-paused" || { cat "${TEST_ROOT}/kill.log" >&2; exit 1; }
kill -KILL "${pid}"; set +e; wait "${pid}"; set -e
for _ in $(seq 1 80); do
  assert_rules_absent && grep -q 'iptables-save-failed' /run/cats-q124-fault-mock-kill/cleanup-errors.log 2>/dev/null && break
  sleep 0.05
done
assert_rules_absent
grep -q 'iptables-save-failed' /run/cats-q124-fault-mock-kill/cleanup-errors.log
case_result kill-ssm-interruption-watchdog-retry PASS
sleep 4

reset_mock
set +e; MOCK_IPV6_ROUTABLE=true MOCK_IPV6_EMPTY=true run_remote mock-ipv6-empty >"${TEST_ROOT}/ipv6.log" 2>&1; rc=$?; set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
case_result ipv6-empty PASS

reset_mock
run_remote mock-duplicate >"${TEST_ROOT}/duplicate-first.log"
set +e; run_remote mock-duplicate >"${TEST_ROOT}/duplicate-second.log" 2>&1; rc=$?; set -e
[[ "${rc}" -ne 0 ]]
case_result duplicate-run-id PASS

reset_mock
set +e; MOCK_SECRET_EXTRA=true run_remote mock-secret >"${TEST_ROOT}/secret.log" 2>&1; rc=$?; set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
grep -q '^Q124_RESULT functional_rc=72 cleanup_rc=0$' "${TEST_ROOT}/secret.log" || {
  cat "${TEST_ROOT}/secret.log" >&2; exit 1;
}
grep -q 'unsafe evidence was rejected before SSM emission' "${TEST_ROOT}/secret.log" || {
  cat "${TEST_ROOT}/secret.log" >&2; exit 1;
}
if grep -q '^Q124_OWNERSHIP_' "${TEST_ROOT}/secret.log"; then exit 1; fi
case_result secret-extra-field PASS

assert_combo_evidence() {
  local run_id="$1" expected_count="$2" state_dir
  state_dir="/run/cats-q124-fault-${run_id}"
  jq -e --argjson count "${expected_count}" '
    .mode == "simultaneous" and (.dependencies | length) == $count and
    ([.dependencies[].comment] | unique | length) == $count and
    ([.dependencies[].watchdog_unit] | unique | length) == $count and
    ([.dependencies[].chains[]] | unique | length) == ($count * 4)
  ' "${state_dir}/combination-provenance.json" >/dev/null
  [[ "$(jq 'length' "${state_dir}/recovery-steps.json")" == "${expected_count}" ]]
  [[ "$(awk -F '\t' 'NR > 1 && $3 == "injected" {n++} END {print n+0}' "${state_dir}/combination-order.tsv")" == "${expected_count}" ]]
  [[ "$(awk -F '\t' 'NR > 1 && $3 == "restored" {n++} END {print n+0}' "${state_dir}/combination-order.tsv")" == "${expected_count}" ]]
  [[ "$(awk -F '\t' 'NR > 1 && $3 == "isolated-verified" {n++} END {print n+0}' "${state_dir}/combination-order.tsv")" == 1 ]]
  [[ "$(awk -F '\t' 'NR > 1 && $3 == "recovered-verified" {n++} END {print n+0}' "${state_dir}/combination-order.tsv")" == 1 ]]
}

for combo_case in db-s3 db-control-plane s3-control-plane all-3; do
  reset_mock
  run_id="mock-combo-${combo_case}"
  run_remote "${run_id}" "${combo_case}" >"${TEST_ROOT}/${combo_case}.log" 2>&1 || {
    cat "${TEST_ROOT}/${combo_case}.log" >&2; exit 1;
  }
  assert_rules_absent
  expected_count=2; [[ "${combo_case}" != all-3 ]] || expected_count=3
  assert_combo_evidence "${run_id}" "${expected_count}"
  if [[ "${combo_case}" == all-3 ]]; then
    (( $(wc -c <"${TEST_ROOT}/${combo_case}.log") < 22000 ))
  fi
  case_result "combo-${combo_case}" PASS
done

reset_mock
set +e
MOCK_XTABLES_FAIL_AT=7 run_remote mock-combo-partial all-3 >"${TEST_ROOT}/combo-partial.log" 2>&1
rc=$?
set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
case_result combo-partial-create-cleanup PASS

reset_mock
set +e
MOCK_ARM_SAVE_FAILURE=true run_remote mock-combo-save-fail all-3 >"${TEST_ROOT}/combo-save-fail.log" 2>&1
rc=$?
set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
grep -q '^Q124_RESULT functional_rc=0 cleanup_rc=70$' "${TEST_ROOT}/combo-save-fail.log"
grep -q '^dependency-' /run/cats-q124-fault-mock-combo-save-fail/cleanup-errors.log
case_result combo-save-failure-ledger PASS

reset_mock
MOCK_PAUSE_EXERCISE=true MOCK_WATCHDOG_DELAY_SECONDS=1 MOCK_EXEC_REMOTE=true \
  run_remote mock-combo-kill all-3 >"${TEST_ROOT}/combo-kill.log" 2>&1 & pid=$!
wait_for_file "${MOCK_ROOT}/exercise-paused" || { cat "${TEST_ROOT}/combo-kill.log" >&2; exit 1; }
kill -KILL "${pid}"; set +e; wait "${pid}"; set -e
for _ in $(seq 1 80); do assert_rules_absent && break; sleep 0.05; done
assert_rules_absent
case_result combo-kill-independent-watchdogs PASS
sleep 4

reset_mock
set +e
MOCK_LARGE_EVIDENCE=true run_remote mock-transport-budget >"${TEST_ROOT}/transport-budget.log" 2>&1
rc=$?
set -e
[[ "${rc}" -ne 0 ]] && assert_rules_absent
grep -q '^Q124_RESULT functional_rc=73 cleanup_rc=0$' "${TEST_ROOT}/transport-budget.log" || {
  cat "${TEST_ROOT}/transport-budget.log" >&2; exit 1;
}
grep -q 'compressed evidence exceeds the safe SSM stdout budget' "${TEST_ROOT}/transport-budget.log" || {
  cat "${TEST_ROOT}/transport-budget.log" >&2; exit 1;
}
if grep -q '^Q124_STATE_' "${TEST_ROOT}/transport-budget.log"; then exit 1; fi
case_result transport-budget-fail-closed PASS

printf 'result=PASS linux_mock_cases=%s evidence=%s\n' "${pass}" "${TEST_ROOT}"
