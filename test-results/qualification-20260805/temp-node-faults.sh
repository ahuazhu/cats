#!/usr/bin/env bash
set -euo pipefail

# Issue #124 temporary-node dependency-fault harness. The default is a
# non-mutating dry run. Live mode targets one explicit EC2 instance through SSM;
# tags are assertions and are never used as mutation selectors.

MODE="${CATS_FAULT_MODE:-dry-run}"
SCENARIO="${CATS_FAULT_SCENARIO:-db}"
ALLOW_ALL="${CATS_FAULT_ALLOW_ALL:-false}"
AWS_REGION="${AWS_REGION:-us-east-1}"
EXPECTED_ACCOUNT_ID="869621413820"
SOURCE_INSTANCE_ID="i-0b9ba48168ed092fc"
TEMP_INSTANCE_ID="${TEMP_INSTANCE_ID:-}"
NODE_ID="${NODE_ID:-}"
ISSUE="${CATS_ISSUE:-124}"
WORKSPACE_ID="${CATS_WORKSPACE_ID:-ws_788c5bfc3931}"
WORKSPACE="${CATS_WORKSPACE:-default/qual-124-20260805}"
OWNERSHIP_SNAPSHOT="${CATS_OWNERSHIP_SNAPSHOT:-}"
PROVISIONING_MANIFEST="${CATS_PROVISIONING_MANIFEST:-}"
REMOTE_CONFIG="${CATS_REMOTE_FAULT_CONFIG:-/etc/cats/qualification-124/fault-targets.json}"
REMOTE_HOOK="${CATS_REMOTE_WORKLOAD_HOOK:-/usr/local/libexec/cats/q124-fault-workload}"
RUN_ID="${CATS_FAULT_RUN_ID:-$(date -u +%Y%m%dT%H%M%SZ)-$(openssl rand -hex 3)}"
RESULT_ROOT="${CATS_FAULT_RESULT_ROOT:-test-results/qualification-20260805/raw/temp-node-faults}"
RUN_DIR="${RESULT_ROOT}/${RUN_ID}"
SSM_TIMEOUT_SECONDS="${CATS_FAULT_SSM_TIMEOUT_SECONDS:-900}"
LIVE_CONFIRM="${CATS_FAULT_CONFIRM:-}"
HARNESS_SHA256="$(shasum -a 256 "$0" | awk '{print $1}')"

die() {
  printf 'error: %s\n' "$*" >&2
  exit 2
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command is unavailable: $1"
}

contains_secret_like() {
  LC_ALL=C grep -Eiq 'authorization:|proxy-authorization:|bearer[[:space:]]|set-cookie:|cookie:|x-amz-security-token|aws_(access_key|secret_access_key|session_token)|(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}|password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|client_secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]|token[[:space:]]*[:=]|worker[.]env|BEGIN ([A-Z ]+ )?PRIVATE KEY|postgres(ql)?://[^[:space:]:]+:[^[:space:]@]+@|eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.]'
}

validate_ref() {
  local label="$1" value="$2"
  [[ "${value}" =~ ^/[A-Za-z0-9._/-]+$ ]] || die "${label} must be an absolute safe path"
  [[ "${value}" != *".."* ]] || die "${label} cannot contain .."
  case "${value,,}" in
    *token*|*password*|*secret*|*worker.env*)
      die "${label} must reference non-secret tooling/config, not secret material"
      ;;
  esac
}

validate_inputs() {
  [[ "${TEMP_INSTANCE_ID}" =~ ^i-[0-9a-f]{17}$ ]] ||
    die "TEMP_INSTANCE_ID must be one exact modern EC2 instance ID"
  [[ "${TEMP_INSTANCE_ID}" != "${SOURCE_INSTANCE_ID}" ]] ||
    die "TEMP_INSTANCE_ID must never be the fixed production source worker"
  [[ "${NODE_ID}" =~ ^q124-[a-z0-9-]{8,55}$ ]] ||
    die "NODE_ID must be one exact q124-* temporary Node ID"
  [[ "${ISSUE}" == "124" ]] || die "CATS_ISSUE must be exactly 124"
  [[ "${WORKSPACE_ID}" == "ws_788c5bfc3931" ]] ||
    die "CATS_WORKSPACE_ID must be the qualification workspace ID"
  [[ "${WORKSPACE}" == "default/qual-124-20260805" ]] ||
    die "CATS_WORKSPACE must be the qualification workspace"
  [[ "${RUN_ID}" =~ ^[A-Za-z0-9._-]{8,80}$ ]] || die "unsafe CATS_FAULT_RUN_ID"
  [[ "${SSM_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || die "invalid SSM timeout"
  (( SSM_TIMEOUT_SECONDS >= 600 && SSM_TIMEOUT_SECONDS <= 3600 )) ||
    die "SSM timeout must be between 600 and 3600 seconds"
  validate_ref CATS_REMOTE_FAULT_CONFIG "${REMOTE_CONFIG}"
  validate_ref CATS_REMOTE_WORKLOAD_HOOK "${REMOTE_HOOK}"

  case "${MODE}" in
    dry-run|fixture|live) ;;
    *) die "CATS_FAULT_MODE must be dry-run, fixture, or live" ;;
  esac
  case "${SCENARIO}" in
    db|s3|control-plane) SCENARIOS=("${SCENARIO}") ;;
    all)
      [[ "${ALLOW_ALL}" == "true" ]] ||
        die "scenario=all requires CATS_FAULT_ALLOW_ALL=true"
      SCENARIOS=(db s3 control-plane)
      ;;
    *) die "CATS_FAULT_SCENARIO must be db, s3, control-plane, or all" ;;
  esac
  [[ -n "${OWNERSHIP_SNAPSHOT}" ]] || die "CATS_OWNERSHIP_SNAPSHOT is required"
  [[ -f "${OWNERSHIP_SNAPSHOT}" ]] || die "ownership snapshot does not exist"
  [[ -n "${PROVISIONING_MANIFEST}" ]] || die "CATS_PROVISIONING_MANIFEST is required"
  [[ -f "${PROVISIONING_MANIFEST}" ]] || die "provisioning manifest does not exist"
}

validate_snapshot() {
  local snapshot="$1"
  jq -e \
    --arg instance "${TEMP_INSTANCE_ID}" \
    --arg node "${NODE_ID}" \
    --arg workspace_id "${WORKSPACE_ID}" \
    --arg workspace "${WORKSPACE}" '
      (keys | sort) == (["schema_version","captured_at","temp_instance_id","node_id","node_state","workspace_id","workspace","tags","orphans","assigned_cats","test_sha","dependency_endpoints"] | sort) and
      .schema_version == 1 and .temp_instance_id == $instance and
      .node_id == $node and
      .node_state == "Cordoned" and
      .workspace_id == $workspace_id and
      .workspace == $workspace and
      (.tags | keys | sort) == (["Issue","CatsNodeId","Purpose"] | sort) and
      .tags.Issue == "124" and
      .tags.CatsNodeId == $node and
      .tags.Purpose == "qualification-124" and
      (.captured_at | type == "string" and length > 0) and
      .orphans == 0 and
      (.test_sha | test("^[0-9a-f]{40}$")) and
      (.dependency_endpoints | keys | sort) == (["db_host","s3_host","control_plane_host","node_listen_ip"] | sort) and
      all(.dependency_endpoints[]; type == "string" and length > 0) and
      (.assigned_cats | type == "array" and length > 0) and
      all(.assigned_cats[];
        (keys | sort) == (["cat_id","name","workspace_id","node_id","durability"] | sort) and
        (.cat_id | test("^cat_[A-Za-z0-9_-]+$")) and
        (.name | startswith("q124-")) and
        .workspace_id == $workspace_id and
        .node_id == $node and
        (.durability == "strict" or .durability == "relaxed")) and
      ([.assigned_cats[].cat_id] | unique | length) == (.assigned_cats | length) and
      ([.assigned_cats[].name] | unique | length) == (.assigned_cats | length)
    ' "${snapshot}" >/dev/null ||
    die "ownership snapshot is not the strict Cordoned Issue=124 q124-only schema"
}

validate_manifest() {
  local manifest="$1"
  jq -e \
    --arg account "${EXPECTED_ACCOUNT_ID}" --arg region "${AWS_REGION}" \
    --arg instance "${TEMP_INSTANCE_ID}" --arg node "${NODE_ID}" '
      (keys | sort) == (["schema_version","issue","account_id","aws_region","temp_instance_id","node_id","instance_name","launch_time","expires_at","test_sha","tags","qualification_assets"] | sort) and
      .schema_version == 1 and .issue == 124 and .account_id == $account and
      .aws_region == $region and .temp_instance_id == $instance and .node_id == $node and
      .instance_name == ("cats-" + $node) and
      (.launch_time | fromdateiso8601) <= now and
      (.expires_at | fromdateiso8601) > (now + 600) and
      ((.expires_at | fromdateiso8601) - (.launch_time | fromdateiso8601)) <= 86400 and
      (.test_sha | test("^[0-9a-f]{40}$")) and
      (.tags | keys | sort) == (["Name","Project","Environment","Purpose","Issue","CatsNodeId","ExpiresAt","ManagedBy"] | sort) and
      .tags.Name == ("cats-" + $node) and .tags.Project == "Cats" and
      .tags.Environment == "production" and .tags.Purpose == "qualification-124" and
      .tags.Issue == "124" and .tags.CatsNodeId == $node and
      .tags.ExpiresAt == .expires_at and .tags.ManagedBy == "manual-q124" and
      (.qualification_assets | keys | sort) == (["config_sha256","hook_sha256"] | sort) and
      all(.qualification_assets[]; type == "string" and test("^[0-9a-f]{64}$"))
    ' "${manifest}" >/dev/null || die "provisioning manifest identity/TTL/schema is invalid"
  [[ "$(jq -r .test_sha "${manifest}")" == "$(jq -r .test_sha "${OWNERSHIP_SNAPSHOT}")" ]] ||
    die "ownership snapshot TEST_SHA does not match provisioning manifest"
}

make_run_dir() {
  mkdir -p "${RESULT_ROOT}"
  mkdir "${RUN_DIR}" || die "RUN_ID already exists; duplicate/replay refused"
  chmod 700 "${RUN_DIR}"
  cp "${OWNERSHIP_SNAPSHOT}" "${RUN_DIR}/ownership-snapshot.json"
  cp "${PROVISIONING_MANIFEST}" "${RUN_DIR}/provisioning-manifest.json"
  chmod 600 "${RUN_DIR}/ownership-snapshot.json"
  chmod 600 "${RUN_DIR}/provisioning-manifest.json"
}

write_run_metadata() {
  jq -n \
    --arg run_id "${RUN_ID}" \
    --arg mode "${MODE}" \
    --arg scenario "${SCENARIO}" \
    --arg instance "${TEMP_INSTANCE_ID}" \
    --arg node "${NODE_ID}" \
    --arg issue "${ISSUE}" \
    --arg workspace_id "${WORKSPACE_ID}" \
    --arg workspace "${WORKSPACE}" \
    --arg region "${AWS_REGION}" \
    --arg config_ref "${REMOTE_CONFIG}" \
    --arg hook_ref "${REMOTE_HOOK}" \
    --arg harness_sha256 "${HARNESS_SHA256}" \
    --arg test_sha "$(jq -r .test_sha "${PROVISIONING_MANIFEST}")" \
    --arg config_sha256 "$(jq -r .qualification_assets.config_sha256 "${PROVISIONING_MANIFEST}")" \
    --arg hook_sha256 "$(jq -r .qualification_assets.hook_sha256 "${PROVISIONING_MANIFEST}")" \
    --arg started_at "$(date -u +%FT%TZ)" \
    '{run_id:$run_id,mode:$mode,scenario:$scenario,temp_instance_id:$instance,
      node_id:$node,issue:$issue,workspace_id:$workspace_id,workspace:$workspace,
      aws_region:$region,remote_config_ref:$config_ref,remote_hook_ref:$hook_ref,
      harness_sha256:$harness_sha256,test_sha:$test_sha,
      expected_config_sha256:$config_sha256,expected_hook_sha256:$hook_sha256,
      started_at:$started_at}' >"${RUN_DIR}/run-metadata.json"
}

verify_live_identity() {
  local caller source instance ssm uniqueness manifest
  manifest="$(<"${PROVISIONING_MANIFEST}")"
  caller="$(aws sts get-caller-identity --output json)"
  [[ "$(jq -r .Account <<<"${caller}")" == "${EXPECTED_ACCOUNT_ID}" ]] ||
    die "AWS account mismatch"

  source="$(aws ec2 describe-instances --region "${AWS_REGION}" \
    --instance-ids "${SOURCE_INSTANCE_ID}" --output json)"
  jq -e --arg id "${SOURCE_INSTANCE_ID}" '
    [.Reservations[].Instances[]] as $i |
    ($i | length) == 1 and $i[0].InstanceId == $id and
    $i[0].State.Name == "running"
  ' <<<"${source}" >/dev/null || die "known source worker positive control failed"

  instance="$(aws ec2 describe-instances --region "${AWS_REGION}" \
    --instance-ids "${TEMP_INSTANCE_ID}" --output json)"
  jq -e --arg id "${TEMP_INSTANCE_ID}" --arg node "${NODE_ID}" --argjson manifest "${manifest}" '
    [.Reservations[].Instances[]] as $i |
    ($i[0].Tags | map({key:.Key,value:.Value}) | from_entries) as $tags |
    ($i | length) == 1 and
    $i[0].InstanceId == $id and
    $i[0].State.Name == "running" and
    (($i[0].LaunchTime | sub("[+]00:00$";"Z") | fromdateiso8601) ==
      ($manifest.launch_time | fromdateiso8601)) and
    all($manifest.tags | keys[]; . as $key | $tags[$key] == $manifest.tags[$key]) and
    $tags.CatsNodeId == $node
  ' <<<"${instance}" >/dev/null ||
    die "exact instance launch time/tags do not match the provisioning manifest"
  jq --argjson manifest "${manifest}" '
    [.Reservations[].Instances[]][0] |
    (.Tags | map({key:.Key,value:.Value}) | from_entries) as $tags |
    {InstanceId,LaunchTime,State:{Name:.State.Name},PrivateIpAddress,
     ImageId,InstanceType,SubnetId,VpcId,IamInstanceProfile,
     required_tags:($manifest.tags | with_entries(.value = $tags[.key]))}
  ' <<<"${instance}" >"${RUN_DIR}/instance-identity.json"

  uniqueness="$(aws ec2 describe-instances --region "${AWS_REGION}" \
    --filters "Name=tag:CatsNodeId,Values=${NODE_ID}" \
      'Name=instance-state-name,Values=pending,running,stopping,stopped' --output json)"
  jq -e --arg id "${TEMP_INSTANCE_ID}" '
    [.Reservations[].Instances[].InstanceId] == [$id]
  ' <<<"${uniqueness}" >/dev/null || die "temporary Node identity is not unique in EC2"

  ssm="$(aws ssm describe-instance-information --region "${AWS_REGION}" \
    --filters "Key=InstanceIds,Values=${SOURCE_INSTANCE_ID},${TEMP_INSTANCE_ID}" \
    --output json)"
  jq -e --arg source "${SOURCE_INSTANCE_ID}" --arg temp "${TEMP_INSTANCE_ID}" '
    ([.InstanceInformationList[] | select(.InstanceId == $source and .PingStatus == "Online")] | length) == 1 and
    ([.InstanceInformationList[] | select(.InstanceId == $temp and .PingStatus == "Online")] | length) == 1
  ' <<<"${ssm}" >/dev/null || die "calibrated SSM Online probe failed"
}

remote_payload() {
  emit_remote_program | gzip -9 | openssl base64 -A
}

build_ssm_command() {
  local scenario="$1" payload qrun command remote_helper helper_sha test_sha config_sha hook_sha cat_set_sha
  payload="$(remote_payload)"
  helper_sha="$(emit_remote_program | shasum -a 256 | awk '{print $1}')"
  test_sha="$(jq -r .test_sha "${PROVISIONING_MANIFEST}")"
  config_sha="$(jq -r .qualification_assets.config_sha256 "${PROVISIONING_MANIFEST}")"
  hook_sha="$(jq -r .qualification_assets.hook_sha256 "${PROVISIONING_MANIFEST}")"
  cat_set_sha="$(jq -Sc '[.assigned_cats[] | {cat_id,name,workspace_id,node_id,durability}] | sort_by(.cat_id)' \
    "${OWNERSHIP_SNAPSHOT}" | shasum -a 256 | awk '{print $1}')"
  qrun="${RUN_ID}-${scenario}"
  remote_helper="/run/cats-q124-fault-helper-${qrun}.sh"
  printf -v command \
    'umask 077; printf %%s %q | openssl base64 -d -A | gzip -d > %q; chmod 0700 %q; sudo env Q124_RUN_ID=%q Q124_SCENARIO=%q Q124_INSTANCE_ID=%q Q124_NODE_ID=%q Q124_WORKSPACE_ID=%q Q124_CONFIG_REF=%q Q124_HOOK_REF=%q Q124_TEST_SHA=%q Q124_CONFIG_SHA256=%q Q124_HOOK_SHA256=%q Q124_HARNESS_SHA256=%q Q124_HELPER_SHA256=%q Q124_CAT_SET_SHA256=%q %q' \
    "${payload}" "${remote_helper}" "${remote_helper}" "${qrun}" "${scenario}" "${TEMP_INSTANCE_ID}" "${NODE_ID}" \
    "${WORKSPACE_ID}" "${REMOTE_CONFIG}" "${REMOTE_HOOK}" "${test_sha}" "${config_sha}" "${hook_sha}" \
    "${HARNESS_SHA256}" "${helper_sha}" "${cat_set_sha}" "${remote_helper}"
  if grep -Eqi 'bearer|token|password|secret|worker[.]env' <<<"${command}"; then
    die "refusing to put a secret-like value or worker.env in SSM command text"
  fi
  (( ${#command} <= 20000 )) || die "SSM command exceeds the conservative 20 KiB limit"
  printf '%s' "${command}"
}

write_dry_run() {
  local scenario command
  {
    printf 'mode=dry-run\ninstance_id=%s\nnode_id=%s\nissue=%s\nworkspace_id=%s\n' \
      "${TEMP_INSTANCE_ID}" "${NODE_ID}" "${ISSUE}" "${WORKSPACE_ID}"
    printf 'mutation_selector=exact-instance-id-only\n'
    for scenario in "${SCENARIOS[@]}"; do
      command="$(build_ssm_command "${scenario}")"
      printf 'scenario=%s command_sha256=%s command_bytes=%s\n' \
        "${scenario}" \
        "$(printf '%s' "${command}" | shasum -a 256 | awk '{print $1}')" \
        "${#command}"
    done
    printf 'would_verify=AWS-account,source-positive-control,exact-instance-tags,SSM-online\n'
    printf 'would_execute=sequential-SSM-only\nresult=DRY_RUN\n'
  } | tee "${RUN_DIR}/dry-run-plan.txt"
}

fixture_state() {
  local phase="$1" scenario="$2" generation="17" observed="running"
  [[ "${phase}" != "during" ]] || observed="unknown"
  [[ "${scenario}" != "control-plane" || "${phase}" != "during" ]] || observed="unknown"
  jq -n \
    --arg phase "${phase}" --arg scenario "${scenario}" \
    --arg workspace_id "${WORKSPACE_ID}" --arg node_id "${NODE_ID}" \
    --arg observed "${observed}" --argjson generation "${generation}" '
      def cat($name; $durability; $digest):
        {cat_id:("cat_" + ($name | gsub("-";"_"))),cat_name:$name,durability:$durability,desired_state:"running",
         observed_state:$observed,generation:$generation,node_id:$node_id,
         operation_ids:["op_fixture_124"],
         watermark:{local:23,remote:23,unpublished:0},disk_epoch:9,digest:$digest};
      {schema_version:1,captured_at:"2026-08-05T14:00:00Z",phase:$phase,
       scenario:$scenario,workspace_id:$workspace_id,node_id:$node_id,
       raw_operations:[{operation_id:"op_fixture_124",kind:"fixture_probe",phase:"succeeded",
         started_at:"2026-08-05T14:00:00Z",completed_at:"2026-08-05T14:00:01Z",
         log_ref:"journal://q124/fixture/op_fixture_124"}],
       log_refs:["journal://q124/fixture/state"],
       cats:(if $scenario == "s3" then
         [cat("q124-fixture-s3-strict";"strict";"sha256:fixture-strict"),
          cat("q124-fixture-s3-relaxed";"relaxed";"sha256:fixture-relaxed")]
       else [cat("q124-fixture-fault-cat";"strict";"sha256:fixture-q124-digest")] end)}'
}

fixture_oracle() {
  local phase="$1" scenario="$2"
  case "${scenario}:${phase}" in
    db:isolated)
      checks='{"running_exec_observed":true,"metadata_cas_false_success_absent":true,"sync_false_success_absent":true,"cold_false_success_absent":true,"start_retry_or_failure_observed":true,"new_start_retry_or_failure_observed":true,"corruption_absent":true}'
      ;;
    db:recovered)
      checks='{"dependency_reconnected":true,"pending_operations_converged":true,"digest_verified":true}'
      ;;
    s3:isolated)
      checks='{"strict_sync_false_success_absent":true,"strict_cold_false_success_absent":true,"relaxed_local_fsync_observed":true,"relaxed_sync_false_success_absent":true,"relaxed_drain_false_success_absent":true,"local_remote_watermarks_captured":true,"unpublished_captured":true}'
      ;;
    s3:recovered)
      checks='{"strict_sync_succeeded":true,"relaxed_sync_succeeded":true,"local_remote_watermarks_converged":true,"unpublished_zero":true,"strict_cold_restore_digest_verified":true,"relaxed_cold_restore_digest_verified":true}'
      ;;
    control-plane:isolated)
      checks='{"lease_timeout_plus_five_observed":true,"node_lost_observed":true,"claims_preserved":true,"cat_unknown_or_pending":true,"implicit_fence_absent":true,"generation_replacement_absent":true,"epoch_replacement_absent":true,"admin_fence_absent":true}'
      ;;
    control-plane:recovered)
      checks='{"same_node_identity":true,"inventory_complete":true,"placement_preserved":true,"generation_preserved":true,"disk_epoch_preserved":true,"digest_verified":true}'
      ;;
    *) die "invalid fixture oracle ${scenario}:${phase}" ;;
  esac
  jq -n --arg scenario "${scenario}" --arg phase "${phase}" --argjson checks "${checks}" \
    '{schema_version:1,scenario:$scenario,phase:$phase,
      started_at:"2026-08-05T14:00:00Z",completed_at:"2026-08-05T14:00:01Z",
      checks:$checks,
      raw_operations:[{operation_id:"op_fixture_124",kind:"fixture_exercise",phase:"succeeded",
        started_at:"2026-08-05T14:00:00Z",completed_at:"2026-08-05T14:00:01Z",
        log_ref:"journal://q124/fixture/oracle"}],
      log_refs:["journal://q124/fixture/oracle"]}'
}

run_fixture_scenario() {
  local scenario="$1" functional_rc=0 cleanup_rc=0
  local dir="${RUN_DIR}/${scenario}"
  mkdir -p "${dir}"
  printf 'ordinal\tstate\tresult\n' >"${dir}/timeline.tsv"
  local states=(ownership-snapshot positive-tcp positive-real-read injected \
    negative-tcp negative-real-read workload packet-counter cleanup \
    rules-absent recovery-tcp recovery-real-read converged)
  local ordinal=0 state
  for state in "${states[@]}"; do
    ordinal=$((ordinal + 1))
    printf '%s\t%s\tPASS\n' "${ordinal}" "${state}" >>"${dir}/timeline.tsv"
  done
  fixture_state before "${scenario}" >"${dir}/state-before.json"
  fixture_state during "${scenario}" >"${dir}/state-during.json"
  fixture_state after "${scenario}" >"${dir}/state-after.json"
  fixture_oracle isolated "${scenario}" >"${dir}/oracle-isolated.json"
  fixture_oracle recovered "${scenario}" >"${dir}/oracle-recovered.json"
  if [[ "${CATS_FIXTURE_ORACLE_FAIL:-false}" == "true" ]]; then
    jq '(.checks | keys_unsorted[0]) as $first | .checks[$first] = false' \
      "${dir}/oracle-isolated.json" >"${dir}/oracle-isolated.invalid.json"
    mv "${dir}/oracle-isolated.invalid.json" "${dir}/oracle-isolated.json"
  fi
  printf 'packets_after_probe=2\npackets_after_workload=5\nworkload_delta=3\nipv6_routable=false\n' >"${dir}/fault-counters.txt"
  printf 'started_at\tcompleted_at\tkind\tphase\taddress\tport\trc\texpected\n2026-08-05T14:00:00Z\t2026-08-05T14:00:01Z\ttcp\tbefore\t192.0.2.1\t443\t0\tpositive\n' >"${dir}/probes.tsv"
  cp "${OWNERSHIP_SNAPSHOT}" "${dir}/ownership-before.json"
  cp "${OWNERSHIP_SNAPSHOT}" "${dir}/ownership-isolated.json"
  cp "${OWNERSHIP_SNAPSHOT}" "${dir}/ownership-after.json"
  jq -n --arg node "${NODE_ID}" '{schema_version:1,operation_id:"op_fixture_cordon",
    kind:"ensure_node_cordoned",phase:"succeeded",node_id:$node,
    started_at:"2026-08-05T14:00:00Z",completed_at:"2026-08-05T14:00:01Z",
    log_ref:"journal://q124/fixture/cordon"}' >"${dir}/cordon-operation.json"
  jq -n --arg run_id "${RUN_ID}" --arg scenario "${scenario}" --arg instance "${TEMP_INSTANCE_ID}" \
    --arg node "${NODE_ID}" --arg test_sha "$(jq -r .test_sha "${PROVISIONING_MANIFEST}")" \
    --arg harness_sha "${HARNESS_SHA256}" '{schema_version:1,run_id:$run_id,scenario:$scenario,
      temp_instance_id:$instance,node_id:$node,test_sha:$test_sha,harness_sha256:$harness_sha,
      helper_sha256:("4"*64),config_sha256:("2"*64),hook_sha256:("3"*64),
      firewall:{comment:("cats-q124-"+$run_id),chains:["C124O_fixture","C124I_fixture","C1246O_fixture","C1246I_fixture"]}}' \
    >"${dir}/provenance.json"
  if [[ "${CATS_FIXTURE_FUNCTIONAL_FAIL:-false}" == "true" ]]; then functional_rc=41; fi
  if [[ "${CATS_FIXTURE_CLEANUP_FAIL:-false}" == "true" ]]; then cleanup_rc=42; fi
  printf 'functional_rc\tcleanup_rc\n%s\t%s\n' \
    "${functional_rc}" "${cleanup_rc}" >"${dir}/result.tsv"
  if (( functional_rc != 0 || cleanup_rc != 0 )); then return 1; fi
}

decode_remote_evidence() {
  local stdout_file="$1" scenario_dir="$2" label encoded target
  while IFS='=' read -r label encoded; do
    case "${label}" in
      Q124_STATE_BEFORE) target="state-before.json" ;;
      Q124_STATE_DURING) target="state-during.json" ;;
      Q124_STATE_AFTER) target="state-after.json" ;;
      Q124_ORACLE_ISOLATED) target="oracle-isolated.json" ;;
      Q124_ORACLE_RECOVERED) target="oracle-recovered.json" ;;
      Q124_TIMELINE) target="timeline.tsv" ;;
      Q124_COUNTERS) target="fault-counters.txt" ;;
      Q124_PROBES) target="probes.tsv" ;;
      Q124_PROVENANCE) target="provenance.json" ;;
      Q124_CORDON_OPERATION) target="cordon-operation.json" ;;
      Q124_OWNERSHIP_BEFORE) target="ownership-before.json" ;;
      Q124_OWNERSHIP_ISOLATED) target="ownership-isolated.json" ;;
      Q124_OWNERSHIP_AFTER) target="ownership-after.json" ;;
      Q124_CLEANUP_ERRORS) target="cleanup-errors.log" ;;
      *) continue ;;
    esac
    printf '%s' "${encoded}" | openssl base64 -d -A >"${scenario_dir}/${target}"
  done <"${stdout_file}"
}

validate_scenario_evidence() {
  local dir="$1" scenario="$2" functional_rc cleanup_rc before_identity after_identity
  for file in state-before.json state-during.json state-after.json oracle-isolated.json \
    oracle-recovered.json timeline.tsv fault-counters.txt probes.tsv provenance.json \
    cordon-operation.json ownership-before.json ownership-isolated.json ownership-after.json; do
    [[ -s "${dir}/${file}" ]] || return 1
  done
  for phase in before isolated after; do validate_snapshot "${dir}/ownership-${phase}.json" || return 1; done
  [[ "$(jq -Sc '.assigned_cats | sort_by(.cat_id)' "${dir}/ownership-before.json")" == \
      "$(jq -Sc '.assigned_cats | sort_by(.cat_id)' "${dir}/ownership-isolated.json")" &&
     "$(jq -Sc '.assigned_cats | sort_by(.cat_id)' "${dir}/ownership-before.json")" == \
      "$(jq -Sc '.assigned_cats | sort_by(.cat_id)' "${dir}/ownership-after.json")" ]] || return 1
  jq -e --arg node "${NODE_ID}" '
    (keys | sort) == (["schema_version","operation_id","kind","phase","node_id","started_at","completed_at","log_ref"] | sort) and
    .schema_version == 1 and .kind == "ensure_node_cordoned" and .phase == "succeeded" and .node_id == $node
  ' "${dir}/cordon-operation.json" >/dev/null || return 1
  jq -e --arg run_id "${RUN_ID}" --arg scenario "${scenario}" --arg instance "${TEMP_INSTANCE_ID}" --arg node "${NODE_ID}" '
    (keys | sort) == (["schema_version","run_id","scenario","temp_instance_id","node_id","test_sha","harness_sha256","helper_sha256","config_sha256","hook_sha256","firewall"] | sort) and
    .schema_version == 1 and .run_id == $run_id and .scenario == $scenario and
    .temp_instance_id == $instance and .node_id == $node and
    all([.test_sha][]; test("^[0-9a-f]{40}$")) and
    all([.harness_sha256,.helper_sha256,.config_sha256,.hook_sha256][]; test("^[0-9a-f]{64}$")) and
    (.firewall | keys | sort) == (["comment","chains"] | sort) and
    (.firewall.comment | startswith("cats-q124-")) and
    (.firewall.chains | type == "array" and length == 4)
  ' "${dir}/provenance.json" >/dev/null || return 1
  awk -F= '$1=="workload_delta" {found=1; if ($2+0 <= 0) exit 1} END {exit !found}' "${dir}/fault-counters.txt" || return 1
  for phase in before during after; do
    jq -e --arg ws "${WORKSPACE_ID}" --arg node "${NODE_ID}" --arg scenario "${scenario}" '
      (keys | sort) == (["schema_version","captured_at","phase","scenario","workspace_id","node_id","cats","raw_operations","log_refs"] | sort) and
      .schema_version == 1 and .workspace_id == $ws and .scenario == $scenario and .node_id == $node and
      (.captured_at | type == "string" and length > 0) and
      (.phase == "before" or .phase == "during" or .phase == "after") and
      (.cats | type == "array" and length > 0) and
      all(.cats[];
        (keys | sort) == (["cat_id","cat_name","durability","desired_state","observed_state","generation","node_id","operation_ids","watermark","disk_epoch","digest"] | sort) and
        (.cat_id | test("^cat_[A-Za-z0-9_-]+$")) and
        (.cat_name | startswith("q124-")) and
        (.durability == "strict" or .durability == "relaxed") and
        (.desired_state | type == "string") and
        (.observed_state | type == "string") and
        (.generation | type == "number") and .node_id == $node and
        (.operation_ids | type == "array") and
        (.watermark | keys | sort) == (["local","remote","unpublished"] | sort) and
        all(.watermark[]; type == "number") and
        (.disk_epoch | type == "number") and
        (.digest | type == "string" and length > 0)) and
      (.raw_operations | type == "array" and length > 0) and
      all(.raw_operations[];
        (keys | sort) == (["operation_id","kind","phase","started_at","completed_at","log_ref"] | sort) and
        (.operation_id | test("^op_[A-Za-z0-9_-]+$")) and
        all([.kind,.phase,.started_at,.completed_at,.log_ref][]; type == "string" and length > 0)) and
      (.log_refs | type == "array" and length > 0) and all(.log_refs[]; type == "string" and length > 0) and
      ($scenario != "s3" or
        ([.cats[].durability] | sort) == ["relaxed","strict"])
    ' "${dir}/state-${phase}.json" >/dev/null || return 1
  done
  before_identity="$(jq -Sc '[.cats[] | {cat_name,digest}] | sort_by(.cat_name)' "${dir}/state-before.json")"
  after_identity="$(jq -Sc '[.cats[] | {cat_name,digest}] | sort_by(.cat_name)' "${dir}/state-after.json")"
  [[ "${before_identity}" == "${after_identity}" ]] || return 1
  if [[ "${scenario}" == "control-plane" ]]; then
    before_identity="$(jq -Sc '[.cats[] | {cat_name,generation,node_id,disk_epoch}] | sort_by(.cat_name)' "${dir}/state-before.json")"
    after_identity="$(jq -Sc '[.cats[] | {cat_name,generation,node_id,disk_epoch}] | sort_by(.cat_name)' "${dir}/state-after.json")"
    [[ "${before_identity}" == "${after_identity}" ]] || return 1
  fi
  validate_oracle_file "${dir}/oracle-isolated.json" "${scenario}" isolated || return 1
  validate_oracle_file "${dir}/oracle-recovered.json" "${scenario}" recovered || return 1
  functional_rc="$(awk -F '\t' 'NR == 2 {print $1}' "${dir}/result.tsv")"
  cleanup_rc="$(awk -F '\t' 'NR == 2 {print $2}' "${dir}/result.tsv")"
  [[ "${functional_rc}" == "0" && "${cleanup_rc}" == "0" ]] || return 1
  if grep -Eirq 'authorization:|proxy-authorization:|bearer[[:space:]]|set-cookie:|cookie:|x-amz-security-token|aws_(access_key|secret_access_key|session_token)|(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}|password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|client_secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]|token[[:space:]]*[:=]|worker[.]env|BEGIN ([A-Z ]+ )?PRIVATE KEY|postgres(ql)?://[^[:space:]:]+:[^[:space:]@]+@|eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.]' "${dir}"; then
    return 1
  fi
}

validate_oracle_file() {
  local file="$1" scenario="$2" phase="$3" required
  case "${scenario}:${phase}" in
    db:isolated) required='["running_exec_observed","metadata_cas_false_success_absent","sync_false_success_absent","cold_false_success_absent","start_retry_or_failure_observed","new_start_retry_or_failure_observed","corruption_absent"]' ;;
    db:recovered) required='["dependency_reconnected","pending_operations_converged","digest_verified"]' ;;
    s3:isolated) required='["strict_sync_false_success_absent","strict_cold_false_success_absent","relaxed_local_fsync_observed","relaxed_sync_false_success_absent","relaxed_drain_false_success_absent","local_remote_watermarks_captured","unpublished_captured"]' ;;
    s3:recovered) required='["strict_sync_succeeded","relaxed_sync_succeeded","local_remote_watermarks_converged","unpublished_zero","strict_cold_restore_digest_verified","relaxed_cold_restore_digest_verified"]' ;;
    control-plane:isolated) required='["lease_timeout_plus_five_observed","node_lost_observed","claims_preserved","cat_unknown_or_pending","implicit_fence_absent","generation_replacement_absent","epoch_replacement_absent","admin_fence_absent"]' ;;
    control-plane:recovered) required='["same_node_identity","inventory_complete","placement_preserved","generation_preserved","disk_epoch_preserved","digest_verified"]' ;;
    *) return 1 ;;
  esac
  jq -e --arg scenario "${scenario}" --arg phase "${phase}" --argjson required "${required}" '
    . as $root |
    (keys | sort) == (["schema_version","scenario","phase","started_at","completed_at","checks","raw_operations","log_refs"] | sort) and
    .schema_version == 1 and .scenario == $scenario and .phase == $phase and
    all([.started_at,.completed_at][]; type == "string" and length > 0) and
    (.checks | keys | sort) == ($required | sort) and
    (.raw_operations | type == "array" and length > 0) and
    all(.raw_operations[];
      (keys | sort) == (["operation_id","kind","phase","started_at","completed_at","log_ref"] | sort) and
      (.operation_id | test("^op_[A-Za-z0-9_-]+$")) and
      all([.kind,.phase,.started_at,.completed_at,.log_ref][]; type == "string" and length > 0)) and
    (.log_refs | type == "array" and length > 0) and all(.log_refs[]; type == "string" and length > 0) and
    all($required[]; . as $key | ($root.checks[$key] == true))
  ' "${file}" >/dev/null
}

run_live_scenario() {
  local scenario="$1" command parameters response command_id status rc
  local dir="${RUN_DIR}/${scenario}"
  local functional_rc cleanup_rc stdout_content stderr_content secret_rc=0
  local deadline
  mkdir -p "${dir}"
  command="$(build_ssm_command "${scenario}")"
  parameters="$(jq -cn --arg command "${command}" --arg timeout "${SSM_TIMEOUT_SECONDS}" \
    '{commands:[$command],executionTimeout:[$timeout]}')"
  response="$(aws ssm send-command --region "${AWS_REGION}" \
    --document-name AWS-RunShellScript \
    --instance-ids "${TEMP_INSTANCE_ID}" \
    --timeout-seconds "${SSM_TIMEOUT_SECONDS}" \
    --comment "Issue 124 ${RUN_ID} ${scenario}" \
    --parameters "${parameters}" --output json)"
  command_id="$(jq -r .Command.CommandId <<<"${response}")"
  [[ "${command_id}" =~ ^[0-9a-f-]{36}$ ]] || die "could not parse SSM command ID"
  printf '%s\n' "${command_id}" >"${dir}/ssm-command-id.txt"

  deadline="$(( $(date +%s) + SSM_TIMEOUT_SECONDS + 60 ))"
  while true; do
    response="$(aws ssm get-command-invocation --region "${AWS_REGION}" \
      --command-id "${command_id}" --instance-id "${TEMP_INSTANCE_ID}" --output json 2>/dev/null || true)"
    status="$(jq -r '.Status // "Pending"' <<<"${response:-{}}")"
    case "${status}" in
      Pending|InProgress|Delayed) sleep 2 ;;
      Success|Cancelled|TimedOut|Failed|Cancelling) break ;;
      *) die "unexpected SSM status: ${status}" ;;
    esac
    if (( $(date +%s) >= deadline )); then
      status=LocalPollTimedOut
      response='{}'
      break
    fi
  done
  stdout_content="$(jq -r '.StandardOutputContent // ""' <<<"${response}")"
  stderr_content="$(jq -r '.StandardErrorContent // ""' <<<"${response}")"
  if printf '%s\n%s' "${stdout_content}" "${stderr_content}" | contains_secret_like; then
    printf '[REDACTED: secret-like SSM output rejected]\n' >"${dir}/ssm-stdout.log"
    printf '[REDACTED: secret-like SSM output rejected]\n' >"${dir}/ssm-stderr.log"
    secret_rc=1
  else
    printf '%s\n' "${stdout_content}" >"${dir}/ssm-stdout.log"
    printf '%s\n' "${stderr_content}" >"${dir}/ssm-stderr.log"
  fi
  decode_remote_evidence "${dir}/ssm-stdout.log" "${dir}"
  functional_rc="$(sed -n 's/^Q124_RESULT functional_rc=\([0-9][0-9]*\) cleanup_rc=.*/\1/p' "${dir}/ssm-stdout.log" | tail -1)"
  cleanup_rc="$(sed -n 's/^Q124_RESULT functional_rc=[0-9][0-9]* cleanup_rc=\([0-9][0-9]*\).*/\1/p' "${dir}/ssm-stdout.log" | tail -1)"
  printf 'functional_rc\tcleanup_rc\n%s\t%s\n' \
    "${functional_rc:-missing}" "${cleanup_rc:-missing}" >"${dir}/result.tsv"
  rc=0
  [[ "${status}" == "Success" ]] || rc=1
  (( secret_rc == 0 )) || rc=1
  validate_scenario_evidence "${dir}" "${scenario}" || rc=1
  return "${rc}"
}

main() {
  require_command jq
  require_command openssl
  require_command gzip
  validate_inputs
  validate_snapshot "${OWNERSHIP_SNAPSHOT}"
  validate_manifest "${PROVISIONING_MANIFEST}"
  if [[ "${MODE}" == live ]]; then
    jq -e '(.captured_at | fromdateiso8601) >= (now - 300) and
      (.captured_at | fromdateiso8601) <= (now + 30)' "${OWNERSHIP_SNAPSHOT}" >/dev/null ||
      die "live ownership snapshot must be fresh within five minutes"
  fi
  make_run_dir
  write_run_metadata

  case "${MODE}" in
    dry-run)
      write_dry_run
      ;;
    fixture)
      local scenario
      for scenario in "${SCENARIOS[@]}"; do
        run_fixture_scenario "${scenario}" || {
          printf 'result=FAIL scenario=%s evidence=%s\n' "${scenario}" "${RUN_DIR}" >&2
          return 1
        }
        validate_scenario_evidence "${RUN_DIR}/${scenario}" "${scenario}" ||
          die "fixture evidence validation failed for ${scenario}"
      done
      printf 'result=PASS mode=fixture scenarios=%s evidence=%s\n' \
        "${SCENARIOS[*]}" "${RUN_DIR}"
      ;;
    live)
      require_command aws
      expected="RUN_Q124_FAULT_${TEMP_INSTANCE_ID}_${NODE_ID}_${SCENARIO}"
      [[ "${LIVE_CONFIRM}" == "${expected}" ]] ||
        die "live mode requires CATS_FAULT_CONFIRM=${expected}"
      verify_live_identity
      local scenario
      for scenario in "${SCENARIOS[@]}"; do
        # This loop is intentionally serial. A failed or incomplete cleanup
        # stops the run before another dependency can be isolated.
        run_live_scenario "${scenario}" || {
          printf 'result=FAIL scenario=%s evidence=%s\n' "${scenario}" "${RUN_DIR}" >&2
          return 1
        }
      done
      printf 'result=PASS mode=live scenarios=%s evidence=%s\n' \
        "${SCENARIOS[*]}" "${RUN_DIR}"
      ;;
  esac
}

# The emitted program runs as root on the one exact SSM target. It contains no
# credentials and receives only identifiers plus references to root-owned
# non-secret configuration and a preinstalled workload hook. The hook owns all
# access to host-local credentials and must never print them.
emit_remote_program() {
  cat <<'Q124_REMOTE'
#!/usr/bin/env bash
set -u -o pipefail

RUN_ID="${Q124_RUN_ID:?}"
SCENARIO="${Q124_SCENARIO:?}"
INSTANCE_ID="${Q124_INSTANCE_ID:?}"
NODE_ID="${Q124_NODE_ID:?}"
WORKSPACE_ID="${Q124_WORKSPACE_ID:?}"
CONFIG_REF="${Q124_CONFIG_REF:?}"
HOOK_REF="${Q124_HOOK_REF:?}"
TEST_SHA="${Q124_TEST_SHA:?}"
EXPECTED_CONFIG_SHA256="${Q124_CONFIG_SHA256:?}"
EXPECTED_HOOK_SHA256="${Q124_HOOK_SHA256:?}"
HARNESS_SHA256="${Q124_HARNESS_SHA256:?}"
EXPECTED_HELPER_SHA256="${Q124_HELPER_SHA256:?}"
EXPECTED_CAT_SET_SHA256="${Q124_CAT_SET_SHA256:?}"
STATE_DIR="/run/cats-q124-fault-${RUN_ID}"
LOCK_FILE="/run/lock/cats-q124-fault.lock"
TIMELINE="${STATE_DIR}/timeline.tsv"
COUNTERS="${STATE_DIR}/counters.txt"
PROBES="${STATE_DIR}/probes.tsv"
CLEANUP_SCRIPT="${STATE_DIR}/cleanup.sh"
COMMENT="cats-q124-${RUN_ID}"
HASH="$(printf '%s' "${RUN_ID}" | sha256sum | cut -c1-12)"
CHAIN4O="C124O_${HASH}"
CHAIN4I="C124I_${HASH}"
CHAIN6O="C1246O_${HASH}"
CHAIN6I="C1246I_${HASH}"
WATCHDOG_UNIT="cats-q124-fault-${HASH}"
INJECTED=0
WATCHDOG_ARMED=0
FUNCTIONAL_RC=0
CLEANUP_RC=0
ORDINAL=0
PROVENANCE="${STATE_DIR}/provenance.json"

record() {
  ORDINAL=$((ORDINAL + 1))
  printf '%s\t%s\t%s\t%s\t%s\n' "${ORDINAL}" "$(date -u +%FT%TZ)" "${SCENARIO}" "$1" "$2" >>"${TIMELINE}"
}

fail() {
  printf 'Q124_ERROR %s\n' "$*" >&2
  return 1
}

safe_ref() {
  [[ "$1" =~ ^/[A-Za-z0-9._/-]+$ && "$1" != *".."* ]]
}

validate_root_file() {
  local path="$1" kind="$2" owner mode
  [[ -e "${path}" ]] || fail "missing ${kind} reference"
  owner="$(stat -c '%u:%g' "${path}")"
  mode="$(stat -c '%a' "${path}")"
  [[ "${owner}" == "0:0" ]] || fail "${kind} is not root-owned"
  if [[ "${kind}" == config ]]; then
    [[ "${mode}" == 600 ]] || fail "unsafe config mode ${mode}"
  else
    [[ "${mode}" =~ ^(700|750)$ ]] || fail "unsafe hook mode ${mode}"
  fi
}

conf_get() {
  jq -er --arg key "$1" '.[$key]' "${CONFIG_REF}"
}

snapshot_valid() {
  jq -e --arg instance "${INSTANCE_ID}" --arg node "${NODE_ID}" --arg ws "${WORKSPACE_ID}" --arg test_sha "${TEST_SHA}" '
    (keys | sort) == (["schema_version","captured_at","temp_instance_id","node_id","node_state","workspace_id","workspace","tags","orphans","assigned_cats","test_sha","dependency_endpoints"] | sort) and
    .schema_version == 1 and (.captured_at | fromdateiso8601) >= (now - 120) and
    (.captured_at | fromdateiso8601) <= (now + 30) and
    .temp_instance_id == $instance and .node_id == $node and
    .node_state == "Cordoned" and .workspace_id == $ws and
    .workspace == "default/qual-124-20260805" and .test_sha == $test_sha and
    (.tags | keys | sort) == (["Issue","CatsNodeId","Purpose"] | sort) and
    .tags.Issue == "124" and .tags.CatsNodeId == $node and
    .tags.Purpose == "qualification-124" and .orphans == 0 and
    (.dependency_endpoints | keys | sort) == (["db_host","s3_host","control_plane_host","node_listen_ip"] | sort) and
    all(.dependency_endpoints[]; type == "string" and length > 0) and
    (.assigned_cats | type == "array" and length > 0) and
    all(.assigned_cats[];
      (keys | sort) == (["cat_id","name","workspace_id","node_id","durability"] | sort) and
      (.cat_id | test("^cat_[A-Za-z0-9_-]+$")) and
      (.name | startswith("q124-")) and .workspace_id == $ws and .node_id == $node and
      (.durability == "strict" or .durability == "relaxed")) and
    ([.assigned_cats[].cat_id] | unique | length) == (.assigned_cats | length) and
    ([.assigned_cats[].name] | unique | length) == (.assigned_cats | length)
  ' "$1" >/dev/null
}

snapshot_cat_set_sha() {
  jq -Sc '[.assigned_cats[] | {cat_id,name,workspace_id,node_id,durability}] | sort_by(.cat_id)' "$1" |
    sha256sum | awk '{print $1}'
}

snapshot_matches_baseline() {
  snapshot_valid "$1" &&
    [[ "$(snapshot_cat_set_sha "$1")" == "${EXPECTED_CAT_SET_SHA256}" ]]
}

take_snapshot() {
  local phase="$1"
  local output="${STATE_DIR}/ownership-${phase}.json"
  "${HOOK_REF}" snapshot --scenario "${SCENARIO}" --phase "${phase}" \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" --instance-id "${INSTANCE_ID}" \
    --output "${output}" >/dev/null 2>&1 || return 1
  snapshot_matches_baseline "${output}" || return 1
}

cordon_evidence_valid() {
  jq -e --arg node "${NODE_ID}" '
    (keys | sort) == (["schema_version","operation_id","kind","phase","node_id","started_at","completed_at","log_ref"] | sort) and
    .schema_version == 1 and (.operation_id | test("^op_[A-Za-z0-9_-]+$")) and
    .kind == "ensure_node_cordoned" and .phase == "succeeded" and .node_id == $node and
    all([.started_at,.completed_at,.log_ref][]; type == "string" and length > 0)
  ' "$1" >/dev/null
}

state_valid() {
  jq -e --arg ws "${WORKSPACE_ID}" --arg node "${NODE_ID}" --arg scenario "${SCENARIO}" '
    (keys | sort) == (["schema_version","captured_at","phase","scenario","workspace_id","node_id","cats","raw_operations","log_refs"] | sort) and
    .schema_version == 1 and .workspace_id == $ws and .scenario == $scenario and .node_id == $node and
    (.captured_at | type == "string" and length > 0) and
    (.phase == "before" or .phase == "during" or .phase == "after") and
    (.cats | type == "array" and length > 0) and
    all(.cats[];
      (keys | sort) == (["cat_id","cat_name","durability","desired_state","observed_state","generation","node_id","operation_ids","watermark","disk_epoch","digest"] | sort) and
      (.cat_id | test("^cat_[A-Za-z0-9_-]+$")) and
      (.cat_name | startswith("q124-")) and
      (.durability == "strict" or .durability == "relaxed") and
      (.desired_state | type == "string") and
      (.observed_state | type == "string") and
      (.generation | type == "number") and .node_id == $node and
      (.operation_ids | type == "array") and
      (.watermark | keys | sort) == (["local","remote","unpublished"] | sort) and
      all(.watermark[]; type == "number") and
      (.disk_epoch | type == "number") and
      (.digest | type == "string" and length > 0)) and
    (.raw_operations | type == "array" and length > 0) and
    all(.raw_operations[];
      (keys | sort) == (["operation_id","kind","phase","started_at","completed_at","log_ref"] | sort) and
      (.operation_id | test("^op_[A-Za-z0-9_-]+$")) and
      all([.kind,.phase,.started_at,.completed_at,.log_ref][]; type == "string" and length > 0)) and
    (.log_refs | type == "array" and length > 0) and all(.log_refs[]; type == "string" and length > 0) and
    ($scenario != "s3" or
      ([.cats[].durability] | sort) == ["relaxed","strict"])
  ' "$1" >/dev/null
}

oracle_valid() {
  local file="$1" phase="$2" required
  case "${SCENARIO}:${phase}" in
    db:isolated) required='["running_exec_observed","metadata_cas_false_success_absent","sync_false_success_absent","cold_false_success_absent","start_retry_or_failure_observed","new_start_retry_or_failure_observed","corruption_absent"]' ;;
    db:recovered) required='["dependency_reconnected","pending_operations_converged","digest_verified"]' ;;
    s3:isolated) required='["strict_sync_false_success_absent","strict_cold_false_success_absent","relaxed_local_fsync_observed","relaxed_sync_false_success_absent","relaxed_drain_false_success_absent","local_remote_watermarks_captured","unpublished_captured"]' ;;
    s3:recovered) required='["strict_sync_succeeded","relaxed_sync_succeeded","local_remote_watermarks_converged","unpublished_zero","strict_cold_restore_digest_verified","relaxed_cold_restore_digest_verified"]' ;;
    control-plane:isolated) required='["lease_timeout_plus_five_observed","node_lost_observed","claims_preserved","cat_unknown_or_pending","implicit_fence_absent","generation_replacement_absent","epoch_replacement_absent","admin_fence_absent"]' ;;
    control-plane:recovered) required='["same_node_identity","inventory_complete","placement_preserved","generation_preserved","disk_epoch_preserved","digest_verified"]' ;;
    *) return 1 ;;
  esac
  jq -e --arg scenario "${SCENARIO}" --arg phase "${phase}" --argjson required "${required}" '
    . as $root |
    (keys | sort) == (["schema_version","scenario","phase","started_at","completed_at","checks","raw_operations","log_refs"] | sort) and
    .schema_version == 1 and .scenario == $scenario and .phase == $phase and
    all([.started_at,.completed_at][]; type == "string" and length > 0) and
    (.checks | keys | sort) == ($required | sort) and
    (.raw_operations | type == "array" and length > 0) and
    all(.raw_operations[];
      (keys | sort) == (["operation_id","kind","phase","started_at","completed_at","log_ref"] | sort) and
      (.operation_id | test("^op_[A-Za-z0-9_-]+$")) and
      all([.kind,.phase,.started_at,.completed_at,.log_ref][]; type == "string" and length > 0)) and
    (.log_refs | type == "array" and length > 0) and all(.log_refs[]; type == "string" and length > 0) and
    all($required[]; . as $key | ($root.checks[$key] == true))
  ' "${file}" >/dev/null
}

resolve_v4() {
  getent ahostsv4 "$1" | awk '$2 == "STREAM" {print $1}' | LC_ALL=C sort -u
}

resolve_v6() {
  getent ahostsv6 "$1" | awk '$2 == "STREAM" && $1 ~ /:/ {print $1}' | LC_ALL=C sort -u
}

tcp_probe() {
  # The positional parameters intentionally expand inside the child Bash.
  # shellcheck disable=SC2016
  timeout 5 bash -c 'exec 3<>/dev/tcp/$1/$2' probe "$1" "$2" >/dev/null 2>&1
}

real_probe() {
  "${HOOK_REF}" probe --scenario "${SCENARIO}" --address "$1" --port "$2" >/dev/null 2>&1
}

expect_probe() {
  local kind="$1" phase="$2" expected="$3" address="$4" port="$5" started completed rc=0
  started="$(date -u +%FT%TZ)"
  if [[ "${kind}" == tcp || "${kind}" == tcp-node-ingress ]]; then
    tcp_probe "${address}" "${port}" || rc=$?
  else
    real_probe "${address}" "${port}" || rc=$?
  fi
  completed="$(date -u +%FT%TZ)"
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "${started}" "${completed}" "${kind}" "${phase}" "${address}" "${port}" "${rc}" "${expected}" >>"${PROBES}"
  if [[ "${expected}" == positive ]]; then (( rc == 0 )); else (( rc != 0 )); fi
}

all_probes_positive() {
  local phase="${1:-positive}" ip
  for ip in "${V4_ADDRS[@]}"; do
    expect_probe tcp "${phase}" positive "${ip}" "${TARGET_PORT}" &&
      expect_probe real-read "${phase}" positive "${ip}" "${TARGET_PORT}" || return 1
  done
  if [[ "${IPV6_ROUTABLE}" == true ]]; then
    for ip in "${V6_ADDRS[@]}"; do
      expect_probe tcp "${phase}" positive "${ip}" "${TARGET_PORT}" &&
        expect_probe real-read "${phase}" positive "${ip}" "${TARGET_PORT}" || return 1
    done
  fi
  if [[ "${SCENARIO}" == control-plane ]]; then
    expect_probe tcp-node-ingress "${phase}" positive "${NODE_LISTEN_IP}" "${NODE_LISTEN_PORT}" || return 1
  fi
}

all_probes_negative() {
  local phase="${1:-isolated}" ip
  for ip in "${V4_ADDRS[@]}"; do
    expect_probe tcp "${phase}" negative "${ip}" "${TARGET_PORT}" &&
      expect_probe real-read "${phase}" negative "${ip}" "${TARGET_PORT}" || return 1
  done
  if [[ "${IPV6_ROUTABLE}" == true ]]; then
    for ip in "${V6_ADDRS[@]}"; do
      expect_probe tcp "${phase}" negative "${ip}" "${TARGET_PORT}" &&
        expect_probe real-read "${phase}" negative "${ip}" "${TARGET_PORT}" || return 1
    done
  fi
  if [[ "${SCENARIO}" == control-plane ]]; then
    expect_probe tcp-node-ingress "${phase}" negative "${NODE_LISTEN_IP}" "${NODE_LISTEN_PORT}" || return 1
  fi
}

write_cleanup_script() {
  cat >"${CLEANUP_SCRIPT}" <<EOF
#!/usr/bin/env bash
set -u -o pipefail
LEDGER='${STATE_DIR}/cleanup-errors.log'
COMMENT='${COMMENT}'

log_error() {
  printf '%s\tattempt=%s\t%s\n' "\$(date -u +%FT%TZ)" "\$1" "\$2" >>"\${LEDGER}"
}

save_rules() {
  local save_bin="\$1" output_var="\$2" attempt="\$3" output
  if ! output="\$("\${save_bin}" 2>/dev/null)"; then
    log_error "\${attempt}" "\${save_bin}-failed"
    return 1
  fi
  printf -v "\${output_var}" '%s' "\${output}"
}

cleanup_family() {
  local cmd="\$1" save_bin="\$2" out_chain="\$3" in_chain="\$4" attempt="\$5"
  local snapshot i rc=0
  save_rules "\${save_bin}" snapshot "\${attempt}" || return 1
  for i in 1 2 3 4; do
    grep -Fq -- "--comment \"\${COMMENT}\" -j \${out_chain}" <<<"\${snapshot}" || break
    if ! "\${cmd}" -w 5 -D OUTPUT -m comment --comment "\${COMMENT}" -j "\${out_chain}"; then
      log_error "\${attempt}" "\${cmd}-delete-output-jump-failed"; rc=1; break
    fi
    save_rules "\${save_bin}" snapshot "\${attempt}" || { rc=1; break; }
  done
  for i in 1 2 3 4; do
    grep -Fq -- "--comment \"\${COMMENT}\" -j \${in_chain}" <<<"\${snapshot}" || break
    if ! "\${cmd}" -w 5 -D INPUT -m comment --comment "\${COMMENT}" -j "\${in_chain}"; then
      log_error "\${attempt}" "\${cmd}-delete-input-jump-failed"; rc=1; break
    fi
    save_rules "\${save_bin}" snapshot "\${attempt}" || { rc=1; break; }
  done
  for chain in "\${out_chain}" "\${in_chain}"; do
    if grep -Fq ":\${chain} " <<<"\${snapshot}"; then
      "\${cmd}" -w 5 -F "\${chain}" || { log_error "\${attempt}" "\${cmd}-flush-\${chain}-failed"; rc=1; }
      "\${cmd}" -w 5 -X "\${chain}" || { log_error "\${attempt}" "\${cmd}-delete-\${chain}-failed"; rc=1; }
    fi
  done
  save_rules "\${save_bin}" snapshot "\${attempt}" || rc=1
  if grep -Fq "\${COMMENT}" <<<"\${snapshot}" ||
     grep -Eq ":(\${out_chain}|\${in_chain}) " <<<"\${snapshot}"; then
    log_error "\${attempt}" "\${cmd}-provenance-still-present"; rc=1
  fi
  return "\${rc}"
}

for attempt in \$(seq 1 12); do
  attempt_rc=0
  cleanup_family iptables iptables-save '${CHAIN4O}' '${CHAIN4I}' "\${attempt}" || attempt_rc=1
  if command -v ip6tables-save >/dev/null 2>&1; then
    cleanup_family ip6tables ip6tables-save '${CHAIN6O}' '${CHAIN6I}' "\${attempt}" || attempt_rc=1
  fi
  if (( attempt_rc == 0 )); then exit 0; fi
  sleep 2
done
exit 71
EOF
  chmod 0700 "${CLEANUP_SCRIPT}"
}

inject_rules() {
  local ip
  # Mark before the first mutation so the EXIT trap also cleans a partially
  # constructed ruleset. The independently armed systemd timer is the SIGKILL
  # and lost-session fallback.
  INJECTED=1
  iptables -w 5 -N "${CHAIN4O}" && iptables -w 5 -N "${CHAIN4I}" || return 1
  iptables -w 5 -I OUTPUT 1 -m comment --comment "${COMMENT}" -j "${CHAIN4O}" || return 1
  iptables -w 5 -I INPUT 1 -m comment --comment "${COMMENT}" -j "${CHAIN4I}" || return 1
  for ip in "${V4_ADDRS[@]}"; do
    iptables -w 5 -A "${CHAIN4O}" -d "${ip}/32" -p tcp --dport "${TARGET_PORT}" \
      -m comment --comment "${COMMENT}" -j REJECT --reject-with tcp-reset || return 1
  done
  if [[ "${SCENARIO}" == control-plane ]]; then
    iptables -w 5 -A "${CHAIN4I}" -p tcp --dport "${NODE_LISTEN_PORT}" \
      -m comment --comment "${COMMENT}" -j REJECT --reject-with tcp-reset || return 1
  fi

  if [[ "${IPV6_ROUTABLE}" == true ]]; then
    command -v ip6tables >/dev/null 2>&1 || return 1
    ip6tables -w 5 -N "${CHAIN6O}" && ip6tables -w 5 -N "${CHAIN6I}" || return 1
    ip6tables -w 5 -I OUTPUT 1 -m comment --comment "${COMMENT}" -j "${CHAIN6O}" || return 1
    ip6tables -w 5 -I INPUT 1 -m comment --comment "${COMMENT}" -j "${CHAIN6I}" || return 1
    for ip in "${V6_ADDRS[@]}"; do
      ip6tables -w 5 -A "${CHAIN6O}" -d "${ip}/128" -p tcp --dport "${TARGET_PORT}" \
        -m comment --comment "${COMMENT}" -j REJECT --reject-with tcp-reset || return 1
    done
    if [[ "${SCENARIO}" == control-plane ]]; then
      ip6tables -w 5 -A "${CHAIN6I}" -p tcp --dport "${NODE_LISTEN_PORT}" \
        -m comment --comment "${COMMENT}" -j REJECT --reject-with tcp-reset || return 1
    fi
  fi
}

packet_count() {
  local total=0 value output chain
  for chain in "${CHAIN4O}" "${CHAIN4I}"; do
    output="$(iptables -w 5 -nvxL "${chain}" 2>/dev/null)" || return 1
    value="$(awk 'NR > 2 {n += $1} END {print n+0}' <<<"${output}")"
    [[ "${value}" =~ ^[0-9]+$ ]] || return 1
    total=$((total + value))
  done
  if [[ "${IPV6_ROUTABLE}" == true ]]; then
    for chain in "${CHAIN6O}" "${CHAIN6I}"; do
      output="$(ip6tables -w 5 -nvxL "${chain}" 2>/dev/null)" || return 1
      value="$(awk 'NR > 2 {n += $1} END {print n+0}' <<<"${output}")"
      [[ "${value}" =~ ^[0-9]+$ ]] || return 1
      total=$((total + value))
    done
  fi
  printf '%s' "${total}"
}

rules_absent() {
  local snapshot
  snapshot="$(iptables-save 2>/dev/null)" || return 2
  ! grep -Fq "${COMMENT}" <<<"${snapshot}" || return 1
  ! grep -Eq ":(${CHAIN4O}|${CHAIN4I}) " <<<"${snapshot}" || return 1
  if command -v ip6tables-save >/dev/null 2>&1; then
    snapshot="$(ip6tables-save 2>/dev/null)" || return 2
    ! grep -Fq "${COMMENT}" <<<"${snapshot}" || return 1
    ! grep -Eq ":(${CHAIN6O}|${CHAIN6I}) " <<<"${snapshot}" || return 1
  fi
}

cleanup_now() {
  local rc=0 script_rc=0 absence_rc=0
  if [[ "${INJECTED}" != 1 && "${WATCHDOG_ARMED}" != 1 ]]; then return 0; fi
  if [[ -x "${CLEANUP_SCRIPT}" ]]; then "${CLEANUP_SCRIPT}" || script_rc=$?; fi
  rules_absent || absence_rc=$?
  if (( absence_rc == 0 )); then
    INJECTED=0
    if [[ "${WATCHDOG_ARMED}" == 1 ]]; then
      systemctl stop "${WATCHDOG_UNIT}.timer" >/dev/null 2>&1 || rc=1
      systemctl stop "${WATCHDOG_UNIT}.service" >/dev/null 2>&1 || true
      systemctl reset-failed "${WATCHDOG_UNIT}.service" "${WATCHDOG_UNIT}.timer" >/dev/null 2>&1 || true
      WATCHDOG_ARMED=0
    fi
  fi
  (( script_rc == 0 )) || rc="${script_rc}"
  (( absence_rc == 0 )) || rc="${absence_rc}"
  if [[ -s "${STATE_DIR}/cleanup-errors.log" ]]; then rc=70; fi
  return "${rc}"
}

# Invoked indirectly by EXIT/HUP/INT/TERM traps below.
# shellcheck disable=SC2329
emergency_cleanup() {
  local rc=$?
  trap - EXIT HUP INT TERM
  if [[ "${INJECTED}" == 1 ]]; then cleanup_now || true; fi
  exit "${rc}"
}
trap emergency_cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

setup() {
  local actual_config_sha actual_hook_sha actual_helper_sha address
  [[ "${EUID}" == 0 ]] || fail "remote helper must run as root"
  [[ "${INSTANCE_ID}" =~ ^i-[0-9a-f]{17}$ ]] || fail "invalid exact instance ID"
  [[ "${NODE_ID}" =~ ^q124-[a-z0-9-]{8,55}$ ]] || fail "invalid exact Node ID"
  case "${SCENARIO}" in db|s3|control-plane) ;; *) fail "invalid scenario"; return 1 ;; esac
  safe_ref "${CONFIG_REF}" && safe_ref "${HOOK_REF}" || return 1
  for command in jq iptables iptables-save systemd-run systemctl getent timeout flock sha256sum; do command -v "${command}" >/dev/null || return 1; done
  validate_root_file "${CONFIG_REF}" config || return 1
  validate_root_file "${HOOK_REF}" hook || return 1
  [[ -x "${HOOK_REF}" ]] || return 1
  jq -e '
    (keys | sort) == (["schema_version","db_host","db_port","s3_host","s3_port","control_plane_host","control_plane_port","node_listen_ip","node_listen_port","fault_duration_seconds","control_plane_lease_timeout_seconds"] | sort) and
    .schema_version == 1 and
    all([.db_host,.s3_host,.control_plane_host,.node_listen_ip][]; type == "string" and length > 0) and
    .db_port == 5432 and .s3_port == 443 and .control_plane_port == 443 and
    .node_listen_port == 7301 and
    (.fault_duration_seconds | type == "number" and . >= 5 and . <= 300) and
    (.control_plane_lease_timeout_seconds | type == "number" and . >= 5 and . <= 300)
  ' "${CONFIG_REF}" >/dev/null || { fail "fault target config schema is not the exact allowlist"; return 1; }
  actual_config_sha="$(sha256sum "${CONFIG_REF}" | awk '{print $1}')"
  actual_hook_sha="$(sha256sum "${HOOK_REF}" | awk '{print $1}')"
  actual_helper_sha="$(sha256sum "$0" | awk '{print $1}')"
  [[ "${actual_config_sha}" == "${EXPECTED_CONFIG_SHA256}" &&
     "${actual_hook_sha}" == "${EXPECTED_HOOK_SHA256}" &&
     "${actual_helper_sha}" == "${EXPECTED_HELPER_SHA256}" ]] ||
    { fail "qualification asset SHA mismatch"; return 1; }

  mkdir -p /run/lock
  exec 9>"${LOCK_FILE}"
  flock -n 9 || { fail "another q124 fault run holds the Host lock"; return 1; }
  mkdir "${STATE_DIR}" || { fail "duplicate RUN_ID/provenance directory"; return 1; }
  chmod 0700 "${STATE_DIR}"
  printf 'ordinal\tutc\tscenario\tstate\tresult\n' >"${TIMELINE}"
  printf 'started_at\tcompleted_at\tkind\tphase\taddress\tport\trc\texpected\n' >"${PROBES}"
  jq -n --arg run_id "${RUN_ID}" --arg scenario "${SCENARIO}" \
    --arg instance "${INSTANCE_ID}" --arg node "${NODE_ID}" --arg test_sha "${TEST_SHA}" \
    --arg harness_sha "${HARNESS_SHA256}" --arg helper_sha "${actual_helper_sha}" \
    --arg config_sha "${actual_config_sha}" --arg hook_sha "${actual_hook_sha}" \
    --arg comment "${COMMENT}" --arg chain4o "${CHAIN4O}" --arg chain4i "${CHAIN4I}" \
    --arg chain6o "${CHAIN6O}" --arg chain6i "${CHAIN6I}" \
    '{schema_version:1,run_id:$run_id,scenario:$scenario,temp_instance_id:$instance,
      node_id:$node,test_sha:$test_sha,harness_sha256:$harness_sha,
      helper_sha256:$helper_sha,config_sha256:$config_sha,hook_sha256:$hook_sha,
      firewall:{comment:$comment,chains:[$chain4o,$chain4i,$chain6o,$chain6i]}}' >"${PROVENANCE}"

  "${HOOK_REF}" ensure-cordoned --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/cordon-operation.json" >/dev/null 2>&1 || return 1
  cordon_evidence_valid "${STATE_DIR}/cordon-operation.json" || return 1

  take_snapshot setup || return 1
  record ownership-snapshot PASS

  case "${SCENARIO}" in
    db)
      TARGET_HOST="$(conf_get db_host)"; TARGET_PORT="$(conf_get db_port)"
      [[ "${TARGET_HOST}" == *.rds.amazonaws.com ]] || return 1
      ;;
    s3)
      TARGET_HOST="$(conf_get s3_host)"; TARGET_PORT="$(conf_get s3_port)"
      [[ "${TARGET_HOST}" == s3.*.amazonaws.com || "${TARGET_HOST}" == *.s3.*.amazonaws.com ]] || return 1
      ;;
    control-plane)
      TARGET_HOST="$(conf_get control_plane_host)"
      TARGET_PORT="$(conf_get control_plane_port)"
      NODE_LISTEN_IP="$(conf_get node_listen_ip)"
      NODE_LISTEN_PORT="$(conf_get node_listen_port)"
      [[ "${TARGET_HOST}" == *.cats.run || "${TARGET_HOST}" == cats.run ]] || return 1
      ip -4 -o addr show scope global | awk '{sub(/\/.*/, "", $4); print $4}' | grep -Fxq "${NODE_LISTEN_IP}" || return 1
      ;;
  esac
  [[ "${TARGET_PORT}" =~ ^[0-9]+$ ]] || return 1
  [[ "${SCENARIO}" != db || "${TARGET_PORT}" == 5432 ]] || return 1
  [[ "${SCENARIO}" != s3 || "${TARGET_PORT}" == 443 ]] || return 1
  [[ "${SCENARIO}" != control-plane || ("${TARGET_PORT}" == 443 && "${NODE_LISTEN_PORT}" == 7301) ]] || return 1
  jq -e --arg db "$(conf_get db_host)" --arg s3 "$(conf_get s3_host)" \
    --arg cp "$(conf_get control_plane_host)" --arg node_ip "$(conf_get node_listen_ip)" '
      .dependency_endpoints == {db_host:$db,s3_host:$s3,control_plane_host:$cp,node_listen_ip:$node_ip}
    ' "${STATE_DIR}/ownership-setup.json" >/dev/null ||
    { fail "fault targets do not independently match the Cats runtime snapshot"; return 1; }
  mapfile -t V4_ADDRS < <(resolve_v4 "${TARGET_HOST}")
  ((${#V4_ADDRS[@]} > 0)) || return 1
  for address in "${V4_ADDRS[@]}"; do
    [[ "${address}" =~ ^[0-9]+([.][0-9]+){3}$ ]] || return 1
    ip -4 route get "${address}" >/dev/null 2>&1 || return 1
  done
  IPV6_ROUTABLE=false
  V6_ADDRS=()
  if ip -6 route show default | grep -q .; then
    IPV6_ROUTABLE=true
    command -v ip6tables >/dev/null 2>&1 || return 1
    command -v ip6tables-save >/dev/null 2>&1 || return 1
    mapfile -t V6_ADDRS < <(resolve_v6 "${TARGET_HOST}")
    ((${#V6_ADDRS[@]} > 0)) || { fail "IPv6 default route exists but target AAAA set is empty"; return 1; }
    for address in "${V6_ADDRS[@]}"; do ip -6 route get "${address}" >/dev/null 2>&1 || return 1; done
  fi
  rules_absent || { fail "duplicate RUN_ID firewall provenance already exists"; return 1; }
  write_cleanup_script || return 1
}

pre_injection() {
  "${HOOK_REF}" state --scenario "${SCENARIO}" --phase before \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/state-before.json" >/dev/null 2>&1 || return 1
  state_valid "${STATE_DIR}/state-before.json" || return 1
  all_probes_positive || return 1
  record positive-tcp PASS
  record positive-real-read PASS
  take_snapshot before || return 1
  record ownership-before PASS
}

fault_window() {
  local watchdog_delay packets_after_probe packets_after_workload configured_seconds
  if [[ "${SCENARIO}" == control-plane ]]; then
    configured_seconds="$(conf_get control_plane_lease_timeout_seconds)"
    [[ "${configured_seconds}" =~ ^[0-9]+$ ]] || return 1
    (( configured_seconds >= 5 && configured_seconds <= 300 )) || return 1
    watchdog_delay="$(( configured_seconds + 35 ))s"
  else
    configured_seconds="$(conf_get fault_duration_seconds)"
    [[ "${configured_seconds}" =~ ^[0-9]+$ ]] || return 1
    (( configured_seconds >= 5 && configured_seconds <= 300 )) || return 1
    watchdog_delay="$(( configured_seconds + 30 ))s"
  fi
  systemd-run --quiet --unit "${WATCHDOG_UNIT}" --on-active "${watchdog_delay}" \
    --property Type=oneshot --property Restart=on-failure --property RestartSec=5s \
    --property StartLimitIntervalSec=0 /bin/bash "${CLEANUP_SCRIPT}" || return 1
  systemctl is-active --quiet "${WATCHDOG_UNIT}.timer" || return 1
  WATCHDOG_ARMED=1
  record watchdog-active PASS
  inject_rules || return 1
  record injected PASS
  all_probes_negative isolated || return 1
  record negative-tcp PASS
  record negative-real-read PASS
  packets_after_probe="$(packet_count)" || return 1
  (( packets_after_probe > 0 )) || return 1
  "${HOOK_REF}" exercise --scenario "${SCENARIO}" --phase isolated \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/oracle-isolated.json" >/dev/null 2>&1 || return 1
  oracle_valid "${STATE_DIR}/oracle-isolated.json" isolated || return 1
  packets_after_workload="$(packet_count)" || return 1
  (( packets_after_workload > packets_after_probe )) ||
    { fail "workload produced no firewall counter delta"; return 1; }
  record workload PASS
  "${HOOK_REF}" state --scenario "${SCENARIO}" --phase during \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/state-during.json" >/dev/null 2>&1 || return 1
  state_valid "${STATE_DIR}/state-during.json" || return 1
  take_snapshot isolated || return 1
  record ownership-isolated PASS
  printf 'packets_after_probe=%s\npackets_after_workload=%s\nworkload_delta=%s\nipv6_routable=%s\n' \
    "${packets_after_probe}" "${packets_after_workload}" \
    "$((packets_after_workload - packets_after_probe))" "${IPV6_ROUTABLE}" >"${COUNTERS}"
  record packet-counter PASS
}

post_recovery() {
  local deadline=$((SECONDS + 90)) before_identity after_identity
  record cleanup PASS
  rules_absent || return 1
  record rules-absent PASS
  until all_probes_positive; do
    (( SECONDS < deadline )) || return 1
    sleep 2
  done
  record recovery-tcp PASS
  record recovery-real-read PASS
  "${HOOK_REF}" exercise --scenario "${SCENARIO}" --phase recovered \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/oracle-recovered.json" >/dev/null 2>&1 || return 1
  oracle_valid "${STATE_DIR}/oracle-recovered.json" recovered || return 1
  "${HOOK_REF}" state --scenario "${SCENARIO}" --phase after \
    --workspace-id "${WORKSPACE_ID}" --node-id "${NODE_ID}" \
    --output "${STATE_DIR}/state-after.json" >/dev/null 2>&1 || return 1
  state_valid "${STATE_DIR}/state-after.json" || return 1
  take_snapshot after || return 1
  record ownership-after PASS
  "${HOOK_REF}" assert --scenario "${SCENARIO}" \
    --before "${STATE_DIR}/state-before.json" \
    --during "${STATE_DIR}/state-during.json" \
    --after "${STATE_DIR}/state-after.json" >/dev/null 2>&1 || return 1
  before_identity="$(jq -Sc '[.cats[] | {cat_name,digest}] | sort_by(.cat_name)' "${STATE_DIR}/state-before.json")"
  after_identity="$(jq -Sc '[.cats[] | {cat_name,digest}] | sort_by(.cat_name)' "${STATE_DIR}/state-after.json")"
  [[ "${before_identity}" == "${after_identity}" ]] || return 1
  if [[ "${SCENARIO}" == control-plane ]]; then
    before_identity="$(jq -Sc '[.cats[] | {cat_name,generation,node_id,disk_epoch}] | sort_by(.cat_name)' "${STATE_DIR}/state-before.json")"
    after_identity="$(jq -Sc '[.cats[] | {cat_name,generation,node_id,disk_epoch}] | sort_by(.cat_name)' "${STATE_DIR}/state-after.json")"
    [[ "${before_identity}" == "${after_identity}" ]] || return 1
  fi
  record converged PASS
}

emit_file() {
  [[ -f "$2" ]] || return 0
  printf '%s=' "$1"
  openssl base64 -A -in "$2"
  printf '\n'
}

evidence_safe() {
  local file
  for file in "$@"; do
    [[ ! -f "${file}" ]] || [[ "$(wc -c <"${file}")" -le 65536 ]] || return 1
    [[ ! -f "${file}" ]] || ! grep -Eiq 'authorization:|proxy-authorization:|bearer[[:space:]]|set-cookie:|cookie:|x-amz-security-token|aws_(access_key|secret_access_key|session_token)|(^|[^A-Z0-9])(AKIA|ASIA)[A-Z0-9]{16}|password[[:space:]]*[:=]|passwd[[:space:]]*[:=]|client_secret[[:space:]]*[:=]|api[_-]?key[[:space:]]*[:=]|token[[:space:]]*[:=]|worker[.]env|BEGIN ([A-Z ]+ )?PRIVATE KEY|postgres(ql)?://[^[:space:]:]+:[^[:space:]@]+@|eyJ[A-Za-z0-9_-]{8,}[.]eyJ[A-Za-z0-9_-]{8,}[.]' "${file}" || return 1
  done
}

setup || FUNCTIONAL_RC=$?
if (( FUNCTIONAL_RC == 0 )); then pre_injection || FUNCTIONAL_RC=$?; fi
if (( FUNCTIONAL_RC == 0 )); then fault_window || FUNCTIONAL_RC=$?; fi
cleanup_now || CLEANUP_RC=$?
if (( FUNCTIONAL_RC == 0 && CLEANUP_RC == 0 )); then post_recovery || FUNCTIONAL_RC=$?; fi
evidence_safe "${STATE_DIR}"/*.json "${TIMELINE}" "${PROBES}" "${COUNTERS}" || FUNCTIONAL_RC=72
emit_file Q124_STATE_BEFORE "${STATE_DIR}/state-before.json"
emit_file Q124_STATE_DURING "${STATE_DIR}/state-during.json"
emit_file Q124_STATE_AFTER "${STATE_DIR}/state-after.json"
emit_file Q124_ORACLE_ISOLATED "${STATE_DIR}/oracle-isolated.json"
emit_file Q124_ORACLE_RECOVERED "${STATE_DIR}/oracle-recovered.json"
emit_file Q124_TIMELINE "${TIMELINE}"
emit_file Q124_COUNTERS "${COUNTERS}"
emit_file Q124_PROBES "${PROBES}"
emit_file Q124_PROVENANCE "${PROVENANCE}"
emit_file Q124_CORDON_OPERATION "${STATE_DIR}/cordon-operation.json"
emit_file Q124_OWNERSHIP_BEFORE "${STATE_DIR}/ownership-before.json"
emit_file Q124_OWNERSHIP_ISOLATED "${STATE_DIR}/ownership-isolated.json"
emit_file Q124_OWNERSHIP_AFTER "${STATE_DIR}/ownership-after.json"
emit_file Q124_CLEANUP_ERRORS "${STATE_DIR}/cleanup-errors.log"
printf 'Q124_RESULT functional_rc=%s cleanup_rc=%s\n' "${FUNCTIONAL_RC}" "${CLEANUP_RC}"
trap - EXIT HUP INT TERM
if (( FUNCTIONAL_RC != 0 || CLEANUP_RC != 0 )); then exit 1; fi
exit 0
Q124_REMOTE
}

main "$@"
