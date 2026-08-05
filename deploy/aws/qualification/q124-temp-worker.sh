#!/usr/bin/env bash
# Issue #124 temporary worker lifecycle. Every mutating operation is bound to
# an exact instance id, node id, source proof and canonical manifest digest.
set -euo pipefail
umask 077

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
AWS_BIN=${Q124_AWS_BIN:-aws}
CONTROL_BIN=${Q124_CONTROL_BIN:-$ROOT/deploy/aws/qualification/q124-control-api.sh}
REMOTE_BIN=${Q124_REMOTE_BIN:-$ROOT/deploy/aws/qualification/q124-ssm.sh}
MANIFEST_PUBLISH_BIN=${Q124_MANIFEST_PUBLISH_BIN:-$ROOT/deploy/aws/qualification/q124-manifest-publish.sh}
MODE=${Q124_MODE:-${1:-}}
CREATED_INSTANCE=
CLEANUP_ARMED=0
WORKER_START_ATTEMPTED=0

die() { printf 'q124: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
awsq() { "$AWS_BIN" --region "$Q124_REGION" "$@"; }
control() { "$CONTROL_BIN" "$@"; }
remote() { "$REMOTE_BIN" "$@"; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

emit_evidence() {
  [[ -n ${Q124_EVIDENCE_OUT:-} ]] || return 0
  local status=$1 count=${2:-0} instance=${3:-}
  jq -n --arg status "$status" --arg node "${Q124_NODE_ID:-}" --arg run "${run_id:-}" \
    --arg source_sha "${sha:-}" --arg instance "$instance" --argjson count "$count" \
    --arg manifest_sha "${Q124_EXPECTED_MANIFEST_SHA256:-}" --argjson start_attempted "$WORKER_START_ATTEMPTED" \
    '{schema:1,issue:124,status:$status,node_id:$node,github_run_id:$run,source_sha:$source_sha,manifest_sha256:(if $manifest_sha == "" then null else $manifest_sha end),worker_start_attempted:($start_attempted == 1),discovered_instances:$count,instance_id:(if $instance == "" then null else $instance end)}' \
    >"$Q124_EVIDENCE_OUT"
}

require_operation_window() {
  [[ ${Q124_OPERATION_DEADLINE_EPOCH:-} =~ ^[0-9]{10}$ ]] || die "missing/invalid operation deadline"
  [[ ${Q124_CLEANUP_RESERVE_SECONDS:-} =~ ^[1-9][0-9]{2,3}$ ]] || die "missing/invalid cleanup reserve"
  now_epoch=$(date -u +%s)
  (( now_epoch + Q124_CLEANUP_RESERVE_SECONDS < Q124_OPERATION_DEADLINE_EPOCH )) \
    || die "operation deadline reached; preserving cleanup reserve"
}

prepare_remote_budget() {
  local now_epoch available configured
  require_operation_window
  configured=${Q124_SSM_MAX_EXECUTION_TIMEOUT_SECONDS:-4200}
  [[ $configured =~ ^[1-9][0-9]{2,3}$ ]] && (( configured <= 4200 )) || die "invalid SSM maximum execution timeout"
  now_epoch=$(date -u +%s)
  available=$((Q124_OPERATION_DEADLINE_EPOCH - now_epoch - 270))
  (( available >= 60 )) || die "insufficient time for another bounded SSM command"
  (( configured < available )) && available=$configured
  Q124_SSM_EXECUTION_TIMEOUT_SECONDS=$available
  Q124_SSM_DELIVERY_TIMEOUT_SECONDS=60
  Q124_SSM_POLL_TIMEOUT_SECONDS=$((available + 120))
  Q124_SSM_CANCEL_TIMEOUT_SECONDS=180
  export Q124_SSM_EXECUTION_TIMEOUT_SECONDS Q124_SSM_DELIVERY_TIMEOUT_SECONDS Q124_SSM_POLL_TIMEOUT_SECONDS Q124_SSM_CANCEL_TIMEOUT_SECONDS
}

validate_fixed_inputs() {
  for name in Q124_ACCOUNT_ID Q124_REGION Q124_CLUSTER Q124_WORKSPACE_ID Q124_SOURCE_INSTANCE_ID Q124_SOURCE_NODE_ID Q124_CONTROL_URL Q124_CONTROL_AUTHORITY; do need "$name"; done
  [[ $Q124_ACCOUNT_ID =~ ^[0-9]{12}$ ]] || die "invalid fixed account"
  [[ $Q124_REGION =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]$ ]] || die "invalid fixed region"
  [[ $Q124_CLUSTER =~ ^[A-Za-z0-9._-]+$ && $Q124_WORKSPACE_ID =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid cluster/workspace id"
  [[ $Q124_SOURCE_INSTANCE_ID =~ ^i-[0-9a-f]+$ ]] || die "invalid source instance id"
  [[ $Q124_SOURCE_NODE_ID =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid source node id"
  [[ $Q124_SOURCE_NODE_ID != q124-* ]] || die "source node cannot be a qualification node"
  [[ $Q124_CONTROL_AUTHORITY =~ ^[A-Za-z0-9.-]+(:[0-9]{1,5})?$ ]] || die "invalid control authority"
  if [[ $Q124_CONTROL_AUTHORITY == *:* ]]; then
    control_port=${Q124_CONTROL_AUTHORITY##*:}
    (( control_port <= 65535 )) || die "control authority port is out of range"
  fi
  [[ ${Q124_CONTROL_URL%/} == "https://$Q124_CONTROL_AUTHORITY" ]] || die "control URL must be HTTPS on the expected authority with no path"
  actual=$(awsq sts get-caller-identity --query Account --output text)
  [[ $actual == "$Q124_ACCOUNT_ID" ]] || die "AWS account mismatch: expected $Q124_ACCOUNT_ID"
}

source_positive() {
  # These are calibrators, never mutation targets.
  awsq ec2 describe-instances --instance-ids "$Q124_SOURCE_INSTANCE_ID" --output json \
    | jq -e --arg id "$Q124_SOURCE_INSTANCE_ID" '
        ([.Reservations[].Instances[]] | length) == 1 and
        .Reservations[0].Instances[0].InstanceId == $id and
        .Reservations[0].Instances[0].State.Name == "running"
      ' >/dev/null || die "source instance positive probe failed"
  control get "$Q124_SOURCE_NODE_ID" >/dev/null || die "source node positive probe failed"
}

source_template() {
  local json
  json=$(awsq ec2 describe-instances --instance-ids "$Q124_SOURCE_INSTANCE_ID" --output json)
  jq -e --arg ami "$Q124_AMI_ID" --arg type "$Q124_INSTANCE_TYPE" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" '
    .Reservations[0].Instances[0] as $i |
    $i.ImageId == $ami and $i.InstanceType == $type and $i.SubnetId == $subnet and
    [$i.SecurityGroups[].GroupId] == [$sg] and
    ($i.IamInstanceProfile.Arn | endswith("/" + $profile)) and
    ($i | has("PublicIpAddress") | not) and
    $i.MetadataOptions.HttpTokens == "required" and $i.MetadataOptions.HttpEndpoint == "enabled"
  ' <<<"$json" >/dev/null || die "source worker does not match the fixed read-only launch template"
}

canonical_manifest() {
  jq -S -c . "$1"
}

iso_epoch() {
  date -u -d "$1" +%s 2>/dev/null || date -j -u -f '%Y-%m-%dT%H:%M:%SZ' "$1" +%s 2>/dev/null
}

load_manifest() {
  need Q124_MANIFEST
  need Q124_EXPECTED_MANIFEST_SHA256
  [[ -f $Q124_MANIFEST && ! -L $Q124_MANIFEST ]] || die "manifest must be a regular non-symlink"
  actual=$(canonical_manifest "$Q124_MANIFEST" | sha256sum | awk '{print $1}')
  [[ $actual == "$Q124_EXPECTED_MANIFEST_SHA256" ]] || die "manifest hash mismatch"
  jq -e \
    --arg account "$Q124_ACCOUNT_ID" --arg region "$Q124_REGION" --arg cluster "$Q124_CLUSTER" \
    --arg workspace "$Q124_WORKSPACE_ID" --arg source_i "$Q124_SOURCE_INSTANCE_ID" --arg source_n "$Q124_SOURCE_NODE_ID" '
      .schema == 1 and .issue == 124 and
      .fixed.account_id == $account and .fixed.region == $region and .fixed.cluster == $cluster and
      .fixed.workspace_id == $workspace and .source.instance_id == $source_i and .source.node_id == $source_n and
      (.temporary.instance_id | test("^i-[0-9a-f]+$")) and (.temporary.node_id | test("^q124-[A-Za-z0-9.-]+$")) and
      (.temporary.private_ip | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) and
      .launch.method == "run-instances" and .launch.launch_template == null and
      (.launch.ami | test("^ami-[0-9a-f]+$")) and (.launch.instance_type | endswith(".metal")) and
      (.launch.ami_owner_id | test("^[0-9]{12}$")) and
      (.launch.ami_snapshot_ids | type == "array" and length > 0 and all(.[]; test("^snap-[0-9a-f]+$"))) and
      (.launch.subnet_id | test("^subnet-[0-9A-Za-z]+$")) and (.launch.security_group_id | test("^sg-[0-9A-Za-z]+$")) and
      (.launch.instance_profile | test("^[A-Za-z0-9+=,.@_-]+$")) and (.launch.cache_device | test("^/dev/[A-Za-z0-9._-]+$")) and
      .launch.root_device == "/dev/sda1" and (.launch.root_volume_id | test("^vol-[0-9A-Za-z]+$")) and
      .launch.root_delete_on_termination == true and .launch.root_encrypted == true and
      .launch.root_volume_type == "gp3" and .launch.root_volume_size_gib == 200 and
      (.toolchain.aws_cli_version | test("^2\\.[0-9]+\\.[0-9]+$")) and
      (.toolchain.aws_cli_x86_64_sha256 | test("^[0-9a-f]{64}$")) and
      (.toolchain.jq_version | test("^jq-[0-9]+\\.[0-9]+(\\.[0-9]+)?$")) and
      (.bundle.source_sha | test("^[0-9a-f]{40,64}$")) and
      (.bundle.github_run_id | test("^[0-9]+$")) and
      (.bundle.archive_sha256 | test("^[0-9a-f]{64}$")) and
      .bundle.archive_key == ("worker/qualification-124/" + .bundle.source_sha + "/q124-source-" + .bundle.archive_sha256 + ".tar.gz") and
      (.bundle.orchestrator_sha256 | test("^[0-9a-f]{64}$")) and
      (.bundle.remote_sha256 | test("^[0-9a-f]{64}$")) and
      (.bundle.ssm_sha256 | test("^[0-9a-f]{64}$")) and
      (.bundle.bootstrap_sha256 | test("^[0-9a-f]{64}$")) and
      (.bundle.command_guard_sha256 | test("^[0-9a-f]{64}$"))
    ' "$Q124_MANIFEST" >/dev/null || die "manifest provenance/scope mismatch"
  Q124_INSTANCE_ID=$(jq -er '.temporary.instance_id' "$Q124_MANIFEST")
  Q124_NODE_ID=$(jq -er '.temporary.node_id' "$Q124_MANIFEST")
  Q124_PRIVATE_IP=$(jq -er '.temporary.private_ip' "$Q124_MANIFEST")
  Q124_MANIFEST_SOURCE_SHA=$(jq -er '.bundle.source_sha' "$Q124_MANIFEST")
  Q124_MANIFEST_RUN_ID=$(jq -er '.bundle.github_run_id' "$Q124_MANIFEST")
  Q124_EXPECTED_AMI=$(jq -er '.launch.ami' "$Q124_MANIFEST")
  Q124_EXPECTED_AMI_OWNER=$(jq -er '.launch.ami_owner_id' "$Q124_MANIFEST")
  Q124_EXPECTED_AMI_SNAPSHOTS=$(jq -ec '.launch.ami_snapshot_ids' "$Q124_MANIFEST")
  Q124_EXPECTED_INSTANCE_TYPE=$(jq -er '.launch.instance_type' "$Q124_MANIFEST")
  Q124_EXPECTED_SUBNET=$(jq -er '.launch.subnet_id' "$Q124_MANIFEST")
  Q124_EXPECTED_SECURITY_GROUP=$(jq -er '.launch.security_group_id' "$Q124_MANIFEST")
  Q124_EXPECTED_INSTANCE_PROFILE=$(jq -er '.launch.instance_profile' "$Q124_MANIFEST")
  Q124_EXPECTED_CACHE_DEVICE=$(jq -er '.launch.cache_device' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_DEVICE=$(jq -er '.launch.root_device' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_VOLUME_ID=$(jq -er '.launch.root_volume_id' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION=$(jq -er '.launch.root_delete_on_termination' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_ENCRYPTED=$(jq -er '.launch.root_encrypted' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_VOLUME_TYPE=$(jq -er '.launch.root_volume_type' "$Q124_MANIFEST")
  Q124_EXPECTED_ROOT_VOLUME_SIZE_GIB=$(jq -er '.launch.root_volume_size_gib' "$Q124_MANIFEST")
  Q124_MANIFEST_AWS_CLI_VERSION=$(jq -er '.toolchain.aws_cli_version' "$Q124_MANIFEST")
  Q124_MANIFEST_AWS_CLI_SHA256=$(jq -er '.toolchain.aws_cli_x86_64_sha256' "$Q124_MANIFEST")
  Q124_MANIFEST_JQ_VERSION=$(jq -er '.toolchain.jq_version' "$Q124_MANIFEST")
  created_epoch=$(iso_epoch "$(jq -er '.timestamps.created_at' "$Q124_MANIFEST")") || die "invalid manifest created_at"
  expires_epoch=$(iso_epoch "$(jq -er '.timestamps.expires_at' "$Q124_MANIFEST")") || die "invalid manifest expires_at"
  now_epoch=$(date -u +%s)
  (( expires_epoch > created_epoch && expires_epoch - created_epoch >= 3600 && expires_epoch - created_epoch <= 86400 )) || die "manifest TTL is outside 1..24 hours"
  (( created_epoch <= now_epoch + 300 )) || die "manifest creation timestamp is in the future"
  if [[ $MODE == validate ]] && (( now_epoch > expires_epoch )); then
    die "qualification manifest expired; proceed only with drain/withdraw/return"
  elif (( now_epoch > expires_epoch )); then
    printf 'q124: manifest TTL expired; cleanup transition remains enabled\n' >&2
  fi
  export Q124_INSTANCE_ID Q124_NODE_ID Q124_PRIVATE_IP Q124_MANIFEST_SOURCE_SHA Q124_MANIFEST_RUN_ID
  export Q124_EXPECTED_AMI Q124_EXPECTED_AMI_OWNER Q124_EXPECTED_AMI_SNAPSHOTS Q124_EXPECTED_INSTANCE_TYPE Q124_EXPECTED_SUBNET Q124_EXPECTED_SECURITY_GROUP Q124_EXPECTED_INSTANCE_PROFILE Q124_EXPECTED_CACHE_DEVICE
  export Q124_EXPECTED_ROOT_DEVICE Q124_EXPECTED_ROOT_VOLUME_ID Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION Q124_EXPECTED_ROOT_ENCRYPTED Q124_EXPECTED_ROOT_VOLUME_TYPE Q124_EXPECTED_ROOT_VOLUME_SIZE_GIB
  export Q124_MANIFEST_AWS_CLI_VERSION Q124_MANIFEST_AWS_CLI_SHA256 Q124_MANIFEST_JQ_VERSION
}

assert_instance_identity() {
  local json=$1 expected_sha expected_run expected_ami expected_type expected_subnet expected_sg expected_profile
  expected_sha=${Q124_MANIFEST_SOURCE_SHA:-${GITHUB_SHA:-}}
  expected_run=${Q124_MANIFEST_RUN_ID:-${GITHUB_RUN_ID:-}}
  expected_ami=${Q124_EXPECTED_AMI:-${Q124_AMI_ID:-}}
  expected_type=${Q124_EXPECTED_INSTANCE_TYPE:-${Q124_INSTANCE_TYPE:-}}
  expected_subnet=${Q124_EXPECTED_SUBNET:-${Q124_SUBNET_ID:-}}
  expected_sg=${Q124_EXPECTED_SECURITY_GROUP:-${Q124_SECURITY_GROUP_ID:-}}
  expected_profile=${Q124_EXPECTED_INSTANCE_PROFILE:-${Q124_INSTANCE_PROFILE_NAME:-}}
  [[ -n $expected_ami && -n $expected_type && -n $expected_subnet && -n $expected_sg && -n $expected_profile ]] || die "missing immutable launch allowlist"
  jq -e --arg id "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" --arg ip "${Q124_PRIVATE_IP:-}" --arg source_sha "$expected_sha" --arg run "$expected_run" \
    --arg ami "$expected_ami" --arg type "$expected_type" --arg subnet "$expected_subnet" --arg sg "$expected_sg" --arg profile "$expected_profile" '
    .Reservations[0].Instances[0] as $i |
    $i.InstanceId == $id and
    $i.ImageId == $ami and $i.InstanceType == $type and $i.SubnetId == $subnet and
    [$i.SecurityGroups[].GroupId] == [$sg] and ($i.IamInstanceProfile.Arn | endswith("/" + $profile)) and
    ($ip == "" or $i.PrivateIpAddress == $ip) and ($i | has("PublicIpAddress") | not) and
    $i.MetadataOptions.HttpTokens == "required" and $i.MetadataOptions.HttpEndpoint == "enabled" and
    ($i.Tags | from_entries |
      .CatsIssue == "124" and .CatsPurpose == "temporary-worker-qualification" and
      .CatsNodeId == $node and .Name == ("cats-" + $node) and
      ($source_sha == "" or .CatsSourceSha == $source_sha) and ($run == "" or .CatsRunId == $run))
  ' <<<"$json" >/dev/null || die "instance tags/identity mismatch"
}

exact_instance() {
  local json count
  if ! json=$(awsq ec2 describe-instances --instance-ids "$Q124_INSTANCE_ID" --output json); then
    die "instance lookup failed"
  fi
  count=$(jq -er '[.Reservations[].Instances[]] | length' <<<"$json") || die "instance lookup response was invalid"
  [[ $count == 1 ]] || die "instance lookup was not singular"
  assert_instance_identity "$json"
  printf '%s\n' "$json"
}

lookup_return_instance() {
  # A filter query returns a successful empty result after EC2 purges an old
  # terminated instance, unlike --instance-ids which may return NotFound.
  # Keep count and payload in globals so an API/JQ failure cannot be confused
  # with the only accepted absence state (a successful, valid count of zero).
  if ! RETURN_INSTANCE_JSON=$(awsq ec2 describe-instances --filters \
    "Name=instance-id,Values=$Q124_INSTANCE_ID" --output json); then
    die "return instance lookup failed"
  fi
  RETURN_INSTANCE_COUNT=$(jq -er '[.Reservations[].Instances[]] | length' <<<"$RETURN_INSTANCE_JSON") \
    || die "return instance lookup response was invalid"
  case $RETURN_INSTANCE_COUNT in
    0) ;;
    1) assert_instance_identity "$RETURN_INSTANCE_JSON" ;;
    *) die "return instance lookup was not singular" ;;
  esac
}

no_duplicate_identity() {
  local json
  json=$(awsq ec2 describe-instances --filters \
    "Name=tag:CatsIssue,Values=124" "Name=tag:CatsNodeId,Values=$Q124_NODE_ID" \
    'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down' --output json)
  jq -e --arg id "$Q124_INSTANCE_ID" '
    [.Reservations[].Instances[].InstanceId] as $ids |
    ($ids | length) <= 1 and all($ids[]; . == $id)
  ' <<<"$json" >/dev/null || die "duplicate or conflicting qualification identity"
}

exact_root_volume() {
  local volume=$1 json
  json=$(awsq ec2 describe-volumes --filters "Name=volume-id,Values=$volume" --output json)
  jq -e --arg volume "$volume" --arg instance "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" \
    --arg device "$Q124_EXPECTED_ROOT_DEVICE" --argjson delete_on_termination "$Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION" \
    --arg type "$Q124_EXPECTED_ROOT_VOLUME_TYPE" --argjson size "$Q124_EXPECTED_ROOT_VOLUME_SIZE_GIB" --argjson encrypted "$Q124_EXPECTED_ROOT_ENCRYPTED" '
    (.Volumes | length) == 1 and .Volumes[0].VolumeId == $volume and
    .Volumes[0].Encrypted == $encrypted and .Volumes[0].Size == $size and .Volumes[0].VolumeType == $type and
    (.Volumes[0].Attachments | length) == 1 and .Volumes[0].Attachments[0].InstanceId == $instance and
    .Volumes[0].Attachments[0].Device == $device and
    .Volumes[0].Attachments[0].State == "attached" and
    .Volumes[0].Attachments[0].DeleteOnTermination == $delete_on_termination and
    (.Volumes[0].Tags | from_entries | .CatsIssue == "124" and .CatsPurpose == "temporary-worker-qualification" and .CatsNodeId == $node)
  ' <<<"$json" >/dev/null || die "root volume identity/configuration mismatch"
}

assert_root_binding() {
  local instance_json=$1 root_volume
  root_volume=$(jq -er --arg device "$Q124_EXPECTED_ROOT_DEVICE" --arg volume "$Q124_EXPECTED_ROOT_VOLUME_ID" \
    --argjson delete_on_termination "$Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION" '
      [.Reservations[0].Instances[0].BlockDeviceMappings[] | select(.DeviceName == $device)] as $roots |
      ($roots | length) == 1 and $roots[0].Ebs.VolumeId == $volume and
      $roots[0].Ebs.DeleteOnTermination == $delete_on_termination |
      select(.) | $roots[0].Ebs.VolumeId
    ' <<<"$instance_json") || die "immutable root mapping drifted"
  exact_root_volume "$root_volume"
}

assert_ami() {
  local json snapshots expected_ami expected_owner expected_snapshots
  expected_ami=${Q124_EXPECTED_AMI:-$Q124_AMI_ID}
  expected_owner=${Q124_EXPECTED_AMI_OWNER:-$Q124_AMI_OWNER_ID}
  expected_snapshots=${Q124_EXPECTED_AMI_SNAPSHOTS:-$Q124_AMI_SNAPSHOT_IDS_JSON}
  json=$(awsq ec2 describe-images --image-ids "$expected_ami" --output json) || die "AMI lookup failed"
  jq -e --arg image "$expected_ami" --arg owner "$expected_owner" '
    (.Images | length) == 1 and (.Images[0] as $i |
      $i.ImageId == $image and $i.OwnerId == $owner and $i.Public == true and
      $i.State == "available" and $i.Architecture == "x86_64" and
      $i.RootDeviceType == "ebs" and $i.RootDeviceName == "/dev/sda1" and
      $i.VirtualizationType == "hvm" and $i.EnaSupport == true and
      ($i.BlockDeviceMappings | length) > 0 and
      all($i.BlockDeviceMappings[]; (.Ebs.SnapshotId | type == "string" and test("^snap-[0-9a-f]+$"))) and
      ([$i.BlockDeviceMappings[] | select(.DeviceName == $i.RootDeviceName)] | length) == 1)
  ' <<<"$json" >/dev/null || die "AMI owner/architecture/root mapping contract failed"
  snapshots=$(jq -c '[.Images[0].BlockDeviceMappings[].Ebs.SnapshotId] | unique | sort' <<<"$json") \
    || die "AMI snapshot set was invalid"
  jq -ne --argjson actual "$snapshots" --argjson expected "$expected_snapshots" \
    '$actual == ($expected | unique | sort) and ($actual | length) == ($expected | length) and ($actual | length) > 0' \
    >/dev/null || die "AMI snapshot set differs from the reviewed exact set"
}

confirm() {
  local expected=$1
  [[ ${Q124_CONFIRMATION:-} == "$expected" ]] || die "confirmation mismatch; expected $expected"
}

current_policy_matches_manifest() {
  for name in Q124_AMI_ID Q124_AMI_OWNER_ID Q124_AMI_SNAPSHOT_IDS_JSON Q124_INSTANCE_TYPE Q124_SUBNET_ID Q124_SECURITY_GROUP_ID Q124_INSTANCE_PROFILE_NAME Q124_CACHE_DEVICE Q124_AWS_CLI_VERSION Q124_AWS_CLI_X86_64_SHA256 Q124_JQ_VERSION; do need "$name"; done
  local current_snapshots
  current_snapshots=$(jq -ce 'if type == "array" and length > 0 and all(.[]; type == "string" and test("^snap-[0-9a-f]+$")) then unique | sort else error("invalid") end' <<<"$Q124_AMI_SNAPSHOT_IDS_JSON") \
    || die "current AMI snapshot set is invalid"
  [[ $Q124_AMI_ID == "$Q124_EXPECTED_AMI" && $Q124_INSTANCE_TYPE == "$Q124_EXPECTED_INSTANCE_TYPE" &&
     $Q124_AMI_OWNER_ID == "$Q124_EXPECTED_AMI_OWNER" && $current_snapshots == "$Q124_EXPECTED_AMI_SNAPSHOTS" &&
     $Q124_SUBNET_ID == "$Q124_EXPECTED_SUBNET" && $Q124_SECURITY_GROUP_ID == "$Q124_EXPECTED_SECURITY_GROUP" &&
     $Q124_INSTANCE_PROFILE_NAME == "$Q124_EXPECTED_INSTANCE_PROFILE" && $Q124_CACHE_DEVICE == "$Q124_EXPECTED_CACHE_DEVICE" &&
     $Q124_AWS_CLI_VERSION == "$Q124_MANIFEST_AWS_CLI_VERSION" && $Q124_AWS_CLI_X86_64_SHA256 == "$Q124_MANIFEST_AWS_CLI_SHA256" &&
     $Q124_JQ_VERSION == "$Q124_MANIFEST_JQ_VERSION" ]] \
    || die "current launch policy differs from the immutable manifest"
}

discover_created_instance() {
  local json count discovered deadline
  deadline=$((SECONDS + ${Q124_DISCOVERY_TIMEOUT_SECONDS:-60}))
  while true; do
    if ! json=$(awsq ec2 describe-instances --filters \
      "Name=tag:CatsIssue,Values=124" "Name=tag:CatsPurpose,Values=temporary-worker-qualification" \
      "Name=tag:CatsNodeId,Values=$Q124_NODE_ID" "Name=tag:CatsRunId,Values=$run_id" \
      "Name=tag:CatsSourceSha,Values=$sha" \
      'Name=instance-state-name,Values=pending,running,stopping,stopped,shutting-down' --output json); then
      emit_evidence discovery-error 0
      return 1
    fi
    count=$(jq '[.Reservations[].Instances[]] | length' <<<"$json")
    [[ $count == 1 ]] && break
    if [[ $count != 0 ]] || (( SECONDS >= deadline )); then
      emit_evidence "discovery-count-$count-preserved" "$count"
      printf 'q124: bounded discovery found %s instances; refusing any mutation\n' "$count" >&2
      return 1
    fi
    sleep 5
  done
  discovered=$(jq -er '.Reservations[0].Instances[0].InstanceId | select(test("^i-[0-9a-f]+$"))' <<<"$json") || {
    emit_evidence discovery-invalid-id 1
    return 1
  }
  CREATED_INSTANCE=$discovered
  Q124_INSTANCE_ID=$discovered
  export Q124_INSTANCE_ID
  emit_evidence discovered-singular 1 "$discovered"
}

cleanup_provision_failure() {
  local rc=${1:-$?} fail_rc
  fail_rc=$rc
  (( fail_rc != 0 )) || fail_rc=1
  trap - EXIT INT TERM
  if (( CLEANUP_ARMED )) && [[ -n $CREATED_INSTANCE ]]; then
    printf 'q124: failure cleanup for exact instance %s\n' "$CREATED_INSTANCE" >&2
    Q124_INSTANCE_ID=$CREATED_INSTANCE
    if instance_json=$(exact_instance 2>/dev/null); then
      assert_ami >/dev/null 2>&1 || exit "$fail_rc"
      if [[ -z ${Q124_EXPECTED_ROOT_VOLUME_ID:-} ]]; then
        Q124_EXPECTED_ROOT_VOLUME_ID=$(jq -er --arg device "$Q124_EXPECTED_ROOT_DEVICE" '
          [.Reservations[0].Instances[0].BlockDeviceMappings[] | select(.DeviceName == $device)] as $roots |
          ($roots | length) == 1 and $roots[0].Ebs.DeleteOnTermination == true |
          select(.) | $roots[0].Ebs.VolumeId | select(test("^vol-[0-9A-Za-z]+$"))
        ' <<<"$instance_json") || exit "$fail_rc"
        export Q124_EXPECTED_ROOT_VOLUME_ID
      fi
      assert_root_binding "$instance_json" >/dev/null 2>&1 || exit "$fail_rc"
      if [[ ${Q124_EXPECTED_MANIFEST_SHA256:-} =~ ^[0-9a-f]{64}$ ]]; then
        remote "$CREATED_INSTANCE" recover-active >/dev/null 2>&1 || exit "$fail_rc"
      fi
      # Never kill a host whose workload inventory is unknown or non-empty.
      if control get "$Q124_NODE_ID" >/dev/null 2>&1; then
        control cordon "$Q124_NODE_ID" >/dev/null 2>&1 || exit "$fail_rc"
        if control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124- 2>/dev/null | jq -e 'length == 0' >/dev/null \
          && control get "$Q124_NODE_ID" | jq -e '(.node.state == "cordoned" or .node.state == "lost") and .assigned_cats == 0 and .orphan_cats == 0' >/dev/null; then
          remote "$CREATED_INSTANCE" assert-idle >/dev/null 2>&1 || exit "$fail_rc"
          control get "$Q124_NODE_ID" | jq -e '(.node.state == "cordoned" or .node.state == "lost") and .assigned_cats == 0 and .orphan_cats == 0' >/dev/null || exit "$fail_rc"
          control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124- 2>/dev/null | jq -e 'length == 0' >/dev/null || exit "$fail_rc"
          remote "$CREATED_INSTANCE" stop >/dev/null 2>&1 || exit "$fail_rc"
          control delete "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" "$Q124_WORKSPACE_ID" q124- >/dev/null 2>&1 || exit "$fail_rc"
        else
          printf 'q124: cleanup stopped: node emptiness was not proven\n' >&2
          exit "$fail_rc"
        fi
      else
        # A failed GET is not evidence of absence. The adapter must first
        # prove the source node through the same API and then observe an exact
        # 404 for this node; auth/network/5xx failures stop cleanup.
        control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID" >/dev/null 2>&1 || exit "$fail_rc"
        # Before the first worker start attempt, this invocation's exact fresh
        # instance cannot have accepted a Cat. Bootstrap installs and stages
        # configuration but deliberately does not start cats-worker. Once a
        # start has been attempted, absence from the control plane is not
        # enough: require the host idle/stop gates as well.
        (( WORKER_START_ATTEMPTED == 0 )) || exit "$fail_rc"
      fi
      instance_json=$(exact_instance 2>/dev/null) || exit "$fail_rc"
      assert_root_binding "$instance_json" >/dev/null 2>&1 || exit "$fail_rc"
      assert_ami >/dev/null 2>&1 || exit "$fail_rc"
      awsq ec2 modify-instance-attribute --instance-id "$CREATED_INSTANCE" --disable-api-termination '{"Value":false}' >/dev/null
      awsq ec2 terminate-instances --instance-ids "$CREATED_INSTANCE" >/dev/null
      awsq ec2 wait instance-terminated --instance-ids "$CREATED_INSTANCE"
      emit_evidence cleanup-terminated 1 "$CREATED_INSTANCE"
    else
      exit "$fail_rc"
    fi
  elif (( CLEANUP_ARMED )); then
    discover_created_instance || exit "$fail_rc"
    cleanup_provision_failure "$rc"
  fi
  exit "$rc"
}

provision() {
  confirm PROVISION_Q124_TEMP_WORKER
  for name in Q124_AMI_ID Q124_AMI_OWNER_ID Q124_AMI_SNAPSHOT_IDS_JSON Q124_INSTANCE_TYPE Q124_SUBNET_ID Q124_SECURITY_GROUP_ID Q124_INSTANCE_PROFILE_NAME Q124_ARTIFACT_BUCKET Q124_ARCHIVE_KEY Q124_ARCHIVE_SHA256 Q124_CACHE_DEVICE Q124_CONTROL_URL Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN Q124_DB_SECRET_ARN Q124_DB_NAME Q124_MANIFEST_OUT Q124_AWS_CLI_VERSION Q124_AWS_CLI_X86_64_SHA256 Q124_JQ_VERSION Q124_OPERATION_DEADLINE_EPOCH Q124_CLEANUP_RESERVE_SECONDS GITHUB_REPOSITORY GH_TOKEN; do need "$name"; done
  [[ $GITHUB_REPOSITORY =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid GitHub repository"
  [[ $Q124_INSTANCE_TYPE == *.metal ]] || die "qualification requires a bare-metal instance"
  [[ $Q124_AMI_OWNER_ID =~ ^[0-9]{12}$ ]] || die "invalid expected AMI owner"
  Q124_AMI_SNAPSHOT_IDS_JSON=$(jq -ce 'if type == "array" and length > 0 and all(.[]; type == "string" and test("^snap-[0-9a-f]+$")) then unique | sort else error("invalid") end' <<<"$Q124_AMI_SNAPSHOT_IDS_JSON") \
    || die "invalid exact AMI snapshot set"
  export Q124_AMI_SNAPSHOT_IDS_JSON
  [[ ${Q124_TTL_HOURS:-0} =~ ^([1-9]|1[0-9]|2[0-4])$ ]] || die "TTL must be 1..24 hours"
  assert_ami
  source_positive
  source_template
  require_operation_window
  run_id=${GITHUB_RUN_ID:-local}
  sha=${GITHUB_SHA:-$(git -C "$ROOT" rev-parse HEAD)}
  [[ $run_id =~ ^[0-9]+$ ]] || die "provision requires numeric GITHUB_RUN_ID"
  Q124_NODE_ID="q124-${run_id}-${sha:0:7}"
  Q124_NAME="cats-$Q124_NODE_ID"
  export Q124_NODE_ID

  duplicates=$(awsq ec2 describe-instances --filters \
    "Name=tag:CatsIssue,Values=124" "Name=tag:CatsNodeId,Values=$Q124_NODE_ID" \
    'Name=instance-state-name,Values=pending,running,stopping,stopped' --output json)
  jq -e '[.Reservations[].Instances[]] | length == 0' <<<"$duplicates" >/dev/null || die "duplicate live qualification identity"
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"

  tags=$(jq -cn --arg name "$Q124_NAME" --arg node "$Q124_NODE_ID" --arg run "$run_id" --arg sha "$sha" '
    [{ResourceType:"instance",Tags:[
      {Key:"Name",Value:$name},{Key:"Project",Value:"Cats"},{Key:"CatsIssue",Value:"124"},
      {Key:"CatsPurpose",Value:"temporary-worker-qualification"},{Key:"CatsNodeId",Value:$node},
      {Key:"CatsRunId",Value:$run},{Key:"CatsSourceSha",Value:$sha}
    ]},{ResourceType:"volume",Tags:[
      {Key:"Name",Value:($name + "-root")},{Key:"Project",Value:"Cats"},{Key:"CatsIssue",Value:"124"},
      {Key:"CatsPurpose",Value:"temporary-worker-qualification"},{Key:"CatsNodeId",Value:$node}
    ]}]')
  block=$(jq -cn '[{DeviceName:"/dev/sda1",Ebs:{VolumeSize:200,VolumeType:"gp3",Encrypted:true,DeleteOnTermination:true}}]')
  Q124_EXPECTED_ROOT_DEVICE=/dev/sda1
  Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION=true
  Q124_EXPECTED_ROOT_ENCRYPTED=true
  Q124_EXPECTED_ROOT_VOLUME_TYPE=gp3
  Q124_EXPECTED_ROOT_VOLUME_SIZE_GIB=200
  export Q124_EXPECTED_ROOT_DEVICE Q124_EXPECTED_ROOT_DELETE_ON_TERMINATION Q124_EXPECTED_ROOT_ENCRYPTED Q124_EXPECTED_ROOT_VOLUME_TYPE Q124_EXPECTED_ROOT_VOLUME_SIZE_GIB
  # Arm before RunInstances. AWS may create the instance even when the CLI
  # loses the response or this job receives TERM. The trap can recover only a
  # singular identity matching all five immutable request tags; it never
  # mutates a tag-filter result directly.
  CLEANUP_ARMED=1
  trap cleanup_provision_failure EXIT
  trap 'cleanup_provision_failure 130' INT
  trap 'cleanup_provision_failure 143' TERM
  emit_evidence launch-armed 0
  launched=$(awsq ec2 run-instances --image-id "$Q124_AMI_ID" --instance-type "$Q124_INSTANCE_TYPE" \
    --subnet-id "$Q124_SUBNET_ID" --security-group-ids "$Q124_SECURITY_GROUP_ID" \
    --iam-instance-profile "Name=$Q124_INSTANCE_PROFILE_NAME" --count 1 \
    --client-token "cats-q124-$run_id-${sha:0:12}" --block-device-mappings "$block" \
    --metadata-options 'HttpTokens=required,HttpEndpoint=enabled,HttpPutResponseHopLimit=2' \
    --instance-initiated-shutdown-behavior stop --no-associate-public-ip-address \
    --tag-specifications "$tags" --output json)
  CREATED_INSTANCE=$(jq -er '.Instances | select(length == 1) | .[0].InstanceId' <<<"$launched")
  [[ $CREATED_INSTANCE =~ ^i-[0-9a-f]+$ ]] || die "RunInstances returned no singular instance"
  Q124_INSTANCE_ID=$CREATED_INSTANCE
  export Q124_INSTANCE_ID
  emit_evidence launch-returned-id 1 "$CREATED_INSTANCE"
  awsq ec2 modify-instance-attribute --instance-id "$Q124_INSTANCE_ID" --disable-api-termination '{"Value":true}' >/dev/null
  awsq ec2 wait instance-running --instance-ids "$Q124_INSTANCE_ID"
  awsq ec2 wait instance-status-ok --instance-ids "$Q124_INSTANCE_ID"
  instance=$(exact_instance)
  jq -e --arg ami "$Q124_AMI_ID" --arg type "$Q124_INSTANCE_TYPE" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" '
    .Reservations[0].Instances[0] as $i |
    $i.ImageId == $ami and $i.InstanceType == $type and $i.SubnetId == $subnet and
    [$i.SecurityGroups[].GroupId] == [$sg] and ($i.IamInstanceProfile.Arn | endswith("/" + $profile)) and
    ($i | has("PublicIpAddress") | not) and $i.MetadataOptions.HttpTokens == "required" and
    $i.MetadataOptions.HttpEndpoint == "enabled" and $i.InstanceInitiatedShutdownBehavior == "stop"
  ' <<<"$instance" >/dev/null || die "launched instance differs from fixed template"
  Q124_PRIVATE_IP=$(jq -er '.Reservations[0].Instances[0].PrivateIpAddress' <<<"$instance")
  az=$(jq -er '.Reservations[0].Instances[0].Placement.AvailabilityZone' <<<"$instance")
  root_volume=$(jq -er '
    [.Reservations[0].Instances[0].BlockDeviceMappings[] | select(.DeviceName == "/dev/sda1")] as $roots |
    ($roots | length) == 1 and $roots[0].Ebs.DeleteOnTermination == true and
    ($roots[0].Ebs.VolumeId | test("^vol-[0-9A-Za-z]+$")) |
    select(.) | $roots[0].Ebs.VolumeId
  ' <<<"$instance") || die "root mapping is not singular and DeleteOnTermination=true"
  Q124_EXPECTED_ROOT_VOLUME_ID=$root_volume
  export Q124_EXPECTED_ROOT_VOLUME_ID
  assert_root_binding "$instance"
  export Q124_PRIVATE_IP

  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  expires=$(date -u -d "+${Q124_TTL_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+"${Q124_TTL_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)
  script_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-temp-worker.sh")
  remote_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-remote.sh")
  ssm_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-ssm.sh")
  bootstrap_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-bootstrap-prereqs.sh")
  command_guard_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-command-guard.sh")
  jq -n \
    --arg account "$Q124_ACCOUNT_ID" --arg region "$Q124_REGION" --arg cluster "$Q124_CLUSTER" --arg workspace "$Q124_WORKSPACE_ID" \
    --arg source_i "$Q124_SOURCE_INSTANCE_ID" --arg source_n "$Q124_SOURCE_NODE_ID" \
    --arg instance "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" --arg ip "$Q124_PRIVATE_IP" \
    --arg ami "$Q124_AMI_ID" --arg ami_owner "$Q124_AMI_OWNER_ID" --argjson ami_snapshots "$Q124_AMI_SNAPSHOT_IDS_JSON" \
    --arg type "$Q124_INSTANCE_TYPE" --arg az "$az" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" --arg root_volume "$root_volume" \
    --arg source_sha "$sha" --arg github_run_id "$run_id" --arg archive_key "$Q124_ARCHIVE_KEY" --arg archive_sha "$Q124_ARCHIVE_SHA256" --arg script_sha "$script_sha" --arg remote_sha "$remote_sha" --arg ssm_sha "$ssm_sha" --arg bootstrap_sha "$bootstrap_sha" --arg command_guard_sha "$command_guard_sha" \
    --arg created "$now" --arg expires "$expires" --arg cache "$Q124_CACHE_DEVICE" \
    --arg aws_cli_version "$Q124_AWS_CLI_VERSION" --arg aws_cli_sha "$Q124_AWS_CLI_X86_64_SHA256" --arg jq_version "$Q124_JQ_VERSION" '
      {schema:1,issue:124,fixed:{account_id:$account,region:$region,cluster:$cluster,workspace_id:$workspace},
       source:{instance_id:$source_i,node_id:$source_n},temporary:{instance_id:$instance,node_id:$node,private_ip:$ip},
       launch:{method:"run-instances",launch_template:null,ami:$ami,ami_owner_id:$ami_owner,ami_snapshot_ids:$ami_snapshots,instance_type:$type,availability_zone:$az,subnet_id:$subnet,security_group_id:$sg,instance_profile:$profile,root_device:"/dev/sda1",root_volume_id:$root_volume,root_delete_on_termination:true,root_encrypted:true,root_volume_type:"gp3",root_volume_size_gib:200,cache_device:$cache},
       toolchain:{aws_cli_version:$aws_cli_version,aws_cli_x86_64_sha256:$aws_cli_sha,jq_version:$jq_version},
       bundle:{source_sha:$source_sha,github_run_id:$github_run_id,archive_key:$archive_key,archive_sha256:$archive_sha,orchestrator_sha256:$script_sha,remote_sha256:$remote_sha,ssm_sha256:$ssm_sha,bootstrap_sha256:$bootstrap_sha,command_guard_sha256:$command_guard_sha},
       timestamps:{created_at:$created,expires_at:$expires}}
    ' | jq -S . >"$Q124_MANIFEST_OUT"
  Q124_EXPECTED_MANIFEST_SHA256=$(canonical_manifest "$Q124_MANIFEST_OUT" | sha256sum | awk '{print $1}')
  export Q124_EXPECTED_MANIFEST_SHA256
  emit_evidence manifest-staged 1 "$Q124_INSTANCE_ID"
  "$MANIFEST_PUBLISH_BIN" "$Q124_MANIFEST_OUT" "$Q124_EXPECTED_MANIFEST_SHA256"
  emit_evidence manifest-published 1 "$Q124_INSTANCE_ID"

  require_operation_window
  awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_SOURCE_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 1 and .[0].PingStatus == "Online"' >/dev/null || die "source SSM positive probe failed"
  deadline=$((SECONDS + ${Q124_SSM_TIMEOUT_SECONDS:-600}))
  until awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 1 and .[0].PingStatus == "Online"' >/dev/null; do
    (( SECONDS < deadline )) || die "temporary instance did not become SSM Online"
    sleep 5
  done
  Q124_FORMAT_CONFIRMATION="FORMAT_EPHEMERAL_CACHE_${Q124_INSTANCE_ID}_${Q124_CACHE_DEVICE}"
  export Q124_FORMAT_CONFIRMATION
  prepare_remote_budget
  remote "$Q124_INSTANCE_ID" bootstrap
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
  WORKER_START_ATTEMPTED=1
  emit_evidence worker-start-attempted 1 "$Q124_INSTANCE_ID"
  prepare_remote_budget
  remote "$Q124_INSTANCE_ID" start
  control wait-cordoned "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" 1 >/dev/null
  prepare_remote_budget
  remote "$Q124_INSTANCE_ID" set-capacity
  control wait-cordoned "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" 1024 >/dev/null
  prepare_remote_budget
  remote "$Q124_INSTANCE_ID" validate

  printf 'manifest-sha256=%s\n' "$Q124_EXPECTED_MANIFEST_SHA256"
  CLEANUP_ARMED=0
  trap - EXIT INT TERM
}

validate_mode() {
  confirm "VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; current_policy_matches_manifest; source_positive; assert_ami
  instance=$(exact_instance); assert_root_binding "$instance"; no_duplicate_identity
  control get "$Q124_NODE_ID" | jq -e '.node.state == "cordoned"' >/dev/null || die "node is not Cordoned"
  remote "$Q124_INSTANCE_ID" validate
}

drain_mode() {
  confirm "DRAIN_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; source_positive; assert_ami
  instance=$(exact_instance); assert_root_binding "$instance"; no_duplicate_identity
  assigned=$(control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124-)
  snapshot=$(remote "$Q124_INSTANCE_ID" snapshot)
  jq -e --argjson assigned "$assigned" '([.cats[]] | sort) == ([$assigned[]] | sort)' <<<"$snapshot" >/dev/null || die "control assignment and runtime ledger differ"
  control drain "$Q124_NODE_ID" "$Q124_WORKSPACE_ID"
  control wait-cordoned "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" 1024 >/dev/null
  Q124_PRIOR_ATTACHMENTS_JSON=$(jq -c '.attachments' <<<"$snapshot")
  export Q124_PRIOR_ATTACHMENTS_JSON
  remote "$Q124_INSTANCE_ID" assert-idle
}

withdraw_mode() {
  confirm "WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; source_positive; assert_ami
  instance=$(exact_instance); assert_root_binding "$instance"; no_duplicate_identity
  if summary=$(control get "$Q124_NODE_ID" 2>/dev/null); then
    jq -e '(.node.state == "cordoned" or .node.state == "lost") and .assigned_cats == 0 and .orphan_cats == 0' <<<"$summary" >/dev/null || die "withdraw requires an empty Cordoned/Lost node"
    control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124- >/dev/null
    remote "$Q124_INSTANCE_ID" assert-idle
    control get "$Q124_NODE_ID" | jq -e '(.node.state == "cordoned" or .node.state == "lost") and .assigned_cats == 0 and .orphan_cats == 0' >/dev/null || die "node changed before worker stop"
    control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124- >/dev/null
    remote "$Q124_INSTANCE_ID" stop
    control delete "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" "$Q124_WORKSPACE_ID" q124-
  else
    control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
    remote "$Q124_INSTANCE_ID" assert-idle
    remote "$Q124_INSTANCE_ID" stop
  fi
}

return_mode() {
  load_manifest
  confirm "RETURN_Q124_${Q124_INSTANCE_ID}_${Q124_NODE_ID}"
  source_positive
  assert_ami
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
  root_volume=$(jq -er '.launch.root_volume_id' "$Q124_MANIFEST")
  lookup_return_instance
  # Even after the exact old id is purged, fail if another active instance has
  # appeared with this qualification node identity.
  no_duplicate_identity
  if [[ $RETURN_INSTANCE_COUNT == 1 ]]; then
    state=$(jq -er '.Reservations[0].Instances[0].State.Name' <<<"$RETURN_INSTANCE_JSON")
    if [[ $state != terminated ]]; then
      assert_root_binding "$RETURN_INSTANCE_JSON"
      # A stopped service plus empty ledger is the last data-safety gate.
      remote "$Q124_INSTANCE_ID" assert-idle
      remote "$Q124_INSTANCE_ID" stop
      instance=$(exact_instance)
      assert_root_binding "$instance"
      assert_ami
      awsq ec2 modify-instance-attribute --instance-id "$Q124_INSTANCE_ID" --disable-api-termination '{"Value":false}' >/dev/null
      awsq ec2 terminate-instances --instance-ids "$Q124_INSTANCE_ID" >/dev/null
      awsq ec2 wait instance-terminated --instance-ids "$Q124_INSTANCE_ID"
    fi
  fi
  # Calibrate the same SSM inventory probe against the source before accepting absence.
  awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_SOURCE_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 1 and .[0].PingStatus == "Online"' >/dev/null || die "source SSM calibrator failed"
  deadline=$((SECONDS + ${Q124_SSM_ABSENCE_TIMEOUT_SECONDS:-600}))
  until awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 0' >/dev/null; do
    (( SECONDS < deadline )) || die "terminated instance remains in SSM inventory"
    sleep 5
  done
  deadline=$((SECONDS + ${Q124_VOLUME_ABSENCE_TIMEOUT_SECONDS:-600}))
  until awsq ec2 describe-volumes --filters "Name=volume-id,Values=$root_volume" --output json | jq -e '.Volumes | length == 0' >/dev/null; do
    (( SECONDS < deadline )) || die "qualification root volume was not deleted"
    sleep 5
  done
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
}

recover_provision_mode() {
  confirm "RECOVER_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  need Q124_EVIDENCE_OUT
  [[ -f $Q124_EVIDENCE_OUT && ! -L $Q124_EVIDENCE_OUT ]] || die "recovery evidence must be a regular non-symlink"
  load_manifest
  jq -e --arg instance "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" --arg manifest "$Q124_EXPECTED_MANIFEST_SHA256" '
    .schema == 1 and .issue == 124 and .instance_id == $instance and .node_id == $node and
    .manifest_sha256 == $manifest and (.worker_start_attempted | type == "boolean")
  ' "$Q124_EVIDENCE_OUT" >/dev/null || die "recovery evidence identity mismatch"
  source_positive
  WORKER_START_ATTEMPTED=$(jq -er 'if .worker_start_attempted then 1 else 0 end' "$Q124_EVIDENCE_OUT")
  CREATED_INSTANCE=$Q124_INSTANCE_ID
  CLEANUP_ARMED=1
  cleanup_provision_failure 0
}

validate_fixed_inputs
case $MODE in
  provision) provision ;;
  validate) validate_mode ;;
  drain) drain_mode ;;
  withdraw) withdraw_mode ;;
  return) return_mode ;;
  recover-provision) recover_provision_mode ;;
  *) die "mode must be provision, validate, drain, withdraw, return, or recover-provision" ;;
esac
