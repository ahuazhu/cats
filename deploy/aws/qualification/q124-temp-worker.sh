#!/usr/bin/env bash
# Issue #124 temporary worker lifecycle. Every mutating operation is bound to
# an exact instance id, node id, source proof and canonical manifest digest.
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
AWS_BIN=${Q124_AWS_BIN:-aws}
CONTROL_BIN=${Q124_CONTROL_BIN:-$ROOT/deploy/aws/qualification/q124-control-api.sh}
REMOTE_BIN=${Q124_REMOTE_BIN:-$ROOT/deploy/aws/qualification/q124-ssm.sh}
MODE=${Q124_MODE:-${1:-}}
CREATED_INSTANCE=
CLEANUP_ARMED=0

die() { printf 'q124: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
awsq() { "$AWS_BIN" --region "$Q124_REGION" "$@"; }
control() { "$CONTROL_BIN" "$@"; }
remote() { "$REMOTE_BIN" "$@"; }
sha256_file() { sha256sum "$1" | awk '{print $1}'; }

validate_fixed_inputs() {
  for name in Q124_ACCOUNT_ID Q124_REGION Q124_CLUSTER Q124_WORKSPACE_ID Q124_SOURCE_INSTANCE_ID Q124_SOURCE_NODE_ID Q124_CONTROL_URL Q124_AMI_ID Q124_INSTANCE_TYPE Q124_SUBNET_ID Q124_SECURITY_GROUP_ID Q124_INSTANCE_PROFILE_NAME Q124_CACHE_DEVICE; do need "$name"; done
  [[ $Q124_ACCOUNT_ID =~ ^[0-9]{12}$ ]] || die "invalid fixed account"
  [[ $Q124_REGION =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]$ ]] || die "invalid fixed region"
  [[ $Q124_CLUSTER =~ ^[A-Za-z0-9._-]+$ && $Q124_WORKSPACE_ID =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid cluster/workspace id"
  [[ $Q124_SOURCE_INSTANCE_ID =~ ^i-[0-9a-f]+$ ]] || die "invalid source instance id"
  [[ $Q124_SOURCE_NODE_ID =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid source node id"
  [[ $Q124_SOURCE_NODE_ID != q124-* ]] || die "source node cannot be a qualification node"
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
    --arg workspace "$Q124_WORKSPACE_ID" --arg source_i "$Q124_SOURCE_INSTANCE_ID" --arg source_n "$Q124_SOURCE_NODE_ID" \
    --arg ami "$Q124_AMI_ID" --arg type "$Q124_INSTANCE_TYPE" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" --arg cache "$Q124_CACHE_DEVICE" '
      .schema == 1 and .issue == 124 and
      .fixed.account_id == $account and .fixed.region == $region and .fixed.cluster == $cluster and
      .fixed.workspace_id == $workspace and .source.instance_id == $source_i and .source.node_id == $source_n and
      (.temporary.instance_id | test("^i-[0-9a-f]+$")) and (.temporary.node_id | test("^q124-[A-Za-z0-9.-]+$")) and
      (.temporary.private_ip | test("^[0-9]{1,3}(\\.[0-9]{1,3}){3}$")) and
      .launch.method == "run-instances" and .launch.launch_template == null and
      .launch.ami == $ami and .launch.instance_type == $type and .launch.subnet_id == $subnet and
      .launch.security_group_id == $sg and .launch.instance_profile == $profile and .launch.cache_device == $cache and
      (.launch.root_volume_id | test("^vol-[0-9A-Za-z]+$")) and
      (.bundle.source_sha | test("^[0-9a-f]{40,64}$")) and
      (.bundle.github_run_id | test("^[0-9]+$")) and
      (.bundle.archive_sha256 | test("^[0-9a-f]{64}$")) and
      .bundle.archive_key == ("worker/qualification-124/" + .bundle.source_sha + "/q124-source-" + .bundle.archive_sha256 + ".tar.gz") and
      (.bundle.orchestrator_sha256 | test("^[0-9a-f]{64}$")) and
      (.bundle.remote_sha256 | test("^[0-9a-f]{64}$"))
    ' "$Q124_MANIFEST" >/dev/null || die "manifest provenance/scope mismatch"
  Q124_INSTANCE_ID=$(jq -er '.temporary.instance_id' "$Q124_MANIFEST")
  Q124_NODE_ID=$(jq -er '.temporary.node_id' "$Q124_MANIFEST")
  Q124_PRIVATE_IP=$(jq -er '.temporary.private_ip' "$Q124_MANIFEST")
  Q124_MANIFEST_SOURCE_SHA=$(jq -er '.bundle.source_sha' "$Q124_MANIFEST")
  Q124_MANIFEST_RUN_ID=$(jq -er '.bundle.github_run_id' "$Q124_MANIFEST")
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
}

exact_instance() {
  local json count expected_sha expected_run
  json=$(awsq ec2 describe-instances --instance-ids "$Q124_INSTANCE_ID" --output json)
  count=$(jq '[.Reservations[].Instances[]] | length' <<<"$json")
  [[ $count == 1 ]] || die "instance lookup was not singular"
  expected_sha=${Q124_MANIFEST_SOURCE_SHA:-${GITHUB_SHA:-}}
  expected_run=${Q124_MANIFEST_RUN_ID:-${GITHUB_RUN_ID:-}}
  jq -e --arg id "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" --arg ip "${Q124_PRIVATE_IP:-}" --arg source_sha "$expected_sha" --arg run "$expected_run" \
    --arg ami "$Q124_AMI_ID" --arg type "$Q124_INSTANCE_TYPE" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" '
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
  printf '%s\n' "$json"
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
  jq -e --arg volume "$volume" --arg instance "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" '
    (.Volumes | length) == 1 and .Volumes[0].VolumeId == $volume and
    .Volumes[0].Encrypted == true and .Volumes[0].Size == 200 and .Volumes[0].VolumeType == "gp3" and
    (.Volumes[0].Attachments | length) == 1 and .Volumes[0].Attachments[0].InstanceId == $instance and
    (.Volumes[0].Tags | from_entries | .CatsIssue == "124" and .CatsPurpose == "temporary-worker-qualification" and .CatsNodeId == $node)
  ' <<<"$json" >/dev/null || die "root volume identity/configuration mismatch"
}

confirm() {
  local expected=$1
  [[ ${Q124_CONFIRMATION:-} == "$expected" ]] || die "confirmation mismatch; expected $expected"
}

cleanup_provision_failure() {
  local rc=${1:-$?}
  trap - EXIT INT TERM
  if (( CLEANUP_ARMED )) && [[ -n $CREATED_INSTANCE ]]; then
    printf 'q124: failure cleanup for exact instance %s\n' "$CREATED_INSTANCE" >&2
    Q124_INSTANCE_ID=$CREATED_INSTANCE
    if exact_instance >/dev/null 2>&1; then
      # Never kill a host whose workload inventory is unknown or non-empty.
      if control get "$Q124_NODE_ID" >/dev/null 2>&1; then
        control cordon "$Q124_NODE_ID" >/dev/null 2>&1 || true
        if control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124- 2>/dev/null | jq -e 'length == 0' >/dev/null \
          && control get "$Q124_NODE_ID" | jq -e '.assigned_cats == 0 and .orphan_cats == 0' >/dev/null; then
          remote "$CREATED_INSTANCE" assert-idle >/dev/null 2>&1 || exit "$rc"
          remote "$CREATED_INSTANCE" stop >/dev/null 2>&1 || exit "$rc"
          control delete "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" >/dev/null 2>&1 || exit "$rc"
        else
          printf 'q124: cleanup stopped: node emptiness was not proven\n' >&2
          exit "$rc"
        fi
      else
        # A failed GET is not evidence of absence. The adapter must first
        # prove the source node through the same API and then observe an exact
        # 404 for this node; auth/network/5xx failures stop cleanup.
        control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID" >/dev/null 2>&1 || exit "$rc"
      fi
      awsq ec2 modify-instance-attribute --instance-id "$CREATED_INSTANCE" --disable-api-termination '{"Value":false}' >/dev/null
      awsq ec2 terminate-instances --instance-ids "$CREATED_INSTANCE" >/dev/null
      awsq ec2 wait instance-terminated --instance-ids "$CREATED_INSTANCE"
    fi
  fi
  exit "$rc"
}

provision() {
  confirm PROVISION_Q124_TEMP_WORKER
  for name in Q124_AMI_ID Q124_INSTANCE_TYPE Q124_SUBNET_ID Q124_SECURITY_GROUP_ID Q124_INSTANCE_PROFILE_NAME Q124_ARTIFACT_BUCKET Q124_ARCHIVE_KEY Q124_ARCHIVE_SHA256 Q124_CACHE_DEVICE Q124_CONTROL_URL Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN Q124_DB_SECRET_ARN Q124_DB_NAME Q124_MANIFEST_OUT; do need "$name"; done
  [[ $Q124_INSTANCE_TYPE == *.metal ]] || die "qualification requires a bare-metal instance"
  [[ ${Q124_TTL_HOURS:-0} =~ ^([1-9]|1[0-9]|2[0-4])$ ]] || die "TTL must be 1..24 hours"
  source_positive
  source_template
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
  CLEANUP_ARMED=1
  trap cleanup_provision_failure EXIT
  trap 'cleanup_provision_failure 130' INT
  trap 'cleanup_provision_failure 143' TERM
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
  root_volume=$(jq -er '.Reservations[0].Instances[0].BlockDeviceMappings[] | select(.DeviceName == "/dev/sda1") | .Ebs.VolumeId' <<<"$instance")
  exact_root_volume "$root_volume"
  export Q124_PRIVATE_IP

  awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_SOURCE_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 1 and .[0].PingStatus == "Online"' >/dev/null || die "source SSM positive probe failed"
  deadline=$((SECONDS + ${Q124_SSM_TIMEOUT_SECONDS:-600}))
  until awsq ssm describe-instance-information --filters "Key=InstanceIds,Values=$Q124_INSTANCE_ID" --output json | jq -e '.InstanceInformationList | length == 1 and .[0].PingStatus == "Online"' >/dev/null; do
    (( SECONDS < deadline )) || die "temporary instance did not become SSM Online"
    sleep 5
  done
  Q124_FORMAT_CONFIRMATION="FORMAT_EPHEMERAL_CACHE_${Q124_INSTANCE_ID}_${Q124_CACHE_DEVICE}"
  export Q124_FORMAT_CONFIRMATION
  remote "$Q124_INSTANCE_ID" bootstrap
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
  remote "$Q124_INSTANCE_ID" start
  control wait-cordoned "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" >/dev/null
  remote "$Q124_INSTANCE_ID" validate

  now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
  expires=$(date -u -d "+${Q124_TTL_HOURS} hours" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -v+"${Q124_TTL_HOURS}"H +%Y-%m-%dT%H:%M:%SZ)
  script_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-temp-worker.sh")
  remote_sha=$(sha256_file "$ROOT/deploy/aws/qualification/q124-remote.sh")
  jq -n \
    --arg account "$Q124_ACCOUNT_ID" --arg region "$Q124_REGION" --arg cluster "$Q124_CLUSTER" --arg workspace "$Q124_WORKSPACE_ID" \
    --arg source_i "$Q124_SOURCE_INSTANCE_ID" --arg source_n "$Q124_SOURCE_NODE_ID" \
    --arg instance "$Q124_INSTANCE_ID" --arg node "$Q124_NODE_ID" --arg ip "$Q124_PRIVATE_IP" \
    --arg ami "$Q124_AMI_ID" --arg type "$Q124_INSTANCE_TYPE" --arg az "$az" --arg subnet "$Q124_SUBNET_ID" --arg sg "$Q124_SECURITY_GROUP_ID" --arg profile "$Q124_INSTANCE_PROFILE_NAME" --arg root_volume "$root_volume" \
    --arg source_sha "$sha" --arg github_run_id "$run_id" --arg archive_key "$Q124_ARCHIVE_KEY" --arg archive_sha "$Q124_ARCHIVE_SHA256" --arg script_sha "$script_sha" --arg remote_sha "$remote_sha" \
    --arg created "$now" --arg expires "$expires" --arg cache "$Q124_CACHE_DEVICE" '
      {schema:1,issue:124,fixed:{account_id:$account,region:$region,cluster:$cluster,workspace_id:$workspace},
       source:{instance_id:$source_i,node_id:$source_n},temporary:{instance_id:$instance,node_id:$node,private_ip:$ip},
       launch:{method:"run-instances",launch_template:null,ami:$ami,instance_type:$type,availability_zone:$az,subnet_id:$subnet,security_group_id:$sg,instance_profile:$profile,root_volume_id:$root_volume,cache_device:$cache},
       bundle:{source_sha:$source_sha,github_run_id:$github_run_id,archive_key:$archive_key,archive_sha256:$archive_sha,orchestrator_sha256:$script_sha,remote_sha256:$remote_sha},
       timestamps:{created_at:$created,expires_at:$expires}}
    ' | jq -S . >"$Q124_MANIFEST_OUT"
  printf 'manifest-sha256=%s\n' "$(canonical_manifest "$Q124_MANIFEST_OUT" | sha256sum | awk '{print $1}')"
  CLEANUP_ARMED=0
  trap - EXIT INT TERM
}

validate_mode() {
  confirm "VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; source_positive; exact_instance >/dev/null; no_duplicate_identity
  control get "$Q124_NODE_ID" | jq -e '.node.state == "cordoned"' >/dev/null || die "node is not Cordoned"
  remote "$Q124_INSTANCE_ID" validate
}

drain_mode() {
  confirm "DRAIN_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; source_positive; exact_instance >/dev/null; no_duplicate_identity
  assigned=$(control cats-scope "$Q124_NODE_ID" "$Q124_WORKSPACE_ID" q124-)
  snapshot=$(remote "$Q124_INSTANCE_ID" snapshot)
  jq -e --argjson assigned "$assigned" '([.cats[]] | sort) == ([$assigned[]] | sort)' <<<"$snapshot" >/dev/null || die "control assignment and runtime ledger differ"
  control drain "$Q124_NODE_ID" "$Q124_WORKSPACE_ID"
  control wait-cordoned "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID" >/dev/null
  Q124_PRIOR_ATTACHMENTS_JSON=$(jq -c '.attachments' <<<"$snapshot")
  export Q124_PRIOR_ATTACHMENTS_JSON
  remote "$Q124_INSTANCE_ID" assert-idle
}

withdraw_mode() {
  confirm "WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
  load_manifest; source_positive; exact_instance >/dev/null; no_duplicate_identity
  if summary=$(control get "$Q124_NODE_ID" 2>/dev/null); then
    jq -e '.node.state == "cordoned" and .assigned_cats == 0 and .orphan_cats == 0' <<<"$summary" >/dev/null || die "withdraw requires an empty Cordoned node"
    remote "$Q124_INSTANCE_ID" assert-idle
    remote "$Q124_INSTANCE_ID" stop
    control delete "$Q124_NODE_ID" "$Q124_SOURCE_NODE_ID"
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
  control absent "$Q124_SOURCE_NODE_ID" "$Q124_NODE_ID"
  instance=$(exact_instance)
  no_duplicate_identity
  root_volume=$(jq -er '.launch.root_volume_id' "$Q124_MANIFEST")
  state=$(jq -r '.Reservations[0].Instances[0].State.Name' <<<"$instance")
  if [[ $state != terminated ]]; then
    exact_root_volume "$root_volume"
    # A stopped service plus empty ledger is the last data-safety gate.
    remote "$Q124_INSTANCE_ID" assert-idle
    remote "$Q124_INSTANCE_ID" stop
    awsq ec2 modify-instance-attribute --instance-id "$Q124_INSTANCE_ID" --disable-api-termination '{"Value":false}' >/dev/null
    awsq ec2 terminate-instances --instance-ids "$Q124_INSTANCE_ID" >/dev/null
    awsq ec2 wait instance-terminated --instance-ids "$Q124_INSTANCE_ID"
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

validate_fixed_inputs
case $MODE in
  provision) provision ;;
  validate) validate_mode ;;
  drain) drain_mode ;;
  withdraw) withdraw_mode ;;
  return) return_mode ;;
  *) die "mode must be provision, validate, drain, withdraw, or return" ;;
esac
