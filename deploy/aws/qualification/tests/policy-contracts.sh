#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
MODULE=$HERE/../../terraform/modules/qualification-worker-policy

terraform -chdir="$MODULE" init -backend=false -input=false >/dev/null
common_vars=(
  -var partition=aws -var region=us-east-1 -var account_id=111122223333
  -var ami_id=ami-0124 -var subnet_id=subnet-0124 -var security_group_id=sg-0124
  -var instance_type=c5d.metal
  -var instance_profile_arn=arn:aws:iam::111122223333:instance-profile/cats-worker
  -var worker_role_arn=arn:aws:iam::111122223333:role/cats-worker
  -var artifact_bucket_arn=arn:aws:s3:::cats-artifacts
)
valid_snapshots='["arn:aws:ec2:us-east-1::snapshot/snap-0124aaa","arn:aws:ec2:us-east-1::snapshot/snap-0124bbb"]'
encoded=$(terraform -chdir="$MODULE" console "${common_vars[@]}" \
  -var "snapshot_arns=$valid_snapshots" <<<'local.policy_json')
policy=$(jq -er . <<<"$encoded")

expect_invalid_snapshots() {
  local value=$1
  if terraform -chdir="$MODULE" console "${common_vars[@]}" \
    -var "snapshot_arns=$value" <<<'local.policy_json' >/dev/null 2>&1; then
    printf 'snapshot ARN validation unexpectedly accepted %s\n' "$value" >&2
    exit 1
  fi
}

expect_invalid_snapshots '[]'
expect_invalid_snapshots '["arn:aws:ec2:us-west-2::snapshot/snap-0124aaa"]'
expect_invalid_snapshots '["arn:aws:ec2:us-east-1:111122223333:snapshot/snap-0124aaa"]'
expect_invalid_snapshots '["arn:aws:ec2:us-east-1::snapshot/*"]'

jq -e '
  .Version == "2012-10-17" and
  ([.Statement[] | select(.Action == "ec2:RunInstances")] | length) == 4 and
  ([.Statement[] | select(.Sid == "LaunchWithFixedInfrastructure")][0] as $s |
    ($s | has("Condition") | not) and
    ($s.Resource | sort) == ([
      "arn:aws:ec2:us-east-1::image/ami-0124",
      "arn:aws:ec2:us-east-1:111122223333:security-group/sg-0124",
      "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-0124",
      "arn:aws:ec2:us-east-1::snapshot/snap-0124aaa",
      "arn:aws:ec2:us-east-1::snapshot/snap-0124bbb"
    ] | sort)) and
  ([.. | strings | select(test("snapshot/\\*"))] | length) == 0 and
  ([.Statement[] | select(.Sid == "ReadRegionalEc2AndSsmInventory")][0] as $s |
    ($s.Action | sort) == ([
      "ec2:DescribeImages",
      "ec2:DescribeInstances",
      "ec2:DescribeInstanceStatus",
      "ec2:DescribeVolumes",
      "ssm:DescribeInstanceInformation"
    ] | sort) and
    $s.Resource == "*" and
    $s.Condition.StringEquals["aws:RequestedRegion"] == "us-east-1") and
  ([.Statement[] | select(.Sid == "ReadRegionalSsmCommandResult")][0] as $s |
    $s.Action == "ssm:GetCommandInvocation" and
    $s.Resource == "*" and
    $s.Condition.StringEquals["aws:RequestedRegion"] == "us-east-1") and
  ([.Statement[] | select(.Sid == "CancelRegionalSsmCommand")][0] as $s |
    $s.Action == "ssm:CancelCommand" and
    $s.Resource == "*" and
    $s.Condition.StringEquals["aws:RequestedRegion"] == "us-east-1") and
  ([.. | strings | select(. == "ssm:ListCommandInvocations")] | length) == 0 and
  ([.Statement[] | select(.Sid == "LaunchPrivateInterfaceInFixedSubnet")][0] as $s |
    $s.Resource == "arn:aws:ec2:us-east-1:111122223333:network-interface/*" and
    $s.Condition.ArnEquals["ec2:Subnet"] == "arn:aws:ec2:us-east-1:111122223333:subnet/subnet-0124" and
    $s.Condition.Bool["ec2:AssociatePublicIpAddress"] == "false") and
  ([.Statement[] | select(.Sid == "LaunchTaggedQualificationInstance")][0] as $s |
    $s.Resource == "arn:aws:ec2:us-east-1:111122223333:instance/*" and
    $s.Condition.ArnEquals["ec2:InstanceProfile"] == "arn:aws:iam::111122223333:instance-profile/cats-worker" and
    $s.Condition.StringEquals["ec2:InstanceType"] == "c5d.metal" and
    $s.Condition.StringEquals["ec2:MetadataHttpEndpoint"] == "enabled" and
    $s.Condition.StringEquals["ec2:MetadataHttpTokens"] == "required" and
    $s.Condition.NumericEquals["ec2:MetadataHttpPutResponseHopLimit"] == "2" and
    $s.Condition.StringEquals["aws:RequestTag/CatsIssue"] == "124" and
    $s.Condition.StringEquals["aws:RequestTag/CatsPurpose"] == "temporary-worker-qualification") and
  ([.Statement[] | select(.Sid == "LaunchTaggedEncryptedRootVolume")][0] as $s |
    $s.Resource == "arn:aws:ec2:us-east-1:111122223333:volume/*" and
    $s.Condition.Bool["ec2:Encrypted"] == "true" and
    $s.Condition.NumericEquals["ec2:VolumeSize"] == "200" and
    $s.Condition.StringEquals["ec2:VolumeType"] == "gp3" and
    ($s.Condition.ArnEquals["ec2:ParentSnapshot"] | sort) == ([
      "arn:aws:ec2:us-east-1::snapshot/snap-0124aaa",
      "arn:aws:ec2:us-east-1::snapshot/snap-0124bbb"
    ] | sort) and
    $s.Condition.StringEquals["aws:RequestTag/CatsIssue"] == "124") and
  ([.Statement[] | select(.Sid == "PassOnlyWorkerRoleToEc2")][0] as $s |
    $s.Resource == "arn:aws:iam::111122223333:role/cats-worker" and
    $s.Condition.StringEquals["iam:PassedToService"] == "ec2.amazonaws.com") and
  ([.Statement[] | select(.Sid == "OperateOnlyQualificationInstances")][0] as $s |
    $s.Resource == "arn:aws:ec2:us-east-1:111122223333:instance/*" and
    $s.Condition.StringEquals["ec2:ResourceTag/CatsIssue"] == "124" and
    $s.Condition.StringEquals["ec2:ResourceTag/CatsPurpose"] == "temporary-worker-qualification") and
  ([.Statement[] | select(.Sid == "QualificationBundleBucketLocation")][0] as $s |
    $s.Action == "s3:GetBucketLocation" and
    $s.Resource == "arn:aws:s3:::cats-artifacts" and
    ($s | has("Condition") | not)) and
  ([.Statement[] | select(.Sid == "ListQualificationBundlePrefix")][0] as $s |
    $s.Action == "s3:ListBucket" and
    $s.Resource == "arn:aws:s3:::cats-artifacts" and
    $s.Condition.StringLike["s3:prefix"] == "worker/qualification-124/*")
' <<<"$policy" >/dev/null

printf 'q124 IAM policy contracts: PASS\n'
