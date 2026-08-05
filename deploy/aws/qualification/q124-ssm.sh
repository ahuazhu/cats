#!/usr/bin/env bash
# Execute the reviewed #124 host probe through SSM. Only non-secret identifiers
# cross the command boundary; the host obtains runtime credentials itself.
set -euo pipefail

die() { printf 'q124-ssm: %s\n' "$*" >&2; exit 1; }
instance=${1:?instance id required}
mode=${2:?remote mode required}
[[ $instance =~ ^i-[0-9a-f]+$ ]] || die "invalid instance id"
[[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$ ]] || die "invalid mode"

quote_env() {
  local name
  for name in \
    Q124_INSTANCE_ID Q124_ACCOUNT_ID Q124_REGION Q124_NODE_ID Q124_PRIVATE_IP \
    Q124_CONTROL_URL Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN \
    Q124_DB_SECRET_ARN Q124_DB_NAME Q124_CACHE_DEVICE Q124_FORMAT_CONFIRMATION \
    Q124_GUEST_CIDR Q124_PRIOR_ATTACHMENTS_JSON
  do
    [[ -n ${!name:-} ]] && printf 'export %s=%q\n' "$name" "${!name}"
  done
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
if [[ $mode == bootstrap ]]; then
  for name in Q124_ARTIFACT_BUCKET Q124_ARCHIVE_KEY Q124_ARCHIVE_SHA256; do
    [[ -n ${!name:-} ]] || die "missing $name"
  done
  command=$(cat <<EOF
set -euo pipefail
install -d -m 0700 /opt/cats/q124/source
aws s3 cp 's3://${Q124_ARTIFACT_BUCKET}/${Q124_ARCHIVE_KEY}' /tmp/q124-source.tar.gz --only-show-errors
printf '%s  %s\n' '${Q124_ARCHIVE_SHA256}' /tmp/q124-source.tar.gz | sha256sum -c -
tar -xzf /tmp/q124-source.tar.gz -C /opt/cats/q124/source
$(quote_env)
export Q124_SOURCE_ROOT=/opt/cats/q124/source
bash /opt/cats/q124/source/deploy/aws/qualification/q124-remote.sh prepare
EOF
)
else
  command=$(cat <<EOF
set -euo pipefail
$(quote_env)
export Q124_SOURCE_ROOT=/opt/cats/q124/source
bash /opt/cats/q124/source/deploy/aws/qualification/q124-remote.sh '${mode}'
EOF
)
fi
jq -n --arg command "$command" '{commands:[$command]}' >"$tmp"

command_id=$(aws ssm send-command \
  --instance-ids "$instance" \
  --document-name AWS-RunShellScript \
  --comment "cats issue 124 ${mode}" \
  --parameters "file://$tmp" \
  --query 'Command.CommandId' --output text)
[[ $command_id =~ ^[0-9a-f-]+$ ]] || die "SSM did not return a command id"
printf 'ssm-command-id=%s\n' "$command_id" >&2
aws ssm wait command-executed --command-id "$command_id" --instance-id "$instance"
result=$(aws ssm get-command-invocation --command-id "$command_id" --instance-id "$instance" --output json)
jq -e '.Status == "Success" and .ResponseCode == 0' <<<"$result" >/dev/null || {
  jq -r '.StatusDetails, .StandardErrorContent' <<<"$result" >&2
  die "remote command failed"
}
jq -r '.StandardOutputContent' <<<"$result"
