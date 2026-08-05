#!/usr/bin/env bash
# Execute the reviewed #124 host probe through SSM. Only non-secret identifiers
# cross the command boundary; the host obtains runtime credentials itself.
set -euo pipefail

die() { printf 'q124-ssm: %s\n' "$*" >&2; exit 1; }
[[ -n ${Q124_REGION:-} ]] || die "missing Q124_REGION"
[[ $Q124_REGION =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]$ ]] || die "invalid Q124_REGION"
instance=${1:?instance id required}
mode=${2:?remote mode required}
[[ $instance =~ ^i-[0-9a-f]+$ ]] || die "invalid instance id"
[[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$ ]] || die "invalid mode"
remote_source_root=${Q124_REMOTE_SOURCE_ROOT:-/opt/cats/q124/source}
[[ $remote_source_root =~ ^/[A-Za-z0-9_./-]+$ && $remote_source_root != *..* ]] || die "invalid remote source root"
printf -v remote_source_root_q %q "$remote_source_root"
awsq() { aws --region "$Q124_REGION" "$@"; }

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
  [[ $Q124_ARTIFACT_BUCKET =~ ^[a-z0-9][a-z0-9.-]+$ ]] || die "invalid artifact bucket"
  [[ $Q124_ARCHIVE_KEY =~ ^worker/qualification-124/[A-Za-z0-9._/-]+\.tar\.gz$ && $Q124_ARCHIVE_KEY != *..* ]] || die "invalid archive key"
  [[ $Q124_ARCHIVE_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "invalid archive digest"
  command=$(cat <<EOF
set -euo pipefail
export PATH="/usr/local/bin:\$PATH"
export DEBIAN_FRONTEND=noninteractive
has_command() {
  if [[ -n \${Q124_BOOTSTRAP_COMMAND_PROBE_BIN:-} ]]; then
    "\$Q124_BOOTSTRAP_COMMAND_PROBE_BIN" "\$1"
  else
    command -v "\$1" >/dev/null 2>&1
  fi
}
if ! has_command curl || ! has_command unzip; then
  apt-get update -qq
  apt-get install -qy --no-install-recommends ca-certificates curl unzip
fi
if ! has_command aws; then
  cli_stage=\$(mktemp -d /var/tmp/q124-awscli.XXXXXX)
  trap 'rm -rf -- "\$cli_stage"' EXIT
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-\$(uname -m).zip" -o "\$cli_stage/awscliv2.zip"
  unzip -q "\$cli_stage/awscliv2.zip" -d "\$cli_stage"
  "\$cli_stage/aws/install" --update
  rm -rf -- "\$cli_stage"
  trap - EXIT
fi
if ! has_command jq; then
  apt-get update -qq
  apt-get install -qy --no-install-recommends jq
fi
for required in aws jq tar sha256sum curl; do
  command -v "\$required" >/dev/null 2>&1 || { echo "q124 bootstrap needs \$required" >&2; exit 1; }
done
install -d -m 0700 $remote_source_root_q
aws --region '${Q124_REGION}' s3 cp 's3://${Q124_ARTIFACT_BUCKET}/${Q124_ARCHIVE_KEY}' /tmp/q124-source.tar.gz --only-show-errors
printf '%s  %s\n' '${Q124_ARCHIVE_SHA256}' /tmp/q124-source.tar.gz | sha256sum -c -
tar -xzf /tmp/q124-source.tar.gz -C $remote_source_root_q
$(quote_env)
export AWS_REGION='${Q124_REGION}' AWS_DEFAULT_REGION='${Q124_REGION}'
export Q124_SOURCE_ROOT=$remote_source_root_q
bash $remote_source_root_q/deploy/aws/qualification/q124-remote.sh prepare
EOF
)
else
  command=$(cat <<EOF
set -euo pipefail
$(quote_env)
export AWS_REGION='${Q124_REGION}' AWS_DEFAULT_REGION='${Q124_REGION}'
export Q124_SOURCE_ROOT=$remote_source_root_q
bash $remote_source_root_q/deploy/aws/qualification/q124-remote.sh '${mode}'
EOF
)
fi
jq -n --arg command "$command" '{commands:[$command]}' >"$tmp"

command_id=$(awsq ssm send-command \
  --instance-ids "$instance" \
  --document-name AWS-RunShellScript \
  --comment "cats issue 124 ${mode}" \
  --parameters "file://$tmp" \
  --query 'Command.CommandId' --output text)
[[ $command_id =~ ^[0-9a-f-]+$ ]] || die "SSM did not return a command id"
printf 'ssm-command-id=%s\n' "$command_id" >&2
awsq ssm wait command-executed --command-id "$command_id" --instance-id "$instance"
result=$(awsq ssm get-command-invocation --command-id "$command_id" --instance-id "$instance" --output json)
jq -e '.Status == "Success" and .ResponseCode == 0' <<<"$result" >/dev/null || {
  jq -r '.StatusDetails, .StandardErrorContent' <<<"$result" >&2
  die "remote command failed"
}
jq -r '.StandardOutputContent' <<<"$result"
