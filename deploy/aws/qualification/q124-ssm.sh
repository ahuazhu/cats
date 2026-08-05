#!/usr/bin/env bash
# Execute the reviewed #124 host probe through SSM. Only non-secret identifiers
# cross the command boundary; the host obtains runtime credentials itself.
set -euo pipefail
umask 077

die() { printf 'q124-ssm: %s\n' "$*" >&2; exit 1; }
ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
BOOTSTRAP_BIN=${Q124_BOOTSTRAP_BIN:-$ROOT/deploy/aws/qualification/q124-bootstrap-prereqs.sh}
GUARD_BIN=${Q124_COMMAND_GUARD_BIN:-$ROOT/deploy/aws/qualification/q124-command-guard.sh}
PROVENANCE_BIN=${Q124_PROVENANCE_BIN:-$ROOT/deploy/aws/qualification/q124-provenance.sh}
EVIDENCE_BIN=${Q124_SSM_EVIDENCE_BIN:-$ROOT/deploy/aws/qualification/q124-ssm-command-evidence.sh}
[[ -n ${Q124_REGION:-} ]] || die "missing Q124_REGION"
[[ $Q124_REGION =~ ^[a-z]{2}(-gov)?-[a-z]+-[0-9]$ ]] || die "invalid Q124_REGION"
instance=${1:?instance id required}
mode=${2:?remote mode required}
[[ $instance =~ ^i-[0-9a-f]+$ ]] || die "invalid instance id"
[[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop|recover-active)$ ]] || die "invalid mode"
[[ ${Q124_EXPECTED_MANIFEST_SHA256:-} =~ ^[0-9a-f]{64}$ ]] || die "missing/invalid Q124_EXPECTED_MANIFEST_SHA256"
Q124_SSM_EXECUTION_TIMEOUT_SECONDS=${Q124_SSM_EXECUTION_TIMEOUT_SECONDS:-4200}
Q124_SSM_DELIVERY_TIMEOUT_SECONDS=${Q124_SSM_DELIVERY_TIMEOUT_SECONDS:-60}
Q124_SSM_POLL_TIMEOUT_SECONDS=${Q124_SSM_POLL_TIMEOUT_SECONDS:-4320}
Q124_SSM_CANCEL_TIMEOUT_SECONDS=${Q124_SSM_CANCEL_TIMEOUT_SECONDS:-180}
Q124_SSM_POLL_INTERVAL_SECONDS=${Q124_SSM_POLL_INTERVAL_SECONDS:-2}
[[ $Q124_SSM_EXECUTION_TIMEOUT_SECONDS =~ ^[1-9][0-9]{1,3}$ ]] && (( Q124_SSM_EXECUTION_TIMEOUT_SECONDS >= 60 && Q124_SSM_EXECUTION_TIMEOUT_SECONDS <= 4200 )) || die "invalid SSM execution timeout"
[[ $Q124_SSM_DELIVERY_TIMEOUT_SECONDS =~ ^[1-9][0-9]{1,2}$ ]] && (( Q124_SSM_DELIVERY_TIMEOUT_SECONDS >= 30 && Q124_SSM_DELIVERY_TIMEOUT_SECONDS <= 300 )) || die "invalid SSM delivery timeout"
[[ $Q124_SSM_POLL_TIMEOUT_SECONDS =~ ^[1-9][0-9]{0,3}$ ]] && (( Q124_SSM_POLL_TIMEOUT_SECONDS <= 4500 )) || die "invalid SSM poll timeout"
[[ $Q124_SSM_CANCEL_TIMEOUT_SECONDS =~ ^[1-9][0-9]{0,2}$ ]] && (( Q124_SSM_CANCEL_TIMEOUT_SECONDS <= 300 )) || die "invalid SSM cancel timeout"
[[ $Q124_SSM_POLL_INTERVAL_SECONDS =~ ^[0-9]$ ]] || die "invalid SSM poll interval"
remote_source_root=${Q124_REMOTE_SOURCE_ROOT:-/opt/cats/q124/bundles/$Q124_EXPECTED_MANIFEST_SHA256}
[[ $remote_source_root =~ ^/[A-Za-z0-9_./-]+$ && $remote_source_root != *..* ]] || die "invalid remote source root"
command_guard_dir=${Q124_COMMAND_GUARD_DIR:-/run/lock/cats-q124-command}
[[ $command_guard_dir =~ ^/[A-Za-z0-9_./-]+$ && $command_guard_dir != *..* ]] || die "invalid command guard directory"
printf -v remote_source_root_q %q "$remote_source_root"
for name in Q124_MANIFEST_REMOTE_SHA256 Q124_MANIFEST_DEVICE_PROOF_SHA256 Q124_MANIFEST_INSTALL_WORKER_SHA256 \
  Q124_MANIFEST_REQUIRE_IDLE_SHA256 Q124_MANIFEST_BOOTSTRAP_SHA256 Q124_MANIFEST_COMMAND_GUARD_SHA256 \
  Q124_MANIFEST_PROVENANCE_SHA256 Q124_MANIFEST_SSM_EVIDENCE_SHA256; do
  [[ ${!name:-} =~ ^[0-9a-f]{64}$ ]] || die "missing/invalid $name"
done
[[ -f $EVIDENCE_BIN && ! -L $EVIDENCE_BIN ]] || die "SSM evidence contract must be a regular non-symlink"
[[ $(sha256sum "$EVIDENCE_BIN" | awk '{print $1}') == "$Q124_MANIFEST_SSM_EVIDENCE_SHA256" ]] \
  || die "SSM evidence contract differs from manifest"
[[ -f $PROVENANCE_BIN && ! -L $PROVENANCE_BIN ]] || die "provenance contract must be a regular non-symlink"
[[ $(sha256sum "$PROVENANCE_BIN" | awk '{print $1}') == "$Q124_MANIFEST_PROVENANCE_SHA256" ]] \
  || die "provenance contract differs from manifest"
provenance_sha=$Q124_MANIFEST_PROVENANCE_SHA256
provenance_encoded=$(base64 <"$PROVENANCE_BIN" | tr -d '\n')
provenance_owner_uid=${Q124_PROVENANCE_OWNER_UID:-0}
[[ $provenance_owner_uid =~ ^[0-9]+$ ]] || die "invalid provenance owner uid"
awsq() { aws --region "$Q124_REGION" "$@"; }

quote_env() {
  local name
  for name in \
    Q124_INSTANCE_ID Q124_ACCOUNT_ID Q124_REGION Q124_NODE_ID Q124_PRIVATE_IP \
    Q124_CONTROL_URL Q124_CHUNKSTORE_BUCKET Q124_RUNTIME_SECRET_ARN \
    Q124_DB_SECRET_ARN Q124_DB_NAME Q124_CACHE_DEVICE Q124_FORMAT_CONFIRMATION \
    Q124_GUEST_CIDR Q124_PRIOR_ATTACHMENTS_JSON Q124_EXPECTED_MANIFEST_SHA256 \
    Q124_AWS_CLI_VERSION Q124_AWS_CLI_X86_64_SHA256 Q124_JQ_VERSION
  do
    [[ -n ${!name:-} ]] && printf 'export %s=%q\n' "$name" "${!name}"
  done
}

command_result() {
  local wanted_command=$1 wanted_instance=$2 error_file=$3
  if result=$(awsq ssm get-command-invocation --command-id "$wanted_command" --instance-id "$wanted_instance" --output json 2>"$error_file"); then
    printf '%s\n' "$result"
    return 0
  fi
  grep -q 'InvocationDoesNotExist' "$error_file" && return 2
  return 1
}

wait_terminal() {
  local wanted_command=$1 wanted_instance=$2 timeout=$3 deadline result status probe_rc error_file
  deadline=$((SECONDS + timeout))
  error_file=$(mktemp)
  while (( SECONDS <= deadline )); do
    set +e
    result=$(command_result "$wanted_command" "$wanted_instance" "$error_file")
    probe_rc=$?
    set -e
    if (( probe_rc == 0 )); then
      status=$(jq -er '.Status | select(type == "string")' <<<"$result") || { rm -f "$error_file"; return 1; }
      case $status in
        Success|Cancelled|TimedOut|Failed) rm -f "$error_file"; printf '%s\n' "$result"; return 0 ;;
        Pending|InProgress|Delayed|Cancelling) ;;
        *) rm -f "$error_file"; return 1 ;;
      esac
    elif (( probe_rc != 2 )); then
      rm -f "$error_file"
      return 1
    fi
    sleep "$Q124_SSM_POLL_INTERVAL_SECONDS"
  done
  rm -f "$error_file"
  return 1
}

cancel_exact_command() {
  local wanted_command=$1 wanted_instance=$2 terminal status
  awsq ssm cancel-command --command-id "$wanted_command" --instance-ids "$wanted_instance" >/dev/null \
    || return 1
  terminal=$(wait_terminal "$wanted_command" "$wanted_instance" "$Q124_SSM_CANCEL_TIMEOUT_SECONDS") \
    || return 1
  status=$(jq -er '.Status' <<<"$terminal") || return 1
  [[ $status =~ ^(Success|Cancelled|TimedOut|Failed)$ ]]
}

probe_guard_absent() {
  local nonce=$1 delivery_deadline=$2 not_after=$3 now wait_seconds parameters probe_command probe_id terminal status output
  (( not_after >= delivery_deadline )) || return 1
  now=$(date -u +%s)
  # Once this upper bound passes, an accepted-but-delayed original command can
  # no longer enter its guard. A delivery-deadline-only probe has a race where
  # the original starts after an apparently empty lock check.
  while (( now < not_after )); do
    wait_seconds=$((not_after - now))
    (( wait_seconds > 5 )) && wait_seconds=5
    sleep "$wait_seconds"
    now=$(date -u +%s)
  done
  parameters=$(mktemp)
  printf -v guard_dir_q %q "$command_guard_dir"
  probe_command=$(cat <<EOF
set -euo pipefail
guard_dir=$guard_dir_q
now=$(date -u +%s)
(( now >= $not_after )) || exit 74
install -d -m 0700 "\$guard_dir"
exec 9>"\$guard_dir/active.lock"
if flock -n 9; then
  printf 'guard=absent nonce=%s manifest=%s\\n' '$nonce' '$Q124_EXPECTED_MANIFEST_SHA256'
else
  [[ ! -f "\$guard_dir/active" ]] || sed -n '1,8p' "\$guard_dir/active" >&2
  exit 75
fi
EOF
)
  jq -n --arg command "$probe_command" '{commands:[$command],executionTimeout:["60"]}' >"$parameters"
  probe_id=$(awsq ssm send-command --instance-ids "$instance" --document-name AWS-RunShellScript \
    --comment "cats issue 124 guard probe" --parameters "file://$parameters" --timeout-seconds 60 \
    --query 'Command.CommandId' --output text) || { rm -f "$parameters"; return 1; }
  rm -f "$parameters"
  [[ $probe_id =~ ^[0-9a-f-]+$ ]] || return 1
  terminal=$(wait_terminal "$probe_id" "$instance" 120) || return 1
  status=$(jq -er '.Status' <<<"$terminal") || return 1
  output=$(jq -er '.StandardOutputContent' <<<"$terminal") || return 1
  [[ $status == Success && $(jq -er '.ResponseCode' <<<"$terminal") == 0 &&
     $output == "guard=absent nonce=$nonce manifest=$Q124_EXPECTED_MANIFEST_SHA256" ]]
}

recover_durable_commands() {
  local records intents commands record nonce intent_mode command_id command_mode command_count status result probe_rc error_file delivery_deadline not_after
  records=$(mktemp)
  intents=$(mktemp)
  commands=$(mktemp)
  error_file=$(mktemp)
  trap 'rm -f "$records" "$intents" "$commands" "$error_file"' RETURN
  "$EVIDENCE_BIN" list "$Q124_EXPECTED_MANIFEST_SHA256" \
    | jq -sc --arg instance "$instance" '[.[] | select(.instance_id == $instance)] | unique' >"$records"
  jq -c '.[] | select(.kind == "intent")' "$records" >"$intents"
  jq -c '.[] | select(.kind == "command")' "$records" >"$commands"
  [[ $(jq -s 'length' "$intents") == $(jq -s 'map(.nonce) | unique | length' "$intents") ]] || return 1
  [[ $(jq -s 'length' "$commands") == $(jq -s 'map(.command_id) | unique | length' "$commands") ]] || return 1
  while IFS= read -r record; do
    [[ -n $record ]] || continue
    nonce=$(jq -er '.nonce' <<<"$record") || return 1
    delivery_deadline=$(jq -er '.delivery_deadline_epoch' <<<"$record") || return 1
    not_after=$(jq -er '.not_after_epoch' <<<"$record") || return 1
    command_count=$(jq -s --arg nonce "$nonce" '[.[] | select(.nonce == $nonce)] | length' "$commands")
    if [[ $command_count == 0 ]]; then
      probe_guard_absent "$nonce" "$delivery_deadline" "$not_after" || return 1
      continue
    fi
    [[ $command_count == 1 ]] || return 1
    intent_mode=$(jq -er '.mode' <<<"$record") || return 1
    command_id=$(jq -sr --arg nonce "$nonce" '.[] | select(.nonce == $nonce) | .command_id' "$commands") || return 1
    command_mode=$(jq -sr --arg nonce "$nonce" '.[] | select(.nonce == $nonce) | .mode' "$commands") || return 1
    [[ $command_mode == "$intent_mode" ]] || return 1
    set +e
    result=$(command_result "$command_id" "$instance" "$error_file")
    probe_rc=$?
    set -e
    (( probe_rc == 0 )) || return 1
    status=$(jq -er '.Status' <<<"$result") || return 1
    case $status in
      Success|Cancelled|TimedOut|Failed) ;;
      Pending|InProgress|Delayed) cancel_exact_command "$command_id" "$instance" || return 1 ;;
      Cancelling) wait_terminal "$command_id" "$instance" "$Q124_SSM_CANCEL_TIMEOUT_SECONDS" >/dev/null || return 1 ;;
      *) return 1 ;;
    esac
  done <"$intents"
  # A command record without its preceding exact intent is journal corruption.
  jq -se --slurpfile intents "$intents" 'all(.[]; .nonce as $nonce | any($intents[]; .nonce == $nonce))' "$commands" >/dev/null || return 1
  rm -f "$records" "$intents" "$commands" "$error_file"
  trap - RETURN
}

if [[ $mode == recover-active ]]; then
  recover_durable_commands || die "durable SSM recovery was ambiguous"
  printf 'ssm-recovery=terminal\n'
  exit 0
fi

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT
[[ -f $GUARD_BIN && ! -L $GUARD_BIN ]] || die "command guard must be a regular non-symlink"
[[ $(sha256sum "$GUARD_BIN" | awk '{print $1}') == "$Q124_MANIFEST_COMMAND_GUARD_SHA256" ]] \
  || die "command guard differs from manifest"
intent_nonce=${Q124_SSM_INTENT_NONCE:-$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')}
[[ $intent_nonce =~ ^[0-9a-f]{32}$ ]] || die "invalid SSM intent nonce"
issued_epoch=$(date -u +%s)
delivery_deadline=$((issued_epoch + Q124_SSM_DELIVERY_TIMEOUT_SECONDS + 30))
intent_not_after=$((delivery_deadline + Q124_SSM_EXECUTION_TIMEOUT_SECONDS + 30))
if [[ $mode == bootstrap ]]; then
  for name in Q124_ARTIFACT_BUCKET Q124_ARCHIVE_KEY Q124_ARCHIVE_SHA256 Q124_AWS_CLI_VERSION Q124_AWS_CLI_X86_64_SHA256 Q124_JQ_VERSION; do
    [[ -n ${!name:-} ]] || die "missing $name"
  done
  [[ $Q124_ARTIFACT_BUCKET =~ ^[a-z0-9][a-z0-9.-]+$ ]] || die "invalid artifact bucket"
  [[ $Q124_ARCHIVE_KEY =~ ^worker/qualification-124/[A-Za-z0-9._/-]+\.tar\.gz$ && $Q124_ARCHIVE_KEY != *..* ]] || die "invalid archive key"
  [[ $Q124_ARCHIVE_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "invalid archive digest"
  [[ -f $BOOTSTRAP_BIN && ! -L $BOOTSTRAP_BIN ]] || die "bootstrap contract must be a regular non-symlink"
  [[ $(sha256sum "$BOOTSTRAP_BIN" | awk '{print $1}') == "$Q124_MANIFEST_BOOTSTRAP_SHA256" ]] \
    || die "bootstrap contract differs from manifest"
  bootstrap_sha=$(sha256sum "$BOOTSTRAP_BIN" | awk '{print $1}')
  bootstrap_encoded=$(base64 <"$BOOTSTRAP_BIN" | tr -d '\n')
  command=$(cat <<EOF
set -euo pipefail
bootstrap_contract=/var/tmp/q124-bootstrap-${bootstrap_sha}.sh
provenance_contract=/var/tmp/q124-provenance-${provenance_sha}.sh
cleanup_bootstrap_contracts() { rm -f "\$bootstrap_contract" "\$provenance_contract"; }
trap cleanup_bootstrap_contracts EXIT HUP INT TERM
printf '%s' '${bootstrap_encoded}' | base64 --decode >"\$bootstrap_contract"
printf '%s' '${provenance_encoded}' | base64 --decode >"\$provenance_contract"
printf '%s  %s\n' '${bootstrap_sha}' "\$bootstrap_contract" | sha256sum -c - >/dev/null
printf '%s  %s\n' '${provenance_sha}' "\$provenance_contract" | sha256sum -c - >/dev/null
chmod 0700 "\$bootstrap_contract" "\$provenance_contract"
$(quote_env)
bash "\$bootstrap_contract"
rm -f "\$bootstrap_contract"
[[ ! -e $remote_source_root_q && ! -L $remote_source_root_q ]]
install -d -m 0700 $remote_source_root_q
aws --region '${Q124_REGION}' s3 cp 's3://${Q124_ARTIFACT_BUCKET}/${Q124_ARCHIVE_KEY}' /tmp/q124-source.tar.gz --only-show-errors
printf '%s  %s\n' '${Q124_ARCHIVE_SHA256}' /tmp/q124-source.tar.gz | sha256sum -c -
tar -xzf /tmp/q124-source.tar.gz -C $remote_source_root_q
Q124_PROVENANCE_OWNER_UID='${provenance_owner_uid}' bash "\$provenance_contract" $remote_source_root_q \
  'deploy/aws/qualification/q124-remote.sh=${Q124_MANIFEST_REMOTE_SHA256}' \
  'deploy/aws/qualification/q124-device-proof.sh=${Q124_MANIFEST_DEVICE_PROOF_SHA256}' \
  'deploy/aws/metal/install-worker.sh=${Q124_MANIFEST_INSTALL_WORKER_SHA256}' \
  'deploy/aws/metal/require-idle-worker.sh=${Q124_MANIFEST_REQUIRE_IDLE_SHA256}'
export AWS_REGION='${Q124_REGION}' AWS_DEFAULT_REGION='${Q124_REGION}'
export Q124_SOURCE_ROOT=$remote_source_root_q
bash $remote_source_root_q/deploy/aws/qualification/q124-remote.sh prepare
EOF
)
else
  command=$(cat <<EOF
set -euo pipefail
provenance_contract=/var/tmp/q124-provenance-${provenance_sha}.sh
trap 'rm -f "\$provenance_contract"' EXIT HUP INT TERM
printf '%s' '${provenance_encoded}' | base64 --decode >"\$provenance_contract"
printf '%s  %s\n' '${provenance_sha}' "\$provenance_contract" | sha256sum -c - >/dev/null
chmod 0700 "\$provenance_contract"
$(quote_env)
export AWS_REGION='${Q124_REGION}' AWS_DEFAULT_REGION='${Q124_REGION}'
export Q124_SOURCE_ROOT=$remote_source_root_q
Q124_PROVENANCE_OWNER_UID='${provenance_owner_uid}' bash "\$provenance_contract" $remote_source_root_q \
  'deploy/aws/qualification/q124-remote.sh=${Q124_MANIFEST_REMOTE_SHA256}' \
  'deploy/aws/qualification/q124-device-proof.sh=${Q124_MANIFEST_DEVICE_PROOF_SHA256}' \
  'deploy/aws/metal/install-worker.sh=${Q124_MANIFEST_INSTALL_WORKER_SHA256}' \
  'deploy/aws/metal/require-idle-worker.sh=${Q124_MANIFEST_REQUIRE_IDLE_SHA256}'
bash $remote_source_root_q/deploy/aws/qualification/q124-remote.sh '${mode}'
EOF
)
fi
payload=$command
guard_sha=$(sha256sum "$GUARD_BIN" | awk '{print $1}')
guard_encoded=$(base64 <"$GUARD_BIN" | tr -d '\n')
payload_sha=$(printf '%s\n' "$payload" | sha256sum | awk '{print $1}')
payload_encoded=$(printf '%s\n' "$payload" | base64 | tr -d '\n')
guard_timeout=$((Q124_SSM_EXECUTION_TIMEOUT_SECONDS - 30))
printf -v command_guard_dir_q %q "$command_guard_dir"
command=$(cat <<EOF
set -euo pipefail
guard_contract=/var/tmp/q124-guard-${intent_nonce}.sh
payload_contract=/var/tmp/q124-payload-${intent_nonce}.sh
cleanup_contracts() { rm -f "\$guard_contract" "\$payload_contract"; }
trap cleanup_contracts EXIT HUP INT TERM
printf '%s' '${guard_encoded}' | base64 --decode >"\$guard_contract"
printf '%s' '${payload_encoded}' | base64 --decode >"\$payload_contract"
printf '%s  %s\n' '${guard_sha}' "\$guard_contract" | sha256sum -c - >/dev/null
printf '%s  %s\n' '${payload_sha}' "\$payload_contract" | sha256sum -c - >/dev/null
chmod 0700 "\$guard_contract" "\$payload_contract"
export Q124_COMMAND_GUARD_DIR=$command_guard_dir_q
bash "\$guard_contract" "\$payload_contract" '${Q124_EXPECTED_MANIFEST_SHA256}' '${intent_nonce}' '${mode}' '${intent_not_after}' '${guard_timeout}'
EOF
)
jq -n --arg command "$command" --arg execution "$Q124_SSM_EXECUTION_TIMEOUT_SECONDS" \
  '{commands:[$command],executionTimeout:[$execution]}' >"$tmp"

"$EVIDENCE_BIN" publish-intent "$instance" "$intent_nonce" "$mode" "$Q124_EXPECTED_MANIFEST_SHA256" "$delivery_deadline" "$intent_not_after" \
  || die "durable command intent publication failed"
command_id=$(awsq ssm send-command \
  --instance-ids "$instance" \
  --document-name AWS-RunShellScript \
  --comment "cats issue 124 ${mode}" \
  --parameters "file://$tmp" \
  --timeout-seconds "$Q124_SSM_DELIVERY_TIMEOUT_SECONDS" \
  --query 'Command.CommandId' --output text)
[[ $command_id =~ ^[0-9a-f-]+$ ]] || die "SSM did not return a command id"
printf 'ssm-command-id=%s\n' "$command_id" >&2
if ! "$EVIDENCE_BIN" publish-command "$instance" "$command_id" "$mode" "$Q124_EXPECTED_MANIFEST_SHA256" "$intent_nonce"; then
  cancel_exact_command "$command_id" "$instance" || die "evidence failed and command cancellation was ambiguous"
  die "durable command evidence failed"
fi
command_active=1
cancel_on_signal() {
  trap - INT TERM
  if (( command_active )); then
    cancel_exact_command "$command_id" "$instance" || exit 125
  fi
  exit 130
}
trap cancel_on_signal INT TERM
deadline=$((SECONDS + Q124_SSM_POLL_TIMEOUT_SECONDS))
error_file=$(mktemp)
while (( SECONDS <= deadline )); do
  set +e
  result=$(command_result "$command_id" "$instance" "$error_file")
  probe_rc=$?
  set -e
  if (( probe_rc == 0 )); then
    status=$(jq -er '.Status | select(type == "string")' <<<"$result") || die "invalid SSM invocation status"
    case $status in
      Success)
        jq -e '.ResponseCode == 0' <<<"$result" >/dev/null || die "successful SSM status had nonzero response"
        command_active=0
        trap - INT TERM
        rm -f "$error_file"
        jq -r '.StandardOutputContent' <<<"$result"
        exit 0
        ;;
      Pending|InProgress|Delayed|Cancelling) ;;
      Cancelled|TimedOut|Failed)
        command_active=0
        trap - INT TERM
        jq -r '.StatusDetails, .StandardErrorContent' <<<"$result" >&2
        die "remote command reached terminal failure"
        ;;
      *) die "unknown SSM invocation status" ;;
    esac
  elif (( probe_rc != 2 )); then
    die "SSM invocation lookup was ambiguous"
  fi
  sleep "$Q124_SSM_POLL_INTERVAL_SECONDS"
done
cancel_exact_command "$command_id" "$instance" || die "SSM poll timed out and cancellation was ambiguous"
command_active=0
die "SSM command timed out and was cancelled"
