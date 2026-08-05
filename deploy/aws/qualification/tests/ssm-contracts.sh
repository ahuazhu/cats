#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
SSM=$HERE/../q124-ssm.sh
TMP=$(mktemp -d)
cleanup() {
  rc=$?
  if (( rc != 0 )); then
    [[ ! -f $TMP/stderr ]] || { printf '%s\n' '--- remote stderr ---' >&2; sed -n '1,200p' "$TMP/stderr" >&2; }
    [[ ! -f $TMP/command.sh ]] || { printf '%s\n' '--- captured command ---' >&2; sed -n '1,240p' "$TMP/command.sh" >&2; }
    [[ ! -f $TMP/remote/aws ]] || { printf '%s\n' '--- installed aws wrapper ---' >&2; sed -n '1,40p' "$TMP/remote/aws" >&2; }
  fi
  rm -rf "$TMP"
  exit "$rc"
}
trap cleanup EXIT
mkdir -p "$TMP/outer" "$TMP/remote" "$TMP/source" "$TMP/config" "$TMP/marker"
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$HERE/fake-ssm-aws.sh" >"$TMP/outer/aws"
chmod 0755 "$TMP/outer/aws"
for kind in apt-get curl unzip systemctl true probe uname flock timeout; do
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-bootstrap-command.sh" "$kind" >"$TMP/remote/$kind"
  chmod 0755 "$TMP/remote/$kind"
done
tar -czf "$TMP/source.tar.gz" -C "$ROOT" deploy/aws/qualification/q124-remote.sh
export Q124_REAL_JQ
Q124_REAL_JQ=$(command -v jq)
export Q124_EXPECTED_MANIFEST_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
export Q124_AWS_CLI_VERSION=2.99.0
export Q124_AWS_CLI_X86_64_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
export Q124_JQ_VERSION=jq-1.7
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$(command -v sha256sum)" >"$TMP/remote/sha256sum"
chmod 0755 "$TMP/remote/sha256sum"
export Q124_REGION=us-east-1 Q124_INSTANCE_ID=i-0abc124 Q124_ACCOUNT_ID=111122223333
export Q124_NODE_ID=q124-fixture Q124_PRIVATE_IP=10.0.1.124 Q124_CONTROL_URL=https://control.example
export Q124_CHUNKSTORE_BUCKET=chunks Q124_RUNTIME_SECRET_ARN=runtime-secret Q124_DB_SECRET_ARN=db-secret Q124_DB_NAME=cats
export Q124_CACHE_DEVICE=/dev/nvme1n1 Q124_FORMAT_CONFIRMATION=FORMAT_EPHEMERAL_CACHE_i-0abc124_/dev/nvme1n1
export Q124_ARTIFACT_BUCKET=cats-artifacts Q124_ARCHIVE_SHA256
Q124_ARCHIVE_SHA256=$(sha256sum "$TMP/source.tar.gz" | awk '{print $1}')
export Q124_ARCHIVE_KEY="worker/qualification-124/fixture/q124-source-${Q124_ARCHIVE_SHA256}.tar.gz"
export Q124_REMOTE_SOURCE_ROOT=$TMP/source Q124_BOOTSTRAP_ARCHIVE=$TMP/source.tar.gz
export Q124_WORKER_ENV=$TMP/config/worker.env Q124_STATE_DIR=$TMP/state Q124_BIN_ROOT=$TMP/runtime-bin Q124_MARKER_DIR=$TMP/marker
export Q124_INSTALL_WORKER_BIN=$TMP/remote/true Q124_DEVICE_PROOF_BIN=$TMP/remote/true Q124_ROOT_PROBE_BIN=$TMP/remote/true
export Q124_REMOTE_FAKE_BIN=$TMP/remote Q124_BOOTSTRAP_HELPER=$HERE/fake-bootstrap-command.sh
export Q124_BOOTSTRAP_COMMAND_PROBE_BIN=$TMP/remote/probe
export Q124_SSM_REMOTE_PATH="$TMP/remote:/usr/bin:/bin" Q124_BOOTSTRAP_AWS_LOG=$TMP/aws.log
export Q124_CAPTURED_COMMAND=$TMP/command.sh Q124_SSM_STDOUT=$TMP/stdout Q124_SSM_STDERR=$TMP/stderr Q124_SSM_RC=$TMP/rc
export Q124_SSM_FAKE_STATE=$TMP/ssm-state.json Q124_SSM_EVIDENCE_JOURNAL=$TMP/ssm-evidence.jsonl
export Q124_SSM_EVIDENCE_BIN=$HERE/fake-ssm-evidence.sh Q124_BOOTSTRAP_CALL_LOG=$TMP/bootstrap.log
export Q124_COMMAND_GUARD_DIR=$TMP/guard Q124_SSM_INTENT_NONCE=0124abcd0124abcd0124abcd0124abcd
export Q124_SSM_EXECUTION_TIMEOUT_SECONDS=60 Q124_SSM_DELIVERY_TIMEOUT_SECONDS=30 Q124_SSM_POLL_TIMEOUT_SECONDS=60
export Q124_SSM_CANCEL_TIMEOUT_SECONDS=5 Q124_SSM_POLL_INTERVAL_SECONDS=0
: >"$Q124_SSM_EVIDENCE_JOURNAL"
: >"$Q124_SSM_STDOUT"
: >"$Q124_SSM_STDERR"

[[ ! -e $TMP/remote/aws && ! -e $TMP/remote/jq ]]
PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" bootstrap >/dev/null
[[ -x $TMP/remote/aws && -x $TMP/remote/jq ]]
grep -q '^CATS_NODE_ID=q124-fixture$' "$Q124_WORKER_ENV"
grep -q '^AWS_REGION=us-east-1$' "$Q124_WORKER_ENV"
grep -q '^AWS_DEFAULT_REGION=us-east-1$' "$Q124_WORKER_ENV"
[[ $(<"$TMP/marker/instance-id") == "$Q124_INSTANCE_ID" ]]
[[ $(grep -c -- '--region us-east-1' "$Q124_BOOTSTRAP_AWS_LOG") -ge 4 ]]
! grep -v -q -- '--region us-east-1' "$Q124_BOOTSTRAP_AWS_LOG"
! grep -q 'apt-get .*awscli' "$Q124_CAPTURED_COMMAND"
grep -q "awscli-exe-linux-x86_64-${Q124_AWS_CLI_VERSION}.zip" "$Q124_BOOTSTRAP_CALL_LOG"
grep -q '^timeout --foreground --signal=TERM --kill-after=15 30 bash ' "$Q124_BOOTSTRAP_CALL_LOG"
[[ ! -e $Q124_COMMAND_GUARD_DIR/active ]]
jq -se 'length == 2 and (map(.kind) | sort) == ["command","intent"] and all(.[]; .instance_id == "i-0abc124" and .mode == "bootstrap" and .manifest_sha256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and .nonce == "0124abcd0124abcd0124abcd0124abcd")' "$Q124_SSM_EVIDENCE_JOURNAL" >/dev/null
before=$(wc -l <"$Q124_BOOTSTRAP_AWS_LOG")
if Q124_REGION=bad-region PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null 2>&1; then
  printf 'invalid region unexpectedly reached SSM\n' >&2
  exit 1
fi
[[ $(wc -l <"$Q124_BOOTSTRAP_AWS_LOG") == "$before" ]]

# InvocationDoesNotExist is retryable; an unrelated lookup error is ambiguous.
export Q124_SSM_NOT_FOUND_POLLS=2 Q124_SSM_STATUS_SEQUENCE=Success Q124_SSM_SKIP_EXECUTE=1
PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null
unset Q124_SSM_NOT_FOUND_POLLS
export Q124_SSM_LOOKUP_ERROR=1
if PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null 2>&1; then
  printf 'ambiguous SSM lookup unexpectedly succeeded\n' >&2
  exit 1
fi
unset Q124_SSM_LOOKUP_ERROR

# A 4200-second reviewed ceiling accepts long-running progress without using a
# real-time sleep in the fixture.
export Q124_SSM_EXECUTION_TIMEOUT_SECONDS=4200 Q124_SSM_POLL_TIMEOUT_SECONDS=4320
export Q124_SSM_STATUS_SEQUENCE=InProgress,Success Q124_SSM_SKIP_EXECUTE=1
PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null

# Timeout owns cancellation and observes an authoritative terminal result.
export Q124_SSM_STATUS_SEQUENCE=InProgress Q124_SSM_EXECUTION_TIMEOUT_SECONDS=60 Q124_SSM_POLL_TIMEOUT_SECONDS=1 Q124_SSM_GET_DELAY_SECONDS=0.05
if PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null 2>&1; then
  printf 'nonterminal SSM command unexpectedly succeeded\n' >&2
  exit 1
fi
jq -e '.cancelled == true and .cancel_poll >= 2' "$Q124_SSM_FAKE_STATE" >/dev/null
unset Q124_SSM_GET_DELAY_SECONDS

# If SendCommand succeeded but command-id publication failed, the live owner
# cancels the exact in-memory command; only the earlier durable intent remains.
: >"$Q124_SSM_EVIDENCE_JOURNAL"
export Q124_SSM_COMMAND_EVIDENCE_FAIL=1 Q124_ALLOW_UNJOURNALED_COMMAND=1
export Q124_SSM_STATUS_SEQUENCE=InProgress Q124_SSM_EXECUTION_TIMEOUT_SECONDS=60 Q124_SSM_POLL_TIMEOUT_SECONDS=60
if PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null 2>&1; then
  printf 'command evidence loss unexpectedly succeeded\n' >&2
  exit 1
fi
jq -e '.cancelled == true and .cancel_poll >= 2' "$Q124_SSM_FAKE_STATE" >/dev/null
jq -se 'length == 1 and .[0].kind == "intent" and .[0].nonce == "0124abcd0124abcd0124abcd0124abcd"' "$Q124_SSM_EVIDENCE_JOURNAL" >/dev/null
unset Q124_SSM_COMMAND_EVIDENCE_FAIL Q124_ALLOW_UNJOURNALED_COMMAND

# The same intent-only journal models runner loss in the Send response/comment
# gap. After the durable delivery deadline, an exact read-only lock probe is
# required before fresh cleanup may continue.
delivery=$(( $(date -u +%s) - 1 ))
not_after=$(( delivery + 4230 ))
printf '%s\n' "{\"kind\":\"intent\",\"instance_id\":\"i-0abc124\",\"nonce\":\"0124abcd0124abcd0124abcd0124abcd\",\"mode\":\"validate\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"delivery_deadline_epoch\":$delivery,\"not_after_epoch\":$not_after}" >"$Q124_SSM_EVIDENCE_JOURNAL"
unset Q124_SSM_SKIP_EXECUTE
export Q124_SSM_STATUS_SEQUENCE=Success Q124_SSM_EXECUTION_TIMEOUT_SECONDS=60 Q124_SSM_POLL_TIMEOUT_SECONDS=60
PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" recover-active >/dev/null
grep -q 'guard=absent nonce=0124abcd0124abcd0124abcd0124abcd manifest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' "$Q124_SSM_STDOUT"

# Busy/mismatched guard proof is ambiguous and must preserve the host.
export Q124_FAKE_FLOCK_BUSY=1
if PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" recover-active >/dev/null 2>&1; then
  printf 'busy command guard unexpectedly allowed recovery\n' >&2
  exit 1
fi
unset Q124_FAKE_FLOCK_BUSY

# A durable active record is cancelled by fresh-session recovery.
export Q124_SSM_EXECUTION_TIMEOUT_SECONDS=60 Q124_SSM_POLL_TIMEOUT_SECONDS=60
past=$(( $(date -u +%s) - 1 ))
printf '%s\n' \
  "{\"kind\":\"intent\",\"instance_id\":\"i-0abc124\",\"nonce\":\"0124abcd0124abcd0124abcd0124abcd\",\"mode\":\"start\",\"manifest_sha256\":\"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"delivery_deadline_epoch\":$((past - 60)),\"not_after_epoch\":$past}" \
  '{"kind":"command","instance_id":"i-0abc124","command_id":"0124abcd-0000-0000-0000-000000000124","nonce":"0124abcd0124abcd0124abcd0124abcd","mode":"start","manifest_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}' >"$Q124_SSM_EVIDENCE_JOURNAL"
jq -n '{poll:0,cancel_poll:0,cancelled:false,rc:0}' >"$Q124_SSM_FAKE_STATE"
export Q124_SSM_STATUS_SEQUENCE=InProgress
PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" recover-active >/dev/null
jq -e '.cancelled == true and .cancel_poll >= 2' "$Q124_SSM_FAKE_STATE" >/dev/null

printf 'q124 SSM bootstrap-to-remote contracts: PASS\n'
