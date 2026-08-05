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
for kind in apt-get curl unzip systemctl true probe; do
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-bootstrap-command.sh" "$kind" >"$TMP/remote/$kind"
  chmod 0755 "$TMP/remote/$kind"
done
tar -czf "$TMP/source.tar.gz" -C "$ROOT" deploy/aws/qualification/q124-remote.sh
export Q124_REAL_JQ
Q124_REAL_JQ=$(command -v jq)
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
before=$(wc -l <"$Q124_BOOTSTRAP_AWS_LOG")
if Q124_REGION=bad-region PATH="$TMP/outer:$PATH" "$SSM" "$Q124_INSTANCE_ID" validate >/dev/null 2>&1; then
  printf 'invalid region unexpectedly reached SSM\n' >&2
  exit 1
fi
[[ $(wc -l <"$Q124_BOOTSTRAP_AWS_LOG") == "$before" ]]

printf 'q124 SSM bootstrap-to-remote contracts: PASS\n'
