#!/usr/bin/env bash
# Install and verify the exact prerequisite toolchain used by a fresh q124 host.
set -euo pipefail
umask 077

die() { printf 'q124-bootstrap: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
for required_env in Q124_AWS_CLI_VERSION Q124_AWS_CLI_X86_64_SHA256 Q124_JQ_VERSION; do
  need "$required_env"
done
[[ $Q124_AWS_CLI_VERSION =~ ^2\.[0-9]+\.[0-9]+$ ]] || die "AWS CLI must be a pinned v2 version"
[[ $Q124_AWS_CLI_X86_64_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "invalid x86_64 AWS CLI digest"
[[ $Q124_JQ_VERSION =~ ^jq-[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || die "invalid jq version"

has_command() {
  if [[ -n ${Q124_BOOTSTRAP_COMMAND_PROBE_BIN:-} ]]; then
    "$Q124_BOOTSTRAP_COMMAND_PROBE_BIN" "$1"
  else
    command -v "$1" >/dev/null 2>&1
  fi
}

architecture=$(${Q124_UNAME_BIN:-uname} -m) || die "cannot determine host architecture"
case $architecture in
  x86_64) archive_arch=x86_64; archive_sha=$Q124_AWS_CLI_X86_64_SHA256 ;;
  *) die "unsupported host architecture: $architecture" ;;
esac

export PATH="/usr/local/bin:$PATH"
export DEBIAN_FRONTEND=noninteractive
if ! has_command curl || ! has_command unzip; then
  apt-get update -qq
  apt-get install -qy --no-install-recommends ca-certificates curl unzip
fi

aws_version=
if has_command aws; then
  aws_version=$(aws --version 2>&1 | sed -n 's/^aws-cli\/\([^ ]*\).*/\1/p')
fi
if [[ $aws_version != "$Q124_AWS_CLI_VERSION" ]]; then
  stage=$(mktemp -d /var/tmp/q124-awscli.XXXXXX)
  cleanup() { rm -rf -- "$stage"; }
  trap cleanup EXIT HUP INT TERM
  archive=$stage/awscliv2.zip
  curl --proto '=https' --tlsv1.2 -fsSL \
    "https://awscli.amazonaws.com/awscli-exe-linux-${archive_arch}-${Q124_AWS_CLI_VERSION}.zip" \
    -o "$archive"
  printf '%s  %s\n' "$archive_sha" "$archive" | sha256sum -c - >/dev/null \
    || die "AWS CLI archive digest mismatch"
  unzip -q "$archive" -d "$stage"
  install_args=(--bin-dir /usr/local/bin --install-dir /usr/local/aws-cli)
  [[ -z $aws_version ]] || install_args+=(--update)
  "$stage/aws/install" "${install_args[@]}"
  cleanup
  trap - EXIT HUP INT TERM
fi

if ! has_command jq; then
  apt-get update -qq
  apt-get install -qy --no-install-recommends jq
fi
actual_aws=$(aws --version 2>&1 | sed -n 's/^aws-cli\/\([^ ]*\).*/\1/p')
[[ $actual_aws == "$Q124_AWS_CLI_VERSION" ]] || die "AWS CLI version mismatch"
[[ $(jq --version) == "$Q124_JQ_VERSION" ]] || die "jq version mismatch"
printf 'bootstrap-toolchain=aws-cli/%s,%s,%s\n' "$actual_aws" "$Q124_JQ_VERSION" "$architecture"
