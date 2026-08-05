#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=$HERE/../q124-bootstrap-prereqs.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
export Q124_REMOTE_FAKE_BIN=$TMP/bin Q124_BOOTSTRAP_HELPER=$HERE/fake-bootstrap-command.sh
export Q124_BOOTSTRAP_COMMAND_PROBE_BIN=$TMP/bin/probe Q124_BOOTSTRAP_CALL_LOG=$TMP/calls.log
export Q124_REAL_JQ
Q124_REAL_JQ=$(command -v jq)
export Q124_AWS_CLI_VERSION=2.99.0
export Q124_AWS_CLI_X86_64_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
export Q124_JQ_VERSION=jq-1.7 Q124_BOOTSTRAP_AWS_LOG=$TMP/aws.log
for kind in apt-get curl unzip probe uname; do
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-bootstrap-command.sh" "$kind" >"$TMP/bin/$kind"
  chmod 0755 "$TMP/bin/$kind"
done
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$(command -v sha256sum)" >"$TMP/bin/sha256sum"
chmod 0755 "$TMP/bin/sha256sum"

reset_tools() {
  rm -f "$TMP/bin/aws" "$TMP/bin/jq" "$TMP/calls.log"
  : >"$TMP/calls.log"
  unset Q124_BOOTSTRAP_CURL_FAIL Q124_BOOTSTRAP_INSTALL_FAIL Q124_FAKE_AWS_VERSION Q124_FAKE_JQ_VERSION Q124_FAKE_ARCH
}
expect_fail() {
  if PATH="$TMP/bin:/usr/bin:/bin" "$TOOL" >/dev/null 2>&1; then
    printf 'bootstrap negative unexpectedly succeeded: %s\n' "$1" >&2
    exit 1
  fi
}

reset_tools
PATH="$TMP/bin:/usr/bin:/bin" "$TOOL" >/dev/null
grep -q "curl .*--proto =https .*--tlsv1.2 .*awscli-exe-linux-x86_64-${Q124_AWS_CLI_VERSION}.zip" "$TMP/calls.log"
grep -q '^install-aws .*--bin-dir /usr/local/bin --install-dir /usr/local/aws-cli$' "$TMP/calls.log"

reset_tools; export Q124_AWS_CLI_X86_64_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
expect_fail digest
! grep -q '^install-aws ' "$TMP/calls.log"
export Q124_AWS_CLI_X86_64_SHA256=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855

reset_tools; export Q124_FAKE_ARCH=arm64
expect_fail architecture
! grep -q '^curl ' "$TMP/calls.log"

reset_tools; export Q124_BOOTSTRAP_CURL_FAIL=1
expect_fail download
! grep -q '^install-aws ' "$TMP/calls.log"

reset_tools; export Q124_BOOTSTRAP_INSTALL_FAIL=1
expect_fail install

reset_tools; export Q124_FAKE_AWS_VERSION=2.98.0
expect_fail aws-version

reset_tools; export Q124_FAKE_JQ_VERSION=jq-1.6
expect_fail jq-version

printf 'q124 pinned bootstrap contracts: PASS\n'
