#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
RECOVERY=$HERE/../q124-manifest-recovery.sh
TMP=$(mktemp -d)
trap 'find "$TMP" -type f -delete; rmdir "$TMP"' EXIT

export GITHUB_REPOSITORY=cats/test Q124_GH_BIN=$HERE/fake-gh.sh
Q124_TEST_MANIFEST_CANONICAL=$(jq -S -c <<<'{"issue":124,"nested":{"multiline":"preserved"},"schema":1}')
Q124_EXPECTED_MANIFEST_SHA256=$(printf '%s\n' "$Q124_TEST_MANIFEST_CANONICAL" | sha256sum | awk '{print $1}')
Q124_TEST_MANIFEST_BASE64=$(printf '%s\n' "$Q124_TEST_MANIFEST_CANONICAL" | base64 | tr -d '\n')
export Q124_TEST_MANIFEST_CANONICAL Q124_EXPECTED_MANIFEST_SHA256 Q124_TEST_MANIFEST_BASE64

Q124_GH_SCENARIO=multi-page-multiline
Q124_MANIFEST=$TMP/recovered.json
export Q124_GH_SCENARIO Q124_MANIFEST
"$RECOVERY" >/dev/null
[[ $(jq -S -c . "$Q124_MANIFEST") == "$Q124_TEST_MANIFEST_CANONICAL" ]]

expect_recovery_failure() {
  local scenario=$1
  Q124_GH_SCENARIO=$scenario
  Q124_MANIFEST=$TMP/$scenario.json
  export Q124_GH_SCENARIO Q124_MANIFEST
  if "$RECOVERY" >/dev/null 2>&1; then
    printf 'manifest recovery unexpectedly accepted %s\n' "$scenario" >&2
    exit 1
  fi
  [[ ! -e $Q124_MANIFEST ]] || { printf 'failed recovery published a manifest\n' >&2; exit 1; }
}

expect_recovery_failure duplicate-marker
expect_recovery_failure multiple-base64
expect_recovery_failure malformed-base64
printf 'q124 manifest recovery contracts: PASS\n'
