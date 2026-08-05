#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
CONTROL=$HERE/../q124-control-api.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$HERE/fake-curl.sh" >"$TMP/bin/curl"
chmod 0755 "$TMP/bin/curl"
export PATH="$TMP/bin:$PATH" Q124_CURL_LOG=$TMP/curl.log Q124_CONTROL_FAKE_STATE=$TMP/deleted
export Q124_CONTROL_URL=https://control.example Q124_CONTROL_AUTHORITY=control.example
export Q124_ADMIN_TOKEN_FILE=$TMP/token Q124_CURL_CONNECT_TIMEOUT=7 Q124_CURL_MAX_TIME=19
printf 'token-safe\n' >"$Q124_ADMIN_TOKEN_FILE"
chmod 0600 "$Q124_ADMIN_TOKEN_FILE"
expect_fail() { if "$@" >/dev/null 2>&1; then printf 'expected control failure\n' >&2; exit 1; fi; }

Q124_CONTROL_URL=http://control.example expect_fail "$CONTROL" get metal-source
Q124_CONTROL_URL=https://other.example expect_fail "$CONTROL" get metal-source
[[ ! -e $Q124_CURL_LOG ]] || { printf 'invalid authority reached curl\n' >&2; exit 1; }

export Q124_CONTROL_URL=https://control.example Q124_CONTROL_SCENARIO=lost
"$CONTROL" get metal-source >/dev/null
grep -q -- "--proto =https --tlsv1.2 --connect-timeout 7 --max-time 19" "$Q124_CURL_LOG"

: >"$Q124_CURL_LOG"
Q124_CONTROL_SCENARIO=nonempty expect_fail "$CONTROL" delete q124-node metal-source ws-q124 q124-
! grep -q -- '--request DELETE' "$Q124_CURL_LOG"

: >"$Q124_CURL_LOG"
Q124_CONTROL_SCENARIO=wrong-scope expect_fail "$CONTROL" delete q124-node metal-source ws-q124 q124-
! grep -q -- '--request DELETE' "$Q124_CURL_LOG"

: >"$Q124_CURL_LOG"
export Q124_CONTROL_SCENARIO=delete-race
"$CONTROL" delete q124-node metal-source ws-q124 q124-
grep -q -- '--request DELETE' "$Q124_CURL_LOG"
grep -q -- 'https://control.example/v1/admin/nodes/metal-source' "$Q124_CURL_LOG"

printf 'q124 control API contracts: PASS\n'
