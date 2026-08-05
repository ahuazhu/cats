#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
GUARD=$HERE/../q124-command-guard.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/guard"
for kind in flock timeout; do
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-bootstrap-command.sh" "$kind" >"$TMP/bin/$kind"
  chmod 0755 "$TMP/bin/$kind"
done
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "${Q124_FAKE_NOW:?}"\n' >"$TMP/bin/date"
chmod 0755 "$TMP/bin/date"
printf '#!/usr/bin/env bash\nprintf executed >%q\n' "$TMP/executed" >"$TMP/payload.sh"
chmod 0700 "$TMP/payload.sh"
manifest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
nonce=0124abcd0124abcd0124abcd0124abcd
now=$(/bin/date -u +%s)
past=$((now - 1))
if Q124_FAKE_NOW=$now Q124_COMMAND_GUARD_DIR=$TMP/guard PATH="$TMP/bin:$PATH" \
  "$GUARD" "$TMP/payload.sh" "$manifest" "$nonce" validate "$past" 60 >/dev/null 2>&1; then
  printf 'expired command guard intent unexpectedly executed\n' >&2
  exit 1
fi
[[ ! -e $TMP/executed && ! -e $TMP/guard/active ]]
if Q124_FAKE_NOW=$now Q124_COMMAND_GUARD_DIR=$TMP/guard PATH="$TMP/bin:$PATH" \
  "$GUARD" "$TMP/payload.sh" "$manifest" "$nonce" validate "$now" 60 >/dev/null 2>&1; then
  printf 'upper-bound command guard intent unexpectedly executed\n' >&2
  exit 1
fi
[[ ! -e $TMP/executed && ! -e $TMP/guard/active ]]
future=$((now + 60))
Q124_FAKE_NOW=$now Q124_COMMAND_GUARD_DIR=$TMP/guard PATH="$TMP/bin:$PATH" \
  "$GUARD" "$TMP/payload.sh" "$manifest" "$nonce" validate "$future" 60 >/dev/null
[[ -f $TMP/executed && ! -e $TMP/guard/active ]]
printf 'q124 command guard expiry contracts: PASS\n'
