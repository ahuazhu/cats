#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROVENANCE=$HERE/../q124-provenance.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/root/source"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TMP/root/source/action.sh"
chmod 0755 "$TMP/root/source/action.sh"
digest=$(sha256sum "$TMP/root/source/action.sh" | awk '{print $1}')
owner=$(id -u)
Q124_PROVENANCE_OWNER_UID=$owner "$PROVENANCE" "$TMP/root/source" "action.sh=$digest"
chmod 0775 "$TMP/root/source"
if Q124_PROVENANCE_OWNER_UID=$owner "$PROVENANCE" "$TMP/root/source" "action.sh=$digest" >/dev/null 2>&1; then
  printf 'writable provenance ancestor unexpectedly accepted\n' >&2
  exit 1
fi
chmod 0755 "$TMP/root/source"
mv "$TMP/root/source/action.sh" "$TMP/root/source/real.sh"
ln -s real.sh "$TMP/root/source/action.sh"
if Q124_PROVENANCE_OWNER_UID=$owner "$PROVENANCE" "$TMP/root/source" "action.sh=$digest" >/dev/null 2>&1; then
  printf 'symlinked provenance file unexpectedly accepted\n' >&2
  exit 1
fi
printf 'q124 immutable provenance contracts: PASS\n'
