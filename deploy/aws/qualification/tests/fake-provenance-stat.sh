#!/usr/bin/env bash
# Fixture-only stat protocol for deterministic ownership failures.
set -euo pipefail

field=${1:?field required}
path=${2:?path required}
if [[ $field == uid && $path == "${Q124_PROVENANCE_WRONG_OWNER_PATH:-}" ]]; then
  printf '%s\n' "${Q124_PROVENANCE_WRONG_OWNER_UID:?wrong owner uid required}"
  exit 0
fi
case $field in
  uid) stat -c '%u' "$path" 2>/dev/null || stat -f '%u' "$path" ;;
  mode) stat -c '%a' "$path" 2>/dev/null || stat -f '%Lp' "$path" ;;
  *) exit 2 ;;
esac
