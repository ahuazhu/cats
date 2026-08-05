#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROVENANCE=$HERE/../q124-provenance.sh
STAT_DOUBLE=$HERE/fake-provenance-stat.sh
TMP=$(mktemp -d "$HERE/.provenance-fixture.XXXXXX")
TMP=$(cd "$TMP" && pwd -P)
trap 'rm -rf "$TMP"' EXIT
owner=$(id -u)

run_provenance() { "$PROVENANCE" --fixture "$owner" "$@"; }
expect_rejected() {
  local message=$1
  shift
  if "$@" >/dev/null 2>&1; then
    printf '%s unexpectedly accepted\n' "$message" >&2
    exit 1
  fi
}

mkdir -p "$TMP/trusted/bundles/root/source"
printf '#!/usr/bin/env bash\nexit 0\n' >"$TMP/trusted/bundles/root/source/action.sh"
chmod 0755 "$TMP/trusted/bundles/root/source/action.sh"
root=$TMP/trusted/bundles/root
digest=$(sha256sum "$root/source/action.sh" | awk '{print $1}')
run_provenance "$root" "source/action.sh=$digest"

# The source root and internal ancestors remain immutable manifest input.
chmod 0775 "$root/source"
expect_rejected "writable internal provenance ancestor" run_provenance \
  "$root" "source/action.sh=$digest"
chmod 0755 "$root/source"

# A writable directory above the source root permits wholesale replacement of
# the already-verified root. It must fail even when the replacement carries the
# same file bytes and therefore the same manifest digest.
cp -R "$TMP/trusted/bundles/root" "$TMP/trusted/bundles/replacement"
chmod 0775 "$TMP/trusted/bundles"
mv "$TMP/trusted/bundles/root" "$TMP/trusted/bundles/original"
mv "$TMP/trusted/bundles/replacement" "$TMP/trusted/bundles/root"
root=$TMP/trusted/bundles/root
expect_rejected "replaceable whole source root" run_provenance "$root" "source/action.sh=$digest"
chmod 0755 "$TMP/trusted/bundles"
run_provenance "$root" "source/action.sh=$digest"

# Canonical-path comparison and the component walk both reject a symlinked
# parent, even when it resolves to otherwise trusted content.
ln -s "$TMP/trusted/bundles" "$TMP/trusted/bundle-link"
expect_rejected "symlinked provenance parent" run_provenance \
  "$TMP/trusted/bundle-link/root" "source/action.sh=$digest"

# Ownership is part of the ancestor trust decision. A fixture-only stat double
# makes this deterministic even when the contracts themselves run as root.
export Q124_PROVENANCE_FIXTURE_STAT_BIN=$STAT_DOUBLE
export Q124_PROVENANCE_WRONG_OWNER_PATH=$TMP/trusted
export Q124_PROVENANCE_WRONG_OWNER_UID=$((owner + 10000))
expect_rejected "wrong-owner provenance parent" run_provenance "$root" "source/action.sh=$digest"
unset Q124_PROVENANCE_FIXTURE_STAT_BIN Q124_PROVENANCE_WRONG_OWNER_PATH Q124_PROVENANCE_WRONG_OWNER_UID

# Per-file symlink rejection and digest checking are retained.
mv "$root/source/action.sh" "$root/source/real.sh"
ln -s real.sh "$root/source/action.sh"
expect_rejected "symlinked provenance file" run_provenance "$root" "source/action.sh=$digest"
rm "$root/source/action.sh"
mv "$root/source/real.sh" "$root/source/action.sh"
printf '#!/usr/bin/env bash\nexit 1\n' >"$root/source/action.sh"
chmod 0755 "$root/source/action.sh"
expect_rejected "mismatched provenance digest" run_provenance "$root" "source/action.sh=$digest"

# Only the exact immutable production anchor is eligible for installation.
expect_rejected "non-production bundle anchor" "$PROVENANCE" --prepare-production-root \
  "$TMP/trusted/bundles/$(printf 'a%.0s' {1..64})"
printf 'q124 immutable provenance contracts: PASS\n'
