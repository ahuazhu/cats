#!/usr/bin/env bash
# Verify manifest-bound scripts before a root SSM payload executes them.
set -euo pipefail

die() { printf 'q124-provenance: %s\n' "$*" >&2; exit 1; }
root=${1:?source root required}
shift
[[ $root == /* && -d $root && ! -L $root ]] || die "source root must be an absolute non-symlink directory"
(( $# > 0 )) || die "at least one path=digest binding is required"
owner_uid=${Q124_PROVENANCE_OWNER_UID:-0}
[[ $owner_uid =~ ^[0-9]+$ ]] || die "invalid trusted owner uid"

stat_uid() {
  stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

stat_mode() {
  stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

assert_owned_unwritable() {
  local path=$1 kind=$2 uid mode
  uid=$(stat_uid "$path") || die "cannot stat $kind $path"
  mode=$(stat_mode "$path") || die "cannot read mode for $kind $path"
  [[ $uid == "$owner_uid" ]] || die "$kind is not owned by trusted uid: $path"
  (( (8#$mode & 8#022) == 0 )) || die "$kind is group/other writable: $path"
}

assert_owned_unwritable "$root" "source root"
for binding in "$@"; do
  [[ $binding == *=* ]] || die "invalid path=digest binding"
  relative=${binding%%=*}
  expected=${binding#*=}
  [[ $relative =~ ^[A-Za-z0-9_./-]+$ && $relative != /* && $relative != *..* ]] || die "invalid relative source path"
  [[ $expected =~ ^[0-9a-f]{64}$ ]] || die "invalid source digest"
  path=$root/$relative
  [[ -f $path && ! -L $path ]] || die "source script must be a regular non-symlink: $relative"
  case $path in "$root"/*) ;; *) die "source path escaped root" ;; esac
  parent=${path%/*}
  while :; do
    [[ -d $parent && ! -L $parent ]] || die "source ancestor must be a non-symlink directory: $parent"
    assert_owned_unwritable "$parent" "source ancestor"
    [[ $parent == "$root" ]] && break
    next=${parent%/*}
    [[ $next != "$parent" && $next == "$root"* ]] || die "source ancestor escaped root"
    parent=$next
  done
  assert_owned_unwritable "$path" "source script"
  actual=$(sha256sum "$path" | awk '{print $1}')
  [[ $actual == "$expected" ]] || die "source digest mismatch: $relative"
done
printf 'provenance=verified\n'
