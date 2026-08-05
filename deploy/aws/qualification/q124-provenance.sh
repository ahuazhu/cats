#!/usr/bin/env bash
# Establish the production bundle anchor and verify manifest-bound scripts
# before a root SSM payload executes them.
set -euo pipefail

die() { printf 'q124-provenance: %s\n' "$*" >&2; exit 1; }
mode=${1:?trust model required}
shift
fixture_uid=
fixture_stat=
case $mode in
  --production) ;;
  --fixture)
    fixture_uid=${1:?fixture trusted uid required}
    shift
    [[ $fixture_uid =~ ^[0-9]+$ && $fixture_uid == "$(/usr/bin/id -u)" ]] \
      || die "fixture trusted uid must be the current uid"
    fixture_stat=${Q124_PROVENANCE_FIXTURE_STAT_BIN:-}
    [[ -z $fixture_stat || ( $fixture_stat == /* && -f $fixture_stat && ! -L $fixture_stat && -x $fixture_stat ) ]] \
      || die "fixture stat double must be an absolute executable regular file"
    ;;
  --prepare-production-root)
    root=${1:?source root required}
    [[ $root =~ ^/opt/cats/q124/bundles/[0-9a-f]{64}$ ]] \
      || die "production source root is outside the manifest bundle anchor"
    for directory in / /opt /opt/cats /opt/cats/q124 /opt/cats/q124/bundles; do
      if [[ ! -e $directory && ! -L $directory ]]; then
        /usr/bin/install -d -o 0 -g 0 -m 0755 "$directory" \
          || die "cannot install production bundle anchor: $directory"
      fi
      [[ -d $directory && ! -L $directory ]] \
        || die "production bundle anchor must be a non-symlink directory: $directory"
      uid=$(/usr/bin/stat -c '%u' "$directory" 2>/dev/null || /usr/bin/stat -f '%u' "$directory") \
        || die "cannot stat production bundle anchor: $directory"
      permissions=$(/usr/bin/stat -c '%a' "$directory" 2>/dev/null || /usr/bin/stat -f '%Lp' "$directory") \
        || die "cannot read production bundle anchor mode: $directory"
      [[ $uid =~ ^[0-9]+$ && $uid == 0 ]] \
        || die "production bundle anchor is not root-owned: $directory"
      [[ $permissions =~ ^[0-7]{3,4}$ ]] \
        || die "production bundle anchor has an invalid mode: $directory"
      (( (8#$permissions & 8#022) == 0 )) \
        || die "production bundle anchor is group/other writable: $directory"
    done
    printf 'production-anchor=verified\n'
    exit 0
    ;;
  *) die "invalid trust model" ;;
esac

root=${1:?source root required}
shift
[[ $root == /* && $root != *$'\n'* && $root != *$'\r'* && -d $root && ! -L $root ]] \
  || die "source root must be an absolute non-symlink directory"
canonical_root=$(cd -- "$root" && pwd -P) || die "cannot resolve source root"
[[ $root == "$canonical_root" ]] || die "source root must be an absolute canonical path"
(( $# > 0 )) || die "at least one path=digest binding is required"

stat_uid() {
  if [[ -n $fixture_stat ]]; then
    "$fixture_stat" uid "$1"
    return
  fi
  /usr/bin/stat -c '%u' "$1" 2>/dev/null || /usr/bin/stat -f '%u' "$1"
}

stat_mode() {
  if [[ -n $fixture_stat ]]; then
    "$fixture_stat" mode "$1"
    return
  fi
  /usr/bin/stat -c '%a' "$1" 2>/dev/null || /usr/bin/stat -f '%Lp' "$1"
}

assert_owned_unwritable() {
  local path=$1 kind=$2 uid mode
  uid=$(stat_uid "$path") || die "cannot stat $kind $path"
  mode=$(stat_mode "$path") || die "cannot read mode for $kind $path"
  [[ $uid =~ ^[0-9]+$ ]] || die "$kind has an invalid owner uid: $path"
  [[ $mode =~ ^[0-7]{3,4}$ ]] || die "$kind has an invalid mode: $path"
  if [[ $uid != 0 && ( -z $fixture_uid || $uid != "$fixture_uid" ) ]]; then
    die "$kind is not owned by a trusted uid: $path"
  fi
  (( (8#$mode & 8#022) == 0 )) || die "$kind is group/other writable: $path"
}

# Walk down from the filesystem root. Since each already-checked parent is
# trusted and not group/other writable, an untrusted process cannot replace the
# next pathname component between its symlink/type check and its stat.
directory=/
[[ -d $directory && ! -L $directory ]] || die "filesystem root must be a non-symlink directory"
assert_owned_unwritable "$directory" "source ancestor"
remaining=${root#/}
while [[ -n $remaining ]]; do
  component=${remaining%%/*}
  [[ -n $component ]] || die "source root must not contain empty path components"
  if [[ $remaining == */* ]]; then remaining=${remaining#*/}; else remaining=; fi
  if [[ $directory == / ]]; then directory=/$component; else directory=$directory/$component; fi
  [[ -d $directory && ! -L $directory ]] \
    || die "source ancestor must be a non-symlink directory: $directory"
  assert_owned_unwritable "$directory" "source ancestor"
done
[[ $directory == "$root" ]] || die "source ancestor walk did not reach source root"

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
