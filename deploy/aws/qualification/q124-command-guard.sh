#!/usr/bin/env bash
# Serialize one manifest-bound remote action and leave a no-secret active marker
# that fresh-session cleanup can inspect without trusting runner-local state.
set -euo pipefail
umask 077

die() { printf 'q124-command-guard: %s\n' "$*" >&2; exit 1; }
payload=${1:?payload required}
manifest_sha=${2:?manifest digest required}
nonce=${3:?intent nonce required}
mode=${4:?mode required}
not_after=${5:?intent upper bound required}
hard_timeout=${6:?hard timeout required}
[[ -f $payload && ! -L $payload ]] || die "payload must be a regular non-symlink"
[[ $manifest_sha =~ ^[0-9a-f]{64}$ && $nonce =~ ^[0-9a-f]{32}$ ]] || die "invalid intent identity"
[[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$ ]] || die "invalid mode"
[[ $not_after =~ ^[1-9][0-9]{9}$ ]] || die "invalid intent upper bound"
[[ $hard_timeout =~ ^[1-9][0-9]{1,3}$ ]] && (( hard_timeout <= 4170 )) || die "invalid hard timeout"
guard_dir=${Q124_COMMAND_GUARD_DIR:-/var/lib/cats/q124-command}
[[ $guard_dir =~ ^/[A-Za-z0-9_./-]+$ && $guard_dir != *..* ]] || die "invalid guard directory"
command -v flock >/dev/null 2>&1 || die "flock is required"
command -v timeout >/dev/null 2>&1 || die "timeout is required"
install -d -m 0700 "$guard_dir"
exec 9>"$guard_dir/active.lock"
flock -n 9 || die "another q124 remote command is active"
marker_tmp=$(mktemp "$guard_dir/.active.XXXXXX")
printf 'schema=1\nmanifest_sha256=%s\nnonce=%s\nmode=%s\nnot_after=%s\n' \
  "$manifest_sha" "$nonce" "$mode" "$not_after" >"$marker_tmp"
chmod 0600 "$marker_tmp"
mv "$marker_tmp" "$guard_dir/active"
cleanup() { rm -f -- "$marker_tmp" "$guard_dir/active"; }
trap cleanup EXIT HUP INT TERM
timeout --foreground --signal=TERM --kill-after=15 "$hard_timeout" bash "$payload"
