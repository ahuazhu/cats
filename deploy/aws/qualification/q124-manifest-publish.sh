#!/usr/bin/env bash
# Persist the no-secret manifest before provisioning cleanup is disarmed.
set -euo pipefail
umask 077

die() { printf 'q124-manifest-publish: %s\n' "$*" >&2; exit 1; }
manifest=${1:?manifest file required}
expected=${2:?canonical SHA-256 required}
[[ $expected =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
[[ -f $manifest && ! -L $manifest ]] || die "manifest must be a regular non-symlink"
[[ ${GITHUB_REPOSITORY:-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid GitHub repository"
[[ -n ${GH_TOKEN:-} ]] || die "missing GH_TOKEN"

canonical=$(jq -S -c . "$manifest") || die "manifest is not valid JSON"
actual=$(printf '%s\n' "$canonical" | sha256sum | awk '{print $1}')
[[ $actual == "$expected" ]] || die "manifest digest mismatch"
encoded=$(printf '%s\n' "$canonical" | base64 | tr -d '\n')
[[ $encoded =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || die "base64 encoding failed"
body=$(printf '<!-- cats-q124-manifest:%s -->\nq124-manifest-base64: %s\n\nProvisioned manifest (contains identifiers, no credentials):\n```json\n%s\n```\n' \
  "$expected" "$encoded" "$(jq . "$manifest")")
gh api "repos/${GITHUB_REPOSITORY}/issues/124/comments" -f body="$body" >/dev/null \
  || die "durable issue publication failed"
printf 'manifest-published-sha256=%s\n' "$expected" >&2
