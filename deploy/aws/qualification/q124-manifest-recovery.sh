#!/usr/bin/env bash
# Recover one exact no-secret manifest comment without losing GitHub's JSON
# object/page boundaries when a comment body contains multiple lines.
set -euo pipefail
umask 077

die() { printf 'q124-manifest: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }

need GITHUB_REPOSITORY
need Q124_EXPECTED_MANIFEST_SHA256
need Q124_MANIFEST
[[ $GITHUB_REPOSITORY =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid repository"
[[ $Q124_EXPECTED_MANIFEST_SHA256 =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
[[ ! -e $Q124_MANIFEST && ! -L $Q124_MANIFEST ]] || die "manifest output must not already exist"

GH_BIN=${Q124_GH_BIN:-gh}
marker="<!-- cats-q124-manifest:${Q124_EXPECTED_MANIFEST_SHA256} -->"
if ! pages=$($GH_BIN api --paginate "repos/${GITHUB_REPOSITORY}/issues/124/comments"); then
  die "GitHub comment lookup failed"
fi
if ! matches=$(jq -s --arg marker "$marker" \
  '[.[][] | select(((.body // "") | type) == "string" and ((.body // "") | contains($marker)))]' <<<"$pages"); then
  die "GitHub comment response was not a sequence of JSON arrays"
fi
[[ $(jq -er 'length' <<<"$matches") == 1 ]] || die "manifest comment was not unique"
body=$(jq -er '.[0].body | select(type == "string")' <<<"$matches") || die "manifest comment body was invalid"

prefix='q124-manifest-base64: '
encoded_lines=$(jq -cn --arg body "$body" --arg prefix "$prefix" \
  '[$body | split("\n")[] | select(startswith($prefix)) | ltrimstr($prefix)]')
[[ $(jq -er 'length' <<<"$encoded_lines") == 1 ]] || die "manifest comment must contain exactly one base64 line"
encoded=$(jq -er '.[0] | select(type == "string")' <<<"$encoded_lines") || die "manifest base64 value was invalid"
(( ${#encoded} >= 4 && ${#encoded} <= 65536 && ${#encoded} % 4 == 0 )) || die "manifest base64 length is invalid"
[[ $encoded =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || die "manifest base64 characters are invalid"

tmp=$(mktemp "${Q124_MANIFEST}.tmp.XXXXXX") || die "cannot create manifest staging file"
cleanup() { [[ ! -e $tmp || -f $tmp ]] && rm -f "$tmp"; }
trap cleanup EXIT
if ! printf '%s' "$encoded" | base64 --decode >"$tmp"; then
  die "manifest base64 decoding failed"
fi
[[ -s $tmp ]] || die "decoded manifest is empty"
actual=$(jq -S -c . "$tmp" | sha256sum | awk '{print $1}') || die "decoded manifest is not valid JSON"
[[ $actual == "$Q124_EXPECTED_MANIFEST_SHA256" ]] || die "manifest digest mismatch"
mv "$tmp" "$Q124_MANIFEST"
trap - EXIT
printf 'manifest-recovered-sha256=%s\n' "$actual"
