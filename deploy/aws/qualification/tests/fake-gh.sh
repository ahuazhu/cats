#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == api && ${2:-} == --paginate && ${3:-} == "repos/${GITHUB_REPOSITORY}/issues/124/comments" && $# == 3 ]] || exit 2
marker="<!-- cats-q124-manifest:${Q124_EXPECTED_MANIFEST_SHA256} -->"
good_body=$(printf '%s\nq124-manifest-base64: %s\n\nProvisioned manifest:\n```json\n%s\n```' \
  "$marker" "$Q124_TEST_MANIFEST_BASE64" "$Q124_TEST_MANIFEST_CANONICAL")

case ${Q124_GH_SCENARIO:-multi-page-multiline} in
  multi-page-multiline)
    jq -nc '[{"body":"unrelated first-page comment\nwith multiple lines"}, {"body":null}]'
    jq -nc --arg body "$good_body" '[{"body":$body}]'
    ;;
  duplicate-marker)
    jq -nc --arg body "$good_body" '[{"body":$body}]'
    jq -nc --arg body "$good_body" '[{"body":$body}]'
    ;;
  multiple-base64)
    body=$(printf '%s\nq124-manifest-base64: %s\nq124-manifest-base64: %s\n' \
      "$marker" "$Q124_TEST_MANIFEST_BASE64" "$Q124_TEST_MANIFEST_BASE64")
    jq -nc --arg body "$body" '[{"body":$body}]'
    ;;
  malformed-base64)
    body=$(printf '%s\nq124-manifest-base64: %s\n' "$marker" 'AAAA%%%=====')
    jq -nc --arg body "$body" '[{"body":$body}]'
    ;;
  *) exit 2 ;;
esac
