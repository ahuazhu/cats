#!/usr/bin/env bash
set -euo pipefail
[[ ${1:-} == api && ${2:-} == "repos/${GITHUB_REPOSITORY}/issues/124/comments" ]] || exit 2
shift 2
[[ ${1:-} == -f && ${2:-} == body=* ]] || exit 3
[[ ${Q124_PUBLISH_GH_SCENARIO:-success} == success ]] || exit 4
printf '%s\n' "${2#body=}" >"$Q124_PUBLISHED_BODY"
printf '{"id":124}\n'
