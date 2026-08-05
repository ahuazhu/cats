#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PUBLISH=$HERE/../q124-manifest-publish.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir "$TMP/bin"
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$HERE/fake-publish-gh.sh" >"$TMP/bin/gh"
chmod 0755 "$TMP/bin/gh"
export PATH="$TMP/bin:$PATH" GITHUB_REPOSITORY=owner/cats GH_TOKEN=fake-token Q124_PUBLISHED_BODY=$TMP/body
printf '{"schema":1,"issue":124}\n' >"$TMP/manifest.json"
digest=$(jq -S -c . "$TMP/manifest.json" | sha256sum | awk '{print $1}')
"$PUBLISH" "$TMP/manifest.json" "$digest" >/dev/null
grep -q "<!-- cats-q124-manifest:${digest} -->" "$Q124_PUBLISHED_BODY"
encoded=$(sed -n 's/^q124-manifest-base64: //p' "$Q124_PUBLISHED_BODY")
[[ $(printf '%s' "$encoded" | base64 --decode) == "$(jq -S -c . "$TMP/manifest.json")" ]]

rm -f "$Q124_PUBLISHED_BODY"
Q124_PUBLISH_GH_SCENARIO=fail
export Q124_PUBLISH_GH_SCENARIO
if "$PUBLISH" "$TMP/manifest.json" "$digest" >/dev/null 2>&1; then
  printf 'manifest publisher accepted failed durable write\n' >&2
  exit 1
fi
[[ ! -e $Q124_PUBLISHED_BODY ]]
printf 'q124 manifest publication contracts: PASS\n'
