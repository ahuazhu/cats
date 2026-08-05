#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
TOOL=$HERE/../q124-ssm-command-evidence.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin"
printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$HERE/fake-ssm-evidence-gh.sh" >"$TMP/bin/gh"
chmod 0755 "$TMP/bin/gh"
export GITHUB_REPOSITORY=owner/cats GH_TOKEN=fake Q124_SSM_GH_STORE=$TMP/comments.jsonl
: >"$Q124_SSM_GH_STORE"
manifest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
other=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
nonce=0124abcd0124abcd0124abcd0124abcd
PATH="$TMP/bin:$PATH" "$TOOL" publish-intent i-0abc124 "$nonce" start "$manifest" 1900000060 1900004290
PATH="$TMP/bin:$PATH" "$TOOL" publish-command i-0abc124 0124abcd-0000-0000-0000-000000000124 start "$manifest" "$nonce"
PATH="$TMP/bin:$PATH" "$TOOL" publish-intent i-0abc124 bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb stop "$other" 1900000060 1900004290
records=$(PATH="$TMP/bin:$PATH" "$TOOL" list "$manifest")
jq -se --arg manifest "$manifest" '
  length == 2 and (map(.kind) | sort) == ["command","intent"] and
  all(.[]; .schema == 1 and .issue == 124 and .instance_id == "i-0abc124" and
    .nonce == "0124abcd0124abcd0124abcd0124abcd" and
    .mode == "start" and .manifest_sha256 == $manifest) and
  (map(select(.kind == "command"))[0].command_id == "0124abcd-0000-0000-0000-000000000124") and
  (map(select(.kind == "intent"))[0].not_after_epoch == 1900004290)
' <<<"$records" >/dev/null
[[ -z $(PATH="$TMP/bin:$PATH" "$TOOL" list cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc) ]]
if Q124_SSM_GH_MALFORMED=1 PATH="$TMP/bin:$PATH" "$TOOL" list "$manifest" >/dev/null 2>&1; then
  printf 'malformed durable SSM evidence unexpectedly succeeded\n' >&2
  exit 1
fi
printf 'q124 durable SSM command evidence contracts: PASS\n'
