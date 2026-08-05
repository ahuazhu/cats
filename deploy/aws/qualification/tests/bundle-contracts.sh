#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
BUNDLE=$HERE/../q124-bundle-exec.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/source/deploy/aws/qualification"
printf '#!/usr/bin/env bash\nprintf exact-bundle >%q\n' "$TMP/executed" >"$TMP/source/deploy/aws/qualification/q124-temp-worker.sh"
chmod 0755 "$TMP/source/deploy/aws/qualification/q124-temp-worker.sh"
orchestrator=$(sha256sum "$TMP/source/deploy/aws/qualification/q124-temp-worker.sh" | awk '{print $1}')
tar -czf "$TMP/source.tar.gz" -C "$TMP/source" .
archive=$(sha256sum "$TMP/source.tar.gz" | awk '{print $1}')
source_sha=0124abc0124abc0124abc0124abc0124abc0124a
jq -n --arg source "$source_sha" --arg archive "$archive" --arg orchestrator "$orchestrator" \
  '{bundle:{source_sha:$source,archive_key:("worker/qualification-124/"+$source+"/q124-source-"+$archive+".tar.gz"),archive_sha256:$archive,orchestrator_sha256:$orchestrator}}' \
  >"$TMP/manifest.json"
Q124_MANIFEST=$TMP/manifest.json Q124_BUNDLE_ARCHIVE=$TMP/source.tar.gz Q124_BUNDLE_WORK_DIR=$TMP/work \
  "$BUNDLE"
[[ -f $TMP/executed ]]
rm -f "$TMP/executed"
jq '.bundle.orchestrator_sha256="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"' \
  "$TMP/manifest.json" >"$TMP/tampered.json"
if Q124_MANIFEST=$TMP/tampered.json Q124_BUNDLE_ARCHIVE=$TMP/source.tar.gz Q124_BUNDLE_WORK_DIR=$TMP/work-bad \
  "$BUNDLE" >/dev/null 2>&1; then
  printf 'bundle with mismatched orchestrator unexpectedly executed\n' >&2
  exit 1
fi
[[ ! -e $TMP/executed ]]
printf 'q124 manifest-bound bundle contracts: PASS\n'
