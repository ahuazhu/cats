#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
EVIDENCE=$HERE/../q124-launch-evidence.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
export GITHUB_REPOSITORY=owner/cats GH_TOKEN=fake-token
export Q124_GH_BIN=$HERE/fake-launch-evidence-gh.sh
export Q124_LAUNCH_EVIDENCE_STORE=$TMP/comments.json
printf '[]\n' >"$Q124_LAUNCH_EVIDENCE_STORE"
run=124001
source=0124abc0124abc0124abc0124abc0124abc0124a
node=q124-124001-0124abc
instance=i-0abc124
manifest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
"$EVIDENCE" publish launch-armed "$run" "$source" "$node" - - false
"$EVIDENCE" publish instance-identified "$run" "$source" "$node" "$instance" - false
"$EVIDENCE" publish manifest-published "$run" "$source" "$node" "$instance" "$manifest" false
"$EVIDENCE" publish worker-start-attempted "$run" "$source" "$node" "$instance" "$manifest" true

# Issue #124 retains evidence for every run. Unrelated, valid records must not
# poison recovery of this exact run identity.
other_run=124002
other_source=1124abc1124abc1124abc1124abc1124abc1124a
other_node=q124-124002-1124abc
"$EVIDENCE" publish launch-armed "$other_run" "$other_source" "$other_node" - - false
"$EVIDENCE" publish instance-identified "$other_run" "$other_source" "$other_node" i-0def124 - false
recovered=$("$EVIDENCE" recover "$run" "$source" "$node")
jq -e --arg instance "$instance" --arg manifest "$manifest" \
  '.instance_id == $instance and .manifest_sha256 == $manifest and .worker_start_attempted == true and .launch_armed == true' \
  <<<"$recovered" >/dev/null

# A forged/conflicting identity can only make recovery fail closed.
"$EVIDENCE" publish instance-identified "$run" "$source" "$node" i-0dead124 - false
if "$EVIDENCE" recover "$run" "$source" "$node" >/dev/null 2>&1; then
  printf 'conflicting durable launch evidence unexpectedly recovered\n' >&2
  exit 1
fi

# A later phase cannot stand in for missing durable predecessors.
printf '[]\n' >"$Q124_LAUNCH_EVIDENCE_STORE"
"$EVIDENCE" publish launch-armed "$run" "$source" "$node" - - false
"$EVIDENCE" publish worker-start-attempted "$run" "$source" "$node" "$instance" "$manifest" true
if "$EVIDENCE" recover "$run" "$source" "$node" >/dev/null 2>&1; then
  printf 'incomplete durable launch phase chain unexpectedly recovered\n' >&2
  exit 1
fi
printf 'q124 durable launch evidence contracts: PASS\n'
