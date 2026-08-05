#!/usr/bin/env bash
# Executable state-machine contracts for the #124 tooling. These tests assert
# fake external state and ordered calls; they do not grep implementation text.
set -euo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/../../../.." && pwd)
TOOL=$ROOT/deploy/aws/qualification/q124-temp-worker.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
"$HERE/device-contracts.sh"
"$HERE/remote-contracts.sh"
"$HERE/control-contracts.sh"
"$HERE/ssm-contracts.sh"
"$HERE/manifest-recovery-contracts.sh"
"$HERE/manifest-publish-contracts.sh"
"$HERE/policy-contracts.sh"

fail() { printf 'contracts: %s\n' "$*" >&2; exit 1; }
state_set() {
  local filter=$1 next=$Q124_FAKE_STATE.next
  jq "$filter" "$Q124_FAKE_STATE" >"$next" && mv "$next" "$Q124_FAKE_STATE"
}
assert_state() { jq -e "$1" "$Q124_FAKE_STATE" >/dev/null || fail "state assertion failed: $1"; }
expect_fail() { if "$@" >/dev/null 2>&1; then fail "expected failure: $*"; fi; }
wait_for_state() {
  local filter=$1
  for _ in {1..100}; do
    jq -e "$filter" "$Q124_FAKE_STATE" >/dev/null && return 0
    sleep 0.02
  done
  fail "timed out waiting for fake state: $filter"
}

reset_case() {
  local name=$1
  export Q124_FAKE_STATE=$TMP/$name.json
  python3 "$HERE/fake.py" init
  export Q124_AWS_BIN=$HERE/fake-aws.sh
  export Q124_CONTROL_BIN=$HERE/fake-control.sh
  export Q124_REMOTE_BIN=$HERE/fake-remote.sh
  export Q124_MANIFEST_PUBLISH_BIN=$HERE/fake-publish.sh
  export Q124_ACCOUNT_ID=111122223333 Q124_REGION=us-east-1 Q124_CLUSTER=cats-production
  export Q124_WORKSPACE_ID=ws-q124 Q124_SOURCE_INSTANCE_ID=i-a00124 Q124_SOURCE_NODE_ID=metal-source
  export Q124_AMI_ID=ami-0124 Q124_INSTANCE_TYPE=c5d.metal Q124_SUBNET_ID=subnet-0124
  export Q124_SECURITY_GROUP_ID=sg-0124 Q124_INSTANCE_PROFILE_NAME=cats-worker
  export Q124_ARTIFACT_BUCKET=cats-artifact
  export Q124_ARCHIVE_SHA256=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  export Q124_CACHE_DEVICE=/dev/nvme1n1 Q124_CONTROL_URL=https://cats.invalid Q124_CONTROL_AUTHORITY=cats.invalid
  export Q124_CHUNKSTORE_BUCKET=cats-chunks Q124_RUNTIME_SECRET_ARN=arn:aws:secretsmanager:us-east-1:111122223333:secret:runtime
  export Q124_DB_SECRET_ARN=arn:aws:secretsmanager:us-east-1:111122223333:secret:db Q124_DB_NAME=cats
  export Q124_TTL_HOURS=8 GITHUB_RUN_ID=124001 GITHUB_SHA=0124abc0124abc0124abc0124abc0124abc0124a
  export GITHUB_REPOSITORY=owner/cats GH_TOKEN=fake-token
  export Q124_DISCOVERY_TIMEOUT_SECONDS=0
  export Q124_ARCHIVE_KEY="worker/qualification-124/${GITHUB_SHA}/q124-source-${Q124_ARCHIVE_SHA256}.tar.gz"
  export Q124_MANIFEST_OUT=$TMP/$name-manifest.json Q124_MANIFEST=$TMP/$name-manifest.json
  unset Q124_EXPECTED_MANIFEST_SHA256
  unset Q124_EVIDENCE_OUT
  unset Q124_MANIFEST_SOURCE_SHA Q124_MANIFEST_RUN_ID Q124_EXPECTED_AMI Q124_EXPECTED_INSTANCE_TYPE
  unset Q124_EXPECTED_SUBNET Q124_EXPECTED_SECURITY_GROUP Q124_EXPECTED_INSTANCE_PROFILE Q124_EXPECTED_CACHE_DEVICE
}

provision_ok() {
  export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
  "$TOOL" >/dev/null
  export Q124_EXPECTED_MANIFEST_SHA256
  Q124_EXPECTED_MANIFEST_SHA256=$(jq -S -c . "$Q124_MANIFEST" | sha256sum | awk '{print $1}')
  assert_state '.instance_state == "running" and .termination_protection == true and .control_present == true and .control_state == "cordoned" and .worker_running == true and .published_manifests == 1'
  jq -e '
    .log as $l |
    ($l | index("control wait-cordoned q124-124001-0124abc metal-source 1")) < ($l | index("remote i-0abc124 set-capacity")) and
    ($l | index("remote i-0abc124 set-capacity")) < ($l | index("control wait-cordoned q124-124001-0124abc metal-source 1024"))
  ' "$Q124_FAKE_STATE" >/dev/null || fail "capacity was not staged 1 MiB -> 1024 MiB"
}

reset_case wrong-account
export Q124_ACCOUNT_ID=999900001111 Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '[.log[] | select(contains("run-instances") or contains("terminate-instances"))] == []'

reset_case wrong-control-authority
export Q124_CONTROL_URL=http://cats.invalid Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '[.log[] | select(contains("run-instances") or contains("terminate-instances"))] == []'

reset_case duplicate
state_set '.duplicate = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '[.log[] | select(contains("run-instances"))] == []'

reset_case multi-sg
state_set '.security_groups = ["sg-0124", "sg-unreviewed"]'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '[.log[] | select(contains("run-instances"))] == []'

reset_case initial-ready
state_set '.start_ready = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '.instance_state == "terminated"'
assert_state '[.log[] | select(contains("set-capacity"))] == []'

reset_case root-not-deletable
state_set '.root_delete_on_termination = false'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '.instance_state == "terminated" and .published_manifests == 0'

reset_case response-lost
state_set '.run_response_lost = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER Q124_EVIDENCE_OUT=$TMP/response-lost-evidence.json
expect_fail "$TOOL"
assert_state '.instance_state == "terminated"'
assert_state '[.log[] | select(contains("terminate-instances"))] as $calls | ($calls | length) == 1 and ($calls[0] | contains("--instance-ids i-0abc124"))'
jq -e '.status == "cleanup-terminated" and .instance_id == "i-0abc124" and .discovered_instances == 1' "$Q124_EVIDENCE_OUT" >/dev/null

reset_case response-lost-multiple
state_set '.run_response_lost = true | .discovery_multiple = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER Q124_EVIDENCE_OUT=$TMP/response-lost-multiple-evidence.json
expect_fail "$TOOL"
assert_state '.instance_state == "pending" and ([.log[] | select(contains("terminate-instances"))] | length == 0)'
jq -e '.status == "discovery-count-2-preserved" and .discovered_instances == 2 and .instance_id == null' "$Q124_EVIDENCE_OUT" >/dev/null

reset_case response-lost-zero
state_set '.run_preaccept_fail = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER Q124_EVIDENCE_OUT=$TMP/response-lost-zero-evidence.json
expect_fail "$TOOL"
assert_state '.instance_state == "absent" and ([.log[] | select(contains("terminate-instances"))] | length == 0)'
jq -e '.status == "discovery-count-0-preserved" and .discovered_instances == 0' "$Q124_EVIDENCE_OUT" >/dev/null

reset_case response-loss-cancelled
state_set '.sleep_run_response_loss = 2'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER Q124_EVIDENCE_OUT=$TMP/response-loss-cancelled-evidence.json
set +e
"$TOOL" >/dev/null 2>&1 & response_loss_pid=$!
wait_for_state '.instance_state == "pending"'
kill -TERM "$response_loss_pid"
wait "$response_loss_pid"
response_loss_rc=$?
set -e
[[ $response_loss_rc -ne 0 ]] || fail "response-loss cancellation unexpectedly succeeded"
assert_state '.instance_state == "terminated" and ([.log[] | select(contains("terminate-instances"))] | length == 1)'
jq -e '.status == "cleanup-terminated" and .instance_id == "i-0abc124"' "$Q124_EVIDENCE_OUT" >/dev/null

reset_case bad-hash
provision_ok
export Q124_MODE=validate Q124_EXPECTED_MANIFEST_SHA256=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb Q124_CONFIRMATION=VALIDATE_Q124_bbbbbbbbbbbb
before=$(jq '.log|length' "$Q124_FAKE_STATE")
expect_fail "$TOOL"
assert_state ".log[$before:] | all(contains(\"run-instances\") or contains(\"terminate-instances\") | not)"

reset_case bad-workspace
provision_ok
export Q124_WORKSPACE_ID=ws-wrong Q124_MODE=validate Q124_CONFIRMATION="VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.instance_state == "running"'

reset_case bad-source
provision_ok
export Q124_SOURCE_INSTANCE_ID=i-deadbeef Q124_MODE=validate Q124_CONFIRMATION="VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.instance_state == "running"'

reset_case expired
provision_ok
jq '.timestamps.created_at="2020-01-01T00:00:00Z" | .timestamps.expires_at="2020-01-01T01:00:00Z"' "$Q124_MANIFEST" >"$Q124_MANIFEST.next" && mv "$Q124_MANIFEST.next" "$Q124_MANIFEST"
Q124_EXPECTED_MANIFEST_SHA256=$(jq -S -c . "$Q124_MANIFEST" | sha256sum | awk '{print $1}')
export Q124_EXPECTED_MANIFEST_SHA256 Q124_MODE=validate Q124_CONFIRMATION="VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.instance_state == "running"'

reset_case live-provenance
provision_ok
state_set '.tag_overrides.CatsSourceSha = "ffffffffffffffffffffffffffffffffffffffff"'
export Q124_MODE=validate Q124_CONFIRMATION="VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '[.log[] | select(contains("terminate-instances"))] == []'

reset_case validate-policy-drift
provision_ok
export Q124_AMI_ID=ami-dead Q124_MODE=validate Q124_CONFIRMATION="VALIDATE_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.instance_state == "running" and ([.log[] | select(contains("terminate-instances"))] | length == 0)'

reset_case half-scope
provision_ok
state_set '.cats=[{"id":"cat-1","name":"q124-owned","workspace":"ws-q124"},{"id":"cat-2","name":"other","workspace":"ws-other"}] | .ledger_cats=["cat-1","cat-2"]'
export Q124_MODE=drain Q124_CONFIRMATION="DRAIN_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.cats|length == 2'
assert_state '[.log[] | select(startswith("control drain"))] == []'

reset_case non-empty
provision_ok
state_set '.cats=[{"id":"cat-1","name":"q124-owned","workspace":"ws-q124"}] | .ledger_cats=["cat-1"]'
export Q124_MODE=withdraw Q124_CONFIRMATION="WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
before=$(jq '.log|length' "$Q124_FAKE_STATE")
expect_fail "$TOOL"
assert_state '.control_present == true and .instance_state == "running"'
assert_state "[.log[$before:][] | select(startswith(\"remote i-0abc124 stop\") or startswith(\"control delete\") or contains(\"terminate-instances\"))] == []"

reset_case wrong-empty-scope
provision_ok
state_set '.cats_scope_error = true'
export Q124_MODE=withdraw Q124_CONFIRMATION="WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
before=$(jq '.log|length' "$Q124_FAKE_STATE")
expect_fail "$TOOL"
assert_state "[.log[$before:][] | select(startswith(\"remote i-0abc124 stop\") or startswith(\"control delete\") or contains(\"terminate-instances\"))] == []"

reset_case manifest-publication-failure
state_set '.fail_publish = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '.published_manifests == 0 and .instance_state == "terminated" and .control_present == false'
assert_state '[.log[] | select(startswith("publish "))] | length == 1'

reset_case cleanup-idle-probe-failure
state_set '.fail_validate = true | .fail_assert_idle = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '.instance_state == "running" and .control_present == true and .worker_running == true'
assert_state '[.log[] | select(startswith("remote i-0abc124 stop") or startswith("control delete") or contains("terminate-instances"))] == []'

reset_case partial-failure
state_set '.fail_validate = true'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
expect_fail "$TOOL"
assert_state '.instance_state == "terminated" and .control_present == false and .worker_running == false'
jq -er '
  [.log[] | select(startswith("remote") or startswith("control cordon") or startswith("control delete") or contains("modify-instance-attribute") or contains("terminate-instances"))] as $l |
  ($l | index("remote i-0abc124 start")) < ($l | index("remote i-0abc124 validate")) and
  ($l | index("remote i-0abc124 validate")) < ($l | index("control cordon q124-124001-0124abc")) and
  ($l | index("control delete q124-124001-0124abc metal-source ws-q124 q124-")) < ([range(0;$l|length) | select($l[.] | contains("terminate-instances"))] | first)
' "$Q124_FAKE_STATE" >/dev/null || fail "partial-failure cleanup order"

reset_case cancelled
state_set '.sleep_bootstrap = 2'
export Q124_MODE=provision Q124_CONFIRMATION=PROVISION_Q124_TEMP_WORKER
set +e
"$TOOL" >/dev/null 2>&1 & cancelled_pid=$!
wait_for_state '[.log[] | select(contains("remote i-0abc124 bootstrap"))] | length == 1'
kill -TERM "$cancelled_pid"
wait "$cancelled_pid"
cancelled_rc=$?
set -e
[[ $cancelled_rc -ne 0 ]] || fail "cancelled run unexpectedly succeeded"
assert_state '.instance_state == "terminated"'
assert_state '[.log[] | select(contains("terminate-instances"))] | length == 1'

reset_case exact-return
provision_ok
# Cleanup must remain possible after main advances; the manifest and live tags,
# not the runner's newer checkout, are the provenance pair.
export GITHUB_SHA=ffffffffffffffffffffffffffffffffffffffff
unset Q124_AMI_ID Q124_INSTANCE_TYPE Q124_SUBNET_ID Q124_SECURITY_GROUP_ID Q124_INSTANCE_PROFILE_NAME Q124_CACHE_DEVICE
export Q124_MODE=drain Q124_CONFIRMATION="DRAIN_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
"$TOOL" >/dev/null
"$TOOL" >/dev/null # retry is idempotent
export Q124_MODE=withdraw Q124_CONFIRMATION="WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
"$TOOL" >/dev/null
"$TOOL" >/dev/null # retry is idempotent
state_set '.tag_overrides.CatsNodeId = "q124-someone-else"'
export Q124_MODE=return Q124_CONFIRMATION=RETURN_Q124_i-0abc124_q124-124001-0124abc
before=$(jq '.log|length' "$Q124_FAKE_STATE")
expect_fail "$TOOL"
assert_state ".log[$before:] | any(contains(\"terminate-instances\")) | not"
state_set 'del(.tag_overrides)'
"$TOOL" >/dev/null
before=$(jq '.log|length' "$Q124_FAKE_STATE")
state_set '.return_lookup_multiple = true'
expect_fail "$TOOL"
assert_state ".log[$before:] | any(contains(\"terminate-instances\")) | not"
state_set '.return_lookup_multiple = false'
before=$(jq '.log|length' "$Q124_FAKE_STATE")
state_set '.return_lookup_error = true'
expect_fail "$TOOL"
assert_state ".log[$before:] | any(contains(\"terminate-instances\")) | not"
state_set '.return_lookup_error = false | .purge_terminated_inventory = true'
"$TOOL" >/dev/null # purged terminated instance + final absence oracles are idempotent
state_set '.conflicting_identity = true'
expect_fail "$TOOL" # purged exact id does not hide a conflicting active identity
state_set '.conflicting_identity = false'
assert_state '.instance_state == "terminated" and .control_present == false'
assert_state '[.log[] | select(contains("terminate-instances"))] | length == 1'

reset_case delete-response-lost
provision_ok
state_set '.delete_fail_once = true'
export Q124_MODE=withdraw Q124_CONFIRMATION="WITHDRAW_Q124_${Q124_EXPECTED_MANIFEST_SHA256:0:12}"
expect_fail "$TOOL"
assert_state '.control_present == true and .control_state == "lost" and .worker_running == false and .instance_state == "running"'
assert_state '[.log[] | select(contains("terminate-instances"))] | length == 0'
"$TOOL" >/dev/null
assert_state '.control_present == false and .instance_state == "running"'

printf 'q124 contract tests: PASS\n'
