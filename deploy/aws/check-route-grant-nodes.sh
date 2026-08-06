#!/usr/bin/env bash
# Fail closed unless every schedulable/serving Node is in one safe Route Grant
# rollout cohort: all legacy (the additive first release) or all enforcing the
# exact deployment key. A mixed cohort is an interrupted worker rollout.
set -euo pipefail

[[ $# -eq 2 ]] || {
  echo "usage: $0 <expected-public-key-sha256> <node-summaries.json>" >&2
  exit 2
}

expected_fingerprint=$1
nodes_json=$2
[[ $expected_fingerprint =~ ^[0-9a-f]{64}$ ]] || {
  echo "invalid expected Route Grant fingerprint" >&2
  exit 2
}
jq -e '.items | type == "array"' "$nodes_json" >/dev/null

serving='select(
  .node.state == "ready"
  or (.assigned_cats // 0) > 0
  or (.orphan_cats // 0) > 0
)'
incompatible="$(
  jq -r --arg expected "$expected_fingerprint" ".items[]
    | $serving
    | select((.node.route_grant_public_key_sha256 // \"\") != \"\")
    | select(.node.route_grant_public_key_sha256 != \$expected)
    | .node.id" "$nodes_json"
)"
if [[ -n $incompatible ]]; then
  echo "Schedulable or serving Nodes verify a different Route Grant key: $incompatible. Drain and upgrade those Nodes before rotating the application key." >&2
  exit 1
fi

legacy="$(
  jq -r ".items[]
    | $serving
    | select((.node.route_grant_public_key_sha256 // \"\") == \"\")
    | .node.id" "$nodes_json"
)"
enforcing="$(
  jq -r ".items[]
    | $serving
    | select((.node.route_grant_public_key_sha256 // \"\") != \"\")
    | .node.id" "$nodes_json"
)"
if [[ -n $legacy && -n $enforcing ]]; then
  echo "Interrupted Route Grant worker rollout: legacy serving Nodes ($legacy) and enforcing serving Nodes ($enforcing) coexist. Finish the drained worker rollout before mutating the application." >&2
  exit 1
fi
if [[ -n $legacy ]]; then
  echo "Additive first rollout: all schedulable or serving Nodes are legacy ($legacy). Control plane must roll before Gateway, then workers one at a time."
else
  echo "Every schedulable or serving Node accepts Route Grant key $expected_fingerprint."
fi
