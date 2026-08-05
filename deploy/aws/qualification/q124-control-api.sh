#!/usr/bin/env bash
# Narrow, fail-closed adapter for the administrator node APIs used by #124.
set -euo pipefail

die() { printf 'q124-control: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }

need Q124_CONTROL_URL
need Q124_ADMIN_TOKEN_FILE
[[ -f $Q124_ADMIN_TOKEN_FILE && ! -L $Q124_ADMIN_TOKEN_FILE ]] || die "token file must be a regular non-symlink"
[[ $(stat -c '%a' "$Q124_ADMIN_TOKEN_FILE" 2>/dev/null || stat -f '%Lp' "$Q124_ADMIN_TOKEN_FILE") == 600 ]] || die "token file mode must be 0600"
[[ $(<"$Q124_ADMIN_TOKEN_FILE") =~ ^[A-Za-z0-9._~-]+$ ]] || die "token contains characters unsafe for curl config"

request() {
  local method=$1 path=$2 output=$3 expected=$4 status
  status=$(curl --silent --show-error --output "$output" --write-out '%{http_code}' \
    --config <(printf 'header = "Authorization: Bearer %s"\n' "$(<"$Q124_ADMIN_TOKEN_FILE")") \
    --request "$method" "${Q124_CONTROL_URL%/}$path") || die "HTTP request failed"
  [[ $status == "$expected" ]] || {
    jq -c '{error:(.error // .message // "redacted")}' "$output" 2>/dev/null >&2 || true
    die "$method $path returned $status, expected $expected"
  }
}

node_get() {
  local node=$1 out
  [[ $node =~ ^[A-Za-z0-9._-]+$ ]] || die "invalid node id"
  out=$(mktemp)
  request GET "/v1/admin/nodes/$node" "$out" 200
  jq -e --arg node "$node" '.node.id == $node' "$out" >/dev/null || die "node response identity mismatch"
  cat "$out"
  rm -f "$out"
}

assert_empty_cordoned() {
  node_get "$1" | jq -e '
    .node.state == "cordoned" and .assigned_cats == 0 and .orphan_cats == 0
  ' >/dev/null || die "node is not cordoned with zero assigned and orphan Cats"
}

case ${1:-} in
  get)
    node_get "${2:?node id required}"
    ;;
  absent)
    source_node=${2:?source node required}; node=${3:?node id required}
    node_get "$source_node" >/dev/null # known-positive calibration
    out=$(mktemp); trap 'rm -f "$out"' EXIT
    request GET "/v1/admin/nodes/$node" "$out" 404
    ;;
  cats-scope)
    node=${2:?node id required}; workspace=${3:?workspace required}; prefix=${4:-q124-}
    out=$(mktemp); trap 'rm -f "$out"' EXIT
    request GET "/v1/admin/nodes/$node/cats" "$out" 200
    jq -e --arg node "$node" --arg workspace "$workspace" --arg prefix "$prefix" '
      (.items | type == "array") and
      all(.items[];
        (.cat.id | type == "string" and length > 0) and
        .cat.node_id == $node and
        .cat.workspace_id == $workspace and
        (.cat.name | type == "string" and startswith($prefix)))
    ' "$out" >/dev/null || die "assigned Cat scope is not wholly owned by #124"
    jq -c '[.items[].cat.id]' "$out"
    ;;
  wait-cordoned)
    node=${2:?node id required}; source_node=${3:?source node required}; expected_memory=${4:?expected memory MiB required}; deadline=$((SECONDS + ${Q124_CONTROL_TIMEOUT_SECONDS:-300}))
    [[ $expected_memory =~ ^[0-9]+$ ]] || die "invalid expected memory"
    first=1
    while (( SECONDS < deadline )); do
      summary=$(node_get "$node" 2>/dev/null || true)
      if [[ -n $summary ]]; then
        if (( first )); then
          jq -e '.node.state == "cordoned"' <<<"$summary" >/dev/null || die "first registration was not Cordoned"
          first=0
        fi
        if jq -e '.node.state == "cordoned" and .assigned_cats == 0 and .orphan_cats == 0' <<<"$summary" >/dev/null; then
          jq -e --argjson memory "$expected_memory" '.node.capacity.cpus == 1 and .node.capacity.memory_mib == $memory' <<<"$summary" >/dev/null || die "qualification capacity differs from the staged value"
          jq -e '.heartbeat_age_seconds <= 30' <<<"$summary" >/dev/null || die "qualification heartbeat is stale"
          printf '%s\n' "$summary"
          exit 0
        fi
      fi
      sleep 2
    done
    node_get "$source_node" >/dev/null
    die "node did not become empty Cordoned before timeout"
    ;;
  drain)
    node=${2:?node id required}; workspace=${3:?workspace required}
    "$0" cats-scope "$node" "$workspace" q124- >/dev/null
    out=$(mktemp); trap 'rm -f "$out"' EXIT
    request POST "/v1/admin/nodes/$node/actions/drain" "$out" 202
    ;;
  cordon)
    node=${2:?node id required}; out=$(mktemp); trap 'rm -f "$out"' EXIT
    request POST "/v1/admin/nodes/$node/actions/cordon" "$out" 200
    ;;
  delete)
    node=${2:?node id required}; source_node=${3:?source node required}
    assert_empty_cordoned "$node"
    out=$(mktemp); trap 'rm -f "$out"' EXIT
    request DELETE "/v1/admin/nodes/$node" "$out" 204
    "$0" absent "$source_node" "$node"
    ;;
  *)
    die "usage: $0 {get|absent|cats-scope|wait-cordoned|drain|cordon|delete} ..."
    ;;
esac
