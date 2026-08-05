#!/usr/bin/env bash
# Append/recover no-secret pre/post-launch identity records on issue #124.
set -euo pipefail
umask 077

die() { printf 'q124-launch-evidence: %s\n' "$*" >&2; exit 1; }
GH_BIN=${Q124_GH_BIN:-gh}
[[ ${GITHUB_REPOSITORY:-} =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid GitHub repository"
[[ -n ${GH_TOKEN:-} ]] || die "missing GH_TOKEN"

case ${1:-} in
  publish)
    phase=${2:?phase required}; run=${3:?run id required}; source_sha=${4:?source sha required}; node=${5:?node id required}
    instance=${6:--}; manifest=${7:--}; start_attempted=${8:-false}
    [[ $phase =~ ^(launch-armed|instance-identified|manifest-published|worker-start-attempted)$ ]] || die "invalid phase"
    [[ $run =~ ^[0-9]+$ && $source_sha =~ ^[0-9a-f]{40,64}$ && $node == "q124-$run-${source_sha:0:7}" ]] || die "invalid launch identity"
    [[ $instance == - || $instance =~ ^i-[0-9a-f]+$ ]] || die "invalid instance id"
    [[ $manifest == - || $manifest =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
    [[ $start_attempted == true || $start_attempted == false ]] || die "invalid start marker"
    case $phase in
      launch-armed) [[ $instance == - && $manifest == - && $start_attempted == false ]] || die "launch-armed fields drifted" ;;
      instance-identified) [[ $instance != - && $manifest == - && $start_attempted == false ]] || die "instance phase fields drifted" ;;
      manifest-published) [[ $instance != - && $manifest != - && $start_attempted == false ]] || die "manifest phase fields drifted" ;;
      worker-start-attempted) [[ $instance != - && $manifest != - && $start_attempted == true ]] || die "start phase fields drifted" ;;
    esac
    record=$(jq -cn --arg phase "$phase" --arg run "$run" --arg source "$source_sha" --arg node "$node" \
      --arg instance "$instance" --arg manifest "$manifest" --argjson start "$start_attempted" \
      '{schema:1,issue:124,phase:$phase,github_run_id:$run,source_sha:$source,node_id:$node,instance_id:(if $instance=="-" then null else $instance end),manifest_sha256:(if $manifest=="-" then null else $manifest end),worker_start_attempted:$start}')
    encoded=$(printf '%s\n' "$record" | base64 | tr -d '\n')
    body=$(printf '<!-- cats-q124-launch:%s:%s -->\nq124-launch-base64: %s\n' "$run" "$phase" "$encoded")
    "$GH_BIN" api "repos/${GITHUB_REPOSITORY}/issues/124/comments" -f body="$body" >/dev/null \
      || die "durable launch evidence publication failed"
    ;;
  recover)
    run=${2:?run id required}; source_sha=${3:?source sha required}; node=${4:?node id required}
    [[ $run =~ ^[0-9]+$ && $source_sha =~ ^[0-9a-f]{40,64}$ && $node == "q124-$run-${source_sha:0:7}" ]] || die "invalid recovery identity"
    pages=$($GH_BIN api --paginate "repos/${GITHUB_REPOSITORY}/issues/124/comments") || die "launch evidence lookup failed"
    encoded=$(jq -sr --arg marker "<!-- cats-q124-launch:$run:" --arg prefix 'q124-launch-base64: ' '
      [.[][] | (.body // "") | select(type == "string" and startswith($marker)) | split("\n")[] |
       select(startswith($prefix)) | ltrimstr($prefix)] | .[]
    ' <<<"$pages") || die "invalid issue comment response"
    records=$(mktemp)
    trap 'rm -f "$records"' EXIT
    while IFS= read -r item; do
      (( ${#item} >= 4 && ${#item} <= 4096 && ${#item} % 4 == 0 )) \
        || die "invalid launch evidence length"
      [[ $item =~ ^[A-Za-z0-9+/]+={0,2}$ ]] || die "invalid launch evidence encoding"
      printf '%s' "$item" | base64 --decode \
        | jq -ce --arg run "$run" --arg source "$source_sha" --arg node "$node" '
          select(.schema == 1 and .issue == 124 and .github_run_id == $run and .source_sha == $source and .node_id == $node) |
          select(.phase | test("^(launch-armed|instance-identified|manifest-published|worker-start-attempted)$")) |
          select((.instance_id == null or (.instance_id | test("^i-[0-9a-f]+$"))) and
                 (.manifest_sha256 == null or (.manifest_sha256 | test("^[0-9a-f]{64}$"))) and
                 (.worker_start_attempted | type == "boolean")) |
          select(
            (.phase == "launch-armed" and .instance_id == null and .manifest_sha256 == null and .worker_start_attempted == false) or
            (.phase == "instance-identified" and .instance_id != null and .manifest_sha256 == null and .worker_start_attempted == false) or
            (.phase == "manifest-published" and .instance_id != null and .manifest_sha256 != null and .worker_start_attempted == false) or
            (.phase == "worker-start-attempted" and .instance_id != null and .manifest_sha256 != null and .worker_start_attempted == true)
          )
        ' >>"$records" || die "invalid launch evidence record"
    done <<<"$encoded"
    jq -se '
      select(any(.[]; .phase == "launch-armed")) |
      ([.[] | .instance_id | select(. != null)] | unique) as $instances |
      ([.[] | .manifest_sha256 | select(. != null)] | unique) as $manifests |
      select(($instances|length) <= 1 and ($manifests|length) <= 1) |
      select(($instances|length) == 0 or any(.[]; .phase == "instance-identified")) |
      select(($manifests|length) == 0 or any(.[]; .phase == "manifest-published")) |
      select((any(.[]; .worker_start_attempted) | not) or any(.[]; .phase == "worker-start-attempted")) |
      {launch_armed:true,instance_id:($instances[0] // null),manifest_sha256:($manifests[0] // null),worker_start_attempted:any(.[]; .worker_start_attempted)}
    ' "$records" || die "launch evidence is absent or conflicting"
    ;;
  *) die "mode must be publish or recover" ;;
esac
