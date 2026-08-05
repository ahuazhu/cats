#!/usr/bin/env bash
# Durable, no-secret SSM command journal used by fresh-session recovery.
set -euo pipefail
umask 077

die() { printf 'q124-ssm-evidence: %s\n' "$*" >&2; exit 1; }
need() { [[ -n ${!1:-} ]] || die "missing $1"; }
need GITHUB_REPOSITORY
need GH_TOKEN
[[ $GITHUB_REPOSITORY =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || die "invalid GitHub repository"

case ${1:-} in
  publish-intent)
    instance=${2:?instance id required}; nonce=${3:?intent nonce required}
    mode=${4:?mode required}; manifest_sha=${5:?manifest digest required}
    delivery_deadline=${6:?delivery deadline required}; not_after=${7:?upper bound required}
    [[ $instance =~ ^i-[0-9a-f]+$ && $nonce =~ ^[0-9a-f]{32}$ ]] || die "invalid SSM intent identity"
    [[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$ ]] || die "invalid SSM mode"
    [[ $manifest_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
    [[ $delivery_deadline =~ ^[1-9][0-9]{9}$ && $not_after =~ ^[1-9][0-9]{9}$ ]] \
      && (( not_after > delivery_deadline )) || die "invalid intent time bounds"
    record=$(jq -cn --arg instance "$instance" --arg nonce "$nonce" --arg mode "$mode" --arg manifest "$manifest_sha" \
      --argjson delivery "$delivery_deadline" --argjson not_after "$not_after" \
      '{schema:1,issue:124,kind:"intent",instance_id:$instance,nonce:$nonce,mode:$mode,manifest_sha256:$manifest,delivery_deadline_epoch:$delivery,not_after_epoch:$not_after}')
    marker_key=$nonce
    ;;
  publish-command)
    instance=${2:?instance id required}; command_id=${3:?command id required}
    mode=${4:?mode required}; manifest_sha=${5:?manifest digest required}; nonce=${6:?intent nonce required}
    [[ $instance =~ ^i-[0-9a-f]+$ && $command_id =~ ^[0-9a-f-]+$ ]] || die "invalid SSM identity"
    [[ $nonce =~ ^[0-9a-f]{32}$ ]] || die "invalid SSM intent nonce"
    [[ $mode =~ ^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$ ]] || die "invalid SSM mode"
    [[ $manifest_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
    record=$(jq -cn --arg instance "$instance" --arg command "$command_id" --arg nonce "$nonce" --arg mode "$mode" --arg manifest "$manifest_sha" \
      '{schema:1,issue:124,kind:"command",instance_id:$instance,command_id:$command,nonce:$nonce,mode:$mode,manifest_sha256:$manifest}')
    marker_key=$command_id
    ;;
  list)
    ;;
  *) die "usage: $0 {publish-intent|publish-command|list} ..." ;;
esac

case ${1:-} in
  publish-intent|publish-command)
    encoded=$(printf '%s\n' "$record" | base64 | tr -d '\n')
    body=$(printf '<!-- cats-q124-ssm-command:%s:%s -->\nq124-ssm-command-base64: %s\n' "$manifest_sha" "$marker_key" "$encoded")
    gh api "repos/${GITHUB_REPOSITORY}/issues/124/comments" -f body="$body" >/dev/null \
      || die "command evidence publication failed"
    ;;
  list)
    manifest_sha=${2:?manifest digest required}
    [[ $manifest_sha =~ ^[0-9a-f]{64}$ ]] || die "invalid manifest digest"
    comments=$(mktemp)
    trap 'rm -f "$comments"' EXIT HUP INT TERM
    gh api --paginate "repos/${GITHUB_REPOSITORY}/issues/124/comments?per_page=100" --slurp >"$comments" \
      || die "command evidence lookup failed"
    jq -r --arg marker "<!-- cats-q124-ssm-command:${manifest_sha}:" '
      [ .[][] | .body | select(type == "string" and contains($marker)) |
        split("\n")[] | select(startswith("q124-ssm-command-base64: ")) |
        ltrimstr("q124-ssm-command-base64: ") ] | .[]
    ' "$comments" | while IFS= read -r encoded; do
      [[ ${#encoded} -ge 4 && ${#encoded} -le 4096 && $encoded =~ ^[A-Za-z0-9+/]+={0,2}$ ]] \
        || die "invalid encoded command evidence"
      decoded=$(printf '%s' "$encoded" | base64 --decode) || die "command evidence decode failed"
      jq -ce --arg manifest "$manifest_sha" 'select(
        .schema == 1 and .issue == 124 and .manifest_sha256 == $manifest and
        (.instance_id | test("^i-[0-9a-f]+$")) and
        (.nonce | test("^[0-9a-f]{32}$")) and
        (.mode | test("^(bootstrap|start|set-capacity|validate|snapshot|assert-idle|stop)$")) and
        ((.kind == "intent" and (.delivery_deadline_epoch | type == "number") and
          (.not_after_epoch | type == "number") and .not_after_epoch > .delivery_deadline_epoch) or
         (.kind == "command" and (.command_id | test("^[0-9a-f-]+$"))))
      )' <<<"$decoded" || die "invalid command evidence record"
    done
    ;;
esac
