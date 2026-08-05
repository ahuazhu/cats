#!/usr/bin/env bash
set -euo pipefail
kind=${1:?kind required}
shift
case $kind in
  apt-get)
    if [[ " $* " == *' jq '* ]]; then
      printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$Q124_REAL_JQ" >"$Q124_REMOTE_FAKE_BIN/jq"
      chmod 0755 "$Q124_REMOTE_FAKE_BIN/jq"
    fi
    ;;
  curl)
    url= output=
    args=("$@")
    for ((i=0; i<${#args[@]}; i++)); do
      [[ ${args[$i]} == -o ]] && output=${args[$((i + 1))]}
      [[ ${args[$i]} == http* ]] && url=${args[$i]}
    done
    case $url in
      https://awscli.amazonaws.com/*) : >"$output" ;;
      */api/token) printf 'token\n' ;;
      */dynamic/instance-identity/document)
        printf '{"instanceId":"%s","accountId":"%s","region":"%s"}\n' "$Q124_INSTANCE_ID" "$Q124_ACCOUNT_ID" "$Q124_REGION"
        ;;
      *) exit 6 ;;
    esac
    ;;
  unzip)
    destination=
    while (($#)); do
      [[ $1 == -d ]] && { destination=$2; break; }
      shift
    done
    mkdir -p "$destination/aws"
    printf '#!/usr/bin/env bash\nexec %q install-aws "$@"\n' "$Q124_BOOTSTRAP_HELPER" >"$destination/aws/install"
    chmod 0755 "$destination/aws/install"
    ;;
  install-aws)
    printf '#!/usr/bin/env bash\nexec %q aws "$@"\n' "$Q124_BOOTSTRAP_HELPER" >"$Q124_REMOTE_FAKE_BIN/aws"
    chmod 0755 "$Q124_REMOTE_FAKE_BIN/aws"
    ;;
  aws)
    [[ ${1:-} == --region && ${2:-} == "$Q124_REGION" ]] || exit 7
    printf 'remote-aws %s\n' "$*" >>"$Q124_BOOTSTRAP_AWS_LOG"
    shift 2
    case "${1:-} ${2:-}" in
      's3 cp') cp "$Q124_BOOTSTRAP_ARCHIVE" "$4" ;;
      'sts get-caller-identity') printf '%s\n' "$Q124_ACCOUNT_ID" ;;
      'secretsmanager get-secret-value')
        secret=${4:-}
        if [[ $secret == "$Q124_RUNTIME_SECRET_ARN" ]]; then
          printf '{"CATS_AUTH_TOKEN":"runtime-token"}\n'
        else
          printf '{"host":"db.internal","port":5432}\n'
        fi
        ;;
      *) exit 8 ;;
    esac
    ;;
  systemctl)
    if [[ ${1:-} == show ]]; then printf '/system.slice/cats-worker.service\n'; fi
    ;;
  true) exit 0 ;;
  probe)
    case ${1:-} in
      aws|jq) [[ -x $Q124_REMOTE_FAKE_BIN/$1 ]] ;;
      *) command -v "$1" >/dev/null 2>&1 ;;
    esac
    ;;
  *) exit 9 ;;
esac
