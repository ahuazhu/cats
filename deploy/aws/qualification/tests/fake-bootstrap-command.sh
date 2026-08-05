#!/usr/bin/env bash
set -euo pipefail
kind=${1:?kind required}
shift
[[ -z ${Q124_BOOTSTRAP_CALL_LOG:-} ]] || printf '%s %s\n' "$kind" "$*" >>"$Q124_BOOTSTRAP_CALL_LOG"
case $kind in
  apt-get)
    if [[ " $* " == *' jq '* ]]; then
      printf '#!/usr/bin/env bash\nexec %q jq "$@"\n' "$Q124_BOOTSTRAP_HELPER" >"$Q124_REMOTE_FAKE_BIN/jq"
      chmod 0755 "$Q124_REMOTE_FAKE_BIN/jq"
    fi
    ;;
  curl)
    [[ ${Q124_BOOTSTRAP_CURL_FAIL:-0} != 1 ]] || exit 22
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
    [[ ${Q124_BOOTSTRAP_INSTALL_FAIL:-0} != 1 ]] || exit 23
    printf '#!/usr/bin/env bash\nexec %q aws "$@"\n' "$Q124_BOOTSTRAP_HELPER" >"$Q124_REMOTE_FAKE_BIN/aws"
    chmod 0755 "$Q124_REMOTE_FAKE_BIN/aws"
    ;;
  aws)
    if [[ ${1:-} == --version ]]; then
      printf 'aws-cli/%s Python/3.12 Linux/fixture exe/x86_64\n' "${Q124_FAKE_AWS_VERSION:-$Q124_AWS_CLI_VERSION}"
      exit 0
    fi
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
  jq)
    if [[ ${1:-} == --version ]]; then
      printf '%s\n' "${Q124_FAKE_JQ_VERSION:-$Q124_JQ_VERSION}"
    else
      exec "$Q124_REAL_JQ" "$@"
    fi
    ;;
  systemctl)
    if [[ ${1:-} == show ]]; then printf '/system.slice/cats-worker.service\n'; fi
    ;;
  uname) [[ ${1:-} == -m ]] && printf '%s\n' "${Q124_FAKE_ARCH:-x86_64}" ;;
  flock) [[ ${Q124_FAKE_FLOCK_BUSY:-0} != 1 ]] ;;
  timeout)
    while (($#)); do
      [[ $1 == bash ]] && exec "$@"
      shift
    done
    exit 2
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
