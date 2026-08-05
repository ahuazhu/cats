#!/usr/bin/env bash
set -euo pipefail
kind=${1:?fake command kind required}
shift
case $kind in
  curl)
    url=${*: -1}
    case $url in
      */api/token) printf 'token\n' ;;
      */dynamic/instance-identity/document)
        printf '{"instanceId":"%s","accountId":"%s","region":"%s"}\n' "$Q124_INSTANCE_ID" "$Q124_ACCOUNT_ID" "$Q124_REGION"
        ;;
      *) exit 2 ;;
    esac
    ;;
  aws)
    [[ ${1:-} == --region && ${2:-} == "$Q124_REGION" ]] || exit 3
    shift 2
    case "${1:-} ${2:-}" in
      'sts get-caller-identity') printf '%s\n' "$Q124_ACCOUNT_ID" ;;
      *) exit 4 ;;
    esac
    ;;
  findmnt)
    [[ ${Q124_REMOTE_SCENARIO:-idle} != mount-error ]] || exit 5
    printf '%s\n' "${Q124_FAKE_MOUNT_SOURCE:?fake mount source required}"
    ;;
  find)
    first=${1:-}
    scenario=${Q124_REMOTE_SCENARIO:-idle}
    [[ ! ($scenario == ledger-find-error && $first == "$Q124_STATE_DIR/runtime-ledger") ]] || exit 6
    [[ ! ($scenario == pending-find-error && $first == "$Q124_STATE_DIR/cats") ]] || exit 7
    [[ ! ($scenario == cgroup-find-error && $first == "$Q124_FAKE_CGROUP_ROOT") ]] || exit 8
    [[ ! ($scenario == runtime-find-error && $first == "$Q124_STATE_DIR/runtimes") ]] || exit 10
    [[ ! ($scenario == pack-find-error && $first == */pending) ]] || exit 11
    exec "$Q124_REAL_FIND" "$@"
    ;;
  systemctl)
    printf 'systemctl %s\n' "$*" >>"$Q124_SYSTEMCTL_LOG"
    ;;
  true) exit 0 ;;
  *) exit 9 ;;
esac
