#!/usr/bin/env bash
set -euo pipefail
case ${1:-} in
  recover) printf '%s\n' "${Q124_LAUNCH_RECOVERY_JSON:?}" ;;
  publish) ;;
  *) exit 2 ;;
esac
