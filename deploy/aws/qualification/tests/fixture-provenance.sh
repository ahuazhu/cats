#!/usr/bin/env bash
# Adapt the production-only SSM invocation to an explicit local fixture trust
# model. This file is itself the manifest-bound provenance program in the SSM
# contract, so production never receives a fixture switch.
set -euo pipefail

real=${Q124_PROVENANCE_FIXTURE_REAL:?real provenance contract required}
uid=${Q124_PROVENANCE_FIXTURE_UID:?fixture trusted uid required}
case ${1:-} in
  --prepare-production-root)
    [[ ${2:-} == "${Q124_REMOTE_SOURCE_ROOT:?fixture source root required}" ]] || exit 2
    [[ -d ${2%/*} && ! -L ${2%/*} ]] || exit 2
    ;;
  --production)
    shift
    exec "$real" --fixture "$uid" "$@"
    ;;
  *) exit 2 ;;
esac
