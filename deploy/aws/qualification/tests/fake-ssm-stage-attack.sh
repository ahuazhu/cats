#!/usr/bin/env bash
# Inject fixture-only objects after the exclusive stage is created but before
# production contract creation. The captured SSM command retains a no-op.
set -euo pipefail

stage=${1:?stage required}
[[ -d $stage && ! -L $stage ]]
printf '%s\n' "$stage" >"${Q124_SSM_STAGE_RECORD:?stage record required}"
case ${Q124_SSM_STAGE_ATTACK_KIND:-} in
  ''|replace-after-check) ;;
  archive)
    printf 'attacker-owned archive\n' >"$stage/source.tar.gz"
    chmod 0600 "$stage/source.tar.gz"
    ;;
  bootstrap|provenance|guard|payload)
    ln -s "${Q124_SSM_STAGE_OUTSIDE_FILE:?outside file required}" \
      "$stage/${Q124_SSM_STAGE_ATTACK_KIND}.sh"
    ;;
  *) exit 2 ;;
esac
