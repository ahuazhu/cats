#!/usr/bin/env bash
# Replace the staged archive exactly after its first successful checksum to
# exercise the checksum-to-extraction barrier.
set -euo pipefail

set +e
"${Q124_REAL_SHA256SUM:?real sha256sum required}" "$@"
rc=$?
set -e
if (( rc == 0 )) && [[ ${Q124_SSM_STAGE_ATTACK_KIND:-} == replace-after-check &&
  -n ${Q124_SSM_STAGE:-} && -f $Q124_SSM_STAGE/source.tar.gz &&
  ! -e ${Q124_SSM_STAGE_REPLACED_MARKER:?replacement marker required} ]]; then
  replacement=$Q124_SSM_STAGE/source.tar.gz.replacement
  cp "${Q124_SSM_REPLACEMENT_ARCHIVE:?replacement archive required}" "$replacement"
  chmod 0600 "$replacement"
  mv "$replacement" "$Q124_SSM_STAGE/source.tar.gz"
  : >"$Q124_SSM_STAGE_REPLACED_MARKER"
fi
exit "$rc"
