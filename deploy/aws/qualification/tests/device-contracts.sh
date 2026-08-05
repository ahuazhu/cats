#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
PROOF=$HERE/../q124-device-proof.sh
TMP=$(mktemp -d)
trap 'find "$TMP" -type f -delete; rmdir "$TMP/holders" "$TMP"' EXIT
mkdir "$TMP/holders"
export Q124_INSTANCE_ID=i-0abc124 Q124_CACHE_DEVICE=/dev/nvme1n1
export Q124_FORMAT_CONFIRMATION=FORMAT_EPHEMERAL_CACHE_i-0abc124_/dev/nvme1n1
export Q124_HOLDERS_DIR=$TMP/holders
# The production script accepts executable paths, not shell fragments. Wrapper
# commands keep that property while choosing the fake operation by basename.
for kind in lsblk findmnt wipefs blkid find; do
  wrapper=$TMP/$kind
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-device-command.sh" "$kind" >"$wrapper"
  chmod 0755 "$wrapper"
  export "Q124_${kind^^}_BIN=$wrapper"
done

expect_fail() { if "$PROOF" >/dev/null 2>&1; then echo "expected device proof failure" >&2; exit 1; fi; }
Q124_DEVICE_SCENARIO=clean "$PROOF" >/dev/null
Q124_DEVICE_SCENARIO=partition expect_fail
Q124_DEVICE_SCENARIO=child-list-partial-error expect_fail
Q124_DEVICE_SCENARIO=signature expect_fail
Q124_DEVICE_SCENARIO=mounted expect_fail
Q124_DEVICE_SCENARIO=mount-query-error expect_fail
Q124_DEVICE_SCENARIO=wrong-type expect_fail
Q124_DEVICE_SCENARIO=root expect_fail
Q124_DEVICE_SCENARIO=wipefs-error expect_fail
Q124_DEVICE_SCENARIO=blkid-error expect_fail
Q124_DEVICE_SCENARIO=blkid-io-error expect_fail
Q124_DEVICE_SCENARIO=holders-find-error expect_fail
touch "$TMP/holders/dm-0"
Q124_DEVICE_SCENARIO=clean expect_fail
printf 'q124 device contracts: PASS\n'
