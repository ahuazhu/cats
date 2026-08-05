#!/usr/bin/env bash
set -euo pipefail
HERE=$(cd "$(dirname "$0")" && pwd)
REMOTE=$HERE/../q124-remote.sh
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
mkdir -p "$TMP/bin" "$TMP/state/runtime-ledger" "$TMP/state/cats" "$TMP/state/runtimes" "$TMP/cgroup" "$TMP/runtime-bin"
mkdir -p "$TMP/state/cats/cat-fixture/pending"
touch "$TMP/cache-device" "$TMP/worker.env" "$TMP/systemctl.log"
printf 'CATS_METERING_CGROUP_ROOT=%q\n' "$TMP/cgroup" >"$TMP/worker.env"
export Q124_INSTANCE_ID=i-0abc124 Q124_ACCOUNT_ID=111122223333 Q124_REGION=us-east-1
export Q124_CACHE_DEVICE=$TMP/cache-device Q124_FAKE_MOUNT_SOURCE=$TMP/cache-device
export Q124_STATE_DIR=$TMP/state Q124_WORKER_ENV=$TMP/worker.env Q124_BIN_ROOT=$TMP/runtime-bin
export Q124_SYSTEMCTL_LOG=$TMP/systemctl.log Q124_FAKE_CGROUP_ROOT=$TMP/cgroup
export Q124_REAL_FIND
Q124_REAL_FIND=$(command -v find)
export Q124_SOURCE_ROOT=$(cd "$HERE/../../../.." && pwd)

for kind in curl aws findmnt find systemctl true; do
  wrapper=$TMP/bin/$kind
  printf '#!/usr/bin/env bash\nexec %q %q "$@"\n' "$HERE/fake-remote-command.sh" "$kind" >"$wrapper"
  chmod 0755 "$wrapper"
done
export PATH="$TMP/bin:$PATH"
export Q124_FIND_BIN=$TMP/bin/find Q124_FINDMNT_BIN=$TMP/bin/findmnt
export Q124_BLOCK_DEVICE_PROBE_BIN=$TMP/bin/true Q124_ROOT_PROBE_BIN=$TMP/bin/true

expect_stop_fail_closed() {
  : >"$Q124_SYSTEMCTL_LOG"
  if "$REMOTE" stop >/dev/null 2>&1; then
    printf 'remote stop unexpectedly accepted scenario %s\n' "$Q124_REMOTE_SCENARIO" >&2
    exit 1
  fi
  [[ ! -s $Q124_SYSTEMCTL_LOG ]] || { printf 'failed safety probe reached systemctl stop\n' >&2; exit 1; }
}

Q124_REMOTE_SCENARIO=idle "$REMOTE" assert-idle >/dev/null
for Q124_REMOTE_SCENARIO in mount-error ledger-find-error pending-find-error pack-find-error runtime-find-error cgroup-find-error; do
  export Q124_REMOTE_SCENARIO
  expect_stop_fail_closed
done
Q124_REMOTE_SCENARIO=idle
export Q124_BLOCK_DEVICE_PROBE_BIN
Q124_BLOCK_DEVICE_PROBE_BIN=$(command -v false)
expect_stop_fail_closed
Q124_BLOCK_DEVICE_PROBE_BIN=$TMP/bin/true
export Q124_FAKE_MOUNT_SOURCE=$TMP/wrong-device
touch "$Q124_FAKE_MOUNT_SOURCE"
expect_stop_fail_closed

printf 'q124 remote idle contracts: PASS\n'
