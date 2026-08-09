#!/usr/bin/env bash
# Atomically refresh release-owned files inside the Cloud Hypervisor golden
# RootDisk. Existing Cats keep their own RootDisks; the worker restart after
# this script clears the node's cached golden-root reference for new Cats.
set -euo pipefail

usage() {
  echo "usage: $0 ROOTFS_EXT4 GUEST_AGENT GUEST_SYSTEMD_DIR" >&2
}

[[ $# -eq 3 ]] || {
  usage
  exit 2
}

seed_image=$1
guest_agent=$2
guest_systemd_dir=$3

[[ -f $seed_image ]] || {
  echo "guest seed image does not exist: $seed_image" >&2
  exit 1
}
[[ -x $guest_agent ]] || {
  echo "guest agent is not executable: $guest_agent" >&2
  exit 1
}

units=(
  cats-mount-propagation.service
  cats-grow-root.service
  cats-network.service
  cats-guest-agent.service
)
for unit in "${units[@]}"; do
  [[ -f "$guest_systemd_dir/$unit" ]] || {
    echo "guest systemd unit does not exist: $guest_systemd_dir/$unit" >&2
    exit 1
  }
done

for required in cp debugfs e2fsck flock mv stat sync systemctl; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "guest seed update needs $required on the worker" >&2
    exit 1
  }
done

# This script is installed for the Terraform worker transaction, but it is not
# an independent mutation authority. A manual or overlapping invocation must
# prove both the inherited Host deployment lock and a stopped worker before it
# creates staging bytes beside the live seed.
transaction_helper=/opt/cats/bin/worker-deployment-transaction.sh
[[ -f $transaction_helper && ! -L $transaction_helper ]] || {
  echo "installed worker deployment transaction helper is missing" >&2
  exit 1
}
# shellcheck source=/dev/null
. "$transaction_helper"
cats_require_worker_deployment_lock
cats_require_node_service_stopped cats-worker

seed_dir=$(dirname "$seed_image")
stage_dir=$(mktemp -d "$seed_dir/.guest-seed-update.XXXXXX")
staged_seed="$stage_dir/rootfs.ext4"
staged_backup="$stage_dir/rootfs.ext4.previous"

cleanup() {
  rm -rf -- "$stage_dir"
}
trap cleanup EXIT

# Work on a private same-filesystem copy so a failed debugfs/e2fsck operation
# cannot corrupt the live golden RootDisk. Reflink is opportunistic.
cp --reflink=auto --sparse=always --preserve=mode,ownership,timestamps \
  "$seed_image" "$staged_seed"

replace_file() {
  local source=$1
  local destination=$2
  local mode=$3

  debugfs -w -R "rm $destination" "$staged_seed" >/dev/null 2>&1 || true
  debugfs -w -R "write $source $destination" "$staged_seed" >/dev/null
  debugfs -w -R "set_inode_field $destination mode $mode" "$staged_seed" >/dev/null
}

replace_file "$guest_agent" /usr/bin/cats-guest-agent 0100755
for unit in "${units[@]}"; do
  replace_file \
    "$guest_systemd_dir/$unit" \
    "/etc/systemd/system/$unit" \
    0100644
done

# Older seeds were built from a shell that could inherit umask 077. APT drops
# resolver work to `_apt`, so a 0600 resolv.conf makes package installation look
# like a transient DNS outage even though the Guest network is healthy. Repair
# the installed seed on every worker release as well as fixing future builds.
debugfs -w \
  -R "set_inode_field /etc/resolv.conf mode 0100644" \
  "$staged_seed" >/dev/null

mount_unit=/etc/systemd/system/sysinit.target.wants/cats-mount-propagation.service
debugfs -w -R "rm $mount_unit" "$staged_seed" >/dev/null 2>&1 || true
debugfs -w \
  -R "symlink $mount_unit ../cats-mount-propagation.service" \
  "$staged_seed" >/dev/null

# `-n` is deliberately read-only. Any inconsistency aborts before the atomic
# replacement and leaves both the live seed and running worker untouched.
e2fsck -fn "$staged_seed" >/dev/null

# Keep one recoverable previous seed. Both copies are prepared beside the
# destination, then renamed atomically on the same filesystem.
cp --reflink=auto --sparse=always --preserve=mode,ownership,timestamps \
  "$seed_image" "$staged_backup"
sync "$staged_seed" "$staged_backup"
mv -f "$staged_backup" "$seed_image.previous"
mv -f "$staged_seed" "$seed_image"
sync -f "$seed_dir"
