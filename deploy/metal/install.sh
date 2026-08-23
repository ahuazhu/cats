#!/usr/bin/env bash
# Install the full Cats stack on an AWS bare-metal instance (Ubuntu 22.04/24.04,
# x86_64, /dev/kvm). Run as root from a checkout of this repository:
#
#   sudo deploy/metal/install.sh
#
# Then select the storage adapters in /etc/cats/cats.env and run deploy/metal/e2e.sh.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CH_VERSION=${CH_VERSION:-v53.0}
PREFIX=/opt/cats
GUEST_RUNTIME_RELEASE_SOURCE=${CATS_GUEST_RUNTIME_RELEASE_DIR:-}
CONTROL_BOOT_IMAGE=${CATS_BOOT_IMAGE:-}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm missing: use a *.metal instance" >&2; exit 1; }
[[ -d $GUEST_RUNTIME_RELEASE_SOURCE ]] || {
  echo "CATS_GUEST_RUNTIME_RELEASE_DIR must name the qualified guest-runtime-release.v1 payload" >&2
  exit 1
}
if [[ -f /etc/cats/cats.env ]]; then
  configured_boot_image=$(sed -nE \
    's/^CATS_BOOT_IMAGE=(sha256:[0-9a-f]{64})$/\1/p' /etc/cats/cats.env)
  CONTROL_BOOT_IMAGE=$configured_boot_image
fi
[[ $CONTROL_BOOT_IMAGE =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "CATS_BOOT_IMAGE must name the current qualified Golden Root digest" >&2
  echo "set it for the first install or in /etc/cats/cats.env before an upgrade" >&2
  exit 1
}
"$REPO/deploy/aws/metal/validate-node-identity-installation.sh"
. "$REPO/deploy/aws/metal/worker-deployment-transaction.sh"

echo "==> apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# libssl-dev is required by the PostgreSQL metadata adapter's native-tls stack.
apt-get install -qy build-essential curl git nbd-client busybox-static \
  musl-tools e2fsprogs cpio zstd pkg-config libssl-dev debootstrap iptables \
  util-linux openssl jq
for required in flock stat curl jq openssl findmnt systemd-run systemd-tmpfiles; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "worker deployment needs $required" >&2
    exit 1
  }
done

echo "==> rust toolchain"
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "==> build workspace (release)"
(cd "$REPO" && cargo build --release --workspace)

# This script runs as root with the caller's HOME, so the build leaves root-owned
# files in ~/.cargo, ~/.rustup and the repo's target/. Any later `cargo` as the
# normal user then dies with "Permission denied" on the registry cache -- which
# silently cost a whole set of benchmark phases twice. Hand it all back.
if [[ -n ${SUDO_USER:-} ]]; then
  for dir in "$HOME/.cargo" "$HOME/.rustup" "$REPO/target"; do
    [[ -d $dir ]] && chown -R "$SUDO_USER:$(id -gn "$SUDO_USER")" "$dir"
  done
fi

export CATS_NODE_SERVICE_NAME=cats-noded
release_installer="$REPO/deploy/aws/metal/install-guest-runtime-release.sh"
"$release_installer" verify "$GUEST_RUNTIME_RELEASE_SOURCE"
cgroup_v2_root=$(cats_worker_cgroup_v2_root)
"$REPO/deploy/aws/metal/require-idle-worker.sh" \
  "$cgroup_v2_root" "$PREFIX/bin" /usr/local/bin/cloud-hypervisor
release_transaction_active=0
deployment_cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ $release_transaction_active -eq 1 ]]; then
    systemctl mask --runtime cats-noded >/dev/null 2>&1 || true
    cats_stop_node_service cats-noded >/dev/null 2>&1 || true
    "$release_installer" rollback >/dev/null 2>&1 || true
  fi
  exit "$status"
}
trap deployment_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cats_acquire_worker_deployment_lock
# The unlocked check above is only an early, non-mutating preflight. Recompute
# the cgroup root after serialization and prove physical idle again immediately
# before masking/stopping the service, because another deployment may have
# started runtime children while this process waited for the Host lock.
cgroup_v2_root=$(cats_worker_cgroup_v2_root)
"$REPO/deploy/aws/metal/require-idle-worker.sh" \
  "$cgroup_v2_root" "$PREFIX/bin" /usr/local/bin/cloud-hypervisor
cats_gate_node_service cats-noded
cats_worker_deployment_crash_probe after-mask-worker
# `enable --now` does not restart an already-running service. Stop Control
# before replacing its binary/unit so the process that later becomes Ready is
# necessarily the direct semantic composition from this release.
systemctl stop cats-controld.service >/dev/null 2>&1 || true

install -D -m 0755 "$REPO/deploy/aws/metal/install-guest-runtime-release.sh" \
  "$PREFIX/bin/install-guest-runtime-release"
cats_worker_deployment_crash_probe after-install-release-installer
install -D -m 0755 "$REPO/deploy/aws/metal/worker-deployment-transaction.sh" \
  "$PREFIX/bin/worker-deployment-transaction"
cats_worker_deployment_crash_probe after-install-deployment-transaction
install -m 0644 "$REPO/deploy/metal/systemd/cats-noded.service" \
  /etc/systemd/system/cats-noded.service
cats_worker_deployment_crash_probe after-install-worker-unit
sync -f "$PREFIX/bin/install-guest-runtime-release"
sync -f "$PREFIX/bin/worker-deployment-transaction"
sync -f "$PREFIX/bin"
sync -f /etc/systemd/system/cats-noded.service
sync -f /etc/systemd/system
cats_worker_deployment_crash_probe after-fsync-worker-recovery-gate
systemctl daemon-reload
cats_worker_deployment_crash_probe after-recovery-gate-daemon-reload
release_installer="$PREFIX/bin/install-guest-runtime-release"
release_transaction_active=1
"$release_installer" prepare "$GUEST_RUNTIME_RELEASE_SOURCE"
cats_worker_deployment_crash_probe after-installer-return

echo "==> install binaries to $PREFIX/bin"
install -d "$PREFIX/bin"
cats_worker_deployment_crash_probe after-install-bin-directory
for bin in cats cats-controld cats-noded cats-blockd cats-guest-agent; do
  install -m 0755 "$REPO/target/release/$bin" "$PREFIX/bin/$bin"
  cats_worker_deployment_crash_probe "after-install-$bin"
done
ln -sf "$PREFIX/bin/cats" /usr/local/bin/cats
cats_worker_deployment_crash_probe after-install-cli-link

echo "==> cloud-hypervisor $CH_VERSION"
if [[ ! -x /usr/local/bin/cloud-hypervisor ]]; then
  curl -fsSL -o /usr/local/bin/cloud-hypervisor \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static"
  chmod +x /usr/local/bin/cloud-hypervisor
  cats_worker_deployment_crash_probe after-install-cloud-hypervisor
fi
/usr/local/bin/cloud-hypervisor --version

echo "==> kernel NBD module (nbds_max=64)"
modprobe nbd nbds_max=64 || true
echo nbd > /etc/modules-load.d/cats.conf
echo "options nbd nbds_max=64" > /etc/modprobe.d/cats-nbd.conf
cats_worker_deployment_crash_probe after-install-nbd-configuration

echo "==> guest outbound network"
install -m 0755 "$REPO/deploy/metal/setup-guest-network.sh" \
  "$PREFIX/bin/setup-guest-network"
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.default.rp_filter=1\n' \
  > /etc/sysctl.d/90-cats-guest-network.conf
cats_worker_deployment_crash_probe after-install-network-configuration
CATS_GUEST_NETWORK_CIDR=${CATS_GUEST_NETWORK_CIDR:-10.240.0.0/16} \
  "$PREFIX/bin/setup-guest-network"
cats_worker_deployment_crash_probe after-setup-guest-network

echo "==> shared Guest runtime release"
# --------------------------------------------------------------------------
# Local NVMe for the ChunkStore cache and the file object store.
#
# On i4i and friends the instance store is the whole point of the machine, and
# leaving /var/lib/cats on the EBS root silently turns every storage measurement
# into an EBS measurement -- which is exactly what happened on 2026-07-27, where
# 4 KiB random write read 40x lower than the run that had mounted it. Mount it
# here so the documented environment is what you get, rather than something an
# operator has to remember.
#
# CATS_DATA_DEVICE=none skips this; CATS_DATA_DEVICE=/dev/nvmeXn1 picks one.
# --------------------------------------------------------------------------
DATA_DEVICE=${CATS_DATA_DEVICE:-auto}
if [[ $DATA_DEVICE == auto ]]; then
  # AWS labels instance storage in the device model, which is the only signal
  # here that cannot be confused with something else. In particular the `nbd`
  # module this script loads a few lines up creates /dev/nbd0..63, and lsblk
  # reports those as TYPE=disk with no mountpoint -- picking one of those is how
  # the first version of this got it wrong.
  # -P emits key="value" pairs. Column output cannot be used: awk collapses an
  # empty MOUNTPOINT, so $4 becomes the first word of MODEL and `$4 == ""` never
  # matches. This branch therefore never selected anything, and every host so
  # far was picked by the size fallback below -- which will happily choose a
  # data EBS volume on a machine that has one.
  root_src=$(findmnt -no SOURCE / | sed 's/p\?[0-9]*$//')
  DATA_DEVICE=$(lsblk -dnp -P -o NAME,TYPE,SIZE,MOUNTPOINT,MODEL |
    while read -r entry; do
      NAME= TYPE= SIZE= MOUNTPOINT= MODEL=
      eval "$entry"
      [[ $TYPE == disk && $NAME != "$root_src" && -z $MOUNTPOINT ]] || continue
      [[ $NAME =~ ^/dev/(nbd|loop|ram|zram|md|dm-) ]] && continue
      [[ $MODEL == *"Instance Storage"* ]] && { echo "$NAME"; break; }
    done | head -1)
  if [[ -z ${DATA_DEVICE:-} ]]; then
    # No vendor label: fall back to the largest unmounted real disk, still
    # excluding the virtual device classes.
    DATA_DEVICE=$(lsblk -dnpb -P -o NAME,TYPE,SIZE,MOUNTPOINT |
      while read -r entry; do
        NAME= TYPE= SIZE= MOUNTPOINT=
        eval "$entry"
        [[ $TYPE == disk && $NAME != "$root_src" && -z $MOUNTPOINT && $SIZE -gt 0 ]] || continue
        [[ $NAME =~ ^/dev/(nbd|loop|ram|zram|md|dm-) ]] && continue
        echo "$SIZE $NAME"
      done | sort -rn | head -1 | awk '{print $2}')
  fi
  DATA_DEVICE=${DATA_DEVICE:-none}
fi
if [[ $DATA_DEVICE != none ]]; then
  if mountpoint -q /var/lib/cats; then
    echo "==> /var/lib/cats is already a mount point; leaving it alone"
  else
    echo "==> local data device $DATA_DEVICE -> /var/lib/cats"
    [[ -b $DATA_DEVICE ]] || { echo "$DATA_DEVICE is not a block device" >&2; exit 1; }
    blkid "$DATA_DEVICE" >/dev/null 2>&1 || mkfs.ext4 -q -F "$DATA_DEVICE"
    install -d /var/lib/cats
    mount "$DATA_DEVICE" /var/lib/cats
    cats_worker_deployment_crash_probe after-mount-state-filesystem
    # Instance storage does not survive a stop/start, so this is deliberately not
    # written to /etc/fstab: a reboot should come up with an empty cache, not fail
    # to boot on a device that no longer has a filesystem.
  fi
else
  echo "==> no local data device found; /var/lib/cats stays on the root filesystem"
  echo "    (fine for functional testing, NOT comparable for storage benchmarks)"
fi

echo "==> state dirs + config"
install -d /var/lib/cats/{node,blob} /etc/cats
cats_worker_deployment_crash_probe after-install-state-directories
install -D -o root -g root -m 0644 "$REPO/deploy/metal/tmpfiles/cats-vmm.conf" \
  /usr/lib/tmpfiles.d/cats-vmm.conf
install -o root -g root -m 0755 \
  "$REPO/deploy/aws/metal/provision-vmm-socket-namespaces.sh" \
  "$PREFIX/bin/provision-vmm-socket-namespaces"
"$PREFIX/bin/provision-vmm-socket-namespaces"
cats_worker_deployment_crash_probe after-provision-vmm-socket-namespaces
if [[ ! -f /etc/cats/cats.env ]]; then
  install -m 0600 "$REPO/deploy/metal/cats.env.example" /etc/cats/cats.env
  printf '\nCATS_BOOT_IMAGE=%s\n' "$CONTROL_BOOT_IMAGE" >> /etc/cats/cats.env
  cats_worker_deployment_crash_probe after-install-cats-environment
  echo "    wrote /etc/cats/cats.env (edit for S3; defaults to local file blobstore)"
fi

echo "==> systemd units"
# A host upgraded from the V1 development shape may still have the old
# Gateway enabled. Stop it before daemon-reload and remove its exact unit and
# binary; leaving either behind would let a reboot revive legacy route
# resolve/wake and Node proxy traffic.
cats_retire_legacy_gateway \
  /etc/systemd/system/cats-gatewayd.service \
  /etc/systemd/system/multi-user.target.wants/cats-gatewayd.service \
  "$PREFIX/bin/cats-gatewayd"
cats_worker_deployment_crash_probe after-remove-legacy-gateway
for unit in "$REPO"/deploy/metal/systemd/*.service; do
  [[ ${unit##*/} == cats-noded.service ]] && continue
  install -m 0644 "$unit" /etc/systemd/system/
done
cats_worker_deployment_crash_probe after-install-systemd-units
systemctl daemon-reload
cats_worker_deployment_crash_probe after-daemon-reload
systemctl enable --now cats-controld
cats_worker_deployment_crash_probe after-start-control-services
cats_begin_candidate_lifetime cats-noded "$release_installer"
cats_worker_deployment_crash_probe after-authorize-worker-start
cats_ungate_node_service cats-noded
cats_worker_deployment_crash_probe after-unmask-worker
systemctl enable --now cats-noded
cats_worker_deployment_crash_probe after-start-worker
cats_bind_candidate_main cats-noded "$release_installer"
cats_worker_deployment_crash_probe after-bind-worker-main
cats_wait_for_registered_node cats-noded
cats_worker_deployment_crash_probe after-registration-readiness
cats_commit_candidate "$release_installer"
release_transaction_active=0
cats_worker_deployment_crash_probe after-release-commit

sleep 1
systemctl --no-pager --lines 0 status cats-controld cats-noded | grep -E "●|Active"
echo
echo "install complete. Try:"
echo "  cats create dev --root-size 1GiB && cats exec dev -- uname -a"
echo "  deploy/metal/e2e.sh   # full acceptance run"
