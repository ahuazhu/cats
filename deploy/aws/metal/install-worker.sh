#!/usr/bin/env bash
# Install only the Cats worker data plane on Linux x86_64 bare metal.
# The web UI, control plane and gateway stay in EKS.
set -euo pipefail

CATS_REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
CATS_PREFIX=/opt/cats
CATS_CH_VERSION=${CATS_CH_VERSION:-v53.0}
GUEST_RUNTIME_RELEASE_SOURCE=${CATS_GUEST_RUNTIME_RELEASE_DIR:-}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo "x86_64 is required" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm missing: use a bare-metal instance" >&2; exit 1; }
[[ -d $GUEST_RUNTIME_RELEASE_SOURCE ]] || {
  echo "CATS_GUEST_RUNTIME_RELEASE_DIR must name the qualified guest-runtime-release.v1 payload" >&2
  exit 1
}

# Validate every required operator input before apt, build, installed-file or
# systemd mutation. Staging closes the validate/use race if the supplied path
# is replaced while this long-running bootstrap builds the Guest image.
ROUTE_V2_NODE_ARTIFACT_SOURCE=${CATS_ROUTE_V2_NODE_ARTIFACT_DIR:-}
[[ -n $ROUTE_V2_NODE_ARTIFACT_SOURCE ]] || {
  echo "CATS_ROUTE_V2_NODE_ARTIFACT_DIR is required" >&2
  exit 1
}
[[ $ROUTE_V2_NODE_ARTIFACT_SOURCE == /* && -d $ROUTE_V2_NODE_ARTIFACT_SOURCE && ! -L $ROUTE_V2_NODE_ARTIFACT_SOURCE ]] || {
  echo "CATS_ROUTE_V2_NODE_ARTIFACT_DIR must be an absolute real directory" >&2
  exit 1
}
for required in cmp find install stat wc; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "worker deployment needs $required before Route v2 artifact validation" >&2
    exit 1
  }
done
# Keep transient private material on the boot-scoped tmpfs. The final fixed
# private key is durable root-only state; staging copies must not survive a
# Host reboot if the installer is killed before its EXIT trap runs.
ROUTE_V2_NODE_ARTIFACT_STAGE=$(mktemp -d /run/cats-route-v2-stage.XXXXXX)
chmod 0700 "$ROUTE_V2_NODE_ARTIFACT_STAGE"
cleanup_route_v2_artifacts() {
  rm -rf -- "$ROUTE_V2_NODE_ARTIFACT_STAGE"
}
trap cleanup_route_v2_artifacts EXIT
route_v2_expected=(
  public-key-ring.v1.json
  rotation-operator-trust.v1.json
  gateway-client-ca-bundle.pem
  node-machine-server-certificate.pem
  node-machine-server-private-key.pem
)
[[ $(find "$ROUTE_V2_NODE_ARTIFACT_SOURCE" -mindepth 1 -maxdepth 1 | wc -l) -eq 5 ]] || {
  echo "Node Route v2 artifact source contains an unexpected entry" >&2
  exit 1
}
[[ $(find "$ROUTE_V2_NODE_ARTIFACT_SOURCE" -mindepth 1 -maxdepth 1 -type f -links 1 | wc -l) -eq 5 ]] || {
  echo "Node Route v2 artifact source must contain exactly five single-link regular files" >&2
  exit 1
}
for name in "${route_v2_expected[@]}"; do
  [[ -f $ROUTE_V2_NODE_ARTIFACT_SOURCE/$name && ! -L $ROUTE_V2_NODE_ARTIFACT_SOURCE/$name ]] || {
    echo "missing Node Route v2 artifact: $name" >&2
    exit 1
  }
  mode=0644
  [[ $name != node-machine-server-private-key.pem ]] || mode=0600
  install -o root -g root -m "$mode" \
    "$ROUTE_V2_NODE_ARTIFACT_SOURCE/$name" "$ROUTE_V2_NODE_ARTIFACT_STAGE/$name"
  [[ -s $ROUTE_V2_NODE_ARTIFACT_STAGE/$name ]] || {
    echo "empty Node Route v2 artifact: $name" >&2
    exit 1
  }
done
"$CATS_REPO/deploy/aws/metal/validate-node-identity-installation.sh"
. "$CATS_REPO/deploy/aws/metal/worker-deployment-transaction.sh"
. "$CATS_REPO/deploy/aws/metal/install-route-v2-node-r1.sh"
for required in flock stat curl openssl cmp wc findmnt systemd-run systemd-tmpfiles; do
  command -v "$required" >/dev/null 2>&1 || {
    echo "worker deployment needs $required" >&2
    exit 1
  }
done

# SSM RunShellScript and cloud-init use non-login root shells where HOME may
# be absent. rustup and cargo still need a stable home before the guest-image
# builder runs, so make the root-only install contract explicit.
export HOME="${HOME:-/root}"

export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -qy build-essential curl jq nbd-client busybox-static musl-tools \
  e2fsprogs cpio zstd pkg-config libssl-dev ca-certificates debootstrap iptables

export PATH="/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  export PATH="/root/.cargo/bin:$PATH"
fi

(cd "$CATS_REPO" && cargo build --locked --release \
  -p cats-cli -p cats-node-agent-daemon -p cats-blockd-daemon -p cats-guest-agent)
"$CATS_REPO/target/release/cats-route-v2-node-r1-validator" \
  --directory "$ROUTE_V2_NODE_ARTIFACT_STAGE"

release_installer="$CATS_REPO/deploy/aws/metal/install-guest-runtime-release.sh"
"$release_installer" verify "$GUEST_RUNTIME_RELEASE_SOURCE"
release_transaction_active=0
deployment_cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ $release_transaction_active -eq 1 ]]; then
    systemctl mask --runtime cats-worker >/dev/null 2>&1 || true
    cats_stop_node_service cats-worker >/dev/null 2>&1 || true
    "$release_installer" rollback >/dev/null 2>&1 || true
  fi
  cleanup_route_v2_artifacts
  exit "$status"
}
trap deployment_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cats_acquire_worker_deployment_lock
# Classify only while holding the Host-global lock, immediately before any
# systemctl or installed-file mutation. A second installer that won the lock
# while this bootstrap built can therefore yield only exact replay or a
# fail-closed conflict.
ROUTE_V2_INSTALL_STATE=$(cats_classify_route_v2_node_r1 \
  "$CATS_REPO/target/release/cats-route-v2-node-r1-validator" \
  "$ROUTE_V2_NODE_ARTIFACT_STAGE" /etc/cats/route-v2)
[[ $ROUTE_V2_INSTALL_STATE == absent || $ROUTE_V2_INSTALL_STATE == exact ]]
# Only after the artifact state is classified under the Host lock may systemd
# be queried. Prove physical idle immediately before masking/stopping so a
# worker deployment cannot race a runtime child.
metering_root=$(cats_worker_metering_root cats-worker)
"$CATS_REPO/deploy/aws/metal/require-idle-worker.sh" \
  "$metering_root" "$CATS_PREFIX/bin"
cats_gate_node_service cats-worker
cats_worker_deployment_crash_probe after-mask-worker

if [[ $ROUTE_V2_INSTALL_STATE == absent ]]; then
  cats_publish_route_v2_node_r1 \
    "$CATS_REPO/target/release/cats-route-v2-node-r1-validator" \
    "$ROUTE_V2_NODE_ARTIFACT_STAGE" /etc/cats/route-v2
  cats_worker_deployment_crash_probe after-install-route-v2-artifacts
fi

# Establish the reboot recovery gate before the release journal or any state
# filesystem mutation. The runtime mask covers this boot; fsynced installed
# bytes plus daemon-reload cover direct start after reboot.
install -D -m 0755 "$CATS_REPO/deploy/aws/metal/install-guest-runtime-release.sh" \
  "$CATS_PREFIX/bin/install-guest-runtime-release"
cats_worker_deployment_crash_probe after-install-release-installer
install -D -m 0755 "$CATS_REPO/deploy/aws/metal/worker-deployment-transaction.sh" \
  "$CATS_PREFIX/bin/worker-deployment-transaction"
cats_worker_deployment_crash_probe after-install-deployment-transaction
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-worker.service" \
  /etc/systemd/system/cats-worker.service
cats_worker_deployment_crash_probe after-install-worker-unit
sync -f "$CATS_PREFIX/bin/install-guest-runtime-release"
sync -f "$CATS_PREFIX/bin/worker-deployment-transaction"
sync -f "$CATS_PREFIX/bin"
sync -f /etc/systemd/system/cats-worker.service
sync -f /etc/systemd/system
cats_worker_deployment_crash_probe after-fsync-worker-recovery-gate
systemctl daemon-reload
cats_worker_deployment_crash_probe after-recovery-gate-daemon-reload
release_installer="$CATS_PREFIX/bin/install-guest-runtime-release"

# Local NVMe discovery and mkfs/mount both happen inside the same Host
# deployment transaction as every other installed-state mutation. In
# particular, never hide a live Agent's selected state tree with a new mount
# before taking the deployment lock and stopping it.
DATA_DEVICE=${CATS_DATA_DEVICE:-auto}
if [[ $DATA_DEVICE == auto ]]; then
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
    DATA_DEVICE=$(lsblk -dnpb -P -o NAME,TYPE,SIZE,MOUNTPOINT |
      while read -r entry; do
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
    # Deliberately not in /etc/fstab: instance storage does not survive a
    # stop/start, and a reboot should come up with an empty cache rather than
    # fail to boot on a device that no longer has a filesystem.
  fi
else
  echo "==> no local data device found; /var/lib/cats stays on the root filesystem"
  echo "    (fine for functional testing, NOT comparable for storage benchmarks)"
fi

release_transaction_active=1
"$release_installer" prepare "$GUEST_RUNTIME_RELEASE_SOURCE"
cats_worker_deployment_crash_probe after-installer-return

install -d "$CATS_PREFIX/bin" "$CATS_PREFIX/guest" /var/lib/cats/node /etc/cats
cats_worker_deployment_crash_probe after-install-runtime-directories
install -D -o root -g root -m 0644 "$CATS_REPO/deploy/metal/tmpfiles/cats-vmm.conf" \
  /usr/lib/tmpfiles.d/cats-vmm.conf
install -o root -g root -m 0755 \
  "$CATS_REPO/deploy/aws/metal/provision-vmm-socket-namespaces.sh" \
  "$CATS_PREFIX/bin/provision-vmm-socket-namespaces"
"$CATS_PREFIX/bin/provision-vmm-socket-namespaces"
cats_worker_deployment_crash_probe after-provision-vmm-socket-namespaces
install -m 0755 "$CATS_REPO/target/release/cats" "$CATS_PREFIX/bin/cats"
cats_worker_deployment_crash_probe after-install-cats-cli
install -m 0755 "$CATS_REPO/target/release/cats-noded" "$CATS_PREFIX/bin/cats-noded"
cats_worker_deployment_crash_probe after-install-cats-noded
install -m 0755 "$CATS_REPO/target/release/cats-route-v2-node-r1-validator" "$CATS_PREFIX/bin/cats-route-v2-node-r1-validator"
cats_worker_deployment_crash_probe after-install-cats-route-v2-node-r1-validator
install -m 0755 "$CATS_REPO/target/release/cats-vmm-launcher" "$CATS_PREFIX/bin/cats-vmm-launcher"
cats_worker_deployment_crash_probe after-install-cats-vmm-launcher
install -m 0755 "$CATS_REPO/target/release/cats-runtime-e3-probe" "$CATS_PREFIX/bin/cats-runtime-e3-probe"
cats_worker_deployment_crash_probe after-install-cats-runtime-e3-probe
install -m 0755 "$CATS_REPO/target/release/cats-blockd" "$CATS_PREFIX/bin/cats-blockd"
cats_worker_deployment_crash_probe after-install-cats-blockd
install -m 0755 "$CATS_REPO/target/release/cats-guest-agent" "$CATS_PREFIX/bin/cats-guest-agent"
cats_worker_deployment_crash_probe after-install-cats-guest-agent
install -m 0755 "$CATS_REPO/target/release/cats-e3-guest-workload" "$CATS_PREFIX/bin/cats-e3-guest-workload"
cats_worker_deployment_crash_probe after-install-cats-e3-guest-workload
if [[ ! -x "$CATS_PREFIX/bin/cloud-hypervisor" ]]; then
  curl -fsSL -o "$CATS_PREFIX/bin/cloud-hypervisor" \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CATS_CH_VERSION/cloud-hypervisor-static"
  chmod 0755 "$CATS_PREFIX/bin/cloud-hypervisor"
  cats_worker_deployment_crash_probe after-install-cloud-hypervisor
fi

modprobe nbd nbds_max=64
echo nbd > /etc/modules-load.d/cats.conf
echo "options nbd nbds_max=64" > /etc/modprobe.d/cats-nbd.conf
cats_worker_deployment_crash_probe after-install-nbd-configuration

install -m 0755 "$CATS_REPO/deploy/metal/setup-guest-network.sh" \
  "$CATS_PREFIX/bin/setup-guest-network"
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.default.rp_filter=1\n' \
  > /etc/sysctl.d/90-cats-guest-network.conf
cats_worker_deployment_crash_probe after-install-network-configuration
CATS_GUEST_NETWORK_CIDR=${CATS_GUEST_NETWORK_CIDR:-10.240.0.0/16} \
  "$CATS_PREFIX/bin/setup-guest-network"
cats_worker_deployment_crash_probe after-setup-guest-network

curl -fsSL https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem \
  -o /etc/cats/rds-ca.pem
chmod 0644 /etc/cats/rds-ca.pem
cats_worker_deployment_crash_probe after-install-rds-ca

install -m 0755 "$CATS_REPO/deploy/aws/metal/render-postgres-url.sh" \
  "$CATS_PREFIX/bin/render-postgres-url"
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-postgres-url.service" \
  /etc/systemd/system/cats-postgres-url.service
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-postgres-url.timer" \
  /etc/systemd/system/cats-postgres-url.timer
cats_worker_deployment_crash_probe after-install-systemd-units
systemctl daemon-reload
cats_worker_deployment_crash_probe after-daemon-reload

# The timer is started, not merely enabled: an enabled-but-unstarted timer
# leaves the mid-run rotation window unbounded until the next boot fires
# OnBootSec. It can only start once worker.env exists, since the unit reads it.
if [[ -f /etc/cats/worker.env ]]; then
  # Signed Agent registration replaced the Host-wide shared Control bearer.
  # Remove a value retained by an older install before the candidate can run.
  worker_env_temp=$(mktemp /etc/cats/.worker.env.XXXXXX)
  awk -F= '$1 != "CATS_AUTH_TOKEN" && $1 != "CATS_ROUTE_V2_MACHINE_LISTEN"' \
    /etc/cats/worker.env > "$worker_env_temp"
  chown root:root "$worker_env_temp"
  chmod 0600 "$worker_env_temp"
  mv -f -- "$worker_env_temp" /etc/cats/worker.env
  sync -f /etc/cats/worker.env
  sync -f /etc/cats
  cats_worker_deployment_crash_probe after-remove-worker-shared-bearer
  systemctl enable --now cats-postgres-url.timer
  cats_worker_deployment_crash_probe after-enable-postgres-timer
  cats_begin_candidate_lifetime cats-worker "$release_installer"
  cats_worker_deployment_crash_probe after-authorize-worker-start
  cats_ungate_node_service cats-worker
  cats_worker_deployment_crash_probe after-unmask-worker
  systemctl enable --now cats-worker
  cats_worker_deployment_crash_probe after-start-worker
  cats_bind_candidate_main cats-worker "$release_installer"
  cats_worker_deployment_crash_probe after-bind-worker-main
  cats_wait_for_registered_node cats-worker
  cats_worker_deployment_crash_probe after-registration-readiness
  cats_commit_candidate "$release_installer"
  release_transaction_active=0
  cats_worker_deployment_crash_probe after-release-commit
else
  install -m 0600 "$CATS_REPO/deploy/aws/metal/worker.env.example" /etc/cats/worker.env
  cats_worker_deployment_crash_probe after-install-worker-environment
  systemctl enable cats-postgres-url.timer
  cats_stop_node_service cats-worker
  "$release_installer" recover
  release_transaction_active=0
  echo "created /etc/cats/worker.env; fill its values, then rerun this installer" >&2
fi
