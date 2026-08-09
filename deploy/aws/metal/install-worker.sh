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
ROUTE_GRANT_PUBLIC_KEY_SOURCE=${CATS_ROUTE_GRANT_PUBLIC_KEY_FILE:-}
[[ -n $ROUTE_GRANT_PUBLIC_KEY_SOURCE ]] || {
  echo "CATS_ROUTE_GRANT_PUBLIC_KEY_FILE is required" >&2
  exit 1
}
[[ -f $ROUTE_GRANT_PUBLIC_KEY_SOURCE ]] || {
  echo "Route Grant public key is not a regular file: $ROUTE_GRANT_PUBLIC_KEY_SOURCE" >&2
  exit 1
}
ROUTE_GRANT_PUBLIC_KEY_STAGE=$(mktemp)
cleanup_route_grant_key() {
  rm -f -- "$ROUTE_GRANT_PUBLIC_KEY_STAGE"
}
trap cleanup_route_grant_key EXIT
install -m 0600 "$ROUTE_GRANT_PUBLIC_KEY_SOURCE" "$ROUTE_GRANT_PUBLIC_KEY_STAGE"
"$CATS_REPO/deploy/aws/metal/validate-route-grant-public-key.sh" \
  "$ROUTE_GRANT_PUBLIC_KEY_STAGE"

"$CATS_REPO/deploy/aws/metal/validate-node-identity-installation.sh"
. "$CATS_REPO/deploy/aws/metal/worker-deployment-transaction.sh"
for required in flock stat curl; do
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
apt-get install -qy build-essential curl nbd-client busybox-static musl-tools \
  e2fsprogs cpio zstd pkg-config libssl-dev ca-certificates debootstrap iptables

export PATH="/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  export PATH="/root/.cargo/bin:$PATH"
fi

(cd "$CATS_REPO" && cargo build --locked --release \
  -p cats-node-agent-daemon -p cats-blockd-daemon -p cats-guest-agent)

release_installer="$CATS_REPO/deploy/aws/metal/install-guest-runtime-release.sh"
"$release_installer" verify "$GUEST_RUNTIME_RELEASE_SOURCE"
cats_acquire_worker_deployment_lock
release_transaction_active=1
deployment_cleanup() {
  status=$?
  trap - EXIT INT TERM
  if [[ $release_transaction_active -eq 1 ]]; then
    cats_stop_node_service cats-worker >/dev/null 2>&1 || true
    "$release_installer" rollback >/dev/null 2>&1 || true
  fi
  cleanup_route_grant_key
  exit "$status"
}
trap deployment_cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
cats_stop_node_service cats-worker

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

"$release_installer" prepare "$GUEST_RUNTIME_RELEASE_SOURCE"
cats_worker_deployment_crash_probe after-installer-return

install -d "$CATS_PREFIX/bin" "$CATS_PREFIX/guest" /var/lib/cats/node /etc/cats
cats_worker_deployment_crash_probe after-install-runtime-directories
install -o root -g root -m 0644 "$ROUTE_GRANT_PUBLIC_KEY_STAGE" \
  /etc/cats/route-grant-public.pem
cats_worker_deployment_crash_probe after-install-route-key
install -m 0755 "$CATS_REPO/target/release/cats-noded" "$CATS_PREFIX/bin/cats-noded"
cats_worker_deployment_crash_probe after-install-cats-noded
install -m 0755 "$CATS_REPO/target/release/cats-blockd" "$CATS_PREFIX/bin/cats-blockd"
cats_worker_deployment_crash_probe after-install-cats-blockd
install -m 0755 "$CATS_REPO/target/release/cats-guest-agent" "$CATS_PREFIX/bin/cats-guest-agent"
cats_worker_deployment_crash_probe after-install-cats-guest-agent
install -m 0755 "$CATS_REPO/deploy/aws/metal/install-guest-runtime-release.sh" \
  "$CATS_PREFIX/bin/install-guest-runtime-release"
install -m 0755 "$CATS_REPO/deploy/aws/metal/worker-deployment-transaction.sh" \
  "$CATS_PREFIX/bin/worker-deployment-transaction"
cats_worker_deployment_crash_probe after-install-deployment-transaction

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
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-worker.service" \
  /etc/systemd/system/cats-worker.service
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
  chmod 0600 /etc/cats/worker.env
  systemctl enable --now cats-postgres-url.timer
  cats_worker_deployment_crash_probe after-enable-postgres-timer
  "$release_installer" authorize-start
  cats_worker_deployment_crash_probe after-authorize-worker-start
  systemctl enable --now cats-worker
  cats_worker_deployment_crash_probe after-start-worker
  cats_wait_for_registered_node cats-worker
  cats_worker_deployment_crash_probe after-registration-readiness
  "$release_installer" commit
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
