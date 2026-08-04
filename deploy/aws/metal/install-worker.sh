#!/usr/bin/env bash
# Install only the Cats worker data plane on Linux x86_64 bare metal.
# The web UI, control plane and gateway stay in EKS.
set -euo pipefail

CATS_REPO="$(cd "$(dirname "$0")/../../.." && pwd)"
CATS_PREFIX=/opt/cats
CATS_CH_VERSION=${CATS_CH_VERSION:-v53.0}

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo "x86_64 is required" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm missing: use a bare-metal instance" >&2; exit 1; }

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

# Local NVMe for the ChunkStore cache and the per-Cat state filesystem.
#
# deploy/metal/install.sh grew this on 2026-07-27 after an i4i run measured 4 KiB
# random write 40x low purely because /var/lib/cats had been left on the EBS
# root. This installer -- the one production workers actually run -- never got
# the same treatment, so every AWS worker silently benchmarked and ran its
# ChunkStore cache on EBS. Mount it before anything creates state under it.
#
# CATS_DATA_DEVICE=none skips this; CATS_DATA_DEVICE=/dev/nvmeXn1 picks one.
DATA_DEVICE=${CATS_DATA_DEVICE:-auto}
if [[ $DATA_DEVICE == auto ]]; then
  # -P emits key="value" pairs. Column output cannot be used here: awk collapses
  # an empty MOUNTPOINT, so $4 becomes the first word of MODEL and a test for an
  # unmounted disk never matches. That is why the equivalent block in
  # deploy/metal/install.sh only ever selected through its size fallback.
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
    # No vendor label: largest unmounted real disk, excluding virtual classes.
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
    # Deliberately not in /etc/fstab: instance storage does not survive a
    # stop/start, and a reboot should come up with an empty cache rather than
    # fail to boot on a device that no longer has a filesystem.
  fi
else
  echo "==> no local data device found; /var/lib/cats stays on the root filesystem"
  echo "    (fine for functional testing, NOT comparable for storage benchmarks)"
fi

install -d "$CATS_PREFIX/bin" "$CATS_PREFIX/guest" /var/lib/cats/node /etc/cats
install -m 0755 "$CATS_REPO/target/release/cats-noded" "$CATS_PREFIX/bin/cats-noded"
install -m 0755 "$CATS_REPO/target/release/cats-blockd" "$CATS_PREFIX/bin/cats-blockd"
install -m 0755 "$CATS_REPO/target/release/cats-guest-agent" "$CATS_PREFIX/bin/cats-guest-agent"

if [[ ! -x "$CATS_PREFIX/bin/cloud-hypervisor" ]]; then
  curl -fsSL -o "$CATS_PREFIX/bin/cloud-hypervisor" \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/$CATS_CH_VERSION/cloud-hypervisor-static"
  chmod 0755 "$CATS_PREFIX/bin/cloud-hypervisor"
fi

modprobe nbd nbds_max=64
echo nbd > /etc/modules-load.d/cats.conf
echo "options nbd nbds_max=64" > /etc/modprobe.d/cats-nbd.conf

install -m 0755 "$CATS_REPO/deploy/metal/setup-guest-network.sh" \
  "$CATS_PREFIX/bin/setup-guest-network"
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.default.rp_filter=1\n' \
  > /etc/sysctl.d/90-cats-guest-network.conf
CATS_GUEST_NETWORK_CIDR=${CATS_GUEST_NETWORK_CIDR:-10.240.0.0/16} \
  "$CATS_PREFIX/bin/setup-guest-network"

OUT="$CATS_PREFIX/guest" "$CATS_REPO/deploy/metal/build-guest-image.sh"
curl -fsSL https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem \
  -o /etc/cats/rds-ca.pem
chmod 0644 /etc/cats/rds-ca.pem

install -m 0755 "$CATS_REPO/deploy/aws/metal/render-postgres-url.sh" \
  "$CATS_PREFIX/bin/render-postgres-url"
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-worker.service" \
  /etc/systemd/system/cats-worker.service
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-postgres-url.service" \
  /etc/systemd/system/cats-postgres-url.service
install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-postgres-url.timer" \
  /etc/systemd/system/cats-postgres-url.timer
systemctl daemon-reload

# The timer is started, not merely enabled: an enabled-but-unstarted timer
# leaves the mid-run rotation window unbounded until the next boot fires
# OnBootSec. It can only start once worker.env exists, since the unit reads it.
if [[ -f /etc/cats/worker.env ]]; then
  chmod 0600 /etc/cats/worker.env
  systemctl enable --now cats-postgres-url.timer
  systemctl enable --now cats-worker
else
  install -m 0600 "$CATS_REPO/deploy/aws/metal/worker.env.example" /etc/cats/worker.env
  systemctl enable cats-postgres-url.timer
  echo "created /etc/cats/worker.env; fill its values, then:" >&2
  echo "  systemctl start cats-postgres-url.timer" >&2
  echo "  systemctl enable --now cats-worker" >&2
fi
