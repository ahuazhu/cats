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

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm missing: use a *.metal instance" >&2; exit 1; }

echo "==> apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
# libssl-dev is required by the PostgreSQL metadata adapter's native-tls stack.
apt-get install -qy build-essential curl git nbd-client busybox-static \
  musl-tools e2fsprogs cpio zstd pkg-config libssl-dev debootstrap iptables \
  util-linux openssl

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

echo "==> install binaries to $PREFIX/bin"
install -d "$PREFIX/bin"
for bin in cats cats-controld cats-noded cats-gatewayd cats-blockd cats-guest-agent; do
  install -m 0755 "$REPO/target/release/$bin" "$PREFIX/bin/$bin"
done
ln -sf "$PREFIX/bin/cats" /usr/local/bin/cats

echo "==> cloud-hypervisor $CH_VERSION"
if [[ ! -x /usr/local/bin/cloud-hypervisor ]]; then
  curl -fsSL -o /usr/local/bin/cloud-hypervisor \
    "https://github.com/cloud-hypervisor/cloud-hypervisor/releases/download/${CH_VERSION}/cloud-hypervisor-static"
  chmod +x /usr/local/bin/cloud-hypervisor
fi
/usr/local/bin/cloud-hypervisor --version

echo "==> kernel NBD module (nbds_max=64)"
modprobe nbd nbds_max=64 || true
echo nbd > /etc/modules-load.d/cats.conf
echo "options nbd nbds_max=64" > /etc/modprobe.d/cats-nbd.conf

echo "==> guest outbound network"
install -m 0755 "$REPO/deploy/metal/setup-guest-network.sh" \
  "$PREFIX/bin/setup-guest-network"
printf 'net.ipv4.ip_forward=1\nnet.ipv4.conf.all.rp_filter=1\nnet.ipv4.conf.default.rp_filter=1\n' \
  > /etc/sysctl.d/90-cats-guest-network.conf
CATS_GUEST_NETWORK_CIDR=${CATS_GUEST_NETWORK_CIDR:-10.240.0.0/16} \
  "$PREFIX/bin/setup-guest-network"

echo "==> guest image"
OUT="$PREFIX/guest" "$REPO/deploy/metal/build-guest-image.sh"

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
if [[ ! -f /etc/cats/cats.env ]]; then
  install -m 0600 "$REPO/deploy/metal/cats.env.example" /etc/cats/cats.env
  echo "    wrote /etc/cats/cats.env (edit for S3; defaults to local file blobstore)"
fi

# The single-host development shape owns one local signing key. Keep the
# private half root-only and derive the public half on every install so the
# files cannot silently drift apart. Production supplies the pair through its
# separate control-plane and worker deployment states.
if [[ ! -f /etc/cats/route-grant-private.pem ]]; then
  route_key_temp=$(mktemp /var/tmp/cats-route-grant-private.XXXXXX)
  trap 'rm -f -- "$route_key_temp"' EXIT
  openssl genpkey -algorithm ED25519 -out "$route_key_temp"
  install -o root -g root -m 0600 "$route_key_temp" /etc/cats/route-grant-private.pem
  rm -f -- "$route_key_temp"
  trap - EXIT
fi
route_public_temp=$(mktemp /var/tmp/cats-route-grant-public.XXXXXX)
trap 'rm -f -- "$route_public_temp"' EXIT
openssl pkey -in /etc/cats/route-grant-private.pem -pubout -out "$route_public_temp"
install -o root -g root -m 0644 "$route_public_temp" /etc/cats/route-grant-public.pem
rm -f -- "$route_public_temp"
trap - EXIT

echo "==> systemd units"
install -m 0644 "$REPO"/deploy/metal/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cats-controld cats-gatewayd cats-noded

sleep 1
systemctl --no-pager --lines 0 status cats-controld cats-gatewayd cats-noded | grep -E "●|Active"
echo
echo "install complete. Try:"
echo "  cats create dev --root-size 1GiB && cats exec dev -- uname -a"
echo "  deploy/metal/e2e.sh   # full acceptance run"
