#!/usr/bin/env bash
# Install the full Cats stack on an AWS bare-metal instance (Ubuntu 22.04/24.04,
# x86_64, /dev/kvm). Run as root from a checkout of this repository:
#
#   sudo deploy/metal/install.sh
#
# Then edit /etc/cats/cats.env (S3 backend) and run deploy/metal/e2e.sh.
set -euo pipefail

REPO="$(cd "$(dirname "$0")/../.." && pwd)"
CH_VERSION=${CH_VERSION:-v53.0}
PREFIX=/opt/cats

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ -e /dev/kvm ]] || { echo "/dev/kvm missing: use a *.metal instance" >&2; exit 1; }

echo "==> apt dependencies"
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -qy build-essential curl git nbd-client busybox-static \
  musl-tools e2fsprogs cpio zstd pkg-config

echo "==> rust toolchain"
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  export PATH="$HOME/.cargo/bin:$PATH"
fi

echo "==> build workspace (release)"
(cd "$REPO" && cargo build --release --workspace)

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

echo "==> guest image"
OUT="$PREFIX/guest" "$REPO/deploy/metal/build-guest-image.sh"

echo "==> state dirs + config"
install -d /var/lib/cats/{node,blob} /etc/cats
if [[ ! -f /etc/cats/cats.env ]]; then
  install -m 0600 "$REPO/deploy/metal/cats.env.example" /etc/cats/cats.env
  echo "    wrote /etc/cats/cats.env (edit for S3; defaults to local file blobstore)"
fi

echo "==> systemd units"
install -m 0644 "$REPO"/deploy/metal/systemd/*.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now cats-controld cats-gatewayd cats-noded

sleep 1
systemctl --no-pager --lines 0 status cats-controld cats-gatewayd cats-noded | grep -E "●|Active"
echo
echo "install complete. Try:"
echo "  cats create dev --root-size 512MiB && cats exec dev -- uname -a"
echo "  deploy/metal/e2e.sh   # full acceptance run"
