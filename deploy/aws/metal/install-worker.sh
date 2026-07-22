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
  e2fsprogs cpio zstd pkg-config libssl-dev ca-certificates

export PATH="/root/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null; then
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
    | sh -s -- -y --default-toolchain stable --profile minimal
  export PATH="/root/.cargo/bin:$PATH"
fi

(cd "$CATS_REPO" && cargo build --locked --release \
  -p cats-node-agent-daemon -p cats-blockd-daemon -p cats-guest-agent)

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

OUT="$CATS_PREFIX/guest" "$CATS_REPO/deploy/metal/build-guest-image.sh"
curl -fsSL https://truststore.pki.rds.amazonaws.com/us-east-1/us-east-1-bundle.pem \
  -o /etc/cats/rds-ca.pem
chmod 0644 /etc/cats/rds-ca.pem

install -m 0644 "$CATS_REPO/deploy/aws/metal/cats-worker.service" \
  /etc/systemd/system/cats-worker.service
systemctl daemon-reload

if [[ -f /etc/cats/worker.env ]]; then
  chmod 0600 /etc/cats/worker.env
  systemctl enable --now cats-worker
else
  install -m 0600 "$CATS_REPO/deploy/aws/metal/worker.env.example" /etc/cats/worker.env
  echo "created /etc/cats/worker.env; fill its values, then enable cats-worker" >&2
fi
