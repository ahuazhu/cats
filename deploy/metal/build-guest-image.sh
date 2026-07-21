#!/usr/bin/env bash
# Build the guest boot artifacts on a metal host, reusing the host's own
# kernel (guest kernel == host kernel => module paths line up):
#
#   /opt/cats/guest/vmlinuz        host kernel image (direct boot)
#   /opt/cats/guest/initramfs.img  busybox initramfs: virtio+ext4 -> switch_root
#   /opt/cats/guest/rootfs.ext4    golden root: busybox + cats-guest-agent(vsock)
#
# Requires: busybox-static, cpio, zstd/gzip, e2fsprogs, musl target rustup.
set -euo pipefail

OUT=${OUT:-/opt/cats/guest}
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
KVER=${KVER:-$(uname -r)}
ROOTFS_MB=${ROOTFS_MB:-256}
BUSYBOX=${BUSYBOX:-/usr/bin/busybox}   # busybox-static
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

mkdir -p "$OUT"

# --------------------------------------------------------------------------
# 0. Static guest agent (musl) — no shared libraries inside the guest.
# --------------------------------------------------------------------------
export PATH="$HOME/.cargo/bin:$PATH"
rustup target add x86_64-unknown-linux-musl >/dev/null
(cd "$REPO" && cargo build --release -p cats-guest-agent --target x86_64-unknown-linux-musl)
AGENT="$REPO/target/x86_64-unknown-linux-musl/release/cats-guest-agent"

# --------------------------------------------------------------------------
# 1. Kernel: boot the host's kernel directly (bzImage, per the experiments).
# --------------------------------------------------------------------------
cp "/boot/vmlinuz-$KVER" "$OUT/vmlinuz"

# Resolve a module list (with dependencies, in load order) for the host
# kernel. Built-in modules print "builtin" lines: skip them.
resolve_modules() {
  for mod in "$@"; do
    modprobe --show-depends "$mod" 2>/dev/null | awk '$1=="insmod"{print $2}'
  done | awk '!seen[$0]++'
}

# --------------------------------------------------------------------------
# 2. Initramfs: load virtio/ext4, mount /dev/vda, switch_root.
# --------------------------------------------------------------------------
IR="$WORK/initramfs"
mkdir -p "$IR"/{bin,dev,proc,sys,newroot,lib/modules}
cp "$BUSYBOX" "$IR/bin/busybox"

INITRD_MODULES=$(resolve_modules virtio_pci virtio_blk ext4)
n=0
: > "$IR/modules.order"
for m in $INITRD_MODULES; do
  base=$(printf '%03d' "$n")-$(basename "$m")
  cp "$m" "$IR/lib/modules/$base"
  echo "/lib/modules/$base" >> "$IR/modules.order"
  n=$((n+1))
done

cat > "$IR/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev
while read -r m; do /bin/busybox insmod "$m" 2>/dev/null; done < /modules.order
i=0
while [ ! -b /dev/vda ] && [ $i -lt 100 ]; do /bin/busybox sleep 0.1; i=$((i+1)); done
/bin/busybox mount -o rw /dev/vda /newroot || exec /bin/busybox sh
/bin/busybox mount --move /dev /newroot/dev
/bin/busybox umount /proc /sys 2>/dev/null
exec /bin/busybox switch_root /newroot /sbin/init
EOF
chmod +x "$IR/init"
(cd "$IR" && find . | cpio -o -H newc --quiet | gzip -9) > "$OUT/initramfs.img"

# --------------------------------------------------------------------------
# 3. Golden rootfs: busybox userland + guest agent on vsock 5000.
# --------------------------------------------------------------------------
RF="$WORK/rootfs"
mkdir -p "$RF"/{bin,sbin,usr/bin,dev,proc,sys,tmp,etc,root,lib/cats-modules}
cp "$BUSYBOX" "$RF/bin/busybox"
for tool in sh mount umount insmod sleep sync cat echo uname hostname ls ps vi mkdir grep head; do
  ln -sf /bin/busybox "$RF/bin/$tool"
done
cp "$AGENT" "$RF/usr/bin/cats-guest-agent"

VSOCK_MODULES=$(resolve_modules vmw_vsock_virtio_transport)
n=0
: > "$RF/etc/cats-modules.order"
for m in $VSOCK_MODULES; do
  base=$(printf '%03d' "$n")-$(basename "$m")
  cp "$m" "$RF/lib/cats-modules/$base"
  echo "/lib/cats-modules/$base" >> "$RF/etc/cats-modules.order"
  n=$((n+1))
done

cat > "$RF/sbin/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc 2>/dev/null
/bin/busybox mount -t sysfs sys /sys 2>/dev/null
/bin/busybox mount -t devtmpfs dev /dev 2>/dev/null
while read -r m; do /bin/busybox insmod "$m" 2>/dev/null; done < /etc/cats-modules.order
/bin/busybox hostname cat
echo "cats guest up (kernel $(/bin/busybox uname -r))"
while true; do
  /usr/bin/cats-guest-agent --mode vm --vsock-port 5000
  echo "guest agent exited; restarting"
  /bin/busybox sleep 1
done
EOF
chmod +x "$RF/sbin/init"

rm -f "$OUT/rootfs.ext4"
truncate -s "${ROOTFS_MB}M" "$OUT/rootfs.ext4"
mkfs.ext4 -q -F -d "$RF" "$OUT/rootfs.ext4"

echo "guest artifacts ready in $OUT:"
ls -la "$OUT"
