#!/usr/bin/env bash
# Build a deliberately tiny initramfs for the fixed benchmark hardware model.
# It contains only static BusyBox, virtio_blk, and the init script that mounts
# /dev/vda1 before handing control to the unmodified Ubuntu root filesystem.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SOURCE_INITRD="${1:?usage: $0 SOURCE_INITRD OUTPUT_INITRD}"
OUTPUT_INITRD="${2:?usage: $0 SOURCE_INITRD OUTPUT_INITRD}"

command -v unmkinitramfs >/dev/null || { echo "missing unmkinitramfs" >&2; exit 1; }
command -v cpio >/dev/null || { echo "missing cpio" >&2; exit 1; }
command -v zstd >/dev/null || { echo "missing zstd" >&2; exit 1; }
[ -x /bin/busybox ] || { echo "install busybox-static first" >&2; exit 1; }

BUILD_DIR="$(mktemp -d)"
EXTRACT_DIR="$BUILD_DIR/extracted"
ROOT_DIR="$BUILD_DIR/root"
cleanup() {
  rm -rf "$BUILD_DIR"
}
trap cleanup EXIT

mkdir -p "$EXTRACT_DIR" "$ROOT_DIR/bin" "$ROOT_DIR/dev" "$ROOT_DIR/proc" \
  "$ROOT_DIR/sys" "$ROOT_DIR/newroot" "$ROOT_DIR/lib/modules"
unmkinitramfs "$SOURCE_INITRD" "$EXTRACT_DIR"

BLOCK_MODULE_PATH="$(find "$EXTRACT_DIR" -type f -path '*/kernel/drivers/block/virtio_blk.ko' -print -quit)"
NET_MODULE_PATH="$(find "$EXTRACT_DIR" -type f -path '*/kernel/drivers/net/virtio_net.ko' -print -quit)"
NET_FAILOVER_MODULE_PATH="$(find "$EXTRACT_DIR" -type f -path '*/kernel/drivers/net/net_failover.ko' -print -quit)"
FAILOVER_MODULE_PATH="$(find "$EXTRACT_DIR" -type f -path '*/kernel/net/core/failover.ko' -print -quit)"
[ -n "$BLOCK_MODULE_PATH" ] || { echo "virtio_blk.ko not found in $SOURCE_INITRD" >&2; exit 1; }
[ -n "$NET_MODULE_PATH" ] || { echo "virtio_net.ko not found in $SOURCE_INITRD" >&2; exit 1; }
[ -n "$NET_FAILOVER_MODULE_PATH" ] || { echo "net_failover.ko not found in $SOURCE_INITRD" >&2; exit 1; }
[ -n "$FAILOVER_MODULE_PATH" ] || { echo "failover.ko not found in $SOURCE_INITRD" >&2; exit 1; }

install -m 0755 /bin/busybox "$ROOT_DIR/bin/busybox"
install -m 0755 "$SCRIPT_DIR/minimal-init" "$ROOT_DIR/init"
install -m 0644 "$BLOCK_MODULE_PATH" "$ROOT_DIR/lib/modules/virtio_blk.ko"
install -m 0644 "$FAILOVER_MODULE_PATH" "$ROOT_DIR/lib/modules/failover.ko"
install -m 0644 "$NET_FAILOVER_MODULE_PATH" "$ROOT_DIR/lib/modules/net_failover.ko"
install -m 0644 "$NET_MODULE_PATH" "$ROOT_DIR/lib/modules/virtio_net.ko"

mkdir -p "$(dirname "$OUTPUT_INITRD")"
(
  cd "$ROOT_DIR"
  find . -print0 | cpio --null --create --format=newc --quiet | zstd -q -f -3 -T0 -o "$OUTPUT_INITRD"
)
chmod 0644 "$OUTPUT_INITRD"
printf 'built=%s compressed_bytes=%s\n' "$OUTPUT_INITRD" "$(stat -c %s "$OUTPUT_INITRD")"
