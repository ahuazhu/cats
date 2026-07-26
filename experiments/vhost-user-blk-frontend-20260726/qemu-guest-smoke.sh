#!/usr/bin/env bash
# Boot a real Linux guest against the vhost-user-blk backend and put a real ext4
# on it, with QEMU as the vhost-user frontend.
#
# Why this exists: the acceptance tests in blockd/tests/ drive the backend from a
# harness this repository wrote, and Cloud Hypervisor needs KVM. QEMU with TCG
# needs no KVM, so it can validate the two things the harness cannot:
#
#   * an independent vhost-user frontend implementation (QEMU's, not ours);
#   * the real Linux `virtio_blk` driver and a real ext4 on top of it,
#     including the FLUSH the journal issues on umount.
#
# It does NOT validate Cloud Hypervisor itself or Warm (`vm.snapshot`/
# `--restore`) device-state alignment. Those still need bare metal with KVM.
#
# Scenario:
#   boot 1  raw sector write/read outside the filesystem area, then mkfs.ext4,
#           mount, write files, sync, umount, e2fsck
#   host    kill the backend and DELETE the local cache directory, then attach
#           the same volume with an empty cache (spec §8 criterion 2)
#   boot 2  e2fsck, mount, re-verify every digest, re-read the raw region
#
#   ./qemu-guest-smoke.sh
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
rel="${here#"$repo"/}"
image="${CATS_QEMU_IMAGE:-cats-qemu-guest}"

if [ "$(uname -s)" != "Linux" ]; then
  case "$(uname -m)" in
    arm64 | aarch64) platform=linux/arm64 ;;
    x86_64) platform=linux/amd64 ;;
    *)
      echo "unsupported host architecture $(uname -m)" >&2
      exit 1
      ;;
  esac
  # The image needs QEMU, a guest kernel, busybox and e2fsprogs; build it once.
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    echo "== building $image"
    docker build --platform "$platform" -t "$image" - <<'DOCKERFILE'
FROM rust:1.97-bookworm
RUN apt-get -qq update && apt-get -qq install -y --no-install-recommends \
      qemu-system-arm qemu-system-x86 ipxe-qemu busybox-static cpio kmod e2fsprogs file \
      "linux-image-$(dpkg --print-architecture)" \
    && rm -rf /var/lib/apt/lists/*
DOCKERFILE
  fi
  echo "== not Linux: re-running in $image ($platform)"
  exec docker run --rm --platform "$platform" \
    -v "$repo":/work -w /work \
    -v cats-cargo-registry:/usr/local/cargo/registry \
    -v cats-target-linux:/target \
    -e CATS_TARGET_DIR=/target \
    "$image" "/work/$rel/qemu-guest-smoke.sh"
fi

target_dir="${CATS_TARGET_DIR:-$repo/target-linux/$(uname -m)}"
raw="$here/raw"
mkdir -p "$raw"
work="$(mktemp -d)"
kver="$(ls /lib/modules | head -1)"
volume_bytes=$((256 * 1024 * 1024))
# The filesystem covers the first 200 MiB; the raw-sector test uses 220 MiB so
# the two never overlap.
fs_blocks=$((200 * 1024 * 1024 / 4096))
raw_offset_mib=220

case "$(uname -m)" in
  aarch64) qemu=qemu-system-aarch64; machine=(-M virt -cpu max); console=ttyAMA0 ;;
  x86_64) qemu=qemu-system-x86_64; machine=(-M q35 -cpu max); console=ttyS0 ;;
  *)
    echo "unsupported architecture" >&2
    exit 1
    ;;
esac

blockd_pid=""
cleanup() {
  [ -n "$blockd_pid" ] && kill "$blockd_pid" 2>/dev/null || true
  wait "$blockd_pid" 2>/dev/null || true
  rm -rf "$work"
}
trap cleanup EXIT

# --------------------------------------------------------------------------
# Guest image: busybox initramfs with virtio/ext4 modules and e2fsprogs.
# --------------------------------------------------------------------------
ir="$work/ir"
mkdir -p "$ir"/{bin,sbin,dev,proc,sys,tmp,mnt,lib/modules}
cp /bin/busybox "$ir/bin/busybox"
ln -s busybox "$ir/bin/sh"

resolve_modules() {
  for mod in "$@"; do
    modprobe -S "$kver" --show-depends "$mod" 2>/dev/null | awk '$1=="insmod"{print $2}'
  done | awk '!seen[$0]++'
}
: >"$ir/modules.order"
index=0
for module in $(resolve_modules virtio_pci virtio_blk ext4); do
  name="$(printf '%03d' "$index")-$(basename "${module%.zst}")"
  case "$module" in
    *.zst) zstd -q -d -c "$module" >"$ir/lib/modules/$name" ;;
    *.xz) xz -dc "$module" >"$ir/lib/modules/$name" ;;
    *) cp "$module" "$ir/lib/modules/$name" ;;
  esac
  echo "/lib/modules/$name" >>"$ir/modules.order"
  index=$((index + 1))
done

for binary in /sbin/mkfs.ext4 /sbin/e2fsck /sbin/dumpe2fs; do
  cp "$binary" "$ir/sbin/"
  ldd "$binary" | awk '/=> \//{print $3}' | while read -r lib; do
    mkdir -p "$ir$(dirname "$lib")"
    cp -n "$lib" "$ir$lib" 2>/dev/null || true
  done
done
for loader in /lib/ld-linux-aarch64.so.1 /lib64/ld-linux-x86-64.so.2; do
  [ -e "$loader" ] && { mkdir -p "$ir$(dirname "$loader")" && cp -n "$loader" "$ir$loader"; }
done

# Deterministic file contents so both boots can compare digests.
cat >"$ir/init" <<INIT
#!/bin/busybox sh
/bin/busybox --install -s /bin
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
for m in \$(cat /modules.order); do insmod "\$m" || echo "GUEST insmod failed: \$m"; done
i=0
while [ ! -b /dev/vda ] && [ \$i -lt 200 ]; do sleep 0.05; i=\$((i + 1)); done
[ -b /dev/vda ] || { echo "GUEST FAIL no /dev/vda"; poweroff -f; }

mode=\$(sed -n 's/.*catsmode=\([a-z]*\).*/\1/p' /proc/cmdline)
echo "GUEST mode=\$mode"
echo "GUEST capacity_bytes=\$(blockdev --getsize64 /dev/vda)"
echo "GUEST logical_block_size=\$(cat /sys/block/vda/queue/logical_block_size)"
echo "GUEST hw_queues=\$(ls -d /sys/block/vda/mq/* 2>/dev/null | wc -l)"
echo "GUEST write_cache=\$(cat /sys/block/vda/queue/write_cache)"

payload() { yes "cats-vhost-user-blk-\$1" | head -c "\$2"; }

if [ "\$mode" = write ]; then
  # Raw sectors outside the filesystem area: IN/OUT/FLUSH without a filesystem.
  payload raw \$((1024 * 1024)) > /tmp/raw.bin
  dd if=/tmp/raw.bin of=/dev/vda bs=1M seek=$raw_offset_mib conv=notrunc 2>/dev/null
  sync
  blockdev --flushbufs /dev/vda 2>/dev/null || true
  dd if=/dev/vda of=/tmp/raw.back bs=1M skip=$raw_offset_mib count=1 2>/dev/null
  if cmp -s /tmp/raw.bin /tmp/raw.back; then echo "GUEST raw_roundtrip=ok"; else echo "GUEST raw_roundtrip=MISMATCH"; fi
  echo "GUEST raw_digest=\$(sha256sum < /tmp/raw.bin | cut -d' ' -f1)"

  mkfs.ext4 -F -q -b 4096 /dev/vda $fs_blocks || { echo "GUEST FAIL mkfs"; poweroff -f; }
  mount -t ext4 /dev/vda /mnt || { echo "GUEST FAIL mount"; poweroff -f; }
  payload small 4096 > /mnt/small.bin
  payload large \$((8 * 1024 * 1024)) > /mnt/large.bin
  mkdir -p /mnt/dir && payload nested 65536 > /mnt/dir/nested.bin
  sync
  echo "GUEST small_digest=\$(sha256sum /mnt/small.bin | cut -d' ' -f1)"
  echo "GUEST large_digest=\$(sha256sum /mnt/large.bin | cut -d' ' -f1)"
  echo "GUEST nested_digest=\$(sha256sum /mnt/dir/nested.bin | cut -d' ' -f1)"
  umount /mnt || { echo "GUEST FAIL umount"; poweroff -f; }
  if e2fsck -fn /dev/vda >/tmp/fsck.log 2>&1; then echo "GUEST fsck=clean"; else echo "GUEST fsck=DIRTY"; cat /tmp/fsck.log; fi
elif [ "\$mode" = verify ]; then
  if e2fsck -fn /dev/vda >/tmp/fsck.log 2>&1; then echo "GUEST fsck=clean"; else echo "GUEST fsck=DIRTY"; cat /tmp/fsck.log; fi
  dumpe2fs -h /dev/vda 2>/dev/null | sed -n 's/^Filesystem state: */GUEST fs_state=/p'
  mount -t ext4 /dev/vda /mnt || { echo "GUEST FAIL mount"; poweroff -f; }
  echo "GUEST small_digest=\$(sha256sum /mnt/small.bin | cut -d' ' -f1)"
  echo "GUEST large_digest=\$(sha256sum /mnt/large.bin | cut -d' ' -f1)"
  echo "GUEST nested_digest=\$(sha256sum /mnt/dir/nested.bin | cut -d' ' -f1)"
  umount /mnt
  dd if=/dev/vda of=/tmp/raw.back bs=1M skip=$raw_offset_mib count=1 2>/dev/null
  echo "GUEST raw_digest=\$(sha256sum < /tmp/raw.back | cut -d' ' -f1)"
fi
echo "GUEST MARKER complete"
poweroff -f
INIT
chmod +x "$ir/init"
(cd "$ir" && find . | cpio -o -H newc --quiet | gzip -1) >"$work/initramfs.img"
echo "== guest image: kernel $kver, initramfs $(stat -c %s "$work/initramfs.img") bytes"

# --------------------------------------------------------------------------
# Backend and guest boots
# --------------------------------------------------------------------------
echo "== building cats-blockd (release)"
cargo build --release -p cats-blockd-daemon --target-dir "$target_dir" >/dev/null

start_blockd() { # $1 = data dir
  "$target_dir/release/cats-blockd" \
    --volume-id vol_qemu_guest --attachment-id "att-$(basename "$1")" \
    --data-dir "$1" \
    --metadata-store-adapter sqlite --metadata-store-option "path=$work/meta.db" \
    --object-store-adapter file --object-store-option "root=$work/blob" \
    --listen-unix "$work/nbd.sock" --listen-vhost-user "$work/vhu.sock" \
    --vhost-user-queues 2 --create-volume-size "$volume_bytes" \
    >"$work/ready.log" 2>>"$raw/qemu-blockd.log" &
  blockd_pid=$!
  for _ in $(seq 1 200); do
    grep -q '^READY ' "$work/ready.log" 2>/dev/null && return 0
    sleep 0.1
  done
  echo "cats-blockd never became ready" >&2
  exit 1
}

boot_guest() { # $1 = catsmode, $2 = log file
  timeout 900 "$qemu" "${machine[@]}" -smp 2 -m 512 \
    -object memory-backend-memfd,id=mem,size=512M,share=on -numa node,memdev=mem \
    -kernel "/boot/vmlinuz-$kver" -initrd "$work/initramfs.img" \
    -append "console=$console panic=1 catsmode=$1" \
    -chardev socket,id=blk0,path="$work/vhu.sock" \
    -device vhost-user-blk-pci,chardev=blk0,num-queues=2 \
    -display none -monitor none -serial stdio -no-reboot >"$2" 2>&1
}

: >"$raw/qemu-blockd.log"
echo "== boot 1: raw sectors, mkfs.ext4, write, sync, umount, e2fsck"
start_blockd "$work/data-1"
boot_guest write "$raw/qemu-guest-boot1.log"
# The backend exits on its own when the guest powers off and QEMU drops the
# vhost-user connection; killing it is only a fallback.
kill "$blockd_pid" 2>/dev/null || true
wait "$blockd_pid" 2>/dev/null || true
blockd_pid=""

# Empty-cache restore: the second attachment must serve every read from the
# durable object store, not from local state.
rm -rf "$work/data-1"
objects=$(find "$work/blob" -type f | wc -l)
echo "== local cache deleted; $objects committed objects remain in the object store"

echo "== boot 2: e2fsck, mount, re-verify digests with an empty local cache"
start_blockd "$work/data-2"
boot_guest verify "$raw/qemu-guest-boot2.log"
kill "$blockd_pid" 2>/dev/null || true
wait "$blockd_pid" 2>/dev/null || true
blockd_pid=""

# --------------------------------------------------------------------------
# Verdict
# --------------------------------------------------------------------------
marker() { sed -n "s/^GUEST $1=//p" "$2" | tr -d '\r'; }
fail=0
check() { # description, expected, actual
  if [ "$2" = "$3" ]; then
    echo "  ok    $1: $3"
  else
    echo "  FAIL  $1: expected '$2', got '$3'"
    fail=1
  fi
}

echo "== verdict"
check "guest sees the volume capacity" "$volume_bytes" "$(marker capacity_bytes "$raw/qemu-guest-boot1.log")"
check "logical block size" "512" "$(marker logical_block_size "$raw/qemu-guest-boot1.log")"
check "hardware queues" "2" "$(marker hw_queues "$raw/qemu-guest-boot1.log")"
check "writeback cache advertised" "write back" "$(marker write_cache "$raw/qemu-guest-boot1.log")"
check "raw sector roundtrip" "ok" "$(marker raw_roundtrip "$raw/qemu-guest-boot1.log")"
check "boot 1 e2fsck" "clean" "$(marker fsck "$raw/qemu-guest-boot1.log")"
check "boot 1 completed" "complete" "$(sed -n 's/^GUEST MARKER //p' "$raw/qemu-guest-boot1.log" | tr -d '\r')"
check "boot 2 e2fsck after empty-cache attach" "clean" "$(marker fsck "$raw/qemu-guest-boot2.log")"
check "boot 2 filesystem state" "clean" "$(marker fs_state "$raw/qemu-guest-boot2.log")"
for digest in small large nested raw; do
  check "$digest digest survives the empty-cache attach" \
    "$(marker "${digest}_digest" "$raw/qemu-guest-boot1.log")" \
    "$(marker "${digest}_digest" "$raw/qemu-guest-boot2.log")"
done
generations=$(grep -c 'attached' "$raw/qemu-blockd.log" || true)
echo "  info  backend attachments: $generations; committed objects: $objects"

if [ "$fail" -eq 0 ]; then
  echo "== PASS (logs in $raw/qemu-guest-boot{1,2}.log)"
else
  echo "== FAIL"
  exit 1
fi
