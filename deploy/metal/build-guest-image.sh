#!/usr/bin/env bash
# Build the optimized Ubuntu guest boot artifacts on a metal host, reusing
# the host's own kernel (guest kernel == host kernel => module paths line up):
#
#   /opt/cats/guest/vmlinuz        host kernel image (direct boot)
#   /opt/cats/guest/initramfs.img  busybox initramfs: virtio+ext4 -> switch_root
#   /opt/cats/guest/rootfs.ext4    Ubuntu 24.04 minbase + common CLI tools
#   /opt/cats/guest/rootfs.manifest reproducibility/debug package manifest
#
# BusyBox is deliberately limited to the initramfs. The user-visible root is
# regular Ubuntu: apt, curl, git and the glibc resolver are available after
# switch_root. systemd is PID 1 by default so ordinary enabled Linux services
# and timers work. The Cats Guest Agent is an early systemd service and does
# not wait for multi-user.target, network-online, or background package work.
#
# Requires: busybox-static, cpio, zstd/gzip, e2fsprogs, debootstrap, musl
# target rustup. Run on Ubuntu/Debian x86_64 as root.
set -euo pipefail

# The caller may be an operator shell or an automation runner with umask 077.
# This image contains no Host credentials, and ordinary Guest system files must
# not inherit caller-specific modes. Files needing tighter permissions set them
# explicitly below.
umask 022

OUT=${OUT:-/opt/cats/guest}
REPO="$(cd "$(dirname "$0")/../.." && pwd)"
KVER=${KVER:-$(uname -r)}
ROOTFS_MB=${ROOTFS_MB:-512}
BUSYBOX=${BUSYBOX:-/usr/bin/busybox}   # busybox-static
UBUNTU_SUITE=${UBUNTU_SUITE:-noble}
UBUNTU_MIRROR=${UBUNTU_MIRROR:-http://archive.ubuntu.com/ubuntu}
INITRAMFS_BASE=${INITRAMFS_BASE:-}
GUEST_INIT_MODE=${GUEST_INIT_MODE:-systemd}
WORK=$(mktemp -d)

cleanup() {
  # debootstrap may be interrupted while its helper filesystems are mounted.
  # Unmount only paths below this build's private mktemp directory before the
  # directory is removed; otherwise a failed build can leave host mounts busy.
  for mounted in \
    "$WORK/rootfs/dev/pts" \
    "$WORK/rootfs/dev" \
    "$WORK/rootfs/proc" \
    "$WORK/rootfs/sys"; do
    if command -v mountpoint >/dev/null 2>&1 && mountpoint -q "$mounted"; then
      umount "$mounted" || umount -l "$mounted" || true
    fi
  done
  rm -rf "$WORK"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

[[ $EUID -eq 0 ]] || { echo "run as root" >&2; exit 1; }
[[ $(uname -m) == x86_64 ]] || { echo "x86_64 is required" >&2; exit 1; }
command -v debootstrap >/dev/null || { echo "debootstrap is required" >&2; exit 1; }

# The production installer invokes this through non-login SSM/cloud-init
# shells, which are allowed to omit HOME. This builder is root-only, and both
# rustup and cargo require a stable home before any toolchain command runs.
export HOME="${HOME:-/root}"

case "$GUEST_INIT_MODE" in
  systemd)
    PRIMARY_INIT=/sbin/init
    FALLBACK_INIT=/usr/bin/cats-init
    ;;
  direct)
    # Retained for reproducing the pre-systemd lifecycle experiments. It is
    # not the production Guest contract.
    PRIMARY_INIT=/usr/bin/cats-init
    FALLBACK_INIT=/sbin/init
    ;;
  *)
    echo "GUEST_INIT_MODE must be systemd or direct (got: $GUEST_INIT_MODE)" >&2
    exit 1
    ;;
esac

mkdir -p "$OUT"

# --------------------------------------------------------------------------
# 0. Static guest agent (musl) — no shared libraries inside the guest.
# --------------------------------------------------------------------------
if [[ -n ${GUEST_AGENT_BIN:-} ]]; then
  AGENT=$GUEST_AGENT_BIN
else
  export PATH="$HOME/.cargo/bin:$PATH"
  rustup target add x86_64-unknown-linux-musl >/dev/null
  (cd "$REPO" && cargo build --release -p cats-guest-agent --target x86_64-unknown-linux-musl)
  AGENT="$REPO/target/x86_64-unknown-linux-musl/release/cats-guest-agent"
fi
[[ -x $AGENT ]] || { echo "Guest Agent is not executable: $AGENT" >&2; exit 1; }

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

# Ubuntu kernels ship modules compressed, while busybox `insmod` expects an
# uncompressed ELF module. Copy each dependency in load order and normalize
# it to a plain .ko inside the guest image.
copy_module() {
  src=$1
  dest=$2
  name=$(basename "$src")
  name=${name%.zst}
  name=${name%.xz}
  name=${name%.gz}
  case "$src" in
    *.zst) zstd -q -d -c "$src" > "$dest/$name" ;;
    *.xz)  xz -d -c "$src" > "$dest/$name" ;;
    *.gz)  gzip -d -c "$src" > "$dest/$name" ;;
    *)     cp "$src" "$dest/$name" ;;
  esac
  printf '%s\n' "$dest/$name"
}

# --------------------------------------------------------------------------
# 2. Initramfs: load virtio/ext4, mount /dev/vda, switch_root.
# --------------------------------------------------------------------------
IR="$WORK/initramfs"
mkdir -p "$IR"/{bin,dev,proc,sys,newroot,lib/modules}
if [[ -n $INITRAMFS_BASE ]]; then
  [[ -f $INITRAMFS_BASE ]] || {
    echo "INITRAMFS_BASE does not exist: $INITRAMFS_BASE" >&2
    exit 1
  }
  # Useful for rebuilding userland away from the metal host. The caller is
  # responsible for pairing a base made for exactly the same kernel.
  (cd "$IR" && gzip -dc "$INITRAMFS_BASE" | cpio -id --quiet)
else
  cp "$BUSYBOX" "$IR/bin/busybox"

  # Load the complete Cold critical path before switch_root. vsock and net
  # must both be available before the fast Guest init starts.
  INITRD_MODULES=$(resolve_modules virtio_pci virtio_blk virtio_net vmw_vsock_virtio_transport ext4)
  n=0
  : > "$IR/modules.order"
  for m in $INITRD_MODULES; do
    base=$(printf '%03d' "$n")
    copied=$(copy_module "$m" "$IR/lib/modules")
    named="$IR/lib/modules/$base-$(basename "$copied")"
    mv "$copied" "$named"
    echo "/lib/modules/$(basename "$named")" >> "$IR/modules.order"
    n=$((n+1))
  done
fi

cat > "$IR/init" <<'EOF'
#!/bin/busybox sh
/bin/busybox mount -t proc proc /proc
/bin/busybox mount -t sysfs sys /sys
/bin/busybox mount -t devtmpfs dev /dev
while read -r m; do
  /bin/busybox insmod "$m" || echo "failed to load initramfs module: $m"
done < /modules.order
i=0
while [ ! -b /dev/vda ] && [ $i -lt 100 ]; do /bin/busybox sleep 0.1; i=$((i+1)); done
/bin/busybox mount -o rw /dev/vda /newroot || exec /bin/busybox sh
/bin/busybox mount --move /dev /newroot/dev
/bin/busybox umount /proc /sys 2>/dev/null
if [ -e /newroot@PRIMARY_INIT@ ] || [ -L /newroot@PRIMARY_INIT@ ]; then
  exec /bin/busybox switch_root /newroot @PRIMARY_INIT@
fi
if [ -e /newroot@FALLBACK_INIT@ ] || [ -L /newroot@FALLBACK_INIT@ ]; then
  exec /bin/busybox switch_root /newroot @FALLBACK_INIT@
fi
echo "Cats Guest root has neither @PRIMARY_INIT@ nor @FALLBACK_INIT@" >&2
exec /bin/busybox sh
EOF
sed -i \
  -e "s|@PRIMARY_INIT@|$PRIMARY_INIT|g" \
  -e "s|@FALLBACK_INIT@|$FALLBACK_INIT|g" \
  "$IR/init"
chmod +x "$IR/init"
(cd "$IR" && find . | cpio -o -H newc --quiet | gzip -9) > "$OUT/initramfs.img"

# --------------------------------------------------------------------------
# 3. Golden rootfs: Ubuntu 24.04 minbase + systemd + early Guest Agent.
# --------------------------------------------------------------------------
RF="$WORK/rootfs"
debootstrap \
  --arch=amd64 \
  --variant=minbase \
  --components=main,universe \
  --include=systemd-sysv,tini,e2fsprogs,ca-certificates,curl,wget,git,iproute2,iputils-ping,netbase,procps,less,nano,openssh-client,bash-completion,ncurses-term,fio \
  "$UBUNTU_SUITE" "$RF" "$UBUNTU_MIRROR"

mkdir -p "$RF"/usr/bin "$RF"/etc/systemd/system/sysinit.target.wants \
  "$RF"/etc/systemd/system/multi-user.target.wants "$RF"/etc/systemd/network \
  "$RF"/etc/profile.d
cp "$AGENT" "$RF/usr/bin/cats-guest-agent"

# Both init modes use exactly the same deterministic Cat network setup. The
# Node encodes the assigned /30 Guest address in the final four bytes of the
# locally administered MAC. Avoiding DHCP keeps network-online off the Cold
# path without hard-coding a per-Cat address in the golden root.
cat > "$RF/usr/bin/cats-network-setup" <<'EOF'
#!/bin/sh
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

ip link set dev lo up

interface=
attempt=0
while [ "$attempt" -lt 100 ] && [ -z "$interface" ]; do
  for candidate in /sys/class/net/*; do
    name=${candidate##*/}
    if [ "$name" != lo ]; then interface=$name; break; fi
  done
  [ -n "$interface" ] || sleep 0.05
  attempt=$((attempt + 1))
done

# A node may intentionally run without the optional tap path. Guest control
# still works over vsock in that shape.
[ -n "$interface" ] || exit 0

IFS=: read -r _ _ first second third fourth < "/sys/class/net/$interface/address"
first=$((0x$first)); second=$((0x$second))
third=$((0x$third)); fourth=$((0x$fourth))
gateway="$first.$second.$third.$((fourth - 1))"
address="$first.$second.$third.$fourth/30"

ip link set dev "$interface" up
ip addr replace "$address" dev "$interface"
ip route replace default via "$gateway" dev "$interface"
EOF
chmod +x "$RF/usr/bin/cats-network-setup"

# Legacy direct PID 1. Production boots systemd; this path remains available
# through GUEST_INIT_MODE=direct so historical lifecycle experiments keep a
# reproducible control image. tini forwards signals and reaps orphaned children.
cat > "$RF/usr/bin/cats-init" <<'EOF'
#!/bin/sh
set -eu
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Match the production systemd Guest contract: mounts created by Guest
# workloads must not propagate to the Guest root or unrelated peer trees.
mount --make-rprivate /
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mkdir -p /dev/pts /dev/shm /run /tmp
mount -t devpts devpts /dev/pts -o gid=5,mode=620,ptmxmode=666
mount -t tmpfs tmpfs /dev/shm -o mode=1777
mount -t tmpfs tmpfs /run
mount -t tmpfs tmpfs /tmp -o mode=1777

# The standard /dev file-descriptor names. devtmpfs does not create them and
# systemd never runs here, so without this a shell's process substitution
# (`cmd < <(other)`) fails with "/dev/fd/63: No such file or directory" and
# anything writing to /dev/stdout fails too — both are ordinary idioms, and
# neither failure names the missing file as the cause.
ln -sfn /proc/self/fd /dev/fd
ln -sfn /proc/self/fd/0 /dev/stdin
ln -sfn /proc/self/fd/1 /dev/stdout
ln -sfn /proc/self/fd/2 /dev/stderr

hostname cat 2>/dev/null || true
resize2fs /dev/vda
/usr/bin/cats-network-setup
exec /usr/bin/tini -- /usr/bin/cats-guest-agent --mode vm --vsock-port 5000
EOF
chmod +x "$RF/usr/bin/cats-init"

# Keep the Guest unit definitions as reviewable, directly verifiable source
# files. This script only installs and enables them in the golden root.
for unit in \
  cats-mount-propagation.service \
  cats-grow-root.service \
  cats-network.service \
  cats-guest-agent.service; do
  install -m 0644 \
    "$REPO/deploy/metal/guest-systemd/$unit" \
    "$RF/etc/systemd/system/$unit"
done

# systemd makes the host mount tree recursively shared during manager startup.
# Restore the Cats Guest isolation contract before any platform or user service
# can create recursive bind mounts.
ln -s ../cats-mount-propagation.service \
  "$RF/etc/systemd/system/sysinit.target.wants/cats-mount-propagation.service"

# Grow the ext4 filesystem to the Cat's requested RootDisk size once per boot.
# This lets the golden image stay small while the normal CLI default remains
# 1 GiB and larger disks expose their full capacity to Ubuntu.
ln -s ../cats-grow-root.service \
  "$RF/etc/systemd/system/sysinit.target.wants/cats-grow-root.service"

# Configure the platform-owned tap address before Guest Agent readiness. This
# is a bounded local operation, not systemd's generic network-online contract.
ln -s ../cats-network.service \
  "$RF/etc/systemd/system/sysinit.target.wants/cats-network.service"

# Readiness is deliberately independent from cloud-init, network-online and
# the rest of multi-user.target. Root growth and deterministic tap setup finish
# first; ordinary user services continue in parallel after Agent readiness.
ln -s ../cats-guest-agent.service \
  "$RF/etc/systemd/system/sysinit.target.wants/cats-guest-agent.service"
ln -sf /lib/systemd/system/multi-user.target "$RF/etc/systemd/system/default.target"

# Keep a networkd policy available for users who explicitly enable networkd,
# but do not start a second manager for the platform-owned link by default.
cat > "$RF/etc/systemd/network/20-cats.network" <<'EOF'
[Match]
Name=en*

[Network]
DHCP=no
KeepConfiguration=static
EOF
rm -f \
  "$RF/etc/systemd/system/multi-user.target.wants/systemd-networkd.service" \
  "$RF/etc/systemd/system/sockets.target.wants/systemd-networkd.socket" \
  "$RF/etc/systemd/system/dbus-org.freedesktop.network1.service"
# Keep DNS independent from systemd-resolved: a regular resolv.conf is ready
# before the rest of the systemd transaction and works in both init modes.
rm -f "$RF/etc/resolv.conf"
printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\noptions timeout:1 attempts:3\n' \
  > "$RF/etc/resolv.conf"
chmod 0644 "$RF/etc/resolv.conf"

# Keep generic Ubuntu background work off the Cold-to-Agent critical path.
# cloud-init/snapd/LXD are not installed by minbase; explicitly mask the
# unused serial getty, wait-online and package timers that add nondeterminism.
for unit in \
  serial-getty@ttyS0.service \
  systemd-networkd-wait-online.service \
  apt-daily.service apt-daily.timer \
  apt-daily-upgrade.service apt-daily-upgrade.timer; do
  ln -sf /dev/null "$RF/etc/systemd/system/$unit"
done

printf 'cat\n' > "$RF/etc/hostname"
printf '127.0.0.1 localhost\n127.0.1.1 cat\n' > "$RF/etc/hosts"
: > "$RF/etc/machine-id"
rm -f "$RF/var/lib/dbus/machine-id"

# A Cat opens directly into an interactive login Bash. Enable Ubuntu's color
# prompt, programmable completion (including completions installed later by
# packages such as gh), and useful Readline completion presentation.
for bashrc in "$RF/root/.bashrc" "$RF/etc/skel/.bashrc"; do
  [[ -f $bashrc ]] || continue
  sed -i 's/^#force_color_prompt=yes$/force_color_prompt=yes/' "$bashrc"
  if ! grep -q 'CATS_BASH_COMPLETION' "$bashrc"; then
    cat >> "$bashrc" <<'EOF'

# CATS_BASH_COMPLETION
if [ -r /usr/share/bash-completion/bash_completion ] && ! shopt -oq posix; then
  . /usr/share/bash-completion/bash_completion
fi
EOF
  fi
done
if [[ ! -f "$RF/etc/inputrc" ]] || ! grep -q 'CATS_READLINE' "$RF/etc/inputrc"; then
  cat >> "$RF/etc/inputrc" <<'EOF'

# CATS_READLINE
set completion-ignore-case on
set show-all-if-ambiguous on
set colored-stats on
set visible-stats on
EOF
fi
cat > "$RF/etc/profile.d/cats-login-bash.sh" <<'EOF'
# Let RootDisks created during the /bin/sh Guest Agent transition pick up the
# same shell UX without changing Ubuntu's system /bin/sh symlink.
if [ "$(id -u)" -eq 0 ]; then
  export HOME=/root USER=root LOGNAME=root
  if [ -t 0 ] && [ -x /bin/bash ] && [ -z "${BASH_VERSION:-}" ]; then
    export SHELL=/bin/bash
    exec /bin/bash -l
  fi
fi
EOF

rm -rf "$RF/var/lib/apt/lists/"* "$RF/var/cache/apt/archives/"*.deb

chroot "$RF" dpkg-query -W -f='${binary:Package}\t${Version}\n' \
  | LC_ALL=C sort > "$OUT/rootfs.manifest"

for required in \
  bin/bash usr/bin/apt-get usr/bin/curl usr/bin/wget usr/bin/git usr/bin/cats-init \
  usr/bin/cats-network-setup usr/bin/cats-guest-agent usr/bin/tini \
  lib/systemd/systemd sbin/init sbin/resize2fs \
  usr/share/bash-completion/bash_completion; do
  [[ -e "$RF/$required" ]] || {
    echo "Ubuntu rootfs is missing required path: /$required" >&2
    exit 1
  }
done

rm -f "$OUT/rootfs.ext4"
truncate -s "${ROOTFS_MB}M" "$OUT/rootfs.ext4"
mkfs.ext4 -q -F -d "$RF" "$OUT/rootfs.ext4"

(cd "$OUT" && sha256sum vmlinuz initramfs.img rootfs.ext4 > SHA256SUMS)

echo "guest artifacts ready in $OUT:"
ls -la "$OUT"
