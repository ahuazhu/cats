#!/usr/bin/env bash
# Destructive-format precondition for the issue #124 ephemeral cache. This is
# separate so stateful command doubles can prove every negative branch.
set -euo pipefail

die() { printf 'q124-device: %s\n' "$*" >&2; exit 1; }
LSBLK=${Q124_LSBLK_BIN:-lsblk}
FINDMNT=${Q124_FINDMNT_BIN:-findmnt}
WIPEFS=${Q124_WIPEFS_BIN:-wipefs}
BLKID=${Q124_BLKID_BIN:-blkid}
FIND=${Q124_FIND_BIN:-find}

device=${Q124_CACHE_DEVICE:?cache device required}
instance=${Q124_INSTANCE_ID:?instance id required}
confirmation=${Q124_FORMAT_CONFIRMATION:?format confirmation required}
[[ $device =~ ^/dev/[A-Za-z0-9._-]+$ ]] || die "invalid cache device path"
[[ $confirmation == "FORMAT_EPHEMERAL_CACHE_${instance}_${device}" ]] || die "cache format confirmation mismatch"

[[ $($LSBLK -dno TYPE "$device") == disk ]] || die "cache device TYPE is not disk"
model=$($LSBLK -dno MODEL "$device")
[[ $model == *'Instance Storage'* ]] || die "device is not EC2 NVMe Instance Storage"

root=$($FINDMNT -no SOURCE /)
root_parent=$($LSBLK -no PKNAME "$root" | head -1)
[[ -n $root_parent ]] && root_parent=/dev/$root_parent
[[ $device != "$root" && $device != "$root_parent" ]] || die "refusing root disk or its parent"

if ! names_output=$($LSBLK -nrpo NAME "$device" 2>&1); then
  die "cache child-list probe failed"
fi
mapfile -t names <<<"$names_output"
[[ ${#names[@]} == 1 && ${names[0]} == "$device" ]] || die "cache device has partitions or child mappings"
if ! mounts_output=$($LSBLK -nrpo MOUNTPOINT "$device" 2>&1); then
  die "cache mount probe failed"
fi
[[ -z $(sed '/^$/d' <<<"$mounts_output") ]] || die "cache device is mounted"

holders=${Q124_HOLDERS_DIR:-/sys/class/block/${device##*/}/holders}
[[ -d $holders ]] || die "kernel holders path is missing"
if ! holders_output=$($FIND "$holders" -mindepth 1 -maxdepth 1 -print -quit 2>&1); then
  die "kernel holders probe failed"
fi
[[ -z $holders_output ]] || die "cache device has kernel holders"

if ! wipefs_output=$($WIPEFS --noheadings --output TYPE "$device" 2>&1); then
  die "wipefs probe failed"
fi
[[ -z $(sed '/^$/d' <<<"$wipefs_output") ]] || die "cache device has an existing signature"

# util-linux blkid low-level probing returns 0 for a signature, 2 when no
# identifier was found, 4 for usage/other errors, and 8 for ambiguity. Exit 2
# can also accompany an unreadable device, so accept it only with empty output;
# wipefs' required-success probe above supplies an independent readability
# check. All other outcomes fail closed.
if blkid_output=$($BLKID -p "$device" 2>&1); then
  die "cache device has an existing filesystem/signature"
else
  blkid_status=$?
fi
[[ $blkid_status == 2 && -z $blkid_output ]] || die "blkid probe failed or was ambiguous"

printf 'safe-ephemeral-cache=%s\n' "$device"
