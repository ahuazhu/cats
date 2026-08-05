#!/usr/bin/env bash
set -euo pipefail
kind=${1:?kind}; shift
scenario=${Q124_DEVICE_SCENARIO:-clean}
device=/dev/nvme1n1
case $kind in
  findmnt) [[ $scenario == root ]] && printf '%s\n' "$device" || printf '/dev/nvme0n1p1\n' ;;
  lsblk)
    case "$*" in
      '-dno TYPE '* ) [[ $scenario == wrong-type ]] && printf 'part\n' || printf 'disk\n' ;;
      '-dno MODEL '* ) printf 'Amazon EC2 NVMe Instance Storage\n' ;;
      '-no PKNAME '* ) printf 'nvme0n1\n' ;;
      '-nrpo NAME '* )
        printf '%s\n' "$device"
        [[ $scenario == partition ]] && printf '%sp1\n' "$device"
        if [[ $scenario == child-list-partial-error ]]; then
          printf 'lsblk: child-list read failed\n' >&2
          exit 4
        fi
        ;;
      '-nrpo MOUNTPOINT '* )
        [[ $scenario == mounted ]] && printf '/mnt/data\n' || printf '\n'
        if [[ $scenario == mount-query-error ]]; then
          printf 'lsblk: mount query failed\n' >&2
          exit 4
        fi
        ;;
      *) exit 2 ;;
    esac
    ;;
  wipefs)
    if [[ $scenario == wipefs-error ]]; then
      printf 'wipefs: device read failed\n' >&2
      exit 4
    fi
    [[ $scenario == signature ]] && printf 'ext4\n' || true
    ;;
  blkid)
    case $scenario in
      signature) exit 0 ;;
      blkid-error) printf 'blkid: probe failed\n' >&2; exit 4 ;;
      blkid-io-error) printf 'blkid: I/O error\n' >&2; exit 2 ;;
      *) exit 2 ;;
    esac
    ;;
  find)
    if [[ $scenario == holders-find-error ]]; then
      printf 'find: holders traversal failed\n' >&2
      exit 1
    fi
    command find "$@"
    ;;
  *) exit 2 ;;
esac
