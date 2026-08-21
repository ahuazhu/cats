#!/bin/sh
set -eu

cgroup_root=${1:?usage: require-idle-worker.sh ABSOLUTE_CGROUP_V2_ROOT [RUNTIME_BIN_ROOT] [VMM_BINARY]}
runtime_bin_root=${2:-/opt/cats/bin}
vmm_binary=${3:-$runtime_bin_root/cloud-hypervisor}
for required_absolute in "$cgroup_root" "$runtime_bin_root" "$vmm_binary"; do
  case "$required_absolute" in
    /*) ;;
    *)
      echo "path must be absolute: $required_absolute" >&2
      exit 1
      ;;
  esac
done

if [ ! -d "$cgroup_root" ] || [ -L "$cgroup_root" ]; then
  echo "configured cgroup-v2 root is not an ordinary directory: $cgroup_root" >&2
  exit 1
fi
if ! canonical_cgroup_root=$(CDPATH= cd -P -- "$cgroup_root" 2>/dev/null && pwd -P); then
  echo "cannot resolve configured cgroup-v2 root: $cgroup_root" >&2
  exit 1
fi
if [ "$canonical_cgroup_root" != "$cgroup_root" ]; then
  echo "configured cgroup-v2 root is not its canonical physical path: $cgroup_root" >&2
  exit 1
fi
if ! mounted_target=$(findmnt --raw --noheadings --first-only --target "$cgroup_root" --output TARGET 2>/dev/null); then
  echo "cannot resolve the mount containing configured cgroup-v2 root: $cgroup_root" >&2
  exit 1
fi
if ! mounted_fstype=$(findmnt --raw --noheadings --first-only --target "$cgroup_root" --output FSTYPE 2>/dev/null); then
  echo "cannot resolve the filesystem type of configured cgroup-v2 root: $cgroup_root" >&2
  exit 1
fi
if [ "$mounted_target" != "$cgroup_root" ] || [ "$mounted_fstype" != cgroup2 ]; then
  echo "configured path is not the exact cgroup2 mount root: $cgroup_root" >&2
  exit 1
fi
cgroup_controllers="$cgroup_root/cgroup.controllers"
if [ ! -f "$cgroup_controllers" ] || [ -L "$cgroup_controllers" ] || [ ! -r "$cgroup_controllers" ]; then
  echo "configured root is not a readable cgroup-v2 hierarchy: $cgroup_root" >&2
  exit 1
fi

is_canonical_cat_slice_name() {
  case "$1" in
    cats-cat-*.slice)
      cat_slice_digest=${1#cats-cat-}
      cat_slice_digest=${cat_slice_digest%.slice}
      [ "${#cat_slice_digest}" -eq 64 ] || return 1
      case "$cat_slice_digest" in *[!0-9a-f]*) return 1 ;; esac
      return 0
      ;;
    *) return 1 ;;
  esac
}

# Calibrate both halves of the negative probe before trusting an empty result:
# the exact namespace matcher must accept a known canonical value, and the
# same directory walk used below must observe cgroup.controllers at this
# configured root. A broken `find`, wrong mount, or unreadable hierarchy is
# therefore an error, never an idle worker.
known_cat_slice=cats-cat-0000000000000000000000000000000000000000000000000000000000000000.slice
if ! is_canonical_cat_slice_name "$known_cat_slice"; then
  echo "internal Cat-slice namespace calibration failed" >&2
  exit 1
fi
if ! cgroup_entries=$(find -P "$cgroup_root" -mindepth 1 -maxdepth 1 -print); then
  echo "cannot enumerate configured cgroup-v2 root: $cgroup_root" >&2
  exit 1
fi

controller_seen=0
entry_count=0
cat_slice_residue=""
old_ifs=$IFS
IFS='
'
for entry in $cgroup_entries; do
  entry_count=$((entry_count + 1))
  if [ "$entry_count" -gt 65536 ]; then
    echo "configured cgroup-v2 root exceeds the bounded entry count" >&2
    exit 1
  fi
  if [ "$entry" = "$cgroup_controllers" ]; then
    controller_seen=1
  fi
  entry_name=${entry##*/}
  case "$entry_name" in
    cats-cat-*)
      if ! is_canonical_cat_slice_name "$entry_name"; then
        echo "malformed reserved Cat-slice entry: $entry" >&2
        exit 1
      fi
      if [ -L "$entry" ] || [ ! -d "$entry" ]; then
        echo "canonical Cat-slice entry is not an ordinary directory: $entry" >&2
        exit 1
      fi
      cat_slice_residue="$cat_slice_residue $entry_name"
      ;;
  esac
done
IFS=$old_ifs

if [ "$controller_seen" -ne 1 ]; then
  echo "cgroup-v2 enumeration calibration did not observe cgroup.controllers" >&2
  exit 1
fi
if [ -n "$cat_slice_residue" ]; then
  echo "worker still has atomic Cat execution slices:$cat_slice_residue" >&2
  echo "drain the node and wait for state=cordoned cats=0 orphans=0 before applying the worker release" >&2
  exit 1
fi

# A managed process outside its mandatory Cat slice is also residue. Walk the
# process table for the installed runtime binaries as a second independent
# check. Match the full argv[0]
# path, never the process comm: comm is truncated to 15 characters, so
# "cloud-hypervisor" (16) can never match itself there.
runtime_pids=""
if ! process_table=$(ps -A -o pid= -o args=); then
  echo "cannot enumerate the Host process table" >&2
  exit 1
fi
process_probe_seen=0
set -f
while IFS= read -r process_line; do
  # Word-split deliberately: $1 is the pid, $2 the argv[0] path.
  # shellcheck disable=SC2086
  set -- $process_line
  [ "$#" -ge 2 ] || continue
  if [ "$1" = "$$" ]; then
    process_probe_seen=1
  fi
  case "$2" in
    "$runtime_bin_root/cats-blockd"|"$runtime_bin_root/cats-vmm-launcher"|"$vmm_binary")
      runtime_pids="$runtime_pids $1(${2##*/})"
      ;;
  esac
done <<PROCESS_TABLE
$process_table
PROCESS_TABLE
set +f

if [ "$process_probe_seen" -ne 1 ]; then
  echo "process-table enumeration calibration did not observe this probe" >&2
  exit 1
fi

if [ -n "$runtime_pids" ]; then
  echo "worker still has live Cat runtime processes:$runtime_pids" >&2
  echo "a live cats-blockd may hold the only copy of unpublished writes; stopping cats-worker would kill it" >&2
  echo "drain the node and wait for state=cordoned cats=0 orphans=0 before applying the worker release" >&2
  echo "if the drain cannot converge, follow the worker release runbook in deploy/aws/terraform/README.md" >&2
  exit 1
fi
