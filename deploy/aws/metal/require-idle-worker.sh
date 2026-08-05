#!/bin/sh
set -eu

metering_root=${1:?usage: require-idle-worker.sh ABSOLUTE_METERING_CGROUP_ROOT [RUNTIME_BIN_ROOT]}
runtime_bin_root=${2:-/opt/cats/bin}
find_bin=${Q124_FIND_BIN:-find}
for required_absolute in "$metering_root" "$runtime_bin_root"; do
  case "$required_absolute" in
    /*) ;;
    *)
      echo "path must be absolute: $required_absolute" >&2
      exit 1
      ;;
  esac
done

active_cat_pids=""
if [ -d "$metering_root" ]; then
  cgroup_list=$(mktemp)
  trap 'rm -f "$cgroup_list"' EXIT HUP INT TERM
  if ! "$find_bin" "$metering_root" -type f -name cgroup.procs -print >"$cgroup_list"; then
    echo "cannot traverse metering cgroups" >&2
    exit 1
  fi
  while IFS= read -r cgroup_procs; do
    while IFS= read -r pid; do
      case "$pid" in
        ""|*[!0-9]*)
          echo "invalid pid in $cgroup_procs: $pid" >&2
          exit 1
          ;;
        *)
          active_cat_pids="$active_cat_pids $pid"
          ;;
      esac
    done < "$cgroup_procs"
  done <"$cgroup_list"
  rm -f "$cgroup_list"
  trap - EXIT HUP INT TERM
elif [ -e "$metering_root" ]; then
  echo "metering root is not a directory: $metering_root" >&2
  exit 1
fi

if [ -n "$active_cat_pids" ]; then
  echo "worker still has active Cat processes:$active_cat_pids" >&2
  echo "drain the node and wait for state=cordoned cats=0 before applying the worker release" >&2
  exit 1
fi

# The metering cgroups above hold only metered processes: the Guest and its
# VMM. A cats-blockd is not metered, so a node whose Guests are gone but whose
# blockd still holds an unpublished journal would pass that walk -- and the
# release then runs `systemctl stop cats-worker`. KillMode=process deliberately
# leaves that journal holder alive for re-adoption, but a release must not
# replace the worker binaries or Guest seed underneath a live runtime. Walk the
# process table for the installed runtime binaries as well. Match the full
# argv[0] path, never the process comm: comm is truncated to 15 characters, so
# "cloud-hypervisor" (16) can never match itself there.
runtime_pids=""
process_table=$(ps -A -o pid= -o args=)
set -f
while IFS= read -r process_line; do
  # Word-split deliberately: $1 is the pid, $2 the argv[0] path.
  # shellcheck disable=SC2086
  set -- $process_line
  [ "$#" -ge 2 ] || continue
  case "$2" in
    "$runtime_bin_root/cats-blockd"|"$runtime_bin_root/cloud-hypervisor")
      runtime_pids="$runtime_pids $1(${2##*/})"
      ;;
  esac
done <<PROCESS_TABLE
$process_table
PROCESS_TABLE
set +f

if [ -n "$runtime_pids" ]; then
  echo "worker still has live Cat runtime processes:$runtime_pids" >&2
  echo "a live cats-blockd may hold the only copy of unpublished writes; do not replace the worker underneath it" >&2
  echo "drain the node and wait for state=cordoned cats=0 orphans=0 before applying the worker release" >&2
  echo "if the drain cannot converge, follow the worker release runbook in deploy/aws/terraform/README.md" >&2
  exit 1
fi
