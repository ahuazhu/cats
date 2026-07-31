#!/bin/sh
set -eu

metering_root=${1:?usage: require-idle-worker.sh ABSOLUTE_METERING_CGROUP_ROOT}
case "$metering_root" in
  /*) ;;
  *)
    echo "metering cgroup root must be absolute: $metering_root" >&2
    exit 1
    ;;
esac

active_cat_pids=""
if [ -d "$metering_root" ]; then
  for cgroup_procs in $(find "$metering_root" -type f -name cgroup.procs -print); do
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
  done
fi

if [ -n "$active_cat_pids" ]; then
  echo "worker still has active Cat processes:$active_cat_pids" >&2
  echo "drain the node and wait for state=cordoned cats=0 before applying the worker release" >&2
  exit 1
fi
