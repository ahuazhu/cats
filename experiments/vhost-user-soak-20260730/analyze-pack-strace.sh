#!/usr/bin/env bash
set -euo pipefail

: "${1:?usage: analyze-pack-strace.sh TRACE_DIRECTORY}"
trace_dir="$1"
volume_fragment="${CATS_STRACE_VOLUME_FRAGMENT:-svhoststracbench/vol-dvhoststracbench}"

if ! compgen -G "$trace_dir/blockd.strace.*" >/dev/null; then
  echo "no blockd.strace.* files under $trace_dir" >&2
  exit 2
fi

summarize() {
  local kind="$1"
  local pattern="$2"
  rg --no-filename "$pattern" "$trace_dir"/blockd.strace.* |
    sed -E 's/.*<([0-9.]+)>.*/\1/' |
    sort -n |
    awk -v kind="$kind" '
      { value[NR] = $1 }
      END {
        count = NR
        if (count == 0) {
          exit 1
        }
        p50 = int(count * 0.50 + 0.999999)
        p95 = int(count * 0.95 + 0.999999)
        p99 = int(count * 0.99 + 0.999999)
        printf "%s,%d,%.3f,%.3f,%.3f,%.3f\n",
          kind, count, value[p50] * 1000, value[p95] * 1000,
          value[p99] * 1000, value[count] * 1000
      }
    '
}

escaped_fragment="${volume_fragment//\//\\/}"
echo "operation,count,p50_ms,p95_ms,p99_ms,max_ms"
summarize \
  "pack_fdatasync" \
  "fdatasync\\(.*${escaped_fragment}/pending/\\.tmp-.*<([0-9.]+)>"
summarize \
  "pending_dir_fsync" \
  "fsync\\(.*${escaped_fragment}/pending>\\).*<([0-9.]+)>"
summarize \
  "pack_rename" \
  "rename\\(.*${escaped_fragment}/pending/\\.tmp-.*<([0-9.]+)>"
