#!/usr/bin/env bash
# The whole benchmark set, on one metal box, in one run.
#
# Written after a run whose numbers were 40x off because the ChunkStore cache was
# left on the EBS root instead of the instance NVMe, and nobody noticed until the
# figures were already in the report. So this script *refuses to start* unless the
# environment matches what the report claims, and records what it actually ran on
# next to every result.
#
#   experiments/vhost-user-blk-frontend-20260726/metal-rebench.sh
#
# Env:
#   CATS_REBENCH_S3_BUCKET   also run the storage benches against this bucket
#   CATS_REBENCH_SKIP_FIO=1  skip the Guest fio matrix (the slow part)
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
raw="$here/raw"
out="$raw/metal-rebench.log"
mkdir -p "$raw"
cd "$repo"

export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [ -z "${CATS_TOKEN:-}" ]; then
  # No [ -r ] test: cats.env is root-only 0600, so the test fails for a normal
  # user even though the read below is sudo. That silently left CATS_TOKEN empty
  # and every measurement in the run failed with "not logged in".
  CATS_TOKEN=$(sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env | tail -1)
  export CATS_TOKEN
fi
cli=${CATS:-/opt/cats/bin/cats}

# --------------------------------------------------------------------------
# Environment gate. Every one of these silently changes the numbers.
# --------------------------------------------------------------------------
fail=0
gate() { # description condition-output expected
  if [ "$2" = "$3" ]; then
    echo "  ok    $1: $2"
  else
    echo "  WRONG $1: got '$2', need '$3'" >&2
    fail=1
  fi
}
echo "== environment gate"
cache_src=$(findmnt -no SOURCE /var/lib/cats 2>/dev/null || findmnt -no SOURCE /)
# lsblk resolves a partition to its parent itself; stripping digits by hand turns
# /dev/nvme8n1 into /dev/nvme8n, which is not a device.
cache_model=$(lsblk -no MODEL "$cache_src" 2>/dev/null | head -1 | sed 's/ *$//')
case "$cache_src" in
  /dev/nvme*) gate "ChunkStore cache is on local NVMe" "nvme" "nvme" ;;
  *) gate "ChunkStore cache is on local NVMe" "$cache_src" "nvme" ;;
esac
gate "/dev/kvm present" "$([ -e /dev/kvm ] && echo yes || echo no)" "yes"
gate "cloud-hypervisor installed" \
  "$(command -v cloud-hypervisor >/dev/null && echo yes || echo no)" "yes"
[ "$fail" -eq 0 ] || {
  echo "environment does not match the documented one; refusing to benchmark" >&2
  echo "(mount the instance NVMe at /var/lib/cats -- CATS_DATA_DEVICE in install.sh)" >&2
  exit 1
}

{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "instance_type: $(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $(curl -sX PUT --max-time 2 -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token || true)" http://169.254.169.254/latest/meta-data/instance-type || echo unknown)"
  echo "uname: $(uname -srm)"
  echo "cpus: $(nproc)"
  echo "memory_kb: $(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  echo "cache_mount: /var/lib/cats on $cache_src (${cache_model:-unknown model})"
  echo "cache_fs: $(findmnt -no FSTYPE /var/lib/cats 2>/dev/null)"
  # Uncommented lines only: cats.env.example ships a commented-out aws-s3 line
  # right under the active one, and grepping without this reports the wrong store.
  echo "blob_store: $(sudo grep -v '^[[:space:]]*#' /etc/cats/cats.env |
    grep -o 'object-store-adapter [a-z0-9-]*' | tail -1)"
  echo "cloud_hypervisor: $(cloud-hypervisor --version 2>&1 | head -1)"
  echo "rustc: $(rustc --version)"
  echo "git: $(git rev-parse --short HEAD 2>/dev/null || echo 'not a git checkout')"
  echo
} > "$out"
cat "$out"

section() { echo | tee -a "$out"; echo "##### $*" | tee -a "$out"; }
strip() { sed -E 's/\x1b\[[0-9;]*m//g' | grep -vE 'INFO|DEBUG|TRACE|Compiling|Finished|Running tests|Downloading|Downloaded|Updating'; }

# --------------------------------------------------------------------------
# 1. Storage layer, against the local file object store, then S3 if given.
# --------------------------------------------------------------------------
export CATS_BENCH_LEASE_TTL_MS=120000
for bench in commit_cost golden_root_cost; do
  section "$bench -- local file object store on $cache_src"
  cargo test --release -p cats-blockd --test "$bench" -- \
    --ignored --nocapture --test-threads=1 2>&1 | strip | tee -a "$out"
done
if [ -n "${CATS_REBENCH_S3_BUCKET:-}" ]; then
  for bench in commit_cost golden_root_cost; do
    section "$bench -- real S3 (s3://$CATS_REBENCH_S3_BUCKET)"
    CATS_BENCH_S3_BUCKET=$CATS_REBENCH_S3_BUCKET \
      cargo test --release -p cats-blockd --test "$bench" -- \
      --ignored --nocapture --test-threads=1 2>&1 | strip | tee -a "$out"
  done
fi

# --------------------------------------------------------------------------
# 2. Guest-visible fio, three configurations, two rounds each.
#
# The third configuration is the one that matters: kernel-nbd with the host page
# cache turned off is the only like-for-like comparison against vhost-user.
# --------------------------------------------------------------------------
set_block_path() { # args
  sudo sed -i "s|^CATS_BLOCK_PATH_ARGS=.*|CATS_BLOCK_PATH_ARGS=$1|" /etc/cats/cats.env
  sudo systemctl restart cats-noded
  sleep 5
}
if [ -z "${CATS_REBENCH_SKIP_FIO:-}" ]; then
  for round in 1 2; do
    for config in "kernel-nbd::" \
                  "kernel-nbd-direct::--ch-block-direct" \
                  "vhost-user::--ch-block-path vhost-user --ch-vhost-user-queues 4"; do
      label=${config%%::*}
      args=${config##*::}
      section "fio $label round $round"
      set_block_path "$args"
      CATS_FIO_CAT="fio-$label-r$round" "$here/metal-guest-fio.sh" "$label" 2>&1 |
        strip | tee -a "$out"
      $cli destroy "fio-$label-r$round" >/dev/null 2>&1
    done
  done
fi

# --------------------------------------------------------------------------
# 3. End to end: concurrent create, and the acceptance suite, on both paths.
# --------------------------------------------------------------------------
for config in "kernel-nbd::" "vhost-user::--ch-block-path vhost-user --ch-vhost-user-queues 2"; do
  label=${config%%::*}
  args=${config##*::}
  set_block_path "$args"

  section "10 concurrent cold creates -- $label"
  CATS_PHASES=create CATS_BENCH_PREFIX="rb${label:0:3}" CATS_SETTLE_SECONDS=300 \
    "$repo/experiments/metal-cluster-20260726/concurrent-start.sh" "$label" 10 2>&1 |
    strip | tee -a "$out"
  for n in $($cli ls 2>/dev/null | awk '{print $1}'); do $cli destroy "$n" >/dev/null 2>&1 & done
  wait

  section "acceptance -- $label"
  CATS_CREATE_ARGS=--no-auto-suspend "$repo/deploy/metal/e2e.sh" 2>&1 | strip | tee -a "$out"
done

echo | tee -a "$out"
echo "== wrote $out" | tee -a "$out"
