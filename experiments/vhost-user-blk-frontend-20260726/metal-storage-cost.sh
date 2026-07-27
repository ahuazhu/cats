#!/usr/bin/env bash
# What delta packs (ADR-0016) and golden roots (ADR-0017) are worth against a real
# object store, on real hardware.
#
# The local numbers in this directory use a file object store, where an object
# costs a create + sync_data + hard_link (~2.3 ms). On S3 it costs a PUT round
# trip, and both changes are about how many bytes and objects reach the store, so
# this is the measurement that decides how much they actually matter.
#
# Run ON the metal box, with an S3 bucket and credentials already in place:
#
#   CATS_BENCH_S3_BUCKET=my-temp-bucket AWS_REGION=us-east-1 \
#     experiments/vhost-user-blk-frontend-20260726/metal-storage-cost.sh
#
# Writes raw/metal-storage-cost.log. Leaves objects under `bench/` in the bucket;
# delete the bucket when done.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
raw="$here/raw"
mkdir -p "$raw"
out="$raw/metal-storage-cost.log"

: "${CATS_BENCH_S3_BUCKET:?set CATS_BENCH_S3_BUCKET to a bucket this run may write to}"
export CATS_BENCH_S3_BUCKET
export AWS_REGION="${AWS_REGION:-us-east-1}"

cd "$repo"

{
  echo "date_utc: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "uname: $(uname -srm)"
  echo "cpus: $(nproc)"
  echo "memory_kb: $(awk '/MemTotal/ {print $2}' /proc/meminfo)"
  echo "instance_type: $(curl -s --max-time 2 -H "X-aws-ec2-metadata-token: $(curl -sX PUT --max-time 2 -H 'X-aws-ec2-metadata-token-ttl-seconds: 60' http://169.254.169.254/latest/api/token || true)" http://169.254.169.254/latest/meta-data/instance-type || echo unknown)"
  echo "rustc: $(rustc --version)"
  echo "bucket: $CATS_BENCH_S3_BUCKET"
  echo "region: $AWS_REGION"
  echo
} > "$out"

echo "== building (release)"
cargo build --release --workspace --all-targets 2>&1 | tail -2

# The same two benches as the local runs, only the object store differs. Serial and
# single-threaded so one measurement never competes with another for bandwidth.
for bench in commit_cost golden_root_cost; do
  echo "== $bench against s3://$CATS_BENCH_S3_BUCKET"
  {
    echo "### $bench (CATS_BENCH_S3_BUCKET=$CATS_BENCH_S3_BUCKET)"
    cargo test --release -p cats-blockd --test "$bench" -- \
      --ignored --nocapture --test-threads=1 2>&1 |
      grep -vE '^\s*(Compiling|Finished|Running|warning)' |
      sed -E 's/\x1b\[[0-9;]*m//g' |
      grep -vE 'INFO|DEBUG|TRACE'
    echo
  } >> "$out"
done

# A control: the same two benches against a local file store on this machine, so
# the S3 column can be read against the same CPU and the same code.
echo "== control: same benches against a local file store"
{
  echo "### control: local file object store on the same machine"
  for bench in commit_cost golden_root_cost; do
    echo "-- $bench"
    env -u CATS_BENCH_S3_BUCKET cargo test --release -p cats-blockd --test "$bench" -- \
      --ignored --nocapture --test-threads=1 2>&1 |
      grep -vE '^\s*(Compiling|Finished|Running|warning)' |
      sed -E 's/\x1b\[[0-9;]*m//g' |
      grep -vE 'INFO|DEBUG|TRACE'
  done
  echo
} >> "$out"

echo "== wrote $out"
