#!/usr/bin/env bash
# Guest-visible block performance on a metal host: fio inside a real Cat, on the
# real ext4 root, through whichever block path the node agent is configured for.
#
# Run ON the metal host after deploy/metal/install.sh, once per block path:
#
#   sudo deploy/metal/... # set CATS_BLOCK_PATH_ARGS in /etc/cats/cats.env
#   experiments/vhost-user-blk-frontend-20260726/metal-guest-fio.sh <label>
#
# Emits CSV on stdout and leaves the raw fio JSON in the Cat under /fio-*.json.
set -uo pipefail

label=${1:?usage: metal-guest-fio.sh <label>}
cat_name=${CATS_FIO_CAT:-fio-$label}
export CATS_API_URL=${CATS_API_URL:-http://127.0.0.1:7300}
if [ -z "${CATS_TOKEN:-}" ]; then
  # No [ -r ] test: cats.env is root-only 0600, so the test fails for a normal
  # user even though the read below is sudo. That silently left CATS_TOKEN empty
  # and every measurement in the run failed with "not logged in".
  CATS_TOKEN=$(sudo sed -n 's/^CATS_ADMIN_TOKEN=//p' /etc/cats/cats.env | tail -1)
  export CATS_TOKEN
fi
cli=${CATS:-/opt/cats/bin/cats}

# fio needs a file large enough that the Guest page cache cannot hide the
# device; O_DIRECT keeps it honest anyway.
size=${CATS_FIO_SIZE:-1G}
runtime=${CATS_FIO_RUNTIME:-10}

$cli destroy "$cat_name" >/dev/null 2>&1
$cli create "$cat_name" --root-size 6GiB --cpus 4 --memory 2GiB --no-auto-suspend >/dev/null || {
  echo "could not create $cat_name" >&2
  exit 1
}
# The Guest Agent accepts exec a moment after the Cat reports running.
for _ in $(seq 1 30); do
  $cli exec "$cat_name" -- true >/dev/null 2>&1 && break
  sleep 2
done

queues=$($cli exec "$cat_name" -- sh -c 'ls /sys/block/vda/mq | wc -l' 2>/dev/null | tr -d ' \r\n')
blocksize=$($cli exec "$cat_name" -- sh -c 'cat /sys/block/vda/queue/logical_block_size' 2>/dev/null | tr -d ' \r\n')
echo "# $label: guest hw queues=$queues logical_block_size=$blocksize" >&2

$cli exec "$cat_name" -- sh -c \
  'command -v fio >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get -qq update >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive apt-get -qq install -y fio >/dev/null 2>&1; }; fio --version' \
  >/dev/null 2>&1

echo "path,workload,rw,block,iodepth,iops,mib_per_sec,mean_us,p50_us,p99_us"
run() { # name rw bs depth
  local name=$1 rw=$2 bs=$3 depth=$4
  local json
  json=$($cli exec "$cat_name" -- sh -c "fio --name=$name --filename=/fio.dat --size=$size \
      --direct=1 --ioengine=libaio --rw=$rw --bs=$bs --iodepth=$depth --numjobs=1 \
      --time_based --runtime=$runtime --ramp_time=2 --norandommap --randrepeat=1 \
      --group_reporting --output-format=json" 2>/dev/null)
  printf '%s' "$json" | python3 -c "
import json, sys
report = json.load(sys.stdin)
job = report['jobs'][0]
side = job['write'] if '$rw' in ('write', 'randwrite') else job['read']
pct = side['clat_ns'].get('percentile', {})
print('$label,$name,$rw,$bs,$depth,{:.0f},{:.1f},{:.1f},{:.0f},{:.0f}'.format(
    side['iops'], side['bw_bytes'] / (1024 * 1024), side['clat_ns']['mean'] / 1000,
    pct.get('50.000000', 0) / 1000, pct.get('99.000000', 0) / 1000))
" || echo "$label,$name,$rw,$bs,$depth,,,,,"
}

run randread-4k-qd1 randread 4k 1
run randwrite-4k-qd1 randwrite 4k 1
run randread-4k-qd32 randread 4k 32
run randwrite-4k-qd32 randwrite 4k 32
run seqread-1m-qd1 read 1M 1
run seqwrite-1m-qd1 write 1M 1

$cli destroy "$cat_name" >/dev/null 2>&1
