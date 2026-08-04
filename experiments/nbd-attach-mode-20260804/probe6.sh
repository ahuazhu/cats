#!/bin/bash
# The real thing: cats-blockd as the NBD server, both attach modes.
exec > /tmp/probe6.log 2>&1
BLOCKD=/home/ubuntu/cats/target/debug/cats-blockd
pkill -9 -x nbd-client; pkill -9 -x cats-blockd; sleep 1

start_blockd() {
  R=/tmp/b$1; rm -rf $R; mkdir -p $R/data $R/blob
  $BLOCKD --volume-id vol_p$1 --attachment-id att_p$1 --lease-ttl-ms 5000 \
    --data-dir $R/data --metadata-store-adapter sqlite \
    --metadata-store-option path=$R/meta.db \
    --object-store-adapter file --object-store-option root=$R/blob \
    --listen-unix $R/nbd.sock --create-volume-size $((1024*1024*1024)) \
    > $R/blockd.log 2>&1 &
  BPID=$!
  for i in $(seq 100); do [ -S $R/nbd.sock ] && break; sleep 0.2; done
  sleep 1
  [ -S $R/nbd.sock ] && echo "blockd_pid=$BPID sock=$R/nbd.sock" || { echo "BLOCKD FAILED"; tail -5 $R/blockd.log; return 1; }
}

bench() {
  N=$1; MODE=$2; DEV=/dev/nbd$N
  start_blockd $N || return
  FLAG=""; [ $MODE = ioctl ] && FLAG="-nonetlink"
  echo ""; echo "########## cats-blockd on nbd$N mode=$MODE ##########"
  nbd-client $FLAG -unix /tmp/b$N/nbd.sock $DEV -b 512 -N "" >/dev/null 2>&1 || { echo attach_failed; return; }
  sleep 1
  P=$(cat /sys/block/nbd$N/pid); echo "attached: pid=$P alive=$([ -d /proc/$P ] && echo YES || echo NO) size=$(cat /sys/block/nbd$N/size)"

  echo "--- throughput, O_DIRECT (this is the number ADR-0015 cares about) ---"
  for run in 1 2; do
    echo -n "  seq_write_256MiB_run$run: "
    dd if=/dev/zero of=$DEV bs=1M count=256 oflag=direct conv=fsync 2>&1 | tail -1
  done
  echo -n "  seq_read_256MiB: "
  dd if=$DEV of=/dev/null bs=1M count=256 iflag=direct 2>&1 | tail -1
  if command -v fio >/dev/null; then
    echo "  --- 4k random write, qd32 ---"
    fio --name=rw --filename=$DEV --rw=randwrite --bs=4k --iodepth=32 --ioengine=libaio \
        --direct=1 --size=256M --runtime=20 --time_based --group_reporting --minimal 2>/dev/null \
        | awk -F';' '{print "  fio_write_KiBps="$47" iops="$49" lat_us_mean="$81}'
  fi

  echo "--- now leak it: kill blockd while the device is held open (production shape) ---"
  setsid sleep 900 < $DEV & H=$!
  sleep 0.5
  kill -9 $BPID; sleep 4
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  echo "  after_blockd_death: pid=[$P] alive=$([ -n "$P" ] && ([ -d /proc/$P ] && echo YES || echo NO) || echo n/a) size=$(cat /sys/block/nbd$N/size)"
  if [ -n "$P" ] && [ ! -d /proc/$P ] && [ "$(cat /sys/block/nbd$N/size)" != 0 ]; then
    echo "  DETECTOR=would flag this device as leaked"
  elif [ ! -e /sys/block/nbd$N/pid ]; then
    echo "  DETECTOR=nothing to flag, kernel already released it"
  else
    echo "  DETECTOR=INDISTINGUISHABLE FROM HEALTHY  <-- detector is blind in this mode"
  fi
  kill -9 $H 2>/dev/null; sleep 2
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  echo "  after_holder_gone: pid=[$P] size=$(cat /sys/block/nbd$N/size)"
  nbd-client -d $DEV >/dev/null 2>&1; sleep 1
  echo "  after_reclaim: pid_attr=$([ -e /sys/block/nbd$N/pid ] && echo present || echo absent) size=$(cat /sys/block/nbd$N/size)"
  pkill -9 -x cats-blockd; sleep 1
}

bench 0 netlink
bench 1 ioctl
echo ""; echo "PROBE6 DONE"
