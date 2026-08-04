#!/bin/bash
exec > /tmp/probe7.log 2>&1
BLOCKD=/home/ubuntu/cats/target/debug/cats-blockd
pkill -9 -x nbd-client; pkill -9 -x cats-blockd; sleep 1
for MODE in netlink ioctl netlink ioctl; do
  N=2; R=/tmp/f$RANDOM; rm -rf $R; mkdir -p $R/data $R/blob
  $BLOCKD --volume-id v --attachment-id a --lease-ttl-ms 5000 --data-dir $R/data \
    --metadata-store-adapter sqlite --metadata-store-option path=$R/meta.db \
    --object-store-adapter file --object-store-option root=$R/blob \
    --listen-unix $R/nbd.sock --create-volume-size $((1024*1024*1024)) > $R/log 2>&1 &
  B=$!
  for i in $(seq 100); do [ -S $R/nbd.sock ] && break; sleep 0.2; done; sleep 1
  FLAG=""; [ $MODE = ioctl ] && FLAG="-nonetlink"
  nbd-client $FLAG -unix $R/nbd.sock /dev/nbd$N -b 512 -N "" >/dev/null 2>&1
  sleep 1
  echo "### mode=$MODE"
  fio --name=w --filename=/dev/nbd$N --rw=randwrite --bs=4k --iodepth=32 --ioengine=libaio \
      --direct=1 --size=512M --runtime=25 --time_based --group_reporting 2>/dev/null \
      | grep -E "^  write:|iops" | head -2
  nbd-client -d /dev/nbd$N >/dev/null 2>&1; kill -9 $B 2>/dev/null; sleep 2
done
echo PROBE7 DONE
