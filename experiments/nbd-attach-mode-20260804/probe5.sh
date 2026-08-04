#!/bin/bash
exec > /tmp/probe5.log 2>&1
IMG=/tmp/probe.img
pkill -9 -x nbd-server; pkill -9 -x nbd-client; sleep 1

# ioctl mode only: the proposed production default.
run() {
  N=$1; WHAT=$2; HOLD=$3; DEV=/dev/nbd$N
  SOCK=/tmp/p5-$N.sock; CONF=/tmp/p5-$N.conf; rm -f $SOCK
  printf '[generic]\n    unixsock = %s\n[cats]\n    exportname = %s\n' $SOCK $IMG > $CONF
  nbd-server -C $CONF; for i in $(seq 20); do [ -S $SOCK ] && break; sleep 0.2; done
  echo ""
  echo "############ nbd$N ioctl :: kill=$WHAT hold=$HOLD ############"
  nbd-client -nonetlink -unix $SOCK $DEV -b 512 -N cats >/dev/null 2>&1
  sleep 1
  dd if=$DEV of=/dev/null bs=4096 count=1 skip=1000 iflag=direct status=none && echo "healthy_read=ok"
  CLIENT=$(cat /sys/block/nbd$N/pid)
  echo "healthy: pid=$CLIENT alive=$([ -d /proc/$CLIENT ] && echo YES) comm=$(cat /proc/$CLIENT/comm) size=$(cat /sys/block/nbd$N/size)"
  H=""; if [ "$HOLD" = hold ]; then setsid sleep 900 < $DEV & H=$!; sleep 0.5; echo "holder=$H"; fi

  case $WHAT in
    client) kill -9 $CLIENT ;;                                   # systemd kills the agent's children
    both)   kill -9 $CLIENT; pkill -9 -x nbd-server ;;           # KillMode=control-group
    server) pkill -9 -x nbd-server ;;
  esac
  sleep 4
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  echo "after: pid=[$P] alive=$([ -n "$P" ] && ([ -d /proc/$P ] && echo YES || echo NO) || echo n/a) size=$(cat /sys/block/nbd$N/size) servers=$(pgrep -c -x nbd-server) clients=$(pgrep -c -x nbd-client)"
  if [ -n "$P" ] && [ ! -d /proc/$P ] && [ "$(cat /sys/block/nbd$N/size)" != 0 ]; then
    echo "  VERDICT=LEAKED (dead pid + non-zero size: exactly what the detector looks for)"
  elif [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ]; then
    echo "  VERDICT=SELF-CLEANED"
  else
    echo "  VERDICT=other"
  fi

  echo "--- reclaim ---"
  S=$(date +%s%N); timeout 60 nbd-client -d $DEV >/dev/null 2>&1; echo "  rc=$? in $(( ($(date +%s%N)-S)/1000000 ))ms"
  for i in $(seq 50); do sleep 0.2
    [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ] && { echo "  settled_ms=$((i*200))"; break; }
  done
  echo "  after_reclaim: pid_attr=$([ -e /sys/block/nbd$N/pid ] && echo present || echo absent) size=$(cat /sys/block/nbd$N/size)"
  if [ -n "$H" ]; then
    kill -9 $H 2>/dev/null; sleep 1
    for i in $(seq 25); do sleep 0.2
      [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ] && { echo "  settled_after_holder_ms=$((i*200))"; break; }
    done
    echo "  after_holder: pid_attr=$([ -e /sys/block/nbd$N/pid ] && echo present || echo absent) size=$(cat /sys/block/nbd$N/size)"
  fi

  echo "--- reuse ---"
  pkill -9 -x nbd-server; sleep 1; rm -f $SOCK
  nbd-server -C $CONF; for i in $(seq 20); do [ -S $SOCK ] && break; sleep 0.2; done
  nbd-client -nonetlink -unix $SOCK $DEV -b 512 -N cats >/dev/null 2>&1
  sleep 2
  echo "  size_after_reattach=$(cat /sys/block/nbd$N/size)"
  dd if=$DEV of=/dev/null bs=4096 count=1 skip=1000 iflag=direct status=none && echo "  reuse_read=ok" || echo "  reuse_read=FAILED"
  nbd-client -d $DEV >/dev/null 2>&1; pkill -9 -x nbd-server; sleep 1
}

run 6 client nohold
run 7 both   nohold
run 8 both   hold
run 9 server hold
echo ""; echo "PROBE5 DONE"
