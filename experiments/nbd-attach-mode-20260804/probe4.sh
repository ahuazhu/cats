#!/bin/bash
exec > /tmp/probe4.log 2>&1
IMG=/tmp/probe.img
pkill -9 -x nbd-server; sleep 1

run() {
  N=$1; MODE=$2; DEV=/dev/nbd$N
  SOCK=/tmp/p4-$N.sock; CONF=/tmp/p4-$N.conf; rm -f $SOCK
  printf '[generic]\n    unixsock = %s\n[cats]\n    exportname = %s\n' $SOCK $IMG > $CONF
  nbd-server -C $CONF; for i in $(seq 20); do [ -S $SOCK ] && break; sleep 0.2; done
  FLAG=""; [ $MODE = ioctl ] && FLAG="-nonetlink"
  echo ""
  echo "############ nbd$N mode=$MODE ############"
  nbd-client $FLAG -unix $SOCK $DEV -b 512 -N cats >/dev/null 2>&1
  sleep 1
  dd if=$DEV of=/dev/null bs=4096 count=1 skip=1000 iflag=direct status=none && echo "healthy_read=ok"
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  echo "healthy: pid=$P alive=$([ -d /proc/$P ] && echo YES || echo NO) size=$(cat /sys/block/nbd$N/size) nbd_clients=[$(pgrep -c nbd-client)] nbd_servers=[$(pgrep -c -x nbd-server)]"

  echo "--- kill EVERY nbd-server (master and the forked connection child) ---"
  pkill -9 -x nbd-server; sleep 4
  echo "remaining_servers=$(pgrep -c -x nbd-server)"
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  echo "after_death: pid=[$P] alive=$([ -n "$P" ] && ([ -d /proc/$P ] && echo YES || echo NO) || echo n/a) size=$(cat /sys/block/nbd$N/size) resident_clients=[$(pgrep -a nbd-client | tr '\n' ';')]"

  echo "--- O_DIRECT read of a dead-server device ---"
  setsid dd if=$DEV of=/dev/null bs=4096 count=1 skip=2000 iflag=direct status=none 2>/tmp/dd$N.err &
  R=$!
  sleep 8
  if [ -d /proc/$R ]; then
    echo "  read_state=$(awk '{print $3}' /proc/$R/stat) wchan=$(cat /proc/$R/wchan 2>/dev/null)  <== BLOCKED"
    kill -9 $R; sleep 3
    [ -d /proc/$R ] && echo "  survived_SIGKILL=YES state=$(awk '{print $3}' /proc/$R/stat)" || echo "  survived_SIGKILL=no"
  else
    echo "  read_returned err=[$(cat /tmp/dd$N.err | tr '\n' ' ')]"
  fi

  echo "--- sysfs attribute read on the dead device ---"
  S=$(date +%s%N); cat /sys/block/nbd$N/pid /sys/block/nbd$N/size >/dev/null 2>&1; E=$(date +%s%N)
  echo "  attr_read_ms=$(( (E-S)/1000000 ))"

  echo "--- nbd-client -d ---"
  S=$(date +%s%N); timeout 60 nbd-client -d $DEV >/dev/null 2>&1; RC=$?; E=$(date +%s%N)
  echo "  rc=$RC in $(( (E-S)/1000000 ))ms"
  for i in $(seq 50); do sleep 0.2
    [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ] && { echo "  settled_ms=$((i*200))"; break; }
  done
  echo "  final: pid_attr=$([ -e /sys/block/nbd$N/pid ] && echo present || echo absent) size=$(cat /sys/block/nbd$N/size)"

  echo "--- reuse after reclaim ---"
  rm -f $SOCK; nbd-server -C $CONF; for i in $(seq 20); do [ -S $SOCK ] && break; sleep 0.2; done
  if timeout 30 nbd-client $FLAG -unix $SOCK $DEV -b 512 -N cats >/dev/null 2>&1; then
    dd if=$DEV of=/dev/null bs=4096 count=1 skip=1000 iflag=direct status=none && echo "  reuse=ok"
  else echo "  reuse=FAILED"; fi
  nbd-client -d $DEV >/dev/null 2>&1; pkill -9 -x nbd-server; sleep 1
}

run 4 netlink
run 5 ioctl
echo ""; echo "PROBE4 DONE"
