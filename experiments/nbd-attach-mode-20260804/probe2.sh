#!/bin/bash
# issue #79 probe v2: netlink vs ioctl, holder vs no holder.
exec > /tmp/probe2.log 2>&1

IMG=/tmp/probe.img
[ -f $IMG ] || dd if=/dev/zero of=$IMG bs=1M count=64 status=none

start_server() {
  SOCK=/tmp/nbd-$1.sock
  CONF=/tmp/nbd-$1.conf
  rm -f $SOCK
  printf '[generic]\n    unixsock = %s\n[cats]\n    exportname = %s\n' $SOCK $IMG > $CONF
  nbd-server -C $CONF
  for i in $(seq 20); do [ -S $SOCK ] && break; sleep 0.2; done
  SRV=$(pgrep -f "nbd-server -C $CONF" | head -1)
  [ -n "$SRV" ] && [ -S $SOCK ] || { echo "SERVER FAILED TO START"; return 1; }
  echo "server_pid=$SRV socket=$SOCK"
}

attrs() {
  N=$1
  echo "  pid_attr=$([ -e /sys/block/nbd$N/pid ] && echo present || echo absent) \
pid_value=$(cat /sys/block/nbd$N/pid 2>/dev/null || echo none) \
size=$(cat /sys/block/nbd$N/size 2>/dev/null)"
  P=$(cat /sys/block/nbd$N/pid 2>/dev/null)
  if [ -n "$P" ]; then
    if [ -d /proc/$P ]; then
      echo "  pid_alive=YES comm=$(cat /proc/$P/comm 2>/dev/null) state=$(awk '{print $3}' /proc/$P/stat)"
    else
      echo "  pid_alive=NO"
    fi
  fi
  echo "  resident_nbd_clients=[$(pgrep -a nbd-client | tr '\n' ';')]"
  S=$(date +%s%N); cat /sys/block/nbd$N/pid /sys/block/nbd$N/size >/dev/null 2>&1; E=$(date +%s%N)
  echo "  attr_read_ms=$(( (E-S)/1000000 ))"
}

# $1=device number  $2=netlink|ioctl  $3=hold|nohold
run_case() {
  N=$1; MODE=$2; HOLD=$3
  DEV=/dev/nbd$N
  echo ""
  echo "############ nbd$N mode=$MODE $HOLD ############"
  start_server $N || return
  FLAG=""; [ "$MODE" = ioctl ] && FLAG="-nonetlink"
  nbd-client $FLAG -unix $SOCK $DEV -b 512 -N cats 2>&1 | tail -2
  sleep 1
  echo "[attached, server alive]"; attrs $N
  dd if=$DEV of=/dev/null bs=4096 count=1 iflag=direct status=none && echo "  direct_read_healthy=ok"

  HOLDER=""
  if [ "$HOLD" = hold ]; then
    setsid sleep 900 < $DEV &
    HOLDER=$!
    sleep 0.5
    echo "  holder_pid=$HOLDER (stands in for Cloud Hypervisor holding the disk open)"
  fi

  kill -9 $SRV; sleep 3
  echo "[server SIGKILLed]"; attrs $N

  # fresh offset + O_DIRECT: never served from the page cache
  setsid dd if=$DEV of=/dev/null bs=4096 count=1 skip=$((RANDOM+1000)) iflag=direct status=none &
  R=$!
  sleep 5
  if [ -d /proc/$R ]; then
    echo "  reader_state=$(awk '{print $3}' /proc/$R/stat) (D = uninterruptible)"
    kill -9 $R; sleep 3
    [ -d /proc/$R ] && echo "  reader_survived_SIGKILL=YES state=$(awk '{print $3}' /proc/$R/stat)" \
                    || echo "  reader_survived_SIGKILL=no"
  else
    echo "  reader_finished=yes (device did NOT block)"
  fi

  S=$(date +%s%N); timeout 60 nbd-client -d $DEV >/dev/null 2>&1; RC=$?; E=$(date +%s%N)
  echo "[nbd-client -d rc=$RC in $(( (E-S)/1000000 ))ms]"
  for i in $(seq 50); do
    sleep 0.2
    [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ] && \
      { echo "  settled_ms=$((i*200))"; break; }
  done
  attrs $N

  if [ -n "$HOLDER" ]; then
    kill -9 $HOLDER 2>/dev/null; sleep 2
    echo "[holder released]"
    for i in $(seq 25); do
      sleep 0.2
      [ ! -e /sys/block/nbd$N/pid ] && [ "$(cat /sys/block/nbd$N/size)" = 0 ] && \
        { echo "  settled_after_release_ms=$((i*200))"; break; }
    done
    attrs $N
  fi

  echo "[reuse: can a new attach take this device?]"
  start_server 9$N || return
  if timeout 30 nbd-client $FLAG -unix $SOCK $DEV -b 512 -N cats >/dev/null 2>&1; then
    echo "  reattach=ok"
    dd if=$DEV of=/dev/null bs=4096 count=1 iflag=direct status=none && echo "  read_after_reuse=ok"
    nbd-client -d $DEV >/dev/null 2>&1
  else
    echo "  reattach=FAILED"
  fi
  pkill -9 -f "nbd-server -C /tmp/nbd-9$N.conf"
}

run_case 0 netlink hold
run_case 1 netlink nohold
run_case 2 ioctl   hold
run_case 3 ioctl   nohold
echo ""
echo "PROBE2 DONE"
