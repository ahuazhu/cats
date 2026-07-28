#!/usr/bin/env python3
"""Sample the guest's nearest pending hrtimer deadline.

Answers whether "timer-aware wake" is feasible: a host that wants to suspend a
guest but re-wake it in time for the guest's own timers must read the nearest
deadline. If that value is dominated by sub-second kernel and JVM housekeeping
timers, the signal is useless for that purpose -- which is exactly what this
sampler is here to measure.

/proc/timer_list is root-only and gives no pid attribution, but the callback
function name classifies the source, which is the part that matters:

  hrtimer_wakeup   a task blocked in schedule_hrtimeout -- epoll_wait timeout,
                   nanosleep, futex timeout. This is where JVM/Go/Node internal
                   schedulers land, and it is the category a host cannot attribute.
  timerfd_tmrproc  timerfd, attributable via /proc/<pid>/fdinfo
  posix_timer_fn   POSIX interval timer, attributable via /proc/<pid>/timers
  tick_sched_timer kernel tick
  *                other kernel housekeeping

Emits one CSV row per sample: the nearest deadline overall plus the nearest per
category, so the report can say how far out the nearest *attributable* timer is
versus the nearest timer of any kind.
"""

import argparse
import csv
import re
import sys
import time

EXPIRY = re.compile(r"^\s*#\d+:\s*<[0-9a-fx]+>,\s*([^,]+),")
IN_NSECS = re.compile(r"\[in (-?\d+) nsecs\]")

CATEGORIES = ["hrtimer_wakeup", "timerfd_tmrproc", "posix_timer_fn", "tick_sched_timer", "other"]


def classify(fn):
    fn = fn.strip()
    return fn if fn in CATEGORIES else "other"


def sample():
    """Return {category: nearest_positive_ns} plus the overall nearest."""
    nearest = {}
    current = None
    try:
        with open("/proc/timer_list", encoding="utf-8", errors="replace") as stream:
            for line in stream:
                match = EXPIRY.match(line)
                if match:
                    current = classify(match.group(1))
                    continue
                found = IN_NSECS.search(line)
                if found and current:
                    delta = int(found.group(1))
                    # Already-expired timers say nothing about the future.
                    if delta > 0:
                        prior = nearest.get(current)
                        if prior is None or delta < prior:
                            nearest[current] = delta
                    current = None
    except PermissionError:
        print("need root to read /proc/timer_list", file=sys.stderr)
        raise SystemExit(2)
    return nearest


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", required=True)
    parser.add_argument("--seconds", type=int, default=300)
    parser.add_argument("--interval", type=float, default=1.0)
    parser.add_argument("--label", default="")
    args = parser.parse_args()

    columns = ["label", "wall_ms", "nearest_ns"] + [f"nearest_{name}_ns" for name in CATEGORIES]
    with open(args.out, "w", newline="", encoding="utf-8") as handle:
        writer = csv.writer(handle)
        writer.writerow(columns)
        deadline = time.monotonic() + args.seconds
        while time.monotonic() < deadline:
            nearest = sample()
            overall = min(nearest.values()) if nearest else -1
            writer.writerow(
                [args.label, int(time.time() * 1000), overall]
                + [nearest.get(name, -1) for name in CATEGORIES]
            )
            handle.flush()
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
