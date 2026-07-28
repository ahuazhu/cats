#!/usr/bin/env python3
"""In-guest probe for what a Cats pause/resume does to the guest's clocks.

Everything goes to stdout, which cats-init has pointed at the serial console, so
the host reads results out of the serial log. No networking, no HTTP, no Java.

Three questions answered in one boot:

CLK   Do the clocks advance across a pause? Sampling all three every 250 ms and
      looking at the delta straddling the pause is the whole answer.
        realtime  CLOCK_REALTIME  -- wall clock, NTP can step it
        mono      CLOCK_MONOTONIC -- what System.nanoTime() and every runtime's
                                     scheduler deadline uses; NTP never steps it
        boot      CLOCK_BOOTTIME  -- like monotonic but counts system suspend
DEADL A thread parked on a deadline that falls *inside* the pause window. How
      long after resume it actually fires is the input to wake_lead_ms.
RATE  A loop using the same next = base + k*period rule that Java's
      ScheduledThreadPoolExecutor uses for fixedRate, so a catch-up burst shows
      up empirically rather than being inferred from the JDK source.
"""

import sys
import threading
import time

TAG_CLK = "CLKPROBE"
TAG_DEADLINE = "DEADLINE"
TAG_RATE = "RATE"
TAG_INFO = "INFO"

SAMPLE_INTERVAL_S = 0.25
RATE_PERIOD_S = 20.0
DEADLINE_AT_S = 45.0     # must land inside the first pause window
RUN_SECONDS = 900


def clocks():
    return (
        time.clock_gettime(time.CLOCK_REALTIME),
        time.clock_gettime(time.CLOCK_MONOTONIC),
        time.clock_gettime(time.CLOCK_BOOTTIME),
    )


def emit(tag, *fields):
    real, mono, boot = clocks()
    line = f"{tag},{real:.4f},{mono:.4f},{boot:.4f}," + ",".join(str(f) for f in fields)
    sys.stdout.write(line + "\n")
    sys.stdout.flush()


def sampler(stop):
    seq = 0
    while not stop.is_set():
        seq += 1
        emit(TAG_CLK, seq)
        time.sleep(SAMPLE_INTERVAL_S)


def deadline_thread(stop):
    """Park on a single deadline that the pause will swallow."""
    start_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
    target_mono = start_mono + DEADLINE_AT_S
    emit(TAG_INFO, "deadline_target_mono", f"{target_mono:.4f}")
    # sleep() is monotonic-based, the same as any runtime's timer.
    remaining = target_mono - time.clock_gettime(time.CLOCK_MONOTONIC)
    if remaining > 0:
        time.sleep(remaining)
    late_mono = time.clock_gettime(time.CLOCK_MONOTONIC) - target_mono
    emit(TAG_DEADLINE, "fired", f"target_mono={target_mono:.4f}",
         f"late_by_mono_s={late_mono:.4f}")


def fixed_rate_thread(stop):
    """Java fixedRate semantics: the next time is previous scheduled + period,
    not now + period. If the clock jumped past several periods, this fires
    repeatedly with no delay until it has caught up -- a burst."""
    base_mono = time.clock_gettime(time.CLOCK_MONOTONIC)
    k = 0
    fires = 0
    while not stop.is_set():
        k += 1
        target = base_mono + k * RATE_PERIOD_S
        now = time.clock_gettime(time.CLOCK_MONOTONIC)
        wait = target - now
        if wait > 0:
            if stop.wait(wait):
                return
        fires += 1
        behind = time.clock_gettime(time.CLOCK_MONOTONIC) - target
        emit(TAG_RATE, f"fire={fires}", f"k={k}",
             f"target_mono={target:.4f}", f"behind_s={behind:.4f}",
             "BURST" if wait <= 0 else "ontime")


def main():
    emit(TAG_INFO, "probe_start", f"sample_interval_s={SAMPLE_INTERVAL_S}",
         f"rate_period_s={RATE_PERIOD_S}", f"deadline_at_s={DEADLINE_AT_S}")
    try:
        with open("/proc/uptime") as f:
            emit(TAG_INFO, "guest_uptime_at_start", f.read().strip().split()[0])
    except OSError:
        pass

    stop = threading.Event()
    threads = [
        threading.Thread(target=sampler, args=(stop,), daemon=True),
        threading.Thread(target=deadline_thread, args=(stop,), daemon=True),
        threading.Thread(target=fixed_rate_thread, args=(stop,), daemon=True),
    ]
    for t in threads:
        t.start()
    time.sleep(RUN_SECONDS)
    stop.set()
    emit(TAG_INFO, "probe_end")


if __name__ == "__main__":
    main()
