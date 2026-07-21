#!/usr/bin/env python3
"""Apply process_madvise to every VMA backed by one exact file."""

from __future__ import annotations

import ctypes
import errno
import json
import os
import pathlib
import sys
import time


SYS_PIDFD_OPEN = 434
SYS_PROCESS_MADVISE = 440
MADV_PAGEOUT = 21
MAX_IOV_BYTES = 1 << 30
POPULATE_READ_BYTES = 1 << 20


class IOVec(ctypes.Structure):
    _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]


def pidfd_open(pid: int) -> int:
    if hasattr(os, "pidfd_open"):
        return os.pidfd_open(pid)
    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(SYS_PIDFD_OPEN, pid, 0)
    if result < 0:
        value = ctypes.get_errno()
        raise OSError(value, os.strerror(value))
    return int(result)


def matching_ranges(pid: int, target: pathlib.Path) -> list[tuple[int, int]]:
    result = []
    with open(f"/proc/{pid}/maps", encoding="utf-8") as stream:
        for line in stream:
            fields = line.rstrip().split(maxsplit=5)
            if len(fields) != 6:
                continue
            try:
                mapped = pathlib.Path(fields[5]).resolve()
            except OSError:
                continue
            if mapped != target:
                continue
            start_text, end_text = fields[0].split("-", 1)
            result.append((int(start_text, 16), int(end_text, 16)))
    return result


def advise(pidfd: int, start: int, length: int, advice: int) -> int:
    libc = ctypes.CDLL(None, use_errno=True)
    advised = 0
    while advised < length:
        size = min(MAX_IOV_BYTES, length - advised)
        iovec = IOVec(ctypes.c_void_p(start + advised), size)
        result = libc.syscall(
            SYS_PROCESS_MADVISE,
            pidfd,
            ctypes.byref(iovec),
            1,
            advice,
            0,
        )
        if result < 0:
            value = ctypes.get_errno()
            raise OSError(value, os.strerror(value))
        if result == 0:
            raise OSError(errno.EIO, "process_madvise made no progress")
        advised += int(result)
    return advised


def populate(pid: int, ranges: list[tuple[int, int]]) -> int:
    """Fault the target VMAs in without changing the remote process."""
    total = 0
    descriptor = os.open(f"/proc/{pid}/mem", os.O_RDONLY)
    try:
        for start, end in ranges:
            offset = start
            while offset < end:
                size = min(POPULATE_READ_BYTES, end - offset)
                data = os.pread(descriptor, size, offset)
                if not data:
                    raise OSError(errno.EIO, "process memory read made no progress")
                offset += len(data)
                total += len(data)
    finally:
        os.close(descriptor)
    return total


def main() -> int:
    if len(sys.argv) != 4 or sys.argv[3] not in {"pageout", "populate"}:
        print(f"usage: {sys.argv[0]} PID BACKING_FILE {{pageout|populate}}", file=sys.stderr)
        return 2

    pid = int(sys.argv[1])
    target = pathlib.Path(sys.argv[2]).resolve(strict=True)
    action = sys.argv[3]
    ranges = matching_ranges(pid, target)
    if not ranges:
        raise SystemExit(f"no mapping for {target} in pid {pid}")

    started = time.monotonic_ns()
    if action == "populate":
        total = populate(pid, ranges)
    else:
        total = 0
        descriptor = pidfd_open(pid)
        try:
            for start, end in ranges:
                total += advise(descriptor, start, end - start, MADV_PAGEOUT)
            os.sync()
            # A second pass reclaims clean pages where the mapping topology
            # permits it. The caller may additionally use cgroup memory.reclaim
            # for pages shared by the VMM and a vhost-user backend.
            for start, end in ranges:
                advise(descriptor, start, end - start, MADV_PAGEOUT)
        finally:
            os.close(descriptor)

    print(
        json.dumps(
            {
                "action": action,
                "pid": pid,
                "mapping_count": len(ranges),
                "advised_bytes": total,
                "elapsed_ms": round((time.monotonic_ns() - started) / 1_000_000, 3),
            },
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
