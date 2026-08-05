#!/usr/bin/env python3
"""Terminate one explicitly identified process tree within a fixed deadline."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 1:
        raise argparse.ArgumentTypeError("must be a process ID greater than one")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def process_table() -> dict[int, tuple[int, str]]:
    output = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,stat="],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    table: dict[int, tuple[int, str]] = {}
    for line in output.splitlines():
        fields = line.split(None, 2)
        if len(fields) == 3:
            table[int(fields[0])] = (int(fields[1]), fields[2])
    return table


def tree_members(root: int, table: dict[int, tuple[int, str]]) -> list[int]:
    descendants: list[int] = []
    frontier = [root]
    while frontier:
        parent = frontier.pop()
        children = sorted(pid for pid, (ppid, _state) in table.items() if ppid == parent)
        descendants.extend(children)
        frontier.extend(children)
    return descendants


def running(pid: int, table: dict[int, tuple[int, str]]) -> bool:
    entry = table.get(pid)
    return entry is not None and not entry[1].startswith("Z")


def signal_processes(pids: list[int], requested: signal.Signals) -> None:
    for pid in pids:
        try:
            os.kill(pid, requested)
        except ProcessLookupError:
            pass
        except PermissionError as error:
            raise RuntimeError(f"cannot signal evidence process {pid}") from error


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root-pid", required=True, type=positive_int)
    parser.add_argument("--timeout-seconds", type=positive_float, default=2.0)
    args = parser.parse_args()
    protected = {os.getpid(), os.getppid()}
    if args.root_pid in protected:
        parser.error("refusing to terminate the helper or its caller")

    try:
        table = process_table()
        if args.root_pid not in table:
            return 0
        descendants = tree_members(args.root_pid, table)
        targets = list(reversed(descendants)) + [args.root_pid]
        if protected.intersection(targets):
            parser.error("process tree unexpectedly contains the helper or its caller")

        signal_processes(targets, signal.SIGTERM)
        deadline = time.monotonic() + args.timeout_seconds
        while time.monotonic() < deadline:
            table = process_table()
            if not any(running(pid, table) for pid in targets):
                return 0
            time.sleep(0.05)

        table = process_table()
        survivors = [pid for pid in targets if running(pid, table)]
        signal_processes(survivors, signal.SIGKILL)
        kill_deadline = time.monotonic() + 1.0
        while time.monotonic() < kill_deadline:
            table = process_table()
            survivors = [pid for pid in survivors if running(pid, table)]
            if not survivors:
                return 0
            time.sleep(0.05)
        print(f"evidence process tree did not stop: {survivors}", file=sys.stderr)
        return 1
    except (OSError, RuntimeError, subprocess.CalledProcessError, ValueError) as error:
        print(f"could not terminate evidence process tree: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
