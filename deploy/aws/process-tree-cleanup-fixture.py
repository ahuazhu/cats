#!/usr/bin/env python3
"""Prove evidence pipeline cleanup recursively terminates nested processes."""

from __future__ import annotations

import argparse
import subprocess
import sys
import time
from pathlib import Path


def descendants(root: int) -> list[int]:
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
    found: list[int] = []
    frontier = [root]
    while frontier:
        parent = frontier.pop()
        children = [pid for pid, (ppid, _state) in table.items() if ppid == parent]
        found.extend(children)
        frontier.extend(children)
    return found


def alive(pid: int) -> bool:
    result = subprocess.run(
        ["ps", "-o", "stat=", "-p", str(pid)],
        capture_output=True,
        text=True,
        check=False,
    )
    return result.returncode == 0 and not result.stdout.strip().startswith("Z")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--helper", required=True, type=Path)
    args = parser.parse_args()
    root: subprocess.Popen[str] | None = None
    try:
        root = subprocess.Popen(
            [
                "bash",
                "-c",
                "bash -c 'sleep 30 & wait' & wait",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.monotonic() + 3
        observed: list[int] = []
        while time.monotonic() < deadline:
            observed = descendants(root.pid)
            if len(observed) >= 2:
                break
            time.sleep(0.05)
        if len(observed) < 2:
            raise AssertionError("known-positive nested process tree was not observed")
        result = subprocess.run(
            [
                sys.executable,
                str(args.helper),
                "--root-pid",
                str(root.pid),
                "--timeout-seconds",
                "1",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            raise AssertionError(f"tree cleanup failed: {result.stderr}")
        root.wait(timeout=2)
        leaked = [pid for pid in [root.pid, *observed] if alive(pid)]
        if leaked:
            raise AssertionError(f"nested evidence processes survived: {leaked}")
        print("process-tree cleanup: nested pipeline stopped with no orphan")
        return 0
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"process-tree cleanup fixture failed: {error}", file=sys.stderr)
        return 1
    finally:
        if root is not None and root.poll() is None:
            root.kill()
            root.wait(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
