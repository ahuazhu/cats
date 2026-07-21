#!/usr/bin/env python3
"""Join an existing cgroup v2 before exec so all allocations are charged there."""

from __future__ import annotations

import os
import pathlib
import sys


def main() -> int:
    if len(sys.argv) < 3:
        print(f"usage: {sys.argv[0]} CGROUP COMMAND [ARG ...]", file=sys.stderr)
        return 2
    cgroup = pathlib.Path(sys.argv[1])
    (cgroup / "cgroup.procs").write_text(f"{os.getpid()}\n", encoding="ascii")
    os.execvp(sys.argv[2], sys.argv[2:])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())
