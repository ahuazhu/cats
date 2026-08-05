#!/usr/bin/env python3
"""Wait for the fixed-rate probe's first complete, sanitized healthy result."""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path


SAFE_HEADER_NAMES = {"server", "via", "x-amz-cf-id", "x-amzn-trace-id", "x-cache"}
HEADER_POLICY = "cats-ha-safe-headers-v1"


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def validate_baseline(output_dir: Path) -> bool:
    result_path = output_dir / "partial-results" / "attempt-0001.json"
    if not result_path.is_file() or result_path.stat().st_size == 0:
        return False
    try:
        result = json.loads(result_path.read_text(encoding="utf-8"))
        if (
            result.get("attempt") != 1
            or result.get("status") != "completed"
            or result.get("curl_exit") != 0
            or result.get("failure_reasons") != []
            or result.get("header_policy") != HEADER_POLICY
        ):
            return False
        header_relative = Path(str(result["headers"]))
        if header_relative.is_absolute() or ".." in header_relative.parts:
            return False
        headers = json.loads(
            (output_dir / header_relative).read_text(encoding="utf-8")
        )
        if headers.get("policy") != HEADER_POLICY:
            return False
        retained = headers.get("headers")
        return isinstance(retained, dict) and set(retained) <= SAFE_HEADER_NAMES
    except (OSError, TypeError, ValueError, KeyError, json.JSONDecodeError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-pid", required=True, type=positive_int)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--timeout-seconds", type=positive_int, default=10)
    args = parser.parse_args()
    deadline = time.monotonic() + args.timeout_seconds
    while True:
        if validate_baseline(args.output_dir):
            print("fixed-rate public probe established a sanitized healthy baseline")
            return 0
        try:
            os.kill(args.probe_pid, 0)
        except ProcessLookupError:
            parser.exit(1, "public probe exited before its healthy baseline\n")
        except PermissionError:
            parser.exit(1, "cannot verify the public probe process\n")
        if time.monotonic() >= deadline:
            parser.exit(124, "public probe baseline readiness timed out\n")
        time.sleep(0.05)


if __name__ == "__main__":
    raise SystemExit(main())
