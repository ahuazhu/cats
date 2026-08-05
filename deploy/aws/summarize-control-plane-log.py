#!/usr/bin/env python3
"""Stream control-plane logs as non-sensitive, fixed-size diagnostic records."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys


MAX_LINE_BYTES = 64 * 1024
CATEGORIES = {
    "error": re.compile(rb"\b(error|failed|failure|panic|fatal)\b", re.IGNORECASE),
    "health": re.compile(rb"\bhealth\b", re.IGNORECASE),
    "leadership": re.compile(rb"\b(leader|leadership|advisory lock)\b", re.IGNORECASE),
    "postgres": re.compile(rb"\b(postgres|database|connection)\b", re.IGNORECASE),
    "shutdown": re.compile(rb"\b(shutdown|signal|sigterm|terminat)\w*\b", re.IGNORECASE),
}
TIMESTAMP = re.compile(rb"^\d{4}-\d{2}-\d{2}T[^ ]+")
SEVERITY = re.compile(rb"\b(TRACE|DEBUG|INFO|WARN|ERROR)\b", re.IGNORECASE)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-line-bytes", type=int, default=MAX_LINE_BYTES)
    args = parser.parse_args()
    if args.max_line_bytes <= 0:
        parser.error("--max-line-bytes must be greater than zero")

    # readline's size cap also bounds memory if an application emits a single
    # unterminated or attacker-controlled log line. Long lines are represented
    # as multiple digest records; the raw bytes never reach retained evidence.
    while line := sys.stdin.buffer.readline(args.max_line_bytes + 1):
        segmented = len(line) > args.max_line_bytes
        line = line.rstrip(b"\r\n")
        timestamp_match = TIMESTAMP.search(line)
        severity_match = SEVERITY.search(line)
        record = {
            "timestamp": (
                timestamp_match.group().decode("ascii", errors="replace")
                if timestamp_match
                else None
            ),
            "severity": (
                severity_match.group().decode("ascii", errors="replace").upper()
                if severity_match
                else None
            ),
            "categories": [
                name for name, pattern in CATEGORIES.items() if pattern.search(line)
            ],
            "message_bytes": len(line),
            "message_sha256": hashlib.sha256(line).hexdigest(),
            "line_segmented": segmented,
        }
        print(json.dumps(record, sort_keys=True, separators=(",", ":")), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
