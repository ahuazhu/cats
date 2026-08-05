#!/usr/bin/env python3
"""Continuously retain a bounded first-and-latest window of JSONL evidence."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import deque
from pathlib import Path


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def atomic_write(path: Path, lines: list[bytes]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("wb") as output:
        output.writelines(lines)
    temporary.replace(path)


def truncated_record(raw: bytes) -> bytes:
    return json.dumps(
        {
            "record_truncated": True,
            "source_bytes": len(raw),
            "source_sha256": hashlib.sha256(raw).hexdigest(),
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode() + b"\n"


def canonical_line(raw: bytes, maximum: int) -> bytes:
    if len(raw) > maximum:
        return truncated_record(raw)
    value = json.loads(raw)
    canonical = (
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode() + b"\n"
    )
    return canonical if len(canonical) <= maximum else truncated_record(raw)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-lines", required=True, type=positive_int)
    parser.add_argument("--max-bytes", required=True, type=positive_int)
    parser.add_argument("--max-record-bytes", type=positive_int, default=64 * 1024)
    args = parser.parse_args()
    if args.max_lines < 3:
        parser.error("--max-lines must allow first, truncation, and latest records")
    if args.max_bytes < 256:
        parser.error("--max-bytes must be at least 256")
    args.output.parent.mkdir(parents=True, exist_ok=True)

    first: bytes | None = None
    latest: deque[bytes] = deque()
    latest_bytes = 0
    seen = 0
    omitted = 0
    for raw in sys.stdin.buffer:
        try:
            line = canonical_line(
                raw, min(args.max_record_bytes, args.max_bytes // 3)
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            print(f"invalid JSONL evidence: {error}", file=sys.stderr)
            return 1
        seen += 1
        if first is None:
            first = line
        else:
            latest.append(line)
            latest_bytes += len(line)

        marker = json.dumps(
            {"evidence_truncated": True, "omitted_records": omitted},
            sort_keys=True,
            separators=(",", ":"),
        ).encode() + b"\n"
        while latest and (
            1 + len(latest) > args.max_lines
            or len(first or b"") + latest_bytes > args.max_bytes
        ):
            latest_bytes -= len(latest.popleft())
            omitted += 1
        if omitted:
            marker = json.dumps(
                {"evidence_truncated": True, "omitted_records": omitted},
                sort_keys=True,
                separators=(",", ":"),
            ).encode() + b"\n"
            while latest and (
                2 + len(latest) > args.max_lines
                or len(first or b"") + len(marker) + latest_bytes > args.max_bytes
            ):
                latest_bytes -= len(latest.popleft())
                omitted += 1
                marker = json.dumps(
                    {"evidence_truncated": True, "omitted_records": omitted},
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode() + b"\n"

        retained = [] if first is None else [first]
        if omitted:
            retained.append(marker)
        retained.extend(latest)
        atomic_write(args.output, retained)

    if seen == 0:
        print("bounded JSONL stream received no calibrated record", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
