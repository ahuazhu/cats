#!/usr/bin/env python3
"""Calibrate bounded stream retention and non-sensitive log summaries."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bounded-jsonl", required=True, type=Path)
    parser.add_argument("--log-summarizer", required=True, type=Path)
    args = parser.parse_args()
    sentinel = "CATS_SECRET_MUST_NOT_ESCAPE"
    try:
        with tempfile.TemporaryDirectory(prefix="cats-ha-boundary-") as directory:
            output = Path(directory) / "timeline.jsonl"
            source = "".join(
                json.dumps({"sequence": index, "safe": "x" * 20}) + "\n"
                for index in range(20)
            )
            bounded = subprocess.run(
                [
                    sys.executable,
                    str(args.bounded_jsonl),
                    "--output",
                    str(output),
                    "--max-lines",
                    "5",
                    "--max-bytes",
                    "512",
                ],
                input=source,
                capture_output=True,
                text=True,
                check=False,
            )
            if bounded.returncode != 0:
                raise AssertionError(f"bounded stream failed: {bounded.stderr}")
            retained = [json.loads(line) for line in output.read_text().splitlines()]
            if len(retained) > 5 or output.stat().st_size > 512:
                raise AssertionError("bounded stream exceeded its configured limit")
            if retained[0].get("sequence") != 0 or retained[-1].get("sequence") != 19:
                raise AssertionError("bounded stream did not retain first and latest records")
            if not any(record.get("evidence_truncated") for record in retained):
                raise AssertionError("bounded stream omitted no truncation marker")

            oversized_output = Path(directory) / "oversized.jsonl"
            oversized_source = (
                json.dumps({"sequence": 0})
                + "\n"
                + json.dumps({"oversized": "x" * 2_000})
                + "\n"
                + json.dumps({"sequence": 2})
                + "\n"
            )
            oversized = subprocess.run(
                [
                    sys.executable,
                    str(args.bounded_jsonl),
                    "--output",
                    str(oversized_output),
                    "--max-lines",
                    "5",
                    "--max-bytes",
                    "512",
                ],
                input=oversized_source,
                capture_output=True,
                text=True,
                check=False,
            )
            if oversized.returncode != 0 or oversized_output.stat().st_size > 512:
                raise AssertionError(f"oversized stream escaped its bound: {oversized.stderr}")
            oversized_records = [
                json.loads(line) for line in oversized_output.read_text().splitlines()
            ]
            if not any(record.get("record_truncated") for record in oversized_records):
                raise AssertionError("oversized JSONL record was retained verbatim")

            log_source = (
                f"2026-08-05T18:00:00.000Z INFO leadership acquired {sentinel}\n"
                f"2026-08-05T18:00:01.000Z ERROR shutdown failed {sentinel}\n"
            )
            summarized = subprocess.run(
                [sys.executable, str(args.log_summarizer)],
                input=log_source,
                capture_output=True,
                text=True,
                check=False,
            )
            if summarized.returncode != 0:
                raise AssertionError(f"log summarizer failed: {summarized.stderr}")
            if sentinel in summarized.stdout:
                raise AssertionError("raw application log text escaped into evidence")
            records = [json.loads(line) for line in summarized.stdout.splitlines()]
            if len(records) != 2 or not all(record["message_sha256"] for record in records):
                raise AssertionError("log summaries lost their diagnostic digest")
            if "leadership" not in records[0]["categories"]:
                raise AssertionError("log summaries lost the leadership category")
            if not {"error", "shutdown"} <= set(records[1]["categories"]):
                raise AssertionError("log summaries lost failure categories")
            print("evidence boundary: first/latest bounded; raw log sentinel excluded")
            return 0
    except (AssertionError, OSError) as error:
        print(f"evidence boundary fixture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
