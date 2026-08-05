#!/usr/bin/env python3
"""Probe one public endpoint on a fixed schedule and retain diagnostic evidence.

Requests are scheduled independently of earlier request completion.  A bounded
semaphore prevents an unhealthy endpoint from creating an unbounded process
fan-out, while schedule lag is itself a failure so saturation cannot turn into
a blind interval.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import math
import sys
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import urlsplit


CURL_WRITE_OUT = "\t".join(
    [
        "%{http_code}",
        "%{remote_ip}",
        "%{time_namelookup}",
        "%{time_connect}",
        "%{time_appconnect}",
        "%{time_starttransfer}",
        "%{time_total}",
    ]
)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso8601(value: datetime) -> str:
    return value.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed <= 0:
        raise argparse.ArgumentTypeError("must be greater than zero")
    return parsed


def positive_float(value: str) -> float:
    parsed = float(value)
    if not math.isfinite(parsed) or parsed <= 0:
        raise argparse.ArgumentTypeError("must be a finite number greater than zero")
    return parsed


def endpoint_url(value: str) -> str:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise argparse.ArgumentTypeError("must be an HTTP(S) URL with a hostname")
    if parsed.username is not None or parsed.password is not None:
        raise argparse.ArgumentTypeError("endpoint URL must not contain credentials")
    return value


def milliseconds(value: str) -> float:
    return positive_float(value)


def http_status(value: str) -> int:
    parsed = int(value)
    if parsed < 100 or parsed > 599:
        raise argparse.ArgumentTypeError("must be an HTTP status from 100 through 599")
    return parsed


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--url", required=True, type=endpoint_url)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--count", type=positive_int, default=240)
    parser.add_argument("--interval-ms", type=milliseconds, default=250.0)
    parser.add_argument("--max-in-flight", type=positive_int, default=16)
    parser.add_argument("--connect-timeout-seconds", type=positive_float, default=2.0)
    parser.add_argument("--max-time-seconds", type=positive_float, default=3.0)
    parser.add_argument(
        "--max-schedule-lag-ms",
        type=milliseconds,
        help="Fail a request that starts this far behind its fixed schedule (default: interval)",
    )
    parser.add_argument("--expected-status", type=http_status, default=200)
    args = parser.parse_args()
    if args.connect_timeout_seconds > args.max_time_seconds:
        parser.error("--connect-timeout-seconds cannot exceed --max-time-seconds")
    minimum_in_flight = math.ceil(
        args.max_time_seconds / (args.interval_ms / 1000.0)
    )
    if args.max_in_flight < minimum_in_flight:
        parser.error(
            "--max-in-flight must cover every request that can overlap at the "
            f"configured rate and timeout (minimum {minimum_in_flight})"
        )
    return args


def seconds_to_ms(value: str) -> float | None:
    try:
        parsed = float(value)
    except ValueError:
        return None
    return round(parsed * 1000.0, 3) if math.isfinite(parsed) else None


@dataclass
class Concurrency:
    active: int = 0
    maximum: int = 0

    def enter(self) -> None:
        self.active += 1
        self.maximum = max(self.maximum, self.active)

    def leave(self) -> None:
        self.active -= 1


async def run_probe(
    *,
    attempt: int,
    scheduled_monotonic: float,
    scheduled_at: datetime,
    semaphore: asyncio.Semaphore,
    concurrency: Concurrency,
    args: argparse.Namespace,
    headers: Path,
    stderr_path: Path,
    result_path: Path,
) -> dict[str, object]:
    async with semaphore:
        started_monotonic = asyncio.get_running_loop().time()
        started_at = utc_now()
        schedule_lag_ms = round(
            max(0.0, started_monotonic - scheduled_monotonic) * 1000.0, 3
        )
        concurrency.enter()
        process: asyncio.subprocess.Process | None = None
        try:
            try:
                process = await asyncio.create_subprocess_exec(
                    "curl",
                    "--silent",
                    "--show-error",
                    "--connect-timeout",
                    str(args.connect_timeout_seconds),
                    "--max-time",
                    str(args.max_time_seconds),
                    "--dump-header",
                    str(headers),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    CURL_WRITE_OUT,
                    args.url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                stdout, stderr = await process.communicate()
                curl_exit = process.returncode
            except OSError as error:
                stdout = b""
                stderr = f"could not execute curl: {error}\n".encode()
                curl_exit = 127
        finally:
            concurrency.leave()

        ended_at = utc_now()
        ended_monotonic = asyncio.get_running_loop().time()
        stderr_path.write_bytes(stderr)

        fields = stdout.decode("utf-8", errors="replace").split("\t")
        fields.extend([""] * (7 - len(fields)))
        try:
            http_code = int(fields[0])
        except ValueError:
            http_code = 0

        max_schedule_lag_ms = args.max_schedule_lag_ms or args.interval_ms
        failure_reasons: list[str] = []
        if curl_exit != 0:
            failure_reasons.append(f"curl_exit={curl_exit}")
        if http_code != args.expected_status:
            failure_reasons.append(
                f"http_code={http_code} expected={args.expected_status}"
            )
        if schedule_lag_ms > max_schedule_lag_ms:
            failure_reasons.append(
                f"schedule_lag_ms={schedule_lag_ms} max={max_schedule_lag_ms}"
            )

        result: dict[str, object] = {
            "attempt": attempt,
            "scheduled_at": iso8601(scheduled_at),
            "started_at": iso8601(started_at),
            "ended_at": iso8601(ended_at),
            "scheduled_monotonic": round(scheduled_monotonic, 6),
            "started_monotonic": round(started_monotonic, 6),
            "ended_monotonic": round(ended_monotonic, 6),
            "schedule_lag_ms": schedule_lag_ms,
            "curl_exit": curl_exit,
            "http_code": http_code,
            "remote_ip": fields[1],
            "time_namelookup_ms": seconds_to_ms(fields[2]),
            "time_connect_ms": seconds_to_ms(fields[3]),
            "time_appconnect_ms": seconds_to_ms(fields[4]),
            "time_starttransfer_ms": seconds_to_ms(fields[5]),
            "time_total_ms": seconds_to_ms(fields[6]),
            "headers": f"headers/{headers.name}",
            "stderr": f"stderr/{stderr_path.name}",
            "failure_reasons": failure_reasons,
        }
        temporary_result = result_path.with_suffix(".tmp")
        temporary_result.write_text(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        temporary_result.replace(result_path)
        return result


async def probe_all(args: argparse.Namespace) -> tuple[list[dict[str, object]], int]:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    headers_dir = args.output_dir / "headers"
    stderr_dir = args.output_dir / "stderr"
    partial_results_dir = args.output_dir / "partial-results"
    headers_dir.mkdir(exist_ok=True)
    stderr_dir.mkdir(exist_ok=True)
    partial_results_dir.mkdir(exist_ok=True)

    loop = asyncio.get_running_loop()
    interval_seconds = args.interval_ms / 1000.0
    monotonic_start = loop.time() + 0.1
    wall_start = utc_now() + timedelta(seconds=0.1)
    semaphore = asyncio.Semaphore(args.max_in_flight)
    concurrency = Concurrency()
    tasks: list[asyncio.Task[dict[str, object]]] = []

    for index in range(args.count):
        scheduled_monotonic = monotonic_start + index * interval_seconds
        delay = scheduled_monotonic - loop.time()
        if delay > 0:
            await asyncio.sleep(delay)
        attempt = index + 1
        tasks.append(
            asyncio.create_task(
                run_probe(
                    attempt=attempt,
                    scheduled_monotonic=scheduled_monotonic,
                    scheduled_at=wall_start + timedelta(seconds=index * interval_seconds),
                    semaphore=semaphore,
                    concurrency=concurrency,
                    args=args,
                    headers=headers_dir / f"attempt-{attempt:04d}.headers",
                    stderr_path=stderr_dir / f"attempt-{attempt:04d}.stderr",
                    result_path=partial_results_dir / f"attempt-{attempt:04d}.json",
                )
            )
        )

    results = sorted(await asyncio.gather(*tasks), key=lambda item: int(item["attempt"]))
    return results, concurrency.maximum


def main() -> int:
    args = parse_args()
    max_schedule_lag_ms = args.max_schedule_lag_ms or args.interval_ms
    started_at = utc_now()
    results, max_observed_in_flight = asyncio.run(probe_all(args))
    completed_at = utc_now()
    failures = [result for result in results if result["failure_reasons"]]

    results_path = args.output_dir / "results.jsonl"
    with results_path.open("w", encoding="utf-8") as output:
        for result in results:
            output.write(json.dumps(result, sort_keys=True, separators=(",", ":")))
            output.write("\n")

    summary = {
        "count": args.count,
        "failures": len(failures),
        "interval_ms": args.interval_ms,
        "max_in_flight": args.max_in_flight,
        "max_observed_in_flight": max_observed_in_flight,
        "max_schedule_lag_ms": max_schedule_lag_ms,
        "max_observed_schedule_lag_ms": max(
            float(result["schedule_lag_ms"]) for result in results
        ),
        "max_observed_total_ms": max(
            float(result["time_total_ms"] or 0.0) for result in results
        ),
        "expected_status": args.expected_status,
        "started_at": iso8601(started_at),
        "completed_at": iso8601(completed_at),
    }
    (args.output_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(
        "public endpoint probe: "
        f"attempts={args.count} failures={len(failures)} "
        f"max_observed_in_flight={max_observed_in_flight}"
    )
    for failure in failures[:40]:
        print(json.dumps(failure, sort_keys=True, separators=(",", ":")))
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
