#!/usr/bin/env python3
"""Probe one public endpoint on a fixed schedule and retain bounded evidence.

SIGTERM and SIGINT stop scheduling, cooperatively terminate every active curl,
and still run the same finalizer as a completed run.  The final manifest always
accounts for every configured attempt, including attempts that were never
scheduled, never started, or interrupted before completion.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import math
import shutil
import signal
import sys
import tempfile
from dataclasses import dataclass, field
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
HEADER_POLICY = "cats-ha-safe-headers-v1"
PLAIN_HEADER_ALLOWLIST = {"server", "via"}
DIGEST_HEADER_ALLOWLIST = {"x-amz-cf-id", "x-amzn-trace-id", "x-cache"}
MAX_HEADER_SOURCE_BYTES = 64 * 1024
MAX_HEADER_VALUE_BYTES = 200
MAX_HEADER_VALUES_PER_NAME = 2
MAX_STDERR_BYTES = 4096
PROCESS_TERMINATION_SECONDS = 2.0


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


def atomic_write_text(path: Path, value: str) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def bounded_stderr(value: bytes) -> tuple[bytes, bool]:
    if len(value) <= MAX_STDERR_BYTES:
        return value, False
    return value[-MAX_STDERR_BYTES:], True


def sanitized_header_value(value: str) -> str:
    without_controls = "".join(
        character if character >= " " and character != "\x7f" else " "
        for character in value
    ).strip()
    encoded = without_controls.encode("utf-8", errors="replace")
    return encoded[:MAX_HEADER_VALUE_BYTES].decode("utf-8", errors="ignore")


def sanitize_headers(source: Path, destination: Path) -> None:
    source_size = source.stat().st_size if source.is_file() else 0
    data = b""
    if source.is_file():
        with source.open("rb") as raw:
            data = raw.read(MAX_HEADER_SOURCE_BYTES)
    retained: dict[str, list[str]] = {}
    for raw_line in data.splitlines():
        line = raw_line.decode("iso-8859-1", errors="replace")
        if ":" not in line:
            continue
        raw_name, raw_value = line.split(":", 1)
        name = raw_name.strip().lower()
        if name not in PLAIN_HEADER_ALLOWLIST | DIGEST_HEADER_ALLOWLIST:
            continue
        values = retained.setdefault(name, [])
        if len(values) >= MAX_HEADER_VALUES_PER_NAME:
            continue
        if name in DIGEST_HEADER_ALLOWLIST:
            digest = hashlib.sha256(
                raw_value.strip().encode("iso-8859-1", errors="replace")
            ).hexdigest()
            values.append(f"sha256:{digest}")
        else:
            values.append(sanitized_header_value(raw_value))
    evidence = {
        "policy": HEADER_POLICY,
        "source_bytes": source_size,
        "source_truncated": source_size > MAX_HEADER_SOURCE_BYTES,
        "headers": retained,
    }
    atomic_write_text(
        destination,
        json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n",
    )
    source.unlink(missing_ok=True)


@dataclass
class Concurrency:
    active: int = 0
    maximum: int = 0

    def enter(self) -> None:
        self.active += 1
        self.maximum = max(self.maximum, self.active)

    def leave(self) -> None:
        self.active -= 1


@dataclass
class ProbeState:
    scheduled_attempts: set[int] = field(default_factory=set)
    started_attempts: set[int] = field(default_factory=set)
    active_processes: dict[int, asyncio.subprocess.Process] = field(default_factory=dict)
    concurrency: Concurrency = field(default_factory=Concurrency)
    interrupt_signal: signal.Signals | None = None
    interrupt_event: asyncio.Event | None = None
    raw_headers_dir: Path | None = None

    def interrupt(self, received: signal.Signals) -> None:
        if self.interrupt_signal is None:
            self.interrupt_signal = received
        if self.interrupt_event is not None:
            self.interrupt_event.set()


async def terminate_and_communicate(
    process: asyncio.subprocess.Process,
    communication: asyncio.Task[tuple[bytes, bytes]],
) -> tuple[bytes, bytes]:
    if process.returncode is None:
        process.terminate()
    try:
        return await asyncio.wait_for(
            asyncio.shield(communication), timeout=PROCESS_TERMINATION_SECONDS
        )
    except TimeoutError:
        if process.returncode is None:
            process.kill()
        return await communication


async def run_probe(
    *,
    attempt: int,
    scheduled_monotonic: float,
    scheduled_at: datetime,
    semaphore: asyncio.Semaphore,
    state: ProbeState,
    args: argparse.Namespace,
    raw_headers: Path,
    headers: Path,
    stderr_path: Path,
    result_path: Path,
) -> dict[str, object] | None:
    async with semaphore:
        assert state.interrupt_event is not None
        if state.interrupt_event.is_set():
            return None
        started_monotonic = asyncio.get_running_loop().time()
        started_at = utc_now()
        schedule_lag_ms = round(
            max(0.0, started_monotonic - scheduled_monotonic) * 1000.0, 3
        )
        state.started_attempts.add(attempt)
        state.concurrency.enter()
        process: asyncio.subprocess.Process | None = None
        stdout = b""
        stderr = b""
        curl_exit = 127
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
                    str(raw_headers),
                    "--output",
                    "/dev/null",
                    "--write-out",
                    CURL_WRITE_OUT,
                    args.url,
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE,
                )
                state.active_processes[attempt] = process
                communication = asyncio.create_task(process.communicate())
                interruption = asyncio.create_task(state.interrupt_event.wait())
                done, _pending = await asyncio.wait(
                    {communication, interruption},
                    return_when=asyncio.FIRST_COMPLETED,
                )
                if communication in done:
                    stdout, stderr = communication.result()
                    curl_exit = process.returncode or 0
                    interruption.cancel()
                    await asyncio.gather(interruption, return_exceptions=True)
                else:
                    await terminate_and_communicate(process, communication)
                    return None
            except OSError as error:
                stderr = f"could not execute curl: {type(error).__name__}\n".encode()
        finally:
            state.active_processes.pop(attempt, None)
            state.concurrency.leave()

        ended_at = utc_now()
        ended_monotonic = asyncio.get_running_loop().time()
        retained_stderr, stderr_truncated = bounded_stderr(stderr)
        stderr_path.write_bytes(retained_stderr)
        sanitize_headers(raw_headers, headers)

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
            "status": "completed",
            "scheduled": True,
            "started": True,
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
            "header_policy": HEADER_POLICY,
            "stderr": f"stderr/{stderr_path.name}",
            "stderr_truncated": stderr_truncated,
            "failure_reasons": failure_reasons,
        }
        atomic_write_text(
            result_path,
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n",
        )
        return result


async def wait_until_or_interrupt(delay: float, state: ProbeState) -> bool:
    assert state.interrupt_event is not None
    if delay <= 0:
        return state.interrupt_event.is_set()
    try:
        await asyncio.wait_for(state.interrupt_event.wait(), timeout=delay)
        return True
    except TimeoutError:
        return False


async def probe_all(args: argparse.Namespace, state: ProbeState) -> None:
    args.output_dir.mkdir(parents=True, exist_ok=True)
    headers_dir = args.output_dir / "headers"
    stderr_dir = args.output_dir / "stderr"
    partial_results_dir = args.output_dir / "partial-results"
    headers_dir.mkdir(exist_ok=True)
    stderr_dir.mkdir(exist_ok=True)
    partial_results_dir.mkdir(exist_ok=True)
    state.raw_headers_dir = Path(tempfile.mkdtemp(prefix="cats-ha-raw-headers-"))

    state.interrupt_event = asyncio.Event()
    if state.interrupt_signal is not None:
        state.interrupt_event.set()

    loop = asyncio.get_running_loop()
    interval_seconds = args.interval_ms / 1000.0
    monotonic_start = loop.time() + 0.1
    wall_start = utc_now() + timedelta(seconds=0.1)
    semaphore = asyncio.Semaphore(args.max_in_flight)
    tasks: list[asyncio.Task[dict[str, object] | None]] = []

    for index in range(args.count):
        if state.interrupt_event.is_set():
            break
        scheduled_monotonic = monotonic_start + index * interval_seconds
        if await wait_until_or_interrupt(scheduled_monotonic - loop.time(), state):
            break
        attempt = index + 1
        state.scheduled_attempts.add(attempt)
        tasks.append(
            asyncio.create_task(
                run_probe(
                    attempt=attempt,
                    scheduled_monotonic=scheduled_monotonic,
                    scheduled_at=wall_start
                    + timedelta(seconds=index * interval_seconds),
                    semaphore=semaphore,
                    state=state,
                    args=args,
                    raw_headers=state.raw_headers_dir
                    / f"attempt-{attempt:04d}.headers",
                    headers=headers_dir / f"attempt-{attempt:04d}.json",
                    stderr_path=stderr_dir / f"attempt-{attempt:04d}.stderr",
                    result_path=partial_results_dir / f"attempt-{attempt:04d}.json",
                )
            )
        )

    try:
        await asyncio.gather(*tasks)
    except BaseException:
        # An evidence write or other unexpected task failure must not strand
        # sibling curl processes. Wake their cooperative interruption path and
        # wait for every child to be reaped before the common finalizer runs.
        state.interrupt_event.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


def load_completed_results(output_dir: Path) -> dict[int, dict[str, object]]:
    completed: dict[int, dict[str, object]] = {}
    for path in sorted((output_dir / "partial-results").glob("attempt-*.json")):
        try:
            result = json.loads(path.read_text(encoding="utf-8"))
            attempt = int(result["attempt"])
        except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
            continue
        if result.get("status") == "completed":
            completed[attempt] = result
    return completed


def finalize(
    args: argparse.Namespace,
    state: ProbeState,
    started_at: datetime,
    internal_error: BaseException | None,
) -> dict[str, object]:
    completed = load_completed_results(args.output_dir)
    missing_attempts = [
        attempt for attempt in range(1, args.count + 1) if attempt not in completed
    ]
    manifest: list[dict[str, object]] = []
    for attempt in range(1, args.count + 1):
        if attempt in completed:
            manifest.append(completed[attempt])
        else:
            manifest.append(
                {
                    "attempt": attempt,
                    "status": "missing",
                    "scheduled": attempt in state.scheduled_attempts,
                    "started": attempt in state.started_attempts,
                    "failure_reasons": ["attempt_incomplete"],
                }
            )

    results_path = args.output_dir / "results.jsonl"
    atomic_write_text(
        results_path,
        "".join(
            json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n"
            for result in manifest
        ),
    )
    failed_attempts = [
        int(result["attempt"])
        for result in completed.values()
        if result.get("failure_reasons")
    ]
    complete = not missing_attempts and state.interrupt_signal is None and internal_error is None
    if state.interrupt_signal is not None:
        run_state = "interrupted"
    elif complete:
        run_state = "complete"
    else:
        run_state = "incomplete"
    max_schedule_lag_ms = args.max_schedule_lag_ms or args.interval_ms
    summary: dict[str, object] = {
        "state": run_state,
        "complete": complete,
        "interrupted": state.interrupt_signal is not None,
        "incomplete": not complete,
        "signal": state.interrupt_signal.name if state.interrupt_signal else None,
        "configured_count": args.count,
        "scheduled_count": len(state.scheduled_attempts),
        "started_count": len(state.started_attempts),
        "completed_count": len(completed),
        "missing_count": len(missing_attempts),
        "missing_attempts": missing_attempts,
        "failed_count": len(failed_attempts),
        "failed_attempts": sorted(failed_attempts),
        "interval_ms": args.interval_ms,
        "max_in_flight": args.max_in_flight,
        "max_observed_in_flight": state.concurrency.maximum,
        "max_schedule_lag_ms": max_schedule_lag_ms,
        "max_observed_schedule_lag_ms": max(
            (float(result["schedule_lag_ms"]) for result in completed.values()),
            default=0.0,
        ),
        "max_observed_total_ms": max(
            (float(result["time_total_ms"] or 0.0) for result in completed.values()),
            default=0.0,
        ),
        "expected_status": args.expected_status,
        "header_policy": HEADER_POLICY,
        "internal_error_type": type(internal_error).__name__ if internal_error else None,
        "started_at": iso8601(started_at),
        "finalized_at": iso8601(utc_now()),
    }
    atomic_write_text(
        args.output_dir / "summary.json",
        json.dumps(summary, indent=2, sort_keys=True) + "\n",
    )
    if state.raw_headers_dir is not None:
        shutil.rmtree(state.raw_headers_dir, ignore_errors=True)
    return summary


def main() -> int:
    args = parse_args()
    args.output_dir.mkdir(parents=True, exist_ok=True)
    state = ProbeState()
    for handled_signal in (signal.SIGTERM, signal.SIGINT):
        signal.signal(
            handled_signal,
            lambda received, _frame: state.interrupt(signal.Signals(received)),
        )
    started_at = utc_now()
    internal_error: BaseException | None = None
    try:
        asyncio.run(probe_all(args, state))
    except KeyboardInterrupt:
        state.interrupt_signal = signal.SIGINT
    except BaseException as error:  # the finalizer must describe unexpected failures
        internal_error = error

    summary = finalize(args, state, started_at, internal_error)
    print(
        "public endpoint probe: "
        f"state={summary['state']} scheduled={summary['scheduled_count']} "
        f"started={summary['started_count']} completed={summary['completed_count']} "
        f"missing={summary['missing_count']} failed={summary['failed_count']}"
    )
    completed = load_completed_results(args.output_dir)
    for attempt in summary["failed_attempts"][:40]:
        print(json.dumps(completed[int(attempt)], sort_keys=True, separators=(",", ":")))

    if state.interrupt_signal == signal.SIGTERM:
        return 143
    if state.interrupt_signal == signal.SIGINT:
        return 130
    if internal_error is not None or summary["incomplete"] or summary["failed_count"]:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
