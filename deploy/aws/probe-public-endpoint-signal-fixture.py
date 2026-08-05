#!/usr/bin/env python3
"""Send SIGTERM mid-probe and prove terminal evidence and curl cleanup."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Requests:
    def __init__(self) -> None:
        self.count = 0
        self.lock = threading.Lock()
        self.hanging_request_started = threading.Event()
        self.release = threading.Event()

    def next(self) -> int:
        with self.lock:
            self.count += 1
            return self.count


class OneFastThenHanging(BaseHTTPRequestHandler):
    requests: Requests

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        request = self.requests.next()
        if request > 1:
            self.requests.hanging_request_started.set()
            self.requests.release.wait(timeout=8)
        body = b"ok\n"
        try:
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def curl_children(parent: int) -> set[int]:
    output = subprocess.run(
        ["ps", "-axo", "pid=,ppid=,command="],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    children: set[int] = set()
    for line in output.splitlines():
        fields = line.strip().split(None, 2)
        if len(fields) != 3:
            continue
        pid, ppid, command = fields
        if int(ppid) == parent and Path(command.split()[0]).name == "curl":
            children.add(int(pid))
    return children


def process_exists(pid: int) -> bool:
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument(
        "--signal", choices=("SIGTERM", "SIGINT"), default="SIGTERM"
    )
    args = parser.parse_args()
    requested_signal = getattr(signal, args.signal)
    expected_exit = 143 if requested_signal == signal.SIGTERM else 130

    requests = Requests()
    handler = type("FixtureHandler", (OneFastThenHanging,), {"requests": requests})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    probe: subprocess.Popen[str] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="cats-ha-signal-") as directory:
            output_dir = Path(directory) / "evidence"
            probe = subprocess.Popen(
                [
                    sys.executable,
                    str(args.probe),
                    "--url",
                    f"http://127.0.0.1:{server.server_port}/healthz",
                    "--output-dir",
                    str(output_dir),
                    "--count",
                    "20",
                    "--interval-ms",
                    "100",
                    "--max-in-flight",
                    "20",
                    "--connect-timeout-seconds",
                    "0.2",
                    "--max-time-seconds",
                    "2",
                    "--max-schedule-lag-ms",
                    "500",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            baseline = output_dir / "partial-results" / "attempt-0001.json"
            deadline = time.monotonic() + 4
            observed_children: set[int] = set()
            while time.monotonic() < deadline:
                observed_children |= curl_children(probe.pid)
                if (
                    baseline.is_file()
                    and requests.hanging_request_started.is_set()
                    and observed_children
                ):
                    break
                if probe.poll() is not None:
                    raise AssertionError("probe exited before the TERM control point")
                time.sleep(0.02)
            if not baseline.is_file():
                raise AssertionError("known-positive completed attempt was not retained")
            if not requests.hanging_request_started.is_set() or not observed_children:
                raise AssertionError("known-positive active curl control was not observed")

            interrupted_at = time.monotonic()
            probe.send_signal(requested_signal)
            stdout, stderr = probe.communicate(timeout=5)
            elapsed = time.monotonic() - interrupted_at
            if probe.returncode != expected_exit:
                raise AssertionError(
                    f"{args.signal} exit was {probe.returncode}, expected {expected_exit}\n"
                    f"stdout:\n{stdout}\nstderr:\n{stderr}"
                )
            if elapsed >= 5:
                raise AssertionError(
                    f"{args.signal} finalization exceeded its bound: {elapsed}"
                )

            summary = json.loads((output_dir / "summary.json").read_text())
            results = [
                json.loads(line)
                for line in (output_dir / "results.jsonl").read_text().splitlines()
                if line
            ]
            if len(results) != 20:
                raise AssertionError(f"manifest has {len(results)} rows, expected 20")
            expected = {
                "state": "interrupted",
                "complete": False,
                "interrupted": True,
                "incomplete": True,
                "signal": args.signal,
                "configured_count": 20,
            }
            for key, value in expected.items():
                if summary.get(key) != value:
                    raise AssertionError(f"summary {key}={summary.get(key)!r}, expected {value!r}")
            if not (
                1 <= int(summary["completed_count"]) < int(summary["configured_count"])
                and int(summary["scheduled_count"]) >= int(summary["started_count"])
                >= int(summary["completed_count"])
                and int(summary["missing_count"])
                == len(summary["missing_attempts"])
                == 20 - int(summary["completed_count"])
            ):
                raise AssertionError(f"summary counts are inconsistent: {summary}")
            completed = [item for item in results if item["status"] == "completed"]
            missing = [item for item in results if item["status"] == "missing"]
            if not completed or len(missing) != int(summary["missing_count"]):
                raise AssertionError("terminal manifest lost completed or missing attempts")
            leaked = sorted(pid for pid in observed_children if process_exists(pid))
            if leaked:
                raise AssertionError(f"curl children survived probe finalization: {leaked}")
            if any(output_dir.rglob("*.headers")):
                raise AssertionError("raw response headers entered retained evidence")
            print(
                f"{args.signal} finalizer: "
                f"scheduled={summary['scheduled_count']} started={summary['started_count']} "
                f"completed={summary['completed_count']} "
                f"missing={summary['missing_count']}; no orphan curl"
            )
            return 0
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"signal fixture failed: {error}", file=sys.stderr)
        return 1
    finally:
        requests.release.set()
        if probe is not None and probe.poll() is None:
            probe.kill()
            probe.wait(timeout=2)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
