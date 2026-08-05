#!/usr/bin/env python3
"""Deterministically prove the public probe detects stale-target drain ordering."""

from __future__ import annotations

import argparse
import http.client
import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class QuietHandler(BaseHTTPRequestHandler):
    def log_message(self, _format: str, *_args: object) -> None:
        pass


class HealthyBackend(QuietHandler):
    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        if self.path != "/healthz":
            self.send_error(404)
            return
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class RetainedTargetState:
    def __init__(self, leader: tuple[str, int], standby: tuple[str, int]) -> None:
        self.leader = leader
        self.standby = standby
        self.stale_until: float | None = None
        self.next_target = 0
        self.lock = threading.Lock()

    def begin_eviction(self, propagation_delay: float) -> None:
        with self.lock:
            self.stale_until = time.monotonic() + propagation_delay

    def target(self) -> tuple[str, int]:
        with self.lock:
            if self.stale_until is None or time.monotonic() < self.stale_until:
                target = self.leader if self.next_target % 2 == 0 else self.standby
                self.next_target += 1
                return target
            return self.standby


class RetainedTargetProxy(QuietHandler):
    state: RetainedTargetState

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        host, port = self.state.target()
        try:
            connection = http.client.HTTPConnection(host, port, timeout=0.1)
            connection.request("GET", self.path)
            response = connection.getresponse()
            body = response.read()
            self.send_response(response.status)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        except (ConnectionError, OSError, TimeoutError):
            body = b"stale target unavailable\n"
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)


class Server:
    def __init__(self, handler: type[BaseHTTPRequestHandler]) -> None:
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        self.thread = threading.Thread(
            target=lambda: self.httpd.serve_forever(poll_interval=0.01), daemon=True
        )
        self.stopped = False

    @property
    def address(self) -> tuple[str, int]:
        host, port = self.httpd.server_address
        return str(host), int(port)

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        if self.stopped:
            return
        self.stopped = True
        self.httpd.shutdown()
        self.httpd.server_close()
        self.thread.join(timeout=2)


def read_results(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line]


def result_artifacts_exist(output_dir: Path, result: dict[str, object]) -> bool:
    headers = output_dir / str(result["headers"])
    stderr = output_dir / str(result["stderr"])
    partial = (
        output_dir
        / "partial-results"
        / f"attempt-{int(result['attempt']):04d}.json"
    )
    return (
        headers.is_file()
        and headers.stat().st_size > 0
        and stderr.is_file()
        and partial.is_file()
    )


def run_case(
    probe: Path, *, drained: bool
) -> tuple[int, list[dict[str, object]], str, bool]:
    leader = Server(HealthyBackend)
    standby = Server(HealthyBackend)
    leader.start()
    standby.start()
    state = RetainedTargetState(leader.address, standby.address)
    handler = type("FixtureProxy", (RetainedTargetProxy,), {"state": state})
    proxy = Server(handler)
    proxy.start()

    try:
        with tempfile.TemporaryDirectory(prefix="cats-ha-probe-") as directory:
            output_dir = Path(directory) / "evidence"
            command = [
                sys.executable,
                str(probe),
                "--url",
                f"http://{proxy.address[0]}:{proxy.address[1]}/healthz",
                "--output-dir",
                str(output_dir),
                "--count",
                "60",
                "--interval-ms",
                "50",
                "--max-in-flight",
                "8",
                "--connect-timeout-seconds",
                "0.1",
                "--max-time-seconds",
                "0.2",
                # This fixture runs inside the full workspace suite. Keep host
                # load jitter below the deliberately longer stale-target window
                # without weakening the production workflow's 250 ms limit.
                "--max-schedule-lag-ms",
                "2000",
            ]
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            time.sleep(0.25)
            propagation_delay = 3.0
            state.begin_eviction(propagation_delay)
            if drained:
                time.sleep(propagation_delay + 0.2)
                leader.stop()
            else:
                leader.stop()
            stdout, stderr = process.communicate(timeout=10)
            diagnostic = f"stdout:\n{stdout}\nstderr:\n{stderr}"
            results_path = output_dir / "results.jsonl"
            if not results_path.is_file():
                return process.returncode, [], diagnostic, False
            results = read_results(results_path)
            summary = json.loads((output_dir / "summary.json").read_text())
            artifacts_valid = (
                int(summary["max_observed_in_flight"]) <= 8
                and all(result_artifacts_exist(output_dir, result) for result in results)
            )
            return process.returncode, results, diagnostic, artifacts_valid
    finally:
        proxy.stop()
        standby.stop()
        leader.stop()


def fixed_schedule_is_present(results: list[dict[str, object]]) -> bool:
    scheduled = [float(result["scheduled_monotonic"]) for result in results]
    return all(
        abs((later - earlier) - 0.05) < 0.002
        for earlier, later in zip(scheduled, scheduled[1:])
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    args = parser.parse_args()

    unsafe_status, unsafe_results, unsafe_diagnostic, unsafe_artifacts = run_case(
        args.probe, drained=False
    )
    unsafe_failures = [
        result
        for result in unsafe_results
        if int(result["http_code"]) != 200 or int(result["curl_exit"]) != 0
    ]
    if (
        unsafe_status == 0
        or not unsafe_failures
        or len(unsafe_results) != 60
        or not unsafe_artifacts
    ):
        print(f"unsafe case did not expose the stale target:\n{unsafe_diagnostic}", file=sys.stderr)
        return 1
    if not fixed_schedule_is_present(unsafe_results):
        print("unsafe case did not retain its fixed schedule", file=sys.stderr)
        return 1
    print("unsafe immediate exit: failures observed")

    drained_status, drained_results, drained_diagnostic, drained_artifacts = run_case(
        args.probe, drained=True
    )
    if drained_status != 0 or len(drained_results) != 60 or not drained_artifacts:
        print(f"drained case failed:\n{drained_diagnostic}", file=sys.stderr)
        return 1
    if any(result["failure_reasons"] for result in drained_results):
        print(f"drained case retained failures:\n{drained_diagnostic}", file=sys.stderr)
        return 1
    if not fixed_schedule_is_present(drained_results):
        print("drained case did not retain its fixed schedule", file=sys.stderr)
        return 1
    print("drained exit: all probes succeeded")
    return 0


if __name__ == "__main__":
    sys.exit(main())
