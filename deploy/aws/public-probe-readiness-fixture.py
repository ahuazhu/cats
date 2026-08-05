#!/usr/bin/env python3
"""Prove a delayed first probe cannot cross the Eviction readiness boundary."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class Gate:
    def __init__(self) -> None:
        self.first_request_started = threading.Event()
        self.release_first_response = threading.Event()
        self.lock = threading.Lock()
        self.requests = 0

    def next_request(self) -> int:
        with self.lock:
            self.requests += 1
            return self.requests


class DelayedHealthyHandler(BaseHTTPRequestHandler):
    gate: Gate

    def log_message(self, _format: str, *_args: object) -> None:
        pass

    def do_GET(self) -> None:  # noqa: N802 - BaseHTTPRequestHandler API
        request = self.gate.next_request()
        if request == 1:
            self.gate.first_request_started.set()
            if not self.gate.release_first_response.wait(timeout=5):
                self.send_error(504)
                return
        body = b"ok\n"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Amzn-Trace-Id", "Root=must-be-digested")
        self.send_header("Set-Cookie", "must-not-be-retained=yes")
        self.end_headers()
        self.wfile.write(body)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe", required=True, type=Path)
    parser.add_argument("--wait-helper", required=True, type=Path)
    args = parser.parse_args()

    gate = Gate()
    handler = type("FixtureHandler", (DelayedHealthyHandler,), {"gate": gate})
    server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    probe: subprocess.Popen[str] | None = None
    try:
        with tempfile.TemporaryDirectory(prefix="cats-ha-readiness-") as directory:
            root = Path(directory)
            output_dir = root / "evidence"
            eviction_log = root / "evictions.log"
            stub = root / "eviction-stub.py"
            stub.write_text(
                "from pathlib import Path\n"
                "import sys\n"
                "with Path(sys.argv[1]).open('a', encoding='utf-8') as output:\n"
                "    output.write('eviction-called\\n')\n",
                encoding="utf-8",
            )
            probe = subprocess.Popen(
                [
                    sys.executable,
                    str(args.probe),
                    "--url",
                    f"http://127.0.0.1:{server.server_port}/healthz",
                    "--output-dir",
                    str(output_dir),
                    "--count",
                    "4",
                    "--interval-ms",
                    "500",
                    "--max-in-flight",
                    "6",
                    "--connect-timeout-seconds",
                    "0.2",
                    "--max-time-seconds",
                    "3",
                    "--max-schedule-lag-ms",
                    "500",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            ordering_result: dict[str, subprocess.CompletedProcess[str]] = {}

            def wait_then_evict() -> None:
                readiness = subprocess.run(
                    [
                        sys.executable,
                        str(args.wait_helper),
                        "--probe-pid",
                        str(probe.pid),
                        "--output-dir",
                        str(output_dir),
                        "--timeout-seconds",
                        "5",
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                ordering_result["readiness"] = readiness
                if readiness.returncode == 0:
                    ordering_result["eviction"] = subprocess.run(
                        [sys.executable, str(stub), str(eviction_log)],
                        capture_output=True,
                        text=True,
                        check=False,
                    )

            ordering = threading.Thread(target=wait_then_evict)
            ordering.start()
            if not gate.first_request_started.wait(timeout=3):
                raise AssertionError("known-positive server never observed the first curl")
            time.sleep(0.15)
            if eviction_log.exists() and eviction_log.stat().st_size > 0:
                raise AssertionError("Eviction stub ran before the baseline completed")
            if (output_dir / "partial-results" / "attempt-0001.json").exists():
                raise AssertionError("delayed first request published readiness too early")

            gate.release_first_response.set()
            ordering.join(timeout=6)
            if ordering.is_alive():
                raise AssertionError("readiness helper did not complete within its bound")
            readiness = ordering_result.get("readiness")
            eviction = ordering_result.get("eviction")
            if readiness is None or readiness.returncode != 0:
                raise AssertionError(f"readiness failed: {readiness}")
            if eviction is None or eviction.returncode != 0:
                raise AssertionError(f"Eviction stub failed: {eviction}")
            calls = eviction_log.read_text(encoding="utf-8").splitlines()
            if calls != ["eviction-called"]:
                raise AssertionError(f"Eviction stub calls were not exactly once: {calls}")

            stdout, stderr = probe.communicate(timeout=10)
            if probe.returncode != 0:
                raise AssertionError(f"probe failed:\nstdout:\n{stdout}\nstderr:\n{stderr}")
            headers = json.loads(
                (output_dir / "headers" / "attempt-0001.json").read_text(
                    encoding="utf-8"
                )
            )
            retained = headers["headers"]
            if "set-cookie" in retained:
                raise AssertionError("Set-Cookie escaped the header policy")
            trace = retained.get("x-amzn-trace-id", [])
            if len(trace) != 1 or not trace[0].startswith("sha256:"):
                raise AssertionError("correlation header was not safely summarized")
            print("delayed baseline: zero Evictions before readiness, exactly one after")
            return 0
    except (AssertionError, OSError, subprocess.TimeoutExpired) as error:
        print(f"readiness fixture failed: {error}", file=sys.stderr)
        return 1
    finally:
        gate.release_first_response.set()
        if probe is not None and probe.poll() is None:
            probe.terminate()
            try:
                probe.wait(timeout=5)
            except subprocess.TimeoutExpired:
                probe.kill()
                probe.wait(timeout=2)
        server.shutdown()
        server.server_close()
        server_thread.join(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
