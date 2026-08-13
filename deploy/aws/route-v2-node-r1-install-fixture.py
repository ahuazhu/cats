#!/usr/bin/env python3
"""Concurrent black-box fixture for immutable Node Route v2 revision-1 install."""

from __future__ import annotations

import fcntl
import argparse
import multiprocessing
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import time


NAMES = {
    "public-key-ring.v1.json": 0o644,
    "gateway-client-ca-bundle.pem": 0o644,
    "node-machine-server-certificate.pem": 0o644,
    "node-machine-server-private-key.pem": 0o600,
}
RING = b'{"version":1,"ring_version":1,"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}]}'
JQ_SORTED_RING = b'{"expected_previous":null,"keys":[{"kid":"2281a02a7f42d92fa9caa5b7907b29c2f060cb00196be280af33fb7bc8e27e99","public_key_spki":"MCowBQYDK2VwAyEAsz3X-kqrYHysotqiQjIuGgGom4LK9bK8tonhiWAQ0To"}],"ring_version":1,"version":1}'


def write_executable(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o755)


def make_candidate(root: Path, suffix: bytes = b"") -> Path:
    root.mkdir(mode=0o700)
    payloads = {
        "public-key-ring.v1.json": RING,
        "gateway-client-ca-bundle.pem": b"fixture-ca" + suffix,
        "node-machine-server-certificate.pem": b"fixture-certificate",
        "node-machine-server-private-key.pem": b"fixture-private-key",
    }
    for name, mode in NAMES.items():
        path = root / name
        path.write_bytes(payloads[name])
        path.chmod(mode)
    return root


def run_locked_installer(
    lock_path: str,
    helper: str,
    validator: str,
    candidate: str,
    installed: str,
    tool_path: str,
    mutation_marker: str,
    delay: float,
    lock_ready: str,
    results: multiprocessing.Queue[tuple[int, str, str]],
) -> None:
    with open(lock_path, "a+b") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        if lock_ready:
            Path(lock_ready).touch()
        script = r'''
set -eu
. "$HELPER"
cats_require_worker_deployment_lock() { test "$CATS_TEST_LOCK_HELD" = 1; }
state="$(cats_classify_route_v2_node_r1 "$VALIDATOR" "$CANDIDATE" "$INSTALLED")"
case "$state" in absent|exact) ;; *) exit 1 ;; esac
sleep "$DELAY"
: > "$MUTATION_MARKER"
if [ "$state" = absent ]; then
  cats_publish_route_v2_node_r1 "$VALIDATOR" "$CANDIDATE" "$INSTALLED"
fi
printf '%s\n' "$state"
'''
        environment = os.environ.copy()
        environment.update(
            {
                "CATS_TEST_LOCK_HELD": "1",
                "HELPER": helper,
                "VALIDATOR": validator,
                "CANDIDATE": candidate,
                "INSTALLED": installed,
                "MUTATION_MARKER": mutation_marker,
                "DELAY": str(delay),
                "PATH": tool_path + os.pathsep + environment["PATH"],
            }
        )
        completed = subprocess.run(
            ["bash", "-c", script],
            text=True,
            capture_output=True,
            env=environment,
            check=False,
        )
        results.put((completed.returncode, completed.stdout.strip(), completed.stderr))


def start_pair(
    root: Path,
    helper: Path,
    validator: Path,
    first: Path,
    second: Path,
    installed: Path,
    tools: Path,
) -> tuple[tuple[int, str, str], tuple[int, str, str]]:
    context = multiprocessing.get_context("spawn")
    results: multiprocessing.Queue[tuple[int, str, str]] = context.Queue()
    first_locked = root / "first.locked"
    arguments = (
        str(root / "install.lock"),
        str(helper),
        str(validator),
    )
    first_process = context.Process(
        target=run_locked_installer,
        args=(
            *arguments,
            str(first),
            str(installed),
            str(tools),
            str(root / "first.mutated"),
            0.2,
            str(first_locked),
            results,
        ),
    )
    second_process = context.Process(
        target=run_locked_installer,
        args=(
            *arguments,
            str(second),
            str(installed),
            str(tools),
            str(root / "second.mutated"),
            0.0,
            "",
            results,
        ),
    )
    first_process.start()
    deadline = time.monotonic() + 5
    while not first_locked.exists() and time.monotonic() < deadline:
        time.sleep(0.01)
    if not first_locked.exists():
        first_process.terminate()
        first_process.join(5)
        raise AssertionError("first installer did not acquire the Host lock")
    second_process.start()
    first_process.join(10)
    second_process.join(10)
    if first_process.exitcode != 0 or second_process.exitcode != 0:
        raise AssertionError("installer fixture process failed to report a result")
    return results.get(timeout=1), results.get(timeout=1)


def assert_installed_matches(candidate: Path, installed: Path) -> None:
    assert set(path.name for path in installed.iterdir()) == set(NAMES)
    for name, mode in NAMES.items():
        assert (installed / name).read_bytes() == (candidate / name).read_bytes()
        assert stat.S_IMODE((installed / name).stat().st_mode) == mode


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--helper", required=True, type=Path)
    parser.add_argument("--manual-installer", required=True, type=Path)
    parser.add_argument("--terraform-module", required=True, type=Path)
    arguments = parser.parse_args()
    helper = arguments.helper.resolve()
    for path in (arguments.manual_installer, arguments.terraform_module):
        text = path.read_text()
        lock = text.index("cats_acquire_worker_deployment_lock")
        classify = text.index("cats_classify_route_v2_node_r1", lock)
        gate = text.index("cats_gate_node_service", classify)
        assert lock < classify < gate
        for line in text[lock:classify].splitlines():
            command = line.strip()
            assert command.startswith("#") or not (
                command.startswith("systemctl ") or "$(systemctl " in command
            )
        assert "cats-route-v2-node-r1-validator" in text
        assert "install-route-v2-node-r1.sh" in text
        assert "jq -cS" not in text
    with tempfile.TemporaryDirectory(prefix="cats-route-v2-r1-") as temporary:
        root = Path(temporary)
        tools = root / "tools"
        tools.mkdir()
        validator = tools / "validator"
        write_executable(
            validator,
            f'''#!/usr/bin/env python3
import os, pathlib, stat, sys
expected = {NAMES!r}
ring = {RING!r}
if len(sys.argv) != 3 or sys.argv[1] != "--directory": sys.exit(2)
directory = pathlib.Path(sys.argv[2])
try:
    if not directory.is_absolute() or stat.S_IMODE(directory.stat().st_mode) != 0o700: sys.exit(1)
    if set(path.name for path in directory.iterdir()) != set(expected): sys.exit(1)
    for name, mode in expected.items():
        path = directory / name
        metadata = path.stat()
        if path.is_symlink() or not path.is_file() or metadata.st_nlink != 1: sys.exit(1)
        if stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size == 0: sys.exit(1)
    if (directory / "public-key-ring.v1.json").read_bytes() != ring: sys.exit(1)
except OSError:
    sys.exit(1)
''',
        )
        write_executable(tools / "sync", "#!/bin/sh\nexit 0\n")
        write_executable(
            tools / "mv",
            "#!/bin/sh\n[ \"$1\" = -T ] && shift\n[ \"$1\" = -- ] && shift\nexec /bin/mv \"$1\" \"$2\"\n",
        )

        exact_root = root / "exact"
        exact_root.mkdir()
        first = make_candidate(exact_root / "candidate-a")
        second = make_candidate(exact_root / "candidate-b")
        installed = exact_root / "etc/route-v2"
        results = start_pair(exact_root, helper, validator, first, second, installed, tools)
        assert sorted((code, state) for code, state, _ in results) == [(0, "absent"), (0, "exact")]
        assert_installed_matches(first, installed)

        conflict_root = root / "conflict"
        conflict_root.mkdir()
        first = make_candidate(conflict_root / "candidate-a")
        second = make_candidate(conflict_root / "candidate-b", b"-conflict")
        installed = conflict_root / "etc/route-v2"
        results = start_pair(conflict_root, helper, validator, first, second, installed, tools)
        assert sum(code == 0 for code, _, _ in results) == 1
        assert sum(code != 0 for code, _, _ in results) == 1
        assert_installed_matches(first, installed)
        assert not (conflict_root / "second.mutated").exists()

        for name, mutate in {
            "jq-order": lambda path: (path / "public-key-ring.v1.json").write_bytes(JQ_SORTED_RING),
            "extra": lambda path: (path / "unexpected.pem").write_bytes(b"unexpected"),
            "missing": lambda path: (path / "gateway-client-ca-bundle.pem").unlink(),
        }.items():
            negative_root = root / name
            negative_root.mkdir()
            candidate = make_candidate(negative_root / "candidate")
            mutate(candidate)
            context = multiprocessing.get_context("spawn")
            results_queue: multiprocessing.Queue[tuple[int, str, str]] = context.Queue()
            process = context.Process(
                target=run_locked_installer,
                args=(
                    str(negative_root / "install.lock"),
                    str(helper),
                    str(validator),
                    str(candidate),
                    str(negative_root / "etc/route-v2"),
                    str(tools),
                    str(negative_root / "mutated"),
                    0.0,
                    "",
                    results_queue,
                ),
            )
            process.start()
            process.join(10)
            code, _, _ = results_queue.get(timeout=1)
            assert code != 0
            assert not (negative_root / "mutated").exists()
            assert not (negative_root / "etc/route-v2").exists()
    print("Route v2 revision-1 install fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
