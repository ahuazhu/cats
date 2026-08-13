#!/usr/bin/env python3
"""Prove Route v2 listener argv with the host's real systemd parser."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def systemctl(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["systemctl", *arguments], text=True, capture_output=True, check=check
    )


def exercise(source: Path, *, production: bool, root: Path) -> list[str]:
    label = "production" if production else "direct"
    unit_name = f"cats-route-v2-effective-argv-{label}.service"
    unit_path = root / unit_name
    environment_path = root / f"{label}.env"
    output_path = root / f"{label}.json"
    recorder_path = root / "record-argv.py"
    environment_path.write_text(
        "\n".join(
            [
                "CATS_ROUTE_V2_MACHINE_LISTEN=127.0.0.1:6553",
                "CATS_CONTROL_PLANE_URL=http://127.0.0.1:7300",
                "CATS_S3_BUCKET=fixture-bucket",
                "CATS_AWS_REGION=us-east-1",
                "CATS_NODE_LISTEN=127.0.0.1:7301",
                "CATS_BLOCK_PATH_ARGS=--block-path fixture",
                "CATS_METADATA_STORE_ARGS=--metadata-store-adapter fixture",
                "CATS_OBJECT_STORE_ARGS=--object-store-adapter fixture",
            ]
        )
        + "\n"
    )
    text = source.read_text()
    text = "\n".join(
        line
        for line in text.splitlines()
        if not line.startswith(("ExecStartPre=", "After=", "Wants="))
    )
    text = text.replace(
        "EnvironmentFile=/etc/cats/worker.env",
        f"EnvironmentFile={environment_path}",
    ).replace(
        "EnvironmentFile=/etc/cats/cats.env",
        f"EnvironmentFile={environment_path}",
    )
    text = text.replace("/opt/cats/bin/cats-noded", str(recorder_path), 1)
    text = text.replace("Restart=always", "Restart=no")
    text = text.replace("RestartSec=2", "")
    text = text.replace("RestartSec=1", "")
    text = text.replace(
        "[Service]", f"[Service]\nEnvironment=CATS_FIXTURE_OUTPUT={output_path}", 1
    )
    unit_path.write_text(text + "\n")

    linked = Path("/run/systemd/system") / unit_name
    try:
        systemctl("link", "--runtime", str(unit_path))
        systemctl("daemon-reload")
        systemctl("start", unit_name)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline and not output_path.exists():
            time.sleep(0.02)
        if not output_path.exists():
            status = systemctl("status", unit_name, "--no-pager", check=False)
            raise AssertionError(f"systemd did not execute fixture unit:\n{status.stdout}{status.stderr}")
        return json.loads(output_path.read_text())
    finally:
        systemctl("stop", unit_name, check=False)
        if linked.exists() or linked.is_symlink():
            linked.unlink()
        systemctl("daemon-reload", check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--production-unit", required=True, type=Path)
    parser.add_argument("--direct-unit", required=True, type=Path)
    arguments = parser.parse_args()
    if os.geteuid() != 0:
        parser.error("this fixture must run as root against a real systemd manager")
    if shutil.which("systemctl") is None:
        parser.error("systemctl is required")
    systemctl("show", "--property=Version", check=True)

    with tempfile.TemporaryDirectory(prefix="cats-systemd-argv-", dir="/run") as temporary:
        root = Path(temporary)
        recorder = root / "record-argv.py"
        recorder.write_text(
            "#!/usr/bin/env python3\n"
            "import json, os, pathlib, sys\n"
            "pathlib.Path(os.environ['CATS_FIXTURE_OUTPUT']).write_text(json.dumps(sys.argv[1:]))\n"
        )
        recorder.chmod(0o755)
        production = exercise(arguments.production_unit.resolve(), production=True, root=root)
        direct = exercise(arguments.direct_unit.resolve(), production=False, root=root)

    flag = "--route-v2-machine-listen"
    assert production.count(flag) == 1
    position = production.index(flag)
    assert production[position + 1] == "0.0.0.0:7444"
    assert "127.0.0.1:6553" not in production
    assert flag not in direct
    assert "127.0.0.1:6553" not in direct
    print("systemd Route v2 effective argv fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
