#!/usr/bin/env python3
"""Check that release Dockerfiles only name real Cargo packages and binaries.

The release images are built once, by hand, on an isolated host. Nothing else
in the gate parses them, so a stale `-p` package name or a renamed binary used
to survive until that build failed tens of minutes in. This check runs from
`quality.sh fast`, where the same mistake costs seconds.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

DOCKERFILES = (
    "deploy/aws/Dockerfile.control-plane",
    "deploy/aws/Dockerfile.gateway",
    "deploy/aws/Dockerfile.worker-artifact",
)

PACKAGE_FLAG = re.compile(r"(?:^|\s)-p\s+(?P<name>[A-Za-z0-9_-]+)")
RELEASE_BINARY = re.compile(r"target/release/(?P<name>[A-Za-z0-9_-]+)")


def workspace_metadata(root: Path) -> tuple[set[str], set[str]]:
    """Return the workspace's package names and its binary target names."""
    raw = subprocess.run(
        ["cargo", "metadata", "--format-version", "1", "--no-deps"],
        cwd=root,
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    metadata = json.loads(raw)
    packages: set[str] = set()
    binaries: set[str] = set()
    for package in metadata["packages"]:
        packages.add(package["name"])
        for target in package["targets"]:
            if "bin" in target["kind"]:
                binaries.add(target["name"])
    return packages, binaries


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    packages, binaries = workspace_metadata(root)
    failures: list[str] = []

    for relative in DOCKERFILES:
        path = root / relative
        if not path.is_file():
            failures.append(f"{relative}: missing release Dockerfile")
            continue
        text = path.read_text(encoding="utf-8")
        for match in PACKAGE_FLAG.finditer(text):
            name = match.group("name")
            if name not in packages:
                failures.append(
                    f"{relative}: cargo package {name!r} is not in the workspace"
                )
        for match in RELEASE_BINARY.finditer(text):
            name = match.group("name")
            if name not in binaries:
                failures.append(
                    f"{relative}: release binary {name!r} is not a workspace binary"
                )

    if failures:
        for failure in sorted(set(failures)):
            print(failure, file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
