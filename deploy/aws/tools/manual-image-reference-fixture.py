#!/usr/bin/env python3
"""Black-box alias and zero-build fixture for manual image references."""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import subprocess
import sys
import tempfile

from manual_image_reference import ImageReferenceError, canonical_image_tag


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--builder", required=True, type=Path)
    arguments = parser.parse_args()
    assert canonical_image_tag("cats:fixture") == "docker.io/library/cats:fixture"
    assert (
        canonical_image_tag("INDEX.DOCKER.IO:443/library/cats:fixture")
        == "docker.io/library/cats:fixture"
    )
    try:
        canonical_image_tag("Registry.Example/Cats/UPPER:fixture")
    except ImageReferenceError:
        pass
    else:
        raise AssertionError("uppercase repository escaped canonical validation")

    with tempfile.TemporaryDirectory(prefix="cats-manual-image-ref-") as temporary:
        root = Path(temporary)
        tools = root / "tools"
        tools.mkdir()
        docker_log = root / "docker.log"
        docker = tools / "docker"
        docker.write_text(f"#!/bin/sh\nprintf '%s\\n' \"$*\" >> {docker_log}\nexit 99\n")
        docker.chmod(0o755)
        environment = os.environ.copy()
        environment["PATH"] = str(tools) + os.pathsep + environment["PATH"]
        result = subprocess.run(
            [
                str(arguments.builder.resolve()),
                "--source-sha",
                "a" * 40,
                "--output",
                str(root / "release"),
                "--image",
                "cats:fixture",
                "--gateway-image",
                "INDEX.DOCKER.IO:443/library/cats:fixture",
            ],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
        )
        assert result.returncode != 0
        assert "same mutable tag" in result.stderr
        assert not docker_log.exists()
        assert not (root / "release").exists()
    print("manual image reference fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
