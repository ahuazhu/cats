#!/usr/bin/env python3
"""Prove Terraform's ordinary and verbose plan output redact the recipient sentinel."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path


SENTINEL = "sentinel-recipient-e5@example.invalid"
TERRAFORM_ROOT = Path(__file__).resolve().parent
PLATFORM = TERRAFORM_ROOT / "stacks" / "platform"


def main() -> int:
    command = [
        "terraform",
        f"-chdir={PLATFORM}",
        "test",
        "-filter=tests/alert_recipients.tftest.hcl",
        "-verbose",
        "-no-color",
    ]
    try:
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        print(
            "Terraform recipient privacy fixture could not run: "
            f"{type(error).__name__}",
            file=sys.stderr,
        )
        return 1
    combined = completed.stdout + completed.stderr
    if SENTINEL in combined:
        print("Terraform recipient privacy fixture leaked the sentinel address", file=sys.stderr)
        return 1
    if completed.returncode != 0:
        safe_output = combined.replace(SENTINEL, "<redacted-recipient>")
        print(safe_output, file=sys.stderr, end="")
        return 1
    print("Terraform alert recipient privacy fixture: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
