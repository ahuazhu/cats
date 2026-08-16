#!/usr/bin/env python3
"""Fail closed unless the active AWS session matches one explicit target."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from typing import NoReturn


ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
PARTITION = re.compile(r"^aws(?:-cn|-us-gov|-iso|-iso-b|-iso-e|-iso-f)?$")
REGION = re.compile(r"^[a-z]{2}(?:-[a-z0-9]+)+-[0-9]+$")


def fail(message: str) -> NoReturn:
    raise SystemExit(f"AWS target verification failed: {message}")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify the active STS caller and configured region before AWS mutations."
    )
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--expected-partition", required=True)
    parser.add_argument("--expected-region", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if ACCOUNT_ID.fullmatch(args.expected_account_id) is None:
        fail("expected account ID must contain exactly 12 digits")
    if PARTITION.fullmatch(args.expected_partition) is None:
        fail("expected partition is not supported")
    if REGION.fullmatch(args.expected_region) is None:
        fail("expected region is not an explicit AWS region")

    configured_regions = {
        name: os.environ.get(name)
        for name in ("AWS_REGION", "AWS_DEFAULT_REGION")
        if os.environ.get(name)
    }
    if not configured_regions:
        fail("AWS_REGION or AWS_DEFAULT_REGION must be configured independently")
    for name, configured in configured_regions.items():
        if configured != args.expected_region:
            fail(f"{name} does not match the expected region")

    try:
        result = subprocess.run(
            [
                "aws",
                "sts",
                "get-caller-identity",
                "--region",
                args.expected_region,
                "--output",
                "json",
                "--no-cli-pager",
            ],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"STS get-caller-identity did not succeed ({error})")

    try:
        identity = json.loads(result.stdout)
    except json.JSONDecodeError:
        fail("STS returned malformed JSON")
    if not isinstance(identity, dict):
        fail("STS identity must be a JSON object")

    account = identity.get("Account")
    arn = identity.get("Arn")
    if account != args.expected_account_id:
        fail("STS account does not match the expected account")
    if not isinstance(arn, str):
        fail("STS identity is missing its ARN")
    arn_parts = arn.split(":", 5)
    if len(arn_parts) != 6 or arn_parts[0] != "arn":
        fail("STS identity ARN is malformed")
    if arn_parts[1] != args.expected_partition:
        fail("STS ARN partition does not match the expected partition")
    if arn_parts[4] != args.expected_account_id:
        fail("STS ARN account does not match the expected account")

    print(
        "AWS target verified: "
        f"partition={args.expected_partition} "
        f"account={args.expected_account_id} "
        f"region={args.expected_region}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
