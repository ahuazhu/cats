#!/usr/bin/env python3
"""Calibrated fake-AWS coverage for the production target fence."""

from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[2]
VERIFIER = ROOT / "deploy/aws/verify-aws-target.py"
RELEASE_WORKFLOW = ROOT / ".github/workflows/release.yml"
DEPLOY_WORKFLOW = ROOT / ".github/workflows/deploy-production.yml"


def run_case(
    temporary: Path,
    *,
    account: str = "123456789012",
    partition: str = "aws",
    configured_region: str = "us-east-1",
    expected_account: str = "123456789012",
    expected_partition: str = "aws",
    expected_region: str = "us-east-1",
    succeeds: bool,
) -> None:
    fake_bin = temporary / "bin"
    fake_bin.mkdir(parents=True, exist_ok=True)
    log = temporary / "aws.log"
    mutation = temporary / "mutation"
    fake_aws = fake_bin / "aws"
    fake_aws.write_text(
        "#!/bin/sh\n"
        "set -eu\n"
        'printf \'%s\\n\' "$*" >> "$FAKE_AWS_LOG"\n'
        'test "$1 $2" = "sts get-caller-identity"\n'
        'printf \'%s\\n\' "$FAKE_AWS_IDENTITY"\n',
        encoding="utf-8",
    )
    fake_aws.chmod(0o755)
    environment = os.environ.copy()
    environment.update(
        {
            "PATH": f"{fake_bin}:{environment['PATH']}",
            "FAKE_AWS_LOG": str(log),
            "FAKE_AWS_IDENTITY": json.dumps(
                {
                    "Account": account,
                    "Arn": f"arn:{partition}:sts::{account}:assumed-role/release/fixture",
                    "UserId": "fixture",
                }
            ),
            "AWS_REGION": configured_region,
            "AWS_DEFAULT_REGION": configured_region,
        }
    )
    command = [
        sys.executable,
        str(VERIFIER),
        "--expected-account-id",
        expected_account,
        "--expected-partition",
        expected_partition,
        "--expected-region",
        expected_region,
    ]
    result = subprocess.run(command, env=environment, capture_output=True, text=True)
    if result.returncode == 0:
        mutation.write_text("would mutate\n", encoding="utf-8")
    assert (result.returncode == 0) is succeeds, result.stderr
    assert mutation.exists() is succeeds
    if log.exists():
        assert log.read_text(encoding="utf-8").splitlines() == [
            "sts get-caller-identity --region us-east-1 --output json --no-cli-pager"
        ]
    else:
        assert not succeeds


def assert_order(text: str, *needles: str) -> None:
    positions = [text.index(needle) for needle in needles]
    assert positions == sorted(positions), needles


def check_workflow_contracts() -> None:
    release = RELEASE_WORKFLOW.read_text(encoding="utf-8")
    deploy = DEPLOY_WORKFLOW.read_text(encoding="utf-8")
    for text in (release, deploy):
        for variable in (
            "EXPECTED_AWS_ACCOUNT_ID",
            "EXPECTED_AWS_PARTITION",
            "EXPECTED_AWS_REGION",
        ):
            assert variable in text
        assert "deploy/aws/verify-aws-target.py" in text

    assert "needs: aws-target" in release
    assert_order(
        release,
        "aws-target:",
        "Verify release AWS target",
        "guest-runtime-release:",
        "Build the one Guest payload",
    )
    control_job = release[
        release.index("  control-plane-image:") : release.index("  credential-refresher-image:")
    ]
    assert_order(
        control_job,
        "Assume AWS role",
        "Reverify release AWS target before registry access",
        "Log in to ECR",
        "Build and push",
    )
    refresher_job = release[
        release.index("  credential-refresher-image:") : release.index("  worker-bundle:")
    ]
    assert_order(
        refresher_job,
        "Assume AWS role",
        "Reverify release AWS target before registry access",
        "Log in to ECR",
        "Build and push credential refresher",
    )
    assert_order(
        deploy,
        "Assume production deployment role",
        "Verify production AWS target",
        "Build the one Guest payload",
        "Log in to ECR",
        "Configure Terraform and Kubernetes",
        "Plan production deployment",
    )


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cats-aws-target-") as directory:
        temporary = Path(directory)
        run_case(temporary / "positive", succeeds=True)
        run_case(temporary / "account", account="999999999999", succeeds=False)
        run_case(temporary / "partition", partition="aws-us-gov", succeeds=False)
        run_case(
            temporary / "region",
            configured_region="us-west-2",
            succeeds=False,
        )
    check_workflow_contracts()
    print("AWS target fence fixtures passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
