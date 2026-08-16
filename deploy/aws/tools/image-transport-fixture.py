#!/usr/bin/env python3
"""Calibrated positive and negative OCI transport verifier fixture."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


def run(command: list[str], *, succeeds: bool) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(command, check=False, capture_output=True)
    if (result.returncode == 0) != succeeds:
        raise AssertionError(
            f"unexpected exit {result.returncode}: {' '.join(command)}\n"
            f"stdout:\n{result.stdout.decode(errors='replace')}\n"
            f"stderr:\n{result.stderr.decode(errors='replace')}"
        )
    return result


def check_reference_rules(verifier: Path) -> None:
    """Check the registry-inference rules without building an image.

    BuildKit records the normalized name in `io.containerd.image.name`. The
    end-to-end fixture below used only a reference whose first component looks
    like a host, which is left untouched, so the short-reference rules stayed
    unexercised until a real release build failed on them.
    """
    specification = importlib.util.spec_from_file_location(
        "cats_verify_image_transport", verifier
    )
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    expected = {
        "cats/control-plane:cutover": "docker.io/cats/control-plane:cutover",
        "debian:bookworm-slim": "docker.io/library/debian:bookworm-slim",
        "cats.invalid/fixture/control-plane:exact": "cats.invalid/fixture/control-plane:exact",
        "public.ecr.aws/docker/library/rust:1.97": "public.ecr.aws/docker/library/rust:1.97",
        "localhost/probe:tag": "localhost/probe:tag",
        "127.0.0.1:5000/probe:tag": "127.0.0.1:5000/probe:tag",
    }
    for reference, canonical in expected.items():
        observed = module.canonical_image_name(reference)
        assert observed == canonical, f"{reference!r} -> {observed!r} != {canonical!r}"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--verifier", required=True, type=Path)
    parser.add_argument(
        "--reference-rules-only",
        action="store_true",
        help="check the registry-inference rules only; requires no container runtime",
    )
    arguments = parser.parse_args()
    verifier = arguments.verifier.resolve()
    check_reference_rules(verifier)
    if arguments.reference_rules_only:
        print("image transport reference rules: PASS")
        return 0
    with tempfile.TemporaryDirectory(prefix="cats-image-transport-") as temporary:
        root = Path(temporary)
        archive = root / "image.tar"
        metadata = root / "metadata.json"
        reference = "cats.invalid/fixture/control-plane:exact"
        subprocess.run(
            [
                "docker",
                "buildx",
                "build",
                "--platform",
                "linux/amd64",
                "--provenance=false",
                "--metadata-file",
                str(metadata),
                "--tag",
                reference,
                "--output",
                f"type=oci,dest={archive}",
                "-",
            ],
            input=b"FROM scratch\nLABEL cats.fixture=image-transport\n",
            check=True,
            stdout=subprocess.DEVNULL,
        )
        built = json.loads(metadata.read_bytes())
        command = [
            "python3",
            "-B",
            str(verifier),
            "--archive",
            str(archive),
            "--reference",
            reference,
            "--image-digest",
            built["containerimage.digest"],
            "--config-digest",
            built["containerimage.config.digest"],
        ]
        positive = run(command, succeeds=True)
        assert b"verified_image=" in positive.stdout

        wrong_reference = command.copy()
        wrong_reference[wrong_reference.index(reference)] = reference + "-wrong"
        negative = run(wrong_reference, succeeds=False)
        assert b"image name differs" in negative.stderr

        wrong_digest = command.copy()
        digest_index = wrong_digest.index(built["containerimage.digest"])
        wrong_digest[digest_index] = "sha256:" + "0" * 64
        negative = run(wrong_digest, succeeds=False)
        assert b"image digest differs" in negative.stderr

    print("image transport fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
