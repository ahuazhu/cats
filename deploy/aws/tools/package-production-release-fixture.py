#!/usr/bin/env python3
"""Offline positive and negative fixture for production release packaging."""

from __future__ import annotations

import argparse
import importlib.util
import io
from pathlib import Path
import subprocess
import tarfile
import tempfile


def load_packager(path: Path):
    specification = importlib.util.spec_from_file_location("cats_package_release", path)
    if specification is None or specification.loader is None:
        raise AssertionError("could not load packager")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def arguments(root: Path, output: Path) -> argparse.Namespace:
    account = "123456789012"
    region = "us-east-1"
    return argparse.Namespace(
        source_repository=root,
        source_sha="a" * 40,
        output=output,
        expected_account_id=account,
        aws_region=region,
        build_host_instance_id="i-0123456789abcdef0",
        source_bucket=f"cats-qualification-v2-build-source-{account}-{region}",
        source_kms_alias_arn=(
            f"arn:aws:kms:{region}:{account}:alias/cats-qualification-v2-build-source"
        ),
        artifact_bucket=f"cats-qualification-v2-build-artifacts-{account}-{region}",
        control_image="123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control:exact",
        credential_refresher_image=(
            "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/refresher:exact"
        ),
        gateway_image="123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/gateway:exact",
        timeout_seconds=10_800,
        poll_interval_seconds=1,
    )


def make_transport(path: Path, members: list[tarfile.TarInfo]) -> None:
    uncompressed = path.with_suffix("")
    with tarfile.open(uncompressed, "w", format=tarfile.USTAR_FORMAT) as archive:
        for member in members:
            if member.isfile():
                raw = member.name.encode()
                member.size = len(raw)
                archive.addfile(member, io.BytesIO(raw))
            else:
                archive.addfile(member)
    subprocess.run(
        ["zstd", "-q", "-f", str(uncompressed), "-o", str(path)], check=True
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--packager", required=True, type=Path)
    options = parser.parse_args()
    packager_path = options.packager.resolve()
    package = load_packager(packager_path)
    repository = packager_path.parents[3]

    with tempfile.TemporaryDirectory(prefix="cats-production-package-fixture-") as temporary:
        scratch = Path(temporary)
        valid = arguments(repository, scratch / "valid-output")
        package.validate_arguments(valid)

        duplicate = arguments(repository, scratch / "duplicate-output")
        duplicate.gateway_image = duplicate.control_image
        try:
            package.validate_arguments(duplicate)
        except package.PackagingError as error:
            assert "distinct mutable tags" in str(error)
        else:
            raise AssertionError("packager accepted duplicate mutable image tags")

        command = package.remote_build_command(
            valid,
            {"manifest_sha256": "b" * 64, "bundle_sha256": "c" * 64},
        )
        for required in (
            "cats-checkout-exact-sha",
            "manual-release-host.sh",
            " prepare ",
            " verify ",
            " build ",
            "cats-publish-content-addressed artifacts",
            valid.control_image,
            valid.credential_refresher_image,
            valid.gateway_image,
            "jq -cnS",
        ):
            assert required in command, f"remote package command lost {required!r}"
        assert "runtime-provisioner" not in command
        assert "private-key" not in command

        observed_aws_commands: list[tuple[str, ...]] = []
        original_aws_json = package.aws_json

        def successful_ssm(_arguments, *aws_command):
            observed_aws_commands.append(aws_command)
            return {"Status": "Success", "ResponseCode": 0}

        package.aws_json = successful_ssm
        try:
            package.wait_ssm(valid, "command-id", "fixture command")
        finally:
            package.aws_json = original_aws_json
        assert observed_aws_commands == [
            (
                "ssm",
                "get-command-invocation",
                "--command-id",
                "command-id",
                "--instance-id",
                valid.build_host_instance_id,
            )
        ]

        member = tarfile.TarInfo("release-manifest.v1.json")
        member.mode = 0o444
        transport = scratch / "positive.tar.zst"
        make_transport(transport, [member])
        extracted = scratch / "positive"
        package.extract_transport(transport, extracted)
        assert (extracted / member.name).read_bytes() == member.name.encode()

        traversal = tarfile.TarInfo("../escape")
        traversal.mode = 0o444
        unsafe_transport = scratch / "unsafe.tar.zst"
        make_transport(unsafe_transport, [traversal])
        try:
            package.extract_transport(unsafe_transport, scratch / "unsafe")
        except package.PackagingError as error:
            assert "unsafe path" in str(error)
        else:
            raise AssertionError("packager extracted a traversal member")
        assert not (scratch / "escape").exists()

        link = tarfile.TarInfo("linked-manifest")
        link.type = tarfile.SYMTYPE
        link.linkname = "release-manifest.v1.json"
        link_transport = scratch / "link.tar.zst"
        make_transport(link_transport, [link])
        try:
            package.extract_transport(link_transport, scratch / "link")
        except package.PackagingError as error:
            assert "link or special member" in str(error)
        else:
            raise AssertionError("packager extracted a link member")

        duplicate_member = tarfile.TarInfo("release-manifest.v1.json")
        duplicate_member.mode = 0o444
        duplicate_transport = scratch / "duplicate.tar.zst"
        make_transport(duplicate_transport, [member, duplicate_member])
        try:
            package.extract_transport(duplicate_transport, scratch / "duplicate")
        except package.PackagingError as error:
            assert "duplicate member" in str(error)
        else:
            raise AssertionError("packager extracted a duplicate member")

        receipt = scratch / "receipt.json"
        package.write_new(receipt, package.canonical_json({"status": "ok"}))
        try:
            package.write_new(receipt, b"replacement")
        except package.PackagingError:
            pass
        else:
            raise AssertionError("packager replaced an existing receipt")

    print("production release packaging fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
