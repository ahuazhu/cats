#!/usr/bin/env python3
"""Build, publish and retain one exact complete production release."""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shlex
import stat
import subprocess
import sys
import tarfile
import time
from typing import Any


COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"(?:sha256:)?[0-9a-f]{64}\Z")
ACCOUNT = re.compile(r"[0-9]{12}\Z")
REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]\Z")
INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")
TERMINAL_SSM = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
MAX_TRANSPORT_BYTES = 5 * 1024 * 1024 * 1024
MAX_EXTRACTED_BYTES = 15 * 1024 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 128


class PackagingError(Exception):
    """The release could not be proven complete and exact."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_file(path: Path) -> str:
    measured = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            measured.update(chunk)
    return measured.hexdigest()


def write_new(path: Path, raw: bytes, mode: int = 0o444) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise PackagingError(f"output must be a new absolute path: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(
    command: list[str],
    *,
    input_bytes: bytes | None = None,
    capture_output: bool = True,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=input_bytes,
        capture_output=capture_output,
        check=False,
    )
    if result.returncode != 0:
        stderr = (
            ""
            if result.stderr is None
            else result.stderr.decode(errors="replace")[-8_192:]
        )
        raise PackagingError(
            f"command failed with exit {result.returncode}: {command[0]}: {stderr}"
        )
    return result


def aws_json(arguments: argparse.Namespace, *command: str) -> Any:
    result = run(
        [
            "aws",
            *command,
            "--region",
            arguments.aws_region,
            "--output",
            "json",
            "--no-cli-pager",
        ]
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise PackagingError(f"AWS returned invalid JSON for {command[0]}") from error


def require_object(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PackagingError(f"{label} is not an object")
    return value


def validate_arguments(arguments: argparse.Namespace) -> None:
    if ACCOUNT.fullmatch(arguments.expected_account_id) is None:
        raise PackagingError("--expected-account-id must be 12 digits")
    if REGION.fullmatch(arguments.aws_region) is None:
        raise PackagingError("--aws-region is invalid")
    if INSTANCE.fullmatch(arguments.build_host_instance_id) is None:
        raise PackagingError("--build-host-instance-id is invalid")
    if COMMIT.fullmatch(arguments.source_sha) is None:
        raise PackagingError("--source-sha must be one exact 40-hex commit")
    if not arguments.source_repository.is_absolute():
        raise PackagingError("--source-repository must be absolute")
    source = arguments.source_repository.resolve()
    if source != arguments.source_repository or not source.is_dir():
        raise PackagingError("--source-repository must be a resolved real directory")
    if not arguments.output.is_absolute() or arguments.output.exists() or arguments.output.is_symlink():
        raise PackagingError("--output must be a new absolute path")
    if not arguments.output.parent.is_dir() or arguments.output.parent.is_symlink():
        raise PackagingError("--output parent must be an existing real directory")
    if arguments.timeout_seconds < 600 or arguments.timeout_seconds > 17_280:
        raise PackagingError("--timeout-seconds must be between 600 and 17280")
    if arguments.poll_interval_seconds < 1 or arguments.poll_interval_seconds > 60:
        raise PackagingError("--poll-interval-seconds must be between 1 and 60")
    expected_source_bucket = (
        f"cats-qualification-v2-build-source-{arguments.expected_account_id}-{arguments.aws_region}"
    )
    if arguments.source_bucket != expected_source_bucket:
        raise PackagingError("source bucket is outside the qualification boundary")
    expected_source_alias = (
        f"arn:aws:kms:{arguments.aws_region}:{arguments.expected_account_id}:"
        "alias/cats-qualification-v2-build-source"
    )
    if arguments.source_kms_alias_arn != expected_source_alias:
        raise PackagingError("source KMS alias is outside the qualification boundary")
    expected_artifact_bucket = (
        f"cats-qualification-v2-build-artifacts-{arguments.expected_account_id}-{arguments.aws_region}"
    )
    if arguments.artifact_bucket != expected_artifact_bucket:
        raise PackagingError("artifact bucket is outside the qualification boundary")
    image_validator = arguments.source_repository / "deploy/aws/tools/manual_image_reference.py"
    run(
        [
            sys.executable,
            "-B",
            str(image_validator),
            arguments.control_image,
            arguments.credential_refresher_image,
            arguments.gateway_image,
        ]
    )


def verify_aws_target(arguments: argparse.Namespace) -> None:
    caller = require_object(
        aws_json(arguments, "sts", "get-caller-identity"), "AWS caller identity"
    )
    if caller.get("Account") != arguments.expected_account_id:
        raise PackagingError("AWS caller account differs from the reviewed account")
    bucket = require_object(
        aws_json(
            arguments,
            "s3api",
            "get-bucket-location",
            "--bucket",
            arguments.source_bucket,
            "--expected-bucket-owner",
            arguments.expected_account_id,
        ),
        "source bucket location",
    )
    observed_region = bucket.get("LocationConstraint") or "us-east-1"
    if observed_region != arguments.aws_region:
        raise PackagingError("source bucket region differs from --aws-region")


def send_ssm(arguments: argparse.Namespace, commands: list[str], timeout: int) -> str:
    response = require_object(
        aws_json(
            arguments,
            "ssm",
            "send-command",
            "--instance-ids",
            arguments.build_host_instance_id,
            "--document-name",
            "AWS-RunShellScript",
            "--parameters",
            json.dumps(
                {
                    "commands": commands,
                    "executionTimeout": [str(timeout)],
                },
                separators=(",", ":"),
            ),
        ),
        "SSM send-command response",
    )
    command = require_object(response.get("Command"), "SSM command")
    command_id = command.get("CommandId")
    if not isinstance(command_id, str) or not command_id:
        raise PackagingError("SSM did not return a command ID")
    return command_id


def wait_ssm(arguments: argparse.Namespace, command_id: str, label: str) -> dict[str, Any]:
    deadline = time.monotonic() + arguments.timeout_seconds
    previous = None
    while time.monotonic() < deadline:
        try:
            response = require_object(
                aws_json(
                    arguments,
                    "ssm",
                    "get-command-invocation",
                    "--command-id",
                    command_id,
                    "--instance-id",
                    arguments.build_host_instance_id,
                ),
                "SSM invocation",
            )
        except PackagingError as error:
            if "InvocationDoesNotExist" not in str(error):
                raise
            time.sleep(arguments.poll_interval_seconds)
            continue
        status = response.get("Status")
        if status != previous:
            print(f"{label}: {status} ({command_id})", flush=True)
            previous = status
        if status in TERMINAL_SSM:
            if status != "Success" or response.get("ResponseCode") != 0:
                stderr = str(response.get("StandardErrorContent", ""))[-8_192:]
                stdout = str(response.get("StandardOutputContent", ""))[-8_192:]
                raise PackagingError(
                    f"{label} failed ({status}, {command_id})\nstdout:\n{stdout}\nstderr:\n{stderr}"
                )
            return response
        time.sleep(arguments.poll_interval_seconds)
    raise PackagingError(f"{label} timed out; retained SSM command ID {command_id}")


def verify_readiness(arguments: argparse.Namespace) -> tuple[str, dict[str, Any]]:
    command_id = send_ssm(
        arguments, ["/usr/local/bin/cats-verify-build-host-readiness"], 120
    )
    response = wait_ssm(arguments, command_id, "build-host readiness")
    try:
        readiness = require_object(
            json.loads(response["StandardOutputContent"]), "build-host readiness"
        )
    except (KeyError, json.JSONDecodeError) as error:
        raise PackagingError("build-host readiness output is invalid") from error
    qualification = require_object(readiness.get("qualification"), "qualification identity")
    host = require_object(readiness.get("host"), "build-host identity")
    publication = require_object(readiness.get("publication"), "artifact publication identity")
    source = require_object(readiness.get("source_policy"), "source policy")
    if (
        readiness.get("status") != "ready"
        or qualification.get("account_id") != arguments.expected_account_id
        or qualification.get("region") != arguments.aws_region
        or host.get("instance_id") != arguments.build_host_instance_id
        or host.get("architecture") != "x86_64"
        or publication.get("bucket") != arguments.artifact_bucket
        or source.get("source_bucket") != arguments.source_bucket
    ):
        raise PackagingError("build-host readiness differs from the reviewed cell")
    return command_id, readiness


def publish_source(arguments: argparse.Namespace, output: Path) -> dict[str, Any]:
    work = output / "source-work"
    evidence = output / "source-publication.v1.json"
    work.mkdir(mode=0o700)
    helper = (
        arguments.source_repository
        / "deploy/aws/terraform/qualification/build-host/tools/publish-source-bundle.sh"
    )
    result = run(
        [
            "/bin/bash",
            str(helper),
            arguments.expected_account_id,
            str(arguments.source_repository),
            arguments.source_sha,
            arguments.source_bucket,
            arguments.source_kms_alias_arn,
            str(work),
            str(evidence),
        ]
    )
    try:
        value = require_object(json.loads(result.stdout), "source publication result")
    except json.JSONDecodeError as error:
        raise PackagingError("source publisher returned invalid JSON") from error
    if value.get("source_sha") != arguments.source_sha:
        raise PackagingError("source publisher returned another commit")
    for field in ("manifest_sha256", "bundle_sha256"):
        if not isinstance(value.get(field), str) or re.fullmatch(
            r"[0-9a-f]{64}", value[field]
        ) is None:
            raise PackagingError(f"source publisher returned invalid {field}")
    return value


def remote_build_command(arguments: argparse.Namespace, source: dict[str, Any]) -> str:
    values = [
        arguments.source_sha,
        source["manifest_sha256"],
        source["bundle_sha256"],
        arguments.control_image,
        arguments.credential_refresher_image,
        arguments.gateway_image,
    ]
    quoted = " ".join(shlex.quote(value) for value in values)
    helper = (
        "/srv/cats-build/source/deploy/aws/terraform/qualification/"
        "build-host/tools/manual-release-host.sh"
    )
    return f"""/bin/bash -c {shlex.quote(f'''set -Eeuo pipefail
log=$(mktemp /var/tmp/cats-production-package.XXXXXX)
finish() {{
  rc=$?
  trap - EXIT
  if (( rc != 0 )); then tail -n 160 "$log" >&2 || true; fi
  rm -f -- "$log"
  exit "$rc"
}}
trap finish EXIT
cats-checkout-exact-sha {values[0]} {values[1]} {values[2]} >"$log" 2>&1
/bin/bash {helper} prepare {quoted} >>"$log" 2>&1
/bin/bash {helper} verify {quoted} >>"$log" 2>&1
/bin/bash {helper} build {quoted} >>"$log" 2>&1
build_json=$(tail -n 1 "$log")
jq -e --arg source_sha {shlex.quote(arguments.source_sha)} '.status == "built" and .source_sha == $source_sha and (.transport_archive_sha256 | test("^[0-9a-f]{{64}}$"))' <<<"$build_json" >/dev/null
transport=$(jq -er '.transport_archive' <<<"$build_json")
publication=$(cats-publish-content-addressed artifacts "$transport")
jq -e --argjson build "$build_json" '.source_sha == $build.source_sha and .sha256 == $build.transport_archive_sha256' <<<"$publication" >/dev/null
jq -cnS --argjson build "$build_json" --argjson publication "$publication" '{{schema_version:1,status:"published",build:$build,publication:$publication}}'
''')}"""


def build_release(
    arguments: argparse.Namespace, source: dict[str, Any]
) -> tuple[str, dict[str, Any]]:
    command_id = send_ssm(
        arguments,
        [remote_build_command(arguments, source)],
        arguments.timeout_seconds,
    )
    response = wait_ssm(arguments, command_id, "native production package")
    stdout = str(response.get("StandardOutputContent", "")).strip()
    try:
        result = require_object(json.loads(stdout), "native package result")
    except json.JSONDecodeError as error:
        raise PackagingError("native package result is not canonical JSON") from error
    build = require_object(result.get("build"), "native build result")
    publication = require_object(result.get("publication"), "artifact publication")
    if (
        result.get("status") != "published"
        or build.get("status") != "built"
        or build.get("source_sha") != arguments.source_sha
        or publication.get("source_sha") != arguments.source_sha
        or publication.get("bucket") != arguments.artifact_bucket
        or publication.get("sha256") != build.get("transport_archive_sha256")
    ):
        raise PackagingError("native package result does not bind the requested release")
    digest = publication.get("sha256")
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise PackagingError("artifact publication returned an invalid digest")
    return command_id, result


def download_transport(
    arguments: argparse.Namespace, package: dict[str, Any], output: Path
) -> Path:
    publication = require_object(package["publication"], "artifact publication")
    digest = publication["sha256"]
    key = publication.get("key")
    if key != f"artifacts/sha256/{digest}":
        raise PackagingError("artifact publication key is not content-addressed")
    path = output / f"cats-production-release-{arguments.source_sha}.tar.zst"
    response = require_object(
        aws_json(
            arguments,
            "s3api",
            "get-object",
            "--bucket",
            arguments.artifact_bucket,
            "--expected-bucket-owner",
            arguments.expected_account_id,
            "--key",
            key,
            "--version-id",
            str(publication.get("version_id")),
            "--checksum-mode",
            "ENABLED",
            str(path),
        ),
        "artifact download",
    )
    if path.stat().st_size <= 0 or path.stat().st_size > MAX_TRANSPORT_BYTES:
        raise PackagingError("downloaded release transport is outside the 5 GiB boundary")
    if sha256_file(path) != digest:
        raise PackagingError("downloaded release transport digest differs")
    expected_checksum = base64.b64encode(bytes.fromhex(digest)).decode()
    if response.get("ChecksumSHA256") != expected_checksum:
        raise PackagingError("downloaded release transport checksum differs")
    path.chmod(0o444)
    return path


def extract_transport(transport: Path, release: Path) -> None:
    release.mkdir(mode=0o700)
    decoder = subprocess.Popen(["zstd", "-dc", str(transport)], stdout=subprocess.PIPE)
    assert decoder.stdout is not None
    try:
        with tarfile.open(fileobj=decoder.stdout, mode="r|") as archive:
            members = []
            member_names: set[str] = set()
            extracted_bytes = 0
            for member in archive:
                if len(members) >= MAX_ARCHIVE_MEMBERS:
                    raise PackagingError("release transport has too many members")
                path = PurePosixPath(member.name)
                if member.name.startswith("/") or ".." in path.parts:
                    raise PackagingError("release transport has an unsafe path")
                if not (member.isdir() or member.isreg()):
                    raise PackagingError("release transport contains a link or special member")
                if member.name in member_names:
                    raise PackagingError("release transport contains a duplicate member")
                member_names.add(member.name)
                if member.size < 0 or extracted_bytes + member.size > MAX_EXTRACTED_BYTES:
                    raise PackagingError("release transport exceeds the 15 GiB extraction boundary")
                extracted_bytes += member.size
                members.append(member)
                archive.extract(member, release, filter="data")
    except BaseException:
        decoder.stdout.close()
        decoder.terminate()
        decoder.wait()
        raise
    finally:
        if not decoder.stdout.closed:
            decoder.stdout.close()
    if decoder.wait() != 0:
        raise PackagingError("zstd rejected the release transport")
    if not members:
        raise PackagingError("release transport is empty")


def publish_images(arguments: argparse.Namespace, release: Path, output: Path) -> Path:
    manifest = release / "release-manifest.v1.json"
    if not manifest.is_file() or manifest.is_symlink():
        raise PackagingError("release transport lacks release-manifest.v1.json")
    manifest_digest = "sha256:" + sha256_file(manifest)
    registry = arguments.control_image.split("/", 1)[0]
    if any(
        reference.split("/", 1)[0] != registry
        for reference in (
            arguments.credential_refresher_image,
            arguments.gateway_image,
        )
    ):
        raise PackagingError("all production images must use the same registry login boundary")
    password = run(
        ["aws", "ecr", "get-login-password", "--region", arguments.aws_region]
    ).stdout
    run(
        ["docker", "login", "--username", "AWS", "--password-stdin", registry],
        input_bytes=password,
    )
    promoted = output / "release-manifest.registry-verified.v1.json"
    publisher = arguments.source_repository / "deploy/aws/tools/publish-manual-release.sh"
    run(
        [
            "/bin/bash",
            str(publisher),
            "--release",
            str(release),
            "--manifest-sha256",
            manifest_digest,
            "--output-manifest",
            str(promoted),
        ],
        capture_output=False,
    )
    if not promoted.is_file() or promoted.is_symlink():
        raise PackagingError("image publisher did not create the promoted manifest")
    promoted.chmod(0o444)
    return promoted


def package(arguments: argparse.Namespace) -> None:
    validate_arguments(arguments)
    verify_aws_target(arguments)
    arguments.output.mkdir(mode=0o700)
    readiness_command_id, readiness = verify_readiness(arguments)
    write_new(
        arguments.output / "build-host-readiness.v1.json",
        canonical_json(readiness),
    )
    source = publish_source(arguments, arguments.output)
    build_command_id, native_package = build_release(arguments, source)
    write_new(
        arguments.output / "native-package-result.v1.json",
        canonical_json(native_package),
    )
    transport = download_transport(arguments, native_package, arguments.output)
    release = arguments.output / "release"
    extract_transport(transport, release)
    promoted = publish_images(arguments, release, arguments.output)
    release_manifest = release / "release-manifest.v1.json"
    receipt = {
        "artifact_publication": native_package["publication"],
        "build_host_instance_id": arguments.build_host_instance_id,
        "build_ssm_command_id": build_command_id,
        "images": {
            "control_plane": arguments.control_image,
            "credential_refresher": arguments.credential_refresher_image,
            "gateway": arguments.gateway_image,
        },
        "promoted_release_manifest_sha256": "sha256:" + sha256_file(promoted),
        "readiness_ssm_command_id": readiness_command_id,
        "release_manifest_sha256": "sha256:" + sha256_file(release_manifest),
        "schema_version": 1,
        "source_bundle_sha256": source["bundle_sha256"],
        "source_manifest_sha256": source["manifest_sha256"],
        "source_sha": arguments.source_sha,
        "status": "registry_verified",
        "transport_sha256": native_package["publication"]["sha256"],
    }
    write_new(
        arguments.output / "production-package-receipt.v1.json",
        canonical_json(receipt),
    )
    print(
        canonical_json(
            {
                "output": str(arguments.output),
                "promoted_release_manifest_sha256": receipt[
                    "promoted_release_manifest_sha256"
                ],
                "source_sha": arguments.source_sha,
                "status": "registry_verified",
            }
        ).decode()
    )


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-repository", required=True, type=Path)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--build-host-instance-id", required=True)
    parser.add_argument("--source-bucket", required=True)
    parser.add_argument("--source-kms-alias-arn", required=True)
    parser.add_argument("--artifact-bucket", required=True)
    parser.add_argument("--control-image", required=True)
    parser.add_argument("--credential-refresher-image", required=True)
    parser.add_argument("--gateway-image", required=True)
    parser.add_argument("--timeout-seconds", type=int, default=10_800)
    parser.add_argument("--poll-interval-seconds", type=int, default=10)
    return parser.parse_args()


def main() -> int:
    try:
        package(parse_arguments())
    except (OSError, PackagingError, subprocess.SubprocessError) as error:
        print(f"production release packaging failed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
