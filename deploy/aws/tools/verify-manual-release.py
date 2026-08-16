#!/usr/bin/env python3
"""Verify the three production artifacts and write one canonical release receipt."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tarfile
import tempfile
from typing import Any

sys.dont_write_bytecode = True
from manual_image_reference import ImageReferenceError, require_distinct_image_tags


MANIFEST_DOMAIN = b"cats.release.guest-runtime-manifest.v1\0"
INPUT_DOMAIN = b"cats.release.manual-build-inputs.v1\0"
SHA256_PATTERN = re.compile(r"sha256:[0-9a-f]{64}\Z")
GIT_OBJECT_PATTERN = re.compile(r"[0-9a-f]{40}(?:[0-9a-f]{24})?\Z")
INPUT_LABEL_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,63}\Z")
MAX_MANIFEST_BYTES = 4096
MAX_PROFILE_BYTES = 4096
MAX_BOOT_MEMBER_BYTES = 512 * 1024 * 1024
MAX_WORKER_BUNDLE_BYTES = 2 * 1024 * 1024 * 1024
MAX_WORKER_ENTRIES = 48
MAX_WORKER_MEMBER_BYTES = 512 * 1024 * 1024
MAX_GATEWAY_BINARY_BYTES = 256 * 1024 * 1024
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
WORKER_STATIC_FILES = {
    "cats",
    "cats-noded",
    "cats-route-v2-node-r1-validator",
    "cats-vmm-launcher",
    "cats-runtime-e3-probe",
    "cats-usage-schema-v16-verifier",
    "cats-usage-terminal-receipt-verifier",
    "cats-blockd",
    "cats-guest-agent",
    "cats-e3-guest-workload",
    "update-guest-seed.sh",
    "require-idle-worker.sh",
    "setup-guest-network.sh",
    "old-host-positive-stop.py",
    "render-postgres-url.sh",
    "install-guest-runtime-release.sh",
    "validate-node-identity-installation.sh",
    "install-route-v2-node-r1.sh",
    "worker-deployment-transaction.sh",
    "guest-systemd/cats-grow-root.service",
    "guest-systemd/cats-guest-agent.service",
    "guest-systemd/cats-mount-propagation.service",
    "guest-systemd/cats-network.service",
    "cats-worker.service",
    "cats-postgres-url.service",
    "cats-postgres-url.timer",
    "guest-runtime-release.v1/manifest.v1.json",
    "guest-runtime-release.v1/guest-runtime-profile.v1.json",
    "guest-runtime-release.v1/guest/vmlinuz",
}
WORKER_DIRECTORIES = {
    ".",
    "guest-systemd",
    "guest-runtime-release.v1",
    "guest-runtime-release.v1/guest",
}
WORKER_EXECUTABLE_FILES = {
    "cats",
    "cats-noded",
    "cats-route-v2-node-r1-validator",
    "cats-vmm-launcher",
    "cats-runtime-e3-probe",
    "cats-usage-schema-v16-verifier",
    "cats-usage-terminal-receipt-verifier",
    "cats-blockd",
    "cats-guest-agent",
    "cats-e3-guest-workload",
    "update-guest-seed.sh",
    "require-idle-worker.sh",
    "setup-guest-network.sh",
    "old-host-positive-stop.py",
    "render-postgres-url.sh",
    "install-guest-runtime-release.sh",
    "validate-node-identity-installation.sh",
    "install-route-v2-node-r1.sh",
    "worker-deployment-transaction.sh",
}
WORKER_BINARY_MEMBER_FILES = {
    relative for relative in WORKER_EXECUTABLE_FILES if relative.startswith("cats")
}


class VerificationError(Exception):
    """A release artifact violated the frozen composition contract."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def _same_metadata(before: os.stat_result, after: os.stat_result) -> bool:
    return (
        before.st_dev,
        before.st_ino,
        before.st_mode,
        before.st_uid,
        before.st_gid,
        before.st_nlink,
        before.st_size,
        before.st_mtime_ns,
        before.st_ctime_ns,
    ) == (
        after.st_dev,
        after.st_ino,
        after.st_mode,
        after.st_uid,
        after.st_gid,
        after.st_nlink,
        after.st_size,
        after.st_mtime_ns,
        after.st_ctime_ns,
    )


def read_regular(path: Path, *, cap: int | None = None, mode: int | None = None) -> bytes:
    try:
        before = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect {path}: {error}") from error
    if not stat.S_ISREG(before.st_mode) or stat.S_ISLNK(before.st_mode):
        raise VerificationError(f"artifact member is not a regular file: {path}")
    if before.st_nlink != 1:
        raise VerificationError(f"artifact member is not single-link: {path}")
    if mode is not None and stat.S_IMODE(before.st_mode) != mode:
        raise VerificationError(f"artifact member mode is not {mode:04o}: {path}")
    if before.st_size <= 0:
        raise VerificationError(f"artifact member is empty: {path}")
    if cap is not None and before.st_size > cap:
        raise VerificationError(f"artifact member exceeds {cap} bytes: {path}")

    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(f"cannot open {path}: {error}") from error
    try:
        opened = os.fstat(descriptor)
        if not _same_metadata(before, opened):
            raise VerificationError(f"artifact member changed before read: {path}")
        chunks: list[bytes] = []
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise VerificationError(f"artifact member ended during read: {path}")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise VerificationError(f"artifact member grew during read: {path}")
        after = os.fstat(descriptor)
        if not _same_metadata(opened, after):
            raise VerificationError(f"artifact member changed during read: {path}")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def hash_regular(path: Path, *, cap: int | None = None) -> tuple[str, int]:
    try:
        before = path.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or stat.S_ISLNK(before.st_mode)
        or before.st_nlink != 1
        or before.st_size <= 0
    ):
        raise VerificationError(f"fingerprinted input is not a non-empty single-link file: {path}")
    if cap is not None and before.st_size > cap:
        raise VerificationError(f"fingerprinted input exceeds {cap} bytes: {path}")
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise VerificationError(f"cannot open {path}: {error}") from error
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if not _same_metadata(before, opened):
            raise VerificationError(f"fingerprinted input changed before read: {path}")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise VerificationError(f"fingerprinted input ended during read: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise VerificationError(f"fingerprinted input grew during read: {path}")
        after = os.fstat(descriptor)
        if not _same_metadata(opened, after):
            raise VerificationError(f"fingerprinted input changed during read: {path}")
    finally:
        os.close(descriptor)
    return "sha256:" + digest.hexdigest(), before.st_size


def decode_canonical_json(raw: bytes, *, name: str) -> dict[str, Any]:
    def closed_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise VerificationError(f"{name} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=closed_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise VerificationError(f"{name} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise VerificationError(f"{name} is not canonical JSON")
    return value


def require_sha256(value: Any, *, name: str) -> str:
    if not isinstance(value, str) or SHA256_PATTERN.fullmatch(value) is None:
        raise VerificationError(f"{name} is not a canonical SHA-256 digest")
    return value


def validate_release_member(
    manifest: dict[str, Any], key: str, literal_path: str, raw: bytes
) -> dict[str, Any]:
    entry = manifest.get(key)
    if not isinstance(entry, dict) or set(entry) != {"path", "sha256", "size_bytes"}:
        raise VerificationError(f"Guest manifest entry {key} has the wrong shape")
    if entry["path"] != literal_path:
        raise VerificationError(f"Guest manifest entry {key} has the wrong path")
    digest = require_sha256(entry["sha256"], name=f"Guest manifest {key} digest")
    if type(entry["size_bytes"]) is not int or entry["size_bytes"] != len(raw):
        raise VerificationError(f"Guest manifest entry {key} has the wrong size")
    if digest != sha256_bytes(raw):
        raise VerificationError(f"Guest manifest entry {key} has the wrong digest")
    return entry


def closed_release_paths(root: Path, expected_files: set[str]) -> None:
    try:
        root_metadata = root.lstat()
    except OSError as error:
        raise VerificationError(f"cannot inspect Guest release root {root}: {error}") from error
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise VerificationError(f"Guest release root is not a real directory: {root}")
    actual_files: set[str] = set()
    actual_directories: set[str] = set()
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"Guest release contains a non-directory: {relative}")
            actual_directories.add(relative)
        for name in filenames:
            path = directory_path / name
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"Guest release contains a non-file: {relative}")
            actual_files.add(relative)
    if actual_directories != {"guest"}:
        raise VerificationError(
            f"Guest release directory set differs: {sorted(actual_directories ^ {'guest'})}"
        )
    if actual_files != expected_files:
        raise VerificationError(
            f"Guest release file set differs: {sorted(actual_files ^ expected_files)}"
        )


def normalized_tar_path(name: str) -> str:
    while name.startswith("./"):
        name = name[2:]
    if name in ("", "."):
        return "."
    parts = name.split("/")
    if name.startswith("/") or any(part in ("", ".", "..") for part in parts):
        raise VerificationError(f"worker bundle has unsafe path {name!r}")
    return "/".join(parts)


def decompress_worker_bundle(bundle: Path, destination: Path) -> None:
    hash_regular(bundle, cap=MAX_WORKER_BUNDLE_BYTES)
    stderr_path = destination.with_suffix(".stderr")
    with destination.open("xb") as output, stderr_path.open("xb") as errors:
        try:
            process = subprocess.Popen(
                ["zstd", "--decompress", "--stdout", "--", str(bundle)],
                stdout=subprocess.PIPE,
                stderr=errors,
            )
        except OSError as error:
            raise VerificationError(f"cannot start zstd: {error}") from error
        assert process.stdout is not None
        total = 0
        while chunk := process.stdout.read(1024 * 1024):
            total += len(chunk)
            if total > MAX_WORKER_BUNDLE_BYTES:
                process.kill()
                process.wait()
                raise VerificationError("worker bundle expands beyond its 2 GiB boundary")
            output.write(chunk)
        result = process.wait()
    if result != 0:
        error = stderr_path.read_text(errors="replace")[:4096]
        raise VerificationError(f"zstd rejected the worker bundle: {error}")
    stderr_path.unlink()


def preflight_worker_archive(archive: tarfile.TarFile) -> list[tuple[tarfile.TarInfo, str]]:
    entries: list[tuple[tarfile.TarInfo, str]] = []
    files: set[str] = set()
    directories: set[str] = set()
    seen: set[str] = set()
    total_size = 0
    for member in archive:
        if len(entries) > MAX_WORKER_ENTRIES:
            raise VerificationError(
                f"worker bundle has more than {MAX_WORKER_ENTRIES} archive entries"
            )
        relative = normalized_tar_path(member.name)
        if relative in seen:
            raise VerificationError(f"worker bundle repeats path {relative!r}")
        seen.add(relative)
        if member.uid != 0 or member.gid != 0:
            raise VerificationError(f"worker bundle member is not root-owned: {relative}")
        if member.isdir():
            allowed_modes = {0o700, 0o755} if relative == "." else {0o755}
            if member.mode & 0o777 not in allowed_modes:
                raise VerificationError(f"worker bundle directory mode is not 0755: {relative}")
            directories.add(relative)
        elif member.isreg():
            expected_mode = 0o755 if relative in WORKER_EXECUTABLE_FILES else 0o644
            if member.mode & 0o777 != expected_mode:
                raise VerificationError(
                    f"worker bundle member mode is not {expected_mode:04o}: {relative}"
                )
            member_cap = MAX_WORKER_MEMBER_BYTES
            if relative.endswith("manifest.v1.json") or relative.endswith(
                "guest-runtime-profile.v1.json"
            ):
                member_cap = MAX_MANIFEST_BYTES
            if member.size <= 0 or member.size > member_cap:
                raise VerificationError(f"worker bundle member size is invalid: {relative}")
            total_size += member.size
            if total_size > MAX_WORKER_BUNDLE_BYTES:
                raise VerificationError("worker bundle members exceed the 2 GiB boundary")
            files.add(relative)
        else:
            raise VerificationError(f"worker bundle contains a link or special member: {relative}")
        entries.append((member, relative))

    expected_without_initramfs = WORKER_STATIC_FILES
    expected_with_initramfs = WORKER_STATIC_FILES | {
        "guest-runtime-release.v1/guest/initramfs.img"
    }
    if files not in (expected_without_initramfs, expected_with_initramfs):
        alternatives = [files ^ expected_without_initramfs, files ^ expected_with_initramfs]
        difference = min(alternatives, key=len)
        raise VerificationError(f"worker bundle file set differs: {sorted(difference)}")
    if directories != WORKER_DIRECTORIES:
        raise VerificationError(
            f"worker bundle directory set differs: {sorted(directories ^ WORKER_DIRECTORIES)}"
        )
    return entries


def require_zero_tar_trailer(path: Path, offset: int) -> None:
    with path.open("rb", buffering=0) as source:
        source.seek(offset)
        while chunk := source.read(1024 * 1024):
            if any(chunk):
                raise VerificationError("worker bundle has data after its first tar end marker")


def extract_worker_bundle(bundle: Path, root: Path) -> None:
    tar_path = root.parent / "worker.tar"
    decompress_worker_bundle(bundle, tar_path)
    try:
        with tarfile.open(tar_path, mode="r:") as archive:
            entries = preflight_worker_archive(archive)
            require_zero_tar_trailer(tar_path, archive.offset)
            root.mkdir(mode=0o700)
            for _member, relative in sorted(
                entries, key=lambda entry: (entry[1].count("/"), entry[1])
            ):
                if relative != "." and _member.isdir():
                    root.joinpath(*relative.split("/")).mkdir(mode=0o700)
            for member, relative in entries:
                if member.isdir():
                    continue
                path = root.joinpath(*relative.split("/"))
                source = archive.extractfile(member)
                if source is None:
                    raise VerificationError(f"cannot read worker bundle member: {relative}")
                flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                if hasattr(os, "O_NOFOLLOW"):
                    flags |= os.O_NOFOLLOW
                descriptor = os.open(path, flags, member.mode & 0o777)
                written = 0
                try:
                    os.fchmod(descriptor, member.mode & 0o777)
                    while chunk := source.read(1024 * 1024):
                        written += len(chunk)
                        if written > member.size:
                            raise VerificationError(
                                f"worker bundle member grew during extraction: {relative}"
                            )
                        offset = 0
                        while offset < len(chunk):
                            offset += os.write(descriptor, chunk[offset:])
                    if written != member.size:
                        raise VerificationError(
                            f"worker bundle member ended during extraction: {relative}"
                        )
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
                    source.close()
    except tarfile.TarError as error:
        raise VerificationError(f"worker bundle is not a valid tar archive: {error}") from error


def verify_guest_release(root: Path) -> dict[str, Any]:
    manifest_raw = read_regular(root / "manifest.v1.json", cap=MAX_MANIFEST_BYTES, mode=0o644)
    manifest = decode_canonical_json(manifest_raw, name="Guest runtime release manifest")
    if set(manifest) != {"version", "guest_runtime_profile", "kernel", "initramfs"}:
        raise VerificationError("Guest runtime release manifest has the wrong shape")
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise VerificationError("Guest runtime release manifest has the wrong version")
    if not isinstance(manifest["guest_runtime_profile"], dict) or not isinstance(
        manifest["kernel"], dict
    ):
        raise VerificationError("Guest runtime release manifest members have the wrong type")
    if manifest["initramfs"] is not None and not isinstance(manifest["initramfs"], dict):
        raise VerificationError("Guest runtime release initramfs has the wrong type")

    expected_files = {
        "manifest.v1.json",
        "guest-runtime-profile.v1.json",
        "guest/vmlinuz",
    }
    if manifest["initramfs"] is not None:
        expected_files.add("guest/initramfs.img")
    closed_release_paths(root, expected_files)

    profile_raw = read_regular(
        root / "guest-runtime-profile.v1.json", cap=MAX_PROFILE_BYTES, mode=0o644
    )
    kernel_raw = read_regular(
        root / "guest/vmlinuz", cap=MAX_BOOT_MEMBER_BYTES, mode=0o644
    )
    initramfs_raw = None
    if manifest["initramfs"] is not None:
        initramfs_raw = read_regular(
            root / "guest/initramfs.img", cap=MAX_BOOT_MEMBER_BYTES, mode=0o644
        )

    profile_member = validate_release_member(
        manifest, "guest_runtime_profile", "guest-runtime-profile.v1.json", profile_raw
    )
    kernel_member = validate_release_member(manifest, "kernel", "guest/vmlinuz", kernel_raw)
    if initramfs_raw is None:
        initramfs_member = None
    else:
        initramfs_member = validate_release_member(
            manifest, "initramfs", "guest/initramfs.img", initramfs_raw
        )

    profile = decode_canonical_json(profile_raw, name="Guest runtime profile")
    if set(profile) != {
        "version",
        "kernel_digest",
        "initramfs_digest",
        "kernel_cmdline",
        "guest_agent_protocol_version",
    }:
        raise VerificationError("Guest runtime profile has the wrong shape")
    if type(profile["version"]) is not int or profile["version"] != 1:
        raise VerificationError("Guest runtime profile has the wrong version")
    if (
        type(profile["guest_agent_protocol_version"]) is not int
        or profile["guest_agent_protocol_version"] != 1
    ):
        raise VerificationError("Guest Agent protocol has the wrong version")
    if (
        not isinstance(profile["kernel_cmdline"], str)
        or not profile["kernel_cmdline"]
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in profile["kernel_cmdline"])
    ):
        raise VerificationError("Guest kernel command line is not non-empty printable ASCII")
    if require_sha256(profile["kernel_digest"], name="Guest profile kernel digest") != kernel_member[
        "sha256"
    ]:
        raise VerificationError("Guest profile kernel digest differs from its manifest")
    if initramfs_member is None:
        if profile["initramfs_digest"] is not None:
            raise VerificationError("Guest profile names an initramfs absent from its manifest")
    elif require_sha256(
        profile["initramfs_digest"], name="Guest profile initramfs digest"
    ) != initramfs_member["sha256"]:
        raise VerificationError("Guest profile initramfs digest differs from its manifest")

    return {
        "manifest_raw": manifest_raw,
        "profile_raw": profile_raw,
        "kernel_raw": kernel_raw,
        "initramfs_raw": initramfs_raw,
        "manifest_sha256": sha256_bytes(manifest_raw),
        "profile_sha256": profile_member["sha256"],
        "kernel": kernel_member,
        "initramfs": initramfs_member,
        "release_id": sha256_bytes(MANIFEST_DOMAIN + manifest_raw),
    }


def verify_exact_copy(path: Path, expected: bytes, *, label: str) -> str:
    actual = read_regular(path, mode=0o644)
    if actual != expected:
        raise VerificationError(f"{label} is not byte-identical to the shared Guest release")
    return sha256_bytes(actual)


def verify_reviewed_worker_program(path: Path, expected: bytes) -> str:
    actual = read_regular(path, cap=MAX_WORKER_MEMBER_BYTES, mode=0o755)
    if actual != expected:
        raise VerificationError(
            "worker old-host-positive-stop.py is not byte-identical to reviewed input "
            "old_host_positive_stop"
        )
    return sha256_bytes(actual)


def parse_input_file(raw: str) -> tuple[str, Path]:
    label, separator, path = raw.partition("=")
    if separator != "=" or INPUT_LABEL_PATTERN.fullmatch(label) is None or not path:
        raise argparse.ArgumentTypeError("input files must use lowercase_label=/absolute/path")
    candidate = Path(path)
    if not candidate.is_absolute():
        raise argparse.ArgumentTypeError("fingerprinted input paths must be absolute")
    return label, candidate


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--shared-guest-runtime", required=True, type=Path)
    parser.add_argument("--control-root", required=True, type=Path)
    parser.add_argument("--gateway-image-root", required=True, type=Path)
    parser.add_argument("--worker-bundle", required=True, type=Path)
    parser.add_argument("--control-image-reference", required=True)
    parser.add_argument("--control-image-digest", required=True)
    parser.add_argument("--control-image-config-digest", required=True)
    parser.add_argument("--control-image-registry-verified", choices=("true", "false"), required=True)
    parser.add_argument("--gateway-image-reference", required=True)
    parser.add_argument("--gateway-image-digest", required=True)
    parser.add_argument("--gateway-image-config-digest", required=True)
    parser.add_argument("--gateway-image-registry-verified", choices=("true", "false"), required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-tree", required=True)
    parser.add_argument("--source-fingerprint", required=True)
    parser.add_argument("--platform", default="linux/amd64")
    parser.add_argument("--guest-target", default="x86_64-unknown-linux-musl")
    parser.add_argument("--input-file", action="append", default=[], type=parse_input_file)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def parse_registry_candidate_arguments(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Verify or registry-promote an existing manual release manifest."
    )
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--manifest-sha256", required=True)
    parser.add_argument("--control-registry-digest")
    parser.add_argument("--gateway-registry-digest")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args(argv)
    promotion = (
        arguments.control_registry_digest,
        arguments.gateway_registry_digest,
        arguments.output,
    )
    if any(value is not None for value in promotion) and not all(
        value is not None for value in promotion
    ):
        parser.error("registry promotion requires both registry digests and --output")
    return arguments


def validate_existing_release_manifest(value: dict[str, Any]) -> dict[str, dict[str, str]]:
    if set(value) != {"artifacts", "build_inputs", "guest_runtime", "source", "version"}:
        raise VerificationError("existing release manifest has the wrong top-level shape")
    if type(value["version"]) is not int or value["version"] != 1:
        raise VerificationError("existing release manifest version is not 1")
    artifacts = value["artifacts"]
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "control_plane",
        "gateway",
        "worker",
    }:
        raise VerificationError("existing release manifest has the wrong artifact set")
    expected_image_keys = {
        "control_plane": {
            "guest_manifest_sha256",
            "guest_profile_sha256",
            "image_config_digest",
            "image_digest",
            "image_reference",
            "registry_verified",
        },
        "gateway": {
            "binary_sha256",
            "binary_size_bytes",
            "image_config_digest",
            "image_digest",
            "image_reference",
            "registry_verified",
        },
    }
    identity: dict[str, dict[str, str]] = {}
    for name, expected_keys in expected_image_keys.items():
        image = artifacts[name]
        if not isinstance(image, dict) or set(image) != expected_keys:
            raise VerificationError(f"existing {name} artifact has the wrong shape")
        if image["registry_verified"] is not False:
            raise VerificationError(f"existing {name} artifact is already registry-verified")
        reference = image["image_reference"]
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 1024
            or "@" in reference
            or any(character.isspace() or ord(character) < 0x20 for character in reference)
        ):
            raise VerificationError(f"existing {name} image reference is invalid")
        image_digest = require_sha256(
            image["image_digest"], name=f"existing {name} OCI digest"
        )
        config_digest = require_sha256(
            image["image_config_digest"], name=f"existing {name} config digest"
        )
        identity[name] = {
            "reference": reference,
            "image_digest": image_digest,
            "config_digest": config_digest,
        }
    try:
        require_distinct_image_tags(
            identity["control_plane"]["reference"], identity["gateway"]["reference"]
        )
    except ImageReferenceError as error:
        raise VerificationError(str(error)) from error

    worker = artifacts["worker"]
    if not isinstance(worker, dict) or set(worker) != {
        "bundle_name",
        "bundle_sha256",
        "bundle_size_bytes",
        "guest_initramfs_sha256",
        "guest_kernel_sha256",
        "guest_manifest_sha256",
        "guest_profile_sha256",
        "members",
    }:
        raise VerificationError("existing worker artifact has the wrong shape")
    if worker["bundle_name"] != "cats-worker.tar.zst":
        raise VerificationError("existing worker artifact has the wrong bundle name")
    members = worker["members"]
    if not isinstance(members, dict) or set(members) != WORKER_BINARY_MEMBER_FILES:
        raise VerificationError("existing worker artifact has the wrong member set")
    for relative in sorted(WORKER_BINARY_MEMBER_FILES):
        member = members[relative]
        if not isinstance(member, dict) or set(member) != {"sha256", "size_bytes"}:
            raise VerificationError(
                f"existing worker member {relative} has the wrong shape"
            )
        require_sha256(
            member["sha256"], name=f"existing worker member {relative} digest"
        )
        if (
            type(member["size_bytes"]) is not int
            or member["size_bytes"] <= 0
            or member["size_bytes"] > MAX_WORKER_MEMBER_BYTES
        ):
            raise VerificationError(
                f"existing worker member {relative} has an invalid size"
            )

    build_inputs = value["build_inputs"]
    guest_runtime = value["guest_runtime"]
    source = value["source"]
    if not isinstance(build_inputs, dict) or set(build_inputs) != {
        "files",
        "fingerprint",
        "guest_target",
        "platform",
    }:
        raise VerificationError("existing release build_inputs has the wrong shape")
    if (
        build_inputs["guest_target"] != "x86_64-unknown-linux-musl"
        or build_inputs["platform"] != "linux/amd64"
    ):
        raise VerificationError("existing release targets are not the production targets")
    if not isinstance(guest_runtime, dict) or set(guest_runtime) != {
        "initramfs",
        "kernel",
        "manifest_sha256",
        "profile_sha256",
        "release_id",
    }:
        raise VerificationError("existing guest_runtime has the wrong shape")
    if not isinstance(source, dict) or set(source) != {"commit", "fingerprint", "tree"}:
        raise VerificationError("existing release source has the wrong shape")
    if (
        GIT_OBJECT_PATTERN.fullmatch(source.get("commit", "")) is None
        or GIT_OBJECT_PATTERN.fullmatch(source.get("tree", "")) is None
    ):
        raise VerificationError("existing release source identity is invalid")

    def validate_named_digests(node: Any, path: str = "manifest") -> None:
        if isinstance(node, dict):
            for key, child in node.items():
                child_path = f"{path}.{key}"
                if (
                    key.endswith(("_sha256", "_digest", "fingerprint", "release_id"))
                    and child is not None
                ):
                    require_sha256(child, name=child_path)
                validate_named_digests(child, child_path)
        elif isinstance(node, list):
            for index, child in enumerate(node):
                validate_named_digests(child, f"{path}[{index}]")

    validate_named_digests(value)
    return identity


def registry_candidate(arguments: argparse.Namespace) -> int:
    raw = read_regular(arguments.manifest, cap=MAX_RELEASE_MANIFEST_BYTES)
    expected_manifest = require_sha256(
        arguments.manifest_sha256, name="approved release manifest digest"
    )
    if sha256_bytes(raw) != expected_manifest:
        raise VerificationError("release manifest differs from its approved digest")
    value = decode_canonical_json(raw, name="release manifest")
    identity = validate_existing_release_manifest(value)
    if arguments.output is None:
        print(canonical_json(identity).decode())
        return 0

    observed = {
        "control_plane": require_sha256(
            arguments.control_registry_digest, name="observed Control registry digest"
        ),
        "gateway": require_sha256(
            arguments.gateway_registry_digest, name="observed Gateway registry digest"
        ),
    }
    for name, digest in observed.items():
        if digest != identity[name]["image_digest"]:
            raise VerificationError(
                f"observed {name} registry digest differs from release manifest"
            )
        value["artifacts"][name]["registry_verified"] = True
    promoted = canonical_json(value)
    atomic_write_new(arguments.output, promoted)
    print(f"release_manifest_sha256={sha256_bytes(promoted)}")
    return 0


def validate_identifier_arguments(arguments: argparse.Namespace) -> None:
    for name, value in (
        ("source commit", arguments.source_commit),
        ("source tree", arguments.source_tree),
    ):
        if GIT_OBJECT_PATTERN.fullmatch(value) is None:
            raise VerificationError(f"{name} is not a lowercase Git object ID")
    require_sha256(arguments.source_fingerprint, name="source fingerprint")
    require_sha256(arguments.control_image_digest, name="Control OCI digest")
    require_sha256(arguments.control_image_config_digest, name="Control image config digest")
    require_sha256(arguments.gateway_image_digest, name="Gateway OCI digest")
    require_sha256(arguments.gateway_image_config_digest, name="Gateway image config digest")
    if (
        not arguments.control_image_reference
        or len(arguments.control_image_reference) > 1024
        or "@" in arguments.control_image_reference
        or any(character.isspace() or ord(character) < 0x20 for character in arguments.control_image_reference)
    ):
        raise VerificationError("Control image reference must be a bounded tag reference without @")
    if (
        not arguments.gateway_image_reference
        or len(arguments.gateway_image_reference) > 1024
        or "@" in arguments.gateway_image_reference
        or any(
            character.isspace() or ord(character) < 0x20
            for character in arguments.gateway_image_reference
        )
    ):
        raise VerificationError("Gateway image reference must be a bounded tag reference without @")
    try:
        require_distinct_image_tags(
            arguments.control_image_reference, arguments.gateway_image_reference
        )
    except ImageReferenceError as error:
        raise VerificationError(str(error)) from error
    if arguments.platform != "linux/amd64":
        raise VerificationError("the production artifact platform must be linux/amd64")
    if arguments.guest_target != "x86_64-unknown-linux-musl":
        raise VerificationError("the Guest Agent target must be x86_64-unknown-linux-musl")


def atomic_write_new(path: Path, raw: bytes) -> None:
    if not path.is_absolute():
        raise VerificationError("release manifest output path must be absolute")
    if path.exists() or path.is_symlink():
        raise VerificationError(f"release manifest output already exists: {path}")
    parent = path.parent
    metadata = parent.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise VerificationError(f"release manifest parent is not a real directory: {parent}")
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(descriptor, 0o644)
        written = 0
        while written < len(raw):
            written += os.write(descriptor, raw[written:])
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        try:
            os.link(temporary, path, follow_symlinks=False)
        except FileExistsError as error:
            raise VerificationError(
                f"release manifest output appeared during verification: {path}"
            ) from error
        temporary.unlink()
        directory_descriptor = os.open(parent, os.O_RDONLY)
        try:
            os.fsync(directory_descriptor)
        finally:
            os.close(directory_descriptor)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def verify_gateway_image_root(root: Path) -> tuple[str, int]:
    expected_directories = {".", "usr", "usr/local", "usr/local/bin"}
    expected_files = {"usr/local/bin/cats-gatewayd"}
    actual_directories: set[str] = {"."}
    actual_files: set[str] = set()
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or stat.S_ISLNK(root_metadata.st_mode):
        raise VerificationError("Gateway image root is not a real directory")
    for directory, names, filenames in os.walk(root, followlinks=False):
        directory_path = Path(directory)
        for name in names:
            path = directory_path / name
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISDIR(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"Gateway image root contains a non-directory: {relative}")
            actual_directories.add(relative)
        for name in filenames:
            path = directory_path / name
            metadata = path.lstat()
            relative = path.relative_to(root).as_posix()
            if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
                raise VerificationError(f"Gateway image root contains a non-file: {relative}")
            actual_files.add(relative)
    if actual_directories != expected_directories:
        raise VerificationError(
            f"Gateway image directory set differs: {sorted(actual_directories ^ expected_directories)}"
        )
    if actual_files != expected_files:
        raise VerificationError(
            f"Gateway image file set differs: {sorted(actual_files ^ expected_files)}"
        )
    binary = read_regular(
        root / "usr/local/bin/cats-gatewayd",
        cap=MAX_GATEWAY_BINARY_BYTES,
        mode=0o755,
    )
    return sha256_bytes(binary), len(binary)


def verify(arguments: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    validate_identifier_arguments(arguments)
    input_files: dict[str, dict[str, Any]] = {}
    reviewed_old_host_positive_stop: bytes | None = None
    for label, path in arguments.input_file:
        if label in input_files:
            raise VerificationError(f"duplicate fingerprinted input label: {label}")
        digest, size = hash_regular(path)
        input_files[label] = {"sha256": digest, "size_bytes": size}
        if label == "old_host_positive_stop":
            reviewed_old_host_positive_stop = read_regular(path, cap=MAX_WORKER_MEMBER_BYTES)
    if not input_files:
        raise VerificationError("at least one exact build input file must be fingerprinted")
    if reviewed_old_host_positive_stop is None:
        raise VerificationError("reviewed input old_host_positive_stop is required")

    shared = verify_guest_release(arguments.shared_guest_runtime)
    worker_binary_members: dict[str, dict[str, Any]] = {}
    worker_temporary = tempfile.TemporaryDirectory(prefix="cats-worker-verify-")
    try:
        worker_root = Path(worker_temporary.name) / "root"
        extract_worker_bundle(arguments.worker_bundle, worker_root)
        worker_release_root = worker_root / "guest-runtime-release.v1"
        worker = verify_guest_release(worker_release_root)

        for field in ("manifest_raw", "profile_raw", "kernel_raw", "initramfs_raw"):
            if worker[field] != shared[field]:
                raise VerificationError(
                    f"worker {field.removesuffix('_raw')} is not byte-identical to the shared Guest release"
                )
        worker_old_host_positive_stop_sha = verify_reviewed_worker_program(
            worker_root / "old-host-positive-stop.py",
            reviewed_old_host_positive_stop,
        )
        if worker_old_host_positive_stop_sha != input_files["old_host_positive_stop"]["sha256"]:
            raise VerificationError(
                "worker old-host-positive-stop.py digest does not match reviewed input "
                "old_host_positive_stop"
            )
        installer = worker_root / "install-guest-runtime-release.sh"
        installer_metadata = installer.lstat()
        if (
            not stat.S_ISREG(installer_metadata.st_mode)
            or stat.S_ISLNK(installer_metadata.st_mode)
            or installer_metadata.st_nlink != 1
            or stat.S_IMODE(installer_metadata.st_mode) & 0o111 == 0
        ):
            raise VerificationError("worker release installer is not an executable single-link file")
        for relative in sorted(WORKER_BINARY_MEMBER_FILES):
            digest, size = hash_regular(
                worker_root / relative, cap=MAX_WORKER_MEMBER_BYTES
            )
            worker_binary_members[relative] = {
                "sha256": digest,
                "size_bytes": size,
            }
    finally:
        worker_temporary.cleanup()
    control_release_root = arguments.control_root / "opt/cats/release"
    control_manifest_sha = verify_exact_copy(
        control_release_root / "guest-runtime-release-manifest.v1.json",
        shared["manifest_raw"],
        label="Control Guest runtime manifest",
    )
    control_profile_sha = verify_exact_copy(
        control_release_root / "guest-runtime-profile.v1.json",
        shared["profile_raw"],
        label="Control Guest runtime profile",
    )
    gateway_binary_sha, gateway_binary_size = verify_gateway_image_root(
        arguments.gateway_image_root
    )

    worker_bundle_sha, worker_bundle_size = hash_regular(
        arguments.worker_bundle, cap=MAX_WORKER_BUNDLE_BYTES
    )
    if arguments.worker_bundle.name != "cats-worker.tar.zst":
        raise VerificationError("worker bundle must use the canonical cats-worker.tar.zst name")

    source = {
        "commit": arguments.source_commit,
        "fingerprint": arguments.source_fingerprint,
        "tree": arguments.source_tree,
    }
    input_identity = {
        "files": input_files,
        "guest_runtime_manifest_sha256": shared["manifest_sha256"],
        "guest_runtime_release_id": shared["release_id"],
        "guest_target": arguments.guest_target,
        "platform": arguments.platform,
        "source": source,
    }
    input_fingerprint = sha256_bytes(INPUT_DOMAIN + canonical_json(input_identity))

    release_manifest = {
        "artifacts": {
            "control_plane": {
                "guest_manifest_sha256": control_manifest_sha,
                "guest_profile_sha256": control_profile_sha,
                "image_config_digest": arguments.control_image_config_digest,
                "image_digest": arguments.control_image_digest,
                "image_reference": arguments.control_image_reference,
                "registry_verified": arguments.control_image_registry_verified == "true",
            },
            "gateway": {
                "binary_sha256": gateway_binary_sha,
                "binary_size_bytes": gateway_binary_size,
                "image_config_digest": arguments.gateway_image_config_digest,
                "image_digest": arguments.gateway_image_digest,
                "image_reference": arguments.gateway_image_reference,
                "registry_verified": arguments.gateway_image_registry_verified == "true",
            },
            "worker": {
                "bundle_name": arguments.worker_bundle.name,
                "bundle_sha256": worker_bundle_sha,
                "bundle_size_bytes": worker_bundle_size,
                "guest_initramfs_sha256": (
                    None if worker["initramfs"] is None else worker["initramfs"]["sha256"]
                ),
                "guest_kernel_sha256": worker["kernel"]["sha256"],
                "guest_manifest_sha256": worker["manifest_sha256"],
                "guest_profile_sha256": worker["profile_sha256"],
                "members": worker_binary_members,
            },
        },
        "build_inputs": {
            "files": input_files,
            "fingerprint": input_fingerprint,
            "guest_target": arguments.guest_target,
            "platform": arguments.platform,
        },
        "guest_runtime": {
            "initramfs": shared["initramfs"],
            "kernel": shared["kernel"],
            "manifest_sha256": shared["manifest_sha256"],
            "profile_sha256": shared["profile_sha256"],
            "release_id": shared["release_id"],
        },
        "source": source,
        "version": 1,
    }
    return release_manifest, canonical_json(release_manifest)


def main() -> int:
    try:
        if sys.argv[1:2] == ["registry-candidate"]:
            return registry_candidate(parse_registry_candidate_arguments(sys.argv[2:]))
        arguments = parse_arguments()
        release_manifest, raw = verify(arguments)
        atomic_write_new(arguments.output, raw)
    except (OSError, VerificationError) as error:
        print(f"manual release verification failed: {error}", file=sys.stderr)
        return 1
    print(f"release_manifest_sha256={sha256_bytes(raw)}")
    print(f"guest_runtime_release_id={release_manifest['guest_runtime']['release_id']}")
    print(
        "control_image="
        f"{release_manifest['artifacts']['control_plane']['image_reference']}@"
        f"{release_manifest['artifacts']['control_plane']['image_digest']}"
    )
    print(
        "gateway_image="
        f"{release_manifest['artifacts']['gateway']['image_reference']}@"
        f"{release_manifest['artifacts']['gateway']['image_digest']}"
    )
    print(f"worker_bundle_sha256={release_manifest['artifacts']['worker']['bundle_sha256']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
