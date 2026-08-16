#!/usr/bin/env python3
"""Verify one buildx OCI transport archive against release-manifest identity."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from typing import Any


SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
MAX_JSON_BYTES = 16 * 1024 * 1024
MAX_MEMBERS = 512
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


class TransportError(Exception):
    """The archive is not the one image named by the release manifest."""


def canonical_image_name(reference: str) -> str:
    """Return the fully qualified name BuildKit records for a tag reference.

    BuildKit writes the normalized name into `io.containerd.image.name`, so a
    short reference like `cats/control-plane:tag` is stored as
    `docker.io/cats/control-plane:tag`. Applying the same registry-inference
    rules here compares references rather than spellings.
    """
    head, separator, rest = reference.partition("/")
    if separator and (
        "." in head or ":" in head or head == "localhost" or head.endswith(".localhost")
    ):
        return reference
    if not separator:
        return f"docker.io/library/{reference}"
    return f"docker.io/{reference}"


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise TransportError(f"{label} is not a canonical SHA-256 digest")
    return value


def blob_path(digest: str) -> str:
    return "blobs/sha256/" + digest.removeprefix("sha256:")


def read_member(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    name: str,
    *,
    expected_size: int | None = None,
) -> bytes:
    member = members.get(name)
    if member is None or not member.isreg():
        raise TransportError(f"OCI transport lacks regular file {name}")
    if member.size <= 0 or member.size > MAX_JSON_BYTES:
        raise TransportError(f"OCI transport JSON member has invalid size: {name}")
    if expected_size is not None and member.size != expected_size:
        raise TransportError(f"OCI transport descriptor size differs for {name}")
    source = archive.extractfile(member)
    if source is None:
        raise TransportError(f"cannot read OCI transport member {name}")
    raw = source.read(MAX_JSON_BYTES + 1)
    if len(raw) != member.size:
        raise TransportError(f"OCI transport member ended or grew while reading: {name}")
    return raw


def decode_json(raw: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TransportError(f"{label} is not valid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise TransportError(f"{label} is not a JSON object")
    return value


def verify_blob(
    archive: tarfile.TarFile,
    members: dict[str, tarfile.TarInfo],
    descriptor: Any,
    label: str,
) -> str:
    if not isinstance(descriptor, dict):
        raise TransportError(f"{label} descriptor is not an object")
    digest = require_digest(descriptor.get("digest"), f"{label} digest")
    size = descriptor.get("size")
    if type(size) is not int or size <= 0:
        raise TransportError(f"{label} descriptor size is invalid")
    name = blob_path(digest)
    member = members.get(name)
    if member is None or not member.isreg() or member.size != size:
        raise TransportError(f"{label} blob size differs from its descriptor")
    source = archive.extractfile(member)
    if source is None:
        raise TransportError(f"cannot read {label} blob")
    measured = hashlib.sha256()
    remaining = size
    while remaining:
        chunk = source.read(min(1024 * 1024, remaining))
        if not chunk:
            raise TransportError(f"{label} blob ended while hashing")
        measured.update(chunk)
        remaining -= len(chunk)
    if source.read(1):
        raise TransportError(f"{label} blob grew while hashing")
    if "sha256:" + measured.hexdigest() != digest:
        raise TransportError(f"{label} blob digest differs from its descriptor")
    return name


def verify(arguments: argparse.Namespace) -> None:
    metadata = arguments.archive.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or metadata.st_nlink != 1
        or metadata.st_size <= 0
    ):
        raise TransportError("OCI transport must be a non-empty single-link regular file")
    expected_image = require_digest(arguments.image_digest, "expected image digest")
    expected_config = require_digest(arguments.config_digest, "expected config digest")
    if (
        not arguments.reference
        or "@" in arguments.reference
        or any(character.isspace() for character in arguments.reference)
    ):
        raise TransportError("expected image reference is not a tag reference")

    try:
        archive = tarfile.open(arguments.archive, mode="r:")
    except tarfile.TarError as error:
        raise TransportError(f"cannot open OCI transport: {error}") from error
    with archive:
        members: dict[str, tarfile.TarInfo] = {}
        directories: set[str] = set()
        for member in archive:
            if len(members) + len(directories) >= MAX_MEMBERS:
                raise TransportError("OCI transport has too many members")
            normalized = member.name.rstrip("/")
            path = PurePosixPath(normalized)
            if (
                not normalized
                or member.name.startswith("/")
                or any(part in ("", ".", "..") for part in path.parts)
            ):
                raise TransportError(f"OCI transport has unsafe path {member.name!r}")
            if normalized in members or normalized in directories:
                raise TransportError(f"OCI transport repeats path {normalized!r}")
            if member.isdir():
                directories.add(normalized)
            elif member.isreg():
                members[normalized] = member
            else:
                raise TransportError(f"OCI transport has link or special member {normalized!r}")

        layout = decode_json(read_member(archive, members, "oci-layout"), "OCI layout")
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise TransportError("OCI transport has an unsupported layout version")
        index = decode_json(read_member(archive, members, "index.json"), "OCI index")
        manifests = index.get("manifests")
        if index.get("schemaVersion") != 2 or not isinstance(manifests, list) or len(manifests) != 1:
            raise TransportError("OCI index must name exactly one image manifest")
        image_descriptor = manifests[0]
        if not isinstance(image_descriptor, dict):
            raise TransportError("OCI image descriptor is not an object")
        if image_descriptor.get("mediaType") not in MANIFEST_MEDIA_TYPES:
            raise TransportError("OCI image descriptor has an unsupported media type")
        if require_digest(image_descriptor.get("digest"), "OCI image digest") != expected_image:
            raise TransportError("OCI image digest differs from release manifest")
        annotations = image_descriptor.get("annotations")
        if not isinstance(annotations, dict) or annotations.get(
            "io.containerd.image.name"
        ) != canonical_image_name(arguments.reference):
            raise TransportError("OCI image name differs from release manifest reference")
        platform = image_descriptor.get("platform")
        if platform is not None and (
            not isinstance(platform, dict)
            or platform.get("architecture") != "amd64"
            or platform.get("os") != "linux"
        ):
            raise TransportError("OCI index image is not linux/amd64")

        image_size = image_descriptor.get("size")
        if type(image_size) is not int or image_size <= 0:
            raise TransportError("OCI image descriptor size is invalid")
        image_raw = read_member(
            archive,
            members,
            blob_path(expected_image),
            expected_size=image_size,
        )
        if "sha256:" + hashlib.sha256(image_raw).hexdigest() != expected_image:
            raise TransportError("OCI image manifest blob has the wrong digest")
        image_manifest = decode_json(image_raw, "OCI image manifest")
        if image_manifest.get("schemaVersion") != 2 or image_manifest.get("mediaType") not in MANIFEST_MEDIA_TYPES:
            raise TransportError("OCI image manifest has an unsupported shape")
        config = image_manifest.get("config")
        if not isinstance(config, dict) or require_digest(config.get("digest"), "OCI config digest") != expected_config:
            raise TransportError("OCI config digest differs from release manifest")

        referenced_files = {"oci-layout", "index.json", blob_path(expected_image)}
        referenced_files.add(verify_blob(archive, members, config, "OCI config"))
        config_raw = read_member(
            archive,
            members,
            blob_path(expected_config),
            expected_size=config["size"],
        )
        config_value = decode_json(config_raw, "OCI image config")
        if config_value.get("architecture") != "amd64" or config_value.get("os") != "linux":
            raise TransportError("OCI image config is not linux/amd64")

        layers = image_manifest.get("layers")
        if layers is None:
            layers = []
        if not isinstance(layers, list):
            raise TransportError("OCI image layers are not a list")
        for index_number, layer in enumerate(layers):
            referenced_files.add(
                verify_blob(archive, members, layer, f"OCI layer {index_number}")
            )
        if set(members) != referenced_files:
            raise TransportError(
                f"OCI transport file set differs: {sorted(set(members) ^ referenced_files)}"
            )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--archive", required=True, type=Path)
    parser.add_argument("--reference", required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--config-digest", required=True)
    arguments = parser.parse_args()
    try:
        verify(arguments)
    except (OSError, TransportError) as error:
        print(f"image transport verification failed: {error}", file=__import__("sys").stderr)
        return 1
    print(f"verified_image={arguments.reference}@{arguments.image_digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
