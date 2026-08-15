#!/usr/bin/env python3
"""Create, verify, package, and install the E13 public operator trust artifact.

The offline Ed25519 private key is accepted only by ``generate``, ``verify``,
and the explicit operator-execution-host installer.
It is never named, hashed, copied, or described by any emitted receipt.  The
Kubernetes and Host paths consume only the canonical public trust bytes and the
non-secret generation receipt.
"""

from __future__ import annotations

import argparse
import base64
import binascii
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import stat
import subprocess
import sys
from typing import Any, Sequence


sys.dont_write_bytecode = True

TRUST_FILE = "production-cutover-operator-trust.v1.json"
GENERATION_RECEIPT_FILE = (
    "production-cutover-operator-trust-generation.receipt.json"
)
VERIFICATION_RECEIPT_FILE = (
    "production-cutover-operator-trust-verification.receipt.json"
)
INSTALLED_TRUST_PATH = Path("/etc/cats") / TRUST_FILE
OPERATOR_HOST_ROOT = Path("/etc/cats/production-cutover-operator")
OPERATOR_HOST_PRIVATE_KEY_PATH = OPERATOR_HOST_ROOT / "operator-private-key.pem"
OPERATOR_HOST_TRUST_PATH = OPERATOR_HOST_ROOT / TRUST_FILE
FINAL_OPEN_STATE_ROOT = Path("/var/lib/cats/production-final-open")
FINAL_OPEN_ADMISSION_STATE = FINAL_OPEN_STATE_ROOT / "admission-state"
FINAL_OPEN_RECEIPTS = FINAL_OPEN_STATE_ROOT / "receipts"
MAX_TRUST_BYTES = 65_536
MAX_RECEIPT_BYTES = 65_536
MAX_PRIVATE_KEY_BYTES = 16_384
MAX_RELEASE_MANIFEST_BYTES = 1024 * 1024
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")
KUBERNETES_DNS_SUBDOMAIN = re.compile(
    r"^[a-z0-9](?:[-a-z0-9.]{0,251}[a-z0-9])?$"
)
KUBERNETES_DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
PARTITIONS = {"aws", "aws-us-gov", "aws-cn"}


class TrustError(Exception):
    """The public trust supply chain failed closed."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


def sha256(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def decode_json(raw: bytes, label: str) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TrustError(f"{label} contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrustError(f"{label} is not one UTF-8 JSON value") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise TrustError(f"{label} is not canonical Cats JSON")
    return value


def decode_release_manifest(raw: bytes) -> dict[str, Any]:
    def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise TrustError(f"release manifest contains duplicate key {key!r}")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise TrustError("release manifest is not one UTF-8 JSON value") from error
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")
    if not isinstance(value, dict) or encoded != raw:
        raise TrustError("release manifest is not canonical JSON")
    return value


def require_exact_fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise TrustError(f"{label} has the wrong closed field set")
    return value


def require_id(value: Any, label: str) -> str:
    if not isinstance(value, str) or ID.fullmatch(value) is None:
        raise TrustError(f"{label} is not a canonical Cats ID")
    return value


def require_commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
        raise TrustError(f"{label} is not a lowercase 40-hex commit")
    return value


def require_sha256(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise TrustError(f"{label} is not a canonical SHA-256 digest")
    return value


def decode_spki(value: Any) -> bytes:
    if not isinstance(value, str) or BASE64URL.fullmatch(value) is None:
        raise TrustError("public_key_spki is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error) as error:
        raise TrustError("public_key_spki is not canonical base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise TrustError("public_key_spki is not canonical base64url")
    if len(decoded) != 44 or not decoded.startswith(ED25519_SPKI_PREFIX):
        raise TrustError("public_key_spki is not canonical Ed25519 SPKI DER")
    return decoded


def encode_spki(value: bytes) -> str:
    if len(value) != 44 or not value.startswith(ED25519_SPKI_PREFIX):
        raise TrustError("OpenSSL did not produce canonical Ed25519 SPKI DER")
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def validate_scope(value: Any) -> dict[str, Any]:
    scope = require_exact_fields(
        value,
        {"aws_partition", "account_id", "role_arn"},
        "operator AWS scope",
    )
    partition = scope["aws_partition"]
    account_id = scope["account_id"]
    role_arn = scope["role_arn"]
    if partition not in PARTITIONS:
        raise TrustError("operator AWS partition is invalid")
    if not isinstance(account_id, str) or ACCOUNT_ID.fullmatch(account_id) is None:
        raise TrustError("operator AWS account ID is invalid")
    role_prefix = f"arn:{partition}:iam::{account_id}:role/"
    if (
        not isinstance(role_arn, str)
        or not role_arn.startswith(role_prefix)
        or len(role_arn) <= len(role_prefix)
        or len(role_arn) > 2_048
        or any(ord(character) < 0x21 or ord(character) > 0x7E for character in role_arn)
        or not role_arn.rsplit("/", 1)[-1]
    ):
        raise TrustError("operator AWS role ARN is outside the exact partition/account")
    return scope


def validate_trust(value: Any) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    trust = require_exact_fields(
        value,
        {
            "version",
            "deployment_id",
            "release_id",
            "source_commit_sha",
            "signature_threshold",
            "credentials",
        },
        "ProductionCutoverOperator trust",
    )
    if type(trust["version"]) is not int or trust["version"] != 1:
        raise TrustError("ProductionCutoverOperator trust version is not 1")
    if (
        type(trust["signature_threshold"]) is not int
        or trust["signature_threshold"] != 1
    ):
        raise TrustError("ProductionCutoverOperator trust threshold is not exactly one")
    require_id(trust["deployment_id"], "trust deployment_id")
    require_sha256(trust["release_id"], "trust release_id")
    require_commit(trust["source_commit_sha"], "trust source_commit_sha")
    credentials = trust["credentials"]
    if not isinstance(credentials, list) or len(credentials) != 1:
        raise TrustError("ProductionCutoverOperator trust must contain exactly one credential")
    credential = require_exact_fields(
        credentials[0],
        {"credential_id", "public_key_spki", "scope"},
        "ProductionCutoverOperator credential",
    )
    require_id(credential["credential_id"], "operator credential_id")
    spki = decode_spki(credential["public_key_spki"])
    validate_scope(credential["scope"])
    return trust, credential, spki


def stable_read(
    path: Path,
    label: str,
    maximum: int,
    *,
    private: bool = False,
    require_root: bool = False,
    exact_mode: int | None = None,
) -> bytes:
    if not path.is_absolute():
        raise TrustError(f"{label} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise TrustError(f"cannot open {label} as a non-symlink file") from error
    try:
        before = os.fstat(descriptor)
        forbidden_mode = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or before.st_mode & forbidden_mode
            or before.st_size <= 0
            or before.st_size > maximum
            or (require_root and (before.st_uid != 0 or before.st_gid != 0))
            or (
                exact_mode is not None
                and stat.S_IMODE(before.st_mode) != exact_mode
            )
        ):
            raise TrustError(f"{label} ownership, links, mode, or size is invalid")
        snapshot = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise TrustError(f"{label} changed during its bounded read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrustError(f"{label} grew during its bounded read")
        after = os.fstat(descriptor)
        if snapshot != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise TrustError(f"{label} changed during its bounded read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


@dataclass(frozen=True)
class DirectoryIdentity:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int


def directory_identity(metadata: os.stat_result) -> DirectoryIdentity:
    return DirectoryIdentity(
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mode=metadata.st_mode,
        uid=metadata.st_uid,
        gid=metadata.st_gid,
    )


def validate_directory(
    metadata: os.stat_result,
    *,
    actor: tuple[int, int],
    label: str,
    output_parent: bool,
    private_parent: bool,
) -> None:
    owner = (metadata.st_uid, metadata.st_gid)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or owner not in {(0, 0), actor}
        or metadata.st_mode & 0o022
        or (output_parent and owner != actor)
        or (output_parent and private_parent and metadata.st_mode & 0o077)
    ):
        raise TrustError(f"unsafe directory in output ancestry: {label}")


def output_components(path: Path) -> tuple[list[str], str]:
    raw = os.fspath(path)
    if (
        not path.is_absolute()
        or raw == "/"
        or raw != os.path.normpath(raw)
        or any(component in {"", ".", ".."} for component in path.parts[1:])
    ):
        raise TrustError("output path must be normalized and absolute")
    return list(path.parts[1:-1]), path.parts[-1]


def open_output_parent(
    path: Path, *, private_parent: bool
) -> tuple[
    tuple[int, ...],
    tuple[str, ...],
    str,
    tuple[DirectoryIdentity, ...],
    tuple[int, int],
]:
    components, output_name = output_components(path)
    actor = (os.geteuid(), os.getegid())
    if actor[0] == 0 and actor != (0, 0):
        raise TrustError("root publication requires effective root:root identity")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_descriptor = os.open("/", flags)
    except OSError as error:
        raise TrustError("cannot pin the output ancestry root") from error
    descriptors = [root_descriptor]
    identities: list[DirectoryIdentity] = []
    try:
        root_metadata = os.fstat(root_descriptor)
        validate_directory(
            root_metadata,
            actor=actor,
            label="/",
            output_parent=not components,
            private_parent=private_parent,
        )
        identities.append(directory_identity(root_metadata))
        traversed = ""
        for index, component in enumerate(components):
            traversed += "/" + component
            try:
                child = os.open(component, flags, dir_fd=descriptors[-1])
            except OSError as error:
                raise TrustError(
                    f"cannot pin real output ancestor {traversed}"
                ) from error
            metadata = os.fstat(child)
            validate_directory(
                metadata,
                actor=actor,
                label=traversed,
                output_parent=index == len(components) - 1,
                private_parent=private_parent,
            )
            identities.append(directory_identity(metadata))
            descriptors.append(child)
        return (
            tuple(descriptors),
            tuple(components),
            output_name,
            tuple(identities),
            actor,
        )
    except BaseException:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


@dataclass
class PinnedOutputParent:
    path: Path
    output_name: str
    descriptors: tuple[int, ...]
    components: tuple[str, ...]
    identities: tuple[DirectoryIdentity, ...]
    actor: tuple[int, int]
    private_parent: bool

    @property
    def descriptor(self) -> int:
        return self.descriptors[-1]

    def verify(self) -> None:
        if len(self.descriptors) != len(self.identities):
            raise TrustError("output ancestry descriptor set is incomplete")
        for index, (descriptor, expected) in enumerate(
            zip(self.descriptors, self.identities)
        ):
            actual = os.fstat(descriptor)
            validate_directory(
                actual,
                actor=self.actor,
                label="/" if index == 0 else "/" + "/".join(self.components[:index]),
                output_parent=index + 1 == len(self.descriptors),
                private_parent=self.private_parent,
            )
            if (
                actual.st_dev,
                actual.st_ino,
                actual.st_mode,
                actual.st_uid,
                actual.st_gid,
            ) != (
                expected.device,
                expected.inode,
                expected.mode,
                expected.uid,
                expected.gid,
            ):
                raise TrustError("pinned output ancestry metadata changed")
            if index:
                named = os.stat(
                    self.components[index - 1],
                    dir_fd=self.descriptors[index - 1],
                    follow_symlinks=False,
                )
                if (
                    named.st_dev,
                    named.st_ino,
                    named.st_mode,
                    named.st_uid,
                    named.st_gid,
                ) != (
                    expected.device,
                    expected.inode,
                    expected.mode,
                    expected.uid,
                    expected.gid,
                ):
                    raise TrustError("output ancestry binding changed")

    def fsync(self) -> None:
        self.verify()
        os.fsync(self.descriptor)
        self.verify()

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)


def pin_output_parent(path: Path, *, private_parent: bool) -> PinnedOutputParent:
    descriptors, components, name, identities, actor = open_output_parent(
        path, private_parent=private_parent
    )
    return PinnedOutputParent(
        path=path,
        output_name=name,
        descriptors=descriptors,
        components=components,
        identities=identities,
        actor=actor,
        private_parent=private_parent,
    )


def directory_receipt(path: Path, metadata: os.stat_result) -> dict[str, Any]:
    return {
        "gid": metadata.st_gid,
        "mode": "0700",
        "path": str(path),
        "type": "directory",
        "uid": metadata.st_uid,
    }


def ensure_private_directory_at(
    parent: PinnedOutputParent,
    name: str,
    path: Path,
    *,
    require_root: bool,
) -> os.stat_result:
    if not name or name in {".", ".."} or "/" in name or path.name != name:
        raise TrustError("fixed private directory name is invalid")
    created = False
    parent.verify()
    try:
        os.mkdir(name, 0o700, dir_fd=parent.descriptor)
        created = True
    except FileExistsError:
        pass
    parent.verify()
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=parent.descriptor)
    except OSError as error:
        raise TrustError(f"fixed private directory is not real: {path}") from error
    try:
        if created:
            parent.verify()
            os.fchmod(descriptor, 0o700)
            if require_root:
                parent.verify()
                os.fchown(descriptor, 0, 0)
        parent.verify()
        metadata = os.fstat(descriptor)
        expected_owner = (0, 0) if require_root else parent.actor
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != expected_owner
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise TrustError(f"fixed private directory metadata is invalid: {path}")
        parent.verify()
        named = os.stat(name, dir_fd=parent.descriptor, follow_symlinks=False)
        if (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino):
            raise TrustError(f"fixed private directory binding changed: {path}")
        parent.verify()
        os.fsync(descriptor)
        parent.fsync()
        parent.verify()
        return os.fstat(descriptor)
    finally:
        os.close(descriptor)


def provision_final_open_state_layout(
    state_root: Path = FINAL_OPEN_STATE_ROOT,
    *,
    require_root: bool = True,
) -> dict[str, Any]:
    """Create the one fixed final-open state layout without storing secrets."""

    if require_root and state_root != FINAL_OPEN_STATE_ROOT:
        raise TrustError("production final-open state root is not the fixed path")
    if require_root and (os.geteuid(), os.getegid()) != (0, 0):
        raise TrustError("production final-open state installation requires root:root")
    root_parent = pin_output_parent(state_root, private_parent=False)
    try:
        root_metadata = ensure_private_directory_at(
            root_parent,
            state_root.name,
            state_root,
            require_root=require_root,
        )
    finally:
        root_parent.close()

    layout_parent = pin_output_parent(
        state_root / ".cats-final-open-layout", private_parent=True
    )
    try:
        if stat.S_IMODE(os.fstat(layout_parent.descriptor).st_mode) != 0o700:
            raise TrustError("production final-open state root mode is not 0700")
        admission_path = state_root / "admission-state"
        receipt_path = state_root / "receipts"
        admission_metadata = ensure_private_directory_at(
            layout_parent,
            admission_path.name,
            admission_path,
            require_root=require_root,
        )
        receipt_metadata = ensure_private_directory_at(
            layout_parent,
            receipt_path.name,
            receipt_path,
            require_root=require_root,
        )
        layout_parent.verify()
        # Linux fdopendir inherits the descriptor offset (macOS rewinds); an
        # already-consumed offset would list nothing and let foreign entries
        # hide, so rewind before enumerating.
        os.lseek(layout_parent.descriptor, 0, os.SEEK_SET)
        direct_children = sorted(os.listdir(layout_parent.descriptor))
        layout_parent.verify()
        if direct_children != ["admission-state", "receipts"]:
            raise TrustError("production final-open state root has foreign direct children")
        layout_parent.fsync()
        return {
            "admission_state": directory_receipt(
                admission_path, admission_metadata
            ),
            "direct_children": direct_children,
            "receipts": directory_receipt(receipt_path, receipt_metadata),
            "root": directory_receipt(state_root, root_metadata),
        }
    finally:
        layout_parent.close()


@dataclass
class PublicationContext:
    parent: PinnedOutputParent
    lock_descriptor: int
    lock_name: str
    lock_identity: tuple[int, int, int, int, int, int, int, int]

    @property
    def output_name(self) -> str:
        return self.parent.output_name

    @property
    def temporary_name(self) -> str:
        return f".{self.output_name}.cats-publish-v1"

    def verify(self) -> None:
        self.parent.verify()
        opened = os.fstat(self.lock_descriptor)
        try:
            named = os.stat(
                self.lock_name,
                dir_fd=self.parent.descriptor,
                follow_symlinks=False,
            )
        except OSError as error:
            raise TrustError("persistent output lock pathname changed") from error
        actual = (
            opened.st_dev,
            opened.st_ino,
            opened.st_mode,
            opened.st_uid,
            opened.st_gid,
            opened.st_nlink,
            opened.st_size,
            opened.st_ctime_ns,
        )
        named_identity = (named.st_dev, named.st_ino)
        if (
            actual != self.lock_identity
            or named_identity != self.lock_identity[:2]
            or not stat.S_ISREG(named.st_mode)
        ):
            raise TrustError("persistent output lock suffered pathname ABA")
        self.parent.verify()


@contextmanager
def hold_publish_lock(
    path: Path, *, private_parent: bool, require_root: bool
):
    """Serialize every inspection and mutation of one output crash state."""

    parent = pin_output_parent(path, private_parent=private_parent)
    if require_root and parent.actor != (0, 0):
        parent.close()
        raise TrustError("root-owned output publication must run as root:root")
    lock_name = f".{parent.output_name}.cats-publish-v1.lock"
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    created = False
    try:
        parent.verify()
        descriptor = os.open(
            lock_name,
            flags | os.O_CREAT | os.O_EXCL,
            0o600,
            dir_fd=parent.descriptor,
        )
        created = True
    except FileExistsError:
        try:
            descriptor = os.open(lock_name, flags, dir_fd=parent.descriptor)
        except OSError as error:
            parent.close()
            raise TrustError("cannot open the persistent output lock") from error
    except BaseException:
        parent.close()
        raise
    try:
        parent.verify()
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
        except OSError as error:
            raise TrustError("cannot acquire the persistent output lock") from error
        if created:
            parent.verify()
            os.fchmod(descriptor, 0o600)
            if require_root:
                parent.verify()
                os.fchown(descriptor, 0, 0)
            parent.verify()
            os.fsync(descriptor)
            parent.fsync()
        parent.verify()
        metadata = os.fstat(descriptor)
        parent.verify()
        named = os.stat(
            lock_name, dir_fd=parent.descriptor, follow_symlinks=False
        )
        expected_owner = (0, 0) if require_root else (os.geteuid(), os.getegid())
        if (
            not stat.S_ISREG(metadata.st_mode)
            or (metadata.st_uid, metadata.st_gid) != expected_owner
            or stat.S_IMODE(metadata.st_mode) != 0o600
            or metadata.st_nlink != 1
            or metadata.st_size != 0
            or (metadata.st_dev, metadata.st_ino) != (named.st_dev, named.st_ino)
        ):
            raise TrustError("persistent output lock metadata is unsafe")
        context = PublicationContext(
            parent=parent,
            lock_descriptor=descriptor,
            lock_name=lock_name,
            lock_identity=(
                metadata.st_dev,
                metadata.st_ino,
                metadata.st_mode,
                metadata.st_uid,
                metadata.st_gid,
                metadata.st_nlink,
                metadata.st_size,
                metadata.st_ctime_ns,
            ),
        )
        context.verify()
        yield context
        context.verify()
    finally:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)
            parent.close()


def validate_publish_metadata(
    metadata: os.stat_result,
    *,
    path: Path,
    mode: int,
    owner: tuple[int, int],
    links: int,
    maximum: int,
) -> None:
    if (
        not stat.S_ISREG(metadata.st_mode)
        or (metadata.st_uid, metadata.st_gid) != owner
        or stat.S_IMODE(metadata.st_mode) != mode
        or metadata.st_nlink != links
        or metadata.st_size <= 0
        or metadata.st_size > maximum
    ):
        raise TrustError(f"interrupted output has unsafe metadata: {path}")


def optional_stat(context: PublicationContext, name: str) -> os.stat_result | None:
    context.verify()
    try:
        metadata = os.stat(
            name, dir_fd=context.parent.descriptor, follow_symlinks=False
        )
    except FileNotFoundError:
        context.verify()
        return None
    context.verify()
    return metadata


def read_output_at(
    context: PublicationContext,
    label: str,
    maximum: int,
    *,
    mode: int,
    require_root: bool,
) -> bytes:
    context.verify()
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(
            context.output_name, flags, dir_fd=context.parent.descriptor
        )
    except OSError as error:
        raise TrustError(f"cannot open pinned {label}") from error
    try:
        before = os.fstat(descriptor)
        owner = (0, 0) if require_root else context.parent.actor
        validate_publish_metadata(
            before,
            path=context.parent.path,
            mode=mode,
            owner=owner,
            links=1,
            maximum=maximum,
        )
        snapshot = (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        )
        remaining = before.st_size
        chunks: list[bytes] = []
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise TrustError(f"pinned {label} ended during read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise TrustError(f"pinned {label} grew during read")
        after = os.fstat(descriptor)
        if snapshot != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_uid,
            after.st_gid,
            after.st_nlink,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise TrustError(f"pinned {label} changed during read")
        context.verify()
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def unlink_output_at(
    context: PublicationContext,
    name: str,
    *,
    expected: tuple[int, int],
) -> None:
    context.verify()
    metadata = os.stat(
        name, dir_fd=context.parent.descriptor, follow_symlinks=False
    )
    if (metadata.st_dev, metadata.st_ino) != expected:
        raise TrustError("refusing to unlink a replaced output inode")
    context.verify()
    os.unlink(name, dir_fd=context.parent.descriptor)
    context.parent.fsync()
    context.verify()


def link_output_at(
    context: PublicationContext,
    source: str,
    destination: str,
    *,
    expected_source: tuple[int, int],
) -> None:
    context.verify()
    source_metadata = os.stat(
        source, dir_fd=context.parent.descriptor, follow_symlinks=False
    )
    if (source_metadata.st_dev, source_metadata.st_ino) != expected_source:
        raise TrustError("refusing to link a replaced temporary inode")
    context.verify()
    try:
        os.link(
            source,
            destination,
            src_dir_fd=context.parent.descriptor,
            dst_dir_fd=context.parent.descriptor,
            follow_symlinks=False,
        )
    except FileExistsError as error:
        raise TrustError("output appeared during no-replace publish") from error
    context.parent.fsync()
    context.verify()


def recover_published_output_locked(
    context: PublicationContext,
    label: str,
    maximum: int,
    *,
    mode: int,
    require_root: bool,
) -> bytes | None:
    """Adopt only this writer's one safe crash state, never a foreign link."""

    final_metadata = optional_stat(context, context.output_name)
    temporary_metadata = optional_stat(context, context.temporary_name)
    if final_metadata is None and temporary_metadata is None:
        return None
    owner = (0, 0) if require_root else context.parent.actor
    if (
        final_metadata is None
        and temporary_metadata is not None
        and stat.S_ISREG(temporary_metadata.st_mode)
        and (temporary_metadata.st_uid, temporary_metadata.st_gid) == owner
        and stat.S_IMODE(temporary_metadata.st_mode) == mode
        and temporary_metadata.st_nlink == 1
        and temporary_metadata.st_size == 0
    ):
        # A process killed after O_EXCL creation but before the first write
        # leaves no candidate bytes. The per-output lock proves that writer is
        # gone, so this sole empty inode is the one recoverable incomplete state.
        unlink_output_at(
            context,
            context.temporary_name,
            expected=(temporary_metadata.st_dev, temporary_metadata.st_ino),
        )
        return None
    if final_metadata is not None and temporary_metadata is not None:
        validate_publish_metadata(
            final_metadata,
            path=context.parent.path,
            mode=mode,
            owner=owner,
            links=2,
            maximum=maximum,
        )
        validate_publish_metadata(
            temporary_metadata,
            path=context.parent.path.with_name(context.temporary_name),
            mode=mode,
            owner=owner,
            links=2,
            maximum=maximum,
        )
        if (final_metadata.st_dev, final_metadata.st_ino) != (
            temporary_metadata.st_dev,
            temporary_metadata.st_ino,
        ):
            raise TrustError("final and interrupted outputs are not the same inode")
        unlink_output_at(
            context,
            context.temporary_name,
            expected=(temporary_metadata.st_dev, temporary_metadata.st_ino),
        )
    elif temporary_metadata is not None:
        validate_publish_metadata(
            temporary_metadata,
            path=context.parent.path.with_name(context.temporary_name),
            mode=mode,
            owner=owner,
            links=1,
            maximum=maximum,
        )
        link_output_at(
            context,
            context.temporary_name,
            context.output_name,
            expected_source=(temporary_metadata.st_dev, temporary_metadata.st_ino),
        )
        unlink_output_at(
            context,
            context.temporary_name,
            expected=(temporary_metadata.st_dev, temporary_metadata.st_ino),
        )
    else:
        if final_metadata is None:
            raise TrustError("interrupted output state disappeared")
        validate_publish_metadata(
            final_metadata,
            path=context.parent.path,
            mode=mode,
            owner=owner,
            links=1,
            maximum=maximum,
        )

    context.verify()
    descriptor = os.open(
        context.output_name,
        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        dir_fd=context.parent.descriptor,
    )
    try:
        context.verify()
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    context.parent.fsync()
    return read_output_at(
        context,
        label,
        maximum,
        mode=mode,
        require_root=require_root,
    )


def recover_published_output(
    path: Path,
    label: str,
    maximum: int,
    *,
    mode: int,
    private_parent: bool,
    require_root: bool,
) -> bytes | None:
    with hold_publish_lock(
        path, private_parent=private_parent, require_root=require_root
    ) as context:
        return recover_published_output_locked(
            context,
            label,
            maximum,
            mode=mode,
            require_root=require_root,
        )


def inspect_published_output(
    path: Path,
    label: str,
    maximum: int,
    *,
    mode: int,
    private_parent: bool,
    require_root: bool,
) -> tuple[bytes, os.stat_result]:
    with hold_publish_lock(
        path, private_parent=private_parent, require_root=require_root
    ) as context:
        raw = read_output_at(
            context, label, maximum, mode=mode, require_root=require_root
        )
        metadata = optional_stat(context, context.output_name)
        if metadata is None:
            raise TrustError(f"pinned {label} disappeared")
        return raw, metadata


def write_new(
    path: Path,
    raw: bytes,
    *,
    mode: int,
    private_parent: bool,
    require_root: bool = False,
) -> None:
    with hold_publish_lock(
        path, private_parent=private_parent, require_root=require_root
    ) as context:
        existing = recover_published_output_locked(
            context,
            path.name,
            len(raw),
            mode=mode,
            require_root=require_root,
        )
        if existing is not None:
            if existing != raw:
                raise TrustError(f"refusing to replace existing output {path}")
            return

        temporary_name = context.temporary_name
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = -1
        linked = False
        temporary_identity: tuple[int, int] | None = None
        try:
            context.verify()
            descriptor = os.open(
                temporary_name,
                flags,
                mode,
                dir_fd=context.parent.descriptor,
            )
        except FileExistsError as error:
            raise TrustError("interrupted output appeared during publish") from error
        try:
            context.verify()
            os.fchmod(descriptor, mode)
            if require_root:
                context.verify()
                os.fchown(descriptor, 0, 0)
            temporary_metadata = os.fstat(descriptor)
            temporary_identity = (
                temporary_metadata.st_dev,
                temporary_metadata.st_ino,
            )
            context.verify()
            if (
                os.environ.get("CATS_E13_TRUST_FIXTURE_KILL_AFTER_TEMP_CREATE")
                == path.name
            ):
                os.kill(os.getpid(), signal.SIGKILL)
            if (
                os.environ.get("CATS_E13_TRUST_FIXTURE_BARRIER_OUTPUT")
                == path.name
            ):
                try:
                    barrier_descriptor = int(
                        os.environ.get("CATS_E13_TRUST_FIXTURE_BARRIER_FD", "")
                    )
                except ValueError as error:
                    raise TrustError("fixture publish barrier fd is invalid") from error
                if (
                    barrier_descriptor < 3
                    or not stat.S_ISFIFO(os.fstat(barrier_descriptor).st_mode)
                    or os.read(barrier_descriptor, 1) != b"x"
                ):
                    raise TrustError("fixture publish barrier did not release")
                context.verify()
            offset = 0
            while offset < len(raw):
                context.verify()
                offset += os.write(descriptor, raw[offset:])
            context.verify()
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            validate_publish_metadata(
                metadata,
                path=path.with_name(temporary_name),
                mode=mode,
                owner=(0, 0) if require_root else (os.geteuid(), os.getegid()),
                links=1,
                maximum=len(raw),
            )
            if metadata.st_size != len(raw):
                raise TrustError("new output has the wrong size before publish")
            os.close(descriptor)
            descriptor = -1
            link_output_at(
                context,
                temporary_name,
                context.output_name,
                expected_source=temporary_identity,
            )
            linked = True
            if os.environ.get("CATS_E13_TRUST_FIXTURE_KILL_AFTER_LINK") == path.name:
                os.kill(os.getpid(), signal.SIGKILL)
            unlink_output_at(
                context,
                temporary_name,
                expected=temporary_identity,
            )
            linked = False
            final = read_output_at(
                context,
                path.name,
                len(raw),
                mode=mode,
                require_root=require_root,
            )
            if final != raw:
                raise TrustError("published output differs from its exact input")
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            # Before the no-replace link, a same-process error owns the lone
            # temp inode and can remove it. After the link, leave the
            # deterministic same-inode pair for the next invocation.
            if not linked and temporary_identity is not None:
                try:
                    context.verify()
                    named = os.stat(
                        temporary_name,
                        dir_fd=context.parent.descriptor,
                        follow_symlinks=False,
                    )
                    if (named.st_dev, named.st_ino) == temporary_identity:
                        unlink_output_at(
                            context,
                            temporary_name,
                            expected=temporary_identity,
                        )
                except (FileNotFoundError, TrustError):
                    pass


def write_exact_or_replay(
    path: Path,
    raw: bytes,
    *,
    mode: int,
    private_parent: bool,
    require_root: bool = False,
) -> None:
    write_new(
        path,
        raw,
        mode=mode,
        private_parent=private_parent,
        require_root=require_root
        or path
        in {
            INSTALLED_TRUST_PATH,
            OPERATOR_HOST_PRIVATE_KEY_PATH,
            OPERATOR_HOST_TRUST_PATH,
        },
    )


def trusted_openssl(path: Path) -> Path:
    if not path.is_absolute():
        raise TrustError("OpenSSL path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise TrustError("OpenSSL is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise TrustError("OpenSSL is not an actor/root-owned nonwritable executable")
    return resolved


def run_openssl(openssl: Path, arguments: list[str], *, stdin: bytes | None = None) -> bytes:
    try:
        result = subprocess.run(
            [str(openssl), *arguments],
            input=stdin,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TrustError("OpenSSL failed before a result") from error
    if result.returncode != 0:
        raise TrustError("OpenSSL rejected the Ed25519 key operation")
    return result.stdout


def public_spki(openssl: Path, private_key: bytes) -> bytes:
    return run_openssl(
        openssl,
        ["pkey", "-pubout", "-outform", "DER"],
        stdin=private_key,
    )


def generation_receipt(
    trust: dict[str, Any], credential: dict[str, Any], spki: bytes, trust_raw: bytes
) -> dict[str, Any]:
    return {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "kind": "cats.production-cutover-operator-trust-generation.v1",
        "public_key_spki_sha256": sha256(spki),
        "release_id": trust["release_id"],
        "scope": credential["scope"],
        "source_commit_sha": trust["source_commit_sha"],
        "trust_file": TRUST_FILE,
        "trust_sha256": sha256(trust_raw),
        "trust_size_bytes": len(trust_raw),
        "version": 1,
    }


def validate_generation_receipt(
    value: Any,
    trust: dict[str, Any],
    credential: dict[str, Any],
    spki: bytes,
    trust_raw: bytes,
) -> dict[str, Any]:
    receipt = require_exact_fields(
        value,
        {
            "kind",
            "version",
            "deployment_id",
            "release_id",
            "source_commit_sha",
            "credential_id",
            "public_key_spki_sha256",
            "scope",
            "trust_file",
            "trust_sha256",
            "trust_size_bytes",
        },
        "trust generation receipt",
    )
    expected = generation_receipt(trust, credential, spki, trust_raw)
    if receipt != expected:
        raise TrustError("trust generation receipt does not bind the exact public trust")
    return receipt


def load_public_pair(
    trust_file: Path, generation_receipt_file: Path
) -> tuple[bytes, dict[str, Any], dict[str, Any], bytes, bytes, dict[str, Any]]:
    trust_raw = stable_read(trust_file, "public cutover trust", MAX_TRUST_BYTES)
    trust, credential, spki = validate_trust(decode_json(trust_raw, "public cutover trust"))
    receipt_raw = stable_read(
        generation_receipt_file,
        "trust generation receipt",
        MAX_RECEIPT_BYTES,
    )
    receipt = validate_generation_receipt(
        decode_json(receipt_raw, "trust generation receipt"),
        trust,
        credential,
        spki,
        trust_raw,
    )
    return trust_raw, trust, credential, spki, receipt_raw, receipt


def assert_expected_release(args: argparse.Namespace, trust: dict[str, Any]) -> None:
    if trust["source_commit_sha"] != args.expected_source_commit:
        raise TrustError("public trust does not match the expected source commit")
    if trust["deployment_id"] != args.expected_deployment_id:
        raise TrustError("public trust does not match the expected deployment")
    if getattr(args, "expected_release_id", None) is not None:
        if trust["release_id"] != args.expected_release_id:
            raise TrustError("public trust does not match the expected release")


def validate_release_manifest_binding(
    args: argparse.Namespace,
    trust: dict[str, Any],
) -> str:
    # The current manual-release manifest closes exactly {control_plane,
    # gateway, worker}; it carries no operator trust member.  Release binding
    # is therefore the independently approved manifest digest plus the exact
    # source-commit equality between that manifest and the public trust.
    manifest_raw = stable_read(
        args.release_manifest,
        "manual release manifest",
        MAX_RELEASE_MANIFEST_BYTES,
    )
    expected_digest = require_sha256(
        args.release_manifest_sha256, "approved release manifest digest"
    )
    if sha256(manifest_raw) != expected_digest:
        raise TrustError("manual release manifest differs from its approved digest")
    manifest = require_exact_fields(
        decode_release_manifest(manifest_raw),
        {"artifacts", "build_inputs", "guest_runtime", "source", "version"},
        "manual release manifest",
    )
    if type(manifest["version"]) is not int or manifest["version"] != 1:
        raise TrustError("manual release manifest version is not 1")
    artifacts = require_exact_fields(
        manifest["artifacts"],
        {"control_plane", "gateway", "worker"},
        "manual release artifacts",
    )
    control_image = require_exact_fields(
        artifacts["control_plane"],
        {
            "guest_manifest_sha256",
            "guest_profile_sha256",
            "image_config_digest",
            "image_digest",
            "image_reference",
            "registry_verified",
        },
        "manual release Control image",
    )
    gateway_image = require_exact_fields(
        artifacts["gateway"],
        {
            "binary_sha256",
            "binary_size_bytes",
            "image_config_digest",
            "image_digest",
            "image_reference",
            "registry_verified",
        },
        "manual release Gateway image",
    )
    for image_name, image in (
        ("control_plane", control_image),
        ("gateway", gateway_image),
    ):
        if image["registry_verified"] is not True:
            raise TrustError(
                f"manual release {image_name} image is not registry-verified"
            )
        reference = image["image_reference"]
        if (
            not isinstance(reference, str)
            or not reference
            or len(reference) > 1_024
            or "@" in reference
            or any(character.isspace() for character in reference)
        ):
            raise TrustError(f"manual release {image_name} reference is invalid")
        require_sha256(image["image_digest"], f"manual release {image_name} digest")
        require_sha256(
            image["image_config_digest"],
            f"manual release {image_name} config digest",
        )
    for field in ("guest_manifest_sha256", "guest_profile_sha256"):
        require_sha256(control_image[field], f"manual release Control {field}")
    require_sha256(gateway_image["binary_sha256"], "manual release Gateway binary")
    if (
        type(gateway_image["binary_size_bytes"]) is not int
        or gateway_image["binary_size_bytes"] <= 0
    ):
        raise TrustError("manual release Gateway binary size is invalid")

    worker = require_exact_fields(
        artifacts["worker"],
        {
            "bundle_name",
            "bundle_sha256",
            "bundle_size_bytes",
            "guest_initramfs_sha256",
            "guest_kernel_sha256",
            "guest_manifest_sha256",
            "guest_profile_sha256",
            "members",
        },
        "manual release worker",
    )
    if worker["bundle_name"] != "cats-worker.tar.zst":
        raise TrustError("manual release worker bundle name is invalid")
    for field in (
        "bundle_sha256",
        "guest_kernel_sha256",
        "guest_manifest_sha256",
        "guest_profile_sha256",
    ):
        require_sha256(worker[field], f"manual release worker {field}")
    if worker["guest_initramfs_sha256"] is not None:
        require_sha256(
            worker["guest_initramfs_sha256"],
            "manual release worker initramfs digest",
        )
    if type(worker["bundle_size_bytes"]) is not int or worker["bundle_size_bytes"] <= 0:
        raise TrustError("manual release worker bundle size is invalid")
    if not isinstance(worker["members"], dict) or not worker["members"]:
        raise TrustError("manual release worker member set is empty")
    for name, member in worker["members"].items():
        if not isinstance(name, str) or not name or "/" in name:
            raise TrustError("manual release worker member name is invalid")
        member = require_exact_fields(
            member, {"sha256", "size_bytes"}, f"manual release worker member {name}"
        )
        require_sha256(member["sha256"], f"manual release worker member {name}")
        if type(member["size_bytes"]) is not int or member["size_bytes"] <= 0:
            raise TrustError(f"manual release worker member {name} size is invalid")
    source = require_exact_fields(
        manifest["source"], {"commit", "fingerprint", "tree"}, "manual release source"
    )
    if source["commit"] != trust["source_commit_sha"]:
        raise TrustError("manual release source differs from public trust")
    require_commit(source["tree"], "manual release source tree")
    require_sha256(source["fingerprint"], "manual release source fingerprint")
    build_inputs = require_exact_fields(
        manifest["build_inputs"],
        {"files", "fingerprint", "guest_target", "platform"},
        "manual release build inputs",
    )
    if (
        build_inputs["guest_target"] != "x86_64-unknown-linux-musl"
        or build_inputs["platform"] != "linux/amd64"
    ):
        raise TrustError("manual release target is not production linux/amd64")
    require_sha256(build_inputs["fingerprint"], "manual release input fingerprint")
    if not isinstance(build_inputs["files"], dict):
        raise TrustError("manual release input file set is invalid")
    guest = require_exact_fields(
        manifest["guest_runtime"],
        {"initramfs", "kernel", "manifest_sha256", "profile_sha256", "release_id"},
        "manual release Guest runtime",
    )
    for field in ("manifest_sha256", "profile_sha256", "release_id"):
        require_sha256(guest[field], f"manual release Guest {field}")
    for field, expected_path in (
        ("kernel", "guest/vmlinuz"),
        ("initramfs", "guest/initramfs.img"),
    ):
        member = guest[field]
        if field == "initramfs" and member is None:
            continue
        member = require_exact_fields(
            member,
            {"path", "sha256", "size_bytes"},
            f"manual release Guest {field}",
        )
        if member["path"] != expected_path:
            raise TrustError(f"manual release Guest {field} path is invalid")
        require_sha256(member["sha256"], f"manual release Guest {field} digest")
        if type(member["size_bytes"]) is not int or member["size_bytes"] <= 0:
            raise TrustError(f"manual release Guest {field} size is invalid")
    return expected_digest


def generate(args: argparse.Namespace) -> dict[str, Any]:
    if args.trust_out.name != TRUST_FILE:
        raise TrustError(f"public trust output must be named {TRUST_FILE}")
    if args.generation_receipt_out.name != GENERATION_RECEIPT_FILE:
        raise TrustError(
            f"generation receipt output must be named {GENERATION_RECEIPT_FILE}"
        )
    deployment_id = require_id(args.deployment_id, "deployment_id")
    release_id = require_sha256(args.release_id, "release_id")
    source_commit = require_commit(args.source_commit, "source commit")
    credential_id = require_id(args.credential_id, "credential_id")
    scope = validate_scope(
        {
            "aws_partition": args.aws_partition,
            "account_id": args.account_id,
            "role_arn": args.role_arn,
        }
    )
    openssl = trusted_openssl(args.openssl)
    private_key = recover_published_output(
        args.private_key_out,
        "offline cutover private key",
        MAX_PRIVATE_KEY_BYTES,
        mode=0o600,
        private_parent=True,
        require_root=False,
    )
    if private_key is None:
        private_key = run_openssl(openssl, ["genpkey", "-algorithm", "ED25519"])
    if (
        not private_key.startswith(b"-----BEGIN PRIVATE KEY-----\n")
        or not private_key.endswith(b"-----END PRIVATE KEY-----\n")
        or len(private_key) > MAX_PRIVATE_KEY_BYTES
    ):
        raise TrustError("OpenSSL did not produce a bounded PKCS#8 Ed25519 private key")
    spki = public_spki(openssl, private_key)
    public_key_spki = encode_spki(spki)
    trust = {
        "credentials": [
            {
                "credential_id": credential_id,
                "public_key_spki": public_key_spki,
                "scope": scope,
            }
        ],
        "deployment_id": deployment_id,
        "release_id": release_id,
        "signature_threshold": 1,
        "source_commit_sha": source_commit,
        "version": 1,
    }
    trust_raw = canonical_json(trust)
    validate_trust(decode_json(trust_raw, "generated public cutover trust"))
    receipt_raw = canonical_json(generation_receipt(trust, trust["credentials"][0], spki, trust_raw))

    # The only secret output is published first as one actor-owned 0600 file.
    # Neither subsequent output contains its path, bytes, or digest.
    write_new(args.private_key_out, private_key, mode=0o600, private_parent=True)
    write_new(args.trust_out, trust_raw, mode=0o644, private_parent=False)
    write_new(
        args.generation_receipt_out,
        receipt_raw,
        mode=0o600,
        private_parent=True,
    )
    return {
        "generation_receipt": str(args.generation_receipt_out),
        "generation_receipt_sha256": sha256(receipt_raw),
        "public_key_spki_sha256": sha256(spki),
        "trust_file": str(args.trust_out),
        "trust_sha256": sha256(trust_raw),
    }


def verify(args: argparse.Namespace) -> dict[str, Any]:
    if args.verification_receipt_out.name != VERIFICATION_RECEIPT_FILE:
        raise TrustError(
            f"verification receipt output must be named {VERIFICATION_RECEIPT_FILE}"
        )
    trust_raw, trust, credential, spki, generation_raw, _ = load_public_pair(
        args.trust_file, args.generation_receipt
    )
    assert_expected_release(args, trust)
    private_key = stable_read(
        args.private_key_file,
        "offline cutover private key",
        MAX_PRIVATE_KEY_BYTES,
        private=True,
    )
    if public_spki(trusted_openssl(args.openssl), private_key) != spki:
        raise TrustError("offline private key does not match the public trust")
    receipt = {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "generation_receipt_sha256": sha256(generation_raw),
        "kind": "cats.production-cutover-operator-trust-verification.v1",
        "public_key_spki_sha256": sha256(spki),
        "release_id": trust["release_id"],
        "scope": credential["scope"],
        "source_commit_sha": trust["source_commit_sha"],
        "trust_sha256": sha256(trust_raw),
        "trust_size_bytes": len(trust_raw),
        "version": 1,
    }
    raw = canonical_json(receipt)
    write_new(args.verification_receipt_out, raw, mode=0o600, private_parent=True)
    return {
        "verification_receipt": str(args.verification_receipt_out),
        "verification_receipt_sha256": sha256(raw),
        "trust_sha256": sha256(trust_raw),
    }


def verify_public(args: argparse.Namespace) -> dict[str, Any]:
    trust_raw, trust, credential, spki, generation_raw, _ = load_public_pair(
        args.trust_file, args.generation_receipt
    )
    assert_expected_release(args, trust)
    return {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "generation_receipt_sha256": sha256(generation_raw),
        "public_key_spki_sha256": sha256(spki),
        "release_id": trust["release_id"],
        "source_commit_sha": trust["source_commit_sha"],
        "trust_sha256": sha256(trust_raw),
        "trust_size_bytes": len(trust_raw),
    }


def package_kubernetes(args: argparse.Namespace) -> dict[str, Any]:
    if (
        KUBERNETES_DNS_SUBDOMAIN.fullmatch(args.secret_name) is None
        or len(args.secret_name) > 253
        or not args.secret_name.endswith("-r1")
    ):
        raise TrustError("Kubernetes trust Secret name must be a DNS subdomain ending in -r1")
    if KUBERNETES_DNS_LABEL.fullmatch(args.namespace) is None:
        raise TrustError("Kubernetes namespace must be one DNS label")
    trust_raw, trust, credential, spki, generation_raw, _ = load_public_pair(
        args.trust_file, args.generation_receipt
    )
    assert_expected_release(args, trust)
    release_manifest_sha256 = validate_release_manifest_binding(args, trust)
    manifest = {
        "apiVersion": "v1",
        "data": {TRUST_FILE: base64.b64encode(trust_raw).decode("ascii")},
        "immutable": True,
        "kind": "Secret",
        "metadata": {
            "annotations": {
                "cats.run/production-cutover-operator-trust-sha256": sha256(trust_raw),
                "cats.run/release-id": trust["release_id"],
                "cats.run/release-manifest-sha256": release_manifest_sha256,
                "cats.run/source-commit": trust["source_commit_sha"],
            },
            "labels": {
                "app.kubernetes.io/managed-by": "cats-offline-authority",
                "app.kubernetes.io/part-of": "cats",
            },
            "name": args.secret_name,
            "namespace": args.namespace,
        },
        "type": "Opaque",
    }
    manifest_raw = canonical_json(manifest)
    receipt = {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "generation_receipt_sha256": sha256(generation_raw),
        "immutable": True,
        "kind": "cats.production-cutover-operator-trust-kubernetes-package.v1",
        "namespace": args.namespace,
        "public_key_spki_sha256": sha256(spki),
        "release_id": trust["release_id"],
        "release_manifest_sha256": release_manifest_sha256,
        "secret_key": TRUST_FILE,
        "secret_manifest_sha256": sha256(manifest_raw),
        "secret_name": args.secret_name,
        "source_commit_sha": trust["source_commit_sha"],
        "trust_sha256": sha256(trust_raw),
        "trust_size_bytes": len(trust_raw),
        "version": 1,
    }
    receipt_raw = canonical_json(receipt)
    write_new(args.manifest_out, manifest_raw, mode=0o600, private_parent=True)
    write_new(args.receipt_out, receipt_raw, mode=0o600, private_parent=True)
    return {
        "package_receipt": str(args.receipt_out),
        "package_receipt_sha256": sha256(receipt_raw),
        "secret_manifest": str(args.manifest_out),
        "secret_manifest_sha256": sha256(manifest_raw),
        "trust_sha256": sha256(trust_raw),
    }


def install_host(args: argparse.Namespace) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TrustError("Host trust installation must run as root")
    trust_raw, trust, credential, spki, generation_raw, _ = load_public_pair(
        args.trust_file, args.generation_receipt
    )
    assert_expected_release(args, trust)
    release_manifest_sha256 = validate_release_manifest_binding(args, trust)
    try:
        parent = INSTALLED_TRUST_PATH.parent.stat(follow_symlinks=False)
    except OSError as error:
        raise TrustError("canonical /etc/cats directory is unavailable") from error
    if (
        not stat.S_ISDIR(parent.st_mode)
        or INSTALLED_TRUST_PATH.parent.is_symlink()
        or parent.st_uid != 0
        or parent.st_gid != 0
        or stat.S_IMODE(parent.st_mode) not in {0o700, 0o755}
    ):
        raise TrustError("canonical /etc/cats directory metadata is invalid")
    write_exact_or_replay(
        INSTALLED_TRUST_PATH,
        trust_raw,
        mode=0o644,
        private_parent=False,
    )
    installed, metadata = inspect_published_output(
        INSTALLED_TRUST_PATH,
        "installed public cutover trust",
        MAX_TRUST_BYTES,
        mode=0o644,
        private_parent=False,
        require_root=True,
    )
    if installed != trust_raw or stat.S_IMODE(metadata.st_mode) != 0o644:
        raise TrustError("installed public cutover trust changed after publish")
    receipt = {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "generation_receipt_sha256": sha256(generation_raw),
        "installed": {
            "gid": metadata.st_gid,
            "mode": "0644",
            "nlink": metadata.st_nlink,
            "path": str(INSTALLED_TRUST_PATH),
            "sha256": sha256(installed),
            "size_bytes": len(installed),
            "uid": metadata.st_uid,
        },
        "kind": "cats.production-cutover-operator-trust-host-installation.v1",
        "public_key_spki_sha256": sha256(spki),
        "release_id": trust["release_id"],
        "release_manifest_sha256": release_manifest_sha256,
        "source_commit_sha": trust["source_commit_sha"],
        "trust_sha256": sha256(trust_raw),
        "version": 1,
    }
    receipt_raw = canonical_json(receipt)
    write_exact_or_replay(
        args.receipt_out,
        receipt_raw,
        mode=0o600,
        private_parent=True,
        require_root=True,
    )
    installed_receipt, _ = inspect_published_output(
        args.receipt_out,
        "Host trust installation receipt",
        MAX_RECEIPT_BYTES,
        mode=0o600,
        private_parent=True,
        require_root=True,
    )
    if installed_receipt != receipt_raw:
        raise TrustError("Host trust installation receipt changed after publish")
    return {
        "installation_receipt": str(args.receipt_out),
        "installation_receipt_sha256": sha256(receipt_raw),
        "trust_sha256": sha256(trust_raw),
    }


def install_operator_host(args: argparse.Namespace) -> dict[str, Any]:
    if os.geteuid() != 0:
        raise TrustError("operator execution Host installation must run as root")
    trust_raw, trust, credential, spki, generation_raw, _ = load_public_pair(
        args.trust_file, args.generation_receipt
    )
    assert_expected_release(args, trust)
    release_manifest_sha256 = validate_release_manifest_binding(args, trust)
    private_key = stable_read(
        args.private_key_file,
        "offline cutover private key",
        MAX_PRIVATE_KEY_BYTES,
        private=True,
        require_root=True,
        exact_mode=0o600,
    )
    if public_spki(trusted_openssl(args.openssl), private_key) != spki:
        raise TrustError("offline private key does not match the release public trust")
    try:
        root = OPERATOR_HOST_ROOT.stat(follow_symlinks=False)
    except OSError as error:
        raise TrustError("canonical operator Host directory is unavailable") from error
    if (
        not stat.S_ISDIR(root.st_mode)
        or OPERATOR_HOST_ROOT.is_symlink()
        or root.st_uid != 0
        or root.st_gid != 0
        or stat.S_IMODE(root.st_mode) != 0o700
    ):
        raise TrustError("canonical operator Host directory must be root:root 0700")
    final_open_state = provision_final_open_state_layout()
    write_exact_or_replay(
        OPERATOR_HOST_TRUST_PATH,
        trust_raw,
        mode=0o644,
        private_parent=True,
    )
    # Publish the public release identity before enabling the matching secret
    # signer. A failed second step cannot leave a usable unbound signer.
    write_exact_or_replay(
        OPERATOR_HOST_PRIVATE_KEY_PATH,
        private_key,
        mode=0o600,
        private_parent=True,
    )
    installed_key, key_metadata = inspect_published_output(
        OPERATOR_HOST_PRIVATE_KEY_PATH,
        "operator Host offline cutover private key",
        MAX_PRIVATE_KEY_BYTES,
        mode=0o600,
        private_parent=True,
        require_root=True,
    )
    installed_trust, trust_metadata = inspect_published_output(
        OPERATOR_HOST_TRUST_PATH,
        "operator Host public cutover trust",
        MAX_TRUST_BYTES,
        mode=0o644,
        private_parent=True,
        require_root=True,
    )
    if (
        installed_key != private_key
        or key_metadata.st_uid != 0
        or key_metadata.st_gid != 0
        or key_metadata.st_nlink != 1
        or stat.S_IMODE(key_metadata.st_mode) != 0o600
        or installed_trust != trust_raw
        or trust_metadata.st_uid != 0
        or trust_metadata.st_gid != 0
        or trust_metadata.st_nlink != 1
        or stat.S_IMODE(trust_metadata.st_mode) != 0o644
    ):
        raise TrustError("operator Host installation metadata changed after publish")
    # Deliberately omit the private input's path, name, bytes, size and digest.
    # A successful receipt proves the typed installer completed; it does not
    # turn secret material into release or evidence identity.
    receipt = {
        "credential_id": credential["credential_id"],
        "deployment_id": trust["deployment_id"],
        "generation_receipt_sha256": sha256(generation_raw),
        "final_open_state": final_open_state,
        "kind": "cats.production-cutover-operator-execution-host-installation.v1",
        "public_key_spki_sha256": sha256(spki),
        "public_trust": {
            "gid": trust_metadata.st_gid,
            "mode": "0644",
            "nlink": trust_metadata.st_nlink,
            "path": str(OPERATOR_HOST_TRUST_PATH),
            "sha256": sha256(installed_trust),
            "size_bytes": len(installed_trust),
            "uid": trust_metadata.st_uid,
        },
        "release_id": trust["release_id"],
        "release_manifest_sha256": release_manifest_sha256,
        "secret_material_recorded": False,
        "source_commit_sha": trust["source_commit_sha"],
        "version": 1,
    }
    receipt_raw = canonical_json(receipt)
    write_exact_or_replay(
        args.receipt_out,
        receipt_raw,
        mode=0o600,
        private_parent=True,
        require_root=True,
    )
    installed_receipt, _ = inspect_published_output(
        args.receipt_out,
        "operator Host installation receipt",
        MAX_RECEIPT_BYTES,
        mode=0o600,
        private_parent=True,
        require_root=True,
    )
    if installed_receipt != receipt_raw:
        raise TrustError("operator Host installation receipt changed after publish")
    return {
        "installation_receipt": str(args.receipt_out),
        "installation_receipt_sha256": sha256(receipt_raw),
        "trust_sha256": sha256(trust_raw),
    }


def add_expected_release(parser: argparse.ArgumentParser, *, release: bool) -> None:
    parser.add_argument("--expected-source-commit", required=True)
    parser.add_argument("--expected-deployment-id", required=True)
    if release:
        parser.add_argument("--expected-release-id", required=True)


def add_release_manifest(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--release-manifest", required=True, type=Path)
    parser.add_argument("--release-manifest-sha256", required=True)


def parse_arguments(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    generate_parser = commands.add_parser(
        "generate", help="create one fresh offline key and canonical public trust"
    )
    generate_parser.add_argument("--deployment-id", required=True)
    generate_parser.add_argument("--release-id", required=True)
    generate_parser.add_argument("--source-commit", required=True)
    generate_parser.add_argument("--credential-id", required=True)
    generate_parser.add_argument("--aws-partition", choices=sorted(PARTITIONS), required=True)
    generate_parser.add_argument("--account-id", required=True)
    generate_parser.add_argument("--role-arn", required=True)
    generate_parser.add_argument("--private-key-out", required=True, type=Path)
    generate_parser.add_argument("--trust-out", required=True, type=Path)
    generate_parser.add_argument(
        "--generation-receipt-out", required=True, type=Path
    )
    generate_parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))

    verify_parser = commands.add_parser(
        "verify", help="prove the offline private key matches the release public trust"
    )
    verify_parser.add_argument("--trust-file", required=True, type=Path)
    verify_parser.add_argument("--generation-receipt", required=True, type=Path)
    verify_parser.add_argument("--private-key-file", required=True, type=Path)
    verify_parser.add_argument(
        "--verification-receipt-out", required=True, type=Path
    )
    verify_parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))
    add_expected_release(verify_parser, release=True)

    public_parser = commands.add_parser(
        "verify-public", help="verify only the public trust and generation receipt"
    )
    public_parser.add_argument("--trust-file", required=True, type=Path)
    public_parser.add_argument("--generation-receipt", required=True, type=Path)
    add_expected_release(public_parser, release=True)

    package_parser = commands.add_parser(
        "package-kubernetes", help="build one immutable one-file Kubernetes Secret"
    )
    package_parser.add_argument("--trust-file", required=True, type=Path)
    package_parser.add_argument("--generation-receipt", required=True, type=Path)
    package_parser.add_argument("--secret-name", required=True)
    package_parser.add_argument("--namespace", required=True)
    package_parser.add_argument("--manifest-out", required=True, type=Path)
    package_parser.add_argument("--receipt-out", required=True, type=Path)
    add_expected_release(package_parser, release=True)
    add_release_manifest(package_parser)

    install_parser = commands.add_parser(
        "install-host", help="install the exact public trust at its fixed Host path"
    )
    install_parser.add_argument("--trust-file", required=True, type=Path)
    install_parser.add_argument("--generation-receipt", required=True, type=Path)
    install_parser.add_argument("--receipt-out", required=True, type=Path)
    add_expected_release(install_parser, release=True)
    add_release_manifest(install_parser)

    operator_install_parser = commands.add_parser(
        "install-operator-host",
        help="install the offline signer on its dedicated execution Host",
    )
    operator_install_parser.add_argument("--trust-file", required=True, type=Path)
    operator_install_parser.add_argument(
        "--generation-receipt", required=True, type=Path
    )
    operator_install_parser.add_argument(
        "--private-key-file", required=True, type=Path
    )
    operator_install_parser.add_argument("--receipt-out", required=True, type=Path)
    operator_install_parser.add_argument(
        "--openssl", type=Path, default=Path("/usr/bin/openssl")
    )
    add_expected_release(operator_install_parser, release=True)
    add_release_manifest(operator_install_parser)
    return parser.parse_args(argv)


def main(argv: Sequence[str] | None = None) -> int:
    args = parse_arguments(argv)
    try:
        if args.command == "generate":
            result = generate(args)
        elif args.command == "verify":
            result = verify(args)
        elif args.command == "verify-public":
            result = verify_public(args)
        elif args.command == "package-kubernetes":
            result = package_kubernetes(args)
        elif args.command == "install-host":
            result = install_host(args)
        else:
            result = install_operator_host(args)
        print(canonical_json(result).decode("ascii"))
        return 0
    except (OSError, TrustError) as error:
        print(f"production cutover operator trust refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
