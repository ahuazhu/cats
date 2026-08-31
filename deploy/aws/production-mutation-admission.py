#!/usr/bin/env python3
"""Dedicated production qualification admission command client.

This client has no WorkOS, A23, G3, administrator-token or Workspace-token
fallback.  ``prepare`` performs a real AWS STS caller-identity lookup, binds
that exact assumed-role principal into a short-lived canonical command, signs
the command with the dedicated offline Ed25519 key and durably publishes a
pending record before any HTTP request can be made.  ``apply`` reuses those
exact bytes for submission, replay and typed discovery.

Control authenticates the offline signature and verifies that the signed STS
claim is inside the release-bound trust scope.  It does not contact STS; the
online lookup and its signed binding are operator-tool evidence, not a second
Control-side authentication factor.  The Qualification wrapper commands use
the same path: they discover the current revision with a signed read-only
request, durably journal each effect command, resolve ambiguous responses by
exact discovery, close before post-run terminal evidence, and never issue a
new effect from the terminalizer.
"""

from __future__ import annotations

import argparse
import base64
import dataclasses
import hashlib
import http.client
import json
import os
import re
import secrets
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any, Sequence
from urllib.parse import urlsplit


COMMAND_PATH = "/v1/admin/production/mutation-admission-commands"
DISCOVERY_PATH = "/v1/admin/production/mutation-admission-command-discoveries"
STATE_PATH = "/v1/admin/production/mutation-admission-state-discoveries"
PRODUCT_INVENTORY_PATH = (
    "/v1/admin/production/qualification-product-inventory-discoveries"
)
CREDENTIAL_HEADER = "cats-production-cutover-credential-id"
SIGNATURE_HEADER = "cats-production-cutover-signature"
CONTENT_TYPE = "application/json"
SIGNATURE_DOMAIN = b"cats.production-mutation-admission.command.v1"
MAX_COMMAND_BYTES = 65_536
MAX_RESPONSE_BYTES = 131_072
MAX_TRUST_BYTES = 65_536
MAX_BINDING_BYTES = 65_536
MAX_KEY_BYTES = 16_384
MAX_COMMAND_LIFETIME_MS = 5 * 60 * 1_000
MAX_QUALIFICATION_LIFETIME_MS = 24 * 60 * 60 * 1_000
CONTROL_SCHEMA_VERSION = 19
DEFAULT_COMMAND_LIFETIME_MS = 4 * 60 * 1_000
DEFAULT_RESOLUTION_SECONDS = 120
QUALIFICATION_BEGIN_RECEIPT_FILE = (
    "production-mutation-qualification-begin.receipt.json"
)
QUALIFICATION_TERMINAL_RECEIPT_FILE = (
    "production-mutation-qualification-terminal.receipt.json"
)
QUALIFICATION_FINAL_STATE_FILE = (
    "production-mutation-qualification-final-admission-state.json"
)
QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-begin.command-receipt.json"
)
QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-close.command-receipt.json"
)
QUALIFICATION_BEGIN_PENDING_FILE = (
    "production-mutation-qualification-begin.pending.json"
)
QUALIFICATION_CLOSE_PENDING_FILE = (
    "production-mutation-qualification-close.pending.json"
)
QUALIFICATION_FINAL_FLEET_FILE = (
    "production-mutation-qualification-final-fleet-closed.receipt.json"
)
QUALIFICATION_CLEANUP_INVENTORY_FILE = (
    "production-mutation-qualification-cleanup-inventory.receipt.json"
)
QUALIFICATION_PRODUCT_INVENTORY_FILE = (
    "production-mutation-qualification-product-inventory.receipt.json"
)
QUALIFICATION_BEGIN_RECEIPT_KIND = (
    "cats.production-mutation-qualification-begin-receipt.v1"
)
QUALIFICATION_TERMINAL_RECEIPT_KIND = (
    "cats.production-mutation-qualification-terminal-receipt.v1"
)
QUALIFICATION_CLEANUP_INVENTORY_KIND = (
    "cats.production-mutation-qualification-cleanup-inventory.v1"
)
QUALIFICATION_PRODUCT_INVENTORY_KIND = (
    "cats.production-mutation-qualification-product-inventory.v1"
)
QUALIFICATION_FINAL_FLEET_KIND = (
    "cats.production-mutation-qualification-final-fleet-closed.v1"
)
MAX_QUALIFICATION_EVIDENCE_BYTES = 1024 * 1024
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RANDOM_ID = re.compile(r"^[0-9a-f]{32}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

QUALIFICATION_BINDING_FIELDS = {
    "qualification_id",
    "deployment_id",
    "release_id",
    "source_commit_sha",
    "control_schema_version",
    "source_manifest_sha256",
    "source_bundle_sha256",
    "build_receipt_sha256",
    "release_manifest_sha256",
    "worker_bundle_sha256",
    "qualification_catalog_sha256",
    "qualification_cell_manifest_sha256",
    "aws_partition",
    "aws_account_id",
    "aws_region",
    "cell_id",
    "cell_namespace",
    "cats_account_id",
    "workspace_id",
    "allowed_mutation_classes",
    "qualification_expires_at_unix_ms",
}
QUALIFICATION_MUTATION_CLASSES = [
    "cat_create",
    "disk_create",
    "disk_delete",
    "runtime_mutation",
]


class AdmissionError(RuntimeError):
    """A bounded, non-secret reason why the command was refused."""


class DuplicateJsonKey(ValueError):
    pass


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise DuplicateJsonKey(key)
        result[key] = value
    return result


def canonical_json(value: Any, *, newline: bool = False) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + suffix
    ).encode("ascii")


def decode_json(data: bytes, label: str) -> Any:
    try:
        text = data.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=reject_duplicate_keys)
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, DuplicateJsonKey) as error:
        raise AdmissionError(f"{label} is not one duplicate-free JSON value") from error
    if text[end:] not in {"", "\n"}:
        raise AdmissionError(f"{label} has trailing bytes")
    return value


def require_fields(value: Any, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise AdmissionError(f"{label} must be an object")
    if set(value) != fields:
        raise AdmissionError(f"{label} does not have its exact closed field set")
    return value


def require_string(value: Any, pattern: re.Pattern[str], label: str) -> str:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise AdmissionError(f"{label} is invalid")
    return value


def version_one(value: Any) -> bool:
    return type(value) is int and value == 1


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def decode_base64url(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or BASE64URL.fullmatch(value) is None:
        raise AdmissionError(f"{label} is not canonical base64url")
    try:
        decoded = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except ValueError as error:
        raise AdmissionError(f"{label} is not canonical base64url") from error
    if base64.urlsafe_b64encode(decoded).rstrip(b"=").decode("ascii") != value:
        raise AdmissionError(f"{label} is not canonical base64url")
    return decoded


def encode_base64url(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


@dataclasses.dataclass(frozen=True)
class FileSnapshot:
    device: int
    inode: int
    mode: int
    uid: int
    gid: int
    links: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileSnapshot":
        return cls(
            value.st_dev,
            value.st_ino,
            value.st_mode,
            value.st_uid,
            value.st_gid,
            value.st_nlink,
            value.st_size,
            value.st_mtime_ns,
            value.st_ctime_ns,
        )


def read_stable_file(path: Path, label: str, maximum: int, *, private: bool) -> bytes:
    if not path.is_absolute():
        raise AdmissionError(f"{label} path must be absolute")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise AdmissionError(f"cannot open {label} as a non-symlink file") from error
    try:
        before_stat = os.fstat(descriptor)
        before = FileSnapshot.from_stat(before_stat)
        forbidden = 0o077 if private else 0o022
        if (
            not stat.S_ISREG(before.mode)
            or before.uid != os.geteuid()
            or before.links != 1
            or before.mode & forbidden
            or before.size <= 0
            or before.size > maximum
        ):
            raise AdmissionError(f"{label} ownership, links, mode or size is invalid")
        chunks: list[bytes] = []
        remaining = before.size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 64 * 1024))
            if not chunk:
                raise AdmissionError(f"{label} changed during its bounded read")
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise AdmissionError(f"{label} grew during its bounded read")
        after = FileSnapshot.from_stat(os.fstat(descriptor))
        if after != before:
            raise AdmissionError(f"{label} changed during its bounded read")
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def validate_private_directory(path: Path) -> None:
    if not path.is_absolute():
        raise AdmissionError("state directory must be absolute")
    inherited = re.fullmatch(r"/(?:proc/self|dev)/fd/([0-9]+)", str(path))
    if inherited is not None:
        try:
            metadata = os.fstat(int(inherited.group(1)))
        except OSError as error:
            raise AdmissionError("inherited state directory descriptor is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise AdmissionError(
                "inherited state directory must be an actor-owned mode-0700 directory"
            )
        return
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise AdmissionError("state directory must already exist") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or metadata.st_mode & 0o077
    ):
        raise AdmissionError("state directory must be an actor-owned mode-0700 real directory")


def write_atomic(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    validate_private_directory(path.parent)
    temporary_descriptor: int | None = None
    temporary_name: str | None = None
    try:
        temporary_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.", dir=path.parent
        )
        os.fchmod(temporary_descriptor, mode)
        offset = 0
        while offset < len(data):
            offset += os.write(temporary_descriptor, data[offset:])
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = None
        try:
            os.link(temporary_name, path, follow_symlinks=False)
        except FileExistsError:
            existing = read_stable_file(path, path.name, len(data), private=True)
            if existing != data:
                raise AdmissionError(f"refusing to replace different durable {path.name}")
        directory = os.open(
            path.parent,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_descriptor is not None:
            os.close(temporary_descriptor)
        if temporary_name is not None:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass


def validate_origin(value: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise AdmissionError("Control origin must be an exact HTTPS origin")
    port = parsed.port
    if port is not None and not 1 <= port <= 65535:
        raise AdmissionError("Control origin port is invalid")
    canonical = f"https://{parsed.hostname}"
    if port not in {None, 443}:
        canonical += f":{port}"
    if value.rstrip("/") != canonical:
        raise AdmissionError("Control origin is not canonical")
    return canonical


def validate_qualification_binding(value: Any) -> dict[str, Any]:
    binding = require_fields(
        value, QUALIFICATION_BINDING_FIELDS, "Qualification admission binding"
    )
    for field in (
        "qualification_id",
        "deployment_id",
        "release_id",
        "cell_id",
        "cats_account_id",
        "workspace_id",
    ):
        require_string(binding[field], ID, f"qualification binding.{field}")
    require_string(
        binding["source_commit_sha"], COMMIT, "qualification binding.source_commit_sha"
    )
    if binding["control_schema_version"] != CONTROL_SCHEMA_VERSION:
        raise AdmissionError(
            "qualification binding.control_schema_version must be "
            f"{CONTROL_SCHEMA_VERSION}"
        )
    for field in (
        "source_manifest_sha256",
        "source_bundle_sha256",
        "build_receipt_sha256",
        "release_manifest_sha256",
        "worker_bundle_sha256",
        "qualification_catalog_sha256",
        "qualification_cell_manifest_sha256",
    ):
        require_string(binding[field], SHA256, f"qualification binding.{field}")
    if binding["aws_partition"] not in {"aws", "aws-us-gov", "aws-cn"}:
        raise AdmissionError("qualification binding AWS partition is invalid")
    require_string(
        binding["aws_account_id"], ACCOUNT_ID, "qualification binding.aws_account_id"
    )
    if (
        not isinstance(binding["aws_region"], str)
        or re.fullmatch(r"[a-z0-9][a-z0-9-]{1,30}[a-z0-9]", binding["aws_region"])
        is None
        or "-" not in binding["aws_region"]
    ):
        raise AdmissionError("qualification binding AWS region is invalid")
    if (
        not isinstance(binding["cell_namespace"], str)
        or re.fullmatch(
            r"[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?", binding["cell_namespace"]
        )
        is None
    ):
        raise AdmissionError("qualification binding cell namespace is invalid")
    if binding["allowed_mutation_classes"] != QUALIFICATION_MUTATION_CLASSES:
        raise AdmissionError(
            "qualification binding must carry the exact sorted mutation-class closed set"
        )
    expires = binding["qualification_expires_at_unix_ms"]
    if not isinstance(expires, int) or isinstance(expires, bool) or expires <= 0:
        raise AdmissionError("qualification binding expiry is invalid")
    return binding


def validate_state_binding(value: Any) -> dict[str, Any]:
    state_binding = require_fields(value, {"kind", "binding"}, "state binding")
    if state_binding["kind"] != "qualification":
        raise AdmissionError("state binding kind is invalid")
    validate_qualification_binding(state_binding["binding"])
    return state_binding


def validate_trust(value: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    trust = require_fields(
        value,
        {
            "version",
            "deployment_id",
            "release_id",
            "source_commit_sha",
            "signature_threshold",
            "credentials",
        },
        "cutover trust bundle",
    )
    if not version_one(trust["version"]) or not version_one(
        trust["signature_threshold"]
    ):
        raise AdmissionError("unsupported cutover trust version or threshold")
    for field in ("deployment_id", "release_id"):
        require_string(trust[field], ID, f"trust.{field}")
    require_string(trust["source_commit_sha"], COMMIT, "trust.source_commit_sha")
    if not isinstance(trust["credentials"], list) or len(trust["credentials"]) != 1:
        raise AdmissionError("cutover trust v1 requires exactly one credential")
    credential = require_fields(
        trust["credentials"][0],
        {"credential_id", "public_key_spki", "scope"},
        "cutover credential",
    )
    require_string(credential["credential_id"], ID, "credential_id")
    spki = decode_base64url(credential["public_key_spki"], "public_key_spki")
    if len(spki) != 44 or not spki.startswith(ED25519_SPKI_PREFIX):
        raise AdmissionError("cutover credential is not canonical Ed25519 SPKI")
    scope = require_fields(
        credential["scope"], {"aws_partition", "account_id", "role_arn"}, "trust scope"
    )
    if scope["aws_partition"] not in {"aws", "aws-us-gov", "aws-cn"}:
        raise AdmissionError("trust AWS partition is invalid")
    require_string(scope["account_id"], ACCOUNT_ID, "trust account_id")
    expected = f"arn:{scope['aws_partition']}:iam::{scope['account_id']}:role/"
    if not isinstance(scope["role_arn"], str) or not scope["role_arn"].startswith(expected):
        raise AdmissionError("trust role ARN is outside its partition/account")
    return trust, credential


def command_runner(argv: Sequence[str], *, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            list(argv),
            input=input_bytes,
            capture_output=True,
            check=False,
            timeout=30,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise AdmissionError(f"{Path(argv[0]).name} failed before a result") from error
    if completed.returncode != 0:
        raise AdmissionError(f"{Path(argv[0]).name} command failed closed")
    return completed.stdout


def trusted_executable(path: Path, label: str) -> Path:
    if not path.is_absolute():
        raise AdmissionError(f"{label} path must be absolute")
    try:
        resolved = path.resolve(strict=True)
        metadata = resolved.stat(follow_symlinks=False)
    except OSError as error:
        raise AdmissionError(f"{label} is unavailable") from error
    if (
        not stat.S_ISREG(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o022
        or not metadata.st_mode & 0o111
    ):
        raise AdmissionError(f"{label} is not a root-owned nonwritable executable")
    return resolved


def discover_sts(aws: Path, scope: dict[str, Any]) -> dict[str, Any]:
    aws = trusted_executable(aws, "AWS CLI")
    output = command_runner(
        [
            str(aws),
            "--no-cli-pager",
            "--no-paginate",
            "--output",
            "json",
            "sts",
            "get-caller-identity",
        ]
    )
    identity = decode_json(output, "AWS STS caller identity")
    identity = require_fields(identity, {"Account", "Arn", "UserId"}, "AWS STS identity")
    if identity["Account"] != scope["account_id"]:
        raise AdmissionError("AWS STS account does not match cutover trust")
    role_name = scope["role_arn"].rsplit("/", 1)[-1]
    prefix = (
        f"arn:{scope['aws_partition']}:sts::{scope['account_id']}:"
        f"assumed-role/{role_name}/"
    )
    if (
        not isinstance(identity["Arn"], str)
        or not identity["Arn"].startswith(prefix)
        or len(identity["Arn"]) == len(prefix)
    ):
        raise AdmissionError("AWS STS principal is not the trusted assumed role")
    return {
        "aws_partition": scope["aws_partition"],
        "account_id": scope["account_id"],
        "role_arn": scope["role_arn"],
        "principal_arn": identity["Arn"],
    }


def signed_frame(trust: dict[str, Any], credential_id: str, body: bytes) -> bytes:
    output = bytearray(SIGNATURE_DOMAIN)
    output.append(0)
    for value in (
        b"POST",
        COMMAND_PATH.encode("ascii"),
        CONTENT_TYPE.encode("ascii"),
        trust["deployment_id"].encode("ascii"),
        trust["release_id"].encode("ascii"),
        trust["source_commit_sha"].encode("ascii"),
        credential_id.encode("ascii"),
    ):
        output.extend(struct.pack(">Q", len(value)))
        output.extend(value)
    output.extend(struct.pack(">Q", len(body)))
    output.extend(hashlib.sha256(body).digest())
    return bytes(output)


def sign_frame(
    openssl: Path,
    private_key: Path,
    expected_spki: bytes,
    frame: bytes,
    state_directory: Path,
) -> bytes:
    key_bytes = read_stable_file(private_key, "cutover private key", MAX_KEY_BYTES, private=True)
    if b"-----BEGIN PRIVATE KEY-----" not in key_bytes:
        raise AdmissionError("cutover private key must be PKCS#8 PEM")
    openssl = trusted_executable(openssl, "OpenSSL")
    key_descriptor, key_name = tempfile.mkstemp(prefix=".cutover-key.", dir=state_directory)
    frame_descriptor, frame_name = tempfile.mkstemp(prefix=".cutover-frame.", dir=state_directory)
    try:
        for descriptor, value in ((key_descriptor, key_bytes), (frame_descriptor, frame)):
            os.fchmod(descriptor, 0o600)
            offset = 0
            while offset < len(value):
                offset += os.write(descriptor, value[offset:])
            os.fsync(descriptor)
            os.close(descriptor)
        key_descriptor = -1
        frame_descriptor = -1
        public = command_runner(
            [str(openssl), "pkey", "-in", key_name, "-pubout", "-outform", "DER"]
        )
        if public != expected_spki:
            raise AdmissionError("cutover private key does not match the release trust artifact")
        signature = command_runner(
            [
                str(openssl),
                "pkeyutl",
                "-sign",
                "-rawin",
                "-inkey",
                key_name,
                "-in",
                frame_name,
            ]
        )
    finally:
        for descriptor in (key_descriptor, frame_descriptor):
            if descriptor >= 0:
                os.close(descriptor)
        for name in (key_name, frame_name):
            try:
                os.unlink(name)
            except FileNotFoundError:
                pass
        directory = os.open(
            state_directory,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_DIRECTORY", 0),
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    if len(signature) != 64:
        raise AdmissionError("OpenSSL did not produce an Ed25519 signature")
    return signature


def validate_command(value: Any) -> dict[str, Any]:
    command = require_fields(
        value,
        {
            "version",
            "command_id",
            "issued_at_unix_ms",
            "expires_at_unix_ms",
            "operator",
            "expected_revision",
            "mutation",
        },
        "production admission command",
    )
    if not version_one(command["version"]):
        raise AdmissionError("unsupported command version")
    require_string(command["command_id"], RANDOM_ID, "command_id")
    issued = command["issued_at_unix_ms"]
    expires = command["expires_at_unix_ms"]
    if (
        not isinstance(issued, int)
        or isinstance(issued, bool)
        or not isinstance(expires, int)
        or isinstance(expires, bool)
        or issued < 0
        or expires <= issued
        or expires - issued > MAX_COMMAND_LIFETIME_MS
    ):
        raise AdmissionError("command execution window is invalid")
    if (
        not isinstance(command["expected_revision"], int)
        or isinstance(command["expected_revision"], bool)
        or command["expected_revision"] <= 0
    ):
        raise AdmissionError("expected revision must be positive")
    require_fields(
        command["operator"],
        {"aws_partition", "account_id", "role_arn", "principal_arn"},
        "command operator",
    )
    mutation = require_fields(command["mutation"], {"kind", "binding"}, "command mutation")
    if mutation["kind"] == "begin_qualification":
        binding = validate_qualification_binding(mutation["binding"])
        qualification_expiry = binding["qualification_expires_at_unix_ms"]
        if (
            qualification_expiry <= expires
            or qualification_expiry - issued > MAX_QUALIFICATION_LIFETIME_MS
        ):
            raise AdmissionError("Qualification lifetime is outside its closed DB window")
    elif mutation["kind"] == "end_qualification":
        validate_qualification_binding(mutation["binding"])
    elif mutation["kind"] == "emergency_close":
        validate_state_binding(mutation["binding"])
    else:
        raise AdmissionError("unsupported admission mutation")
    return command


def command_plain_binding(command: dict[str, Any]) -> dict[str, Any]:
    mutation = command["mutation"]
    if mutation["kind"] == "emergency_close":
        return mutation["binding"]["binding"]
    return mutation["binding"]


def command_state_binding(command: dict[str, Any]) -> dict[str, Any]:
    mutation = command["mutation"]
    if mutation["kind"] == "emergency_close":
        return mutation["binding"]
    return {"kind": "qualification", "binding": mutation["binding"]}


def prepare(args: argparse.Namespace) -> tuple[Path, str]:
    validate_private_directory(args.state_directory)
    origin = validate_origin(args.origin)
    trust_bytes = read_stable_file(args.trust_file, "cutover trust", MAX_TRUST_BYTES, private=False)
    trust_value = decode_json(trust_bytes, "cutover trust")
    trust, credential = validate_trust(trust_value)
    if canonical_json(trust) != trust_bytes:
        raise AdmissionError("cutover trust is not canonical Cats JSON")
    binding_bytes = read_stable_file(
        args.binding_file, "admission binding", MAX_BINDING_BYTES, private=False
    )
    decoded_binding = decode_json(binding_bytes, "admission binding")
    binding = validate_qualification_binding(decoded_binding)
    if canonical_json(binding, newline=True) != binding_bytes:
        raise AdmissionError("admission binding must be canonical JSON with one terminal LF")
    if (
        binding["deployment_id"] != trust["deployment_id"]
        or binding["release_id"] != trust["release_id"]
        or binding["source_commit_sha"] != trust["source_commit_sha"]
    ):
        raise AdmissionError("admission binding does not match cutover trust release scope")
    operator = discover_sts(args.aws, credential["scope"])
    command_id = args.command_id or secrets.token_hex(16)
    require_string(command_id, RANDOM_ID, "command_id")
    issued = time.time_ns() // 1_000_000
    lifetime = args.command_lifetime_seconds * 1_000
    if lifetime <= 0 or lifetime > MAX_COMMAND_LIFETIME_MS:
        raise AdmissionError("command lifetime exceeds the closed five-minute limit")
    wire_binding = (
        {"kind": "qualification", "binding": binding}
        if args.mutation == "emergency_close"
        else binding
    )
    command = {
        "version": 1,
        "command_id": command_id,
        "issued_at_unix_ms": issued,
        "expires_at_unix_ms": issued + lifetime,
        "operator": operator,
        "expected_revision": args.expected_revision,
        "mutation": {"kind": args.mutation, "binding": wire_binding},
    }
    validate_command(command)
    body = canonical_json(command)
    if len(body) > MAX_COMMAND_BYTES:
        raise AdmissionError("canonical command exceeds its wire limit")
    expected_spki = decode_base64url(credential["public_key_spki"], "public_key_spki")
    frame = signed_frame(trust, credential["credential_id"], body)
    signature = sign_frame(
        args.openssl,
        args.private_key_file,
        expected_spki,
        frame,
        args.state_directory,
    )
    pending = {
        "version": 1,
        "origin": origin,
        "method": "POST",
        "target": COMMAND_PATH,
        "discovery_target": DISCOVERY_PATH,
        "state_target": STATE_PATH,
        "credential_id": credential["credential_id"],
        "public_key_spki_sha256": sha256(expected_spki),
        "trust_sha256": sha256(trust_bytes),
        "request_sha256": sha256(body),
        "body_base64": encode_base64url(body),
        "signature": encode_base64url(signature),
        "created_at_unix_ms": issued,
    }
    payload = canonical_json(pending, newline=True)
    path = args.state_directory / f"{command_id}.pending.v1.json"
    write_atomic(path, payload)
    return path, sha256(payload)


def load_pending(path: Path, trust_path: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
    pending_bytes = read_stable_file(path, "pending command", MAX_RESPONSE_BYTES, private=True)
    pending = require_fields(
        decode_json(pending_bytes, "pending command"),
        {
            "version",
            "origin",
            "method",
            "target",
            "discovery_target",
            "state_target",
            "credential_id",
            "public_key_spki_sha256",
            "trust_sha256",
            "request_sha256",
            "body_base64",
            "signature",
            "created_at_unix_ms",
        },
        "pending command",
    )
    if canonical_json(pending, newline=True) != pending_bytes:
        raise AdmissionError("pending command is not canonical")
    if (
        not version_one(pending["version"])
        or pending["method"] != "POST"
        or pending["target"] != COMMAND_PATH
        or pending["discovery_target"] != DISCOVERY_PATH
        or pending["state_target"] != STATE_PATH
    ):
        raise AdmissionError("pending command has an unsupported request binding")
    validate_origin(pending["origin"])
    trust_bytes = read_stable_file(trust_path, "cutover trust", MAX_TRUST_BYTES, private=False)
    trust, credential = validate_trust(decode_json(trust_bytes, "cutover trust"))
    if canonical_json(trust) != trust_bytes or sha256(trust_bytes) != pending["trust_sha256"]:
        raise AdmissionError("pending command trust binding changed")
    if credential["credential_id"] != pending["credential_id"]:
        raise AdmissionError("pending command credential changed")
    if sha256(decode_base64url(credential["public_key_spki"], "public_key_spki")) != pending[
        "public_key_spki_sha256"
    ]:
        raise AdmissionError("pending command public-key binding changed")
    body = decode_base64url(pending["body_base64"], "pending body")
    command = validate_command(decode_json(body, "pending command body"))
    if canonical_json(command) != body or sha256(body) != pending["request_sha256"]:
        raise AdmissionError("pending command body is not its exact canonical request")
    if (
        command_plain_binding(command)["deployment_id"] != trust["deployment_id"]
        or command_plain_binding(command)["release_id"] != trust["release_id"]
        or command_plain_binding(command)["source_commit_sha"] != trust["source_commit_sha"]
        or command["operator"]["aws_partition"] != credential["scope"]["aws_partition"]
        or command["operator"]["account_id"] != credential["scope"]["account_id"]
        or command["operator"]["role_arn"] != credential["scope"]["role_arn"]
    ):
        raise AdmissionError("pending command drifted from its trust scope")
    signature = decode_base64url(pending["signature"], "pending signature")
    if len(signature) != 64:
        raise AdmissionError("pending signature is not Ed25519")
    return pending, body, command


@dataclasses.dataclass(frozen=True)
class HttpResult:
    status: int
    headers: list[tuple[str, str]]
    body: bytes


def post_exact(origin: str, target: str, pending: dict[str, Any], body: bytes) -> HttpResult:
    parsed = urlsplit(origin)
    connection = http.client.HTTPSConnection(
        parsed.hostname,
        parsed.port or 443,
        timeout=30,
    )
    headers = {
        "Accept": CONTENT_TYPE,
        "Accept-Encoding": "identity",
        "Content-Type": CONTENT_TYPE,
        "Content-Length": str(len(body)),
        CREDENTIAL_HEADER: pending["credential_id"],
        SIGNATURE_HEADER: pending["signature"],
    }
    try:
        connection.request("POST", target, body=body, headers=headers)
        response = connection.getresponse()
        data = response.read(MAX_RESPONSE_BYTES + 1)
        if len(data) > MAX_RESPONSE_BYTES:
            raise AdmissionError("Control response exceeds its closed wire limit")
        return HttpResult(response.status, response.getheaders(), data)
    except (OSError, TimeoutError, http.client.HTTPException) as error:
        raise AdmissionError("Control response is ambiguous") from error
    finally:
        connection.close()


def validate_json_response(result: HttpResult) -> None:
    content_types = [value for name, value in result.headers if name.lower() == "content-type"]
    encodings = [value for name, value in result.headers if name.lower() == "content-encoding"]
    cache = [value for name, value in result.headers if name.lower() == "cache-control"]
    if content_types != [CONTENT_TYPE] or encodings or cache != ["no-store"]:
        raise AdmissionError("Control response headers violate the closed JSON contract")


def validate_receipt(
    result: HttpResult,
    command: dict[str, Any],
    body: bytes,
    pending: dict[str, Any],
) -> dict[str, Any]:
    validate_json_response(result)
    receipt = require_fields(
        decode_json(result.body, "admission receipt"),
        {"version", "command", "request_sha256", "principal", "outcome", "committed_at_unix_ms"},
        "admission receipt",
    )
    if canonical_json(receipt) != result.body:
        raise AdmissionError("admission receipt is not canonical Cats JSON")
    if not version_one(receipt["version"]) or receipt["command"] != command:
        raise AdmissionError("admission receipt does not bind the exact command")
    if receipt["request_sha256"] != sha256(body):
        raise AdmissionError("admission receipt request digest does not match")
    principal = require_fields(
        receipt["principal"],
        {"credential_id", "public_key_spki_sha256", "trust_bundle_sha256", "sts"},
        "admission receipt principal",
    )
    if (
        principal["credential_id"] != pending["credential_id"]
        or principal["public_key_spki_sha256"] != pending["public_key_spki_sha256"]
        or principal["trust_bundle_sha256"] != pending["trust_sha256"]
        or principal["sts"] != command["operator"]
    ):
        raise AdmissionError("admission receipt principal does not bind the signed STS claim")
    for field in ("public_key_spki_sha256", "trust_bundle_sha256"):
        require_string(principal[field], SHA256, f"principal.{field}")
    outcome = receipt["outcome"]
    if not isinstance(outcome, dict) or outcome.get("kind") not in {
        "applied",
        "authority_precondition_failed",
    }:
        raise AdmissionError("admission receipt has no terminal outcome")
    if outcome["kind"] == "applied":
        require_fields(outcome, {"kind", "state"}, "applied admission outcome")
        state = validate_state(outcome["state"])
        expected_mode = {
            "begin_qualification": "qualification",
            "end_qualification": "closed",
            "emergency_close": "closed",
        }[command["mutation"]["kind"]]
        if (
            state["mode"] != expected_mode
            or state["revision"] != command["expected_revision"] + 1
            or state["last_command_id"] != command["command_id"]
            or state["binding"] != command_state_binding(command)
            or state["updated_at_unix_ms"] != receipt["committed_at_unix_ms"]
        ):
            raise AdmissionError("applied admission receipt has a mismatched successor")
        if result.status != 200:
            raise AdmissionError("applied admission receipt did not use HTTP 200")
    else:
        require_fields(outcome, {"kind"}, "precondition-failed admission outcome")
        if result.status != 409:
            raise AdmissionError("precondition-failed receipt did not use HTTP 409")
    return receipt


def validate_state(value: Any) -> dict[str, Any]:
    state = require_fields(
        value,
        {"version", "revision", "mode", "binding", "last_command_id", "updated_at_unix_ms"},
        "admission state",
    )
    if (
        not version_one(state["version"])
        or not isinstance(state["revision"], int)
        or isinstance(state["revision"], bool)
        or state["revision"] <= 0
        or state["mode"] not in {"closed", "qualification"}
    ):
        raise AdmissionError("admission state scalar fields are invalid")
    if state["binding"] is None:
        if state["mode"] != "closed" or state["revision"] != 1 or state["last_command_id"] is not None:
            raise AdmissionError("unbound admission state is not initial Closed")
    else:
        state_binding = validate_state_binding(state["binding"])
        if state["mode"] == "qualification" and state_binding["kind"] != "qualification":
            raise AdmissionError("Qualification state does not carry a Qualification binding")
        require_string(state["last_command_id"], RANDOM_ID, "state.last_command_id")
    return state


class Cancellation:
    def __init__(self, parent: Any | None = None) -> None:
        self.requested = False
        self.parent = parent

    def handler(self, _signum: int, _frame: Any) -> None:
        self.requested = True
        if self.parent is not None:
            self.parent.requested = True


def settle(args: argparse.Namespace) -> tuple[Path, str]:
    pending, body, command = load_pending(args.pending, args.trust_file)
    command_id = command["command_id"]
    receipt_path = args.pending.parent / f"{command_id}.receipt.v1.json"
    if receipt_path.exists() or receipt_path.is_symlink():
        receipt_bytes = read_stable_file(
            receipt_path, "existing admission receipt", MAX_RESPONSE_BYTES, private=True
        )
        synthetic = HttpResult(200, [("Content-Type", CONTENT_TYPE), ("Cache-Control", "no-store")], receipt_bytes)
        receipt = decode_json(receipt_bytes, "existing admission receipt")
        status = 200 if receipt.get("outcome", {}).get("kind") == "applied" else 409
        synthetic = dataclasses.replace(synthetic, status=status)
        validate_receipt(synthetic, command, body, pending)
        return receipt_path, sha256(receipt_bytes)

    # A composing transaction may already own the process signal boundary.  It
    # must learn about a signal caught while this nested resolver temporarily
    # owns SIGINT/SIGTERM.  Once a command may have been sent, both layers keep
    # resolving the same immutable request; cancellation cannot turn an
    # ambiguous success into a different command.
    cancellation = Cancellation(getattr(args, "parent_cancellation", None))
    prior_handlers: dict[int, Any] = {}
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        prior_handlers[signal_number] = signal.signal(signal_number, cancellation.handler)
    sent = False
    may_have_been_sent = False
    deadline = time.monotonic() + args.resolution_timeout_seconds
    last_error: AdmissionError | None = None
    try:
        while time.monotonic() < deadline:
            if cancellation.requested and not may_have_been_sent:
                raise AdmissionError("cancelled before any admission command was sent")
            target = pending["discovery_target"] if sent else pending["target"]
            try:
                result = post_exact(pending["origin"], target, pending, body)
                sent = True
                may_have_been_sent = True
            except AdmissionError as error:
                sent = True
                may_have_been_sent = True
                last_error = error
                time.sleep(0.25)
                continue
            if result.status in {200, 409}:
                receipt = validate_receipt(result, command, body, pending)
                payload = canonical_json(receipt)
                write_atomic(receipt_path, payload)
                if receipt["outcome"]["kind"] != "applied":
                    raise AdmissionError("admission command reached terminal precondition failure")
                return receipt_path, sha256(payload)
            if target == pending["discovery_target"] and result.status == 404:
                validate_json_response(result)
                if int(time.time_ns() // 1_000_000) >= command["expires_at_unix_ms"]:
                    raise AdmissionError("command expired without a discoverable terminal receipt")
                sent = False
                time.sleep(0.25)
                continue
            raise AdmissionError(f"Control returned unexpected HTTP {result.status}")
        if last_error is not None:
            raise AdmissionError(
                "admission result remains ambiguous after bounded typed discovery"
            ) from last_error
        raise AdmissionError("admission result did not settle before the resolution deadline")
    finally:
        for signal_number, handler in prior_handlers.items():
            signal.signal(signal_number, handler)


def discover_state(args: argparse.Namespace) -> dict[str, Any]:
    pending, body, _command = load_pending(args.pending, args.trust_file)
    result = post_exact(pending["origin"], pending["state_target"], pending, body)
    if result.status != 200:
        raise AdmissionError(f"state discovery returned unexpected HTTP {result.status}")
    validate_json_response(result)
    state = validate_state(decode_json(result.body, "admission state"))
    if canonical_json(state) != result.body:
        raise AdmissionError("admission state is not canonical Cats JSON")
    return state


def read_canonical_evidence(
    path: Path,
    label: str,
    *,
    private: bool = False,
) -> tuple[dict[str, Any], bytes]:
    raw = read_stable_file(
        path,
        label,
        MAX_QUALIFICATION_EVIDENCE_BYTES,
        private=private,
    )
    value = decode_json(raw, label)
    if not isinstance(value, dict) or raw not in {
        canonical_json(value),
        canonical_json(value, newline=True),
    }:
        raise AdmissionError(f"{label} is not canonical Cats JSON")
    return value, raw


def qualification_command_id(binding: dict[str, Any], phase: str) -> str:
    frame = bytearray(b"cats.production-qualification-admission.v1\0")
    phase_bytes = phase.encode("ascii")
    binding_bytes = canonical_json(binding)
    frame.extend(struct.pack(">Q", len(phase_bytes)))
    frame.extend(phase_bytes)
    frame.extend(struct.pack(">Q", len(binding_bytes)))
    frame.extend(binding_bytes)
    return hashlib.sha256(frame).hexdigest()[:32]


def qualification_binding_sha256(binding: dict[str, Any]) -> str:
    return sha256(canonical_json({"kind": "qualification", "binding": binding}))


def qualification_pending_path(
    state_directory: Path,
    binding: dict[str, Any],
    phase: str,
) -> Path:
    return state_directory / f"{qualification_command_id(binding, phase)}.pending.v1.json"


def ensure_qualification_pending(
    args: argparse.Namespace,
    binding: dict[str, Any],
    *,
    phase: str,
    mutation: str,
    expected_revision: int,
) -> Path:
    command_id = qualification_command_id(binding, phase)
    path = args.state_directory / f"{command_id}.pending.v1.json"
    if path.exists() or path.is_symlink():
        _pending, _body, command = load_pending(path, args.trust_file)
        expected_wire_binding: Any = binding
        if mutation == "emergency_close":
            expected_wire_binding = {"kind": "qualification", "binding": binding}
        if (
            command["command_id"] != command_id
            or command["expected_revision"] != expected_revision
            or command["mutation"]
            != {"kind": mutation, "binding": expected_wire_binding}
        ):
            raise AdmissionError("durable Qualification pending command conflicts")
        return path
    namespace = argparse.Namespace(
        origin=args.origin,
        trust_file=args.trust_file,
        private_key_file=args.private_key_file,
        binding_file=args.binding_file,
        state_directory=args.state_directory,
        expected_revision=expected_revision,
        mutation=mutation,
        command_id=command_id,
        command_lifetime_seconds=args.command_lifetime_seconds,
        aws=args.aws,
        openssl=args.openssl,
    )
    created, _digest = prepare(namespace)
    if created != path:
        raise AdmissionError("Qualification pending path is not deterministic")
    return path


def settle_qualification_pending(
    pending: Path,
    args: argparse.Namespace,
) -> tuple[dict[str, Any], bytes, str]:
    receipt_path, receipt_sha256 = settle(
        argparse.Namespace(
            pending=pending,
            trust_file=args.trust_file,
            resolution_timeout_seconds=args.resolution_timeout_seconds,
        )
    )
    receipt, raw = read_canonical_evidence(
        receipt_path,
        "Qualification admission command receipt",
        private=True,
    )
    if sha256(raw) != receipt_sha256:
        raise AdmissionError("Qualification command receipt digest drifted")
    return receipt, raw, receipt_sha256


def load_existing_qualification_pending_receipt(
    pending_path: Path,
    args: argparse.Namespace,
    label: str,
) -> tuple[dict[str, Any], bytes, str]:
    pending, body, command = load_pending(pending_path, args.trust_file)
    receipt_path = pending_path.parent / f"{command['command_id']}.receipt.v1.json"
    if not receipt_path.exists() or receipt_path.is_symlink():
        raise AdmissionError(f"{label} durable applied receipt is unavailable")
    receipt_raw = read_stable_file(
        receipt_path,
        f"{label} durable applied receipt",
        MAX_RESPONSE_BYTES,
        private=True,
    )
    receipt = decode_json(receipt_raw, f"{label} durable applied receipt")
    status = 200 if receipt.get("outcome", {}).get("kind") == "applied" else 409
    validate_receipt(
        HttpResult(
            status,
            [("Content-Type", CONTENT_TYPE), ("Cache-Control", "no-store")],
            receipt_raw,
        ),
        command,
        body,
        pending,
    )
    if receipt["outcome"]["kind"] != "applied":
        raise AdmissionError(f"{label} did not reach Applied")
    return receipt, receipt_raw, sha256(receipt_raw)


def validate_qualification_authority_inputs(
    args: argparse.Namespace,
) -> dict[str, Any]:
    validate_private_directory(args.state_directory)
    validate_private_directory(args.evidence_directory)
    binding_value, binding_raw = read_canonical_evidence(
        args.binding_file,
        "Qualification admission binding",
    )
    binding = validate_qualification_binding(binding_value)
    if binding_raw != canonical_json(binding, newline=True):
        raise AdmissionError("Qualification binding must have one terminal LF")
    if (
        binding["qualification_id"] != args.run_id
        or binding["workspace_id"] != args.workspace_id
        or binding["source_commit_sha"] != args.exact_commit
    ):
        raise AdmissionError("Qualification runner identity differs from its binding")
    if args.block_path not in {"kernel-nbd", "vhost-user"}:
        raise AdmissionError("Qualification block path is not canonical")

    cell, cell_raw = read_canonical_evidence(
        args.cell_manifest_file,
        "Qualification cell manifest",
    )
    cell = require_fields(
        cell,
        {
            "kind",
            "version",
            "qualification_id",
            "deployment_id",
            "release_id",
            "source_commit_sha",
            "aws_partition",
            "aws_account_id",
            "aws_region",
            "cell_id",
            "cell_namespace",
            "cats_account_id",
            "workspace_id",
            "control_origin",
            "control_schema_version",
            "release_manifest_sha256",
            "worker_bundle_sha256",
            "qualification_catalog_sha256",
            "created_at_unix_ms",
        },
        "Qualification cell manifest",
    )
    if (
        cell["kind"] != "cats.production-qualification-cell-manifest.v1"
        or not version_one(cell["version"])
    ):
        raise AdmissionError("Qualification cell manifest kind/version drifted")
    for field in (
        "qualification_id",
        "deployment_id",
        "release_id",
        "source_commit_sha",
        "aws_partition",
        "aws_account_id",
        "aws_region",
        "cell_id",
        "cell_namespace",
        "cats_account_id",
        "workspace_id",
        "control_schema_version",
        "release_manifest_sha256",
        "worker_bundle_sha256",
        "qualification_catalog_sha256",
    ):
        if cell[field] != binding[field]:
            raise AdmissionError(
                "Qualification cell manifest differs from its admission binding"
            )
    if cell["control_origin"] != validate_origin(args.origin):
        raise AdmissionError("Qualification cell Control origin drifted")
    if (
        not isinstance(cell["created_at_unix_ms"], int)
        or isinstance(cell["created_at_unix_ms"], bool)
        or cell["created_at_unix_ms"] <= 0
        or binding["qualification_cell_manifest_sha256"] != sha256(cell_raw)
    ):
        raise AdmissionError("Qualification cell manifest identity is invalid")

    release, release_raw = read_canonical_evidence(
        args.release_manifest_file,
        "manual release manifest",
    )
    try:
        release_source = release["source"]
        worker = release["artifacts"]["worker"]
    except (KeyError, TypeError) as error:
        raise AdmissionError("manual release manifest shape is unavailable") from error
    if (
        not version_one(release.get("version"))
        or not isinstance(release_source, dict)
        or release_source.get("commit") != binding["source_commit_sha"]
        or not isinstance(worker, dict)
        or worker.get("bundle_sha256") != binding["worker_bundle_sha256"]
        or binding["release_manifest_sha256"] != sha256(release_raw)
    ):
        raise AdmissionError("manual release manifest differs from Qualification binding")
    _catalog, catalog_raw = read_canonical_evidence(
        args.qualification_catalog_file,
        "Qualification catalog",
    )
    if binding["qualification_catalog_sha256"] != sha256(catalog_raw):
        raise AdmissionError("Qualification catalog differs from its binding")
    return binding


def validate_applied_qualification_receipt(
    receipt: dict[str, Any],
    binding: dict[str, Any],
    mutation: str,
) -> dict[str, Any]:
    command = receipt["command"]
    expected_wire_binding: Any = binding
    if mutation == "emergency_close":
        expected_wire_binding = {"kind": "qualification", "binding": binding}
    if command["mutation"] != {"kind": mutation, "binding": expected_wire_binding}:
        raise AdmissionError("Qualification command receipt mutation drifted")
    outcome = receipt.get("outcome")
    if not isinstance(outcome, dict) or outcome.get("kind") != "applied":
        raise AdmissionError("Qualification command did not reach Applied")
    state = validate_state(outcome.get("state"))
    expected_mode = "qualification" if mutation == "begin_qualification" else "closed"
    if (
        state["mode"] != expected_mode
        or state["binding"] != {"kind": "qualification", "binding": binding}
    ):
        raise AdmissionError("Qualification command installed the wrong state")
    return state


def qualification_begin_framework(
    binding: dict[str, Any],
    receipt: dict[str, Any],
    receipt_sha256: str,
) -> dict[str, Any]:
    state = validate_applied_qualification_receipt(
        receipt,
        binding,
        "begin_qualification",
    )
    command = receipt["command"]
    return {
        "kind": QUALIFICATION_BEGIN_RECEIPT_KIND,
        "version": 1,
        "qualification_id": binding["qualification_id"],
        "workspace_id": binding["workspace_id"],
        "release_id": binding["release_id"],
        "source_commit_sha": binding["source_commit_sha"],
        "qualification_catalog_sha256": binding[
            "qualification_catalog_sha256"
        ],
        "allowed_mutation_classes": binding["allowed_mutation_classes"],
        "binding_sha256": qualification_binding_sha256(binding),
        "begin_command_id": command["command_id"],
        "begin_request_sha256": receipt["request_sha256"],
        "begin_command_receipt_sha256": receipt_sha256,
        "resulting_revision": state["revision"],
        "qualification_expires_at_unix_ms": binding[
            "qualification_expires_at_unix_ms"
        ],
    }


def qualification_begin(args: argparse.Namespace) -> tuple[Path, str]:
    binding = validate_qualification_authority_inputs(args)
    begin_pending = qualification_pending_path(
        args.state_directory,
        binding,
        "begin",
    )
    if not begin_pending.exists() and not begin_pending.is_symlink():
        if args.existing_pending_only:
            raise AdmissionError("Qualification Begin pending authority is unavailable")
        probe = ensure_qualification_pending(
            args,
            binding,
            phase="state-probe",
            mutation="begin_qualification",
            expected_revision=1,
        )
        current = discover_state(
            argparse.Namespace(pending=probe, trust_file=args.trust_file)
        )
        if current["mode"] != "closed":
            raise AdmissionError("Qualification Begin requires exact current Closed state")
        begin_pending = ensure_qualification_pending(
            args,
            binding,
            phase="begin",
            mutation="begin_qualification",
            expected_revision=current["revision"],
        )
    receipt, receipt_raw, receipt_sha256 = settle_qualification_pending(
        begin_pending,
        args,
    )
    begin_pending_raw = read_stable_file(
        begin_pending,
        "Qualification Begin pending command",
        MAX_RESPONSE_BYTES,
        private=True,
    )
    write_atomic(
        args.evidence_directory / QUALIFICATION_BEGIN_PENDING_FILE,
        begin_pending_raw,
    )
    write_atomic(
        args.evidence_directory / QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE,
        receipt_raw,
    )
    framework = qualification_begin_framework(binding, receipt, receipt_sha256)
    path = args.evidence_directory / QUALIFICATION_BEGIN_RECEIPT_FILE
    payload = canonical_json(framework)
    write_atomic(path, payload)
    return path, sha256(payload)


def validate_product_inventory(
    value: Any,
    binding: dict[str, Any],
    close_receipt: dict[str, Any],
    close_receipt_sha256: str,
    close_kind: str,
) -> dict[str, Any]:
    value = require_fields(
        value,
        {
            "kind",
            "version",
            "qualification_id",
            "workspace_id",
            "release_id",
            "source_commit_sha",
            "qualification_catalog_sha256",
            "binding_sha256",
            "close_kind",
            "close_command_id",
            "close_request_sha256",
            "close_command_receipt_sha256",
            "closed_revision",
            "evaluated_at_unix_ms",
            "complete",
            "counts",
            "product_resource_count",
        },
        "Qualification product inventory",
    )
    command = close_receipt["command"]
    state = validate_applied_qualification_receipt(
        close_receipt,
        binding,
        close_kind,
    )
    if (
        value["kind"] != QUALIFICATION_PRODUCT_INVENTORY_KIND
        or not version_one(value["version"])
        or value["qualification_id"] != binding["qualification_id"]
        or value["workspace_id"] != binding["workspace_id"]
        or value["release_id"] != binding["release_id"]
        or value["source_commit_sha"] != binding["source_commit_sha"]
        or value["qualification_catalog_sha256"]
        != binding["qualification_catalog_sha256"]
        or value["binding_sha256"] != qualification_binding_sha256(binding)
        or value["close_kind"] != close_kind
        or value["close_command_id"] != command["command_id"]
        or value["close_request_sha256"] != close_receipt["request_sha256"]
        or value["close_command_receipt_sha256"] != close_receipt_sha256
        or value["closed_revision"] != state["revision"]
        or value["complete"] is not True
    ):
        raise AdmissionError("Qualification product inventory binding drifted")
    evaluated = value["evaluated_at_unix_ms"]
    if (
        not isinstance(evaluated, int)
        or isinstance(evaluated, bool)
        or evaluated < close_receipt["committed_at_unix_ms"]
    ):
        raise AdmissionError("Qualification product inventory time is invalid")
    counts = require_fields(
        value["counts"],
        {
            "current_cat_count",
            "root_disk_count",
            "persistent_disk_count",
            "disk_snapshot_count",
            "endpoint_count",
            "hostname_desired_lookup_count",
            "pending_runtime_operation_count",
            "deleted_cat_tombstone_count",
            "terminal_runtime_operation_history_count",
            "api_idempotency_receipt_count",
        },
        "Qualification product inventory counts",
    )
    for name, count in counts.items():
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 0
            or count > 2**63 - 1
        ):
            raise AdmissionError(f"Qualification product inventory {name} is invalid")
    current_fields = (
        "current_cat_count",
        "root_disk_count",
        "persistent_disk_count",
        "disk_snapshot_count",
        "endpoint_count",
        "hostname_desired_lookup_count",
        "pending_runtime_operation_count",
    )
    product_resource_count = value["product_resource_count"]
    if (
        not isinstance(product_resource_count, int)
        or isinstance(product_resource_count, bool)
        or product_resource_count < 0
        or product_resource_count > 2**63 - 1
        or product_resource_count != sum(counts[name] for name in current_fields)
    ):
        raise AdmissionError("Qualification product inventory total drifted")
    return value


def validate_cleanup_inventory(
    value: Any,
    binding: dict[str, Any],
    block_path: str,
) -> dict[str, Any]:
    value = require_fields(
        value,
        {
            "kind",
            "version",
            "qualification_id",
            "workspace_id",
            "source_commit_sha",
            "block_path",
            "evaluated_at_unix_ms",
            "complete",
            "product_inventory_receipt_sha256",
            "product_resource_count",
            "desired_runtime_count",
            "current_runtime_observation_count",
            "active_guard_count",
            "residue_count",
        },
        "Qualification cleanup inventory",
    )
    if (
        value["kind"] != QUALIFICATION_CLEANUP_INVENTORY_KIND
        or not version_one(value["version"])
        or value["qualification_id"] != binding["qualification_id"]
        or value["workspace_id"] != binding["workspace_id"]
        or value["source_commit_sha"] != binding["source_commit_sha"]
        or value["block_path"] != block_path
        or value["complete"] is not True
    ):
        raise AdmissionError("Qualification cleanup inventory binding drifted")
    if (
        not isinstance(value["evaluated_at_unix_ms"], int)
        or isinstance(value["evaluated_at_unix_ms"], bool)
        or value["evaluated_at_unix_ms"] <= 0
    ):
        raise AdmissionError("Qualification cleanup inventory time is invalid")
    require_string(
        value["product_inventory_receipt_sha256"],
        SHA256,
        "Qualification cleanup product inventory digest",
    )
    for field in (
        "product_resource_count",
        "desired_runtime_count",
        "current_runtime_observation_count",
        "active_guard_count",
        "residue_count",
    ):
        if value[field] != 0 or isinstance(value[field], bool):
            raise AdmissionError("Qualification cleanup inventory is not zero")
    return value


def validate_qualification_final_fleet(
    value: Any,
    binding: dict[str, Any],
    block_path: str,
) -> dict[str, Any]:
    value = require_fields(
        value,
        {
            "kind",
            "version",
            "qualification_id",
            "workspace_id",
            "source_commit_sha",
            "block_path",
            "evaluated_at_unix_ms",
            "complete",
            "expected_node_ids",
            "desired_runtime_count",
            "current_runtime_observation_count",
            "active_guard_count",
            "residue_count",
            "fleet_verification_receipt_sha256",
        },
        "Qualification final Fleet Closed receipt",
    )
    if (
        value["kind"] != QUALIFICATION_FINAL_FLEET_KIND
        or not version_one(value["version"])
        or value["qualification_id"] != binding["qualification_id"]
        or value["workspace_id"] != binding["workspace_id"]
        or value["source_commit_sha"] != binding["source_commit_sha"]
        or value["block_path"] != block_path
        or value["complete"] is not True
    ):
        raise AdmissionError("Qualification final Fleet binding drifted")
    expected_nodes = value["expected_node_ids"]
    if (
        not isinstance(expected_nodes, list)
        or not expected_nodes
        or expected_nodes != sorted(set(expected_nodes))
    ):
        raise AdmissionError("Qualification final Fleet Node set is not closed")
    for node_id in expected_nodes:
        require_string(node_id, ID, "Qualification final Fleet Node ID")
    if (
        not isinstance(value["evaluated_at_unix_ms"], int)
        or isinstance(value["evaluated_at_unix_ms"], bool)
        or value["evaluated_at_unix_ms"] <= 0
    ):
        raise AdmissionError("Qualification final Fleet time is invalid")
    require_string(
        value["fleet_verification_receipt_sha256"],
        SHA256,
        "Qualification final Fleet authority digest",
    )
    for field in (
        "desired_runtime_count",
        "current_runtime_observation_count",
        "active_guard_count",
        "residue_count",
    ):
        if value[field] != 0 or isinstance(value[field], bool):
            raise AdmissionError("Qualification final Fleet is not Closed and empty")
    return value


def load_qualification_begin_for_close(
    args: argparse.Namespace,
    binding: dict[str, Any],
    *,
    existing_receipt_only: bool = False,
) -> dict[str, Any]:
    begin_pending = qualification_pending_path(
        args.state_directory,
        binding,
        "begin",
    )
    if not begin_pending.exists() or begin_pending.is_symlink():
        raise AdmissionError("Qualification Begin pending authority is unavailable")
    if existing_receipt_only:
        begin_command_receipt, _receipt_raw, begin_command_receipt_sha256 = (
            load_existing_qualification_pending_receipt(
                begin_pending,
                args,
                "Qualification Begin",
            )
        )
    else:
        begin_command_receipt, _receipt_raw, begin_command_receipt_sha256 = (
            settle_qualification_pending(begin_pending, args)
        )
    expected_begin = qualification_begin_framework(
        binding,
        begin_command_receipt,
        begin_command_receipt_sha256,
    )
    begin_path = args.evidence_directory / QUALIFICATION_BEGIN_RECEIPT_FILE
    begin, begin_raw = read_canonical_evidence(
        begin_path,
        "Qualification Begin framework receipt",
        private=True,
    )
    if begin != expected_begin or begin_raw != canonical_json(expected_begin):
        raise AdmissionError("Qualification Begin framework receipt drifted")
    return begin


def apply_qualification_close(
    args: argparse.Namespace,
    binding: dict[str, Any],
    begin: dict[str, Any],
    *,
    allow_prepare: bool,
) -> tuple[dict[str, Any], dict[str, Any], str, Path]:
    mutation = (
        "end_qualification"
        if args.close_kind == "end_qualification"
        else "emergency_close"
    )
    close_pending = qualification_pending_path(
        args.state_directory,
        binding,
        args.close_kind,
    )
    if not close_pending.exists() and not close_pending.is_symlink():
        if not allow_prepare:
            raise AdmissionError("Qualification close pending authority is unavailable")
        begin_pending = qualification_pending_path(
            args.state_directory,
            binding,
            "begin",
        )
        current = discover_state(
            argparse.Namespace(pending=begin_pending, trust_file=args.trust_file)
        )
        if (
            current["mode"] != "qualification"
            or current["binding"] != {"kind": "qualification", "binding": binding}
        ):
            raise AdmissionError("Qualification close requires its exact installed binding")
        close_pending = ensure_qualification_pending(
            args,
            binding,
            phase=args.close_kind,
            mutation=mutation,
            expected_revision=current["revision"],
        )
    receipt, receipt_raw, receipt_sha256 = settle_qualification_pending(
        close_pending,
        args,
    )
    close_pending_raw = read_stable_file(
        close_pending,
        "Qualification close pending command",
        MAX_RESPONSE_BYTES,
        private=True,
    )
    state = validate_applied_qualification_receipt(receipt, binding, mutation)
    if state["revision"] != begin["resulting_revision"] + 1:
        raise AdmissionError("Qualification close is not the exact Begin successor")
    state_payload = canonical_json(state)
    state_path = args.state_directory / QUALIFICATION_FINAL_STATE_FILE
    write_atomic(state_path, state_payload)
    write_atomic(
        args.evidence_directory / QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE,
        receipt_raw,
    )
    write_atomic(
        args.evidence_directory / QUALIFICATION_CLOSE_PENDING_FILE,
        close_pending_raw,
    )
    write_atomic(
        args.evidence_directory / QUALIFICATION_FINAL_STATE_FILE,
        state_payload,
    )
    return receipt, state, receipt_sha256, state_path


def qualification_close(args: argparse.Namespace) -> tuple[Path, str]:
    binding = validate_qualification_authority_inputs(args)
    begin = load_qualification_begin_for_close(args, binding)
    _receipt, _state, _receipt_sha256, state_path = apply_qualification_close(
        args,
        binding,
        begin,
        allow_prepare=True,
    )
    state_raw = read_stable_file(
        state_path,
        "Qualification final admission state",
        MAX_RESPONSE_BYTES,
        private=True,
    )
    return state_path, sha256(state_raw)


def qualification_product_inventory(args: argparse.Namespace) -> tuple[Path, str]:
    binding = validate_qualification_authority_inputs(args)
    load_qualification_begin_for_close(
        args,
        binding,
        existing_receipt_only=True,
    )
    close_pending = qualification_pending_path(
        args.state_directory,
        binding,
        args.close_kind,
    )
    if not close_pending.exists() or close_pending.is_symlink():
        raise AdmissionError("Qualification close pending authority is unavailable")
    close_receipt, _close_raw, close_receipt_sha256 = (
        load_existing_qualification_pending_receipt(
            close_pending,
            args,
            "Qualification close",
        )
    )
    validate_applied_qualification_receipt(
        close_receipt,
        binding,
        args.close_kind,
    )
    pending, body, _command = load_pending(close_pending, args.trust_file)
    path = args.evidence_directory / QUALIFICATION_PRODUCT_INVENTORY_FILE
    if path.exists() or path.is_symlink():
        value, raw = read_canonical_evidence(
            path,
            "Qualification product inventory receipt",
            private=True,
        )
        value = validate_product_inventory(
            value,
            binding,
            close_receipt,
            close_receipt_sha256,
            args.close_kind,
        )
        if value["product_resource_count"] != 0:
            raise AdmissionError("durable Qualification product inventory is not zero")
        return path, sha256(raw)

    cancellation = Cancellation()
    prior_handlers: dict[int, Any] = {}
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        prior_handlers[signal_number] = signal.signal(
            signal_number,
            cancellation.handler,
        )
    deadline = time.monotonic() + args.resolution_timeout_seconds
    last_error: AdmissionError | None = None
    try:
        while time.monotonic() < deadline:
            if cancellation.requested:
                raise AdmissionError("Qualification product inventory was cancelled")
            try:
                result = post_exact(
                    pending["origin"],
                    PRODUCT_INVENTORY_PATH,
                    pending,
                    body,
                )
            except AdmissionError as error:
                last_error = error
                time.sleep(0.25)
                continue
            if cancellation.requested:
                raise AdmissionError("Qualification product inventory was cancelled")
            if result.status != 200:
                if result.status in {404, 409}:
                    validate_json_response(result)
                raise AdmissionError(
                    f"product inventory discovery returned unexpected HTTP {result.status}"
                )
            validate_json_response(result)
            value = decode_json(result.body, "Qualification product inventory receipt")
            if canonical_json(value) != result.body:
                raise AdmissionError(
                    "Qualification product inventory receipt is not canonical Cats JSON"
                )
            value = validate_product_inventory(
                value,
                binding,
                close_receipt,
                close_receipt_sha256,
                args.close_kind,
            )
            if value["product_resource_count"] != 0:
                raise AdmissionError("Qualification current product inventory is not zero")
            write_atomic(path, result.body)
            return path, sha256(result.body)
        if last_error is not None:
            raise AdmissionError(
                "product inventory remains unavailable after bounded read-only replay"
            ) from last_error
        raise AdmissionError("product inventory did not complete before its deadline")
    finally:
        for signal_number, handler in prior_handlers.items():
            signal.signal(signal_number, handler)


def qualification_terminalize(args: argparse.Namespace) -> tuple[Path, str]:
    binding = validate_qualification_authority_inputs(args)
    if (
        args.fleet_closed_receipt.parent != args.evidence_directory
        or args.product_inventory_receipt.parent != args.evidence_directory
        or args.cleanup_inventory_receipt.parent != args.evidence_directory
        or args.fleet_closed_receipt.name != QUALIFICATION_FINAL_FLEET_FILE
        or args.product_inventory_receipt.name
        != QUALIFICATION_PRODUCT_INVENTORY_FILE
        or args.cleanup_inventory_receipt.name
        != QUALIFICATION_CLEANUP_INVENTORY_FILE
    ):
        raise AdmissionError("Qualification terminal support evidence names drifted")
    begin = load_qualification_begin_for_close(args, binding)
    receipt, state, receipt_sha256, _state_path = apply_qualification_close(
        args,
        binding,
        begin,
        allow_prepare=False,
    )
    state_payload = canonical_json(state)

    fleet, fleet_raw = read_canonical_evidence(
        args.fleet_closed_receipt,
        "Qualification final Fleet Closed receipt",
        private=True,
    )
    product_inventory, product_inventory_raw = read_canonical_evidence(
        args.product_inventory_receipt,
        "Qualification product inventory receipt",
        private=True,
    )
    cleanup, cleanup_raw = read_canonical_evidence(
        args.cleanup_inventory_receipt,
        "Qualification cleanup inventory receipt",
        private=True,
    )
    fleet = validate_qualification_final_fleet(fleet, binding, args.block_path)
    product_inventory = validate_product_inventory(
        product_inventory,
        binding,
        receipt,
        receipt_sha256,
        args.close_kind,
    )
    cleanup = validate_cleanup_inventory(cleanup, binding, args.block_path)
    if (
        product_inventory["product_resource_count"] != 0
        or cleanup["product_inventory_receipt_sha256"]
        != sha256(product_inventory_raw)
        or cleanup["product_resource_count"]
        != product_inventory["product_resource_count"]
        or cleanup["evaluated_at_unix_ms"]
        < product_inventory["evaluated_at_unix_ms"]
        or fleet["evaluated_at_unix_ms"]
        < product_inventory["evaluated_at_unix_ms"]
    ):
        raise AdmissionError(
            "Qualification terminal evidence does not follow the product inventory oracle"
        )
    completed = max(
        cleanup["evaluated_at_unix_ms"],
        fleet["evaluated_at_unix_ms"],
    )
    framework = {
        "kind": QUALIFICATION_TERMINAL_RECEIPT_KIND,
        "version": 1,
        "qualification_id": begin["qualification_id"],
        "workspace_id": begin["workspace_id"],
        "release_id": begin["release_id"],
        "source_commit_sha": begin["source_commit_sha"],
        "qualification_catalog_sha256": begin[
            "qualification_catalog_sha256"
        ],
        "allowed_mutation_classes": begin["allowed_mutation_classes"],
        "qualification_expires_at_unix_ms": begin[
            "qualification_expires_at_unix_ms"
        ],
        "binding_sha256": begin["binding_sha256"],
        "begin_command_id": begin["begin_command_id"],
        "begin_request_sha256": begin["begin_request_sha256"],
        "begin_command_receipt_sha256": begin[
            "begin_command_receipt_sha256"
        ],
        "begin_resulting_revision": begin["resulting_revision"],
        "close_kind": args.close_kind,
        "terminal_outcome": (
            "qualified_closed"
            if args.close_kind == "end_qualification"
            else "emergency_closed"
        ),
        "close_command_id": receipt["command"]["command_id"],
        "close_request_sha256": receipt["request_sha256"],
        "close_command_receipt_sha256": receipt_sha256,
        "final_admission_state_sha256": sha256(state_payload),
        "final_closed_revision": state["revision"],
        "fleet_closed_receipt_sha256": sha256(fleet_raw),
        "product_inventory_receipt_sha256": sha256(product_inventory_raw),
        "cleanup_inventory_receipt_sha256": sha256(cleanup_raw),
        "active_guard_count": cleanup["active_guard_count"],
        "product_resource_count": cleanup["product_resource_count"],
        "residue_count": cleanup["residue_count"],
        "completed_at_unix_ms": completed,
    }
    path = args.evidence_directory / QUALIFICATION_TERMINAL_RECEIPT_FILE
    payload = canonical_json(framework)
    write_atomic(path, payload)
    return path, sha256(payload)


def add_qualification_hook_arguments(
    parser: argparse.ArgumentParser,
    *,
    signing: bool,
) -> None:
    parser.add_argument("--origin", required=True)
    parser.add_argument("--trust-file", required=True, type=Path)
    if signing:
        parser.add_argument("--private-key-file", required=True, type=Path)
    parser.add_argument("--binding-file", required=True, type=Path)
    parser.add_argument("--cell-manifest-file", required=True, type=Path)
    parser.add_argument("--release-manifest-file", required=True, type=Path)
    parser.add_argument("--qualification-catalog-file", required=True, type=Path)
    parser.add_argument("--state-directory", required=True, type=Path)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--exact-commit", required=True)
    parser.add_argument(
        "--block-path",
        required=True,
        choices=("kernel-nbd", "vhost-user"),
    )
    if signing:
        parser.add_argument(
            "--command-lifetime-seconds",
            type=int,
            default=DEFAULT_COMMAND_LIFETIME_MS // 1_000,
        )
    parser.add_argument(
        "--resolution-timeout-seconds",
        type=int,
        default=DEFAULT_RESOLUTION_SECONDS,
    )
    if signing:
        parser.add_argument("--aws", type=Path, default=Path("/usr/local/bin/aws"))
        parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    commands = result.add_subparsers(dest="command", required=True)
    prepare_parser = commands.add_parser("prepare", help="discover STS, sign and journal a command")
    prepare_parser.add_argument("--origin", required=True)
    prepare_parser.add_argument("--trust-file", required=True, type=Path)
    prepare_parser.add_argument("--private-key-file", required=True, type=Path)
    prepare_parser.add_argument("--binding-file", required=True, type=Path)
    prepare_parser.add_argument("--state-directory", required=True, type=Path)
    prepare_parser.add_argument("--expected-revision", required=True, type=int)
    prepare_parser.add_argument(
        "--mutation",
        choices=(
            "begin_qualification",
            "end_qualification",
            "emergency_close",
        ),
        required=True,
    )
    prepare_parser.add_argument("--command-id")
    prepare_parser.add_argument(
        "--command-lifetime-seconds",
        type=int,
        default=DEFAULT_COMMAND_LIFETIME_MS // 1_000,
    )
    prepare_parser.add_argument("--aws", type=Path, default=Path("/usr/local/bin/aws"))
    prepare_parser.add_argument("--openssl", type=Path, default=Path("/usr/bin/openssl"))

    apply_parser = commands.add_parser("apply", help="submit/replay/discover one pending command")
    apply_parser.add_argument("--pending", required=True, type=Path)
    apply_parser.add_argument("--trust-file", required=True, type=Path)
    apply_parser.add_argument(
        "--resolution-timeout-seconds", type=int, default=DEFAULT_RESOLUTION_SECONDS
    )

    state_parser = commands.add_parser("state", help="typed read-only discovery using a pending command")
    state_parser.add_argument("--pending", required=True, type=Path)
    state_parser.add_argument("--trust-file", required=True, type=Path)
    qualification_begin_parser = commands.add_parser(
        "qualification-begin",
        help="discover Closed, apply exact BeginQualification and publish its framework receipt",
    )
    add_qualification_hook_arguments(qualification_begin_parser, signing=True)
    qualification_begin_parser.add_argument(
        "--existing-pending-only",
        action="store_true",
        help="resolve only the deterministic durable Begin pending; never prepare a command",
    )
    qualification_close_parser = commands.add_parser(
        "qualification-close",
        help="apply exact EndQualification/EmergencyClose and publish its final state",
    )
    add_qualification_hook_arguments(qualification_close_parser, signing=True)
    qualification_close_parser.add_argument(
        "--close-kind",
        required=True,
        choices=("end_qualification", "emergency_close"),
    )
    qualification_inventory_parser = commands.add_parser(
        "qualification-product-inventory",
        help="publish the canonical post-close Control product inventory",
    )
    add_qualification_hook_arguments(qualification_inventory_parser, signing=False)
    qualification_inventory_parser.add_argument(
        "--close-kind",
        required=True,
        choices=("end_qualification", "emergency_close"),
    )
    qualification_terminal_parser = commands.add_parser(
        "qualification-terminalize",
        help="bind post-close Fleet/cleanup evidence into the terminal framework receipt",
    )
    add_qualification_hook_arguments(qualification_terminal_parser, signing=False)
    qualification_terminal_parser.add_argument(
        "--close-kind",
        required=True,
        choices=("end_qualification", "emergency_close"),
    )
    qualification_terminal_parser.add_argument(
        "--fleet-closed-receipt",
        required=True,
        type=Path,
    )
    qualification_terminal_parser.add_argument(
        "--product-inventory-receipt",
        required=True,
        type=Path,
    )
    qualification_terminal_parser.add_argument(
        "--cleanup-inventory-receipt",
        required=True,
        type=Path,
    )
    return result


def main(argv: Sequence[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        if args.command == "prepare":
            path, digest = prepare(args)
            value: Any = {"pending": str(path), "sha256": digest}
        elif args.command == "apply":
            if args.resolution_timeout_seconds <= 0 or args.resolution_timeout_seconds > 3600:
                raise AdmissionError("resolution timeout must be from 1 through 3600 seconds")
            path, digest = settle(args)
            value = {"receipt": str(path), "sha256": digest}
        elif args.command == "state":
            value = discover_state(args)
        elif args.command == "qualification-begin":
            if args.resolution_timeout_seconds <= 0 or args.resolution_timeout_seconds > 3600:
                raise AdmissionError("resolution timeout must be from 1 through 3600 seconds")
            path, digest = qualification_begin(args)
            value = {"receipt": str(path), "sha256": digest}
        elif args.command == "qualification-close":
            if args.resolution_timeout_seconds <= 0 or args.resolution_timeout_seconds > 3600:
                raise AdmissionError("resolution timeout must be from 1 through 3600 seconds")
            path, digest = qualification_close(args)
            value = {"receipt": str(path), "sha256": digest}
        elif args.command == "qualification-product-inventory":
            if args.resolution_timeout_seconds <= 0 or args.resolution_timeout_seconds > 3600:
                raise AdmissionError("resolution timeout must be from 1 through 3600 seconds")
            path, digest = qualification_product_inventory(args)
            value = {"receipt": str(path), "sha256": digest}
        else:
            if args.resolution_timeout_seconds <= 0 or args.resolution_timeout_seconds > 3600:
                raise AdmissionError("resolution timeout must be from 1 through 3600 seconds")
            path, digest = qualification_terminalize(args)
            value = {"receipt": str(path), "sha256": digest}
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except AdmissionError as error:
        print(f"production mutation admission refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
