#!/usr/bin/env python3
"""Dedicated E13 ProductionCutoverOperator command client.

This client has no WorkOS, A23, G3, administrator-token or Workspace-token
fallback.  ``prepare`` performs a real AWS STS caller-identity lookup, binds
that exact assumed-role principal into a short-lived canonical command, signs
the command with the dedicated offline Ed25519 key and durably publishes a
pending record before any HTTP request can be made.  ``apply`` reuses those
exact bytes for submission, replay and typed discovery.

Control authenticates the offline signature and verifies that the signed STS
claim is inside the release-bound trust scope.  It does not contact STS; the
online lookup and its signed binding are operator-tool evidence, not a second
Control-side authentication factor.
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
DEFAULT_COMMAND_LIFETIME_MS = 4 * 60 * 1_000
DEFAULT_RESOLUTION_SECONDS = 120
ED25519_SPKI_PREFIX = bytes.fromhex("302a300506032b6570032100")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
RANDOM_ID = re.compile(r"^[0-9a-f]{32}$")
ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
ACCOUNT_ID = re.compile(r"^[0-9]{12}$")
BASE64URL = re.compile(r"^[A-Za-z0-9_-]+$")

BINDING_FIELDS = {
    "reset_id",
    "deployment_id",
    "release_id",
    "source_commit_sha",
    "control_schema_version",
    "source_manifest_sha256",
    "source_bundle_sha256",
    "release_manifest_sha256",
    "qualification_manifest_sha256",
    "qualification_catalog_sha256",
    "proof_set_sha256",
    "fresh_targets_sha256",
    "reset_complete_receipt_sha256",
    "fleet_closed_receipt_sha256",
    "route_v2_rotation_qualification_receipt_sha256",
    "route_v2_rotation_qualification_node_ack_sets_sha256",
    "route_v2_rotation_qualification_transcript_sha256",
    "usage_terminal_receipt_sha256",
    "old_host_coverage_sha256",
    "kernel_nbd_qualification_bundle_sha256",
    "vhost_user_qualification_bundle_sha256",
}


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


def validate_binding(value: Any) -> dict[str, Any]:
    binding = require_fields(value, BINDING_FIELDS, "admission binding")
    for field in ("reset_id", "deployment_id", "release_id"):
        require_string(binding[field], ID, f"binding.{field}")
    require_string(binding["source_commit_sha"], COMMIT, "binding.source_commit_sha")
    if binding["control_schema_version"] != 16:
        raise AdmissionError("binding.control_schema_version must be 16")
    for field in BINDING_FIELDS - {
        "reset_id",
        "deployment_id",
        "release_id",
        "source_commit_sha",
        "control_schema_version",
    }:
        require_string(binding[field], SHA256, f"binding.{field}")
    return binding


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
    if trust["version"] != 1 or trust["signature_threshold"] != 1:
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
    if command["version"] != 1:
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
    if mutation["kind"] not in {"open", "emergency_close"}:
        raise AdmissionError("unsupported admission mutation")
    validate_binding(mutation["binding"])
    return command


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
    binding = validate_binding(decode_json(binding_bytes, "admission binding"))
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
    command = {
        "version": 1,
        "command_id": command_id,
        "issued_at_unix_ms": issued,
        "expires_at_unix_ms": issued + lifetime,
        "operator": operator,
        "expected_revision": args.expected_revision,
        "mutation": {"kind": args.mutation, "binding": binding},
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
        pending["version"] != 1
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
        command["mutation"]["binding"]["deployment_id"] != trust["deployment_id"]
        or command["mutation"]["binding"]["release_id"] != trust["release_id"]
        or command["mutation"]["binding"]["source_commit_sha"] != trust["source_commit_sha"]
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
    if receipt["version"] != 1 or receipt["command"] != command:
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
        expected_mode = "open" if command["mutation"]["kind"] == "open" else "closed"
        if (
            state["mode"] != expected_mode
            or state["revision"] != command["expected_revision"] + 1
            or state["last_command_id"] != command["command_id"]
            or state["binding"] != command["mutation"]["binding"]
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
        state["version"] != 1
        or not isinstance(state["revision"], int)
        or isinstance(state["revision"], bool)
        or state["revision"] <= 0
        or state["mode"] not in {"closed", "open"}
    ):
        raise AdmissionError("admission state scalar fields are invalid")
    if state["binding"] is None:
        if state["mode"] != "closed" or state["revision"] != 1 or state["last_command_id"] is not None:
            raise AdmissionError("unbound admission state is not initial Closed")
    else:
        validate_binding(state["binding"])
        require_string(state["last_command_id"], RANDOM_ID, "state.last_command_id")
    return state


class Cancellation:
    def __init__(self) -> None:
        self.requested = False

    def handler(self, _signum: int, _frame: Any) -> None:
        self.requested = True


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

    cancellation = Cancellation()
    prior_handlers: dict[int, Any] = {}
    for signal_number in (signal.SIGINT, signal.SIGTERM):
        prior_handlers[signal_number] = signal.signal(signal_number, cancellation.handler)
    sent = False
    deadline = time.monotonic() + args.resolution_timeout_seconds
    last_error: AdmissionError | None = None
    try:
        while time.monotonic() < deadline:
            if cancellation.requested and not sent:
                raise AdmissionError("cancelled before any admission command was sent")
            target = pending["discovery_target"] if sent else pending["target"]
            try:
                result = post_exact(pending["origin"], target, pending, body)
                sent = True
            except AdmissionError as error:
                sent = True
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
    prepare_parser.add_argument("--mutation", choices=("open", "emergency_close"), required=True)
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
        else:
            value = discover_state(args)
        print(json.dumps(value, sort_keys=True, separators=(",", ":")))
        return 0
    except AdmissionError as error:
        print(f"production mutation admission refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
