"""Closed E13 proof-set consumer shared by reset and final Open.

This module is deliberately not a producer-specific second authority.  It
closes file identity, release/target binding, Qualification admission,
Fleet-Closed and the accepted V5 runner bundles.  G3, E9 and V3 are consumed
only through typed verifier adapters.  An unavailable adapter has no flag or
environment escape hatch: verification fails closed until the corresponding
reviewed implementation is wired in source.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path
from typing import Any, Protocol


PROOF_SET_FILE = "production-cutover-proof-set.v1.json"
PROOF_SET_KIND = "cats.production-cutover-proof-set.v1"
USAGE_TERMINAL_VERIFIER = Path(
    "/opt/cats/bin/cats-usage-terminal-receipt-verifier"
)
USAGE_TERMINAL_REQUEST_FILE = "usage-target-terminal-request.json"
USAGE_TERMINAL_RECEIPT_FILE = "usage-target-terminal-receipt.json"
USAGE_TERMINAL_VERIFICATION_FILE = (
    "usage-target-terminal-verification.receipt.json"
)
USAGE_TERMINAL_VERIFICATION_KIND = (
    "cats.usage-terminal-receipt-verification.v1"
)
USAGE_TERMINAL_SUCCESS_STDOUT = "Usage terminal receipt verified\n"
QUALIFICATION_BEGIN_KIND = "cats.production-mutation-qualification-begin-receipt.v1"
QUALIFICATION_TERMINAL_KIND = (
    "cats.production-mutation-qualification-terminal-receipt.v1"
)
MAX_PROOF_SET_BYTES = 2 * 1024 * 1024
MAX_PROOF_FILE_BYTES = 16 * 1024 * 1024
FLEET_MAX_AGE_MS = 60_000
PROOF_SET_MAX_AGE_SECONDS = 15 * 60

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
RANDOM_ID = re.compile(r"^[0-9a-f]{32}$")
PROOF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AWS_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)

TARGET_FIELDS = {
    "control_schema",
    "usage_schema",
    "chunkstore_bucket",
    "chunkstore_object_prefix",
    "usage_kinesis_stream",
    "usage_checkpoint_table",
    "usage_archive_bucket",
}
PROOF_SET_FIELDS = {
    "kind",
    "version",
    "cutover_id",
    "reset_id",
    "observed_at",
    "operator",
    "release",
    "old",
    "fresh",
    "proofs",
}


class ProofSetError(RuntimeError):
    """Safe refusal without secret-bearing values."""


class _DuplicateKey(ValueError):
    pass


def _pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKey(key)
        result[key] = value
    return result


def canonical_json(value: Any, *, newline: bool = False) -> bytes:
    suffix = "\n" if newline else ""
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + suffix
    ).encode("ascii")


def decode_json(data: bytes, label: str, *, canonical_lf: bool = False) -> Any:
    try:
        text = data.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=_pairs)
        value, end = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateKey) as error:
        raise ProofSetError(f"{label} is not one duplicate-free JSON value") from error
    if text[end:] not in {"", "\n"}:
        raise ProofSetError(f"{label} has trailing bytes")
    if canonical_lf and canonical_json(value, newline=True) != data:
        raise ProofSetError(f"{label} is not canonical JSON with one terminal LF")
    return value


def fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise ProofSetError(f"{label} does not have its exact closed field set")
    return value


def identifier(value: Any, label: str) -> str:
    if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
        raise ProofSetError(f"{label} is not a bounded identifier")
    return value


def digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise ProofSetError(f"{label} is not a canonical SHA-256 digest")
    return value


def commit(value: Any, label: str) -> str:
    if not isinstance(value, str) or COMMIT.fullmatch(value) is None:
        raise ProofSetError(f"{label} is not a lowercase source commit")
    return value


def integer(value: Any, label: str, *, minimum: int = 0) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < minimum:
        raise ProofSetError(f"{label} is not an integer in its closed range")
    return value


def parse_time(value: Any, label: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ProofSetError(f"{label} is not an RFC3339 UTC-seconds timestamp")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ProofSetError(f"{label} is not an RFC3339 timestamp") from error
    if parsed.utcoffset() != dt.timedelta(0) or parsed.microsecond != 0:
        raise ProofSetError(f"{label} is not an exact UTC-seconds timestamp")
    return parsed


@dataclasses.dataclass(frozen=True)
class _FileIdentity:
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
    def from_stat(cls, value: os.stat_result) -> "_FileIdentity":
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


@dataclasses.dataclass(frozen=True)
class ProofReference:
    file: str
    sha256: str
    size_bytes: int

    @classmethod
    def parse(cls, value: Any, label: str) -> "ProofReference":
        value = fields(value, {"file", "sha256", "size_bytes"}, label)
        name = value["file"]
        if not isinstance(name, str) or PROOF_NAME.fullmatch(name) is None:
            raise ProofSetError(f"{label}.file is not a direct-child proof name")
        size = integer(value["size_bytes"], f"{label}.size_bytes", minimum=1)
        if size > MAX_PROOF_FILE_BYTES:
            raise ProofSetError(f"{label} exceeds the proof byte limit")
        return cls(name, digest(value["sha256"], f"{label}.sha256"), size)


@dataclasses.dataclass(frozen=True)
class VerifiedFile:
    name: str
    data: bytes
    sha256: str
    size_bytes: int


class ProofDirectory:
    """Descriptor-relative, stable, no-symlink proof reader."""

    def __init__(self, path: Path) -> None:
        if not path.is_absolute():
            raise ProofSetError("proof directory path must be absolute")
        try:
            if path.resolve(strict=True) != path:
                raise ProofSetError("proof directory path or ancestor is a symlink")
            metadata = path.stat(follow_symlinks=False)
        except OSError as error:
            raise ProofSetError("proof directory is unavailable") from error
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or path.is_symlink()
            or metadata.st_uid != os.geteuid()
            or metadata.st_mode & 0o077
        ):
            raise ProofSetError(
                "proof directory must be actor-owned mode 0700 and nonsymlink"
            )
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_DIRECTORY", 0
        )
        try:
            self._descriptor = os.open(path, flags)
        except OSError as error:
            raise ProofSetError("proof directory cannot be opened") from error

    def __enter__(self) -> "ProofDirectory":
        return self

    def __exit__(self, *_args: Any) -> None:
        os.close(self._descriptor)

    def read_reference(self, reference: ProofReference, label: str) -> VerifiedFile:
        result = self._read(reference.file, label, reference.size_bytes)
        if (
            result.sha256 != reference.sha256
            or result.size_bytes != reference.size_bytes
        ):
            raise ProofSetError(
                f"{label} digest/size does not match its proof reference"
            )
        return result

    def read_named(self, name: str, label: str, maximum: int) -> VerifiedFile:
        if PROOF_NAME.fullmatch(name) is None:
            raise ProofSetError(f"{label} is not a direct-child proof name")
        return self._read(name, label, maximum)

    def _read(self, name: str, label: str, maximum: int) -> VerifiedFile:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
            os, "O_NOFOLLOW", 0
        )
        try:
            descriptor = os.open(name, flags, dir_fd=self._descriptor)
        except OSError as error:
            raise ProofSetError(f"cannot open {label} through the proof directory") from error
        try:
            before = _FileIdentity.from_stat(os.fstat(descriptor))
            if (
                not stat.S_ISREG(before.mode)
                or before.uid != os.geteuid()
                or before.links != 1
                or before.mode & 0o022
                or before.size <= 0
                or before.size > maximum
            ):
                raise ProofSetError(f"{label} metadata violates the closed file policy")
            chunks: list[bytes] = []
            remaining = before.size
            while remaining:
                chunk = os.read(descriptor, min(remaining, 64 * 1024))
                if not chunk:
                    raise ProofSetError(f"{label} changed during its bounded read")
                chunks.append(chunk)
                remaining -= len(chunk)
            if os.read(descriptor, 1):
                raise ProofSetError(f"{label} grew during its bounded read")
            if _FileIdentity.from_stat(os.fstat(descriptor)) != before:
                raise ProofSetError(f"{label} changed during its bounded read")
            data = b"".join(chunks)
            return VerifiedFile(
                name,
                data,
                "sha256:" + hashlib.sha256(data).hexdigest(),
                len(data),
            )
        finally:
            os.close(descriptor)


@dataclasses.dataclass(frozen=True)
class ProducerContext:
    release_commit: str
    release_manifest_sha256: str
    worker_bundle_sha256: str
    usage_terminal_verifier_binary_sha256: str
    qualification_manifest_sha256: str
    qualification_catalog_sha256: str
    old_targets: dict[str, Any]
    fresh_targets: dict[str, Any]


class RouteV2QualificationVerifier(Protocol):
    def verify(
        self,
        receipt: VerifiedFile,
        node_acks: VerifiedFile,
        transcript: VerifiedFile,
        context: ProducerContext,
    ) -> None: ...


class UsageTargetTerminalVerifier(Protocol):
    """Release-bound Rust verifier boundary; Python does not copy E9 semantics."""

    def verify(
        self,
        receipt: VerifiedFile,
        expected_request: VerifiedFile,
        verification_receipt: VerifiedFile,
        context: ProducerContext,
    ) -> None: ...


class HostFenceTerminalVerifier(Protocol):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None: ...


class LocalPositiveStopVerifier(Protocol):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None: ...


class _UnavailableRouteV2Verifier:
    def verify(
        self,
        _receipt: VerifiedFile,
        _node_acks: VerifiedFile,
        _transcript: VerifiedFile,
        _context: ProducerContext,
    ) -> None:
        raise ProofSetError("G3 qualification verifier is not implementation-accepted")


class _UnavailableUsageVerifier:
    def verify(
        self,
        _receipt: VerifiedFile,
        _expected_request: VerifiedFile,
        _verification_receipt: VerifiedFile,
        _context: ProducerContext,
    ) -> None:
        raise ProofSetError("E9 target-terminal verifier is not wired to its Rust binary")


class _UnavailableHostFenceVerifier:
    def verify(self, _receipt: VerifiedFile, _expected: dict[str, Any]) -> None:
        raise ProofSetError("V3 core HostFence verifier is not implementation-accepted")


class _UnavailableLocalPositiveStopVerifier:
    def verify(self, _receipt: VerifiedFile, _expected: dict[str, Any]) -> None:
        raise ProofSetError(
            "local positive-stop proof is Proposed and not implementation-accepted"
        )


UNAVAILABLE_ROUTE_V2_VERIFIER: RouteV2QualificationVerifier = _UnavailableRouteV2Verifier()
UNAVAILABLE_USAGE_VERIFIER: UsageTargetTerminalVerifier = _UnavailableUsageVerifier()
UNAVAILABLE_HOST_FENCE_VERIFIER: HostFenceTerminalVerifier = _UnavailableHostFenceVerifier()
UNAVAILABLE_LOCAL_POSITIVE_STOP_VERIFIER: LocalPositiveStopVerifier = (
    _UnavailableLocalPositiveStopVerifier()
)


@dataclasses.dataclass(frozen=True)
class VerifiedProofSet:
    value: dict[str, Any]
    sha256: str
    source_manifest_sha256: str
    source_bundle_sha256: str
    release_manifest_sha256: str
    qualification_manifest_sha256: str
    qualification_catalog_sha256: str
    fresh_targets_sha256: str
    fleet_closed_sha256: str
    route_v2_rotation_qualification_receipt_sha256: str
    route_v2_rotation_qualification_node_ack_sets_sha256: str
    route_v2_rotation_qualification_transcript_sha256: str
    usage_terminal_sha256: str
    old_host_coverage_sha256: str
    kernel_nbd_qualification_bundle_sha256: str
    vhost_user_qualification_bundle_sha256: str
    qualification_terminal_sha256: str

    def admission_binding(self, reset_complete_receipt_sha256: str) -> dict[str, Any]:
        release = self.value["release"]
        fresh = self.value["fresh"]
        return {
            "reset_id": self.value["reset_id"],
            "deployment_id": fresh["deployment_id"],
            "release_id": release["release_id"],
            "source_commit_sha": release["source_commit_sha"],
            "control_schema_version": 16,
            "source_manifest_sha256": self.source_manifest_sha256,
            "source_bundle_sha256": self.source_bundle_sha256,
            "release_manifest_sha256": self.release_manifest_sha256,
            "qualification_manifest_sha256": self.qualification_manifest_sha256,
            "qualification_catalog_sha256": self.qualification_catalog_sha256,
            "proof_set_sha256": self.sha256,
            "fresh_targets_sha256": self.fresh_targets_sha256,
            "reset_complete_receipt_sha256": digest(
                reset_complete_receipt_sha256, "reset-complete digest"
            ),
            "fleet_closed_receipt_sha256": self.fleet_closed_sha256,
            "route_v2_rotation_qualification_receipt_sha256": (
                self.route_v2_rotation_qualification_receipt_sha256
            ),
            "route_v2_rotation_qualification_node_ack_sets_sha256": (
                self.route_v2_rotation_qualification_node_ack_sets_sha256
            ),
            "route_v2_rotation_qualification_transcript_sha256": (
                self.route_v2_rotation_qualification_transcript_sha256
            ),
            "usage_terminal_receipt_sha256": self.usage_terminal_sha256,
            "old_host_coverage_sha256": self.old_host_coverage_sha256,
            "kernel_nbd_qualification_bundle_sha256": (
                self.kernel_nbd_qualification_bundle_sha256
            ),
            "vhost_user_qualification_bundle_sha256": (
                self.vhost_user_qualification_bundle_sha256
            ),
        }


def _validate_operator(value: Any) -> dict[str, Any]:
    value = fields(
        value,
        {"aws_partition", "account_id", "role_arn", "principal_arn"},
        "proof-set operator",
    )
    partition = value["aws_partition"]
    account_id = value["account_id"]
    if partition not in {"aws", "aws-us-gov", "aws-cn"}:
        raise ProofSetError("proof-set operator partition is invalid")
    if not isinstance(account_id, str) or ACCOUNT.fullmatch(account_id) is None:
        raise ProofSetError("proof-set operator account is invalid")
    role_prefix = f"arn:{partition}:iam::{account_id}:role/"
    role_arn = value["role_arn"]
    if not isinstance(role_arn, str) or not role_arn.startswith(role_prefix):
        raise ProofSetError("proof-set operator role is outside its account")
    role_name = role_arn.rsplit("/", 1)[-1]
    principal_prefix = f"arn:{partition}:sts::{account_id}:assumed-role/{role_name}/"
    principal = value["principal_arn"]
    if (
        not isinstance(principal, str)
        or not principal.startswith(principal_prefix)
        or len(principal) == len(principal_prefix)
    ):
        raise ProofSetError("proof-set operator is not the assumed-role shape")
    return value


def _validate_targets(value: Any, label: str) -> dict[str, Any]:
    value = fields(value, TARGET_FIELDS, label)
    for name, item in value.items():
        if not isinstance(item, str) or not item or len(item) > 2_048:
            raise ProofSetError(f"{label}.{name} is not a bounded resource identity")
    if not value["chunkstore_object_prefix"].endswith("/"):
        raise ProofSetError(f"{label} ChunkStore prefix has no terminal slash")
    return value


def _validate_source_receipt(value: Any, release: dict[str, Any]) -> None:
    value = fields(
        value,
        {
            "schema_version",
            "source_sha",
            "tree_sha",
            "manifest_sha256",
            "bundle_sha256",
            "manifest_object_key",
            "manifest_version_id",
            "manifest_checksum_sha256",
            "bundle_object_key",
            "bundle_version_id",
            "source_owner",
            "source_writable_by_build",
        },
        "source receipt",
    )
    if (
        value["schema_version"] != 1
        or value["source_sha"] != release["source_commit_sha"]
        or value["manifest_sha256"] != release["source_manifest_sha256"]
        or value["bundle_sha256"] != release["source_bundle_sha256"]
        or value["source_owner"] != "root"
        or value["source_writable_by_build"] is not False
    ):
        raise ProofSetError("source receipt does not bind the immutable source")
    commit(value["tree_sha"], "source receipt tree")
    digest(value["manifest_checksum_sha256"], "source receipt checksum")
    expected_manifest = (
        "source/manifests/sha256/"
        + release["source_manifest_sha256"].removeprefix("sha256:")
        + ".json"
    )
    expected_bundle = (
        "source/bundles/sha256/"
        + release["source_bundle_sha256"].removeprefix("sha256:")
        + ".bundle"
    )
    if (
        value["manifest_object_key"] != expected_manifest
        or value["bundle_object_key"] != expected_bundle
        or not value["manifest_version_id"]
        or not value["bundle_version_id"]
    ):
        raise ProofSetError("source receipt content-addressed identity drifted")


def _validate_build_receipt(value: Any, release: dict[str, Any]) -> None:
    required = {
        "schema_version",
        "source_sha",
        "tree_sha",
        "manifest_sha256",
        "bundle_sha256",
        "exit_status",
        "build_kind",
        "aws_environment_forwarded",
        "registry_credentials_used",
        "reusable_home",
        "job_cgroup_drained",
        "output_frozen",
    }
    if not isinstance(value, dict) or not required.issubset(value):
        raise ProofSetError("build receipt omits required frozen-build fields")
    if (
        value["schema_version"] != 1
        or value["source_sha"] != release["source_commit_sha"]
        or value["manifest_sha256"] != release["source_manifest_sha256"]
        or value["bundle_sha256"] != release["source_bundle_sha256"]
        or value["exit_status"] != 0
        or value["build_kind"] != "manual-release-export-images"
        or value["aws_environment_forwarded"] is not False
        or value["registry_credentials_used"] is not False
        or value["reusable_home"] is not False
        or value["job_cgroup_drained"] is not True
        or value["output_frozen"] is not True
    ):
        raise ProofSetError("build receipt is not a successful frozen exact-source build")
    commit(value["tree_sha"], "build receipt tree")


def _validate_release_manifest(value: Any, release: dict[str, Any]) -> tuple[str, str]:
    value = fields(
        value,
        {"artifacts", "build_inputs", "guest_runtime", "source", "version"},
        "release manifest",
    )
    if value["version"] != 1:
        raise ProofSetError("release manifest version is not 1")
    source = fields(value["source"], {"commit", "fingerprint", "tree"}, "release source")
    if source["commit"] != release["source_commit_sha"]:
        raise ProofSetError("release manifest source commit drifted")
    commit(source["tree"], "release source tree")
    digest(source["fingerprint"], "release source fingerprint")
    artifacts = fields(
        value["artifacts"], {"control_plane", "gateway", "worker"}, "release artifacts"
    )
    worker = artifacts["worker"]
    if not isinstance(worker, dict) or worker.get("bundle_name") != "cats-worker.tar.zst":
        raise ProofSetError("release worker artifact is not the closed production bundle")
    worker_digest = digest(worker.get("bundle_sha256"), "worker bundle digest")
    members = worker.get("members")
    if not isinstance(members, dict) or not members:
        raise ProofSetError("release worker member set is empty")
    for name, member in members.items():
        if not isinstance(name, str) or not name or "/" in name:
            raise ProofSetError("release worker member name is invalid")
        member = fields(member, {"sha256", "size_bytes"}, f"worker member {name}")
        digest(member["sha256"], f"worker member {name} digest")
        integer(member["size_bytes"], f"worker member {name} size", minimum=1)
    usage_verifier = members.get(USAGE_TERMINAL_VERIFIER.name)
    if not isinstance(usage_verifier, dict):
        raise ProofSetError("release omits the E9 terminal verifier worker member")
    inputs = value["build_inputs"]
    if (
        not isinstance(inputs, dict)
        or inputs.get("guest_target") != "x86_64-unknown-linux-musl"
        or inputs.get("platform") != "linux/amd64"
    ):
        raise ProofSetError("release manifest target is not production linux/amd64")
    return worker_digest, usage_verifier["sha256"]


def _validate_usage_verification_projection(
    value: Any,
    *,
    receipt: VerifiedFile,
    expected_request: VerifiedFile,
    context: ProducerContext,
) -> None:
    value = fields(
        value,
        {
            "binary_sha256",
            "expected_request_file_sha256",
            "kind",
            "release_commit",
            "target_receipt_file_sha256",
            "target_request_sha256",
            "validated",
            "version",
            "worker_bundle_sha256",
        },
        "E9 terminal verification receipt",
    )
    if (
        value["kind"] != USAGE_TERMINAL_VERIFICATION_KIND
        or value["version"] != 1
        or value["validated"] is not True
        or value["release_commit"] != context.release_commit
        or value["worker_bundle_sha256"] != context.worker_bundle_sha256
        or value["binary_sha256"]
        != context.usage_terminal_verifier_binary_sha256
        or value["expected_request_file_sha256"] != expected_request.sha256
        or value["target_receipt_file_sha256"] != receipt.sha256
    ):
        raise ProofSetError("E9 terminal verification projection drifted")
    digest(value["target_request_sha256"], "E9 target request digest")


def _validate_qualification_admission(
    begin: Any,
    terminal: Any,
    *,
    release_id: str,
    release_commit: str,
    qualification_catalog_sha256: str,
) -> None:
    begin = fields(
        begin,
        {
            "kind",
            "version",
            "qualification_id",
            "workspace_id",
            "release_id",
            "source_commit_sha",
            "qualification_catalog_sha256",
            "allowed_mutation_classes",
            "binding_sha256",
            "begin_command_id",
            "begin_request_sha256",
            "begin_command_receipt_sha256",
            "resulting_revision",
            "qualification_expires_at_unix_ms",
        },
        "Qualification Begin receipt",
    )
    terminal = fields(
        terminal,
        {
            "kind",
            "version",
            "qualification_id",
            "workspace_id",
            "release_id",
            "source_commit_sha",
            "qualification_catalog_sha256",
            "allowed_mutation_classes",
            "qualification_expires_at_unix_ms",
            "binding_sha256",
            "begin_command_id",
            "begin_request_sha256",
            "begin_command_receipt_sha256",
            "begin_resulting_revision",
            "close_kind",
            "terminal_outcome",
            "close_command_id",
            "close_request_sha256",
            "close_command_receipt_sha256",
            "final_admission_state_sha256",
            "final_closed_revision",
            "fleet_closed_receipt_sha256",
            "cleanup_inventory_receipt_sha256",
            "active_guard_count",
            "product_resource_count",
            "residue_count",
            "completed_at_unix_ms",
        },
        "Qualification terminal receipt",
    )
    if begin["kind"] != QUALIFICATION_BEGIN_KIND or begin["version"] != 1:
        raise ProofSetError("Qualification Begin receipt kind/version drifted")
    if terminal["kind"] != QUALIFICATION_TERMINAL_KIND or terminal["version"] != 1:
        raise ProofSetError("Qualification terminal receipt kind/version drifted")
    identifier(begin["qualification_id"], "Qualification ID")
    identifier(begin["workspace_id"], "Qualification Workspace ID")
    identifier(begin["release_id"], "Qualification release ID")
    commit(begin["source_commit_sha"], "Qualification source commit")
    digest(begin["qualification_catalog_sha256"], "Qualification catalog")
    if begin["allowed_mutation_classes"] != [
        "cat_create",
        "disk_create",
        "disk_delete",
        "runtime_mutation",
    ]:
        raise ProofSetError("Qualification mutation-class set drifted")
    if (
        begin["release_id"] != release_id
        or begin["source_commit_sha"] != release_commit
        or begin["qualification_catalog_sha256"]
        != qualification_catalog_sha256
    ):
        raise ProofSetError("Qualification admission release/catalog binding drifted")
    for value, label in [
        (begin["binding_sha256"], "Qualification binding"),
        (begin["begin_request_sha256"], "Qualification Begin request"),
        (begin["begin_command_receipt_sha256"], "Qualification Begin command receipt"),
        (terminal["close_request_sha256"], "Qualification close request"),
        (terminal["close_command_receipt_sha256"], "Qualification close command receipt"),
        (terminal["final_admission_state_sha256"], "Qualification final state"),
        (terminal["fleet_closed_receipt_sha256"], "Qualification final fleet"),
        (terminal["cleanup_inventory_receipt_sha256"], "Qualification cleanup inventory"),
    ]:
        digest(value, label)
    for value, label in [
        (begin["begin_command_id"], "Qualification Begin command ID"),
        (terminal["close_command_id"], "Qualification close command ID"),
    ]:
        if not isinstance(value, str) or RANDOM_ID.fullmatch(value) is None:
            raise ProofSetError(f"{label} is invalid")
    begin_revision = integer(begin["resulting_revision"], "Qualification Begin revision", minimum=1)
    if (
        terminal["qualification_id"] != begin["qualification_id"]
        or terminal["workspace_id"] != begin["workspace_id"]
        or terminal["release_id"] != begin["release_id"]
        or terminal["source_commit_sha"] != begin["source_commit_sha"]
        or terminal["qualification_catalog_sha256"]
        != begin["qualification_catalog_sha256"]
        or terminal["allowed_mutation_classes"] != begin["allowed_mutation_classes"]
        or terminal["qualification_expires_at_unix_ms"]
        != begin["qualification_expires_at_unix_ms"]
        or terminal["binding_sha256"] != begin["binding_sha256"]
        or terminal["begin_command_id"] != begin["begin_command_id"]
        or terminal["begin_request_sha256"] != begin["begin_request_sha256"]
        or terminal["begin_command_receipt_sha256"]
        != begin["begin_command_receipt_sha256"]
        or terminal["begin_resulting_revision"] != begin_revision
        or terminal["final_closed_revision"] != begin_revision + 1
        or terminal["close_command_id"] == begin["begin_command_id"]
        or (terminal["close_kind"], terminal["terminal_outcome"])
        not in {
            ("end_qualification", "qualified_closed"),
            ("emergency_close", "emergency_closed"),
        }
        or terminal["active_guard_count"] != 0
        or terminal["product_resource_count"] != 0
        or terminal["residue_count"] != 0
    ):
        raise ProofSetError("Qualification terminal receipt is not the exact Closed successor")
    integer(begin["qualification_expires_at_unix_ms"], "Qualification expiry", minimum=1)
    integer(terminal["completed_at_unix_ms"], "Qualification completed time", minimum=1)


def _key_ring_digest(version: int, kids: list[str]) -> str:
    projection = {"key_ring_version": version, "loaded_kids": kids, "version": 1}
    hasher = hashlib.sha256()
    hasher.update(b"cats.runtime.key-ring.v1\0")
    hasher.update(canonical_json(projection))
    return "sha256:" + hasher.hexdigest()


def _zero(value: Any, label: str) -> None:
    if value != 0 or isinstance(value, bool):
        raise ProofSetError(f"{label} is not zero")


def _validate_fleet(value: Any, release_commit: str, now_ms: int) -> None:
    value = fields(
        value,
        {
            "version",
            "release_commit_sha",
            "started_at_unix_ms",
            "deadline_unix_ms",
            "completed_at_unix_ms",
            "expected_nodes",
            "expected_key_ring",
            "snapshot",
        },
        "fleet Closed evidence",
    )
    if value["version"] != 1 or value["release_commit_sha"] != release_commit:
        raise ProofSetError("fleet evidence release binding drifted")
    expected_nodes = value["expected_nodes"]
    if (
        not isinstance(expected_nodes, list)
        or not expected_nodes
        or expected_nodes != sorted(set(expected_nodes))
    ):
        raise ProofSetError("fleet expected Node set is not strict sorted nonempty")
    for node_id in expected_nodes:
        identifier(node_id, "fleet Node ID")
    ring = fields(
        value["expected_key_ring"],
        {"ring_version", "key_ring_digest", "kids"},
        "fleet expected key ring",
    )
    ring_version = integer(ring["ring_version"], "fleet ring version", minimum=1)
    kids = ring["kids"]
    if not isinstance(kids, list) or not kids or kids != sorted(set(kids)):
        raise ProofSetError("fleet expected key IDs are not strict sorted nonempty")
    for kid in kids:
        identifier(kid, "fleet expected key ID")
    if digest(ring["key_ring_digest"], "fleet ring digest") != _key_ring_digest(
        ring_version, kids
    ):
        raise ProofSetError("fleet expected key-ring digest is not canonical")
    snapshot = fields(
        value["snapshot"],
        {
            "version",
            "control_release_commit_sha",
            "evaluated_at_unix_ms",
            "approved_guest_config_digest",
            "desired_runtime_count",
            "current_runtime_observation_count",
            "route_signing_authority",
            "nodes",
        },
        "fleet snapshot",
    )
    evaluated = integer(snapshot["evaluated_at_unix_ms"], "fleet evaluated time")
    if (
        snapshot["version"] != 1
        or snapshot["control_release_commit_sha"] != release_commit
        or evaluated > now_ms
        or now_ms - evaluated >= FLEET_MAX_AGE_MS
    ):
        raise ProofSetError("fleet snapshot is not fresh exact-release evidence")
    digest(snapshot["approved_guest_config_digest"], "approved Guest config")
    _zero(snapshot["desired_runtime_count"], "fleet Desired count")
    _zero(snapshot["current_runtime_observation_count"], "fleet observation count")
    signer = fields(
        snapshot["route_signing_authority"],
        {
            "deployment_id",
            "signer_revision",
            "signer_reference_sha256",
            "active_kid",
            "public_key_ring_version",
            "public_key_ring_digest",
        },
        "fleet Route signing authority",
    )
    identifier(signer["deployment_id"], "fleet signer deployment")
    integer(signer["signer_revision"], "fleet signer revision", minimum=1)
    digest(signer["signer_reference_sha256"], "fleet signer reference")
    if (
        signer["active_kid"] not in kids
        or signer["public_key_ring_version"] != ring_version
        or signer["public_key_ring_digest"] != ring["key_ring_digest"]
    ):
        raise ProofSetError("fleet signer is not the active expected ring")
    nodes = snapshot["nodes"]
    if (
        not isinstance(nodes, list)
        or [node.get("node_id") for node in nodes if isinstance(node, dict)]
        != expected_nodes
    ):
        raise ProofSetError("fleet snapshot Node set differs from expected")
    for node in nodes:
        node = fields(node, {"node_id", "session", "inventory"}, "fleet Node")
        session = fields(
            node["session"],
            {
                "version",
                "node_id",
                "immutable_host_id",
                "node_boot_id",
                "agent_instance_id",
                "agent_session_epoch",
                "registration_attempt_id",
                "guest_config_digest",
                "lease_deadline_unix_ms",
            },
            "fleet Agent session",
        )
        inventory = fields(
            node["inventory"],
            {
                "source_session",
                "attestation",
                "source_observation_id",
                "source_heartbeat_sequence",
                "source_observed_at_unix_ms",
                "complete_inventory",
                "assigned_desired_count",
                "runtime_count",
                "residue_count",
                "lifecycle_open_count",
                "route_active_count",
                "route_closed_count",
                "active_guard_count",
                "cancellation_pending_count",
                "quarantined_condition_count",
                "key_ring_version",
                "key_ring_digest",
                "loaded_kids",
            },
            "fleet inventory",
        )
        source = fields(
            inventory["source_session"],
            {"node_id", "node_boot_id", "agent_instance_id", "agent_session_epoch"},
            "fleet inventory source session",
        )
        attestation = fields(
            inventory["attestation"],
            {
                "version",
                "node_id",
                "agent_session_epoch",
                "inventory_epoch",
                "inventory_digest",
                "inventory_read_position",
                "accepted_at_unix_ms",
            },
            "fleet inventory attestation",
        )
        if (
            session["version"] != 1
            or node["node_id"] != session["node_id"]
            or session["guest_config_digest"] != snapshot["approved_guest_config_digest"]
            or integer(session["lease_deadline_unix_ms"], "session lease") <= evaluated
            or any(
                source[name] != session[name]
                for name in (
                    "node_id",
                    "node_boot_id",
                    "agent_instance_id",
                    "agent_session_epoch",
                )
            )
            or attestation["version"] != 1
            or attestation["node_id"] != node["node_id"]
            or attestation["agent_session_epoch"] != source["agent_session_epoch"]
        ):
            raise ProofSetError("fleet inventory does not bind the current Agent session")
        accepted = integer(attestation["accepted_at_unix_ms"], "inventory accepted time")
        if accepted > evaluated or evaluated - accepted >= FLEET_MAX_AGE_MS:
            raise ProofSetError("fleet inventory is not fresh")
        digest(attestation["inventory_digest"], "fleet inventory digest")
        if inventory["complete_inventory"] is not True:
            raise ProofSetError("fleet inventory is partial")
        for counter in (
            "assigned_desired_count",
            "runtime_count",
            "residue_count",
            "lifecycle_open_count",
            "route_active_count",
            "route_closed_count",
            "active_guard_count",
            "cancellation_pending_count",
            "quarantined_condition_count",
        ):
            _zero(inventory[counter], f"fleet inventory {counter}")
        if (
            inventory["key_ring_version"] != ring_version
            or inventory["key_ring_digest"] != ring["key_ring_digest"]
            or inventory["loaded_kids"] != kids
        ):
            raise ProofSetError("fleet Node has not acknowledged the expected ring")


def _validate_persistent_disk(value: Any, block_path: str) -> None:
    value = fields(
        value,
        {
            "version",
            "proof",
            "block_path",
            "workspace_id",
            "cat_id",
            "node_id",
            "disk_id",
            "volume_id",
            "volume_intent_id",
            "attachment_id",
            "attachment_epoch",
            "guest_device",
            "filesystem_uuid",
            "mount_path",
            "expected_blank_head",
            "initialized_head",
            "first_format",
            "ready",
            "restart",
            "strict_flush",
            "detach",
            "final_inventory",
        },
        "V5 persistent-disk receipt",
    )
    if (
        value["version"] != 1
        or value["proof"] != "persistent_disk_attach_initialize_restart_detach"
        or value["block_path"] != block_path
    ):
        raise ProofSetError("V5 persistent-disk proof identity drifted")
    for name in (
        "workspace_id",
        "cat_id",
        "node_id",
        "disk_id",
        "volume_id",
        "volume_intent_id",
        "attachment_id",
    ):
        identifier(value[name], f"V5 {name}")
    integer(value["attachment_epoch"], "V5 attachment epoch", minimum=1)
    device = fields(value["guest_device"], {"serial", "slot"}, "V5 guest device")
    if not all(isinstance(device[name], str) and device[name] for name in device):
        raise ProofSetError("V5 guest-device identity is incomplete")
    if not isinstance(value["filesystem_uuid"], str) or UUID.fullmatch(
        value["filesystem_uuid"]
    ) is None:
        raise ProofSetError("V5 filesystem UUID is not canonical")
    if (
        not isinstance(value["mount_path"], str)
        or not value["mount_path"].startswith("/")
        or value["mount_path"] == "/"
        or ".." in Path(value["mount_path"]).parts
    ):
        raise ProofSetError("V5 mount path is not absolute non-root")
    if (
        not isinstance(value["expected_blank_head"], str)
        or not value["expected_blank_head"]
        or not isinstance(value["initialized_head"], str)
        or not value["initialized_head"]
        or value["initialized_head"] == value["expected_blank_head"]
    ):
        raise ProofSetError("V5 initialized head is blank")
    first = fields(
        value["first_format"],
        {
            "ambiguous_response_discovered",
            "mkfs_invocations",
            "fault_action",
            "consumed",
            "artifact_sha256",
        },
        "V5 first format",
    )
    if (
        first["ambiguous_response_discovered"] is not True
        or first["mkfs_invocations"] != 1
        or first["fault_action"] != "drop_validated_format_response_once"
        or first["consumed"] is not True
        or not isinstance(first["artifact_sha256"], str)
        or RAW_SHA256.fullmatch(first["artifact_sha256"]) is None
    ):
        raise ProofSetError("V5 first-format ambiguity proof is incomplete")
    ready = fields(
        value["ready"],
        {"runtime_incarnation", "guest_boot_id", "device_path", "mounted_set_complete"},
        "V5 ready",
    )
    if (
        ready["mounted_set_complete"] is not True
        or not isinstance(ready["runtime_incarnation"], str)
        or not ready["runtime_incarnation"]
        or not isinstance(ready["guest_boot_id"], str)
        or not ready["guest_boot_id"]
        or not isinstance(ready["device_path"], str)
        or not ready["device_path"].startswith("/")
    ):
        raise ProofSetError("V5 mounted set is incomplete")
    restart = fields(
        value["restart"],
        {
            "before_agent_session_epoch",
            "after_agent_session_epoch",
            "retained_runtime_incarnation",
            "retained_guest_boot_id",
            "filesystem_uuid",
            "mount_path",
        },
        "V5 restart",
    )
    if integer(
        restart["after_agent_session_epoch"], "V5 after Agent session", minimum=1
    ) <= integer(
        restart["before_agent_session_epoch"], "V5 before Agent session", minimum=1
    ):
        raise ProofSetError("V5 Agent session did not advance on restart")
    if (
        restart["retained_runtime_incarnation"] != ready["runtime_incarnation"]
        or restart["retained_guest_boot_id"] != ready["guest_boot_id"]
        or restart["filesystem_uuid"] != value["filesystem_uuid"]
        or restart["mount_path"] != value["mount_path"]
    ):
        raise ProofSetError("V5 restart did not retain runtime/filesystem identity")
    flush = fields(
        value["strict_flush"], {"before_head", "after_head", "remote_durable"}, "V5 flush"
    )
    if (
        flush["remote_durable"] is not True
        or not isinstance(flush["before_head"], str)
        or not flush["before_head"]
        or not isinstance(flush["after_head"], str)
        or not flush["after_head"]
        or flush["before_head"] == flush["after_head"]
    ):
        raise ProofSetError("V5 Strict FLUSH is not a later remotely durable head")
    detached = fields(
        value["detach"],
        {"desired_volume_absent", "authority_unowned", "device_absent", "mount_absent"},
        "V5 detach",
    )
    if any(result is not True for result in detached.values()):
        raise ProofSetError("V5 detach postcondition is incomplete")
    inventory = fields(
        value["final_inventory"],
        {
            "node_id",
            "agent_session_epoch",
            "complete",
            "gates_closed",
            "active_guard_count",
            "residue_count",
        },
        "V5 final inventory",
    )
    if (
        inventory["node_id"] != value["node_id"]
        or inventory["complete"] is not True
        or inventory["gates_closed"] is not True
    ):
        raise ProofSetError("V5 final inventory is not complete and Closed")
    _zero(inventory["active_guard_count"], "V5 active guards")
    _zero(inventory["residue_count"], "V5 residue")


def _jsonl(data: bytes, label: str) -> list[dict[str, Any]]:
    if not data.endswith(b"\n"):
        raise ProofSetError(f"{label} has no terminal LF")
    values: list[dict[str, Any]] = []
    for index, line in enumerate(data.splitlines(), 1):
        if not line:
            raise ProofSetError(f"{label} contains an empty line")
        value = decode_json(line, f"{label} line {index}")
        if canonical_json(value) != line or not isinstance(value, dict):
            raise ProofSetError(f"{label} line {index} is not canonical object JSON")
        values.append(value)
    return values


def _validate_sha256sums(
    data: bytes,
    expected: dict[str, VerifiedFile],
    label: str,
) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProofSetError(f"{label} is not ASCII") from error
    if not text.endswith("\n"):
        raise ProofSetError(f"{label} has no terminal LF")
    observed: dict[str, str] = {}
    for line in text.splitlines():
        match = re.fullmatch(r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,127})", line)
        if match is None or match.group(2) in observed:
            raise ProofSetError(f"{label} has a malformed or duplicate entry")
        observed[match.group(2)] = "sha256:" + match.group(1)
    for name, verified in expected.items():
        if observed.get(name) != verified.sha256:
            raise ProofSetError(f"{label} does not close {name}")


def _validate_qualification(
    directory: ProofDirectory,
    value: Any,
    block_path: str,
    context: ProducerContext,
    worker_bundle_sha256: str,
) -> str:
    value = fields(
        value,
        {"manifest", "case_evidence", "qualification_catalog", "sha256sums"},
        f"{block_path} qualification",
    )
    refs = {
        name: ProofReference.parse(reference, f"qualification.{block_path}.{name}")
        for name, reference in value.items()
    }
    manifest_file = directory.read_reference(refs["manifest"], f"{block_path} manifest")
    manifest = decode_json(
        manifest_file.data, f"{block_path} manifest", canonical_lf=True
    )
    release_manifest = manifest.get("release_manifest", {})
    installer = manifest.get("installer_receipt", {})
    if (
        not isinstance(manifest, dict)
        or manifest.get("version") != 1
        or manifest.get("state") != "passed"
        or manifest.get("exit_code") != 0
        or manifest.get("schema_version") != 16
        or manifest.get("block_path") != block_path
        or manifest.get("exact_commit") != context.release_commit
        or release_manifest.get("sha256") != context.release_manifest_sha256
        or release_manifest.get("approved_sha256") != context.release_manifest_sha256
        or installer.get("worker_bundle_sha256") != worker_bundle_sha256
        or manifest.get("qualification_catalog", {}).get("sha256")
        != context.qualification_catalog_sha256
    ):
        raise ProofSetError(f"{block_path} qualification is not exact-release passed")
    catalog_file = directory.read_reference(
        refs["qualification_catalog"], f"{block_path} qualification catalog"
    )
    if catalog_file.sha256 != context.qualification_catalog_sha256:
        raise ProofSetError(f"{block_path} qualification catalog drifted")
    evidence_file = directory.read_reference(
        refs["case_evidence"], f"{block_path} case evidence"
    )
    entries = _jsonl(evidence_file.data, f"{block_path} case evidence")
    if manifest.get("case_evidence") != {
        "sha256": evidence_file.sha256,
        "count": len(entries),
    }:
        raise ProofSetError(f"{block_path} case-evidence manifest binding drifted")
    matches = [
        entry
        for entry in entries
        if entry.get("case_id") == "volume-init-matrix"
        and entry.get("filename") == "persistent-disk-receipt.json"
    ]
    if len(matches) != 1:
        raise ProofSetError(f"{block_path} has no unique V5 volume-init evidence")
    entry = fields(
        matches[0],
        {"case_id", "filename", "kind", "sha256", "size_bytes", "content"},
        "V5 case-evidence entry",
    )
    content_bytes = canonical_json(entry["content"], newline=True)
    if (
        entry["kind"] != "json"
        or entry["sha256"] != "sha256:" + hashlib.sha256(content_bytes).hexdigest()
        or entry["size_bytes"] != len(content_bytes)
    ):
        raise ProofSetError("V5 embedded evidence digest/size drifted")
    _validate_persistent_disk(entry["content"], block_path)
    sums_file = directory.read_reference(refs["sha256sums"], f"{block_path} SHA256SUMS")
    _validate_sha256sums(
        sums_file.data,
        {
            "manifest.json": manifest_file,
            "case-evidence.jsonl": evidence_file,
            "qualification-catalog.v1.json": catalog_file,
        },
        f"{block_path} SHA256SUMS",
    )
    return sums_file.sha256


def _validate_local_positive_stop(
    directory: ProofDirectory,
    value: Any,
    expected: dict[str, Any],
    verifier: LocalPositiveStopVerifier,
) -> None:
    value = fields(
        value,
        {"kind", "receipt"},
        "old Host local-positive-stop coverage",
    )
    if value["kind"] != "local_positive_stop":
        raise ProofSetError("old Host local terminal kind drifted")
    reference = ProofReference.parse(value["receipt"], "old Host positive-stop receipt")
    receipt = directory.read_reference(reference, "old Host positive-stop receipt")
    verifier.verify(receipt, expected)


def _validate_host_coverage(
    directory: ProofDirectory,
    inventory: Any,
    coverage: Any,
    host_fence_verifier: HostFenceTerminalVerifier,
    local_positive_stop_verifier: LocalPositiveStopVerifier,
) -> None:
    inventory = fields(inventory, {"version", "hosts"}, "old Host inventory")
    coverage = fields(coverage, {"version", "hosts"}, "old Host coverage")
    if inventory["version"] != 1 or coverage["version"] != 1:
        raise ProofSetError("old Host inventory/coverage version drifted")
    expected: list[tuple[str, tuple[str, ...]]] = []
    for entry in inventory["hosts"]:
        entry = fields(entry, {"host_id", "components"}, "old Host inventory entry")
        host_id = identifier(entry["host_id"], "old Host ID")
        components = entry["components"]
        if (
            not isinstance(components, list)
            or not components
            or components != sorted(set(components))
            or any(
                item not in {"blockd", "controller", "gateway", "node_agent", "vmm"}
                for item in components
            )
        ):
            raise ProofSetError("old Host component set is not closed sorted nonempty")
        expected.append((host_id, tuple(components)))
    if expected != sorted(set(expected)):
        raise ProofSetError("old Host inventory is not strict sorted")
    actual: list[tuple[str, tuple[str, ...]]] = []
    for entry in coverage["hosts"]:
        entry = fields(entry, {"host_id", "components", "terminal"}, "old Host coverage entry")
        pair = (identifier(entry["host_id"], "covered Host ID"), tuple(entry["components"]))
        actual.append(pair)
        terminal = entry["terminal"]
        if not isinstance(terminal, dict):
            raise ProofSetError("old Host coverage terminal proof is missing")
        if terminal.get("kind") == "local_positive_stop":
            _validate_local_positive_stop(
                directory,
                terminal,
                {
                    "host_id": pair[0],
                    "components": list(pair[1]),
                },
                local_positive_stop_verifier,
            )
        elif terminal.get("kind") == "host_fence_event":
            terminal = fields(
                terminal,
                {"kind", "event_id", "receipt"},
                "old Host V3 coverage",
            )
            identifier(terminal["event_id"], "HostFence event ID")
            reference = ProofReference.parse(terminal["receipt"], "V3 terminal receipt")
            receipt = directory.read_reference(reference, "V3 core HostFence receipt")
            host_fence_verifier.verify(
                receipt,
                {
                    "event_id": terminal["event_id"],
                    "host_id": pair[0],
                    "components": list(pair[1]),
                },
            )
        else:
            raise ProofSetError("old Host coverage terminal kind is unavailable")
    if actual != expected:
        raise ProofSetError("old Host coverage is not exact inventory coverage")


def verify(
    proof_directory: Path,
    *,
    expected_reset_id: str,
    expected_release_commit: str,
    expected_operator: dict[str, Any],
    expected_old_targets: dict[str, Any],
    expected_fresh_targets: dict[str, Any],
    route_v2_verifier: RouteV2QualificationVerifier = UNAVAILABLE_ROUTE_V2_VERIFIER,
    usage_verifier: UsageTargetTerminalVerifier = UNAVAILABLE_USAGE_VERIFIER,
    host_fence_verifier: HostFenceTerminalVerifier = UNAVAILABLE_HOST_FENCE_VERIFIER,
    local_positive_stop_verifier: LocalPositiveStopVerifier = (
        UNAVAILABLE_LOCAL_POSITIVE_STOP_VERIFIER
    ),
    now: dt.datetime | None = None,
) -> VerifiedProofSet:
    reference_time = (now or dt.datetime.now(dt.timezone.utc)).astimezone(dt.timezone.utc)
    with ProofDirectory(proof_directory) as directory:
        proof_file = directory.read_named(
            PROOF_SET_FILE, "production cutover proof set", MAX_PROOF_SET_BYTES
        )
        value = fields(
            decode_json(proof_file.data, "production cutover proof set", canonical_lf=True),
            PROOF_SET_FIELDS,
            "production cutover proof set",
        )
        if value["kind"] != PROOF_SET_KIND or value["version"] != 1:
            raise ProofSetError("unsupported production cutover proof-set kind/version")
        identifier(value["cutover_id"], "cutover ID")
        if value["reset_id"] != expected_reset_id:
            raise ProofSetError("proof-set reset ID drifted")
        observed = parse_time(value["observed_at"], "proof-set observed_at")
        if (
            observed > reference_time
            or (reference_time - observed).total_seconds() > PROOF_SET_MAX_AGE_SECONDS
        ):
            raise ProofSetError("proof set is outside its closed freshness window")
        operator = _validate_operator(value["operator"])
        if operator != expected_operator:
            raise ProofSetError("proof-set operator differs from online STS discovery")

        release = fields(
            value["release"],
            {
                "release_id",
                "source_commit_sha",
                "artifact_sha256",
                "source_manifest_sha256",
                "source_bundle_sha256",
                "qualification_manifest_sha256",
                "qualification_catalog_sha256",
                "source_receipt",
                "build_receipt",
                "release_manifest",
                "qualification_manifest",
                "qualification_catalog",
            },
            "proof-set release",
        )
        identifier(release["release_id"], "release ID")
        if commit(release["source_commit_sha"], "release commit") != expected_release_commit:
            raise ProofSetError("proof-set source commit differs from reviewed release")
        for name in (
            "artifact_sha256",
            "source_manifest_sha256",
            "source_bundle_sha256",
            "qualification_manifest_sha256",
            "qualification_catalog_sha256",
        ):
            digest(release[name], f"release {name}")
        release_refs = {
            name: ProofReference.parse(release[name], f"release.{name}")
            for name in (
                "source_receipt",
                "build_receipt",
                "release_manifest",
                "qualification_manifest",
                "qualification_catalog",
            )
        }
        source = decode_json(
            directory.read_reference(release_refs["source_receipt"], "source receipt").data,
            "source receipt",
        )
        _validate_source_receipt(source, release)
        build = decode_json(
            directory.read_reference(release_refs["build_receipt"], "build receipt").data,
            "build receipt",
        )
        _validate_build_receipt(build, release)
        release_manifest_file = directory.read_reference(
            release_refs["release_manifest"], "release manifest"
        )
        if release_manifest_file.sha256 != release["artifact_sha256"]:
            raise ProofSetError("artifact digest is not the release-manifest digest")
        (
            worker_bundle_sha256,
            usage_terminal_verifier_binary_sha256,
        ) = _validate_release_manifest(
            decode_json(
                release_manifest_file.data, "release manifest", canonical_lf=True
            ),
            release,
        )
        qualification_manifest = directory.read_reference(
            release_refs["qualification_manifest"], "qualification manifest"
        )
        qualification_catalog = directory.read_reference(
            release_refs["qualification_catalog"], "qualification catalog"
        )
        if (
            qualification_manifest.sha256 != release["qualification_manifest_sha256"]
            or qualification_catalog.sha256 != release["qualification_catalog_sha256"]
        ):
            raise ProofSetError("qualification manifest/catalog digest drifted")
        decode_json(qualification_manifest.data, "qualification manifest")
        decode_json(qualification_catalog.data, "qualification catalog")

        old_targets = _validate_targets(value["old"], "old targets")
        if old_targets != expected_old_targets:
            raise ProofSetError("proof-set old targets differ from reset invocation")
        fresh = fields(
            value["fresh"],
            {
                "deployment_id",
                "aws_partition",
                "aws_account_id",
                "aws_region",
                "cell_id",
                "cell_namespace",
                "control_schema_version",
                "targets",
            },
            "proof-set fresh target",
        )
        identifier(fresh["deployment_id"], "fresh deployment ID")
        identifier(fresh["cell_id"], "fresh cell ID")
        if (
            fresh["aws_partition"] != operator["aws_partition"]
            or fresh["aws_account_id"] != operator["account_id"]
            or not isinstance(fresh["aws_region"], str)
            or AWS_REGION.fullmatch(fresh["aws_region"]) is None
            or not isinstance(fresh["cell_namespace"], str)
            or DNS_LABEL.fullmatch(fresh["cell_namespace"]) is None
            or fresh["control_schema_version"] != 16
        ):
            raise ProofSetError("fresh cell/release scope is invalid")
        fresh_targets = _validate_targets(fresh["targets"], "fresh targets")
        if fresh_targets != expected_fresh_targets:
            raise ProofSetError("proof-set fresh targets differ from reset invocation")
        context = ProducerContext(
            expected_release_commit,
            release["artifact_sha256"],
            worker_bundle_sha256,
            usage_terminal_verifier_binary_sha256,
            release["qualification_manifest_sha256"],
            release["qualification_catalog_sha256"],
            old_targets,
            fresh_targets,
        )

        proofs = fields(
            value["proofs"],
            {
                "qualification_admission_begin",
                "qualification_admission_terminal",
                "fleet_closed",
                "route_v2_rotation_qualification_receipt",
                "route_v2_rotation_qualification_node_ack_sets",
                "route_v2_rotation_qualification_transcript",
                "usage_terminal_request",
                "usage_terminal_receipt",
                "usage_terminal_verification",
                "old_host_inventory",
                "old_host_coverage",
                "qualification",
            },
            "proof-set proofs",
        )
        proof_refs = {
            name: ProofReference.parse(proofs[name], f"proofs.{name}")
            for name in proofs
            if name != "qualification"
        }
        if (
            proof_refs["usage_terminal_request"].file
            != USAGE_TERMINAL_REQUEST_FILE
            or proof_refs["usage_terminal_receipt"].file
            != USAGE_TERMINAL_RECEIPT_FILE
            or proof_refs["usage_terminal_verification"].file
            != USAGE_TERMINAL_VERIFICATION_FILE
        ):
            raise ProofSetError("E9 proof files do not use their canonical names")
        begin_file = directory.read_reference(
            proof_refs["qualification_admission_begin"], "Qualification Begin receipt"
        )
        terminal_file = directory.read_reference(
            proof_refs["qualification_admission_terminal"],
            "Qualification terminal receipt",
        )
        begin_receipt = decode_json(begin_file.data, "Qualification Begin receipt")
        terminal_receipt = decode_json(
            terminal_file.data, "Qualification terminal receipt"
        )
        _validate_qualification_admission(
            begin_receipt,
            terminal_receipt,
            release_id=release["release_id"],
            release_commit=expected_release_commit,
            qualification_catalog_sha256=release["qualification_catalog_sha256"],
        )
        if terminal_receipt["terminal_outcome"] != "qualified_closed":
            raise ProofSetError(
                "emergency-closed Qualification cannot authorize reset or final Open"
            )
        fleet_file = directory.read_reference(proof_refs["fleet_closed"], "fleet Closed proof")
        _validate_fleet(
            decode_json(fleet_file.data, "fleet Closed proof"),
            expected_release_commit,
            int(reference_time.timestamp() * 1000),
        )
        route_receipt = directory.read_reference(
            proof_refs["route_v2_rotation_qualification_receipt"],
            "G3 rotation qualification receipt",
        )
        route_acks = directory.read_reference(
            proof_refs["route_v2_rotation_qualification_node_ack_sets"],
            "G3 rotation qualification Node ACK sets",
        )
        route_transcript = directory.read_reference(
            proof_refs["route_v2_rotation_qualification_transcript"],
            "G3 rotation qualification transcript",
        )
        route_v2_verifier.verify(route_receipt, route_acks, route_transcript, context)
        usage_request_file = directory.read_reference(
            proof_refs["usage_terminal_request"], "E9 target-terminal request"
        )
        usage_file = directory.read_reference(
            proof_refs["usage_terminal_receipt"], "E9 target-terminal receipt"
        )
        usage_verification_file = directory.read_reference(
            proof_refs["usage_terminal_verification"],
            "E9 target-terminal verification receipt",
        )
        _validate_usage_verification_projection(
            decode_json(
                usage_verification_file.data,
                "E9 target-terminal verification receipt",
                canonical_lf=True,
            ),
            receipt=usage_file,
            expected_request=usage_request_file,
            context=context,
        )
        usage_verifier.verify(
            usage_file,
            usage_request_file,
            usage_verification_file,
            context,
        )
        inventory_file = directory.read_reference(
            proof_refs["old_host_inventory"], "old Host inventory"
        )
        coverage_file = directory.read_reference(
            proof_refs["old_host_coverage"], "old Host coverage"
        )
        _validate_host_coverage(
            directory,
            decode_json(inventory_file.data, "old Host inventory", canonical_lf=True),
            decode_json(coverage_file.data, "old Host coverage", canonical_lf=True),
            host_fence_verifier,
            local_positive_stop_verifier,
        )
        qualification = fields(
            proofs["qualification"], {"kernel_nbd", "vhost_user"}, "qualification proofs"
        )
        kernel_bundle = _validate_qualification(
            directory,
            qualification["kernel_nbd"],
            "kernel-nbd",
            context,
            worker_bundle_sha256,
        )
        vhost_bundle = _validate_qualification(
            directory,
            qualification["vhost_user"],
            "vhost-user",
            context,
            worker_bundle_sha256,
        )
        return VerifiedProofSet(
            value=value,
            sha256=proof_file.sha256,
            source_manifest_sha256=release["source_manifest_sha256"],
            source_bundle_sha256=release["source_bundle_sha256"],
            release_manifest_sha256=release["artifact_sha256"],
            qualification_manifest_sha256=release["qualification_manifest_sha256"],
            qualification_catalog_sha256=release["qualification_catalog_sha256"],
            fresh_targets_sha256="sha256:"
            + hashlib.sha256(canonical_json(fresh_targets)).hexdigest(),
            fleet_closed_sha256=fleet_file.sha256,
            route_v2_rotation_qualification_receipt_sha256=route_receipt.sha256,
            route_v2_rotation_qualification_node_ack_sets_sha256=route_acks.sha256,
            route_v2_rotation_qualification_transcript_sha256=route_transcript.sha256,
            usage_terminal_sha256=usage_file.sha256,
            old_host_coverage_sha256=coverage_file.sha256,
            kernel_nbd_qualification_bundle_sha256=kernel_bundle,
            vhost_user_qualification_bundle_sha256=vhost_bundle,
            qualification_terminal_sha256=terminal_file.sha256,
        )
