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
import signal
import stat
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Protocol


PROOF_SET_FILE = "production-cutover-proof-set.v1.json"
PROOF_SET_KIND = "cats.production-cutover-proof-set.v1"
CONTROL_SCHEMA_VERSION = 19
USAGE_TERMINAL_VERIFIER = Path(
    "/opt/cats/bin/cats-usage-terminal-receipt-verifier"
)
USAGE_SCHEMA_VERIFIER = Path("/opt/cats/bin/cats-usage-schema-v16-verifier")
USAGE_SCHEMA_VERIFICATION_FILE = "usage-schema-v16-verification.receipt.json"
USAGE_SCHEMA_VERIFICATION_KIND = "cats.usage-schema-v16-verification.v1"
USAGE_SCHEMA_SUCCESS_STDOUT = "Usage schema v16 verified\n"
USAGE_TERMINAL_REQUEST_FILE = "usage-target-terminal-request.json"
USAGE_TERMINAL_RECEIPT_FILE = "usage-target-terminal-receipt.json"
USAGE_TERMINAL_TARGETS_FILE = "usage-terminal-targets.json"
USAGE_GLOBAL_FINALIZATION_FILE = (
    "usage-global-terminal-finalization.manifest.json"
)
USAGE_GLOBAL_FINALIZATION_KIND = (
    "cats.usage-global-terminal-finalization.v1"
)
USAGE_GLOBAL_CASE_EVIDENCE_FILE = "case-evidence.jsonl"
USAGE_GLOBAL_QUALIFICATION_CATALOG_FILE = "qualification-catalog.v1.json"
USAGE_GLOBAL_SHA256SUMS_FILE = "SHA256SUMS"
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
QUALIFICATION_BEGIN_FILE = (
    "production-mutation-qualification-begin.receipt.json"
)
QUALIFICATION_TERMINAL_FILE = (
    "production-mutation-qualification-terminal.receipt.json"
)
QUALIFICATION_BEGIN_PENDING_FILE = (
    "production-mutation-qualification-begin.pending.json"
)
QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-begin.command-receipt.json"
)
QUALIFICATION_CLOSE_PENDING_FILE = (
    "production-mutation-qualification-close.pending.json"
)
QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-close.command-receipt.json"
)
QUALIFICATION_FINAL_STATE_FILE = (
    "production-mutation-qualification-final-admission-state.json"
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
QUALIFICATION_FINAL_FLEET_KIND = (
    "cats.production-mutation-qualification-final-fleet-closed.v1"
)
QUALIFICATION_CLEANUP_INVENTORY_KIND = (
    "cats.production-mutation-qualification-cleanup-inventory.v1"
)
QUALIFICATION_PRODUCT_INVENTORY_KIND = (
    "cats.production-mutation-qualification-product-inventory.v1"
)
QUALIFICATION_COMPONENT_JOURNAL_FILE = "component-journal-summary.txt"
QUALIFICATION_EXIT_CODE_FILE = "exit-code"
QUALIFICATION_FINAL_INVENTORY_FILE = "final-inventory.json"
QUALIFICATION_RUNTIME_STATE_FILE = "runtime-state.json"
QUALIFICATION_SCENARIO_RESULTS_FILE = "scenario-results.jsonl"
QUALIFICATION_PROOF_LOGICAL_FILES = {
    "manifest": "manifest.json",
    "case_evidence": "case-evidence.jsonl",
    "qualification_catalog": "qualification-catalog.v1.json",
    "sha256sums": "SHA256SUMS",
    "component_journal_summary": QUALIFICATION_COMPONENT_JOURNAL_FILE,
    "exit_code": QUALIFICATION_EXIT_CODE_FILE,
    "final_inventory": QUALIFICATION_FINAL_INVENTORY_FILE,
    "runtime_state": QUALIFICATION_RUNTIME_STATE_FILE,
    "scenario_results": QUALIFICATION_SCENARIO_RESULTS_FILE,
    "qualification_begin": QUALIFICATION_BEGIN_FILE,
    "qualification_terminal": QUALIFICATION_TERMINAL_FILE,
    "qualification_begin_pending": QUALIFICATION_BEGIN_PENDING_FILE,
    "qualification_begin_command_receipt": QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE,
    "qualification_close_pending": QUALIFICATION_CLOSE_PENDING_FILE,
    "qualification_close_command_receipt": QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE,
    "qualification_final_state": QUALIFICATION_FINAL_STATE_FILE,
    "qualification_final_fleet": QUALIFICATION_FINAL_FLEET_FILE,
    "qualification_product_inventory": QUALIFICATION_PRODUCT_INVENTORY_FILE,
    "qualification_cleanup_inventory": QUALIFICATION_CLEANUP_INVENTORY_FILE,
}
USAGE_SOURCE_TERMINAL_SET_KIND = (
    "cats.usage-source-terminal-receipts.v1"
)
ROUTE_V2_ROTATION_CASE_ID = "route-v2-rotation-disable-live-delivery"
ROUTE_V2_ROTATION_RECEIPT_KIND = "route_v2_rotation_terminal_receipt_v1"
ROUTE_V2_NODE_ACK_SET_KIND = "route_v2_node_ring_ack_set_v1"
ROUTE_V2_ROTATION_TRANSCRIPT_KIND = "route_v2_rotation_transcript_v1"
ROUTE_V2_ROTATION_TERMINAL_MARKER = (
    "route_v2_rotation_disable_recovered_active_http_ws"
)
ROUTE_V2_NODE_ACK_TERMINAL_MARKER = (
    "recovery_ring_acked_and_active_routes_reopened"
)
ROUTE_V2_ROTATION_PHASES = (
    "publish_overlap",
    "switch_active",
    "publish_new_only",
    "retire",
    "disable",
    "publish_recovery",
    "activate",
)
ROUTE_V2_ROTATION_CHECKPOINTS = (
    ("publish_overlap", "switch_active", "all_schedulable_nodes_ack_ring"),
    ("publish_new_only", "retire", "all_schedulable_nodes_ack_ring"),
    ("disable", "publish_recovery", "all_provisioned_nodes_closed_or_fenced"),
    (
        "publish_recovery",
        "activate",
        "all_provisioned_nodes_closed_or_fenced_and_ack_ring",
    ),
)
MANUAL_FENCE_EVIDENCE_KIND = "cats.manual-old-host-fence-evidence.v1"
MANUAL_FENCE_EVIDENCE_DECISION = "cutover-decisions-d7-manual-fence"
MANUAL_FENCE_CHECKLIST_FIELDS = {
    "host_fence_event": {
        "instance_stopped",
        "no_running_writers",
        "object_write_cutoff_verified",
        "forensic_artifact_retained",
    },
    "local_positive_stop": {
        "units_stopped",
        "no_running_writers",
        "object_write_cutoff_verified",
        "forensic_artifact_retained",
    },
}
MANUAL_FENCE_COMPONENTS = {"blockd", "controller", "gateway", "node_agent", "vmm"}
MAX_MANUAL_FENCE_EVIDENCE_BYTES = 1024 * 1024
MAX_PROOF_SET_BYTES = 2 * 1024 * 1024
MAX_PROOF_FILE_BYTES = 16 * 1024 * 1024
MAX_VERIFIER_BINARY_BYTES = 256 * 1024 * 1024
FLEET_MAX_AGE_MS = 60_000
PROOF_SET_MAX_AGE_SECONDS = 15 * 60
USAGE_VERIFIER_TIMEOUT_SECONDS = 120

SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
COMMIT = re.compile(r"^[0-9a-f]{40}$")
ACCOUNT = re.compile(r"^[0-9]{12}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
RANDOM_ID = re.compile(r"^[0-9a-f]{32}$")
PROOF_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
AWS_REGION = re.compile(r"^[a-z0-9][a-z0-9-]{1,30}[a-z0-9]$")
CATS_SCHEMA = re.compile(r"^cats_[a-z][a-z0-9_]{0,61}$")
UUID = re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$"
)
EC2_INSTANCE_ID = re.compile(r"^i-[0-9a-f]{8,32}$")
SYSTEMD_UNIT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:_.@-]{0,246}\.service$")
STS_ASSUMED_ROLE = re.compile(
    r"^arn:(aws|aws-us-gov|aws-cn):sts::([0-9]{12}):assumed-role/[^/]+/.+$"
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


def version_one(value: Any) -> bool:
    return type(value) is int and value == 1


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
    release_id: str
    release_commit: str
    release_manifest_sha256: str
    worker_bundle_sha256: str
    usage_schema_verifier_binary_sha256: str
    usage_terminal_verifier_binary_sha256: str
    qualification_manifest_sha256: str
    qualification_catalog_sha256: str
    aws_account_id: str
    aws_region: str
    old_targets: dict[str, Any]
    fresh_targets: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class QualifiedRun:
    block_path: str
    run_id: str
    workspace_id: str
    manifest_sha256: str
    case_evidence_sha256: str
    qualification_terminal_sha256: str
    qualification_completed_at_unix_ms: int
    expected_targets_file_sha256: str
    source_terminal_set_sha256: str
    sources: tuple[tuple[str, str, str], ...]


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
        finalization_manifest: VerifiedFile,
        expected_targets: VerifiedFile,
        receipt: VerifiedFile,
        expected_request: VerifiedFile,
        verification_receipt: VerifiedFile,
        qualified_runs: tuple[QualifiedRun, QualifiedRun],
        context: ProducerContext,
    ) -> None: ...


class HostFenceTerminalVerifier(Protocol):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None: ...


class LocalPositiveStopVerifier(Protocol):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None: ...


class QualificationAdmissionVerifier(Protocol):
    def verify(
        self,
        begin_pending: VerifiedFile,
        begin_command_receipt: VerifiedFile,
        close_pending: VerifiedFile,
        close_command_receipt: VerifiedFile,
        final_state: VerifiedFile,
        context: ProducerContext,
    ) -> None: ...


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
        _finalization_manifest: VerifiedFile,
        _expected_targets: VerifiedFile,
        _receipt: VerifiedFile,
        _expected_request: VerifiedFile,
        _verification_receipt: VerifiedFile,
        _qualified_runs: tuple[QualifiedRun, QualifiedRun],
        _context: ProducerContext,
    ) -> None:
        raise ProofSetError("E9 target-terminal verifier is not wired to its Rust binary")


class _UnavailableHostFenceVerifier:
    def verify(self, _receipt: VerifiedFile, _expected: dict[str, Any]) -> None:
        raise ProofSetError(
            "V3 automatic HostFenceEvent producer/core verifier is not implemented"
            " (DEFERRED.md V3; docs/specs/production-reset-open-authority-v1.md"
            " section 3.4); under CUTOVER-DECISIONS.md D7 manual fencing, supply"
            " operator attestation through the reset tool"
            " --accept-manual-fence-evidence input instead"
        )


class _UnavailableLocalPositiveStopVerifier:
    def verify(self, _receipt: VerifiedFile, _expected: dict[str, Any]) -> None:
        raise ProofSetError(
            "local positive-stop evidence remains Proposed with no accepted"
            " terminal verifier (DEFERRED.md E13;"
            " docs/specs/old-host-positive-stop-v1.md producer"
            " deploy/aws/old-host-positive-stop.py); under CUTOVER-DECISIONS.md"
            " D7 manual fencing, supply operator attestation through the reset"
            " tool --accept-manual-fence-evidence input instead"
        )


class _UnavailableQualificationAdmissionVerifier:
    def verify(
        self,
        _begin_pending: VerifiedFile,
        _begin_command_receipt: VerifiedFile,
        _close_pending: VerifiedFile,
        _close_command_receipt: VerifiedFile,
        _final_state: VerifiedFile,
        _context: ProducerContext,
    ) -> None:
        raise ProofSetError(
            "Qualification admission live-discovery verifier is not wired"
        )


def _require_root_private_directory(path: Path, label: str) -> None:
    if os.geteuid() != 0:
        raise ProofSetError(f"{label} requires the root production operator")
    if not path.is_absolute():
        raise ProofSetError(f"{label} must be an absolute path")
    try:
        if path.resolve(strict=True) != path:
            raise ProofSetError(f"{label} or an ancestor is a symlink")
        metadata = path.stat(follow_symlinks=False)
        for parent in path.parents:
            parent_metadata = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(parent_metadata.st_mode)
                or parent_metadata.st_uid != 0
                or parent_metadata.st_mode & 0o022
            ):
                raise ProofSetError(f"{label} ancestor is not root-controlled")
    except OSError as error:
        raise ProofSetError(f"{label} is unavailable") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != 0
        or metadata.st_mode & 0o077
    ):
        raise ProofSetError(f"{label} must be root-owned mode 0700")


def _open_release_bound_executable(
    path: Path,
    expected_sha256: str,
) -> tuple[int, _FileIdentity]:
    if not path.is_absolute() or path not in {
        USAGE_SCHEMA_VERIFIER,
        USAGE_TERMINAL_VERIFIER,
    }:
        raise ProofSetError("Usage verifier path is not canonical")
    try:
        if path.resolve(strict=True) != path:
            raise ProofSetError("Usage verifier path contains a symlink")
        for parent in path.parents:
            metadata = parent.stat(follow_symlinks=False)
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or metadata.st_uid != 0
                or metadata.st_mode & 0o022
            ):
                raise ProofSetError(
                    "Usage verifier ancestor is not root-controlled"
                )
    except OSError as error:
        raise ProofSetError("Usage verifier path is unavailable") from error
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(
        os, "O_NOFOLLOW", 0
    )
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ProofSetError("Usage verifier cannot be opened") from error
    try:
        identity = _FileIdentity.from_stat(os.fstat(descriptor))
        if (
            not stat.S_ISREG(identity.mode)
            or identity.uid != 0
            or identity.links != 1
            or identity.mode & 0o022
            or not identity.mode & 0o111
            or identity.size <= 0
            or identity.size > MAX_VERIFIER_BINARY_BYTES
        ):
            raise ProofSetError("Usage verifier metadata is unsafe")
        if _hash_open_descriptor(descriptor, identity) != expected_sha256:
            raise ProofSetError("Usage verifier differs from the release")
        return descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _hash_open_descriptor(descriptor: int, identity: _FileIdentity) -> str:
    try:
        os.lseek(descriptor, 0, os.SEEK_SET)
        hasher = hashlib.sha256()
        remaining = identity.size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1024 * 1024))
            if not chunk:
                raise ProofSetError("Usage verifier changed during hashing")
            hasher.update(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise ProofSetError("Usage verifier grew during hashing")
        if _FileIdentity.from_stat(os.fstat(descriptor)) != identity:
            raise ProofSetError("Usage verifier changed during hashing")
        return "sha256:" + hasher.hexdigest()
    except OSError as error:
        raise ProofSetError("Usage verifier cannot be hashed") from error


def _write_private_staged_file(path: Path, data: bytes) -> None:
    flags = (
        os.O_WRONLY
        | os.O_CREAT
        | os.O_EXCL
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(path, flags, 0o600)
    except OSError as error:
        raise ProofSetError("cannot create the private E9 verifier input") from error
    try:
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise ProofSetError("cannot write the private E9 verifier input")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _terminate_subprocess(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is None:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    process.wait()


def _run_held_usage_verifier(
    argv: list[str],
    binary_descriptor: int,
    *,
    cwd: Path,
    timeout_seconds: int,
) -> tuple[int, bytes, bytes]:
    try:
        process = subprocess.Popen(
            argv,
            executable=f"/proc/self/fd/{binary_descriptor}",
            pass_fds=(binary_descriptor,),
            close_fds=True,
            cwd=cwd,
            env={"LANG": "C", "LC_ALL": "C", "PATH": "/usr/bin:/bin"},
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as error:
        raise ProofSetError("cannot execute the release-bound Usage verifier") from error
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
    except subprocess.TimeoutExpired as error:
        _terminate_subprocess(process)
        raise ProofSetError("release-bound Usage verifier timed out") from error
    except BaseException:
        _terminate_subprocess(process)
        raise
    return process.returncode, stdout, stderr


def _revalidate_release_bound_executable(
    path: Path,
    descriptor: int,
    identity: _FileIdentity,
    expected_sha256: str,
) -> None:
    try:
        path_identity = _FileIdentity.from_stat(path.stat(follow_symlinks=False))
        descriptor_identity = _FileIdentity.from_stat(os.fstat(descriptor))
    except OSError as error:
        raise ProofSetError(
            "Usage verifier identity is unavailable after execution"
        ) from error
    if (
        path_identity != identity
        or descriptor_identity != identity
        or _hash_open_descriptor(descriptor, identity) != expected_sha256
    ):
        raise ProofSetError("Usage verifier changed during execution")


class SubprocessUsageTargetTerminalVerifier:
    """Invoke the exact release-bound Rust E9 verifier in a private directory."""

    def __init__(
        self,
        state_directory: Path,
        *,
        timeout_seconds: int = USAGE_VERIFIER_TIMEOUT_SECONDS,
    ) -> None:
        if (
            type(timeout_seconds) is not int
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ProofSetError("E9 terminal verifier timeout is outside 1..300")
        self._state_directory = state_directory
        self._timeout_seconds = timeout_seconds

    def verify(
        self,
        _finalization_manifest: VerifiedFile,
        expected_targets: VerifiedFile,
        receipt: VerifiedFile,
        expected_request: VerifiedFile,
        verification_receipt: VerifiedFile,
        _qualified_runs: tuple[QualifiedRun, QualifiedRun],
        context: ProducerContext,
    ) -> None:
        _require_root_private_directory(
            self._state_directory,
            "E9 terminal verifier state directory",
        )
        binary_descriptor, binary_identity = _open_release_bound_executable(
            USAGE_TERMINAL_VERIFIER,
            context.usage_terminal_verifier_binary_sha256,
        )
        invocation: Path | None = None
        try:
            try:
                invocation = Path(
                    tempfile.mkdtemp(
                        prefix=".usage-terminal-verifier.",
                        dir=self._state_directory,
                    )
                )
            except OSError as error:
                raise ProofSetError(
                    "cannot create the private E9 verifier invocation directory"
                ) from error
            receipt_path = invocation / USAGE_TERMINAL_RECEIPT_FILE
            request_path = invocation / USAGE_TERMINAL_REQUEST_FILE
            targets_path = invocation / USAGE_TERMINAL_TARGETS_FILE
            output_path = invocation / USAGE_TERMINAL_VERIFICATION_FILE
            _write_private_staged_file(receipt_path, receipt.data)
            _write_private_staged_file(request_path, expected_request.data)
            _write_private_staged_file(targets_path, expected_targets.data)
            directory_descriptor = os.open(
                invocation,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_DIRECTORY", 0),
            )
            try:
                os.fsync(directory_descriptor)
            finally:
                os.close(directory_descriptor)
            argv = [
                str(USAGE_TERMINAL_VERIFIER),
                "--receipt-file",
                str(receipt_path),
                "--expected-request-file",
                str(request_path),
                "--expected-targets-file",
                str(targets_path),
                "--expected-targets-sha256",
                expected_targets.sha256,
                "--release-commit",
                context.release_commit,
                "--worker-bundle-sha256",
                context.worker_bundle_sha256,
                "--receipt-out",
                str(output_path),
            ]
            returncode, stdout, stderr = _run_held_usage_verifier(
                argv,
                binary_descriptor,
                cwd=invocation,
                timeout_seconds=self._timeout_seconds,
            )
            if (
                returncode != 0
                or stdout != USAGE_TERMINAL_SUCCESS_STDOUT.encode("ascii")
                or stderr
            ):
                raise ProofSetError("E9 terminal verifier rejected the proof")
            _revalidate_release_bound_executable(
                USAGE_TERMINAL_VERIFIER,
                binary_descriptor,
                binary_identity,
                context.usage_terminal_verifier_binary_sha256,
            )
            try:
                output_metadata = output_path.stat(follow_symlinks=False)
            except OSError as error:
                raise ProofSetError("E9 terminal verifier emitted no receipt") from error
            if (
                not stat.S_ISREG(output_metadata.st_mode)
                or output_path.is_symlink()
                or output_metadata.st_uid != os.geteuid()
                or output_metadata.st_nlink != 1
                or stat.S_IMODE(output_metadata.st_mode) not in {0o400, 0o600}
            ):
                raise ProofSetError("E9 terminal verifier receipt metadata is unsafe")
            with ProofDirectory(invocation) as directory:
                actual = directory.read_named(
                    USAGE_TERMINAL_VERIFICATION_FILE,
                    "E9 terminal verifier emitted receipt",
                    MAX_PROOF_FILE_BYTES,
                )
            if actual != verification_receipt:
                raise ProofSetError(
                    "E9 terminal verifier receipt differs from the proof set"
                )
        finally:
            os.close(binary_descriptor)
            if invocation is not None:
                expected_names = {
                    USAGE_TERMINAL_RECEIPT_FILE,
                    USAGE_TERMINAL_REQUEST_FILE,
                    USAGE_TERMINAL_TARGETS_FILE,
                    USAGE_TERMINAL_VERIFICATION_FILE,
                }
                try:
                    actual_names = {entry.name for entry in os.scandir(invocation)}
                    if actual_names.issubset(expected_names):
                        for name in actual_names:
                            (invocation / name).unlink()
                        invocation.rmdir()
                        parent_descriptor = os.open(
                            self._state_directory,
                            os.O_RDONLY
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_DIRECTORY", 0),
                        )
                        try:
                            os.fsync(parent_descriptor)
                        finally:
                            os.close(parent_descriptor)
                except OSError:
                    # Failure leaves a root-only invocation directory for diagnosis.
                    pass


class SubprocessUsageSchemaV16Verifier:
    """Verify the fresh Usage schema through the exact installed Rust binary."""

    def __init__(
        self,
        state_directory: Path,
        *,
        timeout_seconds: int = USAGE_VERIFIER_TIMEOUT_SECONDS,
    ) -> None:
        if (
            type(timeout_seconds) is not int
            or timeout_seconds <= 0
            or timeout_seconds > 300
        ):
            raise ProofSetError("Usage schema verifier timeout is outside 1..300")
        self._state_directory = state_directory
        self._timeout_seconds = timeout_seconds

    def verify(
        self,
        *,
        dsn_file: Path,
        ca_file: Path,
        schema: str,
        context: ProducerContext,
    ) -> VerifiedFile:
        _require_root_private_directory(
            self._state_directory,
            "Usage schema verifier state directory",
        )
        if (
            not dsn_file.is_absolute()
            or not ca_file.is_absolute()
            or CATS_SCHEMA.fullmatch(schema) is None
        ):
            raise ProofSetError("Usage schema verifier inputs are not canonical")
        receipt_path = self._state_directory / USAGE_SCHEMA_VERIFICATION_FILE
        binary_descriptor, binary_identity = _open_release_bound_executable(
            USAGE_SCHEMA_VERIFIER,
            context.usage_schema_verifier_binary_sha256,
        )
        try:
            argv = [
                str(USAGE_SCHEMA_VERIFIER),
                "--dsn-file",
                str(dsn_file),
                "--ca-file",
                str(ca_file),
                "--schema",
                schema,
                "--release-commit",
                context.release_commit,
                "--worker-bundle-sha256",
                context.worker_bundle_sha256,
                "--receipt-out",
                str(receipt_path),
            ]
            returncode, stdout, stderr = _run_held_usage_verifier(
                argv,
                binary_descriptor,
                cwd=self._state_directory,
                timeout_seconds=self._timeout_seconds,
            )
            if (
                returncode != 0
                or stdout != USAGE_SCHEMA_SUCCESS_STDOUT.encode("ascii")
                or stderr
            ):
                raise ProofSetError("Usage schema verifier rejected the fresh schema")
            _revalidate_release_bound_executable(
                USAGE_SCHEMA_VERIFIER,
                binary_descriptor,
                binary_identity,
                context.usage_schema_verifier_binary_sha256,
            )
            try:
                output_metadata = receipt_path.stat(follow_symlinks=False)
            except OSError as error:
                raise ProofSetError("Usage schema verifier emitted no receipt") from error
            if (
                not stat.S_ISREG(output_metadata.st_mode)
                or receipt_path.is_symlink()
                or output_metadata.st_uid != os.geteuid()
                or output_metadata.st_nlink != 1
                or stat.S_IMODE(output_metadata.st_mode) != 0o600
            ):
                raise ProofSetError("Usage schema verifier receipt metadata is unsafe")
            with ProofDirectory(self._state_directory) as directory:
                actual = directory.read_named(
                    USAGE_SCHEMA_VERIFICATION_FILE,
                    "Usage schema verification receipt",
                    MAX_PROOF_FILE_BYTES,
                )
            value = fields(
                decode_json(
                    actual.data,
                    "Usage schema verification receipt",
                    canonical_lf=True,
                ),
                {
                    "binary_sha256",
                    "catalog_sha256",
                    "kind",
                    "release_commit",
                    "schema",
                    "schema_version",
                    "verified",
                    "version",
                    "worker_bundle_sha256",
                },
                "Usage schema verification receipt",
            )
            if (
                value["binary_sha256"]
                != context.usage_schema_verifier_binary_sha256
                or value["kind"] != USAGE_SCHEMA_VERIFICATION_KIND
                or value["release_commit"] != context.release_commit
                or value["schema"] != schema
                or type(value["schema_version"]) is not int
                or value["schema_version"] != 16
                or value["verified"] is not True
                or not version_one(value["version"])
                or value["worker_bundle_sha256"] != context.worker_bundle_sha256
            ):
                raise ProofSetError("Usage schema verification receipt drifted")
            digest(value["catalog_sha256"], "Usage schema catalog digest")
            return actual
        finally:
            os.close(binary_descriptor)


class RouteV2RotationQualificationEvidenceVerifier:
    """Reviewed G3 typed verifier over the three exact rotation evidence files.

    The producer is a release-bound dedicated qualification cell. This adapter
    validates the terminal receipt, the Node ring-ACK set and the transcript as one
    bound terminal set: exact kinds and case identity, exact release/catalog
    binding, the closed seven-phase signed command chain, both closed
    disable/recovery checkpoints, the recovered fresh-endpoint proof and the
    exact node-acks/transcript digests named by the receipt.  It does not
    accept a single phase receipt, a provisional template or AWS rollout
    detail as terminal qualification evidence.
    """

    def verify(
        self,
        receipt: VerifiedFile,
        node_acks: VerifiedFile,
        transcript: VerifiedFile,
        context: ProducerContext,
    ) -> None:
        value = fields(
            decode_json(receipt.data, "G3 rotation terminal receipt"),
            {
                "version",
                "kind",
                "case_id",
                "qualification_run_id",
                "source_commit_sha",
                "qualification_catalog_sha256",
                "authority_id",
                "route_deployment_id",
                "rotation_operator_trust_sha256",
                "command_bundle_sha256",
                "recovery_transport_sha256",
                "phase_receipts",
                "disabled_checkpoint",
                "recovery_checkpoint",
                "fresh_endpoint",
                "node_acks_sha256",
                "transcript_sha256",
                "terminal_marker",
            },
            "G3 rotation terminal receipt",
        )
        if (
            not version_one(value["version"])
            or value["kind"] != ROUTE_V2_ROTATION_RECEIPT_KIND
            or value["case_id"] != ROUTE_V2_ROTATION_CASE_ID
            or value["source_commit_sha"] != context.release_commit
            or value["qualification_catalog_sha256"]
            != context.qualification_catalog_sha256
            or value["terminal_marker"] != ROUTE_V2_ROTATION_TERMINAL_MARKER
        ):
            raise ProofSetError(
                "G3 rotation terminal receipt is not the exact-release closed case"
            )
        run_id = identifier(value["qualification_run_id"], "G3 rotation run ID")
        identifier(value["authority_id"], "G3 rotation authority ID")
        deployment_id = identifier(
            value["route_deployment_id"], "G3 rotation Route deployment ID"
        )
        for name in (
            "rotation_operator_trust_sha256",
            "command_bundle_sha256",
            "recovery_transport_sha256",
        ):
            digest(value[name], f"G3 rotation {name}")
        if (
            value["node_acks_sha256"] != node_acks.sha256
            or value["transcript_sha256"] != transcript.sha256
        ):
            raise ProofSetError(
                "G3 rotation receipt does not bind the exact node-acks/transcript files"
            )
        phases = value["phase_receipts"]
        if (
            not isinstance(phases, list)
            or len(phases) != len(ROUTE_V2_ROTATION_PHASES)
            or any(not isinstance(phase, dict) for phase in phases)
            or [phase.get("phase") for phase in phases]
            != list(ROUTE_V2_ROTATION_PHASES)
        ):
            raise ProofSetError(
                "G3 rotation receipt is not the exact seven-phase command chain"
            )
        disabled = fields(
            value["disabled_checkpoint"],
            {
                "signer_revision",
                "ring_version",
                "signer_state",
                "loaded_kids",
                "public_route_closed",
                "public_route_closed_observation_count",
                "disabled_public_route_sha256",
                "all_nodes_closed_or_fenced",
                "active_guard_count",
                "disabled_fleet_sha256",
                "disable_store_receipt_sha256",
                "closed_fleet_settlement_store_receipt_sha256",
            },
            "G3 disabled checkpoint",
        )
        if (
            disabled["signer_state"] != "disabled"
            or disabled["loaded_kids"] != []
            or disabled["public_route_closed"] is not True
            or disabled["public_route_closed_observation_count"] != 3
            or isinstance(disabled["public_route_closed_observation_count"], bool)
            or disabled["all_nodes_closed_or_fenced"] is not True
        ):
            raise ProofSetError("G3 disabled checkpoint is not a closed disable proof")
        integer(disabled["signer_revision"], "G3 disabled signer revision", minimum=1)
        integer(disabled["ring_version"], "G3 disabled ring version", minimum=1)
        _zero(disabled["active_guard_count"], "G3 disabled active guards")
        for name in (
            "disabled_public_route_sha256",
            "disabled_fleet_sha256",
            "disable_store_receipt_sha256",
            "closed_fleet_settlement_store_receipt_sha256",
        ):
            digest(disabled[name], f"G3 disabled {name}")
        recovery = fields(
            value["recovery_checkpoint"],
            {
                "signer_revision",
                "ring_version",
                "signer_state",
                "active_kid",
                "database_current",
                "process_ready",
                "all_nodes_acknowledged",
                "all_active_guards_zero",
                "terminal_fleet_sha256",
            },
            "G3 recovery checkpoint",
        )
        if (
            recovery["signer_state"] != "active"
            or recovery["database_current"] is not True
            or recovery["process_ready"] is not True
            or recovery["all_nodes_acknowledged"] is not True
            or recovery["all_active_guards_zero"] is not True
        ):
            raise ProofSetError("G3 recovery checkpoint is not a closed active recovery")
        recovery_revision = integer(
            recovery["signer_revision"], "G3 recovery signer revision", minimum=1
        )
        recovery_ring = integer(
            recovery["ring_version"], "G3 recovery ring version", minimum=1
        )
        if (
            recovery_revision <= integer(
                disabled["signer_revision"], "G3 disabled signer revision", minimum=1
            )
            or recovery_ring <= integer(
                disabled["ring_version"], "G3 disabled ring version", minimum=1
            )
        ):
            raise ProofSetError("G3 recovery did not advance the disabled signer/ring")
        identifier(recovery["active_kid"], "G3 recovery active kid")
        digest(recovery["terminal_fleet_sha256"], "G3 recovery terminal fleet")
        endpoint = fields(
            value["fresh_endpoint"],
            {
                "mechanism",
                "calibrated_baseline_public_route_sha256",
                "lineage_receipt_sha256",
                "old_endpoint",
                "unbind",
                "fresh_endpoint",
                "bind",
                "pre_probe_collection_sha256",
                "public_route_receipt_sha256",
                "http_guest_body",
                "websocket_guest_echo",
            },
            "G3 fresh-endpoint proof",
        )
        if (
            endpoint["mechanism"] != "unbind_old_bind_fresh_endpoint"
            or endpoint["http_guest_body"] is not True
            or endpoint["websocket_guest_echo"] is not True
            or not isinstance(endpoint["old_endpoint"], dict)
            or not isinstance(endpoint["fresh_endpoint"], dict)
            or not isinstance(endpoint["unbind"], dict)
            or not isinstance(endpoint["bind"], dict)
        ):
            raise ProofSetError("G3 fresh-endpoint proof is not a closed live delivery")
        for name in (
            "calibrated_baseline_public_route_sha256",
            "lineage_receipt_sha256",
            "pre_probe_collection_sha256",
            "public_route_receipt_sha256",
        ):
            digest(endpoint[name], f"G3 fresh-endpoint {name}")
        old_endpoint = endpoint["old_endpoint"]
        fresh_endpoint = endpoint["fresh_endpoint"]
        for label, item in (("old", old_endpoint), ("fresh", fresh_endpoint)):
            for name in ("endpoint_id", "name", "hostname"):
                if not isinstance(item.get(name), str) or not item[name]:
                    raise ProofSetError(
                        f"G3 {label} endpoint identity field {name} is incomplete"
                    )
        if (
            fresh_endpoint["endpoint_id"] == old_endpoint["endpoint_id"]
            or fresh_endpoint["hostname"] != old_endpoint["hostname"]
            or fresh_endpoint.get("route_epoch") != 1
            or isinstance(fresh_endpoint.get("route_epoch"), bool)
        ):
            raise ProofSetError(
                "G3 fresh endpoint is not a fresh epoch-one identity on the old hostname"
            )

        acks = fields(
            decode_json(node_acks.data, "G3 Node ring-ACK set"),
            {
                "version",
                "kind",
                "case_id",
                "qualification_run_id",
                "source_commit_sha",
                "route_deployment_id",
                "expected_nodes",
                "disabled_fleet_sha256",
                "disabled_evaluated_at_unix_ms",
                "disabled_nodes",
                "disabled_all_nodes_closed_or_fenced",
                "checkpoints",
                "terminal_fleet_sha256",
                "terminal_evaluated_at_unix_ms",
                "terminal_signing_authority",
                "terminal_nodes",
                "all_nodes_acknowledged",
                "all_active_guards_zero",
                "terminal_marker",
            },
            "G3 Node ring-ACK set",
        )
        if (
            not version_one(acks["version"])
            or acks["kind"] != ROUTE_V2_NODE_ACK_SET_KIND
            or acks["case_id"] != ROUTE_V2_ROTATION_CASE_ID
            or acks["qualification_run_id"] != run_id
            or acks["source_commit_sha"] != context.release_commit
            or acks["route_deployment_id"] != deployment_id
            or acks["terminal_marker"] != ROUTE_V2_NODE_ACK_TERMINAL_MARKER
            or acks["disabled_all_nodes_closed_or_fenced"] is not True
            or acks["all_nodes_acknowledged"] is not True
            or acks["all_active_guards_zero"] is not True
        ):
            raise ProofSetError("G3 Node ring-ACK set is not the receipt's closed run")
        if (
            acks["disabled_fleet_sha256"] != disabled["disabled_fleet_sha256"]
            or acks["terminal_fleet_sha256"] != recovery["terminal_fleet_sha256"]
        ):
            raise ProofSetError("G3 Node ring-ACK fleet digests differ from the receipt")
        expected_nodes = acks["expected_nodes"]
        if (
            not isinstance(expected_nodes, list)
            or not expected_nodes
            or expected_nodes != sorted(set(expected_nodes))
        ):
            raise ProofSetError("G3 expected Node set is not strict sorted nonempty")
        for node_id in expected_nodes:
            identifier(node_id, "G3 expected Node ID")
        integer(
            acks["disabled_evaluated_at_unix_ms"],
            "G3 disabled evaluation time",
            minimum=1,
        )
        integer(
            acks["terminal_evaluated_at_unix_ms"],
            "G3 terminal evaluation time",
            minimum=1,
        )
        signer = fields(
            acks["terminal_signing_authority"],
            {
                "deployment_id",
                "signer_revision",
                "signer_reference_sha256",
                "active_kid",
                "public_key_ring_version",
                "public_key_ring_digest",
            },
            "G3 terminal signing authority",
        )
        if (
            signer["deployment_id"] != deployment_id
            or signer["signer_revision"] != recovery_revision
            or signer["active_kid"] != recovery["active_kid"]
            or signer["public_key_ring_version"] != recovery_ring
        ):
            raise ProofSetError(
                "G3 terminal signing authority differs from the recovery checkpoint"
            )
        digest(signer["signer_reference_sha256"], "G3 terminal signer reference")
        digest(signer["public_key_ring_digest"], "G3 terminal ring digest")
        checkpoints = acks["checkpoints"]
        if not isinstance(checkpoints, list) or len(checkpoints) != len(
            ROUTE_V2_ROTATION_CHECKPOINTS
        ):
            raise ProofSetError("G3 ring-ACK checkpoints are not the exact four gates")
        for index, expected in enumerate(ROUTE_V2_ROTATION_CHECKPOINTS):
            checkpoint = fields(
                checkpoints[index],
                {
                    "observed_phase",
                    "signer_revision",
                    "ring_version",
                    "ring_digest",
                    "loaded_kids",
                    "settled_by_phase",
                    "required_store_precondition",
                    "settled_by_store_receipt_sha256",
                    "settled_at_unix_ms",
                    "precondition",
                    "store_precondition_satisfied",
                },
                f"G3 ring-ACK checkpoint {index}",
            )
            precondition = checkpoint["precondition"]
            if (
                (
                    checkpoint["observed_phase"],
                    checkpoint["settled_by_phase"],
                    checkpoint["required_store_precondition"],
                )
                != expected
                or checkpoint["store_precondition_satisfied"] is not True
                or not isinstance(precondition, dict)
                or precondition.get("satisfied") is not True
            ):
                raise ProofSetError(
                    f"G3 ring-ACK checkpoint {index} is not its settled Store gate"
                )
            digest(
                checkpoint["settled_by_store_receipt_sha256"],
                f"G3 checkpoint {index} Store receipt",
            )
            integer(
                checkpoint["settled_at_unix_ms"],
                f"G3 checkpoint {index} settlement time",
                minimum=1,
            )
        for label, entries in (
            ("disabled", acks["disabled_nodes"]),
            ("terminal", acks["terminal_nodes"]),
        ):
            if not isinstance(entries, list) or [
                entry.get("node_id")
                for entry in entries
                if isinstance(entry, dict)
            ] != expected_nodes:
                raise ProofSetError(
                    f"G3 {label} Node projection differs from the expected Node set"
                )
            for entry in entries:
                entry = fields(
                    entry, {"node_id", "binding", "inventory"}, f"G3 {label} Node"
                )
                inventory = entry["inventory"]
                if (
                    not isinstance(entry["binding"], dict)
                    or not isinstance(inventory, dict)
                    or inventory.get("complete_inventory") is not True
                ):
                    raise ProofSetError(f"G3 {label} Node inventory is partial")
                _zero(
                    inventory.get("active_guard_count"),
                    f"G3 {label} Node active guards",
                )
                _zero(inventory.get("residue_count"), f"G3 {label} Node residue")
                if label == "disabled":
                    _zero(
                        inventory.get("route_active_count"),
                        "G3 disabled Node active routes",
                    )

        try:
            transcript_text = transcript.data.decode("utf-8")
        except UnicodeDecodeError as error:
            raise ProofSetError("G3 rotation transcript is not UTF-8 text") from error
        if not transcript_text.endswith("\n"):
            raise ProofSetError("G3 rotation transcript has no terminal LF")
        lines = transcript_text.splitlines()
        expected_header = (
            f"version=1 kind={ROUTE_V2_ROTATION_TRANSCRIPT_KIND}"
            f" case_id={ROUTE_V2_ROTATION_CASE_ID}"
            f" qualification_run_id={run_id}"
            f" source_commit_sha={context.release_commit}"
        )
        if not lines or lines[0] != expected_header:
            raise ProofSetError("G3 rotation transcript header is not this exact run")
        markers = [
            line
            for line in lines
            if line == f"terminal_marker={ROUTE_V2_ROTATION_TERMINAL_MARKER}"
        ]
        if len(markers) != 1:
            raise ProofSetError(
                "G3 rotation transcript has no single terminal marker line"
            )


class QualificationAdmissionEvidenceVerifier:
    """Validate the staged Begin/close admission chain with the operator tool.

    The producer is ``deploy/aws/production-mutation-admission.py``.  This
    adapter reuses that module's own reviewed validators (``validate_trust``,
    ``validate_command``, ``validate_state``, ``command_state_binding``); it
    is a consumer of the producer's implementation, not a second authority.
    It proves that both pending commands are the exact canonical signed
    requests under the reset's release-bound cutover trust, that both command
    receipts bind those exact commands and the same STS principal, that Begin
    installed Qualification and close installed the exact Closed successor,
    and that the staged final admission state is byte-exact the close
    receipt's applied state.
    """

    def __init__(self, admission_module: Any, trust_data: bytes) -> None:
        for name in (
            "AdmissionError",
            "validate_trust",
            "validate_command",
            "validate_state",
            "command_plain_binding",
            "command_state_binding",
        ):
            if not hasattr(admission_module, name):
                raise ProofSetError(
                    "Qualification admission verifier requires the reviewed"
                    " production-mutation-admission operator module"
                )
        self._admission = admission_module
        self._trust_data = trust_data

    def verify(
        self,
        begin_pending: VerifiedFile,
        begin_command_receipt: VerifiedFile,
        close_pending: VerifiedFile,
        close_command_receipt: VerifiedFile,
        final_state: VerifiedFile,
        context: ProducerContext,
    ) -> None:
        admission = self._admission
        try:
            trust, credential = admission.validate_trust(
                admission.decode_json(
                    self._trust_data, "production cutover operator trust"
                )
            )
            if (
                admission.canonical_json(trust) != self._trust_data
                or trust["release_id"] != context.release_id
                or trust["source_commit_sha"] != context.release_commit
            ):
                raise ProofSetError(
                    "Qualification admission trust is outside the reset release"
                )
            begin_body, begin_command = self._pending_command(
                begin_pending,
                "Qualification Begin pending command",
                trust,
                credential,
                "begin_qualification",
            )
            close_body, close_command = self._pending_command(
                close_pending,
                "Qualification close pending command",
                trust,
                credential,
                "end_qualification",
            )
            begin_state = self._command_receipt(
                begin_command_receipt,
                "Qualification Begin command receipt",
                begin_command,
                begin_body,
                begin_pending,
                "qualification",
            )
            close_state = self._command_receipt(
                close_command_receipt,
                "Qualification close command receipt",
                close_command,
                close_body,
                close_pending,
                "closed",
            )
            binding = admission.command_plain_binding(begin_command)
            if (
                close_command["mutation"]["binding"] != binding
                or close_command["command_id"] == begin_command["command_id"]
                or close_command["operator"] != begin_command["operator"]
                or close_command["expected_revision"] != begin_state["revision"]
                or close_state["revision"] != begin_state["revision"] + 1
            ):
                raise ProofSetError(
                    "Qualification close is not the exact Begin successor command"
                )
            if (
                binding["release_id"] != context.release_id
                or binding["source_commit_sha"] != context.release_commit
                or binding["release_manifest_sha256"]
                != context.release_manifest_sha256
                or binding["worker_bundle_sha256"] != context.worker_bundle_sha256
                or binding["qualification_catalog_sha256"]
                != context.qualification_catalog_sha256
            ):
                raise ProofSetError(
                    "Qualification admission binding is outside the reset release"
                )
            if final_state.data != admission.canonical_json(close_state):
                raise ProofSetError(
                    "final admission state is not the close receipt's applied state"
                )
        except admission.AdmissionError as error:
            raise ProofSetError(
                "Qualification admission evidence failed the operator-tool validators"
            ) from error

    def _pending_command(
        self,
        pending_file: VerifiedFile,
        label: str,
        trust: dict[str, Any],
        credential: dict[str, Any],
        expected_mutation: str,
    ) -> tuple[bytes, dict[str, Any]]:
        admission = self._admission
        pending = admission.require_fields(
            admission.decode_json(pending_file.data, label),
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
            label,
        )
        if admission.canonical_json(pending, newline=True) != pending_file.data:
            raise ProofSetError(f"{label} is not canonical")
        if (
            not admission.version_one(pending["version"])
            or pending["method"] != "POST"
            or pending["target"] != admission.COMMAND_PATH
            or pending["discovery_target"] != admission.DISCOVERY_PATH
            or pending["state_target"] != admission.STATE_PATH
        ):
            raise ProofSetError(f"{label} has an unsupported request binding")
        admission.validate_origin(pending["origin"])
        if (
            pending["trust_sha256"] != admission.sha256(self._trust_data)
            or pending["credential_id"] != credential["credential_id"]
            or pending["public_key_spki_sha256"]
            != admission.sha256(
                admission.decode_base64url(
                    credential["public_key_spki"], "public_key_spki"
                )
            )
        ):
            raise ProofSetError(f"{label} is outside the reset cutover trust")
        body = admission.decode_base64url(pending["body_base64"], f"{label} body")
        command = admission.validate_command(
            admission.decode_json(body, f"{label} body")
        )
        if (
            admission.canonical_json(command) != body
            or admission.sha256(body) != pending["request_sha256"]
        ):
            raise ProofSetError(f"{label} body is not its exact canonical request")
        if command["mutation"]["kind"] != expected_mutation:
            raise ProofSetError(f"{label} is not one exact {expected_mutation} command")
        plain_binding = admission.command_plain_binding(command)
        scope = credential["scope"]
        if (
            plain_binding["deployment_id"] != trust["deployment_id"]
            or plain_binding["release_id"] != trust["release_id"]
            or plain_binding["source_commit_sha"] != trust["source_commit_sha"]
            or command["operator"]["aws_partition"] != scope["aws_partition"]
            or command["operator"]["account_id"] != scope["account_id"]
            or command["operator"]["role_arn"] != scope["role_arn"]
        ):
            raise ProofSetError(f"{label} drifted from its trust scope")
        if len(admission.decode_base64url(pending["signature"], f"{label} signature")) != 64:
            raise ProofSetError(f"{label} signature is not Ed25519")
        return body, command

    def _command_receipt(
        self,
        receipt_file: VerifiedFile,
        label: str,
        command: dict[str, Any],
        body: bytes,
        pending_file: VerifiedFile,
        expected_mode: str,
    ) -> dict[str, Any]:
        admission = self._admission
        pending = admission.decode_json(pending_file.data, f"{label} pending")
        receipt = admission.require_fields(
            admission.decode_json(receipt_file.data, label),
            {
                "version",
                "command",
                "request_sha256",
                "principal",
                "outcome",
                "committed_at_unix_ms",
            },
            label,
        )
        if admission.canonical_json(receipt) != receipt_file.data:
            raise ProofSetError(f"{label} is not canonical")
        if (
            not admission.version_one(receipt["version"])
            or receipt["command"] != command
            or receipt["request_sha256"] != admission.sha256(body)
        ):
            raise ProofSetError(f"{label} does not bind the exact pending command")
        principal = admission.require_fields(
            receipt["principal"],
            {"credential_id", "public_key_spki_sha256", "trust_bundle_sha256", "sts"},
            f"{label} principal",
        )
        if (
            principal["credential_id"] != pending["credential_id"]
            or principal["public_key_spki_sha256"]
            != pending["public_key_spki_sha256"]
            or principal["trust_bundle_sha256"] != pending["trust_sha256"]
            or principal["sts"] != command["operator"]
        ):
            raise ProofSetError(f"{label} principal does not bind the signed STS claim")
        outcome = receipt["outcome"]
        if not isinstance(outcome, dict) or outcome.get("kind") != "applied":
            raise ProofSetError(f"{label} did not reach the Applied outcome")
        admission.require_fields(outcome, {"kind", "state"}, f"{label} outcome")
        state = admission.validate_state(outcome["state"])
        if (
            state["mode"] != expected_mode
            or state["revision"] != command["expected_revision"] + 1
            or state["last_command_id"] != command["command_id"]
            or state["binding"] != admission.command_state_binding(command)
            or state["updated_at_unix_ms"] != receipt["committed_at_unix_ms"]
        ):
            raise ProofSetError(f"{label} has a mismatched applied successor state")
        return state


class _ManualFenceEntryVerifier:
    """Shared lookup for operator manual-fence attestation entries."""

    def __init__(
        self,
        entries: dict[str, dict[str, Any]],
        terminal_kind: str,
    ) -> None:
        self._entries = entries
        self._terminal_kind = terminal_kind

    def _entry(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None:
        host_id = expected.get("host_id")
        entry = self._entries.get(host_id) if isinstance(host_id, str) else None
        if entry is None or entry["terminal_kind"] != self._terminal_kind:
            raise ProofSetError(
                f"manual fence evidence has no {self._terminal_kind} attestation"
                " for this old Host"
            )
        if entry["components"] != expected.get("components"):
            raise ProofSetError(
                "manual fence attestation component set differs from old Host coverage"
            )
        if self._terminal_kind == "host_fence_event" and entry[
            "event_id"
        ] != expected.get("event_id"):
            raise ProofSetError(
                "manual fence attestation event ID differs from old Host coverage"
            )
        if entry["receipt_sha256"] != receipt.sha256:
            raise ProofSetError(
                "manual fence attestation does not bind this exact staged receipt"
            )


class _ManualHostFenceVerifier(_ManualFenceEntryVerifier):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None:
        self._entry(receipt, expected)


class _ManualLocalPositiveStopVerifier(_ManualFenceEntryVerifier):
    def verify(self, receipt: VerifiedFile, expected: dict[str, Any]) -> None:
        self._entry(receipt, expected)


class ManualOperatorFenceEvidence:
    """CUTOVER-DECISIONS.md D7 operator manual fence/stop attestation.

    V1 has no automatic HostFenceEvent producer and the local positive-stop
    contract remains Proposed (DEFERRED.md V3/E13).  Under decision D7 the
    operator fences old Hosts manually (EC2 stop plus console/CLI forensics,
    or manual systemd stop) and submits the fence facts.  This class is reset
    tool **input validation only**: it validates the operator-supplied
    attestation for completeness (who, when, EC2 stop evidence or stopped
    units, an all-true checklist, and an exact digest binding to each staged
    forensic receipt) and then admits the matching old-Host coverage entries.
    It mints no HostFenceEvent, no takeover authorization and no database
    authority.
    """

    def __init__(self, entries: dict[str, dict[str, Any]]) -> None:
        self._entries = entries

    @classmethod
    def parse(
        cls,
        data: bytes,
        *,
        expected_account_id: str,
        now: dt.datetime,
    ) -> "ManualOperatorFenceEvidence":
        value = fields(
            decode_json(data, "manual fence evidence", canonical_lf=True),
            {
                "kind",
                "version",
                "decision",
                "operator_principal_arn",
                "recorded_at",
                "hosts",
            },
            "manual fence evidence",
        )
        if (
            value["kind"] != MANUAL_FENCE_EVIDENCE_KIND
            or not version_one(value["version"])
            or value["decision"] != MANUAL_FENCE_EVIDENCE_DECISION
        ):
            raise ProofSetError("manual fence evidence kind/version/decision drifted")
        principal = value["operator_principal_arn"]
        match = (
            STS_ASSUMED_ROLE.fullmatch(principal)
            if isinstance(principal, str)
            else None
        )
        if match is None or match.group(2) != expected_account_id:
            raise ProofSetError(
                "manual fence evidence operator is not an assumed-role principal"
                " in the reset account"
            )
        recorded = parse_time(value["recorded_at"], "manual fence evidence recorded_at")
        if recorded > now.astimezone(dt.timezone.utc):
            raise ProofSetError("manual fence evidence is recorded in the future")
        hosts = value["hosts"]
        if not isinstance(hosts, list) or not hosts:
            raise ProofSetError("manual fence evidence has no attested old Host")
        entries: dict[str, dict[str, Any]] = {}
        for index, entry in enumerate(hosts):
            entry = cls._parse_host(entry, f"manual fence evidence host {index}")
            if entry["host_id"] in entries:
                raise ProofSetError(
                    "manual fence evidence attests one old Host more than once"
                )
            entries[entry["host_id"]] = entry
        if list(entries) != sorted(entries):
            raise ProofSetError("manual fence evidence hosts are not strict sorted")
        return cls(entries)

    @staticmethod
    def _parse_host(value: Any, label: str) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise ProofSetError(f"{label} is not an object")
        terminal_kind = value.get("terminal_kind")
        if terminal_kind == "host_fence_event":
            value = fields(
                value,
                {
                    "host_id",
                    "components",
                    "terminal_kind",
                    "event_id",
                    "ec2_stop",
                    "checklist",
                    "receipt_sha256",
                },
                label,
            )
            identifier(value["event_id"], f"{label} event ID")
            ec2_stop = fields(
                value["ec2_stop"], {"instance_id", "stopped_at"}, f"{label} EC2 stop"
            )
            instance_id = ec2_stop["instance_id"]
            if (
                not isinstance(instance_id, str)
                or EC2_INSTANCE_ID.fullmatch(instance_id) is None
            ):
                raise ProofSetError(f"{label} EC2 instance ID is not canonical")
            parse_time(ec2_stop["stopped_at"], f"{label} EC2 stop time")
        elif terminal_kind == "local_positive_stop":
            value = fields(
                value,
                {
                    "host_id",
                    "components",
                    "terminal_kind",
                    "stopped_units",
                    "stopped_at",
                    "checklist",
                    "receipt_sha256",
                },
                label,
            )
            units = value["stopped_units"]
            if (
                not isinstance(units, list)
                or not units
                or units != sorted(set(units))
                or any(
                    not isinstance(unit, str)
                    or SYSTEMD_UNIT.fullmatch(unit) is None
                    for unit in units
                )
            ):
                raise ProofSetError(
                    f"{label} stopped units are not a strict sorted service set"
                )
            parse_time(value["stopped_at"], f"{label} stop time")
        else:
            raise ProofSetError(f"{label} terminal kind is unavailable")
        identifier(value["host_id"], f"{label} Host ID")
        components = value["components"]
        if (
            not isinstance(components, list)
            or not components
            or components != sorted(set(components))
            or any(item not in MANUAL_FENCE_COMPONENTS for item in components)
        ):
            raise ProofSetError(
                f"{label} component set is not closed sorted nonempty"
            )
        checklist = fields(
            value["checklist"],
            MANUAL_FENCE_CHECKLIST_FIELDS[terminal_kind],
            f"{label} checklist",
        )
        if any(item is not True for item in checklist.values()):
            raise ProofSetError(f"{label} checklist is not completely attested")
        digest(value["receipt_sha256"], f"{label} receipt digest")
        return value

    def host_fence_verifier(self) -> HostFenceTerminalVerifier:
        return _ManualHostFenceVerifier(self._entries, "host_fence_event")

    def local_positive_stop_verifier(self) -> LocalPositiveStopVerifier:
        return _ManualLocalPositiveStopVerifier(self._entries, "local_positive_stop")


UNAVAILABLE_ROUTE_V2_VERIFIER: RouteV2QualificationVerifier = _UnavailableRouteV2Verifier()
UNAVAILABLE_USAGE_VERIFIER: UsageTargetTerminalVerifier = _UnavailableUsageVerifier()
UNAVAILABLE_HOST_FENCE_VERIFIER: HostFenceTerminalVerifier = _UnavailableHostFenceVerifier()
UNAVAILABLE_LOCAL_POSITIVE_STOP_VERIFIER: LocalPositiveStopVerifier = (
    _UnavailableLocalPositiveStopVerifier()
)
UNAVAILABLE_QUALIFICATION_ADMISSION_VERIFIER: QualificationAdmissionVerifier = (
    _UnavailableQualificationAdmissionVerifier()
)


@dataclasses.dataclass(frozen=True)
class VerifiedProofSet:
    value: dict[str, Any]
    sha256: str
    source_manifest_sha256: str
    source_bundle_sha256: str
    release_manifest_sha256: str
    worker_bundle_sha256: str
    usage_schema_verifier_binary_sha256: str
    usage_terminal_verifier_binary_sha256: str
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

    def producer_context(self) -> ProducerContext:
        return ProducerContext(
            release_id=self.value["release"]["release_id"],
            release_commit=self.value["release"]["source_commit_sha"],
            release_manifest_sha256=self.release_manifest_sha256,
            worker_bundle_sha256=self.worker_bundle_sha256,
            usage_schema_verifier_binary_sha256=(
                self.usage_schema_verifier_binary_sha256
            ),
            usage_terminal_verifier_binary_sha256=(
                self.usage_terminal_verifier_binary_sha256
            ),
            qualification_manifest_sha256=self.qualification_manifest_sha256,
            qualification_catalog_sha256=self.qualification_catalog_sha256,
            aws_account_id=self.value["fresh"]["aws_account_id"],
            aws_region=self.value["fresh"]["aws_region"],
            old_targets=self.value["old"],
            fresh_targets=self.value["fresh"]["targets"],
        )

    def admission_binding(self, reset_complete_receipt_sha256: str) -> dict[str, Any]:
        release = self.value["release"]
        fresh = self.value["fresh"]
        return {
            "reset_id": self.value["reset_id"],
            "deployment_id": fresh["deployment_id"],
            "release_id": release["release_id"],
            "source_commit_sha": release["source_commit_sha"],
            "control_schema_version": CONTROL_SCHEMA_VERSION,
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
        not version_one(value["schema_version"])
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
        not version_one(value["schema_version"])
        or value["source_sha"] != release["source_commit_sha"]
        or value["manifest_sha256"] != release["source_manifest_sha256"]
        or value["bundle_sha256"] != release["source_bundle_sha256"]
        or type(value["exit_status"]) is not int
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


def _validate_release_manifest(
    value: Any,
    release: dict[str, Any],
) -> tuple[str, str, str]:
    value = fields(
        value,
        {"artifacts", "build_inputs", "guest_runtime", "source", "version"},
        "release manifest",
    )
    if not version_one(value["version"]):
        raise ProofSetError("release manifest version is not 1")
    source = fields(value["source"], {"commit", "fingerprint", "tree"}, "release source")
    if source["commit"] != release["source_commit_sha"]:
        raise ProofSetError("release manifest source commit drifted")
    commit(source["tree"], "release source tree")
    digest(source["fingerprint"], "release source fingerprint")
    artifacts = fields(
        value["artifacts"],
        {"control_plane", "credential_refresher", "gateway", "worker"},
        "release artifacts",
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
    usage_schema_verifier = members.get(USAGE_SCHEMA_VERIFIER.name)
    if not isinstance(usage_schema_verifier, dict):
        raise ProofSetError("release omits the Usage schema verifier worker member")
    inputs = value["build_inputs"]
    if (
        not isinstance(inputs, dict)
        or inputs.get("guest_target") != "x86_64-unknown-linux-musl"
        or inputs.get("platform") != "linux/amd64"
    ):
        raise ProofSetError("release manifest target is not production linux/amd64")
    input_files = inputs.get("files")
    catalog_input = (
        input_files.get("qualification_catalog")
        if isinstance(input_files, dict)
        else None
    )
    if not isinstance(catalog_input, dict) or catalog_input.get("sha256") != release[
        "qualification_catalog_sha256"
    ]:
        raise ProofSetError(
            "release manifest fingerprinted qualification catalog differs from"
            " the proof-set release catalog"
        )
    return (
        worker_digest,
        usage_schema_verifier["sha256"],
        usage_verifier["sha256"],
    )


def _validate_usage_verification_projection(
    value: Any,
    *,
    receipt: VerifiedFile,
    expected_request: VerifiedFile,
    expected_targets: VerifiedFile,
    context: ProducerContext,
) -> dict[str, Any]:
    value = fields(
        value,
        {
            "binary_sha256",
            "expected_request_file_sha256",
            "expected_targets_file_sha256",
            "kind",
            "release_commit",
            "target_binding_sha256",
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
        or not version_one(value["version"])
        or value["validated"] is not True
        or value["release_commit"] != context.release_commit
        or value["worker_bundle_sha256"] != context.worker_bundle_sha256
        or value["binary_sha256"]
        != context.usage_terminal_verifier_binary_sha256
        or value["expected_request_file_sha256"] != expected_request.sha256
        or value["expected_targets_file_sha256"] != expected_targets.sha256
        or value["target_receipt_file_sha256"] != receipt.sha256
    ):
        raise ProofSetError("E9 terminal verification projection drifted")
    digest(value["target_request_sha256"], "E9 target request digest")
    digest(value["target_binding_sha256"], "E9 target binding digest")
    targets = decode_json(
        expected_targets.data,
        "E9 expected targets",
        canonical_lf=True,
    )
    fields(
        targets,
        {"version", "old_target", "fresh_target", "shards"},
        "E9 expected targets",
    )
    if not version_one(targets["version"]):
        raise ProofSetError("E9 expected-targets version drifted")
    usage_target_fields = {
        "aws_account_id",
        "aws_region",
        "usage_schema",
        "stream_name",
        "stream_arn",
        "checkpoint_table_name",
        "checkpoint_table_arn",
        "archive_bucket_name",
        "archive_bucket_arn",
    }
    old_usage_target = fields(
        targets["old_target"],
        usage_target_fields,
        "E9 old Usage target",
    )
    fresh_usage_target = fields(
        targets["fresh_target"],
        usage_target_fields,
        "E9 fresh Usage target",
    )
    for label, usage_target, reset_target in (
        ("old", old_usage_target, context.old_targets),
        ("fresh", fresh_usage_target, context.fresh_targets),
    ):
        if (
            usage_target["aws_account_id"] != context.aws_account_id
            or usage_target["aws_region"] != context.aws_region
            or usage_target["usage_schema"] != reset_target["usage_schema"]
            or usage_target["stream_name"]
            != reset_target["usage_kinesis_stream"]
            or usage_target["checkpoint_table_name"]
            != reset_target["usage_checkpoint_table"]
            or usage_target["archive_bucket_name"]
            != reset_target["usage_archive_bucket"]
        ):
            raise ProofSetError(
                f"E9 {label} Usage target differs from the reset target"
            )
    expected_binding_sha256 = "sha256:" + hashlib.sha256(
        canonical_json(targets)
    ).hexdigest()
    if value["target_binding_sha256"] != expected_binding_sha256:
        raise ProofSetError("E9 expected-targets semantic binding drifted")
    return value


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
            "product_inventory_receipt_sha256",
            "cleanup_inventory_receipt_sha256",
            "active_guard_count",
            "product_resource_count",
            "residue_count",
            "completed_at_unix_ms",
        },
        "Qualification terminal receipt",
    )
    if begin["kind"] != QUALIFICATION_BEGIN_KIND or not version_one(begin["version"]):
        raise ProofSetError("Qualification Begin receipt kind/version drifted")
    if terminal["kind"] != QUALIFICATION_TERMINAL_KIND or not version_one(
        terminal["version"]
    ):
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
        "object_write_ambiguity",
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
        (
            terminal["product_inventory_receipt_sha256"],
            "Qualification product inventory",
        ),
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
        or isinstance(terminal["active_guard_count"], bool)
        or terminal["product_resource_count"] != 0
        or isinstance(terminal["product_resource_count"], bool)
        or terminal["residue_count"] != 0
        or isinstance(terminal["residue_count"], bool)
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
    if not version_one(value["version"]) or value["release_commit_sha"] != release_commit:
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
        not version_one(snapshot["version"])
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
            not version_one(session["version"])
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
            or not version_one(attestation["version"])
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
        not version_one(value["version"])
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
        or not version_one(first["mkfs_invocations"])
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


def _usage_sources(
    value: Any,
    label: str,
) -> tuple[tuple[str, str, str], ...]:
    if not isinstance(value, list) or not value:
        raise ProofSetError(f"{label} is not a nonempty source set")
    result: list[tuple[str, str, str]] = []
    for index, item in enumerate(value):
        item = fields(
            item,
            {"source_id", "source_epoch", "receipt_sha256"},
            f"{label}[{index}]",
        )
        source_id = item["source_id"]
        source_epoch = item["source_epoch"]
        if (
            not isinstance(source_id, str)
            or not source_id
            or len(source_id) > 2_048
            or not isinstance(source_epoch, str)
            or not source_epoch
            or len(source_epoch) > 2_048
        ):
            raise ProofSetError(f"{label} contains an unbounded source identity")
        result.append(
            (
                source_id,
                source_epoch,
                digest(item["receipt_sha256"], f"{label} receipt digest"),
            )
        )
    keys = [(source_id, source_epoch) for source_id, source_epoch, _digest in result]
    if keys != sorted(set(keys)):
        raise ProofSetError(f"{label} is not strict sorted and unique")
    return tuple(result)


def _usage_sources_json(
    value: tuple[tuple[str, str, str], ...],
) -> list[dict[str, str]]:
    return [
        {
            "source_id": source_id,
            "source_epoch": source_epoch,
            "receipt_sha256": receipt_sha256,
        }
        for source_id, source_epoch, receipt_sha256 in value
    ]


def _usage_source_set_sha256(
    value: tuple[tuple[str, str, str], ...],
) -> str:
    # This is the Rust typed request digest, not the recursively key-sorted
    # evidence-file encoding.  `UsageTerminalSourceReceiptRef` declares these
    # fields in this exact order and serde_json emits UTF-8 compact JSON.
    typed_bytes = json.dumps(
        _usage_sources_json(value),
        sort_keys=False,
        separators=(",", ":"),
        ensure_ascii=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(
        typed_bytes
    ).hexdigest()


def _validate_usage_source_terminal_set(
    value: Any,
    *,
    block_path: str,
    run_id: str,
    workspace_id: str,
    context: ProducerContext,
) -> tuple[str, tuple[tuple[str, str, str], ...]]:
    value = fields(
        value,
        {
            "block_path",
            "cat_id",
            "kind",
            "qualification_catalog_sha256",
            "release_commit",
            "run_id",
            "run_window_from_unix_ms",
            "run_window_to_unix_ms",
            "source_set_sha256",
            "sources",
            "version",
            "worker_bundle_sha256",
            "workspace_id",
        },
        f"{block_path} Usage source terminal set",
    )
    if (
        value["kind"] != USAGE_SOURCE_TERMINAL_SET_KIND
        or not version_one(value["version"])
        or value["block_path"] != block_path
        or value["run_id"] != run_id
        or value["workspace_id"] != workspace_id
        or value["release_commit"] != context.release_commit
        or value["worker_bundle_sha256"] != context.worker_bundle_sha256
        or value["qualification_catalog_sha256"]
        != context.qualification_catalog_sha256
    ):
        raise ProofSetError(f"{block_path} Usage source terminal binding drifted")
    identifier(value["cat_id"], f"{block_path} Usage Cat ID")
    started = integer(
        value["run_window_from_unix_ms"],
        f"{block_path} Usage window start",
        minimum=1,
    )
    ended = integer(
        value["run_window_to_unix_ms"],
        f"{block_path} Usage window end",
        minimum=started + 1,
    )
    if ended <= started:
        raise ProofSetError(f"{block_path} Usage window is empty")
    sources = _usage_sources(value["sources"], f"{block_path} Usage sources")
    source_set_sha256 = _usage_source_set_sha256(sources)
    if value["source_set_sha256"] != source_set_sha256:
        raise ProofSetError(f"{block_path} Usage source-set digest drifted")
    return source_set_sha256, sources


def _usage_terminal_epoch_id(
    qualified_runs: tuple[QualifiedRun, QualifiedRun],
    expected_targets_sha256: str,
    source_set_sha256: str,
) -> str:
    hasher = hashlib.sha256()
    for value in (
        "cats.usage-target-terminal-epoch.v1",
        qualified_runs[0].manifest_sha256,
        qualified_runs[1].manifest_sha256,
        expected_targets_sha256,
        source_set_sha256,
    ):
        raw = value.encode("utf-8")
        hasher.update(len(raw).to_bytes(8, "big"))
        hasher.update(raw)
    result = hasher.hexdigest()[:32]
    if result == "0" * 32:
        raise ProofSetError("E9 terminal epoch derived the reserved zero ID")
    return result


def _validate_global_usage_finalization(
    value: Any,
    *,
    finalization_manifest: VerifiedFile,
    expected_targets: VerifiedFile,
    expected_request: VerifiedFile,
    receipt: VerifiedFile,
    verification_file: VerifiedFile,
    verification: dict[str, Any],
    qualified_runs: tuple[QualifiedRun, QualifiedRun],
    context: ProducerContext,
) -> None:
    value = fields(
        value,
        {
            "kind",
            "version",
            "outcome",
            "release_commit",
            "worker_bundle_sha256",
            "qualification_catalog_sha256",
            "expected_targets_file_sha256",
            "target_binding_sha256",
            "block_runs",
            "sources",
            "source_set_sha256",
            "terminal_epoch_id",
            "target_request_sha256",
            "target_request_file_sha256",
            "target_receipt_file_sha256",
            "target_verification_file_sha256",
            "completed_at_unix_ms",
        },
        "E9 global terminal finalization manifest",
    )
    if (
        value["kind"] != USAGE_GLOBAL_FINALIZATION_KIND
        or not version_one(value["version"])
        or value["outcome"] != "terminal"
        or value["release_commit"] != context.release_commit
        or value["worker_bundle_sha256"] != context.worker_bundle_sha256
        or value["qualification_catalog_sha256"]
        != context.qualification_catalog_sha256
        or value["expected_targets_file_sha256"] != expected_targets.sha256
        or value["target_binding_sha256"] != verification["target_binding_sha256"]
        or value["target_request_sha256"] != verification["target_request_sha256"]
        or value["target_request_file_sha256"] != expected_request.sha256
        or value["target_receipt_file_sha256"] != receipt.sha256
        or value["target_verification_file_sha256"] != verification_file.sha256
        or any(
            qualified.expected_targets_file_sha256 != expected_targets.sha256
            for qualified in qualified_runs
        )
    ):
        raise ProofSetError("E9 global terminal finalization binding drifted")
    block_runs = value["block_runs"]
    if not isinstance(block_runs, list) or len(block_runs) != 2:
        raise ProofSetError("E9 global finalizer does not bind exactly two runs")
    for index, qualified in enumerate(qualified_runs):
        run = fields(
            block_runs[index],
            {
                "block_path",
                "run_id",
                "qualification_manifest_sha256",
                "case_evidence_sha256",
                "source_terminal_set_sha256",
            },
            f"E9 global block run {index}",
        )
        if run != {
            "block_path": qualified.block_path,
            "run_id": qualified.run_id,
            "qualification_manifest_sha256": qualified.manifest_sha256,
            "case_evidence_sha256": qualified.case_evidence_sha256,
            "source_terminal_set_sha256": qualified.source_terminal_set_sha256,
        }:
            raise ProofSetError("E9 global finalizer rebound a qualified block run")

    union: dict[tuple[str, str], str] = {}
    for qualified in qualified_runs:
        for source_id, source_epoch, receipt_sha256 in qualified.sources:
            key = (source_id, source_epoch)
            prior = union.get(key)
            if prior is not None and prior != receipt_sha256:
                raise ProofSetError("E9 per-run source sets conflict on one source epoch")
            union[key] = receipt_sha256
    expected_sources = tuple(
        (source_id, source_epoch, receipt_sha256)
        for (source_id, source_epoch), receipt_sha256 in sorted(union.items())
    )
    sources = _usage_sources(value["sources"], "E9 global Usage sources")
    if sources != expected_sources:
        raise ProofSetError("E9 global source set is not the exact two-run union")
    source_set_sha256 = _usage_source_set_sha256(sources)
    if value["source_set_sha256"] != source_set_sha256:
        raise ProofSetError("E9 global source-set digest drifted")
    expected_epoch = _usage_terminal_epoch_id(
        qualified_runs,
        expected_targets.sha256,
        source_set_sha256,
    )
    if value["terminal_epoch_id"] != expected_epoch:
        raise ProofSetError("E9 terminal epoch is not the exact global derivation")
    request = fields(
        decode_json(
            expected_request.data,
            "E9 global target request",
            canonical_lf=True,
        ),
        {
            "contract_version",
            "terminal_epoch_id",
            "release_commit",
            "artifact_sha256",
            "created_at_unix_ms",
            "old_target",
            "fresh_target",
            "sources",
            "source_set_sha256",
            "shards",
        },
        "E9 global target request",
    )
    request_sources = _usage_sources(
        request["sources"],
        "E9 global target request sources",
    )
    if (
        not version_one(request["contract_version"])
        or request["release_commit"] != context.release_commit
        or request["artifact_sha256"]
        != context.worker_bundle_sha256.removeprefix("sha256:")
        or request_sources != sources
        or request["source_set_sha256"] != source_set_sha256
        or request["terminal_epoch_id"] != expected_epoch
    ):
        raise ProofSetError("E9 global target request rebound the qualified runs")
    created_at = integer(
        request["created_at_unix_ms"],
        "E9 global target request creation time",
        minimum=1,
    )
    completed = integer(
        value["completed_at_unix_ms"],
        "E9 global completion time",
        minimum=1,
    )
    if completed < max(
        created_at,
        *(qualified.qualification_completed_at_unix_ms for qualified in qualified_runs),
    ):
        raise ProofSetError("E9 global finalization predates Qualification Closed")
    if finalization_manifest.name != USAGE_GLOBAL_FINALIZATION_FILE:
        raise ProofSetError("E9 global finalization filename drifted")


def _validate_sha256sums(
    data: bytes,
    expected: dict[str, VerifiedFile],
    label: str,
) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProofSetError(f"{label} is not ASCII") from error
    expected_names = sorted(expected)
    lines = text.splitlines(keepends=True)
    if len(lines) != len(expected_names) or any(
        not line.endswith("\n") for line in lines
    ):
        raise ProofSetError(f"{label} is not its exact line set")
    observed_names: list[str] = []
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\n",
            line,
        )
        if match is None:
            raise ProofSetError(f"{label} has a malformed entry")
        name = match.group(2)
        observed_names.append(name)
        verified = expected.get(name)
        if verified is None or verified.sha256 != "sha256:" + match.group(1):
            raise ProofSetError(f"{label} contains a foreign digest")
    if observed_names != expected_names:
        raise ProofSetError(f"{label} is not the exact C-sorted file set")


def _validate_global_sha256sums(
    data: bytes,
    expected: dict[str, VerifiedFile],
) -> None:
    try:
        text = data.decode("ascii")
    except UnicodeDecodeError as error:
        raise ProofSetError("E9 global SHA256SUMS is not ASCII") from error
    expected_names = sorted(expected)
    lines = text.splitlines(keepends=True)
    if not lines or any(not line.endswith("\n") for line in lines):
        raise ProofSetError("E9 global SHA256SUMS has no exact terminal LF rows")
    observed_names: list[str] = []
    for line in lines:
        match = re.fullmatch(
            r"([0-9a-f]{64})  ([A-Za-z0-9][A-Za-z0-9_.-]{0,127})\n",
            line,
        )
        if match is None:
            raise ProofSetError("E9 global SHA256SUMS contains a malformed row")
        name = match.group(2)
        observed_names.append(name)
        verified = expected.get(name)
        if verified is None or verified.sha256 != "sha256:" + match.group(1):
            raise ProofSetError("E9 global SHA256SUMS contains a foreign digest")
    if observed_names != expected_names:
        raise ProofSetError(
            "E9 global SHA256SUMS is not the exact sorted seven-file set"
        )


def _validate_global_case_evidence(
    evidence: VerifiedFile,
    request: VerifiedFile,
    receipt: VerifiedFile,
    verification: VerifiedFile,
) -> None:
    expected = (
        (USAGE_TERMINAL_REQUEST_FILE, request),
        (USAGE_TERMINAL_RECEIPT_FILE, receipt),
        (USAGE_TERMINAL_VERIFICATION_FILE, verification),
    )
    rows = _jsonl(evidence.data, "E9 global case evidence")
    if len(rows) != len(expected):
        raise ProofSetError("E9 global case evidence is not the exact three-row set")
    for row, (filename, standalone) in zip(rows, expected, strict=True):
        row = fields(
            row,
            {"case_id", "content", "filename", "kind", "sha256", "size_bytes"},
            f"E9 global case evidence {filename}",
        )
        content = decode_json(
            standalone.data,
            f"E9 standalone {filename}",
            canonical_lf=True,
        )
        if (
            row["case_id"] != "usage-target-terminal-receipt"
            or row["filename"] != filename
            or row["kind"] != "json"
            or row["content"] != content
            or row["sha256"] != standalone.sha256
            or row["size_bytes"] != standalone.size_bytes
        ):
            raise ProofSetError(f"E9 global case evidence rebound {filename}")


def _validate_qualification_final_support(
    *,
    final_state: VerifiedFile,
    final_fleet: VerifiedFile,
    product_inventory: VerifiedFile,
    cleanup_inventory: VerifiedFile,
    begin: dict[str, Any],
    terminal: dict[str, Any],
    manifest_expected_nodes: list[str],
    final_inventory: VerifiedFile,
    block_path: str,
    context: ProducerContext,
) -> None:
    state = fields(
        decode_json(final_state.data, "Qualification final admission state"),
        {
            "version",
            "revision",
            "mode",
            "binding",
            "last_command_id",
            "updated_at_unix_ms",
        },
        "Qualification final admission state",
    )
    state_binding = fields(
        state["binding"],
        {"kind", "binding"},
        "Qualification final state binding",
    )
    binding = fields(
        state_binding["binding"],
        QUALIFICATION_BINDING_FIELDS,
        "Qualification final binding",
    )
    expected_binding_digest = "sha256:" + hashlib.sha256(
        canonical_json({"kind": "qualification", "binding": binding})
    ).hexdigest()
    if (
        not version_one(state["version"])
        or state["mode"] != "closed"
        or state["revision"] != terminal["final_closed_revision"]
        or state["last_command_id"] != terminal["close_command_id"]
        or state_binding["kind"] != "qualification"
        or binding["qualification_id"] != begin["qualification_id"]
        or binding["workspace_id"] != begin["workspace_id"]
        or binding["release_id"] != begin["release_id"]
        or binding["source_commit_sha"] != context.release_commit
        or binding["control_schema_version"] != CONTROL_SCHEMA_VERSION
        or binding["worker_bundle_sha256"] != context.worker_bundle_sha256
        or binding["release_manifest_sha256"] != context.release_manifest_sha256
        or binding["qualification_catalog_sha256"]
        != context.qualification_catalog_sha256
        or binding["allowed_mutation_classes"]
        != begin["allowed_mutation_classes"]
        or binding["qualification_expires_at_unix_ms"]
        != begin["qualification_expires_at_unix_ms"]
        or expected_binding_digest != begin["binding_sha256"]
    ):
        raise ProofSetError("Qualification final state binding drifted")
    integer(
        state["updated_at_unix_ms"],
        "Qualification final state update time",
        minimum=1,
    )

    fleet = fields(
        decode_json(final_fleet.data, "Qualification final Fleet Closed receipt"),
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
    expected_nodes = fleet["expected_node_ids"]
    if (
        fleet["kind"] != QUALIFICATION_FINAL_FLEET_KIND
        or not version_one(fleet["version"])
        or fleet["qualification_id"] != begin["qualification_id"]
        or fleet["workspace_id"] != begin["workspace_id"]
        or fleet["source_commit_sha"] != context.release_commit
        or fleet["block_path"] != block_path
        or fleet["complete"] is not True
        or not isinstance(expected_nodes, list)
        or not expected_nodes
        or expected_nodes != sorted(set(expected_nodes))
    ):
        raise ProofSetError("Qualification final Fleet binding drifted")
    for node_id in expected_nodes:
        identifier(node_id, "Qualification final Fleet Node ID")
    digest(
        fleet["fleet_verification_receipt_sha256"],
        "Qualification final Fleet authority",
    )
    _validate_qualification_fleet_authority(
        fleet,
        manifest_expected_nodes,
        final_inventory,
    )
    for counter in (
        "desired_runtime_count",
        "current_runtime_observation_count",
        "active_guard_count",
        "residue_count",
    ):
        _zero(fleet[counter], f"Qualification final Fleet {counter}")
    fleet_evaluated = integer(
        fleet["evaluated_at_unix_ms"],
        "Qualification final Fleet time",
        minimum=1,
    )

    product = fields(
        decode_json(
            product_inventory.data,
            "Qualification product inventory receipt",
        ),
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
        "Qualification product inventory receipt",
    )
    if (
        product["kind"] != QUALIFICATION_PRODUCT_INVENTORY_KIND
        or not version_one(product["version"])
        or product["qualification_id"] != begin["qualification_id"]
        or product["workspace_id"] != begin["workspace_id"]
        or product["release_id"] != begin["release_id"]
        or product["source_commit_sha"] != context.release_commit
        or product["qualification_catalog_sha256"]
        != context.qualification_catalog_sha256
        or product["binding_sha256"] != begin["binding_sha256"]
        or product["close_kind"] != terminal["close_kind"]
        or product["close_command_id"] != terminal["close_command_id"]
        or product["close_request_sha256"] != terminal["close_request_sha256"]
        or product["close_command_receipt_sha256"]
        != terminal["close_command_receipt_sha256"]
        or product["closed_revision"] != terminal["final_closed_revision"]
        or product["complete"] is not True
    ):
        raise ProofSetError("Qualification product inventory binding drifted")
    counts = fields(
        product["counts"],
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
        if integer(count, f"Qualification product inventory {name}") > 2**63 - 1:
            raise ProofSetError(
                f"Qualification product inventory {name} exceeds PostgreSQL bigint"
            )
    current_names = (
        "current_cat_count",
        "root_disk_count",
        "persistent_disk_count",
        "disk_snapshot_count",
        "endpoint_count",
        "hostname_desired_lookup_count",
        "pending_runtime_operation_count",
    )
    if product["product_resource_count"] != sum(counts[name] for name in current_names):
        raise ProofSetError("Qualification product inventory total drifted")
    _zero(product["product_resource_count"], "Qualification current product inventory")
    product_evaluated = integer(
        product["evaluated_at_unix_ms"],
        "Qualification product inventory time",
        minimum=1,
    )
    if product_evaluated < state["updated_at_unix_ms"]:
        raise ProofSetError("Qualification product inventory predates Closed")

    cleanup = fields(
        decode_json(
            cleanup_inventory.data,
            "Qualification cleanup inventory receipt",
        ),
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
        "Qualification cleanup inventory receipt",
    )
    if (
        cleanup["kind"] != QUALIFICATION_CLEANUP_INVENTORY_KIND
        or not version_one(cleanup["version"])
        or cleanup["qualification_id"] != begin["qualification_id"]
        or cleanup["workspace_id"] != begin["workspace_id"]
        or cleanup["source_commit_sha"] != context.release_commit
        or cleanup["block_path"] != block_path
        or cleanup["complete"] is not True
    ):
        raise ProofSetError("Qualification cleanup inventory binding drifted")
    if (
        cleanup["product_inventory_receipt_sha256"] != product_inventory.sha256
        or cleanup["product_resource_count"] != product["product_resource_count"]
    ):
        raise ProofSetError("Qualification cleanup rebound the product inventory")
    for counter in (
        "product_resource_count",
        "desired_runtime_count",
        "current_runtime_observation_count",
        "active_guard_count",
        "residue_count",
    ):
        _zero(cleanup[counter], f"Qualification cleanup {counter}")
    cleanup_evaluated = integer(
        cleanup["evaluated_at_unix_ms"],
        "Qualification cleanup time",
        minimum=1,
    )
    if cleanup_evaluated < product_evaluated or fleet_evaluated < product_evaluated:
        raise ProofSetError("Qualification cleanup/Fleet predates product inventory")
    if terminal["completed_at_unix_ms"] != max(
        fleet_evaluated,
        cleanup_evaluated,
    ):
        raise ProofSetError("Qualification terminal completion time drifted")


def _validate_qualification_fleet_authority(
    fleet: dict[str, Any],
    manifest_expected_nodes: list[str],
    final_inventory: VerifiedFile,
) -> None:
    if fleet["expected_node_ids"] != manifest_expected_nodes:
        raise ProofSetError(
            "Qualification final Fleet Node set differs from its manifest"
        )
    if fleet["fleet_verification_receipt_sha256"] != final_inventory.sha256:
        raise ProofSetError(
            "Qualification final Fleet receipt does not bind final-inventory.json"
        )


def _qualification_manifest_evidence(
    manifest: dict[str, Any],
    begin_file: VerifiedFile,
    terminal_file: VerifiedFile,
    block_path: str,
) -> None:
    expected = [
        {
            "filename": QUALIFICATION_BEGIN_FILE,
            "kind": "json",
            "sha256": begin_file.sha256,
            "size_bytes": begin_file.size_bytes,
        },
        {
            "filename": QUALIFICATION_TERMINAL_FILE,
            "kind": "json",
            "sha256": terminal_file.sha256,
            "size_bytes": terminal_file.size_bytes,
        },
    ]
    if manifest.get("qualification_admission_required_evidence") != expected:
        raise ProofSetError(
            f"{block_path} manifest does not bind its exact admission evidence"
        )


def _qualification_catalog_admission(value: Any, block_path: str) -> None:
    if not isinstance(value, dict):
        raise ProofSetError(f"{block_path} qualification catalog is not an object")
    expected = [
        {"filename": QUALIFICATION_BEGIN_FILE, "kind": "json"},
        {"filename": QUALIFICATION_TERMINAL_FILE, "kind": "json"},
    ]
    if value.get("qualification_admission_required_evidence") != expected:
        raise ProofSetError(
            f"{block_path} catalog does not require exact admission evidence"
        )


def _validate_qualification(
    directory: ProofDirectory,
    value: Any,
    block_path: str,
    context: ProducerContext,
    worker_bundle_sha256: str,
    admission_verifier: QualificationAdmissionVerifier,
) -> tuple[QualifiedRun, str]:
    reference_names = set(QUALIFICATION_PROOF_LOGICAL_FILES)
    value = fields(
        value,
        reference_names,
        f"{block_path} qualification",
    )
    refs = {
        name: ProofReference.parse(reference, f"qualification.{block_path}.{name}")
        for name, reference in value.items()
    }
    expected_staged_names = {
        name: f"{block_path}-{logical_name}"
        for name, logical_name in QUALIFICATION_PROOF_LOGICAL_FILES.items()
    }
    if {
        name: reference.file for name, reference in refs.items()
    } != expected_staged_names:
        raise ProofSetError(
            f"{block_path} qualification references do not use exact staged names"
        )
    manifest_file = directory.read_reference(refs["manifest"], f"{block_path} manifest")
    manifest = decode_json(
        manifest_file.data, f"{block_path} manifest", canonical_lf=True
    )
    if not isinstance(manifest, dict):
        raise ProofSetError(f"{block_path} manifest is not an object")
    release_manifest = manifest.get("release_manifest", {})
    installer = manifest.get("installer_receipt", {})
    run_id = manifest.get("run_id")
    qualification_scope = manifest.get("qualification", {})
    workspace_id = (
        qualification_scope.get("workspace_id")
        if isinstance(qualification_scope, dict)
        else None
    )
    manifest_expected_nodes = (
        qualification_scope.get("expected_nodes")
        if isinstance(qualification_scope, dict)
        else None
    )
    if (
        not version_one(manifest.get("version"))
        or manifest.get("state") != "passed"
        or type(manifest.get("exit_code")) is not int
        or manifest.get("exit_code") != 0
        or manifest.get("schema_version") != CONTROL_SCHEMA_VERSION
        or manifest.get("block_path") != block_path
        or manifest.get("exact_commit") != context.release_commit
        or release_manifest.get("sha256") != context.release_manifest_sha256
        or release_manifest.get("approved_sha256") != context.release_manifest_sha256
        or installer.get("worker_bundle_sha256") != worker_bundle_sha256
        or manifest.get("qualification_catalog", {}).get("sha256")
        != context.qualification_catalog_sha256
    ):
        raise ProofSetError(f"{block_path} qualification is not exact-release passed")
    run_id = identifier(run_id, f"{block_path} qualification run ID")
    workspace_id = identifier(workspace_id, f"{block_path} qualification Workspace ID")
    if (
        not isinstance(manifest_expected_nodes, list)
        or not manifest_expected_nodes
        or manifest_expected_nodes != sorted(set(manifest_expected_nodes))
    ):
        raise ProofSetError(
            f"{block_path} manifest expected Node set is not strict sorted nonempty"
        )
    for node_id in manifest_expected_nodes:
        identifier(node_id, f"{block_path} manifest expected Node ID")
    configs = manifest.get("configs")
    if not isinstance(configs, list):
        raise ProofSetError(f"{block_path} manifest config set is unavailable")
    usage_target_configs = [
        item
        for item in configs
        if isinstance(item, dict) and item.get("label") == "usage-terminal-targets"
    ]
    if len(usage_target_configs) != 1:
        raise ProofSetError(f"{block_path} has no unique E9 expected-target config")
    usage_target_config = fields(
        usage_target_configs[0],
        {"label", "path", "staged_path", "sha256", "size_bytes"},
        f"{block_path} E9 expected-target config",
    )
    config_sha256 = usage_target_config["sha256"]
    if not isinstance(config_sha256, str) or RAW_SHA256.fullmatch(config_sha256) is None:
        raise ProofSetError(f"{block_path} E9 expected-target config digest drifted")
    expected_targets_file_sha256 = "sha256:" + config_sha256
    integer(
        usage_target_config["size_bytes"],
        f"{block_path} E9 expected-target config size",
        minimum=1,
    )

    support_names = {
        "qualification_begin",
        "qualification_terminal",
        "qualification_begin_pending",
        "qualification_begin_command_receipt",
        "qualification_close_pending",
        "qualification_close_command_receipt",
        "qualification_final_state",
        "qualification_final_fleet",
        "qualification_product_inventory",
        "qualification_cleanup_inventory",
    }
    support = {
        name: directory.read_reference(
            refs[name],
            f"{block_path} {name.replace('_', ' ')}",
        )
        for name in support_names
    }
    base_references = {
        QUALIFICATION_COMPONENT_JOURNAL_FILE: "component_journal_summary",
        QUALIFICATION_EXIT_CODE_FILE: "exit_code",
        QUALIFICATION_FINAL_INVENTORY_FILE: "final_inventory",
        QUALIFICATION_RUNTIME_STATE_FILE: "runtime_state",
        QUALIFICATION_SCENARIO_RESULTS_FILE: "scenario_results",
    }
    base_files = {
        filename: directory.read_reference(
            refs[reference_name],
            f"{block_path} {filename}",
        )
        for filename, reference_name in base_references.items()
    }
    if base_files[QUALIFICATION_EXIT_CODE_FILE].data != b"0\n":
        raise ProofSetError(f"{block_path} qualification exit-code is not zero")
    begin_file = support["qualification_begin"]
    terminal_file = support["qualification_terminal"]
    begin_receipt = decode_json(begin_file.data, f"{block_path} Qualification Begin")
    terminal_receipt = decode_json(
        terminal_file.data,
        f"{block_path} Qualification terminal",
    )
    if (
        canonical_json(begin_receipt) != begin_file.data
        or canonical_json(terminal_receipt) != terminal_file.data
    ):
        raise ProofSetError(f"{block_path} Qualification framework JSON is not canonical")
    _validate_qualification_admission(
        begin_receipt,
        terminal_receipt,
        release_id=context.release_id,
        release_commit=context.release_commit,
        qualification_catalog_sha256=context.qualification_catalog_sha256,
    )
    if (
        begin_receipt["qualification_id"] != run_id
        or begin_receipt["workspace_id"] != workspace_id
        or terminal_receipt["terminal_outcome"] != "qualified_closed"
        or terminal_receipt["close_kind"] != "end_qualification"
        or begin_receipt["begin_command_receipt_sha256"]
        != support["qualification_begin_command_receipt"].sha256
        or terminal_receipt["close_command_receipt_sha256"]
        != support["qualification_close_command_receipt"].sha256
        or terminal_receipt["final_admission_state_sha256"]
        != support["qualification_final_state"].sha256
        or terminal_receipt["fleet_closed_receipt_sha256"]
        != support["qualification_final_fleet"].sha256
        or terminal_receipt["product_inventory_receipt_sha256"]
        != support["qualification_product_inventory"].sha256
        or terminal_receipt["cleanup_inventory_receipt_sha256"]
        != support["qualification_cleanup_inventory"].sha256
    ):
        raise ProofSetError(f"{block_path} Qualification admission support drifted")
    _qualification_manifest_evidence(
        manifest,
        begin_file,
        terminal_file,
        block_path,
    )
    _validate_qualification_final_support(
        final_state=support["qualification_final_state"],
        final_fleet=support["qualification_final_fleet"],
        product_inventory=support["qualification_product_inventory"],
        cleanup_inventory=support["qualification_cleanup_inventory"],
        begin=begin_receipt,
        terminal=terminal_receipt,
        manifest_expected_nodes=manifest_expected_nodes,
        final_inventory=base_files[QUALIFICATION_FINAL_INVENTORY_FILE],
        block_path=block_path,
        context=context,
    )
    admission_verifier.verify(
        support["qualification_begin_pending"],
        support["qualification_begin_command_receipt"],
        support["qualification_close_pending"],
        support["qualification_close_command_receipt"],
        support["qualification_final_state"],
        context,
    )
    catalog_file = directory.read_reference(
        refs["qualification_catalog"], f"{block_path} qualification catalog"
    )
    if catalog_file.sha256 != context.qualification_catalog_sha256:
        raise ProofSetError(f"{block_path} qualification catalog drifted")
    _qualification_catalog_admission(
        decode_json(
            catalog_file.data,
            f"{block_path} qualification catalog",
        ),
        block_path,
    )
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
    usage_matches = [
        item
        for item in entries
        if item.get("case_id") == "usage-source-terminal-receipts"
        and item.get("filename") == "usage-source-terminal-receipts.json"
    ]
    if len(usage_matches) != 1:
        raise ProofSetError(
            f"{block_path} has no unique Usage source-terminal evidence"
        )
    usage_entry = fields(
        usage_matches[0],
        {"case_id", "filename", "kind", "sha256", "size_bytes", "content"},
        f"{block_path} Usage source-terminal evidence",
    )
    usage_content_bytes = canonical_json(usage_entry["content"], newline=True)
    if (
        usage_entry["kind"] != "json"
        or usage_entry["sha256"]
        != "sha256:" + hashlib.sha256(usage_content_bytes).hexdigest()
        or usage_entry["size_bytes"] != len(usage_content_bytes)
    ):
        raise ProofSetError(f"{block_path} Usage evidence digest/size drifted")
    source_set_sha256, sources = _validate_usage_source_terminal_set(
        usage_entry["content"],
        block_path=block_path,
        run_id=run_id,
        workspace_id=workspace_id,
        context=context,
    )
    sums_file = directory.read_reference(refs["sha256sums"], f"{block_path} SHA256SUMS")
    checksum_support = {
        QUALIFICATION_BEGIN_FILE: begin_file,
        QUALIFICATION_TERMINAL_FILE: terminal_file,
        QUALIFICATION_BEGIN_PENDING_FILE: support["qualification_begin_pending"],
        QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE: support[
            "qualification_begin_command_receipt"
        ],
        QUALIFICATION_CLOSE_PENDING_FILE: support["qualification_close_pending"],
        QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE: support[
            "qualification_close_command_receipt"
        ],
        QUALIFICATION_FINAL_STATE_FILE: support["qualification_final_state"],
        QUALIFICATION_FINAL_FLEET_FILE: support["qualification_final_fleet"],
        QUALIFICATION_PRODUCT_INVENTORY_FILE: support[
            "qualification_product_inventory"
        ],
        QUALIFICATION_CLEANUP_INVENTORY_FILE: support[
            "qualification_cleanup_inventory"
        ],
    }
    _validate_sha256sums(
        sums_file.data,
        {
            **base_files,
            "manifest.json": manifest_file,
            "case-evidence.jsonl": evidence_file,
            "qualification-catalog.v1.json": catalog_file,
            **checksum_support,
        },
        f"{block_path} SHA256SUMS",
    )
    return (
        QualifiedRun(
            block_path=block_path,
            run_id=run_id,
            workspace_id=workspace_id,
            manifest_sha256=manifest_file.sha256,
            case_evidence_sha256=evidence_file.sha256,
            qualification_terminal_sha256=terminal_file.sha256,
            qualification_completed_at_unix_ms=terminal_receipt[
                "completed_at_unix_ms"
            ],
            expected_targets_file_sha256=expected_targets_file_sha256,
            source_terminal_set_sha256=source_set_sha256,
            sources=sources,
        ),
        sums_file.sha256,
    )


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
    if not version_one(inventory["version"]) or not version_one(coverage["version"]):
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
    qualification_admission_verifier: QualificationAdmissionVerifier = (
        UNAVAILABLE_QUALIFICATION_ADMISSION_VERIFIER
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
        if value["kind"] != PROOF_SET_KIND or not version_one(value["version"]):
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
            usage_schema_verifier_binary_sha256,
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
            or fresh["control_schema_version"] != CONTROL_SCHEMA_VERSION
        ):
            raise ProofSetError("fresh cell/release scope is invalid")
        fresh_targets = _validate_targets(fresh["targets"], "fresh targets")
        if fresh_targets != expected_fresh_targets:
            raise ProofSetError("proof-set fresh targets differ from reset invocation")
        context = ProducerContext(
            release_id=release["release_id"],
            release_commit=expected_release_commit,
            release_manifest_sha256=release["artifact_sha256"],
            worker_bundle_sha256=worker_bundle_sha256,
            usage_schema_verifier_binary_sha256=(
                usage_schema_verifier_binary_sha256
            ),
            usage_terminal_verifier_binary_sha256=(
                usage_terminal_verifier_binary_sha256
            ),
            qualification_manifest_sha256=release[
                "qualification_manifest_sha256"
            ],
            qualification_catalog_sha256=release[
                "qualification_catalog_sha256"
            ],
            aws_account_id=fresh["aws_account_id"],
            aws_region=fresh["aws_region"],
            old_targets=old_targets,
            fresh_targets=fresh_targets,
        )

        proofs = fields(
            value["proofs"],
            {
                "fleet_closed",
                "route_v2_rotation_qualification_receipt",
                "route_v2_rotation_qualification_node_ack_sets",
                "route_v2_rotation_qualification_transcript",
                "usage_global_case_evidence",
                "usage_global_finalization_manifest",
                "usage_global_qualification_catalog",
                "usage_global_sha256sums",
                "usage_terminal_targets",
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
            proof_refs["usage_global_case_evidence"].file
            != USAGE_GLOBAL_CASE_EVIDENCE_FILE
            or proof_refs["usage_global_finalization_manifest"].file
            != USAGE_GLOBAL_FINALIZATION_FILE
            or proof_refs["usage_global_qualification_catalog"].file
            != USAGE_GLOBAL_QUALIFICATION_CATALOG_FILE
            or proof_refs["usage_global_sha256sums"].file
            != USAGE_GLOBAL_SHA256SUMS_FILE
            or proof_refs["usage_terminal_targets"].file
            != USAGE_TERMINAL_TARGETS_FILE
            or proof_refs["usage_terminal_request"].file
            != USAGE_TERMINAL_REQUEST_FILE
            or proof_refs["usage_terminal_receipt"].file
            != USAGE_TERMINAL_RECEIPT_FILE
            or proof_refs["usage_terminal_verification"].file
            != USAGE_TERMINAL_VERIFICATION_FILE
        ):
            raise ProofSetError("E9 proof files do not use their canonical names")
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
        qualification = fields(
            proofs["qualification"], {"kernel_nbd", "vhost_user"}, "qualification proofs"
        )
        kernel_run, kernel_bundle = _validate_qualification(
            directory,
            qualification["kernel_nbd"],
            "kernel-nbd",
            context,
            worker_bundle_sha256,
            qualification_admission_verifier,
        )
        vhost_run, vhost_bundle = _validate_qualification(
            directory,
            qualification["vhost_user"],
            "vhost-user",
            context,
            worker_bundle_sha256,
            qualification_admission_verifier,
        )
        if (
            kernel_run.run_id == vhost_run.run_id
            or kernel_run.manifest_sha256 == vhost_run.manifest_sha256
        ):
            raise ProofSetError("qualification block paths reused one runner identity")
        qualified_runs = (kernel_run, vhost_run)
        usage_case_evidence_file = directory.read_reference(
            proof_refs["usage_global_case_evidence"],
            "E9 global case evidence",
        )
        usage_finalization_file = directory.read_reference(
            proof_refs["usage_global_finalization_manifest"],
            "E9 global terminal finalization manifest",
        )
        usage_targets_file = directory.read_reference(
            proof_refs["usage_terminal_targets"],
            "E9 expected targets",
        )
        usage_catalog_file = directory.read_reference(
            proof_refs["usage_global_qualification_catalog"],
            "E9 global qualification catalog",
        )
        if usage_catalog_file.data != qualification_catalog.data:
            raise ProofSetError("E9 global qualification catalog is not the release copy")
        usage_sha256sums_file = directory.read_reference(
            proof_refs["usage_global_sha256sums"],
            "E9 global SHA256SUMS",
        )
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
        usage_verification = _validate_usage_verification_projection(
            decode_json(
                usage_verification_file.data,
                "E9 target-terminal verification receipt",
                canonical_lf=True,
            ),
            receipt=usage_file,
            expected_request=usage_request_file,
            expected_targets=usage_targets_file,
            context=context,
        )
        _validate_global_case_evidence(
            usage_case_evidence_file,
            usage_request_file,
            usage_file,
            usage_verification_file,
        )
        _validate_global_sha256sums(
            usage_sha256sums_file.data,
            {
                USAGE_GLOBAL_CASE_EVIDENCE_FILE: usage_case_evidence_file,
                USAGE_GLOBAL_QUALIFICATION_CATALOG_FILE: usage_catalog_file,
                USAGE_GLOBAL_FINALIZATION_FILE: usage_finalization_file,
                USAGE_TERMINAL_RECEIPT_FILE: usage_file,
                USAGE_TERMINAL_REQUEST_FILE: usage_request_file,
                USAGE_TERMINAL_VERIFICATION_FILE: usage_verification_file,
                USAGE_TERMINAL_TARGETS_FILE: usage_targets_file,
            },
        )
        _validate_global_usage_finalization(
            decode_json(
                usage_finalization_file.data,
                "E9 global terminal finalization manifest",
                canonical_lf=True,
            ),
            finalization_manifest=usage_finalization_file,
            expected_targets=usage_targets_file,
            expected_request=usage_request_file,
            receipt=usage_file,
            verification_file=usage_verification_file,
            verification=usage_verification,
            qualified_runs=qualified_runs,
            context=context,
        )
        usage_verifier.verify(
            usage_finalization_file,
            usage_targets_file,
            usage_file,
            usage_request_file,
            usage_verification_file,
            qualified_runs,
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
        return VerifiedProofSet(
            value=value,
            sha256=proof_file.sha256,
            source_manifest_sha256=release["source_manifest_sha256"],
            source_bundle_sha256=release["source_bundle_sha256"],
            release_manifest_sha256=release["artifact_sha256"],
            worker_bundle_sha256=worker_bundle_sha256,
            usage_schema_verifier_binary_sha256=(
                usage_schema_verifier_binary_sha256
            ),
            usage_terminal_verifier_binary_sha256=(
                usage_terminal_verifier_binary_sha256
            ),
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
        )
