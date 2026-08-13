#!/usr/bin/env python3
"""Fail-closed two-phase executor for the first production clean-slate reset.

This program deliberately does not discover destructive targets.  Every
account, region, cluster, namespace, PostgreSQL schema, bucket, and prefix is
an explicit input.  ``plan`` is read-only.  ``apply`` is also read-only unless
``--execute`` and two independent plan confirmations are present.

The reset is a post-cutover retirement tool.  It proves that a disjoint fresh
schema/object/stream/checkpoint/archive namespace is already qualified and
healthy before deleting the explicitly named old namespace.  Immutable usage
archives, Terraform state, and audit evidence remain retained.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Mapping, Sequence
from urllib.parse import parse_qsl, unquote, urlsplit


KIND_PLAN = "cats.production-clean-slate-plan.v1"
KIND_RECEIPT = "cats.production-clean-slate-reset-receipt.v1"
KIND_GREEN = "cats.production-fresh-namespace-green.v1"
SCHEMA_NAME = re.compile(r"^cats_[a-z][a-z0-9_]{0,61}$")
DNS_LABEL = re.compile(r"^[a-z0-9](?:[-a-z0-9]{0,61}[a-z0-9])?$")
AWS_ACCOUNT = re.compile(r"^[0-9]{12}$")
AWS_REGION = re.compile(r"^[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+$")
BUCKET_NAME = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
HEX_SHA256 = re.compile(r"^[0-9a-f]{64}$")
RESET_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
COMPONENTS = ("gateway", "controller", "node_agent", "vmm", "blockd")
MAX_JSON_BYTES = 64 * 1024
MAX_LIST_PAGES = 100_000
MAX_S3_ENTRIES = 5_000_000
EXPECTED_FRESH_CONTROL_SCHEMA_VERSION = "14"
POST_GREEN_MAX_AGE_SECONDS = 15 * 60
POSTGRES_QUERY_PARAMETERS = {
    "channel_binding",
    "connect_timeout",
    "gssencmode",
    "keepalives",
    "keepalives_count",
    "keepalives_idle",
    "keepalives_interval",
    "krbsrvname",
    "options",
    "requirepeer",
    "sslcert",
    "sslcrl",
    "sslcrldir",
    "sslkey",
    "ssl_max_protocol_version",
    "ssl_min_protocol_version",
    "sslmode",
    "sslnegotiation",
    "sslpassword",
    "sslrootcert",
    "target_session_attrs",
    "tcp_user_timeout",
}


class ResetError(RuntimeError):
    """A safe, non-secret explanation for a refused reset."""


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


class CommandRunner:
    """No-shell subprocess boundary; secret DSNs are allowed only in env."""

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> CommandResult:
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                env=dict(env) if env is not None else None,
                timeout=timeout,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ResetError(f"command failed before a result: {argv[0]}") from error
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclasses.dataclass(frozen=True)
class Config:
    reset_id: str
    release_sha: str
    aws_account_id: str
    aws_region: str
    eks_cluster_name: str
    kubernetes_namespace: str
    kubeconfig: Path
    kube_context: str
    control_postgres_url_file: Path
    control_schema: str
    usage_postgres_url_file: Path
    usage_schema: str
    chunkstore_bucket: str
    chunkstore_prefix: str
    usage_kinesis_stream: str
    usage_checkpoint_table: str
    usage_archive_bucket: str
    new_control_postgres_url_file: Path
    new_control_schema: str
    new_usage_postgres_url_file: Path
    new_usage_schema: str
    new_chunkstore_bucket: str
    new_chunkstore_prefix: str
    new_usage_kinesis_stream: str
    new_usage_checkpoint_table: str
    new_usage_archive_bucket: str
    post_green_evidence_file: Path
    receipt_directory: Path

    @property
    def object_prefix(self) -> str:
        return f"{self.chunkstore_prefix}/"

    @property
    def new_object_prefix(self) -> str:
        return f"{self.new_chunkstore_prefix}/"

    def targets(self) -> dict[str, Any]:
        return {
            "aws_account_id": self.aws_account_id,
            "aws_region": self.aws_region,
            "eks_cluster_name": self.eks_cluster_name,
            "kubernetes_namespace": self.kubernetes_namespace,
            "old": {
                "control_schema": self.control_schema,
                "usage_schema": self.usage_schema,
                "chunkstore_bucket": self.chunkstore_bucket,
                "chunkstore_object_prefix": self.object_prefix,
                "usage_kinesis_stream": self.usage_kinesis_stream,
                "usage_checkpoint_table": self.usage_checkpoint_table,
                "usage_archive_bucket": self.usage_archive_bucket,
            },
            "fresh": self.fresh_targets(),
        }

    def fresh_targets(self) -> dict[str, Any]:
        return {
            "control_schema": self.new_control_schema,
            "usage_schema": self.new_usage_schema,
            "chunkstore_bucket": self.new_chunkstore_bucket,
            "chunkstore_object_prefix": self.new_object_prefix,
            "usage_kinesis_stream": self.new_usage_kinesis_stream,
            "usage_checkpoint_table": self.new_usage_checkpoint_table,
            "usage_archive_bucket": self.new_usage_archive_bucket,
        }


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def parse_time(value: Any, field: str) -> dt.datetime:
    if not isinstance(value, str) or not value.endswith("Z"):
        raise ResetError(f"{field} must be an RFC3339 UTC timestamp ending in Z")
    try:
        parsed = dt.datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as error:
        raise ResetError(f"{field} is not a valid RFC3339 timestamp") from error
    if parsed.utcoffset() != dt.timedelta(0):
        raise ResetError(f"{field} must be UTC")
    return parsed


def require_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ResetError(f"{context} must be a JSON object")
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise ResetError(f"{context} has a non-canonical field set; missing={missing}, extra={extra}")
    return value


def read_json_file(path: Path, context: str, *, canonical: bool = False) -> tuple[dict[str, Any], str]:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
    except OSError as error:
        raise ResetError(f"cannot securely open {context}") from error
    try:
        if not stat.S_ISREG(before.st_mode):
            raise ResetError(f"{context} must be a regular, non-symlink file")
        if before.st_size <= 0 or before.st_size > MAX_JSON_BYTES:
            raise ResetError(f"{context} must be between 1 and {MAX_JSON_BYTES} bytes")
        chunks = bytearray()
        while len(chunks) <= MAX_JSON_BYTES:
            chunk = os.read(descriptor, min(4096, MAX_JSON_BYTES + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResetError(f"{context} changed while it was read")
        raw = bytes(chunks)
    except OSError as error:
        raise ResetError(f"cannot securely read {context}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise ResetError(f"{context} must be between 1 and {MAX_JSON_BYTES} bytes")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ResetError(f"{context} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise ResetError(f"{context} must be a JSON object")
    if canonical and raw != canonical_bytes(value):
        raise ResetError(f"{context} is not canonical JSON")
    return value, sha256_bytes(raw)


def read_small_file(path: Path, context: str, maximum: int) -> bytes:
    """Read one bounded regular file without following its final symlink."""

    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
    except OSError as error:
        raise ResetError(f"cannot securely open {context}") from error
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise ResetError(f"{context} must be a bounded regular file")
        chunks = bytearray()
        while len(chunks) <= maximum:
            chunk = os.read(descriptor, min(4096, maximum + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        raw = bytes(chunks)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResetError(f"{context} changed while it was read")
    except OSError as error:
        raise ResetError(f"cannot securely read {context}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if len(raw) != before.st_size:
        raise ResetError(f"{context} changed length while it was read")
    return raw


def read_stage_receipt(
    directory: Path, reset_id: str, stage: str
) -> tuple[Path, dict[str, Any], str] | None:
    """Load one immutable canonical receipt pair, or report that both files are absent."""

    path = directory / f"{reset_id}.{stage}.json"
    checksum = directory / f"{reset_id}.{stage}.sha256"
    path_exists = path.exists() or path.is_symlink()
    checksum_exists = checksum.exists() or checksum.is_symlink()
    if not path_exists and not checksum_exists:
        return None
    if path_exists != checksum_exists:
        raise ResetError(f"receipt pair for {stage} is incomplete")
    value, digest = read_json_file(path, f"{stage} receipt", canonical=True)
    expected_checksum = f"{digest}  {path.name}\n".encode("ascii")
    if read_small_file(checksum, f"{stage} receipt checksum", 256) != expected_checksum:
        raise ResetError(f"receipt checksum for {stage} does not match its canonical bytes")
    return path, value, digest


def atomic_write_new(path: Path, payload: bytes) -> str:
    """Publish one immutable file by same-directory link, never overwrite."""

    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.is_symlink() or not path.parent.is_dir():
        raise ResetError("receipt directory must be a real directory")
    digest = sha256_bytes(payload)
    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            raise ResetError(f"refusing to overwrite receipt {path.name}") from error
        directory_fd = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass
    return digest


def write_receipt(directory: Path, reset_id: str, stage: str, value: dict[str, Any]) -> tuple[Path, str]:
    path = directory / f"{reset_id}.{stage}.json"
    payload = canonical_bytes(value)
    digest = atomic_write_new(path, payload)
    checksum = directory / f"{reset_id}.{stage}.sha256"
    atomic_write_new(checksum, f"{digest}  {path.name}\n".encode("ascii"))
    return path, digest


def validate_config(config: Config) -> None:
    checks = [
        (RESET_ID, config.reset_id, "reset_id"),
        (HEX_SHA256, config.release_sha, "release_sha"),
        (AWS_ACCOUNT, config.aws_account_id, "aws_account_id"),
        (AWS_REGION, config.aws_region, "aws_region"),
        (DNS_LABEL, config.eks_cluster_name, "eks_cluster_name"),
        (DNS_LABEL, config.kubernetes_namespace, "kubernetes_namespace"),
        (BUCKET_NAME, config.chunkstore_bucket, "chunkstore_bucket"),
        (BUCKET_NAME, config.usage_archive_bucket, "usage_archive_bucket"),
        (BUCKET_NAME, config.new_chunkstore_bucket, "new_chunkstore_bucket"),
        (BUCKET_NAME, config.new_usage_archive_bucket, "new_usage_archive_bucket"),
        (SCHEMA_NAME, config.control_schema, "control_schema"),
        (SCHEMA_NAME, config.usage_schema, "usage_schema"),
        (SCHEMA_NAME, config.new_control_schema, "new_control_schema"),
        (SCHEMA_NAME, config.new_usage_schema, "new_usage_schema"),
    ]
    for pattern, value, field in checks:
        if not pattern.fullmatch(value):
            raise ResetError(f"invalid {field}")
    schemas = [
        config.control_schema,
        config.usage_schema,
        config.new_control_schema,
        config.new_usage_schema,
    ]
    if len(set(schemas)) != len(schemas):
        raise ResetError("old and fresh control/usage schemas must all be distinct")
    for bucket in [config.chunkstore_bucket, config.new_chunkstore_bucket]:
        if bucket in {config.usage_archive_bucket, config.new_usage_archive_bucket}:
            raise ResetError("a usage archive bucket must not be a ChunkStore bucket")
    if config.usage_archive_bucket == config.new_usage_archive_bucket:
        raise ResetError("fresh and old usage archive buckets must be distinct")
    for prefix, field in [
        (config.chunkstore_prefix, "chunkstore_prefix"),
        (config.new_chunkstore_prefix, "new_chunkstore_prefix"),
    ]:
        if (
            not prefix
            or prefix.startswith("/")
            or prefix.endswith("/")
            or ".." in prefix
            or "//" in prefix
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._/-]{0,254}", prefix)
        ):
            raise ResetError(f"{field} must be one non-empty relative canonical prefix")
    if config.chunkstore_bucket == config.new_chunkstore_bucket and (
        config.object_prefix.startswith(config.new_object_prefix)
        or config.new_object_prefix.startswith(config.object_prefix)
    ):
        raise ResetError("old and fresh ChunkStore prefixes overlap in the same bucket")
    if not config.kube_context.strip() or any(char in config.kube_context for char in "\r\n"):
        raise ResetError("invalid kube_context")
    for path, field in [
        (config.kubeconfig, "kubeconfig"),
        (config.control_postgres_url_file, "control_postgres_url_file"),
        (config.usage_postgres_url_file, "usage_postgres_url_file"),
        (config.new_control_postgres_url_file, "new_control_postgres_url_file"),
        (config.new_usage_postgres_url_file, "new_usage_postgres_url_file"),
        (config.post_green_evidence_file, "post_green_evidence_file"),
        (config.receipt_directory, "receipt_directory"),
    ]:
        if not path.is_absolute():
            raise ResetError(f"{field} must be an absolute path")
    try:
        receipt_stat = config.receipt_directory.stat(follow_symlinks=False)
    except OSError as error:
        raise ResetError("receipt_directory must already exist") from error
    if (
        not stat.S_ISDIR(receipt_stat.st_mode)
        or config.receipt_directory.is_symlink()
        or receipt_stat.st_uid != os.geteuid()
        or receipt_stat.st_mode & 0o077
    ):
        raise ResetError("receipt_directory must be a private actor-owned real directory")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", config.usage_kinesis_stream):
        raise ResetError("invalid usage_kinesis_stream")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}", config.new_usage_kinesis_stream):
        raise ResetError("invalid new_usage_kinesis_stream")
    if config.usage_kinesis_stream == config.new_usage_kinesis_stream:
        raise ResetError("fresh and old Kinesis stream names must be distinct")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", config.usage_checkpoint_table):
        raise ResetError("invalid usage_checkpoint_table")
    if not re.fullmatch(r"[A-Za-z0-9_.-]{3,255}", config.new_usage_checkpoint_table):
        raise ResetError("invalid new_usage_checkpoint_table")
    if config.usage_checkpoint_table == config.new_usage_checkpoint_table:
        raise ResetError("fresh and old checkpoint table names must be distinct")


def read_secret_file(path: Path, label: str) -> str:
    descriptor = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
    except OSError as error:
        raise ResetError(f"cannot securely open {label}") from error
    try:
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise ResetError(f"{label} must be a single-link regular file")
        if before.st_mode & 0o077:
            raise ResetError(f"{label} must not be group- or world-accessible")
        if before.st_size <= 0 or before.st_size > 16 * 1024:
            raise ResetError(f"{label} has an invalid size")
        chunks = bytearray()
        while len(chunks) <= 16 * 1024:
            chunk = os.read(descriptor, min(4096, 16 * 1024 + 1 - len(chunks)))
            if not chunk:
                break
            chunks.extend(chunk)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ):
            raise ResetError(f"{label} changed while it was read")
        if len(chunks) > 16 * 1024:
            raise ResetError(f"{label} exceeds the maximum size")
        value = bytes(chunks).decode("utf-8").strip()
    except (OSError, UnicodeDecodeError) as error:
        raise ResetError(f"cannot securely read {label}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
    if any(character in value for character in "\r\n"):
        raise ResetError(f"{label} must contain exactly one line")
    postgres_service_parameters(value, label)
    return value


def postgres_service_parameters(dsn: str, label: str) -> dict[str, str]:
    """Translate one PostgreSQL URL into a private libpq service file."""

    try:
        parsed = urlsplit(dsn)
        port = parsed.port or 5432
    except ValueError as error:
        raise ResetError(f"{label} contains an invalid PostgreSQL URL") from error
    if parsed.scheme not in {"postgres", "postgresql"} or parsed.fragment:
        raise ResetError(f"{label} must contain one PostgreSQL URL without a fragment")
    database = unquote(parsed.path.removeprefix("/"))
    username = unquote(parsed.username or "")
    password = unquote(parsed.password or "")
    hostname = parsed.hostname or ""
    if not all([database, username, password, hostname]):
        raise ResetError(f"{label} must include host, database, user, and password")
    parameters = {
        "host": hostname,
        "port": str(port),
        "dbname": database,
        "user": username,
        "password": password,
    }
    try:
        query = parse_qsl(parsed.query, keep_blank_values=True, strict_parsing=True)
    except ValueError as error:
        raise ResetError(f"{label} contains an invalid PostgreSQL query") from error
    for key, value in query:
        if key not in POSTGRES_QUERY_PARAMETERS:
            raise ResetError(f"{label} contains unsupported PostgreSQL option {key!r}")
        if key in parameters:
            raise ResetError(f"{label} repeats PostgreSQL option {key!r}")
        parameters[key] = value
    if parameters.get("sslmode") not in {"require", "verify-ca", "verify-full"}:
        raise ResetError(f"{label} must require PostgreSQL TLS")
    for value in parameters.values():
        if not value or any(ord(character) < 32 or ord(character) == 127 for character in value):
            raise ResetError(f"{label} contains an empty or control-character parameter")
    return parameters


def postgres_service_value(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'") + "'"


class ResetExecutor:
    def __init__(
        self,
        config: Config,
        runner: CommandRunner,
        *,
        now: dt.datetime | None = None,
    ) -> None:
        validate_config(config)
        self.config = config
        self.runner = runner
        self.now = (now or utc_now()).astimezone(dt.timezone.utc)
        self._fixed_now = now is not None
        self.control_dsn = read_secret_file(
            config.control_postgres_url_file, "control PostgreSQL URL file"
        )
        self.usage_dsn = read_secret_file(
            config.usage_postgres_url_file, "usage PostgreSQL URL file"
        )
        self.new_control_dsn = read_secret_file(
            config.new_control_postgres_url_file, "fresh control PostgreSQL URL file"
        )
        self.new_usage_dsn = read_secret_file(
            config.new_usage_postgres_url_file, "fresh usage PostgreSQL URL file"
        )

    def _current_time(self) -> dt.datetime:
        return self.now if self._fixed_now else utc_now()

    def _run(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> str:
        result = self.runner.run(argv, env=env)
        if result.returncode != 0:
            # Deliberately exclude stderr: cloud and database tools can include
            # connection strings, object keys, or response bodies in errors.
            raise ResetError(f"{Path(argv[0]).name} command failed closed")
        return result.stdout

    def _json_command(
        self, argv: Sequence[str], context: str, *, env: Mapping[str, str] | None = None
    ) -> dict[str, Any]:
        output = self._run(argv, env=env)
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise ResetError(f"{context} returned invalid JSON") from error
        if not isinstance(value, dict):
            raise ResetError(f"{context} returned a non-object")
        return value

    def _aws_json(self, service: str, operation: str, *arguments: str) -> dict[str, Any]:
        return self._json_command(
            [
                "aws",
                "--no-cli-pager",
                "--no-paginate",
                "--region",
                self.config.aws_region,
                "--output",
                "json",
                service,
                operation,
                *arguments,
            ],
            f"AWS {service} {operation}",
        )

    def _aws_json_or_not_found(
        self,
        service: str,
        operation: str,
        not_found_code: str,
        *arguments: str,
    ) -> dict[str, Any] | None:
        """Return None only for the service's exact authoritative not-found error."""

        argv = [
            "aws",
            "--no-cli-pager",
            "--no-paginate",
            "--region",
            self.config.aws_region,
            "--output",
            "json",
            service,
            operation,
            *arguments,
        ]
        result = self.runner.run(argv)
        if result.returncode != 0:
            if f"({not_found_code})" in result.stderr:
                return None
            raise ResetError(f"AWS {service} {operation} failed closed")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ResetError(f"AWS {service} {operation} returned invalid JSON") from error
        if not isinstance(value, dict):
            raise ResetError(f"AWS {service} {operation} returned a non-object")
        return value

    def _aws(self, service: str, operation: str, *arguments: str) -> str:
        return self._run(
            [
                "aws",
                "--no-cli-pager",
                "--no-paginate",
                "--region",
                self.config.aws_region,
                "--output",
                "json",
                service,
                operation,
                *arguments,
            ]
        )

    def _kubectl_json(self, *arguments: str) -> dict[str, Any]:
        return self._json_command(
            [
                "kubectl",
                "--kubeconfig",
                str(self.config.kubeconfig),
                "--context",
                self.config.kube_context,
                *arguments,
                "-o",
                "json",
            ],
            "kubectl",
        )

    def _psql(self, dsn: str, sql: str) -> str:
        environment = dict(os.environ)
        for name in list(environment):
            if name == "DATABASE_URL" or name.startswith("PG"):
                environment.pop(name, None)
        parameters = postgres_service_parameters(dsn, "PostgreSQL URL")
        descriptor, service_name = tempfile.mkstemp(prefix=".cats-reset-pg-service.")
        service_path = Path(service_name)
        try:
            os.fchmod(descriptor, 0o600)
            service = "[cats_reset]\n" + "".join(
                f"{key}={postgres_service_value(value)}\n"
                for key, value in sorted(parameters.items())
            )
            with os.fdopen(descriptor, "w", encoding="utf-8", closefd=True) as handle:
                handle.write(service)
                handle.flush()
                os.fsync(handle.fileno())
            environment.update(
                {
                    "PGSERVICE": "cats_reset",
                    "PGSERVICEFILE": service_name,
                    "PGCONNECT_TIMEOUT": "10",
                    "PGAPPNAME": f"cats-clean-slate-{self.config.reset_id}",
                }
            )
            return self._run(
                [
                    "psql",
                    "-X",
                    "--no-psqlrc",
                    "--set",
                    "ON_ERROR_STOP=1",
                    "--tuples-only",
                    "--no-align",
                    "--command",
                    sql,
                ],
                env=environment,
            ).strip()
        finally:
            try:
                service_path.unlink()
            except FileNotFoundError:
                pass

    def _post_green_evidence(
        self, *, freshness_at: dt.datetime | None = None
    ) -> tuple[dict[str, Any], str]:
        value, digest = read_json_file(
            self.config.post_green_evidence_file, "post-green evidence"
        )
        require_keys(
            value,
            {
                "kind",
                "version",
                "reset_id",
                "observed_at",
                "qualified_release_sha",
                "aws_account_id",
                "aws_region",
                "eks_cluster_name",
                "kubernetes_namespace",
                "fresh_targets",
                "qualification",
                "qualification_manifest_sha256",
                "old_writers",
            },
            "post-green evidence",
        )
        if value["kind"] != KIND_GREEN or value["version"] != 1:
            raise ResetError("unsupported post-green evidence kind/version")
        expected = {
            "reset_id": self.config.reset_id,
            "qualified_release_sha": self.config.release_sha,
            "aws_account_id": self.config.aws_account_id,
            "aws_region": self.config.aws_region,
            "eks_cluster_name": self.config.eks_cluster_name,
            "kubernetes_namespace": self.config.kubernetes_namespace,
        }
        for field, target in expected.items():
            if value[field] != target:
                raise ResetError(f"post-green evidence {field} does not match the target")
        if value["fresh_targets"] != self.config.fresh_targets():
            raise ResetError("post-green evidence fresh targets do not match this invocation")
        if value["qualification"] != "passed":
            raise ResetError("fresh namespace qualification is not passed")
        old_writers = require_keys(value["old_writers"], set(COMPONENTS), "old_writers")
        if any(old_writers[name] != "stopped_or_isolated" for name in COMPONENTS):
            raise ResetError("every old-writer declaration must bind the qualification manifest")
        manifest_digest = value["qualification_manifest_sha256"]
        if not isinstance(manifest_digest, str) or not HEX_SHA256.fullmatch(
            manifest_digest
        ):
            raise ResetError("invalid qualification evidence manifest digest")
        reference = (freshness_at or self.now).astimezone(dt.timezone.utc)
        observed = parse_time(value["observed_at"], "post-green observed_at")
        if observed > reference:
            raise ResetError("post-green evidence timestamp is in the future")
        if (reference - observed).total_seconds() > POST_GREEN_MAX_AGE_SECONDS:
            raise ResetError("post-green evidence is older than the closed 15-minute window")
        return value, digest

    def _cloud_identity(self) -> dict[str, Any]:
        identity = self._aws_json("sts", "get-caller-identity")
        if identity.get("Account") != self.config.aws_account_id:
            raise ResetError("AWS caller account does not match the explicit target")
        caller_arn = identity.get("Arn")
        if not isinstance(caller_arn, str) or not caller_arn.startswith("arn:"):
            raise ResetError("AWS caller identity has no valid ARN")
        eks = self._aws_json(
            "eks", "describe-cluster", "--name", self.config.eks_cluster_name
        ).get("cluster")
        if not isinstance(eks, dict):
            raise ResetError("EKS describe response omitted cluster")
        expected_arn_suffix = (
            f":eks:{self.config.aws_region}:{self.config.aws_account_id}:"
            f"cluster/{self.config.eks_cluster_name}"
        )
        if not str(eks.get("arn", "")).endswith(expected_arn_suffix):
            raise ResetError("EKS cluster ARN does not match account/region/name")
        if eks.get("status") != "ACTIVE":
            raise ResetError("EKS cluster is not ACTIVE")
        endpoint = eks.get("endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            raise ResetError("EKS cluster endpoint is invalid")
        return {
            "eks_cluster_arn": eks["arn"],
            "eks_endpoint_sha256": sha256_bytes(endpoint.encode("utf-8")),
            "eks_endpoint": endpoint,
        }

    def _kubernetes_green(self, endpoint: str) -> dict[str, Any]:
        context_server = self._run(
            [
                "kubectl",
                "--kubeconfig",
                str(self.config.kubeconfig),
                "--context",
                self.config.kube_context,
                "config",
                "view",
                "--minify",
                "--output",
                "jsonpath={.clusters[0].cluster.server}",
            ]
        ).strip()
        if context_server != endpoint:
            raise ResetError("kubeconfig context endpoint does not match the explicit EKS cluster")
        namespace = self._kubectl_json("get", "namespace", self.config.kubernetes_namespace)
        metadata = namespace.get("metadata")
        if not isinstance(metadata, dict) or metadata.get("name") != self.config.kubernetes_namespace:
            raise ResetError("Kubernetes namespace identity mismatch")
        namespace_uid = metadata.get("uid")
        if not isinstance(namespace_uid, str) or not namespace_uid:
            raise ResetError("Kubernetes namespace has no UID")

        deployments = self._kubectl_json(
            "get",
            "deployments",
            "--namespace",
            self.config.kubernetes_namespace,
            "--selector",
            "app.kubernetes.io/name=cats-controld",
        ).get("items")
        if not isinstance(deployments, list) or len(deployments) != 1:
            raise ResetError("expected exactly one Terraform cats-controld Deployment")
        deployment = deployments[0]
        spec = deployment.get("spec", {})
        status_value = deployment.get("status", {})
        desired = spec.get("replicas")
        if not isinstance(desired, int) or desired < 2:
            raise ResetError("fresh cats-controld does not have at least two desired replicas")
        for field in ["replicas", "readyReplicas", "availableReplicas", "updatedReplicas"]:
            if status_value.get(field, 0) != desired:
                raise ResetError("fresh cats-controld Deployment is not fully available")
        dep_metadata = deployment.get("metadata", {})
        generation = dep_metadata.get("generation")
        if not isinstance(generation, int) or status_value.get("observedGeneration", 0) < generation:
            raise ResetError("fresh cats-controld rollout has not observed the current generation")

        pods = self._kubectl_json(
            "get",
            "pods",
            "--namespace",
            self.config.kubernetes_namespace,
            "--selector",
            "app.kubernetes.io/name=cats-controld",
        ).get("items")
        if not isinstance(pods, list) or len(pods) != desired:
            raise ResetError("Kubernetes pod inventory is malformed")
        for pod in pods:
            status = pod.get("status", {})
            ready = any(
                condition.get("type") == "Ready" and condition.get("status") == "True"
                for condition in status.get("conditions", [])
                if isinstance(condition, dict)
            )
            if status.get("phase") != "Running" or not ready:
                raise ResetError("a fresh cats-controld Pod is not Running and Ready")

        ingresses = self._kubectl_json(
            "get",
            "ingresses",
            "--namespace",
            self.config.kubernetes_namespace,
            "--selector",
            "app.kubernetes.io/part-of=cats",
        ).get("items")
        if not isinstance(ingresses, list) or len(ingresses) != 1:
            raise ResetError("fresh Cats public Ingress is not uniquely present")
        ingress_classes = self._kubectl_json(
            "get",
            "ingressclasses",
            "--selector",
            "app.kubernetes.io/part-of=cats",
        ).get("items")
        if not isinstance(ingress_classes, list) or len(ingress_classes) != 1:
            raise ResetError("fresh Cats public IngressClass is not uniquely present")
        return {
            "namespace_uid": namespace_uid,
            "control_deployment_uid": dep_metadata.get("uid"),
            "control_deployment_generation": generation,
            "control_replicas": desired,
            "ready_control_pods": desired,
            "cats_ingresses": 1,
            "cats_ingress_classes": 1,
        }

    def _bucket_region(self, bucket: str) -> str:
        value = self._aws_json(
            "s3api",
            "get-bucket-location",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            self.config.aws_account_id,
        )
        location = value.get("LocationConstraint")
        if location is None:
            return "us-east-1"
        if location == "EU":
            return "eu-west-1"
        if not isinstance(location, str):
            raise ResetError("S3 bucket location is malformed")
        return location

    def _usage_archive(self, archive_bucket: str) -> dict[str, Any]:
        if self._bucket_region(archive_bucket) != self.config.aws_region:
            raise ResetError("usage archive bucket region does not match the explicit region")
        archive_versioning = self._aws_json(
            "s3api",
            "get-bucket-versioning",
            "--bucket",
            archive_bucket,
            "--expected-bucket-owner",
            self.config.aws_account_id,
        )
        if archive_versioning.get("Status") != "Enabled":
            raise ResetError("usage archive bucket versioning is not Enabled")
        object_lock = self._aws_json(
            "s3api",
            "get-object-lock-configuration",
            "--bucket",
            archive_bucket,
            "--expected-bucket-owner",
            self.config.aws_account_id,
        ).get("ObjectLockConfiguration")
        if not isinstance(object_lock, dict) or object_lock.get("ObjectLockEnabled") != "Enabled":
            raise ResetError("usage archive bucket Object Lock is not Enabled")
        return {
            "archive_bucket": archive_bucket,
            "archive_versioning": "Enabled",
            "archive_object_lock": "Enabled",
        }

    def _stream_summary(
        self, stream_name: str, *, allow_absent: bool = False
    ) -> dict[str, Any] | None:
        response = self._aws_json_or_not_found(
            "kinesis",
            "describe-stream-summary",
            "ResourceNotFoundException",
            "--stream-name",
            stream_name,
        )
        if response is None:
            if allow_absent:
                return None
            raise ResetError("usage Kinesis stream is absent")
        summary = response.get("StreamDescriptionSummary")
        if not isinstance(summary, dict):
            raise ResetError("Kinesis stream summary is malformed")
        expected_suffix = (
            f":kinesis:{self.config.aws_region}:{self.config.aws_account_id}:"
            f"stream/{stream_name}"
        )
        if not str(summary.get("StreamARN", "")).endswith(expected_suffix):
            raise ResetError("usage Kinesis stream ARN does not match the explicit target")
        retention_hours = summary.get("RetentionPeriodHours")
        if not isinstance(retention_hours, int) or not 24 <= retention_hours <= 8760:
            raise ResetError("usage Kinesis retention is invalid")
        return {
            "stream_arn": summary["StreamARN"],
            "stream_status": summary.get("StreamStatus"),
            "retention_hours": retention_hours,
        }

    def _table_summary(
        self, table_name: str, *, allow_absent: bool = False
    ) -> dict[str, Any] | None:
        response = self._aws_json_or_not_found(
            "dynamodb",
            "describe-table",
            "ResourceNotFoundException",
            "--table-name",
            table_name,
        )
        if response is None:
            if allow_absent:
                return None
            raise ResetError("usage checkpoint table is absent")
        table = response.get("Table")
        if not isinstance(table, dict):
            raise ResetError("DynamoDB checkpoint table response is malformed")
        expected_table_suffix = (
            f":dynamodb:{self.config.aws_region}:{self.config.aws_account_id}:"
            f"table/{table_name}"
        )
        if not str(table.get("TableArn", "")).endswith(expected_table_suffix):
            raise ResetError("usage checkpoint table ARN does not match the explicit target")
        return {
            "checkpoint_table_arn": table["TableArn"],
            "table_status": table.get("TableStatus"),
        }

    def _usage_resources(
        self, stream_name: str, table_name: str, archive_bucket: str
    ) -> dict[str, Any]:
        stream = self._stream_summary(stream_name)
        table = self._table_summary(table_name)
        if stream is None or stream["stream_status"] != "ACTIVE":
            raise ResetError("usage Kinesis stream is not ACTIVE")
        if table is None or table["table_status"] != "ACTIVE":
            raise ResetError("usage checkpoint table is not ACTIVE")
        archive = self._usage_archive(archive_bucket)
        return {
            "stream_arn": stream["stream_arn"],
            "retention_hours": stream["retention_hours"],
            "checkpoint_table_arn": table["checkpoint_table_arn"],
            **archive,
        }

    def _s3_inventory(
        self, bucket: str, object_prefix: str
    ) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]]]:
        if self._bucket_region(bucket) != self.config.aws_region:
            raise ResetError("ChunkStore bucket region does not match the explicit region")
        versioning = self._aws_json(
            "s3api",
            "get-bucket-versioning",
            "--bucket",
            bucket,
            "--expected-bucket-owner",
            self.config.aws_account_id,
        )
        if versioning.get("Status") != "Enabled" or versioning.get("MFADelete") == "Enabled":
            raise ResetError("ChunkStore bucket must have versioning Enabled and MFA Delete off")

        objects: list[dict[str, str]] = []
        uploads: list[dict[str, str]] = []
        key_marker: str | None = None
        version_marker: str | None = None
        seen_markers: set[tuple[str | None, str | None]] = set()
        pages = 0
        while True:
            arguments = [
                "--bucket",
                bucket,
                "--prefix",
                object_prefix,
                "--expected-bucket-owner",
                self.config.aws_account_id,
                "--max-keys",
                "1000",
            ]
            if key_marker is not None:
                arguments.extend(["--key-marker", key_marker])
            if version_marker is not None:
                arguments.extend(["--version-id-marker", version_marker])
            page = self._aws_json("s3api", "list-object-versions", *arguments)
            pages += 1
            for kind, field in [("version", "Versions"), ("delete_marker", "DeleteMarkers")]:
                entries = page.get(field, [])
                if not isinstance(entries, list):
                    raise ResetError("S3 version inventory is malformed")
                for entry in entries:
                    key = entry.get("Key") if isinstance(entry, dict) else None
                    version_id = entry.get("VersionId") if isinstance(entry, dict) else None
                    if (
                        not isinstance(key, str)
                        or not key.startswith(object_prefix)
                        or not isinstance(version_id, str)
                        or not version_id
                    ):
                        raise ResetError("S3 returned an object outside the exact versioned prefix")
                    objects.append({"key": key, "version_id": version_id, "kind": kind})
                    if len(objects) > MAX_S3_ENTRIES:
                        raise ResetError("S3 reset inventory exceeds the reviewed entry bound")
            if not page.get("IsTruncated", False):
                break
            next_pair = (page.get("NextKeyMarker"), page.get("NextVersionIdMarker"))
            if not isinstance(next_pair[0], str) or not next_pair[0] or next_pair in seen_markers:
                raise ResetError("S3 version pagination did not make progress")
            seen_markers.add(next_pair)
            key_marker, version_marker = next_pair
            if pages >= MAX_LIST_PAGES:
                raise ResetError("S3 version pagination exceeded its reviewed page bound")

        key_marker = None
        upload_marker: str | None = None
        seen_upload_markers: set[tuple[str | None, str | None]] = set()
        upload_pages = 0
        while True:
            arguments = [
                "--bucket",
                bucket,
                "--prefix",
                object_prefix,
                "--expected-bucket-owner",
                self.config.aws_account_id,
                "--max-uploads",
                "1000",
            ]
            if key_marker is not None:
                arguments.extend(["--key-marker", key_marker])
            if upload_marker is not None:
                arguments.extend(["--upload-id-marker", upload_marker])
            page = self._aws_json("s3api", "list-multipart-uploads", *arguments)
            upload_pages += 1
            entries = page.get("Uploads", [])
            if not isinstance(entries, list):
                raise ResetError("S3 multipart inventory is malformed")
            for entry in entries:
                key = entry.get("Key") if isinstance(entry, dict) else None
                upload_id = entry.get("UploadId") if isinstance(entry, dict) else None
                if (
                    not isinstance(key, str)
                    or not key.startswith(object_prefix)
                    or not isinstance(upload_id, str)
                    or not upload_id
                ):
                    raise ResetError("S3 returned a multipart upload outside the exact prefix")
                uploads.append({"key": key, "upload_id": upload_id})
                if len(uploads) > MAX_S3_ENTRIES:
                    raise ResetError("S3 multipart inventory exceeds the reviewed entry bound")
            if not page.get("IsTruncated", False):
                break
            next_pair = (page.get("NextKeyMarker"), page.get("NextUploadIdMarker"))
            if not all(isinstance(item, str) and item for item in next_pair) or next_pair in seen_upload_markers:
                raise ResetError("S3 multipart pagination did not make progress")
            seen_upload_markers.add(next_pair)
            key_marker, upload_marker = next_pair
            if upload_pages >= MAX_LIST_PAGES:
                raise ResetError("S3 multipart pagination exceeded its reviewed page bound")

        version_lines = [
            f"{entry['kind']}\0{entry['key']}\0{entry['version_id']}\n"
            for entry in sorted(objects, key=lambda item: (item["key"], item["version_id"], item["kind"]))
        ]
        upload_lines = [
            f"{entry['key']}\0{entry['upload_id']}\n"
            for entry in sorted(uploads, key=lambda item: (item["key"], item["upload_id"]))
        ]
        summary = {
            "bucket_versioning": "Enabled",
            "version_pages": pages,
            "versions": sum(item["kind"] == "version" for item in objects),
            "delete_markers": sum(item["kind"] == "delete_marker" for item in objects),
            "version_inventory_sha256": sha256_bytes("".join(version_lines).encode("utf-8")),
            "multipart_pages": upload_pages,
            "multipart_uploads": len(uploads),
            "multipart_inventory_sha256": sha256_bytes("".join(upload_lines).encode("utf-8")),
        }
        return summary, objects, uploads

    def _database_schema(self, dsn: str, schema: str, marker: str) -> dict[str, Any]:
        quoted_schema = f'"{schema}"'
        quoted_marker = f'"{marker}"'
        sql = f"""
SELECT json_build_object(
  'database', current_database(),
  'server_address', COALESCE(inet_server_addr()::text, ''),
  'server_port', inet_server_port(),
  'current_user', current_user,
  'schema_exists', EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '{schema}'),
  'schema_owner', (SELECT pg_get_userbyid(nspowner) FROM pg_namespace WHERE nspname = '{schema}'),
  'marker_exists', to_regclass('{quoted_schema}.{quoted_marker}') IS NOT NULL,
  'relations', COALESCE((
    SELECT json_agg(json_build_array(c.relkind::text, c.relname) ORDER BY c.relkind::text, c.relname)
      FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace
     WHERE n.nspname = '{schema}'
  ), '[]'::json)
)::text;
"""
        try:
            catalog = json.loads(self._psql(dsn, sql))
        except json.JSONDecodeError as error:
            raise ResetError("PostgreSQL schema inventory returned invalid JSON") from error
        if not isinstance(catalog, dict):
            raise ResetError("PostgreSQL schema inventory is malformed")
        if catalog.get("schema_exists") is not True or catalog.get("marker_exists") is not True:
            raise ResetError(f"{schema} is not an existing Cats schema with marker {marker}")
        if catalog.get("schema_owner") != catalog.get("current_user"):
            raise ResetError(f"reset actor is not the owner of schema {schema}")
        relations = catalog.get("relations")
        if not isinstance(relations, list) or not relations:
            raise ResetError(f"schema {schema} has no canonical relations")
        version_sql = (
            f"SELECT json_build_object('version', max(version)::text)::text "
            f"FROM {quoted_schema}.{quoted_marker};"
        )
        try:
            version_value = json.loads(self._psql(dsn, version_sql))
        except json.JSONDecodeError as error:
            raise ResetError("PostgreSQL schema marker returned invalid JSON") from error
        version = version_value.get("version") if isinstance(version_value, dict) else None
        if not isinstance(version, str) or not version.isdigit():
            raise ResetError(f"schema {schema} has no valid numeric version")
        dependency_sql = f"""
WITH RECURSIVE closure(classid, objid, objsubid) AS (
  SELECT DISTINCT d.refclassid, d.refobjid, d.refobjsubid
    FROM pg_depend d
    CROSS JOIN LATERAL pg_identify_object(
      d.refclassid, d.refobjid, d.refobjsubid
    ) referenced
   WHERE referenced.schema = '{schema}'
  UNION
  SELECT d.classid, d.objid, d.objsubid
    FROM closure c
    JOIN pg_depend d
      ON d.refclassid = c.classid
     AND d.refobjid = c.objid
     AND d.refobjsubid = c.objsubid
   WHERE d.deptype IN ('n', 'a', 'i', 'P', 'S')
), outside AS (
  SELECT DISTINCT identified.type, identified.schema, identified.name, identified.identity
    FROM closure c
    CROSS JOIN LATERAL pg_identify_object(c.classid, c.objid, c.objsubid) identified
   WHERE identified.schema IS NOT NULL
     AND identified.schema <> '{schema}'
     AND identified.schema <> 'information_schema'
     AND identified.schema !~ '^pg_'
)
SELECT COALESCE(
  json_agg(json_build_array(type, schema, name, identity)
           ORDER BY type, schema, name, identity),
  '[]'::json
)::text
FROM outside;
"""
        try:
            outside_dependencies = json.loads(self._psql(dsn, dependency_sql))
        except json.JSONDecodeError as error:
            raise ResetError("PostgreSQL dependency inventory returned invalid JSON") from error
        if not isinstance(outside_dependencies, list):
            raise ResetError("PostgreSQL dependency inventory is malformed")
        if outside_dependencies:
            raise ResetError(
                f"schema {schema} has dependencies in a non-target schema; refusing CASCADE"
            )
        relation_bytes = canonical_bytes(relations)
        identity = {
            "database": catalog.get("database"),
            "server_address": catalog.get("server_address"),
            "server_port": catalog.get("server_port"),
        }
        return {
            "connection_identity_sha256": sha256_bytes(canonical_bytes(identity)),
            "schema": schema,
            "schema_owner": catalog.get("schema_owner"),
            "marker": marker,
            "schema_version": version,
            "relation_count": len(relations),
            "relation_inventory_sha256": sha256_bytes(relation_bytes),
            "external_dependency_count": 0,
        }

    def preflight(self) -> tuple[dict[str, Any], list[dict[str, str]], list[dict[str, str]]]:
        green, green_digest = self._post_green_evidence()
        cloud = self._cloud_identity()
        kubernetes = self._kubernetes_green(cloud.pop("eks_endpoint"))
        old_usage_resources = self._usage_resources(
            self.config.usage_kinesis_stream,
            self.config.usage_checkpoint_table,
            self.config.usage_archive_bucket,
        )
        fresh_usage_resources = self._usage_resources(
            self.config.new_usage_kinesis_stream,
            self.config.new_usage_checkpoint_table,
            self.config.new_usage_archive_bucket,
        )
        old_s3, objects, uploads = self._s3_inventory(
            self.config.chunkstore_bucket, self.config.object_prefix
        )
        fresh_s3, _fresh_objects, _fresh_uploads = self._s3_inventory(
            self.config.new_chunkstore_bucket, self.config.new_object_prefix
        )
        old_control = self._database_schema(
            self.control_dsn, self.config.control_schema, "control_schema_version"
        )
        old_usage = self._database_schema(
            self.usage_dsn, self.config.usage_schema, "schema_migrations"
        )
        fresh_control = self._database_schema(
            self.new_control_dsn,
            self.config.new_control_schema,
            "control_schema_version",
        )
        if fresh_control["schema_version"] != EXPECTED_FRESH_CONTROL_SCHEMA_VERSION:
            raise ResetError(
                "fresh control schema is not the required terminal schema version 14"
            )
        fresh_usage = self._database_schema(
            self.new_usage_dsn, self.config.new_usage_schema, "schema_migrations"
        )
        stable = {
            "targets": self.config.targets(),
            "release_sha": self.config.release_sha,
            "post_green_evidence_sha256": green_digest,
            "qualification_manifest_sha256": green["qualification_manifest_sha256"],
            "cloud": cloud,
            "kubernetes": kubernetes,
            "old_usage_resources": old_usage_resources,
            "fresh_usage_resources": fresh_usage_resources,
            "chunkstore": {"old": old_s3, "fresh": fresh_s3},
            "databases": {
                "old_control": old_control,
                "old_usage": old_usage,
                "fresh_control": fresh_control,
                "fresh_usage": fresh_usage,
            },
        }
        return stable, objects, uploads

    def _delete_s3(
        self, objects: Sequence[dict[str, str]], uploads: Sequence[dict[str, str]]
    ) -> dict[str, int]:
        deleted_versions = 0
        deleted_markers = 0
        for offset in range(0, len(objects), 1000):
            batch = list(objects[offset : offset + 1000])
            request = {
                "Objects": [
                    {"Key": item["key"], "VersionId": item["version_id"]} for item in batch
                ],
                "Quiet": False,
            }
            fd, filename = tempfile.mkstemp(
                prefix=f".{self.config.reset_id}.s3-delete.", dir=self.config.receipt_directory
            )
            try:
                os.fchmod(fd, 0o600)
                with os.fdopen(fd, "wb", closefd=True) as handle:
                    handle.write(canonical_bytes(request))
                    handle.flush()
                    os.fsync(handle.fileno())
                response = self._aws_json(
                    "s3api",
                    "delete-objects",
                    "--bucket",
                    self.config.chunkstore_bucket,
                    "--expected-bucket-owner",
                    self.config.aws_account_id,
                    "--delete",
                    f"file://{filename}",
                )
            finally:
                try:
                    Path(filename).unlink()
                except FileNotFoundError:
                    pass
            if response.get("Errors"):
                raise ResetError("S3 DeleteObjects returned one or more errors")
            deleted = response.get("Deleted")
            if not isinstance(deleted, list) or len(deleted) != len(batch):
                raise ResetError("S3 DeleteObjects did not acknowledge every exact version")
            expected = sorted((item["key"], item["version_id"]) for item in batch)
            actual = sorted(
                (
                    item.get("Key"),
                    item.get("VersionId") or item.get("DeleteMarkerVersionId"),
                )
                for item in deleted
            )
            if actual != expected:
                raise ResetError("S3 DeleteObjects acknowledgement did not match the exact batch")
            deleted_versions += sum(item["kind"] == "version" for item in batch)
            deleted_markers += sum(item["kind"] == "delete_marker" for item in batch)

        for upload in uploads:
            # AbortMultipartUpload has no response document in the AWS CLI.
            self._aws(
                "s3api",
                "abort-multipart-upload",
                "--bucket",
                self.config.chunkstore_bucket,
                "--key",
                upload["key"],
                "--upload-id",
                upload["upload_id"],
                "--expected-bucket-owner",
                self.config.aws_account_id,
            )
        return {
            "versions": deleted_versions,
            "delete_markers": deleted_markers,
            "multipart_uploads": len(uploads),
        }

    def _assert_current_objects_empty(self) -> int:
        token: str | None = None
        pages = 0
        seen: set[str] = set()
        while True:
            arguments = [
                "--bucket",
                self.config.chunkstore_bucket,
                "--prefix",
                self.config.object_prefix,
                "--expected-bucket-owner",
                self.config.aws_account_id,
                "--max-keys",
                "1000",
            ]
            if token is not None:
                arguments.extend(["--continuation-token", token])
            page = self._aws_json("s3api", "list-objects-v2", *arguments)
            pages += 1
            contents = page.get("Contents", [])
            if not isinstance(contents, list):
                raise ResetError("S3 current-object verification is malformed")
            if contents:
                raise ResetError("ChunkStore prefix still has current objects after deletion")
            if not page.get("IsTruncated", False):
                return pages
            next_token = page.get("NextContinuationToken")
            if not isinstance(next_token, str) or not next_token or next_token in seen:
                raise ResetError("S3 current-object pagination did not make progress")
            seen.add(next_token)
            token = next_token
            if pages >= MAX_LIST_PAGES:
                raise ResetError("S3 current-object pagination exceeded its reviewed page bound")

    def _s3_empty_proof(self) -> dict[str, Any]:
        summary, objects, uploads = self._s3_inventory(
            self.config.chunkstore_bucket, self.config.object_prefix
        )
        current_pages = self._assert_current_objects_empty()
        if objects or uploads:
            raise ResetError("ChunkStore prefix is not authoritatively empty")
        return {
            "bucket": self.config.chunkstore_bucket,
            "object_prefix": self.config.object_prefix,
            "versions": 0,
            "delete_markers": 0,
            "multipart_uploads": 0,
            "version_pages": summary["version_pages"],
            "multipart_pages": summary["multipart_pages"],
            "current_object_pages": current_pages,
            "verified_at": format_time(utc_now()),
        }

    def _aws_wait(self, service: str, waiter: str, *arguments: str) -> None:
        result = self.runner.run(
            [
                "aws",
                "--no-cli-pager",
                "--no-paginate",
                "--region",
                self.config.aws_region,
                service,
                "wait",
                waiter,
                *arguments,
            ],
            timeout=900,
        )
        if result.returncode != 0:
            raise ResetError(f"AWS {service} {waiter} waiter failed closed")

    def _settle_old_usage_transport(self) -> dict[str, Any]:
        stream = self._stream_summary(
            self.config.usage_kinesis_stream, allow_absent=True
        )
        stream_delete_requested = False
        if stream is not None:
            if stream["stream_status"] == "ACTIVE":
                self._aws(
                    "kinesis",
                    "delete-stream",
                    "--stream-name",
                    self.config.usage_kinesis_stream,
                    "--enforce-consumer-deletion",
                )
                stream_delete_requested = True
            elif stream["stream_status"] != "DELETING":
                raise ResetError("old Kinesis stream is neither ACTIVE nor DELETING")
            self._aws_wait(
                "kinesis",
                "stream-not-exists",
                "--stream-name",
                self.config.usage_kinesis_stream,
            )
        if self._stream_summary(self.config.usage_kinesis_stream, allow_absent=True) is not None:
            raise ResetError("old Kinesis stream still exists after its absence proof")

        table = self._table_summary(
            self.config.usage_checkpoint_table, allow_absent=True
        )
        table_delete_requested = False
        if table is not None:
            if table["table_status"] == "ACTIVE":
                self._aws(
                    "dynamodb",
                    "delete-table",
                    "--table-name",
                    self.config.usage_checkpoint_table,
                )
                table_delete_requested = True
            elif table["table_status"] != "DELETING":
                raise ResetError("old checkpoint table is neither ACTIVE nor DELETING")
            self._aws_wait(
                "dynamodb",
                "table-not-exists",
                "--table-name",
                self.config.usage_checkpoint_table,
            )
        if self._table_summary(self.config.usage_checkpoint_table, allow_absent=True) is not None:
            raise ResetError("old checkpoint table still exists after its absence proof")
        return {
            "old_stream": self.config.usage_kinesis_stream,
            "stream_delete_requested_this_attempt": stream_delete_requested,
            "stream_absent": True,
            "old_checkpoint_table": self.config.usage_checkpoint_table,
            "table_delete_requested_this_attempt": table_delete_requested,
            "table_absent": True,
            "old_archive_bucket": self.config.usage_archive_bucket,
            "old_archive_action": "retained_object_lock_evidence",
            "verified_at": format_time(utc_now()),
        }

    def _assert_old_usage_transport_absent(self) -> dict[str, Any]:
        if self._stream_summary(self.config.usage_kinesis_stream, allow_absent=True) is not None:
            raise ResetError("old Kinesis stream reappeared after its stage receipt")
        if self._table_summary(self.config.usage_checkpoint_table, allow_absent=True) is not None:
            raise ResetError("old checkpoint table reappeared after its stage receipt")
        return {
            "old_stream": self.config.usage_kinesis_stream,
            "stream_absent": True,
            "old_checkpoint_table": self.config.usage_checkpoint_table,
            "table_absent": True,
            "old_archive_bucket": self.config.usage_archive_bucket,
            "old_archive_action": "retained_object_lock_evidence",
            "verified_at": format_time(utc_now()),
        }

    def _drop_schema(self, dsn: str, before: Mapping[str, Any]) -> None:
        schema = str(before["schema"])
        marker = str(before["marker"])
        version = str(before["schema_version"])
        sql = f"""
BEGIN;
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '60s';
SELECT pg_advisory_xact_lock(hashtextextended('cats-clean-slate-reset:{schema}', 0));
DO $cats_reset$
DECLARE actual_version text;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname = '{schema}') THEN
    RAISE EXCEPTION 'target schema vanished';
  END IF;
  SELECT max(version)::text INTO actual_version FROM "{schema}"."{marker}";
  IF actual_version IS DISTINCT FROM '{version}' THEN
    RAISE EXCEPTION 'target schema version changed';
  END IF;
END
$cats_reset$;
DROP SCHEMA "{schema}" CASCADE;
COMMIT;
"""
        self._psql(dsn, sql)

    def _assert_schema_absent(self, dsn: str, schema: str) -> dict[str, Any]:
        output = self._psql(
            dsn,
            f"SELECT json_build_object('schema_exists', EXISTS "
            f"(SELECT 1 FROM pg_namespace WHERE nspname = '{schema}'))::text;",
        )
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise ResetError("PostgreSQL empty-schema proof returned invalid JSON") from error
        if not isinstance(value, dict) or value.get("schema_exists") is not False:
            raise ResetError(f"schema {schema} still exists after reset")
        return {"schema": schema, "schema_exists": False, "verified_at": format_time(utc_now())}

    def _schema_exists(self, dsn: str, schema: str) -> bool:
        output = self._psql(
            dsn,
            f"SELECT json_build_object('schema_exists', EXISTS "
            f"(SELECT 1 FROM pg_namespace WHERE nspname = '{schema}'))::text;",
        )
        try:
            value = json.loads(output)
        except json.JSONDecodeError as error:
            raise ResetError("PostgreSQL schema presence probe returned invalid JSON") from error
        if not isinstance(value, dict) or not isinstance(value.get("schema_exists"), bool):
            raise ResetError("PostgreSQL schema presence probe is malformed")
        return value["schema_exists"]

    def _settle_schema_absent(
        self, dsn: str, schema: str, marker: str, expected: Mapping[str, Any]
    ) -> dict[str, Any]:
        if self._schema_exists(dsn, schema):
            current = self._database_schema(dsn, schema, marker)
            if current != expected:
                raise ResetError(f"{schema} changed before its exact DROP")
            self._drop_schema(dsn, expected)
        return self._assert_schema_absent(dsn, schema)

    def _validate_plan_receipt(self, plan: dict[str, Any]) -> dict[str, Any]:
        require_keys(
            plan,
            {
                "kind",
                "version",
                "mode",
                "reset_id",
                "created_at",
                "post_green_evidence_sha256",
                "stable_preflight",
                "stable_preflight_sha256",
                "destructive_actions",
                "retained",
                "rollback_boundary",
            },
            "plan receipt",
        )
        if (
            plan["kind"] != KIND_PLAN
            or plan["version"] != 1
            or plan["mode"] != "read_only_plan"
            or plan["reset_id"] != self.config.reset_id
        ):
            raise ResetError("plan receipt identity does not match this invocation")
        parse_time(plan["created_at"], "plan created_at")
        stable = plan["stable_preflight"]
        if not isinstance(stable, dict):
            raise ResetError("plan receipt stable preflight is malformed")
        require_keys(
            stable,
            {
                "targets",
                "release_sha",
                "post_green_evidence_sha256",
                "qualification_manifest_sha256",
                "cloud",
                "kubernetes",
                "old_usage_resources",
                "fresh_usage_resources",
                "chunkstore",
                "databases",
            },
            "plan stable preflight",
        )
        if stable.get("targets") != self.config.targets():
            raise ResetError("plan receipt destructive targets do not match this invocation")
        if stable.get("release_sha") != self.config.release_sha:
            raise ResetError("plan receipt release does not match this invocation")
        stable_digest = plan["stable_preflight_sha256"]
        if not isinstance(stable_digest, str) or not HEX_SHA256.fullmatch(stable_digest):
            raise ResetError("plan receipt stable preflight digest is malformed")
        if sha256_bytes(canonical_bytes(stable)) != stable_digest:
            raise ResetError("plan receipt internal preflight digest is invalid")
        evidence_digest = plan["post_green_evidence_sha256"]
        if (
            not isinstance(evidence_digest, str)
            or not HEX_SHA256.fullmatch(evidence_digest)
            or stable.get("post_green_evidence_sha256") != evidence_digest
        ):
            raise ResetError("plan receipt post-green evidence binding is invalid")
        qualification_digest = stable["qualification_manifest_sha256"]
        if not isinstance(qualification_digest, str) or not HEX_SHA256.fullmatch(
            qualification_digest
        ):
            raise ResetError("plan receipt qualification manifest binding is invalid")
        chunkstore = require_keys(
            stable["chunkstore"], {"old", "fresh"}, "plan ChunkStore boundary"
        )
        inventory_keys = {
            "bucket_versioning",
            "version_pages",
            "versions",
            "delete_markers",
            "version_inventory_sha256",
            "multipart_pages",
            "multipart_uploads",
            "multipart_inventory_sha256",
        }
        for name in ("old", "fresh"):
            inventory = require_keys(
                chunkstore[name], inventory_keys, f"plan {name} ChunkStore inventory"
            )
            for field in ("versions", "delete_markers", "multipart_uploads"):
                if type(inventory[field]) is not int or inventory[field] < 0:
                    raise ResetError(f"plan {name} ChunkStore {field} is malformed")
        require_keys(
            stable["databases"],
            {"old_control", "old_usage", "fresh_control", "fresh_usage"},
            "plan database boundary",
        )
        for field in (
            "cloud",
            "kubernetes",
            "old_usage_resources",
            "fresh_usage_resources",
            "databases",
        ):
            if not isinstance(stable[field], dict):
                raise ResetError(f"plan stable preflight {field} is malformed")
        return stable

    def _receipt_common(
        self, plan_digest: str, stable_digest: str, evidence_digest: str
    ) -> dict[str, Any]:
        return {
            "kind": KIND_RECEIPT,
            "version": 1,
            "reset_id": self.config.reset_id,
            "release_sha": self.config.release_sha,
            "targets": self.config.targets(),
            "plan_receipt_sha256": plan_digest,
            "stable_preflight_sha256": stable_digest,
            "post_green_evidence_sha256": evidence_digest,
        }

    def _validate_receipt_common(
        self, value: dict[str, Any], common: Mapping[str, Any], stage: str
    ) -> None:
        for field, expected in common.items():
            if value.get(field) != expected:
                raise ResetError(f"{stage} receipt {field} binding drifted")
        parse_time(value.get("created_at"), f"{stage} receipt created_at")

    def _load_receipt_chain(
        self, common: Mapping[str, Any], stable: Mapping[str, Any]
    ) -> dict[str, tuple[Path, dict[str, Any], str]]:
        names = [
            "reset-started",
            "s3-empty",
            "usage-transport-empty",
            "control-schema-empty",
            "usage-schema-empty",
            "reset-complete",
        ]
        loaded: dict[str, tuple[Path, dict[str, Any], str]] = {}
        planned_old_chunkstore = stable["chunkstore"]["old"]
        expected_retired_inventory = {
            field: planned_old_chunkstore[field]
            for field in ("versions", "delete_markers", "multipart_uploads")
        }
        gap = False
        for name in names:
            receipt = read_stage_receipt(self.config.receipt_directory, self.config.reset_id, name)
            if receipt is None:
                gap = True
                continue
            if gap:
                raise ResetError(f"receipt chain has a gap before {name}")
            loaded[name] = receipt

        common_keys = set(common)
        previous_time: dt.datetime | None = None
        for name in names:
            if name not in loaded:
                continue
            _path, value, _digest = loaded[name]
            self._validate_receipt_common(value, common, name)
            created = parse_time(value["created_at"], f"{name} receipt created_at")
            if previous_time is not None and created < previous_time:
                raise ResetError(f"receipt time moved backwards at {name}")
            previous_time = created

            extra_keys: set[str]
            expected_stage: str
            if name == "reset-started":
                expected_stage = "destructive_execution_started"
                extra_keys = {"stage", "created_at", "mutations_executed", "operator_rule"}
                if value.get("mutations_executed") is not True:
                    raise ResetError("reset-started receipt does not cross the boundary")
            elif name == "s3-empty":
                expected_stage = "chunkstore_prefix_empty"
                extra_keys = {
                    "stage",
                    "created_at",
                    "started_receipt_sha256",
                    "retired_inventory",
                    "authoritative_empty_proof",
                }
                if value.get("started_receipt_sha256") != loaded["reset-started"][2]:
                    raise ResetError("s3-empty receipt predecessor drifted")
                proof = value.get("authoritative_empty_proof")
                if not isinstance(proof, dict) or (
                    proof.get("bucket"), proof.get("object_prefix")
                ) != (self.config.chunkstore_bucket, self.config.object_prefix):
                    raise ResetError("s3-empty receipt target proof drifted")
                if value.get("retired_inventory") != expected_retired_inventory or any(
                    proof.get(field) != 0
                    for field in ("versions", "delete_markers", "multipart_uploads")
                ):
                    raise ResetError("s3-empty receipt inventory proof drifted")
            elif name == "usage-transport-empty":
                expected_stage = "old_usage_transport_absent"
                extra_keys = {
                    "stage",
                    "created_at",
                    "s3_empty_receipt_sha256",
                    "authoritative_empty_proof",
                }
                if value.get("s3_empty_receipt_sha256") != loaded["s3-empty"][2]:
                    raise ResetError("usage-transport receipt predecessor drifted")
                proof = value.get("authoritative_empty_proof")
                if not isinstance(proof, dict) or (
                    proof.get("old_stream"), proof.get("old_checkpoint_table")
                ) != (
                    self.config.usage_kinesis_stream,
                    self.config.usage_checkpoint_table,
                ):
                    raise ResetError("usage-transport receipt target proof drifted")
                if proof.get("stream_absent") is not True or proof.get("table_absent") is not True:
                    raise ResetError("usage-transport receipt absence proof drifted")
            elif name == "control-schema-empty":
                expected_stage = "control_schema_absent"
                extra_keys = {
                    "stage",
                    "created_at",
                    "usage_transport_empty_receipt_sha256",
                    "authoritative_empty_proof",
                }
                if value.get("usage_transport_empty_receipt_sha256") != loaded[
                    "usage-transport-empty"
                ][2]:
                    raise ResetError("control-schema receipt predecessor drifted")
                proof = value.get("authoritative_empty_proof")
                if (
                    not isinstance(proof, dict)
                    or proof.get("schema") != self.config.control_schema
                    or proof.get("schema_exists") is not False
                ):
                    raise ResetError("control-schema receipt target proof drifted")
            elif name == "usage-schema-empty":
                expected_stage = "usage_schema_absent"
                extra_keys = {
                    "stage",
                    "created_at",
                    "control_empty_receipt_sha256",
                    "authoritative_empty_proof",
                }
                if value.get("control_empty_receipt_sha256") != loaded[
                    "control-schema-empty"
                ][2]:
                    raise ResetError("usage-schema receipt predecessor drifted")
                proof = value.get("authoritative_empty_proof")
                if (
                    not isinstance(proof, dict)
                    or proof.get("schema") != self.config.usage_schema
                    or proof.get("schema_exists") is not False
                ):
                    raise ResetError("usage-schema receipt target proof drifted")
            else:
                expected_stage = "complete"
                extra_keys = {
                    "stage",
                    "created_at",
                    "started_receipt",
                    "started_receipt_sha256",
                    "s3_empty_receipt_sha256",
                    "usage_transport_empty_receipt_sha256",
                    "control_empty_receipt_sha256",
                    "usage_empty_receipt_sha256",
                    "retired_inventory",
                    "authoritative_empty_proof",
                    "fresh_namespace_proof",
                    "retained_usage_boundaries",
                    "rollback_boundary",
                    "next_gate",
                }
                expected_digests = {
                    "started_receipt_sha256": loaded["reset-started"][2],
                    "s3_empty_receipt_sha256": loaded["s3-empty"][2],
                    "usage_transport_empty_receipt_sha256": loaded[
                        "usage-transport-empty"
                    ][2],
                    "control_empty_receipt_sha256": loaded["control-schema-empty"][2],
                    "usage_empty_receipt_sha256": loaded["usage-schema-empty"][2],
                }
                if value.get("started_receipt") != loaded["reset-started"][0].name:
                    raise ResetError("complete receipt start name drifted")
                if any(value.get(field) != digest for field, digest in expected_digests.items()):
                    raise ResetError("complete receipt chain digest drifted")
                expected_fresh_proof = {
                    "qualification_manifest_sha256": stable[
                        "qualification_manifest_sha256"
                    ],
                    "control_schema_version": stable["databases"]["fresh_control"][
                        "schema_version"
                    ],
                    "usage_resources": stable["fresh_usage_resources"],
                }
                expected_empty_proof = {
                    "chunkstore": loaded["s3-empty"][1]["authoritative_empty_proof"],
                    "usage_transport": loaded["usage-transport-empty"][1][
                        "authoritative_empty_proof"
                    ],
                    "control": loaded["control-schema-empty"][1][
                        "authoritative_empty_proof"
                    ],
                    "usage_billing": loaded["usage-schema-empty"][1][
                        "authoritative_empty_proof"
                    ],
                }
                if (
                    value.get("retired_inventory") != expected_retired_inventory
                    or value.get("fresh_namespace_proof") != expected_fresh_proof
                    or value.get("authoritative_empty_proof") != expected_empty_proof
                    or value.get("retained_usage_boundaries")
                    != {
                        "old_archive_bucket": self.config.usage_archive_bucket,
                        "action": "retained_object_lock_evidence",
                    }
                ):
                    raise ResetError("complete receipt proof drifted")
            require_keys(value, common_keys | extra_keys, f"{name} receipt")
            if value.get("stage") != expected_stage:
                raise ResetError(f"{name} receipt stage drifted")
        return loaded

    def _resume_preflight(
        self,
        stable: Mapping[str, Any],
        evidence_digest: str,
        started: Mapping[str, Any],
    ) -> dict[str, Any]:
        started_at = parse_time(started.get("created_at"), "reset-started created_at")
        green, live_evidence_digest = self._post_green_evidence(freshness_at=started_at)
        if live_evidence_digest != evidence_digest:
            raise ResetError("post-green evidence changed after reset-started")
        cloud = self._cloud_identity()
        kubernetes = self._kubernetes_green(cloud.pop("eks_endpoint"))
        if cloud != stable.get("cloud") or kubernetes != stable.get("kubernetes"):
            raise ResetError("fresh cloud/Kubernetes identity drifted during forward-resume")

        old_archive = self._usage_archive(self.config.usage_archive_bucket)
        expected_old_usage = stable.get("old_usage_resources")
        if not isinstance(expected_old_usage, dict) or any(
            old_archive.get(field) != expected_old_usage.get(field)
            for field in old_archive
        ):
            raise ResetError("retained old usage archive identity drifted")
        fresh_usage = self._usage_resources(
            self.config.new_usage_kinesis_stream,
            self.config.new_usage_checkpoint_table,
            self.config.new_usage_archive_bucket,
        )
        if fresh_usage != stable.get("fresh_usage_resources"):
            raise ResetError("fresh usage authority drifted during forward-resume")
        fresh_s3, _objects, _uploads = self._s3_inventory(
            self.config.new_chunkstore_bucket, self.config.new_object_prefix
        )
        chunkstore = stable.get("chunkstore")
        if not isinstance(chunkstore, dict) or fresh_s3 != chunkstore.get("fresh"):
            raise ResetError("fresh ChunkStore identity/inventory drifted during forward-resume")
        databases = stable.get("databases")
        if not isinstance(databases, dict):
            raise ResetError("plan database identities are malformed")
        fresh_control = self._database_schema(
            self.new_control_dsn,
            self.config.new_control_schema,
            "control_schema_version",
        )
        fresh_usage_schema = self._database_schema(
            self.new_usage_dsn, self.config.new_usage_schema, "schema_migrations"
        )
        if (
            fresh_control != databases.get("fresh_control")
            or fresh_usage_schema != databases.get("fresh_usage")
            or fresh_control.get("schema_version") != EXPECTED_FRESH_CONTROL_SCHEMA_VERSION
        ):
            raise ResetError("fresh PostgreSQL namespace drifted during forward-resume")
        return {
            "qualification_manifest_sha256": green["qualification_manifest_sha256"],
            "control_schema_version": fresh_control["schema_version"],
            "usage_resources": fresh_usage,
        }

    def _assert_no_effect_ahead(
        self,
        existing: Mapping[str, tuple[Path, dict[str, Any], str]],
        stable: Mapping[str, Any],
    ) -> None:
        """Reject physical completion beyond the first receipt-less stage."""

        stages = [
            "s3-empty",
            "usage-transport-empty",
            "control-schema-empty",
            "usage-schema-empty",
            "reset-complete",
        ]
        first_missing = next(
            (index for index, name in enumerate(stages) if name not in existing),
            len(stages),
        )
        databases = stable["databases"]
        if first_missing < 1:
            stream = self._stream_summary(self.config.usage_kinesis_stream, allow_absent=True)
            table = self._table_summary(
                self.config.usage_checkpoint_table, allow_absent=True
            )
            old_usage = stable["old_usage_resources"]
            if (
                stream is None
                or stream.get("stream_status") != "ACTIVE"
                or stream.get("stream_arn") != old_usage.get("stream_arn")
                or stream.get("retention_hours") != old_usage.get("retention_hours")
                or table is None
                or table.get("table_status") != "ACTIVE"
                or table.get("checkpoint_table_arn")
                != old_usage.get("checkpoint_table_arn")
            ):
                raise ResetError("old usage transport advanced ahead of the receipt chain")
        if first_missing < 2:
            if not self._schema_exists(self.control_dsn, self.config.control_schema):
                raise ResetError("old control schema advanced ahead of the receipt chain")
            if (
                self._database_schema(
                    self.control_dsn,
                    self.config.control_schema,
                    "control_schema_version",
                )
                != databases["old_control"]
            ):
                raise ResetError("old control schema drifted ahead of the receipt chain")
        if first_missing < 3:
            if not self._schema_exists(self.usage_dsn, self.config.usage_schema):
                raise ResetError("old usage schema advanced ahead of the receipt chain")
            if (
                self._database_schema(
                    self.usage_dsn, self.config.usage_schema, "schema_migrations"
                )
                != databases["old_usage"]
            ):
                raise ResetError("old usage schema drifted ahead of the receipt chain")

    def plan(self) -> tuple[Path, str]:
        stable, _objects, _uploads = self.preflight()
        receipt = {
            "kind": KIND_PLAN,
            "version": 1,
            "mode": "read_only_plan",
            "reset_id": self.config.reset_id,
            "created_at": format_time(self.now),
            "post_green_evidence_sha256": stable["post_green_evidence_sha256"],
            "stable_preflight": stable,
            "stable_preflight_sha256": sha256_bytes(canonical_bytes(stable)),
            "destructive_actions": [
                "delete every version and delete marker under the exact old ChunkStore object prefix",
                "abort every multipart upload under the exact old ChunkStore object prefix",
                "delete the exact old Kinesis stream and DynamoDB checkpoint table",
                "drop the exact old dedicated control PostgreSQL schema",
                "drop the exact old dedicated usage/billing PostgreSQL schema",
            ],
            "retained": [
                "Terraform state",
                "old immutable Object-Locked usage archive",
                "the qualified fresh namespace",
                "experiment and audit evidence",
            ],
            "rollback_boundary": "before execute: retain old namespace; after execute starts: fresh namespace forward-fix only",
        }
        return write_receipt(
            self.config.receipt_directory, self.config.reset_id, "plan", receipt
        )

    def apply(
        self,
        plan_path: Path,
        supplied_plan_sha256: str,
        confirmation: str,
        *,
        execute: bool,
    ) -> tuple[Path, str]:
        if not HEX_SHA256.fullmatch(supplied_plan_sha256):
            raise ResetError("--plan-sha256 must be an exact lowercase SHA-256")
        plan, actual_plan_digest = read_json_file(plan_path, "plan receipt", canonical=True)
        if actual_plan_digest != supplied_plan_sha256:
            raise ResetError("plan receipt SHA-256 does not match --plan-sha256")
        if confirmation != self.config.reset_id:
            raise ResetError("--confirm-reset-id does not match the explicit reset target")
        planned_stable = self._validate_plan_receipt(plan)
        stable_digest = plan["stable_preflight_sha256"]
        evidence_digest = plan["post_green_evidence_sha256"]
        common = self._receipt_common(actual_plan_digest, stable_digest, evidence_digest)
        existing = self._load_receipt_chain(common, planned_stable)
        if existing and "reset-started" not in existing:
            raise ResetError("receipt chain exists without reset-started")
        if "reset-started" in existing:
            if not execute:
                raise ResetError("reset already started; use --execute to resume forward")
            started_path, started, started_digest = existing["reset-started"]
            if "reset-complete" in existing:
                complete_path, _complete, complete_digest = existing["reset-complete"]
                green, live_evidence_digest = self._post_green_evidence(
                    freshness_at=parse_time(
                        started["created_at"], "reset-started created_at"
                    )
                )
                if (
                    live_evidence_digest != evidence_digest
                    or green["qualification_manifest_sha256"]
                    != planned_stable["qualification_manifest_sha256"]
                ):
                    raise ResetError("post-green evidence changed after reset-started")
                self._s3_empty_proof()
                self._assert_old_usage_transport_absent()
                self._assert_schema_absent(self.control_dsn, self.config.control_schema)
                self._assert_schema_absent(self.usage_dsn, self.config.usage_schema)
                return complete_path, complete_digest
            fresh_namespace_proof = self._resume_preflight(planned_stable, evidence_digest, started)
            self._assert_no_effect_ahead(existing, planned_stable)
            objects: list[dict[str, str]] = []
            uploads: list[dict[str, str]] = []
        else:
            stable, objects, uploads = self.preflight()
            if sha256_bytes(canonical_bytes(stable)) != stable_digest:
                raise ResetError("live preflight changed since plan; create and review a new plan")
            if stable["post_green_evidence_sha256"] != evidence_digest:
                raise ResetError("live post-green evidence changed since plan")
            fresh_namespace_proof = {
                "qualification_manifest_sha256": stable[
                    "qualification_manifest_sha256"
                ],
                "control_schema_version": stable["databases"]["fresh_control"][
                    "schema_version"
                ],
                "usage_resources": stable["fresh_usage_resources"],
            }
        if not execute:
            dry_run = {
                **common,
                "stage": "validated_dry_run",
                "created_at": format_time(self.now),
                "mutations_executed": False,
                "rollback_boundary": "not crossed",
            }
            return write_receipt(
                self.config.receipt_directory, self.config.reset_id, "dry-run", dry_run
            )
        if "reset-started" not in existing:
            started_at = self._current_time()
            _green, start_evidence_digest = self._post_green_evidence(
                freshness_at=started_at
            )
            if start_evidence_digest != evidence_digest:
                raise ResetError("post-green evidence changed immediately before reset-started")
            started = {
                **common,
                "stage": "destructive_execution_started",
                "created_at": format_time(started_at),
                "mutations_executed": True,
                "operator_rule": "from this receipt onward assume the boundary was crossed; forward-fix only",
            }
            started_path, started_digest = write_receipt(
                self.config.receipt_directory, self.config.reset_id, "reset-started", started
            )

        old_chunkstore = planned_stable["chunkstore"]["old"]
        retired_inventory = {
            field: old_chunkstore[field]
            for field in ("versions", "delete_markers", "multipart_uploads")
        }
        if "s3-empty" in existing:
            _s3_path, s3_value, s3_digest = existing["s3-empty"]
            self._s3_empty_proof()
            s3_empty = s3_value["authoritative_empty_proof"]
        else:
            if not objects and not uploads:
                _summary, objects, uploads = self._s3_inventory(
                    self.config.chunkstore_bucket, self.config.object_prefix
                )
            self._delete_s3(objects, uploads)
            s3_empty = self._s3_empty_proof()
            s3_stage = {
                **common,
                "stage": "chunkstore_prefix_empty",
                "started_receipt_sha256": started_digest,
                "retired_inventory": retired_inventory,
                "authoritative_empty_proof": s3_empty,
                "created_at": format_time(utc_now()),
            }
            _s3_path, s3_digest = write_receipt(
                self.config.receipt_directory, self.config.reset_id, "s3-empty", s3_stage
            )

        if "usage-transport-empty" in existing:
            _transport_path, transport_value, transport_digest = existing[
                "usage-transport-empty"
            ]
            self._assert_old_usage_transport_absent()
            usage_transport_empty = transport_value["authoritative_empty_proof"]
        else:
            usage_transport_empty = self._settle_old_usage_transport()
            transport_stage = {
                **common,
                "stage": "old_usage_transport_absent",
                "s3_empty_receipt_sha256": s3_digest,
                "authoritative_empty_proof": usage_transport_empty,
                "created_at": format_time(utc_now()),
            }
            _transport_path, transport_digest = write_receipt(
                self.config.receipt_directory,
                self.config.reset_id,
                "usage-transport-empty",
                transport_stage,
            )

        databases = planned_stable["databases"]
        if "control-schema-empty" in existing:
            _control_path, control_value, control_digest = existing[
                "control-schema-empty"
            ]
            self._assert_schema_absent(self.control_dsn, self.config.control_schema)
            control_empty = control_value["authoritative_empty_proof"]
        else:
            control_empty = self._settle_schema_absent(
                self.control_dsn,
                self.config.control_schema,
                "control_schema_version",
                databases["old_control"],
            )
            control_stage = {
                **common,
                "stage": "control_schema_absent",
                "usage_transport_empty_receipt_sha256": transport_digest,
                "authoritative_empty_proof": control_empty,
                "created_at": format_time(utc_now()),
            }
            _control_path, control_digest = write_receipt(
                self.config.receipt_directory,
                self.config.reset_id,
                "control-schema-empty",
                control_stage,
            )

        if "usage-schema-empty" in existing:
            _usage_path, usage_value, usage_digest = existing["usage-schema-empty"]
            self._assert_schema_absent(self.usage_dsn, self.config.usage_schema)
            usage_empty = usage_value["authoritative_empty_proof"]
        else:
            usage_empty = self._settle_schema_absent(
                self.usage_dsn,
                self.config.usage_schema,
                "schema_migrations",
                databases["old_usage"],
            )
            usage_stage = {
                **common,
                "stage": "usage_schema_absent",
                "control_empty_receipt_sha256": control_digest,
                "authoritative_empty_proof": usage_empty,
                "created_at": format_time(utc_now()),
            }
            _usage_path, usage_digest = write_receipt(
                self.config.receipt_directory,
                self.config.reset_id,
                "usage-schema-empty",
                usage_stage,
            )

        complete = {
            **common,
            "stage": "complete",
            "created_at": format_time(utc_now()),
            "started_receipt": started_path.name,
            "started_receipt_sha256": started_digest,
            "s3_empty_receipt_sha256": s3_digest,
            "usage_transport_empty_receipt_sha256": transport_digest,
            "control_empty_receipt_sha256": control_digest,
            "usage_empty_receipt_sha256": usage_digest,
            "retired_inventory": retired_inventory,
            "authoritative_empty_proof": {
                "chunkstore": s3_empty,
                "usage_transport": usage_transport_empty,
                "control": control_empty,
                "usage_billing": usage_empty,
            },
            "fresh_namespace_proof": fresh_namespace_proof,
            "retained_usage_boundaries": {
                "old_archive_bucket": self.config.usage_archive_bucket,
                "action": "retained_object_lock_evidence",
            },
            "rollback_boundary": "crossed; forward-fix only",
            "next_gate": "independently verify this old-namespace retirement receipt",
        }
        return write_receipt(
            self.config.receipt_directory, self.config.reset_id, "reset-complete", complete
        )


def add_common_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--reset-id", required=True)
    parser.add_argument("--release-sha", required=True)
    parser.add_argument("--aws-account-id", required=True)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--eks-cluster-name", required=True)
    parser.add_argument("--kubernetes-namespace", required=True)
    parser.add_argument("--kubeconfig", required=True, type=Path)
    parser.add_argument("--kube-context", required=True)
    parser.add_argument("--old-control-postgres-url-file", required=True, type=Path)
    parser.add_argument("--old-control-schema", required=True)
    parser.add_argument("--old-usage-postgres-url-file", required=True, type=Path)
    parser.add_argument("--old-usage-schema", required=True)
    parser.add_argument("--old-chunkstore-bucket", required=True)
    parser.add_argument("--old-chunkstore-prefix", required=True)
    parser.add_argument("--old-usage-kinesis-stream", required=True)
    parser.add_argument("--old-usage-checkpoint-table", required=True)
    parser.add_argument("--old-usage-archive-bucket", required=True)
    parser.add_argument("--fresh-control-postgres-url-file", required=True, type=Path)
    parser.add_argument("--fresh-control-schema", required=True)
    parser.add_argument("--fresh-usage-postgres-url-file", required=True, type=Path)
    parser.add_argument("--fresh-usage-schema", required=True)
    parser.add_argument("--fresh-chunkstore-bucket", required=True)
    parser.add_argument("--fresh-chunkstore-prefix", required=True)
    parser.add_argument("--fresh-usage-kinesis-stream", required=True)
    parser.add_argument("--fresh-usage-checkpoint-table", required=True)
    parser.add_argument("--fresh-usage-archive-bucket", required=True)
    parser.add_argument("--post-green-evidence-file", required=True, type=Path)
    parser.add_argument("--receipt-directory", required=True, type=Path)


def config_from_args(args: argparse.Namespace) -> Config:
    return Config(
        reset_id=args.reset_id,
        release_sha=args.release_sha,
        aws_account_id=args.aws_account_id,
        aws_region=args.aws_region,
        eks_cluster_name=args.eks_cluster_name,
        kubernetes_namespace=args.kubernetes_namespace,
        kubeconfig=args.kubeconfig,
        kube_context=args.kube_context,
        control_postgres_url_file=args.old_control_postgres_url_file,
        control_schema=args.old_control_schema,
        usage_postgres_url_file=args.old_usage_postgres_url_file,
        usage_schema=args.old_usage_schema,
        chunkstore_bucket=args.old_chunkstore_bucket,
        chunkstore_prefix=args.old_chunkstore_prefix,
        usage_kinesis_stream=args.old_usage_kinesis_stream,
        usage_checkpoint_table=args.old_usage_checkpoint_table,
        usage_archive_bucket=args.old_usage_archive_bucket,
        new_control_postgres_url_file=args.fresh_control_postgres_url_file,
        new_control_schema=args.fresh_control_schema,
        new_usage_postgres_url_file=args.fresh_usage_postgres_url_file,
        new_usage_schema=args.fresh_usage_schema,
        new_chunkstore_bucket=args.fresh_chunkstore_bucket,
        new_chunkstore_prefix=args.fresh_chunkstore_prefix,
        new_usage_kinesis_stream=args.fresh_usage_kinesis_stream,
        new_usage_checkpoint_table=args.fresh_usage_checkpoint_table,
        new_usage_archive_bucket=args.fresh_usage_archive_bucket,
        post_green_evidence_file=args.post_green_evidence_file,
        receipt_directory=args.receipt_directory,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    plan_parser = subparsers.add_parser("plan", help="read-only preflight and plan receipt")
    add_common_arguments(plan_parser)
    apply_parser = subparsers.add_parser(
        "apply", help="revalidate a reviewed plan; dry-run unless --execute is present"
    )
    add_common_arguments(apply_parser)
    apply_parser.add_argument("--plan-receipt", required=True, type=Path)
    apply_parser.add_argument("--plan-sha256", required=True)
    apply_parser.add_argument("--confirm-reset-id", required=True)
    apply_parser.add_argument(
        "--execute",
        action="store_true",
        help="cross the irreversible reset boundary; omission is a read-only dry-run",
    )
    args = parser.parse_args(argv)
    try:
        executor = ResetExecutor(config_from_args(args), CommandRunner())
        if args.command == "plan":
            path, digest = executor.plan()
        else:
            path, digest = executor.apply(
                args.plan_receipt,
                args.plan_sha256,
                args.confirm_reset_id,
                execute=args.execute,
            )
        print(json.dumps({"receipt": str(path), "sha256": digest}, sort_keys=True))
        return 0
    except ResetError as error:
        print(f"clean-slate reset refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
