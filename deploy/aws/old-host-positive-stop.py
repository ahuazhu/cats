#!/usr/bin/env python3
"""Produce proposed, retained evidence that every declared old writer is stopped or isolated.

The mutating commands are intentionally narrow: ``local-stop`` may invoke
``systemctl --system --no-ask-password stop`` for units named by a canonical
inventory, and ``ec2-isolate`` may replace every declared instance ENI's
security groups with one independently verified deny-all group.  No shell,
pattern kill, process
signal, instance stop, or instance terminate operation exists in this program.

The evidence format is Proposed.  It is not an ADR-0040 HostFenceEvent, does
not prove an object-write cutoff, and is not accepted by the destructive
production reset executor.
"""

from __future__ import annotations

import argparse
import dataclasses
import datetime as dt
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any, Callable, Mapping, Protocol, Sequence


KIND_INVENTORY = "cats.old-host-positive-stop-inventory.v1"
KIND_INTENT = "cats.old-host-positive-stop-intent.v1"
KIND_HOST_RECEIPT = "cats.old-host-positive-stop-host-receipt.v1"
KIND_EVIDENCE_SET = "cats.old-host-positive-stop-evidence-set.v1"
VERSION = 1
COMPONENTS = ("blockd", "controller", "gateway", "node_agent", "vmm")
LIMITATIONS = {
    "coordination_authority": "none",
    "host_fence_event": "not_established",
    "object_write_fence": "not_established",
    "production_reset_prerequisite": "proposed_unaccepted",
}
MAX_JSON_BYTES = 1024 * 1024
MAX_PROCESSES = 131_072
MAX_UNITS = 64
MAX_ENIS = 32
MAX_HOSTS = 256
MAX_COMMAND_SECONDS = 10.0
ID = re.compile(r"[a-z0-9][a-z0-9-]{0,63}\Z")
UNIT = re.compile(r"[A-Za-z0-9][A-Za-z0-9:_.@-]{0,246}\.service\Z")
SHA256 = re.compile(r"sha256:[0-9a-f]{64}\Z")
BOOT_ID = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\Z"
)
MACHINE_ID = re.compile(r"[0-9a-f]{32}\Z")
UTC_SECOND = re.compile(
    r"[0-9]{4}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]Z\Z"
)
AWS_ACCOUNT = re.compile(r"[0-9]{12}\Z")
AWS_REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]+\Z")
INSTANCE_ID = re.compile(r"i-[0-9a-f]{8,32}\Z")
VPC_ID = re.compile(r"vpc-[0-9a-f]{8,32}\Z")
SG_ID = re.compile(r"sg-[0-9a-f]{8,32}\Z")
ENI_ID = re.compile(r"eni-[0-9a-f]{8,32}\Z")


class PositiveStopError(RuntimeError):
    """A bounded, non-secret explanation for refusing an operation."""


class CommandOutcomeUnknown(PositiveStopError):
    """A command did not return a usable response before its local bound."""


@dataclasses.dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str = ""


class Runner(Protocol):
    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult: ...


class CommandRunner:
    """No-shell subprocess boundary."""

    def run(self, argv: Sequence[str], *, timeout: float) -> CommandResult:
        try:
            completed = subprocess.run(
                list(argv),
                check=False,
                capture_output=True,
                text=True,
                timeout=max(timeout, 0.001),
            )
        except (OSError, subprocess.TimeoutExpired, UnicodeError) as error:
            raise CommandOutcomeUnknown(
                f"{Path(argv[0]).name} returned no bounded result"
            ) from error
        return CommandResult(completed.returncode, completed.stdout, completed.stderr)


@dataclasses.dataclass(frozen=True, order=True)
class ProcessIdentity:
    pid: int
    start_ticks: int
    ppid: int
    executable: str
    argv0: str

    def json(self) -> dict[str, Any]:
        return {
            "argv0": self.argv0,
            "executable": self.executable,
            "pid": self.pid,
            "ppid": self.ppid,
            "start_ticks": self.start_ticks,
        }


@dataclasses.dataclass(frozen=True)
class ProcessSnapshot:
    boot_id: str
    machine_id_sha256: str
    processes: Mapping[int, ProcessIdentity]


class LocalFacts(Protocol):
    def snapshot(self, calibration_pid: int) -> ProcessSnapshot: ...


def _bounded_read(path: Path, maximum: int, *, private: bool = False) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size <= 0 or before.st_size > maximum:
            raise PositiveStopError(f"{path} is not a bounded regular file")
        if private and (
            before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            raise PositiveStopError(
                f"{path} must be an actor-owned mode-0600 single-link file"
            )
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        if (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_uid,
            before.st_gid,
            before.st_nlink,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ) != (
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
            raise PositiveStopError(f"{path} changed while it was read")
        if len(raw) != before.st_size:
            raise PositiveStopError(f"{path} changed length while it was read")
        return bytes(raw)
    except OSError as error:
        raise PositiveStopError(f"cannot securely read {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _bounded_proc_read(path: Path, maximum: int, *, allow_empty: bool = False) -> bytes:
    """Read a procfs pseudo-file whose reported st_size is normally zero."""

    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
        )
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise PositiveStopError(f"{path} is not a procfs regular file")
        raw = bytearray()
        while len(raw) <= maximum:
            part = os.read(descriptor, min(4096, maximum + 1 - len(raw)))
            if not part:
                break
            raw.extend(part)
        after = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_mode) != (
            after.st_dev,
            after.st_ino,
            after.st_mode,
        ):
            raise PositiveStopError(f"{path} changed identity while it was read")
        if len(raw) > maximum or (not raw and not allow_empty):
            raise PositiveStopError(f"{path} was empty or exceeded its fixed bound")
        return bytes(raw)
    except OSError as error:
        raise PositiveStopError(f"cannot securely read {path}") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _parse_proc_stat(raw: bytes, expected_pid: int) -> tuple[int, int, int]:
    try:
        text = raw.decode("ascii")
    except UnicodeDecodeError as error:
        raise PositiveStopError("/proc stat was not ASCII") from error
    closing = text.rfind(") ")
    if closing <= 0:
        raise PositiveStopError("/proc stat was malformed")
    try:
        pid = int(text[: text.find(" ")])
        suffix = text[closing + 2 :].split()
        ppid = int(suffix[1])
        start_ticks = int(suffix[19])
    except (ValueError, IndexError) as error:
        raise PositiveStopError("/proc stat identity was malformed") from error
    if pid != expected_pid or pid <= 0 or ppid < 0 or start_ticks <= 0:
        raise PositiveStopError("/proc stat identity was invalid")
    return pid, ppid, start_ticks


class ProcLocalFacts:
    """Stable, bounded Linux process and Host identity reader."""

    def _identity(self, pid: int) -> ProcessIdentity | None:
        root = Path("/proc") / str(pid)
        try:
            first = _bounded_proc_read(root / "stat", 16 * 1024)
        except PositiveStopError:
            if not root.exists():
                return None
            raise
        first_pid, ppid, start_ticks = _parse_proc_stat(first, pid)
        try:
            executable = os.readlink(root / "exe")
            cmdline = _bounded_proc_read(root / "cmdline", 64 * 1024, allow_empty=True)
            second = _bounded_proc_read(root / "stat", 16 * 1024)
        except (FileNotFoundError, ProcessLookupError):
            return None
        except OSError as error:
            raise PositiveStopError(f"cannot inspect process {pid}") from error
        second_pid, second_ppid, second_start = _parse_proc_stat(second, pid)
        if (first_pid, ppid, start_ticks) != (second_pid, second_ppid, second_start):
            raise PositiveStopError(f"process {pid} changed identity while inspected")
        argv0_raw = cmdline.split(b"\0", 1)[0]
        try:
            argv0 = argv0_raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise PositiveStopError(f"process {pid} argv0 was not UTF-8") from error
        if not executable or "\n" in executable or "\x00" in executable:
            raise PositiveStopError(f"process {pid} executable was invalid")
        if "\n" in argv0 or "\x00" in argv0:
            raise PositiveStopError(f"process {pid} argv0 was invalid")
        return ProcessIdentity(pid, start_ticks, ppid, executable, argv0)

    def snapshot(self, calibration_pid: int) -> ProcessSnapshot:
        try:
            names = [entry.name for entry in os.scandir("/proc") if entry.name.isdigit()]
        except OSError as error:
            raise PositiveStopError("cannot enumerate /proc") from error
        if len(names) > MAX_PROCESSES:
            raise PositiveStopError("process inventory exceeded its fixed bound")
        processes: dict[int, ProcessIdentity] = {}
        for pid in sorted(int(name) for name in names):
            identity = self._identity(pid)
            if identity is not None:
                processes[pid] = identity
        # Calibration: an empty or visibility-restricted process probe may not
        # justify the load-bearing conclusion that runtime binaries are absent.
        if calibration_pid not in processes:
            raise PositiveStopError("process probe did not find its known-positive control")
        machine = _bounded_read(Path("/etc/machine-id"), 256).strip()
        boot = _bounded_proc_read(Path("/proc/sys/kernel/random/boot_id"), 256).strip()
        try:
            machine_text = machine.decode("ascii")
            boot_text = boot.decode("ascii")
        except UnicodeDecodeError as error:
            raise PositiveStopError("Host identity was not ASCII") from error
        if MACHINE_ID.fullmatch(machine_text) is None or BOOT_ID.fullmatch(boot_text) is None:
            raise PositiveStopError("Host identity was malformed")
        return ProcessSnapshot(
            boot_id=boot_text,
            machine_id_sha256="sha256:" + hashlib.sha256(machine).hexdigest(),
            processes=processes,
        )


@dataclasses.dataclass(frozen=True)
class Deadline:
    expires_at: float
    monotonic: Callable[[], float]

    @classmethod
    def start(
        cls, seconds: float, monotonic: Callable[[], float]
    ) -> "Deadline":
        if not math.isfinite(seconds) or seconds <= 0 or seconds > 300:
            raise PositiveStopError("deadline must be in (0, 300] seconds")
        started_at = monotonic()
        if not math.isfinite(started_at):
            raise PositiveStopError("monotonic clock returned a non-finite value")
        return cls(started_at + seconds, monotonic)

    def remaining(self, context: str) -> float:
        value = self.expires_at - self.monotonic()
        if not math.isfinite(value) or value <= 0:
            raise PositiveStopError(f"deadline expired during {context}")
        return value

    def command_timeout(self, context: str) -> float:
        return min(MAX_COMMAND_SECONDS, self.remaining(context))


def _validate_stable_seconds(value: float) -> None:
    if not math.isfinite(value) or value < 0 or value > 30:
        raise PositiveStopError("stable read interval must be in [0, 30] seconds")


def canonical_bytes(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def digest_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def now_utc() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def format_time(value: dt.datetime) -> str:
    return value.astimezone(dt.timezone.utc).replace(microsecond=0).isoformat().replace(
        "+00:00", "Z"
    )


def _validate_time(value: Any, field: str) -> str:
    if not isinstance(value, str) or UTC_SECOND.fullmatch(value) is None:
        raise PositiveStopError(f"{field} is not a canonical UTC timestamp")
    try:
        parsed = dt.datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(
            tzinfo=dt.timezone.utc
        )
    except ValueError as error:
        raise PositiveStopError(f"{field} is not a valid UTC timestamp") from error
    if format_time(parsed) != value:
        raise PositiveStopError(f"{field} is not a canonical UTC timestamp")
    return value


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PositiveStopError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def require_keys(value: Any, expected: set[str], context: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PositiveStopError(f"{context} must be an object")
    actual = set(value)
    if actual != expected:
        raise PositiveStopError(
            f"{context} has a non-canonical field set; "
            f"missing={sorted(expected - actual)}, extra={sorted(actual - expected)}"
        )
    return value


def read_json(
    path: Path, context: str, *, canonical: bool, private: bool = False
) -> tuple[dict[str, Any], str]:
    raw = _bounded_read(path, MAX_JSON_BYTES, private=private)
    try:
        value = json.loads(raw, object_pairs_hook=_strict_object)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PositiveStopError(f"{context} is not valid UTF-8 JSON") from error
    if not isinstance(value, dict):
        raise PositiveStopError(f"{context} must be an object")
    if canonical and raw != canonical_bytes(value):
        raise PositiveStopError(f"{context} is not canonical JSON")
    return value, digest_bytes(raw)


def _validate_absolute_path(value: Any, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value.startswith("/")
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
    ):
        raise PositiveStopError(f"{field} must be a control-free absolute path")
    pure = PurePosixPath(value)
    if str(pure) != value or ".." in pure.parts:
        raise PositiveStopError(f"{field} must be canonical")
    return value


def _validate_sorted_strings(
    value: Any,
    field: str,
    *,
    pattern: re.Pattern[str] | None = None,
    maximum: int,
) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise PositiveStopError(f"{field} must be a non-empty bounded array")
    if any(not isinstance(item, str) for item in value):
        raise PositiveStopError(f"{field} must contain strings")
    result = list(value)
    if result != sorted(set(result)):
        raise PositiveStopError(f"{field} must be sorted and unique")
    if pattern is not None and any(pattern.fullmatch(item) is None for item in result):
        raise PositiveStopError(f"{field} contains an invalid identity")
    return result


def _component_names(host: Mapping[str, Any]) -> list[str]:
    if host["method"] == "ec2_security_group_isolation":
        return list(host["components"])
    return [component["component"] for component in host["components"]]


def validate_inventory(value: dict[str, Any]) -> list[dict[str, Any]]:
    require_keys(
        value,
        {"attempt_id", "hosts", "kind", "required_components", "version"},
        "inventory",
    )
    if (
        value["kind"] != KIND_INVENTORY
        or isinstance(value["version"], bool)
        or not isinstance(value["version"], int)
        or value["version"] != VERSION
    ):
        raise PositiveStopError("unsupported positive-stop inventory kind/version")
    if not isinstance(value["attempt_id"], str) or ID.fullmatch(value["attempt_id"]) is None:
        raise PositiveStopError("inventory attempt_id is invalid")
    if value["required_components"] != list(COMPONENTS):
        raise PositiveStopError("inventory must explicitly require the closed old-writer component set")
    hosts = value["hosts"]
    if not isinstance(hosts, list) or not hosts or len(hosts) > MAX_HOSTS:
        raise PositiveStopError("inventory hosts must be a non-empty bounded array")
    if any(not isinstance(host, dict) for host in hosts):
        raise PositiveStopError("every inventory host must be an object")
    host_ids = [host.get("host_id") for host in hosts]
    if any(not isinstance(host_id, str) or ID.fullmatch(host_id) is None for host_id in host_ids):
        raise PositiveStopError("inventory host_id is invalid")
    if host_ids != sorted(set(host_ids)):
        raise PositiveStopError("inventory hosts must be sorted and unique by host_id")

    covered: set[str] = set()
    local_identities: set[tuple[str, str]] = set()
    ec2_instances: set[tuple[str, str, str]] = set()
    ec2_enis: set[tuple[str, str, str]] = set()
    for index, host in enumerate(hosts):
        method = host.get("method")
        context = f"inventory host {index}"
        if method == "local_systemd":
            require_keys(
                host,
                {
                    "components",
                    "expected_boot_id",
                    "expected_machine_id_sha256",
                    "host_id",
                    "idle_preflight",
                    "method",
                },
                context,
            )
            if not isinstance(host["expected_boot_id"], str) or BOOT_ID.fullmatch(
                host["expected_boot_id"]
            ) is None:
                raise PositiveStopError(f"{context} expected_boot_id is invalid")
            if not isinstance(host["expected_machine_id_sha256"], str) or SHA256.fullmatch(
                host["expected_machine_id_sha256"]
            ) is None:
                raise PositiveStopError(f"{context} machine identity digest is invalid")
            local_identity = (
                host["expected_machine_id_sha256"],
                host["expected_boot_id"],
            )
            if local_identity in local_identities:
                raise PositiveStopError("multiple host IDs reuse one local Host/boot identity")
            local_identities.add(local_identity)
            preflight = require_keys(
                host["idle_preflight"],
                {"helper_path", "metering_cgroup_root", "runtime_bin_root"},
                f"{context} idle_preflight",
            )
            helper = _validate_absolute_path(preflight["helper_path"], "idle helper path")
            if not (
                helper.endswith("/require-idle-worker.sh")
                or helper.endswith("/require-idle-worker")
            ):
                raise PositiveStopError(f"{context} does not name require-idle-worker")
            _validate_absolute_path(
                preflight["metering_cgroup_root"], "metering cgroup root"
            )
            runtime_root = _validate_absolute_path(
                preflight["runtime_bin_root"], "runtime binary root"
            )
            components = host["components"]
            if not isinstance(components, list) or not components or len(components) > len(COMPONENTS):
                raise PositiveStopError(f"{context} components must be non-empty and bounded")
            names: list[str] = []
            for component_index, component in enumerate(components):
                component_context = f"{context} component {component_index}"
                require_keys(
                    component,
                    {"component", "executable_paths", "proof"}
                    | ({"units"} if component.get("proof") == "systemd_stop" else set()),
                    component_context,
                )
                name = component["component"]
                if name not in COMPONENTS:
                    raise PositiveStopError(f"{component_context} name is invalid")
                names.append(name)
                executables = _validate_sorted_strings(
                    component["executable_paths"],
                    f"{component_context} executable_paths",
                    maximum=16,
                )
                for executable in executables:
                    _validate_absolute_path(executable, "component executable")
                proof = component["proof"]
                if proof == "systemd_stop":
                    if name in {"vmm", "blockd"}:
                        raise PositiveStopError(
                            "raw VMM and blockd components may only use process_absence proof"
                        )
                    _validate_sorted_strings(
                        component["units"],
                        f"{component_context} units",
                        pattern=UNIT,
                        maximum=MAX_UNITS,
                    )
                elif proof == "process_absence":
                    if name not in {"vmm", "blockd"}:
                        raise PositiveStopError(
                            "process_absence is reserved for VMM/blockd preservation checks"
                        )
                    expected = (
                        [f"{runtime_root}/cats-blockd"]
                        if name == "blockd"
                        else sorted(
                            [
                                f"{runtime_root}/cats-vmm-launcher",
                                f"{runtime_root}/cloud-hypervisor",
                            ]
                        )
                    )
                    if executables != expected:
                        raise PositiveStopError(
                            f"{component_context} must enumerate the exact protected runtime binaries"
                        )
                else:
                    raise PositiveStopError(f"{component_context} proof is invalid")
            if names != sorted(set(names)):
                raise PositiveStopError(f"{context} components must be sorted and unique")
            if not any(component["proof"] == "systemd_stop" for component in components):
                raise PositiveStopError(
                    f"{context} must name at least one explicit systemd unit to stop"
                )
        elif method == "ec2_security_group_isolation":
            require_keys(host, {"aws", "components", "host_id", "method"}, context)
            names = _validate_sorted_strings(
                host["components"], f"{context} components", maximum=len(COMPONENTS)
            )
            if any(name not in COMPONENTS for name in names):
                raise PositiveStopError(f"{context} contains an invalid component")
            aws = require_keys(
                host["aws"],
                {
                    "account_id",
                    "deny_all_security_group_id",
                    "expected_eni_ids",
                    "instance_id",
                    "region",
                    "vpc_id",
                },
                f"{context} aws",
            )
            checks = [
                (AWS_ACCOUNT, aws["account_id"], "account_id"),
                (AWS_REGION, aws["region"], "region"),
                (INSTANCE_ID, aws["instance_id"], "instance_id"),
                (VPC_ID, aws["vpc_id"], "vpc_id"),
                (SG_ID, aws["deny_all_security_group_id"], "deny-all security group"),
            ]
            for pattern, candidate, field in checks:
                if not isinstance(candidate, str) or pattern.fullmatch(candidate) is None:
                    raise PositiveStopError(f"{context} {field} is invalid")
            _validate_sorted_strings(
                aws["expected_eni_ids"],
                f"{context} expected_eni_ids",
                pattern=ENI_ID,
                maximum=MAX_ENIS,
            )
            instance_identity = (aws["account_id"], aws["region"], aws["instance_id"])
            if instance_identity in ec2_instances:
                raise PositiveStopError("multiple host IDs reuse one EC2 instance identity")
            ec2_instances.add(instance_identity)
            for eni_id in aws["expected_eni_ids"]:
                eni_identity = (aws["account_id"], aws["region"], eni_id)
                if eni_identity in ec2_enis:
                    raise PositiveStopError("multiple host IDs reuse one EC2 ENI identity")
                ec2_enis.add(eni_identity)
        else:
            raise PositiveStopError(f"{context} method is invalid")
        covered.update(names)
    if covered != set(COMPONENTS):
        raise PositiveStopError("inventory host/component coverage is incomplete")
    return hosts


def load_inventory(path: Path) -> tuple[dict[str, Any], str, list[dict[str, Any]]]:
    _private_directory(path.parent)
    value, digest = read_json(
        path, "positive-stop inventory", canonical=True, private=True
    )
    hosts = validate_inventory(value)
    return value, digest, hosts


def _private_directory(path: Path) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as error:
        raise PositiveStopError("evidence directory must already exist") from error
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise PositiveStopError("evidence directory must be an actor-owned mode-0700 real directory")


def _atomic_write_new(path: Path, raw: bytes, *, accept_exact_existing: bool) -> str:
    _private_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    temporary_exists = True
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb", closefd=True) as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError as error:
            if not accept_exact_existing:
                raise PositiveStopError(f"refusing to overwrite evidence {path.name}") from error
            if _bounded_read(path, len(raw), private=True) != raw:
                raise PositiveStopError(f"existing evidence {path.name} has different bytes") from error
        temporary.unlink()
        temporary_exists = False
        directory = os.open(path.parent, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if temporary_exists:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass
    return digest_bytes(raw)


def _sidecar_path(path: Path) -> Path:
    if path.suffix != ".json":
        raise PositiveStopError("evidence output must use a .json filename")
    return path.with_suffix(".sha256")


def write_evidence(path: Path, value: dict[str, Any]) -> str:
    raw = canonical_bytes(value)
    if not raw or len(raw) > MAX_JSON_BYTES:
        raise PositiveStopError("canonical evidence exceeded its fixed byte bound")
    digest = _atomic_write_new(path, raw, accept_exact_existing=True)
    sidecar = _sidecar_path(path)
    checksum = f"{digest.removeprefix('sha256:')}  {path.name}\n".encode("ascii")
    _atomic_write_new(sidecar, checksum, accept_exact_existing=True)
    return digest


def read_evidence(path: Path, context: str) -> tuple[dict[str, Any], str] | None:
    _private_directory(path.parent)
    sidecar = _sidecar_path(path)
    exists = path.exists() or path.is_symlink()
    sidecar_exists = sidecar.exists() or sidecar.is_symlink()
    if not exists and not sidecar_exists:
        return None
    if not exists:
        raise PositiveStopError(f"{context} checksum exists without JSON authority")
    value, digest = read_json(path, context, canonical=True, private=True)
    expected = f"{digest.removeprefix('sha256:')}  {path.name}\n".encode("ascii")
    if sidecar_exists:
        if _bounded_read(sidecar, 256, private=True) != expected:
            raise PositiveStopError(f"{context} checksum drifted")
    else:
        _atomic_write_new(sidecar, expected, accept_exact_existing=True)
    return value, digest


def _intent_path(output: Path) -> Path:
    return output.with_name(f"{output.stem}.intent.json")


def _host_for_id(hosts: Sequence[dict[str, Any]], host_id: str) -> dict[str, Any]:
    matches = [host for host in hosts if host["host_id"] == host_id]
    if len(matches) != 1:
        raise PositiveStopError("host_id is not an exact inventory member")
    return matches[0]


def _matching_processes(
    snapshot: ProcessSnapshot, executable_paths: set[str]
) -> list[ProcessIdentity]:
    return sorted(
        identity
        for identity in snapshot.processes.values()
        if identity.executable.removesuffix(" (deleted)") in executable_paths
        or identity.argv0 in executable_paths
    )


def _tree_members(
    roots: Sequence[int], processes: Mapping[int, ProcessIdentity]
) -> list[ProcessIdentity]:
    selected: dict[tuple[int, int], ProcessIdentity] = {}
    frontier = list(sorted(set(roots), reverse=True))
    while frontier:
        pid = frontier.pop()
        identity = processes.get(pid)
        if identity is None:
            raise PositiveStopError(f"systemd process {pid} disappeared before stop intent")
        key = (identity.pid, identity.start_ticks)
        if key in selected:
            continue
        selected[key] = identity
        children = sorted(
            child.pid for child in processes.values() if child.ppid == identity.pid
        )
        frontier.extend(reversed(children))
        if len(selected) > MAX_PROCESSES:
            raise PositiveStopError("systemd process tree exceeded its fixed bound")
    return sorted(selected.values())


def _recorded_process(value: Any, context: str) -> ProcessIdentity:
    process = require_keys(
        value,
        {"argv0", "executable", "pid", "ppid", "start_ticks"},
        context,
    )
    if (
        not isinstance(process["pid"], int)
        or isinstance(process["pid"], bool)
        or process["pid"] <= 1
        or not isinstance(process["ppid"], int)
        or isinstance(process["ppid"], bool)
        or process["ppid"] < 0
        or process["ppid"] == process["pid"]
        or not isinstance(process["start_ticks"], int)
        or isinstance(process["start_ticks"], bool)
        or process["start_ticks"] <= 0
        or not isinstance(process["argv0"], str)
        or "\x00" in process["argv0"]
        or "\n" in process["argv0"]
        or not isinstance(process["executable"], str)
        or not process["executable"]
        or "\x00" in process["executable"]
        or "\n" in process["executable"]
    ):
        raise PositiveStopError(f"{context} is malformed")
    return ProcessIdentity(
        pid=process["pid"],
        start_ticks=process["start_ticks"],
        ppid=process["ppid"],
        executable=process["executable"],
        argv0=process["argv0"],
    )


SYSTEMD_PROPERTIES = (
    "ActiveState",
    "ControlPID",
    "LoadState",
    "MainPID",
    "Result",
    "SubState",
    "UnitFileState",
)
KNOWN_UNIT_FILE_STATES = frozenset(
    {
        "alias",
        "disabled",
        "enabled",
        "enabled-runtime",
        "generated",
        "indirect",
        "linked",
        "linked-runtime",
        "masked",
        "masked-runtime",
        "static",
        "transient",
    }
)
ACCEPTED_LOADED_UNIT_FILE_STATES = KNOWN_UNIT_FILE_STATES - {
    "masked",
    "masked-runtime",
}


def _systemd_show(runner: Runner, unit: str, deadline: Deadline) -> dict[str, Any]:
    argv = ["systemctl", "--system", "--no-ask-password", "show", "--no-pager"]
    argv.extend(f"--property={name}" for name in SYSTEMD_PROPERTIES)
    argv.append(unit)
    result = runner.run(argv, timeout=deadline.command_timeout(f"querying {unit}"))
    if result.returncode != 0:
        raise PositiveStopError(f"systemctl show failed for {unit}")
    parsed: dict[str, str] = {}
    for line in result.stdout.splitlines():
        if "=" not in line:
            raise PositiveStopError(f"systemctl show returned malformed data for {unit}")
        key, value = line.split("=", 1)
        if key in parsed or key not in SYSTEMD_PROPERTIES:
            raise PositiveStopError(f"systemctl show returned an unexpected field for {unit}")
        parsed[key] = value
    if set(parsed) != set(SYSTEMD_PROPERTIES):
        raise PositiveStopError(f"systemctl show omitted a field for {unit}")
    try:
        main_pid = int(parsed["MainPID"])
        control_pid = int(parsed["ControlPID"])
    except ValueError as error:
        raise PositiveStopError(f"systemctl show returned an invalid PID for {unit}") from error
    if main_pid < 0 or control_pid < 0:
        raise PositiveStopError(f"systemctl show returned an invalid PID for {unit}")
    return {
        "active_state": parsed["ActiveState"],
        "control_pid": control_pid,
        "load_state": parsed["LoadState"],
        "main_pid": main_pid,
        "result": parsed["Result"],
        "sub_state": parsed["SubState"],
        "unit": unit,
        "unit_file_state": parsed["UnitFileState"],
    }


def _validate_loaded_unit(observation: Mapping[str, Any]) -> None:
    if observation["load_state"] != "loaded":
        raise PositiveStopError(f"expected unit {observation['unit']} is absent or not loaded")
    if observation["unit_file_state"] not in KNOWN_UNIT_FILE_STATES:
        raise PositiveStopError(
            f"expected unit {observation['unit']} has an unsupported unit-file state"
        )
    if observation["unit_file_state"] not in ACCEPTED_LOADED_UNIT_FILE_STATES:
        raise PositiveStopError(f"expected unit {observation['unit']} is masked")


def _validate_unit_shape(value: Any, context: str) -> dict[str, Any]:
    unit = require_keys(
        value,
        {
            "active_state",
            "control_pid",
            "load_state",
            "main_pid",
            "result",
            "sub_state",
            "unit",
            "unit_file_state",
        },
        context,
    )
    if (
        not isinstance(unit["unit"], str)
        or UNIT.fullmatch(unit["unit"]) is None
        or not isinstance(unit["main_pid"], int)
        or isinstance(unit["main_pid"], bool)
        or unit["main_pid"] < 0
        or not isinstance(unit["control_pid"], int)
        or isinstance(unit["control_pid"], bool)
        or unit["control_pid"] < 0
        or any(
            not isinstance(unit[field], str)
            for field in (
                "active_state",
                "load_state",
                "result",
                "sub_state",
                "unit_file_state",
            )
        )
    ):
        raise PositiveStopError(f"{context} is malformed")
    if unit["unit_file_state"] not in KNOWN_UNIT_FILE_STATES:
        raise PositiveStopError(f"{context} unit_file_state is outside the accepted closed set")
    return unit


def _unit_is_stopped(observation: Mapping[str, Any]) -> bool:
    return (
        observation["load_state"] == "loaded"
        and observation["unit_file_state"] in ACCEPTED_LOADED_UNIT_FILE_STATES
        and observation["active_state"] in {"inactive", "failed"}
        and observation["main_pid"] == 0
        and observation["control_pid"] == 0
    )


def _local_expected_paths(host: Mapping[str, Any]) -> set[str]:
    paths: set[str] = set()
    for component in host["components"]:
        paths.update(component["executable_paths"])
    runtime_root = host["idle_preflight"]["runtime_bin_root"]
    paths.update(
        {
            f"{runtime_root}/cats-blockd",
            f"{runtime_root}/cats-vmm-launcher",
            f"{runtime_root}/cloud-hypervisor",
        }
    )
    return paths


def _local_units(host: Mapping[str, Any]) -> list[str]:
    return sorted(
        {
            unit
            for component in host["components"]
            if component["proof"] == "systemd_stop"
            for unit in component["units"]
        }
    )


def _validate_systemd_process_coverage(
    host: Mapping[str, Any],
    snapshot: ProcessSnapshot,
    unit_observations: Sequence[Mapping[str, Any]],
    process_tree: Sequence[ProcessIdentity],
) -> None:
    tree_keys = {(item.pid, item.start_ticks) for item in process_tree}
    for component in host["components"]:
        if component["proof"] != "systemd_stop":
            continue
        matches = _matching_processes(snapshot, set(component["executable_paths"]))
        active_units = [
            unit
            for unit in unit_observations
            if unit["unit"] in component["units"]
            and unit["active_state"] not in {"inactive", "failed"}
        ]
        if active_units and not matches:
            raise PositiveStopError(
                f"active {component['component']} unit has no expected executable"
            )
        if any((item.pid, item.start_ticks) not in tree_keys for item in matches):
            raise PositiveStopError(
                f"{component['component']} executable exists outside its systemd tree"
            )


def _validate_host_identity(host: Mapping[str, Any], snapshot: ProcessSnapshot) -> None:
    if snapshot.machine_id_sha256 != host["expected_machine_id_sha256"]:
        raise PositiveStopError("local machine identity does not match the inventory")
    if snapshot.boot_id != host["expected_boot_id"]:
        raise PositiveStopError("local boot identity does not match the inventory")


def _local_postcondition(
    runner: Runner,
    facts: LocalFacts,
    host: Mapping[str, Any],
    intent: Mapping[str, Any],
    deadline: Deadline,
    calibration_pid: int,
) -> dict[str, Any]:
    units = [_systemd_show(runner, unit, deadline) for unit in _local_units(host)]
    for unit in units:
        _validate_loaded_unit(unit)
        if not _unit_is_stopped(unit):
            raise PositiveStopError(f"unit {unit['unit']} is not provably stopped")
    snapshot = facts.snapshot(calibration_pid)
    _validate_host_identity(host, snapshot)
    paths = _local_expected_paths(host)
    matches = _matching_processes(snapshot, paths)
    if matches:
        raise PositiveStopError("an expected old-writer executable remains after systemd stop")
    original = intent["precondition"]["process_tree"]
    remaining = []
    for recorded in original:
        live = snapshot.processes.get(recorded["pid"])
        if live is not None and live.start_ticks == recorded["start_ticks"]:
            remaining.append(live.json())
    if remaining:
        raise PositiveStopError("an exact pre-stop process identity remains alive")
    return {
        "boot_id": snapshot.boot_id,
        "expected_executable_processes": [],
        "kind": "systemd_stopped",
        "machine_id_sha256": snapshot.machine_id_sha256,
        "original_process_identities_remaining": [],
        "units": units,
    }


def _stable_local_postcondition(
    runner: Runner,
    facts: LocalFacts,
    host: Mapping[str, Any],
    intent: Mapping[str, Any],
    deadline: Deadline,
    calibration_pid: int,
    stable_seconds: float,
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    first = _local_postcondition(runner, facts, host, intent, deadline, calibration_pid)
    _validate_stable_seconds(stable_seconds)
    if stable_seconds:
        if deadline.remaining("local stable observation") <= stable_seconds:
            raise PositiveStopError("deadline cannot contain the local stable read interval")
        sleeper(stable_seconds)
    second = _local_postcondition(runner, facts, host, intent, deadline, calibration_pid)
    if first != second:
        raise PositiveStopError("local stopped postcondition was not stable across re-read")
    second["stable_observation_sha256"] = digest_bytes(canonical_bytes(first))
    return second


def _validate_common_receipt(
    receipt: dict[str, Any],
    inventory: Mapping[str, Any],
    inventory_digest: str,
    host: Mapping[str, Any],
) -> None:
    require_keys(
        receipt,
        {
            "attempt_id",
            "covered_components",
            "effects",
            "host_id",
            "intent",
            "inventory_sha256",
            "kind",
            "limitations",
            "method",
            "observed_at",
            "outcome",
            "postcondition",
            "version",
        },
        "host receipt",
    )
    expected = {
        "attempt_id": inventory["attempt_id"],
        "covered_components": _component_names(host),
        "host_id": host["host_id"],
        "inventory_sha256": inventory_digest,
        "kind": KIND_HOST_RECEIPT,
        "limitations": LIMITATIONS,
        "method": host["method"],
        "version": VERSION,
    }
    for field, value in expected.items():
        if receipt[field] != value:
            raise PositiveStopError(f"host receipt {field} drifted")
    if isinstance(receipt["version"], bool) or not isinstance(receipt["version"], int):
        raise PositiveStopError("host receipt version is invalid")
    intent = require_keys(receipt["intent"], {"file", "sha256"}, "receipt intent")
    if (
        not isinstance(intent["file"], str)
        or Path(intent["file"]).name != intent["file"]
        or not isinstance(intent["sha256"], str)
        or SHA256.fullmatch(intent["sha256"]) is None
    ):
        raise PositiveStopError("host receipt intent reference is invalid")
    _validate_time(receipt["observed_at"], "host receipt observed_at")
    if host["method"] == "local_systemd":
        if receipt["outcome"] != "stopped":
            raise PositiveStopError("local host receipt outcome drifted")
        effects = receipt["effects"]
        if (
            not isinstance(effects, list)
            or [item.get("unit") for item in effects if isinstance(item, dict)]
            != _local_units(host)
            or any(
                not isinstance(item, dict)
                or set(item) != {"response", "unit"}
                or item["response"]
                not in {
                    "acknowledged",
                    "ambiguous_response_confirmed",
                    "recovered_from_existing_intent",
                }
                for item in effects
            )
        ):
            raise PositiveStopError("local receipt effect coverage drifted")
        post = require_keys(
            receipt["postcondition"],
            {
                "boot_id",
                "expected_executable_processes",
                "kind",
                "machine_id_sha256",
                "original_process_identities_remaining",
                "stable_observation_sha256",
                "units",
            },
            "local receipt postcondition",
        )
        if (
            post["kind"] != "systemd_stopped"
            or post["boot_id"] != host["expected_boot_id"]
            or post["machine_id_sha256"] != host["expected_machine_id_sha256"]
            or post["expected_executable_processes"] != []
            or post["original_process_identities_remaining"] != []
            or not isinstance(post["stable_observation_sha256"], str)
            or SHA256.fullmatch(post["stable_observation_sha256"]) is None
        ):
            raise PositiveStopError("local receipt postcondition is invalid")
        local_projection = dict(post)
        local_digest = local_projection.pop("stable_observation_sha256")
        if digest_bytes(canonical_bytes(local_projection)) != local_digest:
            raise PositiveStopError("local stable observation digest drifted")
        if not isinstance(post["units"], list):
            raise PositiveStopError("local receipt unit inventory is invalid")
        validated_units = [
            _validate_unit_shape(unit, "local receipt unit") for unit in post["units"]
        ]
        for unit in validated_units:
            _validate_loaded_unit(unit)
        if [unit["unit"] for unit in validated_units] != _local_units(host):
            raise PositiveStopError("local receipt omitted an expected unit")
        if any(not _unit_is_stopped(unit) for unit in validated_units):
            raise PositiveStopError("local receipt contains a non-stopped unit")
    else:
        if receipt["outcome"] != "isolated":
            raise PositiveStopError("EC2 host receipt outcome drifted")
        effects = receipt["effects"]
        if (
            not isinstance(effects, list)
            or [item.get("eni_id") for item in effects if isinstance(item, dict)]
            != host["aws"]["expected_eni_ids"]
            or any(
                not isinstance(item, dict)
                or set(item) != {"eni_id", "response"}
                or item["response"]
                not in {
                    "acknowledged",
                    "already_isolated",
                    "ambiguous_response_confirmed",
                    "recovered_from_existing_intent",
                }
                for item in effects
            )
        ):
            raise PositiveStopError("EC2 receipt effect coverage drifted")
        _validate_isolated_projection(receipt["postcondition"], host)


def _validate_intent(
    intent: dict[str, Any],
    inventory: Mapping[str, Any],
    inventory_digest: str,
    host: Mapping[str, Any],
) -> None:
    require_keys(
        intent,
        {
            "attempt_id",
            "created_at",
            "host_id",
            "inventory_sha256",
            "kind",
            "method",
            "precondition",
            "version",
        },
        "positive-stop intent",
    )
    expected = {
        "attempt_id": inventory["attempt_id"],
        "host_id": host["host_id"],
        "inventory_sha256": inventory_digest,
        "kind": KIND_INTENT,
        "method": host["method"],
        "version": VERSION,
    }
    for field, value in expected.items():
        if intent[field] != value:
            raise PositiveStopError(f"positive-stop intent {field} drifted")
    if isinstance(intent["version"], bool) or not isinstance(intent["version"], int):
        raise PositiveStopError("positive-stop intent version is invalid")
    _validate_time(intent["created_at"], "positive-stop intent created_at")
    precondition = intent["precondition"]
    if host["method"] == "local_systemd":
        require_keys(
            precondition,
            {
                "boot_id",
                "idle_preflight",
                "machine_id_sha256",
                "process_probe_control",
                "process_tree",
                "protected_runtime_processes",
                "units",
            },
            "local intent precondition",
        )
        if not isinstance(precondition["units"], list):
            raise PositiveStopError("local intent unit inventory is invalid")
        validated_units = [
            _validate_unit_shape(unit, "local intent unit")
            for unit in precondition["units"]
        ]
        for unit in validated_units:
            _validate_loaded_unit(unit)
        if (
            precondition["boot_id"] != host["expected_boot_id"]
            or precondition["machine_id_sha256"] != host["expected_machine_id_sha256"]
            or precondition["idle_preflight"] != "passed"
            or precondition["protected_runtime_processes"] != []
            or [unit["unit"] for unit in validated_units] != _local_units(host)
        ):
            raise PositiveStopError("local intent precondition drifted")
        if not isinstance(precondition["process_tree"], list):
            raise PositiveStopError("local intent process tree is invalid")
        recorded_processes = [
            _recorded_process(item, "local intent process identity")
            for item in precondition["process_tree"]
        ]
        process_keys = [
            (process.pid, process.start_ticks) for process in recorded_processes
        ]
        if process_keys != sorted(set(process_keys)):
            raise PositiveStopError("local intent process identities are not sorted/unique")
        if len({process.pid for process in recorded_processes}) != len(recorded_processes):
            raise PositiveStopError("local intent reuses one PID for multiple identities")
        by_pid = {process.pid: process for process in recorded_processes}
        roots = {
            pid
            for unit in validated_units
            for pid in (unit["main_pid"], unit["control_pid"])
            if pid != 0
        }
        if not roots.issubset(by_pid):
            raise PositiveStopError("local intent omitted a systemd process-tree root")
        for process in recorded_processes:
            current = process.pid
            visited: set[int] = set()
            while current not in roots:
                if current in visited or current not in by_pid:
                    raise PositiveStopError(
                        "local intent process tree is cyclic or detached from its roots"
                    )
                visited.add(current)
                current = by_pid[current].ppid
        snapshot = ProcessSnapshot(
            boot_id=precondition["boot_id"],
            machine_id_sha256=precondition["machine_id_sha256"],
            processes=by_pid,
        )
        _validate_systemd_process_coverage(
            host, snapshot, validated_units, recorded_processes
        )
        control = _recorded_process(
            precondition["process_probe_control"],
            "local intent process probe control",
        )
        if control.pid in by_pid:
            raise PositiveStopError("process probe control is inside a unit selected for stop")
    else:
        require_keys(
            precondition,
            {"discovery", "discovery_sha256", "deny_all_group_verified"},
            "EC2 intent precondition",
        )
        if precondition["deny_all_group_verified"] != "rules_empty":
            raise PositiveStopError("EC2 intent deny-all group proof drifted")
        if not isinstance(precondition["discovery_sha256"], str) or SHA256.fullmatch(
            precondition["discovery_sha256"]
        ) is None:
            raise PositiveStopError("EC2 intent discovery digest is invalid")
        _validate_ec2_projection(precondition["discovery"], host, stable=False)
        if digest_bytes(canonical_bytes(precondition["discovery"])) != precondition[
            "discovery_sha256"
        ]:
            raise PositiveStopError("EC2 intent discovery digest drifted")


def _load_referenced_intent(
    output: Path,
    receipt: Mapping[str, Any],
    inventory: Mapping[str, Any],
    inventory_digest: str,
    host: Mapping[str, Any],
) -> tuple[dict[str, Any], str]:
    reference = receipt["intent"]
    if reference["file"] != _intent_path(output).name:
        raise PositiveStopError("host receipt references a non-canonical intent filename")
    path = output.parent / reference["file"]
    loaded = read_evidence(path, "referenced positive-stop intent")
    if loaded is None:
        raise PositiveStopError("host receipt references a missing intent")
    intent, digest = loaded
    if digest != reference["sha256"]:
        raise PositiveStopError("host receipt intent digest drifted")
    _validate_intent(intent, inventory, inventory_digest, host)
    return intent, digest


def execute_local_stop(
    *,
    inventory: dict[str, Any],
    inventory_digest: str,
    hosts: Sequence[dict[str, Any]],
    host_id: str,
    output: Path,
    runner: Runner,
    facts: LocalFacts,
    deadline_seconds: float,
    stable_seconds: float,
    now: Callable[[], dt.datetime] = now_utc,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
    calibration_pid: int | None = None,
) -> tuple[dict[str, Any], str]:
    host = _host_for_id(hosts, host_id)
    if host["method"] != "local_systemd":
        raise PositiveStopError("selected host does not use local_systemd")
    _validate_stable_seconds(stable_seconds)
    deadline = Deadline.start(deadline_seconds, monotonic)
    calibration = os.getpid() if calibration_pid is None else calibration_pid
    existing = read_evidence(output, "host positive-stop receipt")
    if existing is not None:
        receipt, receipt_digest = existing
        _validate_common_receipt(receipt, inventory, inventory_digest, host)
        intent, _ = _load_referenced_intent(
            output, receipt, inventory, inventory_digest, host
        )
        _stable_local_postcondition(
            runner,
            facts,
            host,
            intent,
            deadline,
            calibration,
            stable_seconds,
            sleeper,
        )
        return receipt, receipt_digest

    intent_path = _intent_path(output)
    loaded_intent = read_evidence(intent_path, "local positive-stop intent")
    if loaded_intent is None:
        preflight = host["idle_preflight"]
        result = runner.run(
            [
                preflight["helper_path"],
                preflight["metering_cgroup_root"],
                preflight["runtime_bin_root"],
            ],
            timeout=deadline.command_timeout("idle/runtime preflight"),
        )
        if result.returncode != 0:
            raise PositiveStopError("require-idle-worker refused the local stop")
        pre_snapshot = facts.snapshot(calibration)
        _validate_host_identity(host, pre_snapshot)
        control = pre_snapshot.processes[calibration]
        protected = {
            f"{preflight['runtime_bin_root']}/cats-blockd",
            f"{preflight['runtime_bin_root']}/cats-vmm-launcher",
            f"{preflight['runtime_bin_root']}/cloud-hypervisor",
        }
        live_runtime = _matching_processes(pre_snapshot, protected)
        if live_runtime:
            raise PositiveStopError(
                "local stop refused because a VMM or blockd runtime process is live"
            )
        unit_observations = [
            _systemd_show(runner, unit, deadline) for unit in _local_units(host)
        ]
        for observation in unit_observations:
            _validate_loaded_unit(observation)
        roots = sorted(
            {
                pid
                for observation in unit_observations
                for pid in (observation["main_pid"], observation["control_pid"])
                if pid != 0
            }
        )
        process_tree = _tree_members(roots, pre_snapshot.processes) if roots else []
        if any(item.pid == control.pid for item in process_tree):
            raise PositiveStopError(
                "positive-stop process is inside a systemd unit selected for stop"
            )
        _validate_systemd_process_coverage(
            host, pre_snapshot, unit_observations, process_tree
        )
        # Re-run the same calibrated idle probe immediately before publishing
        # the no-replace intent. A negative from only one pass must not become
        # permission to stop a unit if a runtime appeared during enumeration.
        second_preflight = runner.run(
            [
                preflight["helper_path"],
                preflight["metering_cgroup_root"],
                preflight["runtime_bin_root"],
            ],
            timeout=deadline.command_timeout("final idle/runtime preflight"),
        )
        if second_preflight.returncode != 0:
            raise PositiveStopError("final require-idle-worker preflight refused the stop")
        stable_snapshot = facts.snapshot(calibration)
        _validate_host_identity(host, stable_snapshot)
        if _matching_processes(stable_snapshot, protected):
            raise PositiveStopError("a runtime appeared during the local stop preflight")
        stable_units = [
            _systemd_show(runner, unit, deadline) for unit in _local_units(host)
        ]
        if stable_units != unit_observations:
            raise PositiveStopError("systemd unit identity/state changed during preflight")
        stable_tree = _tree_members(roots, stable_snapshot.processes) if roots else []
        if stable_tree != process_tree:
            raise PositiveStopError("systemd process tree changed during preflight")
        _validate_systemd_process_coverage(
            host, stable_snapshot, stable_units, stable_tree
        )
        intent = {
            "attempt_id": inventory["attempt_id"],
            "created_at": format_time(now()),
            "host_id": host_id,
            "inventory_sha256": inventory_digest,
            "kind": KIND_INTENT,
            "method": host["method"],
            "precondition": {
                "boot_id": pre_snapshot.boot_id,
                "idle_preflight": "passed",
                "machine_id_sha256": pre_snapshot.machine_id_sha256,
                "process_probe_control": control.json(),
                "process_tree": [item.json() for item in process_tree],
                "protected_runtime_processes": [],
                "units": unit_observations,
            },
            "version": VERSION,
        }
        intent_digest = write_evidence(intent_path, intent)
        fresh_intent = True
    else:
        intent, intent_digest = loaded_intent
        _validate_intent(intent, inventory, inventory_digest, host)
        fresh_intent = False

    effect_results: list[dict[str, str]] = []
    if fresh_intent:
        for unit in _local_units(host):
            response = "acknowledged"
            try:
                result = runner.run(
                    ["systemctl", "--system", "--no-ask-password", "stop", unit],
                    timeout=deadline.command_timeout(f"stopping {unit}"),
                )
                if result.returncode != 0:
                    response = "ambiguous_response"
            except CommandOutcomeUnknown:
                response = "ambiguous_response"
            observation = _systemd_show(runner, unit, deadline)
            _validate_loaded_unit(observation)
            if not _unit_is_stopped(observation):
                raise PositiveStopError(
                    f"stop response for {unit} was not confirmed by exact discovery"
                )
            if response == "ambiguous_response":
                response = "ambiguous_response_confirmed"
            effect_results.append({"response": response, "unit": unit})
    else:
        effect_results = [
            {"response": "recovered_from_existing_intent", "unit": unit}
            for unit in _local_units(host)
        ]

    try:
        postcondition = _stable_local_postcondition(
            runner,
            facts,
            host,
            intent,
            deadline,
            calibration,
            stable_seconds,
            sleeper,
        )
    except PositiveStopError as error:
        if not fresh_intent:
            raise PositiveStopError(
                "existing local stop intent has no complete postcondition; refusing to repeat the stop"
            ) from error
        raise
    receipt = {
        "attempt_id": inventory["attempt_id"],
        "covered_components": _component_names(host),
        "effects": effect_results,
        "host_id": host_id,
        "intent": {"file": intent_path.name, "sha256": intent_digest},
        "inventory_sha256": inventory_digest,
        "kind": KIND_HOST_RECEIPT,
        "limitations": LIMITATIONS,
        "method": host["method"],
        "observed_at": format_time(now()),
        "outcome": "stopped",
        "postcondition": postcondition,
        "version": VERSION,
    }
    receipt_digest = write_evidence(output, receipt)
    return receipt, receipt_digest


def _aws_argv(region: str, service: str, operation: str, *arguments: str) -> list[str]:
    return [
        "aws",
        "--no-cli-pager",
        "--no-paginate",
        "--region",
        region,
        "--output",
        "json",
        service,
        operation,
        *arguments,
    ]


def _json_command(
    runner: Runner, argv: Sequence[str], deadline: Deadline, context: str
) -> dict[str, Any]:
    result = runner.run(argv, timeout=deadline.command_timeout(context))
    if result.returncode != 0:
        raise PositiveStopError(f"{context} failed closed")
    try:
        value = json.loads(result.stdout or "{}", object_pairs_hook=_strict_object)
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise PositiveStopError(f"{context} returned invalid JSON") from error
    if not isinstance(value, dict):
        raise PositiveStopError(f"{context} returned a non-object")
    return value


def _groups(value: Any, context: str) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > 64:
        raise PositiveStopError(f"{context} groups were malformed")
    groups: list[str] = []
    for group in value:
        if not isinstance(group, dict) or "GroupId" not in group:
            raise PositiveStopError(f"{context} group was malformed")
        group_id = group["GroupId"]
        if not isinstance(group_id, str) or SG_ID.fullmatch(group_id) is None:
            raise PositiveStopError(f"{context} group identity was invalid")
        groups.append(group_id)
    if len(groups) != len(set(groups)):
        raise PositiveStopError(f"{context} groups were duplicated")
    return sorted(groups)


def _eni_projection(value: Any, context: str, instance_id: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PositiveStopError(f"{context} was malformed")
    eni_id = value.get("NetworkInterfaceId")
    owner = value.get("OwnerId")
    vpc_id = value.get("VpcId")
    status_value = value.get("Status")
    attachment = value.get("Attachment")
    if (
        not isinstance(eni_id, str)
        or ENI_ID.fullmatch(eni_id) is None
        or not isinstance(owner, str)
        or AWS_ACCOUNT.fullmatch(owner) is None
        or not isinstance(vpc_id, str)
        or VPC_ID.fullmatch(vpc_id) is None
        or status_value != "in-use"
        or not isinstance(attachment, dict)
    ):
        raise PositiveStopError(f"{context} identity was malformed")
    if attachment.get("InstanceId") != instance_id:
        raise PositiveStopError(f"{context} is not attached to the expected instance")
    device_index = attachment.get("DeviceIndex")
    if not isinstance(device_index, int) or isinstance(device_index, bool) or device_index < 0:
        raise PositiveStopError(f"{context} device index was malformed")
    return {
        "device_index": device_index,
        "eni_id": eni_id,
        "group_ids": _groups(value.get("Groups"), context),
        "instance_id": instance_id,
        "owner_id": owner,
        "status": status_value,
        "vpc_id": vpc_id,
    }


def _discover_ec2(
    runner: Runner, host: Mapping[str, Any], deadline: Deadline
) -> dict[str, Any]:
    aws = host["aws"]
    region = aws["region"]
    identity = _json_command(
        runner,
        _aws_argv(region, "sts", "get-caller-identity"),
        deadline,
        "AWS caller identity discovery",
    )
    if identity.get("Account") != aws["account_id"]:
        raise PositiveStopError("AWS caller account does not match the exact inventory")
    arn = identity.get("Arn")
    if not isinstance(arn, str) or not arn.startswith("arn:"):
        raise PositiveStopError("AWS caller ARN was malformed")
    regions = _json_command(
        runner,
        _aws_argv(
            region, "ec2", "describe-regions", "--region-names", region
        ),
        deadline,
        "AWS region discovery",
    ).get("Regions")
    if not isinstance(regions, list) or len(regions) != 1:
        raise PositiveStopError("AWS region discovery was not exact")
    region_value = regions[0]
    if (
        not isinstance(region_value, dict)
        or region_value.get("RegionName") != region
        or region_value.get("OptInStatus") not in {"opt-in-not-required", "opted-in"}
    ):
        raise PositiveStopError("AWS region does not match an enabled exact target")

    groups = _json_command(
        runner,
        _aws_argv(
            region,
            "ec2",
            "describe-security-groups",
            "--group-ids",
            aws["deny_all_security_group_id"],
        ),
        deadline,
        "deny-all security group discovery",
    ).get("SecurityGroups")
    if not isinstance(groups, list) or len(groups) != 1 or not isinstance(groups[0], dict):
        raise PositiveStopError("deny-all security group discovery was not exact")
    group = groups[0]
    if (
        group.get("GroupId") != aws["deny_all_security_group_id"]
        or group.get("OwnerId") != aws["account_id"]
        or group.get("VpcId") != aws["vpc_id"]
    ):
        raise PositiveStopError("deny-all security group identity does not match the inventory")
    if group.get("IpPermissions") != [] or group.get("IpPermissionsEgress") != []:
        raise PositiveStopError("declared deny-all security group has a non-empty rule set")

    reservations = _json_command(
        runner,
        _aws_argv(
            region,
            "ec2",
            "describe-instances",
            "--instance-ids",
            aws["instance_id"],
        ),
        deadline,
        "EC2 instance discovery",
    ).get("Reservations")
    if not isinstance(reservations, list) or len(reservations) != 1:
        raise PositiveStopError("EC2 instance discovery was not exact")
    reservation = reservations[0]
    if not isinstance(reservation, dict) or reservation.get("OwnerId") != aws["account_id"]:
        raise PositiveStopError("EC2 instance owner does not match the inventory")
    instances = reservation.get("Instances")
    if not isinstance(instances, list) or len(instances) != 1 or not isinstance(instances[0], dict):
        raise PositiveStopError("EC2 instance discovery was not exact")
    instance = instances[0]
    state_value = instance.get("State")
    state_name = state_value.get("Name") if isinstance(state_value, dict) else None
    if (
        instance.get("InstanceId") != aws["instance_id"]
        or instance.get("VpcId") != aws["vpc_id"]
        or state_name not in {"pending", "running", "stopping", "stopped"}
    ):
        raise PositiveStopError("EC2 instance identity/state does not match the inventory")
    embedded = instance.get("NetworkInterfaces")
    if not isinstance(embedded, list):
        raise PositiveStopError("EC2 instance omitted its ENI inventory")
    embedded_projection = [
        _eni_projection(item, "instance ENI", aws["instance_id"]) for item in embedded
    ]
    embedded_projection.sort(key=lambda item: item["eni_id"])
    expected_enis = aws["expected_eni_ids"]
    if [item["eni_id"] for item in embedded_projection] != expected_enis:
        raise PositiveStopError("EC2 instance ENI inventory has a missing or extra interface")

    described = _json_command(
        runner,
        _aws_argv(
            region,
            "ec2",
            "describe-network-interfaces",
            "--network-interface-ids",
            *expected_enis,
        ),
        deadline,
        "EC2 ENI discovery",
    ).get("NetworkInterfaces")
    if not isinstance(described, list):
        raise PositiveStopError("EC2 ENI discovery omitted its inventory")
    described_projection = [
        _eni_projection(item, "described ENI", aws["instance_id"]) for item in described
    ]
    described_projection.sort(key=lambda item: item["eni_id"])
    if [item["eni_id"] for item in described_projection] != expected_enis:
        raise PositiveStopError("described ENI inventory has a missing or extra interface")
    if embedded_projection != described_projection:
        raise PositiveStopError("instance and ENI discovery disagree")
    if any(
        item["owner_id"] != aws["account_id"] or item["vpc_id"] != aws["vpc_id"]
        for item in described_projection
    ):
        raise PositiveStopError("an ENI account/VPC does not match the inventory")
    if len({item["device_index"] for item in described_projection}) != len(
        described_projection
    ):
        raise PositiveStopError("EC2 ENI device indices are duplicated")
    return {
        "account_id": aws["account_id"],
        "deny_all_security_group": {
            "egress_rules": 0,
            "group_id": aws["deny_all_security_group_id"],
            "ingress_rules": 0,
            "owner_id": aws["account_id"],
            "vpc_id": aws["vpc_id"],
        },
        "enis": described_projection,
        "instance_id": aws["instance_id"],
        "instance_state": state_name,
        "kind": "ec2_deny_all_security_group",
        "region": region,
        "vpc_id": aws["vpc_id"],
    }


def _all_enis_isolated(projection: Mapping[str, Any], host: Mapping[str, Any]) -> bool:
    deny_group = host["aws"]["deny_all_security_group_id"]
    return all(eni["group_ids"] == [deny_group] for eni in projection["enis"])


def _validate_ec2_projection(
    value: Any, host: Mapping[str, Any], *, stable: bool
) -> dict[str, Any]:
    required = {
        "account_id",
        "deny_all_security_group",
        "enis",
        "instance_id",
        "instance_state",
        "kind",
        "region",
        "vpc_id",
    }
    if stable:
        required.add("stable_observation_sha256")
    projection = require_keys(value, required, "EC2 isolation projection")
    aws = host["aws"]
    if (
        projection["kind"] != "ec2_deny_all_security_group"
        or projection["account_id"] != aws["account_id"]
        or projection["region"] != aws["region"]
        or projection["instance_id"] != aws["instance_id"]
        or projection["vpc_id"] != aws["vpc_id"]
        or projection["instance_state"]
        not in {"pending", "running", "stopping", "stopped"}
    ):
        raise PositiveStopError("EC2 isolation projection identity drifted")
    group = require_keys(
        projection["deny_all_security_group"],
        {"egress_rules", "group_id", "ingress_rules", "owner_id", "vpc_id"},
        "EC2 deny-all security group projection",
    )
    if (
        isinstance(group["egress_rules"], bool)
        or not isinstance(group["egress_rules"], int)
        or isinstance(group["ingress_rules"], bool)
        or not isinstance(group["ingress_rules"], int)
        or group
        != {
            "egress_rules": 0,
            "group_id": aws["deny_all_security_group_id"],
            "ingress_rules": 0,
            "owner_id": aws["account_id"],
            "vpc_id": aws["vpc_id"],
        }
    ):
        raise PositiveStopError("EC2 deny-all group proof drifted")
    enis = projection["enis"]
    if not isinstance(enis, list):
        raise PositiveStopError("EC2 isolation projection ENIs are malformed")
    validated: list[dict[str, Any]] = []
    for value_eni in enis:
        eni = require_keys(
            value_eni,
            {
                "device_index",
                "eni_id",
                "group_ids",
                "instance_id",
                "owner_id",
                "status",
                "vpc_id",
            },
            "EC2 isolation projection ENI",
        )
        if (
            not isinstance(eni["eni_id"], str)
            or ENI_ID.fullmatch(eni["eni_id"]) is None
            or eni["instance_id"] != aws["instance_id"]
            or eni["owner_id"] != aws["account_id"]
            or eni["vpc_id"] != aws["vpc_id"]
            or not isinstance(eni["device_index"], int)
            or isinstance(eni["device_index"], bool)
            or eni["device_index"] < 0
            or eni["status"] != "in-use"
        ):
            raise PositiveStopError("EC2 isolation projection ENI identity drifted")
        _validate_sorted_strings(
            eni["group_ids"], "EC2 isolation projection ENI groups", pattern=SG_ID, maximum=64
        )
        validated.append(eni)
    if [eni["eni_id"] for eni in validated] != aws["expected_eni_ids"]:
        raise PositiveStopError("EC2 isolation projection omitted an expected ENI")
    if len({eni["device_index"] for eni in validated}) != len(validated):
        raise PositiveStopError("EC2 isolation projection duplicated an ENI device index")
    if stable and (
        not isinstance(projection["stable_observation_sha256"], str)
        or SHA256.fullmatch(projection["stable_observation_sha256"]) is None
    ):
        raise PositiveStopError("EC2 stable observation digest is invalid")
    if stable:
        unstamped = dict(projection)
        stable_digest = unstamped.pop("stable_observation_sha256")
        if digest_bytes(canonical_bytes(unstamped)) != stable_digest:
            raise PositiveStopError("EC2 stable observation digest drifted")
    return projection


def _validate_isolated_projection(value: Any, host: Mapping[str, Any]) -> None:
    projection = _validate_ec2_projection(value, host, stable=True)
    aws = host["aws"]
    if (
        not _all_enis_isolated(projection, host)
        or [eni.get("eni_id") for eni in projection["enis"]]
        != aws["expected_eni_ids"]
    ):
        raise PositiveStopError("EC2 isolation postcondition drifted")
def _stable_ec2_projection(
    runner: Runner,
    host: Mapping[str, Any],
    deadline: Deadline,
    stable_seconds: float,
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    first = _discover_ec2(runner, host, deadline)
    if not _all_enis_isolated(first, host):
        raise PositiveStopError("not every expected ENI has the exact deny-all group")
    _validate_stable_seconds(stable_seconds)
    if stable_seconds:
        if deadline.remaining("EC2 stable observation") <= stable_seconds:
            raise PositiveStopError("deadline cannot contain the EC2 stable read interval")
        sleeper(stable_seconds)
    second = _discover_ec2(runner, host, deadline)
    if first != second or not _all_enis_isolated(second, host):
        raise PositiveStopError("EC2 isolation was not stable across the final re-read")
    second["stable_observation_sha256"] = digest_bytes(canonical_bytes(first))
    return second


def _wait_for_eni_isolation(
    runner: Runner,
    host: Mapping[str, Any],
    eni_id: str,
    deadline: Deadline,
    sleeper: Callable[[float], None],
) -> dict[str, Any]:
    deny_group = host["aws"]["deny_all_security_group_id"]
    while True:
        current = _discover_ec2(runner, host, deadline)
        target = next(item for item in current["enis"] if item["eni_id"] == eni_id)
        if target["group_ids"] == [deny_group]:
            return current
        remaining = deadline.remaining(f"discovering isolation of {eni_id}")
        pause = min(0.25, remaining / 2)
        if pause <= 0:
            raise PositiveStopError(f"deadline expired discovering isolation of {eni_id}")
        sleeper(pause)


def execute_ec2_isolation(
    *,
    inventory: dict[str, Any],
    inventory_digest: str,
    hosts: Sequence[dict[str, Any]],
    host_id: str,
    output: Path,
    runner: Runner,
    deadline_seconds: float,
    stable_seconds: float,
    now: Callable[[], dt.datetime] = now_utc,
    monotonic: Callable[[], float] = time.monotonic,
    sleeper: Callable[[float], None] = time.sleep,
) -> tuple[dict[str, Any], str]:
    host = _host_for_id(hosts, host_id)
    if host["method"] != "ec2_security_group_isolation":
        raise PositiveStopError("selected host does not use EC2 isolation")
    _validate_stable_seconds(stable_seconds)
    deadline = Deadline.start(deadline_seconds, monotonic)
    existing = read_evidence(output, "host isolation receipt")
    if existing is not None:
        receipt, receipt_digest = existing
        _validate_common_receipt(receipt, inventory, inventory_digest, host)
        _load_referenced_intent(output, receipt, inventory, inventory_digest, host)
        _stable_ec2_projection(runner, host, deadline, stable_seconds, sleeper)
        return receipt, receipt_digest

    intent_path = _intent_path(output)
    loaded_intent = read_evidence(intent_path, "EC2 isolation intent")
    if loaded_intent is None:
        discovery = _discover_ec2(runner, host, deadline)
        intent = {
            "attempt_id": inventory["attempt_id"],
            "created_at": format_time(now()),
            "host_id": host_id,
            "inventory_sha256": inventory_digest,
            "kind": KIND_INTENT,
            "method": host["method"],
            "precondition": {
                "deny_all_group_verified": "rules_empty",
                "discovery": discovery,
                "discovery_sha256": digest_bytes(canonical_bytes(discovery)),
            },
            "version": VERSION,
        }
        intent_digest = write_evidence(intent_path, intent)
        fresh_intent = True
    else:
        intent, intent_digest = loaded_intent
        _validate_intent(intent, inventory, inventory_digest, host)
        fresh_intent = False

    if not fresh_intent:
        try:
            postcondition = _stable_ec2_projection(
                runner, host, deadline, stable_seconds, sleeper
            )
        except PositiveStopError as error:
            raise PositiveStopError(
                "existing EC2 isolation intent has no complete postcondition; "
                "refusing to repeat an outcome-unknown modify"
            ) from error
        effect_results = [
            {"eni_id": eni_id, "response": "recovered_from_existing_intent"}
            for eni_id in host["aws"]["expected_eni_ids"]
        ]
    else:
        deny_group = host["aws"]["deny_all_security_group_id"]
        effect_results: list[dict[str, str]] = []
        current = intent["precondition"]["discovery"]
        for eni_id in host["aws"]["expected_eni_ids"]:
            eni = next(item for item in current["enis"] if item["eni_id"] == eni_id)
            if eni["group_ids"] == [deny_group]:
                effect_results.append(
                    {"eni_id": eni_id, "response": "already_isolated"}
                )
                continue
            response = "acknowledged"
            try:
                result = runner.run(
                    _aws_argv(
                        host["aws"]["region"],
                        "ec2",
                        "modify-network-interface-attribute",
                        "--network-interface-id",
                        eni_id,
                        "--groups",
                        deny_group,
                    ),
                    timeout=deadline.command_timeout(f"isolating {eni_id}"),
                )
                if result.returncode != 0:
                    response = "ambiguous_response"
                elif result.stdout.strip() not in {"", "{}"}:
                    response = "ambiguous_response"
            except CommandOutcomeUnknown:
                response = "ambiguous_response"
            # Acknowledged and ambiguous responses have the same authority:
            # fresh exact discovery.  Never issue a second modify for this ENI.
            current = _wait_for_eni_isolation(
                runner, host, eni_id, deadline, sleeper
            )
            if response == "ambiguous_response":
                response = "ambiguous_response_confirmed"
            effect_results.append({"eni_id": eni_id, "response": response})
        postcondition = _stable_ec2_projection(
            runner, host, deadline, stable_seconds, sleeper
        )
        # Response classes are diagnostics only. The receipt's authority is the
        # exact twice-read EC2 postcondition.
        if [item["eni_id"] for item in effect_results] != host["aws"]["expected_eni_ids"]:
            raise PositiveStopError("EC2 effect result coverage is incomplete")

    receipt = {
        "attempt_id": inventory["attempt_id"],
        "covered_components": _component_names(host),
        "effects": effect_results,
        "host_id": host_id,
        "intent": {"file": intent_path.name, "sha256": intent_digest},
        "inventory_sha256": inventory_digest,
        "kind": KIND_HOST_RECEIPT,
        "limitations": LIMITATIONS,
        "method": host["method"],
        "observed_at": format_time(now()),
        "outcome": "isolated",
        "postcondition": postcondition,
        "version": VERSION,
    }
    receipt_digest = write_evidence(output, receipt)
    return receipt, receipt_digest


def verify_coverage(
    *,
    inventory: dict[str, Any],
    inventory_digest: str,
    hosts: Sequence[dict[str, Any]],
    receipt_paths: Sequence[Path],
    output: Path,
    now: Callable[[], dt.datetime] = now_utc,
) -> tuple[dict[str, Any], str]:
    if len(receipt_paths) != len(hosts):
        raise PositiveStopError("receipt count does not match the exact expected Host inventory")
    entries: list[dict[str, Any]] = []
    seen: set[str] = set()
    expected_by_host = {host["host_id"]: host for host in hosts}
    for path in receipt_paths:
        if path.parent != output.parent:
            raise PositiveStopError(
                "Host receipts and evidence set must share one private directory"
            )
        loaded = read_evidence(path, "Host positive-stop receipt")
        if loaded is None:
            raise PositiveStopError("an expected Host receipt is absent")
        receipt, digest = loaded
        host_id = receipt.get("host_id")
        if not isinstance(host_id, str) or host_id not in expected_by_host:
            raise PositiveStopError("receipt covers an unexpected Host")
        if host_id in seen:
            raise PositiveStopError("multiple receipts cover the same Host")
        host = expected_by_host[host_id]
        _validate_common_receipt(receipt, inventory, inventory_digest, host)
        _load_referenced_intent(path, receipt, inventory, inventory_digest, host)
        seen.add(host_id)
        entries.append(
            {
                "covered_components": receipt["covered_components"],
                "file": path.name,
                "host_id": host_id,
                "method": receipt["method"],
                "outcome": receipt["outcome"],
                "sha256": digest,
            }
        )
    if seen != set(expected_by_host):
        raise PositiveStopError("Host receipt coverage is incomplete")
    entries.sort(key=lambda item: item["host_id"])
    coverage = sorted(
        {
            (host["host_id"], component)
            for host in hosts
            for component in _component_names(host)
        }
    )
    aggregate = {
        "attempt_id": inventory["attempt_id"],
        "coverage": [
            {"component": component, "host_id": host_id}
            for host_id, component in coverage
        ],
        "host_receipts": entries,
        "inventory_sha256": inventory_digest,
        "kind": KIND_EVIDENCE_SET,
        "limitations": LIMITATIONS,
        "observed_at": format_time(now()),
        "required_components": list(COMPONENTS),
        "version": VERSION,
    }
    existing = read_evidence(output, "positive-stop evidence set")
    if existing is not None:
        value, digest = existing
        require_keys(value, set(aggregate), "positive-stop evidence set")
        if isinstance(value["version"], bool) or not isinstance(value["version"], int):
            raise PositiveStopError("positive-stop evidence set version is invalid")
        _validate_time(value["observed_at"], "positive-stop evidence set observed_at")
        for field in set(aggregate) - {"observed_at"}:
            if value[field] != aggregate[field]:
                raise PositiveStopError(f"positive-stop evidence set {field} drifted")
        return value, digest
    digest = write_evidence(output, aggregate)
    return aggregate, digest


def _absolute_existing_input(value: str, field: str) -> Path:
    _validate_absolute_path(value, field)
    path = Path(value)
    if not path.is_absolute():
        raise PositiveStopError(f"{field} must be absolute")
    return path


def _absolute_output(value: str) -> Path:
    _validate_absolute_path(value, "--output")
    path = Path(value)
    if not path.is_absolute() or path.suffix != ".json":
        raise PositiveStopError("--output must be an absolute .json path")
    _private_directory(path.parent)
    return path


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("local-stop", "ec2-isolate"):
        action = subparsers.add_parser(name)
        action.add_argument("--inventory", required=True)
        action.add_argument("--host-id", required=True)
        action.add_argument("--output", required=True)
        action.add_argument("--deadline-seconds", type=float, default=60.0)
        action.add_argument("--stable-read-seconds", type=float, default=2.0)
        action.add_argument("--confirm-attempt-id", required=True)
        action.add_argument("--execute", action="store_true")
    verify = subparsers.add_parser("verify")
    verify.add_argument("--inventory", required=True)
    verify.add_argument("--receipt", action="append", required=True)
    verify.add_argument("--output", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        inventory_path = _absolute_existing_input(arguments.inventory, "--inventory")
        inventory, inventory_digest, hosts = load_inventory(inventory_path)
        output = _absolute_output(arguments.output)
        if arguments.command == "verify":
            receipts = [
                _absolute_existing_input(path, "--receipt") for path in arguments.receipt
            ]
            _, digest = verify_coverage(
                inventory=inventory,
                inventory_digest=inventory_digest,
                hosts=hosts,
                receipt_paths=receipts,
                output=output,
            )
        else:
            if not arguments.execute:
                raise PositiveStopError("mutating action requires explicit --execute")
            if arguments.confirm_attempt_id != inventory["attempt_id"]:
                raise PositiveStopError("--confirm-attempt-id does not match the inventory")
            if arguments.command == "local-stop":
                if os.geteuid() != 0:
                    raise PositiveStopError("local-stop must run as root on the exact Host")
                _, digest = execute_local_stop(
                    inventory=inventory,
                    inventory_digest=inventory_digest,
                    hosts=hosts,
                    host_id=arguments.host_id,
                    output=output,
                    runner=CommandRunner(),
                    facts=ProcLocalFacts(),
                    deadline_seconds=arguments.deadline_seconds,
                    stable_seconds=arguments.stable_read_seconds,
                )
            else:
                _, digest = execute_ec2_isolation(
                    inventory=inventory,
                    inventory_digest=inventory_digest,
                    hosts=hosts,
                    host_id=arguments.host_id,
                    output=output,
                    runner=CommandRunner(),
                    deadline_seconds=arguments.deadline_seconds,
                    stable_seconds=arguments.stable_read_seconds,
                )
        print(f"evidence_sha256={digest}")
        return 0
    except PositiveStopError as error:
        print(f"old-host positive stop refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
