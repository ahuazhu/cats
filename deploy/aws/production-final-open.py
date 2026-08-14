#!/usr/bin/env python3
"""Fail-closed E13 final public-open transaction.

The production CLI is intentionally unreachable until the typed A23 Node,
reviewed Terraform ingress, public-probe and cleanup adapter is installed.
Planning validates the exact terminal reset/proof set before it asks that
adapter for a closed effects plan.  Execution journals every terminal result,
uses only the dedicated ProductionCutoverOperator command path for the
mutation-admission CAS, keeps product admission Closed while Nodes, Ingress and
the read-only public probe are prepared, and makes Open the final external
effect.  Before the finalization marker failures close partial infrastructure;
after it, only exact-forward settlement of that one Open command is allowed.
"""

from __future__ import annotations

import argparse
import dataclasses
import hashlib
import importlib.util
import json
import re
import signal
import struct
import sys
import time
from pathlib import Path
from typing import Any, Callable, Protocol, Sequence


def load_sibling(module_name: str, filename: str) -> Any:
    path = Path(__file__).resolve().with_name(filename)
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load required operator module {filename}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


RESET = load_sibling("cats_production_reset_for_open", "production-clean-slate-reset.py")
ADMISSION = load_sibling(
    "cats_production_mutation_admission_for_open",
    "production-mutation-admission.py",
)


PLAN_KIND = "cats.production-final-open-plan.v1"
RECEIPT_KIND = "cats.production-final-open-receipt.v1"
EFFECTS_KIND = "cats.production-final-open-effects-plan.v1"
OPEN_ID = re.compile(r"^[a-z0-9][a-z0-9-]{7,63}$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
RAW_SHA256 = re.compile(r"^[0-9a-f]{64}$")
NODE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
MAX_OPEN_PLAN_BYTES = 2 * 1024 * 1024
OPEN_EXECUTION_MIN_REMAINING_MS = 30_000


class FinalOpenError(RuntimeError):
    """A bounded non-secret reason why final Open was refused."""


def now_unix_ms() -> int:
    return time.time_ns() // 1_000_000


def version_one(value: Any) -> bool:
    return type(value) is int and value == 1


def require_fields(value: Any, expected: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != expected:
        raise FinalOpenError(f"{label} does not have its exact closed field set")
    return value


def require_digest(value: Any, label: str) -> str:
    if not isinstance(value, str) or SHA256.fullmatch(value) is None:
        raise FinalOpenError(f"{label} is not a canonical SHA-256 digest")
    return value


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("ascii")


def sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def read_canonical(path: Path, label: str, maximum: int) -> tuple[dict[str, Any], bytes]:
    try:
        raw = ADMISSION.read_stable_file(path, label, maximum, private=True)
        value = ADMISSION.decode_json(raw, label)
    except ADMISSION.AdmissionError as error:
        raise FinalOpenError(f"{label} is unavailable or malformed") from error
    if not isinstance(value, dict) or raw != canonical_json(value):
        raise FinalOpenError(f"{label} is not canonical JSON with one LF")
    return value, raw


@dataclasses.dataclass(frozen=True)
class OpenAuthority:
    operator: dict[str, Any]
    binding: dict[str, Any]
    reset_plan_sha256: str
    reset_complete_receipt_sha256: str

    def projection(self) -> dict[str, Any]:
        return {
            "operator": self.operator,
            "binding": self.binding,
            "reset_plan_sha256": self.reset_plan_sha256,
            "reset_complete_receipt_sha256": self.reset_complete_receipt_sha256,
        }


@dataclasses.dataclass(frozen=True)
class PreparedAdmission:
    value: dict[str, Any]


class AdmissionClient(Protocol):
    def prepare(self, authority: OpenAuthority) -> PreparedAdmission: ...

    def validate(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> None: ...

    def validate_live_closed(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
        at_unix_ms: int,
    ) -> None: ...

    def settle_open(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
        cancellation: Cancellation,
    ) -> dict[str, Any]: ...

    def validate_open_evidence(
        self,
        evidence: dict[str, Any],
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> None: ...

    def settle_closed(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_closed_evidence(
        self,
        evidence: dict[str, Any],
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> None: ...


class EffectsAdapter(Protocol):
    def prepare(self, authority: OpenAuthority) -> dict[str, Any]: ...

    def validate_plan(self, value: dict[str, Any], authority: OpenAuthority) -> None: ...

    def validate_live_closed_before_start(
        self, value: dict[str, Any], authority: OpenAuthority
    ) -> None: ...

    def validate_post_boundary_forward(
        self, value: dict[str, Any], authority: OpenAuthority
    ) -> None: ...

    def validate_cleanup(
        self, value: dict[str, Any], authority: OpenAuthority
    ) -> None: ...

    def settle_node_schedulable(
        self,
        node: dict[str, Any],
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_node_schedulable(
        self,
        evidence: dict[str, Any],
        node: dict[str, Any],
        authority: OpenAuthority,
    ) -> None: ...

    def settle_ingress_open(
        self,
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_ingress_open(
        self,
        evidence: dict[str, Any],
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> None: ...

    def settle_public_probe(
        self,
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_public_probe(
        self,
        evidence: dict[str, Any],
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> None: ...

    def settle_ingress_closed(
        self,
        effects: dict[str, Any],
        authority: OpenAuthority,
        may_be_open: bool,
    ) -> dict[str, Any]: ...

    def validate_ingress_closed(
        self,
        evidence: dict[str, Any],
        effects: dict[str, Any],
        authority: OpenAuthority,
        may_be_open: bool,
    ) -> None: ...

    def settle_node_cordoned(
        self,
        node: dict[str, Any],
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_node_cordoned(
        self,
        evidence: dict[str, Any],
        node: dict[str, Any],
        authority: OpenAuthority,
    ) -> None: ...

    def settle_cleanup_fleet_closed(
        self,
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> dict[str, Any]: ...

    def validate_cleanup_fleet_closed(
        self,
        evidence: dict[str, Any],
        effects: dict[str, Any],
        authority: OpenAuthority,
    ) -> None: ...


class UnavailableEffectsAdapter:
    def _unavailable(self) -> None:
        raise FinalOpenError(
            "A23/Ingress/public-probe final-open adapter is not implementation-accepted"
        )

    def prepare(self, _authority: OpenAuthority) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_plan(
        self, _value: dict[str, Any], _authority: OpenAuthority
    ) -> None:
        self._unavailable()

    def validate_live_closed_before_start(
        self, _value: dict[str, Any], _authority: OpenAuthority
    ) -> None:
        self._unavailable()

    def validate_post_boundary_forward(
        self, _value: dict[str, Any], _authority: OpenAuthority
    ) -> None:
        self._unavailable()

    def validate_cleanup(
        self, _value: dict[str, Any], _authority: OpenAuthority
    ) -> None:
        self._unavailable()

    def settle_node_schedulable(
        self, _node: dict[str, Any], _authority: OpenAuthority
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_node_schedulable(
        self,
        _evidence: dict[str, Any],
        _node: dict[str, Any],
        _authority: OpenAuthority,
    ) -> None:
        self._unavailable()

    def settle_ingress_open(
        self, _effects: dict[str, Any], _authority: OpenAuthority
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_ingress_open(
        self,
        _evidence: dict[str, Any],
        _effects: dict[str, Any],
        _authority: OpenAuthority,
    ) -> None:
        self._unavailable()

    def settle_public_probe(
        self, _effects: dict[str, Any], _authority: OpenAuthority
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_public_probe(
        self,
        _evidence: dict[str, Any],
        _effects: dict[str, Any],
        _authority: OpenAuthority,
    ) -> None:
        self._unavailable()

    def settle_ingress_closed(
        self,
        _effects: dict[str, Any],
        _authority: OpenAuthority,
        _may_be_open: bool,
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_ingress_closed(
        self,
        _evidence: dict[str, Any],
        _effects: dict[str, Any],
        _authority: OpenAuthority,
        _may_be_open: bool,
    ) -> None:
        self._unavailable()

    def settle_node_cordoned(
        self, _node: dict[str, Any], _authority: OpenAuthority
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_node_cordoned(
        self,
        _evidence: dict[str, Any],
        _node: dict[str, Any],
        _authority: OpenAuthority,
    ) -> None:
        self._unavailable()

    def settle_cleanup_fleet_closed(
        self, _effects: dict[str, Any], _authority: OpenAuthority
    ) -> dict[str, Any]:
        self._unavailable()
        raise AssertionError("unreachable")

    def validate_cleanup_fleet_closed(
        self,
        _evidence: dict[str, Any],
        _effects: dict[str, Any],
        _authority: OpenAuthority,
    ) -> None:
        self._unavailable()


UNAVAILABLE_EFFECTS_ADAPTER: EffectsAdapter = UnavailableEffectsAdapter()


def open_command_id(open_id: str, binding: dict[str, Any], phase: str) -> str:
    framed = bytearray(b"cats.production-final-open.command.v1\0")
    for value in (open_id, phase):
        encoded = value.encode("ascii")
        framed.extend(struct.pack(">Q", len(encoded)))
        framed.extend(encoded)
    binding_bytes = ADMISSION.canonical_json(binding)
    framed.extend(struct.pack(">Q", len(binding_bytes)))
    framed.extend(binding_bytes)
    return hashlib.sha256(framed).hexdigest()[:32]


def file_reference(path: Path, label: str) -> dict[str, Any]:
    raw = ADMISSION.read_stable_file(
        path,
        label,
        ADMISSION.MAX_RESPONSE_BYTES,
        private=True,
    )
    return {"file": path.name, "sha256": ADMISSION.sha256(raw), "size_bytes": len(raw)}


class ProductionAdmissionClient:
    def __init__(
        self,
        *,
        open_id: str,
        origin: str,
        trust_file: Path,
        private_key_file: Path,
        state_directory: Path,
        command_lifetime_seconds: int = ADMISSION.DEFAULT_COMMAND_LIFETIME_MS // 1_000,
        resolution_timeout_seconds: int = ADMISSION.DEFAULT_RESOLUTION_SECONDS,
    ) -> None:
        try:
            ADMISSION.validate_private_directory(state_directory)
            self.origin = ADMISSION.validate_origin(origin)
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("final-open admission state boundary is invalid") from error
        self.open_id = open_id
        self.trust_file = trust_file
        self.private_key_file = private_key_file
        self.state_directory = state_directory
        self.command_lifetime_seconds = command_lifetime_seconds
        self.resolution_timeout_seconds = resolution_timeout_seconds

    def _binding_path(self) -> Path:
        return self.state_directory / f"{self.open_id}.open-binding.v1.json"

    def _pending_path(self, binding: dict[str, Any], phase: str) -> Path:
        command_id = open_command_id(self.open_id, binding, phase)
        return self.state_directory / f"{command_id}.pending.v1.json"

    def _ensure_pending(
        self,
        authority: OpenAuthority,
        *,
        phase: str,
        expected_revision: int,
        mutation: str,
    ) -> Path:
        path = self._pending_path(authority.binding, phase)
        command_id = open_command_id(self.open_id, authority.binding, phase)
        if path.exists() or path.is_symlink():
            try:
                _pending, _body, command = ADMISSION.load_pending(path, self.trust_file)
            except ADMISSION.AdmissionError as error:
                raise FinalOpenError("durable final-open pending command is invalid") from error
            if (
                command["command_id"] != command_id
                or command["expected_revision"] != expected_revision
                or command["operator"] != authority.operator
                or command["mutation"]
                != {"kind": mutation, "binding": authority.binding}
            ):
                raise FinalOpenError("durable final-open pending command conflicts")
            return path
        args = argparse.Namespace(
            origin=self.origin,
            trust_file=self.trust_file,
            private_key_file=self.private_key_file,
            binding_file=self._binding_path(),
            state_directory=self.state_directory,
            expected_revision=expected_revision,
            mutation=mutation,
            binding_kind=None,
            command_id=command_id,
            command_lifetime_seconds=self.command_lifetime_seconds,
            aws=Path("/usr/local/bin/aws"),
            openssl=Path("/usr/bin/openssl"),
        )
        try:
            created, _digest = ADMISSION.prepare(args)
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("cannot prepare the signed final-open command") from error
        if created != path:
            raise FinalOpenError("final-open pending command path drifted")
        return path

    def prepare(self, authority: OpenAuthority) -> PreparedAdmission:
        binding_payload = ADMISSION.canonical_json(authority.binding, newline=True)
        binding_path = self._binding_path()
        try:
            ADMISSION.write_atomic(binding_path, binding_payload)
            state_probe = self._ensure_pending(
                authority,
                phase="state-probe",
                expected_revision=1,
                mutation="open",
            )
            state = ADMISSION.discover_state(
                argparse.Namespace(pending=state_probe, trust_file=self.trust_file)
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("cannot discover final-open admission state") from error
        if state["mode"] != "closed":
            raise FinalOpenError("final Open requires current mutation admission Closed")
        open_pending = self._ensure_pending(
            authority,
            phase="open",
            expected_revision=state["revision"],
            mutation="open",
        )
        try:
            _pending, _body, command = ADMISSION.load_pending(
                open_pending,
                self.trust_file,
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("cannot reload final-open pending command") from error
        value = {
            "version": 1,
            "binding_file": file_reference(binding_path, "final-open binding"),
            "state_probe_pending": file_reference(
                state_probe,
                "final-open state probe pending",
            ),
            "observed_closed_state": state,
            "open_pending": file_reference(open_pending, "final-open pending command"),
            "command_id": command["command_id"],
            "request_sha256": ADMISSION.sha256(_body),
            "expected_revision": command["expected_revision"],
            "expires_at_unix_ms": command["expires_at_unix_ms"],
        }
        prepared = PreparedAdmission(value)
        self.validate(prepared, authority)
        return prepared

    def _read_ref(self, value: Any, label: str) -> Path:
        reference = require_fields(value, {"file", "sha256", "size_bytes"}, label)
        name = reference["file"]
        if (
            not isinstance(name, str)
            or "/" in name
            or name in {"", ".", ".."}
            or require_digest(reference["sha256"], f"{label} digest")
            != reference["sha256"]
            or type(reference["size_bytes"]) is not int
            or reference["size_bytes"] <= 0
        ):
            raise FinalOpenError(f"{label} reference is invalid")
        path = self.state_directory / name
        raw = ADMISSION.read_stable_file(
            path,
            label,
            ADMISSION.MAX_RESPONSE_BYTES,
            private=True,
        )
        if ADMISSION.sha256(raw) != reference["sha256"] or len(raw) != reference["size_bytes"]:
            raise FinalOpenError(f"{label} bytes drifted")
        return path

    def validate(self, prepared: PreparedAdmission, authority: OpenAuthority) -> None:
        value = require_fields(
            prepared.value,
            {
                "version",
                "binding_file",
                "state_probe_pending",
                "observed_closed_state",
                "open_pending",
                "command_id",
                "request_sha256",
                "expected_revision",
                "expires_at_unix_ms",
            },
            "prepared final-open admission",
        )
        if not version_one(value["version"]):
            raise FinalOpenError("prepared final-open admission version drifted")
        binding_path = self._read_ref(value["binding_file"], "final-open binding")
        state_probe = self._read_ref(
            value["state_probe_pending"],
            "final-open state probe pending",
        )
        open_pending = self._read_ref(value["open_pending"], "final-open pending command")
        if (
            binding_path != self._binding_path()
            or state_probe != self._pending_path(authority.binding, "state-probe")
            or open_pending != self._pending_path(authority.binding, "open")
        ):
            raise FinalOpenError("final-open prepared filename drifted")
        try:
            binding_raw = ADMISSION.read_stable_file(
                binding_path,
                "final-open binding",
                ADMISSION.MAX_BINDING_BYTES,
                private=False,
            )
            if binding_raw != ADMISSION.canonical_json(authority.binding, newline=True):
                raise FinalOpenError("final-open binding bytes drifted")
            _probe_pending, _probe_body, probe_command = ADMISSION.load_pending(
                state_probe,
                self.trust_file,
            )
            _pending, body, command = ADMISSION.load_pending(
                open_pending,
                self.trust_file,
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("prepared final-open admission cannot be verified") from error
        state = ADMISSION.validate_state(value["observed_closed_state"])
        if (
            state["mode"] != "closed"
            or probe_command["operator"] != authority.operator
            or probe_command["mutation"]
            != {"kind": "open", "binding": authority.binding}
            or probe_command["command_id"]
            != open_command_id(self.open_id, authority.binding, "state-probe")
            or probe_command["expected_revision"] != 1
            or command["operator"] != authority.operator
            or command["mutation"] != {"kind": "open", "binding": authority.binding}
            or command["command_id"]
            != open_command_id(self.open_id, authority.binding, "open")
            or command["command_id"] != value["command_id"]
            or command["expected_revision"] != state["revision"]
            or command["expected_revision"] != value["expected_revision"]
            or command["expires_at_unix_ms"] != value["expires_at_unix_ms"]
            or ADMISSION.sha256(body) != value["request_sha256"]
        ):
            raise FinalOpenError("prepared final-open admission binding drifted")

    def validate_live_closed(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
        at_unix_ms: int,
    ) -> None:
        self.validate(prepared, authority)
        if type(at_unix_ms) is not int or at_unix_ms <= 0:
            raise FinalOpenError("final-open live-Closed evaluation time is invalid")
        pending_path = self._read_ref(
            prepared.value["open_pending"],
            "final-open pending command",
        )
        try:
            _pending, _body, command = ADMISSION.load_pending(
                pending_path,
                self.trust_file,
            )
            live = ADMISSION.discover_state(
                argparse.Namespace(pending=pending_path, trust_file=self.trust_file)
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError(
                "cannot revalidate live Closed admission before open-started"
            ) from error
        planned = ADMISSION.validate_state(prepared.value["observed_closed_state"])
        if (
            command["issued_at_unix_ms"] > at_unix_ms
            or command["expires_at_unix_ms"] - at_unix_ms
            < OPEN_EXECUTION_MIN_REMAINING_MS
        ):
            raise FinalOpenError(
                "signed final-open request has insufficient safe lifetime"
            )
        if live != planned or live["mode"] != "closed":
            raise FinalOpenError(
                "mutation admission revision/mode changed before open-started"
            )

    def settle_open(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
        cancellation: Cancellation,
    ) -> dict[str, Any]:
        self.validate(prepared, authority)
        pending_path = self._read_ref(
            prepared.value["open_pending"],
            "final-open pending command",
        )
        try:
            receipt_path, receipt_digest = ADMISSION.settle(
                argparse.Namespace(
                    pending=pending_path,
                    trust_file=self.trust_file,
                    resolution_timeout_seconds=self.resolution_timeout_seconds,
                    parent_cancellation=cancellation,
                )
            )
            receipt_raw = ADMISSION.read_stable_file(
                receipt_path,
                "final-open admission receipt",
                ADMISSION.MAX_RESPONSE_BYTES,
                private=True,
            )
            receipt = ADMISSION.decode_json(receipt_raw, "final-open admission receipt")
            outcome = receipt["outcome"]
            state = ADMISSION.validate_state(outcome["state"])
            discovered = ADMISSION.discover_state(
                argparse.Namespace(pending=pending_path, trust_file=self.trust_file)
            )
        except (ADMISSION.AdmissionError, KeyError, TypeError) as error:
            raise FinalOpenError("final-open admission did not settle") from error
        if (
            receipt_digest != ADMISSION.sha256(receipt_raw)
            or outcome.get("kind") != "applied"
            or state != discovered
            or state["mode"] != "open"
            or state["binding"] != {"kind": "open", "binding": authority.binding}
        ):
            raise FinalOpenError("final-open admission settled to a foreign state")
        return {
            "kind": "cats.production-final-open-admission-applied.v1",
            "version": 1,
            "command_id": receipt["command"]["command_id"],
            "request_sha256": receipt["request_sha256"],
            "pending_sha256": prepared.value["open_pending"]["sha256"],
            "command_receipt_sha256": receipt_digest,
            "resulting_state_sha256": ADMISSION.sha256(ADMISSION.canonical_json(state)),
            "resulting_revision": state["revision"],
            "committed_at_unix_ms": receipt["committed_at_unix_ms"],
        }

    def validate_open_evidence(
        self,
        evidence: dict[str, Any],
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> None:
        pending_path = self._read_ref(
            prepared.value["open_pending"],
            "final-open pending command",
        )
        try:
            pending, body, command = ADMISSION.load_pending(
                pending_path,
                self.trust_file,
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("cannot validate final-open pending command") from error
        receipt_path = pending_path.parent / (
            f"{command['command_id']}.receipt.v1.json"
        )
        if not receipt_path.exists() and not receipt_path.is_symlink():
            raise FinalOpenError(
                "final-open journal exists without its Store admission receipt"
            )
        try:
            receipt_raw = ADMISSION.read_stable_file(
                receipt_path,
                "final-open admission receipt",
                ADMISSION.MAX_RESPONSE_BYTES,
                private=True,
            )
            result = ADMISSION.HttpResult(
                200,
                [
                    ("Content-Type", ADMISSION.CONTENT_TYPE),
                    ("Cache-Control", "no-store"),
                ],
                receipt_raw,
            )
            receipt = ADMISSION.validate_receipt(
                result,
                command,
                body,
                pending,
            )
            state = ADMISSION.validate_state(receipt["outcome"]["state"])
        except (ADMISSION.AdmissionError, KeyError, TypeError) as error:
            raise FinalOpenError(
                "final-open Store admission receipt cannot be validated"
            ) from error
        settled = {
            "kind": "cats.production-final-open-admission-applied.v1",
            "version": 1,
            "command_id": receipt["command"]["command_id"],
            "request_sha256": receipt["request_sha256"],
            "pending_sha256": prepared.value["open_pending"]["sha256"],
            "command_receipt_sha256": ADMISSION.sha256(receipt_raw),
            "resulting_state_sha256": ADMISSION.sha256(
                ADMISSION.canonical_json(state)
            ),
            "resulting_revision": state["revision"],
            "committed_at_unix_ms": receipt["committed_at_unix_ms"],
        }
        if (
            receipt["outcome"].get("kind") != "applied"
            or state["mode"] != "open"
            or state["binding"] != {"kind": "open", "binding": authority.binding}
            or settled != evidence
        ):
            raise FinalOpenError("final-open admission replay evidence drifted")

    def settle_closed(
        self,
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> dict[str, Any]:
        self.validate(prepared, authority)
        open_pending = self._read_ref(
            prepared.value["open_pending"],
            "final-open pending command",
        )
        try:
            discovered = ADMISSION.discover_state(
                argparse.Namespace(pending=open_pending, trust_file=self.trust_file)
            )
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError(
                "cannot discover mutation admission during closed cleanup"
            ) from error
        planned_closed = ADMISSION.validate_state(
            prepared.value["observed_closed_state"]
        )
        if discovered["mode"] == "closed":
            if discovered == planned_closed:
                return {
                    "kind": "cats.production-final-open-admission-closed.v1",
                    "version": 1,
                    "close_kind": "already_closed",
                    "command_id": None,
                    "request_sha256": None,
                    "command_receipt_sha256": None,
                    "resulting_state": discovered,
                    "resulting_state_sha256": ADMISSION.sha256(
                        ADMISSION.canonical_json(discovered)
                    ),
                    "resulting_revision": discovered["revision"],
                    "committed_at_unix_ms": discovered["updated_at_unix_ms"],
                }
            if discovered["binding"] != {
                "kind": "open",
                "binding": authority.binding,
            }:
                raise FinalOpenError(
                    "closed cleanup discovered a foreign admission binding"
                )
            raise FinalOpenError(
                "closed cleanup discovered a foreign command for the same Open binding"
            )
        if discovered["mode"] != "open" or discovered["binding"] != {
            "kind": "open",
            "binding": authority.binding,
        }:
            raise FinalOpenError("closed cleanup discovered foreign admission authority")
        raise FinalOpenError(
            "closed cleanup discovered a foreign Open command for the same binding"
        )

    def validate_closed_evidence(
        self,
        evidence: dict[str, Any],
        prepared: PreparedAdmission,
        authority: OpenAuthority,
    ) -> None:
        evidence = require_fields(
            evidence,
            {
                "kind",
                "version",
                "close_kind",
                "command_id",
                "request_sha256",
                "command_receipt_sha256",
                "resulting_state",
                "resulting_state_sha256",
                "resulting_revision",
                "committed_at_unix_ms",
            },
            "closed cleanup admission evidence",
        )
        try:
            state = ADMISSION.validate_state(evidence["resulting_state"])
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("closed cleanup state evidence is malformed") from error
        planned_closed = ADMISSION.validate_state(
            prepared.value["observed_closed_state"]
        )
        if (
            evidence["kind"] != "cats.production-final-open-admission-closed.v1"
            or not version_one(evidence["version"])
            or evidence["close_kind"] != "already_closed"
            or state != planned_closed
            or evidence["resulting_state_sha256"]
            != ADMISSION.sha256(ADMISSION.canonical_json(state))
            or evidence["resulting_revision"] != state["revision"]
            or evidence["committed_at_unix_ms"] != state["updated_at_unix_ms"]
        ):
            raise FinalOpenError("closed cleanup admission evidence drifted")
        if any(
            evidence[field] is not None
            for field in (
                "command_id",
                "request_sha256",
                "command_receipt_sha256",
            )
        ):
            raise FinalOpenError("already-Closed evidence names a command")
        # A prior local cleanup receipt is not current admission authority.
        # Re-discover through the immutable Open request and require the same
        # exact planned Closed bytes before publishing later cleanup stages.
        if self.settle_closed(prepared, authority) != evidence:
            raise FinalOpenError("closed cleanup admission state changed after receipt")


def validate_authority(value: OpenAuthority, open_id: str) -> OpenAuthority:
    try:
        binding = ADMISSION.validate_open_binding(value.binding)
    except ADMISSION.AdmissionError as error:
        raise FinalOpenError("final-open binding is not canonical") from error
    operator = require_fields(
        value.operator,
        {"aws_partition", "account_id", "role_arn", "principal_arn"},
        "final-open operator",
    )
    if (
        binding["reset_id"] == ""
        or binding["proof_set_sha256"] != require_digest(
            binding["proof_set_sha256"],
            "final-open proof set",
        )
        or binding["reset_complete_receipt_sha256"]
        != value.reset_complete_receipt_sha256
        or require_digest(value.reset_complete_receipt_sha256, "reset-complete receipt")
        != value.reset_complete_receipt_sha256
        or require_digest(value.reset_plan_sha256, "reset plan")
        != value.reset_plan_sha256
        or not isinstance(operator["principal_arn"], str)
        or not operator["principal_arn"]
        or not OPEN_ID.fullmatch(open_id)
    ):
        raise FinalOpenError("final-open authority binding drifted")
    return value


def validate_effects(value: Any, authority: OpenAuthority, open_id: str) -> dict[str, Any]:
    value = require_fields(
        value,
        {
            "kind",
            "version",
            "open_id",
            "deployment_id",
            "release_id",
            "source_commit_sha",
            "proof_set_sha256",
            "nodes",
            "ingress_open_plan_sha256",
            "ingress_close_plan_sha256",
            "public_probe_target_sha256",
            "public_probe_method",
            "public_probe_path",
            "public_probe_admission_mode",
        },
        "final-open effects plan",
    )
    binding = authority.binding
    if (
        value["kind"] != EFFECTS_KIND
        or not version_one(value["version"])
        or value["open_id"] != open_id
        or value["deployment_id"] != binding["deployment_id"]
        or value["release_id"] != binding["release_id"]
        or value["source_commit_sha"] != binding["source_commit_sha"]
        or value["proof_set_sha256"] != binding["proof_set_sha256"]
        or value["public_probe_method"] != "GET"
        or value["public_probe_path"] != "/healthz"
        or value["public_probe_admission_mode"] != "closed"
    ):
        raise FinalOpenError("final-open effects plan lineage drifted")
    for field in (
        "ingress_open_plan_sha256",
        "ingress_close_plan_sha256",
        "public_probe_target_sha256",
    ):
        require_digest(value[field], f"effects {field}")
    nodes = value["nodes"]
    if not isinstance(nodes, list) or not nodes:
        raise FinalOpenError("final-open effects require a nonempty Node set")
    prior = ""
    for item in nodes:
        item = require_fields(
            item,
            {"node_id", "schedulable_request_sha256", "cordon_request_sha256"},
            "final-open Node effect",
        )
        node_id = item["node_id"]
        if not isinstance(node_id, str) or NODE_ID.fullmatch(node_id) is None or node_id <= prior:
            raise FinalOpenError("final-open Node effects are not strictly sorted")
        prior = node_id
        require_digest(item["schedulable_request_sha256"], "Node schedulable request")
        require_digest(item["cordon_request_sha256"], "Node cordon request")
    return value


@dataclasses.dataclass
class Cancellation:
    requested: bool = False

    def handler(self, _signal: int, _frame: Any) -> None:
        self.requested = True


class FinalOpenExecutor:
    def __init__(
        self,
        *,
        open_id: str,
        reset_executor: Any,
        reset_plan_path: Path,
        reset_plan_sha256: str,
        admission: AdmissionClient,
        effects: EffectsAdapter = UNAVAILABLE_EFFECTS_ADAPTER,
        receipt_directory: Path,
        authority_verifier: Callable[[], OpenAuthority] | None = None,
        forward_authority_verifier: Callable[[], OpenAuthority] | None = None,
        cleanup_authority_verifier: Callable[[], OpenAuthority] | None = None,
        receipt_publication_hook: Callable[[str, Path], None] | None = None,
    ) -> None:
        if OPEN_ID.fullmatch(open_id) is None:
            raise FinalOpenError("open_id is invalid")
        try:
            ADMISSION.validate_private_directory(receipt_directory)
        except ADMISSION.AdmissionError as error:
            raise FinalOpenError("final-open receipt directory is invalid") from error
        self.open_id = open_id
        self.reset_executor = reset_executor
        self.reset_plan_path = reset_plan_path
        self.reset_plan_sha256 = reset_plan_sha256
        self.admission = admission
        self.effects = effects
        self.receipt_directory = receipt_directory
        self.authority_verifier = authority_verifier
        self.forward_authority_verifier = forward_authority_verifier
        self.cleanup_authority_verifier = cleanup_authority_verifier
        self.receipt_publication_hook = receipt_publication_hook

    def _authority(self) -> OpenAuthority:
        if self.authority_verifier is not None:
            return validate_authority(self.authority_verifier(), self.open_id)
        try:
            completion = self.reset_executor.verify_complete(
                self.reset_plan_path,
                self.reset_plan_sha256,
            )
            binding = completion.authority.proof_set.admission_binding(
                completion.reset_complete_sha256
            )
        except (RESET.ResetError, RESET.cutover_proof.ProofSetError) as error:
            raise FinalOpenError("terminal reset/proof revalidation failed closed") from error
        return validate_authority(
            OpenAuthority(
                operator=completion.authority.operator,
                binding=binding,
                reset_plan_sha256="sha256:" + completion.plan_sha256,
                reset_complete_receipt_sha256=completion.reset_complete_sha256,
            ),
            self.open_id,
        )

    def _validate_post_boundary_completion(
        self,
        completion: Any,
        planned: OpenAuthority,
    ) -> OpenAuthority:
        frozen = completion.cutover_authority
        if not isinstance(frozen, dict) or set(frozen) != RESET.CUTOVER_AUTHORITY_FIELDS:
            raise FinalOpenError("post-boundary reset authority is malformed")
        trust = require_fields(
            completion.operator_trust,
            {
                "version",
                "deployment_id",
                "release_id",
                "source_commit_sha",
                "signature_threshold",
                "credentials",
            },
            "post-boundary cutover trust",
        )
        if not isinstance(trust["credentials"], list) or len(trust["credentials"]) != 1:
            raise FinalOpenError("post-boundary cutover trust credential drifted")
        credential = require_fields(
            trust["credentials"][0],
            {"credential_id", "public_key_spki", "scope"},
            "post-boundary cutover credential",
        )
        scope = require_fields(
            credential["scope"],
            {"aws_partition", "account_id", "role_arn"},
            "post-boundary cutover scope",
        )
        complete = completion.reset_complete
        binding = planned.binding
        projection_bindings = {
            "release_id": "release_id",
            "release_manifest_sha256": "release_manifest_sha256",
            "qualification_manifest_sha256": "qualification_manifest_sha256",
            "qualification_catalog_sha256": "qualification_catalog_sha256",
            "proof_set_sha256": "proof_set_sha256",
            "fresh_targets_sha256": "fresh_targets_sha256",
            "fleet_closed_receipt_sha256": "fleet_closed_receipt_sha256",
            "route_v2_rotation_qualification_receipt_sha256": (
                "route_v2_rotation_qualification_receipt_sha256"
            ),
            "route_v2_rotation_qualification_node_ack_sets_sha256": (
                "route_v2_rotation_qualification_node_ack_sets_sha256"
            ),
            "route_v2_rotation_qualification_transcript_sha256": (
                "route_v2_rotation_qualification_transcript_sha256"
            ),
            "usage_terminal_receipt_sha256": "usage_terminal_receipt_sha256",
            "old_host_coverage_sha256": "old_host_coverage_sha256",
            "kernel_nbd_qualification_bundle_sha256": (
                "kernel_nbd_qualification_bundle_sha256"
            ),
            "vhost_user_qualification_bundle_sha256": (
                "vhost_user_qualification_bundle_sha256"
            ),
        }
        if (
            completion.plan_sha256 != planned.reset_plan_sha256.removeprefix("sha256:")
            or completion.reset_complete_sha256
            != planned.reset_complete_receipt_sha256
            or complete.get("reset_id") != binding["reset_id"]
            or complete.get("release_commit") != binding["source_commit_sha"]
            or complete.get("artifact_sha256")
            != binding["release_manifest_sha256"].removeprefix("sha256:")
            or frozen["operator"] != planned.operator
            or trust["deployment_id"] != binding["deployment_id"]
            or trust["release_id"] != binding["release_id"]
            or trust["source_commit_sha"] != binding["source_commit_sha"]
            or scope["aws_partition"] != planned.operator["aws_partition"]
            or scope["account_id"] != planned.operator["account_id"]
            or scope["role_arn"] != planned.operator["role_arn"]
            or any(
                frozen[projection_field] != binding[binding_field]
                for projection_field, binding_field in projection_bindings.items()
            )
        ):
            raise FinalOpenError("post-boundary reset authority drifted")
        return planned

    def _post_boundary_authority(
        self,
        planned: OpenAuthority,
        *,
        cleanup: bool,
    ) -> OpenAuthority:
        injected = (
            self.cleanup_authority_verifier
            if cleanup
            else self.forward_authority_verifier
        )
        if injected is None:
            injected = self.authority_verifier
        if injected is not None:
            live = validate_authority(injected(), self.open_id)
            if live != planned:
                raise FinalOpenError("post-boundary reset/proof authority drifted")
            return live
        try:
            verifier = (
                self.reset_executor.verify_complete_for_cleanup
                if cleanup
                else self.reset_executor.verify_complete_after_open_started
            )
            completion = verifier(
                self.reset_plan_path,
                self.reset_plan_sha256,
            )
            return self._validate_post_boundary_completion(completion, planned)
        except (RESET.ResetError, RESET.cutover_proof.ProofSetError) as error:
            mode = "cleanup" if cleanup else "forward recovery"
            raise FinalOpenError(
                f"post-boundary reset authority failed closed for {mode}"
            ) from error

    def _write(self, stage: str, value: dict[str, Any]) -> tuple[Path, str]:
        return RESET.write_receipt(
            self.receipt_directory,
            self.open_id,
            stage,
            value,
            publication_hook=self.receipt_publication_hook,
        )

    def _stage_names(self, effects: dict[str, Any]) -> list[str]:
        return [
            "open-started",
            *[
                f"node-{node['node_id']}-schedulable"
                for node in effects["nodes"]
            ],
            "nodes-schedulable",
            "public-ingress-open",
            "public-probe-terminal",
            "mutation-admission-open-finalizing",
            "mutation-admission-open",
            "open-complete",
        ]

    @staticmethod
    def _open_finalizing_evidence(prepared: PreparedAdmission) -> dict[str, Any]:
        return {
            "status": "exact_open_forward_settlement_required",
            "command_id": prepared.value["command_id"],
            "request_sha256": prepared.value["request_sha256"],
            "expected_revision": prepared.value["expected_revision"],
        }

    def _receipt(
        self,
        *,
        stage: str,
        plan_sha256: str,
        authority_sha256: str,
        previous_sha256: str | None,
        evidence: dict[str, Any],
    ) -> dict[str, Any]:
        return {
            "kind": RECEIPT_KIND,
            "version": 1,
            "open_id": self.open_id,
            "stage": stage,
            "created_at_unix_ms": now_unix_ms(),
            "plan_sha256": plan_sha256,
            "authority_sha256": authority_sha256,
            "previous_receipt_sha256": previous_sha256,
            "evidence": evidence,
        }

    def plan(self) -> tuple[Path, str]:
        existing = RESET.read_stage_receipt(
            self.receipt_directory,
            self.open_id,
            "open-plan",
        )
        if existing is not None:
            path, _value, digest = existing
            plan, _plan_digest, authority, _prepared, _effects = self._validate_plan(
                path,
                digest,
            )
            if self._authority() != authority:
                raise FinalOpenError(
                    "terminal reset/proof authority changed since the existing plan"
                )
            if now_unix_ms() >= plan["execution_deadline_unix_ms"]:
                raise FinalOpenError(
                    "the existing final-open plan expired; use a new open_id"
                )
            return path, digest
        authority = self._authority()
        effects = validate_effects(
            self.effects.prepare(authority),
            authority,
            self.open_id,
        )
        self.effects.validate_plan(effects, authority)
        prepared = self.admission.prepare(authority)
        self.admission.validate(prepared, authority)
        authority_projection = authority.projection()
        created_at_unix_ms = now_unix_ms()
        expires_at_unix_ms = prepared.value.get("expires_at_unix_ms")
        if (
            type(expires_at_unix_ms) is not int
            or expires_at_unix_ms - created_at_unix_ms
            <= OPEN_EXECUTION_MIN_REMAINING_MS
        ):
            raise FinalOpenError(
                "signed final-open request has no safe reviewed execution window"
            )
        plan = {
            "kind": PLAN_KIND,
            "version": 1,
            "mode": "read_only_plan",
            "open_id": self.open_id,
            "created_at_unix_ms": created_at_unix_ms,
            "execution_deadline_unix_ms": (
                expires_at_unix_ms - OPEN_EXECUTION_MIN_REMAINING_MS
            ),
            "authority": authority_projection,
            "authority_sha256": sha256(canonical_json(authority_projection)),
            "admission": prepared.value,
            "admission_sha256": sha256(canonical_json(prepared.value)),
            "effects": effects,
            "effects_sha256": sha256(canonical_json(effects)),
            "rollback_boundary": (
                "before open-started: mutation-free; after open-started and before "
                "mutation-admission-open-finalizing: close ingress, re-cordon, prove "
                "admission/Fleet Closed; after finalizing: exact-forward Open only"
            ),
        }
        return self._write("open-plan", plan)

    def _validate_plan(
        self,
        plan_path: Path,
        supplied_sha256: str,
    ) -> tuple[dict[str, Any], str, OpenAuthority, PreparedAdmission, dict[str, Any]]:
        if RAW_SHA256.fullmatch(supplied_sha256) is None:
            raise FinalOpenError("open plan SHA-256 must be exact lowercase hex")
        plan, raw = read_canonical(plan_path, "final-open plan", MAX_OPEN_PLAN_BYTES)
        actual = hashlib.sha256(raw).hexdigest()
        if actual != supplied_sha256:
            raise FinalOpenError("final-open plan digest drifted")
        plan = require_fields(
            plan,
            {
                "kind",
                "version",
                "mode",
                "open_id",
                "created_at_unix_ms",
                "execution_deadline_unix_ms",
                "authority",
                "authority_sha256",
                "admission",
                "admission_sha256",
                "effects",
                "effects_sha256",
                "rollback_boundary",
            },
            "final-open plan",
        )
        if (
            plan["kind"] != PLAN_KIND
            or not version_one(plan["version"])
            or plan["mode"] != "read_only_plan"
            or plan["open_id"] != self.open_id
            or type(plan["created_at_unix_ms"]) is not int
            or plan["created_at_unix_ms"] <= 0
            or type(plan["execution_deadline_unix_ms"]) is not int
            or plan["execution_deadline_unix_ms"] <= plan["created_at_unix_ms"]
            or type(plan["admission"].get("expires_at_unix_ms")) is not int
            or plan["execution_deadline_unix_ms"]
            != plan["admission"]["expires_at_unix_ms"]
            - OPEN_EXECUTION_MIN_REMAINING_MS
            or plan["authority_sha256"] != sha256(canonical_json(plan["authority"]))
            or plan["admission_sha256"] != sha256(canonical_json(plan["admission"]))
            or plan["effects_sha256"] != sha256(canonical_json(plan["effects"]))
        ):
            raise FinalOpenError("final-open plan binding drifted")
        authority_value = require_fields(
            plan["authority"],
            {
                "operator",
                "binding",
                "reset_plan_sha256",
                "reset_complete_receipt_sha256",
            },
            "final-open plan authority",
        )
        authority = validate_authority(
            OpenAuthority(**authority_value),
            self.open_id,
        )
        prepared = PreparedAdmission(plan["admission"])
        effects = validate_effects(plan["effects"], authority, self.open_id)
        self.admission.validate(prepared, authority)
        self.effects.validate_plan(effects, authority)
        return plan, "sha256:" + actual, authority, prepared, effects

    def _load_chain(
        self,
        stages: list[str],
        plan_sha256: str,
        authority_sha256: str,
    ) -> dict[str, tuple[Path, dict[str, Any], str]]:
        loaded: dict[str, tuple[Path, dict[str, Any], str]] = {}
        gap = False
        previous: str | None = None
        for stage in stages:
            item = RESET.read_stage_receipt(self.receipt_directory, self.open_id, stage)
            if item is None:
                gap = True
                continue
            if gap:
                raise FinalOpenError(f"final-open receipt chain has a gap before {stage}")
            path, value, raw_digest = item
            value = require_fields(
                value,
                {
                    "kind",
                    "version",
                    "open_id",
                    "stage",
                    "created_at_unix_ms",
                    "plan_sha256",
                    "authority_sha256",
                    "previous_receipt_sha256",
                    "evidence",
                },
                f"{stage} receipt",
            )
            if (
                value["kind"] != RECEIPT_KIND
                or not version_one(value["version"])
                or value["open_id"] != self.open_id
                or value["stage"] != stage
                or type(value["created_at_unix_ms"]) is not int
                or value["created_at_unix_ms"] <= 0
                or value["plan_sha256"] != plan_sha256
                or value["authority_sha256"] != authority_sha256
                or value["previous_receipt_sha256"] != previous
                or not isinstance(value["evidence"], dict)
            ):
                raise FinalOpenError(f"{stage} receipt binding drifted")
            previous = "sha256:" + raw_digest
            loaded[stage] = (path, value, previous)
        return loaded

    def _validate_main_chain(
        self,
        loaded: dict[str, tuple[Path, dict[str, Any], str]],
        *,
        authority: OpenAuthority,
        prepared: PreparedAdmission,
        effects: dict[str, Any],
    ) -> None:
        if "open-started" in loaded:
            expected = {
                "status": "closed_preparation_started",
                "reset_complete_receipt_sha256": (
                    authority.reset_complete_receipt_sha256
                ),
                "proof_set_sha256": authority.binding["proof_set_sha256"],
            }
            if loaded["open-started"][1]["evidence"] != expected:
                raise FinalOpenError("open-started evidence drifted")
        for node in effects["nodes"]:
            stage = f"node-{node['node_id']}-schedulable"
            if stage in loaded:
                self.effects.validate_node_schedulable(
                    loaded[stage][1]["evidence"],
                    node,
                    authority,
                )
        if "nodes-schedulable" in loaded:
            expected = {
                "node_ids": [node["node_id"] for node in effects["nodes"]],
                "count": len(effects["nodes"]),
            }
            if loaded["nodes-schedulable"][1]["evidence"] != expected:
                raise FinalOpenError("Node schedulable aggregate evidence drifted")
        if "public-ingress-open" in loaded:
            self.effects.validate_ingress_open(
                loaded["public-ingress-open"][1]["evidence"],
                effects,
                authority,
            )
        if "public-probe-terminal" in loaded:
            self.effects.validate_public_probe(
                loaded["public-probe-terminal"][1]["evidence"],
                effects,
                authority,
            )
        if "mutation-admission-open-finalizing" in loaded:
            if (
                loaded["mutation-admission-open-finalizing"][1]["evidence"]
                != self._open_finalizing_evidence(prepared)
            ):
                raise FinalOpenError("Open finalization marker evidence drifted")
        if "mutation-admission-open" in loaded:
            self.admission.validate_open_evidence(
                loaded["mutation-admission-open"][1]["evidence"],
                prepared,
                authority,
            )
        if "open-complete" in loaded:
            expected = {
                "outcome": "open_complete",
                "node_count": len(effects["nodes"]),
                "public_probe_target_sha256": effects[
                    "public_probe_target_sha256"
                ],
            }
            if loaded["open-complete"][1]["evidence"] != expected:
                raise FinalOpenError("open-complete evidence drifted")

    def _cleanup_stage_names(self, node_ids: list[str]) -> list[str]:
        return [
            "cleanup-started",
            "cleanup-public-ingress-closed",
            *[f"cleanup-node-{node_id}-cordoned" for node_id in reversed(node_ids)],
            "cleanup-mutation-admission-closed",
            "cleanup-fleet-closed",
            "open-aborted",
        ]

    def _conservative_cleanup_projection(
        self,
        main: dict[str, tuple[Path, dict[str, Any], str]],
        effects: dict[str, Any],
    ) -> tuple[bool, bool, list[dict[str, Any]]]:
        """Include the one receipt-less effect that may already have applied."""

        admission_may_be_open = "mutation-admission-open-finalizing" in main
        possibly_schedulable: list[dict[str, Any]] = []
        if "open-started" in main:
            for node in effects["nodes"]:
                possibly_schedulable.append(node)
                if f"node-{node['node_id']}-schedulable" not in main:
                    break
        ingress_may_be_open = "nodes-schedulable" in main
        return admission_may_be_open, ingress_may_be_open, possibly_schedulable

    def _stage_artifact_exists(self, stage: str) -> bool:
        return any(
            candidate.exists() or candidate.is_symlink()
            for candidate in (
                self.receipt_directory / f"{self.open_id}.{stage}.json",
                self.receipt_directory / f"{self.open_id}.{stage}.sha256",
            )
        )

    def _load_cleanup_chain(
        self,
        *,
        main: dict[str, tuple[Path, dict[str, Any], str]],
        plan_sha256: str,
        authority_sha256: str,
        effects: dict[str, Any],
    ) -> tuple[
        dict[str, Any],
        dict[str, tuple[Path, dict[str, Any], str]],
    ] | None:
        start = RESET.read_stage_receipt(
            self.receipt_directory,
            self.open_id,
            "cleanup-started",
        )
        all_node_ids = [node["node_id"] for node in effects["nodes"]]
        possible_later = self._cleanup_stage_names(all_node_ids)[1:]
        if start is None:
            if any(self._stage_artifact_exists(stage) for stage in possible_later):
                raise FinalOpenError(
                    "cleanup journal has an effect receipt without cleanup-started"
                )
            return None
        if "mutation-admission-open-finalizing" in main:
            raise FinalOpenError(
                "cleanup journal crossed the forward-only Open finalization marker"
            )
        _path, start_value, _digest = start
        if not isinstance(start_value, dict):
            raise FinalOpenError("cleanup-started receipt is not an object")
        evidence = start_value.get("evidence")
        evidence = require_fields(
            evidence,
            {
                "failed",
                "admission_may_be_open",
                "ingress_may_be_open",
                "possibly_schedulable_node_ids",
            },
            "cleanup-started evidence",
        )
        node_ids = evidence["possibly_schedulable_node_ids"]
        if (
            not isinstance(evidence["failed"], str)
            or not evidence["failed"]
            or len(evidence["failed"]) > 256
            or type(evidence["admission_may_be_open"]) is not bool
            or type(evidence["ingress_may_be_open"]) is not bool
            or not isinstance(node_ids, list)
            or any(not isinstance(node_id, str) for node_id in node_ids)
            or node_ids != all_node_ids[: len(node_ids)]
            or (evidence["ingress_may_be_open"] and node_ids != all_node_ids)
            or evidence["admission_may_be_open"]
            or (
                "public-ingress-open" in main
                and not evidence["ingress_may_be_open"]
            )
        ):
            raise FinalOpenError("cleanup-started projection drifted")
        for node in effects["nodes"]:
            stage = f"node-{node['node_id']}-schedulable"
            if stage in main and node["node_id"] not in node_ids:
                raise FinalOpenError(
                    "cleanup-started omitted a possibly schedulable Node"
                )
        stages = self._cleanup_stage_names(node_ids)
        for stage in possible_later:
            if stage not in stages and self._stage_artifact_exists(stage):
                raise FinalOpenError("cleanup journal contains a foreign Node stage")
        loaded = self._load_chain(stages, plan_sha256, authority_sha256)
        return evidence, loaded

    def _validate_cleanup_chain(
        self,
        context: dict[str, Any],
        loaded: dict[str, tuple[Path, dict[str, Any], str]],
        *,
        authority: OpenAuthority,
        prepared: PreparedAdmission,
        effects: dict[str, Any],
    ) -> None:
        if loaded["cleanup-started"][1]["evidence"] != context:
            raise FinalOpenError("cleanup-started evidence changed during replay")
        if "cleanup-public-ingress-closed" in loaded:
            self.effects.validate_ingress_closed(
                loaded["cleanup-public-ingress-closed"][1]["evidence"],
                effects,
                authority,
                context["ingress_may_be_open"],
            )
        nodes_by_id = {node["node_id"]: node for node in effects["nodes"]}
        for node_id in reversed(context["possibly_schedulable_node_ids"]):
            stage = f"cleanup-node-{node_id}-cordoned"
            if stage in loaded:
                self.effects.validate_node_cordoned(
                    loaded[stage][1]["evidence"],
                    nodes_by_id[node_id],
                    authority,
                )
        if "cleanup-mutation-admission-closed" in loaded:
            self.admission.validate_closed_evidence(
                loaded["cleanup-mutation-admission-closed"][1]["evidence"],
                prepared,
                authority,
            )
        if "cleanup-fleet-closed" in loaded:
            self.effects.validate_cleanup_fleet_closed(
                loaded["cleanup-fleet-closed"][1]["evidence"],
                effects,
                authority,
            )
        if "open-aborted" in loaded and loaded["open-aborted"][1]["evidence"] != {
            "outcome": "closed_cleanup_terminal"
        }:
            raise FinalOpenError("open-aborted evidence drifted")

    def _reject_foreign_journal_files(
        self,
        effects: dict[str, Any],
    ) -> None:
        stages = {
            "open-plan",
            "open-dry-run",
            *self._stage_names(effects),
            *self._cleanup_stage_names(
                [node["node_id"] for node in effects["nodes"]]
            ),
        }
        allowed = {
            f"{self.open_id}.{stage}.{suffix}"
            for stage in stages
            for suffix in ("json", "sha256")
        }
        prefix = f"{self.open_id}."
        for entry in self.receipt_directory.iterdir():
            if entry.name.startswith(prefix) and entry.name not in allowed:
                raise FinalOpenError("final-open journal contains a foreign artifact")

    def _publish_stage(
        self,
        stage: str,
        evidence: dict[str, Any],
        *,
        plan_sha256: str,
        authority_sha256: str,
        previous_sha256: str | None,
    ) -> tuple[Path, dict[str, Any], str]:
        value = self._receipt(
            stage=stage,
            plan_sha256=plan_sha256,
            authority_sha256=authority_sha256,
            previous_sha256=previous_sha256,
            evidence=evidence,
        )
        path, digest = self._write(stage, value)
        return path, value, "sha256:" + digest

    def apply(
        self,
        plan_path: Path,
        plan_sha256: str,
        confirmation: str,
        *,
        execute: bool,
    ) -> tuple[Path, str]:
        if confirmation != self.open_id:
            raise FinalOpenError("--confirm-open-id does not match the reviewed target")
        plan, plan_digest, planned_authority, prepared, effects = self._validate_plan(
            plan_path,
            plan_sha256,
        )
        stored_plan = RESET.read_stage_receipt(
            self.receipt_directory,
            self.open_id,
            "open-plan",
        )
        if (
            stored_plan is None
            or stored_plan[1] != plan
            or stored_plan[2] != plan_sha256
        ):
            raise FinalOpenError(
                "apply requires the exact immutable plan published for this open_id"
            )
        authority_digest = plan["authority_sha256"]
        stages = self._stage_names(effects)
        existing = self._load_chain(stages, plan_digest, authority_digest)
        self._reject_foreign_journal_files(effects)
        cleanup = self._load_cleanup_chain(
            main=existing,
            plan_sha256=plan_digest,
            authority_sha256=authority_digest,
            effects=effects,
        )
        self._validate_main_chain(
            existing,
            authority=planned_authority,
            prepared=prepared,
            effects=effects,
        )
        if cleanup is not None:
            cleanup_context, cleanup_existing = cleanup
            self._validate_cleanup_chain(
                cleanup_context,
                cleanup_existing,
                authority=planned_authority,
                prepared=prepared,
                effects=effects,
            )
            if "open-aborted" in cleanup_existing:
                raise FinalOpenError(
                    "this final-open plan was terminally aborted; create a new open_id and plan"
                )
            if not execute:
                raise FinalOpenError(
                    "closed cleanup is incomplete; use --execute to resume it"
                )
            live_authority = self._post_boundary_authority(
                planned_authority,
                cleanup=True,
            )
            self.admission.validate(prepared, live_authority)
            self.effects.validate_cleanup(effects, live_authority)
            self._resume_cleanup(
                context=cleanup_context,
                existing=cleanup_existing,
                plan_digest=plan_digest,
                authority_digest=authority_digest,
                authority=live_authority,
                prepared=prepared,
                effects=effects,
            )
            raise FinalOpenError(
                "the prior final-open attempt is now terminally closed; create a new plan"
            )
        if "open-complete" in existing:
            path, _value, digest = existing["open-complete"]
            return path, digest.removeprefix("sha256:")

        started_on_entry = "open-started" in existing
        finalizing_on_entry = "mutation-admission-open-finalizing" in existing
        if started_on_entry:
            try:
                live_authority = self._post_boundary_authority(
                    planned_authority,
                    cleanup=False,
                )
                self.admission.validate(prepared, live_authority)
                self.effects.validate_post_boundary_forward(
                    effects,
                    live_authority,
                )
            except BaseException as forward_error:
                if finalizing_on_entry:
                    raise FinalOpenError(
                        "Open finalization authority is unavailable; exact-forward resume is required"
                    ) from forward_error
                if not execute:
                    raise FinalOpenError(
                        "post-boundary forward authority failed; use --execute for cleanup"
                    ) from forward_error
                cleanup_authority = self._post_boundary_authority(
                    planned_authority,
                    cleanup=True,
                )
                self.admission.validate(prepared, cleanup_authority)
                self.effects.validate_cleanup(effects, cleanup_authority)
                (
                    admission_may_be_open,
                    ingress_may_be_open,
                    possibly_schedulable,
                ) = self._conservative_cleanup_projection(existing, effects)
                self._start_or_resume_cleanup(
                    plan_digest=plan_digest,
                    authority_digest=authority_digest,
                    authority=cleanup_authority,
                    prepared=prepared,
                    effects=effects,
                    admission_may_be_open=admission_may_be_open,
                    ingress_may_be_open=ingress_may_be_open,
                    possibly_schedulable=possibly_schedulable,
                )
                raise FinalOpenError(
                    "post-boundary forward authority failed; closed cleanup is terminal"
                ) from forward_error
        else:
            live_authority = self._authority()
            if live_authority != planned_authority:
                raise FinalOpenError(
                    "terminal reset/proof authority changed since planning"
                )
            self.admission.validate(prepared, live_authority)
        if not execute:
            if existing:
                raise FinalOpenError(
                    "final Open already crossed open-started; use --execute to resume"
                )
            evaluated_at_unix_ms = now_unix_ms()
            if evaluated_at_unix_ms >= plan["execution_deadline_unix_ms"]:
                raise FinalOpenError(
                    "final-open plan expired before its mutation-free dry-run"
                )
            self.admission.validate_live_closed(
                prepared,
                live_authority,
                evaluated_at_unix_ms,
            )
            self.effects.validate_live_closed_before_start(
                effects,
                live_authority,
            )
            dry_run = RESET.read_stage_receipt(
                self.receipt_directory,
                self.open_id,
                "open-dry-run",
            )
            if dry_run is not None:
                path, value, digest = dry_run
                expected_fields = {
                    "kind",
                    "version",
                    "open_id",
                    "stage",
                    "created_at_unix_ms",
                    "plan_sha256",
                    "authority_sha256",
                    "previous_receipt_sha256",
                    "evidence",
                }
                if (
                    not isinstance(value, dict)
                    or set(value) != expected_fields
                    or value["kind"] != RECEIPT_KIND
                    or not version_one(value["version"])
                    or value["open_id"] != self.open_id
                    or value["stage"] != "open-dry-run"
                    or type(value["created_at_unix_ms"]) is not int
                    or value["created_at_unix_ms"] <= 0
                    or value["plan_sha256"] != plan_digest
                    or value["authority_sha256"] != authority_digest
                    or value["previous_receipt_sha256"] is not None
                    or value["evidence"] != {"mutations_executed": False}
                ):
                    raise FinalOpenError("existing final-open dry-run receipt drifted")
                return path, digest
            value = self._receipt(
                stage="open-dry-run",
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=None,
                evidence={"mutations_executed": False},
            )
            return self._write("open-dry-run", value)

        previous = existing[stages[len(existing) - 1]][2] if existing else None
        cancellation = Cancellation()
        prior_handlers: dict[int, Any] = {}
        for signal_number in (signal.SIGINT, signal.SIGTERM):
            prior_handlers[signal_number] = signal.signal(signal_number, cancellation.handler)
        (
            admission_may_be_open,
            ingress_may_be_open,
            possibly_schedulable,
        ) = self._conservative_cleanup_projection(existing, effects)
        admission_finalization_started = finalizing_on_entry
        try:
            if not started_on_entry:
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled before open-started")
                evaluated_at_unix_ms = now_unix_ms()
                if evaluated_at_unix_ms >= plan["execution_deadline_unix_ms"]:
                    raise FinalOpenError(
                        "final-open plan expired before open-started"
                    )
                self.admission.validate_live_closed(
                    prepared,
                    live_authority,
                    evaluated_at_unix_ms,
                )
                self.effects.validate_live_closed_before_start(
                    effects,
                    live_authority,
                )
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled before open-started")
                _path, _value, previous = self._publish_stage(
                    "open-started",
                    {
                        "status": "closed_preparation_started",
                        "reset_complete_receipt_sha256": (
                            live_authority.reset_complete_receipt_sha256
                        ),
                        "proof_set_sha256": live_authority.binding["proof_set_sha256"],
                    },
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=None,
                )
            if started_on_entry and not finalizing_on_entry:
                evaluated_at_unix_ms = now_unix_ms()
                if evaluated_at_unix_ms >= plan["execution_deadline_unix_ms"]:
                    raise FinalOpenError(
                        "signed Open expired before finalization; closing the attempt"
                    )
                self.admission.validate_live_closed(
                    prepared,
                    live_authority,
                    evaluated_at_unix_ms,
                )

            for node in effects["nodes"]:
                stage = f"node-{node['node_id']}-schedulable"
                if stage in existing:
                    if node not in possibly_schedulable:
                        possibly_schedulable.append(node)
                    continue
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled at a stage boundary")
                if node not in possibly_schedulable:
                    possibly_schedulable.append(node)
                evidence = self.effects.settle_node_schedulable(node, live_authority)
                _path, _value, previous = self._publish_stage(
                    stage,
                    evidence,
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            if "nodes-schedulable" not in existing:
                _path, _value, previous = self._publish_stage(
                    "nodes-schedulable",
                    {
                        "node_ids": [node["node_id"] for node in effects["nodes"]],
                        "count": len(effects["nodes"]),
                    },
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            if "public-ingress-open" not in existing:
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled at a stage boundary")
                ingress_may_be_open = True
                evidence = self.effects.settle_ingress_open(effects, live_authority)
                _path, _value, previous = self._publish_stage(
                    "public-ingress-open",
                    evidence,
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            if "public-probe-terminal" not in existing:
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled at a stage boundary")
                evidence = self.effects.settle_public_probe(effects, live_authority)
                _path, _value, previous = self._publish_stage(
                    "public-probe-terminal",
                    evidence,
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            if "mutation-admission-open-finalizing" not in existing:
                if cancellation.requested:
                    raise FinalOpenError("final Open cancelled before Open finalization")
                evaluated_at_unix_ms = now_unix_ms()
                if evaluated_at_unix_ms >= plan["execution_deadline_unix_ms"]:
                    raise FinalOpenError(
                        "signed Open expired before finalization; closing the attempt"
                    )
                self.admission.validate_live_closed(
                    prepared,
                    live_authority,
                    evaluated_at_unix_ms,
                )
                if cancellation.requested:
                    raise FinalOpenError(
                        "final Open cancelled before Open finalization"
                    )
                # Once this immutable marker may have linked, cancellation and
                # every ambiguous result converge only by settling the exact
                # reviewed Open command.  There is no later external effect.
                admission_finalization_started = True
                admission_may_be_open = True
                _path, _value, previous = self._publish_stage(
                    "mutation-admission-open-finalizing",
                    self._open_finalizing_evidence(prepared),
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            if "mutation-admission-open" not in existing:
                evidence = self.admission.settle_open(
                    prepared,
                    live_authority,
                    cancellation,
                )
                _path, _value, previous = self._publish_stage(
                    "mutation-admission-open",
                    evidence,
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
            else:
                open_evidence = existing["mutation-admission-open"][1]["evidence"]
                settled = self.admission.settle_open(
                    prepared,
                    live_authority,
                    cancellation,
                )
                if settled != open_evidence:
                    raise FinalOpenError("final-open admission replay drifted")
            complete_path, _complete, complete_digest = self._publish_stage(
                "open-complete",
                {
                    "outcome": "open_complete",
                    "node_count": len(effects["nodes"]),
                    "public_probe_target_sha256": effects[
                        "public_probe_target_sha256"
                    ],
                },
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=previous,
            )
            return complete_path, complete_digest.removeprefix("sha256:")
        except BaseException as error:
            if admission_finalization_started:
                raise FinalOpenError(
                    "Open finalization is incomplete; resume the exact plan to settle it"
                ) from error
            if "open-started" in existing or previous is not None:
                try:
                    self._start_or_resume_cleanup(
                        plan_digest=plan_digest,
                        authority_digest=authority_digest,
                        authority=live_authority,
                        prepared=prepared,
                        effects=effects,
                        admission_may_be_open=admission_may_be_open,
                        ingress_may_be_open=ingress_may_be_open,
                        possibly_schedulable=possibly_schedulable,
                    )
                except BaseException as cleanup_error:
                    raise FinalOpenError(
                        "final Open failed and closed cleanup is not terminal"
                    ) from cleanup_error
                raise FinalOpenError(
                    "final Open failed; closed cleanup reached its terminal receipt"
                ) from error
            if isinstance(error, FinalOpenError):
                raise
            raise FinalOpenError("final Open failed closed") from error
        finally:
            for signal_number, handler in prior_handlers.items():
                signal.signal(signal_number, handler)

    def _start_or_resume_cleanup(
        self,
        *,
        plan_digest: str,
        authority_digest: str,
        authority: OpenAuthority,
        prepared: PreparedAdmission,
        effects: dict[str, Any],
        admission_may_be_open: bool,
        ingress_may_be_open: bool,
        possibly_schedulable: list[dict[str, Any]],
    ) -> None:
        context = {
            "failed": "final_open_failed_or_cancelled",
            "admission_may_be_open": admission_may_be_open,
            "ingress_may_be_open": ingress_may_be_open,
            "possibly_schedulable_node_ids": [
                node["node_id"] for node in possibly_schedulable
            ],
        }
        existing_start = RESET.read_stage_receipt(
            self.receipt_directory,
            self.open_id,
            "cleanup-started",
        )
        if existing_start is None:
            _path, _value, previous = self._publish_stage(
                "cleanup-started",
                context,
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=None,
            )
        else:
            existing_context = existing_start[1].get("evidence")
            if existing_context != context:
                raise FinalOpenError("cleanup restart context drifted")
        stages = self._cleanup_stage_names(context["possibly_schedulable_node_ids"])
        existing = self._load_chain(stages, plan_digest, authority_digest)
        self._validate_cleanup_chain(
            context,
            existing,
            authority=authority,
            prepared=prepared,
            effects=effects,
        )
        self._resume_cleanup(
            context=context,
            existing=existing,
            plan_digest=plan_digest,
            authority_digest=authority_digest,
            authority=authority,
            prepared=prepared,
            effects=effects,
        )

    def _resume_cleanup(
        self,
        *,
        context: dict[str, Any],
        existing: dict[str, tuple[Path, dict[str, Any], str]],
        plan_digest: str,
        authority_digest: str,
        authority: OpenAuthority,
        prepared: PreparedAdmission,
        effects: dict[str, Any],
    ) -> None:
        stages = self._cleanup_stage_names(context["possibly_schedulable_node_ids"])
        previous = existing[stages[len(existing) - 1]][2]
        if "cleanup-public-ingress-closed" not in existing:
            evidence = self.effects.settle_ingress_closed(
                effects,
                authority,
                context["ingress_may_be_open"],
            )
            _path, _value, previous = self._publish_stage(
                "cleanup-public-ingress-closed",
                evidence,
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=previous,
            )
        nodes_by_id = {node["node_id"]: node for node in effects["nodes"]}
        for node_id in reversed(context["possibly_schedulable_node_ids"]):
            stage = f"cleanup-node-{node_id}-cordoned"
            if stage not in existing:
                evidence = self.effects.settle_node_cordoned(
                    nodes_by_id[node_id],
                    authority,
                )
                _path, _value, previous = self._publish_stage(
                    stage,
                    evidence,
                    plan_sha256=plan_digest,
                    authority_sha256=authority_digest,
                    previous_sha256=previous,
                )
        if "cleanup-mutation-admission-closed" not in existing:
            closed = self.admission.settle_closed(prepared, authority)
            _path, _value, previous = self._publish_stage(
                "cleanup-mutation-admission-closed",
                closed,
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=previous,
            )
        if "cleanup-fleet-closed" not in existing:
            fleet = self.effects.settle_cleanup_fleet_closed(effects, authority)
            _path, _value, previous = self._publish_stage(
                "cleanup-fleet-closed",
                fleet,
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=previous,
            )
        if "open-aborted" not in existing:
            self._publish_stage(
                "open-aborted",
                {"outcome": "closed_cleanup_terminal"},
                plan_sha256=plan_digest,
                authority_sha256=authority_digest,
                previous_sha256=previous,
            )


def add_open_arguments(parser: argparse.ArgumentParser) -> None:
    RESET.add_common_arguments(parser)
    parser.add_argument("--open-id", required=True)
    parser.add_argument("--control-origin", required=True)
    parser.add_argument(
        "--production-cutover-operator-private-key-file",
        required=True,
        type=Path,
    )
    parser.add_argument("--open-state-directory", required=True, type=Path)
    parser.add_argument("--open-receipt-directory", required=True, type=Path)
    parser.add_argument("--reset-plan-receipt", required=True, type=Path)
    parser.add_argument("--reset-plan-sha256", required=True)


def executor_from_args(args: argparse.Namespace) -> FinalOpenExecutor:
    reset_executor = RESET.ResetExecutor(RESET.config_from_args(args), RESET.CommandRunner())
    admission = ProductionAdmissionClient(
        open_id=args.open_id,
        origin=args.control_origin,
        trust_file=args.production_cutover_operator_trust_file,
        private_key_file=args.production_cutover_operator_private_key_file,
        state_directory=args.open_state_directory,
    )
    return FinalOpenExecutor(
        open_id=args.open_id,
        reset_executor=reset_executor,
        reset_plan_path=args.reset_plan_receipt,
        reset_plan_sha256=args.reset_plan_sha256,
        admission=admission,
        receipt_directory=args.open_receipt_directory,
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    plan_parser = commands.add_parser("plan", help="verify and publish a read-only final-open plan")
    add_open_arguments(plan_parser)
    apply_parser = commands.add_parser("apply", help="apply or exact-replay one reviewed plan")
    add_open_arguments(apply_parser)
    apply_parser.add_argument("--open-plan-receipt", required=True, type=Path)
    apply_parser.add_argument("--open-plan-sha256", required=True)
    apply_parser.add_argument("--confirm-open-id", required=True)
    apply_parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    try:
        executor = executor_from_args(args)
        if args.command == "plan":
            path, digest = executor.plan()
        else:
            path, digest = executor.apply(
                args.open_plan_receipt,
                args.open_plan_sha256,
                args.confirm_open_id,
                execute=args.execute,
            )
        print(json.dumps({"receipt": str(path), "sha256": digest}, sort_keys=True))
        return 0
    except (FinalOpenError, RESET.ResetError, ADMISSION.AdmissionError) as error:
        print(f"production final Open refused: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
