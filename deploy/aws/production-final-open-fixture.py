#!/usr/bin/env python3
"""Focused offline contract fixture for the E13 final-open journal."""

from __future__ import annotations

import argparse
import importlib.util
import os
import signal
import stat
import sys
import tempfile
import time
import types
from pathlib import Path
from typing import Any


def load_operator() -> Any:
    path = Path(__file__).resolve().with_name("production-final-open.py")
    spec = importlib.util.spec_from_file_location("cats_final_open_fixture_subject", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load final-open operator")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


OPEN = load_operator()
DIGEST = "sha256:" + "1" * 64


def authority() -> Any:
    binding = {field: DIGEST for field in OPEN.ADMISSION.OPEN_BINDING_FIELDS}
    binding.update(
        {
            "reset_id": "reset-stageb-01",
            "deployment_id": "deployment-stageb-01",
            "release_id": "release-stageb-01",
            "source_commit_sha": "a" * 40,
            "control_schema_version": 16,
            "reset_complete_receipt_sha256": "sha256:" + "2" * 64,
        }
    )
    return OPEN.OpenAuthority(
        operator={
            "aws_partition": "aws",
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/cats-cutover",
            "principal_arn": (
                "arn:aws:sts::123456789012:assumed-role/cats-cutover/session"
            ),
        },
        binding=binding,
        reset_plan_sha256="sha256:" + "3" * 64,
        reset_complete_receipt_sha256=binding[
            "reset_complete_receipt_sha256"
        ],
    )


class FixtureProofSet:
    def admission_binding(self, reset_complete_sha256: str) -> dict[str, Any]:
        value = dict(authority().binding)
        assert value["reset_complete_receipt_sha256"] == reset_complete_sha256
        return value


class ResetAuthoritySpy:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.pristine_refuses = False
        self.forward_refuses = False
        self.cleanup_refuses = False
        self.session_refreshed = False

    @staticmethod
    def _post_completion() -> Any:
        expected = authority()
        frozen = {field: DIGEST for field in OPEN.RESET.CUTOVER_AUTHORITY_FIELDS}
        frozen.update(
            {
                "cutover_id": "cutover-stageb-01",
                "operator": expected.operator,
                "release_id": expected.binding["release_id"],
                "release_manifest_sha256": expected.binding[
                    "release_manifest_sha256"
                ],
                "qualification_manifest_sha256": expected.binding[
                    "qualification_manifest_sha256"
                ],
                "qualification_catalog_sha256": expected.binding[
                    "qualification_catalog_sha256"
                ],
                "proof_set_sha256": expected.binding["proof_set_sha256"],
                "fresh_targets_sha256": expected.binding["fresh_targets_sha256"],
                "fleet_closed_receipt_sha256": expected.binding[
                    "fleet_closed_receipt_sha256"
                ],
                "route_v2_rotation_qualification_receipt_sha256": expected.binding[
                    "route_v2_rotation_qualification_receipt_sha256"
                ],
                "route_v2_rotation_qualification_node_ack_sets_sha256": (
                    expected.binding[
                        "route_v2_rotation_qualification_node_ack_sets_sha256"
                    ]
                ),
                "route_v2_rotation_qualification_transcript_sha256": (
                    expected.binding[
                        "route_v2_rotation_qualification_transcript_sha256"
                    ]
                ),
                "usage_terminal_receipt_sha256": expected.binding[
                    "usage_terminal_receipt_sha256"
                ],
                "old_host_coverage_sha256": expected.binding[
                    "old_host_coverage_sha256"
                ],
                "kernel_nbd_qualification_bundle_sha256": expected.binding[
                    "kernel_nbd_qualification_bundle_sha256"
                ],
                "vhost_user_qualification_bundle_sha256": expected.binding[
                    "vhost_user_qualification_bundle_sha256"
                ],
            }
        )
        trust = {
            "version": 1,
            "deployment_id": expected.binding["deployment_id"],
            "release_id": expected.binding["release_id"],
            "source_commit_sha": expected.binding["source_commit_sha"],
            "signature_threshold": 1,
            "credentials": [
                {
                    "credential_id": "cutover-a",
                    "public_key_spki": "fixture-public-key",
                    "scope": {
                        "aws_partition": expected.operator["aws_partition"],
                        "account_id": expected.operator["account_id"],
                        "role_arn": expected.operator["role_arn"],
                    },
                }
            ],
        }
        return types.SimpleNamespace(
            cutover_authority=frozen,
            operator_trust=trust,
            plan_sha256=expected.reset_plan_sha256.removeprefix("sha256:"),
            reset_complete_sha256=expected.reset_complete_receipt_sha256,
            reset_complete={
                "reset_id": expected.binding["reset_id"],
                "release_commit": expected.binding["source_commit_sha"],
                "artifact_sha256": expected.binding[
                    "release_manifest_sha256"
                ].removeprefix("sha256:"),
            },
        )

    def verify_complete(self, _path: Path, _digest: str) -> Any:
        self.calls.append("pristine")
        if self.pristine_refuses:
            raise OPEN.RESET.ResetError("fixture pristine state changed")
        expected = authority()
        return types.SimpleNamespace(
            authority=types.SimpleNamespace(
                operator=expected.operator,
                proof_set=FixtureProofSet(),
            ),
            plan_sha256=expected.reset_plan_sha256.removeprefix("sha256:"),
            reset_complete_sha256=expected.reset_complete_receipt_sha256,
        )

    def verify_complete_after_open_started(self, _path: Path, _digest: str) -> Any:
        self.calls.append("forward")
        if self.forward_refuses:
            raise OPEN.RESET.ResetError("fixture post-boundary forward state changed")
        return self._post_completion()

    def verify_complete_for_cleanup(self, _path: Path, _digest: str) -> Any:
        self.calls.append("cleanup")
        if self.cleanup_refuses:
            raise OPEN.RESET.ResetError("fixture cleanup target identity changed")
        return self._post_completion()


class FakeAdmission:
    def __init__(
        self,
        *,
        fail_open_after_effect: bool = False,
        cancel_during_open: bool = False,
        fail_closed: int = 0,
    ) -> None:
        self.calls: list[str] = []
        self.live_closed = True
        self.fail_open_after_effect = fail_open_after_effect
        self.cancel_during_open = cancel_during_open
        self.fail_closed = fail_closed
        planned_closed = {
            "version": 1,
            "revision": 2,
            "mode": "closed",
            "binding": None,
            "last_command_id": None,
            "updated_at_unix_ms": 1_700_000_000_000,
        }
        self.prepared = OPEN.PreparedAdmission(
            {
                "version": 1,
                "command_id": "b" * 32,
                "request_sha256": "sha256:" + "4" * 64,
                "expected_revision": 2,
                "expires_at_unix_ms": OPEN.now_unix_ms() + 180_000,
                "observed_closed_state": planned_closed,
            }
        )
        self.open_evidence = {
            "kind": "cats.production-final-open-admission-applied.v1",
            "version": 1,
            "command_id": "b" * 32,
            "request_sha256": "sha256:" + "4" * 64,
            "pending_sha256": "sha256:" + "5" * 64,
            "command_receipt_sha256": "sha256:" + "6" * 64,
            "resulting_state_sha256": "sha256:" + "7" * 64,
            "resulting_revision": 3,
            "committed_at_unix_ms": 1_700_000_000_000,
        }
        self.closed_evidence = {
            "kind": "cats.production-final-open-admission-closed.v1",
            "version": 1,
            "close_kind": "already_closed",
            "command_id": None,
            "request_sha256": None,
            "command_receipt_sha256": None,
            "resulting_state": planned_closed,
            "resulting_state_sha256": OPEN.ADMISSION.sha256(
                OPEN.ADMISSION.canonical_json(planned_closed)
            ),
            "resulting_revision": planned_closed["revision"],
            "committed_at_unix_ms": planned_closed["updated_at_unix_ms"],
        }

    def prepare(self, _authority: Any) -> Any:
        self.calls.append("prepare")
        return self.prepared

    def validate(self, prepared: Any, _authority: Any) -> None:
        if prepared != self.prepared:
            raise OPEN.FinalOpenError("fake prepared admission drifted")

    def validate_live_closed(
        self,
        prepared: Any,
        authority_value: Any,
        at_unix_ms: int,
    ) -> None:
        self.validate(prepared, authority_value)
        self.calls.append("validate-live-closed")
        if (
            not self.live_closed
            or self.prepared.value["expires_at_unix_ms"] - at_unix_ms
            < OPEN.OPEN_EXECUTION_MIN_REMAINING_MS
        ):
            raise OPEN.FinalOpenError("fake live Closed state drifted")

    def settle_open(
        self,
        prepared: Any,
        authority_value: Any,
        cancellation: Any,
    ) -> dict[str, Any]:
        self.validate(prepared, authority_value)
        self.calls.append("settle-open")
        if self.cancel_during_open:
            self.cancel_during_open = False
            cancellation.handler(signal.SIGTERM, None)
        if self.fail_open_after_effect:
            self.fail_open_after_effect = False
            raise OPEN.FinalOpenError("injected ambiguous Open response loss")
        return self.open_evidence

    def validate_open_evidence(
        self,
        evidence: dict[str, Any],
        prepared: Any,
        authority_value: Any,
    ) -> None:
        self.validate(prepared, authority_value)
        if evidence != self.open_evidence:
            raise OPEN.FinalOpenError("fake Open evidence drifted")

    def settle_closed(self, prepared: Any, authority_value: Any) -> dict[str, Any]:
        self.validate(prepared, authority_value)
        self.calls.append("settle-closed")
        if self.fail_closed:
            self.fail_closed -= 1
            raise OPEN.FinalOpenError("injected ambiguous admission-close response loss")
        return self.closed_evidence

    def validate_closed_evidence(
        self,
        evidence: dict[str, Any],
        prepared: Any,
        authority_value: Any,
    ) -> None:
        self.validate(prepared, authority_value)
        if evidence != self.closed_evidence:
            raise OPEN.FinalOpenError("fake Closed evidence drifted")


class FakeEffects:
    def __init__(
        self,
        *,
        failures: dict[str, int] | None = None,
        fail_node_id: str | None = None,
        cancel_during_public_probe: bool = False,
        refuse_post_boundary_forward: bool = False,
        open_id: str = "final-open-01",
    ) -> None:
        self.calls: list[str] = []
        self.failures = dict(failures or {})
        self.fail_node_id = fail_node_id
        self.cancel_during_public_probe = cancel_during_public_probe
        self.refuse_post_boundary_forward = refuse_post_boundary_forward
        self.value = {
            "kind": OPEN.EFFECTS_KIND,
            "version": 1,
            "open_id": open_id,
            "deployment_id": "deployment-stageb-01",
            "release_id": "release-stageb-01",
            "source_commit_sha": "a" * 40,
            "proof_set_sha256": DIGEST,
            "nodes": [
                {
                    "node_id": "node-a",
                    "schedulable_request_sha256": "sha256:" + "b" * 64,
                    "cordon_request_sha256": "sha256:" + "c" * 64,
                },
                {
                    "node_id": "node-b",
                    "schedulable_request_sha256": "sha256:" + "d" * 64,
                    "cordon_request_sha256": "sha256:" + "e" * 64,
                },
            ],
            "ingress_open_plan_sha256": "sha256:" + "f" * 64,
            "ingress_close_plan_sha256": "sha256:" + "0" * 64,
            "public_probe_target_sha256": "sha256:" + "1" * 64,
            "public_probe_method": "GET",
            "public_probe_path": "/healthz",
            "public_probe_admission_mode": "closed",
        }

    def _terminal(self, action: str, **projection: Any) -> dict[str, Any]:
        self.calls.append(f"settle:{action}")
        remaining = self.failures.get(action, 0)
        if remaining:
            self.failures[action] = remaining - 1
            raise OPEN.FinalOpenError(f"injected {action} failure")
        return {"kind": f"fixture.{action}.v1", "version": 1, **projection}

    @staticmethod
    def _validate(
        evidence: dict[str, Any],
        action: str,
        **projection: Any,
    ) -> None:
        if evidence != {"kind": f"fixture.{action}.v1", "version": 1, **projection}:
            raise OPEN.FinalOpenError(f"fixture {action} evidence drifted")

    def prepare(self, _authority: Any) -> dict[str, Any]:
        self.calls.append("prepare")
        return self.value

    def validate_plan(self, value: dict[str, Any], _authority: Any) -> None:
        if value != self.value:
            raise OPEN.FinalOpenError("fixture effects plan drifted")

    def validate_live_closed_before_start(
        self, value: dict[str, Any], authority_value: Any
    ) -> None:
        self.validate_plan(value, authority_value)
        self.calls.append("validate:live-closed-before-start")

    def validate_post_boundary_forward(
        self, value: dict[str, Any], authority_value: Any
    ) -> None:
        self.validate_plan(value, authority_value)
        self.calls.append("validate:post-boundary-forward")
        if self.refuse_post_boundary_forward:
            raise OPEN.FinalOpenError("fixture forward effect state drifted")

    def validate_cleanup(
        self, value: dict[str, Any], authority_value: Any
    ) -> None:
        self.validate_plan(value, authority_value)
        self.calls.append("validate:cleanup")

    def settle_node_schedulable(
        self, node: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
        if self.fail_node_id == node["node_id"]:
            self.calls.append(f"settle:node-schedulable:{node['node_id']}")
            self.fail_node_id = None
            raise OPEN.FinalOpenError("injected ambiguous Node response loss")
        return self._terminal("node-schedulable", node_id=node["node_id"])

    def validate_node_schedulable(
        self, evidence: dict[str, Any], node: dict[str, Any], _authority: Any
    ) -> None:
        self._validate(evidence, "node-schedulable", node_id=node["node_id"])

    def settle_ingress_open(
        self, _effects: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
        return self._terminal("ingress-open")

    def validate_ingress_open(
        self, evidence: dict[str, Any], _effects: dict[str, Any], _authority: Any
    ) -> None:
        self._validate(evidence, "ingress-open")

    def settle_public_probe(
        self, _effects: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
        evidence = self._terminal("public-probe")
        if self.cancel_during_public_probe:
            self.cancel_during_public_probe = False
            signal.raise_signal(signal.SIGTERM)
        return evidence

    def validate_public_probe(
        self, evidence: dict[str, Any], _effects: dict[str, Any], _authority: Any
    ) -> None:
        self._validate(evidence, "public-probe")

    def settle_ingress_closed(
        self, _effects: dict[str, Any], _authority: Any, may_be_open: bool
    ) -> dict[str, Any]:
        return self._terminal("ingress-closed", may_be_open=may_be_open)

    def validate_ingress_closed(
        self,
        evidence: dict[str, Any],
        _effects: dict[str, Any],
        _authority: Any,
        may_be_open: bool,
    ) -> None:
        self._validate(evidence, "ingress-closed", may_be_open=may_be_open)

    def settle_node_cordoned(
        self, node: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
        return self._terminal(f"node-cordoned:{node['node_id']}", node_id=node["node_id"])

    def validate_node_cordoned(
        self, evidence: dict[str, Any], node: dict[str, Any], _authority: Any
    ) -> None:
        self._validate(
            evidence,
            f"node-cordoned:{node['node_id']}",
            node_id=node["node_id"],
        )

    def settle_cleanup_fleet_closed(
        self, _effects: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
        return self._terminal("fleet-closed", active_guard_count=0, residue_count=0)

    def validate_cleanup_fleet_closed(
        self, evidence: dict[str, Any], _effects: dict[str, Any], _authority: Any
    ) -> None:
        self._validate(
            evidence,
            "fleet-closed",
            active_guard_count=0,
            residue_count=0,
        )


class CrashAfterReceiptLink:
    def __init__(self, stage: str) -> None:
        self.stage = stage
        self.fired = False

    def __call__(self, phase: str, path: Path) -> None:
        if (
            not self.fired
            and phase == "after_link"
            and path.name == f"final-open-01.{self.stage}.json"
        ):
            self.fired = True
            raise RuntimeError(f"fixture crash after {self.stage} receipt link")


def executor(
    root: Path,
    admission: FakeAdmission,
    effects: Any,
    *,
    open_id: str = "final-open-01",
    reset_executor: Any | None = None,
    inject_authority: bool = True,
    receipt_publication_hook: Any | None = None,
    process_lock_acquisition_hook: Any | None = None,
) -> Any:
    root.mkdir(mode=0o700, parents=True)
    root.chmod(0o700)
    receipts = root / "receipts"
    receipts.mkdir(mode=0o700)
    receipts.chmod(0o700)
    return existing_executor(
        root,
        admission,
        effects,
        open_id=open_id,
        reset_executor=reset_executor,
        inject_authority=inject_authority,
        receipt_publication_hook=receipt_publication_hook,
        process_lock_acquisition_hook=process_lock_acquisition_hook,
    )


def existing_executor(
    root: Path,
    admission: FakeAdmission,
    effects: Any,
    *,
    open_id: str = "final-open-01",
    reset_executor: Any | None = None,
    inject_authority: bool = True,
    receipt_publication_hook: Any | None = None,
    process_lock_acquisition_hook: Any | None = None,
) -> Any:
    receipts = root / "receipts"
    optional: dict[str, Any] = {}
    if process_lock_acquisition_hook is not None:
        optional["process_lock_acquisition_hook"] = process_lock_acquisition_hook
    return OPEN.FinalOpenExecutor(
        open_id=open_id,
        reset_executor=reset_executor if reset_executor is not None else object(),
        reset_plan_path=root / "unused-reset-plan.json",
        reset_plan_sha256="3" * 64,
        admission=admission,
        effects=effects,
        receipt_directory=receipts,
        authority_verifier=authority if inject_authority else None,
        receipt_publication_hook=receipt_publication_hook,
        **optional,
    )


def expect_refusal(call: Any, fragment: str) -> None:
    try:
        call()
    except OPEN.FinalOpenError as error:
        if fragment not in str(error):
            raise AssertionError(f"unexpected refusal: {error}") from error
    else:
        raise AssertionError(f"expected refusal containing {fragment!r}")


def append_durable_line(path: Path, value: str) -> None:
    descriptor = os.open(
        path,
        os.O_WRONLY
        | os.O_APPEND
        | os.O_CREAT
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0),
        0o600,
    )
    try:
        payload = (value + "\n").encode("ascii")
        offset = 0
        while offset < len(payload):
            offset += os.write(descriptor, payload[offset:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def durable_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    return path.read_text(encoding="ascii").splitlines()


def wait_for_path(path: Path, timeout_seconds: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if path.exists():
            return
        time.sleep(0.01)
    raise AssertionError(f"timed out waiting for {path.name}")


def wait_for_child(pid: int, timeout_seconds: float = 5.0) -> int:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        waited, status = os.waitpid(pid, os.WNOHANG)
        if waited == pid:
            return status
        time.sleep(0.01)
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    os.waitpid(pid, 0)
    raise AssertionError(f"timed out waiting for child {pid}")


def kill_and_reap(pid: int) -> None:
    try:
        os.kill(pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass


def process_lock_is_persistent_and_rejects_aba(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    subject = executor(root / "persistent", admission, effects)
    plan_path, plan_digest = subject.plan()
    lock_path = subject.process_lock_path
    metadata = lock_path.stat(follow_symlinks=False)
    identity = (metadata.st_dev, metadata.st_ino)
    assert stat.S_ISREG(metadata.st_mode)
    assert metadata.st_uid == os.geteuid()
    assert stat.S_IMODE(metadata.st_mode) == 0o600
    assert metadata.st_nlink == 1
    assert metadata.st_size == 0
    assert lock_path.read_bytes() == b""
    assert lock_path.name == OPEN.OpenProcessLock.FILENAME

    assert subject.plan() == (plan_path, plan_digest)
    second_open_id = "final-open-02"
    second = existing_executor(
        root / "persistent",
        FakeAdmission(),
        FakeEffects(open_id=second_open_id),
        open_id=second_open_id,
    )
    second.plan()
    second_metadata = lock_path.stat(follow_symlinks=False)
    assert (second_metadata.st_dev, second_metadata.st_ino) == identity
    subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=False,
    )
    replay_metadata = lock_path.stat(follow_symlinks=False)
    assert (replay_metadata.st_dev, replay_metadata.st_ino) == identity

    aba = executor(root / "aba", FakeAdmission(), FakeEffects())
    aba.plan()

    def replace_while_locked() -> None:
        with aba._process_lock():
            aba.process_lock_path.unlink()
            descriptor = os.open(
                aba.process_lock_path,
                os.O_CREAT | os.O_EXCL | os.O_RDWR,
                0o600,
            )
            os.close(descriptor)
            aba._assert_process_lock()

    expect_refusal(replace_while_locked, "unlinked, replaced, or changed")


def malformed_process_locks_fail_before_adapter_calls(root: Path) -> None:
    for case in ("bytes", "symlink", "hardlink", "mode"):
        admission = FakeAdmission()
        effects = FakeEffects()
        subject = executor(root / case, admission, effects)
        source = root / case / "lock-source"
        OPEN.RESET.atomic_write_new(source, b"")
        if case == "bytes":
            OPEN.RESET.atomic_write_new(subject.process_lock_path, b"foreign\n")
        elif case == "symlink":
            subject.process_lock_path.symlink_to(source)
        elif case == "hardlink":
            os.link(source, subject.process_lock_path)
        else:
            OPEN.RESET.atomic_write_new(subject.process_lock_path, b"")
            subject.process_lock_path.chmod(0o640)
        expect_refusal(subject.plan, "final-open process lock")
        assert admission.calls == []
        assert effects.calls == []


def production_cli_uses_one_fixed_state_root() -> None:
    parser = argparse.ArgumentParser()
    OPEN.add_open_arguments(parser)
    help_text = parser.format_help()
    assert "--open-id" in help_text
    assert "--open-state-directory" not in help_text
    assert "--open-receipt-directory" not in help_text
    assert OPEN.PRODUCTION_FINAL_OPEN_STATE_ROOT == Path(
        "/var/lib/cats/production-final-open"
    )
    assert OPEN.PRODUCTION_ADMISSION_STATE_DIRECTORY == (
        OPEN.PRODUCTION_FINAL_OPEN_STATE_ROOT / "admission-state"
    )
    assert OPEN.PRODUCTION_OPEN_RECEIPT_DIRECTORY == (
        OPEN.PRODUCTION_FINAL_OPEN_STATE_ROOT / "receipts"
    )

    real_config_from_args = OPEN.RESET.config_from_args
    real_reset_executor = OPEN.RESET.ResetExecutor
    real_command_runner = OPEN.RESET.CommandRunner
    real_admission = OPEN.ProductionAdmissionClient
    real_executor = OPEN.FinalOpenExecutor
    real_state_root_validation = OPEN.validate_production_final_open_state_root
    admission_arguments: dict[str, Any] = {}
    validated = False
    try:
        OPEN.RESET.config_from_args = lambda _args: object()
        OPEN.RESET.CommandRunner = lambda: object()
        OPEN.RESET.ResetExecutor = lambda _config, _runner: object()

        def capture_admission(**kwargs: Any) -> object:
            admission_arguments.update(kwargs)
            return object()

        def validate_fixed_root() -> None:
            nonlocal validated
            validated = True

        OPEN.validate_production_final_open_state_root = validate_fixed_root
        OPEN.ProductionAdmissionClient = capture_admission
        OPEN.FinalOpenExecutor = lambda **kwargs: kwargs
        result = OPEN.executor_from_args(
            types.SimpleNamespace(
                open_id="final-open-01",
                control_origin="https://control.example",
                production_cutover_operator_trust_file=Path("/fixed/trust.json"),
                production_cutover_operator_private_key_file=Path("/secret/key.pem"),
                reset_plan_receipt=Path("/evidence/reset-plan.json"),
                reset_plan_sha256="3" * 64,
            )
        )
    finally:
        OPEN.RESET.config_from_args = real_config_from_args
        OPEN.RESET.ResetExecutor = real_reset_executor
        OPEN.RESET.CommandRunner = real_command_runner
        OPEN.validate_production_final_open_state_root = real_state_root_validation
        OPEN.ProductionAdmissionClient = real_admission
        OPEN.FinalOpenExecutor = real_executor
    assert validated
    assert admission_arguments["state_directory"] == (
        OPEN.PRODUCTION_ADMISSION_STATE_DIRECTORY
    )
    assert result["receipt_directory"] == OPEN.PRODUCTION_OPEN_RECEIPT_DIRECTORY


def process_lock_creation_sigkill_is_replayable(root: Path) -> None:
    phases = (
        "after_create_before_fsync",
        "after_file_fsync_before_directory_fsync",
        "after_directory_fsync_before_flock",
        "after_flock_before_return",
    )
    for phase in phases:
        case_root = root / phase

        def crash_at_phase(observed: str, _path: Path) -> None:
            if observed == phase:
                os.kill(os.getpid(), signal.SIGKILL)

        crashing = executor(
            case_root,
            FakeAdmission(),
            FakeEffects(),
            process_lock_acquisition_hook=crash_at_phase,
        )
        pid = os.fork()
        if pid == 0:
            crashing.plan()
            os._exit(7)
        status = wait_for_child(pid)
        assert os.WIFSIGNALED(status)
        assert os.WTERMSIG(status) == signal.SIGKILL

        lock_path = case_root / "receipts" / OPEN.OpenProcessLock.FILENAME
        metadata = lock_path.stat(follow_symlinks=False)
        assert stat.S_ISREG(metadata.st_mode)
        assert stat.S_IMODE(metadata.st_mode) == 0o600
        assert metadata.st_nlink == 1
        assert metadata.st_size == 0

        replay = existing_executor(case_root, FakeAdmission(), FakeEffects())
        plan_path, _plan_digest = replay.plan()
        assert plan_path.name == "final-open-01.open-plan.json"
        assert {entry.name for entry in replay.receipt_directory.iterdir()} == {
            OPEN.OpenProcessLock.FILENAME,
            "final-open-01.open-plan.json",
            "final-open-01.open-plan.sha256",
        }


def process_lock_serializes_real_processes(root: Path) -> None:
    first_open_id = "final-open-01"
    contender_open_id = "final-open-02"
    event_log = root / "effects.log"
    barrier = root / "first-at-probe"
    first_result = root / "first-result"
    contender_result = root / "contender-result"
    resume_result = root / "resume-result"

    class LoggedAdmission(FakeAdmission):
        def settle_open(
            self,
            prepared: Any,
            authority_value: Any,
            cancellation: Any,
        ) -> dict[str, Any]:
            append_durable_line(event_log, "admission-open")
            return super().settle_open(prepared, authority_value, cancellation)

        def settle_closed(
            self,
            prepared: Any,
            authority_value: Any,
        ) -> dict[str, Any]:
            append_durable_line(event_log, "admission-closed")
            return super().settle_closed(prepared, authority_value)

    class LoggedEffects(FakeEffects):
        def settle_node_schedulable(
            self, node: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            append_durable_line(event_log, f"node:{node['node_id']}")
            return super().settle_node_schedulable(node, authority_value)

        def settle_ingress_open(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            append_durable_line(event_log, "ingress-open")
            return super().settle_ingress_open(effects_value, authority_value)

        def settle_public_probe(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            append_durable_line(event_log, "public-probe")
            return super().settle_public_probe(effects_value, authority_value)

        def settle_ingress_closed(
            self,
            effects_value: dict[str, Any],
            authority_value: Any,
            may_be_open: bool,
        ) -> dict[str, Any]:
            append_durable_line(event_log, "cleanup-ingress")
            return super().settle_ingress_closed(
                effects_value,
                authority_value,
                may_be_open,
            )

        def settle_node_cordoned(
            self, node: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            append_durable_line(event_log, f"cleanup-node:{node['node_id']}")
            return super().settle_node_cordoned(node, authority_value)

        def settle_cleanup_fleet_closed(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            append_durable_line(event_log, "cleanup-fleet")
            return super().settle_cleanup_fleet_closed(
                effects_value,
                authority_value,
            )

    class BarrierEffects(LoggedEffects):
        def settle_public_probe(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            OPEN.RESET.atomic_write_new(barrier, b"ready\n")
            deadline = time.monotonic() + 15.0
            while time.monotonic() < deadline:
                time.sleep(0.01)
            raise RuntimeError("fixture barrier timed out")

    first_planned_admission = FakeAdmission()
    contender_planned_admission = FakeAdmission()

    def matching_logged_admission(planned: FakeAdmission) -> LoggedAdmission:
        value = LoggedAdmission()
        value.prepared = planned.prepared
        return value

    initial = executor(root, first_planned_admission, FakeEffects())
    plan_path, plan_digest = initial.plan()
    contender_plan_owner = existing_executor(
        root,
        contender_planned_admission,
        FakeEffects(open_id=contender_open_id),
        open_id=contender_open_id,
    )
    contender_plan_path, contender_plan_digest = contender_plan_owner.plan()

    first_pid = os.fork()
    if first_pid == 0:
        try:
            first = existing_executor(
                root,
                matching_logged_admission(first_planned_admission),
                BarrierEffects(),
            )
            first.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            )
            append_durable_line(first_result, "unexpected-success")
            os._exit(2)
        except BaseException as error:
            append_durable_line(
                first_result,
                f"{type(error).__name__}:{error}",
            )
            os._exit(3)

    contender_status = -1
    events_before_contender: list[str] = []
    events_after_contender: list[str] = []
    try:
        try:
            wait_for_path(barrier)
        except AssertionError as error:
            raise AssertionError(durable_lines(first_result)) from error
        assert (
            root / "receipts" / "final-open-01.open-started.json"
        ).exists()
        assert (
            root / "receipts" / "final-open-01.public-ingress-open.json"
        ).exists()
        events_before_contender = durable_lines(event_log)
        assert events_before_contender == [
            "node:node-a",
            "node:node-b",
            "ingress-open",
        ]

        contender_pid = os.fork()
        if contender_pid == 0:
            contender = existing_executor(
                root,
                matching_logged_admission(contender_planned_admission),
                LoggedEffects(open_id=contender_open_id),
                open_id=contender_open_id,
            )
            outcomes: list[str] = []
            for label, operation in (
                ("plan", contender.plan),
                (
                    "apply",
                    lambda: contender.apply(
                        contender_plan_path,
                        contender_plan_digest,
                        contender_open_id,
                        execute=True,
                    ),
                ),
            ):
                try:
                    operation()
                except OPEN.FinalOpenError as error:
                    outcomes.append(f"{label}:refused:{error}")
                except BaseException as error:
                    outcomes.append(
                        f"{label}:wrong-error:{type(error).__name__}:{error}"
                    )
                else:
                    outcomes.append(f"{label}:accepted")
            for outcome in outcomes:
                append_durable_line(contender_result, outcome)
            expected_fragment = "another final-open process owns final-open"
            if all(
                outcome.startswith(f"{label}:refused:")
                and expected_fragment in outcome
                for label, outcome in zip(("plan", "apply"), outcomes)
            ):
                os._exit(0)
            os._exit(4)
        contender_status = wait_for_child(contender_pid)
        events_after_contender = durable_lines(event_log)
    finally:
        kill_and_reap(first_pid)

    assert os.WIFEXITED(contender_status)
    assert os.WEXITSTATUS(contender_status) == 0, durable_lines(contender_result)
    assert events_after_contender == events_before_contender
    assert not (
        root / "receipts" / "final-open-01.cleanup-started.json"
    ).exists()
    assert not (
        root / "receipts" / "final-open-01.mutation-admission-open-finalizing.json"
    ).exists()

    post_crash_contender = existing_executor(
        root,
        matching_logged_admission(contender_planned_admission),
        LoggedEffects(open_id=contender_open_id),
        open_id=contender_open_id,
    )
    expect_refusal(
        post_crash_contender.plan,
        "foreign final-open transaction is active",
    )
    expect_refusal(
        lambda: post_crash_contender.apply(
            contender_plan_path,
            contender_plan_digest,
            contender_open_id,
            execute=True,
        ),
        "foreign final-open transaction is active",
    )
    assert durable_lines(event_log) == events_before_contender

    resume_pid = os.fork()
    if resume_pid == 0:
        try:
            resumed = existing_executor(
                root,
                matching_logged_admission(first_planned_admission),
                LoggedEffects(),
            )
            complete, _digest = resumed.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            )
            append_durable_line(resume_result, complete.name)
            os._exit(0)
        except BaseException as error:
            append_durable_line(
                resume_result,
                f"{type(error).__name__}:{error}",
            )
            os._exit(5)
    resume_status = wait_for_child(resume_pid)
    assert os.WIFEXITED(resume_status)
    assert os.WEXITSTATUS(resume_status) == 0, durable_lines(resume_result)
    assert durable_lines(resume_result) == ["final-open-01.open-complete.json"]
    assert durable_lines(event_log) == [
        "node:node-a",
        "node:node-b",
        "ingress-open",
        "public-probe",
        "admission-open",
    ]
    assert not (
        root / "receipts" / "final-open-01.cleanup-started.json"
    ).exists()

    completed_contender = existing_executor(
        root,
        matching_logged_admission(contender_planned_admission),
        LoggedEffects(open_id=contender_open_id),
        open_id=contender_open_id,
    )
    expect_refusal(
        completed_contender.plan,
        "foreign final-open transaction already completed",
    )
    expect_refusal(
        lambda: completed_contender.apply(
            contender_plan_path,
            contender_plan_digest,
            contender_open_id,
            execute=True,
        ),
        "foreign final-open transaction already completed",
    )
    assert durable_lines(event_log) == [
        "node:node-a",
        "node:node-b",
        "ingress-open",
        "public-probe",
        "admission-open",
    ]


def terminal_aborted_open_allows_a_new_open_id(root: Path) -> None:
    real_now_unix_ms = OPEN.now_unix_ms
    base = 1_800_000_000_000
    for case, preplanned_at, aborted_at, fresh_at in (
        ("clock-rollback", base + 400, base + 300, base + 200),
        ("same-millisecond", base + 100, base + 100, base + 100),
    ):
        case_root = root / case
        clock = [base]
        OPEN.now_unix_ms = lambda: clock[0]
        try:
            first = executor(
                case_root,
                FakeAdmission(),
                FakeEffects(failures={"public-probe": 1}),
            )
            first_plan, first_digest = first.plan()

            preplanned_open_id = "final-open-02"
            clock[0] = preplanned_at
            preplanned_admission = FakeAdmission()
            preplanned_effects = FakeEffects(open_id=preplanned_open_id)
            preplanned = existing_executor(
                case_root,
                preplanned_admission,
                preplanned_effects,
                open_id=preplanned_open_id,
            )
            preplanned_plan, preplanned_digest = preplanned.plan()
            preplanned_item = OPEN.RESET.read_stage_receipt(
                first.receipt_directory,
                preplanned_open_id,
                "open-plan",
            )
            assert preplanned_item is not None
            assert preplanned_item[1]["prior_terminal_aborts"] == []
            preplanned_admission_calls = list(preplanned_admission.calls)
            preplanned_calls = list(preplanned_effects.calls)

            clock[0] = aborted_at
            expect_refusal(
                lambda: first.apply(
                    first_plan,
                    first_digest,
                    "final-open-01",
                    execute=True,
                ),
                "closed cleanup reached its terminal receipt",
            )
            aborted_item = OPEN.RESET.read_stage_receipt(
                first.receipt_directory,
                "final-open-01",
                "open-aborted",
            )
            assert aborted_item is not None
            aborted_value = aborted_item[1]
            aborted_digest = "sha256:" + aborted_item[2]
            assert preplanned_item[1]["created_at_unix_ms"] >= aborted_at

            expect_refusal(
                preplanned.plan,
                "existing plan does not bind the current foreign terminal aborts",
            )
            expect_refusal(
                lambda: preplanned.apply(
                    preplanned_plan,
                    preplanned_digest,
                    preplanned_open_id,
                    execute=True,
                ),
                "plan does not bind the current foreign terminal aborts",
            )
            assert preplanned_admission.calls == preplanned_admission_calls
            assert preplanned_effects.calls == preplanned_calls

            clock[0] = fresh_at
            next_open_id = "final-open-03"
            second = existing_executor(
                case_root,
                FakeAdmission(),
                FakeEffects(open_id=next_open_id),
                open_id=next_open_id,
            )
            second_plan, second_digest = second.plan()
            second_item = OPEN.RESET.read_stage_receipt(
                first.receipt_directory,
                next_open_id,
                "open-plan",
            )
            assert second_item is not None
            assert second_item[1]["created_at_unix_ms"] <= aborted_value[
                "created_at_unix_ms"
            ]
            assert second_item[1]["prior_terminal_aborts"] == [
                {
                    "open_id": "final-open-01",
                    "open_aborted_sha256": aborted_digest,
                }
            ]
            complete, _complete_digest = second.apply(
                second_plan,
                second_digest,
                next_open_id,
                execute=True,
            )
            assert complete.name == "final-open-03.open-complete.json"
        finally:
            OPEN.now_unix_ms = real_now_unix_ms


def disappearing_foreign_abort_invalidates_plan(root: Path) -> None:
    first = executor(
        root,
        FakeAdmission(),
        FakeEffects(failures={"public-probe": 1}),
    )
    first_plan, first_digest = first.plan()
    expect_refusal(
        lambda: first.apply(
            first_plan,
            first_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup reached its terminal receipt",
    )

    next_open_id = "final-open-02"
    next_admission = FakeAdmission()
    next_effects = FakeEffects(open_id=next_open_id)
    next_open = existing_executor(
        root,
        next_admission,
        next_effects,
        open_id=next_open_id,
    )
    next_plan, next_digest = next_open.plan()
    next_item = OPEN.RESET.read_stage_receipt(
        first.receipt_directory,
        next_open_id,
        "open-plan",
    )
    assert next_item is not None
    assert len(next_item[1]["prior_terminal_aborts"]) == 1
    admission_calls = list(next_admission.calls)
    effect_calls = list(next_effects.calls)

    for path in first.receipt_directory.iterdir():
        if path.name.startswith("final-open-01."):
            path.unlink()
    expect_refusal(
        lambda: next_open.apply(
            next_plan,
            next_digest,
            next_open_id,
            execute=True,
        ),
        "plan does not bind the current foreign terminal aborts",
    )
    assert next_admission.calls == admission_calls
    assert next_effects.calls == effect_calls
    assert not (
        first.receipt_directory / f"{next_open_id}.open-started.json"
    ).exists()


def foreign_aborted_cleanup_chain_must_be_complete(root: Path) -> None:
    for case, expected in (
        ("missing-ingress", "omitted Ingress cleanup"),
        ("missing-node", "cleanup Node set drifted"),
        ("node-chain", "Node cleanup chain drifted"),
    ):
        case_root = root / case
        first = executor(
            case_root,
            FakeAdmission(),
            FakeEffects(failures={"public-probe": 1}),
        )
        first_plan, first_digest = first.plan()
        expect_refusal(
            lambda: first.apply(
                first_plan,
                first_digest,
                "final-open-01",
                execute=True,
            ),
            "closed cleanup reached its terminal receipt",
        )
        receipts = first.receipt_directory

        def remove_stage(stage: str) -> None:
            (receipts / f"final-open-01.{stage}.json").unlink()
            (receipts / f"final-open-01.{stage}.sha256").unlink()

        if case == "missing-ingress":
            remove_stage("cleanup-public-ingress-closed")
        elif case == "missing-node":
            remove_stage("cleanup-node-node-b-cordoned")
        else:
            stage = "cleanup-node-node-b-cordoned"
            loaded = OPEN.RESET.read_stage_receipt(
                receipts,
                "final-open-01",
                stage,
            )
            assert loaded is not None
            _path, value, _digest = loaded
            value["previous_receipt_sha256"] = "sha256:" + "9" * 64
            remove_stage(stage)
            OPEN.RESET.write_receipt(
                receipts,
                "final-open-01",
                stage,
                value,
            )

        next_open_id = "final-open-02"
        next_admission = FakeAdmission()
        next_effects = FakeEffects(open_id=next_open_id)
        next_open = existing_executor(
            case_root,
            next_admission,
            next_effects,
            open_id=next_open_id,
        )
        expect_refusal(next_open.plan, expected)
        assert next_admission.calls == []
        assert next_effects.calls == []


def successful_replay(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    replay_path, replay_digest = subject.plan()
    assert (plan_path, plan_digest) == (replay_path, replay_digest)
    complete_path, complete_digest = subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    assert complete_path.name == "final-open-01.open-complete.json"
    assert (complete_path, complete_digest) == subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    assert admission.calls.count("settle-open") == 1
    assert "settle:public-probe" in effects.calls


def admission_open_is_the_final_external_effect(root: Path) -> None:
    trace: list[str] = []

    class TracedAdmission(FakeAdmission):
        def settle_open(
            self,
            prepared: Any,
            authority_value: Any,
            cancellation: Any,
        ) -> dict[str, Any]:
            trace.append("admission-open")
            return super().settle_open(prepared, authority_value, cancellation)

    class TracedEffects(FakeEffects):
        def settle_node_schedulable(
            self, node: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            trace.append(f"node:{node['node_id']}")
            return super().settle_node_schedulable(node, authority_value)

        def settle_ingress_open(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            trace.append("ingress-open")
            return super().settle_ingress_open(effects_value, authority_value)

        def settle_public_probe(
            self, effects_value: dict[str, Any], authority_value: Any
        ) -> dict[str, Any]:
            trace.append("public-probe")
            return super().settle_public_probe(effects_value, authority_value)

    admission = TracedAdmission()
    effects = TracedEffects()
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    assert trace == [
        "node:node-a",
        "node:node-b",
        "ingress-open",
        "public-probe",
        "admission-open",
    ]


def unavailable_is_mutation_free(root: Path) -> None:
    admission = FakeAdmission()
    subject = executor(root, admission, OPEN.UNAVAILABLE_EFFECTS_ADAPTER)
    expect_refusal(subject.plan, "not implementation-accepted")
    assert admission.calls == []


def public_probe_descriptor_is_exact() -> None:
    planned = FakeEffects().value
    for field, foreign in (
        ("public_probe_method", "POST"),
        ("public_probe_path", "/v1/workspaces"),
        ("public_probe_admission_mode", "open"),
    ):
        drifted = dict(planned)
        drifted[field] = foreign
        expect_refusal(
            lambda value=drifted: OPEN.validate_effects(
                value,
                authority(),
                "final-open-01",
            ),
            "effects plan lineage drifted",
        )


def cancellation_before_start_is_mutation_free(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    real_signal = OPEN.signal.signal
    injected = False

    def inject(signum: int, handler: Any) -> Any:
        nonlocal injected
        prior = real_signal(signum, handler)
        if not injected and signum == signal.SIGINT and callable(handler):
            injected = True
            handler(signum, None)
        return prior

    OPEN.signal.signal = inject
    try:
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "cancelled before open-started",
        )
    finally:
        OPEN.signal.signal = real_signal
    assert admission.calls.count("settle-open") == 0
    assert not (root / "receipts" / "final-open-01.open-started.json").exists()

    class CancelDuringInitialClosedDiscovery(FakeAdmission):
        def validate_live_closed(
            self,
            prepared: Any,
            authority_value: Any,
            at_unix_ms: int,
        ) -> None:
            super().validate_live_closed(prepared, authority_value, at_unix_ms)
            signal.raise_signal(signal.SIGTERM)

    admission = CancelDuringInitialClosedDiscovery()
    subject = executor(root / "during-live-discovery", admission, FakeEffects())
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "cancelled before open-started",
    )
    assert admission.calls.count("settle-open") == 0
    assert not (
        subject.receipt_directory / "final-open-01.open-started.json"
    ).exists()


def cancellation_boundaries_keep_admission_closed_or_finish_open(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects(cancel_during_public_probe=True)
    subject = executor(root / "before-finalization", admission, effects)
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup reached its terminal receipt",
    )
    assert admission.calls.count("settle-open") == 0
    assert admission.calls.count("settle-closed") == 1
    assert not (
        subject.receipt_directory
        / "final-open-01.mutation-admission-open-finalizing.json"
    ).exists()

    class CancelDuringFinalClosedDiscovery(FakeAdmission):
        def __init__(self) -> None:
            super().__init__()
            self.live_validations = 0

        def validate_live_closed(
            self,
            prepared: Any,
            authority_value: Any,
            at_unix_ms: int,
        ) -> None:
            super().validate_live_closed(prepared, authority_value, at_unix_ms)
            self.live_validations += 1
            if self.live_validations == 2:
                signal.raise_signal(signal.SIGTERM)

    admission = CancelDuringFinalClosedDiscovery()
    subject = executor(root / "during-final-closed-discovery", admission, FakeEffects())
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup reached its terminal receipt",
    )
    assert admission.calls.count("settle-open") == 0
    assert not (
        subject.receipt_directory
        / "final-open-01.mutation-admission-open-finalizing.json"
    ).exists()

    admission = FakeAdmission(cancel_during_open=True)
    effects = FakeEffects()
    subject = executor(root / "during-final-open", admission, effects)
    plan_path, plan_digest = subject.plan()
    complete_path, _digest = subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    assert complete_path.name == "final-open-01.open-complete.json"
    assert admission.calls.count("settle-open") == 1
    assert admission.calls.count("settle-closed") == 0
    assert not (
        subject.receipt_directory / "final-open-01.cleanup-started.json"
    ).exists()

    outer = OPEN.Cancellation()
    nested = OPEN.ADMISSION.Cancellation(outer)
    nested.handler(signal.SIGINT, None)
    assert nested.requested and outer.requested


def cancellation_after_send_keeps_exact_admission_settlement(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True)
    pending_path = root / "exact-open.pending.v1.json"
    trust_path = root / "unused-trust.json"
    pending = {
        "origin": "https://control.example.invalid",
        "target": "/v1/production-mutation-admission",
        "discovery_target": "/v1/production-mutation-admission/commands/exact",
    }
    command = {
        "command_id": "b" * 32,
        "expires_at_unix_ms": OPEN.now_unix_ms() + 60_000,
    }
    receipt = {"outcome": {"kind": "applied"}}
    calls: list[str] = []

    real_load = OPEN.ADMISSION.load_pending
    real_post = OPEN.ADMISSION.post_exact
    real_validate_json = OPEN.ADMISSION.validate_json_response
    real_validate_receipt = OPEN.ADMISSION.validate_receipt
    real_sleep = OPEN.ADMISSION.time.sleep

    def load_pending(_pending: Path, _trust: Path) -> tuple[Any, bytes, Any]:
        return pending, b"exact-request", command

    def post_exact(
        _origin: str,
        target: str,
        _pending: dict[str, Any],
        _body: bytes,
    ) -> Any:
        calls.append(target)
        if len(calls) == 1:
            signal.raise_signal(signal.SIGTERM)
            raise OPEN.ADMISSION.AdmissionError("injected response loss after send")
        if target == pending["discovery_target"]:
            return OPEN.ADMISSION.HttpResult(404, [], b"{}")
        return OPEN.ADMISSION.HttpResult(200, [], b"fixture-receipt")

    OPEN.ADMISSION.load_pending = load_pending
    OPEN.ADMISSION.post_exact = post_exact
    OPEN.ADMISSION.validate_json_response = lambda _result: None
    OPEN.ADMISSION.validate_receipt = lambda *_args: receipt
    OPEN.ADMISSION.time.sleep = lambda _seconds: None
    try:
        settled_path, _digest = OPEN.ADMISSION.settle(
            types.SimpleNamespace(
                pending=pending_path,
                trust_file=trust_path,
                resolution_timeout_seconds=2,
            )
        )
    finally:
        OPEN.ADMISSION.load_pending = real_load
        OPEN.ADMISSION.post_exact = real_post
        OPEN.ADMISSION.validate_json_response = real_validate_json
        OPEN.ADMISSION.validate_receipt = real_validate_receipt
        OPEN.ADMISSION.time.sleep = real_sleep
    assert settled_path.name == f"{command['command_id']}.receipt.v1.json"
    assert calls == [
        pending["target"],
        pending["discovery_target"],
        pending["target"],
    ]


def foreign_same_binding_command_is_not_cleanup_authority(root: Path) -> None:
    root.mkdir(mode=0o700, parents=True)
    planned_closed = {
        "version": 1,
        "revision": 1,
        "mode": "closed",
        "binding": None,
        "last_command_id": None,
        "updated_at_unix_ms": 1_700_000_000_000,
    }
    prepared = OPEN.PreparedAdmission(
        {"observed_closed_state": planned_closed, "open_pending": {}}
    )

    class Harness(OPEN.ProductionAdmissionClient):
        def __init__(self) -> None:
            self.open_id = "final-open-01"
            self.state_directory = root
            self.trust_file = root / "unused-trust.json"

        def validate(self, _prepared: Any, _authority: Any) -> None:
            pass

        def _read_ref(self, _value: Any, _label: str) -> Path:
            return root / "exact-open.pending.v1.json"

    subject = Harness()
    real_load = OPEN.ADMISSION.load_pending
    real_discover = OPEN.ADMISSION.discover_state
    discovered = planned_closed

    def load_pending(_path: Path, _trust: Path) -> tuple[dict[str, Any], bytes, dict[str, Any]]:
        return {}, b"exact-open", {"command_id": "b" * 32}

    def discover_state(_args: Any) -> dict[str, Any]:
        return discovered

    OPEN.ADMISSION.load_pending = load_pending
    OPEN.ADMISSION.discover_state = discover_state
    try:
        positive = subject.settle_closed(prepared, authority())
        assert positive["close_kind"] == "already_closed"
        subject.validate_closed_evidence(positive, prepared, authority())

        discovered = {
            "version": 1,
            "revision": 2,
            "mode": "open",
            "binding": {"kind": "open", "binding": authority().binding},
            "last_command_id": "f" * 32,
            "updated_at_unix_ms": 1_700_000_000_100,
        }
        expect_refusal(
            lambda: subject.settle_closed(prepared, authority()),
            "foreign Open command for the same binding",
        )
        expect_refusal(
            lambda: subject.validate_closed_evidence(
                positive,
                prepared,
                authority(),
            ),
            "foreign Open command for the same binding",
        )

        discovered = {
            "version": 1,
            "revision": 2,
            "mode": "open",
            "binding": {"kind": "open", "binding": authority().binding},
            "last_command_id": "b" * 32,
            "updated_at_unix_ms": 1_700_000_000_100,
        }
        expect_refusal(
            lambda: subject.settle_closed(prepared, authority()),
            "foreign Open command for the same binding",
        )

        discovered = {
            "version": 1,
            "revision": 3,
            "mode": "closed",
            "binding": {"kind": "open", "binding": authority().binding},
            "last_command_id": "e" * 32,
            "updated_at_unix_ms": 1_700_000_000_200,
        }
        expect_refusal(
            lambda: subject.settle_closed(prepared, authority()),
            "foreign command for the same Open binding",
        )
    finally:
        OPEN.ADMISSION.load_pending = real_load
        OPEN.ADMISSION.discover_state = real_discover


def cleanup_resumes_without_reopening(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects(
        failures={"ingress-open": 1, "node-cordoned:node-b": 1}
    )
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "cleanup is not terminal",
    )
    assert (root / "receipts" / "final-open-01.cleanup-started.json").exists()
    assert not (root / "receipts" / "final-open-01.open-aborted.json").exists()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "prior final-open attempt is now terminally closed",
    )
    assert (root / "receipts" / "final-open-01.open-aborted.json").exists()
    assert admission.calls.count("settle-open") == 0
    assert admission.calls.count("settle-closed") == 1
    settled_before = [call for call in effects.calls if call.startswith("settle:")]
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "terminally aborted",
    )
    assert [call for call in effects.calls if call.startswith("settle:")] == settled_before


def stale_plan_and_revision_drift_are_pre_marker(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    plan = OPEN.read_canonical(
        plan_path,
        "fixture final-open plan",
        OPEN.MAX_OPEN_PLAN_BYTES,
    )[0]
    real_now = OPEN.now_unix_ms
    OPEN.now_unix_ms = lambda: plan["execution_deadline_unix_ms"]
    try:
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "expired before open-started",
        )
    finally:
        OPEN.now_unix_ms = real_now
    assert admission.calls.count("settle-open") == 0
    assert not (root / "receipts" / "final-open-01.open-started.json").exists()

    admission.live_closed = False
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "fake live Closed state drifted",
    )
    assert admission.calls.count("settle-open") == 0
    assert not (root / "receipts" / "final-open-01.open-started.json").exists()


def expired_started_attempt_closes_without_open(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    subject = executor(root, admission, effects)
    plan_path, plan_digest = subject.plan()
    plan = OPEN.read_canonical(
        plan_path,
        "fixture final-open plan",
        OPEN.MAX_OPEN_PLAN_BYTES,
    )[0]
    with subject._process_lock():
        subject._publish_stage(
            "open-started",
            {
                "status": "closed_preparation_started",
                "reset_complete_receipt_sha256": (
                    authority().reset_complete_receipt_sha256
                ),
                "proof_set_sha256": authority().binding["proof_set_sha256"],
            },
            plan_sha256="sha256:" + plan_digest,
            authority_sha256=plan["authority_sha256"],
            previous_sha256=None,
        )
    real_now = OPEN.now_unix_ms
    OPEN.now_unix_ms = lambda: plan["execution_deadline_unix_ms"]
    try:
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "closed cleanup reached its terminal receipt",
        )
    finally:
        OPEN.now_unix_ms = real_now
    assert admission.calls.count("settle-open") == 0
    assert admission.calls.count("settle-closed") == 1
    assert (root / "receipts" / "final-open-01.open-aborted.json").exists()


def publish_through_ingress(
    subject: Any,
    plan_digest: str,
    admission: FakeAdmission,
    effects: FakeEffects,
) -> None:
    plan = OPEN.read_canonical(
        subject.receipt_directory / "final-open-01.open-plan.json",
        "fixture final-open plan",
        OPEN.MAX_OPEN_PLAN_BYTES,
    )[0]
    authority_value = authority()
    previous: str | None = None
    stages = [
        (
            "open-started",
            {
                "status": "closed_preparation_started",
                "reset_complete_receipt_sha256": (
                    authority_value.reset_complete_receipt_sha256
                ),
                "proof_set_sha256": authority_value.binding["proof_set_sha256"],
            },
        ),
        (
            "node-node-a-schedulable",
            {"kind": "fixture.node-schedulable.v1", "version": 1, "node_id": "node-a"},
        ),
        (
            "node-node-b-schedulable",
            {"kind": "fixture.node-schedulable.v1", "version": 1, "node_id": "node-b"},
        ),
        ("nodes-schedulable", {"node_ids": ["node-a", "node-b"], "count": 2}),
        ("public-ingress-open", {"kind": "fixture.ingress-open.v1", "version": 1}),
    ]
    with subject._process_lock():
        for stage, evidence in stages:
            _path, _value, previous = subject._publish_stage(
                stage,
                evidence,
                plan_sha256="sha256:" + plan_digest,
                authority_sha256=plan["authority_sha256"],
                previous_sha256=previous,
            )


def post_boundary_reset_verifier_selection(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects(failures={"public-probe": 1})
    reset = ResetAuthoritySpy()
    subject = executor(
        root / "ingress-crash",
        admission,
        effects,
        reset_executor=reset,
        inject_authority=False,
    )
    plan_path, plan_digest = subject.plan()
    publish_through_ingress(subject, plan_digest, admission, effects)
    reset.calls.clear()
    reset.pristine_refuses = True
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup reached its terminal receipt",
    )
    assert reset.calls == ["forward"]
    assert (subject.receipt_directory / "final-open-01.open-aborted.json").exists()

    admission = FakeAdmission()
    effects = FakeEffects()
    reset = ResetAuthoritySpy()
    subject = executor(
        root / "forward-drift",
        admission,
        effects,
        reset_executor=reset,
        inject_authority=False,
    )
    plan_path, plan_digest = subject.plan()
    plan = OPEN.read_canonical(
        plan_path,
        "fixture final-open plan",
        OPEN.MAX_OPEN_PLAN_BYTES,
    )[0]
    with subject._process_lock():
        subject._publish_stage(
            "open-started",
            {
                "status": "closed_preparation_started",
                "reset_complete_receipt_sha256": (
                    authority().reset_complete_receipt_sha256
                ),
                "proof_set_sha256": authority().binding["proof_set_sha256"],
            },
            plan_sha256="sha256:" + plan_digest,
            authority_sha256=plan["authority_sha256"],
            previous_sha256=None,
        )
    reset.calls.clear()
    reset.pristine_refuses = True
    reset.forward_refuses = True
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup is terminal",
    )
    assert reset.calls == ["forward", "cleanup"]
    assert (subject.receipt_directory / "final-open-01.open-aborted.json").exists()

    admission = FakeAdmission()
    effects = FakeEffects(refuse_post_boundary_forward=True)
    reset = ResetAuthoritySpy()
    subject = executor(
        root / "forward-effect-drift",
        admission,
        effects,
        reset_executor=reset,
        inject_authority=False,
    )
    plan_path, plan_digest = subject.plan()
    publish_through_ingress(subject, plan_digest, admission, effects)
    reset.calls.clear()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "closed cleanup is terminal",
    )
    assert reset.calls == ["forward", "cleanup"]
    assert (subject.receipt_directory / "final-open-01.open-aborted.json").exists()


def complete_replay_uses_only_immutable_journal(root: Path) -> None:
    admission = FakeAdmission()
    effects = FakeEffects()
    reset = ResetAuthoritySpy()
    subject = executor(
        root,
        admission,
        effects,
        reset_executor=reset,
        inject_authority=False,
    )
    plan_path, plan_digest = subject.plan()
    complete = subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    reset.calls.clear()
    reset.pristine_refuses = True
    reset.forward_refuses = True
    reset.cleanup_refuses = True
    reset.session_refreshed = True
    assert subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    ) == complete
    assert reset.calls == []


def receipt_loss_cleanup_is_conservative(root: Path) -> None:
    cases = [
        (
            "node-a",
            FakeAdmission(),
            FakeEffects(failures={"node-schedulable": 1}),
            {
                "admission_may_be_open": False,
                "ingress_may_be_open": False,
                "possibly_schedulable_node_ids": ["node-a"],
            },
        ),
        (
            "node-b",
            FakeAdmission(),
            FakeEffects(fail_node_id="node-b"),
            {
                "admission_may_be_open": False,
                "ingress_may_be_open": False,
                "possibly_schedulable_node_ids": ["node-a", "node-b"],
            },
        ),
        (
            "ingress",
            FakeAdmission(),
            FakeEffects(failures={"ingress-open": 1}),
            {
                "admission_may_be_open": False,
                "ingress_may_be_open": True,
                "possibly_schedulable_node_ids": ["node-a", "node-b"],
            },
        ),
        (
            "public-probe",
            FakeAdmission(),
            FakeEffects(failures={"public-probe": 1}),
            {
                "admission_may_be_open": False,
                "ingress_may_be_open": True,
                "possibly_schedulable_node_ids": ["node-a", "node-b"],
            },
        ),
    ]
    for label, admission, effects, expected in cases:
        case_root = root / label
        subject = executor(case_root, admission, effects)
        plan_path, plan_digest = subject.plan()
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "closed cleanup reached its terminal receipt",
        )
        cleanup = OPEN.read_canonical(
            subject.receipt_directory / "final-open-01.cleanup-started.json",
            "fixture cleanup-started",
            OPEN.MAX_OPEN_PLAN_BYTES,
        )[0]["evidence"]
        assert cleanup == {"failed": "final_open_failed_or_cancelled", **expected}

    admission = FakeAdmission(fail_open_after_effect=True)
    effects = FakeEffects()
    subject = executor(root / "open", admission, effects)
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "Open finalization is incomplete",
    )
    assert not (
        subject.receipt_directory / "final-open-01.cleanup-started.json"
    ).exists()
    assert (
        subject.receipt_directory
        / "final-open-01.mutation-admission-open-finalizing.json"
    ).exists()
    complete_path, _digest = subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )
    assert complete_path.name == "final-open-01.open-complete.json"
    assert admission.calls.count("settle-closed") == 0


def receipt_publication_crash_matrix(root: Path) -> None:
    cleanup_stages = [
        "node-node-a-schedulable",
        "node-node-b-schedulable",
        "public-ingress-open",
        "public-probe-terminal",
    ]
    for stage in cleanup_stages:
        hook = CrashAfterReceiptLink(stage)
        admission = FakeAdmission()
        effects = FakeEffects()
        subject = executor(
            root / stage,
            admission,
            effects,
            receipt_publication_hook=hook,
        )
        plan_path, plan_digest = subject.plan()
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "closed cleanup reached its terminal receipt",
        )
        assert hook.fired
        assert admission.calls.count("settle-open") == 0
        assert admission.calls.count("settle-closed") == 1
        assert (
            subject.receipt_directory / "final-open-01.open-aborted.json"
        ).exists()

    forward_stages = [
        "mutation-admission-open-finalizing",
        "mutation-admission-open",
        "open-complete",
    ]
    for stage in forward_stages:
        hook = CrashAfterReceiptLink(stage)
        admission = FakeAdmission()
        effects = FakeEffects()
        subject = executor(
            root / stage,
            admission,
            effects,
            receipt_publication_hook=hook,
        )
        plan_path, plan_digest = subject.plan()
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "Open finalization is incomplete",
        )
        assert hook.fired
        assert not (
            subject.receipt_directory / "final-open-01.cleanup-started.json"
        ).exists()
        complete_path, _digest = subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        )
        assert complete_path.name == "final-open-01.open-complete.json"
        assert admission.calls.count("settle-closed") == 0

    hook = CrashAfterReceiptLink("open-started")
    admission = FakeAdmission()
    subject = executor(
        root / "open-started",
        admission,
        FakeEffects(),
        receipt_publication_hook=hook,
    )
    plan_path, plan_digest = subject.plan()
    expect_refusal(
        lambda: subject.apply(
            plan_path,
            plan_digest,
            "final-open-01",
            execute=True,
        ),
        "final Open failed closed",
    )
    assert hook.fired
    assert not (
        subject.receipt_directory / "final-open-01.cleanup-started.json"
    ).exists()
    assert subject.apply(
        plan_path,
        plan_digest,
        "final-open-01",
        execute=True,
    )[0].name == "final-open-01.open-complete.json"


def cleanup_receipt_publication_crash_matrix(root: Path) -> None:
    stages = [
        "cleanup-started",
        "cleanup-public-ingress-closed",
        "cleanup-node-node-b-cordoned",
        "cleanup-node-node-a-cordoned",
        "cleanup-mutation-admission-closed",
        "cleanup-fleet-closed",
        "open-aborted",
    ]
    for stage in stages:
        hook = CrashAfterReceiptLink(stage)
        admission = FakeAdmission()
        effects = FakeEffects(failures={"public-probe": 1})
        subject = executor(
            root / stage,
            admission,
            effects,
            receipt_publication_hook=hook,
        )
        plan_path, plan_digest = subject.plan()
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            "cleanup is not terminal",
        )
        assert hook.fired
        assert admission.calls.count("settle-open") == 0
        if stage == "open-aborted":
            expected = "terminally aborted"
        else:
            expected = "prior final-open attempt is now terminally closed"
        expect_refusal(
            lambda: subject.apply(
                plan_path,
                plan_digest,
                "final-open-01",
                execute=True,
            ),
            expected,
        )
        assert (
            subject.receipt_directory / "final-open-01.open-aborted.json"
        ).exists()
        assert admission.calls.count("settle-open") == 0


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cats-final-open-fixture-") as temporary:
        root = Path(temporary)
        production_cli_uses_one_fixed_state_root()
        process_lock_serializes_real_processes(root / "process-lock-concurrency")
        process_lock_creation_sigkill_is_replayable(root / "process-lock-sigkill")
        process_lock_is_persistent_and_rejects_aba(root / "process-lock-identity")
        malformed_process_locks_fail_before_adapter_calls(root / "process-lock-invalid")
        terminal_aborted_open_allows_a_new_open_id(root / "aborted-next-open")
        disappearing_foreign_abort_invalidates_plan(
            root / "aborted-disappeared"
        )
        foreign_aborted_cleanup_chain_must_be_complete(
            root / "aborted-cleanup-chain"
        )
        unavailable_is_mutation_free(root / "unavailable")
        public_probe_descriptor_is_exact()
        successful_replay(root / "success")
        admission_open_is_the_final_external_effect(root / "open-last")
        cancellation_before_start_is_mutation_free(root / "cancel")
        cancellation_boundaries_keep_admission_closed_or_finish_open(
            root / "cancel-boundaries"
        )
        cancellation_after_send_keeps_exact_admission_settlement(
            root / "cancel-after-send"
        )
        foreign_same_binding_command_is_not_cleanup_authority(
            root / "foreign-open"
        )
        cleanup_resumes_without_reopening(root / "cleanup")
        stale_plan_and_revision_drift_are_pre_marker(root / "stale")
        expired_started_attempt_closes_without_open(root / "expired-started")
        post_boundary_reset_verifier_selection(root / "post-boundary")
        complete_replay_uses_only_immutable_journal(root / "complete-replay")
        receipt_loss_cleanup_is_conservative(root / "receipt-loss")
        receipt_publication_crash_matrix(root / "receipt-publication-crash")
        cleanup_receipt_publication_crash_matrix(root / "cleanup-publication-crash")
    print("production final-open fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
