#!/usr/bin/env python3
"""Focused offline contract fixture for the E13 final-open journal."""

from __future__ import annotations

import importlib.util
import signal
import sys
import tempfile
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


class FakeAdmission:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.prepared = OPEN.PreparedAdmission(
            {
                "version": 1,
                "request_sha256": "sha256:" + "4" * 64,
                "expected_revision": 2,
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
            "close_kind": "emergency_close",
            "command_id": "c" * 32,
            "request_sha256": "sha256:" + "8" * 64,
            "command_receipt_sha256": "sha256:" + "9" * 64,
            "resulting_state_sha256": "sha256:" + "a" * 64,
            "resulting_revision": 4,
            "committed_at_unix_ms": 1_700_000_000_100,
        }

    def prepare(self, _authority: Any) -> Any:
        self.calls.append("prepare")
        return self.prepared

    def validate(self, prepared: Any, _authority: Any) -> None:
        if prepared != self.prepared:
            raise OPEN.FinalOpenError("fake prepared admission drifted")

    def settle_open(self, prepared: Any, authority_value: Any) -> dict[str, Any]:
        self.validate(prepared, authority_value)
        self.calls.append("settle-open")
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
    def __init__(self, *, failures: dict[str, int] | None = None) -> None:
        self.calls: list[str] = []
        self.failures = dict(failures or {})
        self.value = {
            "kind": OPEN.EFFECTS_KIND,
            "version": 1,
            "open_id": "final-open-01",
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

    def validate(self, value: dict[str, Any], _authority: Any) -> None:
        if value != self.value:
            raise OPEN.FinalOpenError("fixture effects plan drifted")

    def settle_node_schedulable(
        self, node: dict[str, Any], _authority: Any
    ) -> dict[str, Any]:
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
        return self._terminal("public-probe")

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


def executor(
    root: Path,
    admission: FakeAdmission,
    effects: Any,
) -> Any:
    root.mkdir(mode=0o700)
    root.chmod(0o700)
    receipts = root / "receipts"
    receipts.mkdir(mode=0o700)
    receipts.chmod(0o700)
    return OPEN.FinalOpenExecutor(
        open_id="final-open-01",
        reset_executor=object(),
        reset_plan_path=root / "unused-reset-plan.json",
        reset_plan_sha256="3" * 64,
        admission=admission,
        effects=effects,
        receipt_directory=receipts,
        authority_verifier=authority,
    )


def expect_refusal(call: Any, fragment: str) -> None:
    try:
        call()
    except OPEN.FinalOpenError as error:
        if fragment not in str(error):
            raise AssertionError(f"unexpected refusal: {error}") from error
    else:
        raise AssertionError(f"expected refusal containing {fragment!r}")


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


def unavailable_is_mutation_free(root: Path) -> None:
    admission = FakeAdmission()
    subject = executor(root, admission, OPEN.UNAVAILABLE_EFFECTS_ADAPTER)
    expect_refusal(subject.plan, "not implementation-accepted")
    assert admission.calls == []


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
    assert admission.calls.count("settle-open") == 1
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


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cats-final-open-fixture-") as temporary:
        root = Path(temporary)
        unavailable_is_mutation_free(root / "unavailable")
        successful_replay(root / "success")
        cancellation_before_start_is_mutation_free(root / "cancel")
        cleanup_resumes_without_reopening(root / "cleanup")
    print("production final-open fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
