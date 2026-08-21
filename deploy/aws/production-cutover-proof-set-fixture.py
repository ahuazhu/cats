#!/usr/bin/env python3
"""Focused synthetic regressions for E13 proof and operator boundaries."""

from __future__ import annotations

import copy
import dataclasses
import datetime as dt
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
from typing import Any


HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "production_cutover_proof_set",
    HERE / "production_cutover_proof_set.py",
)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("proof consumer module is unavailable")
PROOF = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = PROOF
SPEC.loader.exec_module(PROOF)
ADMISSION_SPEC = importlib.util.spec_from_file_location(
    "production_mutation_admission",
    HERE / "production-mutation-admission.py",
)
if ADMISSION_SPEC is None or ADMISSION_SPEC.loader is None:
    raise SystemExit("production mutation admission module is unavailable")
ADMISSION = importlib.util.module_from_spec(ADMISSION_SPEC)
sys.modules[ADMISSION_SPEC.name] = ADMISSION
ADMISSION_SPEC.loader.exec_module(ADMISSION)

SHA_A = "sha256:" + "a" * 64
SHA_B = "sha256:" + "b" * 64
SHA_C = "sha256:" + "c" * 64
SHA_D = "sha256:" + "d" * 64
COMMIT = "1" * 40


def usage_target(name: str) -> dict[str, Any]:
    resource_name = name.replace("_", "-")
    return {
        "archive_bucket_arn": f"arn:aws:s3:::usage-{resource_name}-archive",
        "archive_bucket_name": f"usage-{resource_name}-archive",
        "aws_account_id": "123456789012",
        "aws_region": "us-east-1",
        "checkpoint_table_arn": (
            "arn:aws:dynamodb:us-east-1:123456789012:"
            f"table/usage-{resource_name}-checkpoints"
        ),
        "checkpoint_table_name": f"usage-{resource_name}-checkpoints",
        "stream_arn": (
            "arn:aws:kinesis:us-east-1:123456789012:"
            f"stream/usage-{resource_name}"
        ),
        "stream_name": f"usage-{resource_name}",
        "usage_schema": f"cats_usage_{name}",
    }


def reset_target(name: str) -> dict[str, Any]:
    return {
        "chunkstore_bucket": f"chunks-{name}",
        "chunkstore_object_prefix": f"chunks-{name}/",
        "control_schema": f"cats_control_{name}",
        "usage_archive_bucket": f"usage-{name}-archive",
        "usage_checkpoint_table": f"usage-{name}-checkpoints",
        "usage_kinesis_stream": f"usage-{name}",
        "usage_schema": f"cats_usage_{name}",
    }


def verified(name: str, value: Any) -> Any:
    data = PROOF.canonical_json(value, newline=True)
    return PROOF.VerifiedFile(
        name,
        data,
        "sha256:" + hashlib.sha256(data).hexdigest(),
        len(data),
    )


def opaque(name: str, marker: str) -> Any:
    return verified(name, {"marker": marker})


def verified_bytes(name: str, data: bytes) -> Any:
    return PROOF.VerifiedFile(
        name,
        data,
        "sha256:" + hashlib.sha256(data).hexdigest(),
        len(data),
    )


def expect_proof_error(call: Any, message: str) -> None:
    try:
        call()
    except PROOF.ProofSetError:
        return
    raise AssertionError(message)


def fixture() -> tuple[Any, Any, Any, Any, Any, Any, tuple[Any, Any], dict[str, Any]]:
    targets = verified(
        PROOF.USAGE_TERMINAL_TARGETS_FILE,
        {
            "fresh_target": usage_target("fresh"),
            "old_target": usage_target("old"),
            "shards": [],
            "version": 1,
        },
    )
    runs = (
        PROOF.QualifiedRun(
            "kernel-nbd",
            "run_kernel",
            "workspace_a",
            SHA_A,
            SHA_C,
            SHA_D,
            100,
            targets.sha256,
            SHA_A,
            (("node/a", "epoch_a", SHA_A),),
        ),
        PROOF.QualifiedRun(
            "vhost-user",
            "run_vhost",
            "workspace_a",
            SHA_B,
            SHA_D,
            SHA_C,
            200,
            targets.sha256,
            SHA_B,
            (("node/b", "epoch_b", SHA_B),),
        ),
    )
    sources = PROOF._usage_sources_json(runs[0].sources + runs[1].sources)
    source_set = PROOF._usage_source_set_sha256(runs[0].sources + runs[1].sources)
    epoch = PROOF._usage_terminal_epoch_id(runs, targets.sha256, source_set)
    request_value = {
        "artifact_sha256": "2" * 64,
        "contract_version": 1,
        "created_at_unix_ms": 250,
        "fresh_target": usage_target("fresh"),
        "old_target": usage_target("old"),
        "release_commit": COMMIT,
        "shards": [],
        "source_set_sha256": source_set,
        "sources": sources,
        "terminal_epoch_id": epoch,
    }
    request = verified(PROOF.USAGE_TERMINAL_REQUEST_FILE, request_value)
    receipt = opaque(PROOF.USAGE_TERMINAL_RECEIPT_FILE, "receipt")
    verification_file = opaque(PROOF.USAGE_TERMINAL_VERIFICATION_FILE, "verified")
    verification = {
        "target_binding_sha256": "sha256:"
        + hashlib.sha256(
            PROOF.canonical_json(
                PROOF.decode_json(
                    targets.data,
                    "fixture Usage targets",
                    canonical_lf=True,
                )
            )
        ).hexdigest(),
        "target_request_sha256": SHA_D,
    }
    context = PROOF.ProducerContext(
        release_id="release_a",
        release_commit=COMMIT,
        release_manifest_sha256=SHA_A,
        worker_bundle_sha256="sha256:" + "2" * 64,
        usage_schema_verifier_binary_sha256=SHA_A,
        usage_terminal_verifier_binary_sha256=SHA_B,
        qualification_manifest_sha256=SHA_C,
        qualification_catalog_sha256=SHA_D,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        old_targets=reset_target("old"),
        fresh_targets=reset_target("fresh"),
    )
    manifest_value = {
        "block_runs": [
            {
                "block_path": run.block_path,
                "case_evidence_sha256": run.case_evidence_sha256,
                "qualification_manifest_sha256": run.manifest_sha256,
                "run_id": run.run_id,
                "source_terminal_set_sha256": run.source_terminal_set_sha256,
            }
            for run in runs
        ],
        "completed_at_unix_ms": 300,
        "expected_targets_file_sha256": targets.sha256,
        "kind": PROOF.USAGE_GLOBAL_FINALIZATION_KIND,
        "outcome": "terminal",
        "qualification_catalog_sha256": context.qualification_catalog_sha256,
        "release_commit": COMMIT,
        "source_set_sha256": source_set,
        "sources": sources,
        "target_binding_sha256": verification["target_binding_sha256"],
        "target_receipt_file_sha256": receipt.sha256,
        "target_request_file_sha256": request.sha256,
        "target_request_sha256": verification["target_request_sha256"],
        "target_verification_file_sha256": verification_file.sha256,
        "terminal_epoch_id": epoch,
        "version": 1,
        "worker_bundle_sha256": context.worker_bundle_sha256,
    }
    manifest = verified(PROOF.USAGE_GLOBAL_FINALIZATION_FILE, manifest_value)
    return (
        manifest,
        targets,
        request,
        receipt,
        verification_file,
        context,
        runs,
        verification,
    )


def usage_verification_projection(
    targets: Any,
    request: Any,
    receipt: Any,
    context: Any,
) -> dict[str, Any]:
    targets_value = PROOF.decode_json(
        targets.data,
        "fixture Usage targets",
        canonical_lf=True,
    )
    return {
        "binary_sha256": context.usage_terminal_verifier_binary_sha256,
        "expected_request_file_sha256": request.sha256,
        "expected_targets_file_sha256": targets.sha256,
        "kind": PROOF.USAGE_TERMINAL_VERIFICATION_KIND,
        "release_commit": context.release_commit,
        "target_binding_sha256": "sha256:"
        + hashlib.sha256(PROOF.canonical_json(targets_value)).hexdigest(),
        "target_receipt_file_sha256": receipt.sha256,
        "target_request_sha256": SHA_D,
        "validated": True,
        "version": 1,
        "worker_bundle_sha256": context.worker_bundle_sha256,
    }


def validate_usage_targets_match_reset_targets() -> None:
    (
        _manifest,
        targets,
        request,
        receipt,
        _verification_file,
        context,
        _runs,
        _verification,
    ) = fixture()
    PROOF._validate_usage_verification_projection(
        usage_verification_projection(targets, request, receipt, context),
        receipt=receipt,
        expected_request=request,
        expected_targets=targets,
        context=context,
    )

    foreign_targets_value = {
        "fresh_target": usage_target("foreign_fresh"),
        "old_target": usage_target("foreign_old"),
        "shards": [],
        "version": 1,
    }
    foreign_targets = verified(
        PROOF.USAGE_TERMINAL_TARGETS_FILE,
        foreign_targets_value,
    )
    foreign_request_value = PROOF.decode_json(
        request.data,
        "fixture Usage request",
        canonical_lf=True,
    )
    foreign_request_value["old_target"] = foreign_targets_value["old_target"]
    foreign_request_value["fresh_target"] = foreign_targets_value["fresh_target"]
    foreign_request = verified(
        PROOF.USAGE_TERMINAL_REQUEST_FILE,
        foreign_request_value,
    )
    foreign_receipt = verified(
        PROOF.USAGE_TERMINAL_RECEIPT_FILE,
        {
            "barriers": [],
            "contract_version": 1,
            "request": foreign_request_value,
            "request_sha256": SHA_D,
            "source_receipts": [],
        },
    )
    try:
        PROOF._validate_usage_verification_projection(
            usage_verification_projection(
                foreign_targets,
                foreign_request,
                foreign_receipt,
                context,
            ),
            receipt=foreign_receipt,
            expected_request=foreign_request,
            expected_targets=foreign_targets,
            context=context,
        )
    except PROOF.ProofSetError:
        pass
    else:
        raise AssertionError(
            "coherent foreign Usage terminal targets escaped the reset binding"
        )


def validate_with_request(request_value: dict[str, Any]) -> None:
    manifest, targets, _request, receipt, verification_file, context, runs, verification = fixture()
    request = verified(PROOF.USAGE_TERMINAL_REQUEST_FILE, request_value)
    manifest_value = PROOF.decode_json(manifest.data, "manifest", canonical_lf=True)
    manifest_value["target_request_file_sha256"] = request.sha256
    manifest = verified(PROOF.USAGE_GLOBAL_FINALIZATION_FILE, manifest_value)
    PROOF._validate_global_usage_finalization(
        manifest_value,
        finalization_manifest=manifest,
        expected_targets=targets,
        expected_request=request,
        receipt=receipt,
        verification_file=verification_file,
        verification=verification,
        qualified_runs=runs,
        context=context,
    )


def validate_inventory_is_observation_only() -> None:
    original_load_pending = ADMISSION.load_pending
    original_post_exact = ADMISSION.post_exact
    with tempfile.TemporaryDirectory() as temporary:
        directory = Path(temporary)
        pending_path = directory / "close.pending.v1.json"
        calls: list[tuple[str, str, bytes]] = []
        try:
            ADMISSION.load_pending = lambda _path, _trust: (
                {},
                b"{}",
                {"command_id": "0" * 32},
            )

            def unexpected_post(origin: str, target: str, pending: Any, body: bytes) -> Any:
                calls.append((origin, target, body))
                raise AssertionError("missing applied close receipt reached the network")

            ADMISSION.post_exact = unexpected_post
            try:
                ADMISSION.load_existing_qualification_pending_receipt(
                    pending_path,
                    SimpleNamespace(trust_file=directory / "trust.json"),
                    "Qualification close",
                )
            except ADMISSION.AdmissionError:
                pass
            else:
                raise AssertionError("missing applied close receipt was accepted")
            if calls:
                raise AssertionError("missing applied close receipt caused network I/O")
        finally:
            ADMISSION.load_pending = original_load_pending
            ADMISSION.post_exact = original_post_exact

    original_functions = {
        name: getattr(ADMISSION, name)
        for name in (
            "validate_qualification_authority_inputs",
            "load_qualification_begin_for_close",
            "qualification_pending_path",
            "load_existing_qualification_pending_receipt",
            "validate_applied_qualification_receipt",
            "load_pending",
            "post_exact",
            "validate_product_inventory",
        )
    }
    original_sleep = ADMISSION.time.sleep
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        evidence = root / "evidence"
        state = root / "state"
        evidence.mkdir(mode=0o700)
        state.mkdir(mode=0o700)
        pending_path = state / "close.pending.v1.json"
        pending_path.write_bytes(b"pending")
        response = ADMISSION.canonical_json({"product_resource_count": 0})
        calls = []
        begin_modes: list[bool] = []
        attempts = 0
        try:
            ADMISSION.validate_qualification_authority_inputs = lambda _args: {
                "qualification_id": "run_a"
            }

            def load_begin(_args: Any, _binding: Any, *, existing_receipt_only: bool = False) -> Any:
                begin_modes.append(existing_receipt_only)
                return {}

            ADMISSION.load_qualification_begin_for_close = load_begin
            ADMISSION.qualification_pending_path = (
                lambda _state, _binding, _kind: pending_path
            )
            ADMISSION.load_existing_qualification_pending_receipt = (
                lambda _pending, _args, _label: ({"outcome": {"kind": "applied"}}, b"r", SHA_A)
            )
            ADMISSION.validate_applied_qualification_receipt = (
                lambda _receipt, _binding, _kind: {}
            )
            ADMISSION.load_pending = lambda _pending, _trust: (
                {"origin": "https://control.example"},
                b"same-signed-close",
                {},
            )

            def post_inventory(origin: str, target: str, pending: Any, body: bytes) -> Any:
                nonlocal attempts
                attempts += 1
                calls.append((origin, target, body))
                if attempts == 1:
                    raise ADMISSION.AdmissionError("ambiguous read response")
                return ADMISSION.HttpResult(
                    200,
                    [
                        ("Content-Type", ADMISSION.CONTENT_TYPE),
                        ("Cache-Control", "no-store"),
                    ],
                    response,
                )

            ADMISSION.post_exact = post_inventory
            ADMISSION.validate_product_inventory = (
                lambda value, _binding, _receipt, _sha, _kind: value
            )
            ADMISSION.time.sleep = lambda _seconds: None
            path, _digest = ADMISSION.qualification_product_inventory(
                SimpleNamespace(
                    state_directory=state,
                    evidence_directory=evidence,
                    trust_file=root / "trust.json",
                    close_kind="end_qualification",
                    resolution_timeout_seconds=2,
                )
            )
            if begin_modes != [True] or len(calls) != 2:
                raise AssertionError("inventory replay did not require existing authority")
            if any(
                target != ADMISSION.PRODUCT_INVENTORY_PATH
                or body != b"same-signed-close"
                for _origin, target, body in calls
            ):
                raise AssertionError("inventory replay changed endpoint or signed bytes")
            if path.read_bytes() != response:
                raise AssertionError("inventory replay did not durably publish exact bytes")
        finally:
            for name, function in original_functions.items():
                setattr(ADMISSION, name, function)
            ADMISSION.time.sleep = original_sleep


def validate_qualification_fleet_cross_binding() -> None:
    final_inventory = opaque(PROOF.QUALIFICATION_FINAL_INVENTORY_FILE, "fleet")
    fleet = {
        "expected_node_ids": ["node-a", "node-b"],
        "fleet_verification_receipt_sha256": final_inventory.sha256,
    }
    PROOF._validate_qualification_fleet_authority(
        fleet,
        ["node-a", "node-b"],
        final_inventory,
    )
    for foreign in (
        {**fleet, "expected_node_ids": ["node-a"]},
        {**fleet, "fleet_verification_receipt_sha256": SHA_D},
    ):
        try:
            PROOF._validate_qualification_fleet_authority(
                foreign,
                ["node-a", "node-b"],
                final_inventory,
            )
        except PROOF.ProofSetError:
            continue
        raise AssertionError("foreign qualification Fleet authority was accepted")


def validate_release_bound_usage_subprocess() -> None:
    if not Path("/proc/self/fd").is_dir():
        # The production adapter is Linux-only. The native Linux gate executes
        # the held-descriptor race below; non-Linux static gates still parse it.
        return
    (
        manifest,
        targets,
        request,
        receipt,
        verification_file,
        context,
        runs,
        _verification,
    ) = fixture()
    original_binary = PROOF.USAGE_TERMINAL_VERIFIER
    original_private_directory = PROOF._require_root_private_directory
    original_open_executable = PROOF._open_release_bound_executable
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        state = root / "state"
        state.mkdir(mode=0o700)
        executable = root / "cats-usage-terminal-receipt-verifier"
        original_marker = root / "original-executed"
        foreign_marker = root / "foreign-executed"
        executable.write_text(
            f"""#!{sys.executable}
import argparse
import os
from pathlib import Path
import sys

parser = argparse.ArgumentParser()
parser.add_argument("--receipt-file", required=True)
parser.add_argument("--expected-request-file", required=True)
parser.add_argument("--expected-targets-file", required=True)
parser.add_argument("--expected-targets-sha256", required=True)
parser.add_argument("--release-commit", required=True)
parser.add_argument("--worker-bundle-sha256", required=True)
parser.add_argument("--receipt-out", required=True)
args = parser.parse_args()
if (
    Path(args.receipt_file).name != {PROOF.USAGE_TERMINAL_RECEIPT_FILE!r}
    or Path(args.expected_request_file).name != {PROOF.USAGE_TERMINAL_REQUEST_FILE!r}
    or Path(args.expected_targets_file).name != {PROOF.USAGE_TERMINAL_TARGETS_FILE!r}
    or args.expected_targets_sha256 != {targets.sha256!r}
    or args.release_commit != {context.release_commit!r}
    or args.worker_bundle_sha256 != {context.worker_bundle_sha256!r}
):
    raise SystemExit(2)
output = Path(args.receipt_out)
output.write_bytes(bytes.fromhex({verification_file.data.hex()!r}))
os.chmod(output, 0o600)
Path({str(original_marker)!r}).write_text("original", encoding="utf-8")
sys.stdout.write({PROOF.USAGE_TERMINAL_SUCCESS_STDOUT!r})
""",
            encoding="utf-8",
        )
        executable.chmod(0o500)
        context = dataclasses.replace(
            context,
            usage_terminal_verifier_binary_sha256=(
                "sha256:" + hashlib.sha256(executable.read_bytes()).hexdigest()
            ),
        )
        opened: list[str] = []
        swap_path = False

        def open_fixture_executable(path: Path, expected_sha256: str) -> Any:
            if (
                path != executable
                or expected_sha256
                != context.usage_terminal_verifier_binary_sha256
            ):
                raise AssertionError("subprocess adapter did not use the release verifier")
            descriptor = os.open(path, os.O_RDONLY)
            if swap_path:
                foreign = root / "foreign-verifier"
                foreign.write_text(
                    f"#!{sys.executable}\n"
                    f"from pathlib import Path\n"
                    f"Path({str(foreign_marker)!r}).write_text('foreign')\n",
                    encoding="utf-8",
                )
                foreign.chmod(0o500)
                os.replace(foreign, executable)
            opened.append(expected_sha256)
            return descriptor, PROOF._FileIdentity.from_stat(os.fstat(descriptor))

        try:
            PROOF.USAGE_TERMINAL_VERIFIER = executable
            PROOF._require_root_private_directory = lambda _path, _label: None
            PROOF._open_release_bound_executable = open_fixture_executable
            verifier = PROOF.SubprocessUsageTargetTerminalVerifier(state)
            verifier.verify(
                manifest,
                targets,
                receipt,
                request,
                verification_file,
                runs,
                context,
            )
            if opened != [context.usage_terminal_verifier_binary_sha256]:
                raise AssertionError("subprocess adapter did not pin the verifier binary")
            for _attempt in range(16):
                verifier.verify(
                    manifest,
                    targets,
                    receipt,
                    request,
                    verification_file,
                    runs,
                    context,
                )
            wrong = opaque(PROOF.USAGE_TERMINAL_VERIFICATION_FILE, "foreign")
            try:
                verifier.verify(
                    manifest,
                    targets,
                    receipt,
                    request,
                    wrong,
                    runs,
                    context,
                )
            except PROOF.ProofSetError:
                pass
            else:
                raise AssertionError("subprocess adapter accepted foreign verifier bytes")
            original_marker.unlink()
            swap_path = True
            try:
                verifier.verify(
                    manifest,
                    targets,
                    receipt,
                    request,
                    verification_file,
                    runs,
                    context,
                )
            except PROOF.ProofSetError:
                pass
            else:
                raise AssertionError("subprocess adapter ignored verifier path replacement")
            if not original_marker.exists() or foreign_marker.exists():
                raise AssertionError("verifier pathname replacement executed foreign bytes")
        finally:
            PROOF.USAGE_TERMINAL_VERIFIER = original_binary
            PROOF._require_root_private_directory = original_private_directory
            PROOF._open_release_bound_executable = original_open_executable


def validate_release_bound_usage_schema_subprocess() -> None:
    _manifest, _targets, _request, _receipt, _verification, context, _runs, _value = (
        fixture()
    )
    original_binary = PROOF.USAGE_SCHEMA_VERIFIER
    original_private_directory = PROOF._require_root_private_directory
    original_open_executable = PROOF._open_release_bound_executable
    original_run = PROOF._run_held_usage_verifier
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary).resolve()
        state = root / "state"
        state.mkdir(mode=0o700)
        executable = root / "cats-usage-schema-v16-verifier"
        executable.write_bytes(b"fixture usage schema verifier")
        executable.chmod(0o500)
        executable_sha256 = "sha256:" + hashlib.sha256(
            executable.read_bytes()
        ).hexdigest()
        context = dataclasses.replace(
            context,
            usage_schema_verifier_binary_sha256=executable_sha256,
        )
        dsn = root / "dsn"
        ca = root / "ca"
        dsn.write_text("postgresql://fixture\n", encoding="utf-8")
        ca.write_text("fixture-ca\n", encoding="utf-8")

        expected_receipt = PROOF.canonical_json(
            {
                "binary_sha256": executable_sha256,
                "catalog_sha256": SHA_C,
                "kind": PROOF.USAGE_SCHEMA_VERIFICATION_KIND,
                "release_commit": context.release_commit,
                "schema": "cats_usage_fresh",
                "schema_version": 16,
                "verified": True,
                "version": 1,
                "worker_bundle_sha256": context.worker_bundle_sha256,
            },
            newline=True,
        )
        invocations = 0

        def open_fixture_executable(path: Path, expected_sha256: str) -> Any:
            if path != executable or expected_sha256 != executable_sha256:
                raise AssertionError("schema adapter did not select the release binary")
            descriptor = os.open(path, os.O_RDONLY)
            return descriptor, PROOF._FileIdentity.from_stat(os.fstat(descriptor))

        def run_fixture(
            argv: list[str],
            _descriptor: int,
            *,
            cwd: Path,
            timeout_seconds: int,
        ) -> tuple[int, bytes, bytes]:
            nonlocal invocations
            invocations += 1
            expected = [
                str(executable),
                "--dsn-file",
                str(dsn),
                "--ca-file",
                str(ca),
                "--schema",
                "cats_usage_fresh",
                "--release-commit",
                context.release_commit,
                "--worker-bundle-sha256",
                context.worker_bundle_sha256,
                "--receipt-out",
                str(state / PROOF.USAGE_SCHEMA_VERIFICATION_FILE),
            ]
            if argv != expected or cwd != state or timeout_seconds != 120:
                raise AssertionError("schema adapter invocation drifted")
            output = state / PROOF.USAGE_SCHEMA_VERIFICATION_FILE
            if output.exists() and output.read_bytes() != expected_receipt:
                return 1, b"", b"Usage schema v16 verification failed closed\n"
            output.write_bytes(expected_receipt)
            output.chmod(0o600)
            return 0, PROOF.USAGE_SCHEMA_SUCCESS_STDOUT.encode("ascii"), b""

        try:
            PROOF.USAGE_SCHEMA_VERIFIER = executable
            PROOF._require_root_private_directory = lambda _path, _label: None
            PROOF._open_release_bound_executable = open_fixture_executable
            PROOF._run_held_usage_verifier = run_fixture
            actual = PROOF.SubprocessUsageSchemaV16Verifier(state).verify(
                dsn_file=dsn,
                ca_file=ca,
                schema="cats_usage_fresh",
                context=context,
            )
            if actual.name != PROOF.USAGE_SCHEMA_VERIFICATION_FILE:
                raise AssertionError("schema adapter receipt name drifted")
            replay = PROOF.SubprocessUsageSchemaV16Verifier(state).verify(
                dsn_file=dsn,
                ca_file=ca,
                schema="cats_usage_fresh",
                context=context,
            )
            if replay != actual or invocations != 2:
                raise AssertionError("schema adapter exact replay drifted")
            (state / PROOF.USAGE_SCHEMA_VERIFICATION_FILE).write_bytes(
                PROOF.canonical_json(
                    {
                        **PROOF.decode_json(
                            expected_receipt,
                            "schema receipt fixture",
                            canonical_lf=True,
                        ),
                        "catalog_sha256": SHA_D,
                    },
                    newline=True,
                )
            )
            try:
                PROOF.SubprocessUsageSchemaV16Verifier(state).verify(
                    dsn_file=dsn,
                    ca_file=ca,
                    schema="cats_usage_fresh",
                    context=context,
                )
            except PROOF.ProofSetError:
                pass
            else:
                raise AssertionError(
                    "schema adapter accepted a foreign existing receipt"
                )
        finally:
            PROOF.USAGE_SCHEMA_VERIFIER = original_binary
            PROOF._require_root_private_directory = original_private_directory
            PROOF._open_release_bound_executable = original_open_executable
            PROOF._run_held_usage_verifier = original_run


def validate_release_manifest_catalog_cross_check() -> None:
    release = {
        "source_commit_sha": COMMIT,
        "qualification_catalog_sha256": SHA_D,
    }
    manifest = {
        "artifacts": {
            "control_plane": {"marker": "control"},
            "gateway": {"marker": "gateway"},
            "worker": {
                "bundle_name": "cats-worker.tar.zst",
                "bundle_sha256": SHA_A,
                "members": {
                    PROOF.USAGE_SCHEMA_VERIFIER.name: {
                        "sha256": SHA_C,
                        "size_bytes": 1,
                    },
                    PROOF.USAGE_TERMINAL_VERIFIER.name: {
                        "sha256": SHA_B,
                        "size_bytes": 1,
                    },
                },
            },
        },
        "build_inputs": {
            "files": {
                "qualification_catalog": {"sha256": SHA_D, "size_bytes": 1},
            },
            "guest_target": "x86_64-unknown-linux-musl",
            "platform": "linux/amd64",
        },
        "guest_runtime": {"marker": "guest"},
        "source": {
            "commit": COMMIT,
            "fingerprint": SHA_A,
            "tree": "2" * 40,
        },
        "version": 1,
    }
    result = PROOF._validate_release_manifest(copy.deepcopy(manifest), release)
    if result != (SHA_A, SHA_C, SHA_B):
        raise AssertionError("release manifest digests drifted")
    drifted_catalog = copy.deepcopy(manifest)
    drifted_catalog["build_inputs"]["files"]["qualification_catalog"]["sha256"] = SHA_A
    missing_catalog = copy.deepcopy(manifest)
    del missing_catalog["build_inputs"]["files"]["qualification_catalog"]
    missing_files = copy.deepcopy(manifest)
    del missing_files["build_inputs"]["files"]
    for label, candidate in (
        ("drifted", drifted_catalog),
        ("missing catalog input", missing_catalog),
        ("missing fingerprinted files", missing_files),
    ):
        expect_proof_error(
            lambda candidate=candidate: PROOF._validate_release_manifest(
                candidate, release
            ),
            f"release manifest with {label} qualification catalog was accepted",
        )


def route_rotation_fixture(context: Any) -> tuple[Any, Any, Any, dict[str, Any], dict[str, Any]]:
    run_id = "run_route"
    deployment = "route-deployment-a"
    transcript_lines = [
        (
            f"version=1 kind={PROOF.ROUTE_V2_ROTATION_TRANSCRIPT_KIND}"
            f" case_id={PROOF.ROUTE_V2_ROTATION_CASE_ID}"
            f" qualification_run_id={run_id}"
            f" source_commit_sha={context.release_commit}"
        ),
        "phase=setup event=resume_current detail=signer_revision_5",
        f"terminal_marker={PROOF.ROUTE_V2_ROTATION_TERMINAL_MARKER}",
    ]
    transcript = verified_bytes(
        "route-transcript",
        ("\n".join(transcript_lines) + "\n").encode("ascii"),
    )

    def node(route_active: int) -> dict[str, Any]:
        return {
            "node_id": "node-a",
            "binding": {"node_id": "node-a"},
            "inventory": {
                "complete_inventory": True,
                "active_guard_count": 0,
                "residue_count": 0,
                "route_active_count": route_active,
            },
        }

    checkpoints = [
        {
            "observed_phase": observed,
            "signer_revision": 5,
            "ring_version": 4,
            "ring_digest": SHA_A,
            "loaded_kids": ["kid-a"],
            "settled_by_phase": settled,
            "required_store_precondition": condition,
            "settled_by_store_receipt_sha256": SHA_B,
            "settled_at_unix_ms": 100,
            "precondition": {"satisfied": True},
            "store_precondition_satisfied": True,
        }
        for observed, settled, condition in PROOF.ROUTE_V2_ROTATION_CHECKPOINTS
    ]
    acks_value = {
        "version": 1,
        "kind": PROOF.ROUTE_V2_NODE_ACK_SET_KIND,
        "case_id": PROOF.ROUTE_V2_ROTATION_CASE_ID,
        "qualification_run_id": run_id,
        "source_commit_sha": context.release_commit,
        "route_deployment_id": deployment,
        "expected_nodes": ["node-a"],
        "disabled_fleet_sha256": SHA_A,
        "disabled_evaluated_at_unix_ms": 100,
        "disabled_nodes": [node(0)],
        "disabled_all_nodes_closed_or_fenced": True,
        "checkpoints": checkpoints,
        "terminal_fleet_sha256": SHA_B,
        "terminal_evaluated_at_unix_ms": 200,
        "terminal_signing_authority": {
            "deployment_id": deployment,
            "signer_revision": 8,
            "signer_reference_sha256": SHA_C,
            "active_kid": "kid-recovery",
            "public_key_ring_version": 5,
            "public_key_ring_digest": SHA_D,
        },
        "terminal_nodes": [node(1)],
        "all_nodes_acknowledged": True,
        "all_active_guards_zero": True,
        "terminal_marker": PROOF.ROUTE_V2_NODE_ACK_TERMINAL_MARKER,
    }
    acks = verified("route-node-acks", acks_value)
    receipt_value = {
        "version": 1,
        "kind": PROOF.ROUTE_V2_ROTATION_RECEIPT_KIND,
        "case_id": PROOF.ROUTE_V2_ROTATION_CASE_ID,
        "qualification_run_id": run_id,
        "source_commit_sha": context.release_commit,
        "qualification_catalog_sha256": context.qualification_catalog_sha256,
        "authority_id": "authority-a",
        "route_deployment_id": deployment,
        "rotation_operator_trust_sha256": SHA_A,
        "command_bundle_sha256": SHA_B,
        "recovery_transport_sha256": SHA_C,
        "phase_receipts": [
            {"phase": phase} for phase in PROOF.ROUTE_V2_ROTATION_PHASES
        ],
        "disabled_checkpoint": {
            "signer_revision": 6,
            "ring_version": 4,
            "signer_state": "disabled",
            "loaded_kids": [],
            "public_route_closed": True,
            "public_route_closed_observation_count": 3,
            "disabled_public_route_sha256": SHA_A,
            "all_nodes_closed_or_fenced": True,
            "active_guard_count": 0,
            "disabled_fleet_sha256": SHA_A,
            "disable_store_receipt_sha256": SHA_B,
            "closed_fleet_settlement_store_receipt_sha256": SHA_C,
        },
        "recovery_checkpoint": {
            "signer_revision": 8,
            "ring_version": 5,
            "signer_state": "active",
            "active_kid": "kid-recovery",
            "database_current": True,
            "process_ready": True,
            "all_nodes_acknowledged": True,
            "all_active_guards_zero": True,
            "terminal_fleet_sha256": SHA_B,
        },
        "fresh_endpoint": {
            "mechanism": "unbind_old_bind_fresh_endpoint",
            "calibrated_baseline_public_route_sha256": SHA_A,
            "lineage_receipt_sha256": SHA_B,
            "old_endpoint": {
                "endpoint_id": "ep-old",
                "hostname": "app.example",
                "name": "app",
            },
            "unbind": {"operation_id": "op-unbind"},
            "fresh_endpoint": {
                "endpoint_id": "ep-fresh",
                "hostname": "app.example",
                "name": "g3-fresh",
                "route_epoch": 1,
            },
            "bind": {"operation_id": "op-bind"},
            "pre_probe_collection_sha256": SHA_C,
            "public_route_receipt_sha256": SHA_D,
            "http_guest_body": True,
            "websocket_guest_echo": True,
        },
        "node_acks_sha256": acks.sha256,
        "transcript_sha256": transcript.sha256,
        "terminal_marker": PROOF.ROUTE_V2_ROTATION_TERMINAL_MARKER,
    }
    receipt = verified("route-receipt", receipt_value)
    return receipt, acks, transcript, receipt_value, acks_value


def validate_route_v2_rotation_verifier() -> None:
    context = fixture()[5]
    verifier = PROOF.RouteV2RotationQualificationEvidenceVerifier()
    receipt, acks, transcript, receipt_value, acks_value = route_rotation_fixture(
        context
    )
    verifier.verify(receipt, acks, transcript, context)

    def rebound_receipt(**overrides: Any) -> Any:
        candidate = copy.deepcopy(receipt_value)
        candidate.update(overrides)
        return verified("route-receipt", candidate)

    expect_proof_error(
        lambda: verifier.verify(
            rebound_receipt(source_commit_sha="3" * 40),
            acks,
            transcript,
            context,
        ),
        "G3 receipt for a foreign release commit was accepted",
    )
    expect_proof_error(
        lambda: verifier.verify(
            rebound_receipt(node_acks_sha256=SHA_D),
            acks,
            transcript,
            context,
        ),
        "G3 receipt rebinding a foreign node-ack file was accepted",
    )
    expect_proof_error(
        lambda: verifier.verify(
            rebound_receipt(qualification_catalog_sha256=SHA_A),
            acks,
            transcript,
            context,
        ),
        "G3 receipt for a foreign qualification catalog was accepted",
    )

    unsatisfied = copy.deepcopy(acks_value)
    unsatisfied["checkpoints"][2]["store_precondition_satisfied"] = False
    unsatisfied_acks = verified("route-node-acks", unsatisfied)
    expect_proof_error(
        lambda: verifier.verify(
            rebound_receipt(node_acks_sha256=unsatisfied_acks.sha256),
            unsatisfied_acks,
            transcript,
            context,
        ),
        "G3 unsatisfied Store precondition checkpoint was accepted",
    )
    unacknowledged = copy.deepcopy(acks_value)
    unacknowledged["all_nodes_acknowledged"] = False
    unacknowledged_acks = verified("route-node-acks", unacknowledged)
    expect_proof_error(
        lambda: verifier.verify(
            rebound_receipt(node_acks_sha256=unacknowledged_acks.sha256),
            unacknowledged_acks,
            transcript,
            context,
        ),
        "G3 unacknowledged Node ring-ACK set was accepted",
    )

    header, event, marker = transcript.data.decode("ascii").splitlines()
    for label, lines in (
        ("without its terminal marker", [header, event]),
        ("with a repeated terminal marker", [header, event, marker, marker]),
        ("with a foreign header", [event, marker]),
    ):
        candidate = verified_bytes(
            "route-transcript",
            ("\n".join(lines) + "\n").encode("ascii"),
        )
        expect_proof_error(
            lambda candidate=candidate: verifier.verify(
                rebound_receipt(transcript_sha256=candidate.sha256),
                acks,
                candidate,
                context,
            ),
            f"G3 transcript {label} was accepted",
        )


def admission_chain_fixture(context: Any) -> Any:
    spki = ADMISSION.ED25519_SPKI_PREFIX + b"\x00" * 32
    credential = {
        "credential_id": "cred_a",
        "public_key_spki": ADMISSION.encode_base64url(spki),
        "scope": {
            "aws_partition": "aws",
            "account_id": "123456789012",
            "role_arn": "arn:aws:iam::123456789012:role/cutover",
        },
    }
    trust = {
        "version": 1,
        "deployment_id": "dep_a",
        "release_id": context.release_id,
        "source_commit_sha": context.release_commit,
        "signature_threshold": 1,
        "credentials": [credential],
    }
    trust_data = ADMISSION.canonical_json(trust)
    operator = {
        "aws_partition": "aws",
        "account_id": "123456789012",
        "role_arn": credential["scope"]["role_arn"],
        "principal_arn": "arn:aws:sts::123456789012:assumed-role/cutover/session",
    }
    binding = {
        "qualification_id": "qual_a",
        "deployment_id": "dep_a",
        "release_id": context.release_id,
        "source_commit_sha": context.release_commit,
        "control_schema_version": 18,
        "source_manifest_sha256": SHA_A,
        "source_bundle_sha256": SHA_B,
        "build_receipt_sha256": SHA_C,
        "release_manifest_sha256": context.release_manifest_sha256,
        "worker_bundle_sha256": context.worker_bundle_sha256,
        "qualification_catalog_sha256": context.qualification_catalog_sha256,
        "qualification_cell_manifest_sha256": SHA_D,
        "aws_partition": "aws",
        "aws_account_id": "123456789012",
        "aws_region": "us-east-1",
        "cell_id": "cell_a",
        "cell_namespace": "cats",
        "cats_account_id": "acct_a",
        "workspace_id": "workspace_a",
        "allowed_mutation_classes": list(ADMISSION.QUALIFICATION_MUTATION_CLASSES),
        "qualification_expires_at_unix_ms": 10_000_000,
    }

    def command(
        command_id: str,
        issued: int,
        mutation: str,
        expected_revision: int,
    ) -> dict[str, Any]:
        return {
            "version": 1,
            "command_id": command_id,
            "issued_at_unix_ms": issued,
            "expires_at_unix_ms": issued + 240_000,
            "operator": operator,
            "expected_revision": expected_revision,
            "mutation": {"kind": mutation, "binding": binding},
        }

    def pending_file(
        name: str,
        value: dict[str, Any],
        *,
        signature: bytes = b"\x00" * 64,
    ) -> tuple[Any, bytes]:
        body = ADMISSION.canonical_json(value)
        pending = {
            "version": 1,
            "origin": "https://control.example",
            "method": "POST",
            "target": ADMISSION.COMMAND_PATH,
            "discovery_target": ADMISSION.DISCOVERY_PATH,
            "state_target": ADMISSION.STATE_PATH,
            "credential_id": credential["credential_id"],
            "public_key_spki_sha256": ADMISSION.sha256(spki),
            "trust_sha256": ADMISSION.sha256(trust_data),
            "request_sha256": ADMISSION.sha256(body),
            "body_base64": ADMISSION.encode_base64url(body),
            "signature": ADMISSION.encode_base64url(signature),
            "created_at_unix_ms": value["issued_at_unix_ms"],
        }
        return (
            verified_bytes(name, ADMISSION.canonical_json(pending, newline=True)),
            body,
        )

    def receipt_file(
        name: str,
        value: dict[str, Any],
        body: bytes,
        mode: str,
        committed: int,
        *,
        sts: dict[str, Any] | None = None,
    ) -> tuple[Any, dict[str, Any]]:
        state = {
            "version": 1,
            "revision": value["expected_revision"] + 1,
            "mode": mode,
            "binding": {"kind": "qualification", "binding": binding},
            "last_command_id": value["command_id"],
            "updated_at_unix_ms": committed,
        }
        receipt = {
            "version": 1,
            "command": value,
            "request_sha256": ADMISSION.sha256(body),
            "principal": {
                "credential_id": credential["credential_id"],
                "public_key_spki_sha256": ADMISSION.sha256(spki),
                "trust_bundle_sha256": ADMISSION.sha256(trust_data),
                "sts": operator if sts is None else sts,
            },
            "outcome": {"kind": "applied", "state": state},
            "committed_at_unix_ms": committed,
        }
        return verified_bytes(name, ADMISSION.canonical_json(receipt)), state

    begin_command = command("a" * 32, 1_000, "begin_qualification", 1)
    close_command = command("b" * 32, 2_000, "end_qualification", 2)
    begin_pending, begin_body = pending_file("begin-pending", begin_command)
    close_pending, close_body = pending_file("close-pending", close_command)
    begin_receipt, begin_state = receipt_file(
        "begin-receipt", begin_command, begin_body, "qualification", 1_500
    )
    close_receipt, close_state = receipt_file(
        "close-receipt", close_command, close_body, "closed", 2_500
    )
    final_state = verified_bytes(
        "final-state", ADMISSION.canonical_json(close_state)
    )
    return SimpleNamespace(
        trust=trust,
        trust_data=trust_data,
        operator=operator,
        binding=binding,
        command=command,
        pending_file=pending_file,
        receipt_file=receipt_file,
        begin_pending=begin_pending,
        begin_receipt=begin_receipt,
        begin_state=begin_state,
        close_pending=close_pending,
        close_receipt=close_receipt,
        close_state=close_state,
        final_state=final_state,
    )


def validate_qualification_admission_verifier() -> None:
    context = fixture()[5]
    chain = admission_chain_fixture(context)
    verifier = PROOF.QualificationAdmissionEvidenceVerifier(
        ADMISSION, chain.trust_data
    )
    verifier.verify(
        chain.begin_pending,
        chain.begin_receipt,
        chain.close_pending,
        chain.close_receipt,
        chain.final_state,
        context,
    )

    expect_proof_error(
        lambda: verifier.verify(
            chain.begin_pending,
            chain.begin_receipt,
            chain.close_pending,
            chain.close_receipt,
            verified_bytes(
                "final-state", ADMISSION.canonical_json(chain.begin_state)
            ),
            context,
        ),
        "final state that is not the close successor was accepted",
    )
    expect_proof_error(
        lambda: verifier.verify(
            chain.begin_pending,
            chain.begin_receipt,
            chain.close_pending,
            chain.close_receipt,
            chain.final_state,
            dataclasses.replace(
                context, worker_bundle_sha256="sha256:" + "9" * 64
            ),
        ),
        "admission binding outside the reset release was accepted",
    )

    skipped_close = chain.command("c" * 32, 3_000, "end_qualification", 7)
    skipped_pending, skipped_body = chain.pending_file(
        "close-pending", skipped_close
    )
    skipped_receipt, _skipped_state = chain.receipt_file(
        "close-receipt", skipped_close, skipped_body, "closed", 3_500
    )
    expect_proof_error(
        lambda: verifier.verify(
            chain.begin_pending,
            chain.begin_receipt,
            skipped_pending,
            skipped_receipt,
            chain.final_state,
            context,
        ),
        "close command that is not the exact Begin successor was accepted",
    )

    short_pending, _short_body = chain.pending_file(
        "begin-pending",
        chain.command("a" * 32, 1_000, "begin_qualification", 1),
        signature=b"\x00" * 63,
    )
    expect_proof_error(
        lambda: verifier.verify(
            short_pending,
            chain.begin_receipt,
            chain.close_pending,
            chain.close_receipt,
            chain.final_state,
            context,
        ),
        "pending command without an Ed25519 signature was accepted",
    )

    foreign_sts = dict(chain.operator, account_id="210987654321")
    foreign_receipt, _foreign_state = chain.receipt_file(
        "begin-receipt",
        chain.command("a" * 32, 1_000, "begin_qualification", 1),
        ADMISSION.canonical_json(
            chain.command("a" * 32, 1_000, "begin_qualification", 1)
        ),
        "qualification",
        1_500,
        sts=foreign_sts,
    )
    expect_proof_error(
        lambda: verifier.verify(
            chain.begin_pending,
            foreign_receipt,
            chain.close_pending,
            chain.close_receipt,
            chain.final_state,
            context,
        ),
        "command receipt with a foreign STS principal was accepted",
    )

    foreign_trust = copy.deepcopy(chain.trust)
    foreign_trust["release_id"] = "release_b"
    expect_proof_error(
        lambda: PROOF.QualificationAdmissionEvidenceVerifier(
            ADMISSION, ADMISSION.canonical_json(foreign_trust)
        ).verify(
            chain.begin_pending,
            chain.begin_receipt,
            chain.close_pending,
            chain.close_receipt,
            chain.final_state,
            context,
        ),
        "cutover trust outside the reset release was accepted",
    )


def manual_fence_evidence_fixture() -> tuple[dict[str, Any], Any, Any]:
    fence_receipt = verified_bytes("fence-receipt", b"ec2 stop forensic artifact\n")
    stop_receipt = verified_bytes("stop-receipt", b"systemd stop forensic artifact\n")
    evidence = {
        "kind": PROOF.MANUAL_FENCE_EVIDENCE_KIND,
        "version": 1,
        "decision": PROOF.MANUAL_FENCE_EVIDENCE_DECISION,
        "operator_principal_arn": (
            "arn:aws:sts::123456789012:assumed-role/cutover/session"
        ),
        "recorded_at": "2026-08-12T00:00:00Z",
        "hosts": [
            {
                "host_id": "old-host-a",
                "components": ["blockd", "node_agent", "vmm"],
                "terminal_kind": "host_fence_event",
                "event_id": "manual-fence-old-host-a",
                "ec2_stop": {
                    "instance_id": "i-0123456789abcdef0",
                    "stopped_at": "2026-08-11T23:50:00Z",
                },
                "checklist": {
                    "instance_stopped": True,
                    "no_running_writers": True,
                    "object_write_cutoff_verified": True,
                    "forensic_artifact_retained": True,
                },
                "receipt_sha256": fence_receipt.sha256,
            },
            {
                "host_id": "old-host-b",
                "components": ["controller", "gateway"],
                "terminal_kind": "local_positive_stop",
                "stopped_units": [
                    "cats-controld.service",
                    "cats-gatewayd.service",
                ],
                "stopped_at": "2026-08-11T23:40:00Z",
                "checklist": {
                    "units_stopped": True,
                    "no_running_writers": True,
                    "object_write_cutoff_verified": True,
                    "forensic_artifact_retained": True,
                },
                "receipt_sha256": stop_receipt.sha256,
            },
        ],
    }
    return evidence, fence_receipt, stop_receipt


def validate_manual_fence_evidence() -> None:
    now = dt.datetime(2026, 8, 13, tzinfo=dt.timezone.utc)
    evidence, fence_receipt, stop_receipt = manual_fence_evidence_fixture()

    def parse(value: dict[str, Any], *, account: str = "123456789012") -> Any:
        return PROOF.ManualOperatorFenceEvidence.parse(
            PROOF.canonical_json(value, newline=True),
            expected_account_id=account,
            now=now,
        )

    manual = parse(evidence)
    fence_verifier = manual.host_fence_verifier()
    stop_verifier = manual.local_positive_stop_verifier()
    fence_expected = {
        "event_id": "manual-fence-old-host-a",
        "host_id": "old-host-a",
        "components": ["blockd", "node_agent", "vmm"],
    }
    stop_expected = {
        "host_id": "old-host-b",
        "components": ["controller", "gateway"],
    }
    fence_verifier.verify(fence_receipt, fence_expected)
    stop_verifier.verify(stop_receipt, stop_expected)

    unchecked = copy.deepcopy(evidence)
    unchecked["hosts"][0]["checklist"]["object_write_cutoff_verified"] = False
    future = copy.deepcopy(evidence)
    future["recorded_at"] = "2026-08-14T00:00:00Z"
    duplicated = copy.deepcopy(evidence)
    duplicated["hosts"].append(copy.deepcopy(duplicated["hosts"][0]))
    isolation_only = copy.deepcopy(evidence)
    isolation_only["hosts"][0]["terminal_kind"] = "ec2_isolation"
    for label, candidate in (
        ("an incomplete checklist", unchecked),
        ("a future recording time", future),
        ("a duplicated host attestation", duplicated),
        ("an EC2-isolation terminal kind", isolation_only),
    ):
        expect_proof_error(
            lambda candidate=candidate: parse(candidate),
            f"manual fence evidence with {label} was accepted",
        )
    expect_proof_error(
        lambda: parse(evidence, account="210987654321"),
        "manual fence evidence outside the reset account was accepted",
    )

    expect_proof_error(
        lambda: fence_verifier.verify(
            fence_receipt,
            dict(fence_expected, host_id="old-host-c"),
        ),
        "manual fence attestation for an unattested Host was accepted",
    )
    expect_proof_error(
        lambda: fence_verifier.verify(
            fence_receipt,
            dict(fence_expected, event_id="foreign-event"),
        ),
        "manual fence attestation with a foreign event ID was accepted",
    )
    expect_proof_error(
        lambda: fence_verifier.verify(
            fence_receipt,
            dict(fence_expected, components=["blockd"]),
        ),
        "manual fence attestation with drifted components was accepted",
    )
    expect_proof_error(
        lambda: fence_verifier.verify(stop_receipt, fence_expected),
        "manual fence attestation accepted a foreign staged receipt",
    )
    expect_proof_error(
        lambda: fence_verifier.verify(
            stop_receipt,
            dict(stop_expected, event_id="manual-fence-old-host-b"),
        ),
        "host_fence branch accepted a local positive-stop attestation",
    )
    expect_proof_error(
        lambda: stop_verifier.verify(fence_receipt, fence_expected),
        "local positive-stop branch accepted a fence attestation",
    )


def main() -> int:
    if not PROOF.version_one(1) or PROOF.version_one(True):
        raise AssertionError("closed contract version accepted a JSON boolean")
    if (
        len(PROOF.QUALIFICATION_PROOF_LOGICAL_FILES) != 19
        or len(set(PROOF.QUALIFICATION_PROOF_LOGICAL_FILES.values())) != 19
        or PROOF.QUALIFICATION_PROOF_LOGICAL_FILES["sha256sums"] != "SHA256SUMS"
    ):
        raise AssertionError("per-run qualification exact19 mapping drifted")
    expected_typed_digest = (
        "sha256:1ecc587146a29898f40be96fb88679c68106813997ce5778fc046c86388e2ec1"
    )
    typed_sources = (
        (
            "node/node-a/cat/cat-a",
            "epoch-a",
            "sha256:" + "1" * 64,
        ),
        (
            "node/node-b/cat/cat-b",
            "epoch-b",
            "sha256:" + "2" * 64,
        ),
    )
    actual_typed_digest = PROOF._usage_source_set_sha256(
        typed_sources
    )
    if actual_typed_digest != expected_typed_digest:
        raise AssertionError("Usage typed source-set digest ordering drifted")
    generic_sorted_digest = "sha256:" + hashlib.sha256(
        PROOF.canonical_json(PROOF._usage_sources_json(typed_sources))
    ).hexdigest()
    if actual_typed_digest == generic_sorted_digest:
        raise AssertionError("Usage typed digest silently became generic sorted JSON")

    manifest, targets, request, receipt, verification_file, context, runs, verification = fixture()
    PROOF._validate_global_usage_finalization(
        PROOF.decode_json(manifest.data, "manifest", canonical_lf=True),
        finalization_manifest=manifest,
        expected_targets=targets,
        expected_request=request,
        receipt=receipt,
        verification_file=verification_file,
        verification=verification,
        qualified_runs=runs,
        context=context,
    )
    baseline = PROOF.decode_json(request.data, "request", canonical_lf=True)
    candidates = []
    subset = copy.deepcopy(baseline)
    subset["sources"] = subset["sources"][:1]
    candidates.append(subset)
    foreign = copy.deepcopy(baseline)
    foreign["sources"][0]["receipt_sha256"] = SHA_D
    candidates.append(foreign)
    reordered = copy.deepcopy(baseline)
    reordered["sources"].reverse()
    candidates.append(reordered)
    wrong_epoch = copy.deepcopy(baseline)
    wrong_epoch["terminal_epoch_id"] = "f" * 32
    candidates.append(wrong_epoch)
    for candidate in candidates:
        try:
            validate_with_request(candidate)
        except PROOF.ProofSetError:
            continue
        raise AssertionError("foreign global Usage request was accepted")

    checksum_files = {
        "a.txt": opaque("staged-a", "a"),
        "b.txt": opaque("staged-b", "b"),
    }
    checksum_lines = [
        f"{checksum_files[name].sha256.removeprefix('sha256:')}  {name}\n"
        for name in sorted(checksum_files)
    ]
    PROOF._validate_sha256sums(
        "".join(checksum_lines).encode("ascii"),
        checksum_files,
        "fixture SHA256SUMS",
    )
    foreign_line = f"{'f' * 64}  foreign.txt\n"
    checksum_failures = (
        checksum_lines[:1],
        checksum_lines + [foreign_line],
        list(reversed(checksum_lines)),
        [f"{'f' * 64}  a.txt\n", checksum_lines[1]],
    )
    for lines in checksum_failures:
        try:
            PROOF._validate_sha256sums(
                "".join(lines).encode("ascii"),
                checksum_files,
                "fixture SHA256SUMS",
            )
        except PROOF.ProofSetError:
            continue
        raise AssertionError("non-closed per-run SHA256SUMS was accepted")
    validate_usage_targets_match_reset_targets()
    validate_inventory_is_observation_only()
    validate_qualification_fleet_cross_binding()
    validate_release_bound_usage_subprocess()
    validate_release_bound_usage_schema_subprocess()
    validate_release_manifest_catalog_cross_check()
    validate_route_v2_rotation_verifier()
    validate_qualification_admission_verifier()
    validate_manual_fence_evidence()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
