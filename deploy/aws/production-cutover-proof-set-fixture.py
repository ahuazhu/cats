#!/usr/bin/env python3
"""Focused synthetic regressions for E13 proof and operator boundaries."""

from __future__ import annotations

import copy
import dataclasses
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


def fixture() -> tuple[Any, Any, Any, Any, Any, Any, tuple[Any, Any], dict[str, Any]]:
    targets = verified(
        PROOF.USAGE_TERMINAL_TARGETS_FILE,
        {"fresh_target": {}, "old_target": {}, "shards": [], "version": 1},
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
        "fresh_target": {},
        "old_target": {},
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
        "target_binding_sha256": SHA_C,
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
        old_targets={},
        fresh_targets={},
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
            output.write_bytes(
                PROOF.canonical_json(
                    {
                        "binary_sha256": executable_sha256,
                        "catalog_sha256": PROOF.USAGE_SCHEMA_CATALOG_SHA256,
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
            )
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
        finally:
            PROOF.USAGE_SCHEMA_VERIFIER = original_binary
            PROOF._require_root_private_directory = original_private_directory
            PROOF._open_release_bound_executable = original_open_executable
            PROOF._run_held_usage_verifier = original_run


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
    validate_inventory_is_observation_only()
    validate_release_bound_usage_subprocess()
    validate_release_bound_usage_schema_subprocess()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
