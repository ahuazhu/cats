#!/usr/bin/env python3
"""Focused synthetic regressions for the E13 global Usage outer binding."""

from __future__ import annotations

import copy
import hashlib
import importlib.util
from pathlib import Path
import sys
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
        "release_a",
        COMMIT,
        SHA_A,
        "sha256:" + "2" * 64,
        SHA_B,
        SHA_C,
        SHA_D,
        {},
        {},
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


def main() -> int:
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
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
