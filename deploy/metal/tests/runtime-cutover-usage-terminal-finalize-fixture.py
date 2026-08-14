#!/usr/bin/env python3
"""Calibrated fixtures for the global Usage finalizer's Closed gate."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import sys
import tempfile


if len(sys.argv) != 3:
    raise SystemExit(64)
finalizer = Path(sys.argv[1])
mode = sys.argv[2]
if mode not in {
    "positive",
    "emergency",
    "foreign",
    "extra",
    "missing",
    "nonzero",
}:
    raise SystemExit(64)

script = finalizer.read_text(encoding="utf-8")
try:
    support_source = script.split(
        "# QUALIFICATION_CLOSED_SUPPORT_BEGIN\n", 1
    )[1].split("# QUALIFICATION_CLOSED_SUPPORT_END\n", 1)[0]
except IndexError as error:
    raise SystemExit("Closed-support markers are unavailable") from error

DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
ID = re.compile(r"[A-Za-z0-9._:-]{1,128}\Z")
QUALIFICATION_BEGIN_FILE = "production-mutation-qualification-begin.receipt.json"
QUALIFICATION_TERMINAL_FILE = "production-mutation-qualification-terminal.receipt.json"
QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE = (
    "production-mutation-qualification-begin.command-receipt.json"
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
BASE_RUN_FILES = {
    "SHA256SUMS",
    "case-evidence.jsonl",
    "component-journal-summary.txt",
    "exit-code",
    "final-inventory.json",
    "manifest.json",
    "qualification-catalog.v1.json",
    "runtime-state.json",
    "scenario-results.jsonl",
}
QUALIFICATION_SUPPORT_FILES = {
    QUALIFICATION_BEGIN_FILE,
    QUALIFICATION_TERMINAL_FILE,
    "production-mutation-qualification-begin.pending.json",
    QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE,
    "production-mutation-qualification-close.pending.json",
    QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE,
    QUALIFICATION_FINAL_STATE_FILE,
    QUALIFICATION_FINAL_FLEET_FILE,
    QUALIFICATION_CLEANUP_INVENTORY_FILE,
    QUALIFICATION_PRODUCT_INVENTORY_FILE,
}
EXPECTED_RUN_FILES = BASE_RUN_FILES | QUALIFICATION_SUPPORT_FILES
QUALIFICATION_MUTATION_CLASSES = [
    "cat_create",
    "disk_create",
    "disk_delete",
    "runtime_mutation",
]
exact_commit = "d" * 40
release_sha256 = "sha256:" + "a" * 64
worker_bundle_sha256 = "sha256:" + "b" * 64
qualification_catalog_sha256 = "sha256:" + "c" * 64
WIRE_MAX = (1 << 64) - 1
COUNT_MAX = (1 << 63) - 1


class DuplicateKey(ValueError):
    pass


def closed_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise DuplicateKey(key)
        value[key] = item
    return value


def compact(value, *, ascii_only=False):
    return json.dumps(
        value,
        ensure_ascii=ascii_only,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def sha(value):
    return "sha256:" + hashlib.sha256(value).hexdigest()


def load_json(path, kind, maximum=1_048_576, canonical=None):
    raw = path.read_bytes()
    if not 1 <= len(raw) <= maximum:
        raise ValueError(f"{kind} exceeds its byte bound")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=closed_object)
    if canonical == "cats" and raw not in {compact(value), compact(value) + b"\n"}:
        raise ValueError(f"{kind} is not canonical Cats JSON")
    if canonical == "cats-no-lf" and raw != compact(value):
        raise ValueError(f"{kind} is not canonical Cats wire JSON")
    return value, raw


exec(compile(support_source, str(finalizer), "exec"), globals())


def payload(value):
    return compact(value)


def write(directory, filename, value):
    (directory / filename).write_bytes(payload(value))


def digest(character):
    return "sha256:" + character * 64


with tempfile.TemporaryDirectory() as temporary:
    directory = Path(temporary)
    run_id = "run-a"
    workspace_id = "workspace-a"
    block_path = "kernel-nbd"
    begin_command_id = "1" * 32
    close_command_id = "2" * 32

    binding = {
        "qualification_id": run_id,
        "deployment_id": "deployment-a",
        "release_id": "release-a",
        "source_commit_sha": exact_commit,
        "control_schema_version": 16,
        "source_manifest_sha256": digest("1"),
        "source_bundle_sha256": digest("2"),
        "build_receipt_sha256": digest("3"),
        "release_manifest_sha256": release_sha256,
        "worker_bundle_sha256": worker_bundle_sha256,
        "qualification_catalog_sha256": qualification_catalog_sha256,
        "qualification_cell_manifest_sha256": digest("4"),
        "aws_partition": "aws",
        "aws_account_id": "123456789012",
        "aws_region": "us-east-1",
        "cell_id": "cell-a",
        "cell_namespace": "cell-a.example",
        "cats_account_id": "account-a",
        "workspace_id": workspace_id,
        "allowed_mutation_classes": QUALIFICATION_MUTATION_CLASSES,
        "qualification_expires_at_unix_ms": 10_000,
    }
    state_binding = {"kind": "qualification", "binding": binding}
    binding_sha256 = sha(compact(state_binding))
    begin_command_receipt = {"fixture": "begin"}
    close_command_receipt = {"fixture": "close"}
    write(
        directory,
        QUALIFICATION_BEGIN_COMMAND_RECEIPT_FILE,
        begin_command_receipt,
    )
    write(
        directory,
        QUALIFICATION_CLOSE_COMMAND_RECEIPT_FILE,
        close_command_receipt,
    )

    final_state = {
        "version": 1,
        "revision": 3,
        "mode": "closed",
        "binding": state_binding,
        "last_command_id": close_command_id,
        "updated_at_unix_ms": 100,
    }
    fleet = {
        "kind": "cats.production-mutation-qualification-final-fleet-closed.v1",
        "version": 1,
        "qualification_id": run_id,
        "workspace_id": workspace_id,
        "source_commit_sha": exact_commit,
        "block_path": block_path,
        "evaluated_at_unix_ms": 130,
        "complete": True,
        "expected_node_ids": ["node-a"],
        "desired_runtime_count": 0,
        "current_runtime_observation_count": 0,
        "active_guard_count": 0,
        "residue_count": 0,
        "fleet_verification_receipt_sha256": digest("5"),
    }
    counts = {
        "current_cat_count": 0,
        "root_disk_count": 0,
        "persistent_disk_count": 0,
        "disk_snapshot_count": 0,
        "endpoint_count": 0,
        "hostname_desired_lookup_count": 0,
        "pending_runtime_operation_count": 0,
        "deleted_cat_tombstone_count": 1,
        "terminal_runtime_operation_history_count": 1,
        "api_idempotency_receipt_count": 1,
    }
    product_resource_count = 0
    if mode == "nonzero":
        counts["current_cat_count"] = 1
        product_resource_count = 1
    product = {
        "kind": "cats.production-mutation-qualification-product-inventory.v1",
        "version": 1,
        "qualification_id": run_id,
        "workspace_id": workspace_id,
        "release_id": "release-a",
        "source_commit_sha": exact_commit,
        "qualification_catalog_sha256": qualification_catalog_sha256,
        "binding_sha256": binding_sha256,
        "close_kind": "end_qualification",
        "close_command_id": close_command_id,
        "close_request_sha256": digest("6"),
        "close_command_receipt_sha256": sha(payload(close_command_receipt)),
        "closed_revision": 3,
        "evaluated_at_unix_ms": 110,
        "complete": True,
        "counts": counts,
        "product_resource_count": product_resource_count,
    }
    write(directory, QUALIFICATION_PRODUCT_INVENTORY_FILE, product)
    product_sha256 = sha(payload(product))
    cleanup = {
        "kind": "cats.production-mutation-qualification-cleanup-inventory.v1",
        "version": 1,
        "qualification_id": run_id,
        "workspace_id": workspace_id,
        "source_commit_sha": exact_commit,
        "block_path": block_path,
        "evaluated_at_unix_ms": 120,
        "complete": True,
        "product_inventory_receipt_sha256": product_sha256,
        "product_resource_count": product_resource_count,
        "desired_runtime_count": 0,
        "current_runtime_observation_count": 0,
        "active_guard_count": 0,
        "residue_count": 0,
    }
    write(directory, QUALIFICATION_CLEANUP_INVENTORY_FILE, cleanup)
    write(directory, QUALIFICATION_FINAL_STATE_FILE, final_state)
    write(directory, QUALIFICATION_FINAL_FLEET_FILE, fleet)

    begin = {
        "kind": "cats.production-mutation-qualification-begin-receipt.v1",
        "version": 1,
        "qualification_id": run_id,
        "workspace_id": workspace_id,
        "release_id": "release-a",
        "source_commit_sha": exact_commit,
        "qualification_catalog_sha256": qualification_catalog_sha256,
        "allowed_mutation_classes": QUALIFICATION_MUTATION_CLASSES,
        "binding_sha256": binding_sha256,
        "begin_command_id": begin_command_id,
        "begin_request_sha256": digest("7"),
        "begin_command_receipt_sha256": sha(payload(begin_command_receipt)),
        "resulting_revision": 2,
        "qualification_expires_at_unix_ms": 10_000,
    }
    write(directory, QUALIFICATION_BEGIN_FILE, begin)
    terminal = {
        "kind": "cats.production-mutation-qualification-terminal-receipt.v1",
        "version": 1,
        "qualification_id": run_id,
        "workspace_id": workspace_id,
        "release_id": "release-a",
        "source_commit_sha": exact_commit,
        "qualification_catalog_sha256": qualification_catalog_sha256,
        "allowed_mutation_classes": QUALIFICATION_MUTATION_CLASSES,
        "qualification_expires_at_unix_ms": 10_000,
        "binding_sha256": binding_sha256,
        "begin_command_id": begin_command_id,
        "begin_request_sha256": digest("7"),
        "begin_command_receipt_sha256": sha(payload(begin_command_receipt)),
        "begin_resulting_revision": 2,
        "close_kind": "end_qualification",
        "terminal_outcome": "qualified_closed",
        "close_command_id": close_command_id,
        "close_request_sha256": digest("6"),
        "close_command_receipt_sha256": sha(payload(close_command_receipt)),
        "final_admission_state_sha256": sha(payload(final_state)),
        "final_closed_revision": 3,
        "fleet_closed_receipt_sha256": sha(payload(fleet)),
        "product_inventory_receipt_sha256": product_sha256,
        "cleanup_inventory_receipt_sha256": sha(payload(cleanup)),
        "active_guard_count": 0,
        "product_resource_count": product_resource_count,
        "residue_count": 0,
        "completed_at_unix_ms": 130,
    }
    if mode == "emergency":
        terminal["close_kind"] = "emergency_close"
        terminal["terminal_outcome"] = "emergency_closed"
        product["close_kind"] = "emergency_close"
        write(directory, QUALIFICATION_PRODUCT_INVENTORY_FILE, product)
    if mode == "foreign":
        terminal["foreign"] = True
    write(directory, QUALIFICATION_TERMINAL_FILE, terminal)
    if mode == "missing":
        (directory / QUALIFICATION_PRODUCT_INVENTORY_FILE).unlink()

    begin_raw = (directory / QUALIFICATION_BEGIN_FILE).read_bytes()
    terminal_raw = (directory / QUALIFICATION_TERMINAL_FILE).read_bytes()
    manifest = {
        "qualification_admission_required_evidence": [
            {
                "filename": QUALIFICATION_BEGIN_FILE,
                "kind": "json",
                "sha256": sha(begin_raw),
                "size_bytes": len(begin_raw),
            },
            {
                "filename": QUALIFICATION_TERMINAL_FILE,
                "kind": "json",
                "sha256": sha(terminal_raw),
                "size_bytes": len(terminal_raw),
            },
        ]
    }

    rejected = False
    try:
        names = sorted(EXPECTED_RUN_FILES)
        if mode == "missing":
            names.remove(QUALIFICATION_PRODUCT_INVENTORY_FILE)
        if mode == "extra":
            names.append("foreign.json")
        validate_exact_run_file_names(names)
        validate_qualification_closed_support(
            directory,
            manifest,
            run_id,
            workspace_id,
            block_path,
        )
    except (OSError, ValueError):
        rejected = True
    if mode == "positive" and rejected:
        raise SystemExit("positive Closed fixture was rejected")
    if mode != "positive" and not rejected:
        raise SystemExit(f"negative {mode} fixture was accepted")
