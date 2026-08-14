#!/usr/bin/env python3
"""Apply one reviewed G3 saved plan and publish an authenticated current receipt.

This executable belongs on the approved deployment controller/workspace.  The
qualification worker never invokes Terraform and never receives provider
credentials.  A Terraform exit status is not settlement: every path performs
fresh Route-rotation current discovery before a signed receipt can exist.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import re
import signal
import ssl
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import SplitResult, urlsplit

import validate_route_v2_control_rollout_plan as plan_validator


MAX_HTTP_BYTES = 32 * 1024
MAX_APPLY_LOG_BYTES = 8 * 1024 * 1024
MAX_DESCRIPTOR_BYTES = 1024 * 1024
MAX_CLI_OUTPUT_BYTES = 1024 * 1024
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
COMMIT = re.compile(r"[0-9a-f]{40}")
RUN_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
PHASE_REVISIONS = {
    "publish_overlap": 2,
    "switch_active": 3,
    "publish_new_only": 4,
    "retire": 5,
    "disable": 6,
    "publish_recovery": 7,
    "activate": 8,
}
CURRENT_PATH = "/v1/internal/route-v2/signing-authority-current"


class Rejected(ValueError):
    """One authority input, external result or recovery transition is unsafe."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Apply one reviewed Route v2 Control rollout on the deployment controller."
    )
    parser.add_argument("--terraform", required=True, type=Path)
    parser.add_argument("--terraform-working-directory", required=True, type=Path)
    parser.add_argument("--saved-plan", required=True, type=Path)
    parser.add_argument("--command-bundle", required=True, type=Path)
    parser.add_argument("--previous-rollout-reference", required=True, type=Path)
    parser.add_argument("--successor-rollout-reference", required=True, type=Path)
    parser.add_argument("--plan-validation-receipt", required=True, type=Path)
    parser.add_argument("--recovery-transport", required=True, type=Path)
    parser.add_argument("--server-ca-bundle", required=True, type=Path)
    parser.add_argument("--operator-trust", required=True, type=Path)
    parser.add_argument(
        "--operator-private-key", required=True, action="append", type=Path
    )
    parser.add_argument("--cats", required=True, type=Path)
    parser.add_argument("--phase", required=True, choices=tuple(PHASE_REVISIONS))
    parser.add_argument("--state-directory", required=True, type=Path)
    parser.add_argument(
        "--apply-timeout-seconds", type=int, default=900, choices=range(1, 1801)
    )
    parser.add_argument(
        "--discovery-timeout-seconds", type=int, default=180, choices=range(1, 601)
    )
    parser.add_argument(
        "--recover-ambiguous",
        action="store_true",
        help="Never reapply an existing pending attempt; settle it by exact discovery.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        produce(args)
    except (OSError, Rejected, subprocess.SubprocessError) as error:
        # Error text deliberately never includes an inbox URL or response body.
        print(f"reject: {error}", file=sys.stderr)
        return 1
    print("route_v2_control_rollout_apply_receipt=published")
    return 0


def produce(args: argparse.Namespace) -> None:
    deployment_operator_path = Path(os.path.abspath(__file__))
    validator_path = Path(os.path.abspath(plan_validator.__file__))
    expected_validator_path = deployment_operator_path.with_name(
        "validate_route_v2_control_rollout_plan.py"
    )
    if validator_path != expected_validator_path:
        raise Rejected("saved-plan validator is not the exact sibling release input")
    deployment_operator_bytes = plan_validator.checked_file(
        deployment_operator_path, private=False, executable=True
    )
    validator_bytes = plan_validator.checked_file(
        validator_path, private=False, executable=True
    )
    terraform_bytes = plan_validator.checked_file(
        args.terraform, private=False, executable=True
    )
    cats_bytes = plan_validator.checked_file(args.cats, private=False, executable=True)
    saved_plan_bytes = plan_validator.checked_file(args.saved_plan, private=True)
    bundle_bytes = plan_validator.checked_file(args.command_bundle, private=True)
    previous_bytes = plan_validator.checked_file(
        args.previous_rollout_reference, private=True
    )
    successor_bytes = plan_validator.checked_file(
        args.successor_rollout_reference, private=True
    )
    validation_bytes = plan_validator.checked_file(
        args.plan_validation_receipt, private=True
    )
    descriptor_bytes = checked_file(
        args.recovery_transport, private=True, maximum=MAX_DESCRIPTOR_BYTES
    )
    ca_bytes = checked_file(
        args.server_ca_bundle, private=False, maximum=MAX_DESCRIPTOR_BYTES
    )
    trust_bytes = checked_file(
        args.operator_trust, private=False, maximum=MAX_DESCRIPTOR_BYTES
    )
    for private_key in args.operator_private_key:
        checked_file(private_key, private=True, maximum=64 * 1024)
    checked_directory(args.terraform_working_directory)
    state_directory = checked_state_directory(args.state_directory)

    bundle = plan_validator.canonical_object(bundle_bytes, "command bundle")
    if digest(trust_bytes) != bundle.get("rotation_operator_trust_sha256"):
        raise Rejected("operator trust differs from the release-bound command bundle")
    previous = plan_validator.rollout_reference(
        previous_bytes, "previous rollout reference"
    )
    successor = plan_validator.rollout_reference(
        successor_bytes, "successor rollout reference"
    )
    plan_validator.validate_lineage(previous, successor, bundle)
    phase = exact_phase(bundle, args.phase, successor)
    descriptor = recovery_descriptor(descriptor_bytes, bundle, ca_bytes)
    descriptor_phase = descriptor_phase_entry(descriptor, args.phase)
    enforce_phase_order(
        args,
        state_directory,
        descriptor,
        args.server_ca_bundle,
        cats_bytes,
    )

    plan_json = plan_validator.terraform_show(args.terraform, args.saved_plan)
    plan = plan_validator.canonical_object(
        plan_json, "Terraform show JSON", require_canonical=False
    )
    plan_validator.validate_plan(plan, previous, successor)
    expected_validation = plan_validator.build_receipt(
        bundle,
        previous,
        successor,
        terraform_bytes,
        saved_plan_bytes,
        plan_json,
    )
    validation = plan_validator.canonical_object(
        validation_bytes, "plan validation receipt"
    )
    if validation != expected_validation:
        raise Rejected("plan validation receipt differs from fresh closed-plan validation")
    if (
        descriptor_phase["saved_plan_sha256"] != digest(saved_plan_bytes)
        or descriptor_phase["plan_validation_receipt_sha256"]
        != digest(validation_bytes)
    ):
        raise Rejected("recovery descriptor does not freeze the exact reviewed plan")
    rollout_required_bytes = wait_for_rollout_requirement(
        args,
        state_directory,
        descriptor,
        bundle,
        previous,
        phase,
    )

    attempt = apply_once_or_recover(
        args,
        state_directory,
        descriptor,
        descriptor_phase,
        saved_plan_bytes,
        validation_bytes,
        rollout_required_bytes,
    )
    current_bytes, current = discover_exact_current(
        descriptor,
        args.server_ca_bundle,
        phase,
        bundle,
        successor,
        args.discovery_timeout_seconds,
    )
    outcome = (
        "succeeded"
        if attempt["returncode"] == 0 and not attempt["recovered_ambiguous"]
        else "ambiguous_resolved_current"
    )
    payload = build_apply_payload(
        bundle,
        descriptor,
        descriptor_phase,
        phase,
        successor,
        expected_validation,
        validation_bytes,
        attempt,
        outcome,
        current_bytes,
        current,
        deployment_operator_bytes,
        validator_bytes,
        cats_bytes,
    )
    payload_bytes = compact_bytes(payload)
    payload_path = state_directory / f"{args.phase}.apply-receipt-payload.v1.json"
    signed_path = state_directory / f"{args.phase}.apply-receipt.signed.v1.json"
    publish_exact(payload_path, payload_bytes)
    sign_with_cats(
        args.cats,
        args.operator_trust,
        args.operator_private_key,
        payload_path,
        signed_path,
        cats_bytes,
    )
    if (
        digest(
            plan_validator.checked_file(
                deployment_operator_path, private=False, executable=True
            )
        )
        != digest(deployment_operator_bytes)
        or digest(
            plan_validator.checked_file(
                validator_path, private=False, executable=True
            )
        )
        != digest(validator_bytes)
    ):
        raise Rejected("deployment operator release inputs changed during execution")
    signed_bytes = checked_file(
        signed_path, private=True, maximum=MAX_HTTP_BYTES
    )
    publish_inbox(
        descriptor,
        descriptor_phase,
        args.server_ca_bundle,
        signed_bytes,
    )


def checked_file(
    path: Path,
    *,
    private: bool,
    maximum: int,
    executable: bool = False,
    allow_empty: bool = False,
) -> bytes:
    if not path.is_absolute():
        raise Rejected("input path is not absolute")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        before = os.fstat(descriptor)
        mode = stat.S_IMODE(before.st_mode)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_nlink != 1
            or (private and mode != 0o600)
            or (not private and mode & 0o022 != 0)
            or (executable and mode & 0o111 == 0)
        ):
            raise Rejected("input file contract rejected")
        chunks: list[bytes] = []
        size = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - size))
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
            if size > maximum:
                raise Rejected("input exceeds its closed byte limit")
        after = os.fstat(descriptor)
        if plan_validator.inode_identity(before) != plan_validator.inode_identity(after):
            raise Rejected("input changed while read")
        value = b"".join(chunks)
        if not value and not allow_empty:
            raise Rejected("input is empty")
        return value
    finally:
        os.close(descriptor)


def checked_directory(path: Path) -> None:
    if not path.is_absolute():
        raise Rejected("working directory is not absolute")
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o022 != 0
        ):
            raise Rejected("working directory contract rejected")
    finally:
        os.close(descriptor)


def checked_state_directory(path: Path) -> Path:
    if not path.is_absolute() or path == Path("/"):
        raise Rejected("state directory must be absolute and non-root")
    if not path.exists():
        parent = path.parent
        checked_directory(parent)
        os.mkdir(path, 0o700)
        sync_directory(parent)
    checked_directory(path)
    mode = stat.S_IMODE(os.stat(path, follow_symlinks=False).st_mode)
    if mode != 0o700:
        raise Rejected("state directory must have exact mode 0700")
    return path


def compact_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def canonical_sorted_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{label} is not JSON") from error
    if not isinstance(value, dict):
        raise Rejected(f"{label} is not one object")
    expected = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    if expected != data:
        raise Rejected(f"{label} is not sorted canonical JSON")
    return value


def recovery_descriptor(
    data: bytes, bundle: dict[str, Any], ca_bytes: bytes
) -> dict[str, Any]:
    value = canonical_sorted_object(data, "recovery transport descriptor")
    required = {
        "version",
        "kind",
        "case_id",
        "qualification_run_id",
        "source_commit_sha",
        "qualification_catalog_sha256",
        "authority_id",
        "route_deployment_id",
        "rotation_operator_trust_sha256",
        "rotation_origin",
        "rotation_server_name",
        "receipt_inbox_server_name",
        "server_ca_bundle_sha256",
        "immutability_mode",
        "phases",
    }
    phases = value.get("phases")
    if (
        set(value) != required
        or value.get("version") != 1
        or value.get("kind") != "route_v2_rotation_recovery_transport_v1"
        or value.get("case_id") != bundle["case_id"]
        or value.get("qualification_run_id") != bundle["qualification_run_id"]
        or value.get("source_commit_sha") != bundle["source_commit_sha"]
        or RUN_ID.fullmatch(value.get("qualification_run_id", "")) is None
        or COMMIT.fullmatch(value.get("source_commit_sha", "")) is None
        or value.get("authority_id") != bundle["rotation_operator_authority_id"]
        or value.get("route_deployment_id") != bundle["route_deployment_id"]
        or value.get("rotation_operator_trust_sha256")
        != bundle["rotation_operator_trust_sha256"]
        or not isinstance(value.get("qualification_catalog_sha256"), str)
        or SHA256.fullmatch(value["qualification_catalog_sha256"]) is None
        or value.get("server_ca_bundle_sha256") != digest(ca_bytes)
        or value.get("immutability_mode") != "create_only_no_delete_v1"
        or not valid_server_name(value.get("rotation_server_name"))
        or not valid_server_name(value.get("receipt_inbox_server_name"))
        or not isinstance(phases, list)
        or len(phases) != len(PHASE_REVISIONS)
    ):
        raise Rejected("recovery transport descriptor identity is malformed")
    checked_https_url(
        value.get("rotation_origin"), value["rotation_server_name"], origin_only=True
    )
    if [phase.get("phase") for phase in phases if isinstance(phase, dict)] != list(
        PHASE_REVISIONS
    ):
        raise Rejected("recovery descriptor phases are not exact and ordered")
    for phase in phases:
        if not isinstance(phase, dict) or set(phase) != {
            "phase",
            "signer_revision",
            "saved_plan_sha256",
            "plan_validation_receipt_sha256",
            "receipt_url",
            "receipt_url_sha256",
        }:
            raise Rejected("recovery descriptor phase has the wrong field set")
        name = phase["phase"]
        url = phase.get("receipt_url")
        if (
            phase.get("signer_revision") != PHASE_REVISIONS[name]
            or not isinstance(phase.get("saved_plan_sha256"), str)
            or SHA256.fullmatch(phase["saved_plan_sha256"]) is None
            or not isinstance(phase.get("plan_validation_receipt_sha256"), str)
            or SHA256.fullmatch(phase["plan_validation_receipt_sha256"]) is None
            or not isinstance(url, str)
            or phase.get("receipt_url_sha256") != digest(url.encode("utf-8"))
        ):
            raise Rejected("recovery descriptor phase is malformed")
        checked_https_url(url, value["receipt_inbox_server_name"], origin_only=False)
    return value


def valid_server_name(value: Any) -> bool:
    return (
        isinstance(value, str)
        and 1 <= len(value) <= 253
        and re.fullmatch(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?", value) is not None
    )


def checked_https_url(value: Any, server_name: str, *, origin_only: bool) -> SplitResult:
    if not isinstance(value, str) or len(value) > 2048:
        raise Rejected("HTTPS coordinate is malformed")
    split = urlsplit(value)
    try:
        port = split.port
    except ValueError as error:
        raise Rejected("HTTPS coordinate port is malformed") from error
    if (
        split.scheme != "https"
        or split.hostname != server_name
        or split.username is not None
        or split.password is not None
        or split.query
        or split.fragment
        or (origin_only and split.path != "")
        or (not origin_only and (not split.path.startswith("/") or split.path == "/"))
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise Rejected("HTTPS coordinate does not bind the fixed server identity")
    return split


def descriptor_phase_entry(
    descriptor: dict[str, Any], phase: str
) -> dict[str, Any]:
    matches = [entry for entry in descriptor["phases"] if entry["phase"] == phase]
    if len(matches) != 1:
        raise Rejected("recovery descriptor does not contain one exact phase")
    return matches[0]


def enforce_phase_order(
    args: argparse.Namespace,
    state_directory: Path,
    descriptor: dict[str, Any],
    ca_path: Path,
    cats_bytes: bytes,
) -> None:
    phases = [entry["phase"] for entry in descriptor["phases"]]
    index = phases.index(args.phase)
    state_suffixes = (
        "terraform-apply.pending.v1.json",
        "terraform-apply.completed.v1.json",
        "terraform-apply.stdout",
        "terraform-apply.stderr",
        "apply-receipt-payload.v1.json",
        "apply-receipt.signed.v1.json",
        "apply-receipt.prior-verification.v1.json",
        "rollout-required-current.v1.json",
    )
    for future in descriptor["phases"][index + 1 :]:
        if any(
            (state_directory / f"{future['phase']}.{suffix}").exists()
            for suffix in state_suffixes
        ):
            raise Rejected("future rollout state exists before the requested phase")
        future_body = https_request(
            future["receipt_url"],
            descriptor["receipt_inbox_server_name"],
            ca_path,
            "GET",
            None,
            expected=(404,),
        )
        if future_body:
            raise Rejected("absent future rollout receipt returned a body")

    for previous in descriptor["phases"][:index]:
        phase_name = previous["phase"]
        signed_path = state_directory / f"{phase_name}.apply-receipt.signed.v1.json"
        signed_bytes = checked_file(
            signed_path, private=True, maximum=MAX_DESCRIPTOR_BYTES
        )
        published = https_request(
            previous["receipt_url"],
            descriptor["receipt_inbox_server_name"],
            ca_path,
            "GET",
            None,
            expected=(200,),
        )
        if published != signed_bytes:
            raise Rejected("prior rollout receipt inbox bytes differ from controller state")
        verification_path = (
            state_directory / f"{phase_name}.apply-receipt.prior-verification.v1.json"
        )
        command = [
            os.fspath(args.cats),
            "--json",
            "admin",
            "runtime-provisioner",
            "route-v2-r1",
            "verify-control-rollout-apply-receipt",
            "--trust",
            os.fspath(args.operator_trust),
            "--command-bundle",
            os.fspath(args.command_bundle),
            "--phase",
            phase_name,
            "--qualification-catalog-sha256",
            descriptor["qualification_catalog_sha256"],
            "--saved-plan-sha256",
            previous["saved_plan_sha256"],
            "--receipt",
            os.fspath(signed_path),
            "--output",
            os.fspath(verification_path),
        ]
        completed = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={"PATH": "/usr/bin:/bin", "HOME": "/nonexistent"},
            timeout=30,
            check=False,
        )
        if (
            completed.returncode != 0
            or len(completed.stdout) > MAX_CLI_OUTPUT_BYTES
            or len(completed.stderr) > MAX_CLI_OUTPUT_BYTES
            or digest(
                plan_validator.checked_file(
                    args.cats, private=False, executable=True
                )
            )
            != digest(cats_bytes)
        ):
            raise Rejected("prior rollout receipt failed release-bound verification")
        verification_bytes = checked_file(
            verification_path, private=True, maximum=MAX_DESCRIPTOR_BYTES
        )
        verification = canonical_compact_object(
            verification_bytes, "prior rollout receipt verification"
        )
        try:
            report = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise Rejected("prior rollout receipt verifier report is malformed") from error
        if (
            report != verification
            or verification.get("case_id") != descriptor["case_id"]
            or verification.get("qualification_run_id")
            != descriptor["qualification_run_id"]
            or verification.get("source_commit_sha") != descriptor["source_commit_sha"]
            or verification.get("qualification_catalog_sha256")
            != descriptor["qualification_catalog_sha256"]
            or verification.get("phase") != phase_name
            or verification.get("signer_revision") != previous["signer_revision"]
            or verification.get("saved_plan_sha256")
            != previous["saved_plan_sha256"]
            or verification.get("receipt_signer_executable_sha256")
            != digest(cats_bytes)
            or verification.get("exact_signed_receipt_sha256")
            != digest(signed_bytes)
            or verification.get("terminal_marker") != "current_process_bound"
        ):
            raise Rejected("prior rollout receipt does not bind the exact ordered run")


def wait_for_rollout_requirement(
    args: argparse.Namespace,
    state_directory: Path,
    descriptor: dict[str, Any],
    bundle: dict[str, Any],
    previous: dict[str, Any],
    phase: dict[str, Any],
) -> bytes:
    output = state_directory / f"{args.phase}.rollout-required-current.v1.json"
    if output.exists():
        installed = checked_file(output, private=True, maximum=MAX_DESCRIPTOR_BYTES)
        current = canonical_compact_object(installed, "rollout-required current discovery")
        if not predecessor_requires_rollout(
            current, bundle, previous, args.phase, phase
        ):
            raise Rejected("durable rollout requirement does not bind the exact predecessor")
        return installed

    deadline = time.monotonic() + args.discovery_timeout_seconds
    while time.monotonic() < deadline:
        try:
            body = https_request(
                descriptor["rotation_origin"] + CURRENT_PATH,
                descriptor["rotation_server_name"],
                args.server_ca_bundle,
                "GET",
                None,
                expected=(200,),
            )
            current = canonical_compact_object(body, "rollout-required current discovery")
            if predecessor_requires_rollout(
                current, bundle, previous, args.phase, phase
            ):
                publish_exact(output, body)
                return body
        except Rejected:
            pass
        time.sleep(1)
    raise Rejected("Control never proved the exact stale predecessor requiring this rollout")


def predecessor_requires_rollout(
    current: dict[str, Any],
    bundle: dict[str, Any],
    previous: dict[str, Any],
    phase_name: str,
    phase: dict[str, Any],
) -> bool:
    expected_signer, expected_ring_version = predecessor_process_coordinate(
        bundle, phase_name, phase
    )
    expected_state = expected_signer.get("state")
    expected_active_kid = (
        expected_signer.get("active_kid") if expected_state == "active" else None
    )
    return (
        set(current)
        == {
            "version",
            "authority_id",
            "route_deployment_id",
            "release_commit_sha",
            "rotation_operator_trust_sha256",
            "loaded_signer_revision",
            "loaded_signer_reference_sha256",
            "loaded_signer_state",
            "loaded_active_kid",
            "loaded_public_key_ring_version",
            "loaded_public_key_ring_digest",
            "database_current",
            "process_ready",
        }
        and current.get("version") == 1
        and current.get("authority_id") == bundle["rotation_operator_authority_id"]
        and current.get("route_deployment_id") == bundle["route_deployment_id"]
        and current.get("release_commit_sha") == bundle["source_commit_sha"]
        and current.get("rotation_operator_trust_sha256")
        == bundle["rotation_operator_trust_sha256"]
        and current.get("loaded_signer_revision") == previous["signer_revision"]
        and current.get("loaded_signer_reference_sha256")
        == previous["signer_reference_sha256"]
        and current.get("loaded_signer_state") == expected_state
        and current.get("loaded_active_kid") == expected_active_kid
        and current.get("loaded_public_key_ring_version") == expected_ring_version
        and current.get("loaded_public_key_ring_digest")
        == previous["public_key_ring_digest"]
        and current.get("database_current") is False
        and current.get("process_ready") is False
    )


def predecessor_process_coordinate(
    bundle: dict[str, Any], phase_name: str, phase: dict[str, Any]
) -> tuple[dict[str, Any], int]:
    phases = [entry["phase"] for entry in bundle["commands"]]
    index = phases.index(phase_name)
    if index == 0:
        successor = phase["successor"]
        ring_version = successor.get("public_key_ring_version")
        signer = successor.get("signer")
        if (
            not isinstance(ring_version, int)
            or isinstance(ring_version, bool)
            or ring_version <= 1
            or not isinstance(signer, dict)
        ):
            raise Rejected("first rollout command cannot identify its exact predecessor")
        # PublishOverlap retains the installed signer and advances exactly one
        # ring version.  The offline bundle verifier enforces that lineage.
        return signer, ring_version - 1

    prior = bundle["commands"][index - 1]
    try:
        command = json.loads(prior["exact_authority_command_json"])
        successor = command["successor"]
        signer = successor["signer"]
        ring_version = successor["public_key_ring_version"]
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise Rejected("prior rollout command cannot identify its process coordinate") from error
    if (
        not isinstance(signer, dict)
        or signer.get("state") not in {"active", "disabled"}
        or not isinstance(ring_version, int)
        or isinstance(ring_version, bool)
        or ring_version <= 0
    ):
        raise Rejected("prior rollout process coordinate is malformed")
    return signer, ring_version


def exact_phase(
    bundle: dict[str, Any], phase_name: str, successor: dict[str, Any]
) -> dict[str, Any]:
    matches = [entry for entry in bundle["commands"] if entry.get("phase") == phase_name]
    if len(matches) != 1:
        raise Rejected("command bundle does not contain one exact requested phase")
    entry = matches[0]
    if entry.get("signer_revision") != successor["signer_revision"]:
        raise Rejected("requested phase and successor rollout revision differ")
    try:
        command = json.loads(entry["exact_authority_command_json"])
    except (KeyError, TypeError, json.JSONDecodeError) as error:
        raise Rejected("requested authority command is malformed") from error
    if compact_bytes(command).decode("ascii") != entry["exact_authority_command_json"]:
        raise Rejected("requested authority command is not canonical")
    successor_reference = command.get("successor")
    if not isinstance(successor_reference, dict):
        raise Rejected("requested command has no successor reference")
    return {"entry": entry, "command": command, "successor": successor_reference}


def apply_once_or_recover(
    args: argparse.Namespace,
    state_directory: Path,
    descriptor: dict[str, Any],
    descriptor_phase: dict[str, Any],
    saved_plan_bytes: bytes,
    validation_bytes: bytes,
    rollout_required_bytes: bytes,
) -> dict[str, Any]:
    pending_path = state_directory / f"{args.phase}.terraform-apply.pending.v1.json"
    completed_path = state_directory / f"{args.phase}.terraform-apply.completed.v1.json"
    stdout_path = state_directory / f"{args.phase}.terraform-apply.stdout"
    stderr_path = state_directory / f"{args.phase}.terraform-apply.stderr"
    pending = {
        "version": 1,
        "case_id": descriptor["case_id"],
        "qualification_run_id": descriptor["qualification_run_id"],
        "source_commit_sha": descriptor["source_commit_sha"],
        "qualification_catalog_sha256": descriptor[
            "qualification_catalog_sha256"
        ],
        "phase": args.phase,
        "signer_revision": descriptor_phase["signer_revision"],
        "saved_plan_sha256": digest(saved_plan_bytes),
        "plan_validation_receipt_sha256": digest(validation_bytes),
        "rollout_required_current_sha256": digest(rollout_required_bytes),
        "started_at_unix_ms": unix_millis(),
    }
    if pending_path.exists():
        installed = canonical_sorted_object(
            checked_file(pending_path, private=True, maximum=MAX_DESCRIPTOR_BYTES),
            "pending apply record",
        )
        expected = dict(pending)
        expected["started_at_unix_ms"] = installed.get("started_at_unix_ms")
        if installed != expected:
            raise Rejected("existing pending apply record differs from this exact phase")
        if not completed_path.exists() and not args.recover_ambiguous:
            raise Rejected(
                "pending apply has no completion; require explicit --recover-ambiguous discovery"
            )
        pending = installed
    else:
        if args.recover_ambiguous:
            raise Rejected("cannot recover ambiguity without a durable pending apply record")
        publish_sorted_exact(pending_path, pending)

    if completed_path.exists():
        completed = canonical_sorted_object(
            checked_file(completed_path, private=True, maximum=MAX_DESCRIPTOR_BYTES),
            "completed apply record",
        )
        if (
            set(completed)
            != {
                "version",
                "phase",
                "returncode",
                "completed_at_unix_ms",
                "recovered_ambiguous",
            }
            or completed.get("version") != 1
            or completed.get("phase") != args.phase
            or not isinstance(completed.get("returncode"), int)
            or isinstance(completed.get("returncode"), bool)
            or not isinstance(completed.get("completed_at_unix_ms"), int)
            or completed["completed_at_unix_ms"] < pending["started_at_unix_ms"]
            or not isinstance(completed.get("recovered_ambiguous"), bool)
        ):
            raise Rejected("completed apply record is malformed")
    elif args.recover_ambiguous:
        # Exclusive controller/workspace ownership is a precondition of this
        # explicit recovery mode.  It never launches Terraform a second time.
        completed = {
            "version": 1,
            "phase": args.phase,
            "returncode": -1,
            "completed_at_unix_ms": unix_millis(),
            "recovered_ambiguous": True,
        }
        publish_sorted_exact(completed_path, completed)
    else:
        returncode = run_terraform_apply(
            args.terraform,
            args.saved_plan,
            args.terraform_working_directory,
            stdout_path,
            stderr_path,
            args.apply_timeout_seconds,
        )
        completed = {
            "version": 1,
            "phase": args.phase,
            "returncode": returncode,
            "completed_at_unix_ms": unix_millis(),
            "recovered_ambiguous": returncode != 0,
        }
        publish_sorted_exact(completed_path, completed)

    stdout = checked_file(
        stdout_path, private=True, maximum=MAX_APPLY_LOG_BYTES, allow_empty=True
    )
    stderr = checked_file(
        stderr_path, private=True, maximum=MAX_APPLY_LOG_BYTES, allow_empty=True
    )
    return {
        "started_at_unix_ms": pending["started_at_unix_ms"],
        "completed_at_unix_ms": completed["completed_at_unix_ms"],
        "returncode": completed["returncode"],
        "recovered_ambiguous": completed["recovered_ambiguous"],
        "stdout_sha256": digest(stdout),
        "stderr_sha256": digest(stderr),
    }


def run_terraform_apply(
    terraform: Path,
    saved_plan: Path,
    working_directory: Path,
    stdout_path: Path,
    stderr_path: Path,
    timeout_seconds: int,
) -> int:
    stdout = exclusive_output(stdout_path)
    try:
        stderr = exclusive_output(stderr_path)
    except BaseException:
        stdout.close()
        raise
    environment = os.environ.copy()
    environment.update(
        {
            "TF_IN_AUTOMATION": "1",
            "CHECKPOINT_DISABLE": "1",
        }
    )
    process: subprocess.Popen[bytes] | None = None
    try:
        process = subprocess.Popen(
            [
                os.fspath(terraform),
                "apply",
                "-input=false",
                "-no-color",
                os.fspath(saved_plan),
            ],
            cwd=working_directory,
            stdin=subprocess.DEVNULL,
            stdout=stdout,
            stderr=stderr,
            env=environment,
            start_new_session=True,
        )
        try:
            return process.wait(timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            terminate_process_group(process)
            return 124
    finally:
        if process is not None and process.poll() is None:
            terminate_process_group(process)
        stdout.flush()
        stderr.flush()
        os.fsync(stdout.fileno())
        os.fsync(stderr.fileno())
        stdout.close()
        stderr.close()
        sync_directory(stdout_path.parent)
        for path in (stdout_path, stderr_path):
            if path.stat().st_size > MAX_APPLY_LOG_BYTES:
                raise Rejected("Terraform apply output exceeds the closed byte bound")


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=10)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait(timeout=10)


def exclusive_output(path: Path):
    if not path.is_absolute() or path.exists():
        raise Rejected("apply output must be an absent absolute path")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    os.fchmod(descriptor, 0o600)
    return os.fdopen(descriptor, "wb", buffering=0)


def discover_exact_current(
    descriptor: dict[str, Any],
    ca_path: Path,
    phase: dict[str, Any],
    bundle: dict[str, Any],
    rollout: dict[str, Any],
    timeout_seconds: int,
) -> tuple[bytes, dict[str, Any]]:
    deadline = time.monotonic() + timeout_seconds
    last: tuple[bytes, dict[str, Any]] | None = None
    while time.monotonic() < deadline:
        try:
            body = https_request(
                descriptor["rotation_origin"] + CURRENT_PATH,
                descriptor["rotation_server_name"],
                ca_path,
                "GET",
                None,
                expected=(200,),
            )
            value = canonical_compact_object(body, "current discovery")
            last = (body, value)
            if current_is_exact(value, phase, bundle, rollout):
                return body, value
        except Rejected:
            pass
        time.sleep(1)
    if last is not None:
        raise Rejected("fresh current discovery never matched the exact successor")
    raise Rejected("fresh current discovery remained unavailable")


def canonical_compact_object(data: bytes, label: str) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{label} is not JSON") from error
    if not isinstance(value, dict) or compact_bytes(value) != data:
        raise Rejected(f"{label} is not canonical JSON")
    return value


def current_is_exact(
    current: dict[str, Any],
    phase: dict[str, Any],
    bundle: dict[str, Any],
    rollout: dict[str, Any],
) -> bool:
    successor = phase["successor"]
    signer = successor.get("signer")
    if not isinstance(signer, dict):
        return False
    state = signer.get("state")
    active_kid = signer.get("active_kid") if state == "active" else None
    return (
        set(current)
        == {
            "version",
            "authority_id",
            "route_deployment_id",
            "release_commit_sha",
            "rotation_operator_trust_sha256",
            "loaded_signer_revision",
            "loaded_signer_reference_sha256",
            "loaded_signer_state",
            "loaded_active_kid",
            "loaded_public_key_ring_version",
            "loaded_public_key_ring_digest",
            "database_current",
            "process_ready",
        }
        and current.get("version") == 1
        and current.get("authority_id") == bundle["rotation_operator_authority_id"]
        and current.get("route_deployment_id") == bundle["route_deployment_id"]
        and current.get("release_commit_sha") == bundle["source_commit_sha"]
        and current.get("rotation_operator_trust_sha256")
        == bundle["rotation_operator_trust_sha256"]
        and current.get("loaded_signer_revision") == rollout["signer_revision"]
        and current.get("loaded_signer_reference_sha256")
        == rollout["signer_reference_sha256"]
        and current.get("loaded_signer_state") == state
        and current.get("loaded_active_kid") == active_kid
        and current.get("loaded_public_key_ring_version")
        == successor.get("public_key_ring_version")
        and current.get("loaded_public_key_ring_digest")
        == rollout["public_key_ring_digest"]
        and current.get("database_current") is True
        and current.get("process_ready") is (state == "active")
    )


def build_apply_payload(
    bundle: dict[str, Any],
    descriptor: dict[str, Any],
    descriptor_phase: dict[str, Any],
    phase: dict[str, Any],
    rollout: dict[str, Any],
    plan_receipt: dict[str, Any],
    plan_receipt_bytes: bytes,
    attempt: dict[str, Any],
    outcome: str,
    current_bytes: bytes,
    current: dict[str, Any],
    deployment_operator_bytes: bytes,
    validator_bytes: bytes,
    cats_bytes: bytes,
) -> dict[str, Any]:
    successor = phase["successor"]
    signer = successor["signer"]
    state = signer["state"]
    active_kid = signer.get("active_kid") if state == "active" else None
    return {
        "version": 1,
        "case_id": bundle["case_id"],
        "qualification_run_id": bundle["qualification_run_id"],
        "source_commit_sha": bundle["source_commit_sha"],
        "qualification_catalog_sha256": descriptor[
            "qualification_catalog_sha256"
        ],
        "authority_id": bundle["rotation_operator_authority_id"],
        "route_deployment_id": bundle["route_deployment_id"],
        "rotation_operator_trust_sha256": bundle[
            "rotation_operator_trust_sha256"
        ],
        "phase": phase["entry"]["phase"],
        "signer_revision": rollout["signer_revision"],
        "saved_plan_sha256": descriptor_phase["saved_plan_sha256"],
        "terraform_show_json_sha256": plan_receipt[
            "terraform_show_json_sha256"
        ],
        "plan_validation_receipt_sha256": digest(plan_receipt_bytes),
        "terraform_executable_sha256": plan_receipt[
            "terraform_executable_sha256"
        ],
        "deployment_operator_executable_sha256": digest(
            deployment_operator_bytes
        ),
        "saved_plan_validator_executable_sha256": digest(validator_bytes),
        "receipt_signer_executable_sha256": digest(cats_bytes),
        "successor_secret_name": rollout["secret_name"],
        "successor_secret_manifest_sha256": rollout[
            "secret_manifest_sha256"
        ],
        "successor_signer_reference_sha256": rollout[
            "signer_reference_sha256"
        ],
        "successor_signer_state": state,
        "successor_active_kid": active_kid,
        "successor_public_key_ring_version": successor[
            "public_key_ring_version"
        ],
        "successor_public_key_ring_digest": rollout["public_key_ring_digest"],
        "apply_started_at_unix_ms": attempt["started_at_unix_ms"],
        "apply_completed_at_unix_ms": attempt["completed_at_unix_ms"],
        "apply_outcome": outcome,
        "terraform_apply_stdout_sha256": attempt["stdout_sha256"],
        "terraform_apply_stderr_sha256": attempt["stderr_sha256"],
        "postcondition_discovery_sha256": digest(current_bytes),
        "observed_loaded_signer_reference_sha256": current[
            "loaded_signer_reference_sha256"
        ],
        "observed_loaded_signer_state": current["loaded_signer_state"],
        "observed_loaded_active_kid": current["loaded_active_kid"],
        "observed_public_key_ring_version": current[
            "loaded_public_key_ring_version"
        ],
        "observed_public_key_ring_digest": current[
            "loaded_public_key_ring_digest"
        ],
        "observed_database_current": current["database_current"],
        "observed_process_ready": current["process_ready"],
        "terminal_marker": "current_process_bound",
    }


def sign_with_cats(
    cats: Path,
    trust: Path,
    private_keys: list[Path],
    payload: Path,
    output: Path,
    cats_bytes: bytes,
) -> None:
    command = [
        os.fspath(cats),
        "--json",
        "admin",
        "runtime-provisioner",
        "route-v2-r1",
        "sign-control-rollout-apply-receipt",
        "--trust",
        os.fspath(trust),
    ]
    for private_key in private_keys:
        command.extend(["--operator-private-key", os.fspath(private_key)])
    command.extend(["--payload", os.fspath(payload), "--output", os.fspath(output)])
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
    }
    completed = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        timeout=30,
        check=False,
    )
    if (
        completed.returncode != 0
        or len(completed.stdout) > MAX_CLI_OUTPUT_BYTES
        or len(completed.stderr) > MAX_CLI_OUTPUT_BYTES
        or digest(checked_file(cats, private=False, maximum=len(cats_bytes), executable=True))
        != digest(cats_bytes)
    ):
        raise Rejected("release-bound cats failed to sign the apply receipt")


def publish_inbox(
    descriptor: dict[str, Any],
    phase: dict[str, Any],
    ca_path: Path,
    signed_bytes: bytes,
) -> None:
    url = phase["receipt_url"]
    try:
        https_request(
            url,
            descriptor["receipt_inbox_server_name"],
            ca_path,
            "PUT",
            signed_bytes,
            expected=(201, 204),
            headers={
                "Content-Type": "application/json",
                "If-None-Match": "*",
            },
        )
        return
    except Rejected:
        pass
    # A lost PUT response is ambiguous.  Only exact-byte discovery settles it;
    # this path never issues an unconditional overwrite.
    existing = https_request(
        url,
        descriptor["receipt_inbox_server_name"],
        ca_path,
        "GET",
        None,
        expected=(200,),
    )
    if existing != signed_bytes:
        raise Rejected("receipt inbox contains different bytes for this phase")


def https_request(
    url: str,
    server_name: str,
    ca_path: Path,
    method: str,
    body: bytes | None,
    *,
    expected: tuple[int, ...],
    headers: dict[str, str] | None = None,
) -> bytes:
    split = checked_https_url(url, server_name, origin_only=False)
    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=os.fspath(ca_path))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    connection = http.client.HTTPSConnection(
        server_name, split.port or 443, context=context, timeout=30
    )
    request_headers = {
        "Accept": "application/json",
        "Accept-Encoding": "identity",
    }
    if headers:
        request_headers.update(headers)
    try:
        connection.request(method, split.path, body=body, headers=request_headers)
        response = connection.getresponse()
        response_body = response.read(MAX_HTTP_BYTES + 1)
        if len(response_body) > MAX_HTTP_BYTES:
            raise Rejected("HTTPS response exceeds the closed byte bound")
        if response.status not in expected:
            raise Rejected("HTTPS response has an unexpected status")
        encoding = response.getheader("Content-Encoding")
        if encoding not in (None, "identity"):
            raise Rejected("HTTPS response uses an unexpected content encoding")
        if response.status == 200 and response.getheader("Content-Type") != "application/json":
            raise Rejected("HTTPS JSON response has an unexpected content type")
        return response_body
    except (OSError, ssl.SSLError, http.client.HTTPException) as error:
        raise Rejected("HTTPS request failed") from error
    finally:
        connection.close()


def publish_sorted_exact(path: Path, value: dict[str, Any]) -> None:
    publish_exact(
        path, json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    )


def publish_exact(path: Path, value: bytes) -> None:
    if not path.is_absolute():
        raise Rejected("output path is not absolute")
    if path.exists():
        installed = checked_file(path, private=True, maximum=max(len(value), 1))
        if installed != value:
            raise Rejected("existing immutable output differs")
        return
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        os.fchmod(descriptor, 0o600)
        written = 0
        while written < len(value):
            count = os.write(descriptor, value[written:])
            if count <= 0:
                raise OSError("short write while publishing immutable output")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    sync_directory(path.parent)


def sync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def unix_millis() -> int:
    return time.time_ns() // 1_000_000


if __name__ == "__main__":
    raise SystemExit(main())
