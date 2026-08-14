#!/usr/bin/env python3
"""Fail closed unless one saved plan is an exact Route v2 Control rollout."""

from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import stat
import subprocess
import sys
from pathlib import Path
from typing import Any


MAX_PLAN_JSON_BYTES = 64 * 1024 * 1024
MAX_INPUT_JSON_BYTES = 1024 * 1024
MAX_EXECUTABLE_BYTES = 256 * 1024 * 1024
SHA256 = re.compile(r"sha256:[0-9a-f]{64}")
SECRET_NAME = re.compile(r"[a-z0-9](?:[-a-z0-9.]*[a-z0-9])?-r([1-9][0-9]*)")
PHASES = (
    "publish_overlap",
    "switch_active",
    "publish_new_only",
    "retire",
    "disable",
    "publish_recovery",
    "activate",
)
TARGET_DATA = "module.cats_kubernetes.terraform_data.route_v2_control_artifact"
TARGET_DEPLOYMENT = "module.cats_kubernetes.kubernetes_deployment_v1.control_plane"
ALLOWED_READS = frozenset(
    {
        "data.aws_partition.current",
        "data.aws_caller_identity.current",
        "data.aws_region.current",
        "data.aws_lb.public",
    }
)
EXPECTED_ANNOTATIONS = {
    "cats.run/route-v2-control-artifact-secret",
    "cats.run/route-v2-control-artifact-secret-sha256",
    "cats.run/route-v2-control-signer-revision",
}


class Rejected(ValueError):
    """An input or plan violates the closed rollout contract."""


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Validate and receipt one reviewed Route v2 Control saved plan."
    )
    parser.add_argument("--terraform", required=True, type=Path)
    parser.add_argument("--saved-plan", required=True, type=Path)
    parser.add_argument("--command-bundle", required=True, type=Path)
    parser.add_argument("--previous-rollout-reference", required=True, type=Path)
    parser.add_argument("--successor-rollout-reference", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        terraform = checked_file(args.terraform, private=False, executable=True)
        saved_plan = checked_file(args.saved_plan, private=True)
        command_bundle_bytes = checked_file(args.command_bundle, private=True)
        previous_bytes = checked_file(args.previous_rollout_reference, private=True)
        successor_bytes = checked_file(args.successor_rollout_reference, private=True)
        command_bundle = canonical_object(command_bundle_bytes, "command bundle")
        previous = rollout_reference(previous_bytes, "previous rollout reference")
        successor = rollout_reference(successor_bytes, "successor rollout reference")
        validate_lineage(previous, successor, command_bundle)
        plan_json = terraform_show(args.terraform, args.saved_plan)
        plan = canonical_object(plan_json, "Terraform show JSON", require_canonical=False)
        validate_plan(plan, previous, successor)
        receipt = build_receipt(
            command_bundle,
            previous,
            successor,
            terraform,
            saved_plan,
            plan_json,
        )
        receipt_bytes = canonical_bytes(receipt)
        publish_exact(args.output, receipt_bytes)
    except (OSError, Rejected, subprocess.SubprocessError) as error:
        print(f"reject: {error}", file=sys.stderr)
        return 1
    print(receipt_bytes.decode("ascii"))
    return 0


def checked_file(
    path: Path, *, private: bool, executable: bool = False
) -> bytes:
    if not path.is_absolute():
        raise Rejected(f"path must be absolute: {path}")
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
            raise Rejected(f"file contract rejected: {path}")
        if executable:
            limit = MAX_EXECUTABLE_BYTES
        elif path.suffix == ".tfplan":
            limit = MAX_PLAN_JSON_BYTES
        else:
            limit = MAX_INPUT_JSON_BYTES
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(1024 * 1024, limit + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > limit:
                raise Rejected(f"file exceeds closed byte limit: {path}")
        after = os.fstat(descriptor)
        if inode_identity(before) != inode_identity(after):
            raise Rejected(f"file changed while read: {path}")
        data = b"".join(chunks)
        if not data:
            raise Rejected(f"file is empty: {path}")
        return data
    finally:
        os.close(descriptor)


def inode_identity(value: os.stat_result) -> tuple[int, int, int, int, int]:
    return (value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns)


def canonical_object(
    data: bytes, label: str, *, require_canonical: bool = True
) -> dict[str, Any]:
    try:
        value = json.loads(data)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise Rejected(f"{label} is not JSON: {error}") from error
    if not isinstance(value, dict):
        raise Rejected(f"{label} must be one JSON object")
    if require_canonical and compact_bytes(value) != data:
        raise Rejected(f"{label} is not exact canonical JSON")
    return value


def canonical_bytes(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")


def compact_bytes(value: Any) -> bytes:
    return json.dumps(value, separators=(",", ":")).encode("ascii")


def rollout_reference(data: bytes, label: str) -> dict[str, Any]:
    value = canonical_object(data, label)
    if tuple(value) != (
        "version",
        "signer_revision",
        "secret_name",
        "secret_manifest_sha256",
        "signer_reference_sha256",
        "public_key_ring_digest",
    ):
        raise Rejected(f"{label} has the wrong closed ordered field set")
    revision = value.get("signer_revision")
    name = value.get("secret_name")
    if (
        value.get("version") != 1
        or not isinstance(revision, int)
        or isinstance(revision, bool)
        or revision <= 0
        or not isinstance(name, str)
        or SECRET_NAME.fullmatch(name) is None
        or int(SECRET_NAME.fullmatch(name).group(1)) != revision
        or any(
            not isinstance(value.get(field), str)
            or SHA256.fullmatch(value[field]) is None
            for field in (
                "secret_manifest_sha256",
                "signer_reference_sha256",
                "public_key_ring_digest",
            )
        )
    ):
        raise Rejected(f"{label} is malformed")
    return value


def validate_lineage(
    previous: dict[str, Any],
    successor: dict[str, Any],
    bundle: dict[str, Any],
) -> None:
    previous_revision = previous["signer_revision"]
    successor_revision = successor["signer_revision"]
    previous_prefix = previous["secret_name"].removesuffix(f"-r{previous_revision}")
    successor_prefix = successor["secret_name"].removesuffix(f"-r{successor_revision}")
    if (
        successor_revision != previous_revision + 1
        or previous_prefix != successor_prefix
        or previous["secret_name"] == successor["secret_name"]
    ):
        raise Rejected("rollout references are not one immutable adjacent Secret transition")
    required_top = (
        "version",
        "case_id",
        "source_commit_sha",
        "qualification_run_id",
        "route_deployment_id",
        "rotation_operator_authority_id",
        "rotation_operator_trust_sha256",
        "commands",
        "control_rollouts",
    )
    if tuple(bundle) != required_top or bundle.get("version") != 1:
        raise Rejected("command bundle has the wrong closed field set")
    if (
        bundle.get("case_id") != "route-v2-rotation-disable-live-delivery"
        or not isinstance(bundle.get("source_commit_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", bundle["source_commit_sha"]) is None
        or not isinstance(bundle.get("qualification_run_id"), str)
        or not bundle["qualification_run_id"]
        or not isinstance(bundle.get("route_deployment_id"), str)
        or not bundle["route_deployment_id"]
        or not isinstance(bundle.get("rotation_operator_authority_id"), str)
        or not bundle["rotation_operator_authority_id"]
        or not isinstance(bundle.get("rotation_operator_trust_sha256"), str)
        or SHA256.fullmatch(bundle["rotation_operator_trust_sha256"]) is None
    ):
        raise Rejected("command bundle identity is malformed")
    commands = bundle.get("commands")
    rollouts = bundle.get("control_rollouts")
    if not isinstance(commands, list) or not isinstance(rollouts, list) or len(commands) != 7 or len(rollouts) != 7:
        raise Rejected("command bundle does not contain the closed seven-phase lineage")
    if tuple(command.get("phase") for command in commands if isinstance(command, dict)) != PHASES:
        raise Rejected("command bundle phases are not exact and ordered")
    expected_rollout = {
        "signer_revision": successor["signer_revision"],
        "secret_name": successor["secret_name"],
        "signer_reference_sha256": successor["signer_reference_sha256"],
        "public_key_ring_digest": successor["public_key_ring_digest"],
        "secret_manifest_sha256": successor["secret_manifest_sha256"],
    }
    matching = [item for item in rollouts if item == expected_rollout]
    if len(matching) != 1:
        raise Rejected("successor rollout reference is not exact in the command bundle")


def terraform_show(terraform: Path, saved_plan: Path) -> bytes:
    environment = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/nonexistent",
        "TF_IN_AUTOMATION": "1",
        "CHECKPOINT_DISABLE": "1",
    }
    completed = subprocess.run(
        [os.fspath(terraform), "show", "-json", os.fspath(saved_plan)],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        check=False,
        timeout=60,
    )
    if completed.returncode != 0:
        raise Rejected("terraform show rejected the exact saved plan")
    if not completed.stdout or len(completed.stdout) > MAX_PLAN_JSON_BYTES:
        raise Rejected("terraform show JSON is empty or exceeds the closed byte limit")
    return completed.stdout


def validate_plan(
    plan: dict[str, Any], previous: dict[str, Any], successor: dict[str, Any]
) -> None:
    if not isinstance(plan.get("format_version"), str) or not plan["format_version"].startswith("1."):
        raise Rejected("Terraform plan JSON format_version is unsupported")
    variables = plan.get("variables")
    if not isinstance(variables, dict):
        raise Rejected("Terraform plan has no closed variable map")
    exact_variables = {
        "route_v2_control_artifact_secret_name": successor["secret_name"],
        "route_v2_control_artifact_signer_revision": successor["signer_revision"],
        "route_v2_control_artifact_secret_sha256": successor["secret_manifest_sha256"],
    }
    for name, expected in exact_variables.items():
        entry = variables.get(name)
        if not isinstance(entry, dict) or entry.get("value") != expected:
            raise Rejected(f"Terraform plan variable {name} does not match the successor")

    changes = plan.get("resource_changes")
    if not isinstance(changes, list):
        raise Rejected("Terraform plan has no resource_changes array")
    mutations: dict[str, dict[str, Any]] = {}
    for item in changes:
        if not isinstance(item, dict) or not isinstance(item.get("change"), dict):
            raise Rejected("Terraform resource change is malformed")
        address = item.get("address")
        actions = item["change"].get("actions")
        if not isinstance(address, str) or not isinstance(actions, list):
            raise Rejected("Terraform resource change identity is malformed")
        if actions == ["no-op"]:
            continue
        if actions == ["read"] and item.get("mode") == "data" and address in ALLOWED_READS:
            continue
        if actions != ["update"] or address not in {TARGET_DATA, TARGET_DEPLOYMENT}:
            raise Rejected(f"saved plan contains an unauthorized action at {address}: {actions}")
        if address in mutations:
            raise Rejected(f"saved plan repeats mutation address {address}")
        mutations[address] = item["change"]
    if set(mutations) != {TARGET_DATA, TARGET_DEPLOYMENT}:
        raise Rejected("saved plan is missing one exact Control rollout mutation")
    validate_terraform_data(mutations[TARGET_DATA], previous, successor)
    validate_deployment(mutations[TARGET_DEPLOYMENT], previous, successor)
    reject_private_material(plan)


def rollout_coordinate(reference: dict[str, Any]) -> dict[str, Any]:
    return {
        "secret_name": reference["secret_name"],
        "secret_sha256": reference["secret_manifest_sha256"],
        "signer_revision": reference["signer_revision"],
    }


def validate_terraform_data(
    change: dict[str, Any], previous: dict[str, Any], successor: dict[str, Any]
) -> None:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise Rejected("terraform_data rollout change is not fully known")
    if before.get("input") != rollout_coordinate(previous):
        raise Rejected("terraform_data before input does not match previous rollout")
    if after.get("input") != rollout_coordinate(successor):
        raise Rejected("terraform_data after input does not match successor rollout")
    before_copy = copy.deepcopy(before)
    after_copy = copy.deepcopy(after)
    before_copy["input"] = "<rollout>"
    after_copy["input"] = "<rollout>"
    # terraform_data output becomes provider-computed after its input changes.
    before_copy.pop("output", None)
    after_copy.pop("output", None)
    if before_copy != after_copy:
        raise Rejected("terraform_data rollout changes fields outside the exact input")


def deployment_coordinates(value: dict[str, Any]) -> tuple[dict[str, Any], str]:
    try:
        template = value["spec"][0]["template"][0]
        annotations = template["metadata"][0]["annotations"]
        volumes = template["spec"][0]["volume"]
    except (KeyError, IndexError, TypeError) as error:
        raise Rejected("Control deployment has no exact template shape") from error
    if not isinstance(annotations, dict) or not isinstance(volumes, list):
        raise Rejected("Control deployment annotations/volumes are malformed")
    sources = [volume for volume in volumes if isinstance(volume, dict) and volume.get("name") == "route-v2-control-artifact-source"]
    if len(sources) != 1:
        raise Rejected("Control deployment has no unique Route v2 source volume")
    try:
        secret_name = sources[0]["secret"][0]["secret_name"]
    except (KeyError, IndexError, TypeError) as error:
        raise Rejected("Control deployment Route v2 source volume is malformed") from error
    return annotations, secret_name


def validate_deployment(
    change: dict[str, Any], previous: dict[str, Any], successor: dict[str, Any]
) -> None:
    before = change.get("before")
    after = change.get("after")
    if not isinstance(before, dict) or not isinstance(after, dict):
        raise Rejected("Control deployment rollout change is not fully known")
    before_annotations, before_secret = deployment_coordinates(before)
    after_annotations, after_secret = deployment_coordinates(after)
    if before_secret != previous["secret_name"] or after_secret != successor["secret_name"]:
        raise Rejected("Control volume does not switch the exact immutable Secret")
    expected_before = {
        "cats.run/route-v2-control-artifact-secret": previous["secret_name"],
        "cats.run/route-v2-control-artifact-secret-sha256": previous["secret_manifest_sha256"],
        "cats.run/route-v2-control-signer-revision": str(previous["signer_revision"]),
    }
    expected_after = {
        "cats.run/route-v2-control-artifact-secret": successor["secret_name"],
        "cats.run/route-v2-control-artifact-secret-sha256": successor["secret_manifest_sha256"],
        "cats.run/route-v2-control-signer-revision": str(successor["signer_revision"]),
    }
    for name in EXPECTED_ANNOTATIONS:
        if before_annotations.get(name) != expected_before[name] or after_annotations.get(name) != expected_after[name]:
            raise Rejected(f"Control rollout annotation {name} is not exact")
    scrubbed_before = copy.deepcopy(before)
    scrubbed_after = copy.deepcopy(after)
    scrub_deployment_rollout(scrubbed_before)
    scrub_deployment_rollout(scrubbed_after)
    if scrubbed_before != scrubbed_after:
        raise Rejected("Control deployment changes fields outside the exact signer rollout")


def scrub_deployment_rollout(value: dict[str, Any]) -> None:
    annotations, _ = deployment_coordinates(value)
    for name in EXPECTED_ANNOTATIONS:
        annotations[name] = "<rollout>"
    volumes = value["spec"][0]["template"][0]["spec"][0]["volume"]
    source = next(volume for volume in volumes if volume.get("name") == "route-v2-control-artifact-source")
    source["secret"][0]["secret_name"] = "<rollout>"


def reject_private_material(plan: dict[str, Any]) -> None:
    encoded = json.dumps(plan, sort_keys=True, separators=(",", ":"))
    for marker in ("-----BEGIN PRIVATE KEY-----", "PRIVATE KEY-----", "rotation-operator-private-key.pem"):
        if marker in encoded:
            raise Rejected("Terraform saved plan contains Route v2 private material")


def build_receipt(
    bundle: dict[str, Any],
    previous: dict[str, Any],
    successor: dict[str, Any],
    terraform_bytes: bytes,
    saved_plan_bytes: bytes,
    plan_json: bytes,
) -> dict[str, Any]:
    return {
        "version": 1,
        "kind": "route_v2_control_rollout_saved_plan_v1",
        "case_id": bundle["case_id"],
        "qualification_run_id": bundle["qualification_run_id"],
        "source_commit_sha": bundle["source_commit_sha"],
        "route_deployment_id": bundle["route_deployment_id"],
        "rotation_operator_authority_id": bundle["rotation_operator_authority_id"],
        "rotation_operator_trust_sha256": bundle["rotation_operator_trust_sha256"],
        "previous_signer_revision": previous["signer_revision"],
        "successor_signer_revision": successor["signer_revision"],
        "previous_secret_name": previous["secret_name"],
        "successor_secret_name": successor["secret_name"],
        "successor_secret_manifest_sha256": successor["secret_manifest_sha256"],
        "successor_signer_reference_sha256": successor["signer_reference_sha256"],
        "successor_public_key_ring_digest": successor["public_key_ring_digest"],
        "terraform_executable_sha256": digest(terraform_bytes),
        "saved_plan_sha256": digest(saved_plan_bytes),
        "terraform_show_json_sha256": digest(plan_json),
        "managed_update_addresses": [TARGET_DATA, TARGET_DEPLOYMENT],
        "verdict": "accepted",
    }


def digest(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def publish_exact(path: Path, value: bytes) -> None:
    if not path.is_absolute():
        raise Rejected("receipt output path must be absolute")
    if path.exists():
        if checked_file(path, private=True) != value:
            raise Rejected("existing rollout receipt differs")
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
                raise OSError("short write while publishing rollout receipt")
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        os.fsync(parent)
    finally:
        os.close(parent)


if __name__ == "__main__":
    raise SystemExit(main())
