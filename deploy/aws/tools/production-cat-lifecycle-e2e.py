#!/usr/bin/env python3
"""Exercise the synchronous Cat and PersistentDisk protocol in production."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import time
from typing import Any
from urllib.parse import urlsplit


DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
WORKSPACE = re.compile(r"ws_[A-Za-z0-9_-]{1,124}\Z")
RESOURCE_SLUG = re.compile(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\Z")
SLEEP_STATES = {"suspend": "suspended", "warm": "warm", "cold": "cold"}
ACTION_CODES = {
    "suspend": ("cat_suspended", "already_suspended"),
    "warm": ("cat_warm", "already_warm"),
    "cold": ("cat_cold", "already_cold"),
}
QUALIFICATION_CLASSES = [
    "cat_create",
    "disk_create",
    "disk_delete",
    "runtime_mutation",
]
QUALIFICATION_RECEIPT_FIELDS = {
    "allowed_mutation_classes",
    "begin_command_id",
    "begin_command_receipt_sha256",
    "begin_request_sha256",
    "binding_sha256",
    "kind",
    "qualification_catalog_sha256",
    "qualification_expires_at_unix_ms",
    "qualification_id",
    "release_id",
    "resulting_revision",
    "source_commit_sha",
    "version",
    "workspace_id",
}


class E2eError(Exception):
    """The public lifecycle did not reach its exact product postcondition."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def write_new(path: Path, raw: bytes, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise E2eError(f"refusing to replace E2E evidence: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short E2E evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def validate_origin(value: str) -> None:
    parsed = urlsplit(value)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
        or value.rstrip("/") != f"https://{parsed.netloc}"
    ):
        raise E2eError("--api-url must be one exact HTTPS origin")


def read_qualification_receipt(arguments: argparse.Namespace) -> tuple[dict[str, Any], bytes]:
    path = arguments.qualification_begin_receipt
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or path.resolve() != path
    ):
        raise E2eError("--qualification-begin-receipt must be a resolved real file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise E2eError("Qualification Begin receipt is not UTF-8 JSON") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise E2eError("Qualification Begin receipt is not canonical JSON")
    if (
        set(value) != QUALIFICATION_RECEIPT_FIELDS
        or value.get("kind")
        != "cats.production-mutation-qualification-begin-receipt.v1"
        or value.get("version") != 1
        or value.get("workspace_id") != arguments.workspace_id
        or value.get("allowed_mutation_classes") != QUALIFICATION_CLASSES
        or not isinstance(value.get("qualification_expires_at_unix_ms"), int)
        or value["qualification_expires_at_unix_ms"] <= int(time.time() * 1000)
        or not isinstance(value.get("source_commit_sha"), str)
        or re.fullmatch(r"[0-9a-f]{40}", value["source_commit_sha"]) is None
        or any(
            DIGEST.fullmatch(str(value.get(field))) is None
            for field in (
                "begin_command_receipt_sha256",
                "begin_request_sha256",
                "binding_sha256",
                "qualification_catalog_sha256",
            )
        )
        or not isinstance(value.get("resulting_revision"), int)
        or value["resulting_revision"] < 2
        or not isinstance(value.get("qualification_id"), str)
        or not value["qualification_id"]
        or not isinstance(value.get("release_id"), str)
        or not value["release_id"]
    ):
        raise E2eError("Qualification Begin receipt does not authorize this E2E")
    return value, raw


def validate_arguments(arguments: argparse.Namespace) -> tuple[str, dict[str, Any], bytes]:
    if (
        not arguments.cats_cli.is_absolute()
        or not arguments.cats_cli.is_file()
        or arguments.cats_cli.is_symlink()
        or arguments.cats_cli.resolve() != arguments.cats_cli
        or not stat.S_IMODE(arguments.cats_cli.stat().st_mode) & 0o111
    ):
        raise E2eError("--cats-cli must be a resolved executable regular file")
    validate_origin(arguments.api_url)
    if WORKSPACE.fullmatch(arguments.workspace_id) is None:
        raise E2eError("--workspace-id must be one immutable ws_ ID")
    if RESOURCE_SLUG.fullmatch(arguments.cat_name) is None:
        raise E2eError("--cat-name is invalid")
    if RESOURCE_SLUG.fullmatch(arguments.disk_name) is None:
        raise E2eError("--disk-name is invalid")
    if re.fullmatch(r"[1-9][0-9]*GiB", arguments.disk_size) is None:
        raise E2eError("--disk-size must be a positive whole number of GiB")
    if (
        not arguments.mount_path.startswith("/")
        or arguments.mount_path == "/"
        or arguments.mount_path.endswith("/")
        or any(part in ("", ".", "..") for part in arguments.mount_path[1:].split("/"))
    ):
        raise E2eError("--mount-path must be one normalized non-root absolute path")
    if arguments.cpus < 1 or arguments.cpus > 64:
        raise E2eError("--cpus must be between 1 and 64")
    if not arguments.sleep_state:
        arguments.sleep_state = ["suspend", "warm", "cold"]
    if len(set(arguments.sleep_state)) != len(arguments.sleep_state):
        raise E2eError("--sleep-state contains a duplicate action")
    if (
        not arguments.token_file.is_absolute()
        or not arguments.token_file.is_file()
        or arguments.token_file.is_symlink()
        or arguments.token_file.resolve() != arguments.token_file
    ):
        raise E2eError("--token-file must be a resolved real regular file")
    token_metadata = arguments.token_file.stat()
    if token_metadata.st_uid != os.geteuid() or stat.S_IMODE(token_metadata.st_mode) & 0o077:
        raise E2eError("--token-file must be owned by the caller and mode 0600 or stricter")
    token_raw = arguments.token_file.read_bytes()
    if token_raw.endswith(b"\n"):
        token_raw = token_raw[:-1]
    try:
        token = token_raw.decode()
    except UnicodeDecodeError as error:
        raise E2eError("--token-file is not UTF-8") from error
    if not token or len(token) > 16_384 or any(character.isspace() for character in token):
        raise E2eError("--token-file does not contain one bounded bearer token")
    if arguments.output.exists() or arguments.output.is_symlink() or not arguments.output.is_absolute():
        raise E2eError("--output must be a new absolute path")
    if not arguments.output.parent.is_dir() or arguments.output.parent.is_symlink():
        raise E2eError("--output parent must be an existing real directory")
    qualification, qualification_raw = read_qualification_receipt(arguments)
    return token, qualification, qualification_raw


def cli_command(arguments: argparse.Namespace, *command: str) -> list[str]:
    return [
        str(arguments.cats_cli),
        "--api-url",
        arguments.api_url,
        "--workspace",
        arguments.workspace_id,
        "--json",
        *command,
    ]


def run_cli(
    arguments: argparse.Namespace,
    token: str,
    state_directory: Path,
    *command: str,
) -> Any:
    argv = cli_command(arguments, *command)
    environment = {
        **os.environ,
        "CATS_CONFIG_DIR": str(state_directory),
        "CATS_TOKEN": token,
    }
    result = subprocess.run(argv, capture_output=True, check=False, env=environment)
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[-8192:]
        if token in detail:
            detail = detail.replace(token, "<redacted>")
        raise E2eError(f"Cats CLI command {command[0]} failed: {detail}")
    try:
        return json.loads(result.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise E2eError(f"Cats CLI command {command[0]} returned invalid JSON") from error


def require_cat(value: Any, cat_id: str, cat_slug: str, state: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("cat_id") != cat_id
        or value.get("cat_slug") != cat_slug
        or value.get("state") != state
        or value.get("current_action") is not None
    ):
        raise E2eError(f"Cat did not reach synchronous state {state}")
    node_id = value.get("node_id")
    node_name = value.get("node_name")
    if state in {"running", "suspended", "warm"}:
        if not isinstance(node_id, str) or not node_id.startswith("node_") or not node_name:
            raise E2eError(f"{state} Cat lacks exact Node placement")
    elif node_id is not None or node_name is not None:
        raise E2eError(f"{state} Cat unexpectedly retains Node placement")
    return value


def require_cat_response(
    value: Any,
    cat_id: str,
    cat_slug: str,
    state: str,
    status: str,
    code: str,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("status") != status
        or value.get("code") != code
        or not isinstance(value.get("cat"), dict)
    ):
        raise E2eError(f"Cat response is not exact {status}/{code}")
    require_cat(value["cat"], cat_id, cat_slug, state)
    return value["cat"]


def require_disk(
    value: Any,
    disk_id: str,
    disk_slug: str,
    status: str,
    binding_cat_id: str | None,
    mount_path: str | None,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("disk_id") != disk_id
        or value.get("disk_slug") != disk_slug
        or value.get("status") != status
    ):
        raise E2eError(f"PersistentDisk did not reach state {status}")
    binding = value.get("binding")
    if binding_cat_id is None:
        if binding is not None:
            raise E2eError("PersistentDisk unexpectedly remains bound")
    elif (
        not isinstance(binding, dict)
        or binding.get("cat_id") != binding_cat_id
        or binding.get("mount_path") != mount_path
    ):
        raise E2eError("PersistentDisk binding differs from the exact Cat/mount")
    return value


def require_disk_response(
    value: Any,
    disk_id: str,
    disk_slug: str,
    disk_status: str,
    response_status: str,
    code: str,
    binding_cat_id: str | None,
    mount_path: str | None,
) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("status") != response_status
        or value.get("code") != code
        or not isinstance(value.get("disk"), dict)
    ):
        raise E2eError(f"PersistentDisk response is not exact {response_status}/{code}")
    return require_disk(
        value["disk"], disk_id, disk_slug, disk_status, binding_cat_id, mount_path
    )


def record_step(output: Path, sequence: int, label: str, value: Any) -> str:
    raw = canonical_json(value)
    path = output / f"{sequence:02d}-{label}.json"
    write_new(path, raw)
    return sha256_bytes(raw)


def run_e2e(
    arguments: argparse.Namespace,
    token: str,
    qualification: dict[str, Any],
    qualification_raw: bytes,
) -> dict[str, Any]:
    arguments.output.mkdir(mode=0o700)
    state_directory = arguments.output / "cli-state"
    state_directory.mkdir(mode=0o700)
    step = 0
    evidence: list[dict[str, str]] = []

    def invoke(label: str, *command: str) -> Any:
        nonlocal step
        value = run_cli(arguments, token, state_directory, *command)
        step += 1
        digest = record_step(arguments.output, step, label, value)
        evidence.append({"label": label, "sha256": digest})
        return value

    before = invoke("cats-before", "ls")
    if not isinstance(before, list) or any(
        isinstance(cat, dict) and cat.get("cat_slug") == arguments.cat_name for cat in before
    ):
        raise E2eError("preflight Cat list is invalid or test slug already exists")
    disks_before = invoke("disks-before", "disk", "ls")
    if not isinstance(disks_before, list) or any(
        isinstance(disk, dict) and disk.get("disk_slug") == arguments.disk_name
        for disk in disks_before
    ):
        raise E2eError("preflight PersistentDisk list is invalid or test slug already exists")

    disk_created = invoke(
        "disk-created", "disk", "create", arguments.disk_name, "--size", arguments.disk_size
    )
    if not isinstance(disk_created, dict) or not isinstance(disk_created.get("disk"), dict):
        raise E2eError("PersistentDisk create returned no exact resource")
    disk_id = disk_created["disk"].get("disk_id")
    if not isinstance(disk_id, str) or not disk_id.startswith("disk_"):
        raise E2eError("PersistentDisk create returned an invalid identity")
    require_disk_response(
        disk_created,
        disk_id,
        arguments.disk_name,
        "normal",
        "ok",
        "disk_created",
        None,
        None,
    )
    require_disk_response(
        invoke(
            "disk-create-replay",
            "disk",
            "create",
            arguments.disk_name,
            "--size",
            arguments.disk_size,
        ),
        disk_id,
        arguments.disk_name,
        "normal",
        "already_exists",
        "already_exists",
        None,
        None,
    )

    created = invoke(
        "cat-created",
        "create",
        arguments.cat_name,
        "--cpu",
        str(arguments.cpus),
        "--memory",
        arguments.memory,
        "--mount",
        f"{arguments.disk_name}:{arguments.mount_path}",
    )
    if (
        not isinstance(created, dict)
        or not isinstance(created.get("cat"), dict)
        or not isinstance(created["cat"].get("cat_id"), str)
        or not created["cat"]["cat_id"].startswith("cat_")
    ):
        raise E2eError("Cat create did not return one exact synchronous resource identity")
    cat_id = created["cat"]["cat_id"]
    running = require_cat_response(
        created, cat_id, arguments.cat_name, "running", "ok", "cat_created"
    )
    boot_image_digest = running.get("boot_image")
    if not isinstance(boot_image_digest, str) or DIGEST.fullmatch(boot_image_digest) is None:
        raise E2eError("Control did not bind one exact default boot image digest")
    if running.get("mounts") != [
        {
            "disk_id": disk_id,
            "disk_slug": arguments.disk_name,
            "mount_path": arguments.mount_path,
        }
    ]:
        raise E2eError("Running Cat lacks the exact PersistentDisk mount")
    first_node_id = running["node_id"]
    require_cat_response(
        invoke(
            "cat-create-replay",
            "create",
            arguments.cat_name,
            "--cpu",
            str(arguments.cpus),
            "--memory",
            arguments.memory,
            "--mount",
            f"{arguments.disk_name}:{arguments.mount_path}",
        ),
        cat_id,
        arguments.cat_name,
        "running",
        "already_exists",
        "already_exists",
    )
    require_cat(invoke("create-running", "get", arguments.cat_name), cat_id, arguments.cat_name, "running")

    for sleep_action in arguments.sleep_state:
        success_code, replay_code = ACTION_CODES[sleep_action]
        sleeping = require_cat_response(
            invoke(f"{sleep_action}-terminal", sleep_action, arguments.cat_name),
            cat_id,
            arguments.cat_name,
            SLEEP_STATES[sleep_action],
            "ok",
            success_code,
        )
        require_cat_response(
            invoke(f"{sleep_action}-replay", sleep_action, arguments.cat_name),
            cat_id,
            arguments.cat_name,
            SLEEP_STATES[sleep_action],
            "already_done",
            replay_code,
        )
        if sleep_action != "cold" and sleeping["node_id"] != first_node_id:
            raise E2eError(f"{sleep_action} unexpectedly changed Host-bound placement")
        require_cat(
            invoke(f"{sleep_action}-state", "get", arguments.cat_name),
            cat_id,
            arguments.cat_name,
            SLEEP_STATES[sleep_action],
        )
        running = require_cat_response(
            invoke(f"run-after-{sleep_action}-terminal", "run", arguments.cat_name),
            cat_id,
            arguments.cat_name,
            "running",
            "ok",
            "cat_running",
        )
        require_cat_response(
            invoke(f"run-after-{sleep_action}-replay", "run", arguments.cat_name),
            cat_id,
            arguments.cat_name,
            "running",
            "already_done",
            "already_running",
        )
        first_node_id = running["node_id"]

    require_cat_response(
        invoke("cold-for-binding", "cold", arguments.cat_name),
        cat_id,
        arguments.cat_name,
        "cold",
        "ok",
        "cat_cold",
    )
    require_disk_response(
        invoke("disk-detached", "disk", "detach", arguments.disk_name, "--cat", arguments.cat_name),
        disk_id,
        arguments.disk_name,
        "normal",
        "ok",
        "disk_detached",
        None,
        None,
    )
    require_disk_response(
        invoke("disk-detach-replay", "disk", "detach", arguments.disk_name, "--cat", arguments.cat_name),
        disk_id,
        arguments.disk_name,
        "normal",
        "already_done",
        "already_detached",
        None,
        None,
    )
    require_disk_response(
        invoke(
            "disk-attached",
            "disk",
            "attach",
            arguments.disk_name,
            "--cat",
            arguments.cat_name,
            "--mount",
            arguments.mount_path,
        ),
        disk_id,
        arguments.disk_name,
        "normal",
        "ok",
        "disk_attached",
        cat_id,
        arguments.mount_path,
    )
    require_disk_response(
        invoke(
            "disk-attach-replay",
            "disk",
            "attach",
            arguments.disk_name,
            "--cat",
            arguments.cat_name,
            "--mount",
            arguments.mount_path,
        ),
        disk_id,
        arguments.disk_name,
        "normal",
        "already_done",
        "already_attached",
        cat_id,
        arguments.mount_path,
    )
    require_cat_response(
        invoke("run-after-binding", "run", arguments.cat_name),
        cat_id,
        arguments.cat_name,
        "running",
        "ok",
        "cat_running",
    )

    require_cat_response(
        invoke("destroy-terminal", "destroy", arguments.cat_name),
        cat_id,
        arguments.cat_name,
        "destroyed",
        "ok",
        "cat_destroyed",
    )
    require_disk_response(
        invoke("disk-destroyed", "disk", "destroy", arguments.disk_name),
        disk_id,
        arguments.disk_name,
        "deleted",
        "ok",
        "disk_deleted",
        None,
        None,
    )
    after = invoke("cats-after", "ls")
    if not isinstance(after, list) or any(
        isinstance(cat, dict) and cat.get("cat_id") == cat_id for cat in after
    ):
        raise E2eError("destroyed Cat remains in the product list")
    disks_after = invoke("disks-after", "disk", "ls")
    if not isinstance(disks_after, list) or any(
        isinstance(disk, dict) and disk.get("disk_id") == disk_id for disk in disks_after
    ):
        raise E2eError("deleted PersistentDisk remains in the product list")

    replacement_disk = invoke(
        "disk-slug-reused", "disk", "create", arguments.disk_name, "--size", arguments.disk_size
    )
    replacement_disk_id = replacement_disk.get("disk", {}).get("disk_id")
    if not isinstance(replacement_disk_id, str) or replacement_disk_id == disk_id:
        raise E2eError("PersistentDisk slug reuse did not allocate a new immutable identity")
    require_disk_response(
        replacement_disk,
        replacement_disk_id,
        arguments.disk_name,
        "normal",
        "ok",
        "disk_created",
        None,
        None,
    )
    replacement_cat = invoke(
        "cat-slug-reused",
        "create",
        arguments.cat_name,
        "--cpu",
        str(arguments.cpus),
        "--memory",
        arguments.memory,
    )
    replacement_cat_id = replacement_cat.get("cat", {}).get("cat_id")
    if not isinstance(replacement_cat_id, str) or replacement_cat_id == cat_id:
        raise E2eError("Cat slug reuse did not allocate a new immutable identity")
    require_cat_response(
        replacement_cat,
        replacement_cat_id,
        arguments.cat_name,
        "running",
        "ok",
        "cat_created",
    )
    require_cat_response(
        invoke("replacement-cat-destroyed", "destroy", arguments.cat_name),
        replacement_cat_id,
        arguments.cat_name,
        "destroyed",
        "ok",
        "cat_destroyed",
    )
    require_disk_response(
        invoke("replacement-disk-destroyed", "disk", "destroy", arguments.disk_name),
        replacement_disk_id,
        arguments.disk_name,
        "deleted",
        "ok",
        "disk_deleted",
        None,
        None,
    )
    return {
        "api_url": arguments.api_url,
        "boot_image_digest": boot_image_digest,
        "cat_id": cat_id,
        "cat_name": arguments.cat_name,
        "disk_id": disk_id,
        "disk_name": arguments.disk_name,
        "evidence": evidence,
        "qualification_begin_receipt_sha256": sha256_bytes(qualification_raw),
        "qualification_id": qualification["qualification_id"],
        "release_source_sha": qualification["source_commit_sha"],
        "schema_version": 1,
        "sleep_states": arguments.sleep_state,
        "status": "passed",
        "workspace_id": arguments.workspace_id,
    }


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cats-cli", required=True, type=Path)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--token-file", required=True, type=Path)
    parser.add_argument("--qualification-begin-receipt", required=True, type=Path)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--cat-name", required=True)
    parser.add_argument("--disk-name", required=True)
    parser.add_argument("--disk-size", default="1GiB")
    parser.add_argument("--mount-path", default="/data")
    parser.add_argument(
        "--sleep-state",
        action="append",
        choices=sorted(SLEEP_STATES),
        help="repeat to select public sleep states; default: suspend, warm and cold",
    )
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--memory", default="2GiB")
    parser.add_argument("--output", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        token, qualification, qualification_raw = validate_arguments(arguments)
        receipt = run_e2e(arguments, token, qualification, qualification_raw)
        write_new(
            arguments.output / "production-cat-lifecycle-e2e-receipt.v1.json",
            canonical_json(receipt),
        )
        print(canonical_json({"output": str(arguments.output), **receipt}).decode())
    except E2eError as error:
        print(f"production Cat lifecycle E2E failed closed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
