#!/usr/bin/env python3
"""Exercise public Cat create, sleep, wake and destroy in one exact Workspace."""

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
CAT_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,62}\Z")
SLEEP_STATES = {"suspend": "suspended", "warm": "warm", "cold": "cold"}
QUALIFICATION_CLASSES = [
    "cat_create",
    "disk_create",
    "disk_delete",
    "object_write_ambiguity",
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
    if DIGEST.fullmatch(arguments.boot_image_digest) is None:
        raise E2eError("--boot-image-digest is invalid")
    if CAT_NAME.fullmatch(arguments.cat_name) is None:
        raise E2eError("--cat-name is invalid")
    if arguments.cpus < 1 or arguments.cpus > 64:
        raise E2eError("--cpus must be between 1 and 64")
    if not arguments.sleep_state:
        arguments.sleep_state = ["suspend"]
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


def require_operation(value: Any, action: str, cat_id: str) -> dict[str, Any]:
    if (
        not isinstance(value, dict)
        or value.get("version") != 1
        or value.get("action") != action
        or value.get("state") != "succeeded"
        or value.get("cat_id") != cat_id
        or not isinstance(value.get("operation_id"), str)
        or not value["operation_id"].startswith("op_")
        or not isinstance(value.get("terminal_at_unix_ms"), int)
    ):
        raise E2eError(f"{action} did not return one exact succeeded product Operation")
    return value


def require_cat(value: Any, cat_id: str, stable_state: str) -> dict[str, Any]:
    lifecycle = value.get("lifecycle") if isinstance(value, dict) else None
    if (
        not isinstance(lifecycle, dict)
        or value.get("version") != 1
        or value.get("id") != cat_id
        or lifecycle.get("stable_state") != stable_state
        or lifecycle.get("deleted_at_unix_ms") is not None
    ):
        raise E2eError(f"Cat did not reach product state {stable_state}")
    runtime_incarnation = lifecycle.get("runtime_incarnation")
    if stable_state in {"running", "suspended"}:
        if not isinstance(runtime_incarnation, str) or not runtime_incarnation:
            raise E2eError(f"{stable_state} Cat lacks a runtime incarnation")
    elif runtime_incarnation is not None:
        raise E2eError(f"{stable_state} Cat retained a runtime incarnation")
    return value


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
        isinstance(cat, dict) and cat.get("name") == arguments.cat_name for cat in before
    ):
        raise E2eError("preflight Cat list is invalid or test name already exists")
    accepted = invoke(
        "create-accepted",
        "create",
        arguments.cat_name,
        "--boot-image-digest",
        arguments.boot_image_digest,
        "--cpus",
        str(arguments.cpus),
        "--memory",
        arguments.memory,
        "--root-size",
        arguments.root_size,
        "--durability",
        "strict",
    )
    if (
        not isinstance(accepted, dict)
        or set(accepted) != {"cat_id", "operation_id"}
        or not isinstance(accepted.get("cat_id"), str)
        or not accepted["cat_id"].startswith("cat_")
        or not isinstance(accepted.get("operation_id"), str)
        or not accepted["operation_id"].startswith("op_")
    ):
        raise E2eError("create did not return one exact accepted Cat/Operation identity")
    cat_id = accepted["cat_id"]
    create = invoke("create-terminal", "operation", "wait", accepted["operation_id"])
    require_operation(create, "create", cat_id)
    running = require_cat(invoke("create-running", "get", cat_id), cat_id, "running")
    current_incarnation = running["lifecycle"]["runtime_incarnation"]

    for sleep_action in arguments.sleep_state:
        terminal = invoke(f"{sleep_action}-terminal", sleep_action, cat_id)
        require_operation(terminal, sleep_action, cat_id)
        sleeping = require_cat(
            invoke(f"{sleep_action}-state", "get", cat_id),
            cat_id,
            SLEEP_STATES[sleep_action],
        )
        if sleep_action == "suspend" and (
            sleeping["lifecycle"]["runtime_incarnation"] != current_incarnation
        ):
            raise E2eError("suspend changed the retained runtime incarnation")
        wake = invoke(f"run-after-{sleep_action}-terminal", "run", cat_id)
        require_operation(wake, "run", cat_id)
        running = require_cat(
            invoke(f"running-after-{sleep_action}", "get", cat_id), cat_id, "running"
        )
        if sleep_action == "suspend" and (
            running["lifecycle"]["runtime_incarnation"] != current_incarnation
        ):
            raise E2eError("run after suspend replaced the retained runtime incarnation")
        current_incarnation = running["lifecycle"]["runtime_incarnation"]

    destroy = invoke("destroy-terminal", "destroy", cat_id)
    require_operation(destroy, "destroy", cat_id)
    after = invoke("cats-after", "ls")
    if not isinstance(after, list) or any(
        isinstance(cat, dict) and cat.get("id") == cat_id for cat in after
    ):
        raise E2eError("destroyed Cat remains in the product list")
    return {
        "api_url": arguments.api_url,
        "boot_image_digest": arguments.boot_image_digest,
        "cat_id": cat_id,
        "cat_name": arguments.cat_name,
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
    parser.add_argument("--boot-image-digest", required=True)
    parser.add_argument("--cat-name", required=True)
    parser.add_argument(
        "--sleep-state",
        action="append",
        choices=sorted(SLEEP_STATES),
        help="repeat to exercise multiple public sleep states; default: suspend",
    )
    parser.add_argument("--cpus", type=int, default=2)
    parser.add_argument("--memory", default="2GiB")
    parser.add_argument("--root-size", default="4GiB")
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
