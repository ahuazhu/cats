#!/usr/bin/env python3
"""Offline lifecycle trace fixture for production-cat-lifecycle-e2e.py."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import tempfile
import time


def load_driver(path: Path):
    specification = importlib.util.spec_from_file_location("cats_lifecycle_e2e", path)
    if specification is None or specification.loader is None:
        raise AssertionError("could not load lifecycle E2E driver")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def cat(cat_id: str, state: str, *, mounts: list[dict] | None = None) -> dict:
    placed = state in {"running", "suspended", "warm"}
    return {
        "boot_image": "sha256:" + "1" * 64,
        "cat_id": cat_id,
        "cat_slug": "release-e2e",
        "cpu": 2,
        "created_at_unix_ms": 1,
        "current_action": None,
        "destroyed_at_unix_ms": 2 if state == "destroyed" else None,
        "last_error": None,
        "memory_bytes": 2 * 1024**3,
        "mounts": mounts or [],
        "node_id": "node_fixture" if placed else None,
        "node_name": "fixture-node" if placed else None,
        "state": state,
        "updated_at_unix_ms": 2,
        "workspace_id": "ws_fixture",
    }


def cat_response(cat_value: dict, status: str, code: str) -> dict:
    return {"cat": cat_value, "code": code, "status": status}


def disk(
    disk_id: str,
    status: str = "normal",
    binding: dict | None = None,
) -> dict:
    return {
        "binding": binding,
        "created_at_unix_ms": 1,
        "deleted_at_unix_ms": 2 if status == "deleted" else None,
        "disk_id": disk_id,
        "disk_slug": "release-disk",
        "size_bytes": 1024**3,
        "status": status,
        "workspace_id": "ws_fixture",
    }


def disk_response(disk_value: dict, status: str, code: str) -> dict:
    return {"code": code, "disk": disk_value, "status": status}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--driver", required=True, type=Path)
    options = parser.parse_args()
    driver = load_driver(options.driver.resolve())

    with tempfile.TemporaryDirectory(prefix="cats-production-lifecycle-fixture-") as temporary:
        root = Path(temporary).resolve()
        cli = root / "cats"
        cli.write_text("#!/bin/sh\nexit 1\n")
        cli.chmod(0o755)
        token_file = root / "token"
        token_file.write_text("fixture-secret-token\n")
        token_file.chmod(0o600)
        qualification_file = root / "production-mutation-qualification-begin.receipt.json"
        qualification = {
            "allowed_mutation_classes": [
                "cat_create",
                "disk_create",
                "disk_delete",
                "object_write_ambiguity",
                "runtime_mutation",
            ],
            "begin_command_id": "command_fixture",
            "begin_command_receipt_sha256": "sha256:" + "1" * 64,
            "begin_request_sha256": "sha256:" + "2" * 64,
            "binding_sha256": "sha256:" + "3" * 64,
            "kind": "cats.production-mutation-qualification-begin-receipt.v1",
            "qualification_catalog_sha256": "sha256:" + "4" * 64,
            "qualification_expires_at_unix_ms": int(time.time() * 1000) + 60_000,
            "qualification_id": "qualification_fixture",
            "release_id": "release_fixture",
            "resulting_revision": 2,
            "source_commit_sha": "a" * 40,
            "version": 1,
            "workspace_id": "ws_fixture",
        }
        qualification_file.write_bytes(
            json.dumps(qualification, sort_keys=True, separators=(",", ":")).encode()
        )
        arguments = argparse.Namespace(
            cats_cli=cli,
            api_url="https://cats.run",
            token_file=token_file,
            qualification_begin_receipt=qualification_file,
            workspace_id="ws_fixture",
            boot_image_digest="sha256:" + "1" * 64,
            cat_name="release-e2e",
            disk_name="release-disk",
            disk_size="1GiB",
            mount_path="/data",
            sleep_state=["suspend", "warm", "cold"],
            cpus=2,
            memory="2GiB",
            output=root / "evidence",
        )
        token, observed_qualification, qualification_raw = driver.validate_arguments(arguments)
        assert token == "fixture-secret-token"
        assert observed_qualification == qualification
        assert token not in driver.cli_command(arguments, "ls")

        cat_id = "cat_fixture"
        disk_id = "disk_fixture"
        replacement_cat_id = "cat_replacement"
        replacement_disk_id = "disk_replacement"
        mount = {
            "disk_id": disk_id,
            "disk_slug": "release-disk",
            "mount_path": "/data",
        }
        binding = {
            "cat_id": cat_id,
            "cat_slug": "release-e2e",
            "mount_path": "/data",
        }
        responses = iter(
            [
                [],
                [],
                disk_response(disk(disk_id), "ok", "disk_created"),
                disk_response(disk(disk_id), "already_exists", "already_exists"),
                cat_response(cat(cat_id, "running", mounts=[mount]), "ok", "cat_created"),
                cat_response(
                    cat(cat_id, "running", mounts=[mount]),
                    "already_exists",
                    "already_exists",
                ),
                cat(cat_id, "running", mounts=[mount]),
                cat_response(cat(cat_id, "suspended", mounts=[mount]), "ok", "cat_suspended"),
                cat_response(
                    cat(cat_id, "suspended", mounts=[mount]),
                    "already_done",
                    "already_suspended",
                ),
                cat(cat_id, "suspended", mounts=[mount]),
                cat_response(cat(cat_id, "running", mounts=[mount]), "ok", "cat_running"),
                cat_response(
                    cat(cat_id, "running", mounts=[mount]),
                    "already_done",
                    "already_running",
                ),
                cat_response(cat(cat_id, "warm", mounts=[mount]), "ok", "cat_warm"),
                cat_response(
                    cat(cat_id, "warm", mounts=[mount]), "already_done", "already_warm"
                ),
                cat(cat_id, "warm", mounts=[mount]),
                cat_response(cat(cat_id, "running", mounts=[mount]), "ok", "cat_running"),
                cat_response(
                    cat(cat_id, "running", mounts=[mount]),
                    "already_done",
                    "already_running",
                ),
                cat_response(cat(cat_id, "cold", mounts=[mount]), "ok", "cat_cold"),
                cat_response(
                    cat(cat_id, "cold", mounts=[mount]), "already_done", "already_cold"
                ),
                cat(cat_id, "cold", mounts=[mount]),
                cat_response(cat(cat_id, "running", mounts=[mount]), "ok", "cat_running"),
                cat_response(
                    cat(cat_id, "running", mounts=[mount]),
                    "already_done",
                    "already_running",
                ),
                cat_response(cat(cat_id, "cold", mounts=[mount]), "ok", "cat_cold"),
                disk_response(disk(disk_id), "ok", "disk_detached"),
                disk_response(disk(disk_id), "already_done", "already_detached"),
                disk_response(disk(disk_id, binding=binding), "ok", "disk_attached"),
                disk_response(
                    disk(disk_id, binding=binding), "already_done", "already_attached"
                ),
                cat_response(cat(cat_id, "running", mounts=[mount]), "ok", "cat_running"),
                cat_response(cat(cat_id, "destroyed"), "ok", "cat_destroyed"),
                disk_response(disk(disk_id, "deleted"), "ok", "disk_deleted"),
                [],
                [],
                disk_response(disk(replacement_disk_id), "ok", "disk_created"),
                cat_response(cat(replacement_cat_id, "running"), "ok", "cat_created"),
                cat_response(cat(replacement_cat_id, "destroyed"), "ok", "cat_destroyed"),
                disk_response(
                    disk(replacement_disk_id, "deleted"), "ok", "disk_deleted"
                ),
            ]
        )
        observed_commands: list[tuple[str, ...]] = []
        original_run_cli = driver.run_cli

        def fake_run_cli(_arguments, observed_token, _state_directory, *command):
            assert observed_token == token
            observed_commands.append(command)
            return next(responses)

        driver.run_cli = fake_run_cli
        try:
            receipt = driver.run_e2e(
                arguments, token, observed_qualification, qualification_raw
            )
        finally:
            driver.run_cli = original_run_cli
        assert receipt["status"] == "passed"
        assert receipt["cat_id"] == cat_id
        assert receipt["disk_id"] == disk_id
        assert receipt["sleep_states"] == ["suspend", "warm", "cold"]
        assert len(receipt["evidence"]) == len(observed_commands) == 36
        assert observed_commands[0] == ("ls",)
        assert observed_commands[1] == ("disk", "ls")
        assert observed_commands[-2] == ("destroy", "release-e2e")
        assert observed_commands[-1] == ("disk", "destroy", "release-disk")
        assert all(token not in command for command in observed_commands)

        try:
            driver.require_cat(cat(cat_id, "cold") | {"node_id": "node_bad"}, cat_id, "release-e2e", "cold")
        except driver.E2eError as error:
            assert "retains Node placement" in str(error)
        else:
            raise AssertionError("Cold incorrectly accepted retained placement")

    print("production Cat lifecycle E2E fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
