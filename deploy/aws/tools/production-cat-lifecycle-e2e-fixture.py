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


def cat(cat_id: str, state: str, incarnation: str | None) -> dict:
    return {
        "version": 1,
        "id": cat_id,
        "name": "release-e2e",
        "lifecycle": {
            "stable_state": state,
            "runtime_incarnation": incarnation,
            "deleted_at_unix_ms": None,
        },
    }


def operation(cat_id: str, action: str, sequence: int) -> dict:
    return {
        "version": 1,
        "operation_id": f"op_{sequence}",
        "cat_id": cat_id,
        "action": action,
        "state": "succeeded",
        "terminal_at_unix_ms": sequence,
    }


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
            sleep_state=["suspend", "warm", "cold"],
            cpus=2,
            memory="2GiB",
            root_size="4GiB",
            output=root / "evidence",
        )
        token, observed_qualification, qualification_raw = driver.validate_arguments(arguments)
        assert token == "fixture-secret-token"
        assert observed_qualification == qualification
        assert token not in driver.cli_command(arguments, "ls")

        cat_id = "cat_fixture"
        first_incarnation = "1" * 32
        warm_incarnation = "2" * 32
        cold_incarnation = "3" * 32
        responses = iter(
            [
                [],
                {"cat_id": cat_id, "operation_id": "op_create"},
                operation(cat_id, "create", 1),
                cat(cat_id, "running", first_incarnation),
                operation(cat_id, "suspend", 2),
                cat(cat_id, "suspended", first_incarnation),
                operation(cat_id, "run", 3),
                cat(cat_id, "running", first_incarnation),
                operation(cat_id, "warm", 4),
                cat(cat_id, "warm", None),
                operation(cat_id, "run", 5),
                cat(cat_id, "running", warm_incarnation),
                operation(cat_id, "cold", 6),
                cat(cat_id, "cold", None),
                operation(cat_id, "run", 7),
                cat(cat_id, "running", cold_incarnation),
                operation(cat_id, "destroy", 8),
                [],
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
        assert receipt["sleep_states"] == ["suspend", "warm", "cold"]
        assert len(receipt["evidence"]) == len(observed_commands) == 18
        assert observed_commands[0] == ("ls",)
        assert observed_commands[-2] == ("destroy", cat_id)
        assert observed_commands[-1] == ("ls",)
        assert all(token not in command for command in observed_commands)

        try:
            driver.require_cat(cat(cat_id, "warm", first_incarnation), cat_id, "warm")
        except driver.E2eError as error:
            assert "retained a runtime incarnation" in str(error)
        else:
            raise AssertionError("Warm incorrectly accepted a retained incarnation")

    print("production Cat lifecycle E2E fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
