#!/usr/bin/env python3
"""Offline end-to-end fixture for provision-cordoned-nodes.py."""

from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile


def canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def write(path: Path, raw: bytes, mode: int) -> None:
    path.write_bytes(raw)
    path.chmod(mode)


FAKE_AWS = r'''#!/usr/bin/env python3
import base64
import json
import os
from pathlib import Path
import re
import sys

root = Path(os.environ["FAKE_AWS_STATE"])
root.mkdir(parents=True, exist_ok=True)
args = sys.argv[1:]

def option(name):
    return args[args.index(name) + 1]

if args[:2] == ["sts", "get-caller-identity"]:
    if args != [
        "sts", "get-caller-identity", "--region", "us-east-1", "--output", "json"
    ]:
        raise SystemExit("unexpected STS arguments: " + repr(args))
    account = os.environ.get("FAKE_AWS_ACCOUNT_ID", "123456789012")
    arn = os.environ.get(
        "FAKE_AWS_CALLER_ARN",
        f"arn:aws:iam::{account}:role/cats-provisioner-fixture",
    )
    print(json.dumps({"Account": account, "Arn": arn, "UserId": "fixture"}))
elif args[:2] == ["ssm", "send-command"]:
    instance = option("--instance-ids")
    program = json.loads(option("--parameters"))["commands"][0]
    counter_path = root / "counter"
    counter = int(counter_path.read_text() or "0") + 1 if counter_path.exists() else 1
    counter_path.write_text(str(counter))
    command_id = f"command-{counter}"
    with (root / "programs.jsonl").open("a") as log:
        log.write(json.dumps({"instance": instance, "program": program}) + "\n")

    identity_path = root / f"{instance}.identity"
    status = "Success"
    stderr = ""
    if os.environ.get("FAKE_AWS_FAIL_INSTANCE") == instance:
        status = "Failed"
        stdout = ""
        stderr = "calibrated fake SSM failure"
    elif " node-identity prepare " in program:
        if identity_path.exists():
            raw = identity_path.read_bytes()
        else:
            def program_option(name):
                match = re.search(rf"{re.escape(name)} ([A-Za-z0-9._:-]+)", program)
                if match is None:
                    raise SystemExit(f"missing {name}")
                return match.group(1)
            identity = {
                "credential_binding": {
                    "kind": "public_key",
                    "public_key_spki_sha256": "sha256:" + "a" * 64,
                },
                "credential_id": program_option("--credential-id"),
                "immutable_host_id": program_option("--immutable-host-id"),
                "node_id": program_option("--node-id"),
                "provider_scope": {
                    "account_id": program_option("--host-account-id"),
                    "partition": program_option("--host-partition"),
                    "provider": program_option("--host-provider"),
                    "region": program_option("--host-region"),
                },
                "state": "provisioned",
                "state_path_id": program_option("--state-path-id"),
                "version": 1,
            }
            raw = json.dumps(identity, sort_keys=True, separators=(",", ":")).encode()
            identity_path.write_bytes(raw)
        stdout = base64.b64encode(raw).decode()
    elif " node-identity activate " in program:
        stdout = base64.b64encode(identity_path.read_bytes()).decode()
    else:
        raise SystemExit("unexpected SSM program")
    (root / f"{command_id}.json").write_text(json.dumps({
        "Status": status,
        "StandardOutputContent": stdout,
        "StandardErrorContent": stderr,
    }))
    print(command_id)
elif args[:2] == ["ssm", "get-command-invocation"]:
    print((root / f"{option('--command-id')}.json").read_text())
else:
    raise SystemExit("unexpected fake aws arguments: " + repr(args))
'''


FAKE_CATS = r'''#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

args = sys.argv[1:]
if "provision" not in args:
    raise SystemExit("unexpected fake cats command")
identity = json.loads(Path(args[args.index("--identity") + 1]).read_text())
pending = Path(os.environ["FAKE_AWS_STATE"]) / f"{identity['node_id']}.authority-pending"
if not pending.exists():
    pending.write_text("pending")
    print(
        "error: Runtime Node authority response was not terminal; retry the same "
        "command to replay apply fixture (pending fixture)",
        file=sys.stderr,
    )
    raise SystemExit(1)
result = {
    "apply_id": "apply-" + identity["node_id"],
    "identity_state": "provisioned",
    "node_id": identity["node_id"],
    "outcome": "provisioned",
    "policy_revision": 1,
    "version": 1,
}
sys.stdout.buffer.write(json.dumps(result, sort_keys=True, separators=(",", ":")).encode())
'''


def invoke(
    script: Path,
    root: Path,
    *,
    fail_instance: str | None = None,
    aws_account_id: str | None = None,
    aws_caller_arn: str | None = None,
) -> subprocess.CompletedProcess[bytes]:
    fake_bin = root / "bin"
    state = root / "aws-state"
    evidence = root / "evidence"
    cats = fake_bin / "cats"
    operator_cats = fake_bin / "operator-cats"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_AWS_STATE"] = str(state)
    if fail_instance is not None:
        env["FAKE_AWS_FAIL_INSTANCE"] = fail_instance
    if aws_account_id is not None:
        env["FAKE_AWS_ACCOUNT_ID"] = aws_account_id
    if aws_caller_arn is not None:
        env["FAKE_AWS_CALLER_ARN"] = aws_caller_arn
    command = [
        sys.executable,
        str(script),
        "--nodes",
        str(root / "nodes.json"),
        "--cats-cli",
        str(cats),
        "--cats-cli-sha256",
        hashlib.sha256(cats.read_bytes()).hexdigest(),
        "--operator-cats-cli",
        str(operator_cats),
        "--operator-cats-cli-sha256",
        hashlib.sha256(operator_cats.read_bytes()).hexdigest(),
        "--worker-bundle-s3-uri",
        "s3://fixture-bucket/worker/release/cats-worker.tar.zst",
        "--worker-bundle-sha256",
        "b" * 64,
        "--api-url",
        "https://control.fixture.invalid",
        "--deployment-id",
        "fixture-deployment-r1",
        "--provisioner-credential-id",
        "fixture-provisioner-r1",
        "--provisioner-private-key-file",
        str(root / "provisioner.pem"),
        "--evidence-dir",
        str(evidence),
        "--aws-region",
        "us-east-1",
        "--ssm-timeout-seconds",
        "5",
    ]
    return subprocess.run(command, env=env, check=False, capture_output=True)


def make_fixture(root: Path) -> None:
    fake_bin = root / "bin"
    fake_bin.mkdir()
    write(fake_bin / "aws", FAKE_AWS.encode(), 0o755)
    write(fake_bin / "cats", FAKE_CATS.encode(), 0o755)
    write(fake_bin / "operator-cats", FAKE_CATS.encode() + b"\n# operator build\n", 0o755)
    write(root / "provisioner.pem", b"fixture-private-key\n", 0o600)

    nodes = []
    for number in (1, 2):
        node_id = f"metal-{number}"
        policy_path = root / f"{node_id}-policy.json"
        policy = {
            "allocatable_memory_bytes": 1024,
            "allocatable_vcpus": 1,
            "capabilities": {},
            "guest_ipv4_pool": {
                "kind": "private_ipv4_16",
                "network_address": "10.240.0.0",
                "prefix_length": 16,
            },
            "node_id": node_id,
            "node_transport_target": f"https://{node_id}.fixture.invalid:7301",
            "policy_revision": 1,
            "scheduling_state": "cordoned",
            "version": 1,
        }
        write(policy_path, canonical(policy), 0o600)
        nodes.append(
            {
                "credential_id": f"credential-{number}",
                "host_account_id": "123456789012",
                "host_partition": "aws",
                "host_provider": "aws",
                "host_region": "us-east-1",
                "immutable_host_id": f"i-0000000000000000{number}",
                "instance_id": f"i-0000000000000000{number}",
                "node_id": node_id,
                "policy_file": str(policy_path),
                "state_path_id": f"state_{node_id}_fixture",
            }
        )
    write(root / "nodes.json", canonical(nodes), 0o600)


def mutate_first_node(root: Path, field: str, value: str) -> None:
    nodes = json.loads((root / "nodes.json").read_bytes())
    nodes[0][field] = value
    write(root / "nodes.json", canonical(nodes), 0o600)


def existing_identity(root: Path) -> dict[str, object]:
    nodes = json.loads((root / "nodes.json").read_bytes())
    node = nodes[0]
    return {
        "credential_binding": {
            "kind": "public_key",
            "public_key_spki_sha256": "sha256:" + "a" * 64,
        },
        "credential_id": node["credential_id"],
        "immutable_host_id": node["immutable_host_id"],
        "node_id": node["node_id"],
        "provider_scope": {
            "account_id": node["host_account_id"],
            "partition": node["host_partition"],
            "provider": node["host_provider"],
            "region": node["host_region"],
        },
        "state": "provisioned",
        "state_path_id": node["state_path_id"],
        "version": 1,
    }


def install_existing_identity(root: Path, identity: dict[str, object]) -> None:
    nodes = json.loads((root / "nodes.json").read_bytes())
    state = root / "aws-state"
    state.mkdir()
    write(state / f"{nodes[0]['instance_id']}.identity", canonical(identity), 0o600)


def assert_manifest_drift_rejected(
    field: str, value: str, expected_error: bytes
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=f"cats-node-provision-{field}-negative-"
    ) as temporary:
        root = Path(temporary)
        make_fixture(root)
        mutate_first_node(root, field, value)
        failed = invoke(
            Path(__file__).resolve().with_name("provision-cordoned-nodes.py"), root
        )
        assert failed.returncode != 0, field
        assert expected_error in failed.stderr, failed.stderr.decode()
        assert not (root / "aws-state/programs.jsonl").exists(), field


def assert_existing_identity_drift_rejected(
    description: str, path: tuple[str, ...], value: object
) -> None:
    with tempfile.TemporaryDirectory(
        prefix=f"cats-node-provision-identity-{description}-negative-"
    ) as temporary:
        root = Path(temporary)
        make_fixture(root)
        identity = existing_identity(root)
        target = identity
        for component in path[:-1]:
            child = target[component]
            assert isinstance(child, dict)
            target = child
        target[path[-1]] = value
        install_existing_identity(root, identity)
        failed = invoke(
            Path(__file__).resolve().with_name("provision-cordoned-nodes.py"), root
        )
        assert failed.returncode != 0, description
        assert b"returned a different public identity" in failed.stderr, (
            description,
            failed.stderr.decode(),
        )
        assert not (root / "aws-state/metal-1.authority-pending").exists(), description


def main() -> int:
    script = Path(__file__).resolve().with_name("provision-cordoned-nodes.py")
    with tempfile.TemporaryDirectory(prefix="cats-node-provision-fixture-") as temporary:
        root = Path(temporary)
        make_fixture(root)
        first = invoke(script, root)
        assert first.returncode == 0, first.stderr.decode()
        receipt_path = root / "evidence/cordoned-node-provisioning-receipt.v1.json"
        receipt = json.loads(receipt_path.read_bytes())
        assert receipt["kind"] == "cats.cordoned-node-provisioning-receipt.v1"
        assert [node["node_id"] for node in receipt["nodes"]] == ["metal-1", "metal-2"]
        assert stat_mode(receipt_path) == 0o600

        replay = invoke(script, root)
        assert replay.returncode == 0, replay.stderr.decode()
        programs = (root / "aws-state/programs.jsonl").read_text()
        assert "fixture-private-key" not in programs
        assert programs.count("node-identity prepare") == 4
        assert programs.count("node-identity activate") == 4

    with tempfile.TemporaryDirectory(prefix="cats-node-provision-negative-") as temporary:
        root = Path(temporary)
        make_fixture(root)
        failed = invoke(script, root, fail_instance="i-00000000000000001")
        assert failed.returncode != 0
        assert b"calibrated fake SSM failure" in failed.stderr

    for field, value, expected_error in [
        (
            "immutable_host_id",
            "i-000000000000000ff",
            b"does not match its SSM instance",
        ),
        ("host_provider", "not_aws", b"provider scope"),
        ("host_partition", "aws-us-gov", b"provider scope"),
        ("host_account_id", "999999999999", b"provider scope"),
        ("host_region", "us-west-2", b"provider scope"),
    ]:
        assert_manifest_drift_rejected(field, value, expected_error)

    with tempfile.TemporaryDirectory(
        prefix="cats-node-provision-sts-account-negative-"
    ) as temporary:
        root = Path(temporary)
        make_fixture(root)
        failed = invoke(
            script,
            root,
            aws_account_id="not-an-account",
            aws_caller_arn="arn:aws:iam::not-an-account:role/fixture",
        )
        assert failed.returncode != 0
        assert b"account ID is not 12 decimal digits" in failed.stderr
        assert not (root / "aws-state/programs.jsonl").exists()

    with tempfile.TemporaryDirectory(
        prefix="cats-node-provision-sts-arn-negative-"
    ) as temporary:
        root = Path(temporary)
        make_fixture(root)
        failed = invoke(
            script,
            root,
            aws_caller_arn="arn:aws:s3::123456789012:bucket/fixture",
        )
        assert failed.returncode != 0
        assert b"AWS caller ARN is malformed" in failed.stderr
        assert not (root / "aws-state/programs.jsonl").exists()

    for description, path, value in [
        ("version", ("version",), 2),
        ("state", ("state",), "retired"),
        (
            "provider-scope",
            ("provider_scope", "account_id"),
            "999999999999",
        ),
        ("credential-id", ("credential_id",), "stale-credential"),
        (
            "binding-kind",
            ("credential_binding",),
            {
                "kind": "provider_principal",
                "principal": "stale-principal",
                "provider": "aws",
            },
        ),
    ]:
        assert_existing_identity_drift_rejected(description, path, value)
    print("provision-cordoned-nodes fixture: ok")
    return 0


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    raise SystemExit(main())
