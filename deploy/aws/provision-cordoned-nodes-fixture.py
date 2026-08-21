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

if args[:2] == ["ssm", "send-command"]:
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
from pathlib import Path
import sys

args = sys.argv[1:]
if "provision" not in args:
    raise SystemExit("unexpected fake cats command")
identity = json.loads(Path(args[args.index("--identity") + 1]).read_text())
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
) -> subprocess.CompletedProcess[bytes]:
    fake_bin = root / "bin"
    state = root / "aws-state"
    evidence = root / "evidence"
    cats = fake_bin / "cats"
    env = os.environ.copy()
    env["PATH"] = f"{fake_bin}:{env['PATH']}"
    env["FAKE_AWS_STATE"] = str(state)
    if fail_instance is not None:
        env["FAKE_AWS_FAIL_INSTANCE"] = fail_instance
    command = [
        sys.executable,
        str(script),
        "--nodes",
        str(root / "nodes.json"),
        "--cats-cli",
        str(cats),
        "--cats-cli-sha256",
        hashlib.sha256(cats.read_bytes()).hexdigest(),
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
    print("provision-cordoned-nodes fixture: ok")
    return 0


def stat_mode(path: Path) -> int:
    return path.stat().st_mode & 0o777


if __name__ == "__main__":
    raise SystemExit(main())
