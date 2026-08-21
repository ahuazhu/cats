#!/usr/bin/env python3
"""Provision and activate a fresh, cordoned Runtime Node fleet through SSM.

The deployment provisioner private key never leaves this operator process. Node
Hosts receive only their own public identity apply result.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import stat
import subprocess
import sys
import time
from typing import Any


COMPONENT_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
DIGEST_RE = re.compile(r"^[0-9a-f]{64}$")
INSTANCE_RE = re.compile(r"^i-[0-9a-f]{8,32}$")
HTTPS_ORIGIN_RE = re.compile(r"^https://[A-Za-z0-9.-]+(?::[0-9]{1,5})?$")
S3_URI_RE = re.compile(r"^s3://[A-Za-z0-9][A-Za-z0-9.-]{1,62}/[^\s]+$")


class ProvisionError(RuntimeError):
    pass


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, ensure_ascii=False, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def read_bytes(path: Path, description: str) -> bytes:
    try:
        metadata = path.lstat()
    except OSError as error:
        raise ProvisionError(f"cannot inspect {description} {path}: {error}") from error
    if not stat.S_ISREG(metadata.st_mode) or stat.S_ISLNK(metadata.st_mode):
        raise ProvisionError(f"{description} is not a regular file: {path}")
    if metadata.st_size <= 0:
        raise ProvisionError(f"{description} is empty: {path}")
    if metadata.st_mode & 0o022:
        raise ProvisionError(f"{description} is writable by another user: {path}")
    try:
        return path.read_bytes()
    except OSError as error:
        raise ProvisionError(f"cannot read {description} {path}: {error}") from error


def read_json(path: Path, description: str) -> tuple[Any, bytes]:
    raw = read_bytes(path, description)
    try:
        return json.loads(raw), raw
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ProvisionError(f"{description} is not JSON: {path}: {error}") from error


def require_private_key(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISREG(metadata.st_mode)
        or stat.S_ISLNK(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o600
        or metadata.st_nlink != 1
        or metadata.st_uid != os.geteuid()
    ):
        raise ProvisionError(
            "provisioner private key must be a current-user-owned, single-link 0600 file"
        )
    if metadata.st_size <= 0:
        raise ProvisionError("provisioner private key is empty")


def write_exact(path: Path, raw: bytes) -> None:
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        if path.read_bytes() != raw:
            raise ProvisionError(f"evidence path conflicts with this run: {path}")
        if stat.S_IMODE(path.stat().st_mode) != 0o600:
            raise ProvisionError(f"existing evidence is not mode 0600: {path}")
        return
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def checked_component(value: Any, description: str) -> str:
    if not isinstance(value, str) or COMPONENT_RE.fullmatch(value) is None:
        raise ProvisionError(f"{description} is not a safe identifier")
    return value


def run(command: list[str], description: str) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(command, check=False, capture_output=True)
    except OSError as error:
        raise ProvisionError(f"cannot run {description}: {error}") from error
    if result.returncode != 0:
        detail = result.stderr.decode("utf-8", "replace").strip()
        raise ProvisionError(f"{description} failed: {detail[-4000:]}")
    return result


class SsmRunner:
    def __init__(self, region: str, timeout_seconds: int) -> None:
        self.region = region
        self.timeout_seconds = timeout_seconds

    def invoke(self, instance_id: str, shell_program: str, description: str) -> bytes:
        parameters = json.dumps(
            {"commands": [shell_program]}, ensure_ascii=True, separators=(",", ":")
        )
        sent = run(
            [
                "aws",
                "ssm",
                "send-command",
                "--region",
                self.region,
                "--instance-ids",
                instance_id,
                "--document-name",
                "AWS-RunShellScript",
                "--parameters",
                parameters,
                "--query",
                "Command.CommandId",
                "--output",
                "text",
            ],
            f"submit {description}",
        )
        command_id = sent.stdout.decode("ascii", "strict").strip()
        if COMPONENT_RE.fullmatch(command_id) is None:
            raise ProvisionError(f"submit {description} returned an invalid command ID")

        deadline = time.monotonic() + self.timeout_seconds
        while time.monotonic() < deadline:
            observed = subprocess.run(
                [
                    "aws",
                    "ssm",
                    "get-command-invocation",
                    "--region",
                    self.region,
                    "--command-id",
                    command_id,
                    "--instance-id",
                    instance_id,
                    "--output",
                    "json",
                ],
                check=False,
                capture_output=True,
            )
            if observed.returncode != 0:
                if b"InvocationDoesNotExist" in observed.stderr:
                    time.sleep(1)
                    continue
                raise ProvisionError(
                    f"observe {description} failed: "
                    + observed.stderr.decode("utf-8", "replace")[-4000:]
                )
            try:
                invocation = json.loads(observed.stdout)
            except json.JSONDecodeError as error:
                raise ProvisionError(f"observe {description} returned invalid JSON") from error
            status = invocation.get("Status")
            if status == "Success":
                output = invocation.get("StandardOutputContent", "")
                if not isinstance(output, str):
                    raise ProvisionError(f"{description} stdout is not text")
                return output.encode("utf-8")
            if status in {"Cancelled", "Cancelling", "Failed", "TimedOut"}:
                stderr = invocation.get("StandardErrorContent", "")
                stdout = invocation.get("StandardOutputContent", "")
                raise ProvisionError(
                    f"{description} ended {status}: stdout={str(stdout)[-2000:]} "
                    f"stderr={str(stderr)[-4000:]}"
                )
            time.sleep(1)
        raise ProvisionError(f"{description} exceeded {self.timeout_seconds} seconds")


def shell_join(lines: list[str]) -> str:
    return "\n".join(["set -eu", "umask 077", *lines])


def prepare_program(
    node: dict[str, str],
    *,
    deployment_id: str,
    bundle_uri: str,
    bundle_sha256: str,
    cats_cli_sha256: str,
) -> str:
    remote_root = f"/root/cats-node-provision/{deployment_id}/{node['node_id']}"
    q = shlex.quote
    prepare = [
        q(f"{remote_root}/cats"),
        "admin",
        "runtime-provisioner",
        "node-identity",
        "prepare",
        "--node-id",
        q(node["node_id"]),
        "--host-provider",
        q(node["host_provider"]),
        "--host-partition",
        q(node["host_partition"]),
        "--host-account-id",
        q(node["host_account_id"]),
        "--host-region",
        q(node["host_region"]),
        "--immutable-host-id",
        q(node["immutable_host_id"]),
        "--state-path-id",
        q(node["state_path_id"]),
        "--credential-id",
        q(node["credential_id"]),
    ]
    return shell_join(
        [
            "if systemctl is-active --quiet cats-worker.service; then "
            "echo 'cats-worker must be stopped before identity provisioning' >&2; exit 41; fi",
            f"install -d -m 0700 {q(remote_root)}",
            f"bundle={q(remote_root + '/cats-worker.tar.zst')}",
            f"stage=$(mktemp -d {q(remote_root + '/stage.XXXXXX')})",
            "trap 'rm -rf -- \"$stage\"' EXIT INT TERM",
            f"aws s3 cp --only-show-errors --no-progress {q(bundle_uri)} \"$bundle\"",
            f"printf '%s  %s\\n' {q(bundle_sha256)} \"$bundle\" | sha256sum --check --strict - >/dev/null",
            "tar --zstd -xf \"$bundle\" -C \"$stage\" ./cats",
            f"printf '%s  %s\\n' {q(cats_cli_sha256)} \"$stage/cats\" | sha256sum --check --strict - >/dev/null",
            f"install -m 0755 \"$stage/cats\" {q(remote_root + '/cats')}",
            "if [ -s /etc/cats/identity/node-identity.v1.json ]; then",
            "  base64 -w0 /etc/cats/identity/node-identity.v1.json",
            "else",
            "  " + " ".join(prepare) + " >/dev/null",
            f"  {q(remote_root + '/cats')} admin runtime-provisioner node-identity export | base64 -w0",
            "fi",
        ]
    )


def activate_program(
    node: dict[str, str], *, deployment_id: str, result_b64: str
) -> str:
    remote_root = f"/root/cats-node-provision/{deployment_id}/{node['node_id']}"
    q = shlex.quote
    result = f"{remote_root}/node-authority-result.v1.json"
    return shell_join(
        [
            "if systemctl is-active --quiet cats-worker.service; then "
            "echo 'cats-worker must be stopped before identity activation' >&2; exit 41; fi",
            f"install -d -m 0700 {q(remote_root)}",
            f"printf '%s' {q(result_b64)} | base64 -d > {q(result)}",
            f"chmod 0600 {q(result)}",
            f"{q(remote_root + '/cats')} admin runtime-provisioner node-identity activate "
            f"--apply-result {q(result)} >/dev/null",
            "base64 -w0 /etc/cats/identity/node-identity.v1.json",
        ]
    )


def load_nodes(path: Path) -> list[dict[str, str]]:
    value, _ = read_json(path, "Node manifest")
    if not isinstance(value, list) or not value:
        raise ProvisionError("Node manifest must be a non-empty JSON array")
    required = {
        "node_id",
        "instance_id",
        "host_provider",
        "host_partition",
        "host_account_id",
        "host_region",
        "immutable_host_id",
        "state_path_id",
        "credential_id",
        "policy_file",
    }
    nodes: list[dict[str, str]] = []
    seen_nodes: set[str] = set()
    seen_instances: set[str] = set()
    for position, candidate in enumerate(value):
        if not isinstance(candidate, dict) or set(candidate) != required:
            raise ProvisionError(
                f"Node manifest entry {position} must contain exactly {sorted(required)}"
            )
        node = {key: str(candidate[key]) for key in required}
        for key in required - {"policy_file", "instance_id"}:
            checked_component(node[key], f"entry {position} {key}")
        if INSTANCE_RE.fullmatch(node["instance_id"]) is None:
            raise ProvisionError(f"entry {position} has an invalid EC2 instance ID")
        if node["node_id"] in seen_nodes or node["instance_id"] in seen_instances:
            raise ProvisionError("Node manifest contains a duplicate Node or instance")
        seen_nodes.add(node["node_id"])
        seen_instances.add(node["instance_id"])

        policy_path = Path(node["policy_file"])
        if not policy_path.is_absolute():
            raise ProvisionError(f"policy_file must be absolute for {node['node_id']}")
        policy, policy_raw = read_json(policy_path, "cordoned Node policy")
        if canonical_json(policy) != policy_raw:
            raise ProvisionError(f"Node policy is not canonical JSON: {policy_path}")
        if not isinstance(policy, dict) or any(
            [
                policy.get("node_id") != node["node_id"],
                policy.get("policy_revision") != 1,
                policy.get("scheduling_state") != "cordoned",
            ]
        ):
            raise ProvisionError(
                f"policy for {node['node_id']} must be initial revision 1 and cordoned"
            )
        nodes.append(node)
    return nodes


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nodes", required=True, type=Path)
    parser.add_argument("--cats-cli", required=True, type=Path)
    parser.add_argument("--cats-cli-sha256", required=True)
    parser.add_argument("--worker-bundle-s3-uri", required=True)
    parser.add_argument("--worker-bundle-sha256", required=True)
    parser.add_argument("--api-url", required=True)
    parser.add_argument("--deployment-id", required=True)
    parser.add_argument("--provisioner-credential-id", required=True)
    parser.add_argument("--provisioner-private-key-file", required=True, type=Path)
    parser.add_argument("--evidence-dir", required=True, type=Path)
    parser.add_argument("--aws-region", required=True)
    parser.add_argument("--ssm-timeout-seconds", type=int, default=600)
    return parser.parse_args(argv)


def main(argv: list[str]) -> int:
    args = parse_args(argv)
    for digest, description in [
        (args.cats_cli_sha256, "Cats CLI SHA-256"),
        (args.worker_bundle_sha256, "worker bundle SHA-256"),
    ]:
        if DIGEST_RE.fullmatch(digest) is None:
            raise ProvisionError(f"{description} must be 64 lowercase hex characters")
    if HTTPS_ORIGIN_RE.fullmatch(args.api_url) is None:
        raise ProvisionError("--api-url must be one canonical HTTPS origin")
    if S3_URI_RE.fullmatch(args.worker_bundle_s3_uri) is None:
        raise ProvisionError("--worker-bundle-s3-uri is invalid")
    deployment_id = checked_component(args.deployment_id, "deployment ID")
    provisioner_credential_id = checked_component(
        args.provisioner_credential_id, "provisioner credential ID"
    )
    checked_component(args.aws_region, "AWS region")
    if args.ssm_timeout_seconds <= 0:
        raise ProvisionError("--ssm-timeout-seconds must be positive")

    cats_cli = read_bytes(args.cats_cli, "Cats CLI")
    if sha256(cats_cli) != args.cats_cli_sha256:
        raise ProvisionError("Cats CLI digest does not match --cats-cli-sha256")
    if not os.access(args.cats_cli, os.X_OK):
        raise ProvisionError("Cats CLI is not executable")
    require_private_key(args.provisioner_private_key_file)
    nodes = load_nodes(args.nodes)

    args.evidence_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    evidence_metadata = args.evidence_dir.lstat()
    if (
        not stat.S_ISDIR(evidence_metadata.st_mode)
        or stat.S_ISLNK(evidence_metadata.st_mode)
        or evidence_metadata.st_uid != os.geteuid()
        or stat.S_IMODE(evidence_metadata.st_mode) & 0o077
    ):
        raise ProvisionError("evidence directory must be current-user-owned and mode 0700")

    ssm = SsmRunner(args.aws_region, args.ssm_timeout_seconds)
    receipt_nodes: list[dict[str, str]] = []
    for node in nodes:
        node_id = node["node_id"]
        identity_b64 = ssm.invoke(
            node["instance_id"],
            prepare_program(
                node,
                deployment_id=deployment_id,
                bundle_uri=args.worker_bundle_s3_uri,
                bundle_sha256=args.worker_bundle_sha256,
                cats_cli_sha256=args.cats_cli_sha256,
            ),
            f"prepare Node identity {node_id}",
        ).strip()
        try:
            identity_raw = base64.b64decode(identity_b64, validate=True)
            identity = json.loads(identity_raw)
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProvisionError(f"{node_id} returned an invalid public identity") from error
        if not isinstance(identity, dict) or any(
            [
                identity.get("node_id") != node_id,
                identity.get("immutable_host_id") != node["immutable_host_id"],
                identity.get("state_path_id") != node["state_path_id"],
            ]
        ):
            raise ProvisionError(f"{node_id} returned a different public identity")
        identity_path = args.evidence_dir / f"{node_id}-node-identity.v1.json"
        write_exact(identity_path, identity_raw)

        provisioned = run(
            [
                str(args.cats_cli),
                "--api-url",
                args.api_url,
                "--json",
                "admin",
                "runtime-node",
                "--deployment-id",
                deployment_id,
                "--provisioner-credential-id",
                provisioner_credential_id,
                "--provisioner-private-key-file",
                str(args.provisioner_private_key_file),
                "provision",
                "--identity",
                str(identity_path),
                "--policy",
                node["policy_file"],
            ],
            f"provision Node authority {node_id}",
        ).stdout
        try:
            result = json.loads(provisioned)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ProvisionError(f"official CLI returned invalid JSON for {node_id}") from error
        if not isinstance(result, dict) or any(
            [
                result.get("node_id") != node_id,
                result.get("outcome") != "provisioned",
                result.get("identity_state") != "provisioned",
                result.get("policy_revision") != 1,
            ]
        ):
            raise ProvisionError(f"official CLI did not provision {node_id}")
        result_path = args.evidence_dir / f"{node_id}-authority-result.v1.json"
        write_exact(result_path, provisioned)

        activated_b64 = ssm.invoke(
            node["instance_id"],
            activate_program(
                node,
                deployment_id=deployment_id,
                result_b64=base64.b64encode(provisioned).decode("ascii"),
            ),
            f"activate Node identity {node_id}",
        ).strip()
        try:
            activated = base64.b64decode(activated_b64, validate=True)
        except ValueError as error:
            raise ProvisionError(f"{node_id} returned invalid activated identity") from error
        if activated != identity_raw:
            raise ProvisionError(f"{node_id} activated a different identity")
        receipt_nodes.append(
            {
                "authority_result_sha256": f"sha256:{sha256(provisioned)}",
                "identity_sha256": f"sha256:{sha256(identity_raw)}",
                "instance_id": node["instance_id"],
                "node_id": node_id,
            }
        )

    receipt = {
        "api_origin": args.api_url,
        "deployment_id": deployment_id,
        "kind": "cats.cordoned-node-provisioning-receipt.v1",
        "nodes": sorted(receipt_nodes, key=lambda item: item["node_id"]),
        "provisioner_credential_id": provisioner_credential_id,
        "version": 1,
        "worker_bundle_sha256": f"sha256:{args.worker_bundle_sha256}",
    }
    receipt_path = args.evidence_dir / "cordoned-node-provisioning-receipt.v1.json"
    write_exact(receipt_path, canonical_json(receipt))
    print(receipt_path)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except ProvisionError as error:
        print(f"error: {error}", file=sys.stderr)
        raise SystemExit(1)
