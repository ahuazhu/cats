#!/usr/bin/env python3
"""Plan and apply one exact packaged release to the production AWS cell."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
from typing import Any


ACCOUNT = re.compile(r"[0-9]{12}\Z")
COMMIT = re.compile(r"[0-9a-f]{40}\Z")
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
INSTANCE = re.compile(r"i-[0-9a-f]{8,17}\Z")
REGION = re.compile(r"[a-z]{2}(?:-gov)?-[a-z]+-[0-9]\Z")
SCHEMA = re.compile(r"cats_[a-z0-9_]{1,58}\Z")
TERMINAL_SSM = {"Success", "Cancelled", "TimedOut", "Failed", "Cancelling"}
CONFIG_FIELDS = {
    "application_state_key",
    "application_tfvars",
    "aws_region",
    "control_postgres_schema",
    "default_boot_image_digest",
    "eks_cluster_name",
    "expected_account_id",
    "expected_aws_partition",
    "infrastructure_state_key",
    "infrastructure_tfvars",
    "kubeconfig_context",
    "kubeconfig_path",
    "namespace",
    "schema_version",
    "terraform_state_bucket",
    "worker_instances",
}


class DeploymentError(Exception):
    """The deployment could not preserve its reviewed identity or postcondition."""


def canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256_bytes(raw: bytes) -> str:
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def sha256_file(path: Path) -> str:
    measured = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            measured.update(chunk)
    return "sha256:" + measured.hexdigest()


def read_canonical(path: Path, label: str) -> tuple[dict[str, Any], bytes]:
    if not path.is_absolute() or not path.is_file() or path.is_symlink():
        raise DeploymentError(f"{label} must be an absolute real regular file")
    raw = path.read_bytes()
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise DeploymentError(f"{label} is not one UTF-8 JSON object") from error
    if not isinstance(value, dict) or canonical_json(value) != raw:
        raise DeploymentError(f"{label} is not canonical JSON")
    return value, raw


def require_new_directory(path: Path, label: str) -> None:
    if not path.is_absolute() or path.exists() or path.is_symlink():
        raise DeploymentError(f"{label} must be a new absolute path")
    if not path.parent.is_dir() or path.parent.is_symlink():
        raise DeploymentError(f"{label} parent must be an existing real directory")


def write_new(path: Path, raw: bytes, mode: int = 0o600) -> None:
    if path.exists() or path.is_symlink():
        raise DeploymentError(f"refusing to replace evidence file: {path}")
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("short evidence write")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def run(
    command: list[str],
    *,
    capture_output: bool = True,
    input_bytes: bytes | None = None,
) -> subprocess.CompletedProcess[bytes]:
    result = subprocess.run(
        command,
        input=input_bytes,
        capture_output=capture_output,
        check=False,
        env={**os.environ, "TF_IN_AUTOMATION": "1"},
    )
    if result.returncode != 0:
        stderr = "" if result.stderr is None else result.stderr.decode(errors="replace")[-8192:]
        raise DeploymentError(
            f"command failed with exit {result.returncode}: {command[0]}: {stderr}"
        )
    return result


def require_real_file(value: Any, label: str) -> Path:
    if not isinstance(value, str):
        raise DeploymentError(f"{label} must be an absolute path")
    path = Path(value)
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or path.resolve() != path
    ):
        raise DeploymentError(f"{label} must be a resolved real regular file")
    return path


def load_config(path: Path) -> tuple[dict[str, Any], bytes]:
    config, raw = read_canonical(path, "deployment config")
    if set(config) != CONFIG_FIELDS or config.get("schema_version") != 1:
        raise DeploymentError("deployment config has the wrong version or field set")
    if ACCOUNT.fullmatch(str(config["expected_account_id"])) is None:
        raise DeploymentError("deployment config account ID is invalid")
    if config["expected_aws_partition"] != "aws":
        raise DeploymentError("this production deployer accepts only the aws partition")
    if REGION.fullmatch(str(config["aws_region"])) is None:
        raise DeploymentError("deployment config region is invalid")
    if config["namespace"] != "cats":
        raise DeploymentError("deployment namespace must be cats")
    if not isinstance(config["eks_cluster_name"], str) or not config["eks_cluster_name"]:
        raise DeploymentError("deployment EKS cluster name is invalid")
    if config["kubeconfig_context"] != config["eks_cluster_name"]:
        raise DeploymentError("kubeconfig context must equal the reviewed EKS cluster name")
    require_real_file(config["kubeconfig_path"], "kubeconfig")
    if SCHEMA.fullmatch(str(config["control_postgres_schema"])) is None:
        raise DeploymentError("deployment Control PostgreSQL schema is invalid")
    if DIGEST.fullmatch(str(config["default_boot_image_digest"])) is None:
        raise DeploymentError("deployment default boot image digest is invalid")
    state_bucket = config["terraform_state_bucket"]
    if not isinstance(state_bucket, str) or not state_bucket.startswith("cats-"):
        raise DeploymentError("Terraform state bucket is invalid")
    for field in ("application_state_key", "infrastructure_state_key"):
        value = config[field]
        if not isinstance(value, str) or not value.endswith(".tfstate") or value.startswith("/"):
            raise DeploymentError(f"{field} is invalid")
    if config["application_state_key"] == config["infrastructure_state_key"]:
        raise DeploymentError("application and infrastructure state keys must differ")
    for field in ("application_tfvars", "infrastructure_tfvars"):
        values = config[field]
        if (
            not isinstance(values, list)
            or not values
            or any(not isinstance(value, str) for value in values)
        ):
            raise DeploymentError(f"{field} must be a nonempty list")
        if len(set(values)) != len(values):
            raise DeploymentError(f"{field} contains a duplicate path")
        for index, value in enumerate(values):
            require_real_file(value, f"{field}[{index}]")
    workers = config["worker_instances"]
    if not isinstance(workers, dict) or not workers:
        raise DeploymentError("worker_instances must be a nonempty object")
    if list(workers) != sorted(workers):
        raise DeploymentError("worker_instances keys must be sorted")
    if any(not isinstance(value, str) for value in workers.values()) or len(
        set(workers.values())
    ) != len(workers):
        raise DeploymentError("worker_instances contains a duplicate instance ID")
    for name, instance_id in workers.items():
        if re.fullmatch(r"[a-z0-9][a-z0-9-]{0,31}", name) is None:
            raise DeploymentError("worker_instances contains an invalid worker name")
        if not isinstance(instance_id, str) or INSTANCE.fullmatch(instance_id) is None:
            raise DeploymentError("worker_instances contains an invalid instance ID")
    return config, raw


def load_package(path: Path) -> tuple[dict[str, Any], dict[str, Any], bytes]:
    if not path.is_absolute() or not path.is_dir() or path.is_symlink() or path.resolve() != path:
        raise DeploymentError("package must be a resolved absolute real directory")
    receipt, receipt_raw = read_canonical(
        path / "production-package-receipt.v1.json", "production package receipt"
    )
    if set(receipt) != {
        "artifact_publication",
        "build_host_instance_id",
        "build_ssm_command_id",
        "images",
        "promoted_release_manifest_sha256",
        "readiness_ssm_command_id",
        "release_manifest_sha256",
        "schema_version",
        "source_bundle_sha256",
        "source_manifest_sha256",
        "source_sha",
        "status",
        "transport_sha256",
    } or receipt.get("schema_version") != 1:
        raise DeploymentError("production package receipt has the wrong shape")
    if receipt.get("status") != "registry_verified" or COMMIT.fullmatch(
        str(receipt.get("source_sha"))
    ) is None:
        raise DeploymentError("production package is not registry-verified")
    manifest_path = path / "release-manifest.registry-verified.v1.json"
    manifest, manifest_raw = read_canonical(manifest_path, "registry-verified release manifest")
    if sha256_bytes(manifest_raw) != receipt.get("promoted_release_manifest_sha256"):
        raise DeploymentError("registry-verified release manifest digest differs from package")
    if set(manifest) != {"artifacts", "build_inputs", "guest_runtime", "source", "version"}:
        raise DeploymentError("registry-verified release manifest has the wrong shape")
    source = manifest.get("source")
    if (
        manifest.get("version") != 1
        or not isinstance(source, dict)
        or source.get("commit") != receipt["source_sha"]
    ):
        raise DeploymentError("registry-verified release manifest source differs from package")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, dict) or set(artifacts) != {
        "control_plane",
        "credential_refresher",
        "gateway",
        "worker",
    }:
        raise DeploymentError("registry-verified release manifest has the wrong artifact set")
    receipt_images = receipt.get("images")
    if not isinstance(receipt_images, dict) or set(receipt_images) != {
        "control_plane",
        "credential_refresher",
        "gateway",
    }:
        raise DeploymentError("production package receipt has the wrong image set")
    for name in ("control_plane", "credential_refresher", "gateway"):
        image = artifacts.get(name)
        if not isinstance(image, dict) or image.get("registry_verified") is not True:
            raise DeploymentError(f"{name} image is not registry-verified")
        if not isinstance(image.get("image_reference"), str) or "@" in image["image_reference"]:
            raise DeploymentError(f"{name} image reference is invalid")
        if DIGEST.fullmatch(str(image.get("image_digest"))) is None:
            raise DeploymentError(f"{name} image digest is invalid")
        if receipt_images.get(name) != image["image_reference"]:
            raise DeploymentError(f"{name} image reference differs from package receipt")
    worker = artifacts["worker"]
    if not isinstance(worker, dict) or worker.get("bundle_name") != "cats-worker.tar.zst":
        raise DeploymentError("worker artifact has the wrong shape")
    worker_digest = worker.get("bundle_sha256")
    if DIGEST.fullmatch(str(worker_digest)) is None:
        raise DeploymentError("worker bundle digest is invalid")
    worker_path = path / "release" / "cats-worker.tar.zst"
    if not worker_path.is_file() or worker_path.is_symlink():
        raise DeploymentError("package lacks the real worker bundle")
    if sha256_file(worker_path) != worker_digest:
        raise DeploymentError("worker bundle digest differs from release manifest")
    return receipt, manifest, receipt_raw


def verify_source(repository: Path, source_sha: str) -> None:
    if not repository.is_absolute() or not repository.is_dir() or repository.is_symlink():
        raise DeploymentError("source repository must be an absolute real directory")
    if repository.resolve() != repository:
        raise DeploymentError("source repository must be resolved")
    head = run(["git", "-C", str(repository), "rev-parse", "HEAD"]).stdout.decode().strip()
    if head != source_sha:
        raise DeploymentError("source repository HEAD differs from packaged release")
    dirty = run(["git", "-C", str(repository), "status", "--porcelain=v1"]).stdout
    if dirty:
        raise DeploymentError("source repository must be clean for deployment")


def aws_json(config: dict[str, Any], *command: str) -> Any:
    result = run(
        [
            "aws",
            *command,
            "--region",
            config["aws_region"],
            "--output",
            "json",
            "--no-cli-pager",
        ]
    )
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise DeploymentError(f"AWS returned invalid JSON for {command[0]}") from error


def verify_live_target(config: dict[str, Any]) -> None:
    identity = aws_json(config, "sts", "get-caller-identity")
    if not isinstance(identity, dict) or identity.get("Account") != config["expected_account_id"]:
        raise DeploymentError("AWS caller differs from deployment config")
    cluster = aws_json(config, "eks", "describe-cluster", "--name", config["eks_cluster_name"])
    observed = cluster.get("cluster") if isinstance(cluster, dict) else None
    if not isinstance(observed, dict) or observed.get("status") != "ACTIVE":
        raise DeploymentError("reviewed EKS cluster is not ACTIVE")
    arn = observed.get("arn")
    expected_fragment = (
        f":{config['aws_region']}:{config['expected_account_id']}:cluster/"
        f"{config['eks_cluster_name']}"
    )
    if not isinstance(arn, str) or not arn.endswith(expected_fragment):
        raise DeploymentError("EKS cluster identity differs from deployment config")
    context = run(
        [
            "kubectl",
            "--kubeconfig",
            config["kubeconfig_path"],
            "config",
            "current-context",
        ]
    ).stdout.decode().strip()
    if context != config["kubeconfig_context"]:
        raise DeploymentError("kubeconfig current context differs from deployment config")


def image_refs(manifest: dict[str, Any]) -> dict[str, str]:
    return {
        name: f"{manifest['artifacts'][name]['image_reference']}@{manifest['artifacts'][name]['image_digest']}"
        for name in ("control_plane", "credential_refresher")
    }


def terraform_init_command(repository: Path, config: dict[str, Any], stack: str) -> list[str]:
    state_key = config[f"{stack}_state_key"]
    return [
        "terraform",
        f"-chdir={repository / 'deploy/aws/terraform/stacks' / ('production-' + stack)}",
        "init",
        "-input=false",
        "-reconfigure",
        f"-backend-config=bucket={config['terraform_state_bucket']}",
        f"-backend-config=key={state_key}",
        f"-backend-config=region={config['aws_region']}",
        "-backend-config=encrypt=true",
        "-backend-config=use_lockfile=true",
    ]


def terraform_plan_command(
    repository: Path,
    config: dict[str, Any],
    manifest: dict[str, Any],
    package: Path,
    stack: str,
    output: Path,
) -> list[str]:
    command = [
        "terraform",
        f"-chdir={repository / 'deploy/aws/terraform/stacks' / ('production-' + stack)}",
        "plan",
        "-input=false",
        "-lock-timeout=5m",
        f"-out={output}",
    ]
    for path in config[f"{stack}_tfvars"]:
        command.append(f"-var-file={path}")
    command.extend(
        [
            f"-var=expected_account_id={config['expected_account_id']}",
            f"-var=expected_aws_partition={config['expected_aws_partition']}",
            f"-var=aws_region={config['aws_region']}",
            f"-var=control_postgres_schema={config['control_postgres_schema']}",
        ]
    )
    if stack == "application":
        images = image_refs(manifest)
        command.extend(
            [
                f"-var=kubeconfig_path={config['kubeconfig_path']}",
                f"-var=kubeconfig_context={config['kubeconfig_context']}",
                f"-var=control_plane_image={images['control_plane']}",
                f"-var=default_boot_image_digest={config['default_boot_image_digest']}",
                f"-var=credential_refresher_image={images['credential_refresher']}",
            ]
        )
    else:
        worker = manifest["artifacts"]["worker"]
        command.extend(
            [
                "-var=metal_worker_enabled=true",
                f"-var=worker_bundle_path={package / 'release' / worker['bundle_name']}",
                f"-var=worker_bundle_sha256={worker['bundle_sha256'][7:]}",
                "-var=metal_worker_instances=" + canonical_json(config["worker_instances"]).decode(),
                "-var=metal_worker_deploy_instances="
                + canonical_json(sorted(config["worker_instances"])).decode(),
            ]
        )
    return command


def create_plan(arguments: argparse.Namespace) -> None:
    config, config_raw = load_config(arguments.config)
    receipt, manifest, package_receipt_raw = load_package(arguments.package)
    verify_source(arguments.source_repository, receipt["source_sha"])
    require_new_directory(arguments.output, "plan output")
    verify_live_target(config)
    arguments.output.mkdir(mode=0o700)
    plans: dict[str, dict[str, str]] = {}
    for stack in ("application", "infrastructure"):
        run(terraform_init_command(arguments.source_repository, config, stack), capture_output=False)
        plan_path = arguments.output / f"{stack}.tfplan"
        run(
            terraform_plan_command(
                arguments.source_repository,
                config,
                manifest,
                arguments.package,
                stack,
                plan_path,
            ),
            capture_output=False,
        )
        plan_path.chmod(0o600)
        show = run(
            [
                "terraform",
                f"-chdir={arguments.source_repository / 'deploy/aws/terraform/stacks' / ('production-' + stack)}",
                "show",
                "-json",
                str(plan_path),
            ]
        ).stdout
        show_path = arguments.output / f"{stack}.tfplan.json"
        write_new(show_path, show)
        plans[stack] = {
            "plan_sha256": sha256_file(plan_path),
            "show_sha256": sha256_file(show_path),
        }
    plan_receipt = {
        "config_sha256": sha256_bytes(config_raw),
        "package_receipt_sha256": sha256_bytes(package_receipt_raw),
        "plans": plans,
        "schema_version": 1,
        "source_sha": receipt["source_sha"],
        "status": "planned",
    }
    write_new(arguments.output / "production-deployment-plan-receipt.v1.json", canonical_json(plan_receipt))
    print(canonical_json({"output": str(arguments.output), **plan_receipt}).decode())


def kubectl_json(config: dict[str, Any], kind: str, name: str) -> dict[str, Any]:
    result = run(
        [
            "kubectl",
            "--kubeconfig",
            config["kubeconfig_path"],
            "--context",
            config["kubeconfig_context"],
            "--namespace",
            config["namespace"],
            "get",
            kind,
            name,
            "--output=json",
        ]
    )
    try:
        value = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise DeploymentError(f"kubectl returned invalid JSON for {kind}/{name}") from error
    if not isinstance(value, dict):
        raise DeploymentError(f"kubectl returned a non-object for {kind}/{name}")
    return value


def verify_application(config: dict[str, Any], manifest: dict[str, Any]) -> dict[str, Any]:
    images = image_refs(manifest)
    expected = {
        "cats-controld": images["control_plane"],
    }
    observed: dict[str, Any] = {}
    for deployment, expected_image in expected.items():
        run(
            [
                "kubectl",
                "--kubeconfig",
                config["kubeconfig_path"],
                "--context",
                config["kubeconfig_context"],
                "--namespace",
                config["namespace"],
                "rollout",
                "status",
                f"deployment/{deployment}",
                "--timeout=10m",
            ],
            capture_output=False,
        )
        value = kubectl_json(config, "deployment", deployment)
        pod = value.get("spec", {}).get("template", {}).get("spec", {})
        all_images = {
            container.get("image")
            for field in ("initContainers", "containers")
            for container in pod.get(field, [])
            if isinstance(container, dict) and isinstance(container.get("image"), str)
        }
        if all_images != {expected_image}:
            raise DeploymentError(f"{deployment} does not use only its packaged image")
        observed[deployment] = sorted(all_images)
    refresher = kubectl_json(config, "cronjob", "cats-credential-refresher")
    containers = (
        refresher.get("spec", {})
        .get("jobTemplate", {})
        .get("spec", {})
        .get("template", {})
        .get("spec", {})
        .get("containers", [])
    )
    refresher_images = {
        container.get("image")
        for container in containers
        if isinstance(container, dict) and isinstance(container.get("image"), str)
    }
    if refresher_images != {images["credential_refresher"]}:
        raise DeploymentError("credential refresher does not use its packaged image")
    observed["cats-credential-refresher"] = sorted(refresher_images)
    return observed


def send_worker_probe(config: dict[str, Any], instance_ids: list[str], digest: str) -> str:
    command = (
        "set -eu\n"
        "receipt=/opt/cats/release/worker-installation-receipt.v1.json\n"
        "deadline=$(( $(date +%s) + 600 ))\n"
        "while [ \"$(date +%s)\" -lt \"$deadline\" ]; do\n"
        "  if test -f \"$receipt\" \\\n"
        f"    && test \"$(jq -er .worker_bundle_sha256 \"$receipt\" 2>/dev/null || true)\" = {json.dumps(digest)} \\\n"
        "    && systemctl is-active --quiet cats-worker.service; then\n"
        f"    jq -cnS --arg digest {json.dumps(digest)} "
        "'{status:\"installed\",worker_bundle_sha256:$digest}'\n"
        "    exit 0\n"
        "  fi\n"
        "  sleep 5\n"
        "done\n"
        "echo 'worker installation did not converge before the probe deadline' >&2\n"
        "exit 1\n"
    )
    response = aws_json(
        config,
        "ssm",
        "send-command",
        "--instance-ids",
        *instance_ids,
        "--document-name",
        "AWS-RunShellScript",
        "--parameters",
        json.dumps({"commands": [command], "executionTimeout": ["660"]}, separators=(",", ":")),
    )
    command_id = response.get("Command", {}).get("CommandId") if isinstance(response, dict) else None
    if not isinstance(command_id, str) or not command_id:
        raise DeploymentError("SSM worker probe returned no command ID")
    return command_id


def wait_worker_probe(config: dict[str, Any], command_id: str, instance_id: str) -> None:
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            response = aws_json(
                config,
                "ssm",
                "get-command-invocation",
                "--command-id",
                command_id,
                "--instance-id",
                instance_id,
            )
        except DeploymentError as error:
            if "InvocationDoesNotExist" not in str(error):
                raise
            time.sleep(5)
            continue
        status = response.get("Status") if isinstance(response, dict) else None
        if status in TERMINAL_SSM:
            if status != "Success" or response.get("ResponseCode") != 0:
                raise DeploymentError(f"worker probe failed on {instance_id}: {status}")
            try:
                result = json.loads(str(response.get("StandardOutputContent", "")).strip())
            except json.JSONDecodeError as error:
                raise DeploymentError(f"worker probe output is invalid on {instance_id}") from error
            if not isinstance(result, dict) or result.get("status") != "installed":
                raise DeploymentError(f"worker probe did not prove installation on {instance_id}")
            return
        time.sleep(5)
    raise DeploymentError(f"worker probe timed out on {instance_id}")


def apply_plan(arguments: argparse.Namespace) -> None:
    config, config_raw = load_config(arguments.config)
    package_receipt, manifest, package_receipt_raw = load_package(arguments.package)
    verify_source(arguments.source_repository, package_receipt["source_sha"])
    require_new_directory(arguments.output, "apply output")
    plan_receipt, _ = read_canonical(
        arguments.plan_directory / "production-deployment-plan-receipt.v1.json",
        "deployment plan receipt",
    )
    if set(plan_receipt) != {
        "config_sha256",
        "package_receipt_sha256",
        "plans",
        "schema_version",
        "source_sha",
        "status",
    } or plan_receipt.get("schema_version") != 1 or plan_receipt.get("status") != "planned":
        raise DeploymentError("deployment plan receipt has the wrong shape")
    if (
        plan_receipt.get("config_sha256") != sha256_bytes(config_raw)
        or plan_receipt.get("package_receipt_sha256") != sha256_bytes(package_receipt_raw)
        or plan_receipt.get("source_sha") != package_receipt["source_sha"]
    ):
        raise DeploymentError("deployment plan does not bind this config and package")
    for stack in ("application", "infrastructure"):
        plan_path = arguments.plan_directory / f"{stack}.tfplan"
        show_path = arguments.plan_directory / f"{stack}.tfplan.json"
        plans = plan_receipt.get("plans")
        expected = plans.get(stack) if isinstance(plans, dict) else None
        if (
            not isinstance(expected, dict)
            or not plan_path.is_file()
            or plan_path.is_symlink()
            or not show_path.is_file()
            or show_path.is_symlink()
            or sha256_file(plan_path) != expected.get("plan_sha256")
            or sha256_file(show_path) != expected.get("show_sha256")
        ):
            raise DeploymentError(f"{stack} saved plan differs from its receipt")
    verify_live_target(config)
    arguments.output.mkdir(mode=0o700)
    application_stack = arguments.source_repository / "deploy/aws/terraform/stacks/production-application"
    infrastructure_stack = arguments.source_repository / "deploy/aws/terraform/stacks/production-infrastructure"
    run(
        ["terraform", f"-chdir={application_stack}", "apply", "-input=false", "-auto-approve", str(arguments.plan_directory / "application.tfplan")],
        capture_output=False,
    )
    application = verify_application(config, manifest)
    run(
        ["terraform", f"-chdir={infrastructure_stack}", "apply", "-input=false", "-auto-approve", str(arguments.plan_directory / "infrastructure.tfplan")],
        capture_output=False,
    )
    outputs_raw = run(["terraform", f"-chdir={infrastructure_stack}", "output", "-json"]).stdout
    try:
        outputs = json.loads(outputs_raw)
    except json.JSONDecodeError as error:
        raise DeploymentError("infrastructure Terraform outputs are invalid") from error
    worker_digest = manifest["artifacts"]["worker"]["bundle_sha256"]
    expected_key = f"worker/{worker_digest[7:]}/cats-worker.tar.zst"
    output_value = outputs.get("worker_bundle_key") if isinstance(outputs, dict) else None
    if not isinstance(output_value, dict) or output_value.get("value") != expected_key:
        raise DeploymentError("infrastructure output does not bind the packaged worker")
    instance_ids = list(config["worker_instances"].values())
    worker_probe_id = send_worker_probe(config, instance_ids, worker_digest)
    for instance_id in instance_ids:
        wait_worker_probe(config, worker_probe_id, instance_id)
    receipt = {
        "application_images": application,
        "config_sha256": sha256_bytes(config_raw),
        "package_receipt_sha256": sha256_bytes(package_receipt_raw),
        "plan_receipt_sha256": sha256_file(
            arguments.plan_directory / "production-deployment-plan-receipt.v1.json"
        ),
        "schema_version": 1,
        "source_sha": package_receipt["source_sha"],
        "status": "applied",
        "worker_bundle_key": expected_key,
        "worker_instances": config["worker_instances"],
        "worker_probe_ssm_command_id": worker_probe_id,
    }
    write_new(arguments.output / "production-deployment-receipt.v1.json", canonical_json(receipt))
    print(canonical_json({"output": str(arguments.output), **receipt}).decode())


def parse_arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="operation", required=True)
    for operation in ("plan", "apply"):
        subparser = subparsers.add_parser(operation)
        subparser.add_argument("--source-repository", required=True, type=Path)
        subparser.add_argument("--package", required=True, type=Path)
        subparser.add_argument("--config", required=True, type=Path)
        subparser.add_argument("--output", required=True, type=Path)
        if operation == "apply":
            subparser.add_argument("--plan-directory", required=True, type=Path)
    return parser.parse_args()


def main() -> int:
    arguments = parse_arguments()
    try:
        if arguments.operation == "plan":
            create_plan(arguments)
        else:
            apply_plan(arguments)
    except DeploymentError as error:
        print(f"production deployment failed closed: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
