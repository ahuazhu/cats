#!/usr/bin/env python3
"""Offline positive and negative fixture for the production deployment controller."""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile


def load_deployer(path: Path):
    specification = importlib.util.spec_from_file_location("cats_deploy_release", path)
    if specification is None or specification.loader is None:
        raise AssertionError("could not load production deployer")
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


def write_canonical(path: Path, value) -> None:
    path.write_bytes(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())


def fixture_config(root: Path) -> dict:
    kubeconfig = root / "kubeconfig"
    kubeconfig.write_text("fixture\n")
    application = root / "application.tfvars.json"
    infrastructure = root / "infrastructure.tfvars.json"
    write_canonical(application, {})
    write_canonical(infrastructure, {})
    return {
        "application_state_key": "cats/production/application.tfstate",
        "application_tfvars": [str(application)],
        "aws_region": "us-east-1",
        "control_postgres_schema": "cats_r26",
        "eks_cluster_name": "cats-production",
        "expected_account_id": "123456789012",
        "expected_aws_partition": "aws",
        "infrastructure_state_key": "cats/production/infrastructure.tfstate",
        "infrastructure_tfvars": [str(infrastructure)],
        "kubeconfig_context": "cats-production",
        "kubeconfig_path": str(kubeconfig),
        "namespace": "cats",
        "schema_version": 1,
        "terraform_state_bucket": "cats-terraform-state-123456789012-us-east-1",
        "worker_instances": {
            "metal-1": "i-0123456789abcdef0",
            "metal-2": "i-0123456789abcdef1",
        },
    }


def fixture_package(root: Path, deployer) -> tuple[Path, dict]:
    package = root / "package"
    release = package / "release"
    release.mkdir(parents=True)
    worker = release / "cats-worker.tar.zst"
    worker.write_bytes(b"fixture worker bundle\n")
    worker_digest = deployer.sha256_file(worker)
    references = {
        "control_plane": "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/control:exact",
        "credential_refresher": "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/refresher:exact",
        "gateway": "123456789012.dkr.ecr.us-east-1.amazonaws.com/cats/gateway:exact",
    }
    manifest = {
        "artifacts": {
            **{
                name: {
                    "image_digest": "sha256:" + character * 64,
                    "image_reference": reference,
                    "registry_verified": True,
                }
                for (name, reference), character in zip(
                    references.items(), ("1", "2", "3"), strict=True
                )
            },
            "worker": {
                "bundle_name": "cats-worker.tar.zst",
                "bundle_sha256": worker_digest,
            },
        },
        "build_inputs": {},
        "guest_runtime": {},
        "source": {"commit": "a" * 40},
        "version": 1,
    }
    promoted = package / "release-manifest.registry-verified.v1.json"
    write_canonical(promoted, manifest)
    receipt = {
        "artifact_publication": {},
        "build_host_instance_id": "i-0123456789abcdef2",
        "build_ssm_command_id": "build-command",
        "images": references,
        "promoted_release_manifest_sha256": deployer.sha256_file(promoted),
        "readiness_ssm_command_id": "readiness-command",
        "release_manifest_sha256": "sha256:" + "4" * 64,
        "schema_version": 1,
        "source_bundle_sha256": "5" * 64,
        "source_manifest_sha256": "6" * 64,
        "source_sha": "a" * 40,
        "status": "registry_verified",
        "transport_sha256": "7" * 64,
    }
    write_canonical(package / "production-package-receipt.v1.json", receipt)
    return package, manifest


def deployment(kind: str, name: str, image: str) -> dict:
    del kind, name
    return {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "runtime", "image": image}],
                    "initContainers": [{"name": "renderer", "image": image}],
                }
            }
        }
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--deployer", required=True, type=Path)
    options = parser.parse_args()
    deployer_path = options.deployer.resolve()
    deployer = load_deployer(deployer_path)
    repository = deployer_path.parents[3]

    with tempfile.TemporaryDirectory(prefix="cats-production-deploy-fixture-") as temporary:
        root = Path(temporary).resolve()
        config_value = fixture_config(root)
        config_path = root / "deployment-config.v1.json"
        write_canonical(config_path, config_value)
        config, _ = deployer.load_config(config_path)
        package, expected_manifest = fixture_package(root, deployer)
        receipt, manifest, _ = deployer.load_package(package)
        assert receipt["source_sha"] == "a" * 40
        assert manifest == expected_manifest

        duplicate_state = dict(config_value)
        duplicate_state["infrastructure_state_key"] = duplicate_state[
            "application_state_key"
        ]
        invalid_path = root / "invalid-config.v1.json"
        write_canonical(invalid_path, duplicate_state)
        try:
            deployer.load_config(invalid_path)
        except deployer.DeploymentError as error:
            assert "state keys must differ" in str(error)
        else:
            raise AssertionError("deployer accepted one state key for both stacks")

        plan = deployer.terraform_plan_command(
            repository,
            config,
            manifest,
            package,
            "application",
            root / "application.tfplan",
        )
        joined = "\n".join(plan)
        images = deployer.image_refs(manifest)
        for required in (
            f"-var=control_plane_image={images['control_plane']}",
            f"-var=credential_refresher_image={images['credential_refresher']}",
        ):
            assert required in joined
        assert "gateway_image" not in joined
        assert "object_write_gateway_image" not in joined
        worker_plan = deployer.terraform_plan_command(
            repository,
            config,
            manifest,
            package,
            "infrastructure",
            root / "infrastructure.tfplan",
        )
        worker_joined = "\n".join(worker_plan)
        assert "-var=metal_worker_enabled=true" in worker_joined
        assert (
            '-var=metal_worker_instances={"metal-1":"i-0123456789abcdef0",'
            '"metal-2":"i-0123456789abcdef1"}'
            in worker_joined
        )
        assert (
            '-var=metal_worker_deploy_instances=["metal-1","metal-2"]'
            in worker_joined
        )
        assert manifest["artifacts"]["worker"]["bundle_sha256"][7:] in worker_joined

        original_run = deployer.run
        original_kubectl_json = deployer.kubectl_json
        rollout_commands: list[list[str]] = []

        def successful_run(command, **_kwargs):
            rollout_commands.append(command)
            return subprocess.CompletedProcess(command, 0, b"", b"")

        expected_images = {
            "cats-controld": images["control_plane"],
        }

        def workload(_config, kind, name):
            if kind == "cronjob":
                return {
                    "spec": {
                        "jobTemplate": {
                            "spec": {
                                "template": {
                                    "spec": {
                                        "containers": [
                                            {"image": images["credential_refresher"]}
                                        ]
                                    }
                                }
                            }
                        }
                    }
                }
            return deployment(kind, name, expected_images[name])

        deployer.run = successful_run
        deployer.kubectl_json = workload
        try:
            observed = deployer.verify_application(config, manifest)
        finally:
            deployer.run = original_run
            deployer.kubectl_json = original_kubectl_json
        assert set(observed) == {
            "cats-controld",
            "cats-credential-refresher",
        }
        assert len(rollout_commands) == 1

        observed_aws: list[tuple[str, ...]] = []
        original_aws_json = deployer.aws_json

        def sent(_config, *command):
            observed_aws.append(command)
            return {"Command": {"CommandId": "worker-probe"}}

        deployer.aws_json = sent
        try:
            command_id = deployer.send_worker_probe(
                config,
                list(config["worker_instances"].values()),
                manifest["artifacts"]["worker"]["bundle_sha256"],
            )
        finally:
            deployer.aws_json = original_aws_json
        assert command_id == "worker-probe"
        serialized = " ".join(observed_aws[0])
        assert "worker-installation-receipt.v1.json" in serialized
        assert "private-key" not in serialized
        assert "CATS_AUTH_TOKEN" not in serialized

    print("production release deployment fixture: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
