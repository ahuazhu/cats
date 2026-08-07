from __future__ import annotations

import hashlib
import json
import os
import runpy
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


QUALIFICATION_DIR = Path(__file__).resolve().parents[1]
BUILD_HOST_DIR = QUALIFICATION_DIR / "build-host"
BOOTSTRAP_DIR = BUILD_HOST_DIR / "bootstrap"
CONTRACT_PATH = QUALIFICATION_DIR / "contracts" / "h2-build-host-create-v1.json"
PREPARATION_CONTRACT_PATH = (
    QUALIFICATION_DIR / "contracts" / "h2-build-host-preparation-v1.json"
)
MAINTENANCE_CONTRACT_PATH = (
    QUALIFICATION_DIR / "contracts" / "h2-build-host-maintenance-v1.json"
)
POLICY_REPAIR_CONTRACT_PATH = (
    QUALIFICATION_DIR / "contracts" / "h2-bucket-policy-repair-v1.json"
)
KMS_POLICY_REPAIR_CONTRACT_PATH = (
    QUALIFICATION_DIR / "contracts" / "h2-bucket-kms-policy-repair-v2.json"
)
ARTIFACT_KMS_CONTEXT_REPAIR_CONTRACT_PATH = (
    QUALIFICATION_DIR
    / "contracts"
    / "h2-artifact-kms-context-repair-v3.json"
)


class BuildHostBoundaryTests(unittest.TestCase):
    def text(self, relative: str) -> str:
        return (BUILD_HOST_DIR / relative).read_text(encoding="utf-8")

    def test_candidate_has_no_daemon_or_instance_role_path(self) -> None:
        bootstrap = self.text("bootstrap/bootstrap.sh")
        readiness = self.text("bootstrap/verify-readiness.py")
        guard = self.text("bootstrap/imds-guard.sh")
        self.assertNotIn("usermod --append --groups docker cats-build", bootstrap)
        self.assertIn("--group=root", bootstrap)
        self.assertIn("--group root --oci-worker-net=bridge", bootstrap)
        self.assertNotIn("security.insecure", bootstrap)
        self.assertIn("buildkit_worker_uses_cni(workers)", readiness)
        self.assertIn('"--verbose"', readiness)
        self.assertIn('"Dockerfile.positive"', readiness)
        self.assertIn('"Dockerfile.negative"', readiness)
        self.assertNotIn('"type=cacheonly"', readiness)
        self.assertIn("--uid-owner", guard)
        self.assertIn("FORWARD", guard)
        self.assertIn("169.254.169.254/32", guard)

    def test_readiness_accepts_only_the_verbose_cni_worker_label(self) -> None:
        namespace = runpy.run_path(str(BOOTSTRAP_DIR / "verify-readiness.py"))
        worker_uses_cni = namespace["buildkit_worker_uses_cni"]
        self.assertTrue(
            worker_uses_cni(
                "Labels:\n"
                "\torg.mobyproject.buildkit.worker.executor:\t\toci\n"
                "\torg.mobyproject.buildkit.worker.network:\t\tcni\n"
                "\torg.mobyproject.buildkit.worker.snapshotter:\t\toverlayfs\n"
            )
        )
        self.assertTrue(
            worker_uses_cni(
                "org.mobyproject.buildkit.worker.network: cni\n"
            )
        )
        self.assertFalse(
            worker_uses_cni(
                "Labels:\n"
                "\torg.mobyproject.buildkit.worker.network:\t\thost\n"
            )
        )
        self.assertFalse(
            worker_uses_cni(
                "org.mobyproject.buildkit.worker.network.mode:\t\tcni\n"
            )
        )
        self.assertFalse(worker_uses_cni("Labels:\n"))
        self.assertFalse(
            worker_uses_cni(
                "org.mobyproject.buildkit.worker.network:\t\tcni\n"
                "org.mobyproject.buildkit.worker.network:\t\tcni\n"
            )
        )
        self.assertFalse(
            worker_uses_cni(
                "org.mobyproject.buildkit.worker.network:\t\tcni\n"
                "org.mobyproject.buildkit.worker.network:\t\thost\n"
            )
        )

    def test_isolated_build_path_exposes_native_system_tools(self) -> None:
        build_path = "/opt/cats-build/cargo/bin:/usr/local/bin:/usr/bin:/usr/sbin"
        self.assertEqual(build_path.split(":")[-1], "/usr/sbin")
        self.assertEqual(len(build_path.split(":")), len(set(build_path.split(":"))))

        runner = self.text("bootstrap/run-build.sh")
        self.assertIn(f"PATH={build_path}", runner)
        self.assertIn("RUST_TEST_THREADS=4", runner)

    def test_bootstrap_refreezes_toolchain_after_success_and_failure(self) -> None:
        bootstrap = self.text("bootstrap/bootstrap.sh")
        start = "toolchain_needs_refreeze=false"
        end = "trap cleanup EXIT"
        lifecycle = start + bootstrap.split(start, 1)[1].split(end, 1)[0] + end

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cargo = root / "cargo"
            rustup = root / "rustup"
            for path in (cargo, rustup):
                path.mkdir()
                (path / "probe").write_text("frozen", encoding="utf-8")
                (path / "probe").chmod(0o444)
                path.chmod(0o555)

            lifecycle = lifecycle.replace(
                "/opt/cats-build/cargo", shlex.quote(str(cargo))
            ).replace("/opt/cats-build/rustup", shlex.quote(str(rustup)))

            def run_case(name: str, body: str) -> subprocess.CompletedProcess[str]:
                work = root / name
                work.mkdir()
                script = f"""
set -euo pipefail
readonly work_dir={shlex.quote(str(work))}
chown() {{ return 0; }}
{lifecycle}
{body}
"""
                return subprocess.run(
                    ["bash", "-c", script],
                    text=True,
                    capture_output=True,
                    check=False,
                )

            success = run_case(
                "success-work",
                f"""
thaw_toolchain
printf updated >{shlex.quote(str(cargo / 'probe'))}
freeze_toolchain
""",
            )
            self.assertEqual(success.returncode, 0, success.stderr)
            self.assertFalse((root / "success-work").exists())
            self.assertEqual(stat.S_IMODE((cargo / "probe").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(cargo.stat().st_mode), 0o555)

            failure = run_case(
                "failure-work",
                f"""
thaw_toolchain
printf interrupted >{shlex.quote(str(rustup / 'probe'))}
false
""",
            )
            self.assertNotEqual(failure.returncode, 0)
            self.assertFalse((root / "failure-work").exists())
            self.assertEqual(stat.S_IMODE((rustup / "probe").stat().st_mode), 0o444)
            self.assertEqual(stat.S_IMODE(rustup.stat().st_mode), 0o555)

            prepare_failure = run_case(
                "prepare-failure-work",
                """
install() { command install "$@"; return 23; }
thaw_toolchain
""",
            )
            self.assertEqual(prepare_failure.returncode, 23)
            self.assertFalse((root / "prepare-failure-work").exists())
            for path in (cargo, rustup):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o555)
                self.assertEqual(stat.S_IMODE((path / "probe").stat().st_mode), 0o444)

    def test_source_delivery_has_no_github_credential_route(self) -> None:
        corpus = "\n".join(
            path.read_text(encoding="utf-8")
            for path in BUILD_HOST_DIR.rglob("*")
            if path.is_file()
            and ".terraform" not in path.parts
            and path.suffix in {".tf", ".json", ".md", ".sh", ".py", ".tftpl"}
            and not path.name.endswith(".plan.json")
        )
        for forbidden in (
            "secretsmanager:",
            "aws_secretsmanager",
            "github-deploy-key",
            "ssh.github.com",
            "known_hosts",
        ):
            self.assertNotIn(forbidden, corpus.lower())

    def test_instance_uses_the_provider_canonical_kms_key_arn(self) -> None:
        instance = self.text("instance.tf")
        self.assertIn(
            "kms_key_id            = aws_kms_key.build_volume.arn", instance
        )
        self.assertNotIn(
            "kms_key_id            = local.volume_kms_alias_arn", instance
        )

        create_contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertNotIn(
            "root_block_device[0].kms_key_id",
            create_contract["required_known_change_paths"]["aws_instance.build"],
        )

    def test_source_iam_is_read_only_and_prefix_scoped(self) -> None:
        iam = self.text("iam.tf")
        self.assertIn('"s3:GetObject"', iam)
        self.assertIn('"s3:GetObjectVersion"', iam)
        self.assertIn("/source/bundles/sha256/*", iam)
        self.assertIn("/source/manifests/sha256/*", iam)
        self.assertIn('variable = "kms:ViaService"', iam)
        self.assertIn('variable = "kms:EncryptionContext:aws:s3:arn"', iam)
        source_read = iam[iam.index('sid = "ReadControllerPublishedSource"') :]
        source_read = source_read[: source_read.index("resource \"aws_iam_policy\"")]
        self.assertNotIn("s3:PutObject", source_read)
        self.assertNotIn("s3:DeleteObject", source_read)
        self.assertNotIn("s3:ListBucket", source_read)

    def test_source_bucket_is_append_only_and_dedicated(self) -> None:
        source = self.text("source-delivery.tf")
        publisher = self.text("tools/publish-source-bundle.sh")
        self.assertIn('resource "aws_s3_bucket" "source"', source)
        self.assertIn('resource "aws_kms_key" "source"', source)
        self.assertIn('bucket_key_enabled = false', source)
        self.assertIn('"s3:DeleteObjectVersion"', source)
        self.assertNotIn('variable = "s3:if-none-match"', source)
        self.assertIn("values   = [aws_kms_key.source.arn]", source)
        self.assertNotIn("values   = [local.source_kms_alias_arn]", source)
        self.assertIn("--if-none-match '*'", publisher)
        self.assertIn('--ssekms-key-id "${source_kms_key_arn}"', publisher)
        self.assertNotIn('--ssekms-key-id "${source_kms_alias_arn}"', publisher)
        self.assertIn("same-digest publication", publisher)

    def test_artifact_bucket_does_not_use_unsupported_header_conditions(self) -> None:
        artifacts = self.text("artifacts.tf")
        publisher = self.text("bootstrap/publish-content-addressed.sh")
        self.assertIn('"s3:DeleteObjectVersion"', artifacts)
        self.assertNotIn('variable = "s3:if-none-match"', artifacts)
        self.assertIn("values   = [aws_kms_key.artifacts.arn]", artifacts)
        self.assertNotIn("values   = [local.artifact_kms_alias_arn]", artifacts)
        self.assertIn("--if-none-match '*'", publisher)
        self.assertIn('--ssekms-key-id "${kms_key_arn}"', publisher)
        self.assertNotIn('--ssekms-key-id "${kms_alias_arn}"', publisher)

    def test_artifact_kms_context_matches_s3_bucket_keys(self) -> None:
        iam = self.text("iam.tf")
        artifacts = self.text("artifacts.tf")
        encryption = iam[iam.index('sid = "EncryptPublishedObjects"') :]
        encryption = encryption[: encryption.index("DescribePublishedArtifactsKey")]

        self.assertIn("bucket_key_enabled = true", artifacts)
        self.assertIn('test     = "StringEquals"', encryption)
        self.assertIn('variable = "kms:EncryptionContext:aws:s3:arn"', encryption)
        self.assertIn("values   = [local.artifact_bucket_arn]", encryption)
        self.assertNotIn('arn:aws:s3:::${local.artifact_bucket_name}/*', encryption)

    def test_checkout_uses_only_exact_digests_and_root_publication(self) -> None:
        checkout = self.text("bootstrap/checkout-exact-sha.sh")
        self.assertIn("cats-checkout-exact-sha must run as root", checkout)
        self.assertIn("<40hex-commit> <64hex-manifest-sha256> <64hex-bundle-sha256>", checkout)
        self.assertIn('manifest_key="source/manifests/sha256/', checkout)
        self.assertIn('bundle_key="source/bundles/sha256/', checkout)
        self.assertIn("GIT_CONFIG_NOSYSTEM=1", checkout)
        self.assertIn("core.hooksPath=/dev/null", checkout)
        self.assertLess(checkout.index('mv -- "${stage_repo}" "${source_dir}"'), checkout.index("write_immutable_receipt"))
        self.assertIn("cats-active-delivery-v1.json", checkout)
        self.assertNotIn("runuser", checkout)

    def test_build_and_publication_are_per_job_root_mediated(self) -> None:
        runner = self.text("bootstrap/run-build.sh")
        publisher = self.text("bootstrap/publish-content-addressed.sh")
        stager = self.text("bootstrap/stage-build-output.py")
        self.assertIn("manifest_sha256", runner)
        self.assertIn("cats-active-delivery-v1.json", runner)
        self.assertIn('"${job_dir}/home"', runner)
        self.assertIn("env -i", runner)
        self.assertIn("--uid=cats-build", runner)
        self.assertIn("--gid=cats-build", runner)
        self.assertIn("--property=ProtectHome=true", runner)
        self.assertIn("--property=PrivateTmp=true", runner)
        self.assertIn("--property=PrivateIPC=true", runner)
        self.assertIn("--property=NoNewPrivileges=true", runner)
        self.assertIn("--property=LimitNOFILE=65536", runner)
        self.assertNotIn("/usr/sbin/runuser", runner)
        self.assertIn("bootstrap_payload_sha256", runner)
        self.assertIn('chown root:root "${job_dir}"', runner)
        self.assertIn('chmod 0555 "${job_dir}"', runner)
        self.assertIn("artifact publication is root-mediated", publisher)
        self.assertIn("aws kms describe-key", publisher)
        self.assertIn('--ssekms-key-id "${kms_key_arn}"', publisher)
        self.assertIn("stage-build-output", publisher)
        self.assertIn('.output_frozen == true', publisher)
        self.assertIn('.job_cgroup_drained == true', publisher)
        self.assertIn('.output_dir == ("/srv/cats-build/target/"', publisher)
        self.assertIn("os.O_NOFOLLOW", stager)
        self.assertIn("source_stat.st_uid != 0", stager)
        self.assertIn("MAX_BYTES", stager)

    def test_contract_freezes_the_exact_bootstrap_payload(self) -> None:
        component_files = {
            "bootstrap": "bootstrap.sh",
            "checkout": "checkout-exact-sha.sh",
            "imds_guard": "imds-guard.sh",
            "immutable_receipt": "immutable-receipt.sh",
            "publish": "publish-content-addressed.sh",
            "readiness": "verify-readiness.py",
            "run_build": "run-build.sh",
            "stage_output": "stage-build-output.py",
            "toolchain_lock": "toolchain-lock-v1.json",
        }
        observed = {
            name: hashlib.sha256((BOOTSTRAP_DIR / filename).read_bytes()).hexdigest()
            for name, filename in component_files.items()
        }
        payload = json.dumps(
            observed, sort_keys=True, separators=(",", ":")
        ).encode()
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        expected = contract["manifest"]["expected"]["bootstrap"]
        self.assertEqual(expected["components_sha256"], observed)
        self.assertEqual(
            expected["payload_sha256"], hashlib.sha256(payload).hexdigest()
        )

    def test_contract_requires_privileged_plan_values_to_be_known(self) -> None:
        common_expected = {
            "aws_iam_policy.build_boundary": ["policy"],
            "aws_iam_policy.deployer_boundary": ["policy"],
            "aws_iam_role.build": ["assume_role_policy"],
            "aws_iam_role.deployer": ["assume_role_policy"],
            "aws_iam_role_policy.build": ["policy"],
            "aws_iam_role_policy.deployer": ["policy"],
            "aws_instance.build": ["user_data_base64"],
            "aws_kms_key.artifacts": ["policy"],
            "aws_kms_key.build_volume": ["policy"],
            "aws_kms_key.source": ["policy"],
            "aws_s3_bucket_policy.artifacts": ["policy"],
            "aws_s3_bucket_policy.source": ["policy"],
            "aws_vpc_endpoint.build_storage": ["policy"],
        }
        create_contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        create_expected = dict(common_expected)
        create_expected.pop("aws_s3_bucket_policy.artifacts")
        create_expected.pop("aws_s3_bucket_policy.source")
        self.assertEqual(
            create_contract["required_known_change_paths"], create_expected
        )
        preparation_contract = json.loads(
            PREPARATION_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        preparation_expected = dict(common_expected)
        preparation_expected["aws_instance.build"] = [
            "force_destroy",
            "user_data_base64",
        ]
        self.assertEqual(
            preparation_contract["required_known_change_paths"],
            preparation_expected,
        )
        maintenance_contract = json.loads(
            MAINTENANCE_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            maintenance_contract["required_known_change_paths"],
            preparation_expected,
        )
        policy_contract = json.loads(
            POLICY_REPAIR_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            policy_contract["required_known_change_paths"],
            preparation_expected,
        )
        kms_policy_contract = json.loads(
            KMS_POLICY_REPAIR_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            kms_policy_contract["required_known_change_paths"],
            preparation_expected,
        )
        artifact_kms_context_contract = json.loads(
            ARTIFACT_KMS_CONTEXT_REPAIR_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(
            artifact_kms_context_contract["required_known_change_paths"],
            preparation_expected,
        )

    def test_create_contract_binds_unknown_kms_configuration_references(self) -> None:
        contract = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))
        self.assertEqual(
            contract["required_configuration_references"],
            {
                "aws_instance.build": {
                    "root_block_device[0].kms_key_id.references": [
                        "aws_kms_key.build_volume.arn",
                        "aws_kms_key.build_volume",
                    ]
                },
                "aws_s3_bucket_policy.artifacts": {
                    "policy.references": [
                        "data.aws_iam_policy_document.artifact_bucket.json",
                        "data.aws_iam_policy_document.artifact_bucket",
                    ]
                },
                "aws_s3_bucket_policy.source": {
                    "policy.references": [
                        "data.aws_iam_policy_document.source_bucket.json",
                        "data.aws_iam_policy_document.source_bucket",
                    ]
                },
                "data.aws_iam_policy_document.artifact_bucket": {
                    "statement[4].condition[0].values.references": [
                        "aws_kms_key.artifacts.arn",
                        "aws_kms_key.artifacts",
                    ]
                },
                "data.aws_iam_policy_document.source_bucket": {
                    "statement[4].condition[0].values.references": [
                        "aws_kms_key.source.arn",
                        "aws_kms_key.source",
                    ]
                },
            },
        )

    def test_preparation_contract_freezes_the_complete_safe_transition(self) -> None:
        contract = json.loads(
            PREPARATION_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(contract["mode"], "maintenance")
        self.assertRegex(contract["expected_managed_changes_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(contract["expected_resource_drift_sha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(len(contract["required_change_actions"]), 41)
        self.assertEqual(
            contract["required_change_actions"]["aws_instance.build"],
            ["update"],
        )
        self.assertEqual(
            contract["required_before_identity_templates"]["aws_instance.build"],
            {"disable_api_termination": True, "force_destroy": False},
        )
        self.assertTrue(
            contract["required_identity_templates"]["aws_instance.build"][
                "force_destroy"
            ]
        )

    def test_maintenance_contract_freezes_the_final_replacement(self) -> None:
        contract = json.loads(
            MAINTENANCE_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        self.assertEqual(contract["mode"], "maintenance")
        self.assertEqual(len(contract["required_change_actions"]), 41)
        self.assertEqual(
            contract["required_change_actions"]["aws_instance.build"],
            ["delete", "create"],
        )
        self.assertEqual(
            contract["required_before_identity_templates"]["aws_instance.build"],
            {"disable_api_termination": True, "force_destroy": True},
        )
        self.assertFalse(
            contract["required_identity_templates"]["aws_instance.build"][
                "force_destroy"
            ]
        )

    def test_policy_repair_contract_allows_only_two_bucket_policy_updates(self) -> None:
        for path in (POLICY_REPAIR_CONTRACT_PATH, KMS_POLICY_REPAIR_CONTRACT_PATH):
            contract = json.loads(path.read_text(encoding="utf-8"))
            non_noop = {
                address: actions
                for address, actions in contract["required_change_actions"].items()
                if actions != ["no-op"]
            }
            self.assertEqual(
                non_noop,
                {
                    "aws_s3_bucket_policy.artifacts": ["update"],
                    "aws_s3_bucket_policy.source": ["update"],
                },
            )

    def test_artifact_kms_context_contract_allows_only_two_iam_updates(self) -> None:
        contract = json.loads(
            ARTIFACT_KMS_CONTEXT_REPAIR_CONTRACT_PATH.read_text(encoding="utf-8")
        )
        non_noop = {
            address: actions
            for address, actions in contract["required_change_actions"].items()
            if actions != ["no-op"]
        }
        self.assertEqual(
            non_noop,
            {
                "aws_iam_policy.build_boundary": ["update"],
                "aws_iam_role_policy.build": ["update"],
            },
        )
        self.assertEqual(
            contract["expected_resource_drift_sha256"],
            "c816b433995ee36a15513bcb7521bb07008c4dd1b7f23d91374291705b021a70",
        )

    def test_cloud_init_privileged_entrypoints_are_root_only(self) -> None:
        template = self.text("bootstrap/cloud-init.yaml.tftpl")
        for path in (
            "/usr/local/bin/cats-publish-content-addressed",
            "/usr/local/sbin/cats-run-build",
            "/usr/local/libexec/cats-build/stage-build-output",
        ):
            block = template[template.index(f"path: {path}") :]
            self.assertIn("permissions: '0700'", block[:300])

    def test_shell_scripts_parse_and_receipt_smoke(self) -> None:
        scripts = [
            *BOOTSTRAP_DIR.glob("*.sh"),
            *BUILD_HOST_DIR.joinpath("tools").glob("*.sh"),
            *BUILD_HOST_DIR.joinpath("tests").glob("*.sh"),
        ]
        for script in scripts:
            subprocess.run(["bash", "-n", str(script)], check=True)
        subprocess.run(
            ["bash", str(BUILD_HOST_DIR / "tests" / "immutable-receipt-smoke.sh")],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    def test_controller_source_publication_is_exact_and_idempotent(self) -> None:
        account_id = "123456789012"
        kms_key_arn = f"arn:aws:kms:us-east-1:{account_id}:key/01234567-89ab-cdef-0123-456789abcdef"
        kms_alias_arn = f"arn:aws:kms:us-east-1:{account_id}:alias/cats-qualification-v2-build-source"
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            repository = root / "repository"
            repository.mkdir()
            subprocess.run(["git", "init", "--initial-branch=main", repository], check=True, stdout=subprocess.DEVNULL)
            subprocess.run(["git", "-C", repository, "config", "user.name", "Cats Test"], check=True)
            subprocess.run(["git", "-C", repository, "config", "user.email", "cats@example.invalid"], check=True)
            subprocess.run(["git", "-C", repository, "remote", "add", "origin", "https://github.com/ahuazhu/cats.git"], check=True)
            (repository / "README").write_text("exact source\n", encoding="utf-8")
            subprocess.run(["git", "-C", repository, "add", "README"], check=True)
            subprocess.run(["git", "-C", repository, "commit", "-m", "fixture"], check=True, stdout=subprocess.DEVNULL)
            source_sha = subprocess.run(
                ["git", "-C", repository, "rev-parse", "HEAD"],
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()

            fake_bin = root / "bin"
            fake_bin.mkdir()
            fake_aws = fake_bin / "aws"
            fake_aws.write_text(
                f"#!{sys.executable}\nexec(compile(open({str(BUILD_HOST_DIR / 'tests' / 'fake-aws.py')!r}).read(), {str(BUILD_HOST_DIR / 'tests' / 'fake-aws.py')!r}, 'exec'))\n",
                encoding="utf-8",
            )
            fake_aws.chmod(0o755)
            store = root / "store"
            work = root / "work"
            evidence = root / "evidence"
            for directory in (store, work, evidence):
                directory.mkdir()
            environment = {
                **os.environ,
                "PATH": f"{fake_bin}:{os.environ['PATH']}",
                "FAKE_AWS_ACCOUNT_ID": account_id,
                "FAKE_AWS_KMS_KEY_ARN": kms_key_arn,
                "FAKE_AWS_STORE": str(store),
            }
            command = [
                "bash",
                str(BUILD_HOST_DIR / "tools" / "publish-source-bundle.sh"),
                account_id,
                str(repository),
                source_sha,
                f"cats-qualification-v2-build-source-{account_id}-us-east-1",
                kms_alias_arn,
                str(work),
            ]
            first_evidence = evidence / "first.json"
            subprocess.run([*command, str(first_evidence)], check=True, env=environment, stdout=subprocess.DEVNULL)
            first = json.loads(first_evidence.read_text(encoding="utf-8"))
            self.assertEqual(first["source_sha"], source_sha)
            self.assertFalse(first["github_credential_on_build_host"])
            self.assertTrue(first["conditional_create"])

            second_evidence = evidence / "second.json"
            subprocess.run([*command, str(second_evidence)], check=True, env=environment, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            second = json.loads(second_evidence.read_text(encoding="utf-8"))
            self.assertEqual(first["manifest_sha256"], second["manifest_sha256"])
            self.assertEqual(first["bundle_sha256"], second["bundle_sha256"])

            wrong_sha = "0" * 40
            wrong = subprocess.run(
                [*command[:4], wrong_sha, *command[5:], str(evidence / "wrong.json")],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(wrong.returncode, 0)
            self.assertIn("HEAD is not the requested exact commit", wrong.stderr)

            (repository / "untracked").write_text("dirty\n", encoding="utf-8")
            dirty = subprocess.run(
                [*command, str(evidence / "dirty.json")],
                env=environment,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(dirty.returncode, 0)
            self.assertIn("controller repository must be clean", dirty.stderr)


if __name__ == "__main__":
    unittest.main()
