#!/usr/bin/env python3
"""Offline contract fixture for production-clean-slate-reset.py.

The fake command boundary proves that a qualified, disjoint fresh namespace is
left untouched while the exact old namespace is retired. It also exercises
multi-page version/delete-marker listing, multipart abort, exact PostgreSQL
schema drops, dry-run behavior, immutable canonical receipts, closed
forward-resume and crash replay without contacting AWS, Kubernetes, or
PostgreSQL.
"""

from __future__ import annotations

import datetime as dt
import dataclasses
import importlib.util
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Callable, Mapping, Sequence


SCRIPT = Path(__file__).with_name("production-clean-slate-reset.py")
SPEC = importlib.util.spec_from_file_location("cats_clean_slate_reset", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load clean-slate reset module")
reset = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = reset
SPEC.loader.exec_module(reset)


class FakeRunner(reset.CommandRunner):
    def __init__(self, account: str, region: str, cluster: str) -> None:
        self.account = account
        self.region = region
        self.cluster = cluster
        self.endpoint = "https://fixture.eks.example"
        self.ingress_closed = True
        self.objects = {
            "cats-chunks-old-fixture": [
                {
                    "key": f"cats-old/data/chunk-{index:04d}",
                    "version_id": f"v-{index:04d}",
                    "kind": "version",
                }
                for index in range(1001)
            ]
            + [
                {
                    "key": "cats-old/images/image-1/manifest.json",
                    "version_id": "delete-marker-1",
                    "kind": "delete_marker",
                }
            ],
            "cats-chunks-fresh-fixture": [
                {
                    "key": "cats-fresh/images/golden/manifest.json",
                    "version_id": "fresh-version-1",
                    "kind": "version",
                }
            ],
        }
        self.uploads = {
            "cats-chunks-old-fixture": [
                {"key": "cats-old/data/incomplete", "upload_id": "upload-1"}
            ],
            "cats-chunks-fresh-fixture": [],
        }
        self.schemas = {
            "cats_control_old": True,
            "cats_usage_old": True,
            "cats_control_fresh": True,
            "cats_usage_fresh": True,
        }
        self.schema_versions = {
            "cats_control_old": "13",
            "cats_usage_old": "5",
            "cats_control_fresh": reset.EXPECTED_FRESH_CONTROL_SCHEMA_VERSION,
            "cats_usage_fresh": "5",
        }
        self.streams = {"cats-usage-old", "cats-usage-fresh"}
        self.tables = {"cats-usage-checkpoints-old", "cats-usage-checkpoints-fresh"}
        self.archive_buckets = {
            "cats-usage-archive-old-fixture",
            "cats-usage-archive-fresh-fixture",
        }
        self.calls: list[tuple[list[str], Mapping[str, str] | None]] = []
        self.delete_calls = 0
        self.abort_calls = 0
        self.stream_delete_calls = 0
        self.table_delete_calls = 0
        self.drop_calls: list[str] = []

    @staticmethod
    def _arg(arguments: Sequence[str], name: str) -> str | None:
        try:
            return arguments[arguments.index(name) + 1]
        except (ValueError, IndexError):
            return None

    @staticmethod
    def _json(value: object) -> reset.CommandResult:
        return reset.CommandResult(0, json.dumps(value))

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> reset.CommandResult:
        del timeout
        arguments = list(argv)
        self.calls.append((arguments, env))
        if arguments[0] == "aws":
            return self._aws(arguments)
        if arguments[0] == "kubectl":
            return self._kubectl(arguments)
        if arguments[0] == "psql":
            return self._psql(arguments, env)
        return reset.CommandResult(64, "", "unexpected executable")

    def _aws(self, arguments: list[str]) -> reset.CommandResult:
        if "--no-paginate" not in arguments:
            return reset.CommandResult(64, "", "AWS CLI auto-pagination was not disabled")
        if "--output" in arguments:
            service, operation = arguments[7:9]
        else:
            service, operation = arguments[5:7]
        if service == "s3api" and self._arg(arguments, "--expected-bucket-owner") != self.account:
            return reset.CommandResult(65, "", "S3 expected bucket owner is not exact")
        if (service, operation) == ("sts", "get-caller-identity"):
            return self._json(
                {
                    "Account": self.account,
                    "Arn": f"arn:aws:sts::{self.account}:assumed-role/reset/fixture",
                    "UserId": "fixture",
                }
            )
        if (service, operation) == ("eks", "describe-cluster"):
            return self._json(
                {
                    "cluster": {
                        "arn": f"arn:aws:eks:{self.region}:{self.account}:cluster/{self.cluster}",
                        "endpoint": self.endpoint,
                        "status": "ACTIVE",
                    }
                }
            )
        if (service, operation) == ("s3api", "get-bucket-location"):
            return self._json({"LocationConstraint": None})
        if (service, operation) == ("s3api", "get-bucket-versioning"):
            return self._json({"Status": "Enabled"})
        if (service, operation) == ("s3api", "get-object-lock-configuration"):
            bucket = self._arg(arguments, "--bucket")
            if bucket not in self.archive_buckets:
                return reset.CommandResult(65, "", "object lock checked on non-archive")
            return self._json(
                {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}}
            )
        if (service, operation) == ("kinesis", "describe-stream-summary"):
            stream = self._arg(arguments, "--stream-name")
            if stream not in self.streams:
                return reset.CommandResult(
                    65,
                    "",
                    "An error occurred (ResourceNotFoundException) while describing stream",
                )
            return self._json(
                {
                    "StreamDescriptionSummary": {
                        "StreamARN": f"arn:aws:kinesis:{self.region}:{self.account}:stream/{stream}",
                        "StreamStatus": "ACTIVE",
                        "RetentionPeriodHours": 24,
                    }
                }
            )
        if (service, operation) == ("dynamodb", "describe-table"):
            table = self._arg(arguments, "--table-name")
            if table not in self.tables:
                return reset.CommandResult(
                    65,
                    "",
                    "An error occurred (ResourceNotFoundException) while describing table",
                )
            return self._json(
                {
                    "Table": {
                        "TableArn": f"arn:aws:dynamodb:{self.region}:{self.account}:table/{table}",
                        "TableStatus": "ACTIVE",
                    }
                }
            )
        if (service, operation) == ("s3api", "list-object-versions"):
            if self._arg(arguments, "--max-keys") != "1000":
                return reset.CommandResult(64, "", "version page bound is not explicit")
            bucket = self._arg(arguments, "--bucket")
            prefix = self._arg(arguments, "--prefix")
            if bucket not in self.objects or prefix is None:
                return reset.CommandResult(65, "", "unknown ChunkStore target")
            objects = [item for item in self.objects[bucket] if item["key"].startswith(prefix)]
            marker = self._arg(arguments, "--key-marker")
            if marker is None and len(objects) > 1000:
                selected = objects[:1000]
                truncated = True
            elif marker is not None:
                selected = objects[1000:]
                truncated = False
            else:
                selected = objects
                truncated = False
            response: dict[str, object] = {
                "Versions": [
                    {"Key": item["key"], "VersionId": item["version_id"]}
                    for item in selected
                    if item["kind"] == "version"
                ],
                "DeleteMarkers": [
                    {"Key": item["key"], "VersionId": item["version_id"]}
                    for item in selected
                    if item["kind"] == "delete_marker"
                ],
                "IsTruncated": truncated,
            }
            if truncated:
                response.update(
                    {
                        "NextKeyMarker": f"{prefix}page-2",
                        "NextVersionIdMarker": "page-2",
                    }
                )
            return self._json(response)
        if (service, operation) == ("s3api", "list-multipart-uploads"):
            if self._arg(arguments, "--max-uploads") != "1000":
                return reset.CommandResult(64, "", "multipart page bound is not explicit")
            bucket = self._arg(arguments, "--bucket")
            prefix = self._arg(arguments, "--prefix")
            if bucket not in self.uploads or prefix is None:
                return reset.CommandResult(65, "", "unknown ChunkStore target")
            return self._json(
                {
                    "Uploads": [
                        {"Key": item["key"], "UploadId": item["upload_id"]}
                        for item in self.uploads[bucket]
                        if item["key"].startswith(prefix)
                    ],
                    "IsTruncated": False,
                }
            )
        if (service, operation) == ("s3api", "delete-objects"):
            bucket = self._arg(arguments, "--bucket")
            if bucket != "cats-chunks-old-fixture":
                return reset.CommandResult(65, "", "fresh ChunkStore delete attempted")
            delete_path = self._arg(arguments, "--delete")
            if delete_path is None or not delete_path.startswith("file://"):
                return reset.CommandResult(64, "", "missing exact delete document")
            request = json.loads(Path(delete_path.removeprefix("file://")).read_text())
            wanted = {(item["Key"], item["VersionId"]) for item in request["Objects"]}
            existing = {
                (item["key"], item["version_id"]) for item in self.objects[bucket]
            }
            if not wanted <= existing or len(wanted) != len(request["Objects"]):
                return reset.CommandResult(65, "", "unexpected delete target")
            self.objects[bucket] = [
                item
                for item in self.objects[bucket]
                if (item["key"], item["version_id"]) not in wanted
            ]
            self.delete_calls += 1
            return self._json(
                {
                    "Deleted": [
                        {"Key": item["Key"], "VersionId": item["VersionId"]}
                        for item in request["Objects"]
                    ]
                }
            )
        if (service, operation) == ("s3api", "abort-multipart-upload"):
            bucket = self._arg(arguments, "--bucket")
            if bucket != "cats-chunks-old-fixture":
                return reset.CommandResult(65, "", "fresh multipart abort attempted")
            key = self._arg(arguments, "--key")
            upload_id = self._arg(arguments, "--upload-id")
            before = len(self.uploads[bucket])
            self.uploads[bucket] = [
                item
                for item in self.uploads[bucket]
                if (item["key"], item["upload_id"]) != (key, upload_id)
            ]
            if len(self.uploads[bucket]) != before - 1:
                return reset.CommandResult(65, "", "unexpected multipart target")
            self.abort_calls += 1
            return reset.CommandResult(0, "")
        if (service, operation) == ("s3api", "list-objects-v2"):
            if self._arg(arguments, "--max-keys") != "1000":
                return reset.CommandResult(64, "", "current-object page bound is not explicit")
            bucket = self._arg(arguments, "--bucket")
            prefix = self._arg(arguments, "--prefix")
            if bucket not in self.objects or prefix is None:
                return reset.CommandResult(65, "", "unknown ChunkStore target")
            return self._json(
                {
                    "Contents": [
                        {"Key": item["key"]}
                        for item in self.objects[bucket]
                        if item["kind"] == "version"
                        and item["key"].startswith(prefix)
                    ],
                    "IsTruncated": False,
                }
            )
        if (service, operation) == ("kinesis", "delete-stream"):
            stream = self._arg(arguments, "--stream-name")
            if stream != "cats-usage-old" or stream not in self.streams:
                return reset.CommandResult(65, "", "fresh or unknown stream delete")
            self.streams.remove(stream)
            self.stream_delete_calls += 1
            return reset.CommandResult(0, "")
        if (service, operation) == ("dynamodb", "delete-table"):
            table = self._arg(arguments, "--table-name")
            if table != "cats-usage-checkpoints-old" or table not in self.tables:
                return reset.CommandResult(65, "", "fresh or unknown table delete")
            self.tables.remove(table)
            self.table_delete_calls += 1
            return reset.CommandResult(0, "")
        if service == "kinesis" and operation == "wait":
            stream = self._arg(arguments, "--stream-name")
            if arguments[7] != "stream-not-exists" or stream in self.streams:
                return reset.CommandResult(65, "", "stream waiter target still exists")
            return reset.CommandResult(0, "")
        if service == "dynamodb" and operation == "wait":
            table = self._arg(arguments, "--table-name")
            if arguments[7] != "table-not-exists" or table in self.tables:
                return reset.CommandResult(65, "", "table waiter target still exists")
            return reset.CommandResult(0, "")
        return reset.CommandResult(64, "", f"unexpected AWS call {service} {operation}")

    def _kubectl(self, arguments: list[str]) -> reset.CommandResult:
        if "config" in arguments and "view" in arguments:
            return reset.CommandResult(0, self.endpoint)
        resource = arguments[arguments.index("get") + 1]
        if resource == "namespace":
            return self._json(
                {
                    "metadata": {
                        "name": "cats",
                        "uid": "namespace-uid",
                        "labels": {
                            "cats.run/ingress": (
                                "disabled" if self.ingress_closed else "enabled"
                            )
                        },
                    }
                }
            )
        if resource == "deployments":
            return self._json(
                {
                    "items": [
                        {
                            "metadata": {"uid": "deployment-uid", "generation": 7},
                            "spec": {"replicas": 2},
                            "status": {
                                "replicas": 2,
                                "readyReplicas": 2,
                                "availableReplicas": 2,
                                "updatedReplicas": 2,
                                "observedGeneration": 7,
                            },
                        }
                    ]
                }
            )
        if resource == "pods":
            pod = {
                "status": {
                    "phase": "Running",
                    "conditions": [{"type": "Ready", "status": "True"}],
                }
            }
            return self._json({"items": [pod, pod]})
        if resource in {"ingresses", "ingressclasses"}:
            items = [] if self.ingress_closed else [{"metadata": {"uid": "public"}}]
            return self._json({"items": items})
        return reset.CommandResult(64, "", f"unexpected kubectl resource {resource}")

    def _psql(
        self, arguments: list[str], env: Mapping[str, str] | None
    ) -> reset.CommandResult:
        if env is None or env.get("PGSERVICE") != "cats_reset" or "PGSERVICEFILE" not in env:
            return reset.CommandResult(64, "", "private libpq service was not selected")
        if any("fixture-secret" in argument for argument in arguments):
            return reset.CommandResult(65, "", "secret appeared in argv")
        service_path = Path(env["PGSERVICEFILE"])
        if service_path.stat().st_mode & 0o077:
            return reset.CommandResult(65, "", "libpq service file is not private")
        service = service_path.read_text()
        if "fixture-secret" not in service:
            return reset.CommandResult(65, "", "libpq service lost the password")
        hosts = {
            "old-control-db": "cats_control_old",
            "old-usage-db": "cats_usage_old",
            "fresh-control-db": "cats_control_fresh",
            "fresh-usage-db": "cats_usage_fresh",
        }
        matches = [schema for host, schema in hosts.items() if host in service]
        if len(matches) != 1:
            return reset.CommandResult(65, "", "unknown PostgreSQL authority")
        schema = matches[0]
        sql = arguments[arguments.index("--command") + 1]
        if "DROP SCHEMA" in sql:
            if not self.schemas[schema] or f'DROP SCHEMA "{schema}" CASCADE' not in sql:
                return reset.CommandResult(65, "", "wrong schema drop")
            if schema not in {"cats_control_old", "cats_usage_old"}:
                return reset.CommandResult(65, "", "fresh schema drop attempted")
            self.schemas[schema] = False
            self.drop_calls.append(schema)
            return reset.CommandResult(0, "")
        if "'relations'" in sql:
            marker = (
                "control_schema_version" if "control" in schema else "schema_migrations"
            )
            return self._json(
                {
                    "database": "cats",
                    "server_address": "10.0.0.10",
                    "server_port": 5432,
                    "current_user": (
                        "cats_readonly" if schema.endswith("_fresh") else "cats_owner"
                    ),
                    "schema_exists": self.schemas[schema],
                    "schema_owner": "cats_owner",
                    "marker_exists": self.schemas[schema],
                    "relations": [["r", marker], ["r", "fixture_table"]],
                }
            )
        if "max(version)::text" in sql:
            return self._json({"version": self.schema_versions[schema]})
        if "WITH RECURSIVE closure" in sql:
            return self._json([])
        if "'schema_exists', EXISTS" in sql:
            return self._json({"schema_exists": self.schemas[schema]})
        return reset.CommandResult(64, "", "unexpected PostgreSQL query")


class SabotagedS3OwnerRunner(FakeRunner):
    """Model a regression that omits or changes the S3 account precondition."""

    def __init__(self, account: str, region: str, cluster: str, replacement: str | None) -> None:
        super().__init__(account, region, cluster)
        self.replacement = replacement

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> reset.CommandResult:
        arguments = list(argv)
        if "s3api" in arguments and "--expected-bucket-owner" in arguments:
            index = arguments.index("--expected-bucket-owner")
            if self.replacement is None:
                del arguments[index : index + 2]
            else:
                arguments[index + 1] = self.replacement
        return super().run(arguments, env=env, timeout=timeout)


class ResponseLossRunner(FakeRunner):
    """Apply one exact effect, then hide its successful response once."""

    def __init__(
        self, account: str, region: str, cluster: str, lost_effect: str
    ) -> None:
        super().__init__(account, region, cluster)
        self.lost_effect = lost_effect
        self.response_lost = False

    def run(
        self,
        argv: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        timeout: int = 120,
    ) -> reset.CommandResult:
        arguments = list(argv)
        result = super().run(arguments, env=env, timeout=timeout)
        if self.response_lost or result.returncode != 0:
            return result
        effect: str | None = None
        if arguments[0] == "aws":
            if "delete-objects" in arguments:
                effect = "s3-delete"
            elif "abort-multipart-upload" in arguments:
                effect = "s3-abort"
            elif "delete-stream" in arguments:
                effect = "stream-delete"
            elif "delete-table" in arguments:
                effect = "table-delete"
        elif arguments[0] == "psql" and "--command" in arguments:
            sql = arguments[arguments.index("--command") + 1]
            if 'DROP SCHEMA "cats_control_old"' in sql:
                effect = "control-drop"
            elif 'DROP SCHEMA "cats_usage_old"' in sql:
                effect = "usage-drop"
        if effect == self.lost_effect:
            self.response_lost = True
            return reset.CommandResult(75, "", "simulated successful-effect response loss")
        return result


def write_private(path: Path, value: str) -> None:
    path.write_text(value)
    path.chmod(0o600)


FIXTURE_NOW = dt.datetime(2026, 8, 13, 0, 0, tzinfo=dt.timezone.utc)


def fixture_cutover_authority(
    config: reset.Config,
    reference_time: dt.datetime,
) -> dict[str, object]:
    if config.legacy_fixture_post_green_evidence_file is None:
        raise reset.ResetError("fixture cutover evidence is unavailable")
    value, raw_digest = reset.read_json_file(
        config.legacy_fixture_post_green_evidence_file,
        "fixture cutover evidence",
    )
    reset.require_keys(
        value,
        {
            "kind",
            "version",
            "reset_id",
            "observed_at",
            "qualified_release_commit",
            "qualified_artifact_sha256",
            "aws_account_id",
            "aws_region",
            "eks_cluster_name",
            "kubernetes_namespace",
            "fresh_targets",
            "qualification",
            "qualification_manifest_sha256",
            "old_writers",
        },
        "fixture cutover evidence",
    )
    if (
        value["kind"] != reset.KIND_GREEN
        or type(value["version"]) is not int
        or value["version"] != 1
        or value["reset_id"] != config.reset_id
        or value["qualified_release_commit"] != config.release_commit
        or value["qualified_artifact_sha256"] != config.artifact_sha256
        or value["aws_account_id"] != config.aws_account_id
        or value["aws_region"] != config.aws_region
        or value["eks_cluster_name"] != config.eks_cluster_name
        or value["kubernetes_namespace"] != config.kubernetes_namespace
        or value["fresh_targets"] != config.fresh_targets()
        or value["qualification"] != "passed"
    ):
        raise reset.ResetError("fixture cutover evidence binding drifted")
    old_writers = reset.require_keys(
        value["old_writers"], set(reset.COMPONENTS), "fixture old writers"
    )
    if any(old_writers[name] != "stopped_or_isolated" for name in reset.COMPONENTS):
        raise reset.ResetError("fixture old writer is not terminal")
    qualification = value["qualification_manifest_sha256"]
    if not isinstance(qualification, str) or reset.HEX_SHA256.fullmatch(qualification) is None:
        raise reset.ResetError("fixture qualification digest is malformed")
    observed = reset.parse_time(value["observed_at"], "fixture observed_at")
    if (
        observed > reference_time
        or (reference_time - observed).total_seconds()
        > reset.POST_GREEN_MAX_AGE_SECONDS
    ):
        raise reset.ResetError("fixture cutover evidence is stale")
    proof_digest = "sha256:" + raw_digest
    return {
        "cutover_id": "legacy_fixture_cutover",
        "proof_set_sha256": proof_digest,
        "operator": {
            "aws_partition": "aws",
            "account_id": config.aws_account_id,
            "role_arn": f"arn:aws:iam::{config.aws_account_id}:role/fixture-cutover",
            "principal_arn": (
                f"arn:aws:sts::{config.aws_account_id}:"
                "assumed-role/fixture-cutover/session"
            ),
        },
        "operator_trust_sha256": proof_digest,
        "release_id": "legacy_fixture_release",
        "release_manifest_sha256": "sha256:" + config.artifact_sha256,
        "worker_bundle_sha256": proof_digest,
        "qualification_manifest_sha256": "sha256:" + qualification,
        "qualification_catalog_sha256": proof_digest,
        "fresh_targets_sha256": proof_digest,
        "fleet_closed_receipt_sha256": proof_digest,
        "route_v2_rotation_qualification_receipt_sha256": proof_digest,
        "route_v2_rotation_qualification_node_ack_sets_sha256": proof_digest,
        "route_v2_rotation_qualification_transcript_sha256": proof_digest,
        "usage_terminal_receipt_sha256": proof_digest,
        "old_host_coverage_sha256": proof_digest,
        "kernel_nbd_qualification_bundle_sha256": proof_digest,
        "vhost_user_qualification_bundle_sha256": proof_digest,
        "usage_schema_verification_receipt_sha256": proof_digest,
        "usage_schema_catalog_sha256": proof_digest,
    }


def fixture_executor(
    config: reset.Config,
    runner: FakeRunner,
    *,
    now: dt.datetime = FIXTURE_NOW,
    receipt_publication_hook: Callable[[str, Path], None] | None = None,
) -> reset.ResetExecutor:
    return reset.ResetExecutor(
        config,
        runner,
        now=now,
        cutover_authority_verifier=lambda reference: fixture_cutover_authority(
            config,
            reference,
        ),
        receipt_publication_hook=receipt_publication_hook,
    )


def build_scenario(
    parent: Path,
    reset_id: str,
    *,
    lost_effect: str | None = None,
    observed_at: str = "2026-08-12T23:55:00Z",
    qualification_digest: str = "b" * 64,
) -> tuple[reset.Config, FakeRunner, reset.ResetExecutor, Path, str]:
    root = parent / reset_id
    root.mkdir()
    receipts = root / "receipts"
    receipts.mkdir(mode=0o700)
    kubeconfig = root / "kubeconfig"
    kubeconfig.write_text("fixture")
    paths = {
        name: root / f"{name}.url"
        for name in ("old-control", "old-usage", "fresh-control", "fresh-usage")
    }
    for name, host in [
        ("old-control", "old-control-db"),
        ("old-usage", "old-usage-db"),
        ("fresh-control", "fresh-control-db"),
        ("fresh-usage", "fresh-usage-db"),
    ]:
        write_private(
            paths[name],
            f"postgresql://cats:fixture-secret@{host}/cats?sslmode=require\n",
        )
    release_commit = "a" * 40
    artifact_sha256 = "d" * 64
    evidence = root / "post-green.json"
    evidence.write_text(
        json.dumps(
            {
                "kind": reset.KIND_GREEN,
                "version": 1,
                "reset_id": reset_id,
                "observed_at": observed_at,
                "qualified_release_commit": release_commit,
                "qualified_artifact_sha256": artifact_sha256,
                "aws_account_id": "123456789012",
                "aws_region": "us-east-1",
                "eks_cluster_name": "cats-production",
                "kubernetes_namespace": "cats",
                "fresh_targets": {
                    "control_schema": "cats_control_fresh",
                    "usage_schema": "cats_usage_fresh",
                    "chunkstore_bucket": "cats-chunks-fresh-fixture",
                    "chunkstore_object_prefix": "cats-fresh/",
                    "usage_kinesis_stream": "cats-usage-fresh",
                    "usage_checkpoint_table": "cats-usage-checkpoints-fresh",
                    "usage_archive_bucket": "cats-usage-archive-fresh-fixture",
                },
                "qualification": "passed",
                "qualification_manifest_sha256": qualification_digest,
                "old_writers": {
                    name: "stopped_or_isolated" for name in reset.COMPONENTS
                },
            }
        )
        + "\n"
    )
    config = reset.Config(
        reset_id=reset_id,
        release_commit=release_commit,
        artifact_sha256=artifact_sha256,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        eks_cluster_name="cats-production",
        kubernetes_namespace="cats",
        kubeconfig=kubeconfig,
        kube_context="fixture-context",
        control_postgres_url_file=paths["old-control"],
        control_schema="cats_control_old",
        usage_postgres_url_file=paths["old-usage"],
        usage_schema="cats_usage_old",
        chunkstore_bucket="cats-chunks-old-fixture",
        chunkstore_prefix="cats-old",
        usage_kinesis_stream="cats-usage-old",
        usage_checkpoint_table="cats-usage-checkpoints-old",
        usage_archive_bucket="cats-usage-archive-old-fixture",
        new_control_postgres_url_file=paths["fresh-control"],
        new_control_schema="cats_control_fresh",
        new_usage_postgres_url_file=paths["fresh-usage"],
        new_usage_schema="cats_usage_fresh",
        new_chunkstore_bucket="cats-chunks-fresh-fixture",
        new_chunkstore_prefix="cats-fresh",
        new_usage_kinesis_stream="cats-usage-fresh",
        new_usage_checkpoint_table="cats-usage-checkpoints-fresh",
        new_usage_archive_bucket="cats-usage-archive-fresh-fixture",
        receipt_directory=receipts,
        cutover_proof_directory=root / "unused-proof-directory",
        production_cutover_operator_trust_file=root / "unused-cutover-trust.json",
        fresh_usage_postgres_ca_file=root / "unused-usage-ca.pem",
        legacy_fixture_post_green_evidence_file=evidence,
    )
    if lost_effect is None:
        runner: FakeRunner = FakeRunner(
            config.aws_account_id, config.aws_region, config.eks_cluster_name
        )
    else:
        runner = ResponseLossRunner(
            config.aws_account_id,
            config.aws_region,
            config.eks_cluster_name,
            lost_effect,
        )
    executor = fixture_executor(config, runner)
    plan_path, plan_digest = executor.plan()
    return config, runner, executor, plan_path, plan_digest


def mutation_counts(runner: FakeRunner) -> tuple[int, int, int, int, tuple[str, ...]]:
    return (
        runner.delete_calls,
        runner.abort_calls,
        runner.stream_delete_calls,
        runner.table_delete_calls,
        tuple(runner.drop_calls),
    )


def assert_forward_resume(parent: Path) -> None:
    expected_final = (2, 1, 1, 1, ("cats_control_old", "cats_usage_old"))
    for index, effect in enumerate(
        [
            "s3-delete",
            "s3-abort",
            "stream-delete",
            "table-delete",
            "control-drop",
            "usage-drop",
        ],
        start=1,
    ):
        config, runner, executor, plan_path, plan_digest = build_scenario(
            parent, f"cutover-loss-{index:04d}", lost_effect=effect
        )
        try:
            executor.apply(plan_path, plan_digest, config.reset_id, execute=True)
        except reset.ResetError:
            pass
        else:
            raise AssertionError(f"{effect} response loss did not interrupt the first apply")
        resumed = fixture_executor(config, runner)
        final_path, final_digest = resumed.apply(
            plan_path, plan_digest, config.reset_id, execute=True
        )
        if mutation_counts(runner) != expected_final:
            raise AssertionError(f"{effect} was repeated or left a later effect incomplete")
        before_replay = mutation_counts(runner)
        replay_path, replay_digest = fixture_executor(
            config, runner, now=FIXTURE_NOW + dt.timedelta(days=2)
        ).apply(plan_path, plan_digest, config.reset_id, execute=True)
        if (replay_path, replay_digest) != (final_path, final_digest):
            raise AssertionError(f"{effect} complete replay changed the final receipt")
        if mutation_counts(runner) != before_replay:
            raise AssertionError(f"{effect} complete replay repeated a physical effect")

    for index, stage in enumerate(
        [
            "s3-empty",
            "usage-transport-empty",
            "control-schema-empty",
            "usage-schema-empty",
            "reset-complete",
        ],
        start=1,
    ):
        config, runner, executor, plan_path, plan_digest = build_scenario(
            parent, f"cutover-crash-{index:04d}"
        )
        original_write_receipt = reset.write_receipt
        crashed = False

        def crash_before_receipt(
            directory: Path,
            reset_id: str,
            candidate_stage: str,
            value: dict[str, object],
        ) -> tuple[Path, str]:
            nonlocal crashed
            if candidate_stage == stage and not crashed:
                crashed = True
                raise reset.ResetError(f"simulated crash before {stage} receipt")
            return original_write_receipt(directory, reset_id, candidate_stage, value)

        reset.write_receipt = crash_before_receipt
        try:
            try:
                executor.apply(plan_path, plan_digest, config.reset_id, execute=True)
            except reset.ResetError as error:
                if f"before {stage} receipt" not in str(error):
                    raise
            else:
                raise AssertionError(f"{stage} crash point did not interrupt apply")
        finally:
            reset.write_receipt = original_write_receipt
        final_path, final_digest = fixture_executor(
            config, runner, now=FIXTURE_NOW + dt.timedelta(days=2)
        ).apply(plan_path, plan_digest, config.reset_id, execute=True)
        if mutation_counts(runner) != expected_final:
            raise AssertionError(f"{stage} crash replay repeated or missed an effect")
        before_replay = mutation_counts(runner)
        replay_path, replay_digest = fixture_executor(
            config, runner, now=FIXTURE_NOW + dt.timedelta(days=3)
        ).apply(plan_path, plan_digest, config.reset_id, execute=True)
        if (replay_path, replay_digest) != (final_path, final_digest):
            raise AssertionError(f"{stage} crash replay changed final receipt identity")
        if mutation_counts(runner) != before_replay:
            raise AssertionError(f"{stage} duplicate replay executed an effect")


def assert_receipt_publication_recovery(parent: Path) -> None:
    case = 0
    for receipt_name, operation in (("plan", "plan"), ("dry-run", "dry-run")):
        for suffix in (".json", ".sha256"):
            for crash_point in ("after_link", "after_directory_fsync"):
                case += 1
                config, runner, _executor, plan_path, plan_digest = build_scenario(
                    parent, f"cutover-publish-read-only-{case:04d}"
                )
                if operation == "plan":
                    plan_path.unlink()
                    plan_path.with_suffix(".sha256").unlink()
                crashed = False

                def crash_read_only_publication(point: str, path: Path) -> None:
                    nonlocal crashed
                    if (
                        not crashed
                        and point == crash_point
                        and path.name
                        == f"{config.reset_id}.{receipt_name}{suffix}"
                    ):
                        crashed = True
                        raise reset.ResetError(
                            f"simulated {receipt_name}{suffix} {crash_point} crash"
                        )

                executor = fixture_executor(
                    config,
                    runner,
                    receipt_publication_hook=crash_read_only_publication,
                )
                try:
                    if operation == "plan":
                        executor.plan()
                    else:
                        executor.apply(
                            plan_path,
                            plan_digest,
                            config.reset_id,
                            execute=False,
                        )
                except reset.ResetError as error:
                    if f"{receipt_name}{suffix} {crash_point}" not in str(error):
                        raise
                else:
                    raise AssertionError(
                        f"{receipt_name}{suffix} {crash_point} did not interrupt publication"
                    )
                if operation == "plan":
                    fixture_executor(config, runner).plan()
                else:
                    fixture_executor(config, runner).apply(
                        plan_path,
                        plan_digest,
                        config.reset_id,
                        execute=False,
                    )
                if mutation_counts(runner) != (0, 0, 0, 0, ()):
                    raise AssertionError(
                        f"{receipt_name}{suffix} {crash_point} crossed the mutation boundary"
                    )

    expected_final = (2, 1, 1, 1, ("cats_control_old", "cats_usage_old"))
    stages = [
        "reset-started",
        "s3-empty",
        "usage-transport-empty",
        "control-schema-empty",
        "usage-schema-empty",
        "reset-complete",
    ]
    case = 0
    for stage in stages:
        for suffix in (".json", ".sha256"):
            for crash_point in ("after_link", "after_directory_fsync"):
                case += 1
                config, runner, _executor, plan_path, plan_digest = build_scenario(
                    parent, f"cutover-publish-{case:04d}"
                )
                crashed = False

                def crash_publication(point: str, path: Path) -> None:
                    nonlocal crashed
                    if (
                        not crashed
                        and point == crash_point
                        and path.name == f"{config.reset_id}.{stage}{suffix}"
                    ):
                        crashed = True
                        raise reset.ResetError(
                            f"simulated {stage}{suffix} {crash_point} crash"
                        )

                try:
                    fixture_executor(
                        config,
                        runner,
                        receipt_publication_hook=crash_publication,
                    ).apply(plan_path, plan_digest, config.reset_id, execute=True)
                except reset.ResetError as error:
                    if f"{stage}{suffix} {crash_point}" not in str(error):
                        raise
                else:
                    raise AssertionError(
                        f"{stage}{suffix} {crash_point} did not interrupt publication"
                    )
                final_path, final_digest = fixture_executor(config, runner).apply(
                    plan_path, plan_digest, config.reset_id, execute=True
                )
                if mutation_counts(runner) != expected_final:
                    raise AssertionError(
                        f"{stage}{suffix} {crash_point} repeated or missed an effect"
                    )
                before = mutation_counts(runner)
                replay_path, replay_digest = fixture_executor(config, runner).apply(
                    plan_path, plan_digest, config.reset_id, execute=True
                )
                if (replay_path, replay_digest) != (final_path, final_digest):
                    raise AssertionError(
                        f"{stage}{suffix} {crash_point} changed final authority"
                    )
                if mutation_counts(runner) != before:
                    raise AssertionError(
                        f"{stage}{suffix} {crash_point} replayed a physical effect"
                    )


def assert_unaccepted_proofs_block_execute(parent: Path) -> None:
    random_digest = os.urandom(32).hex()
    config, _plan_runner, _executor, plan_path, plan_digest = build_scenario(
        parent,
        "cutover-proof-block-0001",
        qualification_digest=random_digest,
    )
    cases = [
        (
            "production cutover proof",
            None,
        ),
        (
            "cutover authority projection",
            lambda _reference: {},
        ),
    ]
    for label, verifier in cases:
        runner = FakeRunner(
            config.aws_account_id, config.aws_region, config.eks_cluster_name
        )
        executor = reset.ResetExecutor(
            config,
            runner,
            now=FIXTURE_NOW,
            cutover_authority_verifier=verifier,
        )
        try:
            executor.apply(plan_path, plan_digest, config.reset_id, execute=True)
        except reset.ResetError as error:
            if label not in str(error):
                raise
        else:
            raise AssertionError(f"unaccepted {label} did not mechanically block")
        if runner.calls or mutation_counts(runner) != (0, 0, 0, 0, ()):
            raise AssertionError(
                f"random digest crossed AWS/PostgreSQL boundary before {label} block"
            )


def assert_cutover_authority_ordering_and_replay(parent: Path) -> None:
    config, runner, _executor, plan_path, plan_digest = build_scenario(
        parent,
        "cutover-authority-order-0001",
    )
    projection = fixture_cutover_authority(config, FIXTURE_NOW)
    verification_calls: list[dt.datetime] = []

    def exact_verifier(reference: dt.datetime) -> dict[str, object]:
        verification_calls.append(reference)
        # Model a deterministic Rust verification receipt replay, rather than
        # returning shared mutable fixture state.
        return json.loads(json.dumps(projection))

    original_write_receipt = reset.write_receipt

    def crash_before_reset_started(
        directory: Path,
        reset_id: str,
        stage: str,
        value: dict[str, object],
    ) -> tuple[Path, str]:
        if stage == "reset-started":
            raise reset.ResetError(
                "simulated crash after schema verification before reset-started"
            )
        return original_write_receipt(directory, reset_id, stage, value)

    runner.calls.clear()
    reset.write_receipt = crash_before_reset_started
    try:
        try:
            reset.ResetExecutor(
                config,
                runner,
                now=FIXTURE_NOW,
                cutover_authority_verifier=exact_verifier,
            ).apply(plan_path, plan_digest, config.reset_id, execute=True)
        except reset.ResetError as error:
            if "after schema verification before reset-started" not in str(error):
                raise
        else:
            raise AssertionError("pre-reset-started verification crash did not stop")
    finally:
        reset.write_receipt = original_write_receipt
    if mutation_counts(runner) != (0, 0, 0, 0, ()):
        raise AssertionError("schema verification crash crossed the mutation boundary")
    if reset.read_stage_receipt(
        config.receipt_directory,
        config.reset_id,
        "reset-started",
    ) is not None:
        raise AssertionError("pre-publication crash manufactured reset-started authority")
    if len(verification_calls) != 2:
        raise AssertionError(
            "proof/schema authority was not checked in preflight and at the boundary"
        )

    verification_calls.clear()
    final_path, final_digest = reset.ResetExecutor(
        config,
        runner,
        now=FIXTURE_NOW,
        cutover_authority_verifier=exact_verifier,
    ).apply(plan_path, plan_digest, config.reset_id, execute=True)
    if len(verification_calls) != 2:
        raise AssertionError("exact proof/schema receipt replay was not revalidated")
    before = mutation_counts(runner)
    verification_calls.clear()
    replay_path, replay_digest = reset.ResetExecutor(
        config,
        runner,
        now=FIXTURE_NOW + dt.timedelta(days=2),
        cutover_authority_verifier=exact_verifier,
    ).apply(plan_path, plan_digest, config.reset_id, execute=True)
    if (replay_path, replay_digest) != (final_path, final_digest):
        raise AssertionError("completed reset exact replay changed its receipt")
    if mutation_counts(runner) != before:
        raise AssertionError("completed reset exact replay repeated a mutation")
    if verification_calls != [FIXTURE_NOW]:
        raise AssertionError(
            "forward replay did not bind proof verification to reset-started time"
        )


def assert_binding_failures(parent: Path) -> None:
    config, runner, executor, plan_path, plan_digest = build_scenario(
        parent, "cutover-bindings-0001"
    )
    for label, digest, confirmation in [
        ("plan", "0" * 64, config.reset_id),
        ("reset", plan_digest, "cutover-wrong-confirmation"),
    ]:
        try:
            executor.apply(plan_path, digest, confirmation, execute=True)
        except reset.ResetError:
            pass
        else:
            raise AssertionError(f"wrong {label} binding was accepted")
    if mutation_counts(runner) != (0, 0, 0, 0, ()):
        raise AssertionError("a wrong plan/reset binding crossed the mutation boundary")

    boolean_version_plan = plan_path.with_name("boolean-version-plan.json")
    boolean_version = json.loads(plan_path.read_text())
    boolean_version["version"] = True
    boolean_version_plan.write_bytes(reset.canonical_bytes(boolean_version))
    try:
        executor.apply(
            boolean_version_plan,
            reset.sha256_bytes(boolean_version_plan.read_bytes()),
            config.reset_id,
            execute=True,
        )
    except reset.ResetError:
        pass
    else:
        raise AssertionError("JSON boolean was accepted as reset plan version 1")
    if mutation_counts(runner) != (0, 0, 0, 0, ()):
        raise AssertionError("boolean plan version crossed the mutation boundary")

    original_write_receipt = reset.write_receipt
    crashed = False

    def crash_after_start(
        directory: Path,
        reset_id: str,
        stage: str,
        value: dict[str, object],
    ) -> tuple[Path, str]:
        nonlocal crashed
        if stage == "s3-empty" and not crashed:
            crashed = True
            raise reset.ResetError("simulated evidence-binding crash")
        return original_write_receipt(directory, reset_id, stage, value)

    reset.write_receipt = crash_after_start
    try:
        try:
            executor.apply(plan_path, plan_digest, config.reset_id, execute=True)
        except reset.ResetError as error:
            if "evidence-binding crash" not in str(error):
                raise
        else:
            raise AssertionError("evidence-binding setup did not cross reset-started")
    finally:
        reset.write_receipt = original_write_receipt
    before = mutation_counts(runner)
    evidence_value = json.loads(
        config.legacy_fixture_post_green_evidence_file.read_text()
    )
    evidence_value["qualification_manifest_sha256"] = "c" * 64
    config.legacy_fixture_post_green_evidence_file.write_text(
        json.dumps(evidence_value) + "\n"
    )
    try:
        fixture_executor(config, runner).apply(
            plan_path, plan_digest, config.reset_id, execute=True
        )
    except reset.ResetError as error:
        if "evidence changed" not in str(error):
            raise
    else:
        raise AssertionError("changed post-green evidence resumed an existing reset")
    if mutation_counts(runner) != before:
        raise AssertionError("changed post-green evidence executed a resumed effect")

    plan_config, plan_runner, plan_executor, original_plan, original_digest = build_scenario(
        parent, "cutover-wrong-plan-0001"
    )
    original_write_receipt = reset.write_receipt
    crashed = False

    def crash_with_started_receipt(
        directory: Path,
        reset_id: str,
        stage: str,
        value: dict[str, object],
    ) -> tuple[Path, str]:
        nonlocal crashed
        if stage == "s3-empty" and not crashed:
            crashed = True
            raise reset.ResetError("simulated wrong-plan setup crash")
        return original_write_receipt(directory, reset_id, stage, value)

    reset.write_receipt = crash_with_started_receipt
    try:
        try:
            plan_executor.apply(
                original_plan, original_digest, plan_config.reset_id, execute=True
            )
        except reset.ResetError as error:
            if "wrong-plan setup crash" not in str(error):
                raise
        else:
            raise AssertionError("wrong-plan setup did not create reset-started")
    finally:
        reset.write_receipt = original_write_receipt
    before = mutation_counts(plan_runner)
    tampered = json.loads(original_plan.read_text())
    tampered["retained"] = [*tampered["retained"], "tampered binding"]
    tampered_path = original_plan.parent / "tampered-plan.json"
    tampered_path.write_bytes(reset.canonical_bytes(tampered))
    tampered_digest = reset.sha256_bytes(tampered_path.read_bytes())
    try:
        fixture_executor(plan_config, plan_runner).apply(
            tampered_path, tampered_digest, plan_config.reset_id, execute=True
        )
    except reset.ResetError as error:
        if "plan_receipt_sha256" not in str(error):
            raise
    else:
        raise AssertionError("another plan resumed an existing reset")
    if mutation_counts(plan_runner) != before:
        raise AssertionError("wrong resume plan executed another effect")

    gap_config, gap_runner, gap_executor, gap_plan, gap_digest = build_scenario(
        parent, "cutover-gap-0001"
    )
    gap_executor.apply(gap_plan, gap_digest, gap_config.reset_id, execute=True)
    before = mutation_counts(gap_runner)
    for suffix in ("json", "sha256"):
        (gap_config.receipt_directory / f"{gap_config.reset_id}.control-schema-empty.{suffix}").unlink()
    try:
        fixture_executor(gap_config, gap_runner).apply(
            gap_plan, gap_digest, gap_config.reset_id, execute=True
        )
    except reset.ResetError as error:
        if "gap" not in str(error):
            raise
    else:
        raise AssertionError("a receipt chain gap was accepted")
    if mutation_counts(gap_runner) != before:
        raise AssertionError("a receipt chain gap executed another effect")

    pair_config, pair_runner, pair_executor, pair_plan, pair_digest = build_scenario(
        parent, "cutover-pair-0001"
    )
    pair_executor.apply(pair_plan, pair_digest, pair_config.reset_id, execute=True)
    before = mutation_counts(pair_runner)
    (
        pair_config.receipt_directory
        / f"{pair_config.reset_id}.s3-empty.sha256"
    ).unlink()
    fixture_executor(pair_config, pair_runner).apply(
        pair_plan, pair_digest, pair_config.reset_id, execute=True
    )
    repaired_checksum = (
        pair_config.receipt_directory
        / f"{pair_config.reset_id}.s3-empty.sha256"
    )
    if not repaired_checksum.is_file():
        raise AssertionError("missing derived checksum was not repaired from JSON authority")
    if mutation_counts(pair_runner) != before:
        raise AssertionError("derived checksum repair executed another effect")
    (
        pair_config.receipt_directory
        / f"{pair_config.reset_id}.s3-empty.json"
    ).unlink()
    try:
        fixture_executor(pair_config, pair_runner).apply(
            pair_plan, pair_digest, pair_config.reset_id, execute=True
        )
    except reset.ResetError as error:
        if "without JSON authority" not in str(error):
            raise
    else:
        raise AssertionError("orphan receipt checksum was accepted as authority")
    if mutation_counts(pair_runner) != before:
        raise AssertionError("orphan receipt checksum executed another effect")

    ahead_config, ahead_runner, ahead_executor, ahead_plan, ahead_digest = build_scenario(
        parent, "cutover-ahead-0001"
    )
    original_write_receipt = reset.write_receipt
    crashed = False

    def crash_before_s3_receipt(
        directory: Path,
        reset_id: str,
        stage: str,
        value: dict[str, object],
    ) -> tuple[Path, str]:
        nonlocal crashed
        if stage == "s3-empty" and not crashed:
            crashed = True
            raise reset.ResetError("simulated ahead-of-chain setup crash")
        return original_write_receipt(directory, reset_id, stage, value)

    reset.write_receipt = crash_before_s3_receipt
    try:
        try:
            ahead_executor.apply(
                ahead_plan, ahead_digest, ahead_config.reset_id, execute=True
            )
        except reset.ResetError as error:
            if "ahead-of-chain setup crash" not in str(error):
                raise
        else:
            raise AssertionError("ahead-of-chain setup did not stop before s3 receipt")
    finally:
        reset.write_receipt = original_write_receipt
    ahead_runner.schemas["cats_control_old"] = False
    before = mutation_counts(ahead_runner)
    try:
        fixture_executor(ahead_config, ahead_runner).apply(
            ahead_plan, ahead_digest, ahead_config.reset_id, execute=True
        )
    except reset.ResetError as error:
        if "advanced ahead" not in str(error):
            raise
    else:
        raise AssertionError("a physical effect ahead of the receipt chain was accepted")
    if mutation_counts(ahead_runner) != before:
        raise AssertionError("an ahead-of-chain contradiction executed another effect")

    stale_config, stale_runner, _executor, _plan, _digest = build_scenario(
        parent, "cutover-stale-0001"
    )
    stale_value = json.loads(
        stale_config.legacy_fixture_post_green_evidence_file.read_text()
    )
    stale_value["observed_at"] = "2026-08-12T23:44:59Z"
    stale_config.legacy_fixture_post_green_evidence_file.write_text(
        json.dumps(stale_value) + "\n"
    )
    try:
        fixture_executor(stale_config, stale_runner).plan()
    except reset.ResetError as error:
        if "older than" not in str(error):
            raise
    else:
        raise AssertionError("stale post-green evidence was accepted")

    wrong_id_config, wrong_id_runner, _executor, _plan, _digest = build_scenario(
        parent, "cutover-evidence-id-0001"
    )
    wrong_id_value = json.loads(
        wrong_id_config.legacy_fixture_post_green_evidence_file.read_text()
    )
    wrong_id_value["reset_id"] = "cutover-evidence-id-wrong"
    wrong_id_config.legacy_fixture_post_green_evidence_file.write_text(
        json.dumps(wrong_id_value) + "\n"
    )
    try:
        fixture_executor(wrong_id_config, wrong_id_runner).plan()
    except reset.ResetError as error:
        if "reset_id" not in str(error):
            raise
    else:
        raise AssertionError("post-green evidence for another reset was accepted")

    boundary_config, boundary_runner, boundary_executor, boundary_plan, boundary_digest = (
        build_scenario(parent, "cutover-boundary-stale-0001")
    )
    boundary_executor.now = FIXTURE_NOW + dt.timedelta(seconds=901)
    try:
        boundary_executor.apply(
            boundary_plan,
            boundary_digest,
            boundary_config.reset_id,
            execute=True,
        )
    except reset.ResetError as error:
        if "older than" not in str(error):
            raise
    else:
        raise AssertionError("evidence that aged out during preflight crossed reset-started")
    if mutation_counts(boundary_runner) != (0, 0, 0, 0, ()):
        raise AssertionError("aged-out pre-start evidence executed a physical effect")


def main() -> int:
    try:
        with tempfile.TemporaryDirectory(prefix="cats-clean-slate-fixture-") as directory:
            root = Path(directory)
            receipts = root / "receipts"
            receipts.mkdir(mode=0o700)
            kubeconfig = root / "kubeconfig"
            kubeconfig.write_text("fixture")
            old_control_url = root / "old-control.url"
            old_usage_url = root / "old-usage.url"
            fresh_control_url = root / "fresh-control.url"
            fresh_usage_url = root / "fresh-usage.url"
            write_private(
                old_control_url,
                "postgresql://cats:fixture-secret@old-control-db/cats?sslmode=require\n",
            )
            write_private(
                old_usage_url,
                "postgresql://cats:fixture-secret@old-usage-db/cats?sslmode=require\n",
            )
            write_private(
                fresh_control_url,
                "postgresql://cats:fixture-secret@fresh-control-db/cats?sslmode=require\n",
            )
            write_private(
                fresh_usage_url,
                "postgresql://cats:fixture-secret@fresh-usage-db/cats?sslmode=require\n",
            )
            release_commit = "a" * 40
            artifact_sha256 = "d" * 64
            fresh_targets = {
                "control_schema": "cats_control_fresh",
                "usage_schema": "cats_usage_fresh",
                "chunkstore_bucket": "cats-chunks-fresh-fixture",
                "chunkstore_object_prefix": "cats-fresh/",
                "usage_kinesis_stream": "cats-usage-fresh",
                "usage_checkpoint_table": "cats-usage-checkpoints-fresh",
                "usage_archive_bucket": "cats-usage-archive-fresh-fixture",
            }
            evidence = root / "post-green.json"
            evidence.write_text(
                json.dumps(
                    {
                        "kind": reset.KIND_GREEN,
                        "version": 1,
                        "reset_id": "cutover-fixture-0001",
                        "observed_at": "2026-08-12T23:55:00Z",
                        "qualified_release_commit": release_commit,
                        "qualified_artifact_sha256": artifact_sha256,
                        "aws_account_id": "123456789012",
                        "aws_region": "us-east-1",
                        "eks_cluster_name": "cats-production",
                        "kubernetes_namespace": "cats",
                        "fresh_targets": fresh_targets,
                        "qualification": "passed",
                        "qualification_manifest_sha256": "b" * 64,
                        "old_writers": {
                            name: "stopped_or_isolated" for name in reset.COMPONENTS
                        },
                    }
                )
                + "\n"
            )
            config = reset.Config(
                reset_id="cutover-fixture-0001",
                release_commit=release_commit,
                artifact_sha256=artifact_sha256,
                aws_account_id="123456789012",
                aws_region="us-east-1",
                eks_cluster_name="cats-production",
                kubernetes_namespace="cats",
                kubeconfig=kubeconfig,
                kube_context="fixture-context",
                control_postgres_url_file=old_control_url,
                control_schema="cats_control_old",
                usage_postgres_url_file=old_usage_url,
                usage_schema="cats_usage_old",
                chunkstore_bucket="cats-chunks-old-fixture",
                chunkstore_prefix="cats-old",
                usage_kinesis_stream="cats-usage-old",
                usage_checkpoint_table="cats-usage-checkpoints-old",
                usage_archive_bucket="cats-usage-archive-old-fixture",
                new_control_postgres_url_file=fresh_control_url,
                new_control_schema="cats_control_fresh",
                new_usage_postgres_url_file=fresh_usage_url,
                new_usage_schema="cats_usage_fresh",
                new_chunkstore_bucket="cats-chunks-fresh-fixture",
                new_chunkstore_prefix="cats-fresh",
                new_usage_kinesis_stream="cats-usage-fresh",
                new_usage_checkpoint_table="cats-usage-checkpoints-fresh",
                new_usage_archive_bucket="cats-usage-archive-fresh-fixture",
                receipt_directory=receipts,
                cutover_proof_directory=root / "unused-proof-directory",
                production_cutover_operator_trust_file=(
                    root / "unused-cutover-trust.json"
                ),
                fresh_usage_postgres_ca_file=root / "unused-usage-ca.pem",
                legacy_fixture_post_green_evidence_file=evidence,
            )
            runner = FakeRunner(
                config.aws_account_id, config.aws_region, config.eks_cluster_name
            )
            executor = fixture_executor(config, runner)
            plan_path, plan_digest = executor.plan()
            s3_calls = [
                arguments
                for arguments, _environment in runner.calls
                if "s3api" in arguments
            ]
            if not s3_calls:
                raise AssertionError("known-positive preflight did not exercise S3")
            for arguments in s3_calls:
                if FakeRunner._arg(arguments, "--expected-bucket-owner") != config.aws_account_id:
                    raise AssertionError("known-positive S3 call lost its exact expected owner")
            dry_path, _dry_digest = executor.apply(
                plan_path, plan_digest, config.reset_id, execute=False
            )
            if runner.delete_calls or runner.abort_calls or runner.drop_calls:
                raise AssertionError("dry-run crossed a destructive boundary")
            if "cats-usage-old" not in runner.streams or "cats-usage-checkpoints-old" not in runner.tables:
                raise AssertionError("dry-run retired an old usage authority")
            final_path, final_digest = executor.apply(
                plan_path, plan_digest, config.reset_id, execute=True
            )
            if runner.delete_calls != 2:
                raise AssertionError("1002 version/delete-marker targets were not batched 1000+2")
            if runner.abort_calls != 1 or runner.drop_calls != [
                "cats_control_old",
                "cats_usage_old",
            ]:
                raise AssertionError("multipart abort or exact schema drop contract was lost")
            if runner.objects["cats-chunks-old-fixture"] or runner.uploads[
                "cats-chunks-old-fixture"
            ]:
                raise AssertionError("old ChunkStore authority is not empty after reset")
            if not runner.objects["cats-chunks-fresh-fixture"]:
                raise AssertionError("fresh ChunkStore was deleted")
            if runner.schemas != {
                "cats_control_old": False,
                "cats_usage_old": False,
                "cats_control_fresh": True,
                "cats_usage_fresh": True,
            }:
                raise AssertionError("schema retirement crossed the old/fresh boundary")
            if runner.streams != {"cats-usage-fresh"} or runner.tables != {
                "cats-usage-checkpoints-fresh"
            }:
                raise AssertionError("usage transport retirement crossed the old/fresh boundary")
            if runner.archive_buckets != {
                "cats-usage-archive-old-fixture",
                "cats-usage-archive-fresh-fixture",
            }:
                raise AssertionError("an immutable usage archive was retired")
            for path in [plan_path, dry_path, final_path]:
                raw = path.read_bytes()
                value = json.loads(raw)
                if raw != reset.canonical_bytes(value):
                    raise AssertionError(f"receipt is not canonical: {path.name}")
                if "fixture-secret" in raw.decode():
                    raise AssertionError(f"secret escaped into receipt: {path.name}")
                sidecar = path.with_suffix(".sha256").read_text()
                if reset.sha256_bytes(raw) not in sidecar:
                    raise AssertionError(f"receipt SHA sidecar mismatch: {path.name}")
            if reset.sha256_bytes(final_path.read_bytes()) != final_digest:
                raise AssertionError("final digest does not cover the canonical final receipt")
            for arguments, _environment in runner.calls:
                if (
                    "s3api" in arguments
                    and FakeRunner._arg(arguments, "--expected-bucket-owner")
                    != config.aws_account_id
                ):
                    raise AssertionError("a read/list/delete/abort S3 call lost expected owner")
            plan_value = json.loads(plan_path.read_text())
            evidence_digest = plan_value["cutover_authority_sha256"]
            for receipt_path in receipts.glob(f"{config.reset_id}.*.json"):
                receipt_value = json.loads(receipt_path.read_text())
                if receipt_value.get("cutover_authority_sha256") != evidence_digest:
                    raise AssertionError(
                        f"receipt lost the exact post-green digest: {receipt_path.name}"
                    )

            invalid = dataclasses.replace(config, control_schema="public")
            try:
                reset.validate_config(invalid)
            except reset.ResetError:
                pass
            else:
                raise AssertionError("public schema was accepted as a destructive target")

            overlap = dataclasses.replace(
                config,
                new_chunkstore_bucket=config.chunkstore_bucket,
                new_chunkstore_prefix="cats-old/fresh",
            )
            try:
                reset.validate_config(overlap)
            except reset.ResetError:
                pass
            else:
                raise AssertionError("overlapping old/fresh ChunkStore prefixes were accepted")

            for label, invalid_release in [
                ("release commit", dataclasses.replace(config, release_commit="a" * 64)),
                ("artifact digest", dataclasses.replace(config, artifact_sha256="a" * 40)),
            ]:
                try:
                    reset.validate_config(invalid_release)
                except reset.ResetError:
                    pass
                else:
                    raise AssertionError(f"invalid {label} identity was accepted")

            public_reset_id = "cutover-public-0001"
            public_evidence = root / "post-green-public.json"
            public_value = json.loads(evidence.read_text())
            public_value["reset_id"] = public_reset_id
            public_evidence.write_text(json.dumps(public_value) + "\n")
            public_runner = FakeRunner(
                config.aws_account_id, config.aws_region, config.eks_cluster_name
            )
            public_runner.ingress_closed = False
            try:
                fixture_executor(
                    dataclasses.replace(
                        config,
                        reset_id=public_reset_id,
                        legacy_fixture_post_green_evidence_file=public_evidence,
                    ),
                    public_runner,
                ).plan()
            except reset.ResetError as error:
                if "ingress is not explicitly Closed" not in str(error):
                    raise
            else:
                raise AssertionError("public fresh rollout passed reset preflight")
            if mutation_counts(public_runner) != (0, 0, 0, 0, ()):
                raise AssertionError("public-rollout preflight executed a physical effect")

            # A post-green failure must stop before any old target mutation.
            blocked_evidence = root / "post-green-blocked.json"
            blocked_value = json.loads(evidence.read_text())
            blocked_value["reset_id"] = "cutover-fixture-0002"
            blocked_value["qualification"] = "failed"
            blocked_evidence.write_text(json.dumps(blocked_value) + "\n")
            blocked_runner = FakeRunner(
                config.aws_account_id, config.aws_region, config.eks_cluster_name
            )
            blocked_executor = fixture_executor(
                dataclasses.replace(
                    config,
                    reset_id="cutover-fixture-0002",
                    legacy_fixture_post_green_evidence_file=blocked_evidence,
                ),
                blocked_runner,
                now=dt.datetime(2026, 8, 13, 0, 0, tzinfo=dt.timezone.utc),
            )
            try:
                blocked_executor.plan()
            except reset.ResetError as error:
                if "fixture cutover evidence binding drifted" not in str(error):
                    raise
            else:
                raise AssertionError("failed fresh qualification did not block retirement")
            if blocked_runner.delete_calls or blocked_runner.drop_calls:
                raise AssertionError("post-green-blocked plan mutated a target")

            for label, replacement in [
                ("missing", None),
                ("wrong", "999999999999"),
            ]:
                owner_reset_id = f"cutover-owner-{label}"
                owner_evidence = root / f"post-green-owner-{label}.json"
                owner_value = json.loads(evidence.read_text())
                owner_value["reset_id"] = owner_reset_id
                owner_evidence.write_text(json.dumps(owner_value) + "\n")
                owner_runner = SabotagedS3OwnerRunner(
                    config.aws_account_id,
                    config.aws_region,
                    config.eks_cluster_name,
                    replacement,
                )
                owner_executor = fixture_executor(
                    dataclasses.replace(
                        config,
                        reset_id=owner_reset_id,
                        legacy_fixture_post_green_evidence_file=owner_evidence,
                    ),
                    owner_runner,
                    now=dt.datetime(2026, 8, 13, 0, 0, tzinfo=dt.timezone.utc),
                )
                try:
                    owner_executor.plan()
                except reset.ResetError:
                    pass
                else:
                    raise AssertionError(f"{label} S3 expected owner did not fail closed")
                if owner_runner.delete_calls or owner_runner.abort_calls or owner_runner.drop_calls:
                    raise AssertionError(f"{label} S3 expected owner crossed mutation boundary")

            assert_forward_resume(root)
            assert_receipt_publication_recovery(root)
            assert_binding_failures(root)
            assert_unaccepted_proofs_block_execute(root)
            assert_cutover_authority_ordering_and_replay(root)

            print(
                "clean-slate fixture: paginated versions+markers, multipart abort, "
                "fresh namespace preserved, exact old retire, dry-run, receipts, "
                "post-green blocker passed, closed forward-resume, crash replay, binding failures, "
                "mechanical prerequisite blocks, recoverable receipt publication, and S3 "
                "expected-owner gates passed; fresh DB read-only and ingress Closed passed"
            )
            return 0
    except (AssertionError, OSError, reset.ResetError) as error:
        print(f"clean-slate reset fixture failed: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
