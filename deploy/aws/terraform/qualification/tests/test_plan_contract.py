from __future__ import annotations

import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path


QUALIFICATION_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(QUALIFICATION_DIR / "tools"))

from plan_contract import (  # noqa: E402
    Contract,
    ContractInputError,
    ForbiddenInventory,
    ValidationContext,
    load_json_object,
    validate_plan,
)


ACCOUNT_ID = "123456789012"
PRINCIPAL_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/qualification-bootstrap"


def managed_changes_digest(changes: list[dict[str, object]]) -> str:
    ordered = sorted(changes, key=lambda change: str(change["address"]))
    return hashlib.sha256(
        json.dumps(ordered, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def configuration_digest(root: dict[str, object]) -> str:
    return hashlib.sha256(
        json.dumps(root, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


EMPTY_DRIFT_SHA256 = hashlib.sha256(b"[]").hexdigest()
JQ_EMPTY_DRIFT_SHA256 = hashlib.sha256(b"[]\n").hexdigest()


class SavedPlanContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.contract = Contract.load(
            load_json_object(
                QUALIFICATION_DIR / "contracts" / "bootstrap-create-v1.json"
            )
        )
        cls.inventory = ForbiddenInventory.load(
            {
                "schema_version": 1,
                "observed_account_id": ACCOUNT_ID,
                "observed_region": "us-east-1",
                "identifiers": [
                    "cats-production",
                    "vpc-0deadbeef12345678",
                    f"arn:aws:rds:us-east-1:{ACCOUNT_ID}:db:cats-production",
                ],
            }
        )

    def setUp(self) -> None:
        fixture_context = ValidationContext(
            template_values={
                "account_id": ACCOUNT_ID,
                "bootstrap_principal_arn": PRINCIPAL_ARN,
            },
            contract=self.contract,
            inventory=self.inventory,
        )
        self.plan = make_valid_plan(fixture_context)
        fixture_contract = replace(
            self.contract,
            expected_managed_changes_sha256=managed_changes_digest(
                self.plan["resource_changes"]
            ),
        )
        self.context = ValidationContext(
            template_values=fixture_context.template_values,
            contract=fixture_contract,
            inventory=self.inventory,
        )

    def assert_rejected(self, expected_fragment: str) -> None:
        result = validate_plan(self.plan, self.context)
        self.assertFalse(result.accepted)
        self.assertTrue(
            any(expected_fragment in error for error in result.errors),
            f"missing {expected_fragment!r} in {result.errors!r}",
        )

    def test_accepts_exact_new_qualification_bootstrap(self) -> None:
        result = validate_plan(self.plan, self.context)
        self.assertTrue(result.accepted, result.errors)
        self.assertEqual(
            result.managed_create_count,
            len(self.contract.required_create_addresses),
        )
        self.assertEqual(len(result.manifest_sha256 or ""), 64)

    def test_create_contract_requires_full_managed_change_digest(self) -> None:
        raw = load_json_object(
            QUALIFICATION_DIR / "contracts" / "bootstrap-create-v1.json"
        )
        raw.pop("expected_managed_changes_sha256")
        with self.assertRaisesRegex(
            ContractInputError,
            "requires expected_managed_changes_sha256",
        ):
            Contract.load(raw)

    def test_configuration_references_require_full_configuration_digest(self) -> None:
        raw = load_json_object(
            QUALIFICATION_DIR / "contracts" / "h2-build-host-create-v1.json"
        )
        raw.pop("expected_configuration_root_sha256")
        with self.assertRaisesRegex(
            ContractInputError,
            "requires expected_configuration_root_sha256",
        ):
            Contract.load(raw)

        raw = load_json_object(
            QUALIFICATION_DIR / "contracts" / "bootstrap-create-v1.json"
        )
        raw.pop("required_known_change_paths")
        with self.assertRaisesRegex(
            ContractInputError,
            "requires required_known_change_paths",
        ):
            Contract.load(raw)

    def test_create_contract_rejects_iam_policy_wildcard_expansion(self) -> None:
        expanded = copy.deepcopy(self.plan)
        find_change(expanded, "aws_iam_role_policy.state")["change"]["after"][
            "policy"
        ] = json.dumps({"Action": "*", "Resource": "*"})
        result = validate_plan(expanded, self.context)
        self.assertFalse(result.accepted)
        self.assertTrue(
            any("exact reviewed transition" in error for error in result.errors),
            result.errors,
        )

    def test_rejects_wrong_account(self) -> None:
        self.plan["variables"]["expected_account_id"]["value"] = "999999999999"
        self.assert_rejected("expected_account_id")

    def test_rejects_wrong_region(self) -> None:
        self.plan["variables"]["aws_region"]["value"] = "us-west-2"
        self.assert_rejected("aws_region")

    def test_rejects_wrong_namespace(self) -> None:
        self.plan["variables"]["qualification_namespace"]["value"] = (
            "cats-production"
        )
        self.assert_rejected("qualification_namespace")

    def test_rejects_manifest_that_marks_cell_as_production(self) -> None:
        manifest = self.plan["planned_values"]["outputs"][
            "qualification_manifest_seed"
        ]["value"]
        manifest["environment_is_production"] = True
        self.assert_rejected("manifest_seed")

    def test_rejects_production_named_create(self) -> None:
        change = find_change(self.plan, "aws_s3_bucket.state")
        change["change"]["after"]["bucket"] = "cats-production-state"
        self.assert_rejected("existing production identifier")

    def test_rejects_production_update(self) -> None:
        change = find_change(self.plan, "aws_s3_bucket.state")
        change["change"] = {
            "actions": ["update"],
            "before": {
                "bucket": "cats-production-terraform-state",
                "id": "cats-production-terraform-state",
            },
            "after": change["change"]["after"],
        }
        self.assert_rejected("permits create only")

    def test_rejects_production_delete(self) -> None:
        change = find_change(self.plan, "aws_s3_bucket.state")
        change["change"] = {
            "actions": ["delete"],
            "before": {
                "bucket": "cats-production-terraform-state",
                "id": "cats-production-terraform-state",
            },
            "after": None,
        }
        self.assert_rejected("permits create only")

    def test_rejects_existing_aws_id_nested_in_policy(self) -> None:
        change = find_change(self.plan, "aws_s3_bucket_policy.state")
        change["change"]["after"]["policy"] = json.dumps(
            {"Resource": "vpc-0deadbeef12345678"}
        )
        self.assert_rejected("existing production identifier")

    def test_rejects_nonqualification_arn_even_if_inventory_missed_it(self) -> None:
        change = find_change(self.plan, "aws_iam_role_policy.state")
        change["change"]["after"]["policy"] = json.dumps(
            {
                "Resource": (
                    f"arn:aws:s3:::unlisted-sensitive-bucket-{ACCOUNT_ID}"
                )
            }
        )
        self.assert_rejected("ARN is outside the contract ownership boundary")

    def test_rejects_missing_identity_tag(self) -> None:
        change = find_change(self.plan, "aws_kms_key.state")
        del change["change"]["after"]["tags_all"]["QualificationCell"]
        self.assert_rejected("tag QualificationCell")

    def test_rejects_unapproved_resource_address(self) -> None:
        self.plan["resource_changes"].append(
            {
                "address": "aws_vpc.production_decoy",
                "mode": "managed",
                "type": "aws_vpc",
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": {
                        "tags_all": {
                            **self.contract.required_tags,
                            "Name": "cats-qualification-v2-vpc",
                        }
                    },
                },
            }
        )
        self.assert_rejected("outside the qualification bootstrap contract")

    def test_rejects_unapproved_data_source(self) -> None:
        self.plan["resource_changes"].append(
            {
                "address": "data.aws_vpc.production",
                "mode": "data",
                "type": "aws_vpc",
                "change": {
                    "actions": ["read"],
                    "before": None,
                    "after": {"id": "vpc-0deadbeef12345678"},
                },
            }
        )
        self.assert_rejected("unapproved data-source authority")

    def test_rejects_existing_id_in_an_allowed_data_source(self) -> None:
        self.plan["resource_changes"].append(
            {
                "address": "data.aws_iam_policy_document.state_access",
                "mode": "data",
                "change": {
                    "actions": ["read"],
                    "before": None,
                    "after": {"json": "vpc-0deadbeef12345678"},
                },
            }
        )
        self.assert_rejected("existing production identifier")

    def test_rejects_noop_managed_resource(self) -> None:
        self.plan["resource_changes"].append(
            {
                "address": "aws_vpc.production_decoy",
                "mode": "managed",
                "change": {
                    "actions": ["no-op"],
                    "before": {"id": "vpc-0deadbeef12345678"},
                    "after": {"id": "vpc-0deadbeef12345678"},
                },
            }
        )
        self.assert_rejected("outside the qualification bootstrap contract")

    def test_rejects_existing_managed_prior_state(self) -> None:
        self.plan["prior_state"]["values"]["root_module"]["resources"] = [
            {
                "address": "aws_vpc.production_decoy",
                "mode": "managed",
            }
        ]
        self.assert_rejected("prior state contains a managed resource")

    def test_rejects_failed_or_missing_checks(self) -> None:
        self.plan["checks"][0]["status"] = "fail"
        self.assert_rejected("saved-plan check did not pass")

    def test_rejects_inventory_from_another_account(self) -> None:
        context = ValidationContext(
            template_values={
                "account_id": ACCOUNT_ID,
                "bootstrap_principal_arn": PRINCIPAL_ARN,
            },
            contract=self.contract,
            inventory=ForbiddenInventory(
                observed_account_id="999999999999",
                observed_region="us-east-1",
                identifiers=("cats-production",),
            ),
        )
        result = validate_plan(self.plan, context)
        self.assertFalse(result.accepted)
        self.assertIn(
            "forbidden inventory account does not match the contract",
            result.errors,
        )

    def test_empty_inventory_cannot_issue_a_verdict(self) -> None:
        with self.assertRaisesRegex(ContractInputError, "at least one identifier"):
            ForbiddenInventory.load(
                {
                    "schema_version": 1,
                    "observed_account_id": ACCOUNT_ID,
                    "observed_region": "us-east-1",
                    "identifiers": [],
                }
            )


class ContractDrivenGateTests(unittest.TestCase):
    def test_maintenance_contract_requires_exact_actions_and_before_after_identity(self) -> None:
        raw = {
            "schema_version": 1,
            "mode": "maintenance",
            "contract_id": "example-maintenance-v1",
            "resource_label": "example host maintenance",
            "required_template_values": [],
            "required_variables": {"formation_mode": True},
            "manifest": {"output": "manifest", "expected": {"schema_version": 1}},
            "forbidden_inventory": {"account_id": ACCOUNT_ID, "region": "us-east-1"},
            "identity": {
                "allowed_external_arns": [],
                "owned_arn_globs": [],
                "approved_external_identifiers": [],
            },
            "required_tags": {"Environment": "qualification"},
            "required_check_addresses": ["check.boundary"],
            "allowed_data_addresses": [],
            "required_change_actions": {"aws_instance.build": ["delete", "create"]},
            "tagged_resource_addresses": ["aws_instance.build"],
            "required_identity_templates": {"aws_instance.build": {"instance_type": "c7i.12xlarge"}},
            "required_before_identity_templates": {"aws_instance.build": {"instance_type": "c7i.12xlarge"}},
            "required_absent_configuration_paths": {},
        }
        values = {
            "instance_type": "c7i.12xlarge",
            "tags_all": {"Environment": "qualification"},
        }
        replacement_change = {
            "address": "aws_instance.build",
            "mode": "managed",
            "change": {
                "actions": ["delete", "create"],
                "before": values,
                "after": values,
                "after_unknown": {},
            },
        }
        raw["expected_managed_changes_sha256"] = managed_changes_digest(
            [replacement_change]
        )
        raw["expected_resource_drift_sha256"] = EMPTY_DRIFT_SHA256
        typo = copy.deepcopy(raw)
        typo["required_identity_templates"] = {"aws_instance.typo": {"instance_type": "c7i.12xlarge"}}
        with self.assertRaisesRegex(ContractInputError, "unmanaged addresses"):
            Contract.load(typo)
        context = ValidationContext(
            template_values={},
            contract=Contract.load(raw),
            inventory=ForbiddenInventory(
                observed_account_id=ACCOUNT_ID,
                observed_region="us-east-1",
                identifiers=("cats-production",),
            ),
        )
        plan = {
            "errored": False,
            "applyable": True,
            "complete": True,
            "variables": {"formation_mode": {"value": True}},
            "planned_values": {
                "outputs": {"manifest": {"value": {"schema_version": 1}}},
                "root_module": {"resources": []},
            },
            "configuration": {"root_module": {"resources": []}},
            "resource_changes": [replacement_change],
            "resource_drift": [],
            "prior_state": {"values": {"root_module": {"resources": [{"address": "aws_instance.build", "mode": "managed"}]}}},
            "checks": [{"address": {"to_display": "check.boundary"}, "status": "pass", "instances": [{"status": "pass"}]}],
        }

        accepted = validate_plan(plan, context)
        self.assertTrue(accepted.accepted, accepted.errors)

        newline_digest = copy.deepcopy(raw)
        newline_digest["expected_resource_drift_sha256"] = JQ_EMPTY_DRIFT_SHA256
        rejected = validate_plan(
            plan,
            ValidationContext(
                template_values={},
                contract=Contract.load(newline_digest),
                inventory=context.inventory,
            ),
        )
        self.assertTrue(
            any("plan drift differs" in error for error in rejected.errors)
        )

        wrong_action = copy.deepcopy(plan)
        wrong_action["resource_changes"][0]["change"]["actions"] = ["update"]
        rejected = validate_plan(wrong_action, context)
        self.assertTrue(any("expected maintenance actions" in error for error in rejected.errors))

        wrong_before = copy.deepcopy(plan)
        wrong_before["resource_changes"][0]["change"]["before"]["instance_type"] = "m7i.12xlarge"
        rejected = validate_plan(wrong_before, context)
        self.assertTrue(any("expected qualification identity" in error for error in rejected.errors))

        self.assertTrue(validate_plan(plan, context).accepted)
        expanded = copy.deepcopy(plan)
        expanded["resource_changes"][0]["change"]["after"]["policy"] = json.dumps(
            {"Action": "*", "Resource": "*"}
        )
        rejected = validate_plan(expanded, context)
        self.assertTrue(
            any("exact reviewed transition" in error for error in rejected.errors)
        )

        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            plan_path = directory / "plan.json"
            contract_path = directory / "contract.json"
            inventory_path = directory / "inventory.json"
            plan_path.write_text(json.dumps(plan), encoding="utf-8")
            contract_path.write_text(json.dumps(raw), encoding="utf-8")
            inventory_path.write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "observed_account_id": ACCOUNT_ID,
                        "observed_region": "us-east-1",
                        "identifiers": ["cats-production"],
                    }
                ),
                encoding="utf-8",
            )
            command = subprocess.run(
                [
                    sys.executable,
                    str(QUALIFICATION_DIR / "tools" / "validate_saved_plan.py"),
                    "--plan-json",
                    str(plan_path),
                    "--contract",
                    str(contract_path),
                    "--forbidden-inventory",
                    str(inventory_path),
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            self.assertEqual(json.loads(command.stdout)["contract_mode"], "maintenance")

    def test_maintenance_contract_accepts_an_exact_pure_delete(self) -> None:
        raw = {
            "schema_version": 1,
            "mode": "maintenance",
            "contract_id": "example-delete-v1",
            "resource_label": "example residue cleanup",
            "required_template_values": [],
            "required_variables": {"formation_mode": True},
            "manifest": {"output": "manifest", "expected": {"schema_version": 1}},
            "forbidden_inventory": {
                "account_id": ACCOUNT_ID,
                "region": "us-east-1",
            },
            "identity": {
                "allowed_external_arns": [],
                "owned_arn_globs": [],
                "approved_external_identifiers": [],
            },
            "required_tags": {"Environment": "qualification"},
            "required_check_addresses": ["check.boundary"],
            "allowed_data_addresses": [],
            "required_change_actions": {"aws_instance.residue": ["delete"]},
            "tagged_resource_addresses": [],
            "required_identity_templates": {},
            "required_before_identity_templates": {
                "aws_instance.residue": {"instance_type": "c7i.12xlarge"}
            },
            "required_absent_configuration_paths": {},
        }
        delete_change = {
            "address": "aws_instance.residue",
            "mode": "managed",
            "change": {
                "actions": ["delete"],
                "before": {"instance_type": "c7i.12xlarge"},
                "after": None,
            },
        }
        raw["expected_managed_changes_sha256"] = managed_changes_digest(
            [delete_change]
        )
        raw["expected_resource_drift_sha256"] = EMPTY_DRIFT_SHA256
        context = ValidationContext(
            template_values={},
            contract=Contract.load(raw),
            inventory=ForbiddenInventory(
                observed_account_id=ACCOUNT_ID,
                observed_region="us-east-1",
                identifiers=("cats-production",),
            ),
        )
        plan = {
            "errored": False,
            "applyable": True,
            "complete": True,
            "variables": {"formation_mode": {"value": True}},
            "planned_values": {
                "outputs": {"manifest": {"value": {"schema_version": 1}}},
                "root_module": {"resources": []},
            },
            "configuration": {"root_module": {"resources": []}},
            "resource_changes": [delete_change],
            "resource_drift": [],
            "prior_state": {
                "values": {
                    "root_module": {
                        "resources": [
                            {"address": "aws_instance.residue", "mode": "managed"}
                        ]
                    }
                }
            },
            "checks": [
                {
                    "address": {"to_display": "check.boundary"},
                    "status": "pass",
                    "instances": [{"status": "pass"}],
                }
            ],
        }
        accepted = validate_plan(plan, context)
        self.assertTrue(accepted.accepted, accepted.errors)

        unexpected_after = copy.deepcopy(plan)
        unexpected_after["resource_changes"][0]["change"]["after"] = {
            "instance_type": "c7i.12xlarge"
        }
        rejected = validate_plan(unexpected_after, context)
        self.assertTrue(
            any("pure delete unexpectedly has a planned value" in error for error in rejected.errors)
        )

    def test_maintenance_contract_accepts_only_declared_owned_ids(self) -> None:
        raw = {
            "schema_version": 1,
            "mode": "maintenance",
            "contract_id": "example-owned-id-v1",
            "resource_label": "example maintenance",
            "required_template_values": [],
            "required_variables": {"formation_mode": True},
            "manifest": {"output": "manifest", "expected": {"schema_version": 1}},
            "forbidden_inventory": {
                "account_id": ACCOUNT_ID,
                "region": "us-east-1",
            },
            "identity": {
                "allowed_external_arns": [],
                "owned_arn_globs": [],
                "approved_external_identifiers": [],
                "owned_identifiers": ["vpc-0123456789abcdef0"],
            },
            "required_tags": {"Environment": "qualification"},
            "required_check_addresses": ["check.boundary"],
            "allowed_data_addresses": [],
            "required_change_actions": {"aws_vpc.build": ["no-op"]},
            "tagged_resource_addresses": [],
            "required_identity_templates": {
                "aws_vpc.build": {"id": "vpc-0123456789abcdef0"}
            },
            "required_before_identity_templates": {
                "aws_vpc.build": {"id": "vpc-0123456789abcdef0"}
            },
            "required_absent_configuration_paths": {},
        }
        values = {"id": "vpc-0123456789abcdef0"}
        no_op_change = {
            "address": "aws_vpc.build",
            "mode": "managed",
            "change": {
                "actions": ["no-op"],
                "before": values,
                "after": values,
                "after_unknown": {},
            },
        }
        raw["expected_managed_changes_sha256"] = managed_changes_digest(
            [no_op_change]
        )
        raw["expected_resource_drift_sha256"] = EMPTY_DRIFT_SHA256
        context = ValidationContext(
            template_values={},
            contract=Contract.load(raw),
            inventory=ForbiddenInventory(
                observed_account_id=ACCOUNT_ID,
                observed_region="us-east-1",
                identifiers=("cats-production",),
            ),
        )
        plan = {
            "errored": False,
            "applyable": True,
            "complete": True,
            "variables": {"formation_mode": {"value": True}},
            "planned_values": {
                "outputs": {"manifest": {"value": {"schema_version": 1}}},
                "root_module": {"resources": []},
            },
            "configuration": {"root_module": {"resources": []}},
            "resource_changes": [no_op_change],
            "resource_drift": [],
            "prior_state": {
                "values": {
                    "root_module": {
                        "resources": [{"address": "aws_vpc.build", "mode": "managed"}]
                    }
                }
            },
            "checks": [
                {
                    "address": {"to_display": "check.boundary"},
                    "status": "pass",
                    "instances": [{"status": "pass"}],
                }
            ],
        }
        self.assertTrue(validate_plan(plan, context).accepted)
        undeclared = copy.deepcopy(plan)
        undeclared["resource_changes"][0]["change"]["after"]["id"] = (
            "vpc-0fedcba9876543210"
        )
        rejected = validate_plan(undeclared, context)
        self.assertTrue(
            any("concrete existing AWS resource ID" in error for error in rejected.errors)
        )

    def test_a_second_stack_supplies_semantics_without_copying_the_gate(self) -> None:
        contract = Contract.load(
            {
                "schema_version": 1,
                "mode": "create-only",
                "contract_id": "example-build-create-v1",
                "resource_label": "example build host",
                "required_template_values": ["source_sha"],
                "required_variables": {"source_sha": "{source_sha}"},
                "manifest": {
                    "output": "build_manifest",
                    "expected": {
                        "schema_version": 1,
                        "source_sha": "{source_sha}",
                    },
                },
                "forbidden_inventory": {
                    "account_id": ACCOUNT_ID,
                    "region": "us-east-1",
                },
                "identity": {
                    "allowed_external_arns": [],
                    "owned_arn_globs": [
                        "arn:aws:s3:::cats-qualification-v2-*"
                    ],
                    "approved_external_identifiers": [
                        "ami-052355af2a014bd2c"
                    ],
                },
                "required_tags": {"Environment": "qualification"},
                "required_check_addresses": ["check.build_identity"],
                "allowed_data_addresses": [],
                "required_create_addresses": ["aws_instance.build_host"],
                "tagged_resource_addresses": ["aws_instance.build_host"],
                "required_identity_templates": {
                    "aws_instance.build_host": {
                        "ami": "ami-052355af2a014bd2c",
                        "associate_public_ip_address": False,
                        "instance_type": "c7i.12xlarge",
                        "metadata_options[0].http_tokens": "required",
                        "root_block_device[0].volume_size": 500,
                    }
                },
                "required_absent_configuration_paths": {
                    "aws_instance.build_host": ["key_name"],
                },
                "required_configuration_references": {
                    "aws_instance.build_host": {
                        "root_block_device[0].kms_key_id.references": [
                            "aws_kms_key.build_volume.arn",
                            "aws_kms_key.build_volume",
                        ]
                    }
                },
                "expected_configuration_root_sha256": "0" * 64,
                "required_known_change_paths": {
                    "aws_instance.build_host": ["user_data"]
                },
                "expected_managed_changes_sha256": "0" * 64,
            }
        )
        context = ValidationContext(
            template_values={"source_sha": "abc123"},
            contract=contract,
            inventory=ForbiddenInventory(
                observed_account_id=ACCOUNT_ID,
                observed_region="us-east-1",
                identifiers=("cats-production",),
            ),
        )
        plan = {
            "errored": False,
            "applyable": True,
            "complete": True,
            "variables": {"source_sha": {"value": "abc123"}},
            "planned_values": {
                "outputs": {
                    "build_manifest": {
                        "value": {"schema_version": 1, "source_sha": "abc123"}
                    }
                },
                "root_module": {"resources": []},
            },
            "configuration": {
                "root_module": {
                    "resources": [
                        {
                            "address": "aws_instance.build_host",
                            "expressions": {
                                "root_block_device": [
                                    {
                                        "kms_key_id": {
                                            "references": [
                                                "aws_kms_key.build_volume.arn",
                                                "aws_kms_key.build_volume",
                                            ]
                                        }
                                    }
                                ]
                            },
                        }
                    ]
                }
            },
            "resource_changes": [
                {
                    "address": "aws_instance.build_host",
                    "mode": "managed",
                    "change": {
                        "actions": ["create"],
                        "before": None,
                        "after": {
                            "ami": "ami-052355af2a014bd2c",
                            "associate_public_ip_address": False,
                            "instance_type": "c7i.12xlarge",
                            "metadata_options": [{"http_tokens": "required"}],
                            "root_block_device": [{"volume_size": 500}],
                            "user_data": "bootstrap-v1",
                            "tags_all": {"Environment": "qualification"},
                        },
                        "after_unknown": {
                            "metadata_options": [{}],
                            "root_block_device": [{}],
                        },
                    },
                }
            ],
            "resource_drift": [],
            "prior_state": {
                "values": {"root_module": {"resources": []}}
            },
            "checks": [
                {
                    "address": {"to_display": "check.build_identity"},
                    "status": "pass",
                    "instances": [{"status": "pass"}],
                }
            ],
        }
        contract = replace(
            contract,
            expected_configuration_root_sha256=configuration_digest(
                plan["configuration"]["root_module"]
            ),
            expected_managed_changes_sha256=managed_changes_digest(
                plan["resource_changes"]
            ),
        )
        context = ValidationContext(
            template_values={"source_sha": "abc123"},
            contract=contract,
            inventory=context.inventory,
        )

        result = validate_plan(plan, context)

        self.assertTrue(result.accepted, result.errors)
        self.assertEqual(result.managed_create_count, 1)

        wrong_key_reference = copy.deepcopy(plan)
        wrong_key_reference["configuration"]["root_module"]["resources"][0][
            "expressions"
        ]["root_block_device"][0]["kms_key_id"]["references"] = [
            "aws_kms_key.source.arn",
            "aws_kms_key.source",
        ]
        rejected = validate_plan(wrong_key_reference, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("configuration references differ" in error for error in rejected.errors),
            rejected.errors,
        )

        same_reference_semantic_inversion = copy.deepcopy(plan)
        same_reference_semantic_inversion["configuration"]["root_module"][
            "resources"
        ][0]["expressions"]["root_block_device"][0]["kms_key_id"][
            "function"
        ] = "wrong_key_transform"
        rejected = validate_plan(same_reference_semantic_inversion, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("configuration root differs" in error for error in rejected.errors),
            rejected.errors,
        )

        extra_key_reference = copy.deepcopy(plan)
        extra_key_reference["configuration"]["root_module"]["resources"][0][
            "expressions"
        ]["root_block_device"][0]["kms_key_id"]["references"].append(
            "aws_kms_key.source"
        )
        rejected = validate_plan(extra_key_reference, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("configuration references differ" in error for error in rejected.errors),
            rejected.errors,
        )

        missing_key_reference = copy.deepcopy(plan)
        del missing_key_reference["configuration"]["root_module"]["resources"][0][
            "expressions"
        ]["root_block_device"][0]["kms_key_id"]
        rejected = validate_plan(missing_key_reference, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("configuration references differ" in error for error in rejected.errors),
            rejected.errors,
        )

        changed_bootstrap = copy.deepcopy(plan)
        changed_bootstrap["resource_changes"][0]["change"]["after"][
            "user_data"
        ] = "bootstrap-v2"
        rejected = validate_plan(changed_bootstrap, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("exact reviewed transition" in error for error in rejected.errors),
            rejected.errors,
        )

        unknown_bootstrap = copy.deepcopy(plan)
        unknown_bootstrap["resource_changes"][0]["change"]["after_unknown"][
            "user_data"
        ] = True
        rejected = validate_plan(unknown_bootstrap, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("required reviewed change value remains unknown" in error for error in rejected.errors),
            rejected.errors,
        )

        null_bootstrap = copy.deepcopy(plan)
        null_bootstrap["resource_changes"][0]["change"]["after"]["user_data"] = None
        rejected = validate_plan(null_bootstrap, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("required reviewed change value is missing or null" in error for error in rejected.errors),
            rejected.errors,
        )

        near_miss = copy.deepcopy(plan)
        near_miss["resource_changes"][0]["change"]["after"]["ami"] = (
            "ami-052355af2a014bd2d"
        )
        rejected = validate_plan(near_miss, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("concrete existing AWS resource ID" in error for error in rejected.errors),
            rejected.errors,
        )

        middle_marker = copy.deepcopy(plan)
        middle_marker["resource_changes"][0]["change"]["after"]["policy"] = (
            f"arn:aws:secretsmanager:us-east-1:{ACCOUNT_ID}:"
            "secret:prod-secret/cats-qualification-v2-decoy"
        )
        rejected = validate_plan(middle_marker, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("outside the contract ownership boundary" in error for error in rejected.errors),
            rejected.errors,
        )

        public_ip = copy.deepcopy(plan)
        public_ip["resource_changes"][0]["change"]["after"][
            "associate_public_ip_address"
        ] = True
        rejected = validate_plan(public_ip, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("associate_public_ip_address" in error for error in rejected.errors),
            rejected.errors,
        )

        unknown_volume = copy.deepcopy(plan)
        unknown_volume["resource_changes"][0]["change"]["after_unknown"] = {
            "root_block_device": [{"volume_size": True}]
        }
        rejected = validate_plan(unknown_volume, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("volume_size" in error and "unknown" in error for error in rejected.errors),
            rejected.errors,
        )

        hidden_data = copy.deepcopy(plan)
        hidden_data["planned_values"]["root_module"]["resources"] = [
            {
                "address": "data.aws_secretsmanager_secret.production",
                "mode": "data",
                "values": {"name": "production-secret"},
            }
        ]
        rejected = validate_plan(hidden_data, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("unapproved planned data-source" in error for error in rejected.errors),
            rejected.errors,
        )

        ssh_key = copy.deepcopy(plan)
        ssh_key["configuration"]["root_module"]["resources"][0]["expressions"] = {
            "key_name": {"constant_value": "production-key"}
        }
        rejected = validate_plan(ssh_key, context)
        self.assertFalse(rejected.accepted)
        self.assertTrue(
            any("key_name" in error and "must be absent" in error for error in rejected.errors),
            rejected.errors,
        )
        with self.assertRaisesRegex(ContractInputError, "missing template values"):
            ValidationContext(
                template_values={},
                contract=contract,
                inventory=context.inventory,
            )


def make_valid_plan(context: ValidationContext) -> dict:
    tags = {
        **context.contract.required_tags,
        "Name": "cats-qualification-v2-resource",
        "Component": "terraform-state",
    }
    after_by_address = {
        "aws_iam_role.state": {
            "assume_role_policy": json.dumps({"Action": "sts:AssumeRole"}),
            "name": "cats-qualification-v2-terraform-state",
            "tags_all": copy.deepcopy(tags),
        },
        "aws_iam_role_policy.state": {
            "name": "cats-qualification-v2-terraform-state-access",
            "policy": json.dumps({"Action": "s3:GetObject"}),
        },
        "aws_kms_alias.state": {
            "name": "alias/cats-qualification-v2-terraform-state"
        },
        "aws_kms_key.state": {
            "policy": json.dumps({"Action": "kms:*"}),
            "tags_all": copy.deepcopy(tags),
        },
        "aws_s3_bucket.state": {
            "bucket": (
                f"cats-qualification-v2-tfstate-{ACCOUNT_ID}-us-east-1"
            ),
            "tags_all": copy.deepcopy(tags),
        },
        "aws_s3_bucket_policy.state": {
            "policy": json.dumps({"Action": "s3:*"})
        },
    }
    resource_changes = []
    for address in sorted(context.contract.required_create_addresses):
        resource_changes.append(
            {
                "address": address,
                "mode": "managed",
                "type": address.split(".", maxsplit=1)[0],
                "change": {
                    "actions": ["create"],
                    "before": None,
                    "after": copy.deepcopy(after_by_address.get(address, {})),
                },
            }
        )
    return {
        "format_version": "1.2",
        "terraform_version": "1.14.9",
        "errored": False,
        "applyable": True,
        "complete": True,
        "variables": {
            "expected_account_id": {"value": ACCOUNT_ID},
            "aws_region": {"value": "us-east-1"},
            "qualification_namespace": {"value": "cats-qualification-v2"},
            "qualification_cell_id": {"value": "qcell-use1-v1"},
            "bootstrap_principal_arn": {"value": PRINCIPAL_ARN},
        },
        "planned_values": {
            "outputs": {
                context.contract.manifest_output: {
                    "sensitive": False,
                    "value": copy.deepcopy(context.rendered_manifest),
                }
            },
            "root_module": {"resources": []},
        },
        "resource_changes": resource_changes,
        "resource_drift": [],
        "prior_state": {
            "values": {
                "root_module": {
                    "resources": [],
                }
            }
        },
        "checks": [
            {
                "address": {"to_display": address},
                "status": "pass",
                "instances": [{"status": "pass"}],
            }
            for address in sorted(context.contract.required_check_addresses)
        ],
    }


def find_change(plan: dict, address: str) -> dict:
    return next(
        change for change in plan["resource_changes"] if change["address"] == address
    )


if __name__ == "__main__":
    unittest.main()
