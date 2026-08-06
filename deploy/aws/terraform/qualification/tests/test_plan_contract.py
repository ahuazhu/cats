from __future__ import annotations

import copy
import json
import sys
import unittest
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
        self.context = ValidationContext(
            template_values={
                "account_id": ACCOUNT_ID,
                "bootstrap_principal_arn": PRINCIPAL_ARN,
            },
            contract=self.contract,
            inventory=self.inventory,
        )
        self.plan = make_valid_plan(self.context)

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
                        "instance_type": "c7i.12xlarge",
                    }
                },
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
                            "instance_type": "c7i.12xlarge",
                            "tags_all": {"Environment": "qualification"},
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

        result = validate_plan(plan, context)

        self.assertTrue(result.accepted, result.errors)
        self.assertEqual(result.managed_create_count, 1)

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
            "name": "cats-qualification-v2-terraform-state",
            "tags_all": copy.deepcopy(tags),
        },
        "aws_iam_role_policy.state": {
            "name": "cats-qualification-v2-terraform-state-access"
        },
        "aws_kms_alias.state": {
            "name": "alias/cats-qualification-v2-terraform-state"
        },
        "aws_kms_key.state": {"tags_all": copy.deepcopy(tags)},
        "aws_s3_bucket.state": {
            "bucket": (
                f"cats-qualification-v2-tfstate-{ACCOUNT_ID}-us-east-1"
            ),
            "tags_all": copy.deepcopy(tags),
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
            }
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
