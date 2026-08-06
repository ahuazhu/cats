#!/usr/bin/env python3
"""Validate one Terraform saved plan against the G0 qualification contract."""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

from plan_contract import (
    Contract,
    ContractInputError,
    ProductionInventory,
    ValidationContext,
    load_json_object,
    validate_plan,
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Fail closed unless a saved Terraform plan is qualification-only."
    )
    parser.add_argument("--plan-json", required=True, type=Path)
    parser.add_argument("--contract", required=True, type=Path)
    parser.add_argument("--forbidden-inventory", required=True, type=Path)
    parser.add_argument("--expected-account-id", required=True)
    parser.add_argument("--bootstrap-principal-arn", required=True)
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if not re.fullmatch(r"[0-9]{12}", args.expected_account_id):
        print("error: --expected-account-id must be a 12-digit AWS account ID", file=sys.stderr)
        return 2

    expected_principal_prefix = f"arn:aws:iam::{args.expected_account_id}:"
    if not args.bootstrap_principal_arn.startswith(expected_principal_prefix):
        print(
            "error: bootstrap principal is not in the expected account",
            file=sys.stderr,
        )
        return 2

    try:
        plan = load_json_object(args.plan_json)
        contract = Contract.load(load_json_object(args.contract))
        inventory = ProductionInventory.load(
            load_json_object(args.forbidden_inventory)
        )
        result = validate_plan(
            plan,
            ValidationContext(
                account_id=args.expected_account_id,
                bootstrap_principal_arn=args.bootstrap_principal_arn,
                contract=contract,
                inventory=inventory,
            ),
        )
    except ContractInputError as error:
        print(f"error: {error}", file=sys.stderr)
        return 2

    if not result.accepted:
        for error in result.errors:
            print(f"reject: {error}", file=sys.stderr)
        return 1

    print(
        json.dumps(
            {
                "verdict": "accepted",
                "contract_mode": "bootstrap-create",
                "managed_create_count": result.managed_create_count,
                "manifest_sha256": result.manifest_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
