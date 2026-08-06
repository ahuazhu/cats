#!/usr/bin/env python3
"""Validate one Terraform saved plan against the G0 qualification contract."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from plan_contract import (
    Contract,
    ContractInputError,
    ForbiddenInventory,
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
    parser.add_argument(
        "--template-value",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="Provide one exact runtime value declared by the selected contract.",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        plan = load_json_object(args.plan_json)
        contract = Contract.load(load_json_object(args.contract))
        template_values = _parse_template_values(args.template_value)
        inventory = ForbiddenInventory.load(
            load_json_object(args.forbidden_inventory)
        )
        result = validate_plan(
            plan,
            ValidationContext(
                template_values=template_values,
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
                "contract_id": contract.contract_id,
                "contract_mode": contract.mode,
                "managed_create_count": result.managed_create_count,
                "manifest_sha256": result.manifest_sha256,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
    )
    return 0


def _parse_template_values(entries: list[str]) -> dict[str, str]:
    values: dict[str, str] = {}
    for entry in entries:
        name, separator, value = entry.partition("=")
        if not separator or not name or not value:
            raise ContractInputError(
                "--template-value must use a non-empty NAME=VALUE"
            )
        if name in values:
            raise ContractInputError(f"duplicate template value {name!r}")
        values[name] = value
    return values


if __name__ == "__main__":
    raise SystemExit(main())
