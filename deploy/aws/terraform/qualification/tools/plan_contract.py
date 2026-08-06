"""Pure validation model for a qualification Terraform saved plan."""

from __future__ import annotations

import hashlib
import json
import re
from fnmatch import fnmatchcase
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping


AWS_RESOURCE_ID = re.compile(
    r"(?<![A-Za-z0-9])(?:ami|acl|eipalloc|eni|fs|i|igw|nat|rtb|sg|snap|subnet|vol|vpc|vpce)-[0-9a-f]{8,}(?![A-Za-z0-9])"
)
AWS_ARN = re.compile(r"arn:[A-Za-z0-9-]+:[A-Za-z0-9-]*:[^\s\"']*")


class ContractInputError(ValueError):
    """The validator input is malformed, so no verdict can be issued."""


@dataclass(frozen=True)
class Contract:
    contract_id: str
    resource_label: str
    required_template_values: frozenset[str]
    required_variables: Mapping[str, Any]
    manifest_output: str
    expected_manifest: Mapping[str, Any]
    inventory_account_id: str
    inventory_region: str
    allowed_external_arns: tuple[str, ...]
    owned_arn_globs: tuple[str, ...]
    approved_external_identifiers: tuple[str, ...]
    required_tags: Mapping[str, str]
    required_check_addresses: frozenset[str]
    allowed_data_addresses: frozenset[str]
    required_create_addresses: frozenset[str]
    tagged_resource_addresses: frozenset[str]
    required_identity_templates: Mapping[str, Mapping[str, str]]

    @classmethod
    def load(cls, raw: Mapping[str, Any]) -> "Contract":
        if raw.get("schema_version") != 1:
            raise ContractInputError("contract schema_version must be 1")
        if raw.get("mode") != "create-only":
            raise ContractInputError("only create-only mode is supported")
        manifest = _required_object(raw, "manifest")
        inventory = _required_object(raw, "forbidden_inventory")
        identity = _required_object(raw, "identity")
        return cls(
            contract_id=_required_string(raw, "contract_id"),
            resource_label=_required_string(raw, "resource_label"),
            required_template_values=frozenset(
                _string_list(raw, "required_template_values")
            ),
            required_variables=_required_object(raw, "required_variables"),
            manifest_output=_required_string(manifest, "output"),
            expected_manifest=_required_object(manifest, "expected"),
            inventory_account_id=_required_string(inventory, "account_id"),
            inventory_region=_required_string(inventory, "region"),
            allowed_external_arns=tuple(
                _string_list(identity, "allowed_external_arns")
            ),
            owned_arn_globs=tuple(_string_list(identity, "owned_arn_globs")),
            approved_external_identifiers=tuple(
                _string_list(identity, "approved_external_identifiers")
            ),
            required_tags=_string_map(raw, "required_tags"),
            required_check_addresses=frozenset(
                _string_list(raw, "required_check_addresses")
            ),
            allowed_data_addresses=frozenset(
                _string_list(raw, "allowed_data_addresses")
            ),
            required_create_addresses=frozenset(
                _string_list(raw, "required_create_addresses")
            ),
            tagged_resource_addresses=frozenset(
                _string_list(raw, "tagged_resource_addresses")
            ),
            required_identity_templates=_nested_string_map(
                raw, "required_identity_templates"
            ),
        )


@dataclass(frozen=True)
class ForbiddenInventory:
    observed_account_id: str
    observed_region: str
    identifiers: tuple[str, ...]

    @classmethod
    def load(cls, raw: Mapping[str, Any]) -> "ForbiddenInventory":
        if raw.get("schema_version") != 1:
            raise ContractInputError("inventory schema_version must be 1")
        identifiers = tuple(_string_list(raw, "identifiers"))
        if not identifiers:
            raise ContractInputError(
                "forbidden inventory must contain at least one identifier"
            )
        return cls(
            observed_account_id=_required_string(raw, "observed_account_id"),
            observed_region=_required_string(raw, "observed_region"),
            identifiers=identifiers,
        )


@dataclass(frozen=True)
class ValidationContext:
    template_values: Mapping[str, str]
    contract: Contract
    inventory: ForbiddenInventory

    def __post_init__(self) -> None:
        missing = self.contract.required_template_values - self.template_values.keys()
        extra = self.template_values.keys() - self.contract.required_template_values
        if missing:
            raise ContractInputError(
                f"missing template values: {', '.join(sorted(missing))}"
            )
        if extra:
            raise ContractInputError(
                f"undeclared template values: {', '.join(sorted(extra))}"
            )
        for arn in self.rendered_external_arns:
            if any(token in arn for token in "*?[") or AWS_ARN.fullmatch(arn) is None:
                raise ContractInputError(
                    f"allowed external ARN must be exact and valid: {arn!r}"
                )
        for pattern in self.rendered_owned_arn_globs:
            if not pattern.startswith("arn:"):
                raise ContractInputError(
                    f"owned ARN glob must be anchored at arn:: {pattern!r}"
                )
        for identifier in self.rendered_external_identifiers:
            if AWS_RESOURCE_ID.fullmatch(identifier) is None:
                raise ContractInputError(
                    f"approved external identifier must be one exact AWS ID: {identifier!r}"
                )

    def render(self, value: Any) -> Any:
        return _render_value(value, self.template_values)

    @property
    def rendered_manifest(self) -> Mapping[str, Any]:
        rendered = self.render(self.contract.expected_manifest)
        if not isinstance(rendered, dict):
            raise ContractInputError("rendered manifest must be an object")
        return rendered

    @property
    def rendered_external_arns(self) -> frozenset[str]:
        return frozenset(self.render(value) for value in self.contract.allowed_external_arns)

    @property
    def rendered_owned_arn_globs(self) -> tuple[str, ...]:
        return tuple(self.render(value) for value in self.contract.owned_arn_globs)

    @property
    def rendered_external_identifiers(self) -> frozenset[str]:
        return frozenset(
            self.render(value)
            for value in self.contract.approved_external_identifiers
        )


@dataclass(frozen=True)
class ValidationResult:
    errors: tuple[str, ...]
    manifest_sha256: str | None
    managed_create_count: int

    @property
    def accepted(self) -> bool:
        return not self.errors


def load_json_object(path: Path) -> Mapping[str, Any]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ContractInputError(f"cannot read JSON object {path}: {error}") from error
    if not isinstance(raw, dict):
        raise ContractInputError(f"{path} must contain a JSON object")
    return raw


def validate_plan(
    plan: Mapping[str, Any], context: ValidationContext
) -> ValidationResult:
    errors: list[str] = []
    _validate_observation(context, errors)
    _validate_plan_identity(plan, context, errors)
    _validate_plan_status(plan, context, errors)
    _validate_empty_managed_state(plan, errors)
    manifest = _validate_manifest(plan, context, errors)
    create_count = _validate_changes(plan, context, errors)

    digest = None
    if manifest is not None:
        digest = hashlib.sha256(_canonical_json(manifest)).hexdigest()
    return ValidationResult(tuple(errors), digest, create_count)


def _validate_observation(context: ValidationContext, errors: list[str]) -> None:
    inventory = context.inventory
    expected_account_id = context.render(context.contract.inventory_account_id)
    expected_region = context.render(context.contract.inventory_region)
    if inventory.observed_account_id != expected_account_id:
        errors.append(
            "forbidden inventory account does not match the contract"
        )
    if inventory.observed_region != expected_region:
        errors.append(
            "forbidden inventory region does not match the contract"
        )
    if expected_account_id in inventory.identifiers:
        errors.append(
            "forbidden inventory must list resource identifiers, not its bare account ID"
        )


def _validate_plan_identity(
    plan: Mapping[str, Any], context: ValidationContext, errors: list[str]
) -> None:
    variables = plan.get("variables")
    if not isinstance(variables, dict):
        errors.append("plan has no variables object")
        return

    expected = context.render(context.contract.required_variables)
    if not isinstance(expected, dict):
        raise ContractInputError("rendered required_variables must be an object")
    for key, wanted in expected.items():
        entry = variables.get(key)
        value = entry.get("value") if isinstance(entry, dict) else None
        if value != wanted:
            errors.append(f"plan variable {key} does not match the contract")

    if plan.get("errored") is True:
        errors.append("Terraform marked the saved plan as errored")
    drift = plan.get("resource_drift", [])
    if drift:
        errors.append(f"{context.contract.resource_label} plan contains resource drift")


def _validate_plan_status(
    plan: Mapping[str, Any], context: ValidationContext, errors: list[str]
) -> None:
    if plan.get("applyable") is not True:
        errors.append("saved plan is not applyable")
    if plan.get("complete") is not True:
        errors.append("saved plan is not complete")

    checks = plan.get("checks")
    if not isinstance(checks, list):
        errors.append("saved plan has no checks array")
        return
    seen: set[str] = set()
    for check in checks:
        address = check.get("address") if isinstance(check, dict) else None
        display = address.get("to_display") if isinstance(address, dict) else None
        status = check.get("status") if isinstance(check, dict) else None
        if not isinstance(display, str):
            errors.append("saved plan contains a check without an address")
            continue
        seen.add(display)
        if status != "pass":
            errors.append(f"{display}: saved-plan check did not pass")
        instances = check.get("instances")
        if not isinstance(instances, list) or not instances:
            errors.append(f"{display}: saved-plan check has no instances")
        elif any(
            not isinstance(instance, dict) or instance.get("status") != "pass"
            for instance in instances
        ):
            errors.append(f"{display}: a saved-plan check instance did not pass")

    missing = context.contract.required_check_addresses - seen
    for address in sorted(missing):
        errors.append(f"{address}: required saved-plan check is missing")


def _validate_empty_managed_state(
    plan: Mapping[str, Any], errors: list[str]
) -> None:
    prior = plan.get("prior_state")
    values = prior.get("values") if isinstance(prior, dict) else None
    root = values.get("root_module") if isinstance(values, dict) else None
    if not isinstance(root, dict):
        errors.append("saved plan has no inspectable prior state")
        return

    for module in _walk_modules(root):
        resources = module.get("resources", [])
        if not isinstance(resources, list):
            errors.append("saved plan prior state has malformed resources")
            continue
        for resource in resources:
            if not isinstance(resource, dict):
                errors.append("saved plan prior state has a malformed resource")
                continue
            if resource.get("mode", "managed") == "managed":
                address = resource.get("address", "<unknown>")
                errors.append(
                    f"{address}: create-only prior state contains a managed resource"
                )


def _validate_manifest(
    plan: Mapping[str, Any], context: ValidationContext, errors: list[str]
) -> Mapping[str, Any] | None:
    planned = plan.get("planned_values")
    outputs = planned.get("outputs") if isinstance(planned, dict) else None
    output_name = context.contract.manifest_output
    entry = outputs.get(output_name) if isinstance(outputs, dict) else None
    manifest = entry.get("value") if isinstance(entry, dict) else None
    if not isinstance(manifest, dict):
        errors.append(f"{output_name} is missing or unknown")
        return None
    if _canonical_json(manifest) != _canonical_json(context.rendered_manifest):
        errors.append(f"{output_name} does not match the exact contract")
    return manifest


def _validate_changes(
    plan: Mapping[str, Any], context: ValidationContext, errors: list[str]
) -> int:
    raw_changes = plan.get("resource_changes")
    if not isinstance(raw_changes, list):
        errors.append("plan has no resource_changes array")
        return 0

    seen_creates: set[str] = set()
    create_count = 0
    for raw in raw_changes:
        if not isinstance(raw, dict):
            errors.append("resource_changes contains a non-object entry")
            continue
        address = raw.get("address")
        if not isinstance(address, str):
            errors.append("resource change has no address")
            continue
        label = context.contract.resource_label
        mode = raw.get("mode", "managed")
        change = raw.get("change")
        actions = change.get("actions") if isinstance(change, dict) else None
        if not isinstance(actions, list) or not all(
            isinstance(action, str) for action in actions
        ):
            errors.append(f"{address}: change actions are missing")
            continue

        if mode == "data" or address.startswith("data."):
            if address not in context.contract.allowed_data_addresses:
                errors.append(f"{address}: unapproved data-source authority")
            if actions != ["read"]:
                errors.append(f"{address}: data source action must be read")
            if isinstance(change, dict) and isinstance(change.get("after"), dict):
                _scan_forbidden_values(
                    address, change["after"], context, errors
                )
            continue

        if address not in context.contract.required_create_addresses:
            errors.append(
                f"{address}: resource address is outside the {label} contract"
            )
        if actions != ["create"]:
            errors.append(
                f"{address}: {label} contract permits create only, got {actions}"
            )
        else:
            seen_creates.add(address)
            create_count += 1

        if isinstance(change, dict):
            before = change.get("before")
            after = change.get("after")
            if before is not None:
                errors.append(f"{address}: create plan unexpectedly has prior state")
            if not isinstance(after, dict):
                errors.append(f"{address}: planned value is missing or unknown")
                continue
            _scan_forbidden_values(address, after, context, errors)
            _validate_identity_templates(address, after, context, errors)
            _validate_tags(address, after, context, errors)

    missing = context.contract.required_create_addresses - seen_creates
    for address in sorted(missing):
        errors.append(
            f"{address}: required {context.contract.resource_label} create is missing"
        )
    return create_count


def _scan_forbidden_values(
    address: str,
    value: Any,
    context: ValidationContext,
    errors: list[str],
) -> None:
    for path, string in _walk_strings(value):
        for identifier in context.inventory.identifiers:
            if identifier in string:
                errors.append(
                    f"{address}.{path}: contains existing production identifier {identifier!r}"
                )
        for match in AWS_RESOURCE_ID.finditer(string):
            identifier = match.group(0)
            if identifier not in context.rendered_external_identifiers:
                errors.append(
                    f"{address}.{path}: contains concrete existing AWS resource ID {identifier!r}"
                )
        for arn in AWS_ARN.findall(string):
            if arn in context.rendered_external_arns:
                continue
            if not any(
                fnmatchcase(arn, pattern)
                for pattern in context.rendered_owned_arn_globs
            ):
                errors.append(
                    f"{address}.{path}: ARN is outside the contract ownership boundary: {arn!r}"
                )


def _validate_identity_templates(
    address: str,
    after: Mapping[str, Any],
    context: ValidationContext,
    errors: list[str],
) -> None:
    templates = context.contract.required_identity_templates.get(address, {})
    for path, template in templates.items():
        expected = context.render(template)
        actual = _lookup_path(after, path)
        if actual != expected:
            errors.append(
                f"{address}.{path}: expected qualification identity {expected!r}, got {actual!r}"
            )


def _validate_tags(
    address: str,
    after: Mapping[str, Any],
    context: ValidationContext,
    errors: list[str],
) -> None:
    if address not in context.contract.tagged_resource_addresses:
        return
    tags = after.get("tags_all", after.get("tags"))
    if not isinstance(tags, dict):
        errors.append(f"{address}: exact qualification tags are missing")
        return
    for key, expected in context.contract.required_tags.items():
        if tags.get(key) != expected:
            errors.append(f"{address}: tag {key} must equal {expected!r}")


def _walk_strings(value: Any, path: str = "after") -> Iterable[tuple[str, str]]:
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, child in value.items():
            yield from _walk_strings(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield from _walk_strings(child, f"{path}[{index}]")


def _walk_modules(module: Mapping[str, Any]) -> Iterable[Mapping[str, Any]]:
    yield module
    children = module.get("child_modules", [])
    if isinstance(children, list):
        for child in children:
            if isinstance(child, dict):
                yield from _walk_modules(child)


def _lookup_path(value: Mapping[str, Any], path: str) -> Any:
    current: Any = value
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current


def _canonical_json(value: Any) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


TEMPLATE_TOKEN = re.compile(r"\{([A-Za-z_][A-Za-z0-9_]*)\}")


def _render_value(value: Any, template_values: Mapping[str, str]) -> Any:
    if isinstance(value, str):
        def replace(match: re.Match[str]) -> str:
            name = match.group(1)
            if name not in template_values:
                raise ContractInputError(f"template references undeclared value {name!r}")
            return template_values[name]

        return TEMPLATE_TOKEN.sub(replace, value)
    if isinstance(value, dict):
        return {
            key: _render_value(child, template_values)
            for key, child in value.items()
        }
    if isinstance(value, list):
        return [_render_value(child, template_values) for child in value]
    return value


def _required_string(raw: Mapping[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value:
        raise ContractInputError(f"{key} must be a non-empty string")
    return value


def _required_object(raw: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    value = raw.get(key)
    if not isinstance(value, dict) or not value:
        raise ContractInputError(f"{key} must be a non-empty object")
    return value


def _string_list(raw: Mapping[str, Any], key: str) -> list[str]:
    value = raw.get(key)
    if not isinstance(value, list) or not all(
        isinstance(item, str) and item for item in value
    ):
        raise ContractInputError(f"{key} must be an array of non-empty strings")
    return value


def _string_map(raw: Mapping[str, Any], key: str) -> Mapping[str, str]:
    value = raw.get(key)
    if not isinstance(value, dict) or not value or not all(
        isinstance(item_key, str)
        and item_key
        and isinstance(item_value, str)
        and item_value
        for item_key, item_value in value.items()
    ):
        raise ContractInputError(f"{key} must be a non-empty string map")
    return value


def _nested_string_map(
    raw: Mapping[str, Any], key: str
) -> Mapping[str, Mapping[str, str]]:
    value = raw.get(key)
    if not isinstance(value, dict):
        raise ContractInputError(f"{key} must be an object")
    result: dict[str, Mapping[str, str]] = {}
    for nested_key, nested in value.items():
        if not isinstance(nested_key, str) or not nested_key or not isinstance(nested, dict):
            raise ContractInputError(f"{key} must map addresses to string maps")
        if not all(
            isinstance(item_key, str)
            and item_key
            and isinstance(item_value, str)
            and item_value
            for item_key, item_value in nested.items()
        ):
            raise ContractInputError(f"{key}.{nested_key} must be a string map")
        result[nested_key] = nested
    return result
