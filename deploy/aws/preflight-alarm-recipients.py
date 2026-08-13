#!/usr/bin/env python3
"""Fail-closed, read-only validation for the production usage alarm path."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Protocol, Sequence


MAX_AWS_JSON_BYTES = 1024 * 1024
STATUS_ONLY_SUBSCRIPTIONS = frozenset(
    {"Deleted", "PendingConfirmation", "deleted", "pending confirmation"}
)
ALARM_METRICS = (
    ("write-throttled", "WriteProvisionedThroughputExceeded"),
    ("read-throttled", "ReadProvisionedThroughputExceeded"),
    ("consumer-lag", "GetRecords.IteratorAgeMilliseconds"),
)
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
PARTITION_RE = re.compile(r"^[a-z0-9-]+$")
REGION_RE = re.compile(r"^[a-z0-9-]+$")
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")


class PreflightError(RuntimeError):
    """The live alarm path did not prove the required postcondition."""


@dataclass(frozen=True)
class TopicIdentity:
    arn: str
    partition: str
    region: str
    account_id: str
    name: str


class AwsJsonRunner(Protocol):
    def call(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
        deadline: float,
    ) -> dict[str, Any]: ...


def decode_aws_json(value: str, label: str) -> dict[str, Any]:
    if not value.strip():
        raise PreflightError(f"{label} returned an empty response")
    if len(value.encode("utf-8")) > MAX_AWS_JSON_BYTES:
        raise PreflightError(f"{label} response exceeded the bounded parser input")
    try:
        decoded = json.loads(value)
    except json.JSONDecodeError as error:
        raise PreflightError(f"{label} did not return valid JSON") from error
    if not isinstance(decoded, dict):
        raise PreflightError(f"{label} did not return a JSON object")
    return decoded


class AwsCliRunner:
    """Runs only the fixed read operations selected by ``run_preflight``."""

    def __init__(self, executable: str = "aws") -> None:
        if not executable or "\x00" in executable:
            raise PreflightError("AWS CLI executable must be non-empty")
        self.executable = executable

    def command(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
    ) -> list[str]:
        return [
            self.executable,
            "--region",
            region,
            "--output",
            "json",
            "--no-cli-pager",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "10",
            service,
            operation,
            *arguments,
        ]

    def call(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
        deadline: float,
    ) -> dict[str, Any]:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise PreflightError("alarm-recipient preflight exceeded its absolute deadline")
        command = self.command(
            region=region,
            service=service,
            operation=operation,
            arguments=arguments,
        )
        environment = dict(os.environ)
        environment["AWS_PAGER"] = ""
        environment["AWS_MAX_ATTEMPTS"] = "2"
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=remaining,
                env=environment,
            )
        except FileNotFoundError as error:
            raise PreflightError("AWS CLI executable was not found") from error
        except subprocess.TimeoutExpired as error:
            raise PreflightError(
                "alarm-recipient preflight exceeded its absolute deadline"
            ) from error
        if completed.returncode != 0:
            # AWS stderr can contain account inventory. The operator can rerun the
            # exact read directly when diagnosing; this verifier never echoes it.
            raise PreflightError(
                f"AWS {service} {operation} failed with exit status "
                f"{completed.returncode}"
            )
        try:
            stdout = completed.stdout.decode("utf-8", errors="strict")
        except UnicodeDecodeError as error:
            raise PreflightError(
                f"AWS {service} {operation} returned non-UTF-8 output"
            ) from error
        return decode_aws_json(stdout, f"AWS {service} {operation}")


def parse_topic_arn(value: str) -> TopicIdentity:
    if value != value.strip():
        raise PreflightError("topic ARN must not have surrounding whitespace")
    parts = value.split(":", 5)
    if len(parts) != 6 or parts[0] != "arn" or parts[2] != "sns":
        raise PreflightError("topic ARN must be an SNS topic ARN")
    partition, region, account_id, name = parts[1], parts[3], parts[4], parts[5]
    if (
        not PARTITION_RE.fullmatch(partition)
        or not REGION_RE.fullmatch(region)
        or not ACCOUNT_RE.fullmatch(account_id)
        or not 1 <= len(name) <= 256
        or not NAME_RE.fullmatch(name)
    ):
        raise PreflightError("topic ARN has an invalid partition, region, account, or name")
    return TopicIdentity(value, partition, region, account_id, name)


def validate_subscription_arn(value: str, topic: TopicIdentity) -> None:
    if value in STATUS_ONLY_SUBSCRIPTIONS:
        raise PreflightError(f"subscription is not confirmed: {value}")
    prefix = f"{topic.arn}:"
    if not value.startswith(prefix):
        raise PreflightError("subscription ARN is not bound to the exact alert topic")
    identifier = value[len(prefix) :]
    try:
        parsed = uuid.UUID(identifier)
    except ValueError as error:
        raise PreflightError("subscription ARN does not end in a UUID") from error
    if str(parsed) != identifier:
        raise PreflightError("subscription ARN UUID is not canonical lowercase text")


def validate_usage_resource_name(value: str) -> tuple[str, ...]:
    if value != value.strip() or not value or not NAME_RE.fullmatch(value):
        raise PreflightError(
            "usage resource name must contain only letters, digits, underscores, or hyphens"
        )
    names = tuple(f"{value}-{suffix}" for suffix, _metric in ALARM_METRICS)
    if any(len(name) > 255 for name in names):
        raise PreflightError("derived CloudWatch alarm name exceeds 255 characters")
    return names


def require_map(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PreflightError(f"{label} is not an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise PreflightError(f"{label} is not an array")
    return value


def require_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise PreflightError(f"{label} is not a non-empty string")
    return value


def require_complete_page(value: dict[str, Any], label: str) -> None:
    if value.get("NextToken") not in (None, ""):
        raise PreflightError(f"{label} returned an incomplete paginated response")


def validate_caller(payload: dict[str, Any], topic: TopicIdentity) -> None:
    account_id = require_string(payload.get("Account"), "caller Account")
    if account_id != topic.account_id:
        raise PreflightError(
            "AWS caller account does not match the account encoded in the alert topic"
        )


def validate_topic(payload: dict[str, Any], topic: TopicIdentity) -> None:
    attributes = require_map(payload.get("Attributes"), "topic Attributes")
    if attributes.get("TopicArn") != topic.arn:
        raise PreflightError("SNS returned a different topic ARN")
    if attributes.get("Owner") != topic.account_id:
        raise PreflightError("SNS topic owner does not match the exact topic account")
    confirmed = require_string(
        attributes.get("SubscriptionsConfirmed"), "SubscriptionsConfirmed"
    )
    if not confirmed.isdigit() or int(confirmed) < 1:
        raise PreflightError("alert topic has no confirmed subscription")


def validate_subscription_list(
    payload: dict[str, Any], topic: TopicIdentity, subscription_arn: str
) -> None:
    require_complete_page(payload, "SNS subscription list")
    subscriptions = require_list(payload.get("Subscriptions"), "Subscriptions")
    matches: list[dict[str, Any]] = []
    observed_statuses: set[str] = set()
    for index, raw in enumerate(subscriptions):
        subscription = require_map(raw, f"Subscriptions[{index}]")
        if subscription.get("TopicArn") != topic.arn:
            raise PreflightError("SNS topic listing contained a cross-topic subscription")
        listed_arn = require_string(
            subscription.get("SubscriptionArn"),
            f"Subscriptions[{index}].SubscriptionArn",
        )
        if listed_arn in STATUS_ONLY_SUBSCRIPTIONS:
            observed_statuses.add(listed_arn)
        elif listed_arn == subscription_arn:
            matches.append(subscription)
    if len(matches) != 1:
        if observed_statuses:
            statuses = ", ".join(sorted(observed_statuses))
            raise PreflightError(
                f"exact subscription is not confirmed; observed status: {statuses}"
            )
        raise PreflightError("exact confirmed subscription was not listed for the topic")
    match = matches[0]
    if match.get("Protocol") != "email":
        raise PreflightError("exact alert subscription is not an email subscription")
    if match.get("Owner") != topic.account_id:
        raise PreflightError("exact alert subscription has the wrong owner")
    # Presence is required, but the address itself is deliberately never copied
    # into the evidence document or an error message.
    require_string(match.get("Endpoint"), "exact subscription Endpoint")


def validate_subscription_attributes(
    payload: dict[str, Any], topic: TopicIdentity, subscription_arn: str
) -> None:
    attributes = require_map(payload.get("Attributes"), "subscription Attributes")
    if attributes.get("SubscriptionArn") != subscription_arn:
        raise PreflightError("SNS returned attributes for a different subscription")
    if attributes.get("TopicArn") != topic.arn:
        raise PreflightError("subscription attributes name a different topic")
    if attributes.get("Owner") != topic.account_id:
        raise PreflightError("subscription attributes name a different owner")
    if attributes.get("Protocol") != "email":
        raise PreflightError("subscription attributes do not describe an email subscription")
    require_string(attributes.get("Endpoint"), "subscription Endpoint")
    # A confirmed ARN plus a successful exact-ARN read is the portable proof.
    # AWS does not promise PendingConfirmation in this response, but reject it
    # if an implementation does expose an affirmative value.
    if attributes.get("PendingConfirmation") not in (None, "false"):
        raise PreflightError("exact subscription is still pending confirmation")


def validate_alarms(
    payload: dict[str, Any], topic: TopicIdentity, usage_resource_name: str
) -> tuple[str, ...]:
    require_complete_page(payload, "CloudWatch alarm read")
    composites = require_list(payload.get("CompositeAlarms"), "CompositeAlarms")
    if composites:
        raise PreflightError("usage alarm read unexpectedly returned composite alarms")
    log_alarms = payload.get("LogAlarms", [])
    if require_list(log_alarms, "LogAlarms"):
        raise PreflightError("usage alarm read unexpectedly returned log alarms")
    alarms = require_list(payload.get("MetricAlarms"), "MetricAlarms")
    by_name: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(alarms):
        alarm = require_map(raw, f"MetricAlarms[{index}]")
        name = require_string(alarm.get("AlarmName"), f"MetricAlarms[{index}].AlarmName")
        if name in by_name:
            raise PreflightError(f"CloudWatch returned duplicate alarm {name}")
        by_name[name] = alarm

    expected_names = validate_usage_resource_name(usage_resource_name)
    if set(by_name) != set(expected_names):
        raise PreflightError("CloudWatch did not return exactly the three usage alarms")

    for (_suffix, expected_metric), name in zip(ALARM_METRICS, expected_names):
        alarm = by_name[name]
        if alarm.get("ActionsEnabled") is not True:
            raise PreflightError(f"usage alarm {name} has ActionsEnabled=false")
        for field in ("AlarmActions", "OKActions"):
            actions = require_list(alarm.get(field), f"{name}.{field}")
            if any(not isinstance(action, str) for action in actions):
                raise PreflightError(f"{name}.{field} contains a non-string action")
            if topic.arn not in actions:
                raise PreflightError(f"usage alarm {name} does not include the exact topic in {field}")
        expected_arn = (
            f"arn:{topic.partition}:cloudwatch:{topic.region}:{topic.account_id}:alarm:{name}"
        )
        if alarm.get("AlarmArn") != expected_arn:
            raise PreflightError(f"usage alarm {name} has the wrong ARN/account/region")
        if alarm.get("Namespace") != "AWS/Kinesis":
            raise PreflightError(f"usage alarm {name} has the wrong metric namespace")
        if alarm.get("MetricName") != expected_metric:
            raise PreflightError(f"usage alarm {name} has the wrong metric")
        dimensions = require_list(alarm.get("Dimensions"), f"{name}.Dimensions")
        dimension_pairs: list[tuple[Any, Any]] = []
        for index, raw in enumerate(dimensions):
            dimension = require_map(raw, f"{name}.Dimensions[{index}]")
            dimension_pairs.append((dimension.get("Name"), dimension.get("Value")))
        if dimension_pairs != [("StreamName", usage_resource_name)]:
            raise PreflightError(f"usage alarm {name} does not bind the exact stream")
    return expected_names


def run_preflight(
    *,
    runner: AwsJsonRunner,
    topic_arn: str,
    subscription_arn: str,
    usage_resource_name: str,
    deadline_seconds: int,
    now: datetime | None = None,
) -> dict[str, Any]:
    if deadline_seconds < 1 or deadline_seconds > 300:
        raise PreflightError("deadline seconds must be between 1 and 300")
    topic = parse_topic_arn(topic_arn)
    validate_subscription_arn(subscription_arn, topic)
    alarm_names = validate_usage_resource_name(usage_resource_name)
    deadline = time.monotonic() + deadline_seconds

    def read(service: str, operation: str, *arguments: str) -> dict[str, Any]:
        return runner.call(
            region=topic.region,
            service=service,
            operation=operation,
            arguments=arguments,
            deadline=deadline,
        )

    validate_caller(read("sts", "get-caller-identity"), topic)
    validate_topic(
        read("sns", "get-topic-attributes", "--topic-arn", topic.arn), topic
    )
    validate_subscription_list(
        read(
            "sns",
            "list-subscriptions-by-topic",
            "--topic-arn",
            topic.arn,
            "--max-items",
            "100",
        ),
        topic,
        subscription_arn,
    )
    validate_subscription_attributes(
        read(
            "sns",
            "get-subscription-attributes",
            "--subscription-arn",
            subscription_arn,
        ),
        topic,
        subscription_arn,
    )
    validate_alarms(
        read("cloudwatch", "describe-alarms", "--alarm-names", *alarm_names),
        topic,
        usage_resource_name,
    )

    checked_at = now or datetime.now(timezone.utc)
    if checked_at.tzinfo is None:
        raise PreflightError("evidence timestamp must include a timezone")
    return {
        "account_id": topic.account_id,
        "alarm_names": list(alarm_names),
        "checked_at": checked_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
        "kind": "cats-alarm-recipient-preflight",
        "region": topic.region,
        "status": "passed",
        "subscription_arn": subscription_arn,
        "topic_arn": topic.arn,
        "usage_resource_name": usage_resource_name,
        "version": 1,
    }


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Read the exact SNS subscription and all three usage alarms; no AWS mutation "
            "operation is implemented by this command."
        )
    )
    parser.add_argument("--topic-arn", required=True)
    parser.add_argument("--subscription-arn", required=True)
    parser.add_argument(
        "--usage-resource-name",
        default="cats-production-usage",
        help="Terraform usage resource_name prefix; defaults to cats-production-usage.",
    )
    parser.add_argument("--deadline-seconds", type=int, default=30)
    parser.add_argument("--aws-cli", default="aws", help=argparse.SUPPRESS)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        evidence = run_preflight(
            runner=AwsCliRunner(options.aws_cli),
            topic_arn=options.topic_arn,
            subscription_arn=options.subscription_arn,
            usage_resource_name=options.usage_resource_name,
            deadline_seconds=options.deadline_seconds,
        )
    except PreflightError as error:
        print(f"alarm-recipient preflight failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(evidence, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
