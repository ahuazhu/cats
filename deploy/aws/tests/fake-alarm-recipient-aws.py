#!/usr/bin/env python3
"""Strict offline AWS CLI double for the E5 preflight fixture."""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Sequence


UUID = "11111111-2222-3333-4444-555555555555"
ALARM_METRICS = {
    "write-throttled": "WriteProvisionedThroughputExceeded",
    "read-throttled": "ReadProvisionedThroughputExceeded",
    "consumer-lag": "GetRecords.IteratorAgeMilliseconds",
}


def fail(message: str) -> int:
    print(message, file=sys.stderr)
    return 2


def option(arguments: Sequence[str], name: str) -> str:
    try:
        index = arguments.index(name)
        return arguments[index + 1]
    except (ValueError, IndexError) as error:
        raise ValueError(f"missing {name}") from error


def topic_parts(topic: str) -> tuple[str, str, str]:
    parts = topic.split(":", 5)
    if len(parts) != 6 or parts[2] != "sns":
        raise ValueError("invalid topic ARN")
    return parts[1], parts[3], parts[4]


def alarm(name: str, topic: str) -> dict[str, Any]:
    partition, region, account = topic_parts(topic)
    suffix = next((suffix for suffix in ALARM_METRICS if name.endswith(f"-{suffix}")), None)
    if suffix is None:
        raise ValueError("unexpected alarm name")
    stream = name[: -(len(suffix) + 1)]
    return {
        "ActionsEnabled": True,
        "AlarmActions": [topic],
        "AlarmArn": f"arn:{partition}:cloudwatch:{region}:{account}:alarm:{name}",
        "AlarmName": name,
        "Dimensions": [{"Name": "StreamName", "Value": stream}],
        "MetricName": ALARM_METRICS[suffix],
        "Namespace": "AWS/Kinesis",
        "OKActions": [topic],
        "StateValue": "OK",
    }


def response(arguments: Sequence[str]) -> dict[str, Any]:
    expected_prefix = [
        "--region",
        option(arguments, "--region"),
        "--output",
        "json",
        "--no-cli-pager",
        "--cli-connect-timeout",
        "5",
        "--cli-read-timeout",
        "10",
    ]
    if list(arguments[: len(expected_prefix)]) != expected_prefix:
        raise ValueError("unexpected global AWS CLI options")
    remaining = list(arguments[len(expected_prefix) :])
    if len(remaining) < 2:
        raise ValueError("missing AWS service/operation")
    service, operation, *operation_arguments = remaining
    region = option(arguments, "--region")

    if (service, operation) == ("sts", "get-caller-identity"):
        if operation_arguments:
            raise ValueError("unexpected STS arguments")
        return {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:role/offline-fixture",
            "UserId": "offline-fixture",
        }
    if (service, operation) == ("sns", "get-topic-attributes"):
        topic = option(operation_arguments, "--topic-arn")
        _partition, topic_region, account = topic_parts(topic)
        if topic_region != region:
            raise ValueError("region/topic mismatch")
        return {
            "Attributes": {
                "Owner": account,
                "SubscriptionsConfirmed": "1",
                "SubscriptionsDeleted": "0",
                "SubscriptionsPending": "0",
                "TopicArn": topic,
            }
        }
    if (service, operation) == ("sns", "list-subscriptions-by-topic"):
        topic = option(operation_arguments, "--topic-arn")
        _partition, topic_region, account = topic_parts(topic)
        if topic_region != region:
            raise ValueError("region/topic mismatch")
        return {
            "Subscriptions": [
                {
                    "Endpoint": "operator@example.invalid",
                    "Owner": account,
                    "Protocol": "email",
                    "SubscriptionArn": f"{topic}:{UUID}",
                    "TopicArn": topic,
                }
            ]
        }
    if (service, operation) == ("sns", "get-subscription-attributes"):
        subscription = option(operation_arguments, "--subscription-arn")
        topic, identifier = subscription.rsplit(":", 1)
        if identifier != UUID:
            raise ValueError("unexpected subscription identity")
        _partition, topic_region, account = topic_parts(topic)
        if topic_region != region:
            raise ValueError("region/topic mismatch")
        return {
            "Attributes": {
                "Endpoint": "operator@example.invalid",
                "Owner": account,
                "Protocol": "email",
                "SubscriptionArn": subscription,
                "TopicArn": topic,
            }
        }
    if (service, operation) == ("cloudwatch", "describe-alarms"):
        if not operation_arguments or operation_arguments[0] != "--alarm-names":
            raise ValueError("alarm names were not explicit")
        names = operation_arguments[1:]
        if len(names) != 3:
            raise ValueError("expected exactly three alarm names")
        # The fixture topic is fixed because DescribeAlarms carries only the
        # actions, not a separate topic argument.
        topic = f"arn:aws:sns:{region}:123456789012:cats-production-alerts"
        return {
            "CompositeAlarms": [],
            "MetricAlarms": [alarm(name, topic) for name in names],
        }
    raise ValueError(f"unexpected or mutating AWS operation: {service} {operation}")


def main() -> int:
    mode = os.environ.get("CATS_ALARM_PREFLIGHT_FAKE_MODE", "ok")
    if mode == "error":
        # The real verifier must never echo provider stderr, which can carry a
        # subscription endpoint or other inventory.
        print("fake provider error for operator@example.invalid", file=sys.stderr)
        return 42
    if mode == "empty":
        return 0
    if mode != "ok":
        return fail("invalid fake mode")
    try:
        payload = response(sys.argv[1:])
    except ValueError as error:
        return fail(str(error))
    print(json.dumps(payload, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
