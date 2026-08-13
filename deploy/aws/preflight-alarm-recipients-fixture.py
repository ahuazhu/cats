#!/usr/bin/env python3
"""Offline contract tests for preflight-alarm-recipients.py."""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).with_name("preflight-alarm-recipients.py")
FAKE_AWS = Path(__file__).with_name("tests") / "fake-alarm-recipient-aws.py"
SPEC = importlib.util.spec_from_file_location("alarm_recipient_preflight", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load alarm-recipient preflight")
preflight = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = preflight
SPEC.loader.exec_module(preflight)


ACCOUNT = "123456789012"
REGION = "us-east-1"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:cats-production-alerts"
SUBSCRIPTION = f"{TOPIC}:11111111-2222-3333-4444-555555555555"
USAGE_NAME = "cats-production-usage"
ALARM_NAMES = tuple(
    f"{USAGE_NAME}-{suffix}" for suffix, _metric in preflight.ALARM_METRICS
)


def alarm(name: str, metric: str) -> dict[str, Any]:
    return {
        "ActionsEnabled": True,
        "AlarmActions": [TOPIC],
        "AlarmArn": f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:{name}",
        "AlarmName": name,
        "Dimensions": [{"Name": "StreamName", "Value": USAGE_NAME}],
        "MetricName": metric,
        "Namespace": "AWS/Kinesis",
        "OKActions": [TOPIC],
        "StateValue": "OK",
    }


def responses() -> dict[tuple[str, str], dict[str, Any]]:
    return {
        ("sts", "get-caller-identity"): {
            "Account": ACCOUNT,
            "Arn": f"arn:aws:iam::{ACCOUNT}:role/offline-fixture",
            "UserId": "offline-fixture",
        },
        ("sns", "get-topic-attributes"): {
            "Attributes": {
                "Owner": ACCOUNT,
                "SubscriptionsConfirmed": "1",
                "SubscriptionsDeleted": "0",
                "SubscriptionsPending": "0",
                "TopicArn": TOPIC,
            }
        },
        ("sns", "list-subscriptions-by-topic"): {
            "Subscriptions": [
                {
                    "Endpoint": "operator@example.invalid",
                    "Owner": ACCOUNT,
                    "Protocol": "email",
                    "SubscriptionArn": SUBSCRIPTION,
                    "TopicArn": TOPIC,
                }
            ]
        },
        ("sns", "get-subscription-attributes"): {
            "Attributes": {
                "Endpoint": "operator@example.invalid",
                "Owner": ACCOUNT,
                "Protocol": "email",
                "SubscriptionArn": SUBSCRIPTION,
                "TopicArn": TOPIC,
            }
        },
        ("cloudwatch", "describe-alarms"): {
            "CompositeAlarms": [],
            "MetricAlarms": [
                alarm(name, metric)
                for name, (_suffix, metric) in zip(ALARM_NAMES, preflight.ALARM_METRICS)
            ],
        },
    }


class FakeRunner:
    def __init__(self, values: dict[tuple[str, str], dict[str, Any]]) -> None:
        self.values = values
        self.calls: list[tuple[str, str, str, tuple[str, ...], float]] = []

    def call(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
        deadline: float,
    ) -> dict[str, Any]:
        self.calls.append((region, service, operation, tuple(arguments), deadline))
        key = (service, operation)
        if key not in self.values:
            raise AssertionError(f"unexpected AWS read: {key}")
        return copy.deepcopy(self.values[key])


def run(values: dict[tuple[str, str], dict[str, Any]]) -> tuple[dict[str, Any], FakeRunner]:
    runner = FakeRunner(values)
    evidence = preflight.run_preflight(
        runner=runner,
        topic_arn=TOPIC,
        subscription_arn=SUBSCRIPTION,
        usage_resource_name=USAGE_NAME,
        deadline_seconds=30,
        now=datetime(2026, 8, 13, 1, 2, 3, tzinfo=timezone.utc),
    )
    return evidence, runner


def expect_failure(
    label: str,
    values: dict[tuple[str, str], dict[str, Any]],
    expected_fragment: str,
) -> None:
    try:
        run(values)
    except preflight.PreflightError as error:
        if expected_fragment not in str(error):
            raise AssertionError(
                f"{label}: expected {expected_fragment!r}, got {str(error)!r}"
            ) from error
    else:
        raise AssertionError(f"{label}: unsafe fixture passed")


def main() -> int:
    evidence, runner = run(responses())
    if evidence != {
        "account_id": ACCOUNT,
        "alarm_names": list(ALARM_NAMES),
        "checked_at": "2026-08-13T01:02:03Z",
        "kind": "cats-alarm-recipient-preflight",
        "region": REGION,
        "status": "passed",
        "subscription_arn": SUBSCRIPTION,
        "topic_arn": TOPIC,
        "usage_resource_name": USAGE_NAME,
        "version": 1,
    }:
        raise AssertionError(f"unexpected positive evidence: {evidence!r}")
    encoded = json.dumps(evidence, sort_keys=True)
    if "operator@example.invalid" in encoded:
        raise AssertionError("recipient address leaked into preflight evidence")

    expected_calls = [
        ("sts", "get-caller-identity", ()),
        ("sns", "get-topic-attributes", ("--topic-arn", TOPIC)),
        (
            "sns",
            "list-subscriptions-by-topic",
            ("--topic-arn", TOPIC, "--max-items", "100"),
        ),
        (
            "sns",
            "get-subscription-attributes",
            ("--subscription-arn", SUBSCRIPTION),
        ),
        ("cloudwatch", "describe-alarms", ("--alarm-names", *ALARM_NAMES)),
    ]
    observed_calls = [(service, operation, arguments) for _, service, operation, arguments, _ in runner.calls]
    if observed_calls != expected_calls:
        raise AssertionError(f"unexpected AWS operation sequence: {observed_calls!r}")
    if any(region != REGION for region, *_rest in runner.calls):
        raise AssertionError("an AWS read escaped the topic's exact region")
    deadlines = {deadline for *_rest, deadline in runner.calls}
    if len(deadlines) != 1:
        raise AssertionError("AWS reads did not share one absolute deadline")

    command = preflight.AwsCliRunner("aws-fixture").command(
        region=REGION,
        service="sns",
        operation="get-topic-attributes",
        arguments=("--topic-arn", TOPIC),
    )
    if command[-4:] != ["sns", "get-topic-attributes", "--topic-arn", TOPIC]:
        # Keep the executable contract visible without ever invoking it.
        raise AssertionError(f"unexpected AWS CLI command: {command!r}")
    if "--output" not in command or "json" not in command or "--no-cli-pager" not in command:
        raise AssertionError("AWS CLI command lost bounded JSON/no-pager options")

    for status in sorted(preflight.STATUS_ONLY_SUBSCRIPTIONS):
        values = responses()
        values[("sns", "list-subscriptions-by-topic")]["Subscriptions"][0][
            "SubscriptionArn"
        ] = status
        expect_failure(status, values, status)

    values = responses()
    values[("sns", "get-subscription-attributes")]["Attributes"][
        "PendingConfirmation"
    ] = "true"
    expect_failure("pending attributes", values, "pending confirmation")

    values = responses()
    values[("sns", "get-topic-attributes")]["Attributes"][
        "SubscriptionsConfirmed"
    ] = "0"
    expect_failure("no confirmed subscription", values, "no confirmed subscription")

    values = responses()
    values[("sns", "list-subscriptions-by-topic")]["NextToken"] = "more"
    expect_failure("partial subscription page", values, "incomplete paginated response")

    values = responses()
    values[("sns", "list-subscriptions-by-topic")]["Subscriptions"][0][
        "TopicArn"
    ] = f"arn:aws:sns:{REGION}:{ACCOUNT}:another-topic"
    expect_failure("cross-topic subscription", values, "cross-topic")

    values = responses()
    values[("cloudwatch", "describe-alarms")]["MetricAlarms"][0][
        "ActionsEnabled"
    ] = False
    expect_failure("disabled alarm", values, "ActionsEnabled=false")

    values = responses()
    values[("cloudwatch", "describe-alarms")]["MetricAlarms"][1][
        "AlarmActions"
    ] = []
    expect_failure("missing alarm action", values, "does not include the exact topic")

    values = responses()
    values[("cloudwatch", "describe-alarms")]["MetricAlarms"].pop()
    expect_failure("missing alarm", values, "exactly the three usage alarms")

    values = responses()
    values[("cloudwatch", "describe-alarms")]["MetricAlarms"].append(
        copy.deepcopy(values[("cloudwatch", "describe-alarms")]["MetricAlarms"][0])
    )
    expect_failure("duplicate alarm", values, "duplicate alarm")

    values = responses()
    values[("sts", "get-caller-identity")]["Account"] = "999999999999"
    expect_failure("wrong account", values, "caller account does not match")

    if preflight.decode_aws_json('{"ok":true}', "positive") != {"ok": True}:
        raise AssertionError("known-positive JSON parser control failed")
    for malformed in ("", "[]", "not json"):
        try:
            preflight.decode_aws_json(malformed, "malformed fixture")
        except preflight.PreflightError:
            pass
        else:
            raise AssertionError(f"malformed AWS JSON passed: {malformed!r}")

    for status in sorted(preflight.STATUS_ONLY_SUBSCRIPTIONS):
        try:
            preflight.run_preflight(
                runner=FakeRunner(responses()),
                topic_arn=TOPIC,
                subscription_arn=status,
                usage_resource_name=USAGE_NAME,
                deadline_seconds=30,
            )
        except preflight.PreflightError as error:
            if status not in str(error):
                raise
        else:
            raise AssertionError(f"status-only subscription {status} passed input validation")

    environment = dict(os.environ)
    environment.pop("CATS_ALARM_PREFLIGHT_FAKE_MODE", None)
    command = [
        sys.executable,
        str(SCRIPT),
        "--aws-cli",
        str(FAKE_AWS),
        "--topic-arn",
        TOPIC,
        "--subscription-arn",
        SUBSCRIPTION,
        "--usage-resource-name",
        USAGE_NAME,
    ]
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
        env=environment,
    )
    if completed.returncode != 0:
        raise AssertionError(f"offline AWS CLI positive failed: {completed.stderr!r}")
    cli_evidence = json.loads(completed.stdout)
    if cli_evidence.get("status") != "passed" or cli_evidence.get("alarm_names") != list(
        ALARM_NAMES
    ):
        raise AssertionError(f"offline AWS CLI evidence is wrong: {cli_evidence!r}")
    if "operator@example.invalid" in completed.stdout + completed.stderr:
        raise AssertionError("offline AWS CLI positive leaked the subscription endpoint")

    for mode, expected_error in (
        ("empty", "returned an empty response"),
        ("error", "failed with exit status 42"),
    ):
        negative_environment = dict(environment)
        negative_environment["CATS_ALARM_PREFLIGHT_FAKE_MODE"] = mode
        completed = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=10,
            env=negative_environment,
        )
        if completed.returncode == 0 or expected_error not in completed.stderr:
            raise AssertionError(
                f"offline AWS CLI {mode} was not rejected cleanly: {completed!r}"
            )
        if "operator@example.invalid" in completed.stdout + completed.stderr:
            raise AssertionError(f"offline AWS CLI {mode} leaked provider stderr")
        if "Traceback" in completed.stderr:
            raise AssertionError(f"offline AWS CLI {mode} exposed a traceback")

    print("alarm recipient preflight fixture: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
