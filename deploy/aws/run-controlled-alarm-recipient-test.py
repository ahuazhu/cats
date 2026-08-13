#!/usr/bin/env python3
"""Run one approval-gated, bounded CloudWatch alarm recipient test."""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Protocol, Sequence


MAX_AWS_JSON_BYTES = 1024 * 1024
ALARM_SUFFIX = "write-throttled"
ALARM_METRIC = "WriteProvisionedThroughputExceeded"
APPROVAL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")
ACCOUNT_RE = re.compile(r"^[0-9]{12}$")
PARTITION_RE = re.compile(r"^[a-z0-9-]+$")
REGION_RE = re.compile(r"^[a-z0-9-]+$")
AWS_PARTITIONS = frozenset(
    {"aws", "aws-cn", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f", "aws-us-gov"}
)


class ControlledTestError(RuntimeError):
    """The controlled test was refused or could not prove safe restoration."""


@dataclass(frozen=True)
class Target:
    topic_arn: str
    alarm_arn: str
    alarm_name: str
    usage_resource_name: str
    partition: str
    region: str
    account_id: str


class AwsRunner(Protocol):
    def call(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
        deadline: float,
        expect_json: bool = True,
    ) -> dict[str, Any] | None: ...


def canonical_bytes(value: Mapping[str, Any]) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        + "\n"
    ).encode("utf-8")


def checked_at(now: Callable[[], datetime]) -> str:
    value = now()
    if value.tzinfo is None:
        raise ControlledTestError("evidence clock must return a timezone-aware value")
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def decode_json(value: bytes, label: str) -> dict[str, Any]:
    if not value.strip():
        raise ControlledTestError(f"{label} returned an empty response")
    if len(value) > MAX_AWS_JSON_BYTES:
        raise ControlledTestError(f"{label} exceeded the bounded parser input")
    try:
        decoded = json.loads(value.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlledTestError(f"{label} did not return valid UTF-8 JSON") from error
    if not isinstance(decoded, dict):
        raise ControlledTestError(f"{label} did not return a JSON object")
    return decoded


class AwsCliRunner:
    def __init__(self, executable: str = "aws") -> None:
        if not executable or "\x00" in executable:
            raise ControlledTestError("AWS CLI executable must be non-empty")
        self.executable = executable

    def call(
        self,
        *,
        region: str,
        service: str,
        operation: str,
        arguments: Sequence[str],
        deadline: float,
        expect_json: bool = True,
    ) -> dict[str, Any] | None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ControlledTestError("controlled alarm test exceeded its absolute deadline")
        command = [
            self.executable,
            "--region",
            region,
            "--output",
            "json",
            "--no-cli-pager",
            "--no-paginate",
            "--cli-connect-timeout",
            "5",
            "--cli-read-timeout",
            "10",
            service,
            operation,
            *arguments,
        ]
        environment = dict(os.environ)
        for name in tuple(environment):
            if name.upper().startswith("AWS_ENDPOINT_URL"):
                del environment[name]
        environment["AWS_IGNORE_CONFIGURED_ENDPOINT_URLS"] = "true"
        environment["AWS_MAX_ATTEMPTS"] = "2"
        environment["AWS_PAGER"] = ""
        try:
            completed = subprocess.run(
                command,
                check=False,
                capture_output=True,
                timeout=remaining,
                env=environment,
            )
        except FileNotFoundError as error:
            raise ControlledTestError("AWS CLI executable was not found") from error
        except subprocess.TimeoutExpired as error:
            raise ControlledTestError(
                "controlled alarm test exceeded its absolute deadline"
            ) from error
        if completed.returncode != 0:
            raise ControlledTestError(
                f"AWS {service} {operation} failed with exit status {completed.returncode}"
            )
        if expect_json:
            return decode_json(completed.stdout, f"AWS {service} {operation}")
        if len(completed.stdout) > MAX_AWS_JSON_BYTES:
            raise ControlledTestError(
                f"AWS {service} {operation} exceeded the bounded output limit"
            )
        return None


def parse_target(topic_arn: str, alarm_arn: str, usage_resource_name: str) -> Target:
    if any(value != value.strip() for value in (topic_arn, alarm_arn, usage_resource_name)):
        raise ControlledTestError("target inputs must not have surrounding whitespace")
    if not usage_resource_name or not NAME_RE.fullmatch(usage_resource_name):
        raise ControlledTestError("usage resource name is malformed")
    alarm_name = f"{usage_resource_name}-{ALARM_SUFFIX}"
    if len(alarm_name) > 255:
        raise ControlledTestError("derived alarm name exceeds 255 characters")
    topic_parts = topic_arn.split(":", 5)
    if len(topic_parts) != 6 or topic_parts[0] != "arn" or topic_parts[2] != "sns":
        raise ControlledTestError("topic ARN must be an SNS topic ARN")
    partition, region, account_id, topic_name = (
        topic_parts[1],
        topic_parts[3],
        topic_parts[4],
        topic_parts[5],
    )
    if (
        not PARTITION_RE.fullmatch(partition)
        or partition not in AWS_PARTITIONS
        or not REGION_RE.fullmatch(region)
        or not ACCOUNT_RE.fullmatch(account_id)
        or not topic_name
        or not NAME_RE.fullmatch(topic_name)
    ):
        raise ControlledTestError("topic ARN identity is malformed")
    expected_alarm_arn = (
        f"arn:{partition}:cloudwatch:{region}:{account_id}:alarm:{alarm_name}"
    )
    if alarm_arn != expected_alarm_arn:
        raise ControlledTestError(
            "alarm ARN must be the exact write-throttled alarm in the topic "
            "partition/account/region"
        )
    return Target(
        topic_arn,
        alarm_arn,
        alarm_name,
        usage_resource_name,
        partition,
        region,
        account_id,
    )


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ControlledTestError(f"{label} must be an object")
    return value


def require_list(value: Any, label: str) -> list[Any]:
    if not isinstance(value, list):
        raise ControlledTestError(f"{label} must be an array")
    return value


def validate_caller(payload: dict[str, Any], target: Target) -> None:
    if payload.get("Account") != target.account_id:
        raise ControlledTestError("AWS caller account does not match the exact target")
    arn = payload.get("Arn")
    if not isinstance(arn, str):
        raise ControlledTestError("AWS caller ARN is missing")
    parts = arn.split(":", 5)
    if (
        len(parts) != 6
        or parts[0] != "arn"
        or parts[1] != target.partition
        or parts[4] != target.account_id
        or not parts[5]
    ):
        raise ControlledTestError(
            "AWS caller ARN partition/account does not match the exact target"
        )


def validate_alarm(
    payload: dict[str, Any], target: Target, expected_state: str
) -> dict[str, Any]:
    if payload.get("NextToken") not in (None, ""):
        raise ControlledTestError("CloudWatch alarm read was paginated")
    if require_list(payload.get("CompositeAlarms"), "CompositeAlarms"):
        raise ControlledTestError("CloudWatch returned a composite alarm")
    alarms = require_list(payload.get("MetricAlarms"), "MetricAlarms")
    if not alarms:
        raise ControlledTestError("CloudWatch did not return the exact metric alarm")
    if len(alarms) != 1:
        raise ControlledTestError("CloudWatch did not return exactly one metric alarm")
    alarm = require_dict(alarms[0], "MetricAlarms[0]")
    expected = {
        "ActionsEnabled": True,
        "AlarmActions": [target.topic_arn],
        "AlarmArn": target.alarm_arn,
        "AlarmName": target.alarm_name,
        "Dimensions": [{"Name": "StreamName", "Value": target.usage_resource_name}],
        "InsufficientDataActions": [],
        "MetricName": ALARM_METRIC,
        "Namespace": "AWS/Kinesis",
        "OKActions": [target.topic_arn],
        "StateValue": expected_state,
    }
    for field, value in expected.items():
        if alarm.get(field) != value:
            raise ControlledTestError(
                f"exact alarm precondition failed for {field}; expected {value!r}"
            )
    return expected


def history_entries(payload: dict[str, Any], target: Target) -> list[dict[str, Any]]:
    if payload.get("NextToken") not in (None, ""):
        raise ControlledTestError("CloudWatch alarm history was paginated")
    entries: list[dict[str, Any]] = []
    raw_items = require_list(payload.get("AlarmHistoryItems"), "AlarmHistoryItems")
    for index, raw in enumerate(raw_items):
        item = require_dict(raw, f"AlarmHistoryItems[{index}]")
        if (
            item.get("AlarmName") != target.alarm_name
            or item.get("HistoryItemType") != "StateUpdate"
        ):
            raise ControlledTestError(
                "alarm history contains an unexpected alarm or item type"
            )
        timestamp = item.get("Timestamp")
        summary = item.get("HistorySummary")
        history_data = item.get("HistoryData")
        if not all(
            isinstance(value, str) and value
            for value in (timestamp, summary, history_data)
        ):
            raise ControlledTestError("alarm history item is incomplete")
        try:
            parsed_data = json.loads(history_data)
        except json.JSONDecodeError as error:
            raise ControlledTestError("alarm HistoryData is not JSON") from error
        entries.append(
            {
                "history_data": require_dict(parsed_data, "HistoryData"),
                "history_item_type": "StateUpdate",
                "history_summary": summary,
                "timestamp": timestamp,
            }
        )
    return sorted(
        entries,
        key=lambda entry: (
            parse_aws_timestamp(entry["timestamp"]),
            json.dumps(entry["history_data"], sort_keys=True, separators=(",", ":")),
        ),
    )


def parse_aws_timestamp(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ControlledTestError("alarm history timestamp is not RFC3339") from error
    if parsed.tzinfo is None:
        raise ControlledTestError("alarm history timestamp has no timezone")
    return parsed.astimezone(timezone.utc)


def has_transition(
    entries: Sequence[dict[str, Any]], state: str, reason: str, not_before: datetime
) -> bool:
    for entry in entries:
        new_state = entry["history_data"].get("newState")
        if isinstance(new_state, dict) and (
            new_state.get("stateValue") == state
            and new_state.get("stateReason") == reason
            and parse_aws_timestamp(entry["timestamp"]) >= not_before
        ):
            return True
    return False


def evidence_paths(directory: Path) -> dict[str, Path]:
    return {
        stage: directory / f"e5-controlled-alarm-{stage}.json"
        for stage in ("before", "history", "after")
    }


def validate_evidence_destination(directory: Path) -> dict[str, Path]:
    if not directory.is_dir() or directory.is_symlink():
        raise ControlledTestError(
            "evidence directory must be an existing non-symlink directory"
        )
    paths = evidence_paths(directory)
    if any(path.exists() or path.is_symlink() for path in paths.values()):
        raise ControlledTestError("controlled-test evidence files already exist")
    return paths


def write_exclusive(path: Path, payload: Mapping[str, Any]) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
    try:
        descriptor = os.open(path, flags, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(canonical_bytes(payload))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as error:
        raise ControlledTestError(f"could not create canonical {path.name} evidence") from error


def run_controlled_test(
    *,
    runner: AwsRunner,
    topic_arn: str,
    alarm_arn: str,
    usage_resource_name: str,
    approval_id: str,
    confirmation: str,
    evidence_directory: Path,
    deadline_seconds: int,
    execute: bool,
    now: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    monotonic: Callable[[], float] = time.monotonic,
) -> dict[str, Path]:
    if not execute:
        raise ControlledTestError("controlled alarm mutation requires --execute")
    if not APPROVAL_RE.fullmatch(approval_id):
        raise ControlledTestError("approval ID must be 3-64 safe identifier characters")
    target = parse_target(topic_arn, alarm_arn, usage_resource_name)
    if confirmation != target.alarm_arn:
        raise ControlledTestError("confirmation must exactly equal the target alarm ARN")
    if deadline_seconds < 5 or deadline_seconds > 300:
        raise ControlledTestError("deadline seconds must be between 5 and 300")
    paths = validate_evidence_destination(evidence_directory)
    started_at = now()
    if started_at.tzinfo is None:
        raise ControlledTestError("evidence clock must return a timezone-aware value")
    started_at = started_at.astimezone(timezone.utc)
    history_not_before = started_at - timedelta(seconds=5)
    deadline = monotonic() + deadline_seconds
    restoration_reserve = max(2.0, min(10.0, deadline_seconds / 3))
    effect_deadline = deadline - restoration_reserve

    def call(
        service: str,
        operation: str,
        *arguments: str,
        expect_json: bool = True,
        restore_budget: bool = False,
    ) -> dict[str, Any] | None:
        return runner.call(
            region=target.region,
            service=service,
            operation=operation,
            arguments=arguments,
            deadline=deadline if restore_budget else effect_deadline,
            expect_json=expect_json,
        )

    caller = require_dict(call("sts", "get-caller-identity"), "caller identity")
    validate_caller(caller, target)
    before_raw = require_dict(
        call("cloudwatch", "describe-alarms", "--alarm-names", target.alarm_name),
        "before alarm read",
    )
    before_alarm = validate_alarm(before_raw, target, "OK")
    write_exclusive(
        paths["before"],
        {
            "alarm": before_alarm,
            "approval_id": approval_id,
            "captured_at": checked_at(now),
            "kind": "cats.alarm-recipient-controlled-test.before.v1",
        },
    )

    alarm_reason = f"Cats approved alarm recipient test {approval_id}"
    restore_reason = f"Cats approved alarm recipient test restoration {approval_id}"
    alarm_attempted = False
    try:
        alarm_attempted = True
        try:
            call(
                "cloudwatch",
                "set-alarm-state",
                "--alarm-name",
                target.alarm_name,
                "--state-value",
                "ALARM",
                "--state-reason",
                alarm_reason,
                expect_json=False,
            )
        except ControlledTestError:
            # SetAlarmState can have an ambiguous response. The exact history
            # and restoration reads below are the authority, not its exit code.
            pass
    finally:
        if alarm_attempted:
            try:
                call(
                    "cloudwatch",
                    "set-alarm-state",
                    "--alarm-name",
                    target.alarm_name,
                    "--state-value",
                    "OK",
                    "--state-reason",
                    restore_reason,
                    expect_json=False,
                    restore_budget=True,
                )
            except ControlledTestError:
                # An ambiguous restoration response is followed by exact
                # state discovery below. Only the observed postcondition wins.
                pass
    try:
        after_raw = require_dict(
            call(
                "cloudwatch",
                "describe-alarms",
                "--alarm-names",
                target.alarm_name,
                restore_budget=True,
            ),
            "after alarm read",
        )
        after_alarm = validate_alarm(after_raw, target, "OK")
    except ControlledTestError as error:
        raise ControlledTestError(
            "ALARM was attempted but restoration to exact OK is unproven; "
            "treat this as a live incident"
        ) from error
    write_exclusive(
        paths["after"],
        {
            "alarm": after_alarm,
            "approval_id": approval_id,
            "captured_at": checked_at(now),
            "kind": "cats.alarm-recipient-controlled-test.after.v1",
            "restoration": "proved-ok",
        },
    )
    while True:
        final_history_raw = require_dict(
            call(
                "cloudwatch",
                "describe-alarm-history",
                "--alarm-name",
                target.alarm_name,
                "--history-item-type",
                "StateUpdate",
                "--start-date",
                history_not_before.isoformat().replace("+00:00", "Z"),
                "--max-records",
                "20",
                restore_budget=True,
            ),
            "alarm history read",
        )
        observed_history = history_entries(final_history_raw, target)
        if has_transition(
            observed_history, "ALARM", alarm_reason, history_not_before
        ) and has_transition(
            observed_history, "OK", restore_reason, history_not_before
        ):
            break
        remaining = deadline - monotonic()
        if remaining <= 0.25:
            raise ControlledTestError(
                "history does not prove both test and restoration transitions before the deadline"
            )
        time.sleep(min(0.25, remaining))
    write_exclusive(
        paths["history"],
        {
            "alarm_arn": target.alarm_arn,
            "approval_id": approval_id,
            "captured_at": checked_at(now),
            "items": observed_history,
            "kind": "cats.alarm-recipient-controlled-test.history.v1",
        },
    )
    return paths


def parse_args(arguments: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--topic-arn", required=True)
    parser.add_argument("--alarm-arn", required=True)
    parser.add_argument("--usage-resource-name", default="cats-production-usage")
    parser.add_argument("--approval-id", required=True)
    parser.add_argument("--confirm-alarm-arn", required=True)
    parser.add_argument("--evidence-directory", required=True, type=Path)
    parser.add_argument("--deadline-seconds", type=int, default=60)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--aws-cli", default="aws", help=argparse.SUPPRESS)
    return parser.parse_args(arguments)


def main(arguments: Sequence[str] | None = None) -> int:
    options = parse_args(sys.argv[1:] if arguments is None else arguments)
    try:
        paths = run_controlled_test(
            runner=AwsCliRunner(options.aws_cli),
            topic_arn=options.topic_arn,
            alarm_arn=options.alarm_arn,
            usage_resource_name=options.usage_resource_name,
            approval_id=options.approval_id,
            confirmation=options.confirm_alarm_arn,
            evidence_directory=options.evidence_directory,
            deadline_seconds=options.deadline_seconds,
            execute=options.execute,
        )
    except ControlledTestError as error:
        print(f"controlled alarm recipient test failed: {error}", file=sys.stderr)
        return 1
    print(
        json.dumps(
            {name: str(path) for name, path in sorted(paths.items())},
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
