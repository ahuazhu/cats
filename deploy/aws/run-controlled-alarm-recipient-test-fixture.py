#!/usr/bin/env python3
"""Offline contract fixture for the controlled alarm recipient test."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Sequence


SCRIPT = Path(__file__).with_name("run-controlled-alarm-recipient-test.py")
SPEC = importlib.util.spec_from_file_location("cats_controlled_alarm_test", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("could not load controlled alarm test")
controlled = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = controlled
SPEC.loader.exec_module(controlled)

ACCOUNT = "123456789012"
REGION = "us-east-1"
USAGE = "cats-production-usage"
ALARM_NAME = f"{USAGE}-write-throttled"
TOPIC = f"arn:aws:sns:{REGION}:{ACCOUNT}:cats-production-alerts"
ALARM_ARN = f"arn:aws:cloudwatch:{REGION}:{ACCOUNT}:alarm:{ALARM_NAME}"
APPROVAL = "change-e5-fixture"
NOW = datetime(2026, 8, 13, 8, 0, 0, tzinfo=timezone.utc)


def option(arguments: Sequence[str], name: str) -> str:
    try:
        return arguments[arguments.index(name) + 1]
    except (ValueError, IndexError) as error:
        raise AssertionError(f"missing {name}") from error


class FakeAws:
    def __init__(self) -> None:
        self.state = "OK"
        self.calls: list[tuple[str, str, tuple[str, ...], float, bool]] = []
        self.history: list[dict[str, Any]] = []
        self.caller_account = ACCOUNT
        self.caller_arn = f"arn:aws:iam::{ACCOUNT}:role/offline-fixture"
        self.wrong_alarm_arn: str | None = None
        self.fail_set_states: set[str] = set()
        self.hide_history = False

    def alarm(self) -> dict[str, Any]:
        return {
            "ActionsEnabled": True,
            "AlarmActions": [TOPIC],
            "AlarmArn": self.wrong_alarm_arn or ALARM_ARN,
            "AlarmName": ALARM_NAME,
            "Dimensions": [{"Name": "StreamName", "Value": USAGE}],
            "InsufficientDataActions": [],
            "MetricName": "WriteProvisionedThroughputExceeded",
            "Namespace": "AWS/Kinesis",
            "OKActions": [TOPIC],
            "StateValue": self.state,
        }

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
        if region != REGION:
            raise AssertionError("AWS call escaped exact region")
        args = tuple(arguments)
        self.calls.append((service, operation, args, deadline, expect_json))
        if (service, operation) == ("sts", "get-caller-identity"):
            if args or not expect_json:
                raise AssertionError("invalid STS call")
            return {
                "Account": self.caller_account,
                "Arn": self.caller_arn,
                "UserId": "offline-fixture",
            }
        if (service, operation) == ("cloudwatch", "describe-alarms"):
            if args != ("--alarm-names", ALARM_NAME) or not expect_json:
                raise AssertionError("alarm read was not exact")
            return {"CompositeAlarms": [], "MetricAlarms": [self.alarm()]}
        if (service, operation) == ("cloudwatch", "set-alarm-state"):
            if expect_json:
                raise AssertionError("SetAlarmState expected JSON")
            state = option(args, "--state-value")
            reason = option(args, "--state-reason")
            if option(args, "--alarm-name") != ALARM_NAME or state not in {"ALARM", "OK"}:
                raise AssertionError("mutation was not the exact bounded alarm/state")
            old_state = self.state
            self.state = state
            self.history.insert(
                0,
                {
                    "AlarmName": ALARM_NAME,
                    "HistoryData": json.dumps(
                        {
                            "newState": {"stateReason": reason, "stateValue": state},
                            "oldState": {"stateValue": old_state},
                            "version": "1.0",
                        },
                        sort_keys=True,
                        separators=(",", ":"),
                    ),
                    "HistoryItemType": "StateUpdate",
                    "HistorySummary": f"Alarm updated from {old_state} to {state}",
                    "Timestamp": (
                        "2026-08-13T08:00:01Z"
                        if state == "ALARM"
                        else "2026-08-13T08:00:02Z"
                    ),
                },
            )
            if state in self.fail_set_states:
                raise controlled.ControlledTestError("ambiguous fake SetAlarmState response")
            return None
        if (service, operation) == ("cloudwatch", "describe-alarm-history"):
            if (
                option(args, "--alarm-name") != ALARM_NAME
                or option(args, "--history-item-type") != "StateUpdate"
                or option(args, "--max-records") != "20"
                or option(args, "--start-date") != "2026-08-13T07:59:55Z"
                or not expect_json
            ):
                raise AssertionError("history read was not exact and bounded")
            return {"AlarmHistoryItems": [] if self.hide_history else list(self.history)}
        raise AssertionError(f"unexpected or real AWS call: {service} {operation}")


def invoke(fake: FakeAws, directory: Path, **overrides: Any) -> dict[str, Path]:
    arguments: dict[str, Any] = {
        "runner": fake,
        "topic_arn": TOPIC,
        "alarm_arn": ALARM_ARN,
        "usage_resource_name": USAGE,
        "approval_id": APPROVAL,
        "confirmation": ALARM_ARN,
        "evidence_directory": directory,
        "deadline_seconds": 30,
        "execute": True,
        "now": lambda: NOW,
    }
    arguments.update(overrides)
    return controlled.run_controlled_test(**arguments)


def expect_no_mutation_failure(
    label: str, fake: FakeAws, directory: Path, **overrides: Any
) -> None:
    try:
        invoke(fake, directory, **overrides)
    except controlled.ControlledTestError:
        pass
    else:
        raise AssertionError(f"{label}: unsafe fixture passed")
    if any(operation == "set-alarm-state" for _service, operation, *_rest in fake.calls):
        raise AssertionError(f"{label}: failure mutated AWS")


def main() -> int:
    with tempfile.TemporaryDirectory(prefix="cats-controlled-alarm-fixture-") as raw:
        root = Path(raw)
        positive = root / "positive"
        positive.mkdir()
        fake = FakeAws()
        paths = invoke(fake, positive)
        if fake.state != "OK":
            raise AssertionError("positive fixture did not restore exactly OK")
        mutations = [
            option(arguments, "--state-value")
            for service, operation, arguments, _deadline, _expect_json in fake.calls
            if (service, operation) == ("cloudwatch", "set-alarm-state")
        ]
        if mutations != ["ALARM", "OK"]:
            raise AssertionError(f"unexpected mutation sequence: {mutations!r}")
        deadlines = [deadline for *_prefix, deadline, _expect_json in fake.calls]
        if max(deadlines) - min(deadlines) != 10.0:
            raise AssertionError(f"restoration budget was not reserved: {deadlines!r}")
        for stage, path in paths.items():
            raw_evidence = path.read_bytes()
            parsed = json.loads(raw_evidence)
            if raw_evidence != controlled.canonical_bytes(parsed):
                raise AssertionError(f"{stage} evidence is not canonical JSON")
            if path.stat().st_mode & 0o077:
                raise AssertionError(f"{stage} evidence permissions are not private")
        if json.loads(paths["before"].read_text())["alarm"]["StateValue"] != "OK":
            raise AssertionError("before evidence did not prove OK")
        if json.loads(paths["after"].read_text())["restoration"] != "proved-ok":
            raise AssertionError("after evidence did not prove restoration")
        history = json.loads(paths["history"].read_text())["items"]
        if len(history) != 2:
            raise AssertionError("history evidence did not retain both transitions")

        ambiguous = root / "ambiguous"
        ambiguous.mkdir()
        fake = FakeAws()
        fake.fail_set_states = {"ALARM", "OK"}
        invoke(fake, ambiguous)
        if fake.state != "OK":
            raise AssertionError("ambiguous responses defeated postcondition discovery")

        deadline = root / "deadline"
        deadline.mkdir()
        fake = FakeAws()
        fake.hide_history = True
        clock_values = iter((100.0, 106.0))
        try:
            invoke(
                fake,
                deadline,
                deadline_seconds=5,
                monotonic=lambda: next(clock_values),
            )
        except controlled.ControlledTestError as error:
            if "before the deadline" not in str(error):
                raise
        else:
            raise AssertionError("missing history escaped the absolute deadline")
        if fake.state != "OK" or not (
            deadline / "e5-controlled-alarm-after.json"
        ).is_file():
            raise AssertionError("deadline failure did not retain exact OK restoration evidence")

        for label, overrides, configure in (
            ("missing execute", {"execute": False}, lambda fake: None),
            ("wrong confirmation", {"confirmation": "wrong"}, lambda fake: None),
            (
                "wrong alarm ARN",
                {"alarm_arn": ALARM_ARN.replace(REGION, "us-west-2")},
                lambda fake: None,
            ),
            ("initial ALARM", {}, lambda fake: setattr(fake, "state", "ALARM")),
            ("wrong account", {}, lambda fake: setattr(fake, "caller_account", "999999999999")),
            (
                "wrong caller partition",
                {},
                lambda fake: setattr(
                    fake,
                    "caller_arn",
                    f"arn:aws-us-gov:iam::{ACCOUNT}:role/offline-fixture",
                ),
            ),
            (
                "wrong live alarm ARN",
                {},
                lambda fake: setattr(
                    fake,
                    "wrong_alarm_arn",
                    ALARM_ARN.replace(ACCOUNT, "999999999999"),
                ),
            ),
        ):
            directory = root / label.replace(" ", "-")
            directory.mkdir()
            fake = FakeAws()
            configure(fake)
            expect_no_mutation_failure(label, fake, directory, **overrides)

        existing = root / "existing"
        existing.mkdir()
        (existing / "e5-controlled-alarm-before.json").write_text("do not overwrite")
        expect_no_mutation_failure("existing evidence", FakeAws(), existing)

    print("controlled alarm recipient test fixture: ok")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
