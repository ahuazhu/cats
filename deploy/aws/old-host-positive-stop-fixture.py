#!/usr/bin/env python3
"""Offline calibrated fixture for old-host-positive-stop.py.

No real systemctl or AWS command is reachable from this fixture.  The fake
runners reject every command outside the executor's closed command set.
"""

from __future__ import annotations

import argparse
import copy
import datetime as dt
import importlib.util
import json
from pathlib import Path
import sys
import tempfile
from typing import Any, Sequence


def load_tool(path: Path) -> Any:
    spec = importlib.util.spec_from_file_location("cats_old_host_positive_stop", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot import positive-stop tool")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeLocalFacts:
    def __init__(
        self,
        tool: Any,
        *,
        boot_id: str,
        machine_digest: str,
        processes: Sequence[Any],
    ) -> None:
        self.tool = tool
        self.boot_id = boot_id
        self.machine_digest = machine_digest
        self.processes = {process.pid: process for process in processes}
        self.snapshots = 0

    def snapshot(self, calibration_pid: int) -> Any:
        self.snapshots += 1
        if calibration_pid not in self.processes:
            raise self.tool.PositiveStopError(
                "fake process probe did not find its known-positive control"
            )
        return self.tool.ProcessSnapshot(
            boot_id=self.boot_id,
            machine_id_sha256=self.machine_digest,
            processes=dict(self.processes),
        )


def unit_state(
    *,
    active: str,
    main_pid: int,
    load: str = "loaded",
    sub: str | None = None,
    result: str = "success",
) -> dict[str, Any]:
    return {
        "ActiveState": active,
        "ControlPID": "0",
        "LoadState": load,
        "MainPID": str(main_pid),
        "Result": result,
        "SubState": sub or ("running" if active == "active" else active),
        "UnitFileState": "enabled",
    }


class FakeLocalRunner:
    def __init__(
        self,
        tool: Any,
        facts: FakeLocalFacts,
        units: dict[str, dict[str, Any]],
        *,
        ambiguous_units: set[str] | None = None,
        reuse_pid: bool = False,
        survivor_pid: int | None = None,
        idle_returncode: int = 0,
    ) -> None:
        self.tool = tool
        self.facts = facts
        self.units = copy.deepcopy(units)
        self.ambiguous_units = ambiguous_units or set()
        self.reuse_pid = reuse_pid
        self.survivor_pid = survivor_pid
        self.idle_returncode = idle_returncode
        self.calls: list[tuple[str, ...]] = []
        self.stop_calls: list[str] = []

    def run(self, argv: Sequence[str], *, timeout: float) -> Any:
        if timeout <= 0:
            raise AssertionError("executor passed a non-positive timeout")
        command = tuple(argv)
        self.calls.append(command)
        if argv[0].endswith("/require-idle-worker.sh"):
            if command != (
                "/opt/cats/bin/require-idle-worker.sh",
                "/sys/fs/cgroup",
                "/opt/cats/bin",
            ):
                raise AssertionError("executor changed the exact idle/runtime preflight")
            return self.tool.CommandResult(self.idle_returncode, "")
        if argv[:4] == ["systemctl", "--system", "--no-ask-password", "show"]:
            unit = argv[-1]
            if unit not in self.units:
                raise AssertionError(f"unexpected fake systemd unit: {unit}")
            state = self.units[unit]
            output = "\n".join(f"{key}={state[key]}" for key in self.tool.SYSTEMD_PROPERTIES)
            return self.tool.CommandResult(0, output + "\n")
        if (
            argv[:4] == ["systemctl", "--system", "--no-ask-password", "stop"]
            and len(argv) == 5
        ):
            unit = argv[4]
            if unit not in self.units:
                raise AssertionError(f"unexpected fake stop unit: {unit}")
            self.stop_calls.append(unit)
            state = self.units[unit]
            root = int(state["MainPID"])
            if root:
                original_processes = dict(self.facts.processes)
                descendants = {root}
                changed = True
                while changed:
                    changed = False
                    for process in list(self.facts.processes.values()):
                        if process.ppid in descendants and process.pid not in descendants:
                            descendants.add(process.pid)
                            changed = True
                for pid in descendants:
                    self.facts.processes.pop(pid, None)
                if self.survivor_pid in descendants:
                    self.facts.processes[self.survivor_pid] = original_processes[
                        self.survivor_pid
                    ]
                if self.reuse_pid and 101 in descendants:
                    self.facts.processes[101] = self.tool.ProcessIdentity(
                        101, 99_999, 1, "/usr/bin/unrelated", "/usr/bin/unrelated"
                    )
            state["MainPID"] = "0"
            state["ControlPID"] = "0"
            if state["ActiveState"] != "failed":
                state["ActiveState"] = "inactive"
                state["SubState"] = "dead"
            return self.tool.CommandResult(
                1 if unit in self.ambiguous_units else 0,
                "",
                "simulated response loss" if unit in self.ambiguous_units else "",
            )
        raise AssertionError(f"fixture blocked unexpected local command: {command}")


class FakeAwsRunner:
    def __init__(
        self,
        tool: Any,
        clock: FakeClock,
        *,
        account_id: str,
        region: str,
        instance_id: str,
        vpc_id: str,
        deny_group: str,
        enis: dict[str, list[str]],
        group_vpc_id: str | None = None,
        instance_vpc_id: str | None = None,
        ingress_rules: list[dict[str, Any]] | None = None,
        egress_rules: list[dict[str, Any]] | None = None,
        ambiguous_modify: bool = False,
        seconds_per_call: float = 0.0,
        reported_region: str | None = None,
        drift_after_eni_describes: int | None = None,
        drift_eni: str | None = None,
        drift_groups: list[str] | None = None,
        expected_eni_ids: list[str] | None = None,
    ) -> None:
        self.tool = tool
        self.clock = clock
        self.account_id = account_id
        self.region = region
        self.instance_id = instance_id
        self.vpc_id = vpc_id
        self.group_vpc_id = group_vpc_id or vpc_id
        self.instance_vpc_id = instance_vpc_id or vpc_id
        self.deny_group = deny_group
        self.enis = {eni: list(groups) for eni, groups in enis.items()}
        self.ingress_rules = [] if ingress_rules is None else ingress_rules
        self.egress_rules = [] if egress_rules is None else egress_rules
        self.ambiguous_modify = ambiguous_modify
        self.seconds_per_call = seconds_per_call
        self.reported_region = reported_region or region
        self.drift_after_eni_describes = drift_after_eni_describes
        self.drift_eni = drift_eni
        self.drift_groups = list(drift_groups or [])
        self.expected_eni_ids = list(expected_eni_ids or [ENI_A, ENI_B])
        self.eni_describes = 0
        self.calls: list[tuple[str, ...]] = []
        self.modify_calls: list[str] = []

    def _eni(self, eni_id: str, groups: list[str], index: int) -> dict[str, Any]:
        return {
            "Attachment": {"DeviceIndex": index, "InstanceId": self.instance_id},
            "Groups": [{"GroupId": group} for group in groups],
            "NetworkInterfaceId": eni_id,
            "OwnerId": self.account_id,
            "Status": "in-use",
            "VpcId": self.instance_vpc_id,
        }

    def run(self, argv: Sequence[str], *, timeout: float) -> Any:
        if timeout <= 0:
            raise AssertionError("executor passed a non-positive timeout")
        command = tuple(argv)
        self.calls.append(command)
        self.clock.value += self.seconds_per_call
        if len(argv) < 9 or list(argv[:7]) != [
            "aws",
            "--no-cli-pager",
            "--no-paginate",
            "--region",
            self.region,
            "--output",
            "json",
        ]:
            raise AssertionError(f"fixture blocked unexpected AWS command: {command}")
        service = argv[7]
        operation = argv[8]
        if (service, operation) == ("sts", "get-caller-identity"):
            if len(argv) != 9:
                raise AssertionError("caller discovery had unexpected arguments")
            value = {
                "Account": self.account_id,
                "Arn": f"arn:aws:iam::{self.account_id}:role/fixture",
                "UserId": "fixture",
            }
        elif (service, operation) == ("ec2", "describe-regions"):
            if list(argv[9:]) != ["--region-names", self.region]:
                raise AssertionError("region discovery was not exact")
            value = {
                "Regions": [
                    {
                        "OptInStatus": "opt-in-not-required",
                        "RegionName": self.reported_region,
                    }
                ]
            }
        elif (service, operation) == ("ec2", "describe-security-groups"):
            if list(argv[9:]) != ["--group-ids", self.deny_group]:
                raise AssertionError("security-group discovery was not exact")
            value = {
                "SecurityGroups": [
                    {
                        "GroupId": self.deny_group,
                        "IpPermissions": self.ingress_rules,
                        "IpPermissionsEgress": self.egress_rules,
                        "OwnerId": self.account_id,
                        "VpcId": self.group_vpc_id,
                    }
                ]
            }
        elif (service, operation) == ("ec2", "describe-instances"):
            if list(argv[9:]) != ["--instance-ids", self.instance_id]:
                raise AssertionError("instance discovery was not exact")
            interfaces = [
                self._eni(eni_id, self.enis[eni_id], index)
                for index, eni_id in enumerate(sorted(self.enis))
            ]
            value = {
                "Reservations": [
                    {
                        "Instances": [
                            {
                                "InstanceId": self.instance_id,
                                "NetworkInterfaces": interfaces,
                                "State": {"Name": "running"},
                                "VpcId": self.instance_vpc_id,
                            }
                        ],
                        "OwnerId": self.account_id,
                    }
                ]
            }
        elif (service, operation) == ("ec2", "describe-network-interfaces"):
            self.eni_describes += 1
            requested = list(argv[argv.index("--network-interface-ids") + 1 :])
            if list(argv[9:]) != ["--network-interface-ids", *self.expected_eni_ids]:
                raise AssertionError("ENI discovery was not the exact expected set")
            value = {
                "NetworkInterfaces": [
                    self._eni(eni_id, self.enis[eni_id], sorted(self.enis).index(eni_id))
                    for eni_id in requested
                    if eni_id in self.enis
                ]
            }
            if (
                self.drift_after_eni_describes == self.eni_describes
                and self.drift_eni is not None
            ):
                self.enis[self.drift_eni] = list(self.drift_groups)
        elif (service, operation) == (
            "ec2",
            "modify-network-interface-attribute",
        ):
            eni_id = argv[argv.index("--network-interface-id") + 1]
            group = argv[argv.index("--groups") + 1]
            if list(argv[9:]) != [
                "--network-interface-id",
                eni_id,
                "--groups",
                group,
            ]:
                raise AssertionError("ENI modification had unexpected arguments")
            if eni_id not in self.enis or group != self.deny_group:
                raise AssertionError("executor modified a non-inventory ENI/group")
            self.modify_calls.append(eni_id)
            self.enis[eni_id] = [group]
            if self.ambiguous_modify:
                return self.tool.CommandResult(255, "", "simulated lost response")
            return self.tool.CommandResult(0, "")
        else:
            raise AssertionError(f"fixture blocked unexpected AWS operation: {command}")
        return self.tool.CommandResult(0, json.dumps(value))


def fixed_now() -> dt.datetime:
    return dt.datetime(2026, 8, 13, 1, 2, 3, tzinfo=dt.timezone.utc)


BOOT = "11111111-2222-4333-8444-555555555555"
MACHINE = "sha256:" + "1" * 64
ACCOUNT = "123456789012"
REGION = "us-east-1"
INSTANCE = "i-11111111111111111"
VPC = "vpc-11111111111111111"
DENY_GROUP = "sg-11111111111111111"
ENI_A = "eni-11111111111111111"
ENI_B = "eni-22222222222222222"


def local_components(*, all_components: bool = True) -> list[dict[str, Any]]:
    components = [
        {
            "component": "blockd",
            "executable_paths": ["/opt/cats/bin/cats-blockd"],
            "proof": "process_absence",
        },
        {
            "component": "node_agent",
            "executable_paths": ["/opt/cats/bin/cats-noded"],
            "proof": "systemd_stop",
            "units": ["cats-worker.service"],
        },
        {
            "component": "vmm",
            "executable_paths": [
                "/opt/cats/bin/cats-vmm-launcher",
                "/opt/cats/bin/cloud-hypervisor",
            ],
            "proof": "process_absence",
        },
    ]
    if all_components:
        components.extend(
            [
                {
                    "component": "controller",
                    "executable_paths": ["/opt/cats/bin/cats-controld"],
                    "proof": "systemd_stop",
                    "units": ["cats-controller.service"],
                },
                {
                    "component": "gateway",
                    "executable_paths": ["/opt/cats/bin/cats-gatewayd"],
                    "proof": "systemd_stop",
                    "units": ["cats-gateway.service"],
                },
            ]
        )
    return sorted(components, key=lambda value: value["component"])


def local_host(*, all_components: bool = True) -> dict[str, Any]:
    return {
        "components": local_components(all_components=all_components),
        "expected_boot_id": BOOT,
        "expected_machine_id_sha256": MACHINE,
        "host_id": "old-local",
        "idle_preflight": {
            "cgroup_v2_root": "/sys/fs/cgroup",
            "helper_path": "/opt/cats/bin/require-idle-worker.sh",
            "runtime_bin_root": "/opt/cats/bin",
        },
        "method": "local_systemd",
    }


def ec2_host(*, components: list[str] | None = None, enis: list[str] | None = None) -> dict[str, Any]:
    return {
        "aws": {
            "account_id": ACCOUNT,
            "deny_all_security_group_id": DENY_GROUP,
            "expected_eni_ids": enis or [ENI_A, ENI_B],
            "instance_id": INSTANCE,
            "region": REGION,
            "vpc_id": VPC,
        },
        "components": components or list(("blockd", "controller", "gateway", "node_agent", "vmm")),
        "host_id": "old-ec2",
        "method": "ec2_security_group_isolation",
    }


def inventory(hosts: list[dict[str, Any]], attempt: str) -> dict[str, Any]:
    return {
        "attempt_id": attempt,
        "hosts": sorted(hosts, key=lambda host: host["host_id"]),
        "kind": "cats.old-host-positive-stop-inventory.v1",
        "required_components": ["blockd", "controller", "gateway", "node_agent", "vmm"],
        "version": 1,
    }


def write_inventory(tool: Any, path: Path, value: dict[str, Any]) -> tuple[Any, ...]:
    path.write_bytes(tool.canonical_bytes(value))
    path.chmod(0o600)
    return tool.load_inventory(path)


def base_processes(tool: Any) -> list[Any]:
    return [
        tool.ProcessIdentity(900, 9_000, 1, "/usr/bin/python3", "/usr/bin/python3"),
        tool.ProcessIdentity(
            100, 1_000, 1, "/opt/cats/bin/cats-noded", "/opt/cats/bin/cats-noded"
        ),
        tool.ProcessIdentity(101, 1_001, 100, "/usr/bin/helper", "/usr/bin/helper"),
        tool.ProcessIdentity(102, 1_002, 101, "/usr/bin/helper-child", "/usr/bin/helper-child"),
        tool.ProcessIdentity(
            300, 3_000, 1, "/opt/cats/bin/cats-gatewayd", "/opt/cats/bin/cats-gatewayd"
        ),
    ]


def base_units() -> dict[str, dict[str, Any]]:
    return {
        # A failed unit is already physically stopped, but remains an explicit
        # loaded unit and is still passed through systemctl stop + discovery.
        "cats-controller.service": unit_state(
            active="failed", main_pid=0, result="exit-code"
        ),
        "cats-gateway.service": unit_state(active="active", main_pid=300),
        "cats-worker.service": unit_state(active="active", main_pid=100),
    }


def expect_refusal(tool: Any, callback: Any, contains: str) -> None:
    try:
        callback()
    except tool.PositiveStopError as error:
        if contains not in str(error):
            raise AssertionError(f"wrong refusal: {error}; expected {contains!r}") from error
    else:
        raise AssertionError(f"operation unexpectedly succeeded; expected {contains!r}")


def run_local_matrix(tool: Any, root: Path) -> tuple[Path, Path, dict[str, Any]]:
    legacy_case = root / "local-legacy-cgroup-field"
    legacy_case.mkdir(mode=0o700)
    legacy_host = local_host()
    legacy_preflight = legacy_host["idle_preflight"]
    legacy_preflight["metering_cgroup_root"] = legacy_preflight.pop("cgroup_v2_root")
    legacy_inventory = legacy_case / "inventory.json"
    legacy_inventory.write_bytes(
        tool.canonical_bytes(inventory([legacy_host], "positive-local-legacy-field"))
    )
    legacy_inventory.chmod(0o600)
    expect_refusal(
        tool,
        lambda: tool.load_inventory(legacy_inventory),
        "non-canonical field set",
    )

    case = root / "local"
    case.mkdir(mode=0o700)
    inv_path = case / "inventory.json"
    inv, inv_digest, hosts = write_inventory(
        tool, inv_path, inventory([local_host()], "positive-local-01")
    )
    facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    runner = FakeLocalRunner(
        tool,
        facts,
        base_units(),
        ambiguous_units={"cats-controller.service", "cats-worker.service"},
        reuse_pid=True,
    )
    clock = FakeClock()
    output = case / "old-local.json"
    receipt, digest = tool.execute_local_stop(
        inventory=inv,
        inventory_digest=inv_digest,
        hosts=hosts,
        host_id="old-local",
        output=output,
        runner=runner,
        facts=facts,
        deadline_seconds=60,
        stable_seconds=1,
        now=fixed_now,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
        calibration_pid=900,
    )
    assert receipt["outcome"] == "stopped"
    assert receipt["effects"] == [
        {"response": "ambiguous_response_confirmed", "unit": "cats-controller.service"},
        {"response": "acknowledged", "unit": "cats-gateway.service"},
        {"response": "ambiguous_response_confirmed", "unit": "cats-worker.service"},
    ]
    failed_unit = next(
        unit
        for unit in receipt["postcondition"]["units"]
        if unit["unit"] == "cats-controller.service"
    )
    assert failed_unit["active_state"] == "failed" and failed_unit["result"] == "exit-code"
    intent = json.loads((case / "old-local.intent.json").read_bytes())
    tree = {(item["pid"], item["start_ticks"]) for item in intent["precondition"]["process_tree"]}
    assert {(100, 1_000), (101, 1_001), (102, 1_002), (300, 3_000)} <= tree
    assert facts.processes[101].start_ticks == 99_999
    assert runner.stop_calls == [
        "cats-controller.service",
        "cats-gateway.service",
        "cats-worker.service",
    ]
    assert sum(call[0].endswith("/require-idle-worker.sh") for call in runner.calls) == 2
    assert all("pkill" not in call and "kill" not in call for argv in runner.calls for call in argv)
    assert output.with_suffix(".sha256").read_text().startswith(digest.removeprefix("sha256:"))

    # Exact replay performs discovery only and never calls systemctl stop again.
    before = len(runner.stop_calls)
    replay, replay_digest = tool.execute_local_stop(
        inventory=inv,
        inventory_digest=inv_digest,
        hosts=hosts,
        host_id="old-local",
        output=output,
        runner=runner,
        facts=facts,
        deadline_seconds=60,
        stable_seconds=1,
        now=fixed_now,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
        calibration_pid=900,
    )
    assert replay == receipt and replay_digest == digest and len(runner.stop_calls) == before

    # If final receipt publication is lost after all stops, the retained intent
    # permits discovery-only settlement and never repeats systemctl stop.
    recovery_case = root / "local-response-loss"
    recovery_case.mkdir(mode=0o700)
    recovery_inv_path = recovery_case / "inventory.json"
    recovery_inv, recovery_digest, recovery_hosts = write_inventory(
        tool,
        recovery_inv_path,
        inventory([local_host()], "positive-local-response-loss"),
    )
    recovery_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    recovery_runner = FakeLocalRunner(tool, recovery_facts, base_units())
    recovery_clock = FakeClock()
    recovery_output = recovery_case / "receipt.json"
    original_write = tool.write_evidence

    def lose_final_receipt(path: Path, value: dict[str, Any]) -> str:
        if path == recovery_output:
            raise tool.PositiveStopError("simulated local receipt response loss")
        return original_write(path, value)

    tool.write_evidence = lose_final_receipt
    try:
        expect_refusal(
            tool,
            lambda: tool.execute_local_stop(
                inventory=recovery_inv,
                inventory_digest=recovery_digest,
                hosts=recovery_hosts,
                host_id="old-local",
                output=recovery_output,
                runner=recovery_runner,
                facts=recovery_facts,
                deadline_seconds=60,
                stable_seconds=1,
                now=fixed_now,
                monotonic=recovery_clock.monotonic,
                sleeper=recovery_clock.sleep,
                calibration_pid=900,
            ),
            "simulated local receipt response loss",
        )
    finally:
        tool.write_evidence = original_write
    recovery_stops = list(recovery_runner.stop_calls)
    recovered, _ = tool.execute_local_stop(
        inventory=recovery_inv,
        inventory_digest=recovery_digest,
        hosts=recovery_hosts,
        host_id="old-local",
        output=recovery_output,
        runner=recovery_runner,
        facts=recovery_facts,
        deadline_seconds=60,
        stable_seconds=1,
        now=fixed_now,
        monotonic=recovery_clock.monotonic,
        sleeper=recovery_clock.sleep,
        calibration_pid=900,
    )
    assert recovery_runner.stop_calls == recovery_stops
    assert all(
        effect["response"] == "recovered_from_existing_intent"
        for effect in recovered["effects"]
    )

    # The known-positive process control works, then the negative runtime
    # result is load-bearing. A live blockd refuses before any unit stop.
    live_case = root / "local-live-runtime"
    live_case.mkdir(mode=0o700)
    live_inv_path = live_case / "inventory.json"
    live_inv, live_digest, live_hosts = write_inventory(
        tool, live_inv_path, inventory([local_host()], "positive-local-live")
    )
    live_processes = base_processes(tool)
    live_processes.append(
        tool.ProcessIdentity(
            400, 4_000, 1, "/opt/cats/bin/cats-blockd (deleted)", "cats-blockd"
        )
    )
    live_processes.append(
        tool.ProcessIdentity(
            401,
            4_001,
            1,
            "/opt/cats/bin/cloud-hypervisor",
            "/opt/cats/bin/cloud-hypervisor",
        )
    )
    live_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=live_processes
    )
    live_runner = FakeLocalRunner(tool, live_facts, base_units())
    expect_refusal(
        tool,
        lambda: tool.execute_local_stop(
            inventory=live_inv,
            inventory_digest=live_digest,
            hosts=live_hosts,
            host_id="old-local",
            output=live_case / "receipt.json",
            runner=live_runner,
            facts=live_facts,
            deadline_seconds=60,
            stable_seconds=0,
            now=fixed_now,
            monotonic=FakeClock().monotonic,
            sleeper=lambda _seconds: None,
            calibration_pid=900,
        ),
        "VMM or blockd",
    )
    assert not live_runner.stop_calls

    idle_case = root / "local-idle-refusal"
    idle_case.mkdir(mode=0o700)
    idle_inv_path = idle_case / "inventory.json"
    idle_inv, idle_digest, idle_hosts = write_inventory(
        tool, idle_inv_path, inventory([local_host()], "positive-local-idle")
    )
    idle_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    idle_runner = FakeLocalRunner(
        tool, idle_facts, base_units(), idle_returncode=1
    )
    expect_refusal(
        tool,
        lambda: tool.execute_local_stop(
            inventory=idle_inv,
            inventory_digest=idle_digest,
            hosts=idle_hosts,
            host_id="old-local",
            output=idle_case / "receipt.json",
            runner=idle_runner,
            facts=idle_facts,
            deadline_seconds=60,
            stable_seconds=0,
            now=fixed_now,
            monotonic=FakeClock().monotonic,
            sleeper=lambda _seconds: None,
            calibration_pid=900,
        ),
        "require-idle-worker refused",
    )
    assert not idle_runner.stop_calls

    # An absent expected unit cannot be interpreted as successfully stopped.
    absent_case = root / "local-absent-unit"
    absent_case.mkdir(mode=0o700)
    absent_inv_path = absent_case / "inventory.json"
    absent_inv, absent_digest, absent_hosts = write_inventory(
        tool, absent_inv_path, inventory([local_host()], "positive-local-absent")
    )
    absent_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    absent_units = base_units()
    absent_units["cats-worker.service"] = unit_state(
        active="inactive", main_pid=0, load="not-found"
    )
    absent_runner = FakeLocalRunner(tool, absent_facts, absent_units)
    expect_refusal(
        tool,
        lambda: tool.execute_local_stop(
            inventory=absent_inv,
            inventory_digest=absent_digest,
            hosts=absent_hosts,
            host_id="old-local",
            output=absent_case / "receipt.json",
            runner=absent_runner,
            facts=absent_facts,
            deadline_seconds=60,
            stable_seconds=0,
            now=fixed_now,
            monotonic=FakeClock().monotonic,
            sleeper=lambda _seconds: None,
            calibration_pid=900,
        ),
        "absent or not loaded",
    )
    assert not absent_runner.stop_calls

    masked_case = root / "local-masked-unit"
    masked_case.mkdir(mode=0o700)
    masked_inv_path = masked_case / "inventory.json"
    masked_inv, masked_digest, masked_hosts = write_inventory(
        tool, masked_inv_path, inventory([local_host()], "positive-local-masked")
    )
    masked_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    masked_units = base_units()
    masked_units["cats-worker.service"]["UnitFileState"] = "masked-runtime"
    masked_runner = FakeLocalRunner(tool, masked_facts, masked_units)
    expect_refusal(
        tool,
        lambda: tool.execute_local_stop(
            inventory=masked_inv,
            inventory_digest=masked_digest,
            hosts=masked_hosts,
            host_id="old-local",
            output=masked_case / "receipt.json",
            runner=masked_runner,
            facts=masked_facts,
            deadline_seconds=60,
            stable_seconds=0,
            now=fixed_now,
            monotonic=FakeClock().monotonic,
            sleeper=lambda _seconds: None,
            calibration_pid=900,
        ),
        "is masked",
    )
    assert not masked_runner.stop_calls

    survivor_case = root / "local-descendant-survivor"
    survivor_case.mkdir(mode=0o700)
    survivor_inv_path = survivor_case / "inventory.json"
    survivor_inv, survivor_digest, survivor_hosts = write_inventory(
        tool,
        survivor_inv_path,
        inventory([local_host()], "positive-local-survivor"),
    )
    survivor_facts = FakeLocalFacts(
        tool, boot_id=BOOT, machine_digest=MACHINE, processes=base_processes(tool)
    )
    survivor_runner = FakeLocalRunner(
        tool, survivor_facts, base_units(), survivor_pid=102
    )
    survivor_clock = FakeClock()
    expect_refusal(
        tool,
        lambda: tool.execute_local_stop(
            inventory=survivor_inv,
            inventory_digest=survivor_digest,
            hosts=survivor_hosts,
            host_id="old-local",
            output=survivor_case / "receipt.json",
            runner=survivor_runner,
            facts=survivor_facts,
            deadline_seconds=60,
            stable_seconds=0,
            now=fixed_now,
            monotonic=survivor_clock.monotonic,
            sleeper=survivor_clock.sleep,
            calibration_pid=900,
        ),
        "exact pre-stop process identity remains alive",
    )
    assert survivor_facts.processes[102].start_ticks == 1_002
    return inv_path, output, receipt


def run_aws_success(
    tool: Any,
    case: Path,
    *,
    attempt: str,
    ambiguous: bool,
    crash_before_final: bool = False,
) -> tuple[Path, Path, Any, dict[str, Any]]:
    case.mkdir(mode=0o700)
    inv_path = case / "inventory.json"
    inv, inv_digest, hosts = write_inventory(
        tool, inv_path, inventory([ec2_host()], attempt)
    )
    clock = FakeClock()
    runner = FakeAwsRunner(
        tool,
        clock,
        account_id=ACCOUNT,
        region=REGION,
        instance_id=INSTANCE,
        vpc_id=VPC,
        deny_group=DENY_GROUP,
        enis={ENI_A: ["sg-aaaaaaaaaaaaaaaaa"], ENI_B: ["sg-bbbbbbbbbbbbbbbbb"]},
        ambiguous_modify=ambiguous,
    )
    output = case / "old-ec2.json"
    if crash_before_final:
        original_write = tool.write_evidence

        def crash_final(path: Path, value: dict[str, Any]) -> str:
            if path == output:
                raise tool.PositiveStopError("simulated final receipt response loss")
            return original_write(path, value)

        tool.write_evidence = crash_final
        try:
            expect_refusal(
                tool,
                lambda: tool.execute_ec2_isolation(
                    inventory=inv,
                    inventory_digest=inv_digest,
                    hosts=hosts,
                    host_id="old-ec2",
                    output=output,
                    runner=runner,
                    deadline_seconds=60,
                    stable_seconds=1,
                    now=fixed_now,
                    monotonic=clock.monotonic,
                    sleeper=clock.sleep,
                ),
                "simulated final receipt response loss",
            )
        finally:
            tool.write_evidence = original_write
        assert not output.exists() and (case / "old-ec2.intent.json").exists()
        before = list(runner.modify_calls)
        receipt, _ = tool.execute_ec2_isolation(
            inventory=inv,
            inventory_digest=inv_digest,
            hosts=hosts,
            host_id="old-ec2",
            output=output,
            runner=runner,
            deadline_seconds=60,
            stable_seconds=1,
            now=fixed_now,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
        assert runner.modify_calls == before
        assert all(
            effect["response"] == "recovered_from_existing_intent"
            for effect in receipt["effects"]
        )
    else:
        receipt, _ = tool.execute_ec2_isolation(
            inventory=inv,
            inventory_digest=inv_digest,
            hosts=hosts,
            host_id="old-ec2",
            output=output,
            runner=runner,
            deadline_seconds=60,
            stable_seconds=1,
            now=fixed_now,
            monotonic=clock.monotonic,
            sleeper=clock.sleep,
        )
    assert runner.modify_calls == [ENI_A, ENI_B]
    assert all(eni["group_ids"] == [DENY_GROUP] for eni in receipt["postcondition"]["enis"])
    before_replay = list(runner.modify_calls)
    replay, _ = tool.execute_ec2_isolation(
        inventory=inv,
        inventory_digest=inv_digest,
        hosts=hosts,
        host_id="old-ec2",
        output=output,
        runner=runner,
        deadline_seconds=60,
        stable_seconds=1,
        now=fixed_now,
        monotonic=clock.monotonic,
        sleeper=clock.sleep,
    )
    assert replay == receipt and runner.modify_calls == before_replay
    return inv_path, output, runner, receipt


def run_aws_negative_matrix(tool: Any, root: Path) -> None:
    def run_case(
        label: str,
        *,
        inventory_host: dict[str, Any] | None = None,
        runner_options: dict[str, Any] | None = None,
        error: str,
        deadline: float = 60,
        stable: float = 0,
    ) -> None:
        case = root / f"aws-{label}"
        case.mkdir(mode=0o700)
        inv_path = case / "inventory.json"
        inv, inv_digest, hosts = write_inventory(
            tool,
            inv_path,
            inventory([inventory_host or ec2_host()], f"positive-aws-{label}"),
        )
        clock = FakeClock()
        options = {
            "account_id": ACCOUNT,
            "region": REGION,
            "instance_id": INSTANCE,
            "vpc_id": VPC,
            "deny_group": DENY_GROUP,
            "enis": {ENI_A: ["sg-aaaaaaaaaaaaaaaaa"], ENI_B: ["sg-bbbbbbbbbbbbbbbbb"]},
        }
        options.update(runner_options or {})
        runner = FakeAwsRunner(tool, clock, **options)
        expect_refusal(
            tool,
            lambda: tool.execute_ec2_isolation(
                inventory=inv,
                inventory_digest=inv_digest,
                hosts=hosts,
                host_id="old-ec2",
                output=case / "receipt.json",
                runner=runner,
                deadline_seconds=deadline,
                stable_seconds=stable,
                now=fixed_now,
                monotonic=clock.monotonic,
                sleeper=clock.sleep,
            ),
            error,
        )
        assert not runner.modify_calls

    run_case(
        "wrong-account",
        runner_options={"account_id": "999999999999"},
        error="caller account",
    )
    run_case(
        "wrong-region",
        runner_options={"reported_region": "us-west-2"},
        error="enabled exact target",
    )
    run_case(
        "wrong-vpc",
        runner_options={"group_vpc_id": "vpc-99999999999999999"},
        error="security group identity",
    )
    run_case(
        "nonempty-rules",
        runner_options={"egress_rules": [{"IpProtocol": "-1"}]},
        error="non-empty rule set",
    )
    run_case(
        "missing-eni",
        runner_options={"enis": {ENI_A: ["sg-aaaaaaaaaaaaaaaaa"]}},
        error="missing or extra interface",
    )
    run_case(
        "extra-eni",
        runner_options={
            "enis": {
                ENI_A: ["sg-aaaaaaaaaaaaaaaaa"],
                ENI_B: ["sg-bbbbbbbbbbbbbbbbb"],
                "eni-33333333333333333": ["sg-ccccccccccccccccc"],
            }
        },
        error="missing or extra interface",
    )
    run_case(
        "deadline",
        runner_options={"seconds_per_call": 2.0},
        error="deadline expired",
        deadline=1,
    )
    run_case(
        "nonfinite-deadline",
        error="deadline must be",
        deadline=float("nan"),
    )
    run_case(
        "nonfinite-stable-read",
        error="stable read interval",
        stable=float("nan"),
    )
    run_case(
        "unstable-final-read",
        runner_options={
            "enis": {ENI_A: [DENY_GROUP], ENI_B: [DENY_GROUP]},
            "drift_after_eni_describes": 2,
            "drift_eni": ENI_A,
            "drift_groups": ["sg-aaaaaaaaaaaaaaaaa"],
        },
        error="not stable across the final re-read",
    )


def run_no_replace_and_coverage(
    tool: Any, root: Path, inventory_path: Path, receipt_path: Path
) -> None:
    inv, inv_digest, hosts = tool.load_inventory(inventory_path)
    aggregate = receipt_path.parent / "evidence-set.json"
    value, digest = tool.verify_coverage(
        inventory=inv,
        inventory_digest=inv_digest,
        hosts=hosts,
        receipt_paths=[receipt_path],
        output=aggregate,
        now=fixed_now,
    )
    assert value["required_components"] == [
        "blockd",
        "controller",
        "gateway",
        "node_agent",
        "vmm",
    ]
    replay, replay_digest = tool.verify_coverage(
        inventory=inv,
        inventory_digest=inv_digest,
        hosts=hosts,
        receipt_paths=[receipt_path],
        output=aggregate,
        now=lambda: fixed_now() + dt.timedelta(minutes=1),
    )
    assert replay == value and replay_digest == digest
    aggregate_sidecar = aggregate.with_suffix(".sha256")
    aggregate_sidecar.unlink()
    repaired = tool.read_evidence(aggregate, "aggregate missing checksum")
    assert repaired is not None and repaired[1] == digest and aggregate_sidecar.exists()
    expect_refusal(
        tool,
        lambda: tool.verify_coverage(
            inventory=inv,
            inventory_digest=inv_digest,
            hosts=hosts,
            receipt_paths=[],
            output=root / "missing.json",
            now=fixed_now,
        ),
        "receipt count",
    )
    expect_refusal(
        tool,
        lambda: tool.verify_coverage(
            inventory=inv,
            inventory_digest=inv_digest,
            hosts=hosts,
            receipt_paths=[receipt_path, receipt_path],
            output=root / "duplicate.json",
            now=fixed_now,
        ),
        "receipt count",
    )

    # A same-checksum attacker model is outside this local receipt boundary,
    # but even a deliberately recomputed checksum cannot make omitted component
    # coverage pass the strict inventory parser.
    omitted = root / "omitted-component.json"
    omitted_value = json.loads(receipt_path.read_bytes())
    omitted_value["covered_components"] = omitted_value["covered_components"][:-1]
    omitted.write_bytes(tool.canonical_bytes(omitted_value))
    omitted.chmod(0o600)
    omitted_digest = tool.digest_bytes(omitted.read_bytes()).removeprefix("sha256:")
    omitted.with_suffix(".sha256").write_text(f"{omitted_digest}  {omitted.name}\n")
    omitted.with_suffix(".sha256").chmod(0o600)
    expect_refusal(
        tool,
        lambda: tool.verify_coverage(
            inventory=inv,
            inventory_digest=inv_digest,
            hosts=hosts,
            receipt_paths=[omitted],
            output=root / "omitted-set.json",
            now=fixed_now,
        ),
        "covered_components",
    )

    original = receipt_path.read_bytes()
    receipt_path.write_bytes(original.replace(b'"host_id":"old-local"', b'"host_id":"drift-host"'))
    drifted = receipt_path.read_bytes()
    expect_refusal(
        tool,
        lambda: tool.read_evidence(receipt_path, "drifted receipt"),
        "checksum drifted",
    )
    assert receipt_path.read_bytes() == drifted
    receipt_path.write_bytes(original)
    repaired_digest = tool.digest_bytes(original).removeprefix("sha256:")
    receipt_path.with_suffix(".sha256").write_text(
        f"{repaired_digest}  {receipt_path.name}\n"
    )

    orphan = root / "orphan.json"
    orphan.with_suffix(".sha256").write_text("0" * 64 + f"  {orphan.name}\n")
    expect_refusal(
        tool,
        lambda: tool.read_evidence(orphan, "orphan receipt"),
        "without JSON authority",
    )

    locked = root / "locked.json"
    first_bytes = tool.canonical_bytes({"kind": "first"})
    tool.write_evidence(locked, {"kind": "first"})
    expect_refusal(
        tool,
        lambda: tool.write_evidence(locked, {"kind": "second"}),
        "different bytes",
    )
    assert locked.read_bytes() == first_bytes

    receipt_path.with_suffix(".sha256").chmod(0o644)
    expect_refusal(
        tool,
        lambda: tool.read_evidence(receipt_path, "public checksum"),
        "mode-0600 single-link",
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", required=True)
    arguments = parser.parse_args()
    tool = load_tool(Path(arguments.tool).resolve())
    with tempfile.TemporaryDirectory(prefix="cats-positive-stop-fixture-") as temporary:
        root = Path(temporary)
        inventory_path, local_receipt, _ = run_local_matrix(tool, root)
        _, _, ambiguous_runner, ambiguous_receipt = run_aws_success(
            tool,
            root / "aws-ambiguous",
            attempt="positive-aws-ambiguous",
            ambiguous=True,
        )
        assert all(
            effect["response"] == "ambiguous_response_confirmed"
            for effect in ambiguous_receipt["effects"]
        )
        assert ambiguous_runner.modify_calls == [ENI_A, ENI_B]
        run_aws_success(
            tool,
            root / "aws-response-loss",
            attempt="positive-aws-response-loss",
            ambiguous=False,
            crash_before_final=True,
        )
        run_aws_negative_matrix(tool, root)
        run_no_replace_and_coverage(tool, root, inventory_path, local_receipt)
    print(
        "old-host positive-stop fixture passed: calibrated runtime refusal, descendant/PID-reuse, "
        "absent/failed units, ambiguous EC2 discovery/replay, exact AWS identity/rules/ENIs/stable-deadline, "
        "no-replace, exact coverage"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
