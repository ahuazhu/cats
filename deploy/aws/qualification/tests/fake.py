#!/usr/bin/env python3
"""Stateful contract double for q124 tools; assertions inspect state, not source text."""
import json
import os
import signal
import sys
import time
from pathlib import Path

state_path = Path(os.environ["Q124_FAKE_STATE"])


def load():
    return json.loads(state_path.read_text())


def save(s):
    state_path.write_text(json.dumps(s, sort_keys=True, indent=2))


def record(s, entry):
    s["log"].append(entry)
    save(s)


def node_summary(node, state="cordoned", cats=None, orphans=0, memory=1024):
    cats = cats or []
    return {
        "node": {
            "id": node,
            "state": state,
            "capacity": {"cpus": 1, "memory_mib": memory},
        },
        "assigned_cats": len(cats),
        "orphan_cats": orphans,
        "heartbeat_age_seconds": 1,
    }


def instance(s, source=False):
    if source:
        ident = s["source_instance"]
    else:
        ident = s["instance"]
    tags = {
        "Name": "cats-" + s["node"],
        "CatsIssue": "124",
        "CatsPurpose": "temporary-worker-qualification",
        "CatsNodeId": s["node"],
        "CatsSourceSha": s["source_sha"],
        "CatsRunId": s["run_id"],
    }
    tags.update(s.get("tag_overrides", {}))
    result = {
        "InstanceId": ident,
        "State": {"Name": "running" if source else s["instance_state"]},
        "ImageId": "ami-0124",
        "InstanceType": "c5d.metal",
        "SubnetId": "subnet-0124",
        "SecurityGroups": [{"GroupId": group} for group in s["security_groups"]],
        "IamInstanceProfile": {"Arn": "arn:aws:iam::111122223333:instance-profile/cats-worker"},
        "MetadataOptions": {"HttpTokens": "required", "HttpEndpoint": "enabled"},
        "InstanceInitiatedShutdownBehavior": "stop",
        "PrivateIpAddress": "10.0.1.124",
        "Placement": {"AvailabilityZone": "us-east-1a"},
        "BlockDeviceMappings": [{"DeviceName": s.get("root_device", "/dev/sda1"), "Ebs": {
            "VolumeId": s.get("root_volume_id", "vol-q124"), "DeleteOnTermination": s.get("root_delete_on_termination", True)
        }}],
        "Tags": [{"Key": k, "Value": v} for k, v in tags.items()],
    }
    if source:
        result["Tags"] = [{"Key": "Name", "Value": "source"}]
    return result


def fake_aws(args):
    s = load()
    if args[:1] == ["--region"]:
        args = args[2:]
    service, action = args[:2]
    record(s, f"aws {service} {action} " + " ".join(args[2:]))
    s = load()
    if s.get("credentials_expired"):
        print("ExpiredToken", file=sys.stderr)
        return 255
    if (service, action) == ("sts", "get-caller-identity"):
        print(s["account"])
    elif (service, action) == ("ec2", "describe-instances"):
        if "--instance-ids" in args:
            ident = args[args.index("--instance-ids") + 1]
            if ident == s["source_instance"]:
                items = [instance(s, True)]
            elif ident == s["instance"] and s["instance_state"] != "absent":
                items = [instance(s)]
            else:
                print("unknown instance", file=sys.stderr)
                return 1
        else:
            return_lookup = any(value.startswith("Name=instance-id,Values=") for value in args)
            if return_lookup and s.get("return_lookup_error"):
                print("return lookup failed", file=sys.stderr)
                return 1
            if return_lookup:
                purged = s["instance_state"] == "absent" or (
                    s["instance_state"] == "terminated" and s.get("purge_terminated_inventory")
                )
                items = [] if purged else [instance(s)]
            else:
                items = [instance(s)] if s.get("duplicate") or (s["instance_state"] not in ("absent", "terminated")) else []
                if s.get("conflicting_identity"):
                    other = dict(instance(s))
                    other["InstanceId"] = "i-0def124"
                    items.append(other)
            if (s.get("discovery_multiple") or (return_lookup and s.get("return_lookup_multiple"))) and items:
                other = dict(instance(s))
                other["InstanceId"] = "i-0def124"
                items.append(other)
        print(json.dumps({"Reservations": [{"Instances": items}] if items else []}))
    elif (service, action) == ("ec2", "describe-images"):
        image = {
            "ImageId": "ami-0124",
            "OwnerId": s["ami_owner"],
            "Public": s["ami_public"],
            "State": s["ami_state"],
            "Architecture": s["ami_architecture"],
            "RootDeviceType": s["ami_root_device_type"],
            "RootDeviceName": s["ami_root_device"],
            "VirtualizationType": s["ami_virtualization_type"],
            "EnaSupport": s["ami_ena_support"],
            "BlockDeviceMappings": [
                {"DeviceName": device, "Ebs": {"SnapshotId": snapshot}}
                for device, snapshot in s["ami_mappings"]
            ],
        }
        images = [] if s.get("ami_zero") else [image]
        if s.get("ami_ambiguous"):
            images.append(dict(image))
        print(json.dumps({"Images": images}))
    elif (service, action) == ("ec2", "run-instances"):
        if s.get("run_preaccept_fail"):
            return 1
        if s["instance_state"] != "absent":
            return 1
        tag_json = json.loads(args[args.index("--tag-specifications") + 1])
        tags = {x["Key"]: x["Value"] for x in tag_json[0]["Tags"]}
        s["node"] = tags["CatsNodeId"]
        s["source_sha"] = tags["CatsSourceSha"]
        s["run_id"] = tags["CatsRunId"]
        s["instance_state"] = "pending"
        save(s)
        if s.get("sleep_run_response_loss"):
            time.sleep(s["sleep_run_response_loss"])
            return 1
        if s.get("run_response_lost"):
            return 1
        print(json.dumps({"Instances": [{"InstanceId": s["instance"]}]}))
    elif (service, action) == ("ec2", "describe-volumes"):
        present = s["instance_state"] not in ("absent", "terminated")
        volume = {
            "VolumeId": s.get("root_volume_id", "vol-q124"),
            "Encrypted": s.get("root_encrypted", True),
            "Size": s.get("root_size", 200),
            "VolumeType": s.get("root_type", "gp3"),
            "Attachments": [{
                "InstanceId": s["instance"],
                "Device": s.get("root_device", "/dev/sda1"),
                "State": "attached",
                "DeleteOnTermination": s.get("root_delete_on_termination", True),
            }],
            "Tags": [
                {"Key": "CatsIssue", "Value": "124"},
                {"Key": "CatsPurpose", "Value": "temporary-worker-qualification"},
                {"Key": "CatsNodeId", "Value": s["node"]},
            ],
        }
        print(json.dumps({"Volumes": [volume] if present else []}))
    elif (service, action) == ("ec2", "modify-instance-attribute"):
        ident = args[args.index("--instance-id") + 1]
        if ident != s["instance"]:
            return 1
        value = json.loads(args[args.index("--disable-api-termination") + 1])["Value"]
        s["termination_protection"] = value
        save(s)
    elif (service, action) == ("ec2", "wait"):
        waiter = args[2]
        if waiter == "instance-running":
            s["instance_state"] = "running"
        elif waiter == "instance-terminated":
            s["instance_state"] = "terminated"
        save(s)
    elif (service, action) == ("ec2", "terminate-instances"):
        ident = args[args.index("--instance-ids") + 1]
        if ident != s["instance"] or s.get("tag_overrides"):
            return 1
        s["instance_state"] = "shutting-down"
        save(s)
        print(json.dumps({"TerminatingInstances": [{"InstanceId": ident}]}))
    elif (service, action) == ("ssm", "describe-instance-information"):
        filt = args[args.index("--filters") + 1]
        ident = filt.split("Values=", 1)[1]
        online = ident == s["source_instance"] or (ident == s["instance"] and s["instance_state"] == "running")
        print(json.dumps({"InstanceInformationList": [{"InstanceId": ident, "PingStatus": "Online"}] if online else []}))
    else:
        print(f"unsupported fake aws call: {args}", file=sys.stderr)
        return 2
    return 0


def fake_control(args):
    s = load()
    action = args[0]
    record(s, "control " + " ".join(args))
    s = load()
    node = args[1] if len(args) > 1 else ""
    if action == "get":
        if node == s["source_node"]:
            print(json.dumps(node_summary(node, "ready")))
        elif node == s["node"] and s["control_present"]:
            print(json.dumps(node_summary(node, s["control_state"], s["cats"], s["orphans"], s["memory_mib"])))
        else:
            return 1
    elif action == "absent":
        source, wanted = args[1:3]
        if source != s["source_node"] or (wanted == s["node"] and s["control_present"]):
            return 1
    elif action == "cats-scope":
        if node != s["node"] or not s["control_present"] or s.get("cats_scope_error"):
            return 1
        workspace = args[2]
        if any(c["workspace"] != workspace or not c["name"].startswith(args[3]) for c in s["cats"]):
            return 1
        print(json.dumps([c["id"] for c in s["cats"]]))
    elif action == "wait-cordoned":
        expected_memory = int(args[3])
        if not s["control_present"] or s["control_state"] != "cordoned" or s["cats"] or s["orphans"] or s["memory_mib"] != expected_memory:
            return 1
        print(json.dumps(node_summary(node, memory=s["memory_mib"])))
    elif action == "cordon":
        if not s["control_present"] or s.get("cordon_fail"):
            return 1
        s["control_state"] = "cordoned"
        save(s)
    elif action == "drain":
        workspace = args[2]
        if any(c["workspace"] != workspace or not c["name"].startswith("q124-") for c in s["cats"]):
            return 1
        s["cats"] = []
        s["ledger_cats"] = []
        s["control_state"] = "cordoned"
        save(s)
    elif action == "delete":
        workspace = args[3]
        prefix = args[4]
        if (s["cats"] or s["orphans"] or s["control_state"] not in ("cordoned", "lost")
                or workspace != "ws-q124" or prefix != "q124-"):
            return 1
        if s.get("delete_fail_once") and not s.get("delete_failed_once"):
            s["delete_failed_once"] = True
            s["control_state"] = "lost"
            save(s)
            return 1
        s["control_present"] = False
        save(s)
    else:
        return 2
    return 0


def fake_remote(args):
    s = load()
    ident, action = args[:2]
    record(s, "remote " + " ".join(args))
    s = load()
    if ident != s["instance"]:
        return 1
    if action == "bootstrap":
        if s.get("sleep_bootstrap"):
            time.sleep(s["sleep_bootstrap"])
        if s.get("fail_bootstrap"):
            return 1
        s["prepared"] = True
        save(s)
    elif action == "start":
        if not s["prepared"]:
            return 1
        s["worker_running"] = True
        s["control_present"] = True
        s["control_state"] = "ready" if s.get("start_ready") else "cordoned"
        s["memory_mib"] = 1
        save(s)
    elif action == "set-capacity":
        if not s["worker_running"] or s["control_state"] != "cordoned" or s["cats"]:
            return 1
        s["memory_mib"] = 1024
        save(s)
    elif action == "validate":
        if s.get("root_drift_on_validate"):
            s["root_encrypted"] = False
            save(s)
        if s.get("root_dot_drift_on_validate"):
            s["root_delete_on_termination"] = False
            save(s)
        if s.get("credentials_expire_on_validate"):
            s["credentials_expired"] = True
            s["recover_active_fail"] = True
            save(s)
        if s.get("fail_validate"):
            return 1
        if not s["worker_running"]:
            return 1
        print("validated")
    elif action == "snapshot":
        print(json.dumps({"cats": s["ledger_cats"], "attachments": s["attachments"], "pending_packs": s["pending_packs"]}))
    elif action == "assert-idle":
        if not s["prepared"] or s.get("fail_assert_idle") or s["ledger_cats"] or s["attachments"] or s["pending_packs"]:
            return 1
        if s.get("ready_after_idle"):
            s["control_state"] = "ready"
            save(s)
        if s.get("assignment_after_idle"):
            s["cats"] = [{"id": "cat-race", "workspace": "ws-q124", "name": "q124-race"}]
            save(s)
        print("idle")
    elif action == "stop":
        if not s["prepared"] or s.get("fail_assert_idle") or s["ledger_cats"] or s["attachments"] or s["pending_packs"]:
            return 1
        s["worker_running"] = False
        save(s)
    elif action == "recover-active":
        if s.get("recover_active_fail"):
            return 1
        print("ssm-recovery=terminal")
    else:
        return 2
    return 0


def init():
    save({
        "account": "111122223333", "source_instance": "i-a00124", "source_node": "metal-source",
        "instance": "i-0abc124", "instance_state": "absent", "node": "q124-unset",
        "source_sha": "", "run_id": "", "security_groups": ["sg-0124"],
        "termination_protection": False, "control_present": False, "control_state": "cordoned",
        "cats": [], "ledger_cats": [], "attachments": [], "pending_packs": 0, "orphans": 0,
        "prepared": False, "worker_running": False, "memory_mib": 0,
        "root_device": "/dev/sda1", "root_volume_id": "vol-q124",
        "root_delete_on_termination": True, "root_encrypted": True,
        "root_size": 200, "root_type": "gp3",
        "ami_owner": "111122223333", "ami_public": True, "ami_state": "available",
        "ami_architecture": "x86_64", "ami_root_device_type": "ebs",
        "ami_root_device": "/dev/sda1", "ami_virtualization_type": "hvm",
        "ami_ena_support": True, "ami_mappings": [["/dev/sda1", "snap-0124aaa"]],
        "published_manifests": 0, "log": []
    })


def fake_publish(args):
    s = load()
    record(s, "publish " + " ".join(args))
    s = load()
    if s.get("fail_publish"):
        return 1
    s["published_manifests"] += 1
    save(s)
    return 0


if __name__ == "__main__":
    kind, *args = sys.argv[1:]
    if kind == "init":
        init()
        raise SystemExit(0)
    raise SystemExit({"aws": fake_aws, "control": fake_control, "remote": fake_remote, "publish": fake_publish}[kind](args))
