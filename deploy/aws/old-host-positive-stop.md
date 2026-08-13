# Old Host positive stop/isolation program

[`old-host-positive-stop.py`](old-host-positive-stop.py) implements the
[Proposed E13 format](../../docs/specs/old-host-positive-stop-v1.md). It is a
maintenance-window tool, not an automatic fencing controller. The format is
not accepted by the production reset executor; a successful command does not
make `production-clean-slate-reset.py apply --execute` available.

Use only the copy carried by the exact reviewed manual worker bundle. Keep the
canonical inventory and evidence in an actor-owned mode-0700 directory outside
the checkout. The inventory must list every old Host/component pair and the
closed five-component set; the tool refuses a partial fleet manifest.

Review the inventory bytes and digest before the window:

```sh
chmod 0600 /absolute/private/e13/old-host-inventory.v1.json
python3 /absolute/reviewed/old-host-positive-stop.py verify --help
sha256sum /absolute/private/e13/old-host-inventory.v1.json
```

For a local Host, derive the inventory identity from that exact boot. The
machine digest is over the validated 32-lowercase-hex machine ID with surrounding
ASCII whitespace removed:

```sh
python3 -c 'import hashlib; print("sha256:" + hashlib.sha256(open("/etc/machine-id", "rb").read().strip()).hexdigest())'
cat /proc/sys/kernel/random/boot_id
```

On a reachable exact local Host, after maintenance admission is closed and the
Node is cordoned/drained, run as root. The inventory supplies the exact
machine-id digest, boot ID, `require-idle-worker` path, metering cgroup root,
runtime binary root, units and executable paths:

```sh
sudo python3 /absolute/reviewed/old-host-positive-stop.py local-stop \
  --inventory /absolute/private/e13/old-host-inventory.v1.json \
  --host-id REPLACE_WITH_EXACT_HOST_ID \
  --output /absolute/private/e13/REPLACE_WITH_HOST_ID.json \
  --deadline-seconds 60 \
  --stable-read-seconds 2 \
  --confirm-attempt-id REPLACE_WITH_EXACT_ATTEMPT_ID \
  --execute
```

Do not use this path if `require-idle-worker` or the independent process scan
finds a VMM/blockd. In particular, do not stop a raw runtime process to make the
probe pass: it may hold the only `R < L` data.

For an unreachable/externally isolated EC2 Host, run from the maintenance
actor outside the target failure domain. The inventory supplies the exact
account, region, instance, VPC, deny-all Security Group and complete ENI set:

```sh
python3 /absolute/reviewed/old-host-positive-stop.py ec2-isolate \
  --inventory /absolute/private/e13/old-host-inventory.v1.json \
  --host-id REPLACE_WITH_EXACT_HOST_ID \
  --output /absolute/private/e13/REPLACE_WITH_HOST_ID.json \
  --deadline-seconds 120 \
  --stable-read-seconds 2 \
  --confirm-attempt-id REPLACE_WITH_EXACT_ATTEMPT_ID \
  --execute
```

The EC2 result proves only the exact twice-read deny-all SG attachment. It is
not an ADR-0040 `HostFenceEvent`, does not revoke IAM/object-store credentials,
and does not establish the provider object-write cutoff/late-PUT barrier.

After every expected Host has a retained Host receipt, build the exact coverage
index. Supply one `--receipt` per inventory Host; omission, duplication and
extra receipts all fail:

```sh
python3 /absolute/reviewed/old-host-positive-stop.py verify \
  --inventory /absolute/private/e13/old-host-inventory.v1.json \
  --receipt /absolute/private/e13/OLD_HOST_1.json \
  --receipt /absolute/private/e13/OLD_HOST_2.json \
  --output /absolute/private/e13/evidence-set.v1.json
```

Retain every inventory, intent, Host receipt, evidence-set JSON and `.sha256`
sidecar. JSON files are the immutable authority; sidecars are derived. Never
edit or replace a receipt. Exact replay re-verifies the live postcondition and
does not repeat a stop/ENI modification. An intent with an incomplete physical
postcondition blocks same-attempt replay; preserve it and investigate before a
new reviewed attempt.
