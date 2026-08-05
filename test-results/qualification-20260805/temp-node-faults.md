# Temporary Node dependency-fault harness

`temp-node-faults.sh` is the executable companion to
`temp-node-qualification-runbook.md`. It does not provision, drain, fence,
withdraw, or terminate a Node. It only isolates one dependency from one exact
temporary instance after the runbook's admission and ownership gates have
passed.

The default is `dry-run`, and the default scenario is only `db`. `all` is
accepted only with `CATS_FAULT_ALLOW_ALL=true`; even then, DB, S3, and control
plane run serially. The next SSM command is not submitted unless the previous
scenario produced both `functional_rc=0` and `cleanup_rc=0`, its rules are
absent, its original probes recover, and its q124 workload converges.

## Inputs and safety gates

Required non-secret inputs:

```sh
export TEMP_INSTANCE_ID=i-0123456789abcdef0
export NODE_ID=q124-20260805000000-abcdef
export CATS_OWNERSHIP_SNAPSHOT=/absolute/path/to/fresh-ownership.json
export CATS_PROVISIONING_MANIFEST=/absolute/path/to/provisioning-manifest.json
export CATS_FAULT_SCENARIO=db       # db, s3, control-plane; one by default
```

The strict ownership JSON must bind the exact instance and Node to Issue 124 and
`ws_788c5bfc3931`, report `node_state=Cordoned`, zero orphans, the deployed
`TEST_SHA`, the runtime dependency endpoints, and the exact assigned Cat set.
Every Cat must be `q124-*`, owned by that workspace, and placed on that Node.
Live snapshots must be less than five minutes old. The Host hook re-snapshots
immediately before injection, under isolation, and after recovery; every copy
must remain Cordoned, have zero orphans, and have the identical Cat-set hash.

The strict provisioning manifest binds the instance ID, unique Node ID, account,
region, Name, launch time, expiry no more than 24 hours after launch, complete
qualification tags, `TEST_SHA`, and expected SHA-256 values of the Host config
and hook. At live start the harness requires at least ten minutes of TTL,
compares EC2 `LaunchTime` and every required tag, and proves that the exact
temporary instance is the only non-terminated EC2 instance with that Node ID.
The fixed production source ID is not configurable and cannot equal the target.

Live mode additionally requires the exact confirmation string:

```sh
export CATS_FAULT_MODE=live
export CATS_FAULT_CONFIRM="RUN_Q124_FAULT_${TEMP_INSTANCE_ID}_${NODE_ID}_${CATS_FAULT_SCENARIO}"
./test-results/qualification-20260805/temp-node-faults.sh
```

Before `send-command`, the harness checks AWS account `869621413820`, uses the
fixed known source worker as a positive control, re-reads the exact instance by
ID, validates it against the provisioning manifest, and
requires both the control and temporary instances to be SSM Online. The only
SSM target is `--instance-ids "$TEMP_INSTANCE_ID"`; tags are never selectors.

The harness has no security-group, RDS, S3 policy, DNS, admin-fence, or fleet
mutation commands. No API token or secret is accepted. The SSM command contains
only identifiers, a compressed non-secret helper, and references to two
root-owned files. It rejects references containing `token`, `password`,
`secret`, or `worker.env`.

## Required Host references

The temporary Host must already contain:

- `/etc/cats/qualification-124/fault-targets.json`, root:root mode 0600. Its
  top-level keys must be exactly `schema_version`, `db_host`, `db_port`,
  `s3_host`, `s3_port`, `control_plane_host`, `control_plane_port`,
  `node_listen_ip`, `node_listen_port`, `fault_duration_seconds`, and
  `control_plane_lease_timeout_seconds`. No extra or secret field is accepted;
- `/usr/local/libexec/cats/q124-fault-workload`, root-owned, mode 0700 or 0750.

Provisioning records both SHA-256 values in the manifest. Before any snapshot or
network mutation, the helper hashes both files and itself and requires exact
matches. It records those values plus the local harness SHA, `TEST_SHA`, run ID,
firewall comments and chain names in `provenance.json`. A Host-wide nonblocking
`flock` and never-reused state directory reject concurrent or duplicate runs.

The hook may read the existing Host-local root-only credential file internally.
It must not print credentials, authorization headers, environment dumps, or
file contents. Its interface is:

```text
snapshot --scenario S --workspace-id W --node-id N --instance-id I --output F
ensure-cordoned --workspace-id W --node-id N --output F
probe    --scenario S --address IP --port P
state    --scenario S --phase before|during|after --workspace-id W --node-id N --output F
exercise --scenario S --phase isolated|recovered --workspace-id W --node-id N --output F
assert   --scenario S --before F --during F --after F
```

The same root-only executable must also implement the HA adapter contract:
`get NODE`, `cats NODE`, `cordon NODE`, and `uncordon NODE`. `get`, `cordon`, and
`uncordon` write only the single administrator `NodeSummary` JSON to stdout;
`cats` writes only the exact assigned-Cat JSON array. The executable must reject
all other Node IDs and verbs and must not expose drain, fence, delete, or secret
output. This lets `ha-handoff.sh` use the identical SHA-pinned adapter without a
second credential surface. `ensure-cordoned` is its idempotent file-output
wrapper used here after test Cats have been placed.

For Relaxed Cats, the hook's read-only watermark probe receives the exact Cat,
workspace, and Node identities and returns only `cat_id`, `node_id`, and
non-negative integer `local_watermark`/`remote_watermark`. The hook validates
the identities before copying the two integers into the allowlisted state JSON;
it never stores the original response or credentials.

`probe` must perform a real minimal dependency read against the exact supplied
IP while preserving the configured TLS/DNS identity (PostgreSQL `SELECT 1`, a
small authenticated S3 object read, or a control-plane health/read request).
`exercise` writes a structured oracle and returns success only when the
scenario-specific q124 workload observed every required behavior—never merely
because the dependency call failed. The harness independently requires the
following boolean evidence:

- DB isolated: ordinary Running exec was observed; metadata/CAS, sync, Cold,
  retrying old starts, and new starts produced no false success; no corruption.
  Recovery must reconnect, converge pending operations, and verify the digest.
- S3 isolated: Strict sync/Cold produced no false success; Relaxed local fsync
  remained observable while remote sync/drain produced no false durability;
  local/remote watermarks and unpublished counts were captured. Recovery must
  sync both Cats, converge watermarks, reach unpublished zero, and Cold-restore
  both digests.
- Control-plane isolated: the hook waited lease timeout plus five seconds,
  observed Lost and Unknown/pending, preserved claims, and proved no implicit or
  admin fence and no generation/epoch replacement. Recovery must prove the same
  Node identity, complete inventory, placement, generation, disk epoch, and
  digest.

`assert` then checks the full before/during/after relationship as a second
oracle.

Every `state` JSON must preserve these evidence fields. S3 snapshots must have
exactly one Strict and one Relaxed Cat entry; the other scenarios need at least
one entry:

```json
{
  "schema_version": 1,
  "captured_at": "...",
  "workspace_id": "ws_788c5bfc3931",
  "scenario": "s3",
  "node_id": "q124-*",
  "cats": [
    {
      "cat_name": "q124-*",
      "cat_id": "cat_*",
      "durability": "strict",
      "desired_state": "running",
      "observed_state": "running",
      "generation": 1,
      "node_id": "q124-*",
      "operation_ids": [],
      "watermark": {"local": 1, "remote": 1, "unpublished": 0},
      "disk_epoch": 1,
      "digest": "sha256:..."
    }
  ],
  "raw_operations": [
    {"operation_id":"op_*","kind":"...","phase":"...",
     "started_at":"...","completed_at":"...","log_ref":"journal://..."}
  ],
  "log_refs": ["journal://..."]
}
```

## Fault state machine and rollback

The remote helper resolves and freezes the exact A addresses before injection.
If the Host has a default IPv6 route, it requires a non-empty AAAA set,
successful `ip -6 route get` for every address, and equivalent `ip6tables`
rules; an empty IPv6 resolution is a failure, not a skipped probe. It proves the
same TCP path and the hook's
real small read are positive, creates per-run chains and comments, then requires
both probes to become negative. Control-plane isolation also rejects ingress
TCP 7301 only on the temporary Host.

Each fault has two independent rollback paths:

1. an idempotent cleanup script invoked by the helper on success, failure, or
   signal;
2. a transient systemd timer scheduled for the configured fault duration plus
   30 seconds (lease timeout plus 35 seconds for the control plane), with
   automatic cleanup retry. The timer must be active before the first rule.

After negative probes, the helper records a counter baseline. The controlled
workload must produce a positive counter delta, proving it traversed the actual
isolated dependency. Cleanup accumulates every xtables and save failure in a
ledger, treats command success separately from comment absence, and never stops
the watchdog until strict IPv4/IPv6 absence succeeds. Any cleanup error remains
`cleanup_rc != 0` even when a retry eventually removes the rules. The helper
removes its exact jump and chains, proves its unique comment is absent from both IPv4 and IPv6 rule
sets, waits for the same TCP and real-read probes to recover, runs the recovery
workload, and validates digest/convergence. A control-plane recovery additionally
requires unchanged Cat generation, placement Node, and disk epoch. It never
invokes admin fence.

Evidence is written under
`test-results/qualification-20260805/raw/temp-node-faults/<run-id>/`, including
the local ownership snapshot, exact instance identity, SSM command ID, state
snapshots, timeline, counters, and separate `functional_rc`/`cleanup_rc`.
EC2 evidence is projected to an explicit allowlist. SSM output is scanned
quietly before persistence and replaced with a rejection marker if it resembles
credentials, cookies, signed headers, access keys, private keys, credentialed
URLs, or JWTs. All JSON evidence rejects unknown fields.

`CATS_FAULT_SCENARIO=all` is deliberately only the serial three-single-fault
gate; it is not evidence for simultaneous dependency failure. R10 simultaneous
pair/all-three isolation requires separate per-dependency chains, timers and
recovery ordering and is tracked separately until that implementation lands.

## Local validation

No AWS call is made by either command:

```sh
CATS_FAULT_MODE=dry-run \
TEMP_INSTANCE_ID=i-0123456789abcdef0 \
NODE_ID=q124-20260805000000-abcdef \
CATS_OWNERSHIP_SNAPSHOT=test-results/qualification-20260805/temp-node-faults.fixture.json \
CATS_PROVISIONING_MANIFEST=test-results/qualification-20260805/temp-node-faults.provisioning.fixture.json \
./test-results/qualification-20260805/temp-node-faults.sh

CATS_FAULT_MODE=fixture CATS_FAULT_SCENARIO=all CATS_FAULT_ALLOW_ALL=true \
TEMP_INSTANCE_ID=i-0123456789abcdef0 \
NODE_ID=q124-20260805000000-abcdef \
CATS_OWNERSHIP_SNAPSHOT=test-results/qualification-20260805/temp-node-faults.fixture.json \
CATS_PROVISIONING_MANIFEST=test-results/qualification-20260805/temp-node-faults.provisioning.fixture.json \
./test-results/qualification-20260805/temp-node-faults.sh
```

Fixture mode exercises the serial orchestration and evidence validators without
claiming that packet filtering or production behavior was tested.

The Linux mock additionally executes the embedded remote helper and its cleanup
script against mock xtables/systemd adapters. It covers successful isolation,
partial chain creation, xtables-save failure and error ledger, TERM cleanup,
KILL/SSM interruption with watchdog retry, routable IPv6 with an empty AAAA
set, duplicate RUN_ID, and a secret extra JSON field:

```sh
docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq openssl util-linux coreutils gzip >/dev/null && ./test-results/qualification-20260805/temp-node-faults-linux-mock.sh'
```
