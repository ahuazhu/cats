# Temporary Node dependency-fault harness

`temp-node-faults.sh` runs one dependency-fault trial against one exact Issue
#124 temporary Node. `temp-node-fault-matrix.sh` is the only supported
multi-window entrypoint. It runs all 13 trials serially and does not start a
later window unless the preceding window passed both its functional and
cleanup gates.

The harness does not provision, withdraw, terminate, delete, fence, or drain a
Node. It never deletes a Cat, disk, database row, or S3 object. The reviewed
worker hook has no control-plane administrator capability. Its mutations are
limited to per-window, exact-address iptables rules on the temporary Host and
host-local test I/O, with an independently armed rollback timer.

The future live controller must perform bounded cordon/uncordon and lifecycle
actions from an independent runner; those actions are intentionally unavailable
in the worker hook.

## Trial matrix

Every harness invocation requires an exact `CATS_FAULT_SCENARIO` and
`CATS_FAULT_TRIAL`. `all` and `matrix` are rejected by the single-window
harness so evidence from different windows cannot share a run directory or
ownership baseline.

| Scenario | Trial | Cat durability |
|---|---|---|
| `db` | `db-running` | Strict |
| `db` | `db-cold-start` | Strict |
| `s3` | `s3-strict` | Strict |
| `s3` | `s3-relaxed` | Relaxed |
| `control-plane` | `control-plane-running` | Strict |
| `db-s3` | `db-s3-strict`, `db-s3-relaxed` | matching suffix |
| `db-control-plane` | `db-control-plane-strict`, `db-control-plane-relaxed` | matching suffix |
| `s3-control-plane` | `s3-control-plane-strict`, `s3-control-plane-relaxed` | matching suffix |
| `all-3` | `all-3-strict`, `all-3-relaxed` | matching suffix |

The Node capacity contract is one CPU / one GiB and at most one admitted Cat.
Every ownership and state schema requires exactly one Cat. The former dual-Cat
S3 contract is a calibrated known-negative and fails closed.

## Live matrix

> **DO NOT RUN LIVE yet.** The safety audit found that the original workload
> hook expected the control plane's global `CATS_ADMIN_TOKEN` to be persisted
> on the worker as `/etc/cats/qualification-124/admin-token`. The immutable
> worker guard rejects that legacy file, and the worker hook source no longer
> contains an administrator token loader, admin endpoints, Node mutations,
> lifecycle actions, API snapshots, preparation, or Lost observer. The external
> re-cordon watchdog is implemented, but an independent runner still must
> implement every prepare/snapshot/action/observer exchange before live mode can pass. Fixture,
> matrix, guard, watchdog, and firewall contracts remain runnable.

The planned live matrix requires two pre-created, non-production q124 Cats: one
Strict and one Relaxed. It may reuse those Cats across serial windows, but every
window must request independent-runner preparation and a new immutable
ownership snapshot. Preparation must start from a Cordoned, orphan-free Node,
allow one bounded uncordon/start placement attempt, require exact placement and
marker identity, and immediately re-cordon. No part of that sequence may run on
the temporary worker.

Required variables include:

```sh
export TEMP_INSTANCE_ID=i-0123456789abcdef0
export NODE_ID=q124-20260805000000-abcdef
export CATS_PROVISIONING_MANIFEST=/absolute/path/to/provisioning-manifest.json
export CATS_FAULT_OWNERSHIP_ROOT=/absolute/path/to/new-ownership-directory
export CATS_FAULT_RESULT_ROOT=/absolute/path/to/new-result-directory
export CATS_FAULT_STRICT_CAT_ID=cat_...
export CATS_FAULT_STRICT_CAT_NAME=q124-...
export CATS_FAULT_RELAXED_CAT_ID=cat_...
export CATS_FAULT_RELAXED_CAT_NAME=q124-...
export CATS_FAULT_MATRIX_CONFIRM="RUN_Q124_MATRIX_${TEMP_INSTANCE_ID}_${NODE_ID}"
./test-results/qualification-20260805/temp-node-fault-matrix.sh
```

The matrix writes a manifest containing each unique window run ID, exact
scenario/trial/durability, timestamps, ownership path and SHA-256, and result.
On the first failure it records that window and exits before starting another.

## Identity and tooling gates

The provisioning manifest binds the AWS account, region, exact instance and
Node IDs, launch time, expiry, Issue/Purpose/Node tags, `TEST_SHA`, and SHA-256
of the fault config, immutable guard, and hook. Live mode verifies the fixed source worker as a
positive control, the exact target instance and tags, unique Node identity, and
SSM Online state. SSM mutations always use the exact instance ID; tags are
assertions, never selectors.

The reviewed hook and guard must be installed at
`/opt/cats/qualification-124/<TEST_SHA>/q124-fault-workload`, root-owned,
and `/opt/cats/qualification-124/<TEST_SHA>/q124-fault-guard`, root-owned,
executable, and byte-identical to the Git blobs named by the manifest. The guard
checks every ancestor, ownership, mode, and SHA before every hook call. The
temporary Host also requires root-only
`/etc/cats/qualification-124/fault-targets.json`. PostgreSQL `psql` is a
reviewed, preinstalled temporary-worker dependency for DB observation; neither
the harness nor hook installs it online, and DB/control-plane trials fail
before injection if it is absent.

The global admin token must not exist on the worker. The independent
`.github/workflows/q124-recordon-watchdog.yml` run obtains it transiently from
the live Kubernetes Secret through OIDC, stores it only in a runner-temporary
0600 file, masks and removes it, and passes it to curl over config stdin. The
token never appears in workflow inputs, manifest, argv, systemd, journal, or
evidence. Before any future uncordon, the parent must wait for the external run
to publish a unique Issue-124 `armed` marker bound to the exact Node, workspace,
workflow run and 128-bit window nonce. The watchdog retries until authoritative
Cordoned or a hard deadline; it does not depend on parent cancellation.

## Fault and probe contract

Before injection the remote helper positively calibrates both TCP and an
authenticated minimal read for every dependency address:

- PostgreSQL: read-only `SELECT 1` using TLS verification and exact `hostaddr`;
- S3: IMDSv2 credentials, signed prefix list and one-byte ranged object read,
  preserving configured TLS SNI and SigV4 host identity;
- control plane: unauthenticated exact-IP `/healthz` read preserving `cats.run`
  TLS identity. Authoritative Node/Cat reads belong only to the independent
  runner and are not used as the worker's connectivity probe.

An empty/negative probe is not trusted until that same probe passed its known
positive. If IPv6 is routable, non-empty AAAA resolution and equivalent IPv6
rules/probes are mandatory.

Each dependency receives unique IPv4/IPv6 chains, comment, cleanup ledger and
systemd watchdog. Combination dependencies must not share an address/port
tuple. The helper proves every dependency negative, runs the trial-specific
workload, and requires a positive firewall counter delta. Combination recovery
is ordered and checked after every step: DB→S3; control-plane→DB;
control-plane→S3; or control-plane→DB→S3.

Cleanup runs on success, error, TERM and ordinary session loss. The independent
watchdog covers SIGKILL/SSM loss. Cleanup success requires both command success
and strict absence of the unique comments/chains. A cleanup error remains a
non-zero `cleanup_rc` even if a later retry removes the rules.

## State and oracle evidence

State and host-oracle schemas are version 2 and include `window_id`, a unique
128-bit `window_nonce`, `scenario`, and `trial`. They require one exact Cat, durability matching the trial, lifecycle
state/generation/placement, root-disk epoch, local/remote/unpublished
watermarks, marker digest, raw operation IDs, and allowlisted log references.

For control-plane windows, the isolated Host cannot authoritatively report its
own Lost state. An independent-runner observer must start first and write a ready
handshake while the Node is authoritatively Cordoned before SSM fault injection
is dispatched. The Host emits the same nonce only after the actual rules are
installed; the caller then writes the observer's armed barrier. The observer
rejects any Lost transition before that barrier. It observes the exact Node
transition to Lost and back to Cordoned while preserving the exact Cat claim
and generation. The host oracle contains only host-local ledger/blockd/marker
facts and is forbidden from claiming `node_lost_observed`. The caller writes
`oracle-isolated-merged.json` and validates that the Lost claim comes only from
`external-observer.json`. Observer/API disconnect, missing evidence, false
checks, generation mismatch, or stale/reused window provenance all fail closed.

DB+control-plane and all-three windows use the immutable before-fault admitted
set plus fresh host-local evidence while both authoritative remote stores are
unreachable. This is not treated as a control-plane Lost observation; only the
external observer supplies that fact.

## Local contracts

These commands perform no AWS or production calls:

```sh
./test-results/qualification-20260805/temp-node-faults-contracts.sh
./test-results/qualification-20260805/temp-node-fault-matrix-contract.sh

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq openssl util-linux coreutils gzip >/dev/null && ./test-results/qualification-20260805/temp-node-faults-linux-mock.sh'

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq python3 ripgrep coreutils >/dev/null && ./test-results/qualification-20260805/q124-fault-workload-linux-contract.sh'

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq ripgrep coreutils >/dev/null && ./deploy/aws/qualification/tests/q124-recordon-watchdog-contracts.sh'

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq ripgrep coreutils >/dev/null && ./deploy/aws/qualification/tests/q124-admin-node-runner-contracts.sh'

Q124_SCAN_BASE_SHA=<review-base-sha> \
  ./test-results/qualification-20260805/q124-capability-leak-contract.sh
```

The v2 contract covers all 13 positive windows and calibrated negatives for a
legacy dual-Cat snapshot, trial/durability mismatch, stale ownership, missing
or false external observer, previous-window provenance reuse, false oracle and
Cat-scope mismatch. The remote Linux mock covers successful and partial rule
creation, cleanup/save failures, TERM, SIGKILL/watchdog rollback, IPv6 fail
closed, duplicate run ID, secret rejection, all combinations, transport budget
and reviewed-hook replacement. The hook contract proves the worker uses the
public health probe without either capability, rejects all legacy administrator
entry points, fails closed on disconnect, pins the Node-agent origin to
loopback, and contains no global admin endpoint or lifecycle mutation path.
