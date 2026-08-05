# Temporary Node dependency-fault harness

`temp-node-faults.sh` runs one dependency-fault trial against one exact Issue
#124 temporary Node. `temp-node-fault-matrix.sh` is the only supported
multi-window entrypoint. It runs all 13 trials serially and does not start a
later window unless the preceding window passed both its functional and
cleanup gates.

The harness does not provision, withdraw, terminate, delete, fence, or drain a
Node. It never deletes a Cat, disk, database row, or S3 object. Its mutations
are limited to:

- bounded cordon/uncordon of the exact q124 temporary Node while placing the
  next test Cat;
- lifecycle actions on the one exact q124 Cat admitted for the current trial;
- per-window, exact-address iptables rules on the temporary Host, with an
  independently armed rollback timer.

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

The matrix requires two pre-created, non-production q124 Cats: one Strict and
one Relaxed. It may reuse those Cats across serial windows, but every window
runs `prepare-trial` again and captures a new immutable ownership snapshot.
Preparation starts from a Cordoned, orphan-free Node, allows one bounded
uncordon/start placement attempt, requires exact placement and marker identity,
then immediately re-cordons. Any return after uncordon re-cordons through a
RETURN cleanup; failure of that cleanup returns 70 and stops the matrix.

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
of the fault config and hook. Live mode verifies the fixed source worker as a
positive control, the exact target instance and tags, unique Node identity, and
SSM Online state. SSM mutations always use the exact instance ID; tags are
assertions, never selectors.

The reviewed hook must be installed at
`/opt/cats/qualification-124/<TEST_SHA>/q124-fault-workload`, root-owned,
executable, and byte-identical to the Git blob named by the manifest. The
temporary Host also requires root-only
`/etc/cats/qualification-124/fault-targets.json`. PostgreSQL `psql` is a
reviewed, preinstalled temporary-worker dependency for DB observation; neither
the harness nor hook installs it online, and DB/control-plane trials fail
before injection if it is absent.

Secrets remain in fixed root-only Host files. They are passed to clients over
stdin or mode-0600 temporary service files, never argv or evidence. Command
text, SSM output, and all evidence are scanned for credential-like material.

## Fault and probe contract

Before injection the remote helper positively calibrates both TCP and an
authenticated minimal read for every dependency address:

- PostgreSQL: read-only `SELECT 1` using TLS verification and exact `hostaddr`;
- S3: IMDSv2 credentials, signed prefix list and one-byte ranged object read,
  preserving configured TLS SNI and SigV4 host identity;
- control plane: authenticated exact-IP admin read preserving `cats.run` TLS
  identity.

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

State and host-oracle schemas are version 2 and include both `scenario` and
`trial`. They require one exact Cat, durability matching the trial, lifecycle
state/generation/placement, root-disk epoch, local/remote/unpublished
watermarks, marker digest, raw operation IDs, and allowlisted log references.

For control-plane windows, the isolated Host cannot authoritatively report its
own Lost state. A caller-side observer is started first and must write a ready
handshake before SSM fault injection is dispatched. It observes the exact Node
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

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq openssl util-linux coreutils gzip >/dev/null && ./test-results/qualification-20260805/temp-node-faults-linux-mock.sh'

docker run --rm -v "$PWD:/work:ro" -w /work ubuntu:24.04 \
  bash -lc 'apt-get update -qq && apt-get install -y -qq jq python3 coreutils >/dev/null && ./test-results/qualification-20260805/q124-fault-workload-linux-contract.sh'
```

The v2 contract covers all 13 positive windows and calibrated negatives for a
legacy dual-Cat snapshot, trial/durability mismatch, stale ownership, missing
or false external observer, previous-window provenance reuse, false oracle and
Cat-scope mismatch. The remote Linux mock covers successful and partial rule
creation, cleanup/save failures, TERM, SIGKILL/watchdog rollback, IPv6 fail
closed, duplicate run ID, secret rejection, all combinations, transport budget
and reviewed-hook replacement. The hook contract executes prepare RETURN
cleanup (including re-cordon failure) and external-observer positive/API-down
paths against deterministic adapters.
