# Control-plane leader handoff lifecycle harness

`ha-handoff.sh` gives issue #124 a guarded, traceable drill for each lifecycle
handoff: Cold Start, Suspended Resume, Warm Restore, Suspend, Warm, and Stop.
Every durability/scenario/round gets a fresh `q124-ha-*` Cat (three rounds by
default), an in-Guest systemd write/sync sentinel, an HTTP endpoint route, and
an independent public `/healthz` probe.

Every live case is pinned to one exact temporary Node from
`CATS_HA_REQUIRED_NODE_ID`, which must be a `q124-*` identity with exactly
1 CPU and 1 GiB declared capacity. Before each case, a positive administrator
read must prove that exact Node is Cordoned with zero assigned Cats and zero
orphans, and its exact assignment list must be empty. The harness then
uncordons only that Node, creates one 1 CPU/1 GiB `q124-ha-*` Cat, and
immediately re-cordons the Node. It requires the Cat's `node_id` and the
administrator assignment set to contain only that exact Cat. A user Cat race,
wrong-node placement, extra assignment, orphan, capacity mismatch, or ambiguous
admin response fails closed with the temporary Node Cordoned. The harness never
drains, fences, or deletes a Node, and never touches a foreign Cat.

Cold Start and the post-Stop cold-restart oracle each need a new placement.
For those two boundaries the harness opens the same Node only until the exact
q124 Cat has claimed it, then re-cordons it. All other lifecycle work runs while
the Node remains Cordoned. Cleanup destroys only the positively recorded Cat
ID and proves the Node is again Cordoned with exact empty assignments and zero
orphans before the next case.

The harness does not contain `kubectl` and cannot delete a Pod itself. It only
dispatches `verify-control-plane-ha.yml` on `main` with the workflow's exact
`mode=disrupt`, `DELETE_ONE_CATS_CONTROLD_LEADER` confirmation and its
default-off
`LOCK_Q124_LIFECYCLE` mode. That mode is hard-limited to issue 124, workspace
`ws_788c5bfc3931`, and one exact `q124-ha-*` Cat/generation/transition tuple.

The workflow starts a TTL-bound PostgreSQL coordinator Pod before posting an
exact-token `CATS_HA_COORD_READY` trace to issue 124. Only then does the harness
submit the lifecycle Operation. When the exact Cat generation, transitional
state, Operation kind, and active Operation row appear, the coordinator uses a
read-only `SELECT ... FOR UPDATE` plus bounded `pg_sleep` transaction to keep
the old leader from settling that Cat row. The workflow rechecks redundancy,
PDB allowance, PostgreSQL advisory-lock owner, selected leader Pod UID, and
coordinator Pod UID before deletion. Any missing/multiple marker or Operation,
timeout, UID change, or coordinator failure exits before deletion; there is no
fallback to an uncoordinated drill.

After the leader Pod is gone, the row lock is released. The coordinator then
requires the replacement reconciler to converge the same exact Operation ID,
generation, and final state. The harness independently requires the workflow's
lock/deletion/release timestamps to be correctly nested, the Operation ID in
all four markers to equal the originally accepted Operation, and that original
Operation's lifetime to contain the deletion.

Live execution has a separate outer confirmation and pins the q124 workspace,
successful production deployment run, full SUT SHA, and absence of another
production deployment:

```bash
CATS_HA_EXECUTE=RUN_ISSUE_124_HA_HANDOFF \
CATS_SUT_RELEASE_SHA=<40-lowercase-hex> \
CATS_SUT_DEPLOY_RUN_ID=<successful-deploy-run-id> \
CATS_SUT_WORKSPACE_ID=ws_788c5bfc3931 \
CATS_TEST_WORKSPACE=default/qual-124-20260805 \
CATS_HA_REQUIRED_NODE_ID=q124-<exact-temporary-node> \
CATS_HA_ADMIN_NODE_HOOK=/absolute/path/to/installed-q124-admin-node \
CATS_HA_ADMIN_NODE_HOOK_REPO_PATH=test-results/qualification-20260805/live-hooks/q124-admin-node \
CATS_WATERMARK_PROBE_CMD='<reviewed read-only root/SSM probe>' \
  ./test-results/qualification-20260805/ha-handoff.sh
```

Before any Cats, administrator-adapter, or GitHub call, live mode requires the
exact workspace ID `ws_788c5bfc3931`, locator
`default/qual-124-20260805`, API `https://cats.run`, workflow filename, and
repository. A wrong workspace therefore has zero create, uncordon, and dispatch
calls. The adapter must be a regular mode-0700 file owned by the harness user;
its hash is checked against the exact repository path at `CATS_SUT_RELEASE_SHA`
both at startup and immediately before every invocation.

The committed root-only administrator adapter keeps administrator
authentication separate from the workspace CLI session. It is invoked only as
`get NODE`, `cats NODE`,
`cordon NODE`, or `uncordon NODE`. `get`, `cordon`, and `uncordon` return the
single NodeSummary JSON; `cats` returns the JSON array from
`/v1/admin/nodes/{id}/cats`. The adapter must accept the exact node argument,
must write only response JSON to stdout, and must never print a token. A wrapper
around a second Cats CLI/admin configuration or a root-only SSM helper is
appropriate. No drain/fence/delete verb can be requested by the harness.

The public Cat and Operation APIs do not expose blockd's local and remote
watermarks. Live Relaxed Resume/Restore therefore fails before mutation unless
`CATS_WATERMARK_PROBE_CMD` is a separately reviewed, read-only root/SSM probe.
The probe receives `CATS_WATERMARK_CAT_NAME`, `CATS_WATERMARK_CAT_ID`,
`CATS_WATERMARK_WORKSPACE_ID`, and `CATS_WATERMARK_NODE_ID`, and must return
that exact `cat_id` and `node_id` plus non-negative integer
`local_watermark`/`remote_watermark`. The harness verifies the identities,
persists only the two watermark fields, and requires
`local_watermark > remote_watermark`; it never infers backlog from timing or
downgrades the live matrix.

Use `--dry-run` to print the complete matrix without calling Cats, GitHub, or
Kubernetes, and `--validate-fixtures` to exercise the transitional-generation,
stale-operation, watermark, and workflow-log parsers locally. Results include
Cat desired/observed state, generation, node, original Operation and
resource-generation, endpoint route snapshots, leader identities, boot ID,
Guest journal digest/counter, public probe rows, and exact deployment identity.
The exit trap waits for any dispatched workflow and active original Operation,
then destroys only Cats whose exact IDs were positively recorded by this run.
It reports `functional_rc`, `cleanup_rc`, and calibrated exact NotFound evidence
separately; it never prints a bearer token.
Fixture validation also proves that a foreign/user Cat in the temporary Node's
assignment set is rejected. Dry-run output reports whether both the exact Node
and administrator adapter are configured without executing either one.
