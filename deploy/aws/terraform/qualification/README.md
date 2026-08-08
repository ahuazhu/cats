# Existing qualification infrastructure

Status: existing exact-SHA evidence infrastructure. Reuse its native Linux build host and immutable
receipts; do not expand it into a second control plane or a new deployment authority.

The persisted names `architecture-v2`, `G0` and `H2` remain in state keys, resource identities and
machine contracts because renaming live Terraform resources can orphan or replace them. They are
opaque infrastructure identities, not product-protocol compatibility requirements.

## Current ownership

- `bootstrap/` created the isolated state bucket, KMS key and state role. Its local state and approved
  encrypted recovery snapshot are required to manage or retire those resources.
- `build-host/` owns the applied native build host, network/IAM boundary, source/artifact buckets and
  KMS resources.
- `contracts/` and `tools/` validate exact saved plans for those existing states.
- These resources are qualification-only. They never authorize access to production data, runtime
  resources, credentials or DNS.

Repository deletion is not AWS cleanup. Keep this directory until a read-only inventory proves every
managed resource has either moved to a standard Terraform stack or been destroyed through its exact
authoritative state.

## Safe next operation

Before any plan or apply:

1. recover the authoritative bootstrap/build-host state and record its checksum;
2. verify caller account, region, state backend, workspace and all managed resource identities;
3. collect a read-only denylist of production resource IDs, names, DNS names and ARNs;
4. run `terraform plan -refresh-only` and then a normal saved plan;
5. stop if the plan contains an unreviewed create, import, replacement, deletion or cross-boundary read;
6. independently review the exact saved plan before applying that same file.

Do not create a fresh state for resources that already exist. Do not use `-target`, console mutation or
resource import to guess ownership.

## Disposition

Choose one reviewed path for the whole state:

- **Migrate:** move still-useful resources into the standard qualification/platform stacks with
  Terraform state moves/imports, no replacement and a post-move zero-drift plan.
- **Decommission:** stop workloads, preserve required evidence/artifacts, run an exact destroy plan from
  the authoritative state, verify AWS absence and archive the final state/plan receipts.

After either path, confirm the state contains no managed resources and AWS inventory contains no tagged
residue before deleting these compatibility contracts.

The qualification boundary is defined by ADR-0038 and reuses normal Terraform, deployment and test
entry points. Keep using the existing build host while it is healthy; migrate or decommission only
through the reviewed state procedure above.

Exact-source publication, the single readiness probe, native Linux `quality.sh full`, SSM polling and
explicit evidence publication are defined in the [build-host runbook](build-host/README.md). An AWS
authentication failure or missing authoritative local state stops that run; it is not evidence that
the remote qualification cell is absent and does not authorize creating a replacement.
