# Runtime lifecycle physical-effect ports gap

- Status: Proposed gap note; not a frozen protocol or implementation authority
- Scope: ADR-0040 Runtime Reconciliation v1 Node lifecycle suffix
- Related: [Runtime lifecycle](../runtime-lifecycle.md),
  [Runtime Reconciliation v1](runtime-reconciliation-v1.md), and
  [Volume Authority](volume-authority.md)

## Already closed by the current contracts

`CleanupRelease::Volume` already carries the complete accepted inventory cursor,
exact owner/epoch, immutable release transition identity, generation, and
disposition. The signed Runtime Volume Transitions route can therefore release
Root and Persistent volumes acquired by either Normal or Takeover. A response is
successful only when the signed result, or the current immutable Release marker
and exact Unowned postcondition, matches every field. Multiple volumes are
processed in canonical order with one durable checkpoint token per volume.

An existing `DeleteDisposableRoot { authorization_id }` token can likewise
consume that exact signed authorization and validate the complete consumed
receipt before accepting `Deleting`. This only fences the old writer. It does
not authorize pathname-based removal of the local lineage, object deletion, or
completion of product rows.

`PauseRuntime` and Network cleanup also have sufficient persisted identity.
Their production adapters retain the Node-global exact process/network proof,
use the one effect deadline and cancellation source, and adopt only a fresh
exact physical postcondition.

## Missing production ports with sufficient persisted identity

The following frozen tokens are sufficient to construct a bounded runtime-only
adapter, but no such sealed production port currently exists:

- `SnapshotWarmRuntime`: retain the snapshot-directory descriptor, create the
  exact temporary file without replacement, bound the VMM request, fsync and
  rename exactly that inode, and expose the existing complete
  `WarmSnapshotEvidence` as the only postcondition.
- `StopRuntime` and `CleanupTarget::Scope`: stop only the retained pidfd/systemd
  unit matching incarnation, start time, scope, executable, and ownership
  proof; fresh process absence is the only postcondition.
- `CleanupTarget::Device`: detach only the Node-global frontend reservation
  matching volume and device ownership token; fresh exact device absence is the
  only postcondition.
- `CleanupTarget::WarmSnapshot`, `OrphanScope`, and `ControlSocket`: retain the
  owning directory/cgroup descriptor, revalidate the complete accepted identity
  and ownership token immediately before the operation, never follow a changed
  pathname, and accept only a fresh exact absence scan.
- `CleanupTarget::CheckpointFile`: execute only from the ADR-0040
  `NodeCleanupCheckpoint` single-slot owner after re-reading the full digest and
  Deleted tombstone. A per-Cat checkpoint may not journal deletion of itself.

Until those ports and positive/negative calibrations exist, the dispatcher must
return typed `Unavailable`/refresh without issuing a physical operation. No new
persisted receipt is required merely to implement these ports: an ambiguous
effect retains the same token and is resolved by the specified full inventory
postcondition.

## Drain requires a protocol decision

The current `DrainPublish` token names one volume and its pre-drain L/R
generations. It does not record that the Guest quiesce fence completed, nor a
canonical cursor or complete postcondition for every Desired volume. An older
accepted `R == L` scan cannot substitute for quiesce because Guest/page-cache
writes may occur after that scan.

Before a production Drain adapter is enabled, an accepted ADR/spec amendment
must choose and freeze one replayable representation that proves:

1. the exact runtime incarnation completed Guest quiesce after admission and
   guards closed;
2. every Desired volume is covered exactly once in canonical order;
3. each local durability barrier completed for the exact attachment/epoch;
4. Warm/Cold/Deleted additionally reached exact authoritative `R == L`; and
5. response loss can only retry the same step or adopt a fresh exact
   postcondition.

This may be a separate checkpointed quiesce step followed by per-volume drain
tokens, or one composite drain token with an explicit quiesce identity and
per-volume cursor. It cannot be inferred from existing projections or added as
an undocumented interpretation of the current wire variant.

## Disposable Root local cleanup boundary

After the signed authorization reaches `Deleting`, Node still needs a separate
descriptor-retained cleanup permit bound to the consumed receipt and the exact
local data-directory inode, attachment lineage/origin, checkpoint, and owner
identity. The permit must prove no live Guest, VMM, blockd, device, mount, or
Warm snapshot can access the lineage. Only then may Node remove that exact local
lineage/tail; a fresh full scan must show both authoritative `Absent` and no
local lineage before Deleted can settle.

The Node must not call normal begin-delete or receive object-store credentials.
The V2 sweeper owns object deletion and row completion. If an Owned `R < L`
Root needs this branch, a signed Control selection/evidence read must supply the
authorization ID; Desired contains only `delete_id`, so the planner must not
guess or synthesize an authorization.
