## The four states

| State | Process memory | Host-bound | Return to Running |
|----|----|----|----|
| **Running** | Resident as needed | Yes | Already active |
| **Suspended** | Preserved; pages may move to local NVMe | Yes | Resume and demand-refault |
| **Warm** | Preserved in a local VM snapshot; VMM exits | Yes | Rebuild runtime and restore |
| **Cold** | Not preserved | No | Fresh boot from durable disks |

Suspended and Warm are intentionally separate. Both preserve process state and depend on the original host. Cold releases that dependency and starts a new kernel and user processes.

## Lifecycle commands

    cats start dev
    cats suspend dev
    cats warm dev
    cats resume dev
    cats stop dev
    cats get dev

- `start` starts or wakes a Cat.
- `suspend` pauses the Guest after the durable disk gate succeeds and pages reclaimable Guest memory to the Host's local state filesystem.
- `warm` creates a host-local snapshot and exits the VMM/backend.
- `resume` resumes either Suspended or Warm.
- `stop` enters Cold and releases runtime attachment leases.

## The durable gate

Before entering Suspended, Warm, or Cold, Cats quiesces new work, asks the Guest to sync filesystems, and waits for required block FLUSH operations to publish a durable generation. A failed FLUSH prevents the platform from claiming a safe sleep state.

**What survives host loss?**

Successful durable FLUSH data survives. Suspended/Warm process memory does not: if the original host is permanently lost, Cats fences the old attachment and performs Cold recovery on another host.

## Fast-resume fallback

A missing backing file, invalid snapshot, version mismatch, VMM error, or Guest readiness timeout must not leave a Cat stuck in a restore state. The platform discards the unsafe local state, obtains a newer disk fencing epoch when required, and converges to Cold boot.

## Work-driven auto-suspend

New Cats enable it by default. Inspect it, disable it for an always-on workload, or turn it back on:

    cats create dev
    cats sleep status dev
    cats sleep off dev
    cats sleep on dev

The status output includes the distributed work count, Guest-signal freshness, current eligibility, and an explanation. If the signal chain is stale or uncertain, the safe behavior is fail-awake. A background workload must hold a Guest work lease or explicitly disable auto-suspend.

The same opt-in policy continues a stable Suspended Cat to Warm after 10
minutes, then a stable Warm Cat to Cold after 24 hours. These clocks begin when
the observed state is committed, survive control-plane restarts, and are
rechecked against live work before each transition. Operators can change or
disable the two boundaries with
`CATS_AUTO_WARM_AFTER_SECONDS`/`CATS_AUTO_COLD_AFTER_SECONDS`; `0` disables
that boundary.

## Absolute expiry

A Cat can carry an absolute expiry: once the time passes, the control plane deletes it exactly as `cats destroy` would. The root disk goes with it; persistent disks survive. Reclamation happens inside the control plane; nothing outside it has to track the deadline.

    cats create scratch --expires-in 28800
    cats expiry scratch                 # show
    cats expiry scratch --in 28800      # renew: 8 more hours from now
    cats expiry scratch --at 1790000000
    cats expiry scratch --never         # keep it

Every `cats ls` row carries `expires=`: the time left, `never`, or `overdue`.

Renewal writes a new absolute time (`PUT /cats/{cat}/expiry`), so retries and replays need no special rules. A Cat without an expiry never expires.

## Connections and time

Preserving Guest memory does not promise that old TCP or WebSocket connections survive. Edge, NAT, and remote peers may time out while the Cat sleeps. Clients should reconnect through the stable Endpoint. Guest time must not move backward across pause/resume.

## Deletion

`cats destroy dev` stops new work, finishes the lifecycle operation, deletes the Cat, and cascades deletion to its RootDisk. It safely detaches but does not delete an independent PersistentDisk.
