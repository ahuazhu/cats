## Understand Operations

Create, lifecycle, and delete requests are asynchronous. The control plane records an Operation with an ID, kind, target resource, phase, timestamps, and an optional structured error.

    cats operation ls
    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

Phases move from pending/running to succeeded or failed. A network timeout does not prove that the original mutation failed—look up the accepted Operation before retrying.

## Common error classes

| Code | Meaning | First response |
|----|----|----|
| `unauthenticated` | Missing or expired identity | Run `cats login` again or refresh the browser session. |
| `permission_denied` | Valid identity, wrong Workspace | Run `cats whoami` and check the saved/overridden Workspace. |
| `not_found` | Resource name or ID does not exist in scope | Run the matching list command in the same Workspace. |
| `already_exists` | Name collision | Choose another name or inspect the existing resource. |
| `failed_precondition` | Current lifecycle or attachment state blocks the action | Inspect Cat/Disk state and finish the prerequisite transition. |
| `conflict` | Concurrent generation or RWO conflict | Refresh state; do not force a second writer. |
| `stale_epoch` | Old disk or route owner attempted work | Treat as fenced; rebuild from the current assignment. |
| `unavailable` | Temporary dependency failure | Retry with bounded backoff and inspect the Operation. |

## Cat does not become Ready

1.  Run `cats get NAME --json` and note desired/observed state and node.
2.  Inspect recent Operations and the final error.
3.  Operators check node heartbeat, blockd/Guest readiness, console output, and attachment epoch.
4.  If Suspended/Warm restore failed, verify the controller converged to Cold fallback instead of remaining in an intermediate state.

## Disk cannot mount, resize, or delete

Run `cats disk get NAME`. A PersistentDisk can have only one active read-write Attachment. Unmount it cleanly before moving or deleting it, and follow the current runtime precondition for resize. Never bypass a fencing conflict.

## Auto-suspend does not trigger

    cats sleep status dev

Check active platform/Guest leases, Guest signal freshness, and the printed reason. A stale signal intentionally fails awake. Confirm that long-running applications release expired work and that no shell, exec, deploy, or gateway activation lease remains.

## Control plane is unreachable

Existing Running Cats may continue because API processes are not in the Guest I/O hot path. New lifecycle changes and durable root publication may be delayed or fail closed. Do not claim a FLUSH succeeded while the authoritative metadata CAS is unavailable.

## Useful evidence

When escalating, preserve the request ID, Operation ID, Account/Workspace slug, Cat/Disk name, node ID, generation, attachment/route epoch, timestamps, CLI version, and the structured error. Remove tokens, cookies, Secret values, Guest disk contents, and terminal plaintext.
