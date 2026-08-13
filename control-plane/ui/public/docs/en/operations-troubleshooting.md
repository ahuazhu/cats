## Understand Operations

Cat create is asynchronous. The control plane returns an ID for the canonical Operation that binds the Cat, desired revision/spec, placement, target, phase, timestamps, and optional terminal result or error.

    cats operation get OPERATION_ID
    cats operation wait OPERATION_ID

An Operation moves from `pending` to exactly one of `succeeded`, `failed`, or `superseded`. Select the same Workspace that accepted the mutation; another Workspace and an absent ID intentionally look identical. Operation list is unavailable. A network timeout does not prove that the original mutation failed—replay the same durable create intent to recover its accepted ID, then query that exact Operation.

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

## Cat does not become Ready after create

1.  Run `cats get CAT_ID --json` and note desired/observed state and node.
2.  Inspect the accepted Operation by ID and its terminal result or error.
3.  Operators check node heartbeat, blockd/Guest readiness, console output, and attachment epoch.
4.  If Suspended/Warm restore failed, verify the controller converged to Cold fallback instead of remaining in an intermediate state.

## A Disk mutation is unavailable

Run `cats disk get DISK_ID` to inspect the current projection. Attachment, snapshot, capacity change, and deletion are outside the release product surface. Do not probe a legacy route or bypass an authority/fencing conflict.

## A lifecycle command is unavailable

Lifecycle and Guest-command clients are intentionally absent during the signed runtime cutover. Preserve the accepted create Operation ID and current Cat projection; do not substitute an old command or route.

## Control plane is unreachable

Existing Running Cats may continue because API processes are not in the Guest I/O hot path. New lifecycle changes and durable root publication may be delayed or fail closed. Do not claim a FLUSH succeeded while the authoritative metadata CAS is unavailable.

## Useful evidence

When escalating, preserve the request ID, Operation ID, Account/Workspace slug, Cat/Disk name, node ID, generation, attachment/route epoch, timestamps, CLI version, and the structured error. Remove tokens, cookies, Secret values, Guest disk contents, and terminal plaintext.
