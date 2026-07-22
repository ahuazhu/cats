## Purpose and discovery

Applications inside a Cat use work leases to say “keep this Cat Running while this task is active.” The API is HTTP/1.1 plus JSON on a Guest-local Unix socket:

    /run/cats/runtime.sock

    curl --unix-socket /run/cats/runtime.sock \
      http://cats-runtime/v1/work-leases

There is no default TCP or UDP listener, no required Cats SDK, and no control-plane or object-store credential in the protocol. Any HTTP client that supports Unix sockets can use it.

## Create a work lease

    curl --unix-socket /run/cats/runtime.sock \
      -H 'Content-Type: application/json' \
      -d '{"label":"release-build","ttl_ms":300000}' \
      http://cats-runtime/v1/work-leases

Success returns `201 Created`, a generated opaque lease ID, and remaining TTL. The default TTL is five minutes, the maximum is one hour, and a Guest may have at most 64 live leases.

## Renew and release

    curl --unix-socket /run/cats/runtime.sock \
      -X PUT -H 'Content-Type: application/json' \
      -d '{"ttl_ms":300000}' \
      http://cats-runtime/v1/work-leases/LEASE_ID

    curl --unix-socket /run/cats/runtime.sock \
      -X DELETE \
      http://cats-runtime/v1/work-leases/LEASE_ID

Renew at roughly one third of the TTL. DELETE is idempotent and returns `204` even when the lease already expired. Always release in success, failure, and cancellation paths; TTL is the crash-recovery boundary.

## Inspect status

    curl --unix-socket /run/cats/runtime.sock \
      http://cats-runtime/v1/work-leases

The response contains `source_epoch`, monotonic `lease_sequence`, `quiescing`, and the current leases. IDs and sequences are opaque coordination values, not user identity or a durable cursor.

## Stable errors

| HTTP | Code | Action |
|----|----|----|
| 400 | `invalid_request` / `invalid_json` | Fix fields, TTL, or JSON. |
| 404 | `lease_not_found` | Create a new lease if work is still active. |
| 409 | `activity_changed` | Suspend quiesce raced with new work; retry after the Cat remains Running. |
| 429 | `too_many_leases` | Release or consolidate callers. |

## Important semantics

- A lease blocks work-driven suspend; it does not prove a Linux process is alive.
- The socket cannot wake an already sleeping Cat because Guest code cannot run then.
- If the socket exists but acquire/renew fails, the keep-awake guarantee was not established.
- On a normal local machine, an application may detect that the socket is absent and continue according to its own policy.

**Do not silently ignore failures inside Cats**

If correctness depends on staying Running, surface acquire or renewal failure and decide whether the task should stop.
