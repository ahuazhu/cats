## Access the fleet boundary

Use the administrator console on the dedicated operations site or sign in through the CLI. WorkOS access requires the configured administrator Organization and `cats:fleet:admin` permission by default. Fleet automation may instead use the separate break-glass administrator machine credential.

    cats login
    cats admin monitoring
    cats admin nodes

    # Break-glass automation only:
    CATS_TOKEN='administrator-credential' cats admin monitoring

**Not a user credential**

The administrator machine token is a fleet automation/break-glass identity. Do not hand it to users, embed it in the console, or put it in a Guest.

## Read fleet monitoring

`cats admin monitoring` reports Cat lifecycle counts, node states, CPU/memory assignments, and Operation phases. The administrator console adds auto-refresh, host telemetry, and raw Prometheus metrics. Investigate per-node and per-workspace data rather than relying only on fleet averages.

## Node actions

    cats admin node get node-a
    cats admin node cordon node-a
    cats admin node drain node-a
    cats admin node uncordon node-a
    cats admin node fence node-a --confirm-host-stopped-or-isolated
    cats admin node delete node-a

| Action | Use | Safety condition |
|----|----|----|
| Cordon | Stop new placement | Existing Cats continue. |
| Drain | Stop/fence and reschedule Cats, then leave node cordoned | Durable disk gate and recovery capacity must be available. |
| Uncordon | Return a healthy node to scheduling | Version, KVM, NVMe, network, and time checks pass. |
| Fence | Revoke claims on a Lost node and cold-recover its Cats | An external mechanism has proved the old Host is powered off or isolated. Heartbeat expiry alone is insufficient. |
| Delete | Remove registry record | Node is empty and cordoned, lost, or fenced. |

## Drain workflow

1.  Confirm replacement capacity and object/metadata service health.
2.  Cordon the node and observe that new allocations stop.
3.  Drain; Suspended and Warm Cats must become Cold before moving hosts.
4.  Verify allocations, dirty/pending commits, route bindings, and local snapshots reach zero.
5.  Delete or replace the node only after identity and local-cache cleanup.

## Lost node

Heartbeat expiry marks the node Lost and its Cats Unknown, but deliberately preserves placement, routes, and disk epochs. It does not start duplicate Guests. The Node returns to Ready only when one heartbeat contains a complete, same-generation runtime inventory for every preserved claim. Registration or an incomplete inventory leaves it Lost so the fence action remains available.

For a permanently lost Host, first obtain independent evidence that it is powered off or isolated (for example from the cloud API, BMC, or network fencing). Then run the explicit `fence` action. Cats persists the terminal Fenced node state, revokes old disk ownership, and cold-recovers its Cats with higher attachment epochs. A Fenced node identity cannot be uncordoned or revived by a late heartbeat; remove it only after Host identity and local-cache cleanup. Rate-limit boot, object GET, and database pressure to avoid a recovery storm.

## Metrics and audit

The `/metrics` endpoint requires administrator authorization. Correlate request ID → Operation → Cat → node → attachment → route epoch. Audit node actions and authorization decisions, but never log tokens, cookies, DSNs, Secret content, terminal plaintext, or Guest disk data.

## Administrator HTTP API

    GET    /v1/admin/monitoring
    GET    /v1/admin/nodes
    GET    /v1/admin/nodes/{id}
    DELETE /v1/admin/nodes/{id}
    POST   /v1/admin/nodes/{id}/actions/{verb}
    GET    /metrics

Supported node action verbs are `cordon`, `uncordon`, `drain`, and `fence`. `fence` requires `{"confirm_host_stopped_or_isolated":true}` and is accepted only for a Lost/Fenced node. Use `uncordon` to cancel a drain. All routes require the fleet administrator identity; node registration, heartbeat, route resolution, and internal work endpoints remain service-only APIs.

## Source-version caveats

The current repository still lacks tap/overlay Guest networking, PostgreSQL for the workspace resource store, and privilege separation. Native vhost-user-blk (ADR-0015) and Suspended page-out (`process_madvise(MADV_PAGEOUT)` over a per-Cat file-backed memory zone) have both landed; kernel NBD remains the default block path for a measured write-throughput trade-off, not for lack of validation. The Cloud Hypervisor path has passed the recorded bare-metal acceptance run, but those remaining items must be closed before calling the entire stack production-ready.
