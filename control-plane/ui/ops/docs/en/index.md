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

`cats admin monitoring` reports Cat lifecycle counts, node states, CPU/memory assignments, and Operation phases. The administrator console adds auto-refresh, host telemetry, and raw Prometheus metrics. Investigate per-node and per-project data rather than relying only on fleet averages.

## Node actions

    cats admin node get node-a
    cats admin node cordon node-a
    cats admin node drain node-a
    cats admin node uncordon node-a
    cats admin node delete node-a

| Action | Use | Safety condition |
|----|----|----|
| Cordon | Stop new placement | Existing Cats continue. |
| Drain | Stop/fence and reschedule Cats, then leave node cordoned | Durable disk gate and recovery capacity must be available. |
| Uncordon | Return a healthy node to scheduling | Version, KVM, NVMe, network, and time checks pass. |
| Delete | Remove registry record | Node is empty and cordoned or lost. |

## Drain workflow

1.  Confirm replacement capacity and object/metadata service health.
2.  Cordon the node and observe that new allocations stop.
3.  Drain; Suspended and Warm Cats must become Cold before moving hosts.
4.  Verify allocations, dirty/pending commits, route bindings, and local snapshots reach zero.
5.  Delete or replace the node only after identity and local-cache cleanup.

## Lost node

Do not immediately start duplicate Guests. Wait for the node lease or cloud fencing evidence, revoke old disk ownership, issue a higher attachment epoch, and recover Cats in controlled batches. Rate-limit boot, object GET, and database pressure to avoid a recovery storm.

## Metrics and audit

The `/metrics` endpoint requires administrator authorization. Correlate request ID → Operation → Cat → node → attachment → route epoch. Audit node actions and authorization decisions, but never log tokens, cookies, DSNs, Secret content, terminal plaintext, or Guest disk data.

## Administrator HTTP API

    GET    /v1/admin/monitoring
    GET    /v1/admin/nodes
    GET    /v1/admin/nodes/{id}
    DELETE /v1/admin/nodes/{id}
    POST   /v1/admin/nodes/{id}/actions/{verb}
    GET    /metrics

Supported node action verbs are `cordon`, `uncordon`, and `drain`. Use `uncordon` to cancel a drain. All routes require the fleet administrator identity; node registration, heartbeat, route resolution, and internal work endpoints remain service-only APIs.

## Source-version caveats

The current repository still lacks native vhost-user-blk, tap/overlay Guest networking, Suspended page-out (the CH path currently pauses only), PostgreSQL for the project resource store, and privilege separation. The Cloud Hypervisor Phase-A path has passed the recorded bare-metal acceptance run, but those remaining items must be closed before calling the entire stack production-ready.
