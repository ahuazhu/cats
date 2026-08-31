## Conventions

The external API is JSON over HTTP. Product resources are scoped by the immutable Workspace ID in `/v1/workspaces/{workspace_id}/…`; mutable slugs are not resource keys. Browser requests use the HttpOnly WorkOS session. CLI and automation requests use the corresponding WorkOS or Workspace credential.

The two create collections require exact `Content-Type: application/json`, exactly one printable `Idempotency-Key`, a canonical Workspace path with no query, and the closed request body shown below. Lifecycle actions instead require an empty body and no `Content-Type`. A retry after an ambiguous response must replay the same path, body, and key.

## Current Cat surface

    POST /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats/{cat_id}
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/run
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/suspend
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/warm
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/cold
    POST /v1/workspaces/{workspace_id}/cats/{cat_id}/actions/destroy

    {
      "name": "dev",
      "vcpus": 2,
      "memory_bytes": 2147483648,
      "root_size_bytes": 1073741824,
      "durability": "strict"
    }

Control automatically binds the deployment's current qualified boot image to a newly created Cat. The request does not accept an image override, and existing Cats keep their original exact digest.

Create returns exact `202 application/json` with `{"cat_id":"…","operation_id":"…"}`. Collection reads accept only bounded `limit` and opaque `cursor` fields. Item reads and lifecycle actions accept immutable `cat_…` IDs only.

Each lifecycle action takes exactly one `Idempotency-Key`, an empty body, and no `Content-Type`; success is exact `202 application/json` with `{"operation_id":"op_…"}`. An ambiguous response remains pending and must be replayed byte-for-byte. The retired `start`, `stop`, `delete`, and `resume` routes are not aliases. Exec, deployment, Endpoint, expiry, and work-policy mutations remain outside this release router.

## Current PersistentDisk surface

    POST /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks/{disk_id}
    POST /v1/workspaces/{workspace_id}/disks/{disk_id}/actions/attach
    POST /v1/workspaces/{workspace_id}/disks/{disk_id}/actions/detach

    {
      "durability": "strict",
      "name": "project-data",
      "size_bytes": 21474836480
    }

Create returns the exact created Disk projection with `201 application/json`. Capacity and durability are immutable in this release. Item reads require immutable `disk_…` IDs. Attach and detach are synchronous, idempotent product transactions for a terminal Cold Cat; both use the closed body `{"cat_id":"cat_…","mount_path":"/absolute/guest/path"}`. Capacity-change mutations are unavailable.

## DiskSnapshot surface

    POST /v1/workspaces/{workspace_id}/snapshots
    GET  /v1/workspaces/{workspace_id}/snapshots
    GET  /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}
    POST /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}/actions/restore
    POST /v1/workspaces/{workspace_id}/snapshots/{snapshot_slug}/actions/destroy

Create has the closed body `{"snapshot_slug":"before-upgrade","disk_slug":"project-data"}`.
Restore has the closed body `{"expected_generation":42}`; this is the target
disk's latest generation, not the Snapshot's captured generation. A successful
restore publishes the captured Root at generation 43 and returns
`disk_head_generation: 43`. Destroy has an empty body. These synchronous routes
do not accept an Idempotency-Key and do not create an Operation.

The Snapshot projection exposes immutable Snapshot/Disk IDs, their current
slugs, capacity, status, captured generation, and create/delete times. It never
exposes internal Root hashes or object keys. The first version supports restore
to the original disk only; clone, hot snapshot, and cross-Workspace copy are not
routes.

## Operations

    GET /v1/workspaces/{workspace_id}/operations/{operation_id}

Cat create and every lifecycle action return an Operation ID. Only exact Operation lookup is exposed. Its product projection contains only `create`, `run`, `suspend`, `warm`, `cold`, or `destroy` and `in_progress`, `succeeded`, or `failed`; Node execution commands and evidence are not returned. Authorization precedes lookup, and another Workspace's opaque ID is indistinguishable from an absent ID. No Operation collection or global Operation URL is available.

## Errors

Errors use a stable JSON `code` plus a human-readable `message`. Clients should branch on the code. A missing route is not permission to fall back to a legacy body or mutation path.

**Version authority**

This page documents the release product router. Account, session, billing, and internal signed-authority routes are separate surfaces; they do not reopen Cat or Disk lifecycle mutations.
