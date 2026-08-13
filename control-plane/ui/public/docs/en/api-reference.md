## Conventions

The external API is JSON over HTTP. Product resources are scoped by the immutable Workspace ID in `/v1/workspaces/{workspace_id}/…`; mutable slugs are not resource keys. Browser requests use the HttpOnly WorkOS session. CLI and automation requests use the corresponding WorkOS or Workspace credential.

The two create collections require exact `Content-Type: application/json`, exactly one printable `Idempotency-Key`, a canonical Workspace path with no query, and the closed request body shown below. A retry after an ambiguous response must replay the same path, body, and key.

## Current Cat surface

    POST /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats
    GET  /v1/workspaces/{workspace_id}/cats/{cat_id}

    {
      "name": "dev",
      "boot_image_digest": "sha256:<64-lowercase-hex>",
      "vcpus": 2,
      "memory_bytes": 2147483648,
      "root_size_bytes": 1073741824,
      "durability": "strict"
    }

Create returns exact `202 application/json` with `{"cat_id":"…","operation_id":"…"}`. Collection reads accept only bounded `limit` and opaque `cursor` fields. Item reads accept immutable `cat_…` IDs only.

Lifecycle, exec, deployment, Endpoint, expiry, work-policy, and delete routes are not part of the release router during the signed runtime cutover. Clients must fail locally instead of probing those paths.

## Current PersistentDisk surface

    POST /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks
    GET  /v1/workspaces/{workspace_id}/disks/{disk_id}

    {
      "durability": "strict",
      "name": "project-data",
      "size_bytes": 21474836480
    }

Create returns the exact created Disk projection with `201 application/json`. Capacity and durability are immutable in this release. Item reads require immutable `disk_…` IDs. Attachment, snapshot, capacity-change, and delete mutations are unavailable.

## Operations

    GET /v1/workspaces/{workspace_id}/operations/{operation_id}

Only exact Operation lookup is exposed. Authorization precedes lookup, and another Workspace's opaque ID is indistinguishable from an absent ID. No Operation collection or global Operation URL is available.

## Errors

Errors use a stable JSON `code` plus a human-readable `message`. Clients should branch on the code. A missing route is not permission to fall back to a legacy body or mutation path.

**Version authority**

This page documents the release product router. Account, session, billing, and internal signed-authority routes are separate surfaces; they do not reopen Cat or Disk lifecycle mutations.
