## Conventions

The external API is JSON over HTTP. User resources are scoped by the compatible project segment in `/v1/projects/{project}/…`; its value is the user-visible Workspace slug. A verified WorkOS identity may access only its selected Workspace, and changing the URL cannot change that authorization context.

    Authorization: Bearer <short-lived-workos-access-token>
    Accept: application/json
    Content-Type: application/json
    Idempotency-Key: <unique-request-id>   # mutations
    If-Match: "<generation>"                # guarded state changes

`cats login` obtains and refreshes the user token through WorkOS Device Authorization without writing it to the normal config file. Other user clients must use an approved WorkOS flow and the same verified JWT contract; static project tokens are not accepted. Browser consoles use their HttpOnly WorkOS session instead of exposing a Bearer token to JavaScript. Service and administrator machine identities have separate scopes.

## Identity and Workspaces

    GET  /auth/config       # public WorkOS client/base-URL configuration
    GET  /v1/me             # user profile and available Workspaces
    GET  /v1/workspaces     # refresh the available Workspace list
    POST /v1/auth/logout    # revoke the CLI WorkOS session

Workspace enumeration returns active WorkOS Organization memberships that have an explicit deployment mapping, plus an isolated personal Workspace for an organizationless user. User access-token signature, issuer, client ID, expiry, subject, and Organization scope are verified before a resource path is authorized.

## Cats

    POST   /v1/projects/{project}/cats
    GET    /v1/projects/{project}/cats
    GET    /v1/projects/{project}/cats/{cat}
    DELETE /v1/projects/{project}/cats/{cat}
    POST   /v1/projects/{project}/cats/{cat}/actions/{verb}
    POST   /v1/projects/{project}/cats/{cat}/exec
    GET    /v1/projects/{project}/cats/{cat}/work
    GET    /v1/projects/{project}/cats/{cat}/auto-suspend
    PUT    /v1/projects/{project}/cats/{cat}/auto-suspend

Lifecycle verbs are `start`, `stop`, `suspend`, `resume`, and `warm`. `auto_suspend` defaults to `true` when omitted from create. Cat create/lifecycle/delete returns an asynchronous Operation response; poll the Operation URL instead of repeating a timed-out mutation with a new intent.

    POST /v1/projects/acme-dev/cats
    Idempotency-Key: request-7f12

    {
      "name": "dev",
      "image": "ubuntu-24.04",
      "cpus": 2,
      "memory_mib": 2048,
      "root_size_bytes": 8589934592
    }

## Disks and snapshots

    POST   /v1/projects/{project}/disks
    GET    /v1/projects/{project}/disks
    GET    /v1/projects/{project}/disks/{disk}
    DELETE /v1/projects/{project}/disks/{disk}
    POST   /v1/projects/{project}/disks/{disk}/actions/{verb}
    POST   /v1/projects/{project}/disks/{disk}/snapshots
    GET    /v1/projects/{project}/disks/{disk}/snapshots

Disk action verbs are `mount`, `unmount`, and `resize`. Mount bodies identify the Cat and Guest path. The service enforces RWO and rejects stale or conflicting attachment state.

## Endpoints

    POST /v1/projects/{project}/cats/{cat}/endpoints
    GET  /v1/projects/{project}/cats/{cat}/endpoints

    {
      "name": "web",
      "target_port": 3000,
      "protocol": "http",
      "wake_policy": "wake_on_request"
    }

## Operations

    GET /v1/projects/{project}/operations
    GET /v1/operations/{operation}

An Operation contains Workspace ownership (stored as project), kind, target resource ID/generation, phase, timestamps, and an optional structured error. Access is still Workspace-scoped even though the single-Operation URL does not contain the project segment.

## Errors

    {
      "code": "failed_precondition",
      "message": "disk must be available before deletion"
    }

Clients should branch on the stable code and show the message for context. Important codes include `invalid_argument`, `unauthenticated`, `permission_denied`, `not_found`, `already_exists`, `failed_precondition`, `conflict`, `stale_epoch`, `deadline_exceeded`, `unavailable`, and `internal`.

**Version authority**

This page documents the current V1 Rust router. For generated clients, derive a reviewed OpenAPI description from the same request/resource types before release; do not infer undocumented fields from architecture examples.
