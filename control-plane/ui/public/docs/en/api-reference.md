## Conventions

The external API is JSON over HTTP. User resources are scoped by the immutable workspace ID in `/v1/workspaces/{workspace_id}/…`; a mutable slug never appears in a resource route. A verified WorkOS identity may access Workspaces owned by its active Account membership, and changing a URL cannot create that membership.

    Authorization: Bearer <short-lived-workos-access-token>
    Accept: application/json
    Content-Type: application/json
    Idempotency-Key: <unique-request-id>   # mutations
    If-Match: "<generation>"                # guarded state changes

`cats login` obtains and refreshes the user token through WorkOS Device Authorization without writing it to the normal config file. Other user clients must use an approved WorkOS flow and the same verified JWT contract; static user tokens are not accepted. Browser consoles use their HttpOnly WorkOS session instead of exposing a Bearer token to JavaScript. Service and administrator machine identities have separate scopes.

## Identity and Workspaces

    GET  /auth/config       # public WorkOS client/base-URL configuration
    GET  /v1/me             # user profile and available Workspaces
    GET  /v1/workspaces     # refresh the available Workspace list
    POST /v1/accounts/{account}/workspaces
    PATCH /v1/workspaces/{workspace}
    GET|POST /v1/accounts/{account}/invitations
    POST /v1/accounts/{account}/invitations/{invitation}/actions/revoke
    GET /v1/accounts/{account}/members
    PATCH|DELETE /v1/accounts/{account}/members/{membership}
    POST /v1/auth/logout    # revoke the CLI WorkOS session

Workspace enumeration returns Personal and Organization Accounts from active WorkOS Organization memberships. Creating or renaming a Workspace requires account-management permission; a rename does not change its immutable ID, so every resource route keeps resolving. Invitation/member mutations require `cats:members:manage`, are rejected for Personal Accounts, and are performed through WorkOS. Creating an invitation also requires `Idempotency-Key`; Cats forwards it to WorkOS so a network retry returns the same invitation. User access-token signature, issuer, client ID, expiry, subject, Organization scope, active membership, Account ID, and Workspace ownership are checked before authorization.

## Cats

    POST   /v1/workspaces/{workspace_id}/cats
    GET    /v1/workspaces/{workspace_id}/cats
    GET    /v1/workspaces/{workspace_id}/cats/{cat}
    DELETE /v1/workspaces/{workspace_id}/cats/{cat}
    POST   /v1/workspaces/{workspace_id}/cats/{cat}/actions/{verb}
    POST   /v1/workspaces/{workspace_id}/cats/{cat}/exec
    GET    /v1/workspaces/{workspace_id}/cats/{cat}/work
    GET    /v1/workspaces/{workspace_id}/cats/{cat}/auto-suspend
    PUT    /v1/workspaces/{workspace_id}/cats/{cat}/auto-suspend

Lifecycle verbs are `start`, `stop`, `suspend`, `resume`, and `warm`. `auto_suspend` defaults to `true` when omitted from create. Cat create/lifecycle/delete returns an asynchronous Operation response; poll the Operation URL instead of repeating a timed-out mutation with a new intent.

Cat, Disk, and Operation responses include the immutable `workspace_id`, which is the only ownership key.

    POST /v1/workspaces/ws_01J8QK.../cats
    Idempotency-Key: request-7f12

    {
      "name": "dev",
      "image": "ubuntu-24.04",
      "cpus": 2,
      "memory_mib": 2048,
      "root_size_bytes": 8589934592
    }

## Disks and snapshots

    POST   /v1/workspaces/{workspace_id}/disks
    GET    /v1/workspaces/{workspace_id}/disks
    GET    /v1/workspaces/{workspace_id}/disks/{disk}
    DELETE /v1/workspaces/{workspace_id}/disks/{disk}
    POST   /v1/workspaces/{workspace_id}/disks/{disk}/actions/{verb}
    POST   /v1/workspaces/{workspace_id}/disks/{disk}/snapshots
    GET    /v1/workspaces/{workspace_id}/disks/{disk}/snapshots

Disk action verbs are `mount`, `unmount`, and `resize`. Mount bodies identify the Cat and Guest path. The service enforces RWO and rejects stale or conflicting attachment state.

## Endpoints

    POST /v1/workspaces/{workspace_id}/cats/{cat}/endpoints
    GET  /v1/workspaces/{workspace_id}/cats/{cat}/endpoints

    {
      "name": "web",
      "target_port": 3000,
      "protocol": "http",
      "wake_policy": "wake_on_request"
    }

## Usage and billing

    GET /v1/workspaces/{workspace_id}/billing/usage
        ?from_ms=<inclusive-unix-milliseconds>
        &to_ms=<exclusive-unix-milliseconds>
        [&cat=<active-cat-name> | &cat_id=<immutable-cat-id>]
        [&bucket_ms=<milliseconds>]
        [&detail=true]

The response is a `provisional` estimate for the open period. It includes range totals, totals by meter, totals by Cat, the immutable rate-card ID, and the latest visible interval end. `cat_id` remains queryable after a Cat is deleted. `bucket_ms` returns server-side time buckets for charts and bounded period detail; it must be at least 60 seconds and produce no more than 512 buckets. `detail=true` returns raw ledger intervals and should be reserved for controlled reconciliation queries rather than long browser ranges.

CPU is rated at `$0.07 / CPU-hour` and memory at `$0.045 / GiB-hour` by the current rate card. Decimal quantities and nanodollar amounts are JSON strings so clients do not lose integer precision. The range total is rated once after aggregation; bucket amounts are display estimates and are not a finalized invoice.

    GET  /v1/workspaces/{workspace_id}/billing/balance
    POST /v1/workspaces/{workspace_id}/billing/checkout
    Idempotency-Key: <unique-key>
    {"amount_cents": 1000}

A new user receives one non-renewing `$10` signup credit on the user's Personal Billing Account. Organization Accounts, extra Workspaces, and invitations do not mint signup credit. The balance response subtracts all-time provisional usage from append-only grants and top-ups. Checkout accepts only the published fixed top-up amounts and returns a Stripe-hosted URL. Returning from Checkout does not add credit: Cats credits the account only after a signed Stripe webhook reports the session as paid.

When available credit is exhausted, paid compute admission returns HTTP `402` with code `payment_required`. Stopping, suspending, and deleting resources remain available.

## Operations

    GET /v1/workspaces/{workspace_id}/operations
    GET /v1/operations/{operation}

An Operation contains immutable `workspace_id` ownership, kind, target resource ID/generation, phase, timestamps, and an optional structured error. Access is still Workspace-scoped even though the single-Operation URL does not contain the workspace segment.

## Errors

    {
      "code": "failed_precondition",
      "message": "disk must be available before deletion"
    }

Clients should branch on the stable code and show the message for context. Important codes include `invalid_argument`, `unauthenticated`, `permission_denied`, `not_found`, `already_exists`, `failed_precondition`, `payment_required`, `conflict`, `stale_epoch`, `deadline_exceeded`, `unavailable`, and `internal`.

**Version authority**

This page documents the current V1 Rust router. For generated clients, derive a reviewed OpenAPI description from the same request/resource types before release; do not infer undocumented fields from architecture examples.
