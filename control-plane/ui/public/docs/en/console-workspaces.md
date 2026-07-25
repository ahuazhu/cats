## Public site versus console

The marketing site and documentation are public. The user console at [`/user/`](/user/) and administrator console at `/admin/` load without credentials so they can start sign-in, but resource data remains unavailable until a valid session is established. Search engines are instructed not to index console or authentication routes.

## WorkOS browser sign-in

1.  Choose **Sign in with WorkOS**.
2.  The server starts an authorization-code flow with PKCE and a short-lived sealed state cookie.
3.  After callback, the server stores access/refresh material only in an encrypted, HttpOnly session cookie.
4.  The page calls the same Workspace-scoped resource APIs as the CLI; no service credential is embedded in JavaScript.

If WorkOS is not configured, the browser sites fail closed and show an operator-facing explanation. They do not fall back to a token entry form.

## CLI Device Login

`cats login` starts WorkOS Device Authorization, prints a verification URL/code, and opens the browser when possible. Access and rotating refresh tokens stay in the operating-system credential store; the `0600` CLI config contains only the API URL, public user/Workspace data, and the current selection. Use `cats whoami`, `cats workspace list`, `cats workspace use ACCOUNT/WORKSPACE`, and `cats logout` to manage that session.

## Workspaces

A user belongs to one or more Personal or Organization Accounts, and each Account owns one or more Workspaces plus one billing boundary. Every Account—including Personal—maps to a WorkOS Organization. A new user receives one Personal Account, a `default` Workspace, and one non-transferable $10 signup grant on that Personal Billing Account. Creating another Workspace or joining an Organization does not issue another grant.

Workspace slugs are unique inside an Account and may be renamed; immutable Account and Workspace IDs retain authorization and resource ownership. The console uses copyable `/user/ACCOUNT/WORKSPACE/` URLs. The CLI accepts the same `account/workspace` locator and permits a bare slug only when it is unambiguous.

**User label versus API compatibility**

The CLI and console call the boundary a *Workspace*. The V1 HTTP API path and resource-store column keep the compatible name `project`; each Workspace has a stable legacy Project route so renaming a slug does not move resources or rewrite usage and credit history.

Login and selection are separate. `cats workspace use acme/dev` saves a default; `--workspace acme/prod` overrides one command without changing it. Switching Workspaces inside one Account is local. Crossing Accounts rotates the WorkOS refresh token into the target Organization scope; concurrent CLI processes serialize that rotation.

## Organization members and invitations

An Organization member with `cats:members:manage` can send an email invitation with an initial `member` or `admin` role. WorkOS binds the invitation to that Organization and creates or activates the membership when accepted. Cats rechecks the active membership for resource and member-management requests; changing a client-side slug or cached role never grants access. Personal Accounts do not accept invitations.

## User console

The console provides:

- Fleet-independent overview of your Cats, sleeping states, disks, and active Operations.
- Create, start, suspend, Warm, stop, exec, expose, and destroy actions for Cats.
- Create, snapshot, mount, unmount, resize, and delete actions for disks.
- Near-real-time provisional billing by meter and Cat, with a selected Cat's range total, per-meter totals, over-time spend curves, and bounded period detail.
- Structured status and error display with automatic session refresh.

## Language switching

Both user and administrator consoles support English and Simplified Chinese. The default follows `navigator.languages`/`navigator.language`. A manual selection is stored locally for the current site and updates static text, dynamic states/actions, form labels, errors, dates, number formatting, document title, and `html lang`.

Language preference affects presentation only. It never changes the session, Workspace mapping, permissions, resource values, or API behavior.

## Administrator isolation

The administrator site uses a separate cookie and requires both the configured administrator Organization and the configured fleet permission (normally `cats:fleet:admin`). A normal organization member or user-console cookie cannot call fleet APIs.

## Sign out and session failure

Browser sign out asks WorkOS to revoke the remote session and clears the local cookie. If a session expires, the console attempts server-side refresh; a failed or unauthorized refresh returns to the sign-in screen. `cats logout` tries remote revocation and removes the local keychain credential even if the network is unavailable. Authentication responses use `no-store`.
