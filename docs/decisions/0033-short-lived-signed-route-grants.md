# ADR-0033: Short-lived signed grants keep Running Endpoint traffic off the control-plane hot path

- Status: Accepted
- Date: 2026-08-06
- Relates to: ADR-0002 (lifecycle states), ADR-0018 (Workspace ownership),
  ADR-0031 (PostgreSQL control store), ADR-0032 (control-plane replicas); issue #187

## Context

The Gateway previously acquired a control-plane work lease before every HTTP
request and WebSocket upgrade, renewed that lease while the WebSocket was open,
and closed the connection if renewal failed. Route lookup had a short process-
local cache, but the unsigned cached value could not authorize a Node hop by
itself. A control-plane Pod or PostgreSQL outage therefore stopped otherwise
healthy traffic to an already Running Guest.

The Node already has the lifecycle fence that request traffic needs. It holds a
`RuntimeActivityGuard` for the complete HTTP request or WebSocket connection;
Suspend first quiesces that local activity source and rejects a transition if
an activity generation changes. A remote lease on every request duplicated
that fence while adding the control store to the data-plane hot path.

The service bearer token is shared by the control plane, Gateway and Nodes. It
cannot be used as route authority: giving a Gateway a symmetric signing secret
would let a compromised Gateway mint arbitrary Cat, Node or port bindings.

## Decision

- The control plane issues a compact Ed25519/EdDSA signed Route Grant only for
  a route whose binding is `active` and whose Cat is observed `Running`.
- A version-1 grant binds issuer, audience, hostname, Workspace ID, Cat ID, Cat
  generation, Node ID, route epoch, target port, issue time and expiry. The
  default lifetime is 120 seconds and is configurable at the control-plane
  composition root.
- The signing private key exists only in the control-plane runtime. Nodes
  receive only the public verification key. The Gateway and Guest receive
  neither the private key nor any capability that can derive it.
- The Gateway treats the signed token as opaque. It may use a cached grant
  after cache freshness only when a resolve attempt fails at transport level
  or with a control-plane 5xx response, the cached route was `active` and
  `Running`, and the advertised grant expiry is still in the future. An
  explicit not-found, other non-success response, malformed response or local
  expiry fails closed.
- The Gateway sends the hostname and token with every Node hop. The Node
  verifies the EdDSA signature, required issuer/audience/time claims, grant
  version, hostname, Cat ID, Cat generation, local Node ID, route epoch and
  target port before acquiring the existing local activity guard. It also
  verifies that the matching runtime is locally `Running`. The route epoch in
  the request must equal the signed epoch; an unsigned Guest address is never
  accepted.
- HTTP requests and WebSocket connections no longer acquire or renew
  control-plane work leases. The Node-local activity generation is the final
  request-versus-Suspend fence, and an established WebSocket keeps its guard
  for the complete connection.
- Wake remains a control-plane operation. A sleeping or unbound Endpoint has
  no usable grant and fails closed while the control plane is unavailable. One
  activation lease covers the bounded wake wait; after Running is observed,
  the same lease is shortened to a non-renewed five-second handoff window so
  the Cat cannot auto-suspend before the Node activity guard is acquired.
  Normal Running traffic never creates or releases that lease.
- A Node stale-route conflict still invalidates the Gateway cache and forces
  one fresh resolve. A rejected grant is never used as the fallback for that
  retry.

The service bearer credential remains as defense in depth for the Gateway-to-
Node hop. It authenticates the calling service but does not authorize a route.

## Consequences

- Already Running HTTP Endpoints continue through a bounded control-plane or
  control-database outage until the cached grant expires. No new authorization
  is invented during the outage.
- Established WebSockets do not depend on renewal through PostgreSQL and stay
  connected while their Node and Guest remain healthy. Their admission was
  authorized before expiry; the held local guard continues to fence Suspend.
- Revocation and same-Node rebinding can lag by at most the short grant
  lifetime unless the Gateway observes an explicit control-plane or Node
  rejection first. Migration to another Node also fails at the old Node's
  local runtime/generation checks.
- Every control-plane replica must share the same current private signing key,
  and every Node in the rollout must have the matching public key before it
  receives traffic. Rotation needs an overlap mechanism before two keys can be
  live simultaneously; V1 uses a coordinated, drained rollout.
- The additive first rollout updates every control-plane replica before any
  Gateway, then drains and updates Nodes one at a time. Old Gateways ignore the
  additional resolve fields and old Nodes ignore the forwarded grant. The
  reverse order is incompatible: a new Gateway rejects an old control-plane
  response without a grant, and a new Node rejects an old Gateway request
  without one. Terraform encodes the control-plane-before-Gateway dependency;
  the worker drain boundary remains operator-controlled.
- Grant expiry is an authorization bound, not a promise that a backend will
  remain Running. Node loss still breaks connections and clients still retry.
