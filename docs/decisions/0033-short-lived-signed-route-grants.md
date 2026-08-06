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
- Every control-plane replica also receives the public half derived from that
  deployment's exact private input. Startup signs and verifies a fixed proof,
  and refuses readiness when two independently valid key halves do not match.
  Grants carry a `kid` equal to the SHA-256 of the public SubjectPublicKeyInfo
  DER. A Node requires that `kid` and reports the same non-secret fingerprint
  in registration. A mismatched registration is atomically cordoned; an
  administrator cannot uncordon a Node until its reported verifier fingerprint
  equals the active signer fingerprint. A missing fingerprint is accepted only
  for an already-Ready legacy Node during the additive first rollout; after it
  is cordoned, it must be upgraded before admission. That exception is backed
  by a durable, one-way database phase rather than inferred forever from a
  nullable fingerprint. Registration, placement and uncordon share one
  transaction linearization point. Once every schedulable or still-serving
  Node reports a verifier identity, the phase closes and cannot reopen; a
  keyed Node reporting no identity is always cordoned as a downgrade.
- The Gateway treats the signed token as opaque. After ordinary cache freshness
  ends, an `active` + `Running` route whose advertised grant expiry is still in
  the future is served immediately while one background resolve per hostname
  refreshes it. Concurrent HTTP requests and WebSocket upgrades share that
  refresh. A transport or control-plane 5xx failure retains the cached grant and
  enters a bounded per-host retry backoff; it never extends signed expiry. Once
  observed, an explicit not-found, other non-success response or malformed
  response invalidates that Gateway's local cached route and fails closed.
  That replica then bypasses the shared mirror for the longest interval in
  which any Grant issued before the rejection could still pass time validation:
  the maximum Grant TTL plus the verifier's accepted clock skew. It therefore
  cannot re-import the capability it just rejected while that capability could
  still be valid. A direct control-plane resolve returning active + Running is
  the only way to clear this safety barrier early. After the complete window
  elapses, the entry may again accept a currently valid, control-plane-signed
  Grant published by another replica; the Node still performs the final
  signature, binding and runtime checks. Local expiry always fails closed
  without stale-while-revalidate.
- The local cache is a fast path, not the replica-consistency boundary. Before
  returning a newly resolved active + Running grant, a production Gateway also
  attempts to publish the complete response to a regional DynamoDB table whose
  lifetime is bounded by the signed expiry. A cold Gateway replica checks that
  strongly consistent shared cache before consulting the control plane. Every
  loaded response repeats the same hostname, state and advertised lifetime
  validation; the Gateway still treats the token as opaque and the Node remains
  the authorization verifier. The table contains only positive capabilities
  signed by the control plane. Its conditional write ordering uses the
  PostgreSQL `routes.epoch` carried in that signed response, then signed issue
  time only to order renewals within one epoch. A Gateway never turns a 404,
  inactive response or its wall clock into shared route authority or a global
  revocation. An older signed capability may therefore remain reusable until
  its signed expiry; this is the same bounded revocation window as any other
  already-issued Route Grant, not an immediate-revocation mechanism.
- The shared cache is independent of PostgreSQL and any Gateway Pod or EKS
  node. Gateway Pod Identity grants only `GetItem` and `PutItem` on that one
  table. DynamoDB is deliberately not a Gateway startup/readiness dependency.
  Shared-cache failure falls back to a healthy control plane; control-plane
  failure falls back to a valid shared or local grant. Thus either dependency
  may fail alone without becoming the new data-plane SPOF. Runtime shared-cache
  reads and writes have a 100 ms hard deadline so a slow DynamoDB request cannot
  hold a healthy control-plane response hostage.
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
- A Node conflict still invalidates the rejected local grant and forces one
  fresh control-plane resolve. Every rejection other than natural signed expiry
  activates the same local shared-mirror barrier, and a rejected grant is never
  used as the fallback for that retry. The Node distinguishes natural expiry
  from other verification and runtime conflicts with machine-readable response
  metadata. Expiry is not a revocation signal: while the control plane is
  unavailable, the Gateway may bypass the long barrier only to import a
  currently valid shared grant that is strictly newer than the rejected grant,
  ordered by route epoch and then signed issue time. The same or an older grant
  remains blocked, and the Node still performs the final verification.
  Concurrent or delayed rejections use that same ordering: a rejection already
  being handled is coalesced with its in-flight refresh, and a rejection for an
  older grant cannot cancel that refresh or remove a newer cached grant. For the
  same grant, a non-expiry conflict is stronger than natural expiry and retains
  the conservative barrier. HTTP and WebSocket retries use the same rule.

The service bearer credential remains as defense in depth for the Gateway-to-
Node hop. It authenticates the calling service but does not authorize a route.

## Consequences

- Already Running HTTP Endpoints continue through a bounded control-plane or
  control-database outage until the cached grant expires. No new authorization
  is invented during the outage. Data-plane requests do not wait on the
  control-plane timeout or multiply resolve load after cache freshness; one
  coalesced refresh per hostname probes recovery under a bounded backoff.
- A grant resolved by any healthy Gateway replica is reusable by another
  replica during that bounded outage. Losing the original Pod, its EKS node or
  load-balancer affinity no longer loses the only cached authorization.
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
- Production CI derives the application public half from the exact private
  secret, compares its DER fingerprint with every schedulable Node and every
  Node still serving assigned or orphan Cats before planning any mutation, and
  then rolls the control plane before the Gateway. An all-legacy cohort is the
  safe additive first release; a mixed legacy/enforcing cohort is an
  interrupted worker rollout and fails the preflight.
  The drained worker association validates and fingerprints the key after
  installation; registration plus the uncordon gate proves that the installed
  verifier matches the serving signer. An interrupted or mismatched worker
  rollout therefore remains unschedulable instead of becoming a partial
  Endpoint outage.
- The additive first rollout updates every control-plane replica before any
  Gateway, then drains and updates Nodes one at a time. Old Gateways ignore the
  additional resolve fields and old Nodes ignore the forwarded grant. The
  reverse order is incompatible: a new Gateway rejects an old control-plane
  response without a grant, and a new Node rejects an old Gateway request
  without one. Terraform encodes the control-plane-before-Gateway dependency;
  the worker drain boundary remains operator-controlled.
- The natural-expiry rejection detail is an additive Node response field. An
  old Gateway safely ignores it, while a new Gateway paired with an old Node
  retains the conservative full barrier. Nodes therefore roll before Gateways
  when this continuity behavior is introduced; either mixed version remains
  fail closed.
- Grant expiry is an authorization bound, not a promise that a backend will
  remain Running. Node loss still breaks connections and clients still retry.
