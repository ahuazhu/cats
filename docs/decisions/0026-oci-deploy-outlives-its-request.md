# ADR-0026: Let the deployment record own OCI deploy work

- Status: Accepted
- Date: 2026-08-03

## Context

OCI pull, verification, extraction, activation, and systemd start can outlive an
HTTP connection. Request cancellation cannot reliably cancel blocking Guest
work, and retrying an ambiguous response must not trigger a second activation
or leak the activity guard that prevents sleep.

## Decision

1. A durable `oci_deployments` row owns each deployment. Database uniqueness on
   `(cat_id, app, image_digest)` turns a request into one of three outcomes:
   - `Claimed`: this attempt drives the work;
   - `AlreadyRunning`: the caller observes the existing attempt;
   - `Replay`: the persisted terminal result is returned without touching the
     Guest.
2. Each `(cat_id, app)` has at most one current successful digest, enforced by a
   database constraint. Activating a new digest and superseding the previous
   current row commit in one transaction. Deploying a superseded digest again
   is new work, which makes rollback explicit.
3. A claimed attempt runs independently of the HTTP request. Its
   `WorkLeaseGuard` owns the Node activity lease and releases it on every task
   exit path through RAII.
4. The API has two successful response shapes:
   - `200` with the deployment when it reaches a terminal result inside the
     bounded wait budget;
   - `202` with its Operation when work continues.

   `wait_ms=0` selects the immediate asynchronous form. The external ingress
   timeout is configured above the maximum server wait budget so infrastructure
   does not replace a valid `202` with an ambiguous timeout.
5. Reads list the current deployments and expose the Operation terminal state;
   clients do not repeat POST as a status query.
6. Every active attempt owns a PostgreSQL session lock as defined by ADR-0032.
   The reaper may fail an abandoned attempt only after it acquires that exact
   owner lock. Completion updates are conditional on the attempt/Operation ID,
   so a stale owner cannot overwrite a retry.
7. Registry credentials remain transient under ADR-0024. Because they are not
   recoverable after owner loss, an abandoned attempt becomes Failed with an
   actionable error; a caller may then submit the same immutable deployment
   identity again.

## Invariants

- Request disconnect neither cancels nor duplicates claimed work.
- Concurrent or repeated requests for one Cat/app/digest produce one Guest
  activation and one terminal record.
- A new app digest cannot leave two rows or two systemd units marked current.
- Every terminal path releases its activity lease.
- A stale controller or reaper cannot publish over the current attempt.
- `202` represents durable tracked work, not an in-memory queue entry.

## Stable boundaries

Replay reports the stored result for the still-current digest; it is not an
implicit application restart or health repair. Application readiness and an
explicit restart action are separate contracts. `cats exec` also retains its
own synchronous API semantics and is not modeled as an OCI deployment.

## Consequences

Deployment correctness no longer depends on HTTP, load-balancer, or client
retry timing. The cost is a durable table, one Operation per attempt, a bounded
background executor, session-lock ownership, and a reaper that must be tested
under cancellation and controller replacement.
