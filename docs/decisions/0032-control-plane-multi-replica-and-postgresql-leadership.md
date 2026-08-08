# ADR-0032: Control-plane replicas share PostgreSQL authority and elect singleton roles

- Status: Accepted
- Date: 2026-08-05
- Relates to: ADR-0011 (usage projector), ADR-0026 (detached OCI deploy),
  ADR-0031 (PostgreSQL control store), ADR-0040 (runtime reconciliation)

## Context

ADR-0031 removed the SQLite/RWO-volume coupling, but raising the Deployment
replica count alone would create new races. API handlers previously separated
idempotency lookup from mutation, placement read capacity before claiming it,
and the reconciler, billing enforcer and usage projector were process-local
singletons. A detached OCI deploy also needed an owner identity visible to
other replicas.

Kubernetes leader election would fence Pods but would add a second authority
and would not solve transaction races in PostgreSQL. PostgreSQL is already the
control authority and managed failover boundary.

## Decision

- Run at least two `cats-controld` API replicas. Use `RollingUpdate` with zero
  unavailable replicas, hard hostname spreading, and a PodDisruptionBudget
  keeping one replica available.
- Elect reconciler, billing enforcer and usage projector independently with
  dedicated PostgreSQL session advisory locks. A separate connection performs
  a one-second health check. Connection loss or election-task cancellation
  aborts the role before its handle is dropped; a dropped Tokio handle must not
  detach old leader work.
- The elected runtime reconciler scans current `DesiredRuntimeSpec` rows. It
  does not own a replica-local command history; a replacement leader resumes
  from PostgreSQL desired state and revision-bound observations.
- Linearize idempotent create/action requests with transaction advisory locks
  scoped by schema, route and idempotency key. The resource mutation, operation
  and idempotency row commit in one transaction.
- Serialize the fleet-wide placement capacity read and claim in PostgreSQL, so
  independent Store connections cannot overcommit a Node.
- Give each detached OCI attempt a PostgreSQL session lock keyed by operation
  id. The elected reaper fails only rows whose owner lock can be acquired, and
  completion updates are conditional on the current operation id so a stale
  owner cannot overwrite a retry.
- Treat a severed ordinary Store connection as a reconnect event. One request
  may receive the connection error; the next connection re-reads the DSN file
  and committed desired state remains authoritative.

## Consequences

- A single control-plane Pod or Kubernetes node loss no longer stops API
  service. Singleton work pauses for the election interval and resumes from
  PostgreSQL state on another replica.
- PostgreSQL availability remains required. This is intentional: no
  home-grown consensus or replica-local authority is introduced. Managed RDS
  Multi-AZ is a separate infrastructure gate, not provided by this ADR.
- The usage projector remains one active process for all shards. True
  multi-projector parallelism still requires conditional shard leases.
- An OCI task whose database owner session disappears may already have sent a
  request to the Guest before cancellation. The operation-id predicate prevents
  stale database publication; end-to-end Guest activation idempotency remains
  an explicit follow-up if deployments must survive that ambiguity without a
  retry.
