# ADR-0034: Bound PostgreSQL backend connections with managed RDS Proxy

- Status: Accepted
- Date: 2026-08-06
- Relates to: ADR-0003 (Direct-S3), ADR-0005 (provider-neutral storage
  adapters), ADR-0028 (runtime survival across noded restart), ADR-0029
  (database-password authority), ADR-0032 (PostgreSQL singleton leadership);
  issue #76

## Context

Each `cats-blockd` deliberately owns two PostgreSQL sessions: metadata work and
lease renewal. Sharing one serialized connection lets a commit delay renewal,
which makes lease takeover latency unpredictable. The separation is correct,
but direct sessions scale as `2 * running Cats` plus bounded control and usage
clients. On the current small RDS class, the database connection ceiling can
therefore stop fleet growth long before CPU or storage capacity is exhausted.

A node-local connection broker would make every live blockd depend on another
process on its Host. Restarting or replacing that broker would affect all Cats
on the node and contradict ADR-0028's rule that a noded restart must not disturb
surviving runtime processes. Raising `max_connections` or the RDS class only
moves the cliff and keeps client count coupled to database memory.

RDS Proxy can multiplex many client sessions over a bounded backend pool and
preserve client connections across an RDS failover. PostgreSQL session state is
the important exception: client `SET` statements and session advisory locks
pin a client to one backend connection. The metadata adapter currently executes
`SET statement_timeout` and `SET lock_timeout` on every connection, so pointing
the existing client at a proxy would retain exactly the scaling failure this
decision is meant to remove.

## Decision

### The storage path uses one managed, multi-AZ RDS Proxy

The platform database module creates an AWS-managed, TLS-required PostgreSQL
RDS Proxy in supported private subnets. EKS and metal-worker security groups can
reach the proxy; only the proxy security group can use its proxy-to-database
rule. Direct RDS ingress remains for the bounded usage clients, operational
access, and immediate rollback.

The proxy authenticates with the existing RDS managed master-user secret. Its
IAM role may read only that secret and decrypt it only through the regional
Secrets Manager service. The proxy is not a metadata authority: PostgreSQL
root/lease CAS and fencing epochs remain the authority, and blockd reconnects
continue to reread the rotating DSN file under ADR-0029.

The default target group:

- may consume at most 80 percent of database `max_connections`, reserving the
  rest for bounded direct clients and operations;
- waits at most five seconds to borrow a backend connection, below the metadata
  adapter's seven-second operation deadline;
- injects `statement_timeout = 5s` and `lock_timeout = 2s` as its initialization
  query on every backend connection; and
- retains at most 50 percent idle backend connections.

RDS Proxy excludes the AWS-documented unsupported physical zones `use1-az3`
and `usw1-az2`. Creation fails closed unless at least two supported private
subnets remain.

### Adapter session setup is explicit and verified

The PostgreSQL metadata adapter accepts `session-setup=client|server-verified`:

- `client` is the backward-compatible default. It executes the existing two
  `SET` statements and is correct for direct PostgreSQL connections.
- `server-verified` never mutates session state. Before schema or metadata work,
  it reads `pg_settings` and requires the exact 5000 ms statement timeout and
  2000 ms lock timeout. Missing or different values fail the connection closed.

This is a proof boundary, not a trust flag. An operator cannot remove or
misconfigure the proxy initialization query and silently leave unbounded SQL
operations. Conversely, a proxy deployment must not use `client`, because the
client `SET` statements would pin every blockd session.

Control-store connections intentionally use session advisory locks for elected
singleton roles. Those sessions can pin and remain correctness-required, but
their count is bounded by the control-plane replica and role counts rather than
the number of Cats. PostgreSQL has no pinning filters for PostgreSQL proxies, so
the live qualification must distinguish this expected bounded baseline from
metadata-session pinning.

The usage store remains on the direct RDS endpoint. Its worker count is already
bounded and its query timeouts and failure isolation are independent of
ChunkStore metadata. Moving it would add no fleet-scaling benefit and would
remove a useful rollback path.

### Cutover is staged and reversible

Merging this ADR does not switch a running environment. The production deploy
workflow preserves direct RDS unless the optional `RDS_PROXY_ENDPOINT`
repository variable is present. When set, it changes only the storage DSN host
and selects `server-verified`; the shared password, port, database, TLS mode and
usage DSN are preserved.

The required order is:

1. apply the platform stack and wait until the proxy target is `AVAILABLE`;
2. test TLS/authentication and both timeout settings from the EKS and worker
   security boundaries;
3. set `RDS_PROXY_ENDPOINT` and roll the active-active control plane;
4. set worker `CATS_POSTGRES_HOST` to the proxy endpoint and
   `CATS_POSTGRES_SESSION_SETUP=server-verified`, then cordon, drain and update
   one worker at a time; and
5. observe at least one normal workload window before moving the next worker.

Rollback removes the repository variable for the control plane and restores
the direct RDS host plus `client` setup on one drained worker at a time. Direct
RDS security-group access is deliberately retained. Neither cutover nor
rollback stops all workers or kills a live blockd to release connections.

## Observability and qualification

Terraform alarms on any backend connection-setup failure, any client
authentication failure at the proxy (which might not reach the PostgreSQL
error log), and borrowed backend connections remaining above 80 percent of the
allowed pool for three minutes. The 80-percent value is an operational
headroom detector, not a product latency or availability SLA.

Production acceptance requires evidence that:

- `ClientConnections` can grow with the Cat count while `DatabaseConnections`
  remains below `MaxDatabaseConnectionsAllowed`;
- `DatabaseConnectionsCurrentlySessionPinned` stays at the measured bounded
  control-plane baseline rather than growing by two per Cat;
- metadata commits, lease renewal and stale-epoch fencing still pass through
  the proxy;
- one proxy endpoint/AZ disruption preserves or automatically restores client
  service; and
- a controlled RDS Multi-AZ failover causes bounded errors/retries and automatic
  reconnection without restarting all workers or losing a successful Strict
  FLUSH.

Measurements must retain the environment, sample count, time window and
correctness oracle. They are qualification evidence, not a production SLA.

## Consequences

Fleet-scale client sessions no longer consume one RDS backend each, and AWS
owns proxy process and AZ failover. Existing blockd metadata/lease isolation and
all storage protocol and persisted-format semantics remain unchanged.

The proxy adds standing AWS cost, one network hop and a new managed service to
observe. Pool exhaustion becomes bounded queuing and load shedding rather than
database-wide connection exhaustion, so alarms and the five-second borrow
timeout are mandatory. RDS Proxy can close long-lived clients; the adapter's
existing reconnect path and rotating DSN reread cover that event.

This decision does not make PostgreSQL region-independent and does not replace
PITR, backups or an RDS Multi-AZ failover drill.
