# ADR-0020: Defer S3 Express One Zone for Strict commits

- Status: Deferred
- Date: 2026-07-29

## Context

A Strict FLUSH acknowledges only after immutable objects and the MetadataStore
Root CAS are durable. S3 Express One Zone can reduce same-AZ object latency, and
an experiment showed benefit for small synchronous commits. Relaxed durability
already removes remote object latency from the Guest ACK path by committing to
local NVMe first.

## Decision

Strict commits continue to use the selected regional object-store adapter. Cats
does not add an S3 Express runtime mode now.

The measured latency improvement does not justify these product and operational
changes:

- the durable copy would have Availability-Zone rather than regional failure
  independence;
- volumes and replacement capacity would become AZ-aware;
- directory-bucket authentication, addressing, IAM, lifecycle, and observability
  would add an AWS-specific serving path;
- regional replication would need a separate protocol before the mode could
  retain the current durability promise;
- Relaxed workloads receive no ACK-latency benefit from the change.

The experiment and its environment boundaries are retained under
[`express-one-zone-flush-20260729`](../../experiments/express-one-zone-flush-20260729/README.md).
Its measurements are comparative evidence, not an SLA or current price model.

## Re-evaluation gate

Reconsider this decision only when a concrete Strict workload requires lower
remote-ACK latency and a proposal supplies all of the following:

- an explicit accepted durability contract for AZ loss;
- scheduling and recovery behavior when same-AZ capacity is unavailable;
- current AWS capability, IAM, lifecycle, and cost evidence;
- regional replication or another mechanism if the product retains regional
  durability;
- real multi-sample FLUSH, failure, fencing, and recovery results against the
  current ChunkStore implementation.

Until then, regional S3 plus PostgreSQL CAS remains the simple Strict authority,
and ADR-0022 remains the low-latency path for workloads that accept Relaxed
Host-loss semantics.
