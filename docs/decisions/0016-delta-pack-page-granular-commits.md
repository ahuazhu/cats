# ADR-0016: Publish dirty 64 KiB pages as bounded delta layers

- Status: Accepted
- Date: 2026-07-26

## Context

The cache tracks dirty data in 64 KiB pages inside each 4 MiB chunk. Publishing
the whole chunk after a small Guest write discarded that precision and created
large write amplification. A commit needs a point-in-time copy of the bytes it
publishes; it does not need to republish unchanged bytes that are already held
in immutable objects.

## Decision

1. A commit publishes one delta object per dirty chunk containing exactly the
   dirty 64 KiB pages in page order. Its `page_mask` identifies the included
   pages. A full mask represents a 4 MiB base object.
2. A map entry is a `Layered` chunk reference with an optional base and an
   ordered list of deltas. Later deltas replace earlier bytes for overlapping
   pages; no base means an all-zero chunk.
3. The exclusive FLUSH barrier captures the dirty page plan and copies exactly
   those pages with `copy_planned_pages`. Copying and hashing remain parallel;
   writes after the barrier belong to the next commit.
4. A chunk has at most `MAX_DELTA_LAYERS` layers, currently four. The next
   commit publishes a fresh full base and clears the chain when the chain is
   full or the new commit dirties more than half the chunk.
5. Hydration fetches the base and deltas, verifies every referenced length and
   SHA-256, applies layers in order, and writes one complete cache chunk.
6. GC treats every object referenced by the current Root as live. Superseded
   layers become collectible through the normal Root reachability rule.
7. Persisted formats remain explicit and fail closed:
   - maps without layered chunks retain the previous encoding;
   - layered maps use the next version;
   - old pending packs decode as full-chunk entries;
   - an older binary rejects a newer map version rather than misreading it.

The bounded chain supplies the correctness and read-amplification guarantee, so
no background compactor is required. A future compactor is an optimization and
must preserve the same Root and fencing semantics.

## Invariants

- A successful Strict FLUSH has published every page in its barrier plan before
  the Root CAS succeeds.
- Relaxed durability changes when remote publication occurs, not which pages a
  commit represents.
- A stale attachment epoch cannot publish either a delta or a base.
- Recovery can replay an old pending pack idempotently.
- A cold read fetches at most five data objects per chunk with the current
  layer bound.

## Evidence and consequences

The retained benchmarks and raw logs are under
[`vhost-user-blk-frontend-20260726`](../../experiments/vhost-user-blk-frontend-20260726/README.md).
They show the measured environment, sample counts, bytes uploaded, PUT count,
and latency. Those measurements are evidence for this decision, not an SLA.

Delta layers reduce sparse-commit bytes and preserve page-level sharing with a
golden root. The tradeoffs are more small objects and bounded cold-read
amplification. Upload concurrency and object-store request counts therefore
remain observable, while multi-chunk object packing stays outside this design
until measurements justify its additional range-read and GC complexity.
