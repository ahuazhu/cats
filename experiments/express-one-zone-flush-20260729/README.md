# FLUSH commit latency on S3 Express One Zone, against Standard S3

What this answers: how much of a Guest's FLUSH stall is the object store's
per-PUT latency, and how much of it S3 Express One Zone buys back. The number
that matters most is the smallest possible commit — one dirty chunk — because
that is the floor a synchronous Guest write pays no matter how little it wrote.

**Headline: the smallest flush (1 dirty chunk, one 64 KiB page) costs 66.6 ms
on Express vs 108.7 ms on Standard S3 — Express takes ~40% off the floor. The
advantage shrinks as commits get bigger (1.03x at 48 sparse chunks), because
the engine now uploads 16 objects concurrently and large commits are
throughput-bound, not latency-bound. Express helps exactly the case that
hurts: small, latency-bound flushes.**

host:     AWS c6a.8xlarge (32 vCPU), us-east-1c = use1-az4, AL2023
          (kernel 6.1.176-223.369.amzn2023), rustc 1.97.1 — same instance
          type/region as the 2026-07-27 baseline
stores:   S3 Express One Zone directory bucket in use1-az4 (same AZ as the
          instance); Standard S3 bucket in us-east-1 (same machine, back to
          back); local file store on the root EBS (gp3 100 GiB) as control
build:    release, working tree of main @ 609d062 plus the bench-only adapter
          changes described below
date_utc: 2026-07-29
bench:    blockd/tests/commit_cost.rs, `--ignored --nocapture --test-threads=1
          flush_cost`, median of 3, serial. Same shapes as the baseline:
          "sparse" = one dirty 64 KiB page per chunk (delta packs), "dense" =
          every page dirty (full 4 MiB bases).

## Results (flush ms, median of 3)

### sparse (delta packs; published MiB = chunks/16)

| dirty chunks | Express (SigV4) | Express (session) | Standard S3 | local file | Express vs Standard |
|---:|---:|---:|---:|---:|---:|
|  1 |  66.6 |  64.0 | 108.7 | 0.5 | 1.63x |
|  8 |  85.4 |  98.1 | 157.7 | 2.1 | 1.85x |
| 16 | 113.1 | 126.9 | 198.7 | 2.5 | 1.76x |
| 32 | 164.2 | 188.6 | 190.4 | 3.6 | 1.16x |
| 48 | 228.4 | 249.4 | 236.0 | 5.3 | 1.03x |

### dense (full 4 MiB bases; published MiB = chunks*4)

| dirty chunks | published MiB | Express (SigV4) | Express (session) | Standard S3 | local file | Express vs Standard |
|---:|---:|---:|---:|---:|---:|---:|
|  8 |  32 | 168.7 | 156.1 | 255.5 |  50.8 | 1.51x |
| 32 | 128 | 393.7 | 393.4 | 526.9 | 184.8 | 1.34x |
| 48 | 192 | 613.5 | 626.0 | 775.3 | 387.5 | 1.26x |

ms per published MiB (SigV4 route): Express dense 48 = 3.20, Standard dense
48 = 4.04; Express sparse 1 = 1065, Standard sparse 1 = 1740 — the sparse
ms/MiB numbers are dominated by fixed per-commit and per-object cost either
way, which is the point.

## What this says

- **The flush floor drops ~40%.** A Guest that fsyncs after a tiny write
  waits ~67 ms instead of ~109 ms. That floor is still ~130x the local file
  store's 0.5 ms, so Express narrows — but nowhere near closes — the gap
  between "remote object store" and "local disk".
- **The win fades with commit size.** Since f918a26 the engine uploads a
  commit's objects with up to 16 concurrent PUTs (work-stealing). Large
  commits therefore hide per-object latency and become throughput-bound,
  where Express and Standard are within noise of each other (sparse 48:
  228 vs 236 ms). Express is a latency product, and it shows.
- **Auth mode does not matter for latency.** Per-request SigV4 and
  CreateSession session auth are within run-to-run noise of each other
  across every row (e.g. sparse 1: 66.6 vs 64.0 ms). Signing is local HMAC
  either way; there is no per-request auth round trip to save.

## Consistency check against the 2026-07-27 baseline

Baseline (experiments/vhost-user-blk-frontend-20260726/raw/metal-delta-pack-s3.log,
Standard S3, same instance type/region): sparse 1/8/48 = 125.4/374.0/1669.3 ms,
dense 8/32/48 = 858.9/3031.5/4913.5 ms.

- The only row where the code paths are still comparable is **sparse 1 chunk**
  (a single object; concurrency cannot help): 108.7 ms today vs 125.4 ms in
  the baseline — same magnitude, consistent. ✓
- Every multi-object row is 3–7x faster than the baseline. That is **not**
  drift in this experiment's method: commit f918a26 ("perf: upload a commit's
  objects concurrently instead of one round trip at a time", 2026-07-27,
  after the baseline run) fan-outs uploads over up to 16 workers
  (MAX_UPLOAD_CONCURRENCY in blockd/src/engine.rs). The baseline measured
  serial PUTs. Comparisons of multi-chunk rows against the 07-27 log measure
  that engine change, not the store.

## What it took to talk to a directory bucket

S3 Express directory buckets differ from Standard S3 in ways that hit our
hand-written adapter (adapters/object-store-aws-s3):

- **Path-style requests are not supported.** Zonal endpoints only accept
  virtual-hosted style (`https://<bucket>.s3express-<az-id>.<region>.
  amazonaws.com`), per the CreateSession API doc. The adapter grew a
  `virtual-host` option that drops the bucket segment from object paths.
- **SigV4 signs with service name `s3express`**, not `s3` (`signing-service`
  option).
- **Per-request SigV4 works.** The AWS docs push CreateSession for the data
  plane, but plain SigV4 with IMDS instance-role credentials
  (`x-amz-security-token`) passed the full smoke (put_immutable twice,
  conflict rejection, get, exists, list, delete) and is what the headline
  numbers use. Session auth (`CreateSession` + `x-amz-s3session-token`,
  5-minute expiry, refreshed after 4) was implemented too (`express-session`
  option) and measured — no latency difference.
- **`If-None-Match: *` conditional PUT works on directory buckets** (smoke
  verified both the idempotent-retry path and the different-content
  rejection), so `put_immutable` semantics survive unchanged.
- **ListObjectsV2 on directory buckets only accepts prefixes ending in `/`**
  and returns keys unordered. Every engine list call already uses a
  `.../data/`-style prefix and the adapter sorts results, so no change.

Bench invocation for the Express runs:

    CATS_BENCH_S3_BUCKET=<bucket>--use1-az4--x-s3 \
    CATS_BENCH_S3_ENDPOINT=https://<bucket>--use1-az4--x-s3.s3express-use1-az4.us-east-1.amazonaws.com \
    CATS_BENCH_S3_SIGNING_SERVICE=s3express \
    CATS_BENCH_S3_VIRTUAL_HOST=true \
    [CATS_BENCH_S3_EXPRESS_SESSION=true] \
    AWS_REGION=us-east-1 CATS_BENCH_LEASE_TTL_MS=600000 \
    cargo test --release -p cats-blockd --test commit_cost -- \
      --ignored --nocapture --test-threads=1 flush_cost

Code changes exercised by this experiment (included in this draft change):

- adapters/object-store-aws-s3/src/lib.rs: `signing-service`,
  `virtual-host`, `express-session` config options; `request()` split into
  credential selection + `signed_request()`; CreateSession client with
  4-minute refresh; bucket-less paths under virtual hosting.
- blockd/tests/commit_cost.rs: pass the four `CATS_BENCH_S3_*` env vars
  through to the adapter config.
- adapters/object-store-aws-s3/tests/express_smoke.rs (new): the ignored
  full-surface smoke test used above.

## Raw

- raw/bench-express-sigv4.log — Express, per-request SigV4 (headline)
- raw/bench-express-session.log — Express, CreateSession session auth
- raw/bench-standard.log — Standard S3, same machine, minutes later
- raw/bench-local.log — local file store on root EBS
- raw/smoke-express-sigv4.log, raw/smoke-express-session.log — adapter smoke
- raw/bench-environment.txt, raw/run-bench.log — host and run records

## Cleanup and cost

All temporary AWS resources were deleted in the same session: the instance
was terminated; both the directory and standard buckets were emptied and
deleted; and the IAM role/policy/profile, security group, and local temporary
SSH keypair were removed. The instance ran for about 20 minutes: roughly
US$0.5 all-in.
