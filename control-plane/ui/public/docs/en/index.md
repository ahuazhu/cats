**Public by design**

These product and usage docs require no Cats session. The console and resource APIs still enforce their normal authentication boundaries.

## Choose a path

<a href="/docs/getting-started/" class="doc-card"><strong>Get started</strong>Build the CLI, configure access, create a Cat, and run your first command.</a> <a href="/docs/cats-lifecycle/" class="doc-card"><strong>Cats and lifecycle</strong>Understand Running, Suspended, Warm, Cold, wake behavior, and deletion.</a> <a href="/docs/storage-disks/" class="doc-card"><strong>Storage and disks</strong>Use RootDisk, PersistentDisk, snapshots, resize, mount, and durable FLUSH.</a> <a href="/docs/endpoints/" class="doc-card"><strong>Endpoints</strong>Publish a Guest port, choose wake behavior, and understand current networking scope.</a> <a href="/docs/cli-reference/" class="doc-card"><strong>CLI reference</strong>All commands, global options, output modes, and automation behavior.</a> <a href="/docs/api-reference/" class="doc-card"><strong>HTTP API reference</strong>Routes, authentication scopes, idempotency, request bodies, Operations, and errors.</a> <a href="/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>Keep work-driven Cats awake through HTTP over a Guest-local Unix socket.</a> <a href="/docs/console-workspaces/" class="doc-card"><strong>Console and identity</strong>WorkOS browser/device sign-in, workspaces, sessions, and language settings.</a> <a href="/docs/operations-troubleshooting/" class="doc-card"><strong>Operations and troubleshooting</strong>Follow asynchronous work, read errors, and recover from common failures.</a>

## Product model

A **Cat** is a long-lived Linux microVM with a required RootDisk. Compute may stop while the Cat name and durable disk remain. A Workspace is the user-visible authorization and resource boundary; the V1 HTTP API keeps the compatible `project` path segment underneath.

- **RootDisk** follows the Cat and is deleted with it.
- **PersistentDisk** is independent, grow-only in V1, and read-write attached to at most one Cat.
- **Endpoint** maps a stable hostname to one Guest port and may wake a sleeping Cat.
- **Operation** records every asynchronous mutation and its final structured error.

## Current V1 developer shape

The Rust workspace implements the control plane, CLI, embedded user/admin consoles, node and Guest agents, endpoint gateway contracts, ChunkStore engine, provider-neutral storage adapters, and a Cloud Hypervisor Phase-A path. The following limitations matter when evaluating or operating this source version:

| Area | Current status | What it means |
|----|----|----|
| Block frontend | Kernel NBD by default; native vhost-user-blk available | Both frontends drive the same engine and commit protocol, and both passed the same bare-metal acceptance run with real KVM including Warm snapshot/restore. Kernel NBD stays the default for a measured write-throughput trade-off, not for lack of validation. |
| Guest networking | Tap/overlay not implemented | Endpoint routing is covered in the FakeVmm development path; do not claim full CH Guest networking yet. |
| Concurrent wakes | Bounded per node | Suspended/Warm wakes are admitted against a node budget accounted in resume-commitment bytes; excess wakes queue rather than fail. Defaults match the 2026-07-21 validated point (10 concurrent) and are not a proven optimum. |
| Control metadata | SQLite development store | The PostgreSQL storage metadata adapter exists, but the project resource store is still SQLite-shaped development state. |
| Privilege separation | Not implemented | Run development components only in an appropriately isolated environment. |

**Performance numbers are evidence, not an SLA**

Repository benchmark results preserve sample count, environment, measurement boundary, and correctness oracle. Never promote those prototype measurements to a production commitment.

## Documentation conventions

Examples use the Workspace selected by `cats login` and a Cat named `dev`. Replace them for your deployment. Sizes accept binary suffixes such as `512MiB` and `8GiB`.
