Cats gives you a long-lived Linux microVM: its own kernel, its own persistent disk, and a stable address. Compute can stop while the disk, the name and the address stay.

**Nothing to install to begin** — create a Cat in the console and it is ready.

## Choose a path

<a href="/docs/getting-started/" class="doc-card"><strong>Get started</strong>Build the CLI, configure access, create a Cat, and run your first command.</a> <a href="/docs/cats-lifecycle/" class="doc-card"><strong>Cats and lifecycle</strong>Understand Running, Suspended, Warm, Cold, wake behavior, and deletion.</a> <a href="/docs/storage-disks/" class="doc-card"><strong>Storage and disks</strong>Use RootDisk, PersistentDisk, snapshots, resize, mount, and durable FLUSH.</a> <a href="/docs/endpoints/" class="doc-card"><strong>Endpoints</strong>Publish a Guest port, choose wake behavior, and understand current networking scope.</a> <a href="/docs/cli-reference/" class="doc-card"><strong>CLI reference</strong>All commands, global options, output modes, and automation behavior.</a> <a href="/docs/api-reference/" class="doc-card"><strong>HTTP API reference</strong>Routes, authentication scopes, idempotency, request bodies, Operations, and errors.</a> <a href="/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>Keep work-driven Cats awake through HTTP over a Guest-local Unix socket.</a> <a href="/docs/console-workspaces/" class="doc-card"><strong>Console and identity</strong>WorkOS browser/device sign-in, workspaces, sessions, and language settings.</a> <a href="/docs/operations-troubleshooting/" class="doc-card"><strong>Operations and troubleshooting</strong>Follow asynchronous work, read errors, and recover from common failures.</a>

## Product model

A **Cat** is a long-lived Linux microVM with a required RootDisk. Compute may stop while the Cat name and durable disk remain. A Workspace is the user-visible authorization and resource boundary, and its immutable ID is what the HTTP API routes on.

- **RootDisk** follows the Cat and is deleted with it.
- **PersistentDisk** is independent, grow-only in V1, and read-write attached to at most one Cat.
- **Endpoint** maps a stable hostname to one Guest port and may wake a sleeping Cat.
- **Operation** records every asynchronous mutation and its final structured error.

## What you will hit today

Cats is moving quickly. These are the boundaries you will actually run into:

| Capability | Where it stands |
|----|----|
| Endpoint protocols | HTTP/1.1, with HTTPS terminated at the regional edge. **Inbound WebSocket is not supported yet.** |
| Guest outbound network | Every Cat gets its own network and outbound access, with sensitive destinations blocked. Private Guest-to-Guest networking across nodes is not offered yet. |
| PersistentDisk | Read-write on one Cat at a time, and it can grow but not shrink. |
| Snapshots | You can create one; convenience commands to list and restore are not there yet — use the HTTP API. |
| Wake concurrency | A node caps how many Cats wake at once. Beyond that, wakes **queue instead of failing**, so a wake can be slower at peak. |
| Interactive terminal | `cats shell` needs the CLI. The console runs one command at a time, with no persistent terminal. |

**Performance numbers are evidence, not an SLA**

Every performance number we publish carries its sample count, hardware and measurement boundary. Prototype measurements never become production commitments — judge them against your own workload.

## Documentation conventions

Examples use the Workspace selected by `cats login` and a Cat named `dev`. Replace them for your deployment. Sizes accept binary suffixes such as `512MiB` and `8GiB`.
