Cats provides durable Linux microVM resources behind one immutable Workspace boundary.

## Current release surface

The signed runtime cutover deliberately exposes a narrow product surface:

- Create, list, and inspect Cats.
- Create, list, and inspect PersistentDisks.
- Inspect one exact accepted Operation by ID.
- Use the Guest-local Runtime API and the independent identity/billing surfaces.

Cat lifecycle, Guest command, deployment, Endpoint, and delete mutations are unavailable. PersistentDisk attachment, snapshot, capacity change, and delete mutations are also unavailable. The console and CLI fail closed instead of probing legacy routes.

## Choose a path

<a href="/docs/getting-started/" class="doc-card"><strong>Get started</strong>Create and inspect a Cat with the current console or CLI.</a> <a href="/docs/cats-lifecycle/" class="doc-card"><strong>Cats and lifecycle</strong>Understand the lifecycle model and the current mutation boundary.</a> <a href="/docs/storage-disks/" class="doc-card"><strong>Storage and disks</strong>Create immutable-capacity disks and understand durability.</a> <a href="/docs/endpoints/" class="doc-card"><strong>Endpoints</strong>Understand the target networking model and current release boundary.</a> <a href="/docs/cli-reference/" class="doc-card"><strong>CLI reference</strong>Commands shipped by the current release.</a> <a href="/docs/api-reference/" class="doc-card"><strong>HTTP API reference</strong>Exact current product routes and DTOs.</a> <a href="/docs/runtime-api/" class="doc-card"><strong>Guest Runtime API</strong>Use the Guest-local Unix socket.</a> <a href="/docs/console-workspaces/" class="doc-card"><strong>Console and identity</strong>WorkOS sessions and Workspace isolation.</a> <a href="/docs/operations-troubleshooting/" class="doc-card"><strong>Operations and troubleshooting</strong>Recover exact create identity and collect evidence.</a>

## Product model

A Cat owns one RootDisk. A PersistentDisk is an independent RWO resource whose release capacity is immutable. Desired runtime state and signed Volume Authority—not a browser or CLI—coordinate lifecycle and writer epochs.
