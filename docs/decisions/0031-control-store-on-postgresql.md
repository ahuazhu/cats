# ADR-0031: The control store lives in managed PostgreSQL, with no SQLite era to carry

- Status: Accepted
- Date: 2026-08-05
- Relates to: ADR-0003 (Direct-S3 backend), ADR-0004 (dev stack), ADR-0029 (database password authority); issue #103

## Context

The control plane's resource authority — accounts, workspaces, the billing
ledger, cats, disks, mount bindings, nodes, operations, routes, work leases —
lived in a single SQLite file on a single EBS volume behind a single-replica
`Recreate` Deployment. That stack of single points was #103: any pod or
volume event was a full control-plane outage, losing the volume erased the
business, and the store could never scale past one replica.

The dev-shape SQLite implementation had no port abstraction and 247 call
sites. A trait-based dual-backend migration (contract suite over both stores,
export/import tooling, rehearsed cutover) was designed and then deliberately
rejected by the operator: production data at this stage is not worth carrying
(two accounts, re-creatable), and compatibility machinery is not worth
building for a backend we are deleting.

## Decision

Rewrite the store in place on the sync `postgres` client, keeping every
method signature and its semantics; delete the SQLite implementation and its
migration ladder rather than abstracting over both.

- **Same database as the storage MetadataStore.** The control tables share
  the managed PostgreSQL instance and database that already holds the
  `cats_storage_*` tables; names are disjoint. A literal DSN may come from
  `--control-store-url` / `CATS_CONTROL_POSTGRES_URL`, falling back to
  `CATS_POSTGRES_URL`. Production mounts that same runtime Secret and uses
  `--control-store-url-file`; the file is re-read on every connect so a
  reconnect observes password rotation (ADR-0029). No new secret is needed.
  The CA file comes from `CATS_CONTROL_POSTGRES_CA_FILE`.
- **A fresh schema ladder.** PostgreSQL schema version 1 is the final SQLite
  layout (v5) re-expressed natively (BOOLEAN columns, plpgsql immutability
  triggers, a `control_schema_version` row instead of `PRAGMA user_version`).
  `Store::connect` upgrades in place inside
  `[OLDEST_MIGRATABLE_SCHEMA_VERSION, SCHEMA_VERSION]` and refuses anything
  else, exactly as `open` did; the production deploy gate now reads the
  stamped version through a one-off in-cluster `psql` pod instead of the
  SQLite file header.
- **No data migration.** The pre-cutover SQLite contents are abandoned; the
  first PostgreSQL boot starts empty and the WorkOS mapping re-provisions
  accounts. The final manual EBS snapshot remains as an archive.
- **The sync client hops off async runtimes.** The `postgres` crate owns an
  internal runtime; using or dropping it on a tokio worker panics. Every
  database operation funnels through `off_runtime`, which runs the closure on
  a scoped helper thread when an ambient runtime exists. Callers block either
  way — the same serialization the SQLite mutex imposed, preserved
  deliberately: the async-native rework is its own decision for the
  multi-replica stage of #103.
- **Tests require a real PostgreSQL and refuse to skip.** Each test isolates
  in a fresh schema via `options=-csearch_path%3D…`; CI provides a service
  container, `quality.sh` runs a disposable docker container, and an unset
  `CATS_TEST_POSTGRES_URL` fails loudly. Schema DDL takes a per-schema
  advisory lock so parallel tests do not queue on one global lock.

## Consequences

- The control plane no longer needs the EBS PVC, the `Recreate`-forced
  single-replica coupling to a volume, or the DLM snapshot stopgap; RDS
  backups cover the control tables. Multi-replica still waits on the
  leader/lease work (#103 stages that remain open).
- Local development and every workspace test now require docker (or an
  external PostgreSQL). The credential-free single-file dev shape is gone for
  the control store; the usage/credit dev stores keep their SQLite shape.
- Merging the change is the cutover: the next production deploy boots on an
  empty control database. Running Cats surface as agent-reported orphans and
  are re-adopted through reverse reconciliation (ADR-0030); accounts
  re-provision through WorkOS on first login.
- A future backend change repeats this playbook (rewrite + fresh ladder)
  unless multiple backends must coexist, at which point the port abstraction
  this ADR declined becomes the right tool.
