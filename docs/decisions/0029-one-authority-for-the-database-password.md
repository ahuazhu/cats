# ADR-0029: Use one authority for the PostgreSQL password

- Status: Accepted
- Date: 2026-08-05

## Context

PostgreSQL authenticates when a connection is opened. A process can therefore
continue using an existing connection after a password rotation while every
new connection fails. If each deployment surface stores its own password copy,
the resulting failure appears gradually and different replicas disagree about
which credential is valid.

Credential rotation, connection pooling, and database leadership are separate
concerns. This ADR defines only the credential authority and refresh contract.
Connection bounds are covered by ADR-0034; control-plane authority and
leadership are covered by ADR-0031 and ADR-0032.

## Decision

1. The RDS `MasterUserSecret` is the only authority for the database password.
   Managed rotation stays enabled.
2. Long-lived component configuration stores only the secret reference and the
   non-rotating connection fields. It does not store a second authoritative
   password.
3. Runtime consumers read a local DSN file whenever they establish or
   re-establish a connection. They do not freeze the DSN captured at process
   startup.
4. Provider-specific deployment code renders that file from the authoritative
   secret:
   - metal uses a systemd pre-start action and periodic refresh;
   - Kubernetes uses one in-cluster refresh task;
   - the release path invokes the same Kubernetes task before replacing Pods.
5. A refresh performs this sequence atomically from the consumer's point of
   view:

   ```text
   read authority -> assemble DSN -> open and authenticate a test connection
                  -> replace the local copy
   ```

   The previous known-good copy remains in place if any step fails.
6. The deployment invocation fails closed before Pod replacement when the
   candidate credential cannot connect. A periodic refresh failure alerts but
   never restarts or evicts a healthy runtime.
7. Authentication failures are exported as metrics and routed to at least one
   confirmed recipient. A configured but undeliverable notification is not a
   successful detector.

The refresh implementation remains outside provider-neutral storage and
control contracts. Guest workloads never receive the database credential.

## Security and failure contract

- Passwords never appear in logs, command-line arguments, Pod specifications,
  Terraform state, or error text.
- DSN files use least-privilege ownership and permissions and are replaced
  atomically.
- Secrets Manager unavailability leaves the last known-good runtime copy in
  place; it is not added to the serving path of an already-running process.
- Reconnection rereads the file, so recovery does not require a process
  restart.
- Tests exercise a rotated password, an invalid candidate, unavailable secret
  delivery, reconnect after rotation, and redaction on every error path.

## Consequences

- Rotation no longer depends on synchronized deployments or manual password
  copying.
- Metal, Kubernetes, and release workflows consume one authority through their
  native delivery mechanisms.
- The refresh task and notification path become small operational components
  that must be monitored and tested.
- PostgreSQL availability is unchanged; this ADR neither introduces a second
  database authority nor provides database failover.
