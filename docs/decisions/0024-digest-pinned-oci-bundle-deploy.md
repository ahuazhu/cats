# ADR-0024: Deploy digest-pinned OCI bundles without a Guest container daemon

- Status: Accepted
- Date: 2026-07-31

## Context

Cats needs to install an already-built application in a Cat. Rebuilding or
running `docker save` workflows inside every Guest duplicates registry, layer,
and supervision logic. The Guest kernel does not need Docker or OverlayFS to
consume the immutable content and process configuration defined by OCI images.

## Decision

1. The CLI and API accept an OCI image by immutable `sha256` digest. Tags and
   ambiguous tag-plus-digest inputs are rejected before network access.
2. The Guest agent resolves OCI or Docker v2 manifests, selects the exact Guest
   Linux architecture, and verifies descriptor digest and size for the
   manifest, config, and every compressed layer.
3. Registry access uses the Guest's ordinary application network. Optional pull
   credentials are transient request data read by the CLI without placing the
   password in argv; Cats does not persist or log them.
4. Layers are flattened in order into
   `/var/lib/cats/oci/<app>/releases/<manifest-digest>/`. Extraction implements
   whiteout semantics and preserves supported metadata while rejecting path
   traversal, parent-symlink escape, and unsupported special files.
5. Cats does not run Docker, containerd, or another image block device in the
   Guest. One digest occupies one expanded RootDisk directory; ChunkStore sees
   ordinary file writes and keeps its existing durability and GC semantics.
6. Activation atomically updates the stable `current` pointer and a systemd
   unit whose `RootDirectory=` names the immutable digest directory directly.
   OCI entrypoint, cmd, environment, working directory, and user/group map to
   that unit. systemd is the sole application supervisor across Running,
   Suspended, Warm, and Cold boot.
7. The deployment holds a Node activity guard across wake, pull, extraction,
   activation, and unit start. Completion means the unit reached systemd active
   state; it does not claim application-level HTTP or dependency readiness.

## Safety contract

- A digest or size mismatch cannot activate a release or replace the current
  unit.
- Whiteouts affect lower layers but never appear in the final filesystem.
- Failed staging may leave only a clearly named, reclaimable work directory;
  the previous active digest remains unchanged.
- Channels, archive entries, expanded bytes, and credential fields are bounded.
- Registry credentials do not appear in CLI argv, debug output, resource rows,
  Operations, or logs.
- Contract tests exercise manifest selection, config and layer verification,
  extraction, activation, and systemd unit generation through the production
  path.

## Configuration and isolation boundary

Environment values written into the systemd unit are persistent RootDisk
configuration and are not a secret store. Sensitive values use a separately
authorized bootstrap or secret-delivery mechanism; naming an input `env` does
not make it confidential.

The expanded OCI root is a process filesystem view, not a new tenant boundary.
Applications that require security isolation run in separate Cats. Release
catalogs, rollback UX, unused-release reclamation, image signing policy, SBOM
policy, and application readiness are separate product capabilities rather
than implicit behavior of this deploy contract.

## Consequences

CI publishes a standard immutable OCI image and Cats reuses systemd, RootDisk,
and lifecycle semantics already present in the Guest. The tradeoff is expanded
disk use per digest and no copy-on-write container layer filesystem inside the
Cat.
