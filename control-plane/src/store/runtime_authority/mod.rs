//! PostgreSQL persistence for the ADR-0042 volume authority core.
//!
//! Only the seams the ADR-0059 semantic protocol actually composes live here:
//! the Host-fence provider queue, object-writer authority roots, placement
//! policy, production mutation admission and the Strict PersistentDisk
//! authority. The retired ADR-0056 lifecycle-Operation, AgentSession and
//! command-poll entrypoints were removed rather than kept as uncompiled
//! source; Git history is their archive.

pub(crate) mod host_fence_provider_queue;
mod object_write_root;
pub(super) mod pg_codec;
pub(crate) mod placement_policy;
pub(crate) mod production_mutation_admission;
pub(super) mod rows;
pub(crate) mod semantic_persistent_disk;
