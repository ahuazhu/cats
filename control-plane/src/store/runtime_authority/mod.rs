//! PostgreSQL persistence for the ADR-0042 volume authority core.
//!
//! Only the seams the ADR-0059 semantic protocol actually composes live here:
//! placement policy, production mutation admission and the Strict PersistentDisk
//! authority. Git history is the archive for retired coordination code.

pub(super) mod pg_codec;
pub(crate) mod placement_policy;
pub(crate) mod production_mutation_admission;
pub(super) mod rows;
pub(crate) mod semantic_persistent_disk;
