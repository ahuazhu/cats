//! PostgreSQL persistence for the ADR-0042 volume authority core.
//!
//! The semantic cutover does not compile the legacy AgentSession machine
//! entrypoints. `object_write.rs`, `lifecycle_volume_transitions.rs`,
//! `persistent_config_mutation.rs`, `delete_sweeper.rs`, `volume.rs` and their
//! focused tests remain as strict storage-authority source for the forthcoming
//! semantic storage adapter; their presence does not mean the retired HTTP or
//! command-poll protocol is composed.

pub(crate) mod host_fence_provider_queue;
mod object_write_root;
pub(super) mod pg_codec;
pub(crate) mod placement_policy;
pub(crate) mod production_mutation_admission;
pub(super) mod rows;
