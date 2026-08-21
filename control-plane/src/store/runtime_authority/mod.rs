//! PostgreSQL persistence for the ADR-0042 volume authority core.

pub(crate) mod cat_create_service;
mod covered_commit;
pub(crate) mod delete_sweeper;
pub(crate) mod gateway_identity;
pub(crate) mod host_fence_provider_queue;
pub(crate) mod image_manifest_resolver;
pub(crate) mod lifecycle_commands;
pub(crate) mod lifecycle_volume_transitions;
pub(crate) mod object_write;
/// Cross-crate object-write acceptance fixture. Release binaries never enable
/// `test-support`, so this composition cannot reach production.
#[cfg(feature = "test-support")]
pub(crate) mod object_write_e2e_fixture;
mod persistent_config_mutation;
pub(crate) mod persistent_disk_create_service;
pub(super) mod pg_codec;
pub(crate) mod placement_planner;
pub(crate) mod placement_policy;
mod product;
pub(crate) mod product_identity;
pub(crate) mod product_mutation_service;
pub(crate) mod product_reads;
mod product_rows;
pub(crate) mod production_mutation_admission;
pub(crate) mod route_controller;
pub(crate) mod route_epoch_engine;
pub(crate) mod route_operations;
pub(crate) mod route_signer;
pub(crate) mod route_signing_authority;
pub(super) mod rows;
pub(crate) mod runtime_spine;
mod volume;

#[cfg(test)]
pub(crate) mod cat_create_service_tests;

#[cfg(test)]
mod persistent_disk_create_service_tests;

#[cfg(test)]
mod persistent_config_mutation_tests;

#[cfg(test)]
mod lifecycle_commands_tests;

#[cfg(test)]
mod lifecycle_volume_transitions_tests;

#[cfg(test)]
mod route_operations_tests;

#[cfg(test)]
mod placement_policy_tests;

#[cfg(test)]
mod object_write_authority_tests;

#[cfg(test)]
mod host_fence_provider_queue_tests;

#[cfg(test)]
mod gateway_identity_tests;

#[cfg(test)]
mod placement_planner_tests;

#[cfg(test)]
pub(crate) mod runtime_spine_tests;
