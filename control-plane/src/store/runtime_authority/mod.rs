//! PostgreSQL persistence for the ADR-0042 volume authority core.

pub(crate) mod cat_create_service;
mod covered_commit;
pub(crate) mod gateway_identity;
pub(crate) mod image_manifest_resolver;
pub(crate) mod normal_delete;
pub(crate) mod persistent_disk_create_service;
pub(super) mod pg_codec;
pub(crate) mod placement_planner;
pub(crate) mod placement_policy;
mod product;
pub(crate) mod product_identity;
pub(crate) mod product_mutation_service;
pub(crate) mod product_reads;
mod product_rows;
pub(crate) mod route_epoch_engine;
pub(crate) mod route_signer;
pub(crate) mod route_signing_authority;
pub(super) mod rows;
pub(crate) mod runtime_spine;
mod volume;
#[allow(
    dead_code,
    reason = "A22 authenticated Store entrypoints are consumed when the internal HTTP routes are composed"
)]
pub(crate) mod volume_transition_auth;

pub(crate) use product::RuntimeOperationRead;
#[allow(
    dead_code,
    reason = "A22 transaction-local evidence loader is composed by the authenticated A23 route"
)]
pub(crate) mod volume_transition_evidence;

#[cfg(test)]
pub(crate) mod cat_create_service_tests;

#[cfg(test)]
mod persistent_disk_create_service_tests;

#[cfg(test)]
pub(crate) mod product_tests;

#[cfg(test)]
mod placement_policy_tests;

#[cfg(test)]
mod gateway_identity_tests;

#[cfg(test)]
mod route_signing_authority_tests;

#[cfg(test)]
mod placement_planner_tests;

#[cfg(test)]
pub(crate) mod runtime_spine_tests;

#[cfg(test)]
pub(crate) mod tests;
