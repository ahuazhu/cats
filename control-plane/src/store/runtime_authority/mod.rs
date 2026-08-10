//! PostgreSQL persistence for the ADR-0042 volume authority core.

#[allow(
    dead_code,
    reason = "F2c is the ready-to-wire service boundary consumed by the F2d HTTP cutover"
)]
pub(crate) mod cat_create_service;
#[allow(
    dead_code,
    reason = "the Gateway authority is consumed by the Route v2 machine listener composition"
)]
pub(crate) mod gateway_identity;
#[allow(
    dead_code,
    reason = "A21 production resolver is composed when the F2d Cat-create route is switched"
)]
pub(crate) mod image_manifest_resolver;
pub(super) mod pg_codec;
pub(crate) mod placement_planner;
pub(crate) mod placement_policy;
mod product;
mod product_rows;
#[allow(
    dead_code,
    reason = "the closed snapshot loader is composed with the Route Grant v2 resolve service after the Node transport target authority lands"
)]
pub(crate) mod route_signer;
#[allow(
    dead_code,
    reason = "the signer PG binding is composed by the Route v2 machine listener in the next commit"
)]
pub(crate) mod route_signing_authority;
pub(super) mod rows;
#[allow(
    dead_code,
    reason = "F3c is consumed by the F3b authenticated routes and F2d planner composition"
)]
pub(crate) mod runtime_spine;
mod volume;
#[allow(
    dead_code,
    reason = "A22 authenticated Store entrypoints are consumed when the internal HTTP routes are composed"
)]
pub(crate) mod volume_transition_auth;
#[allow(
    dead_code,
    reason = "A22 transaction-local evidence loader is composed by the authenticated A23 route"
)]
pub(crate) mod volume_transition_evidence;

#[cfg(test)]
pub(crate) mod cat_create_service_tests;

#[cfg(test)]
mod product_tests;

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
