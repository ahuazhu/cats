//! Versioned, side-effect-free contracts for release qualification evidence.
//!
//! This crate deliberately contains no scheduler, infrastructure client, fault
//! injector, scenario implementation, or mutable authority. It validates files
//! produced by those future components at their trust boundary.

mod model;
mod validation;

pub use model::*;
pub use validation::{
    catalog_sha256, document_sha256, event_record_sha256, observation_record_sha256,
    terminal_record_sha256, validate_catalog, validate_coverage_ledger, validate_trial_record,
    ValidationError, AWS_PERFORMANCE_CASE_COUNT, COST_OBSERVATION_CASE_COUNT,
    FUNCTIONAL_CASE_COUNT, RELEASE_REQUIRED_CASE_COUNT, TOTAL_CASE_COUNT,
};
