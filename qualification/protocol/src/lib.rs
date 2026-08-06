//! Versioned, side-effect-free contracts for release qualification evidence.
//!
//! This crate deliberately contains no scheduler, infrastructure client, fault
//! injector, scenario implementation, or mutable authority. It validates files
//! produced by those future components at their trust boundary.

mod model;
mod validation;

pub use model::*;
pub use validation::{
    actor_authority_signature, append_checkpoint_signature, append_ledger_root, catalog_sha256,
    document_sha256, event_record_sha256, observation_record_sha256, terminal_record_sha256,
    validate_catalog, validate_coverage_ledger, validate_final_qualification,
    validate_trial_record, ValidationError, AWS_PERFORMANCE_CASE_COUNT,
    COST_OBSERVATION_CASE_COUNT, ED25519_PRIVATE_SEED_BYTES, ED25519_PUBLIC_KEY_BYTES,
    FUNCTIONAL_CASE_COUNT, MAX_APPEND_RECEIPTS_DOCUMENT_BYTES, MAX_AUTHORITY_DOCUMENT_BYTES,
    MAX_CATALOG_DOCUMENT_BYTES, MAX_COVERAGE_DOCUMENT_BYTES, MAX_EVENTS_PER_TRIAL,
    MAX_EVIDENCE_PER_TRIAL, MAX_FINAL_DOCUMENT_BYTES, MAX_TEXT_BYTES, MAX_TRIAL_DOCUMENTS,
    MAX_TRIAL_DOCUMENT_BYTES, MAX_TRIAL_PLAN_DOCUMENT_BYTES, RELEASE_REQUIRED_CASE_COUNT,
    TOTAL_CASE_COUNT,
};
