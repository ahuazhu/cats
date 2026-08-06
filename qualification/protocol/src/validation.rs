mod catalog;
mod coverage;
mod primitive;
mod trial;

pub use catalog::validate_catalog;
pub use coverage::validate_coverage_ledger;
pub use primitive::{
    catalog_sha256, document_sha256, event_record_sha256, observation_record_sha256,
    terminal_record_sha256, ValidationError,
};
pub use trial::validate_trial_record;

pub const FUNCTIONAL_CASE_COUNT: usize = 104;
pub const AWS_PERFORMANCE_CASE_COUNT: usize = 9;
pub const RELEASE_REQUIRED_CASE_COUNT: usize = 113;
pub const COST_OBSERVATION_CASE_COUNT: usize = 1;
pub const TOTAL_CASE_COUNT: usize = 114;
