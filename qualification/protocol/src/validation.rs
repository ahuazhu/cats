mod authority;
mod catalog;
mod coverage;
mod environment;
mod final_qualification;
mod primitive;
mod trial;

pub use authority::{actor_authority_signature, append_checkpoint_signature, append_ledger_root};
pub use catalog::validate_catalog;
pub use coverage::validate_coverage_ledger;
pub use final_qualification::validate_final_qualification;
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

pub const MAX_CATALOG_DOCUMENT_BYTES: u64 = 1_048_576;
pub const MAX_TRIAL_PLAN_DOCUMENT_BYTES: u64 = 262_144;
pub const MAX_TRIAL_DOCUMENT_BYTES: u64 = 1_048_576;
pub const MAX_COVERAGE_DOCUMENT_BYTES: u64 = 1_048_576;
pub const MAX_FINAL_DOCUMENT_BYTES: u64 = 65_536;
pub const MAX_AUTHORITY_DOCUMENT_BYTES: u64 = 65_536;
pub const MAX_APPEND_RECEIPTS_DOCUMENT_BYTES: u64 = 524_288;
pub const MAX_TRIAL_DOCUMENTS: usize = TOTAL_CASE_COUNT;
pub const MAX_EVENTS_PER_TRIAL: usize = 256;
pub const MAX_EVIDENCE_PER_TRIAL: usize = 64;
pub const MAX_TEXT_BYTES: usize = 4_096;
pub const ED25519_PRIVATE_SEED_BYTES: usize = 32;
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;
