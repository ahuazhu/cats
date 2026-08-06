mod authority;
mod catalog;
mod coverage;
mod trial;

pub use authority::*;
pub use catalog::*;
pub use coverage::*;
pub use trial::*;

pub const CATALOG_SCHEMA: &str = "cats.qualification.catalog/v1";
pub const TRIAL_SCHEMA: &str = "cats.qualification.trial/v1";
pub const COVERAGE_SCHEMA: &str = "cats.qualification.coverage-ledger/v1";
pub const TRIAL_PLAN_SCHEMA: &str = "cats.qualification.trial-plan/v1";
pub const ACTOR_AUTHORITY_SCHEMA: &str = "cats.qualification.actor-authority/v1";
pub const APPEND_RECEIPTS_SCHEMA: &str = "cats.qualification.append-receipts/v1";
pub const FINAL_QUALIFICATION_SCHEMA: &str = "cats.qualification.final/v1";
pub const PROTOCOL_VERSION: u16 = 1;
