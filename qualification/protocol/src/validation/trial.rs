mod events;
mod evidence;
mod terminal;

use crate::{Catalog, TrialRecord, TRIAL_SCHEMA};

use super::{
    catalog::validate_catalog,
    primitive::{is_scoped_id, require, require_digest, validate_binding, ValidationError},
};
use events::{validate_events, validate_identities};
use evidence::validate_evidence;
use terminal::{validate_observation, validate_terminal};

pub fn validate_trial_record(
    record: &TrialRecord,
    catalog: &Catalog,
    catalog_digest: &str,
) -> Result<(), ValidationError> {
    validate_catalog(catalog)?;
    require_digest(catalog_digest, "actual catalog sha256")?;
    require(record.schema == TRIAL_SCHEMA, "unsupported trial schema")?;
    validate_binding(&record.binding)?;
    require(
        record.binding.catalog_sha256 == catalog_digest,
        "trial catalog digest does not match the catalog bytes",
    )?;
    require(is_scoped_id(&record.window_id), "invalid window_id")?;
    require(is_scoped_id(&record.trial_id), "invalid trial_id")?;
    let case = catalog
        .cases
        .iter()
        .find(|case| case.id == record.case_id)
        .ok_or_else(|| ValidationError::new("trial case_id is not in the bound catalog"))?;
    validate_identities(record)?;
    validate_events(record)?;
    validate_observation(record)?;
    validate_evidence(record, &case.required_evidence_kinds)?;
    validate_terminal(record)
}
