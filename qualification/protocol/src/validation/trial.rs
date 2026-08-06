mod events;
mod evidence;
mod terminal;

use crate::{AuthorityTrustAnchors, Catalog, TrialRecord, TRIAL_SCHEMA};

use super::{
    authority::{validate_actor_authority, validate_append_receipts},
    catalog::validate_catalog,
    environment::validate_execution_environment,
    primitive::{
        is_scoped_id, parse_canonical_utc, require, require_digest, validate_binding,
        ValidationError,
    },
};
use events::validate_events;
use evidence::validate_evidence;
use terminal::{validate_observation, validate_terminal};

pub fn validate_trial_record(
    record: &TrialRecord,
    catalog: &Catalog,
    catalog_digest: &str,
    actor_authority_manifest_bytes: &[u8],
    append_receipts_bytes: &[u8],
    trust: &AuthorityTrustAnchors<'_>,
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
    require_digest(&record.append_receipts_sha256, "append_receipts_sha256")?;
    validate_execution_environment(&record.environment, case)?;
    let authority =
        validate_actor_authority(actor_authority_manifest_bytes, &record.binding, trust)?;
    validate_events(record, &authority.actors)?;
    validate_authority_window(record, &authority.issued_at, &authority.expires_at)?;
    validate_append_receipts(append_receipts_bytes, record, &authority.actors, trust)?;
    validate_evidence(record, &case.required_evidence_kinds, &authority.actors)?;
    validate_observation(record)?;
    validate_terminal(record, &authority.actors)
}

fn validate_authority_window(
    record: &TrialRecord,
    issued_at: &str,
    expires_at: &str,
) -> Result<(), ValidationError> {
    let issued = parse_canonical_utc(issued_at)
        .ok_or_else(|| ValidationError::new("actor authority issued_at is not canonical UTC"))?;
    let expires = parse_canonical_utc(expires_at)
        .ok_or_else(|| ValidationError::new("actor authority expires_at is not canonical UTC"))?;
    require(
        record.events.iter().all(|event| {
            parse_canonical_utc(&event.occurred_at)
                .is_some_and(|event_time| issued <= event_time && event_time <= expires)
        }),
        "event occurs outside authenticated actor-authority validity window",
    )
}
