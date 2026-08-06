use std::collections::{HashMap, HashSet};

use crate::{ActorRole, EventKind, SecretScanStatus, TrialEvent, TrialRecord};

use super::{
    super::primitive::{is_scoped_id, require, require_digest, ValidationError},
    events::identity_for_role,
};

const MAX_EVIDENCE_BYTES: u64 = 1_073_741_824;

pub(super) fn validate_evidence(
    record: &TrialRecord,
    required_kinds: &[String],
) -> Result<(), ValidationError> {
    require(!record.evidence.is_empty(), "trial has no sealed evidence")?;
    let events: HashMap<&str, &TrialEvent> = record
        .events
        .iter()
        .map(|event| (event.event_id.as_str(), event))
        .collect();
    let sequences: HashSet<u64> = record
        .events
        .iter()
        .map(|event| event.ledger_sequence)
        .collect();
    let observer_id = identity_for_role(record, ActorRole::Observer)?;
    let verifier_id = identity_for_role(record, ActorRole::Verifier)?;
    let terminal_sequence = record
        .events
        .last()
        .map(|event| event.ledger_sequence)
        .ok_or_else(|| ValidationError::new("trial has no terminal sequence"))?;
    let mut ids = HashSet::new();
    let mut seal_ids = HashSet::new();
    let mut verify_ids = HashSet::new();
    let kinds: HashSet<&str> = record
        .evidence
        .iter()
        .map(|evidence| evidence.kind.as_str())
        .collect();
    for required in required_kinds {
        require(
            kinds.contains(required.as_str()),
            format!("required evidence kind missing: {required}"),
        )?;
    }
    for evidence in &record.evidence {
        require(is_scoped_id(&evidence.evidence_id), "invalid evidence_id")?;
        require(
            ids.insert(evidence.evidence_id.as_str()),
            "duplicate evidence_id",
        )?;
        require(
            evidence.run_id == record.binding.run_id,
            "evidence run_id binding mismatch",
        )?;
        require(
            evidence.window_id == record.window_id,
            "evidence window_id binding mismatch",
        )?;
        require(
            evidence.trial_id == record.trial_id,
            "evidence trial_id binding mismatch",
        )?;
        require(
            evidence.producer_identity_id == observer_id,
            "raw evidence must be produced by observer",
        )?;
        require(!evidence.kind.trim().is_empty(), "evidence kind is empty")?;
        require(
            !evidence.media_type.trim().is_empty(),
            "evidence media_type is empty",
        )?;
        require_digest(&evidence.sha256, "evidence sha256")?;
        require(
            evidence.immutable_locator == format!("urn:sha256:{}", evidence.sha256),
            "evidence locator must be content-addressed by its sha256",
        )?;
        require(
            evidence.size_bytes > 0,
            "empty evidence object is forbidden",
        )?;
        require(
            evidence.declared_max_bytes > 0
                && evidence.declared_max_bytes <= MAX_EVIDENCE_BYTES
                && evidence.size_bytes <= evidence.declared_max_bytes,
            "evidence object exceeds its bounded size contract",
        )?;
        require_digest(&evidence.redaction_policy_sha256, "redaction_policy_sha256")?;
        require(
            evidence.secret_scan == SecretScanStatus::Passed,
            "evidence secret scan must pass",
        )?;
        require(
            evidence.first_event_sequence <= evidence.last_event_sequence
                && sequences.contains(&evidence.first_event_sequence)
                && sequences.contains(&evidence.last_event_sequence),
            "evidence event sequence range is not in the event ledger",
        )?;
        let sealed = events
            .get(evidence.sealed_event_id.as_str())
            .copied()
            .ok_or_else(|| ValidationError::new("evidence seal event is missing"))?;
        let verified = events
            .get(evidence.verified_event_id.as_str())
            .copied()
            .ok_or_else(|| ValidationError::new("evidence verification event is missing"))?;
        validate_evidence_event(sealed, EventKind::EvidenceSealed, observer_id, evidence)?;
        validate_evidence_event(verified, EventKind::EvidenceVerified, verifier_id, evidence)?;
        require(
            evidence.last_event_sequence < sealed.ledger_sequence
                && sealed.ledger_sequence < verified.ledger_sequence
                && verified.ledger_sequence < terminal_sequence,
            "evidence must be captured, sealed, verified, then used by terminal in ledger order",
        )?;
        require(
            seal_ids.insert(sealed.event_id.as_str()),
            "seal event reused across evidence",
        )?;
        require(
            verify_ids.insert(verified.event_id.as_str()),
            "verification event reused across evidence",
        )?;
    }
    let ledger_seals: HashSet<&str> = record
        .events
        .iter()
        .filter(|event| event.kind == EventKind::EvidenceSealed)
        .map(|event| event.event_id.as_str())
        .collect();
    let ledger_verifications: HashSet<&str> = record
        .events
        .iter()
        .filter(|event| event.kind == EventKind::EvidenceVerified)
        .map(|event| event.event_id.as_str())
        .collect();
    require(
        seal_ids == ledger_seals,
        "event ledger contains unlinked evidence seals",
    )?;
    require(
        verify_ids == ledger_verifications,
        "event ledger contains unlinked evidence verifications",
    )
}

fn validate_evidence_event(
    event: &TrialEvent,
    kind: EventKind,
    actor_id: &str,
    evidence: &crate::EvidenceObject,
) -> Result<(), ValidationError> {
    require(
        event.kind == kind
            && event.actor_identity_id == actor_id
            && event.subject_id.as_deref() == Some(evidence.evidence_id.as_str())
            && event.subject_sha256.as_deref() == Some(evidence.sha256.as_str()),
        format!("{:?} does not exactly bind evidence id/digest/actor", kind),
    )
}
