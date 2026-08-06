use std::collections::{HashMap, HashSet};

use crate::{ActorAction, ActorIdentity, ActorRole, EventKind, TrialEvent, TrialRecord};

use super::super::primitive::{
    event_record_sha256, is_scoped_id, parse_canonical_utc, require, require_digest,
    ValidationError,
};

pub(super) fn validate_events(
    record: &TrialRecord,
    actors: &[ActorIdentity],
) -> Result<(), ValidationError> {
    require(
        record.events.len() >= 5 && record.events.len() <= super::super::MAX_EVENTS_PER_TRIAL,
        "trial event ledger is incomplete or exceeds its protocol cap",
    )?;
    require(
        record.events[0].kind == EventKind::RunBound,
        "first event must bind the run",
    )?;
    require(
        record.events[1].kind == EventKind::TrialScheduled,
        "second event must schedule the trial",
    )?;
    let identities: HashMap<&str, ActorRole> = actors
        .iter()
        .map(|identity| (identity.identity_id.as_str(), identity.role))
        .collect();
    let mut ids = HashSet::new();
    let mut previous_sequence = 0;
    let mut previous_time = None;
    let mut by_kind: HashMap<EventKind, Vec<u64>> = HashMap::new();
    for event in &record.events {
        require(
            event.ledger_sequence > previous_sequence,
            "event ledger_sequence must be strictly increasing",
        )?;
        previous_sequence = event.ledger_sequence;
        let time = parse_canonical_utc(&event.occurred_at).ok_or_else(|| {
            ValidationError::new("event time must be valid UTC with one-second precision")
        })?;
        if let Some(previous) = previous_time {
            require(time >= previous, "event occurred_at must be monotonic")?;
        }
        previous_time = Some(time);
        require(is_scoped_id(&event.event_id), "invalid event_id")?;
        require(ids.insert(event.event_id.as_str()), "duplicate event_id")?;
        require(
            event.run_id == record.binding.run_id,
            "event run_id binding mismatch",
        )?;
        require(
            event.window_id == record.window_id,
            "event window_id binding mismatch",
        )?;
        require(
            event.trial_id == record.trial_id,
            "event trial_id binding mismatch",
        )?;
        require_digest(&event.immutable_record_sha256, "immutable_record_sha256")?;
        require_event_subject(event)?;
        let role = identities
            .get(event.actor_identity_id.as_str())
            .copied()
            .ok_or_else(|| ValidationError::new("event actor is not a bound identity"))?;
        let (expected_role, action) = event_authority(event.kind);
        require(
            role == expected_role,
            format!("{:?} emitted by wrong role", event.kind),
        )?;
        let identity = actors
            .iter()
            .find(|identity| identity.identity_id == event.actor_identity_id)
            .ok_or_else(|| ValidationError::new("event actor disappeared"))?;
        require(
            identity.allowed_actions.contains(&action),
            "event actor lacks matching action",
        )?;
        require(
            event.immutable_record_sha256 == event_record_sha256(event)?,
            "event immutable_record_sha256 does not match canonical preimage",
        )?;
        by_kind
            .entry(event.kind)
            .or_default()
            .push(event.ledger_sequence);
    }
    require_single(&by_kind, EventKind::RunBound)?;
    require_single(&by_kind, EventKind::TrialScheduled)?;
    require_single(&by_kind, EventKind::TerminalIssued)?;
    require(
        record
            .events
            .last()
            .is_some_and(|event| event.kind == EventKind::TerminalIssued),
        "terminal event must be the final ledger event",
    )?;
    require(
        record.events[0].subject_id.as_deref() == Some(record.binding.run_id.as_str())
            && record.events[0].subject_sha256.as_deref()
                == Some(record.binding.artifact_manifest_sha256.as_str()),
        "run-bound event does not identify the bound run/artifact",
    )?;
    require(
        record.events[1].subject_id.as_deref() == Some(record.trial_id.as_str()),
        "trial-scheduled event does not identify the trial",
    )?;
    validate_mutation_flow(&by_kind, &record.events)?;
    Ok(())
}

fn validate_mutation_flow(
    by_kind: &HashMap<EventKind, Vec<u64>>,
    events: &[TrialEvent],
) -> Result<(), ValidationError> {
    let mutations = by_kind.get(&EventKind::MutationStarted).map_or(0, Vec::len);
    require(mutations <= 1, "mutation may start only once")?;
    if mutations == 0 {
        let dangling = [
            EventKind::RecoveryIntentArmed,
            EventKind::FaultApplicationEnded,
            EventKind::RecoveryExecutionRecorded,
            EventKind::CleanupRecorded,
        ]
        .into_iter()
        .any(|kind| by_kind.contains_key(&kind));
        return require(
            !dangling,
            "non-mutating trial contains dangling fault/recovery/cleanup events",
        );
    }
    let recovery_intent = require_single(by_kind, EventKind::RecoveryIntentArmed)?;
    let mutation = by_kind[&EventKind::MutationStarted][0];
    let fault_end = require_single(by_kind, EventKind::FaultApplicationEnded)?;
    let recovery = require_single(by_kind, EventKind::RecoveryExecutionRecorded)?;
    let cleanup = require_single(by_kind, EventKind::CleanupRecorded)?;
    require(
        recovery_intent < mutation,
        "durable recovery intent must precede mutation in ledger order",
    )?;
    require(fault_end > mutation, "fault end must follow mutation start")?;
    require(
        recovery > mutation,
        "recovery execution must follow mutation start",
    )?;
    require(
        cleanup > fault_end && cleanup > recovery,
        "cleanup record must follow fault end and recovery",
    )?;
    require(
        events.iter().all(|event| {
            !matches!(
                event.kind,
                EventKind::EvidenceSealed | EventKind::EvidenceVerified | EventKind::TerminalIssued
            ) || event.ledger_sequence > cleanup
        }),
        "cleanup record must precede every seal, verification and terminal event",
    )?;
    Ok(())
}

fn require_event_subject(event: &TrialEvent) -> Result<(), ValidationError> {
    require(
        event.subject_id.as_ref().is_some_and(|id| is_scoped_id(id)),
        "event must bind a valid subject_id",
    )?;
    let digest = event
        .subject_sha256
        .as_deref()
        .ok_or_else(|| ValidationError::new("event must bind a subject_sha256"))?;
    require_digest(digest, "event subject_sha256")
}

fn require_single(
    by_kind: &HashMap<EventKind, Vec<u64>>,
    kind: EventKind,
) -> Result<u64, ValidationError> {
    let sequences = by_kind.get(&kind).map(Vec::as_slice).unwrap_or_default();
    require(
        sequences.len() == 1,
        format!("trial needs exactly one {kind:?} event"),
    )?;
    Ok(sequences[0])
}

fn event_authority(kind: EventKind) -> (ActorRole, ActorAction) {
    match kind {
        EventKind::RunBound => (ActorRole::Controller, ActorAction::BindRun),
        EventKind::TrialScheduled => (ActorRole::Controller, ActorAction::ScheduleTrial),
        EventKind::RecoveryIntentArmed => (ActorRole::RecoveryActor, ActorAction::ArmRecovery),
        EventKind::MutationStarted => (ActorRole::FaultActor, ActorAction::ApplyFault),
        EventKind::FaultApplicationEnded => (ActorRole::FaultActor, ActorAction::EndFault),
        EventKind::RecoveryExecutionRecorded => {
            (ActorRole::RecoveryActor, ActorAction::ExecuteRecovery)
        }
        EventKind::CleanupRecorded => (ActorRole::RecoveryActor, ActorAction::RecordCleanup),
        EventKind::KnownPositiveProbePassed | EventKind::CalibrationRecorded => {
            (ActorRole::Observer, ActorAction::CaptureCalibration)
        }
        EventKind::ObservationCaptured => (ActorRole::Observer, ActorAction::CaptureObservation),
        EventKind::EvidenceSealed => (ActorRole::Observer, ActorAction::SealEvidence),
        EventKind::EvidenceVerified => (ActorRole::Verifier, ActorAction::VerifyEvidence),
        EventKind::TerminalIssued => (ActorRole::Verifier, ActorAction::IssueTerminal),
    }
}
