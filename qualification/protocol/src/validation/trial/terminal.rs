use std::collections::HashSet;

use crate::{
    ActorIdentity, ActorRole, EventKind, EvidenceObject, ObservationExpectation, ObservationState,
    TerminalOutcome, TrialEvent, TrialRecord,
};

use super::{
    super::authority::identity_for_role,
    super::primitive::{
        is_scoped_id, observation_record_sha256, require, require_bounded_text, require_digest,
        terminal_record_sha256, validate_blocker, ValidationError,
    },
};

pub(super) fn validate_observation(record: &TrialRecord) -> Result<(), ValidationError> {
    let observation = &record.observation;
    require(
        is_scoped_id(&observation.observation_id),
        "invalid observation_id",
    )?;
    require_digest(&observation.record_sha256, "observation record sha256")?;
    require(
        observation.record_sha256 == observation_record_sha256(observation)?,
        "observation record_sha256 does not match canonical preimage",
    )?;
    let captures: Vec<&TrialEvent> = record
        .events
        .iter()
        .filter(|event| event.kind == EventKind::ObservationCaptured)
        .collect();
    require(
        captures.len() == 1,
        "trial needs exactly one ObservationCaptured event",
    )?;
    let capture = captures[0];
    require(
        capture.event_id == observation.captured_event_id
            && capture.subject_id.as_deref() == Some(observation.observation_id.as_str())
            && capture.subject_sha256.as_deref() == Some(observation.record_sha256.as_str()),
        "observation is not exactly linked to its capture event",
    )?;
    require(
        record.events.iter().all(|event| {
            event.kind != EventKind::EvidenceSealed
                || event.ledger_sequence > capture.ledger_sequence
        }),
        "observation capture must precede every evidence seal",
    )?;
    match observation.state {
        ObservationState::ObservedEmpty => validate_empty_calibration(record, capture),
        _ => {
            require(
                observation.calibration_event_id.is_none()
                    && observation.known_positive_event_id.is_none()
                    && observation.calibration_evidence_id.is_none()
                    && observation.known_positive_evidence_id.is_none(),
                "only observed-empty may reference calibration events/evidence",
            )?;
            require(
                record.events.iter().all(|event| {
                    !matches!(
                        event.kind,
                        EventKind::KnownPositiveProbePassed | EventKind::CalibrationRecorded
                    )
                }),
                "non-empty observation contains dangling calibration events",
            )
        }
    }
}

pub(super) fn validate_terminal(
    record: &TrialRecord,
    actors: &[ActorIdentity],
) -> Result<(), ValidationError> {
    require(
        is_scoped_id(&record.terminal.terminal_id),
        "invalid terminal_id",
    )?;
    require_bounded_text(&record.terminal.summary, "terminal summary")?;
    require_digest(&record.terminal.record_sha256, "terminal record sha256")?;
    let verifier_id = identity_for_role(actors, ActorRole::Verifier)?;
    require(
        record.terminal.verifier_identity_id == verifier_id,
        "terminal has wrong verifier identity",
    )?;
    let issued = record
        .events
        .iter()
        .find(|event| event.event_id == record.terminal.issued_event_id)
        .ok_or_else(|| ValidationError::new("terminal-issued event is missing"))?;
    let terminal_evidence: HashSet<&str> = record
        .terminal
        .evidence_ids
        .iter()
        .map(String::as_str)
        .collect();
    let all_evidence: HashSet<&str> = record
        .evidence
        .iter()
        .map(|item| item.evidence_id.as_str())
        .collect();
    require(
        terminal_evidence.len() == record.terminal.evidence_ids.len()
            && terminal_evidence == all_evidence,
        "terminal must account for every sealed evidence object exactly once",
    )?;
    require(
        !terminal_evidence.is_empty(),
        "every terminal outcome requires evidence",
    )?;
    if record.terminal.outcome == TerminalOutcome::Blocked {
        validate_blocker(record.terminal.blocker.as_ref())?;
    } else {
        require(
            record.terminal.blocker.is_none(),
            "only BLOCKED may carry a blocker",
        )?;
    }
    validate_observation_outcome(record)?;
    require(
        record.terminal.record_sha256 == terminal_record_sha256(&record.terminal)?,
        "terminal record_sha256 does not match canonical preimage",
    )?;
    require(
        issued.kind == EventKind::TerminalIssued
            && issued.actor_identity_id == verifier_id
            && issued.subject_id.as_deref() == Some(record.terminal.terminal_id.as_str())
            && issued.subject_sha256.as_deref() == Some(record.terminal.record_sha256.as_str()),
        "terminal record is not exactly linked to verifier-issued event",
    )
}

fn validate_observation_outcome(record: &TrialRecord) -> Result<(), ValidationError> {
    let observation = &record.observation;
    let valid = match record.terminal.outcome {
        TerminalOutcome::Pass => {
            (observation.state == ObservationState::ObservedPresent
                && observation.expectation == ObservationExpectation::Presence)
                || (observation.state == ObservationState::ObservedEmpty
                    && observation.expectation == ObservationExpectation::Absence)
        }
        TerminalOutcome::Fail => observation.state == ObservationState::ObservedPresent,
        TerminalOutcome::Empty => {
            observation.state == ObservationState::ObservedEmpty
                && observation.expectation == ObservationExpectation::Presence
        }
        TerminalOutcome::Incomplete => observation.state == ObservationState::Incomplete,
        TerminalOutcome::Unobserved => observation.state == ObservationState::Unobserved,
        TerminalOutcome::Invalid => true,
        TerminalOutcome::Blocked | TerminalOutcome::Cancelled | TerminalOutcome::TimedOut => {
            matches!(
                observation.state,
                ObservationState::Incomplete | ObservationState::Unobserved
            )
        }
    };
    require(
        valid,
        "terminal outcome contradicts observation state/expectation",
    )
}

fn validate_empty_calibration(
    record: &TrialRecord,
    capture: &TrialEvent,
) -> Result<(), ValidationError> {
    let calibration = record
        .observation
        .calibration_event_id
        .as_deref()
        .ok_or_else(|| ValidationError::new("observed-empty needs calibration evidence"))?;
    let positive = record
        .observation
        .known_positive_event_id
        .as_deref()
        .ok_or_else(|| ValidationError::new("observed-empty needs a known-positive probe"))?;
    let calibration_evidence_id = record
        .observation
        .calibration_evidence_id
        .as_deref()
        .ok_or_else(|| ValidationError::new("observed-empty needs calibration evidence"))?;
    let positive_evidence_id = record
        .observation
        .known_positive_evidence_id
        .as_deref()
        .ok_or_else(|| ValidationError::new("observed-empty needs known-positive evidence"))?;
    let calibration_events: Vec<&TrialEvent> = record
        .events
        .iter()
        .filter(|event| event.kind == EventKind::CalibrationRecorded)
        .collect();
    let positive_events: Vec<&TrialEvent> = record
        .events
        .iter()
        .filter(|event| event.kind == EventKind::KnownPositiveProbePassed)
        .collect();
    require(
        calibration_events.len() == 1
            && positive_events.len() == 1
            && calibration_events[0].event_id == calibration
            && positive_events[0].event_id == positive,
        "observed-empty calibration and known-positive events are missing",
    )?;
    let calibration_event = calibration_events[0];
    let positive_event = positive_events[0];
    let calibration_evidence = evidence(record, calibration_evidence_id)?;
    let positive_evidence = evidence(record, positive_evidence_id)?;
    require(
        positive_evidence.evidence_id != calibration_evidence.evidence_id
            && positive_evidence.sha256 != calibration_evidence.sha256,
        "known-positive and calibration evidence must be distinct",
    )?;
    require(
        positive_evidence.kind == "known_positive_probe_output"
            && calibration_evidence.kind == "calibration_record",
        "observed-empty references the wrong calibration evidence kinds",
    )?;
    require(
        positive_event.subject_id.as_deref() == Some(positive_evidence.evidence_id.as_str())
            && positive_event.subject_sha256.as_deref() == Some(positive_evidence.sha256.as_str())
            && calibration_event.subject_id.as_deref()
                == Some(calibration_evidence.evidence_id.as_str())
            && calibration_event.subject_sha256.as_deref()
                == Some(calibration_evidence.sha256.as_str()),
        "calibration events do not exactly bind their sealed evidence",
    )?;
    require(
        positive_evidence.first_event_sequence <= positive_event.ledger_sequence
            && positive_event.ledger_sequence <= positive_evidence.last_event_sequence
            && calibration_evidence.first_event_sequence <= calibration_event.ledger_sequence
            && calibration_event.ledger_sequence <= calibration_evidence.last_event_sequence,
        "calibration evidence ranges do not cover their source events",
    )?;
    require(
        positive_event.ledger_sequence < calibration_event.ledger_sequence
            && calibration_event.ledger_sequence < capture.ledger_sequence,
        "known-positive must precede calibration, which must precede observation",
    )
}

fn evidence<'a>(
    record: &'a TrialRecord,
    evidence_id: &str,
) -> Result<&'a EvidenceObject, ValidationError> {
    record
        .evidence
        .iter()
        .find(|evidence| evidence.evidence_id == evidence_id)
        .ok_or_else(|| ValidationError::new("calibration evidence object is missing"))
}
