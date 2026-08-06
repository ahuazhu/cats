use serde::Serialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    Blocker, EventKind, Observation, ObservationExpectation, ObservationState, RunBinding,
    TerminalOutcome, TerminalRecord, TrialEvent, PROTOCOL_VERSION,
};

#[derive(Debug, Error, PartialEq, Eq)]
#[error("{0}")]
pub struct ValidationError(String);

impl ValidationError {
    pub(super) fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

pub fn catalog_sha256(bytes: &[u8]) -> String {
    document_sha256(bytes)
}

pub fn document_sha256(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

pub fn event_record_sha256(event: &TrialEvent) -> Result<String, ValidationError> {
    canonical_sha256(&EventPreimage {
        ledger_sequence: event.ledger_sequence,
        event_id: &event.event_id,
        run_id: &event.run_id,
        window_id: &event.window_id,
        trial_id: &event.trial_id,
        kind: event.kind,
        actor_identity_id: &event.actor_identity_id,
        occurred_at: &event.occurred_at,
        subject_id: event.subject_id.as_deref(),
        subject_sha256: event.subject_sha256.as_deref(),
    })
}

pub fn observation_record_sha256(observation: &Observation) -> Result<String, ValidationError> {
    canonical_sha256(&ObservationPreimage {
        observation_id: &observation.observation_id,
        state: observation.state,
        expectation: observation.expectation,
        calibration_event_id: observation.calibration_event_id.as_deref(),
        known_positive_event_id: observation.known_positive_event_id.as_deref(),
        captured_event_id: &observation.captured_event_id,
    })
}

pub fn terminal_record_sha256(terminal: &TerminalRecord) -> Result<String, ValidationError> {
    canonical_sha256(&TerminalPreimage {
        terminal_id: &terminal.terminal_id,
        outcome: terminal.outcome,
        summary: &terminal.summary,
        verifier_identity_id: &terminal.verifier_identity_id,
        evidence_ids: &terminal.evidence_ids,
        blocker: terminal.blocker.as_ref(),
        issued_event_id: &terminal.issued_event_id,
    })
}

fn canonical_sha256(value: &impl Serialize) -> Result<String, ValidationError> {
    let bytes = serde_json::to_vec(value).map_err(|error| {
        ValidationError::new(format!("canonical JSON serialization failed: {error}"))
    })?;
    Ok(document_sha256(&bytes))
}

#[derive(Serialize)]
struct EventPreimage<'a> {
    ledger_sequence: u64,
    event_id: &'a str,
    run_id: &'a str,
    window_id: &'a str,
    trial_id: &'a str,
    kind: EventKind,
    actor_identity_id: &'a str,
    occurred_at: &'a str,
    subject_id: Option<&'a str>,
    subject_sha256: Option<&'a str>,
}

#[derive(Serialize)]
struct ObservationPreimage<'a> {
    observation_id: &'a str,
    state: ObservationState,
    expectation: ObservationExpectation,
    calibration_event_id: Option<&'a str>,
    known_positive_event_id: Option<&'a str>,
    captured_event_id: &'a str,
}

#[derive(Serialize)]
struct TerminalPreimage<'a> {
    terminal_id: &'a str,
    outcome: TerminalOutcome,
    summary: &'a str,
    verifier_identity_id: &'a str,
    evidence_ids: &'a [String],
    blocker: Option<&'a Blocker>,
    issued_event_id: &'a str,
}

pub(super) fn validate_binding(binding: &RunBinding) -> Result<(), ValidationError> {
    require(is_scoped_id(&binding.run_id), "invalid run_id")?;
    require(
        is_lower_hex(&binding.candidate_commit_sha, 40),
        "candidate_commit_sha must be a full lowercase 40-hex Git SHA",
    )?;
    require_digest(
        &binding.source_chain_verdict_sha256,
        "source_chain_verdict_sha256",
    )?;
    require_digest(
        &binding.artifact_manifest_sha256,
        "artifact_manifest_sha256",
    )?;
    require(
        is_scoped_id(&binding.environment_id),
        "invalid environment_id",
    )?;
    require_digest(
        &binding.environment_manifest_sha256,
        "environment_manifest_sha256",
    )?;
    require(
        !binding.environment_is_production,
        "qualification environment must be explicitly non-production",
    )?;
    require(
        binding.protocol_version == PROTOCOL_VERSION,
        "unsupported qualification protocol version",
    )?;
    require_digest(&binding.catalog_sha256, "catalog_sha256")?;
    require_digest(&binding.trial_plan_sha256, "trial_plan_sha256")?;
    require(
        is_lower_hex(&binding.controller_commit_sha, 40),
        "controller_commit_sha must be a full lowercase 40-hex Git SHA",
    )?;
    Ok(())
}

pub(super) fn validate_blocker(blocker: Option<&Blocker>) -> Result<(), ValidationError> {
    let blocker =
        blocker.ok_or_else(|| ValidationError::new("BLOCKED needs an owner and exit condition"))?;
    require(!blocker.owner.trim().is_empty(), "blocker owner is empty")?;
    require(
        !blocker.exit_condition.trim().is_empty(),
        "blocker exit condition is empty",
    )
}

pub(super) fn require_digest(value: &str, name: &str) -> Result<(), ValidationError> {
    require(
        is_lower_hex(value, 64),
        format!("{name} must be lowercase 64-hex sha256"),
    )
}

pub(super) fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(super) fn is_scoped_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':'))
}

pub(super) fn is_case_id(value: &str) -> bool {
    let mut pieces = value.split('-');
    let Some(first) = pieces.next() else {
        return false;
    };
    first.len() >= 3
        && first.bytes().all(|byte| byte.is_ascii_uppercase())
        && pieces.clone().count() >= 1
        && pieces.all(|piece| {
            !piece.is_empty()
                && piece
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit())
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct CanonicalUtc(u32, u32, u32, u32, u32, u32);

pub(super) fn parse_canonical_utc(value: &str) -> Option<CanonicalUtc> {
    let bytes = value.as_bytes();
    if bytes.len() != 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
        || bytes.get(19) != Some(&b'Z')
    {
        return None;
    }
    for range in [0..4, 5..7, 8..10, 11..13, 14..16, 17..19] {
        if !bytes[range].iter().all(u8::is_ascii_digit) {
            return None;
        }
    }
    let number = |start: usize, end: usize| {
        bytes[start..end]
            .iter()
            .fold(0, |value, digit| value * 10 + u32::from(digit - b'0'))
    };
    let year = number(0, 4);
    let month = number(5, 7);
    let day = number(8, 10);
    let hour = number(11, 13);
    let minute = number(14, 16);
    let second = number(17, 19);
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let max_day = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (year >= 2020 && day > 0 && day <= max_day && hour <= 23 && minute <= 59 && second <= 59)
        .then_some(CanonicalUtc(year, month, day, hour, minute, second))
}

pub(super) fn require(condition: bool, message: impl Into<String>) -> Result<(), ValidationError> {
    if condition {
        Ok(())
    } else {
        Err(ValidationError::new(message))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_timestamp_probe_rejects_bad_calendar_and_precision() {
        assert!(parse_canonical_utc("2026-08-06T12:30:45Z").is_some());
        assert!(parse_canonical_utc("2024-02-29T23:59:59Z").is_some());
        assert!(parse_canonical_utc("2026-02-29T12:30:45Z").is_none());
        assert!(parse_canonical_utc("2026-08-06T12:30:45.1Z").is_none());
        assert!(parse_canonical_utc("2026-08-06T25:30:45Z").is_none());
        assert!(parse_canonical_utc("2026-08-06T12:30:45+08:00").is_none());
    }
}
