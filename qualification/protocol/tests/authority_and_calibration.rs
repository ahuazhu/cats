mod support;

use cats_qualification_protocol::{
    append_checkpoint_signature, append_ledger_root, document_sha256, validate_trial_record,
    AppendReceipts, EventKind, EvidenceObject, ObservationExpectation, ObservationState,
    SecretScanStatus, TrialEvent,
};
use support::*;

#[test]
fn authenticated_append_receipt_rejects_replay_under_other_session() {
    let catalog = catalog();
    let digest = catalog_digest();
    let mut trial = trial();
    let mut receipts: AppendReceipts = serde_json::from_slice(RECEIPTS_BYTES).expect("receipts");
    receipts.receipts[0].actor_session_id = "session-fault".to_owned();
    receipts.checkpoint.ledger_root_sha256 = append_ledger_root(&receipts.receipts).expect("root");
    receipts.checkpoint.signature_ed25519 =
        append_checkpoint_signature(&receipts, APPEND_SEED).expect("signature");
    let bytes = serde_json::to_vec(&receipts).expect("receipt bytes");
    trial.append_receipts_sha256 = document_sha256(&bytes);

    let error = validate_trial_record(&trial, &catalog, &digest, AUTHORITY_BYTES, &bytes, &trust())
        .expect_err("re-signed session replay must fail identity binding");
    assert!(error.to_string().contains("actor session does not match"));
}

#[test]
fn calibrated_empty_pass_resolves_distinct_sealed_verified_evidence() {
    let catalog = catalog();
    let digest = catalog_digest();
    let authority = authority();
    let mut trial = trial();
    add_calibrated_empty(&mut trial);
    let receipts = authenticate_trial(&mut trial, &authority);
    validate_trial_record(
        &trial,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect("calibration evidence is sealed and independently verified");

    trial.observation.known_positive_evidence_id =
        trial.observation.calibration_evidence_id.clone();
    let receipts = authenticate_trial(&mut trial, &authority);
    let error = validate_trial_record(
        &trial,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect_err("calibration evidence substitution must fail");
    assert!(error.to_string().contains("must be distinct"));
}

#[test]
fn calibrated_empty_rejects_missing_or_digest_substituted_evidence() {
    let catalog = catalog();
    let digest = catalog_digest();
    let authority = authority();
    let mut missing = trial();
    add_calibrated_empty(&mut missing);
    missing
        .evidence
        .retain(|evidence| evidence.evidence_id != "evidence-known-positive");
    missing
        .terminal
        .evidence_ids
        .retain(|id| id != "evidence-known-positive");
    let receipts = authenticate_trial(&mut missing, &authority);
    let error = validate_trial_record(
        &missing,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect_err("missing known-positive evidence must fail");
    assert!(error.to_string().contains("unlinked evidence seals"));

    let mut substituted = trial();
    add_calibrated_empty(&mut substituted);
    let event = substituted
        .events
        .iter_mut()
        .find(|event| event.kind == EventKind::KnownPositiveProbePassed)
        .expect("known-positive event");
    event.subject_sha256 = Some("f".repeat(64));
    let receipts = authenticate_trial(&mut substituted, &authority);
    let error = validate_trial_record(
        &substituted,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect_err("known-positive digest substitution must fail");
    assert!(error
        .to_string()
        .contains("do not exactly bind their sealed evidence"));
}

fn add_calibrated_empty(trial: &mut cats_qualification_protocol::TrialRecord) {
    let observer_template = trial
        .events
        .iter()
        .find(|event| event.kind == EventKind::ObservationCaptured)
        .expect("observer event")
        .clone();
    let positive = event_from(
        &observer_template,
        "event-known-positive",
        EventKind::KnownPositiveProbePassed,
        "evidence-known-positive",
        '1',
    );
    let calibration = event_from(
        &observer_template,
        "event-calibration",
        EventKind::CalibrationRecorded,
        "evidence-calibration",
        '2',
    );
    trial.events.splice(4..4, [positive, calibration]);
    for evidence in &mut trial.evidence {
        if evidence.first_event_sequence >= 5 {
            evidence.first_event_sequence += 2;
        }
        if evidence.last_event_sequence >= 5 {
            evidence.last_event_sequence += 2;
        }
    }

    let seal_template = trial
        .events
        .iter()
        .find(|event| event.kind == EventKind::EvidenceSealed)
        .expect("seal event")
        .clone();
    let seal_positive = event_from(
        &seal_template,
        "event-seal-known-positive",
        EventKind::EvidenceSealed,
        "evidence-known-positive",
        '1',
    );
    let seal_calibration = event_from(
        &seal_template,
        "event-seal-calibration",
        EventKind::EvidenceSealed,
        "evidence-calibration",
        '2',
    );
    let first_verification = trial
        .events
        .iter()
        .position(|event| event.kind == EventKind::EvidenceVerified)
        .expect("verification");
    trial.events.splice(
        first_verification..first_verification,
        [seal_positive, seal_calibration],
    );

    let verify_template = trial
        .events
        .iter()
        .find(|event| event.kind == EventKind::EvidenceVerified)
        .expect("verify event")
        .clone();
    let verify_positive = event_from(
        &verify_template,
        "event-verify-known-positive",
        EventKind::EvidenceVerified,
        "evidence-known-positive",
        '1',
    );
    let verify_calibration = event_from(
        &verify_template,
        "event-verify-calibration",
        EventKind::EvidenceVerified,
        "evidence-calibration",
        '2',
    );
    let terminal = trial
        .events
        .iter()
        .position(|event| event.kind == EventKind::TerminalIssued)
        .expect("terminal event");
    trial
        .events
        .splice(terminal..terminal, [verify_positive, verify_calibration]);

    for (index, event) in trial.events.iter_mut().enumerate() {
        event.ledger_sequence = index as u64 + 1;
        event.occurred_at = format!("2026-08-06T00:00:{index:02}Z");
    }

    trial.evidence.push(calibration_evidence(
        "evidence-known-positive",
        "known_positive_probe_output",
        '1',
        5,
        5,
        "event-seal-known-positive",
        "event-verify-known-positive",
    ));
    trial.evidence.push(calibration_evidence(
        "evidence-calibration",
        "calibration_record",
        '2',
        5,
        6,
        "event-seal-calibration",
        "event-verify-calibration",
    ));
    trial.observation.state = ObservationState::ObservedEmpty;
    trial.observation.expectation = ObservationExpectation::Absence;
    trial.observation.known_positive_event_id = Some("event-known-positive".to_owned());
    trial.observation.calibration_event_id = Some("event-calibration".to_owned());
    trial.observation.known_positive_evidence_id = Some("evidence-known-positive".to_owned());
    trial.observation.calibration_evidence_id = Some("evidence-calibration".to_owned());
    trial.terminal.evidence_ids.extend([
        "evidence-known-positive".to_owned(),
        "evidence-calibration".to_owned(),
    ]);
}

fn event_from(
    template: &TrialEvent,
    event_id: &str,
    kind: EventKind,
    evidence_id: &str,
    digest_byte: char,
) -> TrialEvent {
    TrialEvent {
        event_id: event_id.to_owned(),
        kind,
        subject_id: Some(evidence_id.to_owned()),
        subject_sha256: Some(digest_byte.to_string().repeat(64)),
        ..template.clone()
    }
}

fn calibration_evidence(
    evidence_id: &str,
    kind: &str,
    digest_byte: char,
    first: u64,
    last: u64,
    sealed_event_id: &str,
    verified_event_id: &str,
) -> EvidenceObject {
    let digest = digest_byte.to_string().repeat(64);
    EvidenceObject {
        evidence_id: evidence_id.to_owned(),
        run_id: "run-20260806-001".to_owned(),
        window_id: "window-001".to_owned(),
        trial_id: "trial-sto-strict-004-001".to_owned(),
        producer_identity_id: "identity-observer".to_owned(),
        kind: kind.to_owned(),
        media_type: "application/json".to_owned(),
        immutable_locator: format!("urn:sha256:{digest}"),
        sha256: digest,
        size_bytes: 128,
        declared_max_bytes: 1_024,
        redaction_policy_sha256: "f".repeat(64),
        secret_scan: SecretScanStatus::Passed,
        first_event_sequence: first,
        last_event_sequence: last,
        sealed_event_id: sealed_event_id.to_owned(),
        verified_event_id: verified_event_id.to_owned(),
    }
}
