mod support;

use cats_qualification_protocol::{
    document_sha256, validate_coverage_ledger, validate_trial_record, MAX_AUTHORITY_DOCUMENT_BYTES,
    MAX_EVENTS_PER_TRIAL, MAX_EVIDENCE_PER_TRIAL, MAX_TEXT_BYTES, MAX_TRIAL_PLAN_DOCUMENT_BYTES,
};
use support::*;

#[test]
fn trial_event_evidence_and_string_caps_fail_closed() {
    let catalog = catalog();
    let digest = catalog_digest();
    let authority = authority();

    let mut events = trial();
    while events.events.len() <= MAX_EVENTS_PER_TRIAL {
        events.events.push(events.events[2].clone());
    }
    let error = validate_trial_record(
        &events,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        RECEIPTS_BYTES,
        &trust(),
    )
    .expect_err("excessive events");
    assert!(error.to_string().contains("protocol cap"));

    let mut evidence = trial();
    while evidence.evidence.len() <= MAX_EVIDENCE_PER_TRIAL {
        evidence.evidence.push(evidence.evidence[0].clone());
    }
    let receipts = authenticate_trial(&mut evidence, &authority);
    let error = validate_trial_record(
        &evidence,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect_err("excessive evidence");
    assert!(error.to_string().contains("evidence count"));

    let mut long_text = trial();
    long_text.terminal.summary = "x".repeat(MAX_TEXT_BYTES + 1);
    let receipts = authenticate_trial(&mut long_text, &authority);
    let error = validate_trial_record(
        &long_text,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        &receipts,
        &trust(),
    )
    .expect_err("excessive summary");
    assert!(error.to_string().contains("terminal summary"));
}

#[test]
fn raw_authority_and_plan_documents_are_bounded_before_json_parse() {
    let catalog = catalog();
    let digest = catalog_digest();
    let mut record = trial();
    let oversized_authority = vec![b' '; MAX_AUTHORITY_DOCUMENT_BYTES as usize + 1];
    record.binding.actor_authority_manifest_sha256 = document_sha256(&oversized_authority);
    let error = validate_trial_record(
        &record,
        &catalog,
        &digest,
        &oversized_authority,
        RECEIPTS_BYTES,
        &trust(),
    )
    .expect_err("oversized authority document");
    assert!(error.to_string().contains("exceeds"));

    let oversized_plan = vec![b' '; MAX_TRIAL_PLAN_DOCUMENT_BYTES as usize + 1];
    let mut ledger = coverage();
    ledger.binding.trial_plan_sha256 = document_sha256(&oversized_plan);
    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &digest,
        &oversized_plan,
        &[],
        AUTHORITY_BYTES,
        &trust(),
    )
    .expect_err("oversized plan document");
    assert!(error.to_string().contains("trial plan exceeds"));
}
