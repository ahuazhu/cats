use cats_qualification_protocol::{
    catalog_sha256, document_sha256, event_record_sha256, observation_record_sha256,
    terminal_record_sha256, validate_catalog, validate_coverage_ledger, validate_trial_record,
    Blocker, Catalog, CoverageEntry, CoverageLedger, CoveragePhase, EventKind,
    ObservationExpectation, ObservationState, PhaseOutcome, PlannedTrial, TerminalOutcome,
    TrialEvent, TrialPlan, TrialRecord, COVERAGE_SCHEMA, TRIAL_PLAN_SCHEMA,
};
use serde::Deserialize;
use serde_json::Value;

const CATALOG_BYTES: &[u8] = include_bytes!("../catalog/case-catalog-v1.json");
const TRIAL_BYTES: &[u8] = include_bytes!("../fixtures/positive/trial-v1.json");
const COVERAGE_BYTES: &[u8] =
    include_bytes!("../fixtures/positive/functional-zero-of-104.coverage.json");
const NEGATIVE_BYTES: &[u8] = include_bytes!("../fixtures/negative/trial-validation-cases-v1.json");
const NEGATIVE_COVERAGE_BYTES: &[u8] =
    include_bytes!("../fixtures/negative/coverage-validation-cases-v1.json");
const EMPTY_PLAN_BYTES: &[u8] = include_bytes!("../fixtures/positive/trial-plan-empty-v1.json");
const ONE_PLAN_BYTES: &[u8] = include_bytes!("../fixtures/positive/trial-plan-one-v1.json");

#[test]
fn known_positive_catalog_trial_and_zero_coverage_validate() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    validate_catalog(&catalog).expect("known-positive catalog must validate");

    let trial: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");
    validate_trial_record(&trial, &catalog, &digest).expect("known-positive trial must validate");

    let ledger: CoverageLedger = serde_json::from_slice(COVERAGE_BYTES).expect("coverage fixture");
    validate_coverage_ledger(&ledger, &catalog, &digest, EMPTY_PLAN_BYTES, &[])
        .expect("explicit zero-of-104 coverage must validate");
    assert_eq!(ledger.entries.len(), 104);
    assert_eq!(ledger.phase_outcome, PhaseOutcome::Incomplete);
}

#[test]
fn phase_denominators_are_distinct_and_release_requires_113() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let base_ledger: CoverageLedger = serde_json::from_slice(COVERAGE_BYTES).expect("coverage");
    for (phase, expected) in [
        (CoveragePhase::Functional, 104),
        (CoveragePhase::AwsPerformance, 9),
        (CoveragePhase::ReleaseRequired, 113),
        (CoveragePhase::CostObservation, 1),
    ] {
        let entries = catalog
            .cases
            .iter()
            .filter(|case| match phase {
                CoveragePhase::Functional => {
                    case.phase == cats_qualification_protocol::CasePhase::Functional
                }
                CoveragePhase::AwsPerformance => {
                    case.phase == cats_qualification_protocol::CasePhase::AwsPerformance
                }
                CoveragePhase::ReleaseRequired => matches!(
                    case.phase,
                    cats_qualification_protocol::CasePhase::Functional
                        | cats_qualification_protocol::CasePhase::AwsPerformance
                ),
                CoveragePhase::CostObservation => {
                    case.phase == cats_qualification_protocol::CasePhase::CostObservation
                }
            })
            .map(|case| CoverageEntry {
                case_id: case.id.clone(),
                outcome: TerminalOutcome::Unobserved,
                trial_id: None,
                trial_record_sha256: None,
                evidence_ids: Vec::new(),
                verifier_identity_id: None,
                blocker: None,
            })
            .collect();
        let ledger = CoverageLedger {
            schema: COVERAGE_SCHEMA.to_owned(),
            binding: base_ledger.binding.clone(),
            phase,
            expected_total: expected,
            entries,
            phase_outcome: PhaseOutcome::Incomplete,
        };
        validate_coverage_ledger(&ledger, &catalog, &digest, EMPTY_PLAN_BYTES, &[])
            .unwrap_or_else(|error| panic!("{phase:?} ledger: {error}"));
    }

    let mut final_ledger: CoverageLedger = serde_json::from_slice(COVERAGE_BYTES).expect("fixture");
    final_ledger.phase = CoveragePhase::ReleaseRequired;
    let error = validate_coverage_ledger(&final_ledger, &catalog, &digest, EMPTY_PLAN_BYTES, &[])
        .expect_err("104 entries must never qualify the final release phase");
    assert!(error.to_string().contains("expected_total=113"));
}

#[test]
fn machine_readable_negative_fixtures_fail_for_the_declared_reason() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let suite: NegativeSuite = serde_json::from_slice(NEGATIVE_BYTES).expect("negative suite");
    assert_eq!(suite.schema, "cats.qualification.negative-fixtures/v1");
    assert_eq!(suite.base, "../positive/trial-v1.json");
    let base: Value = serde_json::from_slice(TRIAL_BYTES).expect("base trial");
    for case in suite.cases {
        let mut document = base.clone();
        apply_mutation(&mut document, &case);
        let record: TrialRecord = serde_json::from_value(document)
            .unwrap_or_else(|error| panic!("{} did not deserialize: {error}", case.name));
        let error = validate_trial_record(&record, &catalog, &digest)
            .expect_err("negative machine fixture unexpectedly validated");
        assert!(
            error.to_string().contains(&case.expected_error),
            "{}: expected {:?}, got {:?}",
            case.name,
            case.expected_error,
            error.to_string()
        );
    }
}

#[test]
fn machine_readable_coverage_negatives_protect_phase_and_binding() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let suite: NegativeSuite =
        serde_json::from_slice(NEGATIVE_COVERAGE_BYTES).expect("negative coverage suite");
    assert_eq!(suite.schema, "cats.qualification.negative-fixtures/v1");
    assert_eq!(
        suite.base,
        "../positive/functional-zero-of-104.coverage.json"
    );
    let base: Value = serde_json::from_slice(COVERAGE_BYTES).expect("base coverage");
    for case in suite.cases {
        let mut document = base.clone();
        apply_mutation(&mut document, &case);
        let ledger: CoverageLedger = serde_json::from_value(document)
            .unwrap_or_else(|error| panic!("{} did not deserialize: {error}", case.name));
        let error = validate_coverage_ledger(&ledger, &catalog, &digest, EMPTY_PLAN_BYTES, &[])
            .expect_err("negative coverage fixture unexpectedly validated");
        assert!(
            error.to_string().contains(&case.expected_error),
            "{}: expected {:?}, got {:?}",
            case.name,
            case.expected_error,
            error.to_string()
        );
    }
}

#[test]
fn coverage_pass_resolves_exact_authoritative_trial_bytes() {
    let catalog = catalog();
    let catalog_digest = catalog_sha256(CATALOG_BYTES);
    let trial: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");
    let mut ledger: CoverageLedger = serde_json::from_slice(COVERAGE_BYTES).expect("coverage");
    ledger.binding = trial.binding.clone();
    {
        let entry = ledger
            .entries
            .iter_mut()
            .find(|entry| entry.case_id == trial.case_id)
            .expect("planned case entry");
        entry.outcome = trial.terminal.outcome;
        entry.trial_id = Some(trial.trial_id.clone());
        entry.trial_record_sha256 = Some(document_sha256(TRIAL_BYTES));
        entry.evidence_ids.clone_from(&trial.terminal.evidence_ids);
        entry.verifier_identity_id = Some(trial.terminal.verifier_identity_id.clone());
        entry.blocker.clone_from(&trial.terminal.blocker);
    }
    validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        ONE_PLAN_BYTES,
        &[TRIAL_BYTES],
    )
    .expect("coverage resolves the exact trial bytes");

    let error = validate_coverage_ledger(&ledger, &catalog, &catalog_digest, ONE_PLAN_BYTES, &[])
        .expect_err("invented references without trial bytes must fail");
    assert!(error.to_string().contains("every and only"));

    ledger
        .entries
        .iter_mut()
        .find(|entry| entry.case_id == trial.case_id)
        .expect("planned case entry")
        .trial_record_sha256 =
        Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        ONE_PLAN_BYTES,
        &[TRIAL_BYTES],
    )
    .expect_err("substituted trial digest must fail");
    assert!(error
        .to_string()
        .contains("exact authoritative trial bytes"));
}

#[test]
fn coverage_cannot_omit_reorder_or_relabel_a_failed_planned_trial() {
    let catalog = catalog();
    let catalog_digest = catalog_sha256(CATALOG_BYTES);
    let mut first: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");
    let mut failed = first.clone();
    retarget_trial(&mut failed, "trial-sto-strict-003-001", "STO-STRICT-003");
    failed.terminal.outcome = TerminalOutcome::Fail;
    rehash_trial(&mut failed);
    let plan = TrialPlan {
        schema: TRIAL_PLAN_SCHEMA.to_owned(),
        run_id: first.binding.run_id.clone(),
        catalog_sha256: catalog_digest.clone(),
        planned_trials: vec![
            PlannedTrial {
                sequence: 1,
                trial_id: first.trial_id.clone(),
                case_id: first.case_id.clone(),
            },
            PlannedTrial {
                sequence: 2,
                trial_id: failed.trial_id.clone(),
                case_id: failed.case_id.clone(),
            },
        ],
    };
    let plan_bytes = serde_json::to_vec(&plan).expect("plan bytes");
    let plan_digest = document_sha256(&plan_bytes);
    first.binding.trial_plan_sha256.clone_from(&plan_digest);
    failed.binding.trial_plan_sha256.clone_from(&plan_digest);
    let first_bytes = serde_json::to_vec(&first).expect("first bytes");
    let failed_bytes = serde_json::to_vec(&failed).expect("failed bytes");
    let mut ledger: CoverageLedger = serde_json::from_slice(COVERAGE_BYTES).expect("coverage");
    ledger.binding = first.binding.clone();
    set_coverage_from_trial(&mut ledger, &first, &first_bytes);
    set_coverage_from_trial(&mut ledger, &failed, &failed_bytes);
    ledger.phase_outcome = PhaseOutcome::Fail;

    validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        &plan_bytes,
        &[&first_bytes, &failed_bytes],
    )
    .expect("plan order and failed terminal remain authoritative");

    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        &plan_bytes,
        &[&failed_bytes, &first_bytes],
    )
    .expect_err("reordered trial bundle must fail");
    assert!(error.to_string().contains("order/identity"));

    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        &plan_bytes,
        &[&first_bytes],
    )
    .expect_err("omitted failed trial must fail");
    assert!(error.to_string().contains("every and only"));

    let failed_entry = ledger
        .entries
        .iter_mut()
        .find(|entry| entry.case_id == failed.case_id)
        .expect("failed case entry");
    failed_entry.outcome = TerminalOutcome::Pass;
    ledger.phase_outcome = PhaseOutcome::Incomplete;
    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &catalog_digest,
        &plan_bytes,
        &[&first_bytes, &failed_bytes],
    )
    .expect_err("failed terminal cannot be relabeled PASS");
    assert!(error.to_string().contains("outcome differs"));
}

#[test]
fn observation_recovery_order_and_receipt_hashes_fail_closed() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let base: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");

    let mut missing_observation = base.clone();
    missing_observation
        .events
        .retain(|event| event.kind != EventKind::ObservationCaptured);
    let error = validate_trial_record(&missing_observation, &catalog, &digest)
        .expect_err("PASS without capture must fail");
    assert!(error
        .to_string()
        .contains("exactly one ObservationCaptured"));

    let mut dangling_recovery = base.clone();
    dangling_recovery
        .events
        .retain(|event| event.kind != EventKind::MutationStarted);
    let error = validate_trial_record(&dangling_recovery, &catalog, &digest)
        .expect_err("non-mutating trial cannot retain recovery/fault records");
    assert!(error
        .to_string()
        .contains("dangling fault/recovery/cleanup"));

    let mut cleanup_after_seal = base.clone();
    cleanup_after_seal.events.swap(7, 8);
    cleanup_after_seal.events[7].ledger_sequence = 8;
    cleanup_after_seal.events[7].occurred_at = "2026-08-06T00:00:07Z".to_owned();
    cleanup_after_seal.events[8].ledger_sequence = 9;
    cleanup_after_seal.events[8].occurred_at = "2026-08-06T00:00:08Z".to_owned();
    rehash_trial(&mut cleanup_after_seal);
    let error = validate_trial_record(&cleanup_after_seal, &catalog, &digest)
        .expect_err("cleanup after a seal must fail");
    assert!(error
        .to_string()
        .contains("cleanup record must precede every seal"));

    let mut fabricated_receipt = base;
    fabricated_receipt.events[0].immutable_record_sha256 =
        "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned();
    let error = validate_trial_record(&fabricated_receipt, &catalog, &digest)
        .expect_err("fabricated canonical event digest must fail");
    assert!(error.to_string().contains("canonical preimage"));

    let mut substituted_observation =
        serde_json::from_slice::<TrialRecord>(TRIAL_BYTES).expect("trial fixture");
    let capture = substituted_observation
        .events
        .iter_mut()
        .find(|event| event.kind == EventKind::ObservationCaptured)
        .expect("capture");
    capture.subject_sha256 =
        Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
    capture.immutable_record_sha256 = event_record_sha256(capture).expect("event hash");
    let error = validate_trial_record(&substituted_observation, &catalog, &digest)
        .expect_err("observation capture substitution must fail");
    assert!(error
        .to_string()
        .contains("exactly linked to its capture event"));

    let mut substituted_terminal =
        serde_json::from_slice::<TrialRecord>(TRIAL_BYTES).expect("trial fixture");
    let issued = substituted_terminal
        .events
        .iter_mut()
        .find(|event| event.kind == EventKind::TerminalIssued)
        .expect("terminal event");
    issued.subject_sha256 =
        Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned());
    issued.immutable_record_sha256 = event_record_sha256(issued).expect("event hash");
    let error = validate_trial_record(&substituted_terminal, &catalog, &digest)
        .expect_err("terminal receipt substitution must fail");
    assert!(error
        .to_string()
        .contains("exactly linked to verifier-issued event"));
}

#[test]
fn calibrated_observed_empty_can_pass_but_uncalibrated_empty_cannot() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let mut trial: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");
    insert_calibration_events(&mut trial);
    trial.observation.state = ObservationState::ObservedEmpty;
    trial.observation.expectation = ObservationExpectation::Absence;
    trial.observation.known_positive_event_id = Some("event-known-positive".to_owned());
    trial.observation.calibration_event_id = Some("event-calibration".to_owned());
    rehash_trial(&mut trial);
    validate_trial_record(&trial, &catalog, &digest).expect("calibrated expected absence may pass");

    let mut wrong_order = trial.clone();
    let positive_index = wrong_order
        .events
        .iter()
        .position(|event| event.kind == EventKind::KnownPositiveProbePassed)
        .expect("known positive");
    let calibration_index = wrong_order
        .events
        .iter()
        .position(|event| event.kind == EventKind::CalibrationRecorded)
        .expect("calibration");
    wrong_order.events.swap(positive_index, calibration_index);
    wrong_order.events[positive_index].ledger_sequence = 5;
    wrong_order.events[positive_index].occurred_at = "2026-08-06T00:00:04Z".to_owned();
    wrong_order.events[calibration_index].ledger_sequence = 6;
    wrong_order.events[calibration_index].occurred_at = "2026-08-06T00:00:04Z".to_owned();
    rehash_trial(&mut wrong_order);
    let error = validate_trial_record(&wrong_order, &catalog, &digest)
        .expect_err("calibration before known-positive must fail");
    assert!(error
        .to_string()
        .contains("known-positive must precede calibration"));

    trial.observation.known_positive_event_id = None;
    rehash_trial(&mut trial);
    let error = validate_trial_record(&trial, &catalog, &digest)
        .expect_err("uncalibrated empty result must fail closed");
    assert!(error.to_string().contains("known-positive"));
}

#[test]
fn outcome_state_matrix_and_blocker_rules_fail_closed() {
    let catalog = catalog();
    let digest = catalog_sha256(CATALOG_BYTES);
    let base: TrialRecord = serde_json::from_slice(TRIAL_BYTES).expect("trial fixture");
    let invalid_pairs = [
        (TerminalOutcome::Empty, ObservationState::ObservedPresent),
        (
            TerminalOutcome::Incomplete,
            ObservationState::ObservedPresent,
        ),
        (
            TerminalOutcome::Unobserved,
            ObservationState::ObservedPresent,
        ),
        (
            TerminalOutcome::Cancelled,
            ObservationState::ObservedPresent,
        ),
        (TerminalOutcome::TimedOut, ObservationState::ObservedPresent),
    ];
    for (outcome, state) in invalid_pairs {
        let mut trial = base.clone();
        trial.terminal.outcome = outcome;
        trial.observation.state = state;
        rehash_trial(&mut trial);
        let error = validate_trial_record(&trial, &catalog, &digest)
            .expect_err("contradictory terminal state must fail");
        assert!(error.to_string().contains("contradicts"));
    }

    let mut blocked = base;
    blocked.terminal.outcome = TerminalOutcome::Blocked;
    blocked.observation.state = ObservationState::Incomplete;
    blocked.terminal.blocker = Some(Blocker {
        owner: "qualification-infra".to_owned(),
        exit_condition: "observer access restored".to_owned(),
    });
    rehash_trial(&mut blocked);
    validate_trial_record(&blocked, &catalog, &digest).expect("well-formed BLOCKED is explicit");
    blocked.terminal.blocker = None;
    rehash_trial(&mut blocked);
    assert!(validate_trial_record(&blocked, &catalog, &digest)
        .expect_err("ownerless blocker must fail")
        .to_string()
        .contains("owner and exit condition"));
}

fn insert_calibration_events(trial: &mut TrialRecord) {
    for event in &mut trial.events[4..] {
        event.ledger_sequence += 2;
    }
    for evidence in &mut trial.evidence {
        evidence.last_event_sequence += 2;
    }
    let template = trial.events[4].clone();
    let positive = TrialEvent {
        ledger_sequence: 5,
        event_id: "event-known-positive".to_owned(),
        kind: EventKind::KnownPositiveProbePassed,
        subject_id: Some("known-positive-probe".to_owned()),
        subject_sha256: Some(
            "abababababababababababababababababababababababababababababababab".to_owned(),
        ),
        immutable_record_sha256: "acacacacacacacacacacacacacacacacacacacacacacacacacacacacacacacac"
            .to_owned(),
        ..template.clone()
    };
    let calibration = TrialEvent {
        ledger_sequence: 6,
        event_id: "event-calibration".to_owned(),
        kind: EventKind::CalibrationRecorded,
        subject_id: Some("calibration-record".to_owned()),
        subject_sha256: Some(
            "adadadadadadadadadadadadadadadadadadadadadadadadadadadadadadadad".to_owned(),
        ),
        immutable_record_sha256: "aeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeaeae"
            .to_owned(),
        ..template
    };
    trial.events.splice(4..4, [positive, calibration]);
}

fn rehash_trial(trial: &mut TrialRecord) {
    trial.observation.record_sha256 =
        observation_record_sha256(&trial.observation).expect("observation hash");
    let capture = trial
        .events
        .iter_mut()
        .find(|event| event.event_id == trial.observation.captured_event_id)
        .expect("observation capture");
    capture.subject_id = Some(trial.observation.observation_id.clone());
    capture.subject_sha256 = Some(trial.observation.record_sha256.clone());

    trial.terminal.record_sha256 = terminal_record_sha256(&trial.terminal).expect("terminal hash");
    let issued = trial
        .events
        .iter_mut()
        .find(|event| event.event_id == trial.terminal.issued_event_id)
        .expect("terminal event");
    issued.subject_id = Some(trial.terminal.terminal_id.clone());
    issued.subject_sha256 = Some(trial.terminal.record_sha256.clone());

    for event in &mut trial.events {
        event.immutable_record_sha256 = event_record_sha256(event).expect("event hash");
    }
}

fn retarget_trial(trial: &mut TrialRecord, trial_id: &str, case_id: &str) {
    trial.trial_id = trial_id.to_owned();
    trial.case_id = case_id.to_owned();
    for event in &mut trial.events {
        event.trial_id.clone_from(&trial.trial_id);
        if event.kind == EventKind::TrialScheduled {
            event.subject_id = Some(trial.trial_id.clone());
        }
    }
    for evidence in &mut trial.evidence {
        evidence.trial_id.clone_from(&trial.trial_id);
    }
    rehash_trial(trial);
}

fn set_coverage_from_trial(ledger: &mut CoverageLedger, trial: &TrialRecord, bytes: &[u8]) {
    let entry = ledger
        .entries
        .iter_mut()
        .find(|entry| entry.case_id == trial.case_id)
        .expect("trial case entry");
    entry.outcome = trial.terminal.outcome;
    entry.trial_id = Some(trial.trial_id.clone());
    entry.trial_record_sha256 = Some(document_sha256(bytes));
    entry.evidence_ids.clone_from(&trial.terminal.evidence_ids);
    entry.verifier_identity_id = Some(trial.terminal.verifier_identity_id.clone());
    entry.blocker.clone_from(&trial.terminal.blocker);
}

fn catalog() -> Catalog {
    serde_json::from_slice(CATALOG_BYTES).expect("catalog fixture")
}

#[derive(Debug, Deserialize)]
struct NegativeSuite {
    schema: String,
    base: String,
    cases: Vec<NegativeCase>,
}

#[derive(Debug, Deserialize)]
struct NegativeCase {
    name: String,
    operation: String,
    pointer: String,
    value: Option<Value>,
    expected_error: String,
}

fn apply_mutation(document: &mut Value, case: &NegativeCase) {
    match case.operation.as_str() {
        "set" => {
            let target = document
                .pointer_mut(&case.pointer)
                .unwrap_or_else(|| panic!("{}: invalid set pointer", case.name));
            *target = case.value.clone().expect("set needs value");
        }
        "remove" => {
            let (parent_pointer, final_token) =
                case.pointer.rsplit_once('/').expect("remove pointer");
            let parent = document
                .pointer_mut(parent_pointer)
                .unwrap_or_else(|| panic!("{}: invalid remove parent", case.name));
            let index: usize = final_token.parse().expect("fixture removes array item");
            parent
                .as_array_mut()
                .expect("remove parent array")
                .remove(index);
        }
        operation => panic!("unsupported fixture mutation: {operation}"),
    }
}
