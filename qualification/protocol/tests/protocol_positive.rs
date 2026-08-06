mod support;

use cats_qualification_protocol::{
    validate_catalog, validate_coverage_ledger, validate_trial_record, PhaseOutcome,
    AWS_PERFORMANCE_CASE_COUNT, COST_OBSERVATION_CASE_COUNT, FUNCTIONAL_CASE_COUNT,
    RELEASE_REQUIRED_CASE_COUNT,
};
use support::*;

#[test]
fn authenticated_catalog_trial_and_zero_coverage_validate() {
    let catalog = catalog();
    let digest = catalog_digest();
    validate_catalog(&catalog).expect("catalog");

    let trial = trial();
    validate_trial_record(
        &trial,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        RECEIPTS_BYTES,
        &trust(),
    )
    .expect("authenticated trial");

    let ledger = coverage();
    validate_coverage_ledger(
        &ledger,
        &catalog,
        &digest,
        EMPTY_PLAN_BYTES,
        &[],
        AUTHORITY_BYTES,
        &trust(),
    )
    .expect("explicit 0/104 coverage");
    assert_eq!(ledger.entries.len(), FUNCTIONAL_CASE_COUNT);
    assert_eq!(ledger.phase_outcome, PhaseOutcome::Incomplete);
}

#[test]
fn phase_denominators_keep_cost_outside_release_required() {
    assert_eq!(FUNCTIONAL_CASE_COUNT, 104);
    assert_eq!(AWS_PERFORMANCE_CASE_COUNT, 9);
    assert_eq!(RELEASE_REQUIRED_CASE_COUNT, 113);
    assert_eq!(COST_OBSERVATION_CASE_COUNT, 1);
}
