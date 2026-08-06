mod support;

use cats_qualification_protocol::{
    document_sha256, validate_coverage_ledger, validate_trial_record, ActorAuthorityManifest,
    CoverageLedger, TrialRecord,
};
use serde::Deserialize;
use serde_json::Value;
use support::*;

const TRIAL_NEGATIVES: &[u8] =
    include_bytes!("../fixtures/negative/trial-validation-cases-v1.json");
const COVERAGE_NEGATIVES: &[u8] =
    include_bytes!("../fixtures/negative/coverage-validation-cases-v1.json");
const AUTHORITY_NEGATIVES: &[u8] =
    include_bytes!("../fixtures/negative/authority-validation-cases-v1.json");

#[test]
fn machine_readable_trial_vectors_fail_for_declared_reason() {
    let catalog = catalog();
    let digest = catalog_digest();
    let suite: NegativeSuite = serde_json::from_slice(TRIAL_NEGATIVES).expect("suite");
    let base: Value = serde_json::from_slice(TRIAL_BYTES).expect("trial value");
    for case in suite.cases {
        let mut value = base.clone();
        apply_mutation(&mut value, &case);
        let record: TrialRecord = serde_json::from_value(value).expect("mutated trial");
        let error = validate_trial_record(
            &record,
            &catalog,
            &digest,
            AUTHORITY_BYTES,
            RECEIPTS_BYTES,
            &trust(),
        )
        .expect_err("negative trial");
        assert_error(&case, &error.to_string());
    }
}

#[test]
fn machine_readable_coverage_vectors_fail_for_declared_reason() {
    let catalog = catalog();
    let digest = catalog_digest();
    let suite: NegativeSuite = serde_json::from_slice(COVERAGE_NEGATIVES).expect("suite");
    let base: Value = serde_json::from_slice(COVERAGE_BYTES).expect("coverage value");
    for case in suite.cases {
        let mut value = base.clone();
        apply_mutation(&mut value, &case);
        let ledger: CoverageLedger = serde_json::from_value(value).expect("mutated ledger");
        let error = validate_coverage_ledger(
            &ledger,
            &catalog,
            &digest,
            EMPTY_PLAN_BYTES,
            &[],
            AUTHORITY_BYTES,
            &trust(),
        )
        .expect_err("negative coverage");
        assert_error(&case, &error.to_string());
    }
}

#[test]
fn fabricated_actor_manifest_cannot_self_assert_five_roles() {
    let catalog = catalog();
    let digest = catalog_digest();
    let suite: NegativeSuite = serde_json::from_slice(AUTHORITY_NEGATIVES).expect("suite");
    let base: Value = serde_json::from_slice(AUTHORITY_BYTES).expect("authority value");
    for case in suite.cases {
        let mut value = base.clone();
        apply_mutation(&mut value, &case);
        let manifest: ActorAuthorityManifest =
            serde_json::from_value(value).expect("mutated authority");
        let bytes = serde_json::to_vec(&manifest).expect("authority bytes");
        let mut record = trial();
        record.binding.actor_authority_manifest_sha256 = document_sha256(&bytes);
        let error =
            validate_trial_record(&record, &catalog, &digest, &bytes, RECEIPTS_BYTES, &trust())
                .expect_err("fabricated authority");
        assert_error(&case, &error.to_string());
    }
}

fn assert_error(case: &NegativeCase, actual: &str) {
    assert!(
        actual.contains(&case.expected_error),
        "{}: expected {:?}, got {actual:?}",
        case.name,
        case.expected_error
    );
}

#[derive(Debug, Deserialize)]
struct NegativeSuite {
    #[allow(dead_code)]
    schema: String,
    #[allow(dead_code)]
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
            *document.pointer_mut(&case.pointer).expect("set pointer") =
                case.value.clone().expect("set value");
        }
        "remove" => {
            let (parent, token) = case.pointer.rsplit_once('/').expect("remove pointer");
            let index = token.parse::<usize>().expect("array index");
            document
                .pointer_mut(parent)
                .expect("remove parent")
                .as_array_mut()
                .expect("array parent")
                .remove(index);
        }
        operation => panic!("unsupported mutation: {operation}"),
    }
}
