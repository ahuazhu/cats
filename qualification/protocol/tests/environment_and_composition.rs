mod support;

use cats_qualification_protocol::{
    document_sha256, validate_coverage_ledger, validate_final_qualification, validate_trial_record,
    CoveragePhase, EnvironmentProfile, FinalQualification, PhaseDocuments, PhaseOutcome,
    ReleaseIdentity, FINAL_QUALIFICATION_SCHEMA,
};
use support::*;

#[test]
fn catalog_selected_profile_is_trial_and_plan_authority() {
    let catalog = catalog();
    let digest = catalog_digest();
    let mut wrong_trial = trial();
    wrong_trial.environment.profile = EnvironmentProfile::Linux;
    let error = validate_trial_record(
        &wrong_trial,
        &catalog,
        &digest,
        AUTHORITY_BYTES,
        RECEIPTS_BYTES,
        &trust(),
    )
    .expect_err("AWS-F-capable functional case must select AWS-F");
    assert!(error.to_string().contains("wrong environment profile"));

    let mut plan: cats_qualification_protocol::TrialPlan =
        serde_json::from_slice(ONE_PLAN_BYTES).expect("plan");
    plan.planned_trials[0].environment.profile = EnvironmentProfile::Linux;
    let plan_bytes = serde_json::to_vec(&plan).expect("plan bytes");
    let mut ledger = coverage();
    ledger.binding = trial().binding;
    ledger.binding.trial_plan_sha256 = document_sha256(&plan_bytes);
    let error = validate_coverage_ledger(
        &ledger,
        &catalog,
        &digest,
        &plan_bytes,
        &[],
        AUTHORITY_BYTES,
        &trust(),
    )
    .expect_err("authoritative plan cannot choose a weaker profile");
    assert!(error.to_string().contains("wrong environment profile"));
}

#[test]
fn final_113_composes_valid_aws_f_and_aws_p_phase_ledgers() {
    let catalog = catalog();
    let digest = catalog_digest();

    let functional = build_phase(
        trial(),
        "run-functional",
        "window-functional",
        CoveragePhase::Functional,
    );

    let mut aws_trial = trial();
    retarget_case(
        &mut aws_trial,
        "PERF-STRICT-001",
        "trial-perf-strict-001",
        environment(EnvironmentProfile::AwsP, "qcell-use1-v1-aws-p", '9'),
    );
    aws_trial.evidence[2].kind = "artifact_environment_manifest".to_owned();
    let aws = build_phase(
        aws_trial,
        "run-aws-performance",
        "window-aws-performance",
        CoveragePhase::AwsPerformance,
    );

    assert_eq!(
        functional.trial.environment.profile,
        EnvironmentProfile::AwsF
    );
    assert_eq!(aws.trial.environment.profile, EnvironmentProfile::AwsP);
    assert_ne!(
        functional.trial.environment.environment_manifest_sha256,
        aws.trial.environment.environment_manifest_sha256
    );

    let final_record = FinalQualification {
        schema: FINAL_QUALIFICATION_SCHEMA.to_owned(),
        release_identity: ReleaseIdentity::from(&functional.ledger.binding),
        functional_ledger_sha256: document_sha256(&functional.ledger_bytes),
        aws_performance_ledger_sha256: document_sha256(&aws.ledger_bytes),
        functional_outcome: PhaseOutcome::Incomplete,
        aws_performance_outcome: PhaseOutcome::Incomplete,
        required_case_count: 113,
        outcome: PhaseOutcome::Incomplete,
    };
    let functional_documents = [trial_document(
        &functional.trial_bytes,
        &functional.receipts_bytes,
    )];
    let aws_documents = [trial_document(&aws.trial_bytes, &aws.receipts_bytes)];
    let functional_input = PhaseDocuments {
        coverage_ledger_bytes: &functional.ledger_bytes,
        trial_plan_bytes: &functional.plan_bytes,
        actor_authority_manifest_bytes: &functional.authority_bytes,
        trial_documents: &functional_documents,
    };
    let aws_input = PhaseDocuments {
        coverage_ledger_bytes: &aws.ledger_bytes,
        trial_plan_bytes: &aws.plan_bytes,
        actor_authority_manifest_bytes: &aws.authority_bytes,
        trial_documents: &aws_documents,
    };
    validate_final_qualification(
        &final_record,
        &catalog,
        &digest,
        &functional_input,
        &aws_input,
        &trust(),
    )
    .expect("phase-specific environments compose under shared release identity");
}

#[test]
fn final_composition_rejects_cross_candidate_or_artifact_substitution() {
    let catalog = catalog();
    let digest = catalog_digest();
    let functional = empty_phase(CoveragePhase::Functional, "run-final-functional");
    let mut aws = empty_phase(CoveragePhase::AwsPerformance, "run-final-aws");
    let mut final_record = FinalQualification {
        schema: FINAL_QUALIFICATION_SCHEMA.to_owned(),
        release_identity: ReleaseIdentity::from(&functional.ledger.binding),
        functional_ledger_sha256: document_sha256(&functional.ledger_bytes),
        aws_performance_ledger_sha256: document_sha256(&aws.ledger_bytes),
        functional_outcome: PhaseOutcome::Incomplete,
        aws_performance_outcome: PhaseOutcome::Incomplete,
        required_case_count: 113,
        outcome: PhaseOutcome::Incomplete,
    };
    aws.ledger.binding.artifact_manifest_sha256 = "f".repeat(64);
    aws.ledger_bytes = serde_json::to_vec(&aws.ledger).expect("ledger bytes");
    final_record.aws_performance_ledger_sha256 = document_sha256(&aws.ledger_bytes);

    let functional_input = PhaseDocuments {
        coverage_ledger_bytes: &functional.ledger_bytes,
        trial_plan_bytes: &functional.plan_bytes,
        actor_authority_manifest_bytes: &functional.authority_bytes,
        trial_documents: &[],
    };
    let aws_input = PhaseDocuments {
        coverage_ledger_bytes: &aws.ledger_bytes,
        trial_plan_bytes: &aws.plan_bytes,
        actor_authority_manifest_bytes: &aws.authority_bytes,
        trial_documents: &[],
    };
    let error = validate_final_qualification(
        &final_record,
        &catalog,
        &digest,
        &functional_input,
        &aws_input,
        &trust(),
    )
    .expect_err("two candidates/artifacts cannot compose");
    assert!(error.to_string().contains("do not share"));
}

struct BuiltPhase {
    trial: cats_qualification_protocol::TrialRecord,
    trial_bytes: Vec<u8>,
    receipts_bytes: Vec<u8>,
    authority_bytes: Vec<u8>,
    plan_bytes: Vec<u8>,
    ledger: cats_qualification_protocol::CoverageLedger,
    ledger_bytes: Vec<u8>,
}

fn build_phase(
    mut trial: cats_qualification_protocol::TrialRecord,
    run_id: &str,
    window_id: &str,
    phase: CoveragePhase,
) -> BuiltPhase {
    let catalog = catalog();
    retarget_run(&mut trial, run_id, window_id);
    let (authority, authority_bytes) = signed_authority_for_run(run_id);
    trial.binding.actor_authority_manifest_sha256 = document_sha256(&authority_bytes);
    let plan_bytes = bind_plan(&mut [&mut trial]);
    let receipts_bytes = authenticate_trial(&mut trial, &authority);
    let trial_bytes = serde_json::to_vec(&trial).expect("trial bytes");
    let mut ledger = phase_ledger(&catalog, phase, trial.binding.clone());
    set_ledger_trial(&mut ledger, &trial, &trial_bytes);
    let ledger_bytes = serde_json::to_vec(&ledger).expect("ledger bytes");
    BuiltPhase {
        trial,
        trial_bytes,
        receipts_bytes,
        authority_bytes,
        plan_bytes,
        ledger,
        ledger_bytes,
    }
}

struct EmptyPhase {
    ledger: cats_qualification_protocol::CoverageLedger,
    ledger_bytes: Vec<u8>,
    plan_bytes: Vec<u8>,
    authority_bytes: Vec<u8>,
}

fn empty_phase(phase: CoveragePhase, run_id: &str) -> EmptyPhase {
    let catalog = catalog();
    let (_, authority_bytes) = signed_authority_for_run(run_id);
    let mut binding = trial().binding;
    binding.run_id = run_id.to_owned();
    binding.actor_authority_manifest_sha256 = document_sha256(&authority_bytes);
    let plan = cats_qualification_protocol::TrialPlan {
        schema: cats_qualification_protocol::TRIAL_PLAN_SCHEMA.to_owned(),
        run_id: run_id.to_owned(),
        catalog_sha256: binding.catalog_sha256.clone(),
        planned_trials: Vec::new(),
    };
    let plan_bytes = serde_json::to_vec(&plan).expect("plan bytes");
    binding.trial_plan_sha256 = document_sha256(&plan_bytes);
    let ledger = phase_ledger(&catalog, phase, binding);
    let ledger_bytes = serde_json::to_vec(&ledger).expect("ledger bytes");
    EmptyPhase {
        ledger,
        ledger_bytes,
        plan_bytes,
        authority_bytes,
    }
}
