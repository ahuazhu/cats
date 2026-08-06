use crate::{
    AuthorityTrustAnchors, CoverageLedger, CoveragePhase, FinalQualification, PhaseDocuments,
    PhaseOutcome, ReleaseIdentity, FINAL_QUALIFICATION_SCHEMA, PROTOCOL_VERSION,
};

use super::{
    coverage::validate_coverage_ledger,
    primitive::{
        document_sha256, is_lower_hex, parse_bounded_json, require, require_digest, ValidationError,
    },
    MAX_COVERAGE_DOCUMENT_BYTES, RELEASE_REQUIRED_CASE_COUNT,
};

pub fn validate_final_qualification(
    final_record: &FinalQualification,
    catalog: &crate::Catalog,
    catalog_digest: &str,
    functional: &PhaseDocuments<'_>,
    aws_performance: &PhaseDocuments<'_>,
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<(), ValidationError> {
    require(
        final_record.schema == FINAL_QUALIFICATION_SCHEMA,
        "unsupported final-qualification schema",
    )?;
    validate_release_identity(&final_record.release_identity, catalog_digest)?;
    require_digest(
        &final_record.functional_ledger_sha256,
        "functional_ledger_sha256",
    )?;
    require_digest(
        &final_record.aws_performance_ledger_sha256,
        "aws_performance_ledger_sha256",
    )?;
    require(
        document_sha256(functional.coverage_ledger_bytes) == final_record.functional_ledger_sha256,
        "final composition functional ledger digest mismatch",
    )?;
    require(
        document_sha256(aws_performance.coverage_ledger_bytes)
            == final_record.aws_performance_ledger_sha256,
        "final composition AWS-P ledger digest mismatch",
    )?;

    let functional_ledger: CoverageLedger = parse_bounded_json(
        functional.coverage_ledger_bytes,
        MAX_COVERAGE_DOCUMENT_BYTES,
        "functional coverage ledger",
    )?;
    let aws_ledger: CoverageLedger = parse_bounded_json(
        aws_performance.coverage_ledger_bytes,
        MAX_COVERAGE_DOCUMENT_BYTES,
        "AWS-P coverage ledger",
    )?;
    require(
        functional_ledger.phase == CoveragePhase::Functional,
        "final composition first input is not functional coverage",
    )?;
    require(
        aws_ledger.phase == CoveragePhase::AwsPerformance,
        "final composition second input is not AWS-P coverage",
    )?;
    validate_coverage_ledger(
        &functional_ledger,
        catalog,
        catalog_digest,
        functional.trial_plan_bytes,
        functional.trial_documents,
        functional.actor_authority_manifest_bytes,
        trust,
    )?;
    validate_coverage_ledger(
        &aws_ledger,
        catalog,
        catalog_digest,
        aws_performance.trial_plan_bytes,
        aws_performance.trial_documents,
        aws_performance.actor_authority_manifest_bytes,
        trust,
    )?;
    require(
        ReleaseIdentity::from(&functional_ledger.binding) == final_record.release_identity
            && ReleaseIdentity::from(&aws_ledger.binding) == final_record.release_identity,
        "phase ledgers do not share the final candidate/artifact/catalog/protocol identity",
    )?;
    require(
        final_record.functional_outcome == functional_ledger.phase_outcome
            && final_record.aws_performance_outcome == aws_ledger.phase_outcome,
        "final composition phase outcomes do not match source ledgers",
    )?;
    require(
        final_record.required_case_count == RELEASE_REQUIRED_CASE_COUNT,
        "final composition must require exactly 113 cases",
    )?;
    let derived = combine_outcomes(functional_ledger.phase_outcome, aws_ledger.phase_outcome);
    require(
        final_record.outcome == derived,
        format!("final composition outcome must be {derived:?}"),
    )
}

fn validate_release_identity(
    identity: &ReleaseIdentity,
    catalog_digest: &str,
) -> Result<(), ValidationError> {
    require(
        is_lower_hex(&identity.candidate_commit_sha, 40),
        "final candidate_commit_sha must be full lowercase 40-hex",
    )?;
    require_digest(
        &identity.source_chain_verdict_sha256,
        "final source_chain_verdict_sha256",
    )?;
    require_digest(
        &identity.artifact_manifest_sha256,
        "final artifact_manifest_sha256",
    )?;
    require(
        identity.protocol_version == PROTOCOL_VERSION,
        "unsupported final protocol version",
    )?;
    require(
        identity.catalog_sha256 == catalog_digest,
        "final catalog digest does not match catalog bytes",
    )?;
    require(
        is_lower_hex(&identity.controller_commit_sha, 40),
        "final controller_commit_sha must be full lowercase 40-hex",
    )
}

fn combine_outcomes(functional: PhaseOutcome, aws: PhaseOutcome) -> PhaseOutcome {
    if matches!(functional, PhaseOutcome::Invalid) || matches!(aws, PhaseOutcome::Invalid) {
        PhaseOutcome::Invalid
    } else if matches!(functional, PhaseOutcome::Fail) || matches!(aws, PhaseOutcome::Fail) {
        PhaseOutcome::Fail
    } else if functional == PhaseOutcome::Pass && aws == PhaseOutcome::Pass {
        PhaseOutcome::Pass
    } else {
        PhaseOutcome::Incomplete
    }
}
