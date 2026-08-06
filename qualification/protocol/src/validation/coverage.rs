use std::collections::{HashMap, HashSet};

use crate::{
    AuthorityTrustAnchors, CasePhase, CoverageEntry, CoverageLedger, CoveragePhase, PhaseOutcome,
    PlannedTrial, TerminalOutcome, TrialDocument, TrialPlan, TrialRecord, COVERAGE_SCHEMA,
    TRIAL_PLAN_SCHEMA,
};

use super::{
    authority::validate_actor_authority,
    catalog::validate_catalog,
    environment::validate_execution_environment,
    primitive::{
        document_sha256, is_scoped_id, parse_bounded_json, require, require_digest,
        validate_binding, ValidationError,
    },
    trial::validate_trial_record,
    AWS_PERFORMANCE_CASE_COUNT, COST_OBSERVATION_CASE_COUNT, FUNCTIONAL_CASE_COUNT,
    MAX_EVIDENCE_PER_TRIAL, MAX_TRIAL_DOCUMENTS, MAX_TRIAL_DOCUMENT_BYTES,
    MAX_TRIAL_PLAN_DOCUMENT_BYTES,
};

pub fn validate_coverage_ledger(
    ledger: &CoverageLedger,
    catalog: &crate::Catalog,
    catalog_digest: &str,
    trial_plan_bytes: &[u8],
    trial_documents: &[TrialDocument<'_>],
    actor_authority_manifest_bytes: &[u8],
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<(), ValidationError> {
    validate_catalog(catalog)?;
    require_digest(catalog_digest, "actual catalog sha256")?;
    require(
        ledger.schema == COVERAGE_SCHEMA,
        "unsupported coverage-ledger schema",
    )?;
    validate_binding(&ledger.binding)?;
    require(
        ledger.binding.catalog_sha256 == catalog_digest,
        "coverage ledger catalog digest does not match the catalog bytes",
    )?;
    validate_actor_authority(actor_authority_manifest_bytes, &ledger.binding, trust)?;
    require(
        trial_documents.len() <= MAX_TRIAL_DOCUMENTS,
        "trial document count exceeds the protocol cap",
    )?;

    let expected_total = phase_total(ledger.phase);
    require(
        ledger.expected_total == expected_total,
        format!(
            "{:?} phase must declare expected_total={expected_total}",
            ledger.phase
        ),
    )?;
    require(
        ledger.entries.len() == expected_total,
        format!("coverage ledger must contain exactly {expected_total} entries"),
    )?;

    let expected_ids: HashSet<&str> = catalog
        .cases
        .iter()
        .filter(|case| belongs(case.phase, ledger.phase))
        .map(|case| case.id.as_str())
        .collect();
    let plan = validate_trial_plan(ledger, catalog, catalog_digest, trial_plan_bytes)?;
    require(
        plan.planned_trials
            .iter()
            .all(|planned| expected_ids.contains(planned.case_id.as_str())),
        "phase trial plan contains a case from another phase",
    )?;
    require(
        trial_documents.len() == plan.planned_trials.len(),
        "trial bundle must contain every and only phase-relevant planned trial",
    )?;
    let resolved = resolve_trials(
        ledger,
        catalog,
        catalog_digest,
        &plan.planned_trials,
        trial_documents,
        actor_authority_manifest_bytes,
        trust,
    )?;

    let mut seen = HashSet::new();
    let mut pass_count = 0;
    let mut has_fail = false;
    let mut has_invalid = false;
    for entry in &ledger.entries {
        require(
            expected_ids.contains(entry.case_id.as_str()),
            format!("unexpected case for phase: {}", entry.case_id),
        )?;
        require(
            seen.insert(entry.case_id.as_str()),
            format!("duplicate coverage entry: {}", entry.case_id),
        )?;
        validate_entry(entry, resolved.get(entry.case_id.as_str()))?;
        match entry.outcome {
            TerminalOutcome::Pass => pass_count += 1,
            TerminalOutcome::Fail => has_fail = true,
            TerminalOutcome::Invalid => has_invalid = true,
            _ => {}
        }
    }
    require(
        seen == expected_ids,
        "coverage ledger omits required case ids",
    )?;
    let derived = if has_invalid {
        PhaseOutcome::Invalid
    } else if has_fail {
        PhaseOutcome::Fail
    } else if pass_count == expected_total {
        PhaseOutcome::Pass
    } else {
        PhaseOutcome::Incomplete
    };
    require(
        ledger.phase_outcome == derived,
        format!("phase_outcome must be {derived:?}"),
    )
}

fn validate_trial_plan(
    ledger: &CoverageLedger,
    catalog: &crate::Catalog,
    catalog_digest: &str,
    bytes: &[u8],
) -> Result<TrialPlan, ValidationError> {
    require(
        document_sha256(bytes) == ledger.binding.trial_plan_sha256,
        "trial plan bytes do not match the run binding",
    )?;
    let plan: TrialPlan = parse_bounded_json(bytes, MAX_TRIAL_PLAN_DOCUMENT_BYTES, "trial plan")?;
    require(
        plan.schema == TRIAL_PLAN_SCHEMA,
        "unsupported trial-plan schema",
    )?;
    require(
        plan.run_id == ledger.binding.run_id,
        "trial plan run_id binding mismatch",
    )?;
    require(
        plan.catalog_sha256 == catalog_digest,
        "trial plan catalog digest mismatch",
    )?;
    require(
        plan.planned_trials.len() <= MAX_TRIAL_DOCUMENTS,
        "trial plan exceeds the protocol case cap",
    )?;
    let cases: HashMap<&str, &crate::CaseContract> = catalog
        .cases
        .iter()
        .map(|case| (case.id.as_str(), case))
        .collect();
    let mut trial_ids = HashSet::new();
    let mut case_ids = HashSet::new();
    for (index, planned) in plan.planned_trials.iter().enumerate() {
        require(
            planned.sequence == index as u64 + 1,
            "trial plan sequence must be contiguous and authoritative",
        )?;
        require(is_scoped_id(&planned.trial_id), "invalid planned trial_id")?;
        require(
            trial_ids.insert(planned.trial_id.as_str()),
            "duplicate trial_id in trial plan",
        )?;
        let case = cases
            .get(planned.case_id.as_str())
            .copied()
            .ok_or_else(|| ValidationError::new("trial plan contains a case outside catalog"))?;
        require(
            case_ids.insert(planned.case_id.as_str()),
            "V1 permits exactly one authoritative trial per case",
        )?;
        validate_execution_environment(&planned.environment, case)?;
    }
    Ok(plan)
}

#[allow(clippy::too_many_arguments)]
fn resolve_trials(
    ledger: &CoverageLedger,
    catalog: &crate::Catalog,
    catalog_digest: &str,
    planned: &[PlannedTrial],
    documents: &[TrialDocument<'_>],
    actor_authority_manifest_bytes: &[u8],
    trust: &AuthorityTrustAnchors<'_>,
) -> Result<HashMap<String, (String, TrialRecord)>, ValidationError> {
    let mut resolved = HashMap::new();
    for (planned, document) in planned.iter().zip(documents) {
        let record: TrialRecord = parse_bounded_json(
            document.trial_bytes,
            MAX_TRIAL_DOCUMENT_BYTES,
            "trial record",
        )?;
        validate_trial_record(
            &record,
            catalog,
            catalog_digest,
            actor_authority_manifest_bytes,
            document.append_receipts_bytes,
            trust,
        )?;
        require(
            record.binding == ledger.binding,
            "trial and coverage RunBinding differ",
        )?;
        require(
            record.trial_id == planned.trial_id
                && record.case_id == planned.case_id
                && record.environment == planned.environment,
            "trial document order/identity/environment differs from authoritative trial plan",
        )?;
        let previous = resolved.insert(
            record.case_id.clone(),
            (document_sha256(document.trial_bytes), record),
        );
        require(previous.is_none(), "duplicate trial document for case")?;
    }
    Ok(resolved)
}

fn validate_entry(
    entry: &CoverageEntry,
    resolved: Option<&(String, TrialRecord)>,
) -> Result<(), ValidationError> {
    require(
        entry.evidence_ids.len() <= MAX_EVIDENCE_PER_TRIAL
            && entry.evidence_ids.iter().all(|id| is_scoped_id(id)),
        "coverage entry contains invalid or excessive evidence ids",
    )?;
    let Some((digest, trial)) = resolved else {
        return require(
            entry.outcome == TerminalOutcome::Unobserved
                && entry.trial_id.is_none()
                && entry.trial_record_sha256.is_none()
                && entry.evidence_ids.is_empty()
                && entry.verifier_identity_id.is_none()
                && entry.blocker.is_none(),
            "an unplanned case must be explicit UNOBSERVED with no invented evidence",
        );
    };
    require(
        entry.trial_id.as_deref() == Some(trial.trial_id.as_str())
            && entry.trial_record_sha256.as_deref() == Some(digest.as_str()),
        "coverage entry does not bind the exact authoritative trial bytes",
    )?;
    require(
        entry.outcome == trial.terminal.outcome,
        "coverage outcome differs from authoritative trial terminal",
    )?;
    require(
        entry.verifier_identity_id.as_deref() == Some(trial.terminal.verifier_identity_id.as_str()),
        "coverage verifier differs from authoritative trial terminal",
    )?;
    require(
        entry.evidence_ids == trial.terminal.evidence_ids,
        "coverage evidence differs from authoritative trial terminal",
    )?;
    require(
        entry.blocker == trial.terminal.blocker,
        "coverage blocker differs from authoritative trial terminal",
    )
}

fn phase_total(phase: CoveragePhase) -> usize {
    match phase {
        CoveragePhase::Functional => FUNCTIONAL_CASE_COUNT,
        CoveragePhase::AwsPerformance => AWS_PERFORMANCE_CASE_COUNT,
        CoveragePhase::CostObservation => COST_OBSERVATION_CASE_COUNT,
    }
}

fn belongs(case: CasePhase, phase: CoveragePhase) -> bool {
    match phase {
        CoveragePhase::Functional => case == CasePhase::Functional,
        CoveragePhase::AwsPerformance => case == CasePhase::AwsPerformance,
        CoveragePhase::CostObservation => case == CasePhase::CostObservation,
    }
}
