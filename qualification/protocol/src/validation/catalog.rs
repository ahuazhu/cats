use std::collections::HashSet;

use crate::{CasePhase, Catalog, EnvironmentProfile, Priority, CATALOG_SCHEMA};

use super::{
    primitive::{is_case_id, is_lower_hex, require, require_digest, ValidationError},
    AWS_PERFORMANCE_CASE_COUNT, COST_OBSERVATION_CASE_COUNT, FUNCTIONAL_CASE_COUNT,
    RELEASE_REQUIRED_CASE_COUNT, TOTAL_CASE_COUNT,
};

const SOURCE_REF: &str =
    "feat/release-qualification:tests/qualification/contracts/registry.json@700a0356737bee9644a120615d9481c72b407997";
const SOURCE_SHA256: &str = "d8eb9218a8daf97e71e0d9efda43d7d8f1662420e826fced44d6ff7ffd610b43";
const COST_CASE: &str = "PERF-COST-001";
const AWS_PERFORMANCE_CASES: [&str; AWS_PERFORMANCE_CASE_COUNT] = [
    "CLEAN-002",
    "REPORT-PERF-001",
    "PERF-ENV-001",
    "PERF-ENV-002",
    "PERF-STRICT-001",
    "PERF-RELAX-001",
    "PERF-LIFE-001",
    "PERF-SCALE-001",
    "PERF-SOAK-001",
];

pub fn validate_catalog(catalog: &Catalog) -> Result<(), ValidationError> {
    require(
        catalog.schema == CATALOG_SCHEMA,
        "unsupported catalog schema",
    )?;
    require(catalog.catalog_version == 1, "unsupported catalog version")?;
    require(
        is_lower_hex(&catalog.architecture_baseline_commit, 40),
        "catalog needs a full architecture baseline commit",
    )?;
    validate_provenance(catalog)?;
    require(
        catalog.counts.functional == FUNCTIONAL_CASE_COUNT
            && catalog.counts.aws_performance == AWS_PERFORMANCE_CASE_COUNT
            && catalog.counts.release_required == RELEASE_REQUIRED_CASE_COUNT
            && catalog.counts.cost_observation == COST_OBSERVATION_CASE_COUNT
            && catalog.counts.total == TOTAL_CASE_COUNT,
        "catalog declares incorrect phase totals",
    )?;
    require(
        !catalog.forbidden_oracle.trim().is_empty(),
        "catalog must define its forbidden oracle",
    )?;
    require(
        catalog.cases.len() == TOTAL_CASE_COUNT,
        "catalog must contain exactly 114 cases",
    )?;

    let aws_ids: HashSet<&str> = AWS_PERFORMANCE_CASES.into_iter().collect();
    let mut ids = HashSet::new();
    let mut functional = 0;
    let mut aws_performance = 0;
    let mut cost_observation = 0;
    for case in &catalog.cases {
        require(
            is_case_id(&case.id),
            format!("invalid case id: {}", case.id),
        )?;
        require(
            ids.insert(case.id.as_str()),
            format!("duplicate case id: {}", case.id),
        )?;
        require(
            !case.title.trim().is_empty(),
            format!("{} has no title", case.id),
        )?;
        require(
            !case.suite.trim().is_empty(),
            format!("{} has no suite", case.id),
        )?;
        require(
            !case.environment_profiles.is_empty(),
            format!("{} has no environment profile", case.id),
        )?;
        require(
            !case.sources.is_empty(),
            format!("{} has no source", case.id),
        )?;
        require(
            !case.oracle_owner.trim().is_empty(),
            format!("{} has no oracle owner", case.id),
        )?;
        require(
            !case.independent_oracle.trim().is_empty(),
            format!("{} has no independent oracle", case.id),
        )?;
        let evidence: HashSet<&str> = case
            .required_evidence_kinds
            .iter()
            .map(String::as_str)
            .collect();
        require(
            evidence.len() == case.required_evidence_kinds.len()
                && evidence.contains("normalized_event_timeline")
                && evidence.contains("independent_oracle_output"),
            format!("{} lacks explicit timeline/oracle evidence", case.id),
        )?;
        match case.phase {
            CasePhase::Functional => {
                require(
                    case.priority != Priority::P2,
                    format!("{}: functional case is P2", case.id),
                )?;
                require(
                    !aws_ids.contains(case.id.as_str()) && case.id != COST_CASE,
                    "case is in wrong phase",
                )?;
                require(
                    !case
                        .environment_profiles
                        .contains(&EnvironmentProfile::AwsP),
                    format!("{}: functional case incorrectly requires AWS-P", case.id),
                )?;
                functional += 1;
            }
            CasePhase::AwsPerformance => {
                require(
                    case.priority != Priority::P2,
                    format!("{}: AWS-P case is P2", case.id),
                )?;
                require(
                    aws_ids.contains(case.id.as_str()),
                    "unexpected AWS performance case",
                )?;
                require(
                    case.environment_profiles
                        .contains(&EnvironmentProfile::AwsP),
                    format!("{}: AWS performance case lacks AWS-P", case.id),
                )?;
                aws_performance += 1;
            }
            CasePhase::CostObservation => {
                require(
                    case.priority == Priority::P2 && case.id == COST_CASE,
                    "invalid cost observation",
                )?;
                require(
                    case.environment_profiles
                        .contains(&EnvironmentProfile::AwsP),
                    "cost observation lacks AWS-P",
                )?;
                cost_observation += 1;
            }
        }
    }
    require(
        functional == FUNCTIONAL_CASE_COUNT,
        "functional phase is not 104 cases",
    )?;
    require(
        aws_performance == AWS_PERFORMANCE_CASE_COUNT,
        "AWS performance phase is not 9 cases",
    )?;
    require(
        cost_observation == COST_OBSERVATION_CASE_COUNT,
        "cost observation phase is not 1 case",
    )
}

fn validate_provenance(catalog: &Catalog) -> Result<(), ValidationError> {
    let provenance = &catalog.migration_provenance;
    require(
        provenance.source_ref == SOURCE_REF,
        "catalog migration source ref changed",
    )?;
    require_digest(&provenance.source_sha256, "migration source sha256")?;
    require(
        provenance.source_sha256 == SOURCE_SHA256,
        "catalog migration source digest changed",
    )?;
    require(
        provenance.source_contract_count == TOTAL_CASE_COUNT,
        "migration source count is not 114",
    )?;
    require(
        provenance.functional_selection_policy
            == "P0/P1 cases excluding the nine aws_performance cases; PERF-COST-001 is P2 observation",
        "functional selection policy changed",
    )?;
    require(
        provenance.aws_performance_case_ids == AWS_PERFORMANCE_CASES.map(str::to_owned),
        "AWS performance migration set changed",
    )?;
    require(
        provenance.cost_observation_case_id == COST_CASE,
        "cost observation migration id changed",
    )
}
