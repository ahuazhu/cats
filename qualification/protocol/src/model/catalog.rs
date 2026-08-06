use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    pub schema: String,
    pub catalog_version: u16,
    pub architecture_baseline_commit: String,
    pub migration_provenance: CatalogProvenance,
    pub counts: CatalogCounts,
    pub forbidden_oracle: String,
    pub cases: Vec<CaseContract>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogProvenance {
    pub source_ref: String,
    pub source_sha256: String,
    pub source_contract_count: usize,
    pub functional_selection_policy: String,
    pub aws_performance_case_ids: Vec<String>,
    pub cost_observation_case_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogCounts {
    pub functional: usize,
    pub aws_performance: usize,
    pub release_required: usize,
    pub cost_observation: usize,
    pub total: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaseContract {
    pub id: String,
    pub title: String,
    pub priority: Priority,
    pub phase: CasePhase,
    pub suite: String,
    pub environment_profiles: Vec<EnvironmentProfile>,
    pub sources: Vec<String>,
    pub oracle_owner: String,
    pub independent_oracle: String,
    pub required_evidence_kinds: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Priority {
    P0,
    P1,
    P2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CasePhase {
    Functional,
    AwsPerformance,
    CostObservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentProfile {
    Ci,
    Linux,
    AwsF,
    AwsP,
}
