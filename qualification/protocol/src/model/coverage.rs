use serde::{Deserialize, Serialize};

use super::{Blocker, RunBinding, TerminalOutcome};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageLedger {
    pub schema: String,
    pub binding: RunBinding,
    pub phase: CoveragePhase,
    pub expected_total: usize,
    pub entries: Vec<CoverageEntry>,
    pub phase_outcome: PhaseOutcome,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoveragePhase {
    Functional,
    AwsPerformance,
    CostObservation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageEntry {
    pub case_id: String,
    pub outcome: TerminalOutcome,
    pub trial_id: Option<String>,
    pub trial_record_sha256: Option<String>,
    pub evidence_ids: Vec<String>,
    pub verifier_identity_id: Option<String>,
    pub blocker: Option<Blocker>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhaseOutcome {
    Pass,
    Fail,
    Incomplete,
    Invalid,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ReleaseIdentity {
    pub candidate_commit_sha: String,
    pub source_chain_verdict_sha256: String,
    pub artifact_manifest_sha256: String,
    pub protocol_version: u16,
    pub catalog_sha256: String,
    pub controller_commit_sha: String,
}

impl From<&RunBinding> for ReleaseIdentity {
    fn from(binding: &RunBinding) -> Self {
        Self {
            candidate_commit_sha: binding.candidate_commit_sha.clone(),
            source_chain_verdict_sha256: binding.source_chain_verdict_sha256.clone(),
            artifact_manifest_sha256: binding.artifact_manifest_sha256.clone(),
            protocol_version: binding.protocol_version,
            catalog_sha256: binding.catalog_sha256.clone(),
            controller_commit_sha: binding.controller_commit_sha.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinalQualification {
    pub schema: String,
    pub release_identity: ReleaseIdentity,
    pub functional_ledger_sha256: String,
    pub aws_performance_ledger_sha256: String,
    pub functional_outcome: PhaseOutcome,
    pub aws_performance_outcome: PhaseOutcome,
    pub required_case_count: usize,
    pub outcome: PhaseOutcome,
}

pub struct PhaseDocuments<'a> {
    pub coverage_ledger_bytes: &'a [u8],
    pub trial_plan_bytes: &'a [u8],
    pub actor_authority_manifest_bytes: &'a [u8],
    pub trial_documents: &'a [super::TrialDocument<'a>],
}
