use serde::{Deserialize, Serialize};

pub const CATALOG_SCHEMA: &str = "cats.qualification.catalog/v1";
pub const TRIAL_SCHEMA: &str = "cats.qualification.trial/v1";
pub const COVERAGE_SCHEMA: &str = "cats.qualification.coverage-ledger/v1";
pub const TRIAL_PLAN_SCHEMA: &str = "cats.qualification.trial-plan/v1";
pub const PROTOCOL_VERSION: u16 = 1;

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentProfile {
    Ci,
    Linux,
    AwsF,
    AwsP,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunBinding {
    pub run_id: String,
    pub candidate_commit_sha: String,
    pub source_chain_verdict_sha256: String,
    pub artifact_manifest_sha256: String,
    pub environment_id: String,
    pub environment_manifest_sha256: String,
    pub environment_is_production: bool,
    pub protocol_version: u16,
    pub catalog_sha256: String,
    pub trial_plan_sha256: String,
    pub controller_commit_sha: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialPlan {
    pub schema: String,
    pub run_id: String,
    pub catalog_sha256: String,
    pub planned_trials: Vec<PlannedTrial>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedTrial {
    pub sequence: u64,
    pub trial_id: String,
    pub case_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorIdentity {
    pub identity_id: String,
    pub role: ActorRole,
    pub principal: String,
    pub session_id: String,
    pub credential_fingerprint_sha256: String,
    pub allowed_actions: Vec<ActorAction>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorRole {
    Controller,
    FaultActor,
    RecoveryActor,
    Observer,
    Verifier,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorAction {
    BindRun,
    ScheduleTrial,
    ApplyFault,
    EndFault,
    ArmRecovery,
    ExecuteRecovery,
    RecordCleanup,
    CaptureCalibration,
    CaptureObservation,
    SealEvidence,
    VerifyEvidence,
    IssueTerminal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRecord {
    pub schema: String,
    pub binding: RunBinding,
    pub window_id: String,
    pub trial_id: String,
    pub case_id: String,
    pub identities: Vec<ActorIdentity>,
    pub events: Vec<TrialEvent>,
    pub evidence: Vec<EvidenceObject>,
    pub observation: Observation,
    pub terminal: TerminalRecord,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialEvent {
    pub ledger_sequence: u64,
    pub event_id: String,
    pub run_id: String,
    pub window_id: String,
    pub trial_id: String,
    pub kind: EventKind,
    pub actor_identity_id: String,
    pub occurred_at: String,
    pub immutable_record_sha256: String,
    pub subject_id: Option<String>,
    pub subject_sha256: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EventKind {
    RunBound,
    TrialScheduled,
    RecoveryIntentArmed,
    MutationStarted,
    FaultApplicationEnded,
    RecoveryExecutionRecorded,
    CleanupRecorded,
    KnownPositiveProbePassed,
    CalibrationRecorded,
    ObservationCaptured,
    EvidenceSealed,
    EvidenceVerified,
    TerminalIssued,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceObject {
    pub evidence_id: String,
    pub run_id: String,
    pub window_id: String,
    pub trial_id: String,
    pub producer_identity_id: String,
    pub kind: String,
    pub media_type: String,
    pub immutable_locator: String,
    pub sha256: String,
    pub size_bytes: u64,
    pub declared_max_bytes: u64,
    pub redaction_policy_sha256: String,
    pub secret_scan: SecretScanStatus,
    pub first_event_sequence: u64,
    pub last_event_sequence: u64,
    pub sealed_event_id: String,
    pub verified_event_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretScanStatus {
    Passed,
    Failed,
    NotRun,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Observation {
    pub observation_id: String,
    pub state: ObservationState,
    pub expectation: ObservationExpectation,
    pub calibration_event_id: Option<String>,
    pub known_positive_event_id: Option<String>,
    pub captured_event_id: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationState {
    ObservedPresent,
    ObservedEmpty,
    Incomplete,
    Unobserved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationExpectation {
    Presence,
    Absence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminalRecord {
    pub terminal_id: String,
    pub outcome: TerminalOutcome,
    pub summary: String,
    pub verifier_identity_id: String,
    pub evidence_ids: Vec<String>,
    pub blocker: Option<Blocker>,
    pub issued_event_id: String,
    pub record_sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TerminalOutcome {
    Pass,
    Fail,
    Blocked,
    Empty,
    Incomplete,
    Unobserved,
    Invalid,
    Cancelled,
    TimedOut,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Blocker {
    pub owner: String,
    pub exit_condition: String,
}

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
    ReleaseRequired,
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
