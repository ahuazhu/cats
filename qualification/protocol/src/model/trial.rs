use serde::{Deserialize, Serialize};

use super::EnvironmentProfile;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RunBinding {
    pub run_id: String,
    pub candidate_commit_sha: String,
    pub source_chain_verdict_sha256: String,
    pub artifact_manifest_sha256: String,
    pub protocol_version: u16,
    pub catalog_sha256: String,
    pub trial_plan_sha256: String,
    pub controller_commit_sha: String,
    pub actor_authority_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExecutionEnvironment {
    pub profile: EnvironmentProfile,
    pub environment_id: String,
    pub environment_manifest_sha256: String,
    pub environment_is_production: bool,
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
    pub environment: ExecutionEnvironment,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrialRecord {
    pub schema: String,
    pub binding: RunBinding,
    pub environment: ExecutionEnvironment,
    pub window_id: String,
    pub trial_id: String,
    pub case_id: String,
    pub append_receipts_sha256: String,
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
    pub calibration_evidence_id: Option<String>,
    pub known_positive_evidence_id: Option<String>,
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

pub struct TrialDocument<'a> {
    pub trial_bytes: &'a [u8],
    pub append_receipts_bytes: &'a [u8],
}
