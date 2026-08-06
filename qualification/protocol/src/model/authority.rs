use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActorAuthorityManifest {
    pub schema: String,
    pub run_id: String,
    pub issuer: String,
    pub authority_key_id: String,
    pub issued_at: String,
    pub expires_at: String,
    pub actors: Vec<ActorIdentity>,
    pub signature_ed25519: String,
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
pub struct AppendReceipts {
    pub schema: String,
    pub run_id: String,
    pub window_id: String,
    pub trial_id: String,
    pub ledger_authority_key_id: String,
    pub receipts: Vec<AppendReceipt>,
    pub checkpoint: AppendCheckpoint,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendReceipt {
    pub ledger_sequence: u64,
    pub event_id: String,
    pub event_record_sha256: String,
    pub actor_identity_id: String,
    pub actor_session_id: String,
    pub actor_credential_fingerprint_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendCheckpoint {
    pub event_count: usize,
    pub first_ledger_sequence: u64,
    pub last_ledger_sequence: u64,
    pub ledger_root_sha256: String,
    pub previous_checkpoint_sha256: String,
    pub signed_at: String,
    pub signature_ed25519: String,
}

pub struct AuthorityTrustAnchors<'a> {
    pub actor_authority_key_id: &'a str,
    pub actor_authority_public_key: &'a [u8],
    pub append_ledger_key_id: &'a str,
    pub append_ledger_public_key: &'a [u8],
}
