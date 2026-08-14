//! Provider-neutral Host-loss recovery snapshots and atomic batch commit.
//!
//! A Host fence is Host-scoped, so recovery cannot consume one Cat and retire
//! the source identity before the other Cats assigned to that Node are dealt
//! with.  These closed records freeze the complete assigned set and let the
//! PostgreSQL owner apply either every safe takeover or none of them.

use std::collections::BTreeSet;

use cats_api::runtime_reconciliation::{
    spec_digest, AcquireOrigin, AdmissionInventoryAttestation, AuthorizationRecord,
    AuthorizationState, ContractVersion, DesiredRuntimeSpec, Epoch, FleetPolicyPrincipal, Id,
    LastVolumeTransition, LocalLineageState, NodeBootId, ObservedRuntimeStatus, ObservedVolume,
    Operation, OperationFailure, OperationPhase, OperationTerminal, RandomId128, SessionBinding,
    Sha256Digest, UnixMillis, VolumeAuthorization, VolumeDurability, VolumeRecord, WireU64,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use crate::authority::{
    validate_authorization_record, validate_volume_record, VolumeOwnerBinding,
    MAX_NODE_OWNED_VOLUMES,
};
use crate::host_fence::validate_host_fence_provider_evidence;
use crate::host_fence::{HostFenceAttemptRequest, HostFenceBinding};
use crate::trusted_host_fence::{validate_trusted_host_fence_event_v1, TrustedHostFenceEventV1};

pub const MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS: usize = 1_024;
pub const MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS: usize = MAX_NODE_OWNED_VOLUMES;
pub const TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES: usize = 64 * 1024 * 1024;

const ASSIGNED_VOLUME_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.assigned-volume.v1";
const ASSIGNED_CAT_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.assigned-cat.v1";
const ASSIGNED_SET_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.assigned-set.v1";
const RECOVERY_ATTEMPT_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.recovery-attempt.v1";
const RECOVERY_ATTEMPT_ID_DOMAIN: &[u8] = b"cats.trusted-host-fence.recovery-attempt-id.v1";
const BATCH_RECOVERY_DIGEST_DOMAIN: &[u8] = b"cats.trusted-host-fence.batch-recovery.v1";
const RECOVERY_ATTEMPT_ID_PREFIX: &str = "host_recovery_v1_";

/// Reference to exact canonical bytes retained in the immutable recovery row.
/// The mutable current-inventory projection is never a replay dependency.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceCanonicalArtifactV1 {
    pub content_sha256: Sha256Digest,
    pub length_bytes: WireU64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedHostFenceInventoryUnavailableReasonV1 {
    NoAcceptedFullInventory,
    AcceptedFullInventoryNotCurrent,
}

/// Immutable source-inventory proof captured when the Host-level barrier is
/// created. Accepted bytes are stored alongside this record under the two
/// content-addressed references and retain their existing 8/16 MiB caps.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedHostFenceSourceInventoryV1 {
    AcceptedFull {
        session: SessionBinding,
        attestation: Box<AdmissionInventoryAttestation>,
        full_observation: TrustedHostFenceCanonicalArtifactV1,
        assigned_snapshot: TrustedHostFenceCanonicalArtifactV1,
    },
    Unavailable {
        session: SessionBinding,
        reason: TrustedHostFenceInventoryUnavailableReasonV1,
        recorded_at_unix_ms: UnixMillis,
    },
}

impl TrustedHostFenceSourceInventoryV1 {
    pub fn session(&self) -> &SessionBinding {
        match self {
            Self::AcceptedFull { session, .. } | Self::Unavailable { session, .. } => session,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedHostFenceAssignedCatInventoryV1 {
    AcceptedFull {
        observed_runtime: Box<ObservedRuntimeStatus>,
    },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedHostFenceAssignedVolumeInventoryV1 {
    AcceptedFull {
        observed_volume: Box<ObservedVolume>,
    },
    Unavailable,
}

/// Whole PostgreSQL authority plus the exact relevant member of the accepted
/// full inventory. No `R == L` boolean can replace these fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceExpectedVolumeAuthorityV1 {
    pub volume_intent_id: Id,
    pub expected_current_volume: VolumeRecord,
    pub expected_owner: VolumeOwnerBinding,
    pub inventory: TrustedHostFenceAssignedVolumeInventoryV1,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceAssignedCatV1 {
    pub expected_current_desired: DesiredRuntimeSpec,
    pub expected_old_operation: Operation,
    pub inventory: TrustedHostFenceAssignedCatInventoryV1,
    pub volumes: Vec<TrustedHostFenceExpectedVolumeAuthorityV1>,
}

/// The immutable Host-level barrier. `assigned_cats` is the exact complete
/// current set for `binding.node_id`, sorted by Cat ID.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceRecoveryAttemptV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub principal: FleetPolicyPrincipal,
    pub binding: HostFenceBinding,
    pub provider_request: HostFenceAttemptRequest,
    pub source_inventory: TrustedHostFenceSourceInventoryV1,
    pub assigned_cats: Vec<TrustedHostFenceAssignedCatV1>,
    pub assigned_set_sha256: Sha256Digest,
    pub requested_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedHostFenceStrictVolumeProblemV1 {
    InventoryUnavailable,
    DesiredOrAuthorityBindingMismatch,
    ObservedVolumeBindingMismatch,
    ObservedAuthorityNotExactOwner,
    LocalLineagesNotCanonical,
    CurrentLineageMissing,
    CurrentLineageDuplicated,
    CurrentLineageBindingMismatch,
    CurrentLineageNotActive,
    LocalGenerationAheadOfRemote,
    RemoteGenerationDoesNotMatchHead,
    PendingPacksRemain,
}

/// The exact PostgreSQL authority member that changed after the immutable
/// attempt was frozen. Provider evidence can remain valid while recovery is
/// conservatively blocked by one of these concurrent Control changes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedHostFenceCurrentAuthorityComponentV1 {
    SourceIdentity,
    SourceAgentSession,
    AssignedCatSet,
    Desired,
    OldOperation,
    VolumeRecord,
    VolumeOwner,
    TakeoverAuthorization,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustedHostFenceRecoveryTargetProblemV1 {
    NoEligibleReplacementNode,
    ReplacementPolicyChanged,
    TakeoverAuthorizationUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedHostFenceRecoveryBlockedReasonV1 {
    SourceInventoryUnavailable {
        reason: TrustedHostFenceInventoryUnavailableReasonV1,
    },
    RelaxedDurabilityUnprovableAfterInventory {
        cat_id: Id,
        volume_id: Id,
    },
    StrictVolumeNotSafelyRecoverable {
        cat_id: Id,
        volume_id: Id,
        problem: TrustedHostFenceStrictVolumeProblemV1,
    },
    CurrentAuthorityChanged {
        cat_id: Option<Id>,
        volume_id: Option<Id>,
        component: TrustedHostFenceCurrentAuthorityComponentV1,
    },
    RecoveryTargetUnavailable {
        cat_id: Id,
        problem: TrustedHostFenceRecoveryTargetProblemV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceBlockedReceiptV1 {
    pub terminal_event: TrustedHostFenceEventV1,
    pub reasons: Vec<TrustedHostFenceRecoveryBlockedReasonV1>,
    pub blocked_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum TrustedHostFenceRecoveryAttemptStateV1 {
    ProviderPending,
    ProviderTerminal {
        terminal_event: TrustedHostFenceEventV1,
    },
    Blocked {
        receipt: TrustedHostFenceBlockedReceiptV1,
    },
    Committed {
        terminal_event_id: Id,
        batch_request_sha256: Sha256Digest,
        committed_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceRecoveryAttemptRecordV1 {
    pub attempt: TrustedHostFenceRecoveryAttemptV1,
    pub attempt_sha256: Sha256Digest,
    pub state: TrustedHostFenceRecoveryAttemptStateV1,
    pub updated_at_unix_ms: UnixMillis,
}

/// One authorization and the digest of the immutable expected Volume proof it
/// consumes. The PostgreSQL transaction reloads that proof from the attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceVolumeRecoveryV1 {
    pub volume_id: Id,
    pub expected_volume_sha256: Sha256Digest,
    pub takeover_authorization: AuthorizationRecord,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceCatRecoveryV1 {
    pub cat_id: Id,
    pub assigned_cat_sha256: Sha256Digest,
    pub replacement_desired: DesiredRuntimeSpec,
    pub settled_old_operation: Operation,
    pub recovery_operation: Operation,
    pub volumes: Vec<TrustedHostFenceVolumeRecoveryV1>,
}

/// One all-or-nothing commit over the complete immutable attempt. It refers to
/// the attempt by digest instead of copying its potentially large proof set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceBatchRecoveryCommitV1 {
    pub version: ContractVersion,
    pub fence_attempt_id: Id,
    pub recovery_attempt_sha256: Sha256Digest,
    pub terminal_event: TrustedHostFenceEventV1,
    pub recoveries: Vec<TrustedHostFenceCatRecoveryV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedHostFenceBatchRecoveryCommitReceiptV1 {
    pub request_sha256: Sha256Digest,
    pub commit: Box<TrustedHostFenceBatchRecoveryCommitV1>,
    pub committed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum TrustedHostFenceRecoveryError {
    #[error("trusted Host recovery JSON is malformed or non-canonical")]
    NonCanonicalJson,
    #[error("trusted Host recovery record exceeds its byte bound")]
    WireLimit,
    #[error("trusted Host recovery source binding is inconsistent")]
    SourceBinding,
    #[error("trusted Host recovery assigned set is incomplete or unordered")]
    AssignedSet,
    #[error("trusted Host recovery assigned-set digest does not match")]
    AssignedSetDigest,
    #[error("trusted Host recovery attempt ID does not match")]
    AttemptId,
    #[error("trusted Host recovery Cat or Volume proof is invalid")]
    AssignedProof,
    #[error("trusted Host recovery attempt digest does not match")]
    AttemptDigest,
    #[error("trusted Host recovery batch does not match the immutable attempt")]
    BatchBinding,
    #[error("trusted Host recovery batch contains an unsafe takeover")]
    UnsafeTakeover,
    #[error("trusted Host recovery terminal event is invalid")]
    TerminalEvent,
    #[error("trusted Host recovery Blocked receipt is invalid or unordered")]
    BlockedReceipt,
}

#[derive(Serialize)]
struct AssignedSetIdentity<'a> {
    cats: Vec<AssignedCatIdentity<'a>>,
}

#[derive(Serialize)]
struct AssignedCatIdentity<'a> {
    cat_id: &'a Id,
    assigned_cat_sha256: Sha256Digest,
}

#[derive(Serialize)]
struct RecoveryAttemptIdentity<'a> {
    apply_id: &'a RandomId128,
    provider_scope: &'a cats_api::runtime_reconciliation::ProviderScope,
    immutable_host_id: &'a Id,
    node_id: &'a Id,
    expected_node_boot_id: &'a NodeBootId,
    expected_agent_session_epoch: Epoch,
    assigned_set_sha256: &'a Sha256Digest,
}

pub fn trusted_host_fence_assigned_volume_sha256(
    volume: &TrustedHostFenceExpectedVolumeAuthorityV1,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    digest_canonical(ASSIGNED_VOLUME_DIGEST_DOMAIN, volume)
}

pub fn trusted_host_fence_assigned_cat_sha256(
    cat: &TrustedHostFenceAssignedCatV1,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    digest_canonical(ASSIGNED_CAT_DIGEST_DOMAIN, cat)
}

pub fn trusted_host_fence_assigned_set_sha256(
    cats: &[TrustedHostFenceAssignedCatV1],
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    let identities = cats
        .iter()
        .map(|cat| {
            Ok(AssignedCatIdentity {
                cat_id: &cat.expected_current_desired.cat_id,
                assigned_cat_sha256: trusted_host_fence_assigned_cat_sha256(cat)?,
            })
        })
        .collect::<Result<Vec<_>, TrustedHostFenceRecoveryError>>()?;
    digest_canonical(
        ASSIGNED_SET_DIGEST_DOMAIN,
        &AssignedSetIdentity { cats: identities },
    )
}

pub fn trusted_host_fence_recovery_attempt_id(
    apply_id: &RandomId128,
    binding: &HostFenceBinding,
    assigned_set_sha256: &Sha256Digest,
) -> Result<Id, TrustedHostFenceRecoveryError> {
    let digest = digest_canonical(
        RECOVERY_ATTEMPT_ID_DOMAIN,
        &RecoveryAttemptIdentity {
            apply_id,
            provider_scope: &binding.provider_scope,
            immutable_host_id: &binding.immutable_host_id,
            node_id: &binding.node_id,
            expected_node_boot_id: &binding.expected_node_boot_id,
            expected_agent_session_epoch: binding.expected_agent_session_epoch,
            assigned_set_sha256,
        },
    )?;
    let hex = digest
        .as_str()
        .strip_prefix("sha256:")
        .ok_or(TrustedHostFenceRecoveryError::AttemptId)?;
    Id::new(format!("{RECOVERY_ATTEMPT_ID_PREFIX}{hex}"))
        .ok_or(TrustedHostFenceRecoveryError::AttemptId)
}

pub fn trusted_host_fence_recovery_attempt_sha256(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    digest_canonical(RECOVERY_ATTEMPT_DIGEST_DOMAIN, attempt)
}

pub fn trusted_host_fence_batch_recovery_sha256(
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    digest_canonical(BATCH_RECOVERY_DIGEST_DOMAIN, commit)
}

pub fn encode_trusted_host_fence_recovery_attempt_v1(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> Result<Vec<u8>, TrustedHostFenceRecoveryError> {
    validate_trusted_host_fence_recovery_attempt_v1(attempt)?;
    encode_bounded(attempt, TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES)
}

pub fn decode_trusted_host_fence_recovery_attempt_v1(
    bytes: &[u8],
) -> Result<TrustedHostFenceRecoveryAttemptV1, TrustedHostFenceRecoveryError> {
    let attempt = decode_bounded(bytes, TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES)?;
    validate_trusted_host_fence_recovery_attempt_v1(&attempt)?;
    Ok(attempt)
}

pub fn encode_trusted_host_fence_batch_recovery_commit_v1(
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> Result<Vec<u8>, TrustedHostFenceRecoveryError> {
    encode_bounded(commit, TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES)
}

pub fn decode_trusted_host_fence_batch_recovery_commit_v1(
    bytes: &[u8],
) -> Result<TrustedHostFenceBatchRecoveryCommitV1, TrustedHostFenceRecoveryError> {
    decode_bounded(bytes, TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES)
}

pub fn validate_trusted_host_fence_recovery_attempt_v1(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> Result<(), TrustedHostFenceRecoveryError> {
    if attempt.version != ContractVersion::V1
        || attempt.provider_request.binding != attempt.binding
        || attempt.source_inventory.session().node_id != attempt.binding.node_id
        || attempt.source_inventory.session().node_boot_id != attempt.binding.expected_node_boot_id
        || attempt.source_inventory.session().agent_session_epoch
            != attempt.binding.expected_agent_session_epoch
    {
        return Err(TrustedHostFenceRecoveryError::SourceBinding);
    }
    if let TrustedHostFenceSourceInventoryV1::AcceptedFull {
        session,
        attestation,
        full_observation,
        assigned_snapshot,
    } = &attempt.source_inventory
    {
        if attestation.version != ContractVersion::V1
            || attestation.node_id != session.node_id
            || attestation.agent_session_epoch != session.agent_session_epoch
            || full_observation.length_bytes.get() == 0
            || full_observation.length_bytes.get()
                > cats_api::runtime_reconciliation::NODE_OBSERVATION_MAX_WIRE_BYTES as u64
            || assigned_snapshot.length_bytes.get() == 0
            || assigned_snapshot.length_bytes.get()
                > cats_api::runtime_reconciliation::DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES as u64
        {
            return Err(TrustedHostFenceRecoveryError::SourceBinding);
        }
    }
    if attempt.assigned_cats.is_empty()
        || attempt.assigned_cats.len() > MAX_TRUSTED_HOST_FENCE_ASSIGNED_CATS
    {
        return Err(TrustedHostFenceRecoveryError::AssignedSet);
    }
    let mut prior_cat: Option<&Id> = None;
    let mut total_volumes = 0_usize;
    for cat in &attempt.assigned_cats {
        let cat_id = &cat.expected_current_desired.cat_id;
        if prior_cat.is_some_and(|prior| prior.as_str() >= cat_id.as_str()) {
            return Err(TrustedHostFenceRecoveryError::AssignedSet);
        }
        prior_cat = Some(cat_id);
        total_volumes = total_volumes
            .checked_add(cat.volumes.len())
            .ok_or(TrustedHostFenceRecoveryError::AssignedSet)?;
        validate_assigned_cat(attempt, cat)?;
    }
    if total_volumes > MAX_TRUSTED_HOST_FENCE_TOTAL_VOLUME_PROOFS {
        return Err(TrustedHostFenceRecoveryError::AssignedSet);
    }
    let assigned_set_sha256 = trusted_host_fence_assigned_set_sha256(&attempt.assigned_cats)?;
    if attempt.assigned_set_sha256 != assigned_set_sha256 {
        return Err(TrustedHostFenceRecoveryError::AssignedSetDigest);
    }
    if attempt.binding.fence_attempt_id
        != trusted_host_fence_recovery_attempt_id(
            &attempt.apply_id,
            &attempt.binding,
            &assigned_set_sha256,
        )?
    {
        return Err(TrustedHostFenceRecoveryError::AttemptId);
    }
    let bytes =
        serde_json::to_vec(attempt).map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?;
    if bytes.len() > TRUSTED_HOST_FENCE_RECOVERY_ATTEMPT_MAX_BYTES {
        return Err(TrustedHostFenceRecoveryError::WireLimit);
    }
    Ok(())
}

pub fn trusted_host_fence_recovery_blockers(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
) -> Result<Vec<TrustedHostFenceRecoveryBlockedReasonV1>, TrustedHostFenceRecoveryError> {
    validate_trusted_host_fence_recovery_attempt_v1(attempt)?;
    let mut reasons = Vec::new();
    if let TrustedHostFenceSourceInventoryV1::Unavailable { reason, .. } = &attempt.source_inventory
    {
        reasons.push(
            TrustedHostFenceRecoveryBlockedReasonV1::SourceInventoryUnavailable { reason: *reason },
        );
    }
    for cat in &attempt.assigned_cats {
        for volume in &cat.volumes {
            if volume.expected_current_volume.durability != VolumeDurability::Strict {
                reasons.push(
                    TrustedHostFenceRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
                        cat_id: cat.expected_current_desired.cat_id.clone(),
                        volume_id: volume.expected_current_volume.volume_id.clone(),
                    },
                );
                continue;
            }
            if let Err(problem) = validate_strict_volume(cat, volume) {
                reasons.push(
                    TrustedHostFenceRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
                        cat_id: cat.expected_current_desired.cat_id.clone(),
                        volume_id: volume.expected_current_volume.volume_id.clone(),
                        problem,
                    },
                );
            }
        }
    }
    canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(&mut reasons)?;
    Ok(reasons)
}

/// Sorts a complete Blocked reason set into its canonical persisted order and
/// rejects duplicates or a component whose Cat/Volume coordinates have the
/// wrong shape. Callers must not silently deduplicate independently-derived
/// reasons.
pub fn canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(
    reasons: &mut [TrustedHostFenceRecoveryBlockedReasonV1],
) -> Result<(), TrustedHostFenceRecoveryError> {
    for reason in reasons.iter() {
        validate_blocked_reason_shape(reason)?;
    }
    reasons.sort_by_cached_key(blocked_reason_sort_key);
    if reasons
        .windows(2)
        .any(|pair| blocked_reason_sort_key(&pair[0]) == blocked_reason_sort_key(&pair[1]))
    {
        return Err(TrustedHostFenceRecoveryError::BlockedReceipt);
    }
    Ok(())
}

pub fn validate_trusted_host_fence_blocked_receipt_v1(
    receipt: &TrustedHostFenceBlockedReceiptV1,
) -> Result<(), TrustedHostFenceRecoveryError> {
    validate_trusted_host_fence_event_v1(&receipt.terminal_event)
        .map_err(|_| TrustedHostFenceRecoveryError::TerminalEvent)?;
    if receipt.reasons.is_empty() {
        return Err(TrustedHostFenceRecoveryError::BlockedReceipt);
    }
    for reason in &receipt.reasons {
        validate_blocked_reason_shape(reason)?;
    }
    for pair in receipt.reasons.windows(2) {
        if blocked_reason_sort_key(&pair[0]) >= blocked_reason_sort_key(&pair[1]) {
            return Err(TrustedHostFenceRecoveryError::BlockedReceipt);
        }
    }
    Ok(())
}

fn blocked_reason_sort_key(
    reason: &TrustedHostFenceRecoveryBlockedReasonV1,
) -> (u8, String, String, u8) {
    match reason {
        TrustedHostFenceRecoveryBlockedReasonV1::SourceInventoryUnavailable { reason } => {
            let reason = match reason {
                TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory => 0,
                TrustedHostFenceInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent => 1,
            };
            (0, String::new(), String::new(), reason)
        }
        TrustedHostFenceRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
            cat_id,
            volume_id,
        } => (
            1,
            cat_id.as_str().to_owned(),
            volume_id.as_str().to_owned(),
            0,
        ),
        TrustedHostFenceRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
            cat_id,
            volume_id,
            problem,
        } => (
            2,
            cat_id.as_str().to_owned(),
            volume_id.as_str().to_owned(),
            strict_volume_problem_order(*problem),
        ),
        TrustedHostFenceRecoveryBlockedReasonV1::CurrentAuthorityChanged {
            cat_id,
            volume_id,
            component,
        } => (
            3,
            cat_id
                .as_ref()
                .map_or_else(String::new, |id| id.as_str().to_owned()),
            volume_id
                .as_ref()
                .map_or_else(String::new, |id| id.as_str().to_owned()),
            current_authority_component_order(*component),
        ),
        TrustedHostFenceRecoveryBlockedReasonV1::RecoveryTargetUnavailable { cat_id, problem } => (
            4,
            cat_id.as_str().to_owned(),
            String::new(),
            recovery_target_problem_order(*problem),
        ),
    }
}

fn strict_volume_problem_order(problem: TrustedHostFenceStrictVolumeProblemV1) -> u8 {
    match problem {
        TrustedHostFenceStrictVolumeProblemV1::InventoryUnavailable => 0,
        TrustedHostFenceStrictVolumeProblemV1::DesiredOrAuthorityBindingMismatch => 1,
        TrustedHostFenceStrictVolumeProblemV1::ObservedVolumeBindingMismatch => 2,
        TrustedHostFenceStrictVolumeProblemV1::ObservedAuthorityNotExactOwner => 3,
        TrustedHostFenceStrictVolumeProblemV1::LocalLineagesNotCanonical => 4,
        TrustedHostFenceStrictVolumeProblemV1::CurrentLineageMissing => 5,
        TrustedHostFenceStrictVolumeProblemV1::CurrentLineageDuplicated => 6,
        TrustedHostFenceStrictVolumeProblemV1::CurrentLineageBindingMismatch => 7,
        TrustedHostFenceStrictVolumeProblemV1::CurrentLineageNotActive => 8,
        TrustedHostFenceStrictVolumeProblemV1::LocalGenerationAheadOfRemote => 9,
        TrustedHostFenceStrictVolumeProblemV1::RemoteGenerationDoesNotMatchHead => 10,
        TrustedHostFenceStrictVolumeProblemV1::PendingPacksRemain => 11,
    }
}

fn current_authority_component_order(component: TrustedHostFenceCurrentAuthorityComponentV1) -> u8 {
    match component {
        TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity => 0,
        TrustedHostFenceCurrentAuthorityComponentV1::SourceAgentSession => 1,
        TrustedHostFenceCurrentAuthorityComponentV1::AssignedCatSet => 2,
        TrustedHostFenceCurrentAuthorityComponentV1::Desired => 3,
        TrustedHostFenceCurrentAuthorityComponentV1::OldOperation => 4,
        TrustedHostFenceCurrentAuthorityComponentV1::VolumeRecord => 5,
        TrustedHostFenceCurrentAuthorityComponentV1::VolumeOwner => 6,
        TrustedHostFenceCurrentAuthorityComponentV1::TakeoverAuthorization => 7,
    }
}

fn recovery_target_problem_order(problem: TrustedHostFenceRecoveryTargetProblemV1) -> u8 {
    match problem {
        TrustedHostFenceRecoveryTargetProblemV1::NoEligibleReplacementNode => 0,
        TrustedHostFenceRecoveryTargetProblemV1::ReplacementPolicyChanged => 1,
        TrustedHostFenceRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable => 2,
    }
}

pub fn validate_trusted_host_fence_batch_recovery_commit_v1(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    commit: &TrustedHostFenceBatchRecoveryCommitV1,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    validate_trusted_host_fence_recovery_attempt_v1(attempt)?;
    if !trusted_host_fence_recovery_blockers(attempt)?.is_empty() {
        return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
    }
    validate_trusted_host_fence_event_v1(&commit.terminal_event)
        .map_err(|_| TrustedHostFenceRecoveryError::TerminalEvent)?;
    validate_host_fence_provider_evidence(
        &attempt.provider_request,
        &commit.terminal_event.provider_evidence,
    )
    .map_err(|_| TrustedHostFenceRecoveryError::TerminalEvent)?;
    let attempt_sha256 = trusted_host_fence_recovery_attempt_sha256(attempt)?;
    if commit.version != ContractVersion::V1
        || commit.fence_attempt_id != attempt.binding.fence_attempt_id
        || commit.recovery_attempt_sha256 != attempt_sha256
        || commit.terminal_event.binding != attempt.binding
        || commit.recoveries.len() != attempt.assigned_cats.len()
    {
        return Err(TrustedHostFenceRecoveryError::BatchBinding);
    }
    let mut operation_ids = BTreeSet::new();
    let mut authorization_ids = BTreeSet::new();
    for (assigned, recovery) in attempt.assigned_cats.iter().zip(&commit.recoveries) {
        validate_cat_recovery(assigned, recovery, &commit.terminal_event)?;
        if !operation_ids.insert(assigned.expected_old_operation.operation_id.as_str())
            || !operation_ids.insert(recovery.recovery_operation.operation_id.as_str())
        {
            return Err(TrustedHostFenceRecoveryError::BatchBinding);
        }
        for volume in &recovery.volumes {
            let VolumeAuthorization::Takeover(authorization) =
                &volume.takeover_authorization.authorization
            else {
                return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
            };
            if !authorization_ids.insert(authorization.authorization_id.as_str()) {
                return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
            }
        }
    }
    let bytes =
        serde_json::to_vec(commit).map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?;
    if bytes.len() > TRUSTED_HOST_FENCE_BATCH_RECOVERY_MAX_BYTES {
        return Err(TrustedHostFenceRecoveryError::WireLimit);
    }
    trusted_host_fence_batch_recovery_sha256(commit)
}

fn validate_assigned_cat(
    attempt: &TrustedHostFenceRecoveryAttemptV1,
    cat: &TrustedHostFenceAssignedCatV1,
) -> Result<(), TrustedHostFenceRecoveryError> {
    let desired = &cat.expected_current_desired;
    let operation = &cat.expected_old_operation;
    if desired.version != ContractVersion::V1
        || spec_digest(desired).ok().as_ref() != Some(&desired.spec_digest)
        || desired.placement.node_id != attempt.binding.node_id
        || operation.version != ContractVersion::V1
        || operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
        || operation.phase != OperationPhase::Pending
        || operation.terminal.is_some()
        || cat.volumes.len() != desired.volumes.len()
        || cat.volumes.len() > 64
    {
        return Err(TrustedHostFenceRecoveryError::AssignedProof);
    }
    match (&attempt.source_inventory, &cat.inventory) {
        (
            TrustedHostFenceSourceInventoryV1::AcceptedFull { .. },
            TrustedHostFenceAssignedCatInventoryV1::AcceptedFull { observed_runtime },
        ) if observed_runtime.cat_id == desired.cat_id => {}
        (
            TrustedHostFenceSourceInventoryV1::Unavailable { .. },
            TrustedHostFenceAssignedCatInventoryV1::Unavailable,
        ) => {}
        _ => return Err(TrustedHostFenceRecoveryError::AssignedProof),
    }
    let mut prior_volume: Option<&Id> = None;
    for (intent, volume) in desired.volumes.iter().zip(&cat.volumes) {
        if prior_volume.is_some_and(|prior| prior.as_str() >= intent.volume_intent_id.as_str())
            || volume.volume_intent_id != intent.volume_intent_id
            || volume.expected_current_volume.volume_id != intent.volume_id
            || volume.expected_owner.volume_id != intent.volume_id
            || volume.expected_owner.owner_node_id != attempt.binding.node_id
            || volume.expected_owner.attachment_id != intent.attachment_id
            || volume.expected_owner.attachment_epoch != volume.expected_current_volume.lease_epoch
            || volume.expected_current_volume.lease_owner.as_ref() != Some(&intent.attachment_id)
        {
            return Err(TrustedHostFenceRecoveryError::AssignedProof);
        }
        validate_volume_record(&volume.expected_current_volume)
            .map_err(|_| TrustedHostFenceRecoveryError::AssignedProof)?;
        match (&attempt.source_inventory, &volume.inventory) {
            (
                TrustedHostFenceSourceInventoryV1::AcceptedFull { .. },
                TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull { .. },
            ) => {}
            (
                TrustedHostFenceSourceInventoryV1::Unavailable { .. },
                TrustedHostFenceAssignedVolumeInventoryV1::Unavailable,
            ) => {}
            _ => return Err(TrustedHostFenceRecoveryError::AssignedProof),
        }
        prior_volume = Some(&intent.volume_intent_id);
    }
    if let TrustedHostFenceAssignedCatInventoryV1::AcceptedFull { observed_runtime } =
        &cat.inventory
    {
        if observed_runtime.volumes.len() != cat.volumes.len()
            || observed_runtime
                .volumes
                .iter()
                .zip(&cat.volumes)
                .any(|(observed, volume)| {
                    !matches!(
                        &volume.inventory,
                        TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull {
                            observed_volume
                        } if observed == observed_volume.as_ref()
                    )
                })
        {
            return Err(TrustedHostFenceRecoveryError::AssignedProof);
        }
    }
    Ok(())
}

fn validate_strict_volume(
    cat: &TrustedHostFenceAssignedCatV1,
    volume: &TrustedHostFenceExpectedVolumeAuthorityV1,
) -> Result<(), TrustedHostFenceStrictVolumeProblemV1> {
    let desired = &cat.expected_current_desired;
    let intent = desired
        .volumes
        .iter()
        .find(|intent| intent.volume_intent_id == volume.volume_intent_id)
        .ok_or(TrustedHostFenceStrictVolumeProblemV1::DesiredOrAuthorityBindingMismatch)?;
    let TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull { observed_volume } =
        &volume.inventory
    else {
        return Err(TrustedHostFenceStrictVolumeProblemV1::InventoryUnavailable);
    };
    if observed_volume.volume_intent_id.as_ref() != Some(&intent.volume_intent_id)
        || observed_volume.disk_id.as_ref() != Some(&intent.disk_id)
        || observed_volume.volume_id != intent.volume_id
        || observed_volume.disk_kind
            != match intent.disk_kind {
                cats_api::runtime_reconciliation::DiskKind::Root => {
                    cats_api::runtime_reconciliation::ObservedDiskKind::Root
                }
                cats_api::runtime_reconciliation::DiskKind::Persistent => {
                    cats_api::runtime_reconciliation::ObservedDiskKind::Persistent
                }
            }
        || observed_volume.size_bytes != Some(volume.expected_current_volume.size_bytes)
        || observed_volume.durability != Some(volume.expected_current_volume.durability)
    {
        return Err(TrustedHostFenceStrictVolumeProblemV1::ObservedVolumeBindingMismatch);
    }
    let cats_api::runtime_reconciliation::VolumeAuthorityEvidence::Owned {
        attachment_id,
        attachment_epoch,
        head,
    } = &observed_volume.authority
    else {
        return Err(TrustedHostFenceStrictVolumeProblemV1::ObservedAuthorityNotExactOwner);
    };
    if attachment_id != &volume.expected_owner.attachment_id
        || *attachment_epoch != volume.expected_owner.attachment_epoch
        || head != &volume.expected_current_volume.head
    {
        return Err(TrustedHostFenceStrictVolumeProblemV1::ObservedAuthorityNotExactOwner);
    }
    let mut prior_key: Option<(String, u64, String, u64, String)> = None;
    for lineage in &observed_volume.local_lineages {
        let key = (
            lineage.attachment_id.as_str().to_owned(),
            lineage.attachment_epoch.get(),
            lineage.node_id.as_str().to_owned(),
            lineage.placement_epoch.get(),
            lineage.data_directory.as_str().to_owned(),
        );
        if prior_key.as_ref().is_some_and(|prior| prior >= &key) {
            return Err(TrustedHostFenceStrictVolumeProblemV1::LocalLineagesNotCanonical);
        }
        prior_key = Some(key);
    }
    let matching = observed_volume
        .local_lineages
        .iter()
        .filter(|lineage| {
            lineage.attachment_id == volume.expected_owner.attachment_id
                && lineage.attachment_epoch == volume.expected_owner.attachment_epoch
                && lineage.node_id == volume.expected_owner.owner_node_id
                && lineage.placement_epoch == desired.placement.placement_epoch
        })
        .collect::<Vec<_>>();
    let [lineage] = matching.as_slice() else {
        return Err(if matching.is_empty() {
            TrustedHostFenceStrictVolumeProblemV1::CurrentLineageMissing
        } else {
            TrustedHostFenceStrictVolumeProblemV1::CurrentLineageDuplicated
        });
    };
    if !lineage_origin_matches(
        intent,
        &volume.expected_current_volume,
        &lineage.acquire_origin,
    ) {
        return Err(TrustedHostFenceStrictVolumeProblemV1::CurrentLineageBindingMismatch);
    }
    if lineage.state != LocalLineageState::Active {
        return Err(TrustedHostFenceStrictVolumeProblemV1::CurrentLineageNotActive);
    }
    if lineage.local_durable_generation > lineage.remote_durable_generation {
        return Err(TrustedHostFenceStrictVolumeProblemV1::LocalGenerationAheadOfRemote);
    }
    if lineage.remote_durable_generation != volume.expected_current_volume.head.generation
        || lineage.local_durable_generation != volume.expected_current_volume.head.generation
    {
        return Err(TrustedHostFenceStrictVolumeProblemV1::RemoteGenerationDoesNotMatchHead);
    }
    if lineage.pending_pack_count.get() != 0 {
        return Err(TrustedHostFenceStrictVolumeProblemV1::PendingPacksRemain);
    }
    Ok(())
}

fn validate_blocked_reason_shape(
    reason: &TrustedHostFenceRecoveryBlockedReasonV1,
) -> Result<(), TrustedHostFenceRecoveryError> {
    let TrustedHostFenceRecoveryBlockedReasonV1::CurrentAuthorityChanged {
        cat_id,
        volume_id,
        component,
    } = reason
    else {
        return Ok(());
    };
    let expected_coordinates = match component {
        TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity
        | TrustedHostFenceCurrentAuthorityComponentV1::SourceAgentSession
        | TrustedHostFenceCurrentAuthorityComponentV1::AssignedCatSet => (false, false),
        TrustedHostFenceCurrentAuthorityComponentV1::Desired
        | TrustedHostFenceCurrentAuthorityComponentV1::OldOperation => (true, false),
        TrustedHostFenceCurrentAuthorityComponentV1::VolumeRecord
        | TrustedHostFenceCurrentAuthorityComponentV1::VolumeOwner
        | TrustedHostFenceCurrentAuthorityComponentV1::TakeoverAuthorization => (true, true),
    };
    if (cat_id.is_some(), volume_id.is_some()) != expected_coordinates {
        return Err(TrustedHostFenceRecoveryError::BlockedReceipt);
    }
    Ok(())
}

fn lineage_origin_matches(
    intent: &cats_api::runtime_reconciliation::VolumeIntent,
    record: &VolumeRecord,
    origin: &AcquireOrigin,
) -> bool {
    match (&intent.acquire, &record.last_transition, origin) {
        (
            cats_api::runtime_reconciliation::VolumeAcquire::Normal { transition_id, .. },
            Some(LastVolumeTransition::NormalAcquire { request, result }),
            AcquireOrigin::Normal {
                transition_id: lineage_transition,
            },
        ) => {
            transition_id == lineage_transition
                && request.transition_id == *transition_id
                && result.transition_id == *transition_id
                && result.attachment_id == intent.attachment_id
                && result.resulting_epoch == record.lease_epoch
                && result.resulting_head == record.head
        }
        (
            cats_api::runtime_reconciliation::VolumeAcquire::Takeover { authorization_id },
            Some(LastVolumeTransition::Takeover {
                authorization_id: marker,
            }),
            AcquireOrigin::Takeover {
                authorization_id: lineage_authorization,
            },
        ) => authorization_id == marker && authorization_id == lineage_authorization,
        _ => false,
    }
}

fn validate_cat_recovery(
    assigned: &TrustedHostFenceAssignedCatV1,
    recovery: &TrustedHostFenceCatRecoveryV1,
    terminal_event: &TrustedHostFenceEventV1,
) -> Result<(), TrustedHostFenceRecoveryError> {
    let current = &assigned.expected_current_desired;
    let replacement = &recovery.replacement_desired;
    let completed_at = terminal_event.committed_at_unix_ms;
    if recovery.cat_id != current.cat_id
        || recovery.assigned_cat_sha256 != trusted_host_fence_assigned_cat_sha256(assigned)?
        || replacement.version != ContractVersion::V1
        || spec_digest(replacement).ok().as_ref() != Some(&replacement.spec_digest)
        || replacement.workspace_id != current.workspace_id
        || replacement.cat_id != current.cat_id
        || replacement.placement.node_id == terminal_event.binding.node_id
        || replacement.desired_revision.get()
            != current
                .desired_revision
                .get()
                .checked_add(1)
                .ok_or(TrustedHostFenceRecoveryError::BatchBinding)?
        || replacement.placement.placement_epoch.get()
            != current
                .placement
                .placement_epoch
                .get()
                .checked_add(1)
                .ok_or(TrustedHostFenceRecoveryError::BatchBinding)?
        || replacement.placement.kind != current.placement.kind
        || replacement.target != current.target
        || replacement.runtime != current.runtime
        || replacement.endpoints != current.endpoints
        || replacement.transition != current.transition
        || recovery.volumes.len() != assigned.volumes.len()
        || replacement.volumes.len() != current.volumes.len()
    {
        return Err(TrustedHostFenceRecoveryError::BatchBinding);
    }
    let mut exact_settlement = assigned.expected_old_operation.clone();
    exact_settlement.phase = OperationPhase::Failed;
    exact_settlement.terminal = Some(OperationTerminal::Failed {
        error: Box::new(OperationFailure::HostLost {
            node_id: terminal_event.binding.node_id.clone(),
            agent_session_epoch: terminal_event.binding.expected_agent_session_epoch,
            host_fence_event_id: terminal_event.event_id.clone(),
        }),
        completed_at_unix_ms: completed_at,
    });
    exact_settlement.updated_at_unix_ms = completed_at;
    if recovery.settled_old_operation != exact_settlement
        || completed_at < assigned.expected_old_operation.updated_at_unix_ms
    {
        return Err(TrustedHostFenceRecoveryError::BatchBinding);
    }
    let operation = &recovery.recovery_operation;
    if operation.version != ContractVersion::V1
        || operation.operation_id == assigned.expected_old_operation.operation_id
        || operation.workspace_id != replacement.workspace_id
        || operation.cat_id != replacement.cat_id
        || operation.desired_revision != replacement.desired_revision
        || operation.desired_spec_digest != replacement.spec_digest
        || operation.placement != replacement.placement
        || operation.target != replacement.target
        || operation.phase != OperationPhase::Pending
        || operation.terminal.is_some()
        || operation.created_at_unix_ms != completed_at
        || operation.updated_at_unix_ms != completed_at
    {
        return Err(TrustedHostFenceRecoveryError::BatchBinding);
    }
    for (((expected, volume), source_intent), successor_intent) in assigned
        .volumes
        .iter()
        .zip(&recovery.volumes)
        .zip(&current.volumes)
        .zip(&replacement.volumes)
    {
        if volume.volume_id != expected.expected_current_volume.volume_id
            || volume.expected_volume_sha256 != trusted_host_fence_assigned_volume_sha256(expected)?
        {
            return Err(TrustedHostFenceRecoveryError::BatchBinding);
        }
        validate_authorization_record(&volume.takeover_authorization)
            .map_err(|_| TrustedHostFenceRecoveryError::UnsafeTakeover)?;
        let VolumeAuthorization::Takeover(authorization) =
            &volume.takeover_authorization.authorization
        else {
            return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
        };
        if !matches!(
            volume.takeover_authorization.state,
            AuthorizationState::Unconsumed
        ) || authorization.host_fence_event_id != terminal_event.event_id
            || authorization.volume_id != expected.expected_current_volume.volume_id
            || authorization.expected_attachment_id != expected.expected_owner.attachment_id
            || authorization.expected_epoch != expected.expected_owner.attachment_epoch
            || authorization.expected_head != expected.expected_current_volume.head
            || authorization.authorized_node_id != replacement.placement.node_id
            || authorization.desired_revision != replacement.desired_revision
            || authorization.new_placement_epoch != replacement.placement.placement_epoch
            || authorization.not_after < completed_at
        {
            return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
        }
        let mut exact_successor = source_intent.clone();
        exact_successor.attachment_id = authorization.new_attachment_id.clone();
        exact_successor.acquire = cats_api::runtime_reconciliation::VolumeAcquire::Takeover {
            authorization_id: authorization.authorization_id.clone(),
        };
        if successor_intent != &exact_successor
            || source_intent.volume_id != expected.expected_current_volume.volume_id
            || source_intent.attachment_id != authorization.expected_attachment_id
            || source_intent.size_bytes != expected.expected_current_volume.size_bytes
            || source_intent.durability != expected.expected_current_volume.durability
        {
            return Err(TrustedHostFenceRecoveryError::UnsafeTakeover);
        }
    }
    Ok(())
}

fn encode_bounded<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, TrustedHostFenceRecoveryError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?;
    if bytes.len() > limit {
        return Err(TrustedHostFenceRecoveryError::WireLimit);
    }
    Ok(bytes)
}

fn decode_bounded<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, TrustedHostFenceRecoveryError> {
    if bytes.len() > limit {
        return Err(TrustedHostFenceRecoveryError::WireLimit);
    }
    let value = serde_json::from_slice(bytes)
        .map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?;
    if serde_json::to_vec(&value).map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?
        != bytes
    {
        return Err(TrustedHostFenceRecoveryError::NonCanonicalJson);
    }
    Ok(value)
}

fn digest_canonical<T: Serialize>(
    domain: &[u8],
    value: &T,
) -> Result<Sha256Digest, TrustedHostFenceRecoveryError> {
    let canonical =
        serde_json::to_vec(value).map_err(|_| TrustedHostFenceRecoveryError::NonCanonicalJson)?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cats_api::runtime_reconciliation::{
        spec_digest, AppliedDesiredEvidence, AsciiText, AssignedKind, AssignedPlacement,
        CheckpointEvidence, DiskKind, Durability, Epoch, FenceEpoch, Generation,
        GuestDeviceIdentity, GuestTransportEvidence, HostPath, Ipv4Address, IsolatedIpv4Kind,
        LifecycleAdmission, LocalVolumeLineage, MacAddress, NetworkConfig, NormalAcquireRequest,
        ObservedDiskKind, OperationPhase, ProviderScope, ReconcileStep, RemoteHead, Revision,
        RuntimeConfig, RuntimeTarget, RuntimeTransition, Sequence, VolumeAccess, VolumeAcquire,
        VolumeAdminState, VolumeAuthorityEvidence, VolumeDisposition, VolumeIntent,
        WarmSnapshotEvidence,
    };

    use crate::authority::normal_acquire;
    use crate::host_fence::{
        host_fence_effect_token, host_fence_provider_attempt_id, HostExecutionCutoffEvidence,
        HostFenceProviderEvidence, ObjectWriteCutoffEvidence, ObjectWriterFenceTarget,
        QuarantinedNetworkInterfaceEvidence, WorkloadNetworkCutoffEvidence,
        HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
    };
    use crate::trusted_host_fence::trusted_host_fence_event_v1;

    fn id(value: &str) -> Id {
        Id::new(value.to_owned()).expect("test ID is valid")
    }

    fn epoch(value: u64) -> Epoch {
        Epoch::new(value).expect("test epoch is nonzero")
    }

    fn revision(value: u64) -> Revision {
        Revision::new(value).expect("test revision is nonzero")
    }

    fn generation(value: u64) -> Generation {
        Generation::new(value).expect("test generation is valid")
    }

    fn fence_epoch(value: u64) -> FenceEpoch {
        FenceEpoch::new(value).expect("test fence epoch is valid")
    }

    fn time(value: u64) -> UnixMillis {
        UnixMillis::new(value).expect("test time is valid")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("test random ID is valid")
    }

    fn ascii(value: &str) -> AsciiText {
        AsciiText::new(value.to_owned()).expect("test ASCII text is valid")
    }

    fn recovery_attempt(
        durability: Durability,
        inventory_available: bool,
    ) -> TrustedHostFenceRecoveryAttemptV1 {
        let node_id = id("node-old");
        let node_boot_id = NodeBootId::new("11111111111111111111111111111111".to_owned())
            .expect("test boot ID is valid");
        let session = SessionBinding {
            node_id: node_id.clone(),
            node_boot_id: node_boot_id.clone(),
            agent_instance_id: random(2),
            agent_session_epoch: epoch(7),
        };
        let head = RemoteHead {
            generation: generation(3),
            root_hash: Some(Sha256Digest::from_bytes([3; 32])),
            root_object_id: Some(ascii("volumes/volume-1/commits/3")),
        };
        let blank = VolumeRecord {
            volume_id: id("volume-1"),
            size_bytes: 4 * 1024 * 1024,
            durability,
            admin_state: VolumeAdminState::Active,
            head,
            lease_owner: None,
            lease_epoch: fence_epoch(1),
            lease_expires_at: None,
            last_transition: None,
        };
        let transition_id = random(3);
        let acquire = NormalAcquireRequest {
            volume_id: blank.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: id("attachment-old"),
            expected_unowned_epoch: blank.lease_epoch,
            desired_revision: revision(1),
            placement_epoch: epoch(5),
            lease_duration_ms: 60_000,
        };
        let (volume, _) =
            normal_acquire(&blank, &acquire, time(10)).expect("test volume acquire is valid");
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: id("workspace-1"),
            cat_id: id("cat-1"),
            desired_revision: revision(1),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: node_id.clone(),
                placement_epoch: epoch(5),
            },
            runtime: RuntimeConfig {
                vcpus: 1,
                memory_bytes: 512 * 1024 * 1024,
                boot_image_digest: Sha256Digest::from_bytes([4; 32]),
                guest_config_digest: Sha256Digest::from_bytes([5; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: id("network-1"),
                    guest_mac: MacAddress::new("02:ca:00:00:00:02").expect("valid test MAC"),
                    guest_ipv4: Ipv4Address::new("10.0.0.2").expect("valid test address"),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.0.0.1").expect("valid test gateway"),
                },
            },
            volumes: vec![VolumeIntent {
                volume_intent_id: id("intent-root"),
                disk_id: id("disk-root"),
                volume_id: volume.volume_id.clone(),
                attachment_id: acquire.attachment_id.clone(),
                size_bytes: volume.size_bytes,
                disk_kind: DiskKind::Root,
                access: VolumeAccess::ReadWriteOnce,
                durability,
                guest_device: GuestDeviceIdentity {
                    serial: id("root-device"),
                    slot: 0,
                },
                acquire: VolumeAcquire::Normal {
                    transition_id: transition_id.clone(),
                    expected_unowned_epoch: acquire.expected_unowned_epoch,
                },
                disposition: VolumeDisposition::Retain,
                mount: None,
            }],
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).expect("test Desired is valid");
        let operation = Operation {
            version: ContractVersion::V1,
            operation_id: id("operation-old"),
            workspace_id: desired.workspace_id.clone(),
            cat_id: desired.cat_id.clone(),
            desired_revision: desired.desired_revision,
            desired_spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
            phase: OperationPhase::Pending,
            terminal: None,
            created_at_unix_ms: time(11),
            updated_at_unix_ms: time(11),
        };
        let observed_volume = ObservedVolume {
            volume_intent_id: Some(desired.volumes[0].volume_intent_id.clone()),
            disk_id: Some(desired.volumes[0].disk_id.clone()),
            volume_id: volume.volume_id.clone(),
            disk_kind: ObservedDiskKind::Root,
            size_bytes: Some(volume.size_bytes),
            durability: Some(durability),
            authority: VolumeAuthorityEvidence::Owned {
                attachment_id: acquire.attachment_id.clone(),
                attachment_epoch: volume.lease_epoch,
                head: volume.head.clone(),
            },
            local_lineages: vec![LocalVolumeLineage {
                attachment_id: acquire.attachment_id.clone(),
                attachment_epoch: volume.lease_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
                local_durable_generation: volume.head.generation,
                remote_durable_generation: volume.head.generation,
                data_directory: HostPath::new("/var/lib/cats/volumes/volume-1")
                    .expect("valid test path"),
                pending_pack_count: WireU64::new(0).expect("zero is a valid count"),
                fenced: false,
                state: LocalLineageState::Active,
            }],
            devices: Vec::new(),
        };
        let observed_runtime = ObservedRuntimeStatus {
            cat_id: desired.cat_id.clone(),
            applied_desired: Some(AppliedDesiredEvidence {
                desired_revision: desired.desired_revision,
                spec_digest: desired.spec_digest.clone(),
                placement: desired.placement.clone(),
                target: desired.target,
            }),
            runtime_incarnation: None,
            stable_state: None,
            step: ReconcileStep::InspectInventory {
                inventory_epoch: epoch(9),
            },
            checkpoint: CheckpointEvidence::Missing {
                checkpoint_path: HostPath::new("/var/lib/cats/runtime/cat-1.json")
                    .expect("valid test path"),
            },
            processes: Vec::new(),
            volumes: vec![observed_volume.clone()],
            mounts: Vec::new(),
            networks: Vec::new(),
            guest_transport: GuestTransportEvidence::Unavailable,
            warm_snapshot: WarmSnapshotEvidence::Absent,
            lifecycle_admission: LifecycleAdmission::Closed,
            routes: Vec::new(),
            platform_guards: 0,
            conditions: Vec::new(),
        };
        let cat = TrustedHostFenceAssignedCatV1 {
            expected_current_desired: desired,
            expected_old_operation: operation,
            inventory: if inventory_available {
                TrustedHostFenceAssignedCatInventoryV1::AcceptedFull {
                    observed_runtime: Box::new(observed_runtime),
                }
            } else {
                TrustedHostFenceAssignedCatInventoryV1::Unavailable
            },
            volumes: vec![TrustedHostFenceExpectedVolumeAuthorityV1 {
                volume_intent_id: id("intent-root"),
                expected_current_volume: volume.clone(),
                expected_owner: VolumeOwnerBinding {
                    volume_id: volume.volume_id.clone(),
                    owner_node_id: node_id.clone(),
                    attachment_id: acquire.attachment_id,
                    attachment_epoch: volume.lease_epoch,
                },
                inventory: if inventory_available {
                    TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull {
                        observed_volume: Box::new(observed_volume),
                    }
                } else {
                    TrustedHostFenceAssignedVolumeInventoryV1::Unavailable
                },
            }],
        };
        let assigned_cats = vec![cat];
        let assigned_set_sha256 = trusted_host_fence_assigned_set_sha256(&assigned_cats)
            .expect("test assigned set is canonical");
        let provider_scope = ProviderScope {
            provider: id("aws"),
            partition: id("aws-partition"),
            account_id: id("account-1"),
            region: id("region-1"),
        };
        let mut binding = HostFenceBinding {
            provider_scope: provider_scope.clone(),
            immutable_host_id: id("host-old"),
            node_id,
            expected_node_boot_id: node_boot_id,
            expected_agent_session_epoch: epoch(7),
            fence_attempt_id: id("pending-fence-attempt"),
        };
        let apply_id = random(4);
        binding.fence_attempt_id =
            trusted_host_fence_recovery_attempt_id(&apply_id, &binding, &assigned_set_sha256)
                .expect("test fence attempt ID derives");
        let provider_request = HostFenceAttemptRequest {
            binding: binding.clone(),
            network_quarantine_boundary_id: ascii("quarantine-boundary-1"),
            object_writer: ObjectWriterFenceTarget {
                writer_authority_id: id("writer-authority-1"),
                provider_scope,
                workload_principal_id: ascii("arn:aws:iam::account-1:role/gateway"),
                object_store_scope_id: ascii("arn:aws:s3:::bucket/volumes"),
            },
        };
        let source_inventory = if inventory_available {
            TrustedHostFenceSourceInventoryV1::AcceptedFull {
                session: session.clone(),
                attestation: Box::new(AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    inventory_epoch: epoch(9),
                    inventory_digest: Sha256Digest::from_bytes([9; 32]),
                    inventory_read_position: Sequence::new(10)
                        .expect("test read position is valid"),
                    accepted_at_unix_ms: time(12),
                }),
                full_observation: TrustedHostFenceCanonicalArtifactV1 {
                    content_sha256: Sha256Digest::from_bytes([10; 32]),
                    length_bytes: WireU64::new(1_024).expect("test length is valid"),
                },
                assigned_snapshot: TrustedHostFenceCanonicalArtifactV1 {
                    content_sha256: Sha256Digest::from_bytes([11; 32]),
                    length_bytes: WireU64::new(2_048).expect("test length is valid"),
                },
            }
        } else {
            TrustedHostFenceSourceInventoryV1::Unavailable {
                session,
                reason: TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory,
                recorded_at_unix_ms: time(12),
            }
        };
        let attempt = TrustedHostFenceRecoveryAttemptV1 {
            version: ContractVersion::V1,
            apply_id,
            principal: FleetPolicyPrincipal::WorkosFleetAdministrator {
                subject: id("fleet-admin"),
                organization_id: id("organization-1"),
            },
            binding,
            provider_request,
            source_inventory,
            assigned_cats,
            assigned_set_sha256,
            requested_at_unix_ms: time(13),
        };
        validate_trusted_host_fence_recovery_attempt_v1(&attempt)
            .expect("test recovery attempt is valid");
        attempt
    }

    fn terminal_event(
        attempt: &TrustedHostFenceRecoveryAttemptV1,
        network_boundary: &str,
    ) -> TrustedHostFenceEventV1 {
        let binding = attempt.binding.clone();
        let object_writer = attempt.provider_request.object_writer.clone();
        let mut object_target = Vec::new();
        for value in [
            object_writer.writer_authority_id.as_str().as_bytes(),
            object_writer.provider_scope.provider.as_str().as_bytes(),
            object_writer.provider_scope.partition.as_str().as_bytes(),
            object_writer.provider_scope.account_id.as_str().as_bytes(),
            object_writer.provider_scope.region.as_str().as_bytes(),
            object_writer.workload_principal_id.as_str().as_bytes(),
            object_writer.object_store_scope_id.as_str().as_bytes(),
        ] {
            object_target.extend_from_slice(
                &u64::try_from(value.len())
                    .expect("test frame length fits u64")
                    .to_be_bytes(),
            );
            object_target.extend_from_slice(value);
        }
        let boundary = ascii(network_boundary);
        let interface_id = id("interface-1");
        let evidence = HostFenceProviderEvidence {
            version: HOST_FENCE_PROVIDER_EVIDENCE_VERSION,
            binding: binding.clone(),
            object_write_cutoff:
                ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
                    binding: binding.clone(),
                    object_writer,
                    effect_token: host_fence_effect_token(
                        &binding,
                        b"object-write-cutoff",
                        &object_target,
                    )
                    .expect("test cutoff token derives"),
                    provider_attempt_id: host_fence_provider_attempt_id(
                        &binding,
                        b"object-write-cutoff",
                        &object_target,
                    )
                    .expect("test cutoff attempt derives"),
                    cutoff_receipt_id: ascii("cutoff-receipt-1"),
                    cutoff_effective_at_unix_ms: time(20),
                    cutoff_sequence: WireU64::new(4).expect("test sequence is valid"),
                    accepted_put_terminal_receipt_id: ascii("terminal-receipt-1"),
                    accepted_puts_terminal_at_unix_ms: time(30),
                    terminal_sequence: WireU64::new(4).expect("test sequence is valid"),
                    terminal_prefix_sha256: Sha256Digest::from_bytes([12; 32]),
                    successful_put_visibility_receipt_id: ascii("visibility-receipt-1"),
                    successful_puts_visible_at_unix_ms: time(40),
                },
            execution_cutoff: HostExecutionCutoffEvidence::HostDestroyed {
                immutable_host_id: binding.immutable_host_id.clone(),
                effect_token: host_fence_effect_token(
                    &binding,
                    b"host-execution-cutoff",
                    binding.immutable_host_id.as_str().as_bytes(),
                )
                .expect("test execution token derives"),
                provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"host-execution-cutoff",
                    binding.immutable_host_id.as_str().as_bytes(),
                )
                .expect("test execution attempt derives"),
                authoritative_observation_id: ascii("execution-observation-1"),
                observed_at_unix_ms: time(50),
            },
            network_cutoff: WorkloadNetworkCutoffEvidence::WorkloadInterfacesQuarantined {
                immutable_host_id: binding.immutable_host_id.clone(),
                quarantine_policy_id: id(boundary.as_str()),
                boundary_effect_token: host_fence_effect_token(
                    &binding,
                    b"network-boundary-cutoff",
                    boundary.as_str().as_bytes(),
                )
                .expect("test boundary token derives"),
                boundary_provider_attempt_id: host_fence_provider_attempt_id(
                    &binding,
                    b"network-boundary-cutoff",
                    boundary.as_str().as_bytes(),
                )
                .expect("test boundary attempt derives"),
                policy_observation_id: ascii("policy-observation-1"),
                policy_observed_at_unix_ms: time(60),
                interfaces: vec![QuarantinedNetworkInterfaceEvidence {
                    interface_id: interface_id.clone(),
                    effect_token: host_fence_effect_token(
                        &binding,
                        b"network-interface-cutoff",
                        interface_id.as_str().as_bytes(),
                    )
                    .expect("test interface token derives"),
                    provider_attempt_id: host_fence_provider_attempt_id(
                        &binding,
                        b"network-interface-cutoff",
                        interface_id.as_str().as_bytes(),
                    )
                    .expect("test interface attempt derives"),
                }],
                authoritative_observation_id: ascii("network-observation-1"),
                observed_at_unix_ms: time(60),
            },
            completed_at_unix_ms: time(60),
        };
        trusted_host_fence_event_v1(evidence, time(70)).expect("test terminal event is valid")
    }

    #[test]
    fn current_authority_blocker_requires_coordinates_for_its_component() {
        let mut reasons = [
            TrustedHostFenceRecoveryBlockedReasonV1::CurrentAuthorityChanged {
                cat_id: Some(id("cat-1")),
                volume_id: None,
                component: TrustedHostFenceCurrentAuthorityComponentV1::SourceIdentity,
            },
        ];

        assert_eq!(
            canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(&mut reasons),
            Err(TrustedHostFenceRecoveryError::BlockedReceipt)
        );
    }

    #[test]
    fn blocked_reasons_have_one_canonical_order_and_reject_duplicates() {
        let relaxed =
            TrustedHostFenceRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
                cat_id: id("cat-1"),
                volume_id: id("volume-1"),
            };
        let source = TrustedHostFenceRecoveryBlockedReasonV1::SourceInventoryUnavailable {
            reason: TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory,
        };
        let mut reasons = [relaxed.clone(), source.clone()];

        canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(&mut reasons)
            .expect("distinct valid reasons canonicalize");
        assert_eq!(reasons, [source.clone(), relaxed]);

        let mut duplicates = [source.clone(), source];
        assert_eq!(
            canonicalize_trusted_host_fence_recovery_blocked_reasons_v1(&mut duplicates),
            Err(TrustedHostFenceRecoveryError::BlockedReceipt)
        );
    }

    #[test]
    fn relaxed_volume_is_blocked_even_when_inventory_has_equal_local_and_remote_heads() {
        let attempt = recovery_attempt(Durability::Relaxed, true);

        assert_eq!(
            trusted_host_fence_recovery_blockers(&attempt).expect("valid attempt is classified"),
            vec![
                TrustedHostFenceRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
                    cat_id: id("cat-1"),
                    volume_id: id("volume-1"),
                }
            ]
        );
    }

    #[test]
    fn unavailable_source_inventory_is_a_terminal_recovery_blocker() {
        let attempt = recovery_attempt(Durability::Strict, false);

        let blockers =
            trusted_host_fence_recovery_blockers(&attempt).expect("valid attempt is classified");
        assert!(blockers.contains(
            &TrustedHostFenceRecoveryBlockedReasonV1::SourceInventoryUnavailable {
                reason: TrustedHostFenceInventoryUnavailableReasonV1::NoAcceptedFullInventory,
            }
        ));
    }

    #[test]
    fn strict_volume_with_exact_owned_head_and_drained_lineage_is_recoverable() {
        let attempt = recovery_attempt(Durability::Strict, true);

        assert_eq!(
            trusted_host_fence_recovery_blockers(&attempt).expect("valid attempt is classified"),
            Vec::new()
        );
    }

    #[test]
    fn strict_volume_rejects_observed_durability_drift() {
        let mut attempt = recovery_attempt(Durability::Strict, true);
        let TrustedHostFenceAssignedVolumeInventoryV1::AcceptedFull { observed_volume } =
            &mut attempt.assigned_cats[0].volumes[0].inventory
        else {
            panic!("test fixture has accepted inventory")
        };
        observed_volume.durability = Some(Durability::Relaxed);
        let TrustedHostFenceAssignedCatInventoryV1::AcceptedFull { observed_runtime } =
            &mut attempt.assigned_cats[0].inventory
        else {
            panic!("test fixture has accepted Cat inventory")
        };
        observed_runtime.volumes[0].durability = Some(Durability::Relaxed);
        attempt.assigned_set_sha256 =
            trusted_host_fence_assigned_set_sha256(&attempt.assigned_cats)
                .expect("mutated assigned set is canonical");
        attempt.binding.fence_attempt_id = trusted_host_fence_recovery_attempt_id(
            &attempt.apply_id,
            &attempt.binding,
            &attempt.assigned_set_sha256,
        )
        .expect("mutated attempt ID derives");
        attempt.provider_request.binding = attempt.binding.clone();

        assert_eq!(
            trusted_host_fence_recovery_blockers(&attempt).expect("valid attempt is classified"),
            vec![
                TrustedHostFenceRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
                    cat_id: id("cat-1"),
                    volume_id: id("volume-1"),
                    problem: TrustedHostFenceStrictVolumeProblemV1::ObservedVolumeBindingMismatch,
                }
            ]
        );
    }

    #[test]
    fn batch_rejects_a_self_consistent_terminal_event_for_another_network_boundary() {
        let attempt = recovery_attempt(Durability::Strict, true);
        let attempt_sha256 = trusted_host_fence_recovery_attempt_sha256(&attempt)
            .expect("test attempt digest derives");
        let matching = TrustedHostFenceBatchRecoveryCommitV1 {
            version: ContractVersion::V1,
            fence_attempt_id: attempt.binding.fence_attempt_id.clone(),
            recovery_attempt_sha256: attempt_sha256.clone(),
            terminal_event: terminal_event(
                &attempt,
                attempt
                    .provider_request
                    .network_quarantine_boundary_id
                    .as_str(),
            ),
            recoveries: Vec::new(),
        };
        assert_eq!(
            validate_trusted_host_fence_batch_recovery_commit_v1(&attempt, &matching),
            Err(TrustedHostFenceRecoveryError::BatchBinding),
            "the matching provider request passes before the intentionally empty recovery set"
        );

        let mismatched = TrustedHostFenceBatchRecoveryCommitV1 {
            terminal_event: terminal_event(&attempt, "quarantine-boundary-other"),
            ..matching
        };
        assert_eq!(
            validate_trusted_host_fence_batch_recovery_commit_v1(&attempt, &mismatched),
            Err(TrustedHostFenceRecoveryError::TerminalEvent)
        );
    }
}
