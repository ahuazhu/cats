//! Deployment-provisioner proof primitives for Host-loss recovery.
//!
//! Apply and discovery deliberately have independent signing domains. The
//! control-plane adapter owns exact header occurrence and closed credential
//! envelope admission; this module owns the bytes shared by clients and the
//! verifier.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use ring::signature::{UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::HashSet;

use crate::agent_registration::{Ed25519RequestSigner, JSON_CONTENT_TYPE};
use crate::runtime_reconciliation::{
    canonical_ed25519_spki_sha256, ContractVersion, Epoch, FleetPolicyPrincipal, Id, NodeBootId,
    ProviderScope, RandomId128, Revision, RuntimeProvisionerCredential, Sequence, Sha256Digest,
    UnixMillis,
};

pub const HOST_LOSS_RECOVERY_APPLY_PATH: &str = "/v1/admin/runtime/host-loss-recovery-applies";
pub const HOST_LOSS_RECOVERY_DISCOVERY_PATH: &str =
    "/v1/admin/runtime/host-loss-recovery-discoveries";
pub const HOST_LOSS_RECOVERY_METHOD: &str = "POST";
pub const HOST_LOSS_RECOVERY_APPLY_ID_HEADER: &str = "cats-host-loss-recovery-apply-id";

pub const HOST_LOSS_RECOVERY_APPLY_REQUEST_MAX_WIRE_BYTES: usize = 1_048_576;
pub const HOST_LOSS_RECOVERY_DISCOVERY_REQUEST_MAX_WIRE_BYTES: usize = 16_384;
pub const HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES: usize = 1_048_576;
pub const HOST_LOSS_RECOVERY_ERROR_MAX_WIRE_BYTES: usize = 32_768;
pub const HOST_LOSS_RECOVERY_MAX_EXPECTED_ASSIGNED_CATS: usize = 1_024;
pub const HOST_LOSS_RECOVERY_TERMINAL_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.host-loss-recovery.terminal-receipt.v1";

const APPLY_SIGNATURE_DOMAIN: &[u8] = b"cats.host-loss-recovery.apply.v1";
const DISCOVERY_SIGNATURE_DOMAIN: &[u8] = b"cats.host-loss-recovery.discovery.v1";
const ED25519_SPKI_PREFIX: [u8; 12] = [
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
];
const ED25519_SPKI_LEN: usize = ED25519_SPKI_PREFIX.len() + 32;

/// The observation-only inventory coordinate accepted by Control before the
/// Host-loss attempt is frozen. `Unavailable` carries no caller-invented
/// reason; Control derives the exact terminal reason under its authority lock.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostLossRecoveryExpectedSourceInventoryV1 {
    AcceptedFull {
        inventory_epoch: Epoch,
        inventory_digest: Sha256Digest,
        inventory_read_position: Sequence,
    },
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryExpectedAssignedCatV1 {
    pub workspace_id: Id,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub spec_digest: Sha256Digest,
    pub placement_epoch: Epoch,
    /// This field is deliberately present as JSON `null` when no retained
    /// runtime is expected. The strict codec rejects an omitted field.
    pub expected_runtime_incarnation: Option<RandomId128>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryApplyV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub source_node_id: Id,
    pub expected_node_boot_id: NodeBootId,
    pub expected_agent_session_epoch: Epoch,
    pub expected_source_inventory: HostLossRecoveryExpectedSourceInventoryV1,
    pub expected_assigned: Vec<HostLossRecoveryExpectedAssignedCatV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryDiscoveryV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub source_node_id: Id,
    pub fence_attempt_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryApplyResultV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub fence_attempt_id: Id,
    pub recovery_attempt_sha256: Sha256Digest,
    pub assigned_set_sha256: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostLossRecoveryInventoryUnavailableReasonV1 {
    NoAcceptedFullInventory,
    AcceptedFullInventoryNotCurrent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostLossRecoveryStrictVolumeProblemV1 {
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostLossRecoveryCurrentAuthorityComponentV1 {
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
pub enum HostLossRecoveryTargetProblemV1 {
    NoEligibleReplacementNode,
    ReplacementPolicyChanged,
    TakeoverAuthorizationUnavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "reason", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostLossRecoveryBlockedReasonV1 {
    SourceInventoryUnavailable {
        unavailable_reason: HostLossRecoveryInventoryUnavailableReasonV1,
    },
    RelaxedDurabilityUnprovableAfterInventory {
        cat_id: Id,
        volume_id: Id,
    },
    StrictVolumeNotSafelyRecoverable {
        cat_id: Id,
        volume_id: Id,
        problem: HostLossRecoveryStrictVolumeProblemV1,
    },
    CurrentAuthorityChanged {
        cat_id: Option<Id>,
        volume_id: Option<Id>,
        component: HostLossRecoveryCurrentAuthorityComponentV1,
    },
    RecoveryTargetUnavailable {
        cat_id: Id,
        problem: HostLossRecoveryTargetProblemV1,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryCommittedCatV1 {
    pub workspace_id: Id,
    pub cat_id: Id,
    pub old_desired_revision: Revision,
    pub old_placement_epoch: Epoch,
    pub old_operation_id: Id,
    pub replacement_desired_revision: Revision,
    pub replacement_spec_digest: Sha256Digest,
    pub replacement_node_id: Id,
    pub replacement_placement_epoch: Epoch,
    pub settled_old_operation_id: Id,
    pub recovery_operation_id: Id,
    pub takeover_authorization_ids: Vec<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostLossRecoveryTerminalOutcomeV1 {
    Blocked {
        reasons: Vec<HostLossRecoveryBlockedReasonV1>,
    },
    Committed {
        batch_request_sha256: Sha256Digest,
        source_retired_at_unix_ms: UnixMillis,
        cats: Vec<HostLossRecoveryCommittedCatV1>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryTerminalReceiptV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub fence_attempt_id: Id,
    pub source_provider_scope: ProviderScope,
    pub immutable_host_id: Id,
    pub source_node_id: Id,
    pub expected_node_boot_id: NodeBootId,
    pub expected_agent_session_epoch: Epoch,
    pub recovery_attempt_sha256: Sha256Digest,
    pub assigned_set_sha256: Sha256Digest,
    pub host_fence_event_id: Id,
    pub provider_evidence_sha256: Sha256Digest,
    pub outcome: HostLossRecoveryTerminalOutcomeV1,
    pub completed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostLossRecoveryDiscoveryOutcomeV1 {
    Pending,
    Terminal {
        receipt: Box<HostLossRecoveryTerminalReceiptV1>,
        receipt_sha256: Sha256Digest,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostLossRecoveryDiscoveryResultV1 {
    pub version: ContractVersion,
    pub apply_id: RandomId128,
    pub fence_attempt_id: Id,
    pub recovery_attempt_sha256: Sha256Digest,
    pub assigned_set_sha256: Sha256Digest,
    pub outcome: HostLossRecoveryDiscoveryOutcomeV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HostLossRecoveryWireError {
    #[error("Host-loss recovery JSON is malformed or non-canonical")]
    NonCanonicalJson,
    #[error("Host-loss recovery value exceeds its wire bound")]
    WireLimit,
    #[error("Host-loss recovery value violates the V1 contract")]
    InvalidContract,
}

pub fn encode_host_loss_recovery_apply_v1(
    value: &HostLossRecoveryApplyV1,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    validate_host_loss_recovery_apply_v1(value)?;
    encode_bounded(value, HOST_LOSS_RECOVERY_APPLY_REQUEST_MAX_WIRE_BYTES)
}

pub fn decode_host_loss_recovery_apply_v1(
    bytes: &[u8],
) -> Result<HostLossRecoveryApplyV1, HostLossRecoveryWireError> {
    let value = decode_bounded(bytes, HOST_LOSS_RECOVERY_APPLY_REQUEST_MAX_WIRE_BYTES)?;
    validate_host_loss_recovery_apply_v1(&value)?;
    Ok(value)
}

pub fn encode_host_loss_recovery_discovery_v1(
    value: &HostLossRecoveryDiscoveryV1,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    validate_host_loss_recovery_discovery_v1(value)?;
    encode_bounded(value, HOST_LOSS_RECOVERY_DISCOVERY_REQUEST_MAX_WIRE_BYTES)
}

pub fn decode_host_loss_recovery_discovery_v1(
    bytes: &[u8],
) -> Result<HostLossRecoveryDiscoveryV1, HostLossRecoveryWireError> {
    let value = decode_bounded(bytes, HOST_LOSS_RECOVERY_DISCOVERY_REQUEST_MAX_WIRE_BYTES)?;
    validate_host_loss_recovery_discovery_v1(&value)?;
    Ok(value)
}

pub fn encode_host_loss_recovery_apply_result_v1(
    value: &HostLossRecoveryApplyResultV1,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    validate_host_loss_recovery_apply_result_v1(value)?;
    encode_bounded(value, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)
}

pub fn decode_host_loss_recovery_apply_result_v1(
    bytes: &[u8],
) -> Result<HostLossRecoveryApplyResultV1, HostLossRecoveryWireError> {
    let value = decode_bounded(bytes, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)?;
    validate_host_loss_recovery_apply_result_v1(&value)?;
    Ok(value)
}

pub fn encode_host_loss_recovery_discovery_result_v1(
    value: &HostLossRecoveryDiscoveryResultV1,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    validate_host_loss_recovery_discovery_result_v1(value)?;
    encode_bounded(value, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)
}

pub fn decode_host_loss_recovery_discovery_result_v1(
    bytes: &[u8],
) -> Result<HostLossRecoveryDiscoveryResultV1, HostLossRecoveryWireError> {
    let value = decode_bounded(bytes, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)?;
    validate_host_loss_recovery_discovery_result_v1(&value)?;
    Ok(value)
}

pub fn encode_host_loss_recovery_terminal_receipt_v1(
    value: &HostLossRecoveryTerminalReceiptV1,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    validate_host_loss_recovery_terminal_receipt_v1(value)?;
    encode_bounded(value, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)
}

pub fn decode_host_loss_recovery_terminal_receipt_v1(
    bytes: &[u8],
) -> Result<HostLossRecoveryTerminalReceiptV1, HostLossRecoveryWireError> {
    let value = decode_bounded(bytes, HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES)?;
    validate_host_loss_recovery_terminal_receipt_v1(&value)?;
    Ok(value)
}

pub fn host_loss_recovery_terminal_receipt_sha256(
    receipt: &HostLossRecoveryTerminalReceiptV1,
) -> Result<Sha256Digest, HostLossRecoveryWireError> {
    let canonical = encode_host_loss_recovery_terminal_receipt_v1(receipt)?;
    let mut hasher = Sha256::new();
    hasher.update(HOST_LOSS_RECOVERY_TERMINAL_RECEIPT_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub fn validate_host_loss_recovery_apply_v1(
    value: &HostLossRecoveryApplyV1,
) -> Result<(), HostLossRecoveryWireError> {
    if value.version != ContractVersion::V1
        || value.expected_assigned.is_empty()
        || value.expected_assigned.len() > HOST_LOSS_RECOVERY_MAX_EXPECTED_ASSIGNED_CATS
        || value
            .expected_assigned
            .windows(2)
            .any(|pair| pair[0].cat_id.as_str() >= pair[1].cat_id.as_str())
    {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    Ok(())
}

pub fn validate_host_loss_recovery_discovery_v1(
    value: &HostLossRecoveryDiscoveryV1,
) -> Result<(), HostLossRecoveryWireError> {
    if value.version != ContractVersion::V1 {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    Ok(())
}

pub fn validate_host_loss_recovery_apply_result_v1(
    value: &HostLossRecoveryApplyResultV1,
) -> Result<(), HostLossRecoveryWireError> {
    if value.version != ContractVersion::V1 {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    Ok(())
}

pub fn validate_host_loss_recovery_discovery_result_v1(
    value: &HostLossRecoveryDiscoveryResultV1,
) -> Result<(), HostLossRecoveryWireError> {
    if value.version != ContractVersion::V1 {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    if let HostLossRecoveryDiscoveryOutcomeV1::Terminal {
        receipt,
        receipt_sha256,
    } = &value.outcome
    {
        if receipt.apply_id != value.apply_id
            || receipt.fence_attempt_id != value.fence_attempt_id
            || receipt.recovery_attempt_sha256 != value.recovery_attempt_sha256
            || receipt.assigned_set_sha256 != value.assigned_set_sha256
            || *receipt_sha256 != host_loss_recovery_terminal_receipt_sha256(receipt)?
        {
            return Err(HostLossRecoveryWireError::InvalidContract);
        }
    }
    Ok(())
}

pub fn validate_host_loss_recovery_terminal_receipt_v1(
    value: &HostLossRecoveryTerminalReceiptV1,
) -> Result<(), HostLossRecoveryWireError> {
    if value.version != ContractVersion::V1 {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    match &value.outcome {
        HostLossRecoveryTerminalOutcomeV1::Blocked { reasons } => {
            validate_blocked_reasons(reasons)?;
        }
        HostLossRecoveryTerminalOutcomeV1::Committed { cats, .. } => {
            if cats.is_empty()
                || cats.len() > HOST_LOSS_RECOVERY_MAX_EXPECTED_ASSIGNED_CATS
                || cats
                    .windows(2)
                    .any(|pair| pair[0].cat_id.as_str() >= pair[1].cat_id.as_str())
            {
                return Err(HostLossRecoveryWireError::InvalidContract);
            }
            let mut recovery_operation_ids = HashSet::with_capacity(cats.len());
            for cat in cats {
                let expected_revision = cat
                    .old_desired_revision
                    .get()
                    .checked_add(1)
                    .and_then(Revision::new)
                    .ok_or(HostLossRecoveryWireError::InvalidContract)?;
                let expected_placement_epoch = cat
                    .old_placement_epoch
                    .get()
                    .checked_add(1)
                    .and_then(Epoch::new)
                    .ok_or(HostLossRecoveryWireError::InvalidContract)?;
                let unique_authorizations = cat
                    .takeover_authorization_ids
                    .iter()
                    .map(Id::as_str)
                    .collect::<HashSet<_>>();
                if cat.replacement_desired_revision != expected_revision
                    || cat.settled_old_operation_id != cat.old_operation_id
                    || cat.recovery_operation_id == cat.old_operation_id
                    || cat.replacement_node_id == value.source_node_id
                    || cat.replacement_placement_epoch != expected_placement_epoch
                    || cat.takeover_authorization_ids.is_empty()
                    || unique_authorizations.len() != cat.takeover_authorization_ids.len()
                    || !recovery_operation_ids.insert(cat.recovery_operation_id.as_str())
                {
                    return Err(HostLossRecoveryWireError::InvalidContract);
                }
            }
        }
    }
    Ok(())
}

/// Canonicalize a producer's complete reason set. Callers must not silently
/// deduplicate independently-derived reasons.
pub fn canonicalize_host_loss_recovery_blocked_reasons_v1(
    reasons: &mut [HostLossRecoveryBlockedReasonV1],
) -> Result<(), HostLossRecoveryWireError> {
    for reason in reasons.iter() {
        validate_blocked_reason_shape(reason)?;
    }
    reasons
        .sort_by(|left, right| blocked_reason_sort_key(left).cmp(&blocked_reason_sort_key(right)));
    validate_blocked_reasons(reasons)
}

fn validate_blocked_reasons(
    reasons: &[HostLossRecoveryBlockedReasonV1],
) -> Result<(), HostLossRecoveryWireError> {
    if reasons.is_empty() {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    for reason in reasons {
        validate_blocked_reason_shape(reason)?;
    }
    if reasons
        .windows(2)
        .any(|pair| blocked_reason_sort_key(&pair[0]) >= blocked_reason_sort_key(&pair[1]))
    {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    Ok(())
}

fn validate_blocked_reason_shape(
    reason: &HostLossRecoveryBlockedReasonV1,
) -> Result<(), HostLossRecoveryWireError> {
    let HostLossRecoveryBlockedReasonV1::CurrentAuthorityChanged {
        cat_id,
        volume_id,
        component,
    } = reason
    else {
        return Ok(());
    };
    let expected_coordinates = match component {
        HostLossRecoveryCurrentAuthorityComponentV1::SourceIdentity
        | HostLossRecoveryCurrentAuthorityComponentV1::SourceAgentSession
        | HostLossRecoveryCurrentAuthorityComponentV1::AssignedCatSet => (false, false),
        HostLossRecoveryCurrentAuthorityComponentV1::Desired
        | HostLossRecoveryCurrentAuthorityComponentV1::OldOperation => (true, false),
        HostLossRecoveryCurrentAuthorityComponentV1::VolumeRecord
        | HostLossRecoveryCurrentAuthorityComponentV1::VolumeOwner
        | HostLossRecoveryCurrentAuthorityComponentV1::TakeoverAuthorization => (true, true),
    };
    if (cat_id.is_some(), volume_id.is_some()) != expected_coordinates {
        return Err(HostLossRecoveryWireError::InvalidContract);
    }
    Ok(())
}

fn blocked_reason_sort_key(reason: &HostLossRecoveryBlockedReasonV1) -> (u8, &str, &str, u8) {
    match reason {
        HostLossRecoveryBlockedReasonV1::SourceInventoryUnavailable { unavailable_reason } => (
            0,
            "",
            "",
            match unavailable_reason {
                HostLossRecoveryInventoryUnavailableReasonV1::NoAcceptedFullInventory => 0,
                HostLossRecoveryInventoryUnavailableReasonV1::AcceptedFullInventoryNotCurrent => 1,
            },
        ),
        HostLossRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
            cat_id,
            volume_id,
        } => (1, cat_id.as_str(), volume_id.as_str(), 0),
        HostLossRecoveryBlockedReasonV1::StrictVolumeNotSafelyRecoverable {
            cat_id,
            volume_id,
            problem,
        } => (
            2,
            cat_id.as_str(),
            volume_id.as_str(),
            strict_volume_problem_order(*problem),
        ),
        HostLossRecoveryBlockedReasonV1::CurrentAuthorityChanged {
            cat_id,
            volume_id,
            component,
        } => (
            3,
            cat_id.as_ref().map_or("", Id::as_str),
            volume_id.as_ref().map_or("", Id::as_str),
            current_authority_component_order(*component),
        ),
        HostLossRecoveryBlockedReasonV1::RecoveryTargetUnavailable { cat_id, problem } => (
            4,
            cat_id.as_str(),
            "",
            recovery_target_problem_order(*problem),
        ),
    }
}

fn strict_volume_problem_order(problem: HostLossRecoveryStrictVolumeProblemV1) -> u8 {
    match problem {
        HostLossRecoveryStrictVolumeProblemV1::InventoryUnavailable => 0,
        HostLossRecoveryStrictVolumeProblemV1::DesiredOrAuthorityBindingMismatch => 1,
        HostLossRecoveryStrictVolumeProblemV1::ObservedVolumeBindingMismatch => 2,
        HostLossRecoveryStrictVolumeProblemV1::ObservedAuthorityNotExactOwner => 3,
        HostLossRecoveryStrictVolumeProblemV1::LocalLineagesNotCanonical => 4,
        HostLossRecoveryStrictVolumeProblemV1::CurrentLineageMissing => 5,
        HostLossRecoveryStrictVolumeProblemV1::CurrentLineageDuplicated => 6,
        HostLossRecoveryStrictVolumeProblemV1::CurrentLineageBindingMismatch => 7,
        HostLossRecoveryStrictVolumeProblemV1::CurrentLineageNotActive => 8,
        HostLossRecoveryStrictVolumeProblemV1::LocalGenerationAheadOfRemote => 9,
        HostLossRecoveryStrictVolumeProblemV1::RemoteGenerationDoesNotMatchHead => 10,
        HostLossRecoveryStrictVolumeProblemV1::PendingPacksRemain => 11,
    }
}

fn current_authority_component_order(component: HostLossRecoveryCurrentAuthorityComponentV1) -> u8 {
    match component {
        HostLossRecoveryCurrentAuthorityComponentV1::SourceIdentity => 0,
        HostLossRecoveryCurrentAuthorityComponentV1::SourceAgentSession => 1,
        HostLossRecoveryCurrentAuthorityComponentV1::AssignedCatSet => 2,
        HostLossRecoveryCurrentAuthorityComponentV1::Desired => 3,
        HostLossRecoveryCurrentAuthorityComponentV1::OldOperation => 4,
        HostLossRecoveryCurrentAuthorityComponentV1::VolumeRecord => 5,
        HostLossRecoveryCurrentAuthorityComponentV1::VolumeOwner => 6,
        HostLossRecoveryCurrentAuthorityComponentV1::TakeoverAuthorization => 7,
    }
}

fn recovery_target_problem_order(problem: HostLossRecoveryTargetProblemV1) -> u8 {
    match problem {
        HostLossRecoveryTargetProblemV1::NoEligibleReplacementNode => 0,
        HostLossRecoveryTargetProblemV1::ReplacementPolicyChanged => 1,
        HostLossRecoveryTargetProblemV1::TakeoverAuthorizationUnavailable => 2,
    }
}

fn encode_bounded<T: Serialize>(
    value: &T,
    limit: usize,
) -> Result<Vec<u8>, HostLossRecoveryWireError> {
    let bytes =
        serde_json::to_vec(value).map_err(|_| HostLossRecoveryWireError::NonCanonicalJson)?;
    if bytes.len() > limit {
        return Err(HostLossRecoveryWireError::WireLimit);
    }
    Ok(bytes)
}

fn decode_bounded<T: for<'de> Deserialize<'de> + Serialize>(
    bytes: &[u8],
    limit: usize,
) -> Result<T, HostLossRecoveryWireError> {
    if bytes.len() > limit {
        return Err(HostLossRecoveryWireError::WireLimit);
    }
    let value =
        serde_json::from_slice(bytes).map_err(|_| HostLossRecoveryWireError::NonCanonicalJson)?;
    if serde_json::to_vec(&value).map_err(|_| HostLossRecoveryWireError::NonCanonicalJson)? != bytes
    {
        return Err(HostLossRecoveryWireError::NonCanonicalJson);
    }
    Ok(value)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("Host-loss recovery request authentication failed")]
pub struct HostLossRecoveryProofError;

/// The two exact deployment-provisioner headers emitted by a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostLossRecoveryProvisionerProof {
    pub credential_id: String,
    pub signature: String,
}

pub fn sign_host_loss_recovery_apply_request(
    deployment_id: &Id,
    signer: &Ed25519RequestSigner,
    exact_body: &[u8],
) -> HostLossRecoveryProvisionerProof {
    sign_request(
        APPLY_SIGNATURE_DOMAIN,
        HOST_LOSS_RECOVERY_APPLY_PATH,
        deployment_id,
        signer,
        exact_body,
    )
}

pub fn sign_host_loss_recovery_discovery_request(
    deployment_id: &Id,
    signer: &Ed25519RequestSigner,
    exact_body: &[u8],
) -> HostLossRecoveryProvisionerProof {
    sign_request(
        DISCOVERY_SIGNATURE_DOMAIN,
        HOST_LOSS_RECOVERY_DISCOVERY_PATH,
        deployment_id,
        signer,
        exact_body,
    )
}

pub fn verify_host_loss_recovery_apply_request(
    deployment_id: &Id,
    credential: &RuntimeProvisionerCredential,
    exact_body: &[u8],
    signature: &str,
) -> Result<FleetPolicyPrincipal, HostLossRecoveryProofError> {
    verify_request(
        APPLY_SIGNATURE_DOMAIN,
        HOST_LOSS_RECOVERY_APPLY_PATH,
        deployment_id,
        credential,
        exact_body,
        signature,
    )
}

pub fn verify_host_loss_recovery_discovery_request(
    deployment_id: &Id,
    credential: &RuntimeProvisionerCredential,
    exact_body: &[u8],
    signature: &str,
) -> Result<FleetPolicyPrincipal, HostLossRecoveryProofError> {
    verify_request(
        DISCOVERY_SIGNATURE_DOMAIN,
        HOST_LOSS_RECOVERY_DISCOVERY_PATH,
        deployment_id,
        credential,
        exact_body,
        signature,
    )
}

fn sign_request(
    domain: &[u8],
    path: &str,
    deployment_id: &Id,
    signer: &Ed25519RequestSigner,
    exact_body: &[u8],
) -> HostLossRecoveryProvisionerProof {
    let signed = signed_request(
        domain,
        path,
        deployment_id.as_str(),
        signer.credential_id().as_str(),
        exact_body,
    );
    HostLossRecoveryProvisionerProof {
        credential_id: signer.credential_id().to_string(),
        signature: URL_SAFE_NO_PAD.encode(signer.sign_framed(&signed)),
    }
}

fn verify_request(
    domain: &[u8],
    path: &str,
    deployment_id: &Id,
    credential: &RuntimeProvisionerCredential,
    exact_body: &[u8],
    signature: &str,
) -> Result<FleetPolicyPrincipal, HostLossRecoveryProofError> {
    let spki = decode_base64url_exact::<ED25519_SPKI_LEN>(credential.public_key_spki.as_str())?;
    if spki[..ED25519_SPKI_PREFIX.len()] != ED25519_SPKI_PREFIX {
        return Err(HostLossRecoveryProofError);
    }
    let signature = decode_base64url_exact::<64>(signature)?;
    let signed = signed_request(
        domain,
        path,
        deployment_id.as_str(),
        credential.credential_id.as_str(),
        exact_body,
    );
    UnparsedPublicKey::new(&ED25519, &spki[ED25519_SPKI_PREFIX.len()..])
        .verify(&signed, &signature)
        .map_err(|_| HostLossRecoveryProofError)?;
    let public_key_spki_sha256 = canonical_ed25519_spki_sha256(&credential.public_key_spki)
        .ok_or(HostLossRecoveryProofError)?;
    Ok(FleetPolicyPrincipal::DeploymentProvisioner {
        deployment_id: deployment_id.clone(),
        credential_id: credential.credential_id.clone(),
        public_key_spki: credential.public_key_spki.clone(),
        public_key_spki_sha256,
    })
}

fn signed_request(
    domain: &[u8],
    path: &str,
    deployment_id: &str,
    credential_id: &str,
    exact_body: &[u8],
) -> Vec<u8> {
    let mut signed = Vec::with_capacity(
        domain.len()
            + 1
            + 8 * 5
            + HOST_LOSS_RECOVERY_METHOD.len()
            + path.len()
            + JSON_CONTENT_TYPE.len()
            + deployment_id.len()
            + credential_id.len()
            + 8
            + 32,
    );
    signed.extend_from_slice(domain);
    signed.push(0);
    append_frame(&mut signed, HOST_LOSS_RECOVERY_METHOD.as_bytes());
    append_frame(&mut signed, path.as_bytes());
    append_frame(&mut signed, JSON_CONTENT_TYPE.as_bytes());
    append_frame(&mut signed, deployment_id.as_bytes());
    append_frame(&mut signed, credential_id.as_bytes());
    signed.extend_from_slice(&(exact_body.len() as u64).to_be_bytes());
    signed.extend_from_slice(&Sha256::digest(exact_body));
    signed
}

fn append_frame(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn decode_base64url_exact<const N: usize>(
    value: &str,
) -> Result<[u8; N], HostLossRecoveryProofError> {
    if value.is_empty()
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'))
    {
        return Err(HostLossRecoveryProofError);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| HostLossRecoveryProofError)?;
    if decoded.len() != N || URL_SAFE_NO_PAD.encode(&decoded) != value {
        return Err(HostLossRecoveryProofError);
    }
    decoded.try_into().map_err(|_| HostLossRecoveryProofError)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_node_authority::{
        PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_SIGNATURE_HEADER,
    };
    use crate::runtime_reconciliation::{Base64UrlNoPad, Sha256Digest};

    const BODY: &[u8] = br#"{"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","version":1}"#;
    const PUBLIC_KEY_SPKI: &str = "MCowBQYDK2VwAyEA11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";

    fn signer() -> Ed25519RequestSigner {
        let mut der = hex::decode("302e020100300506032b657004220420").unwrap();
        der.extend_from_slice(
            &hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
                .unwrap(),
        );
        Ed25519RequestSigner::from_pkcs8_der(Id::new("provisioner_a").unwrap(), &der).unwrap()
    }

    fn credential() -> RuntimeProvisionerCredential {
        RuntimeProvisionerCredential {
            credential_id: Id::new("provisioner_a").unwrap(),
            public_key_spki: Base64UrlNoPad::new(PUBLIC_KEY_SPKI).unwrap(),
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn random(value: char) -> RandomId128 {
        RandomId128::new(value.to_string().repeat(32)).unwrap()
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn apply() -> HostLossRecoveryApplyV1 {
        HostLossRecoveryApplyV1 {
            version: ContractVersion::V1,
            apply_id: random('a'),
            source_node_id: id("node_source"),
            expected_node_boot_id: NodeBootId::new("b".repeat(32)).unwrap(),
            expected_agent_session_epoch: Epoch::new(7).unwrap(),
            expected_source_inventory: HostLossRecoveryExpectedSourceInventoryV1::AcceptedFull {
                inventory_epoch: Epoch::new(11).unwrap(),
                inventory_digest: digest(1),
                inventory_read_position: Sequence::new(13).unwrap(),
            },
            expected_assigned: vec![HostLossRecoveryExpectedAssignedCatV1 {
                workspace_id: id("workspace_a"),
                cat_id: id("cat_a"),
                desired_revision: Revision::new(17).unwrap(),
                spec_digest: digest(2),
                placement_epoch: Epoch::new(19).unwrap(),
                expected_runtime_incarnation: None,
            }],
        }
    }

    fn blocked_receipt() -> HostLossRecoveryTerminalReceiptV1 {
        HostLossRecoveryTerminalReceiptV1 {
            version: ContractVersion::V1,
            apply_id: random('a'),
            fence_attempt_id: id("fence_attempt_a"),
            source_provider_scope: ProviderScope {
                provider: id("aws"),
                partition: id("aws"),
                account_id: id("account_a"),
                region: id("region_a"),
            },
            immutable_host_id: id("host_a"),
            source_node_id: id("node_source"),
            expected_node_boot_id: NodeBootId::new("b".repeat(32)).unwrap(),
            expected_agent_session_epoch: Epoch::new(7).unwrap(),
            recovery_attempt_sha256: digest(3),
            assigned_set_sha256: digest(4),
            host_fence_event_id: id("host_fence_event_a"),
            provider_evidence_sha256: digest(5),
            outcome: HostLossRecoveryTerminalOutcomeV1::Blocked {
                reasons: vec![
                    HostLossRecoveryBlockedReasonV1::SourceInventoryUnavailable {
                        unavailable_reason:
                            HostLossRecoveryInventoryUnavailableReasonV1::NoAcceptedFullInventory,
                    },
                    HostLossRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
                        cat_id: id("cat_a"),
                        volume_id: id("volume_a"),
                    },
                ],
            },
            completed_at_unix_ms: UnixMillis::new(23).unwrap(),
        }
    }

    fn committed_cat(cat: &str, old_revision: u64) -> HostLossRecoveryCommittedCatV1 {
        HostLossRecoveryCommittedCatV1 {
            workspace_id: id("workspace_a"),
            cat_id: id(cat),
            old_desired_revision: Revision::new(old_revision).unwrap(),
            old_placement_epoch: Epoch::new(27).unwrap(),
            old_operation_id: id(&format!("old_operation_{cat}")),
            replacement_desired_revision: Revision::new(old_revision + 1).unwrap(),
            replacement_spec_digest: digest(6),
            replacement_node_id: id("node_replacement"),
            replacement_placement_epoch: Epoch::new(28).unwrap(),
            settled_old_operation_id: id(&format!("old_operation_{cat}")),
            recovery_operation_id: id(&format!("recovery_operation_{cat}")),
            takeover_authorization_ids: vec![id(&format!("authorization_{cat}"))],
        }
    }

    fn terminal_result(
        receipt: HostLossRecoveryTerminalReceiptV1,
    ) -> HostLossRecoveryDiscoveryResultV1 {
        let receipt_sha256 = host_loss_recovery_terminal_receipt_sha256(&receipt).unwrap();
        HostLossRecoveryDiscoveryResultV1 {
            version: ContractVersion::V1,
            apply_id: receipt.apply_id.clone(),
            fence_attempt_id: receipt.fence_attempt_id.clone(),
            recovery_attempt_sha256: receipt.recovery_attempt_sha256.clone(),
            assigned_set_sha256: receipt.assigned_set_sha256.clone(),
            outcome: HostLossRecoveryDiscoveryOutcomeV1::Terminal {
                receipt: Box::new(receipt),
                receipt_sha256,
            },
        }
    }

    #[test]
    fn frozen_transport_constants_are_exact() {
        assert_eq!(HOST_LOSS_RECOVERY_METHOD, "POST");
        assert_eq!(
            HOST_LOSS_RECOVERY_APPLY_PATH,
            "/v1/admin/runtime/host-loss-recovery-applies"
        );
        assert_eq!(
            HOST_LOSS_RECOVERY_DISCOVERY_PATH,
            "/v1/admin/runtime/host-loss-recovery-discoveries"
        );
        assert_eq!(
            HOST_LOSS_RECOVERY_APPLY_ID_HEADER,
            "cats-host-loss-recovery-apply-id"
        );
        assert_eq!(
            PROVISIONER_CREDENTIAL_ID_HEADER,
            "cats-provisioner-credential-id"
        );
        assert_eq!(PROVISIONER_SIGNATURE_HEADER, "cats-provisioner-signature");
        assert_eq!(HOST_LOSS_RECOVERY_APPLY_REQUEST_MAX_WIRE_BYTES, 1_048_576);
        assert_eq!(HOST_LOSS_RECOVERY_DISCOVERY_REQUEST_MAX_WIRE_BYTES, 16_384);
        assert_eq!(HOST_LOSS_RECOVERY_SUCCESS_MAX_WIRE_BYTES, 1_048_576);
        assert_eq!(HOST_LOSS_RECOVERY_ERROR_MAX_WIRE_BYTES, 32_768);
    }

    #[test]
    fn apply_and_discovery_proofs_are_domain_and_path_separated() {
        let deployment_id = Id::new("deployment_a").unwrap();
        let signer = signer();
        let apply = sign_host_loss_recovery_apply_request(&deployment_id, &signer, BODY);
        let discovery = sign_host_loss_recovery_discovery_request(&deployment_id, &signer, BODY);
        assert_eq!(apply.credential_id, "provisioner_a");
        assert_ne!(apply.signature, discovery.signature);

        let apply_principal = verify_host_loss_recovery_apply_request(
            &deployment_id,
            &credential(),
            BODY,
            &apply.signature,
        )
        .unwrap();
        assert!(matches!(
            apply_principal,
            FleetPolicyPrincipal::DeploymentProvisioner {
                deployment_id: ref actual_deployment,
                credential_id: ref actual_credential,
                public_key_spki_sha256,
                ..
            } if actual_deployment == &deployment_id
                && actual_credential.as_str() == "provisioner_a"
                && public_key_spki_sha256 == Sha256Digest::from_bytes(
                    hex::decode("06e3fd8fda29bb60ab59557de61edb0aecdb231134be30e75b455f8e1b792fa9")
                        .unwrap()
                        .try_into()
                        .unwrap()
                )
        ));
        assert!(verify_host_loss_recovery_discovery_request(
            &deployment_id,
            &credential(),
            BODY,
            &apply.signature,
        )
        .is_err());
        assert!(verify_host_loss_recovery_apply_request(
            &deployment_id,
            &credential(),
            b"{}",
            &apply.signature,
        )
        .is_err());
        assert!(verify_host_loss_recovery_apply_request(
            &deployment_id,
            &credential(),
            BODY,
            &format!("{}=", apply.signature),
        )
        .is_err());
    }

    #[test]
    fn signing_frames_have_frozen_digests_and_signatures() {
        let apply_frame = signed_request(
            APPLY_SIGNATURE_DOMAIN,
            HOST_LOSS_RECOVERY_APPLY_PATH,
            "deployment_a",
            "provisioner_a",
            BODY,
        );
        let discovery_frame = signed_request(
            DISCOVERY_SIGNATURE_DOMAIN,
            HOST_LOSS_RECOVERY_DISCOVERY_PATH,
            "deployment_a",
            "provisioner_a",
            BODY,
        );
        assert_eq!(
            hex::encode(Sha256::digest(&apply_frame)),
            "a7f415d909ce0cdcd528e44c5f5fa4f294120e27e29691be3f0636048f3507fa"
        );
        assert_eq!(
            hex::encode(Sha256::digest(&discovery_frame)),
            "abaf8e478480df27c241922b0dae89129ba321715c90845cce0c53cce02cc95d"
        );
        let signer = signer();
        let deployment_id = Id::new("deployment_a").unwrap();
        assert_eq!(
            sign_host_loss_recovery_apply_request(&deployment_id, &signer, BODY).signature,
            "PESKCgp4SnxZH4zz_9fiXSPfC_oZaf3Hauz5qoGrQ1P9d89Eh1iOpPCKfeXiBubCczuGVW7m1BFFd9KeeMl5Dw"
        );
        assert_eq!(
            sign_host_loss_recovery_discovery_request(&deployment_id, &signer, BODY).signature,
            "D_CScXTb1jUqy4spKrxL3rJYg9wh-tLhuUnLFRRtXz1HdstSy1tEgO9sJ7_lZJUzNbSKtgSTdiuQNObf-xQJDg"
        );
    }

    #[test]
    fn apply_codec_requires_one_sorted_set_and_explicit_null_runtime() {
        let value = apply();
        let bytes = encode_host_loss_recovery_apply_v1(&value).unwrap();
        assert!(std::str::from_utf8(&bytes)
            .unwrap()
            .contains("\"expected_runtime_incarnation\":null"));
        assert_eq!(decode_host_loss_recovery_apply_v1(&bytes).unwrap(), value);

        let mut missing_null: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        missing_null["expected_assigned"][0]
            .as_object_mut()
            .unwrap()
            .remove("expected_runtime_incarnation");
        assert_eq!(
            decode_host_loss_recovery_apply_v1(&serde_json::to_vec(&missing_null).unwrap()),
            Err(HostLossRecoveryWireError::NonCanonicalJson)
        );

        let mut empty = value.clone();
        empty.expected_assigned.clear();
        assert_eq!(
            encode_host_loss_recovery_apply_v1(&empty),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        let mut unsorted = value.clone();
        let mut first = unsorted.expected_assigned[0].clone();
        first.cat_id = id("cat_b");
        unsorted.expected_assigned.insert(0, first);
        assert_eq!(
            encode_host_loss_recovery_apply_v1(&unsorted),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        let mut oversized = value;
        oversized.expected_assigned = (0..=HOST_LOSS_RECOVERY_MAX_EXPECTED_ASSIGNED_CATS)
            .map(|index| HostLossRecoveryExpectedAssignedCatV1 {
                workspace_id: id("workspace_a"),
                cat_id: id(&format!("cat_{index:04}")),
                desired_revision: Revision::new(1).unwrap(),
                spec_digest: digest(2),
                placement_epoch: Epoch::new(1).unwrap(),
                expected_runtime_incarnation: None,
            })
            .collect();
        assert_eq!(
            encode_host_loss_recovery_apply_v1(&oversized),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
    }

    #[test]
    fn strict_codecs_reject_noncanonical_unknown_duplicate_and_oversized_json() {
        let bytes = encode_host_loss_recovery_discovery_v1(&HostLossRecoveryDiscoveryV1 {
            version: ContractVersion::V1,
            apply_id: random('a'),
            source_node_id: id("node_source"),
            fence_attempt_id: id("fence_attempt_a"),
        })
        .unwrap();
        let mut spaced = b" ".to_vec();
        spaced.extend_from_slice(&bytes);
        assert_eq!(
            decode_host_loss_recovery_discovery_v1(&spaced),
            Err(HostLossRecoveryWireError::NonCanonicalJson)
        );
        let unknown = bytes
            .strip_suffix(b"}")
            .unwrap()
            .iter()
            .copied()
            .chain(br#","unexpected":true}"#.iter().copied())
            .collect::<Vec<_>>();
        assert_eq!(
            decode_host_loss_recovery_discovery_v1(&unknown),
            Err(HostLossRecoveryWireError::NonCanonicalJson)
        );
        let duplicate = br#"{"version":1,"version":1,"apply_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","source_node_id":"node_source","fence_attempt_id":"fence_attempt_a"}"#;
        assert_eq!(
            decode_host_loss_recovery_discovery_v1(duplicate),
            Err(HostLossRecoveryWireError::NonCanonicalJson)
        );
        assert_eq!(
            decode_host_loss_recovery_discovery_v1(&vec![
                b' ';
                HOST_LOSS_RECOVERY_DISCOVERY_REQUEST_MAX_WIRE_BYTES
                    + 1
            ]),
            Err(HostLossRecoveryWireError::WireLimit)
        );
    }

    #[test]
    fn blocked_reasons_are_closed_sorted_and_coordinate_exact() {
        let source = HostLossRecoveryBlockedReasonV1::SourceInventoryUnavailable {
            unavailable_reason:
                HostLossRecoveryInventoryUnavailableReasonV1::NoAcceptedFullInventory,
        };
        let relaxed = HostLossRecoveryBlockedReasonV1::RelaxedDurabilityUnprovableAfterInventory {
            cat_id: id("cat_a"),
            volume_id: id("volume_a"),
        };
        let mut reasons = vec![relaxed.clone(), source.clone()];
        canonicalize_host_loss_recovery_blocked_reasons_v1(&mut reasons).unwrap();
        assert_eq!(reasons, vec![source.clone(), relaxed]);

        let mut duplicate = vec![source.clone(), source];
        assert_eq!(
            canonicalize_host_loss_recovery_blocked_reasons_v1(&mut duplicate),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        let mut wrong_coordinates =
            vec![HostLossRecoveryBlockedReasonV1::CurrentAuthorityChanged {
                cat_id: Some(id("cat_a")),
                volume_id: None,
                component: HostLossRecoveryCurrentAuthorityComponentV1::SourceIdentity,
            }];
        assert_eq!(
            canonicalize_host_loss_recovery_blocked_reasons_v1(&mut wrong_coordinates),
            Err(HostLossRecoveryWireError::InvalidContract)
        );

        let mut receipt = blocked_receipt();
        receipt.outcome = HostLossRecoveryTerminalOutcomeV1::Blocked {
            reasons: vec![HostLossRecoveryBlockedReasonV1::CurrentAuthorityChanged {
                cat_id: None,
                volume_id: None,
                component: HostLossRecoveryCurrentAuthorityComponentV1::SourceAgentSession,
            }],
        };
        let bytes = encode_host_loss_recovery_terminal_receipt_v1(&receipt).unwrap();
        let wire = std::str::from_utf8(&bytes).unwrap();
        assert!(wire.contains("\"cat_id\":null,\"volume_id\":null"));
        assert_eq!(
            decode_host_loss_recovery_terminal_receipt_v1(&bytes).unwrap(),
            receipt
        );
    }

    #[test]
    fn terminal_discovery_binds_receipt_digest_and_all_prefix_coordinates() {
        let receipt = blocked_receipt();
        let result = terminal_result(receipt.clone());
        let bytes = encode_host_loss_recovery_discovery_result_v1(&result).unwrap();
        assert_eq!(
            decode_host_loss_recovery_discovery_result_v1(&bytes).unwrap(),
            result
        );
        assert_eq!(
            host_loss_recovery_terminal_receipt_sha256(&receipt)
                .unwrap()
                .as_str(),
            "sha256:a2c9de38cd50b136ab93dafc6a9a667c4e6d80eb509e13c071e34fe3dfa88b91"
        );

        let mut wrong_prefix = terminal_result(receipt.clone());
        wrong_prefix.assigned_set_sha256 = digest(9);
        assert_eq!(
            encode_host_loss_recovery_discovery_result_v1(&wrong_prefix),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        let mut wrong_digest = terminal_result(receipt);
        let HostLossRecoveryDiscoveryOutcomeV1::Terminal { receipt_sha256, .. } =
            &mut wrong_digest.outcome
        else {
            unreachable!()
        };
        *receipt_sha256 = digest(9);
        assert_eq!(
            encode_host_loss_recovery_discovery_result_v1(&wrong_digest),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
    }

    #[test]
    fn committed_receipt_rejects_stale_epochs_duplicate_operations_and_authorizations() {
        let mut receipt = blocked_receipt();
        receipt.outcome = HostLossRecoveryTerminalOutcomeV1::Committed {
            batch_request_sha256: digest(7),
            source_retired_at_unix_ms: UnixMillis::new(31).unwrap(),
            cats: vec![committed_cat("cat_a", 17)],
        };
        encode_host_loss_recovery_terminal_receipt_v1(&receipt).unwrap();

        if let HostLossRecoveryTerminalOutcomeV1::Committed { cats, .. } = &mut receipt.outcome {
            cats[0].replacement_placement_epoch = cats[0].old_placement_epoch;
        }
        assert_eq!(
            encode_host_loss_recovery_terminal_receipt_v1(&receipt),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        if let HostLossRecoveryTerminalOutcomeV1::Committed { cats, .. } = &mut receipt.outcome {
            cats[0].replacement_placement_epoch = Epoch::new(28).unwrap();
            let duplicate = cats[0].takeover_authorization_ids[0].clone();
            cats[0].takeover_authorization_ids.push(duplicate);
        }
        assert_eq!(
            encode_host_loss_recovery_terminal_receipt_v1(&receipt),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
        if let HostLossRecoveryTerminalOutcomeV1::Committed { cats, .. } = &mut receipt.outcome {
            cats[0].takeover_authorization_ids.pop();
            let mut second = committed_cat("cat_b", 21);
            second.recovery_operation_id = cats[0].recovery_operation_id.clone();
            cats.push(second);
        }
        assert_eq!(
            encode_host_loss_recovery_terminal_receipt_v1(&receipt),
            Err(HostLossRecoveryWireError::InvalidContract)
        );
    }
}
