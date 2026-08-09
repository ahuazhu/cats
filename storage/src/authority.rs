//! Pure, provider-neutral volume authority transitions from ADR-0042.
//!
//! These functions perform no I/O. The PostgreSQL transaction owner is
//! responsible for locking and validating Control rows before applying the
//! returned replacement rows in the same transaction.

pub use cats_api::runtime_reconciliation::{
    AsciiText, Epoch, FenceEpoch, Generation, Id, NodeBootId, RandomId128, RemoteHead, Revision,
    Sha256Digest, UnixMillis,
};
use serde::{Deserialize, Serialize};

const MAX_INTEGER: u64 = i64::MAX as u64;

/// Exact clean-slate authority schema release understood by the Volume
/// Authority writer and its data-plane adapter. Earlier versions are neither
/// migrated nor repaired by this release.
///
/// The Control Store remains the sole owner of its full schema stamp and DDL.
/// Sharing this release number lets the adapter reject an unstamped or
/// incompatible authority shape without importing the product store or
/// duplicating its schema.
pub const AUTHORITY_RELEASE_SCHEMA_VERSION: i64 = 2;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VolumeDurability {
    Strict,
    Relaxed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAdminState {
    Active,
    Deleting { delete_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeRecord {
    pub volume_id: Id,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub admin_state: VolumeAdminState,
    pub head: RemoteHead,
    pub lease_owner: Option<Id>,
    pub lease_epoch: FenceEpoch,
    pub lease_expires_at: Option<UnixMillis>,
    pub last_transition: Option<LastVolumeTransition>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LastVolumeTransition {
    NormalAcquire {
        request: NormalAcquireRequest,
        result: NormalAcquireResult,
    },
    Release {
        request: ReleaseRequest,
        result: ReleaseResult,
    },
    Takeover {
        authorization_id: Id,
    },
    BeginDelete {
        request: BeginDeleteRequest,
        result: BeginDeleteResult,
    },
    BeginDisposableDelete {
        authorization_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalAcquireRequest {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub expected_unowned_epoch: FenceEpoch,
    pub desired_revision: Revision,
    pub placement_epoch: Epoch,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalAcquireResult {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub lease_expires_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewLeaseRequest {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenewLeaseResult {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub epoch: FenceEpoch,
    pub lease_expires_at: UnixMillis,
}

/// Exact data-plane publication request.
///
/// The complete predecessor head is part of the compare. Comparing only its
/// generation would make two different roots at the same generation
/// indistinguishable after an ambiguous response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHeadCasRequest {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub expected_size_bytes: u64,
    pub expected_head: RemoteHead,
    pub new_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHeadCasResult {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseRequest {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub attachment_id: Id,
    pub expected_epoch: FenceEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseResult {
    pub volume_id: Id,
    pub transition_id: RandomId128,
    pub released_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeTakeoverAuthorization {
    pub authorization_id: Id,
    pub host_fence_event_id: Id,
    pub volume_id: Id,
    pub expected_attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub new_attachment_id: Id,
    pub desired_revision: Revision,
    pub new_placement_epoch: Epoch,
    pub lease_duration_ms: u64,
    pub not_after: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TakeoverConsumedReceipt {
    pub authorization_id: Id,
    pub host_fence_event_id: Id,
    pub volume_id: Id,
    pub new_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub consumed_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakeoverResult {
    pub authorization_id: Id,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub lease_expires_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDeleteRequest {
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub expected_unowned_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDeleteResult {
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DisposableRootDeleteAuthorization {
    pub authorization_id: Id,
    pub delete_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub cat_id: Id,
    pub desired_revision: Revision,
    pub placement_epoch: Epoch,
    pub expected_attachment_id: Id,
    pub expected_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub isolation_basis: DisposableDeleteIsolationBasis,
    pub not_after: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DisposableDeleteIsolationBasis {
    RuntimeStopped {
        node_id: Id,
        agent_session_epoch: Epoch,
        runtime_incarnation: RandomId128,
        observation_id: RandomId128,
    },
    HostFenceEvent {
        event_id: Id,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BeginDisposableDeleteConsumedReceipt {
    pub authorization_id: Id,
    pub volume_id: Id,
    pub disk_id: Id,
    pub cat_id: Id,
    pub delete_id: Id,
    pub prior_attachment_id: Id,
    pub resulting_epoch: FenceEpoch,
    pub resulting_head: RemoteHead,
    pub consumed_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum VolumeAuthorization {
    Takeover(VolumeTakeoverAuthorization),
    DisposableRootDelete(DisposableRootDeleteAuthorization),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorizationConsumedReceipt {
    Takeover(TakeoverConsumedReceipt),
    BeginDisposableDelete(BeginDisposableDeleteConsumedReceipt),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum AuthorizationState {
    Unconsumed,
    Consumed(Box<AuthorizationConsumedReceipt>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationRecord {
    pub authorization: VolumeAuthorization,
    pub state: AuthorizationState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostFenceEvent {
    pub event_id: Id,
    pub provider: Id,
    pub immutable_host_id: Id,
    pub node_id: Id,
    pub expected_node_boot_id: NodeBootId,
    pub expected_agent_session_epoch: Epoch,
    pub fence_attempt_id: Id,
    pub isolation_state: HostIsolationState,
    pub observed_at: UnixMillis,
    pub state: HostFenceEventState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum HostIsolationState {
    Isolated,
    HostDestroyed { receipt: HostDestroyedReceipt },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostFenceEventState {
    Active,
    Rejoined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HostDestroyedReceipt {
    pub provider: Id,
    pub immutable_host_id: Id,
    pub node_id: Id,
    pub expected_node_boot_id: NodeBootId,
    pub expected_agent_session_epoch: Epoch,
    pub state_path_id: Id,
    pub state_storage_disposition: StateStorageDisposition,
    pub destroyed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StateStorageDisposition {
    PermanentlyDestroyed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DeleteCompletionReceipt {
    Normal {
        request: BeginDeleteRequest,
        deleting_epoch: FenceEpoch,
        deleting_head: RemoteHead,
        completed_at: UnixMillis,
    },
    DisposableRoot {
        disk_id: Id,
        volume_id: Id,
        delete_id: Id,
        authorization_id: Id,
        prior_attachment_id: Id,
        deleting_epoch: FenceEpoch,
        deleting_head: RemoteHead,
        completed_at: UnixMillis,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthorityError {
    #[error("volume not found")]
    NotFound,
    #[error("volume has another writer")]
    OtherWriter,
    #[error("attachment owner or epoch is fenced")]
    Fenced,
    #[error("transition identity is stale or was reused with another payload")]
    StaleTransition,
    #[error("lease duration is invalid")]
    InvalidLeaseDuration,
    #[error("fencing epoch is exhausted")]
    EpochExhausted,
    #[error("volume administration is busy")]
    AdminBusy,
    #[error("remote head does not match")]
    HeadConflict,
    #[error("a live snapshot prevents this transition")]
    SnapshotInUse,
    #[error("authorization is absent, expired, or does not match")]
    InvalidAuthorization,
    #[error("stored authority rows do not form a known closed state")]
    BackendUnknown,
}

pub type Result<T> = std::result::Result<T, AuthorityError>;

/// The one provider-neutral boundary used by a block data plane after the
/// Node has already obtained an exact attachment grant.
///
/// Ownership transitions deliberately do not appear here. They remain owned
/// by the Runtime/Volume Authority transaction path; blockd may only inspect,
/// renew and publish under the grant it was given.
pub trait VolumeDataAuthority: Send + Sync {
    /// Reads one fully validated canonical record, including its exact grant
    /// and complete remote-head tuple.
    fn load_volume(&self, volume_id: &Id) -> Result<VolumeRecord>;
    /// Extends only the named owner/epoch, using the authority database clock.
    fn renew_lease(&self, request: &RenewLeaseRequest) -> Result<RenewLeaseResult>;
    /// Replaces only the complete predecessor head under the named grant.
    fn compare_and_swap_head(&self, request: &VolumeHeadCasRequest) -> Result<VolumeHeadCasResult>;
}

/// Exact scalar projection stored beside the canonical JSON VolumeRecord.
///
/// PostgreSQL extraction remains adapter-specific, but both the Control Store
/// writer and the data-plane adapter derive their expected columns here. This
/// keeps one projection/validation rule without putting a database driver in
/// the provider-neutral crate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeRecordProjection {
    pub volume_id: String,
    pub size_bytes: u64,
    pub durability: &'static str,
    pub admin_state: &'static str,
    pub delete_id: Option<String>,
    pub head_generation: Generation,
    pub head_root_hash: Option<String>,
    pub head_root_object_id: Option<String>,
    pub lease_owner: Option<String>,
    pub lease_epoch: FenceEpoch,
    pub lease_expires_at: Option<UnixMillis>,
    pub last_transition_kind: Option<&'static str>,
    pub last_transition_id: Option<String>,
    pub transition_desired_revision: Option<Revision>,
    pub transition_placement_epoch: Option<Epoch>,
    pub transition_lease_duration_ms: Option<u64>,
}

pub fn project_volume_record(record: &VolumeRecord) -> Result<VolumeRecordProjection> {
    validate_volume_record(record)?;
    let (admin_state, delete_id) = match &record.admin_state {
        VolumeAdminState::Active => ("active", None),
        VolumeAdminState::Deleting { delete_id } => ("deleting", Some(delete_id.to_string())),
    };
    let durability = match record.durability {
        VolumeDurability::Strict => "strict",
        VolumeDurability::Relaxed => "relaxed",
    };
    let (kind, transition_id, revision, placement, duration) = match &record.last_transition {
        None => (None, None, None, None, None),
        Some(LastVolumeTransition::NormalAcquire { request, .. }) => (
            Some("normal_acquire"),
            Some(request.transition_id.to_string()),
            Some(request.desired_revision),
            Some(request.placement_epoch),
            Some(request.lease_duration_ms),
        ),
        Some(LastVolumeTransition::Release { request, .. }) => (
            Some("release"),
            Some(request.transition_id.to_string()),
            None,
            None,
            None,
        ),
        Some(LastVolumeTransition::Takeover { authorization_id }) => (
            Some("takeover"),
            Some(authorization_id.to_string()),
            None,
            None,
            None,
        ),
        Some(LastVolumeTransition::BeginDelete { request, .. }) => (
            Some("begin_delete"),
            Some(request.delete_id.to_string()),
            None,
            None,
            None,
        ),
        Some(LastVolumeTransition::BeginDisposableDelete { authorization_id }) => (
            Some("begin_disposable_delete"),
            Some(authorization_id.to_string()),
            None,
            None,
            None,
        ),
    };
    Ok(VolumeRecordProjection {
        volume_id: record.volume_id.to_string(),
        size_bytes: record.size_bytes,
        durability,
        admin_state,
        delete_id,
        head_generation: record.head.generation,
        head_root_hash: record.head.root_hash.as_ref().map(ToString::to_string),
        head_root_object_id: record.head.root_object_id.as_ref().map(ToString::to_string),
        lease_owner: record.lease_owner.as_ref().map(ToString::to_string),
        lease_epoch: record.lease_epoch,
        lease_expires_at: record.lease_expires_at,
        last_transition_kind: kind,
        last_transition_id: transition_id,
        transition_desired_revision: revision,
        transition_placement_epoch: placement,
        transition_lease_duration_ms: duration,
    })
}

/// `RemoteHead` is either the exact empty tuple or a complete non-empty tuple.
pub fn remote_head_is_valid(head: &RemoteHead) -> bool {
    match head.generation.get() {
        0 => head.root_hash.is_none() && head.root_object_id.is_none(),
        _ => head.root_hash.is_some() && head.root_object_id.is_some(),
    }
}

/// Tests the closed successor relation used by authority receipts.
pub fn remote_head_is_same_or_later(current: &RemoteHead, previous: &RemoteHead) -> bool {
    remote_head_is_valid(current)
        && remote_head_is_valid(previous)
        && (current.generation > previous.generation
            || (current.generation == previous.generation && current == previous))
}

/// Validates the invariants that can be decided from a `VolumeRecord` alone.
pub fn validate_volume_record(record: &VolumeRecord) -> Result<()> {
    if !(1..=MAX_INTEGER).contains(&record.size_bytes) || !remote_head_is_valid(&record.head) {
        return Err(AuthorityError::BackendUnknown);
    }

    match (
        &record.admin_state,
        &record.lease_owner,
        &record.lease_expires_at,
    ) {
        (VolumeAdminState::Active, None, None) => {}
        (VolumeAdminState::Active, Some(_), Some(expires_at))
            if record.lease_epoch.get() > 0 && expires_at.get() > 0 => {}
        (VolumeAdminState::Deleting { .. }, None, None) if record.lease_epoch.get() > 0 => {}
        _ => return Err(AuthorityError::BackendUnknown),
    }

    let Some(last) = &record.last_transition else {
        return match (&record.admin_state, &record.lease_owner) {
            (VolumeAdminState::Active, None) => Ok(()),
            _ => Err(AuthorityError::BackendUnknown),
        };
    };

    match last {
        LastVolumeTransition::NormalAcquire { request, result } => {
            validate_normal_acquire_pair(request, result)?;
            if request.volume_id != record.volume_id
                || !matches!(record.admin_state, VolumeAdminState::Active)
                || record.lease_owner.as_ref() != Some(&result.attachment_id)
                || record.lease_epoch != result.resulting_epoch
                || !remote_head_is_same_or_later(&record.head, &result.resulting_head)
            {
                return Err(AuthorityError::BackendUnknown);
            }
        }
        LastVolumeTransition::Release { request, result } => {
            validate_release_pair(request, result)?;
            if request.volume_id != record.volume_id
                || !matches!(record.admin_state, VolumeAdminState::Active)
                || record.lease_owner.is_some()
                || record.lease_epoch != result.resulting_epoch
                || record.head != result.resulting_head
            {
                return Err(AuthorityError::BackendUnknown);
            }
        }
        LastVolumeTransition::Takeover { .. } => {
            if !matches!(record.admin_state, VolumeAdminState::Active)
                || record.lease_owner.is_none()
            {
                return Err(AuthorityError::BackendUnknown);
            }
        }
        LastVolumeTransition::BeginDelete { request, result } => {
            validate_begin_delete_pair(request, result)?;
            if request.volume_id != record.volume_id
                || record.lease_epoch != result.resulting_epoch
                || record.head != result.resulting_head
                || !matches!(
                    &record.admin_state,
                    VolumeAdminState::Deleting { delete_id } if delete_id == &result.delete_id
                )
            {
                return Err(AuthorityError::BackendUnknown);
            }
        }
        LastVolumeTransition::BeginDisposableDelete { .. } => {
            if !matches!(record.admin_state, VolumeAdminState::Deleting { .. }) {
                return Err(AuthorityError::BackendUnknown);
            }
        }
    }
    Ok(())
}

/// Validates the closed payload/receipt relation held by the one authorization row.
pub fn validate_authorization_record(record: &AuthorizationRecord) -> Result<()> {
    match &record.state {
        AuthorizationState::Unconsumed => match &record.authorization {
            VolumeAuthorization::Takeover(authorization) => {
                validate_takeover_authorization(authorization)
            }
            VolumeAuthorization::DisposableRootDelete(authorization) => {
                validate_disposable_authorization(authorization)
            }
        },
        AuthorizationState::Consumed(receipt) => match (&record.authorization, receipt.as_ref()) {
            (
                VolumeAuthorization::Takeover(authorization),
                AuthorizationConsumedReceipt::Takeover(receipt),
            ) => validate_takeover_receipt(authorization, receipt),
            (
                VolumeAuthorization::DisposableRootDelete(authorization),
                AuthorizationConsumedReceipt::BeginDisposableDelete(receipt),
            ) => validate_disposable_receipt(authorization, receipt),
            _ => Err(AuthorityError::BackendUnknown),
        },
    }
}

pub fn validate_host_fence_event(event: &HostFenceEvent) -> Result<()> {
    if let HostIsolationState::HostDestroyed { receipt } = &event.isolation_state {
        if event.state == HostFenceEventState::Rejoined
            || receipt.provider != event.provider
            || receipt.immutable_host_id != event.immutable_host_id
            || receipt.node_id != event.node_id
            || receipt.expected_node_boot_id != event.expected_node_boot_id
            || receipt.expected_agent_session_epoch != event.expected_agent_session_epoch
        {
            return Err(AuthorityError::BackendUnknown);
        }
    }
    Ok(())
}

pub fn validate_delete_completion_receipt(receipt: &DeleteCompletionReceipt) -> Result<()> {
    match receipt {
        DeleteCompletionReceipt::Normal {
            request,
            deleting_epoch,
            deleting_head,
            ..
        } => {
            validate_stored_head(&request.expected_head)?;
            if request.expected_head != *deleting_head
                || stored_next_epoch(request.expected_unowned_epoch)? != *deleting_epoch
            {
                return Err(AuthorityError::BackendUnknown);
            }
        }
        DeleteCompletionReceipt::DisposableRoot { deleting_head, .. } => {
            validate_stored_head(deleting_head)?;
        }
    }
    Ok(())
}

pub fn normal_acquire(
    record: &VolumeRecord,
    request: &NormalAcquireRequest,
    db_now: UnixMillis,
) -> Result<(VolumeRecord, NormalAcquireResult)> {
    if let Some(result) = replay_normal_acquire(record, request)? {
        return Ok((record.clone(), result));
    }
    let lease_expires_at = checked_expiry(db_now, request.lease_duration_ms)?;
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.lease_owner.is_some() {
        return Err(AuthorityError::OtherWriter);
    }
    if record.lease_epoch != request.expected_unowned_epoch {
        return Err(AuthorityError::Fenced);
    }
    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let result = NormalAcquireResult {
        volume_id: request.volume_id.clone(),
        transition_id: request.transition_id.clone(),
        attachment_id: request.attachment_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
        lease_expires_at,
    };
    let mut updated = record.clone();
    updated.lease_owner = Some(request.attachment_id.clone());
    updated.lease_epoch = resulting_epoch;
    updated.lease_expires_at = Some(lease_expires_at);
    updated.last_transition = Some(LastVolumeTransition::NormalAcquire {
        request: request.clone(),
        result: result.clone(),
    });
    Ok((updated, result))
}

/// Returns an exact acquire replay without requiring the caller to read a
/// clock. Reusing the transition ID with another payload is stale.
pub fn replay_normal_acquire(
    record: &VolumeRecord,
    request: &NormalAcquireRequest,
) -> Result<Option<NormalAcquireResult>> {
    validate_volume_record(record)?;
    if let Some(last_id) = normal_transition_id(record.last_transition.as_ref()) {
        if last_id == &request.transition_id {
            return match record.last_transition.as_ref() {
                Some(LastVolumeTransition::NormalAcquire {
                    request: original,
                    result,
                }) if original == request => Ok(Some(result.clone())),
                _ => Err(AuthorityError::StaleTransition),
            };
        }
    }
    if record.volume_id != request.volume_id {
        return Err(AuthorityError::NotFound);
    }
    Ok(None)
}

pub fn renew_lease(
    record: &VolumeRecord,
    request: &RenewLeaseRequest,
    db_now: UnixMillis,
) -> Result<(VolumeRecord, RenewLeaseResult)> {
    validate_volume_record(record)?;
    if record.volume_id != request.volume_id {
        return Err(AuthorityError::NotFound);
    }
    let lease_expires_at = checked_expiry(db_now, request.lease_duration_ms)?;
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.lease_owner.as_ref() != Some(&request.attachment_id)
        || record.lease_epoch != request.expected_epoch
    {
        return Err(AuthorityError::Fenced);
    }
    let mut updated = record.clone();
    updated.lease_expires_at = Some(lease_expires_at);
    let result = RenewLeaseResult {
        volume_id: request.volume_id.clone(),
        attachment_id: request.attachment_id.clone(),
        epoch: request.expected_epoch,
        lease_expires_at,
    };
    Ok((updated, result))
}

/// Publish one exact successor head under the current attachment grant.
///
/// This pure transition intentionally has no retry ledger. A caller that
/// loses the response rereads the VolumeRecord and accepts only the exact
/// requested target; otherwise it retries the same predecessor CAS or fails
/// closed.
pub fn compare_and_swap_head(
    record: &VolumeRecord,
    request: &VolumeHeadCasRequest,
) -> Result<(VolumeRecord, VolumeHeadCasResult)> {
    validate_volume_record(record)?;
    if !remote_head_is_valid(&request.expected_head)
        || !remote_head_is_valid(&request.new_head)
        || request.new_head.generation <= request.expected_head.generation
    {
        return Err(AuthorityError::HeadConflict);
    }
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.volume_id != request.volume_id
        || record.lease_owner.as_ref() != Some(&request.attachment_id)
        || record.lease_epoch != request.expected_epoch
    {
        return Err(AuthorityError::Fenced);
    }
    if record.head != request.expected_head {
        return Err(AuthorityError::HeadConflict);
    }
    if record.size_bytes != request.expected_size_bytes {
        return Err(AuthorityError::HeadConflict);
    }

    let result = VolumeHeadCasResult {
        volume_id: request.volume_id.clone(),
        attachment_id: request.attachment_id.clone(),
        epoch: request.expected_epoch,
        resulting_head: request.new_head.clone(),
    };
    let mut updated = record.clone();
    updated.head = request.new_head.clone();
    validate_volume_record(&updated)?;
    Ok((updated, result))
}

pub fn release(
    record: &VolumeRecord,
    request: &ReleaseRequest,
) -> Result<(VolumeRecord, ReleaseResult)> {
    validate_volume_record(record)?;
    if let Some(last_id) = normal_transition_id(record.last_transition.as_ref()) {
        if last_id == &request.transition_id {
            return match record.last_transition.as_ref() {
                Some(LastVolumeTransition::Release {
                    request: original,
                    result,
                }) if original == request => Ok((record.clone(), result.clone())),
                _ => Err(AuthorityError::StaleTransition),
            };
        }
    }
    if record.volume_id != request.volume_id {
        return Err(AuthorityError::NotFound);
    }
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.lease_owner.as_ref() != Some(&request.attachment_id)
        || record.lease_epoch != request.expected_epoch
    {
        return Err(AuthorityError::Fenced);
    }
    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let result = ReleaseResult {
        volume_id: request.volume_id.clone(),
        transition_id: request.transition_id.clone(),
        released_attachment_id: request.attachment_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
    };
    let mut updated = record.clone();
    updated.lease_owner = None;
    updated.lease_epoch = resulting_epoch;
    updated.lease_expires_at = None;
    updated.last_transition = Some(LastVolumeTransition::Release {
        request: request.clone(),
        result: result.clone(),
    });
    Ok((updated, result))
}

pub fn consume_takeover(
    record: &VolumeRecord,
    event: &HostFenceEvent,
    authorization_record: &AuthorizationRecord,
    authorization_id: &Id,
    db_now: UnixMillis,
) -> Result<(VolumeRecord, AuthorizationRecord, TakeoverResult)> {
    validate_volume_record(record)?;
    validate_host_fence_event(event)?;
    validate_authorization_record(authorization_record)?;
    let VolumeAuthorization::Takeover(authorization) = &authorization_record.authorization else {
        return Err(AuthorityError::InvalidAuthorization);
    };
    if &authorization.authorization_id != authorization_id
        || authorization.host_fence_event_id != event.event_id
        || authorization.volume_id != record.volume_id
    {
        return Err(AuthorityError::InvalidAuthorization);
    }

    if let AuthorizationState::Consumed(receipt) = &authorization_record.state {
        let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_ref() else {
            return Err(AuthorityError::BackendUnknown);
        };
        return Ok((
            record.clone(),
            authorization_record.clone(),
            takeover_result(authorization, receipt)?,
        ));
    }

    if event.state != HostFenceEventState::Active || db_now > authorization.not_after {
        return Err(AuthorityError::InvalidAuthorization);
    }
    let lease_expires_at = checked_expiry(db_now, authorization.lease_duration_ms)?;
    if !matches!(record.admin_state, VolumeAdminState::Active)
        || record.lease_owner.as_ref() != Some(&authorization.expected_attachment_id)
        || record.lease_epoch != authorization.expected_epoch
    {
        return Err(AuthorityError::InvalidAuthorization);
    }
    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let receipt = TakeoverConsumedReceipt {
        authorization_id: authorization.authorization_id.clone(),
        host_fence_event_id: authorization.host_fence_event_id.clone(),
        volume_id: authorization.volume_id.clone(),
        new_attachment_id: authorization.new_attachment_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
        consumed_at: db_now,
    };
    let result = TakeoverResult {
        authorization_id: authorization.authorization_id.clone(),
        volume_id: authorization.volume_id.clone(),
        attachment_id: authorization.new_attachment_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
        lease_expires_at,
    };
    let mut updated = record.clone();
    updated.lease_owner = Some(authorization.new_attachment_id.clone());
    updated.lease_epoch = resulting_epoch;
    updated.lease_expires_at = Some(lease_expires_at);
    updated.last_transition = Some(LastVolumeTransition::Takeover {
        authorization_id: authorization.authorization_id.clone(),
    });
    let updated_authorization = AuthorizationRecord {
        authorization: authorization_record.authorization.clone(),
        state: AuthorizationState::Consumed(Box::new(AuthorizationConsumedReceipt::Takeover(
            receipt,
        ))),
    };
    Ok((updated, updated_authorization, result))
}

/// Reconstructs the immutable result of an already-consumed takeover.
///
/// A replay is owned by the authorization row, not by the volume's current
/// state: the volume may since have been released, reacquired, or removed.
/// The PostgreSQL transaction owner still locks the event and authorization
/// rows before calling this helper so an unconsumed authorization cannot race
/// an `Active -> Rejoined` transition.
pub fn replay_consumed_takeover(
    authorization_record: &AuthorizationRecord,
    authorization_id: &Id,
) -> Result<Option<TakeoverResult>> {
    validate_authorization_record(authorization_record)?;
    let VolumeAuthorization::Takeover(authorization) = &authorization_record.authorization else {
        return Err(AuthorityError::InvalidAuthorization);
    };
    if &authorization.authorization_id != authorization_id {
        return Err(AuthorityError::InvalidAuthorization);
    }
    let AuthorizationState::Consumed(receipt) = &authorization_record.state else {
        return Ok(None);
    };
    let AuthorizationConsumedReceipt::Takeover(receipt) = receipt.as_ref() else {
        return Err(AuthorityError::BackendUnknown);
    };
    takeover_result(authorization, receipt).map(Some)
}

pub fn begin_delete(
    record: &VolumeRecord,
    request: &BeginDeleteRequest,
) -> Result<(VolumeRecord, BeginDeleteResult)> {
    validate_volume_record(record)?;
    if let Some(LastVolumeTransition::BeginDelete {
        request: original,
        result,
    }) = record.last_transition.as_ref()
    {
        if original.delete_id == request.delete_id {
            return if original == request {
                Ok((record.clone(), result.clone()))
            } else {
                Err(AuthorityError::StaleTransition)
            };
        }
    }
    if record.volume_id != request.volume_id {
        return Err(AuthorityError::NotFound);
    }
    validate_request_head(&request.expected_head)?;
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.lease_owner.is_some() {
        return Err(AuthorityError::OtherWriter);
    }
    if record.lease_epoch != request.expected_unowned_epoch {
        return Err(AuthorityError::Fenced);
    }
    if record.head != request.expected_head {
        return Err(AuthorityError::HeadConflict);
    }
    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let result = BeginDeleteResult {
        delete_id: request.delete_id.clone(),
        disk_id: request.disk_id.clone(),
        volume_id: request.volume_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
    };
    let mut updated = record.clone();
    updated.admin_state = VolumeAdminState::Deleting {
        delete_id: request.delete_id.clone(),
    };
    updated.lease_epoch = resulting_epoch;
    updated.last_transition = Some(LastVolumeTransition::BeginDelete {
        request: request.clone(),
        result: result.clone(),
    });
    Ok((updated, result))
}

pub fn consume_disposable_root_delete(
    record: &VolumeRecord,
    host_fence_event: Option<&HostFenceEvent>,
    authorization_record: &AuthorizationRecord,
    authorization_id: &Id,
    db_now: UnixMillis,
) -> Result<(
    VolumeRecord,
    AuthorizationRecord,
    BeginDisposableDeleteConsumedReceipt,
)> {
    validate_volume_record(record)?;
    if let Some(event) = host_fence_event {
        validate_host_fence_event(event)?;
    }
    validate_authorization_record(authorization_record)?;
    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &authorization_record.authorization
    else {
        return Err(AuthorityError::InvalidAuthorization);
    };
    if &authorization.authorization_id != authorization_id
        || authorization.volume_id != record.volume_id
    {
        return Err(AuthorityError::InvalidAuthorization);
    }
    validate_disposable_event_basis(authorization, host_fence_event, false)?;

    if let AuthorizationState::Consumed(receipt) = &authorization_record.state {
        let AuthorizationConsumedReceipt::BeginDisposableDelete(receipt) = receipt.as_ref() else {
            return Err(AuthorityError::BackendUnknown);
        };
        if !disposable_direct_postcondition(record, authorization, receipt) {
            return Err(AuthorityError::BackendUnknown);
        }
        return Ok((
            record.clone(),
            authorization_record.clone(),
            receipt.clone(),
        ));
    }

    validate_disposable_event_basis(authorization, host_fence_event, true)?;
    if db_now > authorization.not_after
        || !matches!(record.admin_state, VolumeAdminState::Active)
        || record.lease_owner.as_ref() != Some(&authorization.expected_attachment_id)
        || record.lease_epoch != authorization.expected_epoch
        || record.head != authorization.expected_head
    {
        return Err(AuthorityError::InvalidAuthorization);
    }
    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let receipt = BeginDisposableDeleteConsumedReceipt {
        authorization_id: authorization.authorization_id.clone(),
        volume_id: authorization.volume_id.clone(),
        disk_id: authorization.disk_id.clone(),
        cat_id: authorization.cat_id.clone(),
        delete_id: authorization.delete_id.clone(),
        prior_attachment_id: authorization.expected_attachment_id.clone(),
        resulting_epoch,
        resulting_head: record.head.clone(),
        consumed_at: db_now,
    };
    let mut updated = record.clone();
    updated.admin_state = VolumeAdminState::Deleting {
        delete_id: authorization.delete_id.clone(),
    };
    updated.lease_owner = None;
    updated.lease_epoch = resulting_epoch;
    updated.lease_expires_at = None;
    updated.last_transition = Some(LastVolumeTransition::BeginDisposableDelete {
        authorization_id: authorization.authorization_id.clone(),
    });
    let updated_authorization = AuthorizationRecord {
        authorization: authorization_record.authorization.clone(),
        state: AuthorizationState::Consumed(Box::new(
            AuthorizationConsumedReceipt::BeginDisposableDelete(receipt.clone()),
        )),
    };
    Ok((updated, updated_authorization, receipt))
}

/// Builds the closed normal receipt after the transaction owner has proved the
/// object prefix empty and has locked the matching Control Disk row.
pub fn complete_normal_delete(
    record: &VolumeRecord,
    completed_at: UnixMillis,
) -> Result<DeleteCompletionReceipt> {
    validate_volume_record(record)?;
    let Some(LastVolumeTransition::BeginDelete { request, result }) =
        record.last_transition.as_ref()
    else {
        return Err(if matches!(record.admin_state, VolumeAdminState::Active) {
            AuthorityError::AdminBusy
        } else {
            AuthorityError::BackendUnknown
        });
    };
    let receipt = DeleteCompletionReceipt::Normal {
        request: request.clone(),
        deleting_epoch: result.resulting_epoch,
        deleting_head: result.resulting_head.clone(),
        completed_at,
    };
    validate_delete_completion_receipt(&receipt)?;
    Ok(receipt)
}

/// Builds the closed disposable receipt after the same external proofs as
/// [`complete_normal_delete`] and an exact consumed authorization row.
pub fn complete_disposable_root_delete(
    record: &VolumeRecord,
    authorization_record: &AuthorizationRecord,
    completed_at: UnixMillis,
) -> Result<DeleteCompletionReceipt> {
    validate_volume_record(record)?;
    validate_authorization_record(authorization_record)?;
    let (
        LastVolumeTransition::BeginDisposableDelete { authorization_id },
        VolumeAuthorization::DisposableRootDelete(authorization),
        AuthorizationState::Consumed(consumed),
    ) = (
        record
            .last_transition
            .as_ref()
            .ok_or(AuthorityError::BackendUnknown)?,
        &authorization_record.authorization,
        &authorization_record.state,
    )
    else {
        return Err(AuthorityError::BackendUnknown);
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref() else {
        return Err(AuthorityError::BackendUnknown);
    };
    if authorization_id != &authorization.authorization_id
        || !disposable_direct_postcondition(record, authorization, consumed)
    {
        return Err(AuthorityError::BackendUnknown);
    }
    let receipt = DeleteCompletionReceipt::DisposableRoot {
        disk_id: authorization.disk_id.clone(),
        volume_id: authorization.volume_id.clone(),
        delete_id: authorization.delete_id.clone(),
        authorization_id: authorization.authorization_id.clone(),
        prior_attachment_id: authorization.expected_attachment_id.clone(),
        deleting_epoch: consumed.resulting_epoch,
        deleting_head: consumed.resulting_head.clone(),
        completed_at,
    };
    validate_delete_completion_receipt(&receipt)?;
    Ok(receipt)
}

/// Replays the direct begin result after both rows were removed in the same
/// transaction that wrote a normal completion receipt.
pub fn replay_completed_normal_delete(
    request: &BeginDeleteRequest,
    receipt: &DeleteCompletionReceipt,
) -> Result<BeginDeleteResult> {
    validate_delete_completion_receipt(receipt)?;
    let DeleteCompletionReceipt::Normal {
        request: original,
        deleting_epoch,
        deleting_head,
        ..
    } = receipt
    else {
        return match receipt {
            DeleteCompletionReceipt::DisposableRoot { delete_id, .. }
                if delete_id == &request.delete_id =>
            {
                Err(AuthorityError::StaleTransition)
            }
            _ => Err(AuthorityError::NotFound),
        };
    };
    if original.delete_id != request.delete_id {
        return Err(AuthorityError::NotFound);
    }
    if original != request {
        return Err(AuthorityError::StaleTransition);
    }
    Ok(BeginDeleteResult {
        delete_id: request.delete_id.clone(),
        disk_id: request.disk_id.clone(),
        volume_id: request.volume_id.clone(),
        resulting_epoch: *deleting_epoch,
        resulting_head: deleting_head.clone(),
    })
}

fn validate_normal_acquire_pair(
    request: &NormalAcquireRequest,
    result: &NormalAcquireResult,
) -> Result<()> {
    let expires_minimum = request.lease_duration_ms;
    if !valid_duration(request.lease_duration_ms)
        || result.volume_id != request.volume_id
        || result.transition_id != request.transition_id
        || result.attachment_id != request.attachment_id
        || result.resulting_epoch != stored_next_epoch(request.expected_unowned_epoch)?
        || !remote_head_is_valid(&result.resulting_head)
        || result.lease_expires_at.get() < expires_minimum
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn validate_release_pair(request: &ReleaseRequest, result: &ReleaseResult) -> Result<()> {
    if result.volume_id != request.volume_id
        || result.transition_id != request.transition_id
        || result.released_attachment_id != request.attachment_id
        || result.resulting_epoch != stored_next_epoch(request.expected_epoch)?
        || !remote_head_is_valid(&result.resulting_head)
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn validate_begin_delete_pair(
    request: &BeginDeleteRequest,
    result: &BeginDeleteResult,
) -> Result<()> {
    validate_stored_head(&request.expected_head)?;
    if result.delete_id != request.delete_id
        || result.disk_id != request.disk_id
        || result.volume_id != request.volume_id
        || result.resulting_epoch != stored_next_epoch(request.expected_unowned_epoch)?
        || result.resulting_head != request.expected_head
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn validate_takeover_authorization(authorization: &VolumeTakeoverAuthorization) -> Result<()> {
    if authorization.new_attachment_id == authorization.expected_attachment_id {
        return Err(AuthorityError::InvalidAuthorization);
    }
    if !valid_duration(authorization.lease_duration_ms) {
        return Err(AuthorityError::InvalidLeaseDuration);
    }
    Ok(())
}

fn validate_takeover_receipt(
    authorization: &VolumeTakeoverAuthorization,
    receipt: &TakeoverConsumedReceipt,
) -> Result<()> {
    validate_takeover_authorization(authorization)?;
    if !valid_duration(authorization.lease_duration_ms)
        || receipt.authorization_id != authorization.authorization_id
        || receipt.host_fence_event_id != authorization.host_fence_event_id
        || receipt.volume_id != authorization.volume_id
        || receipt.new_attachment_id != authorization.new_attachment_id
        || receipt.resulting_epoch != stored_next_epoch(authorization.expected_epoch)?
        || !remote_head_is_valid(&receipt.resulting_head)
        || receipt.consumed_at > authorization.not_after
        || checked_expiry(receipt.consumed_at, authorization.lease_duration_ms).is_err()
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn validate_disposable_authorization(
    authorization: &DisposableRootDeleteAuthorization,
) -> Result<()> {
    validate_stored_head(&authorization.expected_head)
}

fn validate_disposable_receipt(
    authorization: &DisposableRootDeleteAuthorization,
    receipt: &BeginDisposableDeleteConsumedReceipt,
) -> Result<()> {
    validate_disposable_authorization(authorization)?;
    if receipt.authorization_id != authorization.authorization_id
        || receipt.volume_id != authorization.volume_id
        || receipt.disk_id != authorization.disk_id
        || receipt.cat_id != authorization.cat_id
        || receipt.delete_id != authorization.delete_id
        || receipt.prior_attachment_id != authorization.expected_attachment_id
        || receipt.resulting_epoch != stored_next_epoch(authorization.expected_epoch)?
        || receipt.resulting_head != authorization.expected_head
        || receipt.consumed_at > authorization.not_after
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

fn validate_disposable_event_basis(
    authorization: &DisposableRootDeleteAuthorization,
    event: Option<&HostFenceEvent>,
    require_active: bool,
) -> Result<()> {
    match (&authorization.isolation_basis, event) {
        (DisposableDeleteIsolationBasis::RuntimeStopped { .. }, None) => Ok(()),
        (DisposableDeleteIsolationBasis::HostFenceEvent { event_id }, Some(event))
            if event_id == &event.event_id
                && (!require_active || event.state == HostFenceEventState::Active) =>
        {
            Ok(())
        }
        _ => Err(AuthorityError::InvalidAuthorization),
    }
}

fn disposable_direct_postcondition(
    record: &VolumeRecord,
    authorization: &DisposableRootDeleteAuthorization,
    receipt: &BeginDisposableDeleteConsumedReceipt,
) -> bool {
    matches!(
        &record.admin_state,
        VolumeAdminState::Deleting { delete_id } if delete_id == &authorization.delete_id
    ) && record.lease_owner.is_none()
        && record.lease_expires_at.is_none()
        && record.lease_epoch == receipt.resulting_epoch
        && record.head == receipt.resulting_head
        && matches!(
            &record.last_transition,
            Some(LastVolumeTransition::BeginDisposableDelete { authorization_id })
                if authorization_id == &authorization.authorization_id
        )
}

fn takeover_result(
    authorization: &VolumeTakeoverAuthorization,
    receipt: &TakeoverConsumedReceipt,
) -> Result<TakeoverResult> {
    Ok(TakeoverResult {
        authorization_id: receipt.authorization_id.clone(),
        volume_id: receipt.volume_id.clone(),
        attachment_id: receipt.new_attachment_id.clone(),
        resulting_epoch: receipt.resulting_epoch,
        resulting_head: receipt.resulting_head.clone(),
        lease_expires_at: checked_expiry(receipt.consumed_at, authorization.lease_duration_ms)?,
    })
}

fn normal_transition_id(last: Option<&LastVolumeTransition>) -> Option<&RandomId128> {
    match last {
        Some(LastVolumeTransition::NormalAcquire { request, .. }) => Some(&request.transition_id),
        Some(LastVolumeTransition::Release { request, .. }) => Some(&request.transition_id),
        _ => None,
    }
}

fn validate_stored_head(head: &RemoteHead) -> Result<()> {
    if remote_head_is_valid(head) {
        Ok(())
    } else {
        Err(AuthorityError::BackendUnknown)
    }
}

fn validate_request_head(head: &RemoteHead) -> Result<()> {
    if remote_head_is_valid(head) {
        Ok(())
    } else {
        Err(AuthorityError::HeadConflict)
    }
}

fn valid_duration(duration_ms: u64) -> bool {
    (1..=MAX_INTEGER).contains(&duration_ms)
}

fn checked_expiry(db_now: UnixMillis, duration_ms: u64) -> Result<UnixMillis> {
    if !valid_duration(duration_ms) {
        return Err(AuthorityError::InvalidLeaseDuration);
    }
    let expires_at = db_now
        .get()
        .checked_add(duration_ms)
        .filter(|value| *value <= MAX_INTEGER)
        .and_then(UnixMillis::new)
        .ok_or(AuthorityError::InvalidLeaseDuration)?;
    Ok(expires_at)
}

fn next_epoch(epoch: FenceEpoch) -> Result<FenceEpoch> {
    epoch
        .get()
        .checked_add(1)
        .and_then(FenceEpoch::new)
        .ok_or(AuthorityError::EpochExhausted)
}

fn stored_next_epoch(epoch: FenceEpoch) -> Result<FenceEpoch> {
    next_epoch(epoch).map_err(|_| AuthorityError::BackendUnknown)
}
