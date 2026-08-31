//! Pure, provider-neutral volume authority transitions from ADR-0042.
//!
//! These functions perform no I/O. The PostgreSQL transaction owner is
//! responsible for locking and validating Control rows before applying the
//! returned replacement rows in the same transaction.

pub use cats_api::runtime_reconciliation::{
    AcquireOrigin, AsciiText, BeginDeleteRequest, BeginDeleteResult, Epoch, FenceEpoch, Generation,
    Id, LastVolumeTransition, NormalAcquireRequest, NormalAcquireResult, RandomId128,
    ReleaseRequest, ReleaseResult, RemoteHead, Revision, Sha256Digest, SnapshotRestoreRequest,
    SnapshotRestoreResult, UnixMillis, VolumeAdminState, VolumeDurability, VolumeRecord,
};
use serde::{Deserialize, Serialize};

const MAX_INTEGER: u64 = i64::MAX as u64;

/// Exact local attachment lineage written before any blockd data files.
///
/// This is evidence, never ownership authority. A serving process must bind it
/// to a current [`VolumeRecord`] and successfully renew the exact owner/epoch
/// before it may expose Guest I/O.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttachmentLineageIdentity {
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
    pub acquire_origin: AcquireOrigin,
    pub node_id: Id,
    pub placement_epoch: Epoch,
}

/// Node-supplied, closed input for adopting a normal-acquire grant as a
/// serving block data plane. It contains the current immutable Volume tuple
/// plus the exact server-side acquire marker that created the attachment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizedServingAttachment {
    pub identity: AttachmentLineageIdentity,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub head: RemoteHead,
    pub lease_expires_at: UnixMillis,
    /// Immutable independent acquire marker that created this attachment.
    /// A later same-owner renewal updates only the top-level expiry.
    pub acquire_request: NormalAcquireRequest,
    pub acquire_result: NormalAcquireResult,
    pub lease_duration_ms: u64,
}

impl AuthorizedServingAttachment {
    pub fn lease_duration_ms(&self) -> u64 {
        self.lease_duration_ms
    }

    pub fn expected_last_transition(&self) -> LastVolumeTransition {
        LastVolumeTransition::NormalAcquire {
            request: self.acquire_request.clone(),
            result: self.acquire_result.clone(),
        }
    }
}

/// Validate the internally closed serving input before any authority or local
/// I/O. The current head may be later than the acquire result because root
/// provisioning runs under the same owner/epoch before the serving process.
pub fn validate_authorized_serving_attachment(
    attachment: &AuthorizedServingAttachment,
) -> Result<()> {
    let identity = &attachment.identity;
    if !(1..=MAX_INTEGER).contains(&attachment.size_bytes)
        || !remote_head_is_valid(&attachment.head)
        || attachment.lease_expires_at.get() == 0
    {
        return Err(AuthorityError::BackendUnknown);
    }
    let AcquireOrigin::Normal { transition_id } = &identity.acquire_origin;
    let request = &attachment.acquire_request;
    let result = &attachment.acquire_result;
    validate_normal_acquire_pair(request, result)?;
    if attachment.lease_duration_ms == 0
        || attachment.lease_duration_ms != request.lease_duration_ms
        || request.volume_id != identity.volume_id
        || request.transition_id != *transition_id
        || request.attachment_id != identity.attachment_id
        || request.placement_epoch != identity.placement_epoch
        || result.volume_id != identity.volume_id
        || result.transition_id != *transition_id
        || result.attachment_id != identity.attachment_id
        || result.resulting_epoch != identity.attachment_epoch
        || attachment.lease_expires_at < result.lease_expires_at
        || !remote_head_is_same_or_later(&attachment.head, &result.resulting_head)
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

/// Construct the blockd carrier for the direct Control/Node protocol from
/// one independent NormalAcquire and a current same-owner authority reread.
///
/// The direct protocol does not manufacture a lifecycle Operation or Start
/// receipt. The caller must have committed the acquire (or discovered its
/// exact replay), and must pass the current head/expiry from the same locked
/// authority row. Blockd independently rereads and renews this owner before it
/// exposes Guest I/O.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectAcquireServingInput {
    pub node_id: Id,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub request: NormalAcquireRequest,
    pub result: NormalAcquireResult,
    pub current_head: RemoteHead,
    pub current_lease_expires_at: UnixMillis,
}

pub fn authorized_serving_attachment_from_direct_acquire(
    input: DirectAcquireServingInput,
) -> Result<AuthorizedServingAttachment> {
    let DirectAcquireServingInput {
        node_id,
        size_bytes,
        durability,
        request,
        result,
        current_head,
        current_lease_expires_at,
    } = input;
    validate_normal_acquire_pair(&request, &result)?;
    if current_lease_expires_at < result.lease_expires_at
        || !remote_head_is_same_or_later(&current_head, &result.resulting_head)
    {
        return Err(AuthorityError::BackendUnknown);
    }
    let attachment = AuthorizedServingAttachment {
        identity: AttachmentLineageIdentity {
            volume_id: request.volume_id.clone(),
            attachment_id: request.attachment_id.clone(),
            attachment_epoch: result.resulting_epoch,
            acquire_origin: AcquireOrigin::Normal {
                transition_id: request.transition_id.clone(),
            },
            node_id,
            placement_epoch: request.placement_epoch,
        },
        size_bytes,
        durability,
        head: current_head,
        lease_expires_at: current_lease_expires_at,
        acquire_request: request.clone(),
        acquire_result: result,
        lease_duration_ms: request.lease_duration_ms,
    };
    validate_authorized_serving_attachment(&attachment)?;
    Ok(attachment)
}

/// Prove that a strict authority reread is exactly the Node-supplied serving
/// attachment. When supplied, `expected_expiry` binds the second reread to the
/// mandatory startup renewal result. The initial read deliberately ignores the
/// old grant expiry so an exact retry remains valid after a lost renewal reply.
pub fn validate_authorized_serving_record(
    record: &VolumeRecord,
    attachment: &AuthorizedServingAttachment,
    expected_expiry: Option<UnixMillis>,
) -> Result<()> {
    validate_authorized_serving_attachment(attachment)?;
    validate_volume_record(record)?;
    // The exact owner under the exact epoch may have published past the
    // frozen attachment head, so a strictly newer generation is the expected
    // evolution of this same grant; only an equal-generation divergence or a
    // regression below the frozen head is unknown state.
    let head_is_current = if record.head.generation == attachment.head.generation {
        record.head == attachment.head
    } else {
        record.head.generation > attachment.head.generation
    };
    if record.volume_id != attachment.identity.volume_id
        || record.size_bytes != attachment.size_bytes
        || record.durability != attachment.durability
        || !matches!(record.admin_state, VolumeAdminState::Active)
        || !head_is_current
        || record.lease_owner.as_ref() != Some(&attachment.identity.attachment_id)
        || record.lease_epoch != attachment.identity.attachment_epoch
        || !record
            .lease_expires_at
            .is_some_and(|expiry| expiry >= attachment.lease_expires_at)
        || expected_expiry.is_some_and(|expiry| record.lease_expires_at != Some(expiry))
    {
        return Err(AuthorityError::BackendUnknown);
    }
    let marker_matches = record.last_transition == Some(attachment.expected_last_transition());
    if !marker_matches {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
}

/// Exact clean-slate authority schema release understood by the Volume
/// Authority writer and its data-plane adapter. Earlier versions are neither
/// migrated nor repaired by this release.
///
/// The Control Store remains the sole owner of its full schema stamp and DDL.
/// Sharing this release number lets the adapter reject an unstamped or
/// incompatible authority shape without importing the product store or
/// duplicating its schema.
pub const AUTHORITY_RELEASE_SCHEMA_VERSION: i64 = 20;

/// Canonical Node attribution for one currently-owned Volume.
///
/// This is deliberately separate from the block-data-plane `VolumeRecord`
/// wire contract. Control writes it in the same transaction as the owner and
/// epoch transition so Cat teardown and Node reset can release the exact
/// physical writer.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VolumeOwnerBinding {
    pub volume_id: Id,
    pub owner_node_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
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
    #[error("remote generation is exhausted")]
    GenerationExhausted,
    #[error("volume durability is not eligible for this transition")]
    InvalidDurability,
    #[error("volume administration is busy")]
    AdminBusy,
    #[error("remote head does not match")]
    HeadConflict,
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

/// Root identity created or discovered from one current Cat row.
/// These fields are internal storage coordinates; they are not part of the
/// user-facing Cat API and carry no caller-generated idempotency key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RootVolumeSpec {
    pub workspace_id: Id,
    pub cat_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub size_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PersistentInitialization {
    Uninitialized {
        initialization_token: RandomId128,
        expected_blank_head: RemoteHead,
    },
    Initialized {
        initialized_head: RemoteHead,
    },
}

/// Exact product/storage join used to attach one volume to a Cat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CatVolumeRole {
    Root {
        cat_id: Id,
    },
    Persistent {
        cat_id: Id,
        filesystem_uuid: RandomId128,
        mount_path: cats_api::runtime_reconciliation::HostPath,
        initialization: PersistentInitialization,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatVolume {
    pub workspace_id: Id,
    pub disk_id: Id,
    pub volume_id: Id,
    pub size_bytes: u64,
    pub durability: VolumeDurability,
    pub head: RemoteHead,
    pub role: CatVolumeRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeAttachRequest {
    pub node_id: Id,
    pub volume: CatVolume,
    pub lease_duration_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachedVolume {
    pub volume: CatVolume,
    pub serving: AuthorizedServingAttachment,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistentInitializationCommit {
    pub attached: AttachedVolume,
    pub initialized_head: RemoteHead,
    /// Canonical Guest filesystem-control response joined to this commit.
    pub guest_evidence: Vec<u8>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RootDeleteState {
    Absent,
    Deleting,
}

/// Provider-neutral storage transition port used by the Node
/// composition. Its identities are derived from the current Cat, volume and
/// authority row; no external request ID or lifecycle Operation enters this
/// boundary.
pub trait CatVolumeStore: Send + Sync {
    fn ensure_root_volume(&self, spec: &RootVolumeSpec) -> Result<CatVolume>;

    fn load_persistent_volume(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
        disk_id: &Id,
        volume_id: &Id,
        filesystem_uuid: &RandomId128,
        mount_path: &cats_api::runtime_reconciliation::HostPath,
    ) -> Result<CatVolume>;

    fn attach_volume(&self, request: &VolumeAttachRequest) -> Result<AttachedVolume>;

    fn detach_volume(&self, attached: &AttachedVolume) -> Result<()>;

    /// Release every volume still attributed to this Node after the caller
    /// has synchronously stopped all of its local VMM/blockd processes.
    fn detach_node_volumes(&self, node_id: &Id) -> Result<usize>;

    fn commit_persistent_initialization(
        &self,
        commit: &PersistentInitializationCommit,
    ) -> Result<CatVolume>;

    fn begin_root_delete(&self, volume: &CatVolume) -> Result<RootDeleteState>;

    fn complete_root_delete(&self, volume: &CatVolume) -> Result<()>;
}

pub fn validate_volume_owner_binding(
    binding: &VolumeOwnerBinding,
    volume: &VolumeRecord,
) -> Result<()> {
    validate_volume_record(volume)?;
    if binding.volume_id != volume.volume_id
        || volume.lease_owner.as_ref() != Some(&binding.attachment_id)
        || volume.lease_epoch != binding.attachment_epoch
        || volume.lease_expires_at.is_none()
        || !matches!(volume.admin_state, VolumeAdminState::Active)
    {
        return Err(AuthorityError::BackendUnknown);
    }
    Ok(())
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
    let (kind, transition_id, placement, duration) = match &record.last_transition {
        None => (None, None, None, None),
        Some(LastVolumeTransition::NormalAcquire { request, .. }) => (
            Some("normal_acquire"),
            Some(request.transition_id.to_string()),
            Some(request.placement_epoch),
            Some(request.lease_duration_ms),
        ),
        Some(LastVolumeTransition::Release { request, .. }) => (
            Some("release"),
            Some(request.transition_id.to_string()),
            None,
            None,
        ),
        Some(LastVolumeTransition::BeginDelete { request, .. }) => (
            Some("begin_delete"),
            Some(request.delete_id.to_string()),
            None,
            None,
        ),
        Some(LastVolumeTransition::SnapshotRestore { request, .. }) => (
            Some("snapshot_restore"),
            Some(request.snapshot_id.to_string()),
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
        LastVolumeTransition::NormalAcquire {
            request, result, ..
        } => {
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
        LastVolumeTransition::Release {
            request, result, ..
        } => {
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
        LastVolumeTransition::BeginDelete {
            request, result, ..
        } => {
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
        LastVolumeTransition::SnapshotRestore { request, result } => {
            validate_snapshot_restore_pair(request, result)?;
            if request.volume_id != record.volume_id
                || request.expected_size_bytes != record.size_bytes
                || record.durability != VolumeDurability::Strict
                || !matches!(record.admin_state, VolumeAdminState::Active)
                || record.lease_owner.is_some()
                || record.lease_expires_at.is_some()
                || record.lease_epoch != result.resulting_epoch
                || record.head != result.resulting_head
            {
                return Err(AuthorityError::BackendUnknown);
            }
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

/// Republish one captured snapshot root as a new current generation.
///
/// This is a direct storage-authority transition, not a lifecycle Operation.
/// Its exact predecessor head and unowned epoch identify one occurrence. An
/// ambiguous caller may replay the complete request while this marker remains
/// current; after any later transition, the old predecessor fails closed.
pub fn restore_snapshot(
    record: &VolumeRecord,
    request: &SnapshotRestoreRequest,
) -> Result<(VolumeRecord, SnapshotRestoreResult)> {
    validate_volume_record(record)?;
    if let Some(LastVolumeTransition::SnapshotRestore {
        request: original,
        result,
    }) = record.last_transition.as_ref()
    {
        if original == request {
            return Ok((record.clone(), result.clone()));
        }
    }
    if record.volume_id != request.volume_id {
        return Err(AuthorityError::NotFound);
    }
    validate_request_head(&request.expected_head)?;
    validate_request_head(&request.snapshot_head)?;
    if !matches!(record.admin_state, VolumeAdminState::Active) {
        return Err(AuthorityError::AdminBusy);
    }
    if record.durability != VolumeDurability::Strict {
        return Err(AuthorityError::InvalidDurability);
    }
    if record.lease_owner.is_some() {
        return Err(AuthorityError::OtherWriter);
    }
    if record.lease_epoch != request.expected_unowned_epoch {
        return Err(AuthorityError::Fenced);
    }
    if record.size_bytes != request.expected_size_bytes || record.head != request.expected_head {
        return Err(AuthorityError::HeadConflict);
    }

    let resulting_epoch = next_epoch(record.lease_epoch)?;
    let resulting_generation = next_generation(record.head.generation)?;
    let resulting_head = RemoteHead {
        generation: resulting_generation,
        root_hash: request.snapshot_head.root_hash.clone(),
        root_object_id: request.snapshot_head.root_object_id.clone(),
    };
    validate_request_head(&resulting_head)?;
    let result = SnapshotRestoreResult {
        snapshot_id: request.snapshot_id.clone(),
        disk_id: request.disk_id.clone(),
        volume_id: request.volume_id.clone(),
        resulting_epoch,
        resulting_head: resulting_head.clone(),
    };
    let mut updated = record.clone();
    updated.head = resulting_head;
    updated.lease_epoch = resulting_epoch;
    updated.last_transition = Some(LastVolumeTransition::SnapshotRestore {
        request: request.clone(),
        result: result.clone(),
    });
    validate_volume_record(&updated)?;
    Ok((updated, result))
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

fn validate_snapshot_restore_pair(
    request: &SnapshotRestoreRequest,
    result: &SnapshotRestoreResult,
) -> Result<()> {
    validate_stored_head(&request.expected_head)?;
    validate_stored_head(&request.snapshot_head)?;
    let resulting_generation = stored_next_generation(request.expected_head.generation)?;
    if !(1..=MAX_INTEGER).contains(&request.expected_size_bytes)
        || result.snapshot_id != request.snapshot_id
        || result.disk_id != request.disk_id
        || result.volume_id != request.volume_id
        || result.resulting_epoch != stored_next_epoch(request.expected_unowned_epoch)?
        || result.resulting_head.generation != resulting_generation
        || result.resulting_head.root_hash != request.snapshot_head.root_hash
        || result.resulting_head.root_object_id != request.snapshot_head.root_object_id
    {
        return Err(AuthorityError::BackendUnknown);
    }
    validate_stored_head(&result.resulting_head)
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

fn next_generation(generation: Generation) -> Result<Generation> {
    generation
        .get()
        .checked_add(1)
        .and_then(Generation::new)
        .ok_or(AuthorityError::GenerationExhausted)
}

fn stored_next_generation(generation: Generation) -> Result<Generation> {
    next_generation(generation).map_err(|_| AuthorityError::BackendUnknown)
}
