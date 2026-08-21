//! Command-scoped volume proofs for the atomic lifecycle interfaces.
//!
//! The Volume Authority transitions in [`crate::authority`] remain the only
//! owner/epoch/head authority.  This module adds the lifecycle-command binding
//! and the role-specific ordering rules which those single-volume transitions
//! deliberately do not know about.
//!
//! All helpers are pure.  A transaction owner must lock the complete ordered
//! Volume set, call one helper, and persist either every returned replacement
//! row or none of them.  In particular, the disposable Root transition is not
//! reachable until every Persistent volume has produced an exact normal
//! release receipt at `R == L`.

use std::collections::BTreeSet;

use cats_api::runtime_lifecycle::{DiskRole, PlacementIdentity};
use cats_api::runtime_lifecycle_volume::{
    lifecycle_persistent_initialization_original_blank_head,
    persistent_initialization_commit_receipt_digest,
    validate_lifecycle_persistent_initialization_binding,
    validate_lifecycle_persistent_initialization_commit, LifecycleCommandStartVolumeGrantReceipt,
    LifecyclePersistentInitializationBinding, LifecyclePersistentInitializationCommitReceipt,
    LifecyclePersistentInitializationCommitRequest, LifecyclePersistentInitializationInspection,
    LifecyclePersistentInitializationState, LifecycleServingAcquire,
    LifecycleStartVolumeGrantAuthority, LifecycleStoredPersistentInitializationCommit,
};
use cats_api::runtime_reconciliation::{
    AuthorizationConsumedReceipt, AuthorizationRecord, AuthorizationState,
    BeginDisposableDeleteConsumedReceipt, DeleteCompletionReceipt, FenceEpoch, Generation, Id,
    LastVolumeTransition, RandomId128, ReleaseRequest, ReleaseResult, RemoteHead, Sha256Digest,
    UnixMillis, VolumeAuthorization, VolumeRecord, VolumeTransitionSource, WireU64,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest as _, Sha256};

use crate::authority::{
    self, AuthorityError, HostFenceEvent, VolumeAdminState, VolumeOwnerBinding,
};

const COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-normal-release-receipt.v1";
const COMMAND_DISPOSABLE_AUTHORIZATION_CONSUMED_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-disposable-authorization-consumed-receipt.v1";
const COMMAND_DELETE_COMPLETION_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-delete-completion-receipt.v1";
const COMMAND_START_VOLUME_GRANT_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-start-volume-grant-receipt.v1";
const COMMAND_COLD_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-cold-already-unowned-receipt.v1";
const COMMAND_DELETE_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.command-delete-already-unowned-receipt.v1";
const PERSISTENT_DELETE_DISPOSITIONS_DIGEST_DOMAIN: &[u8] =
    b"cats.volume-authority.persistent-delete-dispositions.v1";

pub const LIFECYCLE_VOLUME_RECEIPT_MAX_CANONICAL_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LifecycleVolumeError {
    #[error(transparent)]
    Authority(#[from] AuthorityError),
    #[error("lifecycle operation or Cat identity does not match")]
    CommandScopeMismatch,
    #[error("volume set is incomplete, duplicated, reordered, or has the wrong disk role")]
    VolumeSetMismatch,
    #[error("volume durability proof is not an exact R == L convergence proof")]
    DurabilityNotConverged,
    #[error("default Root discard requires an exact R < L local-tail proof")]
    RootTailNotDisposable,
    #[error("stored lifecycle volume receipt is not internally closed")]
    ReceiptMismatch,
    #[error("PersistentDisk initialization binding or one-way lineage does not match")]
    PersistentInitializationMismatch,
    #[error("lifecycle volume receipt cannot be canonically encoded")]
    ReceiptEncodingFailed,
}

pub type Result<T> = std::result::Result<T, LifecycleVolumeError>;

/// Canonical bytes and the domain-separated digest which PostgreSQL persists
/// for one validated lifecycle Volume Authority receipt.
///
/// The bytes are the Cats Canonical JSON v1 encoding of the complete receipt;
/// the digest additionally prefixes the receipt-kind domain and one NUL byte.
/// Callers must never manufacture this pair from unvalidated wire input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CanonicalLifecycleVolumeReceipt {
    pub canonical_receipt_bytes: Vec<u8>,
    pub receipt_digest: Sha256Digest,
}

/// The PostgreSQL lifecycle Operation which owns one set of volume effects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeCommandScope {
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    pub cat_id: Id,
    pub node_id: Id,
    pub placement_identity: PlacementIdentity,
}

/// One exact command input slot. Slice order is significant and is retained
/// in every command-scoped receipt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeTarget {
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub volume_id: Id,
    pub attachment_id: Id,
    pub attachment_epoch: FenceEpoch,
}

/// Product/config identity shared by Owned and already-Unowned command slots.
///
/// An attachment is deliberately absent.  A command must not synthesize an
/// attachment merely to describe a pristine or previously released Volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LifecycleVolumeIdentity {
    pub disk_id: Id,
    pub disk_role: DiskRole,
    pub volume_id: Id,
}

impl LifecycleVolumeTarget {
    #[must_use]
    pub fn identity(&self) -> LifecycleVolumeIdentity {
        LifecycleVolumeIdentity {
            disk_id: self.disk_id.clone(),
            disk_role: self.disk_role,
            volume_id: self.volume_id.clone(),
        }
    }
}

/// Final blockd durability evidence sampled after Guest-facing I/O has been
/// closed. The complete remote head is retained so a generation number cannot
/// be paired with a different root tuple.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandVolumeDurabilityProof {
    pub scope: LifecycleVolumeCommandScope,
    pub volume: LifecycleVolumeTarget,
    pub remote_head: RemoteHead,
    pub local_durable_generation: Generation,
    pub remote_durable_generation: Generation,
    pub pending_pack_count: WireU64,
}

/// Input for the normal Volume Authority release owned by one lifecycle
/// command. The transition identifier remains the authority replay key; the
/// enclosing command scope prevents a receipt from being transplanted between
/// lifecycle Operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandNormalReleaseInput {
    pub durability: CommandVolumeDurabilityProof,
    pub transition_id: RandomId128,
}

/// Exact request/result pair plus the command-scoped `R == L` proof which
/// admitted the release. This whole value must be persisted: the legacy
/// Release request/result does not carry local `L`, remote `R` or pending-pack
/// count and therefore cannot prove durability convergence by itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandNormalReleaseReceipt {
    pub durability: CommandVolumeDurabilityProof,
    pub request: ReleaseRequest,
    pub result: ReleaseResult,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "authority_kind", rename_all = "snake_case", deny_unknown_fields)]
enum CanonicalPersistentDeleteDisposition {
    NormallyReleased {
        volume_id: Id,
        disk_id: Id,
        disk_role: &'static str,
        disposition: &'static str,
        normal_release_receipt_digest: Sha256Digest,
    },
    AlreadyUnowned {
        volume_id: Id,
        disk_id: Id,
        disk_role: &'static str,
        disposition: &'static str,
        already_unowned_receipt_digest: Sha256Digest,
    },
}

impl CanonicalPersistentDeleteDisposition {
    fn volume_id(&self) -> &Id {
        match self {
            Self::NormallyReleased { volume_id, .. } | Self::AlreadyUnowned { volume_id, .. } => {
                volume_id
            }
        }
    }
}

/// Canonical complete volume set for one Cold command. Slots retain the exact
/// runtime-config stable volume-id ordering; exactly one slot is Root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdCommandVolumeSet {
    pub scope: LifecycleVolumeCommandScope,
    pub volumes: Vec<LifecycleVolumeIdentity>,
}

/// The exact authority state accepted for one Cold/Delete command slot.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleVolumeDispositionInput {
    OwnedRelease {
        release: CommandNormalReleaseInput,
    },
    AlreadyUnowned {
        volume: LifecycleVolumeIdentity,
        expected_epoch: FenceEpoch,
        expected_head: RemoteHead,
        /// Loaded from PostgreSQL authority by the transaction owner. The
        /// Node wire supplies only the expected current Unowned tuple.
        provenance: AlreadyUnownedProvenance,
    },
}

/// A Cold result can carry this value directly. Settlement must still compare
/// it with the canonical command and the locked current Volume rows through
/// [`validate_cold_volume_release_receipts`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ColdVolumeReleaseReceipts {
    pub command: ColdCommandVolumeSet,
    pub dispositions: Vec<CommandVolumeDispositionReceipt>,
}

/// The sole destructive V1 Root disposition. The Root target remains separate
/// from Persistent targets so the role boundary cannot be inferred by index.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DefaultRootDiscardDisposition {
    pub root: LifecycleVolumeIdentity,
    pub delete_id: Id,
}

/// Canonical complete volume set for a Delete command.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteCommandVolumeSet {
    pub scope: LifecycleVolumeCommandScope,
    pub root_disposition: DefaultRootDiscardDisposition,
    pub persistent_volumes: Vec<LifecycleVolumeIdentity>,
}

/// Immutable provenance for a Volume which a command observed already
/// Unowned.  A prior release is accepted only with its exact command receipt
/// and independently recomputed digest; an opaque claimed digest is never
/// sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum AlreadyUnownedProvenance {
    Pristine,
    NormalRelease {
        receipt: Box<CommandNormalReleaseReceipt>,
        receipt_digest: Sha256Digest,
    },
}

/// Command-scoped immutable evidence that one exact slot was already Unowned
/// and therefore required no synthetic second release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandAlreadyUnownedReceipt {
    pub scope: LifecycleVolumeCommandScope,
    pub volume: LifecycleVolumeIdentity,
    pub expected_epoch: FenceEpoch,
    pub expected_head: RemoteHead,
    pub provenance: AlreadyUnownedProvenance,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandVolumeDispositionReceipt {
    NormallyReleased {
        receipt: Box<CommandNormalReleaseReceipt>,
    },
    AlreadyUnowned {
        receipt: Box<CommandAlreadyUnownedReceipt>,
    },
}

/// Interim storage-internal binding until the shared disposable authorization
/// carrier gains an Operation identifier. The embedded authorization remains
/// the only authority which can fence the owner epoch and enter `Deleting`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandBoundDisposableRootAuthorization {
    pub scope: LifecycleVolumeCommandScope,
    pub authorization: AuthorizationRecord,
}

/// Closed input to the all-or-nothing pure Delete begin helper.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteDisposableRootInput {
    pub command: DeleteCommandVolumeSet,
    pub persistent_volumes: Vec<LifecycleVolumeDispositionInput>,
    pub root_durability: CommandVolumeDurabilityProof,
    pub root_authorization: CommandBoundDisposableRootAuthorization,
}

/// Command-scoped evidence produced only after all Persistent releases have
/// validated and the existing disposable Root authorization has been consumed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteDisposableRootBeginReceipt {
    pub command: DeleteCommandVolumeSet,
    pub persistent_dispositions: Vec<CommandVolumeDispositionReceipt>,
    pub root_durability: CommandVolumeDurabilityProof,
    pub root_begin: CommandDisposableAuthorizationConsumedReceipt,
}

/// Exact immutable disposable-Root authorization-consumption receipt bound to
/// the lifecycle Delete command which was allowed to consume it.
///
/// The legacy Volume Authority receipt does not itself carry the atomic
/// lifecycle Operation identity. This closed wrapper supplies that binding;
/// its digest is therefore not reusable by another Operation even if every
/// legacy scalar happens to be identical.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDisposableAuthorizationConsumedReceipt {
    pub command: DeleteCommandVolumeSet,
    pub authorization_id: Id,
    pub persistent_dispositions_digest: Sha256Digest,
    pub receipt: BeginDisposableDeleteConsumedReceipt,
}

/// The exact prior Volume Authority receipt retained by a command-scoped
/// delete completion. Normal Root delete must retain the normal-release pair;
/// the old `DeleteCompletionReceipt::Normal` alone cannot reconstruct it after
/// the Volume row has been removed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "receipt",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum CommandRootDeleteAuthorityReceipt {
    NormalRelease(CommandNormalReleaseReceipt),
    AlreadyUnowned(CommandAlreadyUnownedReceipt),
    DisposableAuthorizationConsumed(CommandDisposableAuthorizationConsumedReceipt),
}

/// Closed command-scoped completion persisted when the Volume row is removed.
/// It is the reconstructable source for Delete settlement and response-loss
/// replay; persisting only the legacy `DeleteCompletionReceipt` is insufficient
/// for the normal Root branch because that DTO omits the prior release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommandDeleteCompletionReceipt {
    pub command: DeleteCommandVolumeSet,
    pub root_authority: CommandRootDeleteAuthorityReceipt,
    pub completion: DeleteCompletionReceipt,
}

/// Strictly decodes canonical receipt bytes without assigning them authority.
/// Callers must subsequently use an `encode_command_*` helper with exact
/// request/result/current-row inputs before accepting the stored digest.
pub fn decode_canonical_command_normal_release_receipt(
    bytes: &[u8],
) -> Result<CommandNormalReleaseReceipt> {
    decode_canonical_receipt(bytes)
}

/// See [`decode_canonical_command_normal_release_receipt`].
pub fn decode_canonical_command_disposable_authorization_consumed_receipt(
    bytes: &[u8],
) -> Result<CommandDisposableAuthorizationConsumedReceipt> {
    decode_canonical_receipt(bytes)
}

/// See [`decode_canonical_command_normal_release_receipt`].
pub fn decode_canonical_command_delete_completion_receipt(
    bytes: &[u8],
) -> Result<CommandDeleteCompletionReceipt> {
    decode_canonical_receipt(bytes)
}

/// Strictly decodes canonical Start-grant receipt bytes without assigning
/// them authority. Callers must subsequently validate the decoded value with
/// [`encode_command_start_volume_grant_receipt`] and the exact current Volume
/// row before accepting its stored digest.
pub fn decode_canonical_command_start_volume_grant_receipt(
    bytes: &[u8],
) -> Result<LifecycleCommandStartVolumeGrantReceipt> {
    decode_canonical_receipt(bytes)
}

/// Strictly decodes canonical already-Unowned receipt bytes without assigning
/// them authority. Callers must select the Cold/Delete domain and revalidate
/// against the exact current Volume row before accepting the stored digest.
pub fn decode_canonical_command_already_unowned_receipt(
    bytes: &[u8],
) -> Result<CommandAlreadyUnownedReceipt> {
    decode_canonical_receipt(bytes)
}

pub fn command_cold_already_unowned_receipt_digest(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_already_unowned_receipt(
        AlreadyUnownedReceiptUse::Cold,
        expected_scope,
        expected_volume,
        current_volume,
        receipt,
    )?
    .receipt_digest)
}

pub fn command_delete_already_unowned_receipt_digest(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_already_unowned_receipt(
        AlreadyUnownedReceiptUse::Delete,
        expected_scope,
        expected_volume,
        current_volume,
        receipt,
    )?
    .receipt_digest)
}

/// Recomputes a Cold already-Unowned digest from the complete immutable
/// receipt alone.
///
/// This is the Node response-verification path after Control has returned a
/// signed command response. It validates every self-contained scope, volume,
/// epoch, head and provenance field before hashing. A `Pristine` claim is not
/// authority by itself; only the Control transaction may establish that fact
/// from the locked current row and persist the receipt.
pub fn command_cold_already_unowned_receipt_digest_from_closed_receipt(
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<Sha256Digest> {
    command_already_unowned_receipt_digest_from_closed_receipt(
        AlreadyUnownedReceiptUse::Cold,
        receipt,
    )
}

/// Recomputes a Delete already-Unowned digest from the complete immutable
/// receipt alone. See
/// [`command_cold_already_unowned_receipt_digest_from_closed_receipt`] for the
/// trust boundary.
pub fn command_delete_already_unowned_receipt_digest_from_closed_receipt(
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<Sha256Digest> {
    command_already_unowned_receipt_digest_from_closed_receipt(
        AlreadyUnownedReceiptUse::Delete,
        receipt,
    )
}

pub fn encode_command_cold_already_unowned_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    encode_command_already_unowned_receipt(
        AlreadyUnownedReceiptUse::Cold,
        expected_scope,
        expected_volume,
        current_volume,
        receipt,
    )
}

pub fn encode_command_delete_already_unowned_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    encode_command_already_unowned_receipt(
        AlreadyUnownedReceiptUse::Delete,
        expected_scope,
        expected_volume,
        current_volume,
        receipt,
    )
}

/// Revalidates a Delete already-Unowned source after generic begin-delete has
/// replaced the live row's previous transition. This is the bounded replay /
/// sweeper adoption path; the immutable receipt itself is not reconstructed.
pub fn encode_command_delete_already_unowned_receipt_for_deleting_root(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_delete_command(expected_command)?;
    let root = &expected_command.root_disposition.root;
    validate_already_unowned_receipt_shape(&expected_command.scope, root, receipt)?;
    authority::validate_volume_record(current_deleting_root_volume)?;
    let Some(LastVolumeTransition::BeginDelete {
        source,
        request,
        result,
    }) = &current_deleting_root_volume.last_transition
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    if current_deleting_root_volume.volume_id != root.volume_id
        || current_deleting_root_volume.head != receipt.expected_head
        || current_deleting_root_volume.lease_epoch != result.resulting_epoch
        || current_deleting_root_volume.lease_owner.is_some()
        || current_deleting_root_volume.lease_expires_at.is_some()
        || !matches!(
            &current_deleting_root_volume.admin_state,
            VolumeAdminState::Deleting { delete_id }
                if delete_id == &expected_command.root_disposition.delete_id
        )
        || source != &lifecycle_transition_source(&expected_command.scope)
        || request.delete_id != expected_command.root_disposition.delete_id
        || request.disk_id != root.disk_id
        || request.volume_id != root.volume_id
        || request.expected_unowned_epoch != receipt.expected_epoch
        || request.expected_head != receipt.expected_head
        || result.delete_id != request.delete_id
        || result.disk_id != request.disk_id
        || result.volume_id != request.volume_id
        || result.resulting_head != request.expected_head
        || result.resulting_epoch != next_fence_epoch(request.expected_unowned_epoch)?
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    encode_canonical_receipt(
        COMMAND_DELETE_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN,
        receipt,
    )
}

/// Returns the domain-separated digest of one exact Start acquire or
/// same-owner renewal receipt.
///
/// Validation happens before hashing. In particular, the helper binds the
/// complete lifecycle Operation scope and runtime-volume config to the exact
/// current owner/epoch/head/expiry and to the current immutable acquire or
/// takeover lineage. A malformed or self-claimed Node receipt is never
/// hashable through this API.
pub fn command_start_volume_grant_receipt_digest(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_grant_sequence: WireU64,
    expected_volume: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    current_volume: &VolumeRecord,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_start_volume_grant_receipt(
        expected_scope,
        expected_grant_sequence,
        expected_volume,
        current_volume,
        receipt,
    )?
    .receipt_digest)
}

/// Validates and canonically encodes one immutable Start-grant receipt for
/// same-transaction PostgreSQL persistence with its authority mutation.
pub fn encode_command_start_volume_grant_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_grant_sequence: WireU64,
    expected_volume: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    current_volume: &VolumeRecord,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_command_scope(expected_scope)?;
    validate_start_volume_grant_receipt(
        expected_scope,
        expected_grant_sequence,
        expected_volume,
        current_volume,
        receipt,
        StartGrantCurrentBinding::Exact,
    )?;
    encode_canonical_receipt(COMMAND_START_VOLUME_GRANT_RECEIPT_DIGEST_DOMAIN, receipt)
}

/// Recomputes an immutable Start-grant digest against the current owner after
/// later same-attachment head publication or lease renewal. The receipt's
/// original request/result remains exact and immutable; only the current row
/// may be a provable monotonic successor of its recorded head/expiry.
pub fn command_start_volume_grant_receipt_digest_for_current_owner(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_grant_sequence: WireU64,
    expected_volume: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    current_volume: &VolumeRecord,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<Sha256Digest> {
    validate_command_scope(expected_scope)?;
    validate_start_volume_grant_receipt(
        expected_scope,
        expected_grant_sequence,
        expected_volume,
        current_volume,
        receipt,
        StartGrantCurrentBinding::SameOrLater,
    )?;
    Ok(
        encode_canonical_receipt(COMMAND_START_VOLUME_GRANT_RECEIPT_DIGEST_DOMAIN, receipt)?
            .receipt_digest,
    )
}

/// Recomputes a Start-grant digest from the complete immutable receipt alone.
///
/// This is the Node/data-plane verification path. It first derives the exact
/// authority row which the receipt claims to have committed and runs the same
/// strict validator used by the PostgreSQL writer. Only then are canonical
/// bytes hashed, so a malformed self-claimed receipt never becomes evidence.
pub fn command_start_volume_grant_receipt_digest_from_closed_receipt(
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<Sha256Digest> {
    let expected_scope = LifecycleVolumeCommandScope {
        operation_id: receipt.scope.operation_id.clone(),
        request_fingerprint: receipt.scope.request_fingerprint.clone(),
        cat_id: receipt.scope.cat_id.clone(),
        node_id: receipt.scope.node_id.clone(),
        placement_identity: receipt.scope.placement_identity.clone(),
    };
    let current = start_volume_grant_claimed_current_record(receipt)?;
    command_start_volume_grant_receipt_digest(
        &expected_scope,
        receipt.grant_sequence,
        &receipt.volume,
        &current,
        receipt,
    )
}

/// Validates the exact current Start writer and returns the closed product
/// initialization lineage. This is a read of the already locked authority
/// graph: it neither formats a device nor changes Volume/Disk state.
pub fn inspect_persistent_initialization(
    binding: &LifecyclePersistentInitializationBinding,
    current_volume: &VolumeRecord,
    current_owner: &VolumeOwnerBinding,
    initialization: &LifecyclePersistentInitializationState,
) -> Result<LifecyclePersistentInitializationInspection> {
    validate_persistent_initialization_authority(binding, current_volume, current_owner)?;
    let original_blank = lifecycle_persistent_initialization_original_blank_head(binding)
        .map_err(|_| LifecycleVolumeError::PersistentInitializationMismatch)?;
    match initialization {
        LifecyclePersistentInitializationState::Uninitialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
        } => {
            if initialization_token == filesystem_uuid
                || current_volume.head != *expected_blank_head
                || expected_blank_head.generation.get() != 0
                || !authority::remote_head_is_valid(expected_blank_head)
                || expected_blank_head != &original_blank
            {
                return Err(LifecycleVolumeError::PersistentInitializationMismatch);
            }
        }
        LifecyclePersistentInitializationState::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            ..
        } => {
            if initialization_token == filesystem_uuid
                || expected_blank_head.generation.get() != 0
                || !authority::remote_head_is_valid(expected_blank_head)
                || expected_blank_head != &original_blank
                || initialized_head.generation.get() == 0
                || !authority::remote_head_is_valid(initialized_head)
                || !authority::remote_head_is_same_or_later(&current_volume.head, initialized_head)
            {
                return Err(LifecycleVolumeError::PersistentInitializationMismatch);
            }
        }
    }
    let inspection = LifecyclePersistentInitializationInspection {
        binding: Box::new(binding.clone()),
        attachment_id: current_owner.attachment_id.clone(),
        attachment_epoch: current_owner.attachment_epoch,
        current_head: current_volume.head.clone(),
        initialization: initialization.clone(),
    };
    // Exercise the shared wire validator without manufacturing a transport
    // Session or relying on a Control-only projection.
    validate_lifecycle_persistent_initialization_binding(&inspection.binding)
        .map_err(|_| LifecycleVolumeError::PersistentInitializationMismatch)?;
    Ok(inspection)
}

/// Pure one-way PersistentDisk initialization transition.
///
/// The transaction owner supplies the already locked Volume, owner binding
/// and Disk initialization tuple. On the first call this returns the exact
/// `Initialized` replacement and receipt. A response-loss replay against the
/// same canonical request returns the exact stored receipt; any evidence
/// mutation is a conflict. A later head is accepted only while the same
/// owner/attachment/epoch and Start grant remain valid.
///
/// `current Start grant` means the latest immutable grant row for this Start,
/// not an unexpired wall-clock lease. This CAS closes already completed Guest
/// format plus `R == L` evidence and performs no new physical I/O. The Node
/// must renew before its subsequent mount/RuntimeReady mutation; replacing the
/// latest grant before this CAS instead makes the journaled request conflict.
pub fn commit_persistent_initialization(
    request: &LifecyclePersistentInitializationCommitRequest,
    current_volume: &VolumeRecord,
    current_owner: &VolumeOwnerBinding,
    initialization: &LifecyclePersistentInitializationState,
    prior_commit: Option<&LifecycleStoredPersistentInitializationCommit>,
    transaction_now: UnixMillis,
) -> Result<(
    LifecyclePersistentInitializationState,
    LifecycleStoredPersistentInitializationCommit,
)> {
    validate_lifecycle_persistent_initialization_commit(request)
        .map_err(|_| LifecycleVolumeError::PersistentInitializationMismatch)?;
    validate_persistent_initialization_authority(&request.binding, current_volume, current_owner)?;
    let original_blank = lifecycle_persistent_initialization_original_blank_head(&request.binding)
        .map_err(|_| LifecycleVolumeError::PersistentInitializationMismatch)?;
    match initialization {
        LifecyclePersistentInitializationState::Uninitialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
        } => {
            if initialization_token != &request.initialization_token
                || filesystem_uuid != &request.filesystem_uuid
                || expected_blank_head != &request.expected_blank_head
                || expected_blank_head != &original_blank
                || current_volume.head != request.initialized_head
                || prior_commit.is_some()
            {
                return Err(LifecycleVolumeError::PersistentInitializationMismatch);
            }
        }
        LifecyclePersistentInitializationState::Initialized {
            initialization_token,
            filesystem_uuid,
            expected_blank_head,
            initialized_head,
            initialized_at,
        } => {
            let stored =
                prior_commit.ok_or(LifecycleVolumeError::PersistentInitializationMismatch)?;
            if initialization_token != &request.initialization_token
                || filesystem_uuid != &request.filesystem_uuid
                || expected_blank_head != &request.expected_blank_head
                || expected_blank_head != &original_blank
                || initialized_head != &request.initialized_head
                || !authority::remote_head_is_same_or_later(&current_volume.head, initialized_head)
                || stored.receipt.request.as_ref() != request
                || stored.receipt.initialized_at != *initialized_at
                || persistent_initialization_commit_receipt_digest(&stored.receipt)
                    .map_err(|_| LifecycleVolumeError::ReceiptEncodingFailed)?
                    != stored.receipt_digest
            {
                return Err(LifecycleVolumeError::PersistentInitializationMismatch);
            }
            return Ok((initialization.clone(), stored.clone()));
        }
    }
    let initialized_at = transaction_now;
    let replacement = LifecyclePersistentInitializationState::Initialized {
        initialization_token: request.initialization_token.clone(),
        filesystem_uuid: request.filesystem_uuid.clone(),
        expected_blank_head: request.expected_blank_head.clone(),
        initialized_head: request.initialized_head.clone(),
        initialized_at,
    };
    let receipt = LifecyclePersistentInitializationCommitReceipt {
        request: Box::new(request.clone()),
        initialized_at,
    };
    let receipt_digest = persistent_initialization_commit_receipt_digest(&receipt)
        .map_err(|_| LifecycleVolumeError::ReceiptEncodingFailed)?;
    Ok((
        replacement,
        LifecycleStoredPersistentInitializationCommit {
            receipt,
            receipt_digest,
        },
    ))
}

fn validate_persistent_initialization_authority(
    binding: &LifecyclePersistentInitializationBinding,
    current_volume: &VolumeRecord,
    current_owner: &VolumeOwnerBinding,
) -> Result<()> {
    validate_lifecycle_persistent_initialization_binding(binding)
        .map_err(|_| LifecycleVolumeError::PersistentInitializationMismatch)?;
    authority::validate_volume_record(current_volume)?;
    let scope = LifecycleVolumeCommandScope {
        operation_id: binding.scope.operation_id.clone(),
        request_fingerprint: binding.scope.request_fingerprint.clone(),
        cat_id: binding.scope.cat_id.clone(),
        node_id: binding.scope.node_id.clone(),
        placement_identity: binding.scope.placement_identity.clone(),
    };
    let recomputed = command_start_volume_grant_receipt_digest_for_current_owner(
        &scope,
        binding.start_grant.receipt.grant_sequence,
        &binding.volume,
        current_volume,
        &binding.start_grant.receipt,
    )?;
    if recomputed != binding.start_grant.receipt_digest
        || current_owner.volume_id != binding.volume.volume_id
        || current_owner.owner_node_id != binding.scope.node_id
        || current_owner.attachment_id
            != current_volume
                .lease_owner
                .clone()
                .ok_or(LifecycleVolumeError::PersistentInitializationMismatch)?
        || current_owner.attachment_epoch != current_volume.lease_epoch
    {
        return Err(LifecycleVolumeError::PersistentInitializationMismatch);
    }
    Ok(())
}

/// Replacement rows returned by [`begin_delete_disposable_root`]. No caller
/// receives this value when any Persistent volume is not exactly converged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeleteDisposableRootBeginOutcome {
    pub persistent_volumes: Vec<VolumeRecord>,
    pub root_volume: VolumeRecord,
    pub root_authorization: CommandBoundDisposableRootAuthorization,
    pub receipt: DeleteDisposableRootBeginReceipt,
}

/// Terminal Volume Authority evidence for the disposable Root branch. The
/// lifecycle Delete command must wait for this completion receipt; a Deleting
/// row or a background-sweeper enqueue is not terminal lifecycle success.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeleteDisposableRootCompletionReceipt {
    pub begin: DeleteDisposableRootBeginReceipt,
    pub consumed_authorization: CommandBoundDisposableRootAuthorization,
    pub completion: DeleteCompletionReceipt,
}

/// Returns the canonical digest of one exact, normally released Volume
/// Authority receipt.
///
/// Validation happens before hashing and includes the canonical lifecycle
/// command scope, the exact volume slot, the request/result pair and the
/// currently locked released Volume row. A caller cannot turn arbitrary bytes
/// into an apparently authoritative receipt digest.
pub fn command_normal_release_receipt_digest(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeTarget,
    current_released_volume: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_normal_release_receipt(
        expected_scope,
        expected_volume,
        current_released_volume,
        receipt,
    )?
    .receipt_digest)
}

/// Recomputes a normal-release digest from the complete immutable receipt
/// alone.
///
/// The helper validates the exact command scope, target, request/result pair
/// and full `R == L`, zero-pending durability proof before hashing. It is for
/// verifying a receipt already authenticated by the signed Control response
/// or immutable ledger; the transaction writer must still use
/// [`command_normal_release_receipt_digest`] against the locked current row.
pub fn command_normal_release_receipt_digest_from_closed_receipt(
    receipt: &CommandNormalReleaseReceipt,
) -> Result<Sha256Digest> {
    validate_normal_release_receipt_shape(
        &receipt.durability.scope,
        &receipt.durability.volume,
        receipt,
    )?;
    digest_canonical(COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN, receipt)
}

/// Validates and canonically encodes a normal-release receipt for immutable
/// PostgreSQL persistence in the same transaction as the release transition.
pub fn encode_command_normal_release_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeTarget,
    current_released_volume: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_command_scope(expected_scope)?;
    validate_normal_release_receipt(
        expected_scope,
        expected_volume,
        current_released_volume,
        receipt,
    )?;
    encode_canonical_receipt(COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN, receipt)
}

/// Computes the canonical digest which closes every retained PersistentDisk
/// disposition before a disposable Root authorization can exist.
///
/// The caller supplies the exact current released rows and immutable normal
/// release receipts, not Node-claimed digests. Every receipt is fully
/// revalidated against its command scope, target, durability proof and current
/// authority row before the bytewise-volume-id-sorted projection is hashed.
pub fn persistent_delete_dispositions_digest(
    expected_command: &DeleteCommandVolumeSet,
    current_volumes: &[VolumeRecord],
    receipts: &[CommandVolumeDispositionReceipt],
) -> Result<Sha256Digest> {
    validate_delete_command(expected_command)?;
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &expected_command.scope,
        &expected_command.persistent_volumes,
        current_volumes,
        receipts,
    )?;
    let mut dispositions = expected_command
        .persistent_volumes
        .iter()
        .zip(current_volumes)
        .zip(receipts)
        .map(|((target, current), receipt)| match receipt {
            CommandVolumeDispositionReceipt::NormallyReleased { receipt } => {
                if receipt.durability.volume.identity() != *target {
                    return Err(LifecycleVolumeError::VolumeSetMismatch);
                }
                Ok(CanonicalPersistentDeleteDisposition::NormallyReleased {
                    volume_id: target.volume_id.clone(),
                    disk_id: target.disk_id.clone(),
                    disk_role: "persistent_ext4",
                    disposition: "retain_detached",
                    normal_release_receipt_digest: command_normal_release_receipt_digest(
                        &expected_command.scope,
                        &receipt.durability.volume,
                        current,
                        receipt,
                    )?,
                })
            }
            CommandVolumeDispositionReceipt::AlreadyUnowned { receipt } => {
                Ok(CanonicalPersistentDeleteDisposition::AlreadyUnowned {
                    volume_id: target.volume_id.clone(),
                    disk_id: target.disk_id.clone(),
                    disk_role: "persistent_ext4",
                    disposition: "retain_detached",
                    already_unowned_receipt_digest: command_delete_already_unowned_receipt_digest(
                        &expected_command.scope,
                        target,
                        current,
                        receipt,
                    )?,
                })
            }
        })
        .collect::<Result<Vec<_>>>()?;
    dispositions.sort_by(|left, right| left.volume_id().as_str().cmp(right.volume_id().as_str()));
    digest_canonical(PERSISTENT_DELETE_DISPOSITIONS_DIGEST_DOMAIN, &dispositions)
}

/// Revalidates a normally released Root after the generic begin-delete CAS
/// has replaced `LastVolumeTransition::Release` with its exact successor.
/// This is the only pre-completion adoption path used by the Delete sweeper.
pub fn command_normal_release_receipt_digest_for_deleting_root(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_normal_release_receipt_for_deleting_root(
        expected_command,
        current_deleting_root_volume,
        receipt,
    )?
    .receipt_digest)
}

/// Revalidates and canonically encodes the persisted normal-release source
/// while its exact generic begin-delete successor is current.
pub fn encode_command_normal_release_receipt_for_deleting_root(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_delete_command(expected_command)?;
    let root = &expected_command.root_disposition.root;
    if receipt.durability.volume.identity() != *root {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_normal_release_receipt_shape(
        &expected_command.scope,
        &receipt.durability.volume,
        receipt,
    )?;
    authority::validate_volume_record(current_deleting_root_volume)?;
    let Some(LastVolumeTransition::BeginDelete {
        source,
        request,
        result,
    }) = &current_deleting_root_volume.last_transition
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    if current_deleting_root_volume.volume_id != root.volume_id
        || current_deleting_root_volume.head != receipt.result.resulting_head
        || current_deleting_root_volume.lease_epoch != result.resulting_epoch
        || current_deleting_root_volume.lease_owner.is_some()
        || current_deleting_root_volume.lease_expires_at.is_some()
        || !matches!(
            &current_deleting_root_volume.admin_state,
            VolumeAdminState::Deleting { delete_id }
                if delete_id == &expected_command.root_disposition.delete_id
        )
        || source != &lifecycle_transition_source(&expected_command.scope)
        || request.delete_id != expected_command.root_disposition.delete_id
        || request.disk_id != root.disk_id
        || request.volume_id != root.volume_id
        || request.expected_unowned_epoch != receipt.result.resulting_epoch
        || request.expected_head != receipt.result.resulting_head
        || result.delete_id != request.delete_id
        || result.disk_id != request.disk_id
        || result.volume_id != request.volume_id
        || result.resulting_head != request.expected_head
        || result.resulting_epoch != next_fence_epoch(request.expected_unowned_epoch)?
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    encode_canonical_receipt(COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN, receipt)
}

/// Returns the canonical digest of the exact disposable-Root authorization
/// consumption receipt after validating the Delete command, consumed parent
/// authorization and currently locked Deleting Volume row.
pub fn command_disposable_authorization_consumed_receipt_digest(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: &VolumeRecord,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &CommandDisposableAuthorizationConsumedReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_disposable_authorization_consumed_receipt(
        expected_command,
        current_deleting_root_volume,
        consumed_authorization,
        receipt,
    )?
    .receipt_digest)
}

/// Validates and canonically encodes a disposable authorization-consumption
/// receipt for immutable PostgreSQL persistence in the same transaction as
/// the authorization consume and `Owned -> Deleting` transition.
pub fn encode_command_disposable_authorization_consumed_receipt(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: &VolumeRecord,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &CommandDisposableAuthorizationConsumedReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_command_disposable_authorization_consumed_receipt(
        expected_command,
        Some(current_deleting_root_volume),
        consumed_authorization,
        receipt,
    )?;
    encode_canonical_receipt(
        COMMAND_DISPOSABLE_AUTHORIZATION_CONSUMED_RECEIPT_DIGEST_DOMAIN,
        receipt,
    )
}

/// Returns the digest of a closed Delete completion after validating that the
/// current Volume row is absent and the full immutable predecessor receipt is
/// retained in the command-scoped completion.
///
/// `consumed_authorization` is required only for the disposable-Root variant.
/// The normal variant carries the prior normal-release request/result pair so
/// Control can recompute both digests after the Volume row has been deleted.
pub fn command_delete_completion_receipt_digest(
    expected_command: &DeleteCommandVolumeSet,
    current_root_volume: Option<&VolumeRecord>,
    consumed_authorization: Option<&CommandBoundDisposableRootAuthorization>,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<Sha256Digest> {
    Ok(encode_command_delete_completion_receipt(
        expected_command,
        current_root_volume,
        consumed_authorization,
        receipt,
    )?
    .receipt_digest)
}

/// Validates and canonically encodes a Delete completion for immutable
/// PostgreSQL persistence. `current_root_volume` must be `None`, so the writer
/// calls this after deleting the Volume row but before committing the same
/// transaction as the generic completion receipt.
pub fn encode_command_delete_completion_receipt(
    expected_command: &DeleteCommandVolumeSet,
    current_root_volume: Option<&VolumeRecord>,
    consumed_authorization: Option<&CommandBoundDisposableRootAuthorization>,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_command_delete_completion_receipt(
        expected_command,
        current_root_volume,
        consumed_authorization,
        receipt,
    )?;
    encode_canonical_receipt(COMMAND_DELETE_COMPLETION_RECEIPT_DIGEST_DOMAIN, receipt)
}

/// Recomputes the nested normal-release authority digest after the Volume row
/// has been removed, using the exact generic completion chain retained in the
/// command completion receipt.
pub fn command_normal_release_receipt_digest_from_delete_completion(
    expected_command: &DeleteCommandVolumeSet,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<Sha256Digest> {
    validate_command_delete_completion_receipt(expected_command, None, None, receipt)?;
    let CommandRootDeleteAuthorityReceipt::NormalRelease(release) = &receipt.root_authority else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    digest_canonical(COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN, release)
}

/// Recomputes the nested disposable authorization-consumption digest after
/// the Volume row has been removed, using the retained parent authorization
/// and exact generic completion chain.
pub fn command_disposable_authorization_consumed_receipt_digest_from_delete_completion(
    expected_command: &DeleteCommandVolumeSet,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<Sha256Digest> {
    validate_command_delete_completion_receipt(
        expected_command,
        None,
        Some(consumed_authorization),
        receipt,
    )?;
    let CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(consumed) =
        &receipt.root_authority
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    digest_canonical(
        COMMAND_DISPOSABLE_AUTHORIZATION_CONSUMED_RECEIPT_DIGEST_DOMAIN,
        consumed,
    )
}

/// Recomputes the nested Delete already-Unowned authority digest after the
/// live Volume row has been removed. The completion wrapper must retain the
/// exact immutable receipt previously validated and written with begin-delete.
pub fn command_delete_already_unowned_receipt_digest_from_delete_completion(
    expected_command: &DeleteCommandVolumeSet,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<Sha256Digest> {
    validate_command_delete_completion_receipt(expected_command, None, None, receipt)?;
    let CommandRootDeleteAuthorityReceipt::AlreadyUnowned(already_unowned) =
        &receipt.root_authority
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    digest_canonical(
        COMMAND_DELETE_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN,
        already_unowned,
    )
}

/// Applies exact normal release to the complete Cold volume set.
///
/// The function validates every proof before returning any replacement. It is
/// replay-safe because the underlying authority transition accepts only the
/// exact original request/result marker.
pub fn release_cold_volume_set(
    command: &ColdCommandVolumeSet,
    current_volumes: &[VolumeRecord],
    inputs: &[LifecycleVolumeDispositionInput],
) -> Result<(Vec<VolumeRecord>, ColdVolumeReleaseReceipts)> {
    validate_cold_command(command)?;
    let (volumes, dispositions) = apply_mixed_volume_set(
        AlreadyUnownedReceiptUse::Cold,
        &command.scope,
        &command.volumes,
        current_volumes,
        inputs,
    )?;
    let receipts = ColdVolumeReleaseReceipts {
        command: command.clone(),
        dispositions,
    };
    validate_cold_volume_release_receipts(command, &volumes, &receipts)?;
    Ok((volumes, receipts))
}

/// Applies exact normal release to the complete Delete volume set when the
/// default Root is also remotely converged. Root is first, followed by the
/// command's frozen Persistent ordering. The returned Root may immediately be
/// advanced through generic begin-delete by the same PostgreSQL transaction,
/// while this exact release receipt remains in the immutable command ledger.
pub fn release_delete_normal_volume_set(
    command: &DeleteCommandVolumeSet,
    current_volumes: &[VolumeRecord],
    inputs: &[LifecycleVolumeDispositionInput],
) -> Result<(Vec<VolumeRecord>, Vec<CommandVolumeDispositionReceipt>)> {
    validate_delete_command(command)?;
    let mut targets = Vec::with_capacity(1 + command.persistent_volumes.len());
    targets.push(command.root_disposition.root.clone());
    targets.extend(command.persistent_volumes.iter().cloned());
    let (volumes, receipts) = apply_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &command.scope,
        &targets,
        current_volumes,
        inputs,
    )?;
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &command.scope,
        &targets,
        &volumes,
        &receipts,
    )?;
    Ok((volumes, receipts))
}

/// Validates and normally releases the complete Persistent subset of a Delete
/// before any disposable Root authorization is derived or consumed.
pub fn release_delete_persistent_volume_set(
    command: &DeleteCommandVolumeSet,
    current_volumes: &[VolumeRecord],
    inputs: &[LifecycleVolumeDispositionInput],
) -> Result<(Vec<VolumeRecord>, Vec<CommandVolumeDispositionReceipt>)> {
    validate_delete_command(command)?;
    let (volumes, receipts) = apply_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &command.scope,
        &command.persistent_volumes,
        current_volumes,
        inputs,
    )?;
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &command.scope,
        &command.persistent_volumes,
        &volumes,
        &receipts,
    )?;
    Ok((volumes, receipts))
}

/// Validates a Cold receipt against the canonical command and the exact
/// currently locked, normally released Volume rows.
pub fn validate_cold_volume_release_receipts(
    expected_command: &ColdCommandVolumeSet,
    released_volumes: &[VolumeRecord],
    receipts: &ColdVolumeReleaseReceipts,
) -> Result<()> {
    validate_cold_command(expected_command)?;
    if receipts.command.scope != expected_command.scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipts.command.volumes != expected_command.volumes {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Cold,
        &expected_command.scope,
        &expected_command.volumes,
        released_volumes,
        &receipts.dispositions,
    )
}

/// Releases every Persistent volume at `R == L`, then and only then consumes
/// the existing disposable Root authorization for an `R < L` default Root.
///
/// This is one pure multi-row transition. A transaction owner persists all
/// returned rows atomically. If a Persistent proof or release fails, this
/// function never invokes the Root transition and returns no Root replacement.
pub fn begin_delete_disposable_root(
    current_persistent_volumes: &[VolumeRecord],
    current_root_volume: &VolumeRecord,
    host_fence_event: Option<&HostFenceEvent>,
    input: &DeleteDisposableRootInput,
    db_now: UnixMillis,
) -> Result<DeleteDisposableRootBeginOutcome> {
    validate_delete_command(&input.command)?;
    if input.root_durability.scope != input.command.scope
        || input.root_authorization.scope != input.command.scope
    {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if input.root_durability.volume.identity() != input.command.root_disposition.root {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }

    // This complete set transition is intentionally first. Nothing below can
    // construct or consume Root authority until every Persistent is proven.
    let (persistent_volumes, persistent_dispositions) = release_delete_persistent_volume_set(
        &input.command,
        current_persistent_volumes,
        &input.persistent_volumes,
    )?;
    let persistent_dispositions_digest = persistent_delete_dispositions_digest(
        &input.command,
        &persistent_volumes,
        &persistent_dispositions,
    )?;

    validate_disposable_root_proof(current_root_volume, &input.root_durability)?;
    validate_command_bound_root_authorization(
        &input.command,
        &input.root_durability.remote_head,
        &persistent_dispositions_digest,
        &input.root_authorization,
    )?;

    let authorization_id = match &input.root_authorization.authorization.authorization {
        VolumeAuthorization::DisposableRootDelete(authorization) => {
            authorization.authorization_id.clone()
        }
        VolumeAuthorization::Takeover(_) => {
            return Err(LifecycleVolumeError::Authority(
                AuthorityError::InvalidAuthorization,
            ));
        }
    };
    let (root_volume, authorization, authority_root_begin) =
        authority::consume_disposable_root_delete_with_source(
            current_root_volume,
            host_fence_event,
            &input.root_authorization.authorization,
            &authorization_id,
            &lifecycle_transition_source(&input.command.scope),
            db_now,
        )?;
    let root_authorization = CommandBoundDisposableRootAuthorization {
        scope: input.command.scope.clone(),
        authorization,
    };
    let root_begin = CommandDisposableAuthorizationConsumedReceipt {
        command: input.command.clone(),
        authorization_id,
        persistent_dispositions_digest,
        receipt: authority_root_begin,
    };
    let receipt = DeleteDisposableRootBeginReceipt {
        command: input.command.clone(),
        persistent_dispositions,
        root_durability: input.root_durability.clone(),
        root_begin,
    };
    validate_delete_disposable_root_begin(
        &input.command,
        &persistent_volumes,
        &root_volume,
        &root_authorization,
        &receipt,
    )?;
    Ok(DeleteDisposableRootBeginOutcome {
        persistent_volumes,
        root_volume,
        root_authorization,
        receipt,
    })
}

/// Produces the terminal command-scoped receipt only after the object-deletion
/// worker has established the external proofs required by
/// [`authority::complete_disposable_root_delete`].
pub fn complete_delete_disposable_root(
    expected_command: &DeleteCommandVolumeSet,
    current_persistent_volumes: &[VolumeRecord],
    deleting_root_volume: &VolumeRecord,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    begin: &DeleteDisposableRootBeginReceipt,
    completed_at: UnixMillis,
) -> Result<DeleteDisposableRootCompletionReceipt> {
    validate_delete_disposable_root_begin(
        expected_command,
        current_persistent_volumes,
        deleting_root_volume,
        consumed_authorization,
        begin,
    )?;
    let completion = authority::complete_disposable_root_delete(
        deleting_root_volume,
        &consumed_authorization.authorization,
        completed_at,
    )?;
    let receipt = DeleteDisposableRootCompletionReceipt {
        begin: begin.clone(),
        consumed_authorization: consumed_authorization.clone(),
        completion,
    };
    validate_delete_disposable_root_completion(
        expected_command,
        current_persistent_volumes,
        &receipt,
    )?;
    Ok(receipt)
}

/// Validates the terminal disposable-Root receipt after the Root Volume and
/// authorization rows may already have been removed. Persistent rows remain
/// retained and must still match their exact normal-release receipts.
pub fn validate_delete_disposable_root_completion(
    expected_command: &DeleteCommandVolumeSet,
    current_persistent_volumes: &[VolumeRecord],
    receipt: &DeleteDisposableRootCompletionReceipt,
) -> Result<()> {
    validate_delete_command(expected_command)?;
    if receipt.begin.command.scope != expected_command.scope
        || receipt.consumed_authorization.scope != expected_command.scope
    {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.begin.command != *expected_command {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &expected_command.scope,
        &expected_command.persistent_volumes,
        current_persistent_volumes,
        &receipt.begin.persistent_dispositions,
    )?;
    validate_command_bound_root_authorization(
        expected_command,
        &receipt.begin.root_durability.remote_head,
        &persistent_delete_dispositions_digest(
            expected_command,
            current_persistent_volumes,
            &receipt.begin.persistent_dispositions,
        )?,
        &receipt.consumed_authorization,
    )?;
    validate_disposable_root_proof_shape(&receipt.begin.root_durability)?;
    authority::validate_authorization_record(&receipt.consumed_authorization.authorization)?;

    let AuthorizationState::Consumed(consumed) =
        &receipt.consumed_authorization.authorization.state
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref() else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    if consumed != &receipt.begin.root_begin.receipt {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    authority::validate_delete_completion_receipt(&receipt.completion)?;
    validate_disposable_completion_pair(&receipt.begin.root_begin.receipt, &receipt.completion)
}

#[derive(Clone, Copy)]
enum AlreadyUnownedReceiptUse {
    Cold,
    Delete,
}

impl AlreadyUnownedReceiptUse {
    const fn digest_domain(self) -> &'static [u8] {
        match self {
            Self::Cold => COMMAND_COLD_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN,
            Self::Delete => COMMAND_DELETE_ALREADY_UNOWNED_RECEIPT_DIGEST_DOMAIN,
        }
    }
}

fn command_already_unowned_receipt_digest_from_closed_receipt(
    receipt_use: AlreadyUnownedReceiptUse,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<Sha256Digest> {
    validate_already_unowned_receipt_shape(&receipt.scope, &receipt.volume, receipt)?;
    digest_canonical(receipt_use.digest_domain(), receipt)
}

fn encode_command_already_unowned_receipt(
    receipt_use: AlreadyUnownedReceiptUse,
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current_volume: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    validate_already_unowned_receipt(expected_scope, expected_volume, current_volume, receipt)?;
    encode_canonical_receipt(receipt_use.digest_domain(), receipt)
}

fn validate_already_unowned_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    current: &VolumeRecord,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<()> {
    validate_command_scope(expected_scope)?;
    authority::validate_volume_record(current)?;
    if receipt.scope != *expected_scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.volume != *expected_volume
        || current.volume_id != expected_volume.volume_id
        || current.lease_epoch != receipt.expected_epoch
        || current.head != receipt.expected_head
        || current.lease_owner.is_some()
        || current.lease_expires_at.is_some()
        || !matches!(current.admin_state, VolumeAdminState::Active)
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    match (&receipt.provenance, &current.last_transition) {
        (AlreadyUnownedProvenance::Pristine, None) => Ok(()),
        (
            AlreadyUnownedProvenance::NormalRelease {
                receipt: prior,
                receipt_digest,
            },
            Some(LastVolumeTransition::Release { .. }),
        ) => {
            if prior.durability.volume.identity() != *expected_volume {
                return Err(LifecycleVolumeError::VolumeSetMismatch);
            }
            let recomputed = command_normal_release_receipt_digest(
                &prior.durability.scope,
                &prior.durability.volume,
                current,
                prior,
            )?;
            if &recomputed != receipt_digest {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            Ok(())
        }
        _ => Err(LifecycleVolumeError::ReceiptMismatch),
    }
}

fn validate_already_unowned_receipt_shape(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_volume: &LifecycleVolumeIdentity,
    receipt: &CommandAlreadyUnownedReceipt,
) -> Result<()> {
    validate_command_scope(expected_scope)?;
    if receipt.scope != *expected_scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.volume != *expected_volume
        || !authority::remote_head_is_valid(&receipt.expected_head)
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    match &receipt.provenance {
        AlreadyUnownedProvenance::Pristine => Ok(()),
        AlreadyUnownedProvenance::NormalRelease {
            receipt: prior,
            receipt_digest,
        } => {
            if prior.durability.volume.identity() != *expected_volume {
                return Err(LifecycleVolumeError::VolumeSetMismatch);
            }
            validate_normal_release_receipt_shape(
                &prior.durability.scope,
                &prior.durability.volume,
                prior,
            )?;
            if prior.result.resulting_epoch != receipt.expected_epoch
                || prior.result.resulting_head != receipt.expected_head
                || digest_canonical(COMMAND_NORMAL_RELEASE_RECEIPT_DIGEST_DOMAIN, prior)?
                    != *receipt_digest
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            Ok(())
        }
    }
}

fn apply_mixed_volume_set(
    receipt_use: AlreadyUnownedReceiptUse,
    scope: &LifecycleVolumeCommandScope,
    expected_volumes: &[LifecycleVolumeIdentity],
    current_volumes: &[VolumeRecord],
    inputs: &[LifecycleVolumeDispositionInput],
) -> Result<(Vec<VolumeRecord>, Vec<CommandVolumeDispositionReceipt>)> {
    if current_volumes.len() != expected_volumes.len() || inputs.len() != expected_volumes.len() {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    let mut transition_ids = BTreeSet::new();
    for ((expected, current), input) in expected_volumes.iter().zip(current_volumes).zip(inputs) {
        match input {
            LifecycleVolumeDispositionInput::OwnedRelease { release } => {
                if release.durability.scope != *scope {
                    return Err(LifecycleVolumeError::CommandScopeMismatch);
                }
                if release.durability.volume.identity() != *expected {
                    return Err(LifecycleVolumeError::VolumeSetMismatch);
                }
                validate_converged_proof(current, &release.durability)?;
                if !transition_ids.insert(release.transition_id.clone()) {
                    return Err(LifecycleVolumeError::ReceiptMismatch);
                }
            }
            LifecycleVolumeDispositionInput::AlreadyUnowned {
                volume,
                expected_epoch,
                expected_head,
                provenance,
            } => {
                let receipt = CommandAlreadyUnownedReceipt {
                    scope: scope.clone(),
                    volume: volume.clone(),
                    expected_epoch: *expected_epoch,
                    expected_head: expected_head.clone(),
                    provenance: provenance.clone(),
                };
                if volume != expected {
                    return Err(LifecycleVolumeError::VolumeSetMismatch);
                }
                encode_command_already_unowned_receipt(
                    receipt_use,
                    scope,
                    expected,
                    current,
                    &receipt,
                )?;
            }
        }
    }

    let mut resulting = Vec::with_capacity(expected_volumes.len());
    let mut receipts = Vec::with_capacity(expected_volumes.len());
    for (current, input) in current_volumes.iter().zip(inputs) {
        match input {
            LifecycleVolumeDispositionInput::OwnedRelease { release } => {
                let target = &release.durability.volume;
                let request = ReleaseRequest {
                    volume_id: target.volume_id.clone(),
                    transition_id: release.transition_id.clone(),
                    attachment_id: target.attachment_id.clone(),
                    expected_epoch: target.attachment_epoch,
                };
                let (released, result) = authority::release_with_source(
                    current,
                    &lifecycle_transition_source(scope),
                    &request,
                )?;
                let receipt = CommandNormalReleaseReceipt {
                    durability: release.durability.clone(),
                    request,
                    result,
                };
                validate_normal_release_receipt(scope, target, &released, &receipt)?;
                resulting.push(released);
                receipts.push(CommandVolumeDispositionReceipt::NormallyReleased {
                    receipt: Box::new(receipt),
                });
            }
            LifecycleVolumeDispositionInput::AlreadyUnowned {
                volume,
                expected_epoch,
                expected_head,
                provenance,
            } => {
                let receipt = CommandAlreadyUnownedReceipt {
                    scope: scope.clone(),
                    volume: volume.clone(),
                    expected_epoch: *expected_epoch,
                    expected_head: expected_head.clone(),
                    provenance: provenance.clone(),
                };
                resulting.push(current.clone());
                receipts.push(CommandVolumeDispositionReceipt::AlreadyUnowned {
                    receipt: Box::new(receipt),
                });
            }
        }
    }
    Ok((resulting, receipts))
}

fn validate_mixed_volume_set(
    receipt_use: AlreadyUnownedReceiptUse,
    scope: &LifecycleVolumeCommandScope,
    expected_volumes: &[LifecycleVolumeIdentity],
    current_volumes: &[VolumeRecord],
    receipts: &[CommandVolumeDispositionReceipt],
) -> Result<()> {
    if current_volumes.len() != expected_volumes.len() || receipts.len() != expected_volumes.len() {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    let mut transition_ids = BTreeSet::new();
    for ((expected, current), receipt) in expected_volumes.iter().zip(current_volumes).zip(receipts)
    {
        match receipt {
            CommandVolumeDispositionReceipt::NormallyReleased { receipt } => {
                if receipt.durability.volume.identity() != *expected {
                    return Err(LifecycleVolumeError::VolumeSetMismatch);
                }
                validate_normal_release_receipt(
                    scope,
                    &receipt.durability.volume,
                    current,
                    receipt,
                )?;
                if !transition_ids.insert(receipt.request.transition_id.clone()) {
                    return Err(LifecycleVolumeError::ReceiptMismatch);
                }
            }
            CommandVolumeDispositionReceipt::AlreadyUnowned { receipt } => {
                encode_command_already_unowned_receipt(
                    receipt_use,
                    scope,
                    expected,
                    current,
                    receipt,
                )?;
            }
        }
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum StartGrantCurrentBinding {
    Exact,
    SameOrLater,
}

fn start_volume_grant_claimed_current_record(
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
) -> Result<VolumeRecord> {
    let (head, lease_owner, lease_epoch, lease_expires_at, last_transition) =
        match &receipt.authority {
            LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result } => {
                if receipt.grant_sequence.get() != 0 {
                    return Err(LifecycleVolumeError::ReceiptMismatch);
                }
                (
                    result.resulting_head.clone(),
                    result.attachment_id.clone(),
                    result.resulting_epoch,
                    result.lease_expires_at,
                    LastVolumeTransition::NormalAcquire {
                        source: lifecycle_transition_source(&LifecycleVolumeCommandScope {
                            operation_id: receipt.scope.operation_id.clone(),
                            request_fingerprint: receipt.scope.request_fingerprint.clone(),
                            cat_id: receipt.scope.cat_id.clone(),
                            node_id: receipt.scope.node_id.clone(),
                            placement_identity: receipt.scope.placement_identity.clone(),
                        }),
                        request: request.clone(),
                        result: result.clone(),
                    },
                )
            }
            LifecycleStartVolumeGrantAuthority::RenewSameNode {
                expected_source,
                serving_acquire,
                request,
                result,
            } => {
                if receipt.grant_sequence.get() == 0 {
                    return Err(LifecycleVolumeError::ReceiptMismatch);
                }
                let LifecycleServingAcquire::Normal {
                    request: acquire_request,
                    result: acquire_result,
                } = serving_acquire.as_ref();
                (
                    result.resulting_head.clone(),
                    request.attachment_id.clone(),
                    request.expected_epoch,
                    result.lease_expires_at,
                    LastVolumeTransition::NormalAcquire {
                        source: expected_source.clone(),
                        request: acquire_request.clone(),
                        result: acquire_result.clone(),
                    },
                )
            }
        };
    Ok(VolumeRecord {
        volume_id: receipt.volume.volume_id.clone(),
        size_bytes: receipt.volume.size_bytes,
        durability: receipt.volume.durability,
        admin_state: VolumeAdminState::Active,
        head,
        lease_owner: Some(lease_owner),
        lease_epoch,
        lease_expires_at: Some(lease_expires_at),
        last_transition: Some(last_transition),
    })
}

fn validate_start_volume_grant_receipt(
    expected_scope: &LifecycleVolumeCommandScope,
    expected_grant_sequence: WireU64,
    expected_volume: &cats_api::runtime_lifecycle::RuntimeVolumeConfig,
    current: &VolumeRecord,
    receipt: &LifecycleCommandStartVolumeGrantReceipt,
    current_binding: StartGrantCurrentBinding,
) -> Result<()> {
    authority::validate_volume_record(current)?;
    let wire_scope = &receipt.scope;
    if wire_scope.operation_id != expected_scope.operation_id
        || wire_scope.request_fingerprint != expected_scope.request_fingerprint
        || wire_scope.cat_id != expected_scope.cat_id
        || wire_scope.node_id != expected_scope.node_id
        || wire_scope.placement_identity != expected_scope.placement_identity
    {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.grant_sequence != expected_grant_sequence
        || receipt.volume != *expected_volume
        || current.volume_id != expected_volume.volume_id
        || current.size_bytes != receipt.volume.size_bytes
        || current.durability != receipt.volume.durability
        || !matches!(current.admin_state, VolumeAdminState::Active)
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }

    match &receipt.authority {
        LifecycleStartVolumeGrantAuthority::NormalAcquire { request, result } => {
            if receipt.grant_sequence.get() != 0 {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let source = lifecycle_transition_source(expected_scope);
            let head_matches = match current_binding {
                StartGrantCurrentBinding::Exact => result.resulting_head == current.head,
                StartGrantCurrentBinding::SameOrLater => {
                    authority::remote_head_is_same_or_later(&current.head, &result.resulting_head)
                }
            };
            let expiry_matches = match current_binding {
                StartGrantCurrentBinding::Exact => {
                    current.lease_expires_at == Some(result.lease_expires_at)
                }
                StartGrantCurrentBinding::SameOrLater => current
                    .lease_expires_at
                    .is_some_and(|expiry| expiry >= result.lease_expires_at),
            };
            if request.volume_id != receipt.volume.volume_id
                || request.placement_epoch != expected_scope.placement_identity.placement_epoch
                || request.lease_duration_ms == 0
                || result.volume_id != receipt.volume.volume_id
                || result.transition_id != request.transition_id
                || result.attachment_id != request.attachment_id
                || result.resulting_epoch != next_fence_epoch(request.expected_unowned_epoch)?
                || !head_matches
                || current.lease_owner.as_ref() != Some(&result.attachment_id)
                || current.lease_epoch != result.resulting_epoch
                || !expiry_matches
                || !matches!(
                    &current.last_transition,
                    Some(LastVolumeTransition::NormalAcquire {
                        source: current_source,
                        request: current_request,
                        result: current_result,
                    }) if current_source == &source
                        && current_request == request
                        && current_result == result
                )
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
        }
        LifecycleStartVolumeGrantAuthority::RenewSameNode {
            expected_source,
            serving_acquire,
            request,
            result,
        } => {
            if receipt.grant_sequence.get() == 0 {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let head_matches = match current_binding {
                StartGrantCurrentBinding::Exact => result.resulting_head == current.head,
                StartGrantCurrentBinding::SameOrLater => {
                    authority::remote_head_is_same_or_later(&current.head, &result.resulting_head)
                }
            };
            let expiry_matches = match current_binding {
                StartGrantCurrentBinding::Exact => {
                    current.lease_expires_at == Some(result.lease_expires_at)
                }
                StartGrantCurrentBinding::SameOrLater => current
                    .lease_expires_at
                    .is_some_and(|expiry| expiry >= result.lease_expires_at),
            };
            if !matches!(expected_source, VolumeTransitionSource::Lifecycle { .. })
                || request.volume_id != receipt.volume.volume_id
                || request.lease_duration_ms.get() == 0
                || result.volume_id != receipt.volume.volume_id
                || result.attachment_id != request.attachment_id
                || result.epoch != request.expected_epoch
                || !head_matches
                || current.lease_owner.as_ref() != Some(&request.attachment_id)
                || current.lease_epoch != request.expected_epoch
                || !expiry_matches
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let current_source = match (&current.last_transition, serving_acquire.as_ref()) {
                (
                    Some(LastVolumeTransition::NormalAcquire {
                        source,
                        request: acquire_request,
                        result: acquire_result,
                    }),
                    LifecycleServingAcquire::Normal { request, result },
                ) if request == acquire_request && result == acquire_result => source,
                _ => return Err(LifecycleVolumeError::ReceiptMismatch),
            };
            if current_source != expected_source {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let LifecycleServingAcquire::Normal {
                request: acquire_request,
                ..
            } = serving_acquire.as_ref();
            if acquire_request.placement_epoch != expected_scope.placement_identity.placement_epoch
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
        }
    }
    Ok(())
}

fn validate_normal_release_receipt(
    scope: &LifecycleVolumeCommandScope,
    expected: &LifecycleVolumeTarget,
    released: &VolumeRecord,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<()> {
    validate_normal_release_receipt_shape(scope, expected, receipt)?;
    authority::validate_volume_record(released)?;
    validate_converged_proof(released, &receipt.durability)?;
    if released.volume_id != expected.volume_id
        || released.head != receipt.result.resulting_head
        || released.lease_epoch != receipt.result.resulting_epoch
        || released.lease_owner.is_some()
        || released.lease_expires_at.is_some()
        || !matches!(released.admin_state, VolumeAdminState::Active)
        || !matches!(
            &released.last_transition,
            Some(LastVolumeTransition::Release { source, request, result })
                if source == &lifecycle_transition_source(scope)
                    && request == &receipt.request && result == &receipt.result
        )
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_normal_release_receipt_shape(
    scope: &LifecycleVolumeCommandScope,
    expected: &LifecycleVolumeTarget,
    receipt: &CommandNormalReleaseReceipt,
) -> Result<()> {
    validate_command_scope(scope)?;
    if receipt.durability.scope != *scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.durability.volume != *expected {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_converged_proof_shape(&receipt.durability)?;
    if receipt.request.volume_id != expected.volume_id
        || receipt.request.attachment_id != expected.attachment_id
        || receipt.request.expected_epoch != expected.attachment_epoch
        || receipt.result.volume_id != expected.volume_id
        || receipt.result.transition_id != receipt.request.transition_id
        || receipt.result.released_attachment_id != expected.attachment_id
        || receipt.result.resulting_epoch != next_fence_epoch(receipt.request.expected_epoch)?
        || receipt.result.resulting_head != receipt.durability.remote_head
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_converged_proof(
    record: &VolumeRecord,
    proof: &CommandVolumeDurabilityProof,
) -> Result<()> {
    validate_proof_record_binding(record, proof)?;
    validate_converged_proof_shape(proof)
}

fn validate_converged_proof_shape(proof: &CommandVolumeDurabilityProof) -> Result<()> {
    validate_command_scope(&proof.scope)?;
    if !authority::remote_head_is_valid(&proof.remote_head) {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    if proof.local_durable_generation != proof.remote_durable_generation
        || proof.remote_durable_generation != proof.remote_head.generation
        || proof.pending_pack_count.get() != 0
    {
        return Err(LifecycleVolumeError::DurabilityNotConverged);
    }
    Ok(())
}

fn validate_disposable_root_proof(
    record: &VolumeRecord,
    proof: &CommandVolumeDurabilityProof,
) -> Result<()> {
    validate_proof_record_binding(record, proof)?;
    validate_disposable_root_proof_shape(proof)
}

fn validate_disposable_root_proof_shape(proof: &CommandVolumeDurabilityProof) -> Result<()> {
    if proof.volume.disk_role != DiskRole::Root {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    if proof.remote_durable_generation != proof.remote_head.generation
        || proof.local_durable_generation <= proof.remote_durable_generation
        || proof.pending_pack_count.get() == 0
    {
        return Err(LifecycleVolumeError::RootTailNotDisposable);
    }
    Ok(())
}

fn validate_proof_record_binding(
    record: &VolumeRecord,
    proof: &CommandVolumeDurabilityProof,
) -> Result<()> {
    authority::validate_volume_record(record)?;
    if !authority::remote_head_is_valid(&proof.remote_head) {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    if record.volume_id != proof.volume.volume_id {
        return Err(LifecycleVolumeError::Authority(AuthorityError::NotFound));
    }
    if record.head != proof.remote_head {
        return Err(LifecycleVolumeError::Authority(
            AuthorityError::HeadConflict,
        ));
    }
    Ok(())
}

fn validate_cold_command(command: &ColdCommandVolumeSet) -> Result<()> {
    validate_command_scope(&command.scope)?;
    if command.volumes.is_empty()
        || command
            .volumes
            .windows(2)
            .any(|pair| pair[0].volume_id.as_str() >= pair[1].volume_id.as_str())
        || command
            .volumes
            .iter()
            .filter(|volume| volume.disk_role == DiskRole::Root)
            .count()
            != 1
    {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_unique_identities(&command.volumes)
}

fn validate_delete_command(command: &DeleteCommandVolumeSet) -> Result<()> {
    validate_command_scope(&command.scope)?;
    if command.root_disposition.root.disk_role != DiskRole::Root
        || command
            .persistent_volumes
            .iter()
            .any(|volume| volume.disk_role != DiskRole::Persistent)
        || command
            .persistent_volumes
            .windows(2)
            .any(|pair| pair[0].volume_id.as_str() >= pair[1].volume_id.as_str())
    {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    let mut complete = Vec::with_capacity(1 + command.persistent_volumes.len());
    complete.push(command.root_disposition.root.clone());
    complete.extend(command.persistent_volumes.iter().cloned());
    validate_unique_identities(&complete)
}

fn validate_unique_identities(targets: &[LifecycleVolumeIdentity]) -> Result<()> {
    let mut disk_ids = BTreeSet::new();
    let mut volume_ids = BTreeSet::new();
    for target in targets {
        if !disk_ids.insert(target.disk_id.clone()) || !volume_ids.insert(target.volume_id.clone())
        {
            return Err(LifecycleVolumeError::VolumeSetMismatch);
        }
    }
    Ok(())
}

fn validate_command_scope(scope: &LifecycleVolumeCommandScope) -> Result<()> {
    if scope.node_id != scope.placement_identity.node_id {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    Ok(())
}

fn lifecycle_transition_source(scope: &LifecycleVolumeCommandScope) -> VolumeTransitionSource {
    VolumeTransitionSource::Lifecycle {
        operation_id: scope.operation_id.clone(),
        request_fingerprint: scope.request_fingerprint.clone(),
    }
}

fn validate_command_bound_root_authorization(
    command: &DeleteCommandVolumeSet,
    expected_head: &RemoteHead,
    expected_persistent_dispositions_digest: &Sha256Digest,
    bound: &CommandBoundDisposableRootAuthorization,
) -> Result<()> {
    if bound.scope != command.scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &bound.authorization.authorization
    else {
        return Err(LifecycleVolumeError::Authority(
            AuthorityError::InvalidAuthorization,
        ));
    };
    let root = &command.root_disposition.root;
    if authorization.operation_id != command.scope.operation_id
        || authorization.request_fingerprint != command.scope.request_fingerprint
        || authorization.cat_id != command.scope.cat_id
        || authorization.authorized_node_id != command.scope.node_id
        || authorization.placement_epoch != command.scope.placement_identity.placement_epoch
        || authorization.delete_id != command.root_disposition.delete_id
        || authorization.disk_id != root.disk_id
        || authorization.volume_id != root.volume_id
        || authorization.expected_head != *expected_head
        || authorization.persistent_dispositions_digest != *expected_persistent_dispositions_digest
    {
        return Err(LifecycleVolumeError::Authority(
            AuthorityError::InvalidAuthorization,
        ));
    }
    authority::validate_authorization_record(&bound.authorization)?;
    Ok(())
}

fn validate_delete_disposable_root_begin(
    expected_command: &DeleteCommandVolumeSet,
    current_persistent_volumes: &[VolumeRecord],
    deleting_root_volume: &VolumeRecord,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &DeleteDisposableRootBeginReceipt,
) -> Result<()> {
    validate_delete_command(expected_command)?;
    if receipt.command.scope != expected_command.scope
        || receipt.root_durability.scope != expected_command.scope
        || consumed_authorization.scope != expected_command.scope
    {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.command != *expected_command
        || receipt.root_durability.volume.identity() != expected_command.root_disposition.root
    {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    validate_mixed_volume_set(
        AlreadyUnownedReceiptUse::Delete,
        &expected_command.scope,
        &expected_command.persistent_volumes,
        current_persistent_volumes,
        &receipt.persistent_dispositions,
    )?;
    let persistent_dispositions_digest = persistent_delete_dispositions_digest(
        expected_command,
        current_persistent_volumes,
        &receipt.persistent_dispositions,
    )?;
    validate_command_bound_root_authorization(
        expected_command,
        &receipt.root_durability.remote_head,
        &persistent_dispositions_digest,
        consumed_authorization,
    )?;
    validate_disposable_root_proof_shape(&receipt.root_durability)?;
    authority::validate_volume_record(deleting_root_volume)?;
    authority::validate_authorization_record(&consumed_authorization.authorization)?;

    let AuthorizationState::Consumed(consumed) = &consumed_authorization.authorization.state else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref() else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    if consumed != &receipt.root_begin.receipt
        || receipt.root_begin.command != *expected_command
        || receipt.root_begin.authorization_id != receipt.root_begin.receipt.authorization_id
        || receipt.root_begin.persistent_dispositions_digest != persistent_dispositions_digest
        || deleting_root_volume.volume_id != receipt.root_begin.receipt.volume_id
        || deleting_root_volume.head != receipt.root_begin.receipt.resulting_head
        || deleting_root_volume.lease_epoch != receipt.root_begin.receipt.resulting_epoch
        || deleting_root_volume.lease_owner.is_some()
        || deleting_root_volume.lease_expires_at.is_some()
        || !matches!(
            &deleting_root_volume.last_transition,
            Some(LastVolumeTransition::BeginDisposableDelete { source, authorization_id })
                if source == &lifecycle_transition_source(&expected_command.scope)
                    && authorization_id == &receipt.root_begin.authorization_id
        )
        || !matches!(
            &deleting_root_volume.admin_state,
            VolumeAdminState::Deleting { delete_id }
                if delete_id == &expected_command.root_disposition.delete_id
        )
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    Ok(())
}

fn validate_command_disposable_authorization_consumed_receipt(
    expected_command: &DeleteCommandVolumeSet,
    current_deleting_root_volume: Option<&VolumeRecord>,
    consumed_authorization: &CommandBoundDisposableRootAuthorization,
    receipt: &CommandDisposableAuthorizationConsumedReceipt,
) -> Result<()> {
    validate_delete_command(expected_command)?;
    if receipt.command.scope != expected_command.scope
        || consumed_authorization.scope != expected_command.scope
    {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.command != *expected_command {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }

    validate_command_bound_root_authorization(
        expected_command,
        &receipt.receipt.resulting_head,
        &receipt.persistent_dispositions_digest,
        consumed_authorization,
    )?;
    authority::validate_authorization_record(&consumed_authorization.authorization)?;

    let VolumeAuthorization::DisposableRootDelete(authorization) =
        &consumed_authorization.authorization.authorization
    else {
        return Err(LifecycleVolumeError::Authority(
            AuthorityError::InvalidAuthorization,
        ));
    };
    let AuthorizationState::Consumed(consumed) = &consumed_authorization.authorization.state else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    let AuthorizationConsumedReceipt::BeginDisposableDelete(consumed) = consumed.as_ref() else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    let root = &expected_command.root_disposition.root;
    if consumed != &receipt.receipt
        || receipt.authorization_id != authorization.authorization_id
        || receipt.persistent_dispositions_digest != authorization.persistent_dispositions_digest
        || receipt.authorization_id != receipt.receipt.authorization_id
        || receipt.receipt.volume_id != root.volume_id
        || receipt.receipt.disk_id != root.disk_id
        || receipt.receipt.cat_id != expected_command.scope.cat_id
        || receipt.receipt.delete_id != expected_command.root_disposition.delete_id
        || receipt.receipt.prior_attachment_id != authorization.expected_attachment_id
        || receipt.receipt.resulting_epoch != next_fence_epoch(authorization.expected_epoch)?
        || receipt.receipt.resulting_head != authorization.expected_head
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }

    if let Some(current) = current_deleting_root_volume {
        authority::validate_volume_record(current)?;
        if current.volume_id != root.volume_id
            || current.head != receipt.receipt.resulting_head
            || current.lease_epoch != receipt.receipt.resulting_epoch
            || current.lease_owner.is_some()
            || current.lease_expires_at.is_some()
            || !matches!(
                &current.admin_state,
                VolumeAdminState::Deleting { delete_id }
                    if delete_id == &expected_command.root_disposition.delete_id
            )
            || !matches!(
                &current.last_transition,
                Some(LastVolumeTransition::BeginDisposableDelete { source, authorization_id })
                    if source == &lifecycle_transition_source(&expected_command.scope)
                        && authorization_id == &receipt.authorization_id
            )
        {
            return Err(LifecycleVolumeError::ReceiptMismatch);
        }
    }
    Ok(())
}

fn validate_command_delete_completion_receipt(
    expected_command: &DeleteCommandVolumeSet,
    current_root_volume: Option<&VolumeRecord>,
    consumed_authorization: Option<&CommandBoundDisposableRootAuthorization>,
    receipt: &CommandDeleteCompletionReceipt,
) -> Result<()> {
    validate_delete_command(expected_command)?;
    if current_root_volume.is_some() {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    if receipt.command.scope != expected_command.scope {
        return Err(LifecycleVolumeError::CommandScopeMismatch);
    }
    if receipt.command != *expected_command {
        return Err(LifecycleVolumeError::VolumeSetMismatch);
    }
    authority::validate_delete_completion_receipt(&receipt.completion)?;

    match (&receipt.root_authority, &receipt.completion) {
        (
            CommandRootDeleteAuthorityReceipt::NormalRelease(release),
            DeleteCompletionReceipt::Normal { request, .. },
        ) => {
            if consumed_authorization.is_some() {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let root = &expected_command.root_disposition.root;
            if release.durability.volume.identity() != *root {
                return Err(LifecycleVolumeError::VolumeSetMismatch);
            }
            validate_normal_release_receipt_shape(
                &expected_command.scope,
                &release.durability.volume,
                release,
            )?;
            if request.delete_id != expected_command.root_disposition.delete_id
                || request.disk_id != root.disk_id
                || request.volume_id != root.volume_id
                || request.expected_unowned_epoch != release.result.resulting_epoch
                || request.expected_head != release.result.resulting_head
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
        }
        (
            CommandRootDeleteAuthorityReceipt::DisposableAuthorizationConsumed(consumed),
            completion @ DeleteCompletionReceipt::DisposableRoot { .. },
        ) => {
            let Some(authorization) = consumed_authorization else {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            };
            validate_command_disposable_authorization_consumed_receipt(
                expected_command,
                None,
                authorization,
                consumed,
            )?;
            validate_disposable_completion_pair(&consumed.receipt, completion)?;
        }
        (
            CommandRootDeleteAuthorityReceipt::AlreadyUnowned(already_unowned),
            DeleteCompletionReceipt::Normal { request, .. },
        ) => {
            if consumed_authorization.is_some() {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
            let root = &expected_command.root_disposition.root;
            validate_already_unowned_receipt_shape(&expected_command.scope, root, already_unowned)?;
            if request.delete_id != expected_command.root_disposition.delete_id
                || request.disk_id != root.disk_id
                || request.volume_id != root.volume_id
                || request.expected_unowned_epoch != already_unowned.expected_epoch
                || request.expected_head != already_unowned.expected_head
            {
                return Err(LifecycleVolumeError::ReceiptMismatch);
            }
        }
        _ => return Err(LifecycleVolumeError::ReceiptMismatch),
    }
    Ok(())
}

fn validate_disposable_completion_pair(
    begin: &BeginDisposableDeleteConsumedReceipt,
    completion: &DeleteCompletionReceipt,
) -> Result<()> {
    let DeleteCompletionReceipt::DisposableRoot {
        disk_id,
        volume_id,
        delete_id,
        authorization_id,
        prior_attachment_id,
        deleting_epoch,
        deleting_head,
        ..
    } = completion
    else {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    };
    if disk_id != &begin.disk_id
        || volume_id != &begin.volume_id
        || delete_id != &begin.delete_id
        || authorization_id != &begin.authorization_id
        || prior_attachment_id != &begin.prior_attachment_id
        || deleting_epoch != &begin.resulting_epoch
        || deleting_head != &begin.resulting_head
    {
        return Err(LifecycleVolumeError::ReceiptMismatch);
    }
    Ok(())
}

fn next_fence_epoch(current: FenceEpoch) -> Result<FenceEpoch> {
    current
        .get()
        .checked_add(1)
        .and_then(FenceEpoch::new)
        .ok_or(LifecycleVolumeError::ReceiptMismatch)
}

fn encode_canonical_receipt<T: Serialize>(
    domain: &[u8],
    input: &T,
) -> Result<CanonicalLifecycleVolumeReceipt> {
    let value =
        serde_json::to_value(input).map_err(|_| LifecycleVolumeError::ReceiptEncodingFailed)?;
    let mut canonical = Vec::new();
    write_canonical_json(&value, &mut canonical);
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update([0]);
    hasher.update(&canonical);
    Ok(CanonicalLifecycleVolumeReceipt {
        canonical_receipt_bytes: canonical,
        receipt_digest: Sha256Digest::from_bytes(hasher.finalize().into()),
    })
}

fn digest_canonical<T: Serialize>(domain: &[u8], input: &T) -> Result<Sha256Digest> {
    Ok(encode_canonical_receipt(domain, input)?.receipt_digest)
}

fn decode_canonical_receipt<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    if bytes.is_empty() || bytes.len() > LIFECYCLE_VOLUME_RECEIPT_MAX_CANONICAL_BYTES {
        return Err(LifecycleVolumeError::ReceiptEncodingFailed);
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| LifecycleVolumeError::ReceiptEncodingFailed)?;
    let mut canonical = Vec::new();
    write_canonical_json(&value, &mut canonical);
    if canonical != bytes {
        return Err(LifecycleVolumeError::ReceiptEncodingFailed);
    }
    serde_json::from_value(value).map_err(|_| LifecycleVolumeError::ReceiptEncodingFailed)
}

fn write_canonical_json(value: &Value, output: &mut Vec<u8>) {
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(true) => output.extend_from_slice(b"true"),
        Value::Bool(false) => output.extend_from_slice(b"false"),
        Value::Number(number) => output.extend_from_slice(number.to_string().as_bytes()),
        Value::String(string) => write_canonical_json_string(string, output),
        Value::Array(items) => {
            output.push(b'[');
            for (index, item) in items.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json(item, output);
            }
            output.push(b']');
        }
        Value::Object(object) => {
            let mut members: Vec<_> = object.iter().collect();
            members.sort_unstable_by(|(left, _), (right, _)| left.as_bytes().cmp(right.as_bytes()));
            output.push(b'{');
            for (index, (key, member)) in members.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write_canonical_json_string(key, output);
                output.push(b':');
                write_canonical_json(member, output);
            }
            output.push(b'}');
        }
    }
}

fn write_canonical_json_string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(br#"\""#),
            '\\' => output.extend_from_slice(br#"\\"#),
            '\u{08}' => output.extend_from_slice(br#"\b"#),
            '\u{0c}' => output.extend_from_slice(br#"\f"#),
            '\n' => output.extend_from_slice(br#"\n"#),
            '\r' => output.extend_from_slice(br#"\r"#),
            '\t' => output.extend_from_slice(br#"\t"#),
            '\u{00}'..='\u{1f}' => {
                output.extend_from_slice(br#"\u00"#);
                let byte = character as u8;
                output.push(canonical_hex_digit(byte >> 4));
                output.push(canonical_hex_digit(byte & 0x0f));
            }
            _ => {
                let mut buffer = [0; 4];
                output.extend_from_slice(character.encode_utf8(&mut buffer).as_bytes());
            }
        }
    }
    output.push(b'"');
}

const fn canonical_hex_digit(value: u8) -> u8 {
    if value < 10 {
        b'0' + value
    } else {
        b'a' + value - 10
    }
}
