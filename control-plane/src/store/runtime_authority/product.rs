//! Covered Cat-create persistence boundary.
//!
//! This module intentionally stops at the Control Store. The HTTP and
//! controller cutover will call these APIs later; keeping the slice here lets
//! the atomic PostgreSQL contract land without a second authority or dual
//! write to the legacy product tables.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use cats_api::chunk::MAX_VOLUME_BYTES;
use cats_api::error::ApiError;
use cats_api::persistent_disk::{
    encode_persistent_disk_create_response, persistent_disk_create_response,
    PERSISTENT_DISK_NAME_CONFLICT_BODY,
};
use cats_api::resources::DiskDurability as PublicDiskDurability;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AsciiText, ContractVersion, DesiredRuntimeSpec, DiskKind,
    Durability, Epoch, Ext4MountIntent, FenceEpoch, FilesystemInitialization, Generation, Hostname,
    HttpProtocol, Id, NodeIdentityState, Operation, OperationPhase, OperationTerminal, RandomId128,
    Revision, RuntimeTarget, RuntimeTransition, Sequence, Sha256Digest, UnixMillis, VolumeAccess,
    VolumeAcquire, VolumeDisposition,
};
use cats_storage::authority::{
    AuthorityError, RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord,
};
use postgres::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cat_create_service::CatCreatePlacementMutation;
use super::covered_commit::{
    CommitResolutionRegistry, CoveredCommitCancellation, CoveredCommitState,
};
use super::normal_delete::{begin_persistent_disk_delete_in, PersistentDiskDeleteContext};
use super::placement_planner::{
    lock_cat_create_placement_for_desired_mutation,
    revalidate_desired_mutation_placement_after_identity_locks,
    revalidate_desired_mutation_post_assignment, PlacementCommitLoad, PlacementTargetSnapshot,
};
use super::product_rows::{
    delete_hostname_lookups_by_cat, insert_api_result, insert_cat, insert_desired, insert_disk,
    insert_endpoint, insert_hostname_lookup, insert_operation,
    load_any_disk_by_filesystem_uuid_for_update, load_any_disk_by_id_for_update,
    load_any_disk_by_initialization_token_for_update, load_any_disk_by_name_unlocked,
    load_api_result_for_update, load_cat_by_id_for_update, load_cat_by_name_unlocked,
    load_desired_by_network_id_unlocked, load_desired_for_update, load_desired_unlocked,
    load_disk_by_id_for_update, load_disk_by_name_for_update, load_endpoint_by_cat_name_unlocked,
    load_endpoint_by_id_for_update, load_endpoint_by_id_unlocked, load_hostname_lookup_for_update,
    load_hostname_lookup_unlocked, load_hostname_lookups_by_cat_unlocked,
    load_operation_by_cat_revision_for_update, load_operation_by_cat_revision_unlocked,
    load_operation_by_workspace_unlocked, load_operation_for_update, load_operation_unlocked,
    load_pending_operation_by_cat_for_update, load_root_disk_by_cat_unlocked, replace_desired,
    update_operation,
};
use super::route_epoch_engine::RequireIdleOpenBusyProof;
use super::rows::{
    database_now, insert_volume, load_any_volume_by_id_for_update, load_volume_for_update,
    volume_has_disposable_root_authorization_for_delete,
};
use super::runtime_spine::{
    lock_placement_admission_for_desired_mutation, validate_require_idle_open_busy_proof_in,
    PlacementAdmissionLoad, PlacementAdmissionSnapshot,
};
use crate::store::agent_sessions::load_identity_by_node_for_update;
use crate::store::transaction::{
    AuthorityExecutionError, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{internal, Result, Store};

const MAX_RESPONSE_BODY_BYTES: usize = 1_048_576;
const CAT_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"cat name already exists"}"#;
const DISK_DELETE_PRECONDITION_BODY: &[u8] =
    br#"{"code":"failed_precondition","message":"disk is not safe to delete"}"#;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatRecord {
    pub(crate) cat_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) created_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointRecord {
    pub(crate) endpoint_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) name: Id,
    pub(crate) created_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HostnameDesiredLookup {
    pub(crate) hostname: Hostname,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) endpoint_id: Id,
    pub(crate) desired_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostnameDesiredLocation {
    pub(crate) cat_id: Id,
    pub(crate) endpoint_id: Id,
    pub(crate) desired_revision: Revision,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiskRecord {
    pub(crate) disk_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) durability: VolumeDurability,
    pub(crate) created_at: UnixMillis,
    pub(crate) admin_state: DiskAdminState,
    pub(crate) role: DiskRole,
}

/// The single product and GC-live-root authority for a durable disk snapshot.
/// Runtime transitions only read this row; the public create/delete/restore
/// API remains a separate future slice.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DiskSnapshotRecord {
    pub(crate) snapshot_id: Id,
    pub(crate) disk_id: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) head: RemoteHead,
    pub(crate) created_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DiskAdminState {
    Active,
    Deleting { delete_id: Id },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum DiskRole {
    Root {
        cat_id: Id,
    },
    Persistent {
        initialization: Box<PersistentDiskInitialization>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum PersistentDiskInitialization {
    Uninitialized {
        initialization_token: cats_api::runtime_reconciliation::RandomId128,
        filesystem_uuid: cats_api::runtime_reconciliation::RandomId128,
        expected_blank_head: RemoteHead,
    },
    Initialized {
        initialization_token: cats_api::runtime_reconciliation::RandomId128,
        filesystem_uuid: cats_api::runtime_reconciliation::RandomId128,
        expected_blank_head: RemoteHead,
        initialized_head: RemoteHead,
        initialized_at: UnixMillis,
    },
}

/// Validates the only two legal PersistentDisk projections into current
/// Desired.  Callers must use the current locked Volume head: an old Desired
/// JSON value is not allowed to choose its own initialization authority.
pub(super) fn persistent_initialization_matches_mount(
    initialization: &PersistentDiskInitialization,
    current_head: &RemoteHead,
    mount: Option<&Ext4MountIntent>,
) -> bool {
    let Some(mount) = mount else {
        return false;
    };
    match (initialization, &mount.initialization) {
        (
            PersistentDiskInitialization::Uninitialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
            },
            FilesystemInitialization::Initialize {
                initialization_token: desired_token,
                expected_blank_head: desired_blank_head,
            },
        ) => {
            mount.filesystem_uuid == *filesystem_uuid
                && desired_token == initialization_token
                && desired_blank_head == expected_blank_head
                && current_head == expected_blank_head
        }
        (
            PersistentDiskInitialization::Initialized {
                initialization_token,
                filesystem_uuid,
                expected_blank_head,
                initialized_head,
                ..
            },
            FilesystemInitialization::Initialize {
                initialization_token: desired_token,
                expected_blank_head: desired_blank_head,
            },
        ) => {
            mount.filesystem_uuid == *filesystem_uuid
                && desired_token == initialization_token
                && desired_blank_head == expected_blank_head
                && initialized_head.generation.get() > 0
                && (current_head.generation.get() > initialized_head.generation.get()
                    || current_head == initialized_head)
        }
        (
            PersistentDiskInitialization::Initialized {
                filesystem_uuid,
                initialized_head,
                ..
            },
            FilesystemInitialization::Existing,
        ) => {
            mount.filesystem_uuid == *filesystem_uuid
                && initialized_head.generation.get() > 0
                && (current_head.generation.get() > initialized_head.generation.get()
                    || current_head == initialized_head)
        }
        _ => false,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DiskRecordCandidate {
    pub(crate) disk_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) durability: VolumeDurability,
    pub(crate) admin_state: DiskAdminState,
    pub(crate) role: DiskRole,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct EndpointRecordCandidate {
    pub(crate) endpoint_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) cat_id: Id,
    pub(crate) name: Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreateCandidate {
    pub(crate) cat_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) root_disk: DiskRecordCandidate,
    pub(crate) volume: VolumeRecord,
    pub(crate) desired: DesiredRuntimeSpec,
    pub(crate) endpoint: EndpointRecordCandidate,
    pub(crate) hostname_lookup: HostnameDesiredLookup,
    pub(crate) operation_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum RuntimeOperationRead {
    Found(Box<Operation>),
    NotFound,
    Corrupt,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiIdempotencyRequest {
    pub(crate) authenticated_workspace_id: Id,
    pub(crate) canonical_route: AsciiText,
    pub(crate) idempotency_key: AsciiText,
    pub(crate) request_fingerprint: Sha256Digest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ExactContentType {
    ApplicationJson,
}

impl ExactContentType {
    pub(super) const fn as_str(self) -> &'static str {
        match self {
            Self::ApplicationJson => "application/json",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ExactHttpResponse {
    http_status: u16,
    content_type: Option<ExactContentType>,
    response_body: Vec<u8>,
}

impl ExactHttpResponse {
    // The HTTP/service boundary constructs these envelopes after its own
    // media-envelope validation; F2a only consumes them in the Store.
    pub(crate) fn new(
        http_status: u16,
        content_type: Option<ExactContentType>,
        response_body: Vec<u8>,
    ) -> Result<Self> {
        if !(200..=599).contains(&http_status) {
            return Err(ApiError::invalid("HTTP result status must be in 200..=599"));
        }
        if response_body.len() > MAX_RESPONSE_BODY_BYTES {
            return Err(ApiError::invalid("HTTP result body exceeds 1 MiB"));
        }
        Ok(Self {
            http_status,
            content_type,
            response_body,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatCreateAcceptedEnvelope {
    response: ExactHttpResponse,
    cat_id: Id,
    operation_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreateEnvelopes {
    accepted: CatCreateAcceptedEnvelope,
    name_conflict: ExactHttpResponse,
}

impl CatCreateEnvelopes {
    pub(crate) fn new(
        accepted_response: ExactHttpResponse,
        accepted_cat_id: Id,
        accepted_operation_id: Id,
        name_conflict: ExactHttpResponse,
    ) -> Result<Self> {
        validate_envelope(&accepted_response, 202)?;
        validate_envelope(&name_conflict, 409)?;
        let canonical_accepted =
            encode_cat_create_accepted_response(&accepted_cat_id, &accepted_operation_id)?;
        if accepted_response.response_body != canonical_accepted {
            return Err(ApiError::invalid(
                "Cat create accepted body does not match its typed identities",
            ));
        }
        if name_conflict.response_body != CAT_NAME_CONFLICT_BODY {
            return Err(ApiError::invalid(
                "Cat name-conflict body is not the canonical already_exists response",
            ));
        }
        Ok(Self {
            accepted: CatCreateAcceptedEnvelope {
                response: accepted_response,
                cat_id: accepted_cat_id,
                operation_id: accepted_operation_id,
            },
            name_conflict,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoveredCatCreateRequest {
    pub(crate) idempotency: ApiIdempotencyRequest,
    pub(crate) candidate: CatCreateCandidate,
    pub(crate) envelopes: CatCreateEnvelopes,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistentDiskCreateCandidate {
    pub(crate) disk_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) name: Id,
    pub(crate) volume_id: Id,
    pub(crate) size_bytes: u64,
    pub(crate) durability: VolumeDurability,
    pub(crate) initialization_token: RandomId128,
    pub(crate) filesystem_uuid: RandomId128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoveredPersistentDiskCreateRequest {
    pub(crate) idempotency: ApiIdempotencyRequest,
    pub(crate) candidate: PersistentDiskCreateCandidate,
    pub(crate) name_conflict: ExactHttpResponse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CoveredDiskDeleteRequest {
    pub(crate) idempotency: ApiIdempotencyRequest,
    pub(crate) disk_id: Id,
    pub(crate) delete_id: Id,
    pub(crate) active_guest_digest: Sha256Digest,
}

/// One complete successor Desired plus every identity that must be locked
/// before the current Cat row. Placement/capacity planners and domain-specific
/// volume/route checks run before constructing this closed commit candidate;
/// this boundary owns the monotonic revision, placement epoch and Operation
/// publication CAS.
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "A1 freezes the Desired commit boundary before A2/G4 production routes consume it"
)]
pub(crate) struct CoveredDesiredMutationRequest {
    pub(crate) idempotency: ApiIdempotencyRequest,
    pub(crate) expected_current: DesiredRuntimeSpec,
    pub(crate) desired: DesiredRuntimeSpec,
    pub(crate) operation_id: Id,
    pub(crate) placement_snapshots: Vec<PlacementTargetSnapshot>,
    pub(crate) active_guest_digest: Sha256Digest,
    pub(crate) endpoint_records: Vec<EndpointRecordCandidate>,
    pub(crate) volume_mutation: DesiredVolumeMutation,
    /// The sole old-serving-epoch recovery exception. `None` is conservative.
    pub(crate) require_idle_open_busy_proof: Option<RequireIdleOpenBusyProof>,
}

/// The only A2 lifecycle mutation allowed to change a VolumeIntent.  The
/// closed value is re-derived against locked Volume/Disk rows; it is not an
/// authorization to mutate ownership or the Volume authority itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum DesiredVolumeMutation {
    Preserve,
    DeleteCat { delete_id: Id },
}

#[derive(Serialize)]
struct DesiredMutationAcceptedResponse<'a> {
    desired_revision: u64,
    operation_id: &'a Id,
}

#[derive(Serialize)]
struct DesiredMutationConvergedResponse {
    desired_revision: u64,
    converged: bool,
}

/// Store-derived mutation class. Callers cannot downgrade a placement or
/// runtime rebuild into the source-only path by supplying a boolean: the class
/// is recomputed from the two complete Desired snapshots on every retry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DesiredMutationClass {
    /// Target convergence away from Running and Endpoint/route-only revisions
    /// serialize on NodeIdentity and exact current Desired, but do not consume
    /// target placement eligibility or a fresh A20 admission receipt.
    SourceOnly,
    /// A new assignment, runtime shape/network change, or entry/re-entry into
    /// Running consumes the complete fresh placement/admission snapshot.
    PlacementRequired,
}

/// Unforgeable within sibling runtime-authority modules. The row layer accepts
/// this token for the destructive Desired/hostname helpers that are legal only
/// inside the covered Desired mutation transaction; no constructor is exposed.
pub(super) struct DesiredMutationRowCapability {
    _private: (),
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "A1 freezes the Desired commit boundary before A2/G4 production routes consume it"
)]
pub(crate) enum DesiredMutationCommit {
    Replayed(ApiIdempotencyResult),
    Converged(ApiIdempotencyResult),
    Changed(ApiIdempotencyResult),
}

#[derive(Debug)]
#[allow(
    dead_code,
    reason = "A1 freezes the Desired commit boundary before A2/G4 production routes consume it"
)]
pub(crate) enum CoveredDesiredMutationError {
    CandidateCollision(CandidateCollision),
    Stale,
    Store(ApiError),
}

/// One bounded BillingEnforcer scan candidate. The commit path treats this as
/// a hint only and re-reads the complete current Desired under the A1 lock
/// order before it can publish a successor revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BillingDesiredCandidate {
    pub(crate) cat_id: Id,
    pub(crate) workspace_id: Id,
    pub(crate) desired_revision: Revision,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(
    dead_code,
    reason = "the common A1 system boundary is consumed by the A3 Billing and G4 RequireIdle composition commits"
)]
pub(crate) enum SystemDesiredMutationCommit {
    Changed,
    Replayed,
    Stale,
}

#[cfg(test)]
pub(super) type BillingDesiredCommit = SystemDesiredMutationCommit;

/// Exact, stable facts that caused the Billing domain to request downward
/// convergence. This is not an API idempotency key and it is not a mutable
/// balance row: its canonical digest is the system event identity used to
/// derive the retained Operation identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct BillingExhaustionDecision {
    pub(crate) billing_account_id: String,
    pub(crate) account_id: String,
    pub(crate) credit_nanos: i128,
    pub(crate) usage_nanos: u128,
    pub(crate) usage_visible_through_unix_ms: Option<i64>,
    pub(crate) rate_card_id: String,
}

/// Stable identity of a RequireIdle attempt. The G4 engine owns the accepted
/// observation validation; this common A1 boundary owns only publication.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequireIdleAttemptSource {
    pub(crate) attempt_id: RandomId128,
    pub(crate) source_revision: Revision,
    pub(crate) source_runtime_incarnation: RandomId128,
}

/// Exact accepted evidence for a Busy RequireIdle attempt. Session and
/// observation fields validate the current proof but are deliberately not in
/// the stable Operation identity: an equivalent later heartbeat must replay
/// the one attempt rather than mint another lifecycle mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequireIdleBusySource {
    pub(crate) node_id: Id,
    pub(crate) agent_session_epoch: Epoch,
    pub(crate) inventory_epoch: Epoch,
    pub(crate) observation_id: RandomId128,
    pub(crate) heartbeat_sequence: Sequence,
    pub(crate) attempt_id: RandomId128,
    pub(crate) source_revision: Revision,
    pub(crate) source_runtime_incarnation: RandomId128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum SystemDesiredMutationSource {
    BillingExhaustion(BillingExhaustionDecision),
    RequireIdleAttempt(RequireIdleAttemptSource),
    RequireIdleBusy(RequireIdleBusySource),
}

/// Opaque system-domain publication request. Sibling modules can only obtain
/// one through a domain-specific constructor, so neither Billing nor G4 can
/// bypass the shared A1 row guards with caller-authored booleans.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct SystemDesiredMutationRequest {
    source: SystemDesiredMutationSource,
    expected_current: DesiredRuntimeSpec,
    desired: DesiredRuntimeSpec,
    placement_snapshots: Vec<PlacementTargetSnapshot>,
    active_guest_digest: Sha256Digest,
    endpoint_records: Vec<EndpointRecordCandidate>,
}

impl SystemDesiredMutationRequest {
    #[allow(dead_code, reason = "consumed by the A3 Billing composition")]
    pub(crate) fn billing_exhaustion(
        expected_current: DesiredRuntimeSpec,
        decision: BillingExhaustionDecision,
        active_guest_digest: Sha256Digest,
        endpoint_records: Vec<EndpointRecordCandidate>,
    ) -> Result<Self> {
        let mut desired = expected_current.clone();
        desired.desired_revision = desired
            .desired_revision
            .get()
            .checked_add(1)
            .and_then(Revision::new)
            .ok_or_else(|| ApiError::internal("Desired revision is exhausted"))?;
        desired.target = RuntimeTarget::Cold;
        desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
        desired.spec_digest = cats_api::runtime_reconciliation::spec_digest(&desired)
            .map_err(|_| ApiError::internal("Billing successor Desired is invalid"))?;
        Ok(Self {
            source: SystemDesiredMutationSource::BillingExhaustion(decision),
            expected_current,
            desired,
            placement_snapshots: Vec::new(),
            active_guest_digest,
            endpoint_records,
        })
    }

    #[cfg(test)]
    pub(super) fn with_desired_for_test(mut self, desired: DesiredRuntimeSpec) -> Self {
        self.desired = desired;
        self
    }

    #[cfg(test)]
    pub(super) fn desired_for_test(&self) -> &DesiredRuntimeSpec {
        &self.desired
    }

    /// G4 adds its exact accepted-evidence validator before this constructor
    /// becomes reachable. Keeping the source typed here prevents a competing
    /// Desired publication suffix from appearing in that module.
    #[allow(dead_code, reason = "consumed by the G4 RequireIdle engine")]
    pub(crate) fn require_idle_attempt(
        source: RequireIdleAttemptSource,
        expected_current: DesiredRuntimeSpec,
        desired: DesiredRuntimeSpec,
        placement_snapshots: Vec<PlacementTargetSnapshot>,
        active_guest_digest: Sha256Digest,
        endpoint_records: Vec<EndpointRecordCandidate>,
    ) -> Self {
        Self {
            source: SystemDesiredMutationSource::RequireIdleAttempt(source),
            expected_current,
            desired,
            placement_snapshots,
            active_guest_digest,
            endpoint_records,
        }
    }

    #[allow(dead_code, reason = "consumed by the G4 RequireIdle engine")]
    pub(crate) fn require_idle_busy(
        source: RequireIdleBusySource,
        expected_current: DesiredRuntimeSpec,
        desired: DesiredRuntimeSpec,
        placement_snapshots: Vec<PlacementTargetSnapshot>,
        active_guest_digest: Sha256Digest,
        endpoint_records: Vec<EndpointRecordCandidate>,
    ) -> Self {
        Self {
            source: SystemDesiredMutationSource::RequireIdleBusy(source),
            expected_current,
            desired,
            placement_snapshots,
            active_guest_digest,
            endpoint_records,
        }
    }
}

/// Request-lifetime cancellation/deadline owner for a system mutation. Drop
/// wins only before PostgreSQL COMMIT is claimed; after that, exact Operation
/// replay resolves ambiguity without inventing an API result row.
pub(crate) struct SystemDesiredMutationCommitGuard {
    _cancellation: CoveredCommitCancellation,
    state: CoveredCommitState,
}

/// Role-lifetime owner for system Desired commits that may outlive the async
/// scan iteration which submitted them. Singleton leadership must remain held
/// until every registered owner has either rolled back a pre-COMMIT
/// cancellation or resolved a COMMIT-sent result by exact Operation replay.
#[derive(Clone, Default)]
pub(crate) struct SystemDesiredMutationResolutionOwner {
    resolutions: std::sync::Arc<CommitResolutionRegistry>,
}

impl SystemDesiredMutationResolutionOwner {
    pub(crate) fn close(&self) {
        self.resolutions.close();
    }

    pub(crate) async fn wait_empty(&self) {
        self.resolutions.wait_empty().await;
    }
}

impl SystemDesiredMutationCommitGuard {
    pub(crate) fn new(operation_name: &'static str, absolute_deadline: Instant) -> Self {
        let (cancellation, state) =
            CoveredCommitCancellation::new(operation_name, absolute_deadline);
        Self {
            _cancellation: cancellation,
            state,
        }
    }

    pub(super) fn state(&self) -> CoveredCommitState {
        self.state.clone()
    }

    #[cfg(test)]
    pub(crate) fn commit_was_sent(&self) -> bool {
        self.state.commit_was_sent()
    }

    #[cfg(test)]
    pub(super) fn cancel_before_commit(&self) -> bool {
        self._cancellation.cancel_before_commit()
    }
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
enum DesiredMutationTransactionOutcome {
    Replayed(ApiIdempotencyResult),
    Converged(ApiIdempotencyResult),
    Changed(ApiIdempotencyResult),
    CandidateCollision(CandidateCollision),
    Stale,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ApiIdempotencyResult {
    pub(crate) authenticated_workspace_id: Id,
    pub(crate) canonical_route: AsciiText,
    pub(crate) idempotency_key: AsciiText,
    pub(crate) request_fingerprint: Sha256Digest,
    pub(crate) http_status: u16,
    pub(crate) content_type: Option<ExactContentType>,
    pub(crate) response_body: Vec<u8>,
    pub(crate) created_at: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum CoveredPlannedDesiredMutation {
    Fixed(ExactHttpResponse),
    Mutation {
        request: Box<CoveredDesiredMutationRequest>,
        fixed_collision: Option<(CandidateCollision, ExactHttpResponse)>,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateCollision {
    CatId,
    DiskIdOrName,
    VolumeId,
    EndpointIdOrName,
    Hostname,
    OperationId,
    NetworkId,
    InitializationToken,
    FilesystemUuid,
}

#[derive(Debug)]
pub(crate) enum CoveredCatCreateError {
    CandidateCollision(
        #[cfg_attr(
            not(test),
            allow(
                dead_code,
                reason = "production retries every candidate collision; tests assert the typed cause"
            )
        )]
        CandidateCollision,
    ),
    PlacementStale,
    Store(ApiError),
}

type CoveredCatCreateResult<T> = std::result::Result<T, CoveredCatCreateError>;

#[derive(Debug)]
pub(crate) enum CoveredPersistentDiskCreateError {
    CandidateCollision(CandidateCollision),
    Store(ApiError),
}

type CoveredPersistentDiskCreateResult<T> =
    std::result::Result<T, CoveredPersistentDiskCreateError>;

enum CreateCatTransactionError {
    Authority(AuthorityTransactionError),
    CandidateCollision(CandidateCollision),
    PlacementStale,
}

impl From<AuthorityTransactionError> for CreateCatTransactionError {
    fn from(error: AuthorityTransactionError) -> Self {
        Self::Authority(error)
    }
}

impl From<cats_storage::authority::AuthorityError> for CreateCatTransactionError {
    fn from(error: cats_storage::authority::AuthorityError) -> Self {
        Self::Authority(error.into())
    }
}

impl From<postgres::Error> for CreateCatTransactionError {
    fn from(error: postgres::Error) -> Self {
        Self::Authority(error.into())
    }
}

enum CreatePersistentDiskTransactionError {
    Authority(AuthorityTransactionError),
    CandidateCollision(CandidateCollision),
}

impl From<AuthorityTransactionError> for CreatePersistentDiskTransactionError {
    fn from(error: AuthorityTransactionError) -> Self {
        Self::Authority(error)
    }
}

impl From<cats_storage::authority::AuthorityError> for CreatePersistentDiskTransactionError {
    fn from(error: cats_storage::authority::AuthorityError) -> Self {
        Self::Authority(error.into())
    }
}

impl From<postgres::Error> for CreatePersistentDiskTransactionError {
    fn from(error: postgres::Error) -> Self {
        Self::Authority(error.into())
    }
}

impl From<ApiError> for CreatePersistentDiskTransactionError {
    fn from(error: ApiError) -> Self {
        Self::Authority(error.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IfMatchFingerprint {
    Absent,
    #[cfg_attr(
        not(test),
        allow(
            dead_code,
            reason = "Cat-create has no If-Match; later product mutations use the generation arm"
        )
    )]
    Generation(Generation),
}

/// Computes the one byte-level request fingerprint shared by every covered
/// Workspace product mutation. Envelope validation happens before this
/// boundary; this function deliberately does no JSON/path normalization.
pub(crate) fn api_request_fingerprint(
    authenticated_workspace_id: &Id,
    canonical_route: &AsciiText,
    raw_path_and_query: &[u8],
    if_match: IfMatchFingerprint,
    raw_body: &[u8],
) -> Result<Sha256Digest> {
    let if_match = match if_match {
        IfMatchFingerprint::Absent => vec![0],
        IfMatchFingerprint::Generation(generation) => {
            let mut payload = Vec::with_capacity(9);
            payload.push(1);
            payload.extend_from_slice(&generation.get().to_be_bytes());
            payload
        }
    };
    let mut hasher = Sha256::new();
    hasher.update(b"cats.api-idempotency.v1");
    hasher.update([0]);
    for payload in [
        authenticated_workspace_id.as_str().as_bytes(),
        canonical_route.as_str().as_bytes(),
        raw_path_and_query,
        &if_match,
        raw_body,
    ] {
        let length = u64::try_from(payload.len())
            .map_err(|_| ApiError::invalid("fingerprint frame is too large"))?;
        hasher.update(length.to_be_bytes());
        hasher.update(payload);
    }
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

pub(crate) fn encode_cat_create_accepted_response(
    cat_id: &Id,
    operation_id: &Id,
) -> Result<Vec<u8>> {
    cats_api::cat_create::encode_cat_create_v2_accepted_response(cat_id, operation_id)
        .map_err(internal)
}

pub(crate) fn encode_cat_name_conflict_response() -> Vec<u8> {
    CAT_NAME_CONFLICT_BODY.to_vec()
}

impl Store {
    /// Read one canonical runtime Operation without exposing a global-ID
    /// authority. The row codec validates the JSON record against every
    /// denormalized projection before returning it.
    pub(crate) fn get_runtime_operation(
        &self,
        workspace_id: &Id,
        operation_id: &Id,
    ) -> Result<RuntimeOperationRead> {
        load_operation_by_workspace_unlocked(self, workspace_id, operation_id)
    }

    /// Optional preflight optimization. It never reserves the key and never
    /// reads a resource; the create transaction below always rechecks.
    pub(super) fn covered_api_result_fast_lookup(
        &self,
        request: &ApiIdempotencyRequest,
    ) -> Result<Option<ApiIdempotencyResult>> {
        super::product_rows::load_api_result_unlocked(self, request).and_then(|result| match result
        {
            Some(result) => check_replay(result, &request.request_fingerprint).map(Some),
            None => Ok(None),
        })
    }

    /// Resolves a result after the original transaction crossed commit-send.
    /// The same API-key advisory reservation is the visibility barrier: a
    /// missing row is definitive only after the original transaction has
    /// committed or rolled back and released this lock.
    pub(super) fn covered_api_result_after_commit(
        &self,
        request: &ApiIdempotencyRequest,
    ) -> Result<Option<ApiIdempotencyResult>> {
        self.authority_transaction(|transaction| {
            reserve_api_key(transaction, request)?;
            load_api_result_for_update(transaction, request)?
                .map(|result| check_replay(result, &request.request_fingerprint))
                .transpose()
                .map_err(AuthorityTransactionError::from)
        })
    }

    /// Runs target/ownership reads, domain planning, revalidation, mutation and
    /// exact-result persistence inside the one transaction that reserves the
    /// API key. A stored result or fingerprint conflict is resolved before the
    /// planner is invoked. Any planner error, including NotFound, rolls the
    /// reservation back and persists no result.
    pub(super) fn commit_planned_desired_mutation_covered(
        &self,
        request: &ApiIdempotencyRequest,
        commit_state: &CoveredCommitState,
        mut planner: impl FnMut(&mut Transaction<'_>) -> AuthorityTxResult<CoveredPlannedDesiredMutation>
            + Send,
    ) -> std::result::Result<DesiredMutationCommit, CoveredDesiredMutationError> {
        let mut collision = None;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                reserve_api_key(transaction, request)?;
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                if let Some(result) = load_api_result_for_update(transaction, request)? {
                    let result = check_replay(result, &request.request_fingerprint)
                        .map_err(AuthorityTransactionError::from)?;
                    checkpoint_covered_commit(transaction, Some(commit_state))?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(DesiredMutationTransactionOutcome::Replayed(result));
                }

                checkpoint_covered_commit(transaction, Some(commit_state))?;
                let planned = planner(transaction)?;
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                let outcome = match planned {
                    CoveredPlannedDesiredMutation::Fixed(response) => {
                        let now = database_now(transaction)?;
                        let result = result_from_envelope(request, &response, now);
                        insert_api_result(transaction, &result)?;
                        DesiredMutationTransactionOutcome::Converged(result)
                    }
                    CoveredPlannedDesiredMutation::Mutation {
                        request: mutation,
                        fixed_collision,
                    } => {
                        if mutation.idempotency != *request {
                            return Err(ApiError::internal(
                                "planned Desired mutation changed its covered API identity",
                            )
                            .into());
                        }
                        match commit_desired_mutation_in(
                            transaction,
                            &mutation,
                            Some(commit_state),
                        )? {
                            DesiredMutationTransactionOutcome::CandidateCollision(kind) => {
                                if let Some((fixed_kind, response)) = fixed_collision {
                                    if kind == fixed_kind {
                                        let now = database_now(transaction)?;
                                        let result = result_from_envelope(request, &response, now);
                                        insert_api_result(transaction, &result)?;
                                        DesiredMutationTransactionOutcome::Converged(result)
                                    } else {
                                        collision = Some(kind);
                                        return Err(AuthorityTransactionError::CandidateCollision);
                                    }
                                } else {
                                    collision = Some(kind);
                                    return Err(AuthorityTransactionError::CandidateCollision);
                                }
                            }
                            DesiredMutationTransactionOutcome::Stale => {
                                return Err(AuthorityTransactionError::PlacementStale);
                            }
                            outcome => outcome,
                        }
                    }
                };
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                commit_state.begin_commit(transaction)?;
                Ok(outcome)
            },
            || commit_state.reset_after_definite_retry(),
        );
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(AuthorityExecutionError::CandidateCollision) => {
                return Err(CoveredDesiredMutationError::CandidateCollision(
                    collision.take().ok_or_else(|| {
                        CoveredDesiredMutationError::Store(ApiError::internal(
                            "candidate-collision transaction lost its typed reason",
                        ))
                    })?,
                ));
            }
            Err(AuthorityExecutionError::PlacementStale) => {
                return Err(CoveredDesiredMutationError::Stale);
            }
            Err(AuthorityExecutionError::Store(error)) => {
                return Err(CoveredDesiredMutationError::Store(error));
            }
        };
        match outcome {
            DesiredMutationTransactionOutcome::Replayed(result) => {
                Ok(DesiredMutationCommit::Replayed(result))
            }
            DesiredMutationTransactionOutcome::Converged(result) => {
                Ok(DesiredMutationCommit::Converged(result))
            }
            DesiredMutationTransactionOutcome::Changed(result) => {
                Ok(DesiredMutationCommit::Changed(result))
            }
            DesiredMutationTransactionOutcome::CandidateCollision(_)
            | DesiredMutationTransactionOutcome::Stale => Err(CoveredDesiredMutationError::Store(
                ApiError::internal("planned Desired mutation returned an unrolled control marker"),
            )),
        }
    }

    /// Locate the current Desired revision for a hostname without returning a
    /// copied route binding. Every hit is closed against the immutable
    /// Endpoint product record and the current complete Desired in one
    /// repeatable-read snapshot.
    #[allow(dead_code, reason = "consumed by the later route-signer cutover")]
    pub(crate) fn locate_hostname_desired(
        &self,
        hostname: &Hostname,
    ) -> Result<Option<HostnameDesiredLocation>> {
        self.authority_transaction(|transaction| {
            transaction
                .batch_execute("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")?;
            let Some(lookup) = load_hostname_lookup_unlocked(transaction, hostname)? else {
                return Ok(None);
            };
            let endpoint = load_endpoint_by_id_unlocked(transaction, &lookup.endpoint_id)?
                .ok_or_else(|| stored_corruption("hostname lookup has no EndpointRecord"))?;
            let desired = load_desired_unlocked(transaction, &lookup.cat_id)?
                .ok_or_else(|| stored_corruption("hostname lookup has no current Desired"))?;
            validate_endpoint_lookup(&endpoint, &lookup, &desired)?;
            Ok(Some(HostnameDesiredLocation {
                cat_id: lookup.cat_id,
                endpoint_id: lookup.endpoint_id,
                desired_revision: lookup.desired_revision,
            }))
        })
    }

    #[cfg(test)]
    pub(crate) fn create_cat_covered_with_admission(
        &self,
        request: &CoveredCatCreateRequest,
        planned_admission: &PlacementAdmissionSnapshot,
        active_guest_digest: &Sha256Digest,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        self.create_cat_covered_inner(
            request,
            Some((planned_admission, active_guest_digest)),
            None,
            None,
        )
    }

    pub(super) fn create_cat_covered_with_placement(
        &self,
        request: &CoveredCatCreateRequest,
        planned_target: &PlacementTargetSnapshot,
        planned_mutation: &CatCreatePlacementMutation,
        active_guest_digest: &Sha256Digest,
        commit_state: &CoveredCommitState,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        self.create_cat_covered_inner(
            request,
            None,
            Some((planned_target, planned_mutation, active_guest_digest)),
            Some(commit_state),
        )
    }

    #[cfg(test)]
    pub(super) fn create_cat_covered_without_admission_for_product_test(
        &self,
        request: &CoveredCatCreateRequest,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        self.create_cat_covered_inner(request, None, None, None)
    }

    fn create_cat_covered_inner(
        &self,
        request: &CoveredCatCreateRequest,
        admission: Option<(&PlacementAdmissionSnapshot, &Sha256Digest)>,
        placement: Option<(
            &PlacementTargetSnapshot,
            &CatCreatePlacementMutation,
            &Sha256Digest,
        )>,
        commit_state: Option<&CoveredCommitState>,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        let mut collision = None;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                if let Some(commit_state) = commit_state {
                    commit_state.checkpoint(transaction)?;
                }
                match create_cat_in(transaction, request, admission, placement, commit_state) {
                    Ok(result) => {
                        if let Some(commit_state) = commit_state {
                            commit_state.begin_commit(transaction)?;
                        }
                        Ok(result)
                    }
                    Err(CreateCatTransactionError::Authority(error)) => Err(error),
                    Err(CreateCatTransactionError::CandidateCollision(kind)) => {
                        collision = Some(kind);
                        Err(AuthorityTransactionError::CandidateCollision)
                    }
                    Err(CreateCatTransactionError::PlacementStale) => {
                        Err(AuthorityTransactionError::PlacementStale)
                    }
                }
            },
            || {
                if let Some(commit_state) = commit_state {
                    commit_state.reset_after_definite_retry();
                }
            },
        );
        match result {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) => match collision.take() {
                Some(kind) => Err(CoveredCatCreateError::CandidateCollision(kind)),
                None => Err(CoveredCatCreateError::Store(ApiError::internal(
                    "candidate-collision transaction lost its typed reason",
                ))),
            },
            Err(AuthorityExecutionError::PlacementStale) => {
                Err(CoveredCatCreateError::PlacementStale)
            }
            Err(AuthorityExecutionError::Store(error)) => Err(CoveredCatCreateError::Store(error)),
        }
    }

    pub(super) fn create_persistent_disk_covered(
        &self,
        request: &CoveredPersistentDiskCreateRequest,
        commit_state: &CoveredCommitState,
    ) -> CoveredPersistentDiskCreateResult<ApiIdempotencyResult> {
        self.create_persistent_disk_covered_inner(request, Some(commit_state))
    }

    pub(super) fn begin_disk_delete_covered(
        &self,
        request: &CoveredDiskDeleteRequest,
        commit_state: &CoveredCommitState,
    ) -> Result<ApiIdempotencyResult> {
        match self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                let result = begin_disk_delete_in(transaction, request, Some(commit_state))?;
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                commit_state.begin_commit(transaction)?;
                Ok(result)
            },
            || commit_state.reset_after_definite_retry(),
        ) {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(ApiError::internal(
                "Disk begin-delete returned an impossible candidate collision",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(ApiError::internal(
                "Disk begin-delete returned an impossible placement marker",
            )),
        }
    }

    fn create_persistent_disk_covered_inner(
        &self,
        request: &CoveredPersistentDiskCreateRequest,
        commit_state: Option<&CoveredCommitState>,
    ) -> CoveredPersistentDiskCreateResult<ApiIdempotencyResult> {
        let mut collision = None;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, commit_state)?;
                match create_persistent_disk_in(transaction, request, commit_state) {
                    Ok(result) => {
                        checkpoint_covered_commit(transaction, commit_state)?;
                        if let Some(commit_state) = commit_state {
                            commit_state.begin_commit(transaction)?;
                        }
                        Ok(result)
                    }
                    Err(CreatePersistentDiskTransactionError::Authority(error)) => Err(error),
                    Err(CreatePersistentDiskTransactionError::CandidateCollision(kind)) => {
                        collision = Some(kind);
                        Err(AuthorityTransactionError::CandidateCollision)
                    }
                }
            },
            || {
                if let Some(commit_state) = commit_state {
                    commit_state.reset_after_definite_retry();
                }
            },
        );
        match result {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) => match collision.take() {
                Some(kind) => Err(CoveredPersistentDiskCreateError::CandidateCollision(kind)),
                None => Err(CoveredPersistentDiskCreateError::Store(ApiError::internal(
                    "candidate-collision transaction lost its typed reason",
                ))),
            },
            Err(AuthorityExecutionError::PlacementStale) => {
                Err(CoveredPersistentDiskCreateError::Store(ApiError::internal(
                    "PersistentDisk create returned an impossible placement-stale marker",
                )))
            }
            Err(AuthorityExecutionError::Store(error)) => {
                Err(CoveredPersistentDiskCreateError::Store(error))
            }
        }
    }

    /// Commits one covered current-Desired mutation. The transaction begins
    /// with the exact API replay key, then locks every affected NodeIdentity in
    /// canonical order before Cat/Desired/Operation. A stale plan is returned
    /// without an idempotency result so the service can re-read and re-plan.
    #[allow(
        dead_code,
        reason = "A1 freezes the Desired commit boundary before A2/G4 production routes consume it"
    )]
    pub(super) fn commit_desired_mutation_covered(
        &self,
        request: &CoveredDesiredMutationRequest,
        commit_state: &CoveredCommitState,
    ) -> std::result::Result<DesiredMutationCommit, CoveredDesiredMutationError> {
        let mut collision = None;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                match commit_desired_mutation_in(transaction, request, Some(commit_state))? {
                    DesiredMutationTransactionOutcome::CandidateCollision(kind) => {
                        collision = Some(kind);
                        Err(AuthorityTransactionError::CandidateCollision)
                    }
                    DesiredMutationTransactionOutcome::Stale => {
                        Err(AuthorityTransactionError::PlacementStale)
                    }
                    outcome => {
                        checkpoint_covered_commit(transaction, Some(commit_state))?;
                        commit_state.begin_commit(transaction)?;
                        Ok(outcome)
                    }
                }
            },
            || commit_state.reset_after_definite_retry(),
        );
        let outcome = match result {
            Ok(outcome) => outcome,
            Err(AuthorityExecutionError::CandidateCollision) => {
                return Err(CoveredDesiredMutationError::CandidateCollision(
                    collision.take().ok_or_else(|| {
                        CoveredDesiredMutationError::Store(ApiError::internal(
                            "candidate-collision transaction lost its typed reason",
                        ))
                    })?,
                ));
            }
            Err(AuthorityExecutionError::PlacementStale) => {
                return Err(CoveredDesiredMutationError::Stale);
            }
            Err(AuthorityExecutionError::Store(error)) => {
                return Err(CoveredDesiredMutationError::Store(error));
            }
        };
        match outcome {
            DesiredMutationTransactionOutcome::Replayed(result) => {
                Ok(DesiredMutationCommit::Replayed(result))
            }
            DesiredMutationTransactionOutcome::Converged(result) => {
                Ok(DesiredMutationCommit::Converged(result))
            }
            DesiredMutationTransactionOutcome::Changed(result) => {
                Ok(DesiredMutationCommit::Changed(result))
            }
            DesiredMutationTransactionOutcome::CandidateCollision(_)
            | DesiredMutationTransactionOutcome::Stale => Err(CoveredDesiredMutationError::Store(
                ApiError::internal("covered Desired mutation returned an unrolled control marker"),
            )),
        }
    }
}

fn begin_disk_delete_in(
    transaction: &mut Transaction<'_>,
    request: &CoveredDiskDeleteRequest,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<ApiIdempotencyResult> {
    checkpoint_covered_commit(transaction, commit_state)?;
    reserve_api_key(transaction, &request.idempotency)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        return check_replay(result, &request.idempotency.request_fingerprint)
            .map_err(AuthorityTransactionError::from);
    }
    let context = PersistentDiskDeleteContext {
        authenticated_workspace_id: request.idempotency.authenticated_workspace_id.clone(),
        disk_id: request.disk_id.clone(),
        delete_id: request.delete_id.clone(),
        active_guest_config_digest: request.active_guest_digest.clone(),
    };
    let mut checkpoint =
        |transaction: &mut Transaction<'_>| checkpoint_covered_commit(transaction, commit_state);
    let result = match begin_persistent_disk_delete_in(transaction, &context, &mut checkpoint) {
        Ok(result) => result,
        // NotFound also covers another Workspace's Disk. Returning an error
        // rolls back the transaction-scoped API-key reservation and preserves
        // the frozen zero-persistent-side-effect rule.
        Err(error @ AuthorityTransactionError::Domain(AuthorityError::NotFound)) => {
            return Err(error);
        }
        Err(AuthorityTransactionError::Domain(
            AuthorityError::OtherWriter
            | AuthorityError::Fenced
            | AuthorityError::StaleTransition
            | AuthorityError::EpochExhausted
            | AuthorityError::AdminBusy
            | AuthorityError::HeadConflict
            | AuthorityError::SnapshotInUse
            | AuthorityError::InvalidAuthorization,
        )) => {
            return store_fixed_disk_delete_result(
                transaction,
                &request.idempotency,
                412,
                DISK_DELETE_PRECONDITION_BODY,
            );
        }
        Err(error) => return Err(error),
    };
    let body = serde_json::to_vec(&result).map_err(stored_corruption_from_debug)?;
    let now = database_now(transaction)?;
    let response = ExactHttpResponse::new(202, Some(ExactContentType::ApplicationJson), body)
        .map_err(AuthorityTransactionError::from)?;
    let result = result_from_envelope(&request.idempotency, &response, now);
    insert_api_result(transaction, &result)?;
    Ok(result)
}

fn store_fixed_disk_delete_result(
    transaction: &mut Transaction<'_>,
    request: &ApiIdempotencyRequest,
    status: u16,
    body: &[u8],
) -> AuthorityTxResult<ApiIdempotencyResult> {
    let now = database_now(transaction)?;
    let response = ExactHttpResponse::new(
        status,
        Some(ExactContentType::ApplicationJson),
        body.to_vec(),
    )
    .map_err(AuthorityTransactionError::from)?;
    let result = result_from_envelope(request, &response, now);
    insert_api_result(transaction, &result)?;
    Ok(result)
}

impl Store {
    /// Read one stable-ID page of currently Running Desired rows for the
    /// production BillingEnforcer. This is deliberately a hint page: funding
    /// is checked outside the Control transaction and the mutation below
    /// performs an exact revision CAS before changing authority.
    pub(crate) fn billing_desired_candidates_after(
        &self,
        after: Option<&Id>,
        limit: usize,
    ) -> Result<Vec<BillingDesiredCandidate>> {
        if limit == 0 || limit > 256 {
            return Err(ApiError::invalid(
                "BillingEnforcer page size must be in 1..=256",
            ));
        }
        let after = after.map(Id::as_str);
        let limit = i64::try_from(limit).map_err(internal)?;
        self.authority_read_snapshot(|transaction| {
            let rows = transaction.query(
                "SELECT cat_id
                       FROM desired_runtime_specs
                      WHERE (target='running' OR record->>'target'='running')
                        AND ($1::TEXT IS NULL OR cat_id COLLATE \"C\" > $1 COLLATE \"C\")
                      ORDER BY cat_id COLLATE \"C\"
                      LIMIT $2",
                &[&after, &limit],
            )?;
            let mut candidates = Vec::with_capacity(rows.len());
            for row in rows {
                let cat_id = Id::new(row.try_get::<_, String>("cat_id")?)
                    .ok_or_else(|| stored_corruption("billing candidate Cat ID is malformed"))?;
                let desired = load_desired_unlocked(transaction, &cat_id)?
                    .ok_or_else(|| stored_corruption("billing candidate Desired disappeared"))?;
                if desired.target != RuntimeTarget::Running {
                    return Err(stored_corruption(
                        "billing candidate Running projection is inconsistent",
                    ));
                }
                candidates.push(BillingDesiredCandidate {
                    cat_id,
                    workspace_id: desired.workspace_id,
                    desired_revision: desired.desired_revision,
                });
            }
            Ok(candidates)
        })
    }

    /// Publish one typed system-domain mutation through the same guarded A1
    /// suffix as Workspace lifecycle APIs. The caller supplies neither an API
    /// replay key nor an Operation ID.
    pub(super) fn commit_system_desired_mutation(
        &self,
        request: &SystemDesiredMutationRequest,
        commit_state: &CoveredCommitState,
    ) -> Result<SystemDesiredMutationCommit> {
        let operation_id = system_operation_id(request)?;
        let volume_mutation = DesiredVolumeMutation::Preserve;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, Some(commit_state))?;
                // A retained Operation is the durable system-domain replay
                // oracle. Resolve it before consulting current Desired or any
                // transient Node/Volume/Endpoint/source evidence: those facts
                // may legitimately have moved or been cleaned after N+2.
                if let Some(operation) = load_operation_unlocked(transaction, &operation_id)? {
                    validate_system_operation_replay(&operation, &operation_id, request)?;
                    return Ok(DesiredPublicationOutcome::Replayed);
                }
                let publication = DesiredMutationPublication {
                    expected_current: &request.expected_current,
                    desired: &request.desired,
                    operation_id: &operation_id,
                    placement_snapshots: &request.placement_snapshots,
                    active_guest_digest: &request.active_guest_digest,
                    endpoint_records: &request.endpoint_records,
                    volume_mutation: &volume_mutation,
                    require_idle_open_busy_proof: None,
                    exact_replay: true,
                    system_request: Some(request),
                };
                let outcome =
                    commit_desired_publication_in(transaction, publication, Some(commit_state))?;
                if matches!(outcome, DesiredPublicationOutcome::Changed { .. }) {
                    commit_state.begin_commit(transaction)?;
                }
                Ok(outcome)
            },
            || commit_state.reset_after_definite_retry(),
        );
        match result {
            Ok(DesiredPublicationOutcome::Changed { .. }) => {
                Ok(SystemDesiredMutationCommit::Changed)
            }
            Ok(DesiredPublicationOutcome::Replayed) => Ok(SystemDesiredMutationCommit::Replayed),
            Ok(DesiredPublicationOutcome::Stale) => Ok(SystemDesiredMutationCommit::Stale),
            Ok(DesiredPublicationOutcome::Converged { .. }) => Err(ApiError::internal(
                "system Desired mutation unexpectedly converged without its stable event",
            )),
            Ok(DesiredPublicationOutcome::CandidateCollision(_)) => Err(ApiError::internal(
                "derived system Operation identity collided with another event",
            )),
            Err(AuthorityExecutionError::Store(error)) => Err(error),
            Err(AuthorityExecutionError::CandidateCollision) => Err(ApiError::internal(
                "system Desired mutation returned an impossible candidate marker",
            )),
            Err(AuthorityExecutionError::PlacementStale) => Err(ApiError::internal(
                "system Desired mutation returned an impossible placement marker",
            )),
        }
    }

    /// Resolve one Billing domain decision through the system mutation's
    /// stable Operation identity. A COMMIT response loss is retried as an
    /// exact read of the retained Operation; no ApiIdempotencyResult is
    /// fabricated for this non-HTTP domain.
    pub(crate) async fn commit_billing_exhaustion(
        self: &std::sync::Arc<Self>,
        candidate: BillingDesiredCandidate,
        decision: BillingExhaustionDecision,
        absolute_deadline: Instant,
        resolution_owner: &SystemDesiredMutationResolutionOwner,
    ) -> Result<SystemDesiredMutationCommit> {
        let planned_candidate = candidate.clone();
        let request = self
            .execute(move |store| store.prepare_billing_exhaustion(&planned_candidate, decision))
            .await?;
        let Some(request) = request else {
            return Ok(SystemDesiredMutationCommit::Stale);
        };
        self.resolve_system_desired_mutation(
            request,
            "Billing system Desired mutation",
            absolute_deadline,
            resolution_owner,
        )
        .await
    }

    async fn resolve_system_desired_mutation(
        self: &std::sync::Arc<Self>,
        request: SystemDesiredMutationRequest,
        operation_name: &'static str,
        absolute_deadline: Instant,
        resolution_owner: &SystemDesiredMutationResolutionOwner,
    ) -> Result<SystemDesiredMutationCommit> {
        let request = std::sync::Arc::new(request);
        let guard = SystemDesiredMutationCommitGuard::new(operation_name, absolute_deadline);
        let Some(active) = resolution_owner.resolutions.begin() else {
            return Err(ApiError::unavailable(
                "Billing system Desired mutation role is stopping",
            ));
        };
        let store = std::sync::Arc::clone(self);
        let commit_request = std::sync::Arc::clone(&request);
        let state = guard.state();
        let observer = state.clone();
        let (result_tx, result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            // Always await the Store execution after it has been admitted. If
            // the role future is cancelled, dropping its guard marks PRE_COMMIT
            // work cancelled; an already-claimed closure must still reach a
            // physical rollback/commit result before this owner is released.
            let execution_store = std::sync::Arc::clone(&store);
            let mut outcome = execution_store
                .execute(move |store| store.commit_system_desired_mutation(&commit_request, &state))
                .await;
            while let Err(error) = &outcome {
                if !observer.commit_was_sent() {
                    break;
                }
                tracing::warn!(
                    %error,
                    "resolving ambiguous Billing system Desired commit by exact replay"
                );
                tokio::time::sleep(std::time::Duration::from_millis(25)).await;
                let replay_request = std::sync::Arc::clone(&request);
                let replay_state = observer.clone();
                outcome = store
                    .execute(move |store| {
                        store.commit_system_desired_mutation(&replay_request, &replay_state)
                    })
                    .await;
            }
            let _ = result_tx.send(outcome);
            drop(active);
        });
        // This guard is intentionally held by the scan iteration. Dropping the
        // iteration can cancel only PRE_COMMIT; the registered owner above
        // remains in the singleton role lifetime until exact resolution.
        let result = result_rx.await.map_err(|_| {
            ApiError::internal("Billing system Desired commit owner stopped without a result")
        })?;
        drop(guard);
        result
    }

    #[cfg(test)]
    pub(super) async fn resolve_system_desired_mutation_for_test(
        self: &std::sync::Arc<Self>,
        request: SystemDesiredMutationRequest,
        absolute_deadline: Instant,
        resolution_owner: &SystemDesiredMutationResolutionOwner,
    ) -> Result<SystemDesiredMutationCommit> {
        self.resolve_system_desired_mutation(
            request,
            "system Desired resolution test",
            absolute_deadline,
            resolution_owner,
        )
        .await
    }

    fn prepare_billing_exhaustion(
        &self,
        candidate: &BillingDesiredCandidate,
        decision: BillingExhaustionDecision,
    ) -> Result<Option<SystemDesiredMutationRequest>> {
        self.authority_read_snapshot(|transaction| {
            let Some(current) = load_desired_unlocked(transaction, &candidate.cat_id)? else {
                return Ok(None);
            };
            if current.workspace_id != candidate.workspace_id
                || current.desired_revision != candidate.desired_revision
                || current.target != RuntimeTarget::Running
            {
                return Ok(None);
            }
            let endpoint_records = current
                .endpoints
                .iter()
                .map(|intent| {
                    load_endpoint_by_id_unlocked(transaction, &intent.endpoint_id)?
                        .map(|record| EndpointRecordCandidate {
                            endpoint_id: record.endpoint_id,
                            workspace_id: record.workspace_id,
                            cat_id: record.cat_id,
                            name: record.name,
                        })
                        .ok_or_else(|| {
                            stored_corruption("billing candidate Endpoint record disappeared")
                        })
                })
                .collect::<AuthorityTxResult<Vec<_>>>()?;
            let active_guest_digest = current.runtime.guest_config_digest.clone();
            SystemDesiredMutationRequest::billing_exhaustion(
                current,
                decision.clone(),
                active_guest_digest,
                endpoint_records,
            )
            .map(Some)
            .map_err(Into::into)
        })
    }

    #[cfg(test)]
    pub(super) fn commit_billing_cold(
        &self,
        candidate: &BillingDesiredCandidate,
    ) -> Result<BillingDesiredCommit> {
        let ledger = self.billing_ledger_for_workspace(candidate.workspace_id.as_str())?;
        let loaded = self.authority_read_snapshot(|transaction| {
            let Some(current) = load_desired_unlocked(transaction, &candidate.cat_id)? else {
                return Ok(None);
            };
            if current.workspace_id != candidate.workspace_id
                || current.desired_revision != candidate.desired_revision
                || current.target != RuntimeTarget::Running
            {
                return Ok(None);
            }
            let endpoint_records = current
                .endpoints
                .iter()
                .map(|intent| {
                    load_endpoint_by_id_unlocked(transaction, &intent.endpoint_id)?
                        .map(|record| EndpointRecordCandidate {
                            endpoint_id: record.endpoint_id,
                            workspace_id: record.workspace_id,
                            cat_id: record.cat_id,
                            name: record.name,
                        })
                        .ok_or_else(|| {
                            stored_corruption("billing candidate Endpoint record disappeared")
                        })
                })
                .collect::<AuthorityTxResult<Vec<_>>>()?;
            Ok(Some((current, endpoint_records)))
        })?;
        let Some((current, endpoint_records)) = loaded else {
            return Ok(BillingDesiredCommit::Stale);
        };
        let request = SystemDesiredMutationRequest::billing_exhaustion(
            current.clone(),
            BillingExhaustionDecision {
                billing_account_id: ledger.billing_account_id.clone(),
                account_id: ledger.account_id.clone(),
                credit_nanos: 0,
                usage_nanos: 1,
                usage_visible_through_unix_ms: Some(1),
                rate_card_id: "test-rate-card-v1".to_string(),
            },
            current.runtime.guest_config_digest.clone(),
            endpoint_records,
        )?;
        let guard = SystemDesiredMutationCommitGuard::new(
            "test Billing mutation",
            Instant::now() + std::time::Duration::from_secs(5),
        );
        let state = guard.state();
        self.commit_system_desired_mutation(&request, &state)
    }
}

fn validate_system_desired_mutation_source(
    transaction: &mut Transaction<'_>,
    request: &SystemDesiredMutationRequest,
) -> AuthorityTxResult<()> {
    match &request.source {
        SystemDesiredMutationSource::BillingExhaustion(decision) => {
            let exhausted = i128::try_from(decision.usage_nanos)
                .map_or(true, |usage| decision.credit_nanos <= usage);
            if decision.billing_account_id.is_empty()
                || decision.account_id.is_empty()
                || decision.rate_card_id.is_empty()
                || !exhausted
                || request.expected_current.target != RuntimeTarget::Running
                || request.desired.target != RuntimeTarget::Cold
            {
                return Err(ApiError::invalid(
                    "BillingExhaustion source is incomplete or not exhausted",
                )
                .into());
            }
            let Some(row) = transaction.query_opt(
                "SELECT account.id, account.billing_account_id
                   FROM workspaces workspace
                   JOIN accounts account ON account.id=workspace.account_id
                  WHERE workspace.id=$1",
                &[&request.expected_current.workspace_id.as_str()],
            )?
            else {
                return Err(stored_corruption(
                    "Billing source Workspace has no Account authority",
                ));
            };
            if row.try_get::<_, String>(0)? != decision.account_id
                || row.try_get::<_, String>(1)? != decision.billing_account_id
            {
                return Err(ApiError::conflict(
                    "Billing exhaustion decision belongs to another Account",
                )
                .into());
            }
            Ok(())
        }
        // G4 composes exact accepted checkpoint/Condition validation here.
        // Until then these variants are typed but mechanically fail closed.
        SystemDesiredMutationSource::RequireIdleAttempt(_)
        | SystemDesiredMutationSource::RequireIdleBusy(_) => Err(ApiError::unavailable(
            "RequireIdle system mutation proof validator is not composed",
        )
        .into()),
    }
}

fn system_operation_id(request: &SystemDesiredMutationRequest) -> Result<Id> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.system-desired-operation.v1")?;
    hash_frame(
        &mut hasher,
        request.expected_current.cat_id.as_str().as_bytes(),
    )?;
    match &request.source {
        SystemDesiredMutationSource::BillingExhaustion(decision) => {
            hash_frame(&mut hasher, b"billing-exhaustion")?;
            // The same Account balance projection can recur after a funded
            // restart. Bind the decision to the exact Running source revision
            // so a later exhaustion cycle cannot collide with its old
            // retained Operation.
            hash_frame(
                &mut hasher,
                &request
                    .expected_current
                    .desired_revision
                    .get()
                    .to_be_bytes(),
            )?;
            hash_frame(&mut hasher, decision.billing_account_id.as_bytes())?;
            hash_frame(&mut hasher, decision.account_id.as_bytes())?;
            hash_frame(&mut hasher, decision.credit_nanos.to_string().as_bytes())?;
            hash_frame(&mut hasher, decision.usage_nanos.to_string().as_bytes())?;
            hash_frame(
                &mut hasher,
                decision
                    .usage_visible_through_unix_ms
                    .map_or_else(|| "none".to_string(), |value| value.to_string())
                    .as_bytes(),
            )?;
            hash_frame(&mut hasher, decision.rate_card_id.as_bytes())?;
        }
        SystemDesiredMutationSource::RequireIdleAttempt(source) => {
            hash_frame(&mut hasher, b"require-idle-attempt")?;
            hash_require_idle_identity(
                &mut hasher,
                &source.attempt_id,
                source.source_revision,
                &source.source_runtime_incarnation,
            )?;
        }
        SystemDesiredMutationSource::RequireIdleBusy(source) => {
            hash_frame(&mut hasher, b"require-idle-busy")?;
            hash_require_idle_identity(
                &mut hasher,
                &source.attempt_id,
                source.source_revision,
                &source.source_runtime_incarnation,
            )?;
        }
    }
    Id::new(format!("op_system_{}", hex::encode(hasher.finalize())))
        .ok_or_else(|| ApiError::internal("derived system Operation ID is malformed"))
}

fn hash_require_idle_identity(
    hasher: &mut Sha256,
    attempt_id: &RandomId128,
    source_revision: Revision,
    source_runtime_incarnation: &RandomId128,
) -> Result<()> {
    hash_frame(hasher, attempt_id.as_str().as_bytes())?;
    hash_frame(hasher, &source_revision.get().to_be_bytes())?;
    hash_frame(hasher, source_runtime_incarnation.as_str().as_bytes())
}

fn hash_frame(hasher: &mut Sha256, payload: &[u8]) -> Result<()> {
    let len = u64::try_from(payload.len())
        .map_err(|_| ApiError::internal("system event identity frame is too large"))?;
    hasher.update(len.to_be_bytes());
    hasher.update(payload);
    Ok(())
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn commit_desired_mutation_in(
    transaction: &mut Transaction<'_>,
    request: &CoveredDesiredMutationRequest,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<DesiredMutationTransactionOutcome> {
    checkpoint_covered_commit(transaction, commit_state)?;
    reserve_api_key(transaction, &request.idempotency)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        let result = check_replay(result, &request.idempotency.request_fingerprint)?;
        return Ok(DesiredMutationTransactionOutcome::Replayed(result));
    }
    validate_desired_mutation_request(request)?;
    let publication = DesiredMutationPublication {
        expected_current: &request.expected_current,
        desired: &request.desired,
        operation_id: &request.operation_id,
        placement_snapshots: &request.placement_snapshots,
        active_guest_digest: &request.active_guest_digest,
        endpoint_records: &request.endpoint_records,
        volume_mutation: &request.volume_mutation,
        require_idle_open_busy_proof: request.require_idle_open_busy_proof.as_ref(),
        exact_replay: false,
        system_request: None,
    };
    match commit_desired_publication_in(transaction, publication, commit_state)? {
        DesiredPublicationOutcome::Converged { revision, now } => {
            let response = desired_mutation_converged_response(revision)?;
            let result = result_from_envelope(&request.idempotency, &response, now);
            insert_api_result(transaction, &result)?;
            Ok(DesiredMutationTransactionOutcome::Converged(result))
        }
        DesiredPublicationOutcome::Changed { now } => {
            let response = desired_mutation_accepted_response(
                request.desired.desired_revision,
                &request.operation_id,
            )?;
            let result = result_from_envelope(&request.idempotency, &response, now);
            insert_api_result(transaction, &result)?;
            Ok(DesiredMutationTransactionOutcome::Changed(result))
        }
        DesiredPublicationOutcome::CandidateCollision(collision) => Ok(
            DesiredMutationTransactionOutcome::CandidateCollision(collision),
        ),
        DesiredPublicationOutcome::Stale => Ok(DesiredMutationTransactionOutcome::Stale),
        DesiredPublicationOutcome::Replayed => Err(stored_corruption(
            "covered API mutation entered the system exact-replay branch",
        )),
    }
}

struct DesiredMutationPublication<'a> {
    expected_current: &'a DesiredRuntimeSpec,
    desired: &'a DesiredRuntimeSpec,
    operation_id: &'a Id,
    placement_snapshots: &'a [PlacementTargetSnapshot],
    active_guest_digest: &'a Sha256Digest,
    endpoint_records: &'a [EndpointRecordCandidate],
    volume_mutation: &'a DesiredVolumeMutation,
    require_idle_open_busy_proof: Option<&'a RequireIdleOpenBusyProof>,
    exact_replay: bool,
    system_request: Option<&'a SystemDesiredMutationRequest>,
}

enum DesiredPublicationOutcome {
    Changed { now: UnixMillis },
    Converged { revision: Revision, now: UnixMillis },
    Replayed,
    CandidateCollision(CandidateCollision),
    Stale,
}

/// The one A1 publication suffix shared by Workspace-covered and typed system
/// mutations. Domain callers choose neither the row lock order nor the
/// Supersede/Operation protocol.
fn commit_desired_publication_in(
    transaction: &mut Transaction<'_>,
    publication: DesiredMutationPublication<'_>,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<DesiredPublicationOutcome> {
    let mutation_class = validate_desired_mutation_bundle(
        publication.expected_current,
        publication.desired,
        publication.placement_snapshots,
        publication.active_guest_digest,
        publication.endpoint_records,
        publication.volume_mutation,
        publication.require_idle_open_busy_proof,
    )?;
    checkpoint_covered_commit(transaction, commit_state)?;

    match mutation_class {
        DesiredMutationClass::SourceOnly => {
            let nodes = BTreeSet::from([
                publication.expected_current.placement.node_id.clone(),
                publication.desired.placement.node_id.clone(),
            ]);
            for node_id in nodes {
                checkpoint_covered_commit(transaction, commit_state)?;
                let identity = load_identity_by_node_for_update(transaction, &node_id)?
                    .ok_or_else(|| {
                        stored_corruption(
                            "assigned current Desired has no NodeIdentity coordination row",
                        )
                    })?;
                if identity.state != NodeIdentityState::Provisioned {
                    return Err(stored_corruption(
                        "assigned current Desired refers to a retired NodeIdentity",
                    ));
                }
            }
        }
        DesiredMutationClass::PlacementRequired => {
            for planned in publication.placement_snapshots {
                checkpoint_covered_commit(transaction, commit_state)?;
                let expected = &planned.admission.node_identity;
                let Some(current) =
                    load_identity_by_node_for_update(transaction, &expected.node_id)?
                else {
                    return Ok(DesiredPublicationOutcome::Stale);
                };
                if current.state != NodeIdentityState::Provisioned || current != *expected {
                    return Ok(DesiredPublicationOutcome::Stale);
                }
            }
            for planned in publication.placement_snapshots {
                let mut checkpoint = |transaction: &mut Transaction<'_>| {
                    checkpoint_covered_commit(transaction, commit_state)
                };
                if revalidate_desired_mutation_placement_after_identity_locks(
                    transaction,
                    planned,
                    publication.active_guest_digest,
                    &mut checkpoint,
                )? == PlacementCommitLoad::Stale
                {
                    return Ok(DesiredPublicationOutcome::Stale);
                }
            }
            checkpoint_covered_commit(transaction, commit_state)?;
            if revalidate_desired_mutation_post_assignment(
                publication.placement_snapshots,
                publication.expected_current,
                publication.desired,
                publication.active_guest_digest,
            )? == PlacementCommitLoad::Stale
            {
                return Ok(DesiredPublicationOutcome::Stale);
            }
        }
    }

    // Domain evidence sits after the complete NodeIdentity/placement prefix
    // and before Volume/Cat/Desired. An exact replay skips transient evidence:
    // the stable source-derived Operation plus current==desired is its durable
    // oracle even when a later observation replaced the original Busy fact.
    if let Some(request) = publication.system_request {
        checkpoint_covered_commit(transaction, commit_state)?;
        let current = load_desired_unlocked(transaction, &request.expected_current.cat_id)?;
        match current {
            Some(current) if publication.exact_replay && current == request.desired => {}
            Some(current) if current == request.expected_current => {
                validate_system_desired_mutation_source(transaction, request)?;
            }
            _ => return Ok(DesiredPublicationOutcome::Stale),
        }
    }

    if let Some(proof) = publication.require_idle_open_busy_proof {
        checkpoint_covered_commit(transaction, commit_state)?;
        if !validate_require_idle_open_busy_proof_in(
            transaction,
            publication.expected_current,
            proof,
        )? {
            return Ok(DesiredPublicationOutcome::Stale);
        }
    }

    if publication.expected_current.placement.node_id != publication.desired.placement.node_id {
        let network_id = &publication.desired.runtime.network_config.network_id;
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_id(transaction, "network", network_id)?;
        if load_desired_by_network_id_unlocked(transaction, network_id)?.is_some() {
            return Ok(DesiredPublicationOutcome::CandidateCollision(
                CandidateCollision::NetworkId,
            ));
        }
    }

    let locked_volumes =
        lock_desired_mutation_volumes(transaction, publication.expected_current, commit_state)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    let Some(cat) = load_cat_by_id_for_update(transaction, &publication.expected_current.cat_id)?
    else {
        return Err(stored_corruption(
            "current Desired has no immutable Cat row",
        ));
    };
    if cat.workspace_id != publication.expected_current.workspace_id {
        return Err(stored_corruption(
            "current Desired belongs to another Workspace",
        ));
    }
    validate_desired_mutation_disks(
        transaction,
        publication.expected_current,
        publication.desired,
        publication.volume_mutation,
        &locked_volumes,
        commit_state,
    )?;

    checkpoint_covered_commit(transaction, commit_state)?;
    let Some(current) = load_desired_for_update(transaction, &publication.expected_current.cat_id)?
    else {
        return Ok(DesiredPublicationOutcome::Stale);
    };
    if current != *publication.expected_current {
        if publication.exact_replay && current == *publication.desired {
            validate_existing_endpoints(transaction, &cat, &current, commit_state)?;
            checkpoint_covered_commit(transaction, commit_state)?;
            let Some(operation) = load_operation_for_update(transaction, publication.operation_id)?
            else {
                return Ok(DesiredPublicationOutcome::Stale);
            };
            validate_operation_binding(&operation, &current)?;
            if operation.operation_id != *publication.operation_id {
                return Err(stored_corruption(
                    "system replay Operation identity changed",
                ));
            }
            return Ok(DesiredPublicationOutcome::Replayed);
        }
        return Ok(DesiredPublicationOutcome::Stale);
    }

    lock_desired_mutation_endpoint_graph(
        transaction,
        &cat,
        &current,
        publication.desired,
        publication.endpoint_records,
        commit_state,
    )?;
    validate_existing_endpoints(transaction, &cat, &current, commit_state)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    let converged = desired_semantics_equal(&current, publication.desired)?;
    if let Some(collision) = validate_mutation_endpoint_candidates(
        transaction,
        publication.expected_current,
        publication.desired,
        publication.endpoint_records,
        converged,
    )? {
        return Ok(DesiredPublicationOutcome::CandidateCollision(collision));
    }

    let row_capability = DesiredMutationRowCapability { _private: () };
    checkpoint_covered_commit(transaction, commit_state)?;
    let Some(mut current_operation) = load_operation_by_cat_revision_for_update(
        transaction,
        &row_capability,
        &current.cat_id,
        current.desired_revision,
    )?
    else {
        return Err(stored_corruption("current Desired has no exact Operation"));
    };
    validate_operation_binding(&current_operation, &current)?;
    if current_operation.phase == OperationPhase::Superseded {
        return Err(stored_corruption(
            "current Desired is bound to an already-superseded Operation",
        ));
    }
    let pending = load_pending_operation_by_cat_for_update(transaction, &current.cat_id)?;
    match (&pending, current_operation.phase) {
        (Some(pending), OperationPhase::Pending) if pending == &current_operation => {}
        (None, OperationPhase::Succeeded | OperationPhase::Failed) => {}
        _ => {
            return Err(stored_corruption(
                "current Desired has an inconsistent Pending Operation set",
            ));
        }
    }

    if converged {
        checkpoint_covered_commit(transaction, commit_state)?;
        return Ok(DesiredPublicationOutcome::Converged {
            revision: current.desired_revision,
            now: database_now(transaction)?,
        });
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "operation", publication.operation_id)?;
    if load_operation_for_update(transaction, publication.operation_id)?.is_some() {
        return Ok(DesiredPublicationOutcome::CandidateCollision(
            CandidateCollision::OperationId,
        ));
    }
    let now = database_now(transaction)?;
    if current_operation.phase == OperationPhase::Pending {
        current_operation.phase = OperationPhase::Superseded;
        current_operation.terminal = Some(OperationTerminal::Superseded {
            superseded_by_revision: publication.desired.desired_revision,
            superseded_by_operation_id: publication.operation_id.clone(),
            completed_at_unix_ms: now,
        });
        current_operation.updated_at_unix_ms = now;
        update_operation(transaction, &current_operation)?;
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    insert_missing_mutation_endpoint_records(transaction, publication.endpoint_records, now)?;
    let old_lookup_count = u64::try_from(current.endpoints.len()).map_err(|_| {
        stored_corruption("current Desired endpoint count does not fit PostgreSQL row count")
    })?;
    if delete_hostname_lookups_by_cat(transaction, &row_capability, &current.cat_id)?
        != old_lookup_count
    {
        return Err(stored_corruption(
            "current Desired hostname lookup set changed under its Cat lock",
        ));
    }
    if !replace_desired(transaction, &row_capability, &current, publication.desired)? {
        return Err(stored_corruption(
            "locked exact current Desired lost its scalar CAS before replacement",
        ));
    }
    for endpoint in &publication.desired.endpoints {
        insert_hostname_lookup(
            transaction,
            &HostnameDesiredLookup {
                hostname: endpoint.hostname.clone(),
                workspace_id: publication.desired.workspace_id.clone(),
                cat_id: publication.desired.cat_id.clone(),
                endpoint_id: endpoint.endpoint_id.clone(),
                desired_revision: publication.desired.desired_revision,
            },
        )?;
    }
    checkpoint_covered_commit(transaction, commit_state)?;
    insert_operation(
        transaction,
        &Operation {
            version: ContractVersion::V1,
            operation_id: publication.operation_id.clone(),
            workspace_id: publication.desired.workspace_id.clone(),
            cat_id: publication.desired.cat_id.clone(),
            desired_revision: publication.desired.desired_revision,
            desired_spec_digest: publication.desired.spec_digest.clone(),
            placement: publication.desired.placement.clone(),
            target: publication.desired.target,
            phase: OperationPhase::Pending,
            terminal: None,
            created_at_unix_ms: now,
            updated_at_unix_ms: now,
        },
    )?;
    Ok(DesiredPublicationOutcome::Changed { now })
}

fn lock_desired_mutation_volumes(
    transaction: &mut Transaction<'_>,
    desired: &DesiredRuntimeSpec,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<BTreeMap<Id, VolumeRecord>> {
    let mut intents = desired.volumes.iter().collect::<Vec<_>>();
    intents.sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
    let mut volumes = BTreeMap::new();
    for intent in intents {
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_id(transaction, "volume", &intent.volume_id)?;
        checkpoint_covered_commit(transaction, commit_state)?;
        let volume = load_volume_for_update(transaction, &intent.volume_id)?
            .ok_or_else(|| stored_corruption("current Desired Volume disappeared"))?;
        if volume.volume_id != intent.volume_id
            || volume.size_bytes != intent.size_bytes
            || !volume_durability_matches(intent.durability, volume.durability)
            || !matches!(volume.admin_state, VolumeAdminState::Active)
        {
            return Err(stored_corruption(
                "current Desired Volume authority does not match its intent",
            ));
        }
        volumes.insert(intent.volume_id.clone(), volume);
    }
    Ok(volumes)
}

fn validate_desired_mutation_disks(
    transaction: &mut Transaction<'_>,
    expected_current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    volume_mutation: &DesiredVolumeMutation,
    volumes: &BTreeMap<Id, VolumeRecord>,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    let mut intents = expected_current.volumes.iter().collect::<Vec<_>>();
    intents.sort_by(|left, right| left.disk_id.cmp(&right.disk_id));
    for intent in intents {
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_id(transaction, "disk", &intent.disk_id)?;
        checkpoint_covered_commit(transaction, commit_state)?;
        let disk = load_disk_by_id_for_update(transaction, &intent.disk_id)?
            .ok_or_else(|| stored_corruption("current Desired Disk disappeared"))?;
        let volume = volumes
            .get(&intent.volume_id)
            .ok_or_else(|| stored_corruption("locked Desired Volume set is incomplete"))?;
        let role_matches = matches!(
            (&intent.disk_kind, &disk.role),
            (DiskKind::Root, DiskRole::Root { cat_id }) if cat_id == &expected_current.cat_id
        ) || matches!(
            (&intent.disk_kind, &disk.role),
            (DiskKind::Persistent, DiskRole::Persistent { .. })
        );
        if disk.disk_id != intent.disk_id
            || disk.workspace_id != expected_current.workspace_id
            || disk.volume_id != intent.volume_id
            || disk.size_bytes != intent.size_bytes
            || !volume_durability_matches(intent.durability, disk.durability)
            || !matches!(disk.admin_state, DiskAdminState::Active)
            || !role_matches
            || matches!(
                &disk.role,
                DiskRole::Persistent { initialization }
                    if !persistent_initialization_matches_mount(
                        initialization,
                        &volume.head,
                        intent.mount.as_ref(),
                    )
            )
        {
            return Err(stored_corruption(
                "current Desired Disk/Volume authority does not match its intent",
            ));
        }
        if let (
            DiskKind::Root,
            DesiredVolumeMutation::DeleteCat { delete_id },
        ) = (&intent.disk_kind, volume_mutation)
        {
            // Cat delete may create this authorization only after the exact
            // Deleted revision is current. Seeing it before publication means
            // another authority acted out of order, so fail closed.
            if volume_has_disposable_root_authorization_for_delete(
                transaction,
                &intent.volume_id,
                delete_id,
                desired.desired_revision,
                desired.placement.placement_epoch,
            )? {
                return Err(stored_corruption(
                    "disposable Root authorization predates its Deleted Desired",
                ));
            }
        }
    }
    Ok(())
}

fn volume_durability_matches(desired: Durability, stored: VolumeDurability) -> bool {
    matches!(
        (desired, stored),
        (Durability::Strict, VolumeDurability::Strict)
            | (Durability::Relaxed, VolumeDurability::Relaxed)
    )
}

fn create_persistent_disk_in(
    transaction: &mut Transaction<'_>,
    request: &CoveredPersistentDiskCreateRequest,
    commit_state: Option<&CoveredCommitState>,
) -> std::result::Result<ApiIdempotencyResult, CreatePersistentDiskTransactionError> {
    checkpoint_covered_commit(transaction, commit_state)?;
    reserve_api_key(transaction, &request.idempotency)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        return check_replay(result, &request.idempotency.request_fingerprint)
            .map_err(AuthorityTransactionError::from)
            .map_err(CreatePersistentDiskTransactionError::from);
    }

    validate_persistent_disk_candidate(request).map_err(AuthorityTransactionError::from)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_disk_name(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if let Some(peeked_disk) = load_any_disk_by_name_unlocked(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )? {
        validate_existing_disk_for_name_conflict(transaction, &peeked_disk, commit_state)?;
        checkpoint_covered_commit(transaction, commit_state)?;
        let now = database_now(transaction)?;
        let result = result_from_envelope(&request.idempotency, &request.name_conflict, now);
        checkpoint_covered_commit(transaction, commit_state)?;
        insert_api_result(transaction, &result)?;
        return Ok(result);
    }

    // The candidate namespace is globally closed in the shared mutation lock
    // order. A collision never reuses part of a bundle; the service retries
    // with four freshly sampled identities.
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &request.candidate.volume_id)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if load_any_volume_by_id_for_update(transaction, &request.candidate.volume_id)?.is_some() {
        return Err(persistent_candidate_collision(CandidateCollision::VolumeId));
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &request.candidate.disk_id)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if load_any_disk_by_id_for_update(transaction, &request.candidate.disk_id)?.is_some() {
        return Err(persistent_candidate_collision(
            CandidateCollision::DiskIdOrName,
        ));
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_text(
        transaction,
        "disk-initialization-token",
        request.candidate.initialization_token.as_str(),
    )?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if load_any_disk_by_initialization_token_for_update(
        transaction,
        &request.candidate.initialization_token,
    )?
    .is_some()
    {
        return Err(persistent_candidate_collision(
            CandidateCollision::InitializationToken,
        ));
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_text(
        transaction,
        "disk-filesystem-uuid",
        request.candidate.filesystem_uuid.as_str(),
    )?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if load_any_disk_by_filesystem_uuid_for_update(transaction, &request.candidate.filesystem_uuid)?
        .is_some()
    {
        return Err(persistent_candidate_collision(
            CandidateCollision::FilesystemUuid,
        ));
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    let now = database_now(transaction)?;
    let blank_head = RemoteHead {
        generation: Generation::new(0).expect("zero is a valid Generation"),
        root_hash: None,
        root_object_id: None,
    };
    let volume = VolumeRecord {
        volume_id: request.candidate.volume_id.clone(),
        size_bytes: request.candidate.size_bytes,
        durability: request.candidate.durability,
        admin_state: VolumeAdminState::Active,
        head: blank_head.clone(),
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).expect("zero is a valid FenceEpoch"),
        lease_expires_at: None,
        last_transition: None,
    };
    let disk = DiskRecord {
        disk_id: request.candidate.disk_id.clone(),
        workspace_id: request.candidate.workspace_id.clone(),
        name: request.candidate.name.clone(),
        volume_id: request.candidate.volume_id.clone(),
        size_bytes: request.candidate.size_bytes,
        durability: request.candidate.durability,
        created_at: now,
        admin_state: DiskAdminState::Active,
        role: DiskRole::Persistent {
            initialization: Box::new(PersistentDiskInitialization::Uninitialized {
                initialization_token: request.candidate.initialization_token.clone(),
                filesystem_uuid: request.candidate.filesystem_uuid.clone(),
                expected_blank_head: blank_head,
            }),
        },
    };
    let public_durability = match request.candidate.durability {
        VolumeDurability::Strict => PublicDiskDurability::Strict,
        VolumeDurability::Relaxed => PublicDiskDurability::Relaxed,
    };
    let response = persistent_disk_create_response(
        &disk.disk_id,
        &disk.workspace_id,
        &disk.name,
        &disk.volume_id,
        disk.size_bytes,
        public_durability,
        now,
    );
    let response = ExactHttpResponse::new(
        201,
        Some(ExactContentType::ApplicationJson),
        encode_persistent_disk_create_response(&response)
            .map_err(|error| internal(format!("failed to encode PersistentDisk: {error}")))?,
    )?;
    let result = result_from_envelope(&request.idempotency, &response, now);

    checkpoint_covered_commit(transaction, commit_state)?;
    insert_volume(transaction, &volume)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    insert_disk(transaction, &disk)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    insert_api_result(transaction, &result)?;
    Ok(result)
}

fn create_cat_in(
    transaction: &mut Transaction<'_>,
    request: &CoveredCatCreateRequest,
    admission: Option<(&PlacementAdmissionSnapshot, &Sha256Digest)>,
    placement: Option<(
        &PlacementTargetSnapshot,
        &CatCreatePlacementMutation,
        &Sha256Digest,
    )>,
    commit_state: Option<&CoveredCommitState>,
) -> std::result::Result<ApiIdempotencyResult, CreateCatTransactionError> {
    checkpoint_cat_create(transaction, commit_state)?;
    reserve_api_key(transaction, &request.idempotency)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        return check_replay(result, &request.idempotency.request_fingerprint)
            .map_err(AuthorityTransactionError::from)
            .map_err(CreateCatTransactionError::from);
    }

    validate_candidate(request).map_err(AuthorityTransactionError::from)?;
    checkpoint_cat_create(transaction, commit_state)?;
    lock_cat_name(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )?;
    checkpoint_cat_create(transaction, commit_state)?;
    if let Some(existing) = load_cat_by_name_unlocked(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )? {
        if existing.cat_id == request.candidate.cat_id {
            return Err(candidate_collision(CandidateCollision::CatId));
        }
        checkpoint_cat_create(transaction, commit_state)?;
        validate_existing_cat_for_name_conflict(transaction, &existing, commit_state)?;
        checkpoint_cat_create(transaction, commit_state)?;
        let now = database_now(transaction)?;
        let result =
            result_from_envelope(&request.idempotency, &request.envelopes.name_conflict, now);
        checkpoint_cat_create(transaction, commit_state)?;
        insert_api_result(transaction, &result)?;
        return Ok(result);
    }

    // Root and Persistent disks share one Workspace-scoped product name
    // namespace. Take that coordination point before any placement/Node lock
    // so the global order remains API key -> Cat name -> Disk name -> Node ->
    // Network -> Volume -> candidate IDs. A concurrent Persistent create then
    // either publishes first and becomes a typed Cat candidate collision, or
    // observes this Root after the same lock and publishes its durable 409.
    checkpoint_cat_create(transaction, commit_state)?;
    lock_disk_name(
        transaction,
        &request.candidate.root_disk.workspace_id,
        &request.candidate.root_disk.name,
    )?;
    checkpoint_cat_create(transaction, commit_state)?;
    if let Some((planned, planned_mutation, active_guest_digest)) = placement {
        if request.candidate.desired.placement.node_id != planned.admission.node_identity.node_id
            || request.candidate.desired.runtime.guest_config_digest != *active_guest_digest
            || !candidate_matches_placement_mutation(&request.candidate, planned_mutation)
        {
            return Err(AuthorityTransactionError::from(ApiError::internal(
                "Cat create candidate is not bound to its placement target",
            ))
            .into());
        }
        let mut checkpoint =
            |transaction: &mut Transaction<'_>| checkpoint_cat_create(transaction, commit_state);
        if lock_cat_create_placement_for_desired_mutation(
            transaction,
            planned,
            planned_mutation,
            active_guest_digest,
            &mut checkpoint,
        )? != PlacementCommitLoad::Accepted
        {
            return Err(CreateCatTransactionError::PlacementStale);
        }
    } else if let Some((planned, active_guest_digest)) = admission {
        if request.candidate.desired.placement.node_id != planned.node_identity.node_id
            || request.candidate.desired.runtime.guest_config_digest != *active_guest_digest
        {
            return Err(AuthorityTransactionError::from(ApiError::internal(
                "Cat create candidate is not bound to its placement admission",
            ))
            .into());
        }
        if !matches!(
            lock_placement_admission_for_desired_mutation(
                transaction,
                planned,
                active_guest_digest,
            )?,
            PlacementAdmissionLoad::Accepted(_)
        ) {
            return Err(AuthorityTransactionError::from(ApiError::unavailable(
                "placement admission changed before Cat create commit",
            ))
            .into());
        }
    }
    checkpoint_cat_create(transaction, commit_state)?;

    // Network identities are globally non-reusable, including across target
    // Nodes. The advisory lock serializes concurrent commits for the same
    // candidate without introducing a second persisted identity authority.
    // It is deliberately after the selected NodeIdentity coordination lock
    // and before Volume, matching the frozen Desired-mutation lock order.
    let network_id = &request.candidate.desired.runtime.network_config.network_id;
    lock_candidate_id(transaction, "network", network_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_desired_by_network_id_unlocked(transaction, network_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::NetworkId));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &request.candidate.volume.volume_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_volume_for_update(transaction, &request.candidate.volume.volume_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::VolumeId));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "cat", &request.candidate.cat_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_cat_by_id_for_update(transaction, &request.candidate.cat_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::CatId));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &request.candidate.root_disk.disk_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let disk_id_collision =
        load_disk_by_id_for_update(transaction, &request.candidate.root_disk.disk_id)?.is_some();
    checkpoint_cat_create(transaction, commit_state)?;
    let disk_name_collision = load_disk_by_name_for_update(
        transaction,
        &request.candidate.root_disk.workspace_id,
        &request.candidate.root_disk.name,
    )?
    .is_some();
    if disk_id_collision || disk_name_collision {
        return Err(candidate_collision(CandidateCollision::DiskIdOrName));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "desired", &request.candidate.cat_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_desired_for_update(transaction, &request.candidate.cat_id)?.is_some() {
        return Err(stored_corruption("current Desired exists without its foreign-key Cat").into());
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(
        transaction,
        "endpoint",
        &request.candidate.endpoint.endpoint_id,
    )?;
    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_endpoint_name(
        transaction,
        &request.candidate.endpoint.cat_id,
        &request.candidate.endpoint.name,
    )?;
    checkpoint_cat_create(transaction, commit_state)?;
    let endpoint_id_collision =
        load_endpoint_by_id_for_update(transaction, &request.candidate.endpoint.endpoint_id)?
            .is_some();
    checkpoint_cat_create(transaction, commit_state)?;
    let endpoint_name_collision = load_endpoint_by_cat_name_unlocked(
        transaction,
        &request.candidate.endpoint.cat_id,
        &request.candidate.endpoint.name,
    )?
    .is_some();
    if endpoint_id_collision || endpoint_name_collision {
        return Err(candidate_collision(CandidateCollision::EndpointIdOrName));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_hostname(transaction, &request.candidate.hostname_lookup.hostname)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_hostname_lookup_for_update(transaction, &request.candidate.hostname_lookup.hostname)?
        .is_some()
    {
        return Err(candidate_collision(CandidateCollision::Hostname));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "operation", &request.candidate.operation_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    if load_operation_for_update(transaction, &request.candidate.operation_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::OperationId));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    let now = database_now(transaction)?;
    let cat = CatRecord {
        cat_id: request.candidate.cat_id.clone(),
        workspace_id: request.candidate.workspace_id.clone(),
        name: request.candidate.name.clone(),
        created_at: now,
    };
    let disk = DiskRecord {
        disk_id: request.candidate.root_disk.disk_id.clone(),
        workspace_id: request.candidate.root_disk.workspace_id.clone(),
        name: request.candidate.root_disk.name.clone(),
        volume_id: request.candidate.root_disk.volume_id.clone(),
        size_bytes: request.candidate.root_disk.size_bytes,
        durability: request.candidate.root_disk.durability,
        created_at: now,
        admin_state: request.candidate.root_disk.admin_state.clone(),
        role: request.candidate.root_disk.role.clone(),
    };
    let endpoint = EndpointRecord {
        endpoint_id: request.candidate.endpoint.endpoint_id.clone(),
        workspace_id: request.candidate.endpoint.workspace_id.clone(),
        cat_id: request.candidate.endpoint.cat_id.clone(),
        name: request.candidate.endpoint.name.clone(),
        created_at: now,
    };
    let operation = Operation {
        version: ContractVersion::V1,
        operation_id: request.candidate.operation_id.clone(),
        workspace_id: request.candidate.desired.workspace_id.clone(),
        cat_id: request.candidate.desired.cat_id.clone(),
        desired_revision: request.candidate.desired.desired_revision,
        desired_spec_digest: request.candidate.desired.spec_digest.clone(),
        placement: request.candidate.desired.placement.clone(),
        target: request.candidate.desired.target,
        phase: OperationPhase::Pending,
        terminal: None,
        created_at_unix_ms: now,
        updated_at_unix_ms: now,
    };
    let result = result_from_envelope(
        &request.idempotency,
        &request.envelopes.accepted.response,
        now,
    );

    checkpoint_cat_create(transaction, commit_state)?;
    insert_volume(transaction, &request.candidate.volume)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_cat(transaction, &cat)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_disk(transaction, &disk)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_desired(transaction, &request.candidate.desired)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_endpoint(transaction, &endpoint)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_hostname_lookup(transaction, &request.candidate.hostname_lookup)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_operation(transaction, &operation)?;
    checkpoint_cat_create(transaction, commit_state)?;
    insert_api_result(transaction, &result)?;
    Ok(result)
}

fn validate_persistent_disk_candidate(request: &CoveredPersistentDiskCreateRequest) -> Result<()> {
    let candidate = &request.candidate;
    if candidate.workspace_id != request.idempotency.authenticated_workspace_id {
        return Err(invalid_persistent_disk_bundle(
            "authenticated Workspace binding mismatch",
        ));
    }
    if !(1..=MAX_VOLUME_BYTES).contains(&candidate.size_bytes) {
        return Err(invalid_persistent_disk_bundle(
            "size_bytes is outside the V1 range",
        ));
    }
    validate_prefixed_random_id(&candidate.disk_id, "disk_")?;
    validate_prefixed_random_id(&candidate.volume_id, "vol_")?;
    if candidate.initialization_token == candidate.filesystem_uuid {
        return Err(invalid_persistent_disk_bundle(
            "initialization token and filesystem UUID share one sample",
        ));
    }
    validate_envelope(&request.name_conflict, 409)?;
    if request.name_conflict.response_body != PERSISTENT_DISK_NAME_CONFLICT_BODY {
        return Err(invalid_persistent_disk_bundle(
            "name-conflict body is not the canonical already_exists response",
        ));
    }
    Ok(())
}

fn validate_prefixed_random_id(value: &Id, prefix: &'static str) -> Result<()> {
    let Some(suffix) = value.as_str().strip_prefix(prefix).filter(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) else {
        return Err(invalid_persistent_disk_bundle(format!(
            "identity must be {prefix} plus 32 lowercase hex digits"
        )));
    };
    debug_assert_eq!(suffix.len(), 32);
    Ok(())
}

fn validate_existing_disk_for_name_conflict(
    transaction: &mut Transaction<'_>,
    peeked_disk: &DiskRecord,
    commit_state: Option<&CoveredCommitState>,
) -> std::result::Result<(), CreatePersistentDiskTransactionError> {
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &peeked_disk.volume_id)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    let volume = load_any_volume_by_id_for_update(transaction, &peeked_disk.volume_id)?
        .ok_or_else(|| stored_corruption("existing Disk Volume disappeared"))?;

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &peeked_disk.disk_id)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    let disk = load_any_disk_by_id_for_update(transaction, &peeked_disk.disk_id)?
        .ok_or_else(|| stored_corruption("existing Disk disappeared"))?;
    let admin_state_matches = match (&disk.admin_state, &volume.admin_state) {
        (DiskAdminState::Active, VolumeAdminState::Active) => true,
        (
            DiskAdminState::Deleting {
                delete_id: disk_delete,
            },
            VolumeAdminState::Deleting {
                delete_id: volume_delete,
            },
        ) => disk_delete == volume_delete,
        _ => false,
    };
    if disk != *peeked_disk
        || disk.volume_id != volume.volume_id
        || disk.size_bytes != volume.size_bytes
        || disk.durability != volume.durability
        || !admin_state_matches
    {
        return Err(stored_corruption("existing Disk/Volume name authority is invalid").into());
    }
    Ok(())
}

pub(super) fn candidate_matches_placement_mutation(
    candidate: &CatCreateCandidate,
    planned: &CatCreatePlacementMutation,
) -> bool {
    candidate.cat_id == planned.cat_id
        && candidate.desired.desired_revision == planned.desired_revision
        && candidate.desired.placement.placement_epoch == planned.placement_epoch
        && candidate.desired.runtime.vcpus == planned.vcpus
        && candidate.desired.runtime.memory_bytes == planned.memory_bytes
        && candidate.desired.runtime.network_config == planned.network_config
}

fn checkpoint_cat_create(
    transaction: &mut Transaction<'_>,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    checkpoint_covered_commit(transaction, commit_state)
}

fn checkpoint_covered_commit(
    transaction: &mut Transaction<'_>,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    commit_state.map_or(Ok(()), |state| state.checkpoint(transaction))
}

fn validate_existing_cat_for_name_conflict(
    transaction: &mut Transaction<'_>,
    peeked_cat: &CatRecord,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    checkpoint_cat_create(transaction, commit_state)?;
    let peeked_disk = load_root_disk_by_cat_unlocked(transaction, &peeked_cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat has no Root Disk"))?;

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &peeked_disk.volume_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let volume = load_volume_for_update(transaction, &peeked_disk.volume_id)?
        .ok_or_else(|| stored_corruption("existing Cat Root Volume disappeared"))?;

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "cat", &peeked_cat.cat_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let cat = load_cat_by_id_for_update(transaction, &peeked_cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat disappeared"))?;
    if cat != *peeked_cat {
        return Err(stored_corruption("existing Cat identity changed"));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &peeked_disk.disk_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let disk = load_disk_by_id_for_update(transaction, &peeked_disk.disk_id)?
        .ok_or_else(|| stored_corruption("existing Cat Root Disk disappeared"))?;
    if disk != peeked_disk
        || disk.workspace_id != cat.workspace_id
        || disk.created_at != cat.created_at
        || disk.volume_id != volume.volume_id
        || disk.size_bytes != volume.size_bytes
        || disk.durability != volume.durability
        || !matches!(&disk.role, DiskRole::Root { cat_id } if *cat_id == cat.cat_id)
    {
        return Err(stored_corruption(
            "existing Cat Root Disk/Volume binding is invalid",
        ));
    }

    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "desired", &cat.cat_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let desired = load_desired_for_update(transaction, &cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat has no current Desired"))?;
    validate_existing_desired(&cat, &disk, &volume, &desired)?;

    checkpoint_cat_create(transaction, commit_state)?;
    validate_existing_endpoints(transaction, &cat, &desired, commit_state)?;

    checkpoint_cat_create(transaction, commit_state)?;
    let peeked_operation = load_operation_by_cat_revision_unlocked(
        transaction,
        &cat.cat_id,
        desired.desired_revision,
    )?
    .ok_or_else(|| stored_corruption("existing Cat has no revision Operation"))?;
    checkpoint_cat_create(transaction, commit_state)?;
    lock_candidate_id(transaction, "operation", &peeked_operation.operation_id)?;
    checkpoint_cat_create(transaction, commit_state)?;
    let operation = load_operation_for_update(transaction, &peeked_operation.operation_id)?
        .ok_or_else(|| stored_corruption("existing Cat Operation disappeared"))?;
    if operation != peeked_operation
        || operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
    {
        return Err(stored_corruption(
            "existing Cat Operation/Desired binding is invalid",
        ));
    }
    Ok(())
}

fn validate_existing_desired(
    cat: &CatRecord,
    disk: &DiskRecord,
    volume: &VolumeRecord,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    if desired.workspace_id != cat.workspace_id || desired.cat_id != cat.cat_id {
        return Err(stored_corruption(
            "existing Cat current Desired owner is invalid",
        ));
    }
    let mut roots = desired
        .volumes
        .iter()
        .filter(|intent| intent.disk_kind == DiskKind::Root);
    let root = roots
        .next()
        .ok_or_else(|| stored_corruption("existing Cat Desired has no Root"))?;
    if roots.next().is_some() {
        return Err(stored_corruption("existing Cat Desired has multiple Roots"));
    }
    let durability = match volume.durability {
        VolumeDurability::Strict => Durability::Strict,
        VolumeDurability::Relaxed => Durability::Relaxed,
    };
    if root.disk_id != disk.disk_id
        || root.volume_id != volume.volume_id
        || root.size_bytes != volume.size_bytes
        || root.durability != durability
    {
        return Err(stored_corruption(
            "existing Cat Desired Root binding is invalid",
        ));
    }
    Ok(())
}

fn validate_existing_endpoints(
    transaction: &mut Transaction<'_>,
    cat: &CatRecord,
    desired: &DesiredRuntimeSpec,
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    checkpoint_cat_create(transaction, commit_state)?;
    let lookups = load_hostname_lookups_by_cat_unlocked(transaction, &cat.cat_id)?;
    if lookups.len() != desired.endpoints.len() {
        return Err(stored_corruption(
            "existing Cat hostname lookup set does not match current Desired",
        ));
    }

    let mut endpoints = Vec::with_capacity(desired.endpoints.len());
    for (binding, peeked_lookup) in desired.endpoints.iter().zip(&lookups) {
        if peeked_lookup.endpoint_id != binding.endpoint_id {
            return Err(stored_corruption(
                "existing Cat hostname lookup identities do not match current Desired",
            ));
        }
        checkpoint_cat_create(transaction, commit_state)?;
        lock_candidate_id(transaction, "endpoint", &binding.endpoint_id)?;
        checkpoint_cat_create(transaction, commit_state)?;
        let endpoint = load_endpoint_by_id_for_update(transaction, &binding.endpoint_id)?
            .ok_or_else(|| stored_corruption("current Desired Endpoint has no product record"))?;
        if endpoint.workspace_id != cat.workspace_id || endpoint.cat_id != cat.cat_id {
            return Err(stored_corruption(
                "current Desired Endpoint product identity is invalid",
            ));
        }
        lock_candidate_endpoint_name(transaction, &endpoint.cat_id, &endpoint.name)?;
        endpoints.push(endpoint);
    }

    let mut hostnames = lookups
        .iter()
        .map(|lookup| lookup.hostname.clone())
        .collect::<Vec<_>>();
    hostnames.sort_by(|left, right| left.as_str().cmp(right.as_str()));
    for hostname in &hostnames {
        checkpoint_cat_create(transaction, commit_state)?;
        lock_candidate_hostname(transaction, hostname)?;
    }

    for (peeked_lookup, endpoint) in lookups.iter().zip(&endpoints) {
        checkpoint_cat_create(transaction, commit_state)?;
        let lookup = load_hostname_lookup_for_update(transaction, &peeked_lookup.hostname)?
            .ok_or_else(|| stored_corruption("current Desired hostname lookup disappeared"))?;
        if lookup != *peeked_lookup {
            return Err(stored_corruption(
                "current Desired hostname lookup changed while closing the graph",
            ));
        }
        validate_endpoint_lookup(endpoint, &lookup, desired)?;
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn validate_desired_mutation_request(
    request: &CoveredDesiredMutationRequest,
) -> Result<DesiredMutationClass> {
    if request.idempotency.authenticated_workspace_id != request.expected_current.workspace_id {
        return Err(invalid_desired_mutation_bundle(
            "authenticated Workspace binding changed",
        ));
    }
    validate_desired_mutation_bundle(
        &request.expected_current,
        &request.desired,
        &request.placement_snapshots,
        &request.active_guest_digest,
        &request.endpoint_records,
        &request.volume_mutation,
        request.require_idle_open_busy_proof.as_ref(),
    )
}

fn validate_desired_mutation_bundle(
    expected_current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    placement_snapshots: &[PlacementTargetSnapshot],
    active_guest_digest: &Sha256Digest,
    endpoint_records: &[EndpointRecordCandidate],
    volume_mutation: &DesiredVolumeMutation,
    require_idle_open_busy_proof: Option<&RequireIdleOpenBusyProof>,
) -> Result<DesiredMutationClass> {
    if desired.workspace_id != expected_current.workspace_id
        || desired.cat_id != expected_current.cat_id
    {
        return Err(invalid_desired_mutation_bundle(
            "Workspace or Cat binding changed",
        ));
    }
    encode_desired_runtime_spec(expected_current).map_err(|error| {
        invalid_desired_mutation_bundle(format!("invalid current CAS: {error}"))
    })?;
    encode_desired_runtime_spec(desired).map_err(|error| {
        invalid_desired_mutation_bundle(format!("invalid successor Desired: {error}"))
    })?;
    let next_revision = expected_current
        .desired_revision
        .get()
        .checked_add(1)
        .and_then(Revision::new)
        .ok_or_else(|| invalid_desired_mutation_bundle("Desired revision is exhausted"))?;
    if desired.desired_revision != next_revision {
        return Err(invalid_desired_mutation_bundle(
            "successor Desired is not exact current revision plus one",
        ));
    }

    let old_placement = &expected_current.placement;
    let new_placement = &desired.placement;
    if old_placement.node_id == new_placement.node_id {
        if old_placement.placement_epoch != new_placement.placement_epoch
            || expected_current.runtime.network_config != desired.runtime.network_config
        {
            return Err(invalid_desired_mutation_bundle(
                "same-Node mutation changed placement epoch or Guest network",
            ));
        }
    } else {
        let next_epoch = old_placement
            .placement_epoch
            .get()
            .checked_add(1)
            .and_then(Epoch::new)
            .ok_or_else(|| invalid_desired_mutation_bundle("placement epoch is exhausted"))?;
        if new_placement.placement_epoch != next_epoch
            || expected_current.runtime.network_config.network_id
                == desired.runtime.network_config.network_id
        {
            return Err(invalid_desired_mutation_bundle(
                "cross-Node placement lacks exact epoch bump and fresh network identity",
            ));
        }
    }
    // Cross-Node volume movement remains closed. It needs exact settled-Cold
    // release/acquire authority and is not part of the lifecycle API slice.
    if old_placement.node_id != new_placement.node_id
        && (!expected_current.volumes.is_empty() || !desired.volumes.is_empty())
    {
        return Err(invalid_desired_mutation_bundle(
            "cross-Node volume authority requires exact Cold settlement, released Volume/Disk locks and fresh acquire tuples",
        ));
    }
    validate_desired_volume_mutation(expected_current, desired, volume_mutation)?;
    validate_route_epoch_successor(
        expected_current,
        desired,
        require_idle_open_busy_proof,
    )?;

    let mutation_class = if old_placement != new_placement
        || expected_current.runtime != desired.runtime
        || runtime_target_activity(desired.target)
            > runtime_target_activity(expected_current.target)
        || (desired.target == RuntimeTarget::Running
            && (expected_current.target != RuntimeTarget::Running
                || expected_current.transition != desired.transition))
    {
        DesiredMutationClass::PlacementRequired
    } else {
        DesiredMutationClass::SourceOnly
    };

    match mutation_class {
        DesiredMutationClass::SourceOnly if !placement_snapshots.is_empty() => {
            return Err(invalid_desired_mutation_bundle(
                "source-only Desired mutation must not carry placement admission authority",
            ));
        }
        DesiredMutationClass::SourceOnly => {}
        DesiredMutationClass::PlacementRequired => {
            let expected_nodes =
                BTreeSet::from([old_placement.node_id.clone(), new_placement.node_id.clone()]);
            let supplied_nodes = placement_snapshots
                .iter()
                .map(|snapshot| snapshot.admission.node_identity.node_id.clone())
                .collect::<BTreeSet<_>>();
            if expected_nodes != supplied_nodes
                || placement_snapshots.len() != supplied_nodes.len()
                || placement_snapshots.windows(2).any(|pair| {
                    pair[0].admission.node_identity.node_id
                        >= pair[1].admission.node_identity.node_id
                })
            {
                return Err(invalid_desired_mutation_bundle(
                    "placement snapshot set is not the exact canonical placement union",
                ));
            }
            if placement_snapshots.iter().any(|snapshot| {
                snapshot.admission.node_identity.state != NodeIdentityState::Provisioned
                    || snapshot.policy.node_id != snapshot.admission.node_identity.node_id
                    || snapshot.policy.capabilities.guest_config_digest != *active_guest_digest
            }) {
                return Err(invalid_desired_mutation_bundle(
                    "placement snapshot is not provisioned or active-release bound",
                ));
            }
        }
    }

    if endpoint_records.len() != desired.endpoints.len()
        || endpoint_records
            .windows(2)
            .any(|pair| pair[0].endpoint_id >= pair[1].endpoint_id)
    {
        return Err(invalid_desired_mutation_bundle(
            "Endpoint product candidates are not the complete canonical Desired set",
        ));
    }
    let mut names = BTreeSet::new();
    for (intent, record) in desired.endpoints.iter().zip(endpoint_records) {
        if record.endpoint_id != intent.endpoint_id
            || record.workspace_id != desired.workspace_id
            || record.cat_id != desired.cat_id
            || !names.insert(record.name.clone())
        {
            return Err(invalid_desired_mutation_bundle(
                "Endpoint product candidate does not match the complete Desired set",
            ));
        }
    }
    Ok(mutation_class)
}

fn validate_desired_volume_mutation(
    expected_current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    volume_mutation: &DesiredVolumeMutation,
) -> Result<()> {
    match volume_mutation {
        DesiredVolumeMutation::Preserve => {
            if desired.volumes != expected_current.volumes {
                return Err(invalid_desired_mutation_bundle(
                    "volume intent changes require a closed covered mutation",
                ));
            }
        }
        DesiredVolumeMutation::DeleteCat { delete_id } => {
            if desired.target != RuntimeTarget::Deleted
                || expected_current.volumes.len() != desired.volumes.len()
            {
                return Err(invalid_desired_mutation_bundle(
                    "Cat delete must preserve the complete VolumeIntent set",
                ));
            }
            let mut roots = 0_u8;
            for (current, successor) in expected_current
                .volumes
                .iter()
                .zip(&desired.volumes)
            {
                let mut normalized = successor.clone();
                normalized.disposition = current.disposition.clone();
                if normalized != *current {
                    return Err(invalid_desired_mutation_bundle(
                        "Cat delete changed VolumeIntent authority outside disposition",
                    ));
                }
                match current.disk_kind {
                    DiskKind::Root => {
                        roots = roots.saturating_add(1);
                        if successor.disposition
                            != (VolumeDisposition::DeleteDisposableRoot {
                                delete_id: delete_id.clone(),
                            })
                        {
                            return Err(invalid_desired_mutation_bundle(
                                "Cat delete Root disposition has another delete lineage",
                            ));
                        }
                    }
                    DiskKind::Persistent => {
                        if successor.disposition != VolumeDisposition::DetachRetained {
                            return Err(invalid_desired_mutation_bundle(
                                "Cat delete must retain PersistentDisk data",
                            ));
                        }
                    }
                }
            }
            if roots != 1 {
                return Err(invalid_desired_mutation_bundle(
                    "Cat delete requires exactly one Root VolumeIntent",
                ));
            }
        }
    }
    Ok(())
}

/// Closes the per-Endpoint serving lineage inside the same transaction that
/// replaces the complete Desired. The request cannot choose whether an epoch
/// bump is necessary: new product identities start at one, exact bindings do
/// not churn, and every changed or re-opened binding advances exactly once.
fn validate_route_epoch_successor(
    current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    require_idle_open_busy_proof: Option<&RequireIdleOpenBusyProof>,
) -> Result<()> {
    // Every successor that re-enters Running, or changes another global
    // Running binding, is a real reopen unless G4 carries the one exact
    // accepted RequireIdle Busy/Open proof and A1 revalidates it under lock.
    let proven_open_busy_recovery = require_idle_open_busy_proof.is_some_and(|proof| {
        matches!(
            &current.transition,
            RuntimeTransition::RequireIdle {
                attempt_id,
                source_revision,
                source_runtime_incarnation,
            } if current.target == RuntimeTarget::Suspended
                && desired.target == RuntimeTarget::Running
                && desired.transition == RuntimeTransition::CancelAndDrain
                && proof.attempt_id == *attempt_id
                && proof.source_revision == *source_revision
                && proof.source_runtime_incarnation == *source_runtime_incarnation
        )
    });
    if require_idle_open_busy_proof.is_some() && !proven_open_busy_recovery {
        return Err(invalid_desired_mutation_bundle(
            "RequireIdle open-Busy proof does not bind this exact recovery",
        ));
    }
    let reopens_running = current.target != RuntimeTarget::Running
        && desired.target == RuntimeTarget::Running
        && !proven_open_busy_recovery;
    let rebinds_running_globally = desired.target == RuntimeTarget::Running
        && (current.placement != desired.placement
            || current.runtime != desired.runtime
            || current.volumes != desired.volumes
            || (current.transition != desired.transition && !proven_open_busy_recovery));
    for successor in &desired.endpoints {
        let Some(predecessor) = current
            .endpoints
            .iter()
            .find(|endpoint| endpoint.endpoint_id == successor.endpoint_id)
        else {
            if successor.route_epoch.get() != 1 {
                return Err(invalid_desired_mutation_bundle(
                    "new Endpoint route epoch must start at one",
                ));
            }
            continue;
        };
        let binding_changed = predecessor.hostname != successor.hostname
            || predecessor.protocol != successor.protocol
            || predecessor.target_port != successor.target_port;
        let expected = if binding_changed || reopens_running || rebinds_running_globally {
            predecessor
                .route_epoch
                .get()
                .checked_add(1)
                .and_then(Epoch::new)
                .ok_or_else(|| {
                    invalid_desired_mutation_bundle("Endpoint route epoch is exhausted")
                })?
        } else {
            predecessor.route_epoch
        };
        if successor.route_epoch != expected {
            let reason = if binding_changed {
                "changed Endpoint binding must advance route epoch exactly once"
            } else if reopens_running {
                "non-Running to Running must advance every retained Endpoint route epoch exactly once"
            } else if rebinds_running_globally {
                "global Running rebind must advance every retained Endpoint route epoch exactly once"
            } else {
                "unchanged Endpoint binding must preserve route epoch"
            };
            return Err(invalid_desired_mutation_bundle(reason));
        }
    }
    Ok(())
}

const fn runtime_target_activity(target: RuntimeTarget) -> u8 {
    match target {
        RuntimeTarget::Deleted => 0,
        RuntimeTarget::Cold => 1,
        RuntimeTarget::Warm => 2,
        RuntimeTarget::Suspended => 3,
        RuntimeTarget::Running => 4,
    }
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn desired_mutation_accepted_response(
    revision: Revision,
    operation_id: &Id,
) -> Result<ExactHttpResponse> {
    let response_body = serde_json::to_vec(&DesiredMutationAcceptedResponse {
        desired_revision: revision.get(),
        operation_id,
    })
    .map_err(internal)?;
    ExactHttpResponse::new(202, Some(ExactContentType::ApplicationJson), response_body)
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn desired_mutation_converged_response(revision: Revision) -> Result<ExactHttpResponse> {
    let response_body = serde_json::to_vec(&DesiredMutationConvergedResponse {
        desired_revision: revision.get(),
        converged: true,
    })
    .map_err(internal)?;
    ExactHttpResponse::new(200, Some(ExactContentType::ApplicationJson), response_body)
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn validate_operation_binding(
    operation: &Operation,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    if operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
    {
        return Err(stored_corruption(
            "current Operation is not bound to the current Desired",
        ));
    }
    Ok(())
}

fn validate_system_operation_replay(
    operation: &Operation,
    operation_id: &Id,
    request: &SystemDesiredMutationRequest,
) -> AuthorityTxResult<()> {
    let mut canonical = request.desired.clone();
    canonical.spec_digest = Sha256Digest::from_bytes([0; 32]);
    let digest = cats_api::runtime_reconciliation::spec_digest(&canonical)
        .map_err(|_| ApiError::invalid("system replay Desired is invalid"))?;
    if digest != request.desired.spec_digest {
        return Err(
            ApiError::conflict("system replay Desired digest does not match its body").into(),
        );
    }
    if operation.operation_id != *operation_id
        || operation.workspace_id != request.desired.workspace_id
        || operation.cat_id != request.desired.cat_id
        || operation.desired_revision != request.desired.desired_revision
        || operation.desired_spec_digest != request.desired.spec_digest
        || operation.placement != request.desired.placement
        || operation.target != request.desired.target
    {
        return Err(ApiError::conflict(
            "system replay request does not match the retained Operation",
        )
        .into());
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn desired_semantics_equal(
    current: &DesiredRuntimeSpec,
    candidate: &DesiredRuntimeSpec,
) -> AuthorityTxResult<bool> {
    // Normalize the older snapshot forward. Normalizing a RequireIdle
    // successor backward can make its source revision equal to the Desired
    // revision, which is intrinsically invalid even though the successor is
    // canonical.
    let mut normalized = current.clone();
    normalized.desired_revision = candidate.desired_revision;
    normalized.spec_digest = Sha256Digest::from_bytes([0; 32]);
    normalized.spec_digest = cats_api::runtime_reconciliation::spec_digest(&normalized)
        .map_err(stored_corruption_from_debug)?;
    Ok(&normalized == candidate)
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn validate_mutation_endpoint_candidates(
    transaction: &mut Transaction<'_>,
    expected_current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    endpoint_records: &[EndpointRecordCandidate],
    require_existing: bool,
) -> AuthorityTxResult<Option<CandidateCollision>> {
    for (intent, candidate) in desired.endpoints.iter().zip(endpoint_records) {
        match load_endpoint_by_id_for_update(transaction, &candidate.endpoint_id)? {
            Some(existing)
                if existing.endpoint_id == candidate.endpoint_id
                    && existing.workspace_id == candidate.workspace_id
                    && existing.cat_id == candidate.cat_id
                    && existing.name == candidate.name
                    && expected_current
                        .endpoints
                        .iter()
                        .any(|current| current.endpoint_id == candidate.endpoint_id) => {}
            Some(_) => {
                // EndpointRecord is retained after removal. Reusing that ID as
                // a "new" epoch-one Endpoint would revive an older serving
                // lineage without a persisted predecessor epoch.
                return Ok(Some(CandidateCollision::EndpointIdOrName));
            }
            None if require_existing => {
                return Err(stored_corruption(
                    "unchanged Desired Endpoint lost its product record",
                ));
            }
            None => {}
        }
        if load_endpoint_by_cat_name_unlocked(transaction, &candidate.cat_id, &candidate.name)?
            .is_some_and(|existing| existing.endpoint_id != candidate.endpoint_id)
        {
            return Ok(Some(CandidateCollision::EndpointIdOrName));
        }

        if let Some(existing) = load_hostname_lookup_for_update(transaction, &intent.hostname)? {
            let current_exact_owner = expected_current.endpoints.iter().any(|current| {
                current.endpoint_id == existing.endpoint_id
                    && current.hostname == existing.hostname
                    && existing.workspace_id == expected_current.workspace_id
                    && existing.cat_id == expected_current.cat_id
            });
            if !current_exact_owner || existing.endpoint_id != intent.endpoint_id {
                return Ok(Some(CandidateCollision::Hostname));
            }
        }
    }
    Ok(None)
}

/// Locks the old+new Endpoint graph as three complete canonical unions. A
/// mutation may otherwise take old Endpoint/hostname locks first and then its
/// candidate locks, allowing two Cats that exchange names or hostnames to
/// form an A->B / B->A advisory-lock cycle.
fn lock_desired_mutation_endpoint_graph(
    transaction: &mut Transaction<'_>,
    cat: &CatRecord,
    current: &DesiredRuntimeSpec,
    desired: &DesiredRuntimeSpec,
    endpoint_records: &[EndpointRecordCandidate],
    commit_state: Option<&CoveredCommitState>,
) -> AuthorityTxResult<()> {
    let endpoint_ids = current
        .endpoints
        .iter()
        .map(|intent| intent.endpoint_id.clone())
        .chain(
            endpoint_records
                .iter()
                .map(|candidate| candidate.endpoint_id.clone()),
        )
        .collect::<BTreeSet<_>>();
    for endpoint_id in &endpoint_ids {
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_id(transaction, "endpoint", endpoint_id)?;
    }

    let mut endpoint_names = endpoint_records
        .iter()
        .map(|candidate| (candidate.cat_id.clone(), candidate.name.clone()))
        .collect::<BTreeSet<_>>();
    for intent in &current.endpoints {
        checkpoint_covered_commit(transaction, commit_state)?;
        let endpoint = load_endpoint_by_id_unlocked(transaction, &intent.endpoint_id)?
            .ok_or_else(|| stored_corruption("current Desired Endpoint has no product record"))?;
        if endpoint.workspace_id != cat.workspace_id || endpoint.cat_id != cat.cat_id {
            return Err(stored_corruption(
                "current Desired Endpoint product identity is invalid",
            ));
        }
        endpoint_names.insert((endpoint.cat_id, endpoint.name));
    }
    for (cat_id, name) in &endpoint_names {
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_endpoint_name(transaction, cat_id, name)?;
    }

    let hostnames = current
        .endpoints
        .iter()
        .map(|intent| intent.hostname.clone())
        .chain(
            desired
                .endpoints
                .iter()
                .map(|intent| intent.hostname.clone()),
        )
        .collect::<BTreeSet<_>>();
    for hostname in &hostnames {
        checkpoint_covered_commit(transaction, commit_state)?;
        lock_candidate_hostname(transaction, hostname)?;
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn insert_missing_mutation_endpoint_records(
    transaction: &mut Transaction<'_>,
    endpoint_records: &[EndpointRecordCandidate],
    now: UnixMillis,
) -> AuthorityTxResult<()> {
    for candidate in endpoint_records {
        if load_endpoint_by_id_for_update(transaction, &candidate.endpoint_id)?.is_none() {
            insert_endpoint(
                transaction,
                &EndpointRecord {
                    endpoint_id: candidate.endpoint_id.clone(),
                    workspace_id: candidate.workspace_id.clone(),
                    cat_id: candidate.cat_id.clone(),
                    name: candidate.name.clone(),
                    created_at: now,
                },
            )?;
        }
    }
    Ok(())
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn stored_corruption_from_debug(_error: impl std::fmt::Debug) -> AuthorityTransactionError {
    stored_corruption("runtime authority candidate failed canonical validation")
}

fn validate_candidate(request: &CoveredCatCreateRequest) -> Result<()> {
    let candidate = &request.candidate;
    if candidate.workspace_id != request.idempotency.authenticated_workspace_id
        || candidate.root_disk.workspace_id != candidate.workspace_id
        || candidate.desired.workspace_id != candidate.workspace_id
        || candidate.desired.cat_id != candidate.cat_id
        || candidate.endpoint.workspace_id != candidate.workspace_id
        || candidate.endpoint.cat_id != candidate.cat_id
        || candidate.hostname_lookup.workspace_id != candidate.workspace_id
        || candidate.hostname_lookup.cat_id != candidate.cat_id
    {
        return Err(invalid_bundle("workspace/cat binding mismatch"));
    }
    if request.envelopes.accepted.cat_id != candidate.cat_id
        || request.envelopes.accepted.operation_id != candidate.operation_id
    {
        return Err(invalid_bundle("accepted response identity mismatch"));
    }
    if candidate.root_disk.name != candidate.root_disk.disk_id
        || candidate.root_disk.volume_id != candidate.volume.volume_id
        || candidate.root_disk.size_bytes != candidate.volume.size_bytes
        || candidate.root_disk.durability != candidate.volume.durability
        || !matches!(candidate.root_disk.admin_state, DiskAdminState::Active)
        || !matches!(
            &candidate.root_disk.role,
            DiskRole::Root { cat_id } if *cat_id == candidate.cat_id
        )
    {
        return Err(invalid_bundle("Root Disk binding is invalid"));
    }
    if !matches!(candidate.volume.admin_state, VolumeAdminState::Active)
        || candidate.volume.lease_owner.is_some()
        || candidate.volume.lease_epoch.get() != 0
        || candidate.volume.lease_expires_at.is_some()
        || candidate.volume.last_transition.is_some()
        || candidate.volume.head.generation.get() != 0
        || candidate.volume.head.root_hash.is_some()
        || candidate.volume.head.root_object_id.is_some()
    {
        return Err(invalid_bundle(
            "initial Root Volume is not blank epoch-zero Unowned",
        ));
    }
    if candidate.desired.desired_revision.get() != 1
        || candidate.desired.target != RuntimeTarget::Running
        || candidate.desired.placement.placement_epoch.get() != 1
        || !matches!(
            candidate.desired.transition,
            RuntimeTransition::CancelAndDrain
        )
    {
        return Err(invalid_bundle(
            "initial Desired revision/target/placement/transition is invalid",
        ));
    }
    encode_desired_runtime_spec(&candidate.desired)
        .map_err(|error| invalid_bundle(format!("invalid DesiredRuntimeSpec: {error}")))?;
    let [root] = candidate.desired.volumes.as_slice() else {
        return Err(invalid_bundle(
            "initial Desired must contain exactly one Root Volume",
        ));
    };
    let expected_durability = match candidate.volume.durability {
        VolumeDurability::Strict => Durability::Strict,
        VolumeDurability::Relaxed => Durability::Relaxed,
    };
    if root.disk_kind != DiskKind::Root
        || root.disk_id != candidate.root_disk.disk_id
        || root.volume_id != candidate.volume.volume_id
        || root.size_bytes != candidate.volume.size_bytes
        || root.durability != expected_durability
        || root.access != VolumeAccess::ReadWriteOnce
        || root.guest_device.serial.as_str() != "cats-root"
        || root.guest_device.slot != 0
        || !matches!(root.disposition, VolumeDisposition::Retain)
        || root.mount.is_some()
        || !matches!(
            &root.acquire,
            VolumeAcquire::Normal { expected_unowned_epoch, .. }
                if expected_unowned_epoch.get() == 0
        )
    {
        return Err(invalid_bundle(
            "Desired Root intent does not match Disk/Volume",
        ));
    }
    let [endpoint_intent] = candidate.desired.endpoints.as_slice() else {
        return Err(invalid_bundle(
            "initial Desired must contain exactly one default Endpoint",
        ));
    };
    let endpoint_id = candidate.endpoint.endpoint_id.as_str();
    let Some(endpoint_suffix) = endpoint_id.strip_prefix("ep_").filter(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }) else {
        return Err(invalid_bundle(
            "default Endpoint ID must be ep_ plus 32 lowercase hex digits",
        ));
    };
    let expected_hostname = format!("{}-{endpoint_suffix}.cats.run", candidate.name);
    if candidate.endpoint.name.as_str() != "web"
        || candidate.endpoint.endpoint_id != endpoint_intent.endpoint_id
        || candidate.hostname_lookup.endpoint_id != endpoint_intent.endpoint_id
        || candidate.hostname_lookup.hostname != endpoint_intent.hostname
        || candidate.hostname_lookup.hostname.as_str() != expected_hostname
        || candidate.hostname_lookup.desired_revision != candidate.desired.desired_revision
        || endpoint_intent.route_epoch.get() != 1
        || endpoint_intent.protocol != HttpProtocol::Http
        || endpoint_intent.target_port != 8080
    {
        return Err(invalid_bundle(
            "default Endpoint/hostname/Desired binding is invalid",
        ));
    }
    Ok(())
}

pub(super) fn validate_endpoint_lookup(
    endpoint: &EndpointRecord,
    lookup: &HostnameDesiredLookup,
    desired: &DesiredRuntimeSpec,
) -> AuthorityTxResult<()> {
    if endpoint.workspace_id != lookup.workspace_id
        || endpoint.cat_id != lookup.cat_id
        || endpoint.endpoint_id != lookup.endpoint_id
        || desired.workspace_id != lookup.workspace_id
        || desired.cat_id != lookup.cat_id
        || desired.desired_revision != lookup.desired_revision
    {
        return Err(stored_corruption(
            "Endpoint/hostname lookup/current Desired identity is invalid",
        ));
    }
    let mut bindings = desired
        .endpoints
        .iter()
        .filter(|binding| binding.endpoint_id == endpoint.endpoint_id);
    let binding = bindings
        .next()
        .ok_or_else(|| stored_corruption("current Desired has no lookup Endpoint binding"))?;
    if bindings.next().is_some() || binding.hostname != lookup.hostname {
        return Err(stored_corruption(
            "hostname lookup does not match the current Desired binding",
        ));
    }
    Ok(())
}

fn validate_envelope(response: &ExactHttpResponse, expected_status: u16) -> Result<()> {
    if response.http_status != expected_status
        || response.content_type != Some(ExactContentType::ApplicationJson)
        || response.response_body.len() > MAX_RESPONSE_BODY_BYTES
    {
        return Err(ApiError::invalid(format!(
            "Cat create envelope must be {expected_status} application/json within 1 MiB"
        )));
    }
    Ok(())
}

fn reserve_api_key(
    transaction: &mut Transaction<'_>,
    request: &ApiIdempotencyRequest,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':api-result:' || $1 || ':' || $2 || ':' || $3,
            0::BIGINT
         ))",
        &[
            &request.authenticated_workspace_id.as_str(),
            &request.canonical_route.as_str(),
            &request.idempotency_key.as_str(),
        ],
    )?;
    Ok(())
}

fn lock_cat_name(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    name: &Id,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':cat-name:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&workspace_id.as_str(), &name.as_str()],
    )?;
    Ok(())
}

fn lock_disk_name(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    name: &Id,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':disk-name:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&workspace_id.as_str(), &name.as_str()],
    )?;
    Ok(())
}

fn lock_candidate_id(
    transaction: &mut Transaction<'_>,
    kind: &'static str,
    id: &Id,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-authority:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&kind, &id.as_str()],
    )?;
    Ok(())
}

fn lock_candidate_text(
    transaction: &mut Transaction<'_>,
    kind: &'static str,
    value: &str,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-authority:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&kind, &value],
    )?;
    Ok(())
}

fn lock_candidate_endpoint_name(
    transaction: &mut Transaction<'_>,
    cat_id: &Id,
    name: &Id,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-authority:endpoint-name:' || $1 || ':' || $2,
            0::BIGINT
         ))",
        &[&cat_id.as_str(), &name.as_str()],
    )?;
    Ok(())
}

fn lock_candidate_hostname(
    transaction: &mut Transaction<'_>,
    hostname: &Hostname,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':runtime-authority:hostname:' || $1,
            0::BIGINT
         ))",
        &[&hostname.as_str()],
    )?;
    Ok(())
}

fn result_from_envelope(
    request: &ApiIdempotencyRequest,
    response: &ExactHttpResponse,
    created_at: UnixMillis,
) -> ApiIdempotencyResult {
    ApiIdempotencyResult {
        authenticated_workspace_id: request.authenticated_workspace_id.clone(),
        canonical_route: request.canonical_route.clone(),
        idempotency_key: request.idempotency_key.clone(),
        request_fingerprint: request.request_fingerprint.clone(),
        http_status: response.http_status,
        content_type: response.content_type,
        response_body: response.response_body.clone(),
        created_at,
    }
}

fn check_replay(
    result: ApiIdempotencyResult,
    expected_fingerprint: &Sha256Digest,
) -> Result<ApiIdempotencyResult> {
    if result.request_fingerprint != *expected_fingerprint {
        return Err(ApiError::conflict(
            "idempotency key was already used for a different request",
        ));
    }
    Ok(result)
}

fn candidate_collision(kind: CandidateCollision) -> CreateCatTransactionError {
    CreateCatTransactionError::CandidateCollision(kind)
}

fn persistent_candidate_collision(
    kind: CandidateCollision,
) -> CreatePersistentDiskTransactionError {
    CreatePersistentDiskTransactionError::CandidateCollision(kind)
}

fn stored_corruption(_message: &'static str) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

fn invalid_bundle(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "covered Cat create candidate is inconsistent: {}",
        message.into()
    ))
}

fn invalid_persistent_disk_bundle(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "covered PersistentDisk create candidate is inconsistent: {}",
        message.into()
    ))
}

#[allow(
    dead_code,
    reason = "reachable with the A1 boundary when A2/G4 production routes are composed"
)]
fn invalid_desired_mutation_bundle(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "covered Desired mutation candidate is inconsistent: {}",
        message.into()
    ))
}
