//! Covered Cat-create persistence boundary.
//!
//! This module intentionally stops at the Control Store. The HTTP and
//! controller cutover will call these APIs later; keeping the slice here lets
//! the atomic PostgreSQL contract land without a second authority or dual
//! write to the legacy product tables.

use cats_api::chunk::MAX_VOLUME_BYTES;
use cats_api::error::ApiError;
use cats_api::persistent_disk::{
    encode_persistent_disk_create_response, persistent_disk_create_response,
    PERSISTENT_DISK_NAME_CONFLICT_BODY,
};
use cats_api::resources::DiskDurability as PublicDiskDurability;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AsciiText, ContractVersion, DesiredRuntimeSpec, DiskKind,
    Durability, FenceEpoch, Generation, Hostname, HttpProtocol, Id, Operation, OperationPhase,
    RandomId128, Revision, RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis,
    VolumeAccess, VolumeAcquire, VolumeDisposition,
};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};
use postgres::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::cat_create_service::CatCreatePlacementMutation;
use super::covered_commit::CoveredCommitState;
use super::placement_planner::{
    lock_cat_create_placement_for_desired_mutation, PlacementCommitLoad, PlacementTargetSnapshot,
};
use super::product_rows::{
    insert_api_result, insert_cat, insert_desired, insert_disk, insert_endpoint,
    insert_hostname_lookup, insert_operation, load_any_disk_by_filesystem_uuid_for_update,
    load_any_disk_by_id_for_update, load_any_disk_by_initialization_token_for_update,
    load_any_disk_by_name_unlocked, load_api_result_for_update, load_cat_by_id_for_update,
    load_cat_by_name_unlocked, load_desired_by_network_id_unlocked, load_desired_for_update,
    load_desired_unlocked, load_disk_by_id_for_update, load_disk_by_name_for_update,
    load_endpoint_by_cat_name_unlocked, load_endpoint_by_id_for_update,
    load_endpoint_by_id_unlocked, load_hostname_lookup_for_update, load_hostname_lookup_unlocked,
    load_hostname_lookups_by_cat_unlocked, load_operation_by_cat_revision_unlocked,
    load_operation_for_update, load_root_disk_by_cat_unlocked,
};
use super::rows::{
    database_now, insert_volume, load_any_volume_by_id_for_update, load_volume_for_update,
};
use super::runtime_spine::{
    lock_placement_admission_for_desired_mutation, PlacementAdmissionLoad,
    PlacementAdmissionSnapshot,
};
use crate::store::transaction::{
    AuthorityExecutionError, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{internal, Result, Store};

const MAX_RESPONSE_BODY_BYTES: usize = 1_048_576;
const CAT_NAME_CONFLICT_BODY: &[u8] =
    br#"{"code":"already_exists","message":"cat name already exists"}"#;

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

        checkpoint_cat_create(transaction, commit_state)?;
        lock_candidate_hostname(transaction, &peeked_lookup.hostname)?;
        checkpoint_cat_create(transaction, commit_state)?;
        let lookup = load_hostname_lookup_for_update(transaction, &peeked_lookup.hostname)?
            .ok_or_else(|| stored_corruption("current Desired hostname lookup disappeared"))?;
        if lookup != *peeked_lookup {
            return Err(stored_corruption(
                "current Desired hostname lookup changed while closing the graph",
            ));
        }
        validate_endpoint_lookup(&endpoint, &lookup, desired)?;
    }
    Ok(())
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
