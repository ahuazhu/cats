//! Neutral product catalog types and covered idempotency helpers.
//!
//! This module deliberately contains no lifecycle intent, Desired revision,
//! observation settlement, Route admission, or Volume transition admission.

use cats_api::chunk::MAX_VOLUME_BYTES;
use cats_api::error::ApiError;
use cats_api::persistent_disk::{
    encode_persistent_disk_create_response, persistent_disk_create_response,
    DiskDurability as PublicDiskDurability, PERSISTENT_DISK_NAME_CONFLICT_BODY,
};
use cats_api::production_mutation_admission::ProductionQualificationMutationClass;
use cats_api::runtime_lifecycle_volume::LifecycleStoredPersistentInitializationCommit;
use cats_api::runtime_reconciliation::{
    AsciiText, FenceEpoch, Generation, Id, RandomId128, Sha256Digest, UnixMillis,
};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};
use postgres::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::covered_commit::CoveredCommitState;
use super::product_rows::{
    insert_api_result, insert_disk, load_any_disk_by_filesystem_uuid_for_update,
    load_any_disk_by_id_for_update, load_any_disk_by_initialization_token_for_update,
    load_any_disk_by_name_unlocked, load_api_result_for_update,
};
use super::production_mutation_admission::require_production_product_mutation_admitted;
use super::rows::{database_now, insert_volume, load_any_volume_by_id_for_update};
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
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
    },
    Initialized {
        initialization_token: RandomId128,
        filesystem_uuid: RandomId128,
        expected_blank_head: RemoteHead,
        initialized_head: RemoteHead,
        initialized_at: UnixMillis,
        commit: Box<LifecycleStoredPersistentInitializationCommit>,
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
    DiskIdOrName,
    VolumeId,
    InitializationToken,
    FilesystemUuid,
}

#[derive(Debug)]
pub(crate) enum CoveredPersistentDiskCreateError {
    CandidateCollision(CandidateCollision),
    Store(ApiError),
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
}

pub(crate) fn api_request_fingerprint(
    authenticated_workspace_id: &Id,
    canonical_route: &AsciiText,
    raw_path_and_query: &[u8],
    if_match: IfMatchFingerprint,
    raw_body: &[u8],
) -> Result<Sha256Digest> {
    let if_match = match if_match {
        IfMatchFingerprint::Absent => [0_u8],
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
    pub(super) fn covered_api_result_fast_lookup(
        &self,
        request: &ApiIdempotencyRequest,
    ) -> Result<Option<ApiIdempotencyResult>> {
        super::product_rows::load_api_result_unlocked(self, request).and_then(|result| {
            result
                .map(|result| check_replay(result, &request.request_fingerprint))
                .transpose()
        })
    }

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

    pub(super) fn create_persistent_disk_covered(
        &self,
        request: &CoveredPersistentDiskCreateRequest,
        commit_state: &CoveredCommitState,
    ) -> std::result::Result<ApiIdempotencyResult, CoveredPersistentDiskCreateError> {
        let mut collision = None;
        let result = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                checkpoint_covered_commit(transaction, commit_state)?;
                match create_persistent_disk_in(transaction, request, commit_state) {
                    Ok(result) => {
                        checkpoint_covered_commit(transaction, commit_state)?;
                        commit_state.begin_commit(transaction)?;
                        Ok(result)
                    }
                    Err(CreatePersistentDiskTransactionError::Authority(error)) => Err(error),
                    Err(CreatePersistentDiskTransactionError::CandidateCollision(kind)) => {
                        collision = Some(kind);
                        Err(AuthorityTransactionError::CandidateCollision)
                    }
                }
            },
            || commit_state.reset_after_definite_retry(),
        );
        match result {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) => Err(collision
                .take()
                .map(CoveredPersistentDiskCreateError::CandidateCollision)
                .unwrap_or_else(|| {
                    CoveredPersistentDiskCreateError::Store(ApiError::internal(
                        "candidate-collision transaction lost its typed reason",
                    ))
                })),
            Err(AuthorityExecutionError::PlacementStale) => {
                Err(CoveredPersistentDiskCreateError::Store(ApiError::internal(
                    "PersistentDisk create returned an impossible placement marker",
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
    commit_state: &CoveredCommitState,
) -> std::result::Result<ApiIdempotencyResult, CreatePersistentDiskTransactionError> {
    checkpoint_covered_commit(transaction, commit_state)?;
    reserve_api_key(transaction, &request.idempotency)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        return check_replay(result, &request.idempotency.request_fingerprint)
            .map_err(CreatePersistentDiskTransactionError::from);
    }
    require_production_product_mutation_admitted(
        transaction,
        &request.idempotency.authenticated_workspace_id,
        ProductionQualificationMutationClass::DiskCreate,
    )?;
    validate_persistent_disk_candidate(request)?;

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_disk_name(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )?;
    if let Some(peeked_disk) = load_any_disk_by_name_unlocked(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )? {
        validate_existing_disk_for_name_conflict(transaction, &peeked_disk, commit_state)?;
        let now = database_now(transaction)?;
        let result = result_from_envelope(&request.idempotency, &request.name_conflict, now);
        insert_api_result(transaction, &result)?;
        return Ok(result);
    }

    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &request.candidate.volume_id)?;
    if load_any_volume_by_id_for_update(transaction, &request.candidate.volume_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::VolumeId));
    }
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &request.candidate.disk_id)?;
    if load_any_disk_by_id_for_update(transaction, &request.candidate.disk_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::DiskIdOrName));
    }
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_text(
        transaction,
        "disk-initialization-token",
        request.candidate.initialization_token.as_str(),
    )?;
    if load_any_disk_by_initialization_token_for_update(
        transaction,
        &request.candidate.initialization_token,
    )?
    .is_some()
    {
        return Err(candidate_collision(CandidateCollision::InitializationToken));
    }
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_text(
        transaction,
        "disk-filesystem-uuid",
        request.candidate.filesystem_uuid.as_str(),
    )?;
    if load_any_disk_by_filesystem_uuid_for_update(transaction, &request.candidate.filesystem_uuid)?
        .is_some()
    {
        return Err(candidate_collision(CandidateCollision::FilesystemUuid));
    }

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
            "name-conflict body is not canonical",
        ));
    }
    Ok(())
}

fn validate_prefixed_random_id(value: &Id, prefix: &'static str) -> Result<()> {
    let valid = value.as_str().strip_prefix(prefix).is_some_and(|suffix| {
        suffix.len() == 32
            && suffix
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    });
    if !valid {
        return Err(invalid_persistent_disk_bundle(format!(
            "identity must be {prefix} plus 32 lowercase hex digits"
        )));
    }
    Ok(())
}

fn validate_existing_disk_for_name_conflict(
    transaction: &mut Transaction<'_>,
    peeked_disk: &DiskRecord,
    commit_state: &CoveredCommitState,
) -> std::result::Result<(), CreatePersistentDiskTransactionError> {
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "volume", &peeked_disk.volume_id)?;
    let volume = load_any_volume_by_id_for_update(transaction, &peeked_disk.volume_id)?
        .ok_or_else(stored_corruption)?;
    checkpoint_covered_commit(transaction, commit_state)?;
    lock_candidate_id(transaction, "disk", &peeked_disk.disk_id)?;
    let disk = load_any_disk_by_id_for_update(transaction, &peeked_disk.disk_id)?
        .ok_or_else(stored_corruption)?;
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
        return Err(stored_corruption());
    }
    Ok(())
}

fn validate_envelope(response: &ExactHttpResponse, expected_status: u16) -> Result<()> {
    if response.http_status != expected_status
        || response.content_type != Some(ExactContentType::ApplicationJson)
        || response.response_body.len() > MAX_RESPONSE_BODY_BYTES
    {
        return Err(ApiError::invalid(format!(
            "HTTP envelope must be {expected_status} application/json within 1 MiB"
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

pub(super) fn lock_disk_name(
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

fn checkpoint_covered_commit(
    transaction: &mut Transaction<'_>,
    commit_state: &CoveredCommitState,
) -> AuthorityTxResult<()> {
    commit_state.checkpoint(transaction)
}

fn candidate_collision(kind: CandidateCollision) -> CreatePersistentDiskTransactionError {
    CreatePersistentDiskTransactionError::CandidateCollision(kind)
}

fn stored_corruption() -> CreatePersistentDiskTransactionError {
    CreatePersistentDiskTransactionError::Authority(
        cats_storage::authority::AuthorityError::BackendUnknown.into(),
    )
}

fn invalid_persistent_disk_bundle(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "covered PersistentDisk create candidate is inconsistent: {}",
        message.into()
    ))
}
