//! Covered Cat-create persistence boundary.
//!
//! This module intentionally stops at the Control Store. The HTTP and
//! controller cutover will call these APIs later; keeping the slice here lets
//! the atomic PostgreSQL contract land without a second authority or dual
//! write to the legacy product tables.

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{
    encode_desired_runtime_spec, AsciiText, ContractVersion, DesiredRuntimeSpec, DiskKind,
    Durability, Generation, Hostname, HttpProtocol, Id, Operation, OperationPhase, Revision,
    RuntimeTarget, RuntimeTransition, Sha256Digest, UnixMillis, VolumeAccess, VolumeAcquire,
    VolumeDisposition,
};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};
use postgres::Transaction;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::product_rows::{
    insert_api_result, insert_cat, insert_desired, insert_disk, insert_endpoint,
    insert_hostname_lookup, insert_operation, load_api_result_for_update,
    load_cat_by_id_for_update, load_cat_by_name_unlocked, load_desired_for_update,
    load_desired_unlocked, load_disk_by_id_for_update, load_disk_by_name_for_update,
    load_endpoint_by_cat_name_unlocked, load_endpoint_by_id_for_update,
    load_endpoint_by_id_unlocked, load_hostname_lookup_for_update, load_hostname_lookup_unlocked,
    load_hostname_lookups_by_cat_unlocked, load_operation_by_cat_revision_unlocked,
    load_operation_for_update, load_root_disk_by_cat_unlocked,
};
use super::rows::{database_now, insert_volume, load_volume_for_update};
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
    #[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
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
    #[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
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
}

#[derive(Debug)]
// F2a exposes this typed boundary before the service cutover consumes it.
#[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
pub(crate) enum CoveredCatCreateError {
    CandidateCollision(CandidateCollision),
    Store(ApiError),
}

type CoveredCatCreateResult<T> = std::result::Result<T, CoveredCatCreateError>;

enum CreateCatTransactionError {
    Authority(AuthorityTransactionError),
    CandidateCollision(CandidateCollision),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code, reason = "consumed by the later HTTP fingerprint cutover")]
pub(crate) enum IfMatchFingerprint {
    Absent,
    Generation(Generation),
}

/// Computes the one byte-level request fingerprint shared by every covered
/// Workspace product mutation. Envelope validation happens before this
/// boundary; this function deliberately does no JSON/path normalization.
#[allow(dead_code, reason = "consumed by the later HTTP fingerprint cutover")]
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

#[derive(Serialize)]
struct CatCreateAcceptedResponse<'a> {
    cat_id: &'a str,
    operation_id: &'a str,
}

pub(crate) fn encode_cat_create_accepted_response(
    cat_id: &Id,
    operation_id: &Id,
) -> Result<Vec<u8>> {
    serde_json::to_vec(&CatCreateAcceptedResponse {
        cat_id: cat_id.as_str(),
        operation_id: operation_id.as_str(),
    })
    .map_err(internal)
}

#[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
pub(crate) fn encode_cat_name_conflict_response() -> Vec<u8> {
    CAT_NAME_CONFLICT_BODY.to_vec()
}

impl Store {
    /// Optional preflight optimization. It never reserves the key and never
    /// reads a resource; the create transaction below always rechecks.
    #[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
    pub(crate) fn cat_create_result_fast_lookup(
        &self,
        request: &ApiIdempotencyRequest,
    ) -> Result<Option<ApiIdempotencyResult>> {
        super::product_rows::load_api_result_unlocked(self, request).and_then(|result| match result
        {
            Some(result) => check_replay(result, &request.request_fingerprint).map(Some),
            None => Ok(None),
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

    #[allow(dead_code, reason = "consumed by the later HTTP/service cutover")]
    pub(crate) fn create_cat_covered_with_admission(
        &self,
        request: &CoveredCatCreateRequest,
        planned_admission: &PlacementAdmissionSnapshot,
        active_guest_digest: &Sha256Digest,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        self.create_cat_covered_inner(request, Some((planned_admission, active_guest_digest)))
    }

    #[cfg(test)]
    pub(super) fn create_cat_covered_without_admission_for_product_test(
        &self,
        request: &CoveredCatCreateRequest,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        self.create_cat_covered_inner(request, None)
    }

    fn create_cat_covered_inner(
        &self,
        request: &CoveredCatCreateRequest,
        admission: Option<(&PlacementAdmissionSnapshot, &Sha256Digest)>,
    ) -> CoveredCatCreateResult<ApiIdempotencyResult> {
        let mut collision = None;
        let result = self.authority_transaction_outcome(|transaction| {
            match create_cat_in(transaction, request, admission) {
                Ok(result) => Ok(result),
                Err(CreateCatTransactionError::Authority(error)) => Err(error),
                Err(CreateCatTransactionError::CandidateCollision(kind)) => {
                    collision = Some(kind);
                    Err(AuthorityTransactionError::CandidateCollision)
                }
            }
        });
        match result {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) => match collision.take() {
                Some(kind) => Err(CoveredCatCreateError::CandidateCollision(kind)),
                None => Err(CoveredCatCreateError::Store(ApiError::internal(
                    "candidate-collision transaction lost its typed reason",
                ))),
            },
            Err(AuthorityExecutionError::Store(error)) => Err(CoveredCatCreateError::Store(error)),
        }
    }
}

fn create_cat_in(
    transaction: &mut Transaction<'_>,
    request: &CoveredCatCreateRequest,
    admission: Option<(&PlacementAdmissionSnapshot, &Sha256Digest)>,
) -> std::result::Result<ApiIdempotencyResult, CreateCatTransactionError> {
    reserve_api_key(transaction, &request.idempotency)?;
    if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)? {
        return check_replay(result, &request.idempotency.request_fingerprint)
            .map_err(AuthorityTransactionError::from)
            .map_err(CreateCatTransactionError::from);
    }

    validate_candidate(request).map_err(AuthorityTransactionError::from)?;
    lock_cat_name(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )?;
    if let Some(existing) = load_cat_by_name_unlocked(
        transaction,
        &request.candidate.workspace_id,
        &request.candidate.name,
    )? {
        if existing.cat_id == request.candidate.cat_id {
            return Err(candidate_collision(CandidateCollision::CatId));
        }
        validate_existing_cat_for_name_conflict(transaction, &existing)?;
        let now = database_now(transaction)?;
        let result =
            result_from_envelope(&request.idempotency, &request.envelopes.name_conflict, now);
        insert_api_result(transaction, &result)?;
        return Ok(result);
    }

    if let Some((planned, active_guest_digest)) = admission {
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

    lock_candidate_id(transaction, "volume", &request.candidate.volume.volume_id)?;
    if load_volume_for_update(transaction, &request.candidate.volume.volume_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::VolumeId));
    }

    lock_candidate_id(transaction, "cat", &request.candidate.cat_id)?;
    if load_cat_by_id_for_update(transaction, &request.candidate.cat_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::CatId));
    }

    lock_candidate_id(transaction, "disk", &request.candidate.root_disk.disk_id)?;
    if load_disk_by_id_for_update(transaction, &request.candidate.root_disk.disk_id)?.is_some()
        || load_disk_by_name_for_update(
            transaction,
            &request.candidate.root_disk.workspace_id,
            &request.candidate.root_disk.name,
        )?
        .is_some()
    {
        return Err(candidate_collision(CandidateCollision::DiskIdOrName));
    }

    lock_candidate_id(transaction, "desired", &request.candidate.cat_id)?;
    if load_desired_for_update(transaction, &request.candidate.cat_id)?.is_some() {
        return Err(stored_corruption("current Desired exists without its foreign-key Cat").into());
    }

    lock_candidate_id(
        transaction,
        "endpoint",
        &request.candidate.endpoint.endpoint_id,
    )?;
    lock_candidate_endpoint_name(
        transaction,
        &request.candidate.endpoint.cat_id,
        &request.candidate.endpoint.name,
    )?;
    if load_endpoint_by_id_for_update(transaction, &request.candidate.endpoint.endpoint_id)?
        .is_some()
        || load_endpoint_by_cat_name_unlocked(
            transaction,
            &request.candidate.endpoint.cat_id,
            &request.candidate.endpoint.name,
        )?
        .is_some()
    {
        return Err(candidate_collision(CandidateCollision::EndpointIdOrName));
    }

    lock_candidate_hostname(transaction, &request.candidate.hostname_lookup.hostname)?;
    if load_hostname_lookup_for_update(transaction, &request.candidate.hostname_lookup.hostname)?
        .is_some()
    {
        return Err(candidate_collision(CandidateCollision::Hostname));
    }

    lock_candidate_id(transaction, "operation", &request.candidate.operation_id)?;
    if load_operation_for_update(transaction, &request.candidate.operation_id)?.is_some() {
        return Err(candidate_collision(CandidateCollision::OperationId));
    }

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

    insert_volume(transaction, &request.candidate.volume)?;
    insert_cat(transaction, &cat)?;
    insert_disk(transaction, &disk)?;
    insert_desired(transaction, &request.candidate.desired)?;
    insert_endpoint(transaction, &endpoint)?;
    insert_hostname_lookup(transaction, &request.candidate.hostname_lookup)?;
    insert_operation(transaction, &operation)?;
    insert_api_result(transaction, &result)?;
    Ok(result)
}

fn validate_existing_cat_for_name_conflict(
    transaction: &mut Transaction<'_>,
    peeked_cat: &CatRecord,
) -> AuthorityTxResult<()> {
    let peeked_disk = load_root_disk_by_cat_unlocked(transaction, &peeked_cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat has no Root Disk"))?;

    lock_candidate_id(transaction, "volume", &peeked_disk.volume_id)?;
    let volume = load_volume_for_update(transaction, &peeked_disk.volume_id)?
        .ok_or_else(|| stored_corruption("existing Cat Root Volume disappeared"))?;

    lock_candidate_id(transaction, "cat", &peeked_cat.cat_id)?;
    let cat = load_cat_by_id_for_update(transaction, &peeked_cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat disappeared"))?;
    if cat != *peeked_cat {
        return Err(stored_corruption("existing Cat identity changed"));
    }

    lock_candidate_id(transaction, "disk", &peeked_disk.disk_id)?;
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

    lock_candidate_id(transaction, "desired", &cat.cat_id)?;
    let desired = load_desired_for_update(transaction, &cat.cat_id)?
        .ok_or_else(|| stored_corruption("existing Cat has no current Desired"))?;
    validate_existing_desired(&cat, &disk, &volume, &desired)?;

    validate_existing_endpoints(transaction, &cat, &desired)?;

    let peeked_operation = load_operation_by_cat_revision_unlocked(
        transaction,
        &cat.cat_id,
        desired.desired_revision,
    )?
    .ok_or_else(|| stored_corruption("existing Cat has no revision Operation"))?;
    lock_candidate_id(transaction, "operation", &peeked_operation.operation_id)?;
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
) -> AuthorityTxResult<()> {
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
        lock_candidate_id(transaction, "endpoint", &binding.endpoint_id)?;
        let endpoint = load_endpoint_by_id_for_update(transaction, &binding.endpoint_id)?
            .ok_or_else(|| stored_corruption("current Desired Endpoint has no product record"))?;
        if endpoint.workspace_id != cat.workspace_id || endpoint.cat_id != cat.cat_id {
            return Err(stored_corruption(
                "current Desired Endpoint product identity is invalid",
            ));
        }

        lock_candidate_hostname(transaction, &peeked_lookup.hostname)?;
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

fn validate_endpoint_lookup(
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

fn stored_corruption(_message: &'static str) -> AuthorityTransactionError {
    cats_storage::authority::AuthorityError::BackendUnknown.into()
}

fn invalid_bundle(message: impl Into<String>) -> ApiError {
    ApiError::internal(format!(
        "covered Cat create candidate is inconsistent: {}",
        message.into()
    ))
}
