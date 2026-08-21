//! Covered product-facing atomic Cat lifecycle mutation service.
//!
//! The public adapter authenticates before constructing this ingress. This
//! module owns exact API replay, atomic lifecycle command admission, terminal
//! Cold PersistentDisk configuration mutation, and the commit-ambiguity
//! boundary. Neither product path publishes a second lifecycle-intent stream.

use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::{ApiError, ErrorCode};
use cats_api::persistent_disk::{PersistentDiskBindingV2Error, PersistentDiskBindingV2Request};
use cats_api::runtime_lifecycle::{
    encode_immutable_runtime_config, encode_lifecycle_command_envelope, ColdSpec,
    ColdVolumeDisposition, ColdVolumeDispositionDigest, DeleteSpec, DiskRole as LifecycleDiskRole,
    ImmutableRuntimeConfig, LifecycleCommand, LifecycleCommandEnvelope, LifecycleOperation,
    LifecycleOperationState, LifecyclePredecessor, LifecycleTerminalResult, NodeResult,
    RequestedVolumeDisposition, RuntimeVolumeAuthorityInput, StartSource, StartSpec,
    StartVolumeAuthority, SuspendAdmissionPolicy, SuspendSpec, TerminalResultKind,
    VolumeTerminalReceipt, WarmSpec, LIFECYCLE_MAX_VOLUMES,
};
use cats_api::runtime_reconciliation::{AsciiText, Id, RandomId128, Sha256Digest, UnixMillis};
use cats_storage::lifecycle_volume::{
    command_cold_already_unowned_receipt_digest,
    command_cold_already_unowned_receipt_digest_from_closed_receipt,
    command_normal_release_receipt_digest,
    command_normal_release_receipt_digest_from_closed_receipt, LifecycleVolumeIdentity,
};
use postgres::Transaction;
use serde::{Deserialize, Serialize};

use super::cat_create_service::lock_cat_create_text;
use super::covered_commit::{CommitResolutionRegistry, CoveredCommitCancellation};
use super::lifecycle_commands::{
    admit_lifecycle_command_in, load_lifecycle_admission_context_in, LifecycleAdmissionContext,
    LifecycleAdmissionRejection, LifecycleCommandAdmission, LifecycleStableState,
};
use super::persistent_config_mutation::{
    commit_persistent_disk_binding_covered, PersistentDiskBindingCommitError,
};
use super::placement_planner::{
    revalidate_cold_start_placement, ColdStartPlacementLoad, ColdStartPlacementPlan,
    ColdStartPlacementRequest, OwnedPlannerExecution, PlacementCommitLoad,
};
use super::product::{
    api_request_fingerprint, ApiIdempotencyRequest, ApiIdempotencyResult, DiskAdminState,
    DiskRole as ProductDiskRole, ExactContentType, IfMatchFingerprint,
    PersistentDiskInitialization,
};
use super::product_identity::ProductIdentitySource;
use super::product_rows::{
    insert_api_result, load_api_result_for_update, load_disk_by_id_for_update,
};
use super::production_mutation_admission::require_production_product_mutation_admitted;
use super::rows::{
    database_now, load_command_already_unowned_receipt_for_update,
    load_command_normal_release_receipt_for_update, load_stored_volume_for_update,
};
use crate::store::transaction::{
    AuthorityExecutionError, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{Result, Store};
use cats_api::production_mutation_admission::ProductionQualificationMutationClass;

pub(crate) const PRODUCT_MUTATION_MAX_BODY_BYTES: usize = 4096;
pub(crate) const CAT_ACTION_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/cats/{cat}/actions/{verb}";
pub(crate) const PERSISTENT_DISK_ACTION_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/disks/{disk}/actions/{verb}";

const TOTAL_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const JSON_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const MAX_REPLANS: usize = 32;
const LIFECYCLE_GRACE_MS: u64 = 30_000;
const LIFECYCLE_CONVERGENCE_MS: u64 = 120_000;
const LIFECYCLE_EFFECT_MS: u64 = 120_000;
const LIFECYCLE_IN_PROGRESS_BODY: &[u8] =
    br#"{"code":"conflict","message":"a lifecycle operation is already unresolved"}"#;
const LIFECYCLE_PRECONDITION_BODY: &[u8] = br#"{"code":"failed_precondition","message":"lifecycle action is not valid from the exact terminal predecessor"}"#;
const LIFECYCLE_NOT_FOUND_BODY: &[u8] = br#"{"code":"not_found","message":"Cat not found"}"#;
const LIFECYCLE_RETIRED_BODY: &[u8] = br#"{"code":"failed_precondition","message":"a Deleted Cat cannot accept another lifecycle command"}"#;

#[derive(Debug, Clone, Default)]
pub(crate) struct ProductMutationHttpFields {
    pub(crate) content_type: Vec<Vec<u8>>,
    pub(crate) content_encoding: Vec<Vec<u8>>,
    pub(crate) if_match: Vec<Vec<u8>>,
    pub(crate) idempotency_key: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatLifecycleAction {
    Run,
    Suspend,
    Warm,
    Cold,
    Destroy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistentDiskBindingAction {
    Attach,
    Detach,
}

impl PersistentDiskBindingAction {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Attach => "attach",
            Self::Detach => "detach",
        }
    }
}

impl CatLifecycleAction {
    pub(crate) const fn requires_funding(self) -> bool {
        matches!(self, Self::Run)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductMutation {
    Lifecycle(CatLifecycleAction),
    PersistentDiskBinding {
        action: PersistentDiskBindingAction,
        disk_id: Id,
        request: PersistentDiskBindingV2Request,
    },
}

impl ProductMutation {
    fn canonical_route(&self) -> &'static str {
        match self {
            Self::Lifecycle(_) => CAT_ACTION_ROUTE,
            Self::PersistentDiskBinding { .. } => PERSISTENT_DISK_ACTION_ROUTE,
        }
    }

    fn has_json_body(&self) -> bool {
        matches!(self, Self::PersistentDiskBinding { .. })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedProductMutationIngress {
    pub(crate) mutation: ProductMutation,
    pub(crate) cat_id: Option<Id>,
    idempotency: ApiIdempotencyRequest,
    absolute_deadline: Instant,
}

impl AuthorizedProductMutationIngress {
    pub(crate) fn authenticated_workspace_id(&self) -> &Id {
        &self.idempotency.authenticated_workspace_id
    }

    pub(crate) fn absolute_deadline(&self) -> Instant {
        self.absolute_deadline
    }
}

pub(crate) fn product_mutation_absolute_deadline(received_at: Instant) -> Result<Instant> {
    received_at
        .checked_add(TOTAL_DEADLINE)
        .ok_or_else(|| ApiError::unavailable("product mutation deadline overflow"))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_authorized_product_mutation(
    authenticated_workspace_id: &Id,
    cat_id: Option<&str>,
    received_at: Instant,
    raw_path_and_query: &[u8],
    fields: &ProductMutationHttpFields,
    raw_body: &[u8],
    mutation: ProductMutation,
) -> Result<AuthorizedProductMutationIngress> {
    let absolute_deadline = product_mutation_absolute_deadline(received_at)?;
    if Instant::now() >= absolute_deadline {
        return Err(ApiError::unavailable("product mutation deadline elapsed"));
    }
    if raw_body.len() > PRODUCT_MUTATION_MAX_BODY_BYTES {
        return Err(ApiError::invalid(
            "product mutation body exceeds 4096 bytes",
        ));
    }
    match fields.content_encoding.as_slice() {
        [] => {}
        [value] if value.as_slice() == IDENTITY_CONTENT_ENCODING => {}
        _ => {
            return Err(ApiError::invalid(
                "Content-Encoding must be absent or one exact identity value",
            ));
        }
    }
    if mutation.has_json_body() {
        if fields.content_type.as_slice() != [JSON_CONTENT_TYPE] {
            return Err(ApiError::invalid(
                "Content-Type must occur once and equal application/json",
            ));
        }
    } else if !fields.content_type.is_empty() || !raw_body.is_empty() {
        return Err(ApiError::invalid(
            "this product mutation requires an empty body and no Content-Type",
        ));
    }
    if !fields.if_match.is_empty() {
        return Err(ApiError::invalid(
            "If-Match is not part of the atomic product mutation API",
        ));
    }
    let [idempotency_key] = fields.idempotency_key.as_slice() else {
        return Err(ApiError::invalid("Idempotency-Key must occur exactly once"));
    };
    let idempotency_key = trim_ows(idempotency_key);
    if idempotency_key.is_empty()
        || idempotency_key.len() > 512
        || !idempotency_key
            .iter()
            .all(|byte| (0x20..=0x7e).contains(byte))
    {
        return Err(ApiError::invalid(
            "Idempotency-Key must be 1..=512 printable ASCII bytes",
        ));
    }
    let idempotency_key = std::str::from_utf8(idempotency_key)
        .ok()
        .and_then(|value| AsciiText::new(value.to_owned()))
        .ok_or_else(|| ApiError::invalid("Idempotency-Key is invalid"))?;
    let supplied_cat_id = cat_id
        .map(|value| {
            Id::new(value.to_owned())
                .ok_or_else(|| ApiError::invalid("Cat ID is not a canonical runtime ID"))
        })
        .transpose()?;
    let cat_id = match &mutation {
        ProductMutation::Lifecycle(_) => supplied_cat_id,
        ProductMutation::PersistentDiskBinding { request, .. } => {
            if supplied_cat_id.is_some() {
                return Err(ApiError::invalid(
                    "PersistentDisk binding carries its Cat ID only in the closed body",
                ));
            }
            Some(request.cat_id.clone())
        }
    };
    validate_canonical_path(
        authenticated_workspace_id,
        cat_id.as_ref(),
        raw_path_and_query,
        &mutation,
    )?;
    let canonical_route =
        AsciiText::new(mutation.canonical_route()).expect("static product mutation route is ASCII");
    let request_fingerprint = api_request_fingerprint(
        authenticated_workspace_id,
        &canonical_route,
        raw_path_and_query,
        IfMatchFingerprint::Absent,
        raw_body,
    )?;
    Ok(AuthorizedProductMutationIngress {
        mutation,
        cat_id,
        idempotency: ApiIdempotencyRequest {
            authenticated_workspace_id: authenticated_workspace_id.clone(),
            canonical_route,
            idempotency_key,
            request_fingerprint,
        },
        absolute_deadline,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_authorized_persistent_disk_binding(
    authenticated_workspace_id: &Id,
    disk_id: &str,
    received_at: Instant,
    raw_path_and_query: &[u8],
    fields: &ProductMutationHttpFields,
    raw_body: &[u8],
    action: PersistentDiskBindingAction,
) -> Result<AuthorizedProductMutationIngress> {
    let disk_id = Id::new(disk_id.to_owned())
        .filter(|disk_id| disk_id.as_str().starts_with("disk_"))
        .ok_or_else(|| ApiError::invalid("Disk ID is not an immutable PersistentDisk ID"))?;
    let mut decoder = serde_json::Deserializer::from_slice(raw_body);
    let request = PersistentDiskBindingV2Request::deserialize(&mut decoder)
        .map_err(|_| ApiError::invalid("PersistentDisk binding body is malformed"))?;
    decoder
        .end()
        .map_err(|_| ApiError::invalid("PersistentDisk binding body has a non-whitespace tail"))?;
    request.validate().map_err(|error| match error {
        PersistentDiskBindingV2Error::CatId
        | PersistentDiskBindingV2Error::GuestRoot
        | PersistentDiskBindingV2Error::MountPath => ApiError::invalid(error.to_string()),
    })?;
    parse_authorized_product_mutation(
        authenticated_workspace_id,
        None,
        received_at,
        raw_path_and_query,
        fields,
        raw_body,
        ProductMutation::PersistentDiskBinding {
            action,
            disk_id,
            request,
        },
    )
}

fn validate_canonical_path(
    workspace_id: &Id,
    cat_id: Option<&Id>,
    raw: &[u8],
    mutation: &ProductMutation,
) -> Result<()> {
    let expected = match mutation {
        ProductMutation::Lifecycle(action) => {
            let verb = match action {
                CatLifecycleAction::Run => "run",
                CatLifecycleAction::Suspend => "suspend",
                CatLifecycleAction::Warm => "warm",
                CatLifecycleAction::Cold => "cold",
                CatLifecycleAction::Destroy => "destroy",
            };
            format!(
                "/v1/workspaces/{workspace_id}/cats/{}/actions/{verb}",
                required_cat(cat_id)?
            )
        }
        ProductMutation::PersistentDiskBinding {
            action, disk_id, ..
        } => format!(
            "/v1/workspaces/{workspace_id}/disks/{disk_id}/actions/{}",
            action.as_str()
        ),
    };
    if raw != expected.as_bytes() {
        return Err(ApiError::invalid(
            "product mutation path must use canonical IDs and no query",
        ));
    }
    Ok(())
}

fn required_cat(cat_id: Option<&Id>) -> Result<&Id> {
    cat_id.ok_or_else(|| ApiError::invalid("Cat mutation is missing its Cat ID"))
}

fn trim_ows(mut value: &[u8]) -> &[u8] {
    while value
        .first()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[1..];
    }
    while value
        .last()
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        value = &value[..value.len() - 1];
    }
    value
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProductMutationHttpResult {
    pub(crate) http_status: u16,
    pub(crate) content_type: Option<&'static str>,
    pub(crate) response_body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum ProductMutationServiceError {
    Request(ApiError),
    TemporarilyUnavailable,
    Fatal(ApiError),
}

impl ProductMutationServiceError {
    fn from_api(error: ApiError) -> Self {
        match error.code {
            ErrorCode::Unavailable | ErrorCode::DeadlineExceeded => Self::TemporarilyUnavailable,
            ErrorCode::Internal => Self::Fatal(error),
            _ => Self::Request(error),
        }
    }
}

impl From<ApiError> for ProductMutationServiceError {
    fn from(error: ApiError) -> Self {
        Self::from_api(error)
    }
}

enum CommitOutcome {
    Committed(ApiIdempotencyResult),
    CandidateIdentityCollision,
    PlacementStale,
}

enum AtomicLifecycleCommitError {
    CandidateIdentityCollision,
    PlacementStale,
    Store(ApiError),
}

#[derive(Debug, Serialize)]
struct LifecycleAcceptedResponse<'a> {
    operation_id: &'a Id,
}

pub(super) fn reserve_atomic_api_key(
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

pub(super) fn exact_api_replay(
    result: ApiIdempotencyResult,
    request: &ApiIdempotencyRequest,
) -> AuthorityTxResult<ApiIdempotencyResult> {
    if result.request_fingerprint != request.request_fingerprint {
        return Err(
            ApiError::conflict("idempotency key was already used for a different request").into(),
        );
    }
    Ok(result)
}

pub(super) fn atomic_api_result(
    request: &ApiIdempotencyRequest,
    http_status: u16,
    response_body: Vec<u8>,
    created_at: cats_api::runtime_reconciliation::UnixMillis,
) -> ApiIdempotencyResult {
    ApiIdempotencyResult {
        authenticated_workspace_id: request.authenticated_workspace_id.clone(),
        canonical_route: request.canonical_route.clone(),
        idempotency_key: request.idempotency_key.clone(),
        request_fingerprint: request.request_fingerprint.clone(),
        http_status,
        content_type: Some(ExactContentType::ApplicationJson),
        response_body,
        created_at,
    }
}

pub(super) fn store_atomic_fixed_result(
    transaction: &mut Transaction<'_>,
    request: &ApiIdempotencyRequest,
    http_status: u16,
    response_body: &[u8],
) -> AuthorityTxResult<ApiIdempotencyResult> {
    let now = database_now(transaction)?;
    let result = atomic_api_result(request, http_status, response_body.to_vec(), now);
    insert_api_result(transaction, &result)?;
    Ok(result)
}

fn lifecycle_deadline(
    now: cats_api::runtime_reconciliation::UnixMillis,
    delta_ms: u64,
) -> Result<cats_api::runtime_reconciliation::UnixMillis> {
    now.get()
        .checked_add(delta_ms)
        .and_then(cats_api::runtime_reconciliation::UnixMillis::new)
        .ok_or_else(|| ApiError::failed_precondition("lifecycle command deadline is exhausted"))
}

fn lifecycle_action_allowed(action: CatLifecycleAction, predecessor: TerminalResultKind) -> bool {
    use CatLifecycleAction::{Cold, Destroy, Run, Suspend, Warm};
    use TerminalResultKind::{
        Cold as WasCold, Deleted, HostLost, Killed, NeedsIntervention, RuntimeReady, StartFailed,
        SuspendDeclined, SuspendFailed, Suspended, Warm as WasWarm, WarmFailed,
    };
    match predecessor {
        RuntimeReady | SuspendDeclined => matches!(action, Suspend | Warm | Cold | Destroy),
        Suspended => matches!(action, Run | Warm | Cold | Destroy),
        WasWarm => matches!(action, Run | Cold | Destroy),
        WasCold => matches!(action, Run | Destroy),
        StartFailed | SuspendFailed | WarmFailed => action == Run,
        Killed | NeedsIntervention | HostLost | Deleted => false,
    }
}

fn same_node_start_source(kind: TerminalResultKind) -> Option<StartSource> {
    match kind {
        TerminalResultKind::Suspended => Some(StartSource::SameNodeSuspended),
        TerminalResultKind::Warm => Some(StartSource::SameNodeWarm),
        TerminalResultKind::Cold => Some(StartSource::SameNodeCold),
        TerminalResultKind::StartFailed
        | TerminalResultKind::SuspendFailed
        | TerminalResultKind::WarmFailed => Some(StartSource::SameNodeRetry),
        _ => None,
    }
}

fn same_node_receipt_authorities(
    config: &cats_api::runtime_lifecycle::ImmutableRuntimeConfig,
    receipts: &[VolumeTerminalReceipt],
) -> Result<Vec<StartVolumeAuthority>> {
    if receipts.len() != config.volumes.len() {
        return Err(ApiError::internal(
            "terminal volume receipts do not cover the immutable runtime config",
        ));
    }
    config
        .volumes
        .iter()
        .zip(receipts)
        .map(|(volume, receipt)| {
            if receipt.volume_id != volume.volume_id
                || receipt.disk_id != volume.disk_id
                || receipt.disk_role != volume.disk_role
            {
                return Err(ApiError::internal(
                    "terminal volume receipt order does not match the immutable runtime config",
                ));
            }
            Ok(StartVolumeAuthority {
                volume_id: volume.volume_id.clone(),
                disk_id: volume.disk_id.clone(),
                authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                    attachment_id: receipt.attachment_id.clone(),
                    attachment_epoch: receipt.attachment_epoch,
                },
            })
        })
        .collect()
}

fn failed_start_retry_authorities(
    config: &ImmutableRuntimeConfig,
    retained: &[VolumeTerminalReceipt],
    failed: &StartSpec,
) -> Result<Vec<StartVolumeAuthority>> {
    if failed.volume_authorities.len() != config.volumes.len()
        || retained.len() > config.volumes.len()
    {
        return Err(ApiError::failed_precondition(
            "failed Start does not carry a complete retry authority basis",
        ));
    }
    config
        .volumes
        .iter()
        .zip(&failed.volume_authorities)
        .map(|(volume, failed_authority)| {
            if failed_authority.volume_id != volume.volume_id
                || failed_authority.disk_id != volume.disk_id
            {
                return Err(ApiError::internal(
                    "failed Start authority order disagrees with its immutable config",
                ));
            }
            let retained = retained
                .binary_search_by(|receipt| {
                    receipt.volume_id.as_str().cmp(volume.volume_id.as_str())
                })
                .ok()
                .map(|index| &retained[index]);
            match retained {
                Some(receipt)
                    if receipt.volume_id == volume.volume_id
                        && receipt.disk_id == volume.disk_id
                        && receipt.disk_role == volume.disk_role =>
                {
                    Ok(StartVolumeAuthority {
                        volume_id: volume.volume_id.clone(),
                        disk_id: volume.disk_id.clone(),
                        authority: RuntimeVolumeAuthorityInput::SameNodeOwned {
                            attachment_id: receipt.attachment_id.clone(),
                            attachment_epoch: receipt.attachment_epoch,
                        },
                    })
                }
                Some(_) => Err(ApiError::internal(
                    "failed Start retained receipt disagrees with its immutable config",
                )),
                None if matches!(
                    &failed_authority.authority,
                    RuntimeVolumeAuthorityInput::NormalUnowned { .. }
                ) =>
                {
                    // Absence from the signed retained subset is useful only
                    // together with the failed Start's immutable input. Reuse
                    // that exact epoch and transition identity; never replace
                    // it with a value inferred from the current Volume row.
                    Ok(failed_authority.clone())
                }
                None => Err(ApiError::failed_precondition(
                    "failed Start omitted retained authority for a previously Owned volume",
                )),
            }
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColdTargetVolumeAuthority {
    volume_id: Id,
    disk_id: Id,
    expected_unowned_epoch: cats_api::runtime_reconciliation::FenceEpoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ColdReleaseEvidence {
    target_authorities: Vec<ColdTargetVolumeAuthority>,
    receipt_digests: Vec<ColdVolumeDispositionDigest>,
}

fn load_exact_cold_release_evidence(
    transaction: &mut Transaction<'_>,
    head: &LifecycleOperation,
    target_config: &ImmutableRuntimeConfig,
) -> AuthorityTxResult<ColdReleaseEvidence> {
    let cold_config = head.canonical_request.runtime_config.as_ref();
    let LifecycleOperationState::Terminal { terminal, .. } = &head.state else {
        return Err(ApiError::internal("Cold predecessor Operation is unresolved").into());
    };
    let LifecycleTerminalResult::NodeResult { response } = terminal.as_ref() else {
        return Err(ApiError::internal("Cold predecessor Operation is HostLost").into());
    };
    let NodeResult::Cold(cold) = &response.result else {
        return Err(ApiError::internal("Cold stable predecessor has a non-Cold result").into());
    };
    if head.runtime_config_id != cold_config.config_id
        || head.runtime_config_digest != cold_config.config_digest
        || cold.runtime_config_digest != cold_config.config_digest
        || cold.volume_dispositions.len() != cold_config.volumes.len()
    {
        return Err(ApiError::internal(
            "Cold predecessor does not cover its immutable runtime config",
        )
        .into());
    }

    // A Cold window may append more than one immutable product config. Lock
    // the complete successor volume set in its canonical volume-id order;
    // this is the set Start will actually acquire. Old, detached Cold slots
    // stay in the predecessor receipt set below but cannot influence a target
    // authority slot merely because they once appeared in the Cat config.
    let mut current_target_volumes = Vec::with_capacity(target_config.volumes.len());
    for volume in &target_config.volumes {
        let Some(current) = load_stored_volume_for_update(transaction, &volume.volume_id)? else {
            return Err(ApiError::internal(
                "Cold Start target is missing its Volume authority row",
            )
            .into());
        };
        if current.record.volume_id != volume.volume_id
            || current.record.size_bytes != volume.size_bytes
            || current.record.durability != volume.durability
            || !matches!(
                current.record.admin_state,
                cats_storage::authority::VolumeAdminState::Active
            )
            || current.record.lease_owner.is_some()
            || current.record.lease_expires_at.is_some()
            || current.owner_binding.is_some()
        {
            return Err(ApiError::failed_precondition(
                "Cold Start target Volume is not exact Active+Unowned authority",
            )
            .into());
        }
        current_target_volumes.push(current);
    }

    // Product Disk identity is not volume authority, but it is the immutable
    // role/UUID source from which the current config was appended. Recheck it
    // after the sorted Volume locks so a concurrent delete cannot turn a
    // previously valid binding into a Start command.
    let mut disk_order = target_config.volumes.iter().collect::<Vec<_>>();
    disk_order.sort_by(|left, right| left.disk_id.as_str().cmp(right.disk_id.as_str()));
    for volume in disk_order {
        let Some(disk) = load_disk_by_id_for_update(transaction, &volume.disk_id)? else {
            return Err(ApiError::internal("Cold Start target Disk row is missing").into());
        };
        let role_matches = match (&disk.role, volume.disk_role, &volume.guest_binding) {
            (
                ProductDiskRole::Root { cat_id },
                LifecycleDiskRole::Root,
                cats_api::runtime_lifecycle::RuntimeVolumeGuestBinding::RootBoot,
            ) => cat_id == &head.cat_id,
            (
                ProductDiskRole::Persistent { initialization },
                LifecycleDiskRole::Persistent,
                cats_api::runtime_lifecycle::RuntimeVolumeGuestBinding::PersistentExt4 {
                    filesystem_uuid,
                    ..
                },
            ) => match initialization.as_ref() {
                PersistentDiskInitialization::Uninitialized {
                    filesystem_uuid: stored,
                    ..
                }
                | PersistentDiskInitialization::Initialized {
                    filesystem_uuid: stored,
                    ..
                } => stored == filesystem_uuid,
            },
            _ => false,
        };
        if disk.workspace_id != head.workspace_id
            || disk.disk_id != volume.disk_id
            || disk.volume_id != volume.volume_id
            || disk.size_bytes != volume.size_bytes
            || disk.durability != volume.durability
            || !matches!(disk.admin_state, DiskAdminState::Active)
            || !role_matches
        {
            return Err(ApiError::internal(
                "Cold Start target Disk/config/Volume identity is corrupt",
            )
            .into());
        }
    }

    #[derive(Debug)]
    struct OldVolumeEvidence {
        volume_id: Id,
        disk_id: Id,
        disk_role: LifecycleDiskRole,
        expected_unowned_epoch: cats_api::runtime_reconciliation::FenceEpoch,
    }

    let mut old_volume_evidence = Vec::with_capacity(cold_config.volumes.len());
    let mut receipt_digests = Vec::with_capacity(cold_config.volumes.len());
    for (volume, terminal_disposition) in cold_config.volumes.iter().zip(&cold.volume_dispositions)
    {
        let current_target = target_config
            .volumes
            .binary_search_by(|candidate| {
                candidate.volume_id.as_str().cmp(volume.volume_id.as_str())
            })
            .ok()
            .map(|index| &current_target_volumes[index].record);
        let expected_unowned_epoch;
        match terminal_disposition {
            ColdVolumeDisposition::NormallyReleased {
                volume: terminal_receipt,
                normal_release_receipt_digest: terminal_digest,
            } => {
                let Some(stored) = load_command_normal_release_receipt_for_update(
                    transaction,
                    &head.operation_id,
                    &volume.volume_id,
                )?
                else {
                    return Err(ApiError::internal(
                        "terminal Cold predecessor is missing an immutable normal-release receipt",
                    )
                    .into());
                };
                let proof = &stored.receipt.durability;
                let request = &stored.receipt.request;
                let result = &stored.receipt.result;
                let computed = match current_target {
                    Some(current) => command_normal_release_receipt_digest(
                        &proof.scope,
                        &proof.volume,
                        current,
                        &stored.receipt,
                    ),
                    None => {
                        command_normal_release_receipt_digest_from_closed_receipt(&stored.receipt)
                    }
                }
                .map_err(|_| {
                    ApiError::internal(
                        "terminal Cold normal-release receipt is not exact closed authority",
                    )
                })?;
                if stored.operation != *head.canonical_request
                    || stored.delete_id.is_some()
                    || stored.receipt_digest != computed
                    || stored.receipt_digest != *terminal_digest
                    || terminal_receipt.authority_receipt_digest.as_ref() != Some(terminal_digest)
                    || proof.scope.operation_id != head.operation_id
                    || proof.scope.request_fingerprint != head.request_fingerprint
                    || proof.scope.cat_id != head.cat_id
                    || proof.scope.node_id != head.node_id
                    || proof.scope.placement_identity != head.placement_identity
                    || proof.volume.volume_id != volume.volume_id
                    || proof.volume.disk_id != volume.disk_id
                    || proof.volume.disk_role != volume.disk_role
                    || terminal_receipt.volume_id != volume.volume_id
                    || terminal_receipt.disk_id != volume.disk_id
                    || terminal_receipt.disk_role != volume.disk_role
                    || terminal_receipt.attachment_id != proof.volume.attachment_id
                    || terminal_receipt.attachment_epoch != proof.volume.attachment_epoch
                    || terminal_receipt.local_durable_generation != proof.local_durable_generation
                    || terminal_receipt.remote_durable_generation != proof.remote_durable_generation
                    || proof.local_durable_generation != proof.remote_durable_generation
                    || proof.remote_head.generation != proof.remote_durable_generation
                    || proof.pending_pack_count.get() != 0
                    || request.volume_id != volume.volume_id
                    || request.attachment_id != proof.volume.attachment_id
                    || request.expected_epoch != proof.volume.attachment_epoch
                    || result.volume_id != volume.volume_id
                    || result.transition_id != request.transition_id
                    || result.released_attachment_id != proof.volume.attachment_id
                    || result.resulting_head != proof.remote_head
                {
                    return Err(ApiError::internal(
                        "terminal Cold predecessor disagrees with its immutable normal-release receipt",
                    )
                    .into());
                }
                expected_unowned_epoch = result.resulting_epoch;
                receipt_digests.push(ColdVolumeDispositionDigest::NormallyReleased {
                    volume_id: volume.volume_id.clone(),
                    normal_release_receipt_digest: stored.receipt_digest,
                });
            }
            ColdVolumeDisposition::AlreadyUnowned {
                volume_id,
                disk_id,
                disk_role,
                unowned_epoch,
                remote_head,
                already_unowned_receipt_digest: terminal_digest,
            } => {
                let identity = LifecycleVolumeIdentity {
                    volume_id: volume_id.clone(),
                    disk_id: disk_id.clone(),
                    disk_role: *disk_role,
                };
                let Some(stored) = load_command_already_unowned_receipt_for_update(
                    transaction,
                    &head.operation_id,
                    &volume.volume_id,
                )?
                else {
                    return Err(ApiError::internal(
                        "terminal Cold predecessor is missing an immutable already-Unowned receipt",
                    )
                    .into());
                };
                let computed = match current_target {
                    Some(current) => command_cold_already_unowned_receipt_digest(
                        &stored.receipt.scope,
                        &identity,
                        current,
                        &stored.receipt,
                    ),
                    None => command_cold_already_unowned_receipt_digest_from_closed_receipt(
                        &stored.receipt,
                    ),
                }
                .map_err(|_| {
                    ApiError::internal(
                        "terminal Cold already-Unowned receipt is not exact closed authority",
                    )
                })?;
                if identity.volume_id != volume.volume_id
                    || identity.disk_id != volume.disk_id
                    || identity.disk_role != volume.disk_role
                    || stored.operation != *head.canonical_request
                    || stored.delete_id.is_some()
                    || stored.receipt.scope.operation_id != head.operation_id
                    || stored.receipt.scope.request_fingerprint != head.request_fingerprint
                    || stored.receipt.scope.cat_id != head.cat_id
                    || stored.receipt.scope.node_id != head.node_id
                    || stored.receipt.scope.placement_identity != head.placement_identity
                    || stored.receipt.volume != identity
                    || stored.receipt.expected_epoch != *unowned_epoch
                    || stored.receipt.expected_head != *remote_head
                    || stored.receipt_digest != computed
                    || stored.receipt_digest != *terminal_digest
                {
                    return Err(ApiError::internal(
                        "terminal Cold predecessor disagrees with its immutable already-Unowned receipt",
                    )
                    .into());
                }
                expected_unowned_epoch = *unowned_epoch;
                receipt_digests.push(ColdVolumeDispositionDigest::AlreadyUnowned {
                    volume_id: volume.volume_id.clone(),
                    already_unowned_receipt_digest: stored.receipt_digest,
                });
            }
        }
        old_volume_evidence.push(OldVolumeEvidence {
            volume_id: volume.volume_id.clone(),
            disk_id: volume.disk_id.clone(),
            disk_role: volume.disk_role,
            expected_unowned_epoch,
        });
    }

    let mut target_authorities = Vec::with_capacity(target_config.volumes.len());
    for (volume, current) in target_config.volumes.iter().zip(&current_target_volumes) {
        let old = old_volume_evidence
            .binary_search_by(|candidate| {
                candidate.volume_id.as_str().cmp(volume.volume_id.as_str())
            })
            .ok()
            .map(|index| &old_volume_evidence[index]);
        let expected_unowned_epoch = match old {
            Some(old) if old.disk_id == volume.disk_id && old.disk_role == volume.disk_role => {
                old.expected_unowned_epoch
            }
            Some(_) => {
                return Err(ApiError::internal(
                    "Cold predecessor and successor reuse a Volume with another Disk identity",
                )
                .into());
            }
            None if volume.disk_role == LifecycleDiskRole::Persistent => {
                // Membership was appended after Cold settled. The source
                // category still fixes this slot to NormalUnowned; the exact
                // locked authority row supplies only its expected epoch.
                current.record.lease_epoch
            }
            None => {
                return Err(ApiError::internal(
                    "Cold successor introduced a Root volume absent from its predecessor",
                )
                .into());
            }
        };
        target_authorities.push(ColdTargetVolumeAuthority {
            volume_id: volume.volume_id.clone(),
            disk_id: volume.disk_id.clone(),
            expected_unowned_epoch,
        });
    }
    Ok(ColdReleaseEvidence {
        target_authorities,
        receipt_digests,
    })
}

fn start_volume_authorities(
    config: &ImmutableRuntimeConfig,
    predecessor_command: &LifecycleCommandEnvelope,
    terminal: &LifecycleTerminalResult,
    normal_transition_ids: &[RandomId128],
    cold_release_evidence: Option<&ColdReleaseEvidence>,
) -> Result<Vec<StartVolumeAuthority>> {
    let LifecycleTerminalResult::NodeResult { response } = terminal else {
        return Err(ApiError::failed_precondition(
            "HostLost Start requires the external recovery flow",
        ));
    };
    match &response.result {
        NodeResult::Suspended(result) => {
            same_node_receipt_authorities(config, &result.local_durability_receipts)
        }
        NodeResult::Warm(result) => same_node_receipt_authorities(config, &result.volume_receipts),
        NodeResult::StartFailed(result) => {
            let LifecycleCommand::Start(failed) = &predecessor_command.command else {
                return Err(ApiError::internal(
                    "StartFailed terminal is not bound to an exact Start command",
                ));
            };
            failed_start_retry_authorities(config, &result.retained_volume_receipts, failed)
        }
        NodeResult::SuspendFailed(result) | NodeResult::WarmFailed(result) => {
            // These commands carry no Unowned input authority. Until the wire
            // has an explicit Unowned terminal disposition, product Run is
            // possible only when exact Owned receipts cover every config slot.
            if result.retained_volume_receipts.len() != config.volumes.len() {
                return Err(ApiError::failed_precondition(
                    "failed suspend/warm does not retain authority for every volume",
                ));
            }
            same_node_receipt_authorities(config, &result.retained_volume_receipts)
        }
        NodeResult::Cold(_) => {
            let evidence = cold_release_evidence.ok_or_else(|| {
                ApiError::internal("Cold Start omitted exact normal-release evidence")
            })?;
            if evidence.target_authorities.len() != config.volumes.len()
                || normal_transition_ids.len() < config.volumes.len()
            {
                return Err(ApiError::internal(
                    "Cold Start authorities do not cover the current immutable runtime config",
                ));
            }
            config
                .volumes
                .iter()
                .zip(&evidence.target_authorities)
                .zip(normal_transition_ids)
                .map(|((volume, authority), transition_id)| {
                    if authority.volume_id != volume.volume_id
                        || authority.disk_id != volume.disk_id
                    {
                        return Err(ApiError::internal(
                            "Cold Start authority order does not match the current runtime config",
                        ));
                    }
                    Ok(StartVolumeAuthority {
                        volume_id: volume.volume_id.clone(),
                        disk_id: volume.disk_id.clone(),
                        authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                            expected_unowned_epoch: authority.expected_unowned_epoch,
                            transition_id: transition_id.clone(),
                        },
                    })
                })
                .collect()
        }
        _ => Err(ApiError::failed_precondition(
            "this predecessor is not a product Run source",
        )),
    }
}

struct AtomicLifecycleCommandBuild<'a> {
    workspace_id: &'a Id,
    cat_id: &'a Id,
    operation_id: Id,
    action: CatLifecycleAction,
    context: &'a LifecycleAdmissionContext,
    cold_start_plan: Option<&'a ColdStartPlacementPlan>,
    now: UnixMillis,
    normal_transition_ids: &'a [RandomId128],
    delete_id: Option<&'a Id>,
}

fn build_atomic_lifecycle_command(
    transaction: &mut Transaction<'_>,
    build: AtomicLifecycleCommandBuild<'_>,
) -> AuthorityTxResult<LifecycleCommandEnvelope> {
    let AtomicLifecycleCommandBuild {
        workspace_id,
        cat_id,
        operation_id,
        action,
        context,
        cold_start_plan,
        now,
        normal_transition_ids,
        delete_id,
    } = build;
    let head = context.lifecycle_head.as_ref().ok_or_else(|| {
        AuthorityTransactionError::from(ApiError::failed_precondition(
            "Cat has no terminal lifecycle predecessor",
        ))
    })?;
    let (terminal, terminal_result_digest) = match &head.state {
        LifecycleOperationState::Terminal {
            terminal,
            terminal_result_digest,
        } => (terminal, terminal_result_digest),
        LifecycleOperationState::Unresolved => {
            return Err(ApiError::internal(
                "Cat lifecycle head unexpectedly references an unresolved Operation",
            )
            .into());
        }
    };
    let terminal_kind = terminal.kind();
    if !lifecycle_action_allowed(action, terminal_kind) {
        return Err(ApiError::failed_precondition(
            "lifecycle action is not valid from the exact terminal predecessor",
        )
        .into());
    }
    if (terminal_kind == TerminalResultKind::Cold && action == CatLifecycleAction::Run)
        != cold_start_plan.is_some()
    {
        return Err(AuthorityTransactionError::PlacementStale);
    }
    let target_runtime_config = cold_start_plan
        .map(|plan| &plan.target_runtime_config)
        .unwrap_or(&context.immutable_runtime_config);
    let cold_release_evidence =
        if action == CatLifecycleAction::Run && terminal_kind == TerminalResultKind::Cold {
            Some(load_exact_cold_release_evidence(
                transaction,
                head,
                target_runtime_config,
            )?)
        } else {
            None
        };
    let target_node_id = cold_start_plan
        .map(|plan| plan.target.node_id())
        .unwrap_or(&head.node_id);
    let target_placement = cold_start_plan
        .map(|plan| &plan.target_placement)
        .unwrap_or(&head.placement_identity);
    let cross_node_cold =
        cold_start_plan.is_some_and(|plan| plan.target.node_id() != &head.node_id);
    let grace_deadline = lifecycle_deadline(now, LIFECYCLE_GRACE_MS)?;
    let convergence_deadline = lifecycle_deadline(now, LIFECYCLE_CONVERGENCE_MS)?;
    let command = match action {
        CatLifecycleAction::Run => LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: start_volume_authorities(
                target_runtime_config,
                head.canonical_request.as_ref(),
                terminal,
                normal_transition_ids,
                cold_release_evidence.as_ref(),
            )?,
            source: if cross_node_cold {
                StartSource::ColdHandoff
            } else {
                same_node_start_source(terminal_kind).ok_or_else(|| {
                    ApiError::failed_precondition(
                        "this predecessor requires an external Start flow",
                    )
                })?
            },
            effect_deadline_unix_ms: lifecycle_deadline(now, LIFECYCLE_EFFECT_MS)?,
        })),
        CatLifecycleAction::Suspend => LifecycleCommand::Suspend(SuspendSpec {
            admission_policy: SuspendAdmissionPolicy::CloseAndDrain,
            grace_deadline_unix_ms: grace_deadline,
        }),
        CatLifecycleAction::Warm => LifecycleCommand::Warm(WarmSpec {
            grace_deadline_unix_ms: grace_deadline,
            convergence_deadline_unix_ms: convergence_deadline,
        }),
        CatLifecycleAction::Cold => LifecycleCommand::Cold(ColdSpec {
            grace_deadline_unix_ms: grace_deadline,
            convergence_deadline_unix_ms: convergence_deadline,
        }),
        CatLifecycleAction::Destroy => LifecycleCommand::Delete(DeleteSpec {
            delete_id: delete_id
                .cloned()
                .ok_or_else(|| ApiError::internal("Delete command has no durable delete_id"))?,
            grace_deadline_unix_ms: grace_deadline,
            convergence_deadline_unix_ms: convergence_deadline,
            volume_dispositions: context
                .immutable_runtime_config
                .volumes
                .iter()
                .map(|volume| match volume.disk_role {
                    LifecycleDiskRole::Root => RequestedVolumeDisposition::DiscardWithCat {
                        volume_id: volume.volume_id.clone(),
                        disk_id: volume.disk_id.clone(),
                        disk_role: volume.disk_role,
                    },
                    LifecycleDiskRole::Persistent => RequestedVolumeDisposition::RetainDetached {
                        volume_id: volume.volume_id.clone(),
                        disk_id: volume.disk_id.clone(),
                        disk_role: volume.disk_role,
                    },
                })
                .collect(),
        }),
    };
    let predecessor = if cross_node_cold {
        let plan = cold_start_plan.ok_or_else(|| {
            AuthorityTransactionError::from(ApiError::internal(
                "cross-Node Cold Start omitted its frozen placement",
            ))
        })?;
        let evidence = cold_release_evidence.as_ref().ok_or_else(|| {
            AuthorityTransactionError::from(ApiError::internal(
                "cross-Node Cold Start omitted its release receipt ledger",
            ))
        })?;
        LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id: head.operation_id.clone(),
            cold_result_digest: terminal_result_digest.clone(),
            source_node_id: head.node_id.clone(),
            source_placement: head.placement_identity.clone(),
            volume_disposition_receipts: evidence.receipt_digests.clone(),
            target_placement: plan.target_placement.clone(),
        }
    } else {
        LifecyclePredecessor::SameNode {
            operation_id: head.operation_id.clone(),
            terminal_result_kind: terminal_kind,
            terminal_result_digest: terminal_result_digest.clone(),
            node_id: head.node_id.clone(),
            placement_identity: head.placement_identity.clone(),
        }
    };
    LifecycleCommandEnvelope::new(
        operation_id,
        workspace_id.clone(),
        cat_id.clone(),
        target_node_id.clone(),
        target_placement.clone(),
        target_runtime_config.clone(),
        Some(head.operation_id.clone()),
        predecessor,
        command,
    )
    .map_err(|_| {
        AuthorityTransactionError::from(ApiError::internal(
            "constructed lifecycle command violates the frozen contract",
        ))
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeConfigAdvance {
    Unchanged,
    Advanced,
    CandidateIdentityCollision,
}

struct AtomicLifecycleCoveredCommit<'a> {
    ingress: &'a AuthorizedProductMutationIngress,
    cat_id: &'a Id,
    action: CatLifecycleAction,
    operation_id: &'a Id,
    normal_transition_ids: &'a [RandomId128],
    delete_id: Option<&'a Id>,
    cold_start_plan: Option<&'a ColdStartPlacementPlan>,
    commit_state: &'a super::covered_commit::CoveredCommitState,
}

fn append_and_advance_cold_runtime_config(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
    plan: &ColdStartPlacementPlan,
    now: UnixMillis,
) -> AuthorityTxResult<RuntimeConfigAdvance> {
    if !plan.advances_runtime_config() {
        return Ok(RuntimeConfigAdvance::Unchanged);
    }
    lock_cat_create_text(
        transaction,
        "config-id",
        plan.target_runtime_config.config_id.as_str(),
        "candidate",
    )?;
    let exists: bool = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM cat_runtime_configs WHERE config_id=$1)",
            &[&plan.target_runtime_config.config_id.as_str()],
        )?
        .try_get(0)?;
    if exists {
        return Ok(RuntimeConfigAdvance::CandidateIdentityCollision);
    }
    let canonical = encode_immutable_runtime_config(&plan.target_runtime_config).map_err(|_| {
        ApiError::internal("planned Cold successor runtime config cannot be encoded")
    })?;
    let now_pg = i64::try_from(now.get())
        .map_err(|_| ApiError::internal("database time exceeds PostgreSQL BIGINT"))?;
    transaction.execute(
        "INSERT INTO cat_runtime_configs (
            config_id, workspace_id, cat_id, canonical_config_bytes,
            canonical_config_sha256, created_at_unix_ms
         ) VALUES ($1,$2,$3,$4,$5,$6)",
        &[
            &plan.target_runtime_config.config_id.as_str(),
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &canonical,
            &plan.target_runtime_config.config_digest.as_str(),
            &now_pg,
        ],
    )?;
    let updated = transaction.execute(
        "UPDATE cat_records
            SET current_runtime_config_id=$1,
                current_runtime_config_sha256=$2
          WHERE workspace_id=$3 AND cat_id=$4
            AND current_runtime_config_id=$5
            AND current_runtime_config_sha256=$6
            AND stable_state='cold' AND deleted_at IS NULL
            AND NOT EXISTS (
                SELECT 1 FROM runtime_operations pending
                 WHERE pending.cat_id=cat_records.cat_id
                   AND pending.state='unresolved'
            )",
        &[
            &plan.target_runtime_config.config_id.as_str(),
            &plan.target_runtime_config.config_digest.as_str(),
            &workspace_id.as_str(),
            &cat_id.as_str(),
            &plan.source_runtime_config.config_id.as_str(),
            &plan.source_runtime_config.config_digest.as_str(),
        ],
    )?;
    if updated != 1 {
        return Err(AuthorityTransactionError::PlacementStale);
    }
    Ok(RuntimeConfigAdvance::Advanced)
}

impl Store {
    fn commit_atomic_lifecycle_covered(
        &self,
        commit: AtomicLifecycleCoveredCommit<'_>,
    ) -> std::result::Result<ApiIdempotencyResult, AtomicLifecycleCommitError> {
        let AtomicLifecycleCoveredCommit {
            ingress,
            cat_id,
            action,
            operation_id,
            normal_transition_ids,
            delete_id,
            cold_start_plan,
            commit_state,
        } = commit;
        let mut candidate_identity_collision = false;
        let outcome = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                commit_state.checkpoint(transaction)?;
                reserve_atomic_api_key(transaction, &ingress.idempotency)?;
                commit_state.checkpoint(transaction)?;
                if let Some(result) = load_api_result_for_update(transaction, &ingress.idempotency)?
                {
                    let result = exact_api_replay(result, &ingress.idempotency)?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                require_production_product_mutation_admitted(
                    transaction,
                    &ingress.idempotency.authenticated_workspace_id,
                    ProductionQualificationMutationClass::RuntimeMutation,
                )?;
                commit_state.checkpoint(transaction)?;
                let Some(context) = load_lifecycle_admission_context_in(
                    transaction,
                    &ingress.idempotency.authenticated_workspace_id,
                    cat_id,
                )?
                else {
                    let result = store_atomic_fixed_result(
                        transaction,
                        &ingress.idempotency,
                        404,
                        LIFECYCLE_NOT_FOUND_BODY,
                    )?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                };
                if context.deleted_at.is_some() {
                    let result = store_atomic_fixed_result(
                        transaction,
                        &ingress.idempotency,
                        412,
                        LIFECYCLE_RETIRED_BODY,
                    )?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                if context.unresolved_operation.is_some() {
                    let result = store_atomic_fixed_result(
                        transaction,
                        &ingress.idempotency,
                        409,
                        LIFECYCLE_IN_PROGRESS_BODY,
                    )?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                let now = database_now(transaction)?;
                let context_is_cold = context.stable_state == Some(LifecycleStableState::Cold)
                    && context.lifecycle_head.as_ref().is_some_and(|head| {
                        head.runtime_config_id == head.canonical_request.runtime_config.config_id
                            && head.runtime_config_digest
                                == head.canonical_request.runtime_config.config_digest
                            && matches!(
                                &head.state,
                                LifecycleOperationState::Terminal { terminal, .. }
                                    if matches!(
                                        terminal.as_ref(),
                                        LifecycleTerminalResult::NodeResult { response }
                                            if matches!(
                                                &response.result,
                                                NodeResult::Cold(cold)
                                                    if cold.runtime_config_digest
                                                        == head.runtime_config_digest
                                            )
                                    )
                            )
                    });
                if action == CatLifecycleAction::Run {
                    match (context_is_cold, cold_start_plan) {
                        (true, Some(plan)) => {
                            if revalidate_cold_start_placement(
                                transaction,
                                plan,
                                &context,
                                now,
                                &mut |transaction| commit_state.checkpoint(transaction),
                            )? != PlacementCommitLoad::Accepted
                            {
                                return Err(AuthorityTransactionError::PlacementStale);
                            }
                        }
                        (false, None) => {}
                        (true, None) | (false, Some(_)) => {
                            return Err(AuthorityTransactionError::PlacementStale);
                        }
                    }
                } else if cold_start_plan.is_some() {
                    return Err(ApiError::internal(
                        "non-Run lifecycle action received a Cold placement plan",
                    )
                    .into());
                }
                let command = match build_atomic_lifecycle_command(
                    transaction,
                    AtomicLifecycleCommandBuild {
                        workspace_id: &ingress.idempotency.authenticated_workspace_id,
                        cat_id,
                        operation_id: operation_id.clone(),
                        action,
                        context: &context,
                        cold_start_plan,
                        now,
                        normal_transition_ids,
                        delete_id,
                    },
                ) {
                    Ok(command) => command,
                    Err(AuthorityTransactionError::Application(error))
                        if error.code == ErrorCode::FailedPrecondition =>
                    {
                        let result = store_atomic_fixed_result(
                            transaction,
                            &ingress.idempotency,
                            412,
                            LIFECYCLE_PRECONDITION_BODY,
                        )?;
                        commit_state.begin_commit(transaction)?;
                        return Ok(result);
                    }
                    Err(error) => return Err(error),
                };
                let config_advanced = match cold_start_plan {
                    Some(plan) => match append_and_advance_cold_runtime_config(
                        transaction,
                        &ingress.idempotency.authenticated_workspace_id,
                        cat_id,
                        plan,
                        now,
                    )? {
                        RuntimeConfigAdvance::Unchanged => false,
                        RuntimeConfigAdvance::Advanced => true,
                        RuntimeConfigAdvance::CandidateIdentityCollision => {
                            candidate_identity_collision = true;
                            return Err(AuthorityTransactionError::CandidateCollision);
                        }
                    },
                    None => false,
                };
                let canonical = encode_lifecycle_command_envelope(&command).map_err(|_| {
                    AuthorityTransactionError::from(ApiError::internal(
                        "constructed lifecycle command cannot be encoded canonically",
                    ))
                })?;
                let admission = admit_lifecycle_command_in(
                    transaction,
                    &ingress.idempotency.authenticated_workspace_id,
                    &command,
                    &canonical,
                )?;
                let result = match admission {
                    LifecycleCommandAdmission::Admitted(operation) => {
                        let body = serde_json::to_vec(&LifecycleAcceptedResponse {
                            operation_id: &operation.operation_id,
                        })
                        .map_err(|_| {
                            AuthorityTransactionError::from(ApiError::internal(
                                "lifecycle accepted response cannot be encoded",
                            ))
                        })?;
                        let result = atomic_api_result(
                            &ingress.idempotency,
                            202,
                            body,
                            database_now(transaction)?,
                        );
                        insert_api_result(transaction, &result)?;
                        result
                    }
                    LifecycleCommandAdmission::ExactReplay(_) => {
                        candidate_identity_collision = true;
                        return Err(AuthorityTransactionError::CandidateCollision);
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::OperationIdentityConflict { .. },
                    ) => {
                        candidate_identity_collision = true;
                        return Err(AuthorityTransactionError::CandidateCollision);
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::LifecycleOperationInProgress { .. },
                    ) => {
                        if config_advanced {
                            return Err(AuthorityTransactionError::PlacementStale);
                        }
                        store_atomic_fixed_result(
                            transaction,
                            &ingress.idempotency,
                            409,
                            LIFECYCLE_IN_PROGRESS_BODY,
                        )?
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::CatNotFound
                        | LifecycleAdmissionRejection::WrongWorkspace,
                    ) => {
                        if config_advanced {
                            return Err(AuthorityTransactionError::PlacementStale);
                        }
                        store_atomic_fixed_result(
                            transaction,
                            &ingress.idempotency,
                            404,
                            LIFECYCLE_NOT_FOUND_BODY,
                        )?
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::CatDeleted,
                    ) => {
                        if config_advanced {
                            return Err(AuthorityTransactionError::PlacementStale);
                        }
                        store_atomic_fixed_result(
                            transaction,
                            &ingress.idempotency,
                            412,
                            LIFECYCLE_RETIRED_BODY,
                        )?
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::InvalidContract
                        | LifecycleAdmissionRejection::StaleOperation { .. }
                        | LifecycleAdmissionRejection::IllegalSuccessor { .. }
                        | LifecycleAdmissionRejection::HostFenceRecoveryUnavailable,
                    ) => {
                        if config_advanced {
                            return Err(AuthorityTransactionError::PlacementStale);
                        }
                        store_atomic_fixed_result(
                            transaction,
                            &ingress.idempotency,
                            412,
                            LIFECYCLE_PRECONDITION_BODY,
                        )?
                    }
                };
                commit_state.begin_commit(transaction)?;
                Ok(result)
            },
            || commit_state.reset_after_definite_retry(),
        );
        match outcome {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) if candidate_identity_collision => {
                Err(AtomicLifecycleCommitError::CandidateIdentityCollision)
            }
            Err(AuthorityExecutionError::PlacementStale) => {
                Err(AtomicLifecycleCommitError::PlacementStale)
            }
            Err(AuthorityExecutionError::Store(error)) => {
                Err(AtomicLifecycleCommitError::Store(error))
            }
            Err(AuthorityExecutionError::CandidateCollision) => {
                Err(AtomicLifecycleCommitError::Store(ApiError::internal(
                    "atomic lifecycle transaction lost its Operation collision",
                )))
            }
        }
    }
}

pub(crate) struct ProductMutationService {
    store: Arc<Store>,
    identities: Arc<dyn ProductIdentitySource>,
    commit_resolutions: Arc<CommitResolutionRegistry>,
    admission: tokio::sync::watch::Sender<bool>,
}

impl ProductMutationService {
    pub(crate) fn new(
        store: Arc<Store>,
        identities: Arc<dyn ProductIdentitySource>,
        _active_guest_digest: Sha256Digest,
    ) -> Self {
        let (admission, _) = tokio::sync::watch::channel(true);
        Self {
            store,
            identities,
            commit_resolutions: Arc::new(CommitResolutionRegistry::default()),
            admission,
        }
    }

    pub(crate) async fn replay(
        &self,
        ingress: &AuthorizedProductMutationIngress,
    ) -> std::result::Result<Option<ProductMutationHttpResult>, ProductMutationServiceError> {
        if !*self.admission.borrow() {
            return Err(ProductMutationServiceError::TemporarilyUnavailable);
        }
        let request = ingress.idempotency.clone();
        await_before_deadline(
            ingress.absolute_deadline,
            self.store
                .execute(move |store| store.covered_api_result_fast_lookup(&request)),
        )
        .await
        .map(|value| value.map(http_result))
        .map_err(ProductMutationServiceError::from_api)
    }

    pub(crate) async fn mutate(
        &self,
        ingress: AuthorizedProductMutationIngress,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        if let Some(result) = self.replay(&ingress).await? {
            return Ok(result);
        }
        match (ingress.mutation.clone(), ingress.cat_id.clone()) {
            (ProductMutation::Lifecycle(action), Some(cat_id)) => {
                self.mutate_lifecycle(ingress, cat_id, action).await
            }
            (ProductMutation::Lifecycle(_), None) => Err(ProductMutationServiceError::Request(
                ApiError::invalid("Cat mutation is missing its Cat ID"),
            )),
            (
                ProductMutation::PersistentDiskBinding {
                    action,
                    disk_id,
                    request,
                },
                Some(cat_id),
            ) if cat_id == request.cat_id => {
                self.mutate_persistent_disk_binding(ingress, disk_id, action, request)
                    .await
            }
            (ProductMutation::PersistentDiskBinding { .. }, _) => {
                Err(ProductMutationServiceError::Fatal(ApiError::internal(
                    "PersistentDisk binding ingress lost its exact Cat identity",
                )))
            }
        }
    }

    async fn mutate_persistent_disk_binding(
        &self,
        ingress: AuthorizedProductMutationIngress,
        disk_id: Id,
        action: PersistentDiskBindingAction,
        request: PersistentDiskBindingV2Request,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let mut shutdown = self.admission.subscribe();
        for _ in 0..MAX_REPLANS {
            if Instant::now() >= ingress.absolute_deadline || !*shutdown.borrow() {
                return Err(ProductMutationServiceError::TemporarilyUnavailable);
            }
            let candidate_config_id = prefixed_id("cfg_", self.identities.random_id()?)?;
            match self
                .commit_persistent_disk_binding(
                    ingress.clone(),
                    disk_id.clone(),
                    action,
                    request.clone(),
                    candidate_config_id,
                    ingress.absolute_deadline,
                    &mut shutdown,
                )
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::CandidateIdentityCollision | CommitOutcome::PlacementStale => {
                    continue;
                }
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    async fn mutate_lifecycle(
        &self,
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        action: CatLifecycleAction,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let mut shutdown = self.admission.subscribe();
        for _ in 0..MAX_REPLANS {
            if Instant::now() >= ingress.absolute_deadline || !*shutdown.borrow() {
                return Err(ProductMutationServiceError::TemporarilyUnavailable);
            }
            let cold_start_plan = if action == CatLifecycleAction::Run {
                let replacement_config_id = prefixed_id("cfg_", self.identities.random_id()?)?;
                let request = ColdStartPlacementRequest {
                    workspace_id: ingress.idempotency.authenticated_workspace_id.clone(),
                    cat_id: cat_id.clone(),
                    replacement_config_id,
                };
                let live = Arc::new(AtomicBool::new(true));
                let worker_live = Arc::clone(&live);
                let store = Arc::clone(&self.store);
                let worker_request = request.clone();
                let execution = store.execute(move |store| {
                    store.plan_cold_start_placement_until(
                        &worker_request,
                        ingress.absolute_deadline,
                        &worker_live,
                    )
                });
                let planning = await_before_deadline(
                    ingress.absolute_deadline,
                    OwnedPlannerExecution::new(live, execution),
                );
                tokio::pin!(planning);
                let outcome = tokio::select! {
                    outcome = &mut planning => outcome,
                    () = wait_for_shutdown(&mut shutdown) => {
                        return Err(ProductMutationServiceError::TemporarilyUnavailable);
                    }
                }
                .map_err(ProductMutationServiceError::from_api)?;
                match outcome {
                    ColdStartPlacementLoad::NotCold => None,
                    ColdStartPlacementLoad::Planned(plan) => Some(*plan),
                    ColdStartPlacementLoad::Unavailable => {
                        return Err(ProductMutationServiceError::TemporarilyUnavailable);
                    }
                    ColdStartPlacementLoad::CandidateIdentityCollision => continue,
                }
            } else {
                None
            };
            let operation_id = prefixed_id("op_", self.identities.random_id()?)?;
            let normal_transition_ids = if action == CatLifecycleAction::Run {
                (0..LIFECYCLE_MAX_VOLUMES)
                    .map(|_| self.identities.random_id())
                    .collect::<Result<Vec<_>>>()?
            } else {
                Vec::new()
            };
            let delete_id = if action == CatLifecycleAction::Destroy {
                Some(prefixed_id("delete_", self.identities.random_id()?)?)
            } else {
                None
            };
            match self
                .commit_atomic_lifecycle(
                    ingress.clone(),
                    cat_id.clone(),
                    action,
                    operation_id,
                    normal_transition_ids,
                    delete_id,
                    cold_start_plan,
                    ingress.absolute_deadline,
                    &mut shutdown,
                )
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::CandidateIdentityCollision | CommitOutcome::PlacementStale => {
                    continue;
                }
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_atomic_lifecycle(
        &self,
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        action: CatLifecycleAction,
        operation_id: Id,
        normal_transition_ids: Vec<RandomId128>,
        delete_id: Option<Id>,
        cold_start_plan: Option<ColdStartPlacementPlan>,
        deadline: Instant,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CommitOutcome, ProductMutationServiceError> {
        let resolution_request = ingress.idempotency.clone();
        let (cancellation, state) =
            CoveredCommitCancellation::new("atomic lifecycle mutation", deadline);
        let observer = state.clone();
        let cancellation_observer = state.clone();
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(ProductMutationServiceError::TemporarilyUnavailable);
        };
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store.execute(move |store| {
                Ok(
                    store.commit_atomic_lifecycle_covered(AtomicLifecycleCoveredCommit {
                        ingress: &ingress,
                        cat_id: &cat_id,
                        action,
                        operation_id: &operation_id,
                        normal_transition_ids: &normal_transition_ids,
                        delete_id: delete_id.as_ref(),
                        cold_start_plan: cold_start_plan.as_ref(),
                        commit_state: &state,
                    }),
                )
            });
            tokio::pin!(execution);
            let execution = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable("atomic lifecycle mutation cancelled before commit"))
                }
            };
            let outcome = match execution {
                Ok(Ok(result)) => Ok(CommitOutcome::Committed(result)),
                Ok(Err(AtomicLifecycleCommitError::CandidateIdentityCollision)) => {
                    Ok(CommitOutcome::CandidateIdentityCollision)
                }
                Ok(Err(AtomicLifecycleCommitError::PlacementStale)) => {
                    Ok(CommitOutcome::PlacementStale)
                }
                Ok(Err(AtomicLifecycleCommitError::Store(error))) | Err(error)
                    if observer.commit_was_sent() =>
                {
                    resolve_commit_loop(store, resolution_request, error)
                        .await
                        .map(CommitOutcome::Committed)
                }
                Ok(Err(AtomicLifecycleCommitError::Store(error))) | Err(error) => Err(error),
            };
            let _ = sender.send(outcome);
            drop(active);
        });
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let outcome = tokio::select! {
            result = &mut receiver => result.map_err(|_| ApiError::internal("atomic lifecycle commit owner stopped"))?,
            () = &mut sleep => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("atomic lifecycle commit owner stopped"))?
            },
            () = wait_for_shutdown(shutdown) => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("atomic lifecycle commit owner stopped"))?
            }
        };
        outcome.map_err(ProductMutationServiceError::from_api)
    }

    #[allow(clippy::too_many_arguments)]
    async fn commit_persistent_disk_binding(
        &self,
        ingress: AuthorizedProductMutationIngress,
        disk_id: Id,
        action: PersistentDiskBindingAction,
        request: PersistentDiskBindingV2Request,
        candidate_config_id: Id,
        deadline: Instant,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CommitOutcome, ProductMutationServiceError> {
        let resolution_request = ingress.idempotency.clone();
        let idempotency = ingress.idempotency.clone();
        let (cancellation, state) =
            CoveredCommitCancellation::new("PersistentDisk config mutation", deadline);
        let observer = state.clone();
        let cancellation_observer = state.clone();
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(ProductMutationServiceError::TemporarilyUnavailable);
        };
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store.execute(move |store| {
                Ok(commit_persistent_disk_binding_covered(
                    store,
                    &idempotency,
                    &disk_id,
                    action,
                    &request,
                    &candidate_config_id,
                    &state,
                ))
            });
            tokio::pin!(execution);
            let execution = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable("PersistentDisk config mutation cancelled before commit"))
                }
            };
            let outcome = match execution {
                Ok(Ok(result)) => Ok(CommitOutcome::Committed(result)),
                Ok(Err(PersistentDiskBindingCommitError::CandidateIdentityCollision)) => {
                    Ok(CommitOutcome::CandidateIdentityCollision)
                }
                Ok(Err(PersistentDiskBindingCommitError::CurrentHeadStale)) => {
                    Ok(CommitOutcome::PlacementStale)
                }
                Ok(Err(PersistentDiskBindingCommitError::Store(error))) | Err(error)
                    if observer.commit_was_sent() =>
                {
                    resolve_commit_loop(store, resolution_request, error)
                        .await
                        .map(CommitOutcome::Committed)
                }
                Ok(Err(PersistentDiskBindingCommitError::Store(error))) | Err(error) => Err(error),
            };
            let _ = sender.send(outcome);
            drop(active);
        });
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let outcome = tokio::select! {
            result = &mut receiver => result.map_err(|_| ApiError::internal("PersistentDisk config commit owner stopped"))?,
            () = &mut sleep => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("PersistentDisk config commit owner stopped"))?
            },
            () = wait_for_shutdown(shutdown) => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("PersistentDisk config commit owner stopped"))?
            }
        };
        outcome.map_err(ProductMutationServiceError::from_api)
    }

    pub(crate) fn begin_shutdown(&self) {
        self.commit_resolutions.close();
        self.admission.send_replace(false);
    }

    pub(crate) async fn shutdown_commit_resolutions(&self) -> Result<()> {
        self.begin_shutdown();
        tokio::time::timeout(SHUTDOWN_DEADLINE, self.commit_resolutions.wait_empty())
            .await
            .map_err(|_| ApiError::unavailable("product mutation commit resolution timed out"))
    }
}

fn prefixed_id(prefix: &str, random: cats_api::runtime_reconciliation::RandomId128) -> Result<Id> {
    Id::new(format!("{prefix}{}", random.as_str()))
        .ok_or_else(|| ApiError::internal("product mutation identity is invalid"))
}

async fn resolve_commit_loop(
    store: Arc<Store>,
    request: ApiIdempotencyRequest,
    original_error: ApiError,
) -> Result<ApiIdempotencyResult> {
    loop {
        let lookup = request.clone();
        match store
            .execute(move |store| store.covered_api_result_after_commit(&lookup))
            .await
        {
            Ok(Some(result)) => return Ok(result),
            Ok(None) => return Err(original_error),
            Err(error) if error.code == ErrorCode::Unavailable => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn await_before_deadline<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), future)
        .await
        .map_err(|_| ApiError::unavailable("product mutation deadline elapsed"))?
}

async fn wait_for_shutdown(shutdown: &mut tokio::sync::watch::Receiver<bool>) {
    if !*shutdown.borrow() {
        return;
    }
    while shutdown.changed().await.is_ok() {
        if !*shutdown.borrow() {
            return;
        }
    }
}

fn http_result(result: ApiIdempotencyResult) -> ProductMutationHttpResult {
    ProductMutationHttpResult {
        http_status: result.http_status,
        content_type: result.content_type.map(ExactContentType::as_str),
        response_body: result.response_body,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn fields(if_match: &[&[u8]]) -> ProductMutationHttpFields {
        ProductMutationHttpFields {
            content_type: Vec::new(),
            content_encoding: Vec::new(),
            if_match: if_match.iter().map(|value| value.to_vec()).collect(),
            idempotency_key: vec![b"exact-key".to_vec()],
        }
    }

    #[test]
    fn lifecycle_parser_closes_aliases_queries_and_nonempty_envelopes() {
        let workspace = id("ws_01");
        let action = ProductMutation::Lifecycle(CatLifecycleAction::Suspend);
        parse_authorized_product_mutation(
            &workspace,
            Some("cat_01"),
            Instant::now(),
            b"/v1/workspaces/ws_01/cats/cat_01/actions/suspend",
            &fields(&[]),
            b"",
            action.clone(),
        )
        .unwrap();
        for path in [
            b"/v1/workspaces/%77s_01/cats/cat_01/actions/suspend".as_slice(),
            b"/v1/workspaces/ws_01/cats/cat_01/actions/suspend?".as_slice(),
            b"/v1/workspaces/ws_01/cats/cat_01/actions/Suspend".as_slice(),
        ] {
            assert!(parse_authorized_product_mutation(
                &workspace,
                Some("cat_01"),
                Instant::now(),
                path,
                &fields(&[]),
                b"",
                action.clone(),
            )
            .is_err());
        }
        let mut with_type = fields(&[]);
        with_type.content_type.push(b"application/json".to_vec());
        assert!(parse_authorized_product_mutation(
            &workspace,
            Some("cat_01"),
            Instant::now(),
            b"/v1/workspaces/ws_01/cats/cat_01/actions/suspend",
            &with_type,
            b"",
            action,
        )
        .is_err());
    }

    #[test]
    fn product_run_uses_only_the_clean_slate_run_verb() {
        let workspace = id("ws_run");
        let action = ProductMutation::Lifecycle(CatLifecycleAction::Run);
        parse_authorized_product_mutation(
            &workspace,
            Some("cat_run"),
            Instant::now(),
            b"/v1/workspaces/ws_run/cats/cat_run/actions/run",
            &fields(&[]),
            b"",
            action.clone(),
        )
        .unwrap();
        for retired in ["start", "stop", "delete"] {
            let path = format!("/v1/workspaces/ws_run/cats/cat_run/actions/{retired}");
            assert!(parse_authorized_product_mutation(
                &workspace,
                Some("cat_run"),
                Instant::now(),
                path.as_bytes(),
                &fields(&[]),
                b"",
                action.clone(),
            )
            .is_err());
        }
    }

    #[test]
    fn atomic_lifecycle_rejects_every_if_match_spelling() {
        let workspace = id("ws_lifecycle");
        for values in [
            vec![b"7".to_vec()],
            vec![b"\"7\"".to_vec()],
            vec![b"*".to_vec()],
            vec![b"7".to_vec(), b"8".to_vec()],
        ] {
            let fields = ProductMutationHttpFields {
                if_match: values,
                ..fields(&[])
            };
            assert!(parse_authorized_product_mutation(
                &workspace,
                Some("cat_lifecycle"),
                Instant::now(),
                b"/v1/workspaces/ws_lifecycle/cats/cat_lifecycle/actions/run",
                &fields,
                b"",
                ProductMutation::Lifecycle(CatLifecycleAction::Run),
            )
            .is_err());
        }
    }

    #[test]
    fn persistent_disk_binding_parser_closes_path_body_and_headers() {
        let workspace = id("ws_binding");
        let body = br#"{"cat_id":"cat_binding","mount_path":"/srv/data"}"#;
        let mut binding_fields = fields(&[]);
        binding_fields.content_type = vec![b"application/json".to_vec()];

        for (action, verb) in [
            (PersistentDiskBindingAction::Attach, "attach"),
            (PersistentDiskBindingAction::Detach, "detach"),
        ] {
            let path = format!("/v1/workspaces/{workspace}/disks/disk_binding/actions/{verb}");
            let parsed = parse_authorized_persistent_disk_binding(
                &workspace,
                "disk_binding",
                Instant::now(),
                path.as_bytes(),
                &binding_fields,
                body,
                action,
            )
            .unwrap();
            assert!(matches!(
                parsed.mutation,
                ProductMutation::PersistentDiskBinding {
                    action: parsed_action,
                    disk_id,
                    request: PersistentDiskBindingV2Request { cat_id, mount_path },
                } if parsed_action == action
                    && disk_id == id("disk_binding")
                    && cat_id == id("cat_binding")
                    && mount_path.as_str() == "/srv/data"
            ));
            assert_eq!(
                parsed.idempotency.canonical_route.as_str(),
                PERSISTENT_DISK_ACTION_ROUTE
            );
        }

        for malformed_body in [
            br#"{"cat_id":"cat_binding","mount_path":"/"}"#.as_slice(),
            br#"{"cat_id":"cat_binding","mount_path":"/srv/data","legacy":true}"#,
            br#"{"cat_id":"cat_binding","mount_path":"relative"}"#,
            br#"{"cat_id":"dev","mount_path":"/srv/data"}"#,
            br#"{"cat_id":"cat_binding","mount_path":"/srv/data"}x"#,
        ] {
            assert!(parse_authorized_persistent_disk_binding(
                &workspace,
                "disk_binding",
                Instant::now(),
                b"/v1/workspaces/ws_binding/disks/disk_binding/actions/attach",
                &binding_fields,
                malformed_body,
                PersistentDiskBindingAction::Attach,
            )
            .is_err());
        }

        for (disk, path) in [
            (
                "data",
                b"/v1/workspaces/ws_binding/disks/data/actions/attach".as_slice(),
            ),
            (
                "disk_binding",
                b"/v1/workspaces/ws_binding/disks/disk_binding/actions/mount".as_slice(),
            ),
            (
                "disk_binding",
                b"/v1/workspaces/ws_binding/disks/disk_binding/actions/attach?".as_slice(),
            ),
        ] {
            assert!(parse_authorized_persistent_disk_binding(
                &workspace,
                disk,
                Instant::now(),
                path,
                &binding_fields,
                body,
                PersistentDiskBindingAction::Attach,
            )
            .is_err());
        }

        let mut bad_type = binding_fields.clone();
        bad_type.content_type = vec![b"application/json; charset=utf-8".to_vec()];
        let mut encoded = binding_fields.clone();
        encoded.content_encoding = vec![b"gzip".to_vec()];
        let mut matched = binding_fields.clone();
        matched.if_match = vec![b"*".to_vec()];
        let mut duplicate_key = binding_fields.clone();
        duplicate_key.idempotency_key.push(b"other".to_vec());
        for rejected_fields in [bad_type, encoded, matched, duplicate_key] {
            assert!(parse_authorized_persistent_disk_binding(
                &workspace,
                "disk_binding",
                Instant::now(),
                b"/v1/workspaces/ws_binding/disks/disk_binding/actions/attach",
                &rejected_fields,
                body,
                PersistentDiskBindingAction::Attach,
            )
            .is_err());
        }
    }

    #[test]
    fn persistent_disk_binding_fingerprint_closes_action_and_exact_body() {
        let workspace = id("ws_binding_fingerprint");
        let mut binding_fields = fields(&[]);
        binding_fields.content_type = vec![b"application/json".to_vec()];
        let attach_path =
            b"/v1/workspaces/ws_binding_fingerprint/disks/disk_binding/actions/attach";
        let attach = parse_authorized_persistent_disk_binding(
            &workspace,
            "disk_binding",
            Instant::now(),
            attach_path,
            &binding_fields,
            br#"{"cat_id":"cat_binding","mount_path":"/srv/data"}"#,
            PersistentDiskBindingAction::Attach,
        )
        .unwrap();
        let spaced = parse_authorized_persistent_disk_binding(
            &workspace,
            "disk_binding",
            Instant::now(),
            attach_path,
            &binding_fields,
            br#"{ "cat_id":"cat_binding", "mount_path":"/srv/data" }"#,
            PersistentDiskBindingAction::Attach,
        )
        .unwrap();
        let detach = parse_authorized_persistent_disk_binding(
            &workspace,
            "disk_binding",
            Instant::now(),
            b"/v1/workspaces/ws_binding_fingerprint/disks/disk_binding/actions/detach",
            &binding_fields,
            br#"{"cat_id":"cat_binding","mount_path":"/srv/data"}"#,
            PersistentDiskBindingAction::Detach,
        )
        .unwrap();
        assert_ne!(
            attach.idempotency.request_fingerprint,
            spaced.idempotency.request_fingerprint
        );
        assert_ne!(
            attach.idempotency.request_fingerprint,
            detach.idempotency.request_fingerprint
        );
    }

    #[test]
    fn lifecycle_idempotency_replays_only_the_exact_request_fingerprint() {
        let workspace = id("ws_lifecycle");
        let ingress = parse_authorized_product_mutation(
            &workspace,
            Some("cat_lifecycle"),
            Instant::now(),
            b"/v1/workspaces/ws_lifecycle/cats/cat_lifecycle/actions/destroy",
            &fields(&[]),
            b"",
            ProductMutation::Lifecycle(CatLifecycleAction::Destroy),
        )
        .unwrap();
        let result = atomic_api_result(
            &ingress.idempotency,
            202,
            br#"{"operation_id":"op_exact"}"#.to_vec(),
            cats_api::runtime_reconciliation::UnixMillis::new(1).unwrap(),
        );
        assert_eq!(
            exact_api_replay(result.clone(), &ingress.idempotency).unwrap(),
            result
        );

        let mut conflicting = ingress.idempotency.clone();
        conflicting.request_fingerprint = Sha256Digest::from_bytes([0x55; 32]);
        assert!(exact_api_replay(result, &conflicting).is_err());
    }

    #[test]
    fn product_lifecycle_matrix_has_only_run_suspend_warm_cold_destroy() {
        use cats_api::runtime_lifecycle::{LifecycleCommandKind, StopSpec};

        for action in [
            CatLifecycleAction::Suspend,
            CatLifecycleAction::Warm,
            CatLifecycleAction::Cold,
            CatLifecycleAction::Destroy,
        ] {
            assert!(lifecycle_action_allowed(
                action,
                TerminalResultKind::RuntimeReady
            ));
        }
        assert!(lifecycle_action_allowed(
            CatLifecycleAction::Run,
            TerminalResultKind::Suspended
        ));
        assert!(lifecycle_action_allowed(
            CatLifecycleAction::Run,
            TerminalResultKind::Warm
        ));
        assert!(lifecycle_action_allowed(
            CatLifecycleAction::Run,
            TerminalResultKind::Cold
        ));
        assert!(!lifecycle_action_allowed(
            CatLifecycleAction::Suspend,
            TerminalResultKind::Cold
        ));
        for predecessor in [
            TerminalResultKind::StartFailed,
            TerminalResultKind::SuspendFailed,
            TerminalResultKind::WarmFailed,
        ] {
            assert!(lifecycle_action_allowed(
                CatLifecycleAction::Run,
                predecessor
            ));
            for action in [
                CatLifecycleAction::Suspend,
                CatLifecycleAction::Warm,
                CatLifecycleAction::Cold,
                CatLifecycleAction::Destroy,
            ] {
                assert!(!lifecycle_action_allowed(action, predecessor));
            }
        }
        for predecessor in [
            TerminalResultKind::Killed,
            TerminalResultKind::NeedsIntervention,
            TerminalResultKind::HostLost,
            TerminalResultKind::Deleted,
        ] {
            for action in [
                CatLifecycleAction::Run,
                CatLifecycleAction::Suspend,
                CatLifecycleAction::Warm,
                CatLifecycleAction::Cold,
                CatLifecycleAction::Destroy,
            ] {
                assert!(!lifecycle_action_allowed(action, predecessor));
            }
        }

        // Product actions do not expose Stop/Killed, but the Node-private
        // execution protocol still keeps its strong-stop command distinct
        // from a remotely durable Cold transition.
        let now = cats_api::runtime_reconciliation::UnixMillis::new(1).unwrap();
        let stop = LifecycleCommand::Stop(StopSpec {
            grace_deadline_unix_ms: now,
        });
        let cold = LifecycleCommand::Cold(ColdSpec {
            grace_deadline_unix_ms: now,
            convergence_deadline_unix_ms: now,
        });
        assert_eq!(stop.kind(), LifecycleCommandKind::Stop);
        assert_eq!(cold.kind(), LifecycleCommandKind::Cold);
        assert_ne!(stop.kind(), cold.kind());
    }

    #[test]
    fn failed_start_retry_uses_receipts_and_exact_prior_unowned_inputs_per_slot() {
        use cats_api::runtime_lifecycle::{
            DiskRole, RuntimeNetworkConfig, RuntimeVolumeConfig, RuntimeVolumeGuestBinding,
        };
        use cats_api::runtime_reconciliation::{
            Durability, FenceEpoch, Generation, Ipv4Address, MacAddress,
        };

        let config = ImmutableRuntimeConfig::new(
            id("cfg_failed_retry"),
            Sha256Digest::from_bytes([1; 32]),
            1,
            512 * 1024 * 1024,
            Sha256Digest::from_bytes([2; 32]),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("net_failed_retry"),
                guest_mac: MacAddress::new("02:ca:00:00:00:03").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.6").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.5").unwrap(),
            },
            vec![
                RuntimeVolumeConfig {
                    volume_id: id("volume.00.failed.root"),
                    disk_id: id("disk.00.failed.root"),
                    disk_role: DiskRole::Root,
                    size_bytes: 4 * 1024 * 1024,
                    durability: Durability::Strict,
                    guest_device_serial: id("root-failed-retry"),
                    guest_device_slot: 0,
                    guest_binding: RuntimeVolumeGuestBinding::RootBoot,
                },
                RuntimeVolumeConfig {
                    volume_id: id("volume.01.failed.data"),
                    disk_id: id("disk.01.failed.data"),
                    disk_role: DiskRole::Persistent,
                    size_bytes: 4 * 1024 * 1024,
                    durability: Durability::Strict,
                    guest_device_serial: id("data-failed-retry"),
                    guest_device_slot: 1,
                    guest_binding: RuntimeVolumeGuestBinding::PersistentExt4 {
                        filesystem_uuid: RandomId128::new("ab".repeat(16)).unwrap(),
                        mount_path: AsciiText::new("/srv/data").unwrap(),
                    },
                },
            ],
        )
        .unwrap();
        let failed = StartSpec {
            volume_authorities: config
                .volumes
                .iter()
                .enumerate()
                .map(|(index, volume)| StartVolumeAuthority {
                    volume_id: volume.volume_id.clone(),
                    disk_id: volume.disk_id.clone(),
                    authority: RuntimeVolumeAuthorityInput::NormalUnowned {
                        expected_unowned_epoch: FenceEpoch::new(index as u64 + 1).unwrap(),
                        transition_id: RandomId128::new(format!("{:02x}", index + 1).repeat(16))
                            .unwrap(),
                    },
                })
                .collect(),
            source: StartSource::Genesis,
            effect_deadline_unix_ms: UnixMillis::new(1).unwrap(),
        };
        let receipt = |index: usize| VolumeTerminalReceipt {
            volume_id: config.volumes[index].volume_id.clone(),
            disk_id: config.volumes[index].disk_id.clone(),
            disk_role: config.volumes[index].disk_role,
            attachment_id: id(&format!("attachment-failed-{index}")),
            attachment_epoch: FenceEpoch::new(index as u64 + 10).unwrap(),
            local_durable_generation: Generation::new(4).unwrap(),
            remote_durable_generation: Generation::new(3).unwrap(),
            authority_receipt_digest: Some(Sha256Digest::from_bytes([index as u8 + 20; 32])),
        };

        assert_eq!(
            failed_start_retry_authorities(&config, &[], &failed).unwrap(),
            failed.volume_authorities
        );
        let partial = failed_start_retry_authorities(&config, &[receipt(0)], &failed).unwrap();
        assert!(matches!(
            &partial[0].authority,
            RuntimeVolumeAuthorityInput::SameNodeOwned { attachment_id, attachment_epoch }
                if attachment_id == &id("attachment-failed-0")
                    && *attachment_epoch == FenceEpoch::new(10).unwrap()
        ));
        assert_eq!(partial[1], failed.volume_authorities[1]);

        let full =
            failed_start_retry_authorities(&config, &[receipt(0), receipt(1)], &failed).unwrap();
        assert!(full.iter().all(|authority| matches!(
            &authority.authority,
            RuntimeVolumeAuthorityInput::SameNodeOwned { .. }
        )));

        let mut tampered = receipt(0);
        tampered.disk_id = id("disk.tampered");
        assert!(failed_start_retry_authorities(&config, &[tampered], &failed).is_err());

        let mut missing_owned = failed.clone();
        missing_owned.volume_authorities[1].authority =
            RuntimeVolumeAuthorityInput::SameNodeOwned {
                attachment_id: id("attachment-prior-owned"),
                attachment_epoch: FenceEpoch::new(30).unwrap(),
            };
        assert!(failed_start_retry_authorities(&config, &[receipt(0)], &missing_owned).is_err());

        use cats_api::runtime_lifecycle::{
            CommandFailedResult, CommandFailureReason, ExecutionAbsenceProof,
            LifecycleCommandResponse, PlacementIdentity, RetainedEvidence, WarmSpec,
        };
        use cats_api::runtime_reconciliation::Epoch;
        let placement = PlacementIdentity {
            node_id: id("node_failed_retry"),
            placement_epoch: Epoch::new(1).unwrap(),
        };
        for (suffix, command) in [
            (
                "suspend",
                LifecycleCommand::Suspend(SuspendSpec {
                    admission_policy: SuspendAdmissionPolicy::CloseAndDrain,
                    grace_deadline_unix_ms: UnixMillis::new(10).unwrap(),
                }),
            ),
            (
                "warm",
                LifecycleCommand::Warm(WarmSpec {
                    grace_deadline_unix_ms: UnixMillis::new(10).unwrap(),
                    convergence_deadline_unix_ms: UnixMillis::new(20).unwrap(),
                }),
            ),
        ] {
            let predecessor = LifecycleCommandEnvelope::new(
                id(&format!("operation_failed_{suffix}")),
                id("workspace_failed_retry"),
                id("cat_failed_retry"),
                placement.node_id.clone(),
                placement.clone(),
                config.clone(),
                Some(id("operation_ready_failed_retry")),
                LifecyclePredecessor::SameNode {
                    operation_id: id("operation_ready_failed_retry"),
                    terminal_result_kind: TerminalResultKind::RuntimeReady,
                    terminal_result_digest: Sha256Digest::from_bytes([60; 32]),
                    node_id: placement.node_id.clone(),
                    placement_identity: placement.clone(),
                },
                command,
            )
            .unwrap();
            let failed = CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: ExecutionAbsenceProof {
                    stop_fence_receipt_digest: Sha256Digest::from_bytes([61; 32]),
                    admission_closed_receipt_digest: Sha256Digest::from_bytes([62; 32]),
                    dedicated_scope_absence_receipt_digest: Sha256Digest::from_bytes([63; 32]),
                    frontend_absence_receipt_digest: Sha256Digest::from_bytes([64; 32]),
                    restart_source_absence_receipt_digest: Sha256Digest::from_bytes([65; 32]),
                },
                retained_evidence: RetainedEvidence {
                    artifact_manifest_digest: Sha256Digest::from_bytes([66; 32]),
                    adoptable_count: 0,
                    gc_candidate_count: 0,
                    retained_authority_or_data_count: 0,
                    quarantined_count: 0,
                },
                retained_volume_receipts: Vec::new(),
            };
            let result = match &predecessor.command {
                LifecycleCommand::Suspend(_) => NodeResult::SuspendFailed(Box::new(failed)),
                LifecycleCommand::Warm(_) => NodeResult::WarmFailed(Box::new(failed)),
                _ => unreachable!(),
            };
            let response = LifecycleCommandResponse::new(&predecessor, result).unwrap();
            let terminal = LifecycleTerminalResult::NodeResult {
                response: Box::new(response),
            };
            let error =
                start_volume_authorities(&config, &predecessor, &terminal, &[], None).unwrap_err();
            assert_eq!(error.code, ErrorCode::FailedPrecondition);
        }
    }

    #[test]
    fn cold_start_uses_the_release_resulting_unowned_epoch() {
        use cats_api::runtime_lifecycle::{
            ColdResult, DiskRole, ExecutionAbsenceProof, LifecycleCommandResponse,
            PlacementIdentity, RuntimeNetworkConfig, RuntimeVolumeConfig,
            RuntimeVolumeGuestBinding,
        };
        use cats_api::runtime_reconciliation::{
            ContractVersion, Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress,
            UnixMillis,
        };

        let config = ImmutableRuntimeConfig::new(
            id("cfg_cold_epoch"),
            Sha256Digest::from_bytes([1; 32]),
            1,
            512 * 1024 * 1024,
            Sha256Digest::from_bytes([2; 32]),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("net_cold_epoch"),
                guest_mac: MacAddress::new("02:ca:00:00:00:02").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_cold_epoch"),
                disk_id: id("disk_cold_epoch"),
                disk_role: DiskRole::Root,
                size_bytes: 4 * 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("root-cold-epoch"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .unwrap();
        let placement = PlacementIdentity {
            node_id: id("node_cold_epoch"),
            placement_epoch: Epoch::new(1).unwrap(),
        };
        let canonical_request = LifecycleCommandEnvelope::new(
            id("operation_cold_epoch"),
            id("workspace_cold_epoch"),
            id("cat_cold_epoch"),
            placement.node_id.clone(),
            placement.clone(),
            config.clone(),
            Some(id("operation_before_cold_epoch")),
            LifecyclePredecessor::SameNode {
                operation_id: id("operation_before_cold_epoch"),
                terminal_result_kind: TerminalResultKind::Killed,
                terminal_result_digest: Sha256Digest::from_bytes([3; 32]),
                node_id: placement.node_id.clone(),
                placement_identity: placement.clone(),
            },
            LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: UnixMillis::new(1).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(2).unwrap(),
            }),
        )
        .unwrap();
        let attachment_epoch = FenceEpoch::new(7).unwrap();
        let receipt_digest = Sha256Digest::from_bytes([4; 32]);
        let cold_result = NodeResult::Cold(Box::new(ColdResult {
            runtime_config_digest: config.config_digest.clone(),
            execution_absence: ExecutionAbsenceProof {
                stop_fence_receipt_digest: Sha256Digest::from_bytes([5; 32]),
                admission_closed_receipt_digest: Sha256Digest::from_bytes([6; 32]),
                dedicated_scope_absence_receipt_digest: Sha256Digest::from_bytes([7; 32]),
                frontend_absence_receipt_digest: Sha256Digest::from_bytes([8; 32]),
                restart_source_absence_receipt_digest: Sha256Digest::from_bytes([9; 32]),
            },
            volume_dispositions: vec![ColdVolumeDisposition::NormallyReleased {
                volume: Box::new(VolumeTerminalReceipt {
                    volume_id: config.volumes[0].volume_id.clone(),
                    disk_id: config.volumes[0].disk_id.clone(),
                    disk_role: DiskRole::Root,
                    attachment_id: id("attachment_cold_epoch"),
                    attachment_epoch,
                    local_durable_generation: Generation::new(9).unwrap(),
                    remote_durable_generation: Generation::new(9).unwrap(),
                    authority_receipt_digest: Some(receipt_digest.clone()),
                }),
                normal_release_receipt_digest: receipt_digest.clone(),
            }],
            local_recovery_dependency_absent_digest: Sha256Digest::from_bytes([10; 32]),
        }));
        let response = LifecycleCommandResponse {
            version: ContractVersion::V1,
            operation_id: canonical_request.operation_id.clone(),
            workspace_id: canonical_request.workspace_id.clone(),
            cat_id: canonical_request.cat_id.clone(),
            node_id: canonical_request.node_id.clone(),
            placement_identity: canonical_request.placement_identity.clone(),
            request_fingerprint: canonical_request.request_fingerprint.clone(),
            result: cold_result,
        };
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(response),
        };
        let evidence = ColdReleaseEvidence {
            target_authorities: vec![ColdTargetVolumeAuthority {
                volume_id: config.volumes[0].volume_id.clone(),
                disk_id: config.volumes[0].disk_id.clone(),
                expected_unowned_epoch: FenceEpoch::new(8).unwrap(),
            }],
            receipt_digests: vec![ColdVolumeDispositionDigest::NormallyReleased {
                volume_id: config.volumes[0].volume_id.clone(),
                normal_release_receipt_digest: receipt_digest,
            }],
        };
        let transition = RandomId128::new("12".repeat(16)).unwrap();
        let authorities = start_volume_authorities(
            &config,
            &canonical_request,
            &terminal,
            std::slice::from_ref(&transition),
            Some(&evidence),
        )
        .unwrap();
        assert!(matches!(
            &authorities[0].authority,
            RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch,
                transition_id,
            } if *expected_unowned_epoch == FenceEpoch::new(8).unwrap()
                && expected_unowned_epoch != &attachment_epoch
                && transition_id == &transition
        ));

        let incomplete = ColdReleaseEvidence {
            target_authorities: Vec::new(),
            receipt_digests: Vec::new(),
        };
        assert!(start_volume_authorities(
            &config,
            &canonical_request,
            &terminal,
            std::slice::from_ref(&transition),
            Some(&incomplete),
        )
        .is_err());
    }
}
