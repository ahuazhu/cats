//! Covered V2 Cat lifecycle mutation service.
//!
//! The public adapter authenticates before constructing this ingress.  This
//! module then owns exact replay, one complete Desired successor, and the A1
//! commit-ambiguity boundary. Endpoint epoch planning is intentionally owned
//! by `route_epoch_engine`; Disk begin-delete has its own cross-row path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::{ApiError, ErrorCode};
use cats_api::persistent_disk::{
    PersistentDiskBindingV2Request,
    PERSISTENT_DISK_BINDING_CONFLICT_BODY as DISK_BINDING_CONFLICT_BODY,
    PERSISTENT_DISK_BINDING_PRECONDITION_BODY as DISK_BINDING_PRECONDITION_BODY,
};
use cats_api::runtime_reconciliation::{
    spec_digest, AsciiText, DesiredRuntimeSpec, DiskKind, Durability, Epoch, Ext4MountIntent,
    FilesystemInitialization, Generation, GuestDeviceIdentity, HostPath, Hostname, Id, RandomId128,
    Revision, RuntimeTarget, RuntimeTransition, Sha256Digest, VolumeAccess, VolumeAcquire,
    VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{VolumeAdminState, VolumeDurability};
use postgres::Transaction;
use serde::Deserialize;

use super::covered_commit::{CommitResolutionRegistry, CoveredCommitCancellation};
use super::placement_planner::PlacementTargetSnapshot;
use super::placement_policy::load_policy_unlocked;
use super::product::{
    api_request_fingerprint, ApiIdempotencyRequest, ApiIdempotencyResult, CandidateCollision,
    CoveredDesiredMutationError, CoveredDesiredMutationRequest, CoveredDiskDeleteRequest,
    CoveredPlannedDesiredMutation, DesiredMutationCommit, DesiredVolumeMutation, DiskAdminState,
    DiskRole, EndpointRecordCandidate, ExactContentType, ExactHttpResponse, IfMatchFingerprint,
    PersistentDiskInitialization,
};
use super::product_identity::ProductIdentitySource;
use super::product_rows::{
    load_cat_by_id_unlocked, load_desired_by_disk_unlocked, load_desired_unlocked,
    load_disk_by_id_unlocked, load_endpoint_by_id_unlocked,
    load_operation_by_cat_revision_unlocked,
};
use super::route_epoch_engine::{
    plan_endpoint_route_mutation_in, EndpointBindingWithoutEpoch, EndpointMutation,
    RouteEpochMutationPlan,
};
use super::rows::{database_now, load_active_event_by_node_unlocked, load_volume_unlocked};
use super::runtime_spine::{
    load_placement_admission_at_in, placement_admission_observes_stable_cold,
    PlacementAdmissionLoad,
};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{Result, Store};

pub(crate) const PRODUCT_MUTATION_MAX_BODY_BYTES: usize = 4096;
pub(crate) const CAT_ACTION_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/cats/{cat}/actions/{verb}";
pub(crate) const CAT_DELETE_ROUTE: &str = "DELETE /v1/workspaces/{workspace}/cats/{cat}";
pub(crate) const ENDPOINT_BIND_ROUTE: &str = "POST /v1/workspaces/{workspace}/cats/{cat}/endpoints";
pub(crate) const ENDPOINT_UNBIND_ROUTE: &str =
    "DELETE /v1/workspaces/{workspace}/cats/{cat}/endpoints/{endpoint}";
pub(crate) const DISK_DELETE_ROUTE: &str = "DELETE /v1/workspaces/{workspace}/disks/{disk}";
pub(crate) const DISK_ATTACH_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/disks/{disk}/actions/attach";
pub(crate) const DISK_DETACH_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/disks/{disk}/actions/detach";

const TOTAL_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const JSON_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const MAX_REPLANS: usize = 32;
const IF_MATCH_BODY: &[u8] =
    br#"{"code":"conflict","message":"If-Match does not name the current Desired revision"}"#;
const PRECONDITION_BODY: &[u8] = br#"{"code":"failed_precondition","message":"lifecycle action is not valid from the current target"}"#;
const ENDPOINT_CONFLICT_BODY: &[u8] =
    br#"{"code":"conflict","message":"endpoint mutation conflicts with current authority"}"#;
const ENDPOINT_PRECONDITION_BODY: &[u8] = br#"{"code":"failed_precondition","message":"endpoint mutation is not valid for the current Cat"}"#;
const RETIRED_BODY: &[u8] =
    br#"{"code":"failed_precondition","message":"a Deleted Cat cannot be revived"}"#;

#[derive(Debug, Clone, Default)]
pub(crate) struct ProductMutationHttpFields {
    pub(crate) content_type: Vec<Vec<u8>>,
    pub(crate) content_encoding: Vec<Vec<u8>>,
    pub(crate) if_match: Vec<Vec<u8>>,
    pub(crate) idempotency_key: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CatLifecycleAction {
    Stop,
    Suspend,
    Warm,
    Resume,
}

impl CatLifecycleAction {
    const fn target(self) -> RuntimeTarget {
        match self {
            Self::Stop => RuntimeTarget::Cold,
            Self::Suspend => RuntimeTarget::Suspended,
            Self::Warm => RuntimeTarget::Warm,
            Self::Resume => RuntimeTarget::Running,
        }
    }

    pub(crate) const fn requires_funding(self) -> bool {
        matches!(self, Self::Resume)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EndpointBindBody {
    pub(crate) name: Id,
    pub(crate) hostname: Hostname,
    pub(crate) target_port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ProductMutation {
    Lifecycle(CatLifecycleAction),
    DeleteCat,
    BindEndpoint(EndpointBindBody),
    UnbindEndpoint {
        endpoint_id: Id,
    },
    DeleteDisk {
        disk_id: Id,
    },
    AttachDisk {
        disk_id: Id,
        binding: PersistentDiskBindingV2Request,
    },
    DetachDisk {
        disk_id: Id,
        binding: PersistentDiskBindingV2Request,
    },
}

impl ProductMutation {
    fn canonical_route(&self) -> &'static str {
        match self {
            Self::Lifecycle(_) => CAT_ACTION_ROUTE,
            Self::DeleteCat => CAT_DELETE_ROUTE,
            Self::BindEndpoint(_) => ENDPOINT_BIND_ROUTE,
            Self::UnbindEndpoint { .. } => ENDPOINT_UNBIND_ROUTE,
            Self::DeleteDisk { .. } => DISK_DELETE_ROUTE,
            Self::AttachDisk { .. } => DISK_ATTACH_ROUTE,
            Self::DetachDisk { .. } => DISK_DETACH_ROUTE,
        }
    }

    fn has_json_body(&self) -> bool {
        matches!(
            self,
            Self::BindEndpoint(_) | Self::AttachDisk { .. } | Self::DetachDisk { .. }
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PersistentDiskBindingAction {
    Attach,
    Detach,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedProductMutationIngress {
    pub(crate) mutation: ProductMutation,
    pub(crate) cat_id: Option<Id>,
    idempotency: ApiIdempotencyRequest,
    if_match: Option<Generation>,
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
    let if_match = parse_if_match(&fields.if_match)?;
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
    let cat_id = cat_id
        .map(|value| {
            Id::new(value.to_owned())
                .ok_or_else(|| ApiError::invalid("Cat ID is not a canonical runtime ID"))
        })
        .transpose()?;
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
        if_match.map_or(IfMatchFingerprint::Absent, IfMatchFingerprint::Generation),
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
        if_match,
        absolute_deadline,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn parse_authorized_endpoint_bind(
    authenticated_workspace_id: &Id,
    cat_id: &str,
    received_at: Instant,
    raw_path_and_query: &[u8],
    fields: &ProductMutationHttpFields,
    raw_body: &[u8],
) -> Result<AuthorizedProductMutationIngress> {
    // Validate the complete media/header/path/idempotency envelope before
    // parsing any JSON field. The placeholder never escapes this function and
    // contributes no bytes to the fingerprint.
    let placeholder = EndpointBindBody {
        name: Id::new("placeholder").expect("static placeholder ID is valid"),
        hostname: Hostname::new("placeholder.cats.invalid")
            .expect("static placeholder hostname is valid"),
        target_port: 1,
    };
    let mut ingress = parse_authorized_product_mutation(
        authenticated_workspace_id,
        Some(cat_id),
        received_at,
        raw_path_and_query,
        fields,
        raw_body,
        ProductMutation::BindEndpoint(placeholder),
    )?;
    let mut decoder = serde_json::Deserializer::from_slice(raw_body);
    let body = EndpointBindBody::deserialize(&mut decoder)
        .map_err(|_| ApiError::invalid("Endpoint bind body is malformed"))?;
    decoder
        .end()
        .map_err(|_| ApiError::invalid("Endpoint bind body has a non-whitespace tail"))?;
    if body.target_port == 0 {
        return Err(ApiError::invalid("Endpoint target_port must be non-zero"));
    }
    ingress.mutation = ProductMutation::BindEndpoint(body);
    Ok(ingress)
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
        .ok_or_else(|| ApiError::invalid("Disk ID is not a canonical runtime ID"))?;
    if !disk_id.as_str().starts_with("disk_") {
        return Err(ApiError::invalid("Disk ID is not an immutable Disk ID"));
    }
    let placeholder = PersistentDiskBindingV2Request {
        cat_id: Id::new("placeholder").expect("static placeholder ID is valid"),
        mount_path: HostPath::new("/placeholder").expect("static placeholder path is valid"),
    };
    let mutation = match action {
        PersistentDiskBindingAction::Attach => ProductMutation::AttachDisk {
            disk_id: disk_id.clone(),
            binding: placeholder,
        },
        PersistentDiskBindingAction::Detach => ProductMutation::DetachDisk {
            disk_id: disk_id.clone(),
            binding: placeholder,
        },
    };
    let mut ingress = parse_authorized_product_mutation(
        authenticated_workspace_id,
        None,
        received_at,
        raw_path_and_query,
        fields,
        raw_body,
        mutation,
    )?;
    let mut decoder = serde_json::Deserializer::from_slice(raw_body);
    let binding = PersistentDiskBindingV2Request::deserialize(&mut decoder)
        .map_err(|_| ApiError::invalid("PersistentDisk binding body is malformed"))?;
    decoder
        .end()
        .map_err(|_| ApiError::invalid("PersistentDisk binding body has a non-whitespace tail"))?;
    binding
        .validate()
        .map_err(|error| ApiError::invalid(error.to_string()))?;
    ingress.mutation = match action {
        PersistentDiskBindingAction::Attach => ProductMutation::AttachDisk { disk_id, binding },
        PersistentDiskBindingAction::Detach => ProductMutation::DetachDisk { disk_id, binding },
    };
    Ok(ingress)
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
                CatLifecycleAction::Stop => "stop",
                CatLifecycleAction::Suspend => "suspend",
                CatLifecycleAction::Warm => "warm",
                CatLifecycleAction::Resume => "resume",
            };
            format!(
                "/v1/workspaces/{workspace_id}/cats/{}/actions/{verb}",
                required_cat(cat_id)?
            )
        }
        ProductMutation::DeleteCat => {
            format!(
                "/v1/workspaces/{workspace_id}/cats/{}",
                required_cat(cat_id)?
            )
        }
        ProductMutation::BindEndpoint(_) => format!(
            "/v1/workspaces/{workspace_id}/cats/{}/endpoints",
            required_cat(cat_id)?
        ),
        ProductMutation::UnbindEndpoint { endpoint_id } => format!(
            "/v1/workspaces/{workspace_id}/cats/{}/endpoints/{endpoint_id}",
            required_cat(cat_id)?
        ),
        ProductMutation::DeleteDisk { disk_id } => {
            if cat_id.is_some() {
                return Err(ApiError::invalid("Disk delete cannot carry a Cat ID"));
            }
            format!("/v1/workspaces/{workspace_id}/disks/{disk_id}")
        }
        ProductMutation::AttachDisk { disk_id, .. } => {
            if cat_id.is_some() {
                return Err(ApiError::invalid("Disk attach cannot carry a path Cat ID"));
            }
            format!("/v1/workspaces/{workspace_id}/disks/{disk_id}/actions/attach")
        }
        ProductMutation::DetachDisk { disk_id, .. } => {
            if cat_id.is_some() {
                return Err(ApiError::invalid("Disk detach cannot carry a path Cat ID"));
            }
            format!("/v1/workspaces/{workspace_id}/disks/{disk_id}/actions/detach")
        }
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

fn parse_if_match(values: &[Vec<u8>]) -> Result<Option<Generation>> {
    let ([] | [_]) = values else {
        return Err(ApiError::invalid("If-Match may occur at most once"));
    };
    let Some(raw) = values.first() else {
        return Ok(None);
    };
    let raw = trim_ows(raw);
    let raw = if raw.len() >= 2 && raw.first() == Some(&b'"') && raw.last() == Some(&b'"') {
        &raw[1..raw.len() - 1]
    } else {
        raw
    };
    if raw.is_empty()
        || (raw.len() > 1 && raw.first() == Some(&b'0'))
        || !raw.iter().all(u8::is_ascii_digit)
    {
        return Err(ApiError::invalid("If-Match is not a canonical Generation"));
    }
    let value = std::str::from_utf8(raw)
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .and_then(Generation::new)
        .ok_or_else(|| ApiError::invalid("If-Match is not a canonical Generation"))?;
    Ok(Some(value))
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
struct LifecycleSnapshot {
    current: DesiredRuntimeSpec,
    endpoint_records: Vec<EndpointRecordCandidate>,
    placement_snapshots: Vec<PlacementTargetSnapshot>,
}

fn load_lifecycle_snapshot_in(
    transaction: &mut Transaction<'_>,
    workspace_id: &Id,
    cat_id: &Id,
) -> AuthorityTxResult<LifecycleSnapshot> {
    let cat = load_cat_by_id_unlocked(transaction, cat_id)?
        .filter(|cat| cat.workspace_id == *workspace_id)
        .ok_or_else(|| ApiError::not_found("Cat"))?;
    if cat.cat_id != *cat_id {
        return Err(ApiError::internal("Cat ID projection is corrupt").into());
    }
    let current = load_desired_unlocked(transaction, cat_id)?
        .ok_or_else(|| ApiError::internal("Cat has no current Desired"))?;
    if current.workspace_id != *workspace_id || current.cat_id != *cat_id {
        return Err(ApiError::internal("Cat/Desired workspace binding is corrupt").into());
    }
    let mut endpoint_records = Vec::with_capacity(current.endpoints.len());
    for endpoint in &current.endpoints {
        let record = load_endpoint_by_id_unlocked(transaction, &endpoint.endpoint_id)?
            .ok_or_else(|| ApiError::internal("Desired Endpoint record is missing"))?;
        if record.workspace_id != *workspace_id || record.cat_id != *cat_id {
            return Err(ApiError::internal("Endpoint product binding is corrupt").into());
        }
        endpoint_records.push(EndpointRecordCandidate {
            endpoint_id: record.endpoint_id,
            workspace_id: record.workspace_id,
            cat_id: record.cat_id,
            name: record.name,
        });
    }
    Ok(LifecycleSnapshot {
        current,
        endpoint_records,
        placement_snapshots: Vec::new(),
    })
}

fn enrich_lifecycle_placement_in(
    transaction: &mut Transaction<'_>,
    snapshot: &mut LifecycleSnapshot,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<()> {
    let node_id = &snapshot.current.placement.node_id;
    let now = database_now(transaction)?;
    let policy = load_policy_unlocked(transaction, node_id)?
        .ok_or_else(|| ApiError::internal("assigned Node placement policy is missing"))?;
    let active_host_fence_event = load_active_event_by_node_unlocked(transaction, node_id)?;
    let admission =
        match load_placement_admission_at_in(transaction, node_id, active_guest_digest, now)? {
            PlacementAdmissionLoad::Accepted(admission) => *admission,
            PlacementAdmissionLoad::Rejected(_) => {
                return Err(ApiError::unavailable(
                    "current placement is not admitted for lifecycle resume",
                )
                .into());
            }
        };
    snapshot.placement_snapshots = vec![PlacementTargetSnapshot {
        policy,
        admission,
        active_host_fence_event,
    }];
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn plan_persistent_disk_binding_in(
    transaction: &mut Transaction<'_>,
    ingress: &AuthorizedProductMutationIngress,
    disk_id: &Id,
    binding: &PersistentDiskBindingV2Request,
    action: PersistentDiskBindingAction,
    attach_candidate: Option<&PersistentDiskAttachCandidate>,
    operation_id: Id,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<CoveredPlannedDesiredMutation> {
    let workspace_id = &ingress.idempotency.authenticated_workspace_id;
    let snapshot = load_lifecycle_snapshot_in(transaction, workspace_id, &binding.cat_id)?;
    if ingress
        .if_match
        .is_some_and(|if_match| if_match.get() != snapshot.current.desired_revision.get())
    {
        return fixed_planned_result(409, IF_MATCH_BODY);
    }
    let disk = load_disk_by_id_unlocked(transaction, disk_id)?
        .filter(|disk| disk.workspace_id == *workspace_id)
        .ok_or_else(|| ApiError::not_found("Disk"))?;
    let volume = load_volume_unlocked(transaction, &disk.volume_id)?
        .ok_or_else(|| ApiError::internal("PersistentDisk Volume is missing"))?;
    if disk.disk_id != *disk_id
        || disk.volume_id != volume.volume_id
        || disk.size_bytes != volume.size_bytes
        || !stored_durability_matches(disk.durability, volume.durability)
    {
        return Err(ApiError::internal("PersistentDisk product authority is corrupt").into());
    }
    let current_binding = load_desired_by_disk_unlocked(transaction, disk_id)?;
    let precondition = matches!(disk.admin_state, DiskAdminState::Active)
        && matches!(volume.admin_state, VolumeAdminState::Active)
        && volume.lease_owner.is_none()
        && volume.lease_expires_at.is_none()
        && snapshot.current.target == RuntimeTarget::Cold
        && exact_settled_cold_in(transaction, &snapshot.current, active_guest_digest)?;

    let (desired, volume_mutation) = match action {
        PersistentDiskBindingAction::Attach => {
            if current_binding.is_some() {
                return fixed_planned_result(409, DISK_BINDING_CONFLICT_BODY);
            }
            let Some(candidate) = attach_candidate else {
                return Err(ApiError::internal("Disk attach identity candidate is missing").into());
            };
            if !precondition || snapshot.current.volumes.len() >= 64 {
                return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
            }
            let DiskRole::Persistent { initialization } = &disk.role else {
                return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
            };
            if snapshot.current.volumes.iter().any(|intent| {
                intent.disk_id == disk.disk_id
                    || intent.volume_id == disk.volume_id
                    || intent
                        .mount
                        .as_ref()
                        .is_some_and(|mount| mount.mount_path == binding.mount_path)
            }) {
                return fixed_planned_result(409, DISK_BINDING_CONFLICT_BODY);
            }
            let next_revision = next_desired_revision(snapshot.current.desired_revision)?;
            let volume_intent_id = Id::new(format!(
                "vint_z{:016x}_{}",
                next_revision.get(),
                candidate.binding_random.as_str()
            ))
            .ok_or_else(|| ApiError::internal("Disk attach VolumeIntent ID is invalid"))?;
            if snapshot
                .current
                .volumes
                .last()
                .is_some_and(|intent| intent.volume_intent_id >= volume_intent_id)
            {
                return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
            }
            let attachment_id = Id::new(format!("att_{}", candidate.binding_random.as_str()))
                .ok_or_else(|| ApiError::internal("Disk attach attachment ID is invalid"))?;
            let serial = Id::new(format!(
                "cats-pd-{}",
                &candidate.serial_random.as_str()[..12]
            ))
            .ok_or_else(|| ApiError::internal("Disk attach Guest serial is invalid"))?;
            if snapshot
                .current
                .volumes
                .iter()
                .any(|intent| intent.guest_device.serial == serial)
            {
                return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
            }
            let filesystem_uuid = match initialization.as_ref() {
                PersistentDiskInitialization::Uninitialized {
                    filesystem_uuid, ..
                }
                | PersistentDiskInitialization::Initialized {
                    filesystem_uuid, ..
                } => filesystem_uuid.clone(),
            };
            let filesystem_initialization = match initialization.as_ref() {
                PersistentDiskInitialization::Uninitialized {
                    initialization_token,
                    filesystem_uuid: _,
                    expected_blank_head,
                } => {
                    if volume.head != *expected_blank_head {
                        return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
                    }
                    FilesystemInitialization::Initialize {
                        initialization_token: initialization_token.clone(),
                        expected_blank_head: expected_blank_head.clone(),
                    }
                }
                PersistentDiskInitialization::Initialized {
                    initialized_head, ..
                } => {
                    if initialized_head.generation.get() == 0
                        || (volume.head.generation.get() < initialized_head.generation.get())
                        || (volume.head.generation == initialized_head.generation
                            && volume.head != *initialized_head)
                    {
                        return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
                    }
                    FilesystemInitialization::Existing
                }
            };
            let mut desired = snapshot.current.clone();
            desired.desired_revision = next_revision;
            desired.volumes.push(VolumeIntent {
                volume_intent_id: volume_intent_id.clone(),
                disk_id: disk.disk_id.clone(),
                volume_id: disk.volume_id.clone(),
                attachment_id: attachment_id.clone(),
                size_bytes: disk.size_bytes,
                disk_kind: DiskKind::Persistent,
                access: VolumeAccess::ReadWriteOnce,
                durability: intent_durability(disk.durability),
                guest_device: GuestDeviceIdentity {
                    serial,
                    slot: u16::try_from(snapshot.current.volumes.len()).map_err(|_| {
                        ApiError::failed_precondition("PersistentDisk slot space is exhausted")
                    })?,
                },
                acquire: VolumeAcquire::Normal {
                    transition_id: candidate.transition_id.clone(),
                    expected_unowned_epoch: volume.lease_epoch,
                },
                disposition: VolumeDisposition::Retain,
                mount: Some(Ext4MountIntent {
                    filesystem_uuid,
                    mount_path: binding.mount_path.clone(),
                    initialization: filesystem_initialization,
                }),
            });
            finalize_binding_desired(&mut desired)?;
            (
                desired,
                DesiredVolumeMutation::AttachPersistent {
                    disk_id: disk.disk_id.clone(),
                    volume_id: disk.volume_id.clone(),
                    volume_intent_id,
                    attachment_id,
                },
            )
        }
        PersistentDiskBindingAction::Detach => {
            let Some(bound) = current_binding.as_ref() else {
                return fixed_planned_result(409, DISK_BINDING_CONFLICT_BODY);
            };
            let Some(index) = bound.volumes.iter().position(|intent| {
                intent.disk_id == *disk_id
                    && intent.disk_kind == DiskKind::Persistent
                    && intent
                        .mount
                        .as_ref()
                        .is_some_and(|mount| mount.mount_path == binding.mount_path)
            }) else {
                return fixed_planned_result(409, DISK_BINDING_CONFLICT_BODY);
            };
            if bound != &snapshot.current || bound.cat_id != binding.cat_id {
                return fixed_planned_result(409, DISK_BINDING_CONFLICT_BODY);
            }
            if !precondition {
                return fixed_planned_result(412, DISK_BINDING_PRECONDITION_BODY);
            }
            let removed = snapshot.current.volumes[index].clone();
            let mut desired = snapshot.current.clone();
            desired.desired_revision = next_desired_revision(desired.desired_revision)?;
            desired.volumes.remove(index);
            for (slot, intent) in desired.volumes.iter_mut().enumerate() {
                intent.guest_device.slot = u16::try_from(slot).map_err(|_| {
                    ApiError::failed_precondition("PersistentDisk slot space is exhausted")
                })?;
            }
            finalize_binding_desired(&mut desired)?;
            (
                desired,
                DesiredVolumeMutation::DetachPersistent {
                    disk_id: removed.disk_id,
                    volume_id: removed.volume_id,
                    volume_intent_id: removed.volume_intent_id,
                    attachment_id: removed.attachment_id,
                },
            )
        }
    };
    Ok(CoveredPlannedDesiredMutation::Mutation {
        request: Box::new(CoveredDesiredMutationRequest {
            idempotency: ingress.idempotency.clone(),
            expected_current: snapshot.current,
            desired,
            operation_id,
            placement_snapshots: Vec::new(),
            active_guest_digest: active_guest_digest.clone(),
            endpoint_records: snapshot.endpoint_records,
            volume_mutation,
            require_idle_open_busy_proof: None,
        }),
        fixed_collision: None,
    })
}

fn exact_settled_cold_in(
    transaction: &mut Transaction<'_>,
    desired: &DesiredRuntimeSpec,
    active_guest_digest: &Sha256Digest,
) -> AuthorityTxResult<bool> {
    let operation = load_operation_by_cat_revision_unlocked(
        transaction,
        &desired.cat_id,
        desired.desired_revision,
    )?
    .ok_or_else(|| ApiError::internal("current Desired has no exact Operation"))?;
    if operation.workspace_id != desired.workspace_id
        || operation.cat_id != desired.cat_id
        || operation.desired_revision != desired.desired_revision
        || operation.desired_spec_digest != desired.spec_digest
        || operation.placement != desired.placement
        || operation.target != desired.target
    {
        return Err(ApiError::internal("current Desired/Operation binding is corrupt").into());
    }
    if operation.phase != cats_api::runtime_reconciliation::OperationPhase::Succeeded {
        return Ok(false);
    }
    let now = database_now(transaction)?;
    let admission = match load_placement_admission_at_in(
        transaction,
        &desired.placement.node_id,
        active_guest_digest,
        now,
    )? {
        PlacementAdmissionLoad::Accepted(admission) => admission,
        PlacementAdmissionLoad::Rejected(_) => return Ok(false),
    };
    Ok(placement_admission_observes_stable_cold(
        &admission, desired,
    ))
}

fn next_desired_revision(current: Revision) -> Result<Revision> {
    current
        .get()
        .checked_add(1)
        .and_then(Revision::new)
        .ok_or_else(|| ApiError::failed_precondition("Desired revision is exhausted"))
}

fn finalize_binding_desired(desired: &mut DesiredRuntimeSpec) -> Result<()> {
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(desired)
        .map_err(|_| ApiError::internal("constructed PersistentDisk Desired is invalid"))?;
    Ok(())
}

fn intent_durability(durability: VolumeDurability) -> Durability {
    match durability {
        VolumeDurability::Strict => Durability::Strict,
        VolumeDurability::Relaxed => Durability::Relaxed,
    }
}

fn stored_durability_matches(left: VolumeDurability, right: VolumeDurability) -> bool {
    matches!(
        (left, right),
        (VolumeDurability::Strict, VolumeDurability::Strict)
            | (VolumeDurability::Relaxed, VolumeDurability::Relaxed)
    )
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
    Stale,
    CandidateCollision(CandidateCollision),
}

#[cfg(test)]
#[derive(Clone)]
struct LifecycleSnapshotPause {
    entered: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[derive(Clone)]
enum PlannedProductMutationRequest {
    Lifecycle {
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        action: Option<CatLifecycleAction>,
        delete_id: Option<Id>,
        operation_id: Id,
        active_guest_digest: Sha256Digest,
        #[cfg(test)]
        snapshot_pause: Option<LifecycleSnapshotPause>,
    },
    Endpoint {
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        mutation: EndpointMutation,
        operation_id: Id,
    },
    PersistentDisk {
        ingress: AuthorizedProductMutationIngress,
        disk_id: Id,
        binding: PersistentDiskBindingV2Request,
        action: PersistentDiskBindingAction,
        attach_candidate: Option<PersistentDiskAttachCandidate>,
        operation_id: Id,
        active_guest_digest: Sha256Digest,
    },
}

#[derive(Clone)]
struct PersistentDiskAttachCandidate {
    binding_random: RandomId128,
    transition_id: RandomId128,
    serial_random: RandomId128,
}

impl Store {
    fn commit_product_mutation_covered(
        &self,
        request: &PlannedProductMutationRequest,
        commit_state: &super::covered_commit::CoveredCommitState,
    ) -> std::result::Result<DesiredMutationCommit, CoveredDesiredMutationError> {
        let idempotency = match request {
            PlannedProductMutationRequest::Lifecycle { ingress, .. }
            | PlannedProductMutationRequest::Endpoint { ingress, .. }
            | PlannedProductMutationRequest::PersistentDisk { ingress, .. } => {
                ingress.idempotency.clone()
            }
        };
        self.commit_planned_desired_mutation_covered(&idempotency, commit_state, |transaction| {
            match request {
                PlannedProductMutationRequest::Lifecycle {
                    ingress,
                    cat_id,
                    action,
                    delete_id,
                    operation_id,
                    active_guest_digest,
                    #[cfg(test)]
                    snapshot_pause,
                } => {
                    let mut snapshot = load_lifecycle_snapshot_in(
                        transaction,
                        &ingress.idempotency.authenticated_workspace_id,
                        cat_id,
                    )?;
                    #[cfg(test)]
                    if let Some(pause) = snapshot_pause {
                        pause.entered.wait();
                        pause.release.wait();
                    }
                    if *action == Some(CatLifecycleAction::Resume)
                        && snapshot.current.target != RuntimeTarget::Running
                    {
                        enrich_lifecycle_placement_in(
                            transaction,
                            &mut snapshot,
                            active_guest_digest,
                        )?;
                    }
                    if ingress.if_match.is_some_and(|if_match| {
                        if_match.get() != snapshot.current.desired_revision.get()
                    }) {
                        return fixed_planned_result(409, IF_MATCH_BODY);
                    }
                    if snapshot.current.target == RuntimeTarget::Deleted && action.is_some() {
                        return fixed_planned_result(412, RETIRED_BODY);
                    }
                    if action.is_some_and(|action| {
                        !lifecycle_precondition(action, snapshot.current.target)
                    }) {
                        return fixed_planned_result(412, PRECONDITION_BODY);
                    }
                    let covered = build_lifecycle_request(
                        ingress,
                        snapshot,
                        *action,
                        delete_id.as_ref(),
                        operation_id.clone(),
                        active_guest_digest.clone(),
                    )?;
                    Ok(CoveredPlannedDesiredMutation::Mutation {
                        request: Box::new(covered),
                        fixed_collision: None,
                    })
                }
                PlannedProductMutationRequest::Endpoint {
                    ingress,
                    cat_id,
                    mutation,
                    operation_id,
                } => {
                    let workspace_id = &ingress.idempotency.authenticated_workspace_id;
                    let cat = load_cat_by_id_unlocked(transaction, cat_id)?
                        .filter(|cat| cat.workspace_id == *workspace_id)
                        .ok_or_else(|| ApiError::not_found("Cat"))?;
                    if cat.cat_id != *cat_id {
                        return Err(ApiError::internal("Cat ID projection is corrupt").into());
                    }
                    let plan = match plan_endpoint_route_mutation_in(
                        transaction,
                        workspace_id,
                        cat_id,
                        mutation.clone(),
                    ) {
                        Ok(plan) => plan,
                        Err(AuthorityTransactionError::Application(error))
                            if error.code == ErrorCode::Conflict =>
                        {
                            return fixed_planned_result(409, ENDPOINT_CONFLICT_BODY);
                        }
                        Err(AuthorityTransactionError::Application(error))
                            if error.code == ErrorCode::FailedPrecondition =>
                        {
                            return fixed_planned_result(412, ENDPOINT_PRECONDITION_BODY);
                        }
                        Err(error) => return Err(error),
                    };
                    if ingress.if_match.is_some_and(|if_match| {
                        if_match.get() != plan.expected_current.desired_revision.get()
                    }) {
                        return fixed_planned_result(409, IF_MATCH_BODY);
                    }
                    if plan.expected_current.target == RuntimeTarget::Deleted {
                        return fixed_planned_result(412, ENDPOINT_PRECONDITION_BODY);
                    }
                    let covered = covered_endpoint_request(ingress, plan, operation_id.clone());
                    Ok(CoveredPlannedDesiredMutation::Mutation {
                        request: Box::new(covered),
                        fixed_collision: Some((
                            CandidateCollision::Hostname,
                            fixed_response(409, ENDPOINT_CONFLICT_BODY)?,
                        )),
                    })
                }
                PlannedProductMutationRequest::PersistentDisk {
                    ingress,
                    disk_id,
                    binding,
                    action,
                    attach_candidate,
                    operation_id,
                    active_guest_digest,
                } => plan_persistent_disk_binding_in(
                    transaction,
                    ingress,
                    disk_id,
                    binding,
                    *action,
                    attach_candidate.as_ref(),
                    operation_id.clone(),
                    active_guest_digest,
                ),
            }
        })
    }
}

fn fixed_response(status: u16, body: &'static [u8]) -> Result<ExactHttpResponse> {
    ExactHttpResponse::new(
        status,
        Some(ExactContentType::ApplicationJson),
        body.to_vec(),
    )
}

fn fixed_planned_result(
    status: u16,
    body: &'static [u8],
) -> AuthorityTxResult<CoveredPlannedDesiredMutation> {
    fixed_response(status, body)
        .map(CoveredPlannedDesiredMutation::Fixed)
        .map_err(Into::into)
}

pub(crate) struct ProductMutationService {
    store: Arc<Store>,
    identities: Arc<dyn ProductIdentitySource>,
    active_guest_digest: Sha256Digest,
    commit_resolutions: Arc<CommitResolutionRegistry>,
    admission: tokio::sync::watch::Sender<bool>,
}

impl ProductMutationService {
    pub(crate) fn new(
        store: Arc<Store>,
        identities: Arc<dyn ProductIdentitySource>,
        active_guest_digest: Sha256Digest,
    ) -> Self {
        let (admission, _) = tokio::sync::watch::channel(true);
        Self {
            store,
            identities,
            active_guest_digest,
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
        let (action, cat_id) = match (ingress.mutation.clone(), ingress.cat_id.clone()) {
            (ProductMutation::Lifecycle(action), Some(cat_id)) => (Some(action), cat_id),
            (ProductMutation::DeleteCat, Some(cat_id)) => (None, cat_id),
            (ProductMutation::DeleteDisk { disk_id }, None) => {
                return self.delete_disk(ingress, disk_id).await;
            }
            (ProductMutation::AttachDisk { disk_id, binding }, None) => {
                return self
                    .mutate_persistent_disk(
                        ingress,
                        disk_id,
                        binding,
                        PersistentDiskBindingAction::Attach,
                    )
                    .await;
            }
            (ProductMutation::DetachDisk { disk_id, binding }, None) => {
                return self
                    .mutate_persistent_disk(
                        ingress,
                        disk_id,
                        binding,
                        PersistentDiskBindingAction::Detach,
                    )
                    .await;
            }
            (ProductMutation::BindEndpoint(body), Some(cat_id)) => {
                return self
                    .mutate_endpoint(ingress, cat_id, Some(body), None)
                    .await;
            }
            (ProductMutation::UnbindEndpoint { endpoint_id }, Some(cat_id)) => {
                return self
                    .mutate_endpoint(ingress, cat_id, None, Some(endpoint_id))
                    .await;
            }
            _ => {
                return Err(ProductMutationServiceError::Request(ApiError::invalid(
                    "Cat mutation is missing its Cat ID",
                )));
            }
        };
        let delete_id = if action.is_none() {
            Some(prefixed_id("delete_", self.identities.random_id()?)?)
        } else {
            None
        };
        let mut shutdown = self.admission.subscribe();
        for _ in 0..MAX_REPLANS {
            if Instant::now() >= ingress.absolute_deadline || !*shutdown.borrow() {
                return Err(ProductMutationServiceError::TemporarilyUnavailable);
            }
            let operation_id = prefixed_id("op_", self.identities.random_id()?)?;
            let planned = PlannedProductMutationRequest::Lifecycle {
                ingress: ingress.clone(),
                cat_id: cat_id.clone(),
                action,
                delete_id: delete_id.clone(),
                operation_id,
                active_guest_digest: self.active_guest_digest.clone(),
                #[cfg(test)]
                snapshot_pause: None,
            };
            match self
                .commit(planned, ingress.absolute_deadline, &mut shutdown)
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::Stale
                | CommitOutcome::CandidateCollision(CandidateCollision::OperationId) => continue,
                CommitOutcome::CandidateCollision(_) => {
                    return Err(ProductMutationServiceError::Fatal(ApiError::internal(
                        "lifecycle mutation returned an impossible candidate collision",
                    )));
                }
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    async fn mutate_endpoint(
        &self,
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        bind: Option<EndpointBindBody>,
        unbind: Option<Id>,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let mut shutdown = self.admission.subscribe();
        for _ in 0..MAX_REPLANS {
            if Instant::now() >= ingress.absolute_deadline || !*shutdown.borrow() {
                return Err(ProductMutationServiceError::TemporarilyUnavailable);
            }
            let endpoint = if let Some(body) = &bind {
                let endpoint_id = prefixed_id("ep_", self.identities.random_id()?)?;
                EndpointMutation::Bind {
                    record: EndpointRecordCandidate {
                        endpoint_id,
                        workspace_id: ingress.idempotency.authenticated_workspace_id.clone(),
                        cat_id: cat_id.clone(),
                        name: body.name.clone(),
                    },
                    intent: EndpointBindingWithoutEpoch::http(
                        body.hostname.clone(),
                        body.target_port,
                    )?,
                }
            } else {
                EndpointMutation::Unbind {
                    endpoint_id: unbind
                        .clone()
                        .ok_or_else(|| ApiError::internal("Endpoint unbind ID is missing"))?,
                }
            };
            let operation_id = prefixed_id("op_", self.identities.random_id()?)?;
            let planned = PlannedProductMutationRequest::Endpoint {
                ingress: ingress.clone(),
                cat_id: cat_id.clone(),
                mutation: endpoint,
                operation_id,
            };
            match self
                .commit(planned, ingress.absolute_deadline, &mut shutdown)
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::Stale
                | CommitOutcome::CandidateCollision(CandidateCollision::OperationId)
                | CommitOutcome::CandidateCollision(CandidateCollision::EndpointIdOrName) => {
                    continue;
                }
                CommitOutcome::CandidateCollision(CandidateCollision::Hostname) => {
                    return Err(ProductMutationServiceError::Fatal(ApiError::internal(
                        "Endpoint hostname collision escaped the covered transaction",
                    )));
                }
                CommitOutcome::CandidateCollision(_) => {
                    return Err(ProductMutationServiceError::Fatal(ApiError::internal(
                        "Endpoint mutation returned an impossible candidate collision",
                    )));
                }
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    async fn mutate_persistent_disk(
        &self,
        ingress: AuthorizedProductMutationIngress,
        disk_id: Id,
        binding: PersistentDiskBindingV2Request,
        action: PersistentDiskBindingAction,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let mut shutdown = self.admission.subscribe();
        for _ in 0..MAX_REPLANS {
            if Instant::now() >= ingress.absolute_deadline || !*shutdown.borrow() {
                return Err(ProductMutationServiceError::TemporarilyUnavailable);
            }
            let attach_candidate = (action == PersistentDiskBindingAction::Attach)
                .then(|| {
                    Ok::<_, ApiError>(PersistentDiskAttachCandidate {
                        binding_random: self.identities.random_id()?,
                        transition_id: self.identities.random_id()?,
                        serial_random: self.identities.random_id()?,
                    })
                })
                .transpose()?;
            let operation_id = prefixed_id("op_", self.identities.random_id()?)?;
            let planned = PlannedProductMutationRequest::PersistentDisk {
                ingress: ingress.clone(),
                disk_id: disk_id.clone(),
                binding: binding.clone(),
                action,
                attach_candidate,
                operation_id,
                active_guest_digest: self.active_guest_digest.clone(),
            };
            match self
                .commit(planned, ingress.absolute_deadline, &mut shutdown)
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::Stale
                | CommitOutcome::CandidateCollision(CandidateCollision::OperationId)
                | CommitOutcome::CandidateCollision(CandidateCollision::VolumeIntentIdentity) => {
                    continue;
                }
                CommitOutcome::CandidateCollision(_) => {
                    return Err(ProductMutationServiceError::Fatal(ApiError::internal(
                        "PersistentDisk mutation returned an impossible candidate collision",
                    )));
                }
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    async fn delete_disk(
        &self,
        ingress: AuthorizedProductMutationIngress,
        disk_id: Id,
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let delete_id = prefixed_id("delete_", self.identities.random_id()?)?;
        let covered = CoveredDiskDeleteRequest {
            idempotency: ingress.idempotency.clone(),
            disk_id,
            delete_id,
            active_guest_digest: self.active_guest_digest.clone(),
        };
        let deadline = ingress.absolute_deadline;
        let resolution_request = covered.idempotency.clone();
        let (cancellation, state) =
            CoveredCommitCancellation::new("PersistentDisk begin-delete", deadline);
        let observer = state.clone();
        let cancellation_observer = state.clone();
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(ProductMutationServiceError::TemporarilyUnavailable);
        };
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store
                .execute(move |store| store.begin_disk_delete_covered(&covered, &state));
            tokio::pin!(execution);
            let execution = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable("PersistentDisk begin-delete cancelled before commit"))
                }
            };
            let outcome = match execution {
                Ok(result) => Ok(result),
                Err(error) if observer.commit_was_sent() => {
                    resolve_commit_loop(store, resolution_request, error).await
                }
                Err(error) => Err(error),
            };
            let _ = sender.send(outcome);
            drop(active);
        });
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let outcome = tokio::select! {
            result = &mut receiver => result.map_err(|_| ApiError::internal("Disk delete commit owner stopped"))?,
            () = &mut sleep => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("Disk delete commit owner stopped"))?
            }
        };
        outcome
            .map(http_result)
            .map_err(ProductMutationServiceError::from_api)
    }

    async fn commit(
        &self,
        planned: PlannedProductMutationRequest,
        deadline: Instant,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CommitOutcome, ProductMutationServiceError> {
        let resolution_request = match &planned {
            PlannedProductMutationRequest::Lifecycle { ingress, .. }
            | PlannedProductMutationRequest::Endpoint { ingress, .. }
            | PlannedProductMutationRequest::PersistentDisk { ingress, .. } => {
                ingress.idempotency.clone()
            }
        };
        let (cancellation, state) =
            CoveredCommitCancellation::new("product lifecycle mutation", deadline);
        let observer = state.clone();
        let cancellation_observer = state.clone();
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(ProductMutationServiceError::TemporarilyUnavailable);
        };
        let (sender, mut receiver) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store
                .execute(move |store| Ok(store.commit_product_mutation_covered(&planned, &state)));
            tokio::pin!(execution);
            let execution = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable("product mutation cancelled before commit"))
                }
            };
            let outcome = match execution {
                Ok(Ok(
                    DesiredMutationCommit::Replayed(result)
                    | DesiredMutationCommit::Converged(result)
                    | DesiredMutationCommit::Changed(result),
                )) => Ok(CommitOutcome::Committed(result)),
                Ok(Err(CoveredDesiredMutationError::Stale)) => Ok(CommitOutcome::Stale),
                Ok(Err(CoveredDesiredMutationError::CandidateCollision(collision))) => {
                    Ok(CommitOutcome::CandidateCollision(collision))
                }
                Ok(Err(CoveredDesiredMutationError::Store(error))) | Err(error)
                    if observer.commit_was_sent() =>
                {
                    resolve_commit_loop(store, resolution_request, error)
                        .await
                        .map(CommitOutcome::Committed)
                }
                Ok(Err(CoveredDesiredMutationError::Store(error))) | Err(error) => Err(error),
            };
            let _ = sender.send(outcome);
            drop(active);
        });
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let outcome = tokio::select! {
            result = &mut receiver => result.map_err(|_| ApiError::internal("product mutation commit owner stopped"))?,
            () = &mut sleep => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("product mutation commit owner stopped"))?
            },
            () = wait_for_shutdown(shutdown) => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("product mutation commit owner stopped"))?
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

    #[cfg(test)]
    pub(super) fn commit_lifecycle_once_paused_for_test(
        &self,
        ingress: AuthorizedProductMutationIngress,
        cat_id: Id,
        action: CatLifecycleAction,
        operation_id: Id,
        entered: Arc<std::sync::Barrier>,
        release: Arc<std::sync::Barrier>,
    ) -> std::result::Result<DesiredMutationCommit, CoveredDesiredMutationError> {
        let deadline = ingress.absolute_deadline;
        let planned = PlannedProductMutationRequest::Lifecycle {
            ingress,
            cat_id,
            action: Some(action),
            delete_id: None,
            operation_id,
            active_guest_digest: self.active_guest_digest.clone(),
            snapshot_pause: Some(LifecycleSnapshotPause { entered, release }),
        };
        let (_cancellation, state) =
            CoveredCommitCancellation::new("paused lifecycle snapshot test", deadline);
        self.store.commit_product_mutation_covered(&planned, &state)
    }
}

fn lifecycle_precondition(action: CatLifecycleAction, current: RuntimeTarget) -> bool {
    match action {
        CatLifecycleAction::Stop => current != RuntimeTarget::Deleted,
        CatLifecycleAction::Suspend => {
            matches!(current, RuntimeTarget::Running | RuntimeTarget::Suspended)
        }
        CatLifecycleAction::Warm => matches!(
            current,
            RuntimeTarget::Running | RuntimeTarget::Suspended | RuntimeTarget::Warm
        ),
        CatLifecycleAction::Resume => current != RuntimeTarget::Deleted,
    }
}

fn build_lifecycle_request(
    ingress: &AuthorizedProductMutationIngress,
    snapshot: LifecycleSnapshot,
    action: Option<CatLifecycleAction>,
    delete_id: Option<&Id>,
    operation_id: Id,
    active_guest_digest: Sha256Digest,
) -> Result<CoveredDesiredMutationRequest> {
    let mut desired = snapshot.current.clone();
    desired.desired_revision = Revision::new(
        desired
            .desired_revision
            .get()
            .checked_add(1)
            .ok_or_else(|| ApiError::failed_precondition("Desired revision is exhausted"))?,
    )
    .ok_or_else(|| ApiError::failed_precondition("Desired revision is exhausted"))?;
    desired.transition = RuntimeTransition::CancelAndDrain;
    let volume_mutation = if let Some(action) = action {
        let target = action.target();
        if snapshot.current.target != RuntimeTarget::Running && target == RuntimeTarget::Running {
            for endpoint in &mut desired.endpoints {
                endpoint.route_epoch =
                    Epoch::new(endpoint.route_epoch.get().checked_add(1).ok_or_else(|| {
                        ApiError::failed_precondition("route epoch is exhausted")
                    })?)
                    .ok_or_else(|| ApiError::failed_precondition("route epoch is exhausted"))?;
            }
        }
        desired.target = target;
        DesiredVolumeMutation::Preserve
    } else if snapshot.current.target == RuntimeTarget::Deleted {
        DesiredVolumeMutation::Preserve
    } else {
        let delete_id = delete_id.ok_or_else(|| ApiError::internal("Cat delete ID is missing"))?;
        desired.target = RuntimeTarget::Deleted;
        for volume in &mut desired.volumes {
            volume.disposition = match volume.disk_kind {
                cats_api::runtime_reconciliation::DiskKind::Root => {
                    VolumeDisposition::DeleteDisposableRoot {
                        delete_id: delete_id.clone(),
                    }
                }
                cats_api::runtime_reconciliation::DiskKind::Persistent => {
                    VolumeDisposition::DetachRetained
                }
            };
        }
        DesiredVolumeMutation::DeleteCat {
            delete_id: delete_id.clone(),
        }
    };
    desired.spec_digest = Sha256Digest::from_bytes([0; 32]);
    desired.spec_digest = spec_digest(&desired)
        .map_err(|_| ApiError::internal("constructed lifecycle Desired is invalid"))?;
    Ok(CoveredDesiredMutationRequest {
        idempotency: ingress.idempotency.clone(),
        expected_current: snapshot.current,
        desired,
        operation_id,
        placement_snapshots: snapshot.placement_snapshots,
        active_guest_digest,
        endpoint_records: snapshot.endpoint_records,
        volume_mutation,
        require_idle_open_busy_proof: None,
    })
}

fn covered_endpoint_request(
    ingress: &AuthorizedProductMutationIngress,
    plan: RouteEpochMutationPlan,
    operation_id: Id,
) -> CoveredDesiredMutationRequest {
    CoveredDesiredMutationRequest {
        idempotency: ingress.idempotency.clone(),
        expected_current: plan.expected_current,
        desired: plan.desired,
        operation_id,
        placement_snapshots: plan.placement_snapshots,
        active_guest_digest: plan.active_guest_digest,
        endpoint_records: plan.endpoint_records,
        volume_mutation: DesiredVolumeMutation::Preserve,
        require_idle_open_busy_proof: plan.require_idle_open_busy_proof,
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
    use cats_api::runtime_reconciliation::{
        DiskKind, Durability, Ext4MountIntent, FenceEpoch, FilesystemInitialization,
        GuestDeviceIdentity, HostPath, RandomId128, VolumeAccess, VolumeAcquire, VolumeIntent,
    };

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
        let parsed = parse_authorized_product_mutation(
            &workspace,
            Some("cat_01"),
            Instant::now(),
            b"/v1/workspaces/ws_01/cats/cat_01/actions/suspend",
            &fields(&[]),
            b"",
            action.clone(),
        )
        .unwrap();
        assert_eq!(parsed.if_match, None);
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
    fn if_match_spellings_share_one_generation_and_invalid_forms_close() {
        assert_eq!(parse_if_match(&[b"7".to_vec()]).unwrap().unwrap().get(), 7);
        assert_eq!(
            parse_if_match(&[b"\"7\"".to_vec()]).unwrap().unwrap().get(),
            7
        );
        for values in [
            vec![b"07".to_vec()],
            vec![b"*".to_vec()],
            vec![b"W/\"7\"".to_vec()],
            vec![b"7".to_vec(), b"8".to_vec()],
        ] {
            assert!(parse_if_match(&values).is_err());
        }
    }

    #[test]
    fn endpoint_bind_parser_fingerprints_exact_json_and_rejects_schema_drift() {
        let workspace = id("ws_endpoint");
        let mut endpoint_fields = fields(&[]);
        endpoint_fields.content_type = vec![b"application/json".to_vec()];
        let path = b"/v1/workspaces/ws_endpoint/cats/cat_endpoint/endpoints";
        let raw = br#"{"name":"web","hostname":"web.example.com","target_port":8080}"#;
        let parsed = parse_authorized_endpoint_bind(
            &workspace,
            "cat_endpoint",
            Instant::now(),
            path,
            &endpoint_fields,
            raw,
        )
        .unwrap();
        assert!(matches!(
            parsed.mutation,
            ProductMutation::BindEndpoint(EndpointBindBody {
                target_port: 8080,
                ..
            })
        ));
        for malformed in [
            br#"{"name":"web","hostname":"web.example.com","target_port":0}"#.as_slice(),
            br#"{"name":"web","hostname":"web.example.com","target_port":8080,"protocol":"http"}"#
                .as_slice(),
            br#"{"name":"web","hostname":"web.example.com","target_port":8080}x"#.as_slice(),
        ] {
            assert!(parse_authorized_endpoint_bind(
                &workspace,
                "cat_endpoint",
                Instant::now(),
                path,
                &endpoint_fields,
                malformed,
            )
            .is_err());
        }
    }

    #[test]
    fn persistent_disk_binding_parser_uses_only_clean_slate_exact_routes() {
        let workspace = id("ws_binding");
        let mut binding_fields = fields(&[]);
        binding_fields.content_type = vec![b"application/json".to_vec()];
        let body = br#"{"cat_id":"cat_binding","mount_path":"/srv/data"}"#;
        let attach_path = b"/v1/workspaces/ws_binding/disks/disk_binding/actions/attach";
        let attach = parse_authorized_persistent_disk_binding(
            &workspace,
            "disk_binding",
            Instant::now(),
            attach_path,
            &binding_fields,
            body,
            PersistentDiskBindingAction::Attach,
        )
        .unwrap();
        assert!(matches!(
            attach.mutation,
            ProductMutation::AttachDisk {
                disk_id,
                binding: PersistentDiskBindingV2Request { cat_id, mount_path },
            } if disk_id == id("disk_binding")
                && cat_id == id("cat_binding")
                && mount_path.as_str() == "/srv/data"
        ));
        assert_eq!(
            attach.idempotency.canonical_route.as_str(),
            DISK_ATTACH_ROUTE
        );

        let detach_path = b"/v1/workspaces/ws_binding/disks/disk_binding/actions/detach";
        let detach = parse_authorized_persistent_disk_binding(
            &workspace,
            "disk_binding",
            Instant::now(),
            detach_path,
            &binding_fields,
            body,
            PersistentDiskBindingAction::Detach,
        )
        .unwrap();
        assert!(matches!(
            detach.mutation,
            ProductMutation::DetachDisk { .. }
        ));
        assert_eq!(
            detach.idempotency.canonical_route.as_str(),
            DISK_DETACH_ROUTE
        );

        for retired_or_aliased in [
            b"/v1/workspaces/ws_binding/disks/disk_binding/actions/mount".as_slice(),
            b"/v1/workspaces/ws_binding/disks/disk_binding/actions/unmount".as_slice(),
            b"/v1/workspaces/ws_binding/disks/disk_binding/actions/attach?".as_slice(),
        ] {
            assert!(parse_authorized_persistent_disk_binding(
                &workspace,
                "disk_binding",
                Instant::now(),
                retired_or_aliased,
                &binding_fields,
                body,
                PersistentDiskBindingAction::Attach,
            )
            .is_err());
        }
        for malformed in [
            br#"{"cat_id":"dev","mount_path":"/srv/data"}"#.as_slice(),
            br#"{"cat_id":"cat_binding","mount_path":"/"}"#.as_slice(),
            br#"{"cat_id":"cat_binding","mount_path":"/srv/data","mount_at":"/legacy"}"#,
            br#"{"cat_id":"cat_binding","mount_path":"relative"}"#,
        ] {
            assert!(parse_authorized_persistent_disk_binding(
                &workspace,
                "disk_binding",
                Instant::now(),
                attach_path,
                &binding_fields,
                malformed,
                PersistentDiskBindingAction::Attach,
            )
            .is_err());
        }
        assert!(parse_authorized_persistent_disk_binding(
            &workspace,
            "data",
            Instant::now(),
            b"/v1/workspaces/ws_binding/disks/data/actions/attach",
            &binding_fields,
            body,
            PersistentDiskBindingAction::Attach,
        )
        .is_err());
    }

    #[test]
    fn lifecycle_successors_are_complete_and_delete_has_one_closed_volume_mode() {
        let workspace = id("ws_lifecycle");
        let create = super::super::product_tests::request(
            &workspace,
            "lifecycle-app",
            71,
            "create-lifecycle-app",
        );
        let mut current = create.candidate.desired.clone();
        current.volumes.push(VolumeIntent {
            volume_intent_id: id("volume-intent_persistent"),
            disk_id: id("disk_persistent"),
            volume_id: id("volume_persistent"),
            attachment_id: id("attachment_persistent"),
            size_bytes: 4 * 1024 * 1024,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: id("cats-persistent"),
                slot: 1,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: RandomId128::new("0000000000000000000000000000d001").unwrap(),
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(Ext4MountIntent {
                filesystem_uuid: RandomId128::new("0000000000000000000000000000d002").unwrap(),
                mount_path: HostPath::new("/data").unwrap(),
                initialization: FilesystemInitialization::Existing,
            }),
        });
        current.spec_digest = Sha256Digest::from_bytes([0; 32]);
        current.spec_digest = spec_digest(&current).unwrap();
        let endpoint_records = vec![create.candidate.endpoint.clone()];
        let snapshot = LifecycleSnapshot {
            current: current.clone(),
            endpoint_records: endpoint_records.clone(),
            placement_snapshots: Vec::new(),
        };
        let ingress = parse_authorized_product_mutation(
            &workspace,
            Some(create.candidate.cat_id.as_str()),
            Instant::now(),
            format!(
                "/v1/workspaces/{workspace}/cats/{}",
                create.candidate.cat_id
            )
            .as_bytes(),
            &fields(&[]),
            b"",
            ProductMutation::DeleteCat,
        )
        .unwrap();
        let delete_id = id("delete_0123456789abcdef0123456789abcdef");
        let delete = build_lifecycle_request(
            &ingress,
            snapshot,
            None,
            Some(&delete_id),
            id("op_delete"),
            current.runtime.guest_config_digest.clone(),
        )
        .unwrap();
        assert_eq!(delete.desired.target, RuntimeTarget::Deleted);
        assert_eq!(
            delete.desired.volumes.len(),
            delete.expected_current.volumes.len()
        );
        assert!(matches!(
            delete.volume_mutation,
            DesiredVolumeMutation::DeleteCat { delete_id: ref actual }
                if actual == &delete_id
        ));
        assert!(matches!(
            delete.desired.volumes[0].disposition,
            VolumeDisposition::DeleteDisposableRoot { delete_id: ref actual }
                if actual == &delete_id
        ));
        assert_eq!(delete.desired.volumes[1].disk_kind, DiskKind::Persistent);
        assert_eq!(
            delete.desired.volumes[1].disposition,
            VolumeDisposition::DetachRetained
        );
        assert_eq!(delete.endpoint_records, endpoint_records);
    }

    #[test]
    fn lifecycle_state_matrix_does_not_merge_suspended_warm_and_cold() {
        assert!(lifecycle_precondition(
            CatLifecycleAction::Suspend,
            RuntimeTarget::Running
        ));
        assert!(!lifecycle_precondition(
            CatLifecycleAction::Suspend,
            RuntimeTarget::Warm
        ));
        assert!(lifecycle_precondition(
            CatLifecycleAction::Warm,
            RuntimeTarget::Suspended
        ));
        assert!(!lifecycle_precondition(
            CatLifecycleAction::Warm,
            RuntimeTarget::Cold
        ));
        assert!(!lifecycle_precondition(
            CatLifecycleAction::Resume,
            RuntimeTarget::Deleted
        ));
    }
}
