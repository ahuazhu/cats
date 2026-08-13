//! Covered V2 Cat lifecycle mutation service.
//!
//! The public adapter authenticates before constructing this ingress.  This
//! module then owns exact replay, one complete Desired successor, and the A1
//! commit-ambiguity boundary. Endpoint epoch planning is intentionally owned
//! by `route_epoch_engine`; Disk begin-delete has its own cross-row path.

use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::{ApiError, ErrorCode};
use cats_api::runtime_reconciliation::{
    spec_digest, AsciiText, DesiredRuntimeSpec, Epoch, Generation, Hostname, Id, Revision,
    RuntimeTarget, RuntimeTransition, Sha256Digest, VolumeDisposition,
};
use serde::Deserialize;

use super::covered_commit::{CommitResolutionRegistry, CoveredCommitCancellation};
use super::placement_planner::PlacementTargetSnapshot;
use super::placement_policy::load_policy_unlocked;
use super::product::{
    api_request_fingerprint, ApiIdempotencyRequest, ApiIdempotencyResult, CandidateCollision,
    CoveredDesiredMutationError, CoveredDesiredMutationRequest, CoveredDiskDeleteRequest,
    DesiredMutationCommit, DesiredVolumeMutation, EndpointRecordCandidate, ExactContentType,
    IfMatchFingerprint,
};
use super::product_identity::ProductIdentitySource;
use super::product_rows::{
    load_cat_by_id_unlocked, load_desired_unlocked, load_endpoint_by_id_unlocked,
};
use super::rows::{database_now, load_active_event_by_node_unlocked};
use super::runtime_spine::{load_placement_admission_at_in, PlacementAdmissionLoad};
use crate::store::{Result, Store};

pub(crate) const PRODUCT_MUTATION_MAX_BODY_BYTES: usize = 4096;
pub(crate) const CAT_ACTION_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/cats/{cat}/actions/{verb}";
pub(crate) const CAT_DELETE_ROUTE: &str = "DELETE /v1/workspaces/{workspace}/cats/{cat}";
pub(crate) const ENDPOINT_BIND_ROUTE: &str = "POST /v1/workspaces/{workspace}/cats/{cat}/endpoints";
pub(crate) const ENDPOINT_UNBIND_ROUTE: &str =
    "DELETE /v1/workspaces/{workspace}/cats/{cat}/endpoints/{endpoint}";
pub(crate) const DISK_DELETE_ROUTE: &str = "DELETE /v1/workspaces/{workspace}/disks/{disk}";

const TOTAL_DEADLINE: Duration = Duration::from_secs(10);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const JSON_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const MAX_REPLANS: usize = 32;
const NOT_FOUND_BODY: &[u8] = br#"{"code":"not_found","message":"resource not found"}"#;
const IF_MATCH_BODY: &[u8] =
    br#"{"code":"conflict","message":"If-Match does not name the current Desired revision"}"#;
const PRECONDITION_BODY: &[u8] = br#"{"code":"failed_precondition","message":"lifecycle action is not valid from the current target"}"#;
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
    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "stop" => Some(Self::Stop),
            "suspend" => Some(Self::Suspend),
            "warm" => Some(Self::Warm),
            "resume" => Some(Self::Resume),
            _ => None,
        }
    }

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
    UnbindEndpoint { endpoint_id: Id },
    DeleteDisk { disk_id: Id },
}

impl ProductMutation {
    fn canonical_route(&self) -> &'static str {
        match self {
            Self::Lifecycle(_) => CAT_ACTION_ROUTE,
            Self::DeleteCat => CAT_DELETE_ROUTE,
            Self::BindEndpoint(_) => ENDPOINT_BIND_ROUTE,
            Self::UnbindEndpoint { .. } => ENDPOINT_UNBIND_ROUTE,
            Self::DeleteDisk { .. } => DISK_DELETE_ROUTE,
        }
    }

    fn has_json_body(&self) -> bool {
        matches!(self, Self::BindEndpoint(_))
    }
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

impl Store {
    fn load_lifecycle_snapshot(
        &self,
        workspace_id: &Id,
        cat_id: &Id,
        active_guest_digest: &Sha256Digest,
        placement_required: bool,
    ) -> Result<Option<LifecycleSnapshot>> {
        self.authority_read_snapshot(|transaction| {
            let Some(cat) = load_cat_by_id_unlocked(transaction, cat_id)? else {
                return Ok(None);
            };
            if cat.workspace_id != *workspace_id {
                return Ok(None);
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
            let placement_snapshots = if placement_required {
                let node_id = &current.placement.node_id;
                let now = database_now(transaction)?;
                let policy = load_policy_unlocked(transaction, node_id)?.ok_or_else(|| {
                    ApiError::internal("assigned Node placement policy is missing")
                })?;
                let active_host_fence_event =
                    load_active_event_by_node_unlocked(transaction, node_id)?;
                let admission = match load_placement_admission_at_in(
                    transaction,
                    node_id,
                    active_guest_digest,
                    now,
                )? {
                    PlacementAdmissionLoad::Accepted(admission) => *admission,
                    PlacementAdmissionLoad::Rejected(_) => return Ok(None),
                };
                vec![PlacementTargetSnapshot {
                    policy,
                    admission,
                    active_host_fence_event,
                }]
            } else {
                Vec::new()
            };
            Ok(Some(LifecycleSnapshot {
                current,
                endpoint_records,
                placement_snapshots,
            }))
        })
    }
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
    NotFound,
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
    OperationCollision,
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
            (ProductMutation::BindEndpoint(_), _) | (ProductMutation::UnbindEndpoint { .. }, _) => {
                return Err(ProductMutationServiceError::Request(
                    ApiError::failed_precondition(
                        "this mutation requires its covered route/disk planner",
                    ),
                ));
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
            let placement_required = false;
            let workspace_id = ingress.idempotency.authenticated_workspace_id.clone();
            let plan_cat_id = cat_id.clone();
            let guest_digest = self.active_guest_digest.clone();
            let snapshot = await_before_deadline(
                ingress.absolute_deadline,
                self.store.execute(move |store| {
                    store.load_lifecycle_snapshot(
                        &workspace_id,
                        &plan_cat_id,
                        &guest_digest,
                        placement_required,
                    )
                }),
            )
            .await
            .map_err(ProductMutationServiceError::from_api)?;
            let mut snapshot = match snapshot {
                Some(snapshot) => snapshot,
                None => return self.fixed_result(ingress, 404, NOT_FOUND_BODY).await,
            };
            if action == Some(CatLifecycleAction::Resume)
                && snapshot.current.target != RuntimeTarget::Running
            {
                let workspace_id = ingress.idempotency.authenticated_workspace_id.clone();
                let plan_cat_id = cat_id.clone();
                let guest_digest = self.active_guest_digest.clone();
                snapshot = await_before_deadline(
                    ingress.absolute_deadline,
                    self.store.execute(move |store| {
                        store.load_lifecycle_snapshot(
                            &workspace_id,
                            &plan_cat_id,
                            &guest_digest,
                            true,
                        )
                    }),
                )
                .await
                .map_err(ProductMutationServiceError::from_api)?
                .ok_or(ProductMutationServiceError::TemporarilyUnavailable)?;
            }
            if let Some(if_match) = ingress.if_match {
                if if_match.get() != snapshot.current.desired_revision.get() {
                    return self.fixed_result(ingress, 409, IF_MATCH_BODY).await;
                }
            }
            if snapshot.current.target == RuntimeTarget::Deleted && action.is_some() {
                return self.fixed_result(ingress, 412, RETIRED_BODY).await;
            }
            if action.is_some_and(|action| !lifecycle_precondition(action, snapshot.current.target))
            {
                return self.fixed_result(ingress, 412, PRECONDITION_BODY).await;
            }
            let operation_id = prefixed_id("op_", self.identities.random_id()?)?;
            let covered = build_lifecycle_request(
                &ingress,
                snapshot,
                action,
                delete_id.as_ref(),
                operation_id,
                self.active_guest_digest.clone(),
            )?;
            match self
                .commit(covered, ingress.absolute_deadline, &mut shutdown)
                .await?
            {
                CommitOutcome::Committed(result) => return Ok(http_result(result)),
                CommitOutcome::Stale | CommitOutcome::OperationCollision => continue,
            }
        }
        Err(ProductMutationServiceError::TemporarilyUnavailable)
    }

    async fn fixed_result(
        &self,
        ingress: AuthorizedProductMutationIngress,
        status: u16,
        body: &'static [u8],
    ) -> std::result::Result<ProductMutationHttpResult, ProductMutationServiceError> {
        let response = super::product::ExactHttpResponse::new(
            status,
            Some(ExactContentType::ApplicationJson),
            body.to_vec(),
        )?;
        let deadline = ingress.absolute_deadline;
        let resolution_request = ingress.idempotency.clone();
        let fixed_request = ingress.idempotency;
        let (cancellation, state) =
            CoveredCommitCancellation::new("fixed product mutation result", deadline);
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
                store.commit_fixed_api_result_covered(&fixed_request, &response, &state)
            });
            tokio::pin!(execution);
            let execution = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable("fixed product result cancelled before commit"))
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
            result = &mut receiver => result.map_err(|_| ApiError::internal("fixed result commit owner stopped"))?,
            () = &mut sleep => {
                if cancellation.cancel_before_commit() {
                    return Err(ProductMutationServiceError::TemporarilyUnavailable);
                }
                receiver.await.map_err(|_| ApiError::internal("fixed result commit owner stopped"))?
            }
        };
        outcome
            .map(http_result)
            .map_err(ProductMutationServiceError::from_api)
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
        covered: CoveredDesiredMutationRequest,
        deadline: Instant,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CommitOutcome, ProductMutationServiceError> {
        let resolution_request = covered.idempotency.clone();
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
                .execute(move |store| Ok(store.commit_desired_mutation_covered(&covered, &state)));
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
                Ok(Err(CoveredDesiredMutationError::CandidateCollision(
                    CandidateCollision::OperationId,
                ))) => Ok(CommitOutcome::OperationCollision),
                Ok(Err(CoveredDesiredMutationError::CandidateCollision(_))) => {
                    Err(ApiError::internal(
                        "lifecycle mutation returned an impossible identity collision",
                    ))
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
    })
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
    fn lifecycle_successors_are_complete_and_delete_has_one_closed_volume_mode() {
        let workspace = id("ws_lifecycle");
        let create = super::super::product_tests::request(
            &workspace,
            "lifecycle-app",
            71,
            "create-lifecycle-app",
        );
        let endpoint_records = vec![create.candidate.endpoint.clone()];
        let snapshot = LifecycleSnapshot {
            current: create.candidate.desired.clone(),
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
            create.candidate.desired.runtime.guest_config_digest.clone(),
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
