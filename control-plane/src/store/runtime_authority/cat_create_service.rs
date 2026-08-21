//! Strict Cat-create ingress and candidate construction.
//!
//! This is the service-side half of the A17 boundary. The production HTTP
//! route is deliberately switched only when the current AgentSession and
//! admission-inventory planner are available; until then this module cannot
//! fall back to the legacy Cat defaults or product tables.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::cat_create::{
    CatCreateV2Request, CatCreateV2ValidationError, CAT_CREATE_V2_MAX_ROOT_SIZE_BYTES,
};
use cats_api::error::{ApiError, ErrorCode};
use cats_api::production_mutation_admission::ProductionQualificationMutationClass;
use cats_api::runtime_inventory::{encode_runtime_inventory_report, RuntimeInventoryBody};
use cats_api::runtime_lifecycle::{
    encode_immutable_runtime_config, encode_lifecycle_command_envelope,
    DiskRole as LifecycleDiskRole, ImmutableRuntimeConfig, LifecycleCommand,
    LifecycleCommandEnvelope, LifecyclePredecessor, PlacementIdentity, RuntimeNetworkConfig,
    RuntimeVolumeAuthorityInput, RuntimeVolumeConfig, RuntimeVolumeGuestBinding, StartSource,
    StartSpec, StartVolumeAuthority,
};
use cats_api::runtime_reconciliation::{
    encode_agent_session, encode_node_identity, encode_node_placement_policy, guest_config_digest,
    AsciiText, ContractVersion, Durability, Epoch, FenceEpoch, Generation,
    GuestRuntimeProfileReceipt, Hostname, Id, NodeIdentityState, RandomId128,
    RuntimeSchedulingState, Sha256Digest,
};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};
use postgres::Transaction;
use serde::Deserialize;

use super::covered_commit::{
    CommitResolutionRegistry, CoveredCommitCancellation, CoveredCommitState,
};
use super::lifecycle_commands::{
    admit_lifecycle_command_in, LifecycleAdmissionRejection, LifecycleCommandAdmission,
};
use super::placement_planner::{
    revalidate_cat_create_placement, runtime_config_placement_claims, runtime_network_id_exists,
    PlacementCommitLoad, PlacementTargetSnapshot,
};
use super::product::{
    api_request_fingerprint, encode_cat_create_accepted_response,
    encode_cat_name_conflict_response, lock_disk_name, ApiIdempotencyRequest, ApiIdempotencyResult,
    CatRecord, DiskAdminState, DiskRecord, DiskRecordCandidate, DiskRole, EndpointRecord,
    EndpointRecordCandidate, ExactContentType, IfMatchFingerprint,
};
use super::product_identity::ProductIdentitySource;
use super::product_rows::{
    insert_api_result, insert_disk, load_api_result_for_update, load_cat_by_name_unlocked,
};
use super::production_mutation_admission::require_production_product_mutation_admitted;
use super::rows::{database_now, insert_volume};
use super::runtime_spine::PLACEMENT_INVENTORY_MAX_AGE_MS;
use crate::store::transaction::{
    AuthorityExecutionError, AuthorityTransactionError, AuthorityTxResult,
};
use crate::store::{Result, Store};

pub(crate) const CAT_CREATE_MAX_BODY_BYTES: usize = 4096;
pub(crate) const CAT_CREATE_CANONICAL_ROUTE: &str = "POST /v1/workspaces/{workspace}/cats";
const CAT_CREATE_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const CHUNK_SIZE_BYTES: u64 = 4_194_304;
pub(crate) const CAT_CREATE_TOTAL_DEADLINE: Duration = Duration::from_secs(10);
const CAT_CREATE_RESOLUTION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);

pub(crate) type ServiceFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub(crate) fn cat_create_absolute_deadline(headers_received_at: Instant) -> Result<Instant> {
    headers_received_at
        .checked_add(CAT_CREATE_TOTAL_DEADLINE)
        .ok_or_else(|| ApiError::unavailable("Cat create deadline overflow"))
}

/// Exact field occurrences after the HTTP parser has removed field-line OWS.
/// Keeping occurrences separate lets the eventual Axum adapter reject a
/// duplicate before comma folding.
#[derive(Debug, Clone, Default)]
pub(crate) struct CatCreateHttpFields {
    pub(crate) content_type: Vec<Vec<u8>>,
    pub(crate) content_encoding: Vec<Vec<u8>>,
    pub(crate) if_match: Vec<Vec<u8>>,
    pub(crate) idempotency_key: Vec<Vec<u8>>,
}

type CatCreateRequestBody = CatCreateV2Request;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedCatCreateIngress {
    request: CatCreateRequestBody,
    idempotency: ApiIdempotencyRequest,
    absolute_deadline: Instant,
}

impl AuthorizedCatCreateIngress {
    pub(crate) fn authenticated_workspace_id(&self) -> &Id {
        &self.idempotency.authenticated_workspace_id
    }

    pub(crate) fn absolute_deadline(&self) -> Instant {
        self.absolute_deadline
    }

    #[cfg(test)]
    pub(super) fn idempotency(&self) -> &ApiIdempotencyRequest {
        &self.idempotency
    }
}

/// Parse only after authentication, current Workspace membership and route
/// permission have produced `authenticated_workspace_id`.
pub(crate) fn parse_authorized_cat_create(
    authenticated_workspace_id: &Id,
    headers_received_at: Instant,
    raw_path_and_query: &[u8],
    fields: &CatCreateHttpFields,
    raw_body: &[u8],
) -> Result<AuthorizedCatCreateIngress> {
    let absolute_deadline = cat_create_absolute_deadline(headers_received_at)?;
    if Instant::now() >= absolute_deadline {
        return Err(ApiError::unavailable("Cat create deadline elapsed"));
    }
    if raw_body.len() > CAT_CREATE_MAX_BODY_BYTES {
        return Err(ApiError::invalid("Cat create body exceeds 4096 bytes"));
    }
    require_exact_single_field(
        &fields.content_type,
        CAT_CREATE_CONTENT_TYPE,
        "Content-Type must occur once and equal application/json",
    )?;
    match fields.content_encoding.as_slice() {
        [] => {}
        [value] if value.as_slice() == IDENTITY_CONTENT_ENCODING => {}
        _ => {
            return Err(ApiError::invalid(
                "Content-Encoding must be absent or one exact identity value",
            ));
        }
    }
    if !fields.if_match.is_empty() {
        return Err(ApiError::invalid("If-Match is not allowed for Cat create"));
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

    let expected_path = format!("/v1/workspaces/{authenticated_workspace_id}/cats");
    if raw_path_and_query != expected_path.as_bytes() {
        return Err(ApiError::invalid(
            "Cat create path must use the canonical workspace ID and no query",
        ));
    }

    let mut decoder = serde_json::Deserializer::from_slice(raw_body);
    let request = CatCreateRequestBody::deserialize(&mut decoder)
        .map_err(|_| ApiError::invalid("Cat create body is malformed"))?;
    decoder
        .end()
        .map_err(|_| ApiError::invalid("Cat create body has a non-whitespace tail"))?;
    validate_request(&request)?;

    let canonical_route = AsciiText::new(CAT_CREATE_CANONICAL_ROUTE)
        .expect("the canonical Cat-create route is valid ASCII");
    let request_fingerprint = api_request_fingerprint(
        authenticated_workspace_id,
        &canonical_route,
        raw_path_and_query,
        IfMatchFingerprint::Absent,
        raw_body,
    )?;
    Ok(AuthorizedCatCreateIngress {
        request,
        idempotency: ApiIdempotencyRequest {
            authenticated_workspace_id: authenticated_workspace_id.clone(),
            canonical_route,
            idempotency_key,
            request_fingerprint,
        },
        absolute_deadline,
    })
}

fn require_exact_single_field(
    occurrences: &[Vec<u8>],
    expected: &[u8],
    message: &'static str,
) -> Result<()> {
    match occurrences {
        [value] if value.as_slice() == expected => Ok(()),
        _ => Err(ApiError::invalid(message)),
    }
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

fn validate_request(request: &CatCreateRequestBody) -> Result<()> {
    request.validate().map_err(|error| match error {
        CatCreateV2ValidationError::Name
        | CatCreateV2ValidationError::Vcpus
        | CatCreateV2ValidationError::MemoryBytes
        | CatCreateV2ValidationError::RootSizeBytes => ApiError::invalid(error.to_string()),
        // JSON decoding rejects this before semantic validation. Keep the arm
        // explicit so a future construction path cannot weaken the boundary.
        CatCreateV2ValidationError::BootImageDigest => {
            ApiError::invalid("Cat create body is malformed")
        }
    })
}

/// Result of the immutable-image adapter's complete manifest validation.
/// The adapter, not this service, owns object-store I/O and blockd manifest
/// grammar; returning the addressed digest prevents alias/catalog fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ValidatedImageManifest {
    pub(crate) boot_image_digest: Sha256Digest,
    pub(crate) size_bytes: u64,
}

pub(crate) trait CatCreateManifestResolver: Send + Sync {
    fn resolve<'a>(
        &'a self,
        boot_image_digest: &'a Sha256Digest,
    ) -> ServiceFuture<'a, ValidatedImageManifest>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreatePlanRequest {
    pub(crate) cat_id: Id,
    pub(crate) vcpus: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) root_size_bytes: u64,
    pub(crate) durability: Durability,
    pub(crate) boot_image_digest: Sha256Digest,
    pub(crate) guest_config_digest: Sha256Digest,
    pub(crate) network_id: Id,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreatePlacementMutation {
    pub(crate) cat_id: Id,
    pub(crate) placement_epoch: Epoch,
    pub(crate) vcpus: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) network_config: RuntimeNetworkConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreatePlan {
    pub(crate) target: PlacementTargetSnapshot,
    pub(crate) mutation: CatCreatePlacementMutation,
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(
    clippy::large_enum_variant,
    reason = "the one bounded successful plan is consumed immediately across this internal async planner boundary"
)]
pub(crate) enum CatCreatePlacementOutcome {
    Planned(CatCreatePlan),
    Unavailable,
    CandidateIdentityCollision,
}

/// The implementation must select only from current AgentSessions plus fresh
/// full admission inventory. The plan is deliberately a complete typed
/// binding, not `capacity_ok` or `network_ok` booleans.
pub(crate) trait CatCreatePlacementPlanner: Send + Sync {
    fn plan<'a>(
        &'a self,
        request: &'a CatCreatePlanRequest,
        absolute_deadline: Instant,
    ) -> ServiceFuture<'a, CatCreatePlacementOutcome>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatCreateIdentities {
    cat: RandomId128,
    cat_creation: RandomId128,
    disk: RandomId128,
    volume: RandomId128,
    config: RandomId128,
    operation: RandomId128,
    endpoint: RandomId128,
    network: RandomId128,
    acquire_transition: RandomId128,
}

impl CatCreateIdentities {
    fn generate(source: &dyn ProductIdentitySource) -> Result<Self> {
        Ok(Self {
            cat: source.random_id()?,
            cat_creation: source.random_id()?,
            disk: source.random_id()?,
            volume: source.random_id()?,
            config: source.random_id()?,
            operation: source.random_id()?,
            endpoint: source.random_id()?,
            network: source.random_id()?,
            acquire_transition: source.random_id()?,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AtomicCatCreateCandidate {
    cat_id: Id,
    cat_creation_id: Id,
    workspace_id: Id,
    name: Id,
    root_disk: DiskRecordCandidate,
    volume: VolumeRecord,
    runtime_config: cats_api::runtime_lifecycle::ImmutableRuntimeConfig,
    start_volume_authorities: Vec<cats_api::runtime_lifecycle::StartVolumeAuthority>,
    endpoint: EndpointRecordCandidate,
    hostname: Hostname,
    operation_id: Id,
    node_id: Id,
    placement_epoch: Epoch,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct AtomicCatCreateRequest {
    idempotency: ApiIdempotencyRequest,
    candidate: AtomicCatCreateCandidate,
    accepted_response_body: Vec<u8>,
    name_conflict_response_body: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatCreateHttpResult {
    pub(crate) http_status: u16,
    pub(crate) content_type: Option<&'static str>,
    pub(crate) response_body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum CatCreateServiceError {
    Request(ApiError),
    PlacementUnavailable,
    TemporarilyUnavailable,
    Fatal(ApiError),
}

impl CatCreateServiceError {
    fn from_api(error: ApiError) -> Self {
        match error.code {
            ErrorCode::Unavailable | ErrorCode::DeadlineExceeded => Self::TemporarilyUnavailable,
            ErrorCode::Internal => Self::Fatal(error),
            _ => Self::Request(error),
        }
    }

    #[cfg(test)]
    pub(super) fn error_code(&self) -> ErrorCode {
        match self {
            Self::Request(error) | Self::Fatal(error) => error.code,
            Self::PlacementUnavailable | Self::TemporarilyUnavailable => ErrorCode::Unavailable,
        }
    }
}

impl From<ApiError> for CatCreateServiceError {
    fn from(error: ApiError) -> Self {
        Self::from_api(error)
    }
}

#[derive(Debug)]
enum CatCreateCommitOutcome {
    Committed(ApiIdempotencyResult),
    CandidateIdentityCollision,
    PlacementStale,
}

#[derive(Debug)]
enum AtomicCatCreateError {
    CandidateIdentityCollision,
    PlacementStale,
    Store(ApiError),
}

pub(crate) struct CatCreateService {
    store: Arc<Store>,
    manifests: Arc<dyn CatCreateManifestResolver>,
    planner: Arc<dyn CatCreatePlacementPlanner>,
    identities: Arc<dyn ProductIdentitySource>,
    guest_config_digest: Sha256Digest,
    commit_resolutions: Arc<CommitResolutionRegistry>,
    admission: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    planner_calls: std::sync::atomic::AtomicUsize,
}

impl CatCreateService {
    pub(crate) fn new(
        store: Arc<Store>,
        manifests: Arc<dyn CatCreateManifestResolver>,
        planner: Arc<dyn CatCreatePlacementPlanner>,
        identities: Arc<dyn ProductIdentitySource>,
        active_release_receipt: &GuestRuntimeProfileReceipt,
    ) -> Result<Self> {
        let guest_config_digest = guest_config_digest(active_release_receipt)
            .map_err(|_| ApiError::invalid("active Guest runtime profile receipt is invalid"))?;
        let (admission, _) = tokio::sync::watch::channel(true);
        Ok(Self {
            store,
            manifests,
            planner,
            identities,
            guest_config_digest,
            commit_resolutions: Arc::new(CommitResolutionRegistry::default()),
            admission,
            #[cfg(test)]
            planner_calls: std::sync::atomic::AtomicUsize::new(0),
        })
    }

    pub(crate) async fn create(
        &self,
        ingress: AuthorizedCatCreateIngress,
    ) -> std::result::Result<CatCreateHttpResult, CatCreateServiceError> {
        let shutdown = self.admission.subscribe();
        if !*shutdown.borrow() {
            return Err(CatCreateServiceError::TemporarilyUnavailable);
        }
        let absolute_deadline = ingress.absolute_deadline;
        self.create_before_deadline(ingress, absolute_deadline, shutdown)
            .await
    }

    /// Reads an authenticated request's exact durable result without any
    /// mutable create admission. Billing may change after the original atomic
    /// commit, but it cannot hide the covered result from the same
    /// Workspace/key/fingerprint.
    pub(crate) async fn replay(
        &self,
        ingress: &AuthorizedCatCreateIngress,
    ) -> std::result::Result<Option<CatCreateHttpResult>, CatCreateServiceError> {
        if !*self.admission.borrow() {
            return Err(CatCreateServiceError::TemporarilyUnavailable);
        }
        self.fast_replay(ingress).await
    }

    async fn fast_replay(
        &self,
        ingress: &AuthorizedCatCreateIngress,
    ) -> std::result::Result<Option<CatCreateHttpResult>, CatCreateServiceError> {
        let fast_request = ingress.idempotency.clone();
        await_cat_create_before_deadline(
            ingress.absolute_deadline,
            self.store
                .execute(move |store| store.covered_api_result_fast_lookup(&fast_request)),
        )
        .await
        .map(|result| result.map(http_result))
        .map_err(CatCreateServiceError::from_api)
    }

    async fn create_before_deadline(
        &self,
        ingress: AuthorizedCatCreateIngress,
        absolute_deadline: Instant,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CatCreateHttpResult, CatCreateServiceError> {
        if let Some(result) = self.fast_replay(&ingress).await? {
            return Ok(result);
        }

        let manifest = await_cat_create_before_deadline(
            absolute_deadline,
            self.manifests.resolve(&ingress.request.boot_image_digest),
        )
        .await
        .map_err(CatCreateServiceError::from_api)?;
        if manifest.boot_image_digest != ingress.request.boot_image_digest {
            return Err(CatCreateServiceError::Fatal(ApiError::internal(
                "image manifest resolver returned a different digest",
            )));
        }
        let root_size_bytes = rounded_root_size(ingress.request.root_size_bytes)
            .map_err(CatCreateServiceError::from_api)?;
        if root_size_bytes < manifest.size_bytes {
            return Err(CatCreateServiceError::Request(ApiError::invalid(
                "root_size_bytes is smaller than the immutable image manifest",
            )));
        }

        let identities = CatCreateIdentities::generate(self.identities.as_ref())
            .map_err(CatCreateServiceError::from_api)?;
        let cat_id =
            prefixed_id("cat_", &identities.cat).map_err(CatCreateServiceError::from_api)?;
        let network_id =
            prefixed_id("net_", &identities.network).map_err(CatCreateServiceError::from_api)?;
        let plan_request = CatCreatePlanRequest {
            cat_id,
            vcpus: ingress.request.vcpus,
            memory_bytes: ingress.request.memory_bytes,
            root_size_bytes,
            durability: ingress.request.durability,
            boot_image_digest: ingress.request.boot_image_digest.clone(),
            guest_config_digest: self.guest_config_digest.clone(),
            network_id: network_id.clone(),
        };
        #[cfg(test)]
        self.planner_calls
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let plan = match await_cat_create_before_deadline(
            absolute_deadline,
            self.planner.plan(&plan_request, absolute_deadline),
        )
        .await
        .map_err(CatCreateServiceError::from_api)?
        {
            CatCreatePlacementOutcome::Planned(plan) => plan,
            CatCreatePlacementOutcome::Unavailable => {
                return Err(CatCreateServiceError::PlacementUnavailable);
            }
            CatCreatePlacementOutcome::CandidateIdentityCollision => {
                return Err(CatCreateServiceError::TemporarilyUnavailable);
            }
        };
        validate_plan_evidence(&plan, &plan_request, &self.guest_config_digest)
            .map_err(CatCreateServiceError::from_api)?;
        let planned_target = plan.target.clone();
        let planned_mutation = plan.mutation.clone();
        let guest_config_digest = self.guest_config_digest.clone();
        let covered = build_covered_request(
            ingress,
            identities,
            plan,
            guest_config_digest.clone(),
            root_size_bytes,
        )
        .map_err(CatCreateServiceError::from_api)?;
        let resolution_request = covered.idempotency.clone();
        let (commit_cancellation, commit_state) =
            CoveredCommitCancellation::new("Cat create", absolute_deadline);
        let commit_observer = commit_state.clone();
        let cancellation_observer = commit_state.clone();
        // Register an owner before the Store job starts. The request handler
        // owns only the receiver and the PRE_COMMIT cancellation token. If the
        // handler disappears after COMMIT_SENT, this task still consumes the
        // worker outcome and resolves any ambiguous commit while shutdown can
        // account for it.
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(CatCreateServiceError::TemporarilyUnavailable);
        };
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store.execute(move |store| {
                Ok(store.create_atomic_cat_covered_with_placement(
                    &covered,
                    &planned_target,
                    &planned_mutation,
                    &guest_config_digest,
                    &commit_state,
                ))
            });
            tokio::pin!(execution);
            let execution_outcome = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    // Dropping a queued Store execution removes it from the
                    // bounded queue. An active worker will observe the same
                    // cancellation at its next transaction checkpoint.
                    Err(ApiError::unavailable(
                        "Cat create was cancelled before PostgreSQL commit",
                    ))
                }
            };
            let outcome = match execution_outcome {
                Ok(Ok(result)) => Ok(CatCreateCommitOutcome::Committed(result)),
                Ok(Err(AtomicCatCreateError::CandidateIdentityCollision)) => {
                    Ok(CatCreateCommitOutcome::CandidateIdentityCollision)
                }
                Ok(Err(AtomicCatCreateError::PlacementStale)) => {
                    Ok(CatCreateCommitOutcome::PlacementStale)
                }
                Ok(Err(AtomicCatCreateError::Store(error))) | Err(error)
                    if commit_observer.commit_was_sent() =>
                {
                    resolve_cat_create_commit_loop(store, resolution_request, error)
                        .await
                        .map(CatCreateCommitOutcome::Committed)
                }
                Ok(Err(AtomicCatCreateError::Store(error))) | Err(error) => Err(error),
            };
            let _ = result_tx.send(outcome);
            drop(active);
        });
        let deadline = tokio::time::sleep_until(tokio::time::Instant::from_std(absolute_deadline));
        tokio::pin!(deadline);
        let outcome = tokio::select! {
            result = &mut result_rx => result.map_err(|_| {
                ApiError::internal("Cat create commit owner stopped without a result")
            })?,
            () = &mut deadline => {
                if commit_cancellation.cancel_before_commit() {
                    // The atomic cancellation won against begin_commit. The
                    // worker may still be unwinding a bounded SQL call, but it
                    // can no longer publish any result or business row.
                    return Err(CatCreateServiceError::TemporarilyUnavailable);
                }
                // PostgreSQL commit has started. The result is no longer an
                // ordinary timeout: await the registered owner, which retains
                // the worker and resolves the exact durable outcome.
                result_rx.await.map_err(|_| {
                    ApiError::internal("Cat create commit owner stopped without a result")
                })?
            },
            () = wait_for_shutdown(&mut shutdown) => {
                if commit_cancellation.cancel_before_commit() {
                    return Err(CatCreateServiceError::TemporarilyUnavailable);
                }
                result_rx.await.map_err(|_| {
                    ApiError::internal("Cat create commit owner stopped without a result")
                })?
            }
        };
        match outcome.map_err(CatCreateServiceError::from_api)? {
            CatCreateCommitOutcome::Committed(result) => Ok(http_result(result)),
            CatCreateCommitOutcome::CandidateIdentityCollision => {
                Err(CatCreateServiceError::TemporarilyUnavailable)
            }
            CatCreateCommitOutcome::PlacementStale => {
                Err(CatCreateServiceError::PlacementUnavailable)
            }
        }
    }

    pub(crate) fn begin_shutdown(&self) {
        self.commit_resolutions.close();
        self.admission.send_replace(false);
    }

    pub(crate) async fn shutdown_commit_resolutions(&self) -> Result<()> {
        self.begin_shutdown();
        tokio::time::timeout(
            CAT_CREATE_RESOLUTION_SHUTDOWN_DEADLINE,
            self.commit_resolutions.wait_empty(),
        )
        .await
        .map_err(|_| {
            ApiError::unavailable(format!(
                "{} Cat create commit resolutions remain after shutdown deadline",
                self.commit_resolutions.active()
            ))
        })
    }

    #[cfg(test)]
    pub(crate) fn active_commit_resolutions(&self) -> usize {
        self.commit_resolutions.active()
    }

    #[cfg(test)]
    pub(crate) fn planner_calls_for_test(&self) -> usize {
        self.planner_calls.load(std::sync::atomic::Ordering::SeqCst)
    }

    #[cfg(test)]
    pub(crate) fn durable_create_row_counts_for_test(&self) -> Result<(i64, i64)> {
        self.store.with(|client| {
            client
                .query_one(
                    "SELECT
                        (SELECT count(*) FROM cat_records),
                        (SELECT count(*) FROM api_idempotency_results)",
                    &[],
                )
                .map(|row| (row.get(0), row.get(1)))
        })
    }
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

async fn resolve_cat_create_commit_loop(
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
            Err(error) if error.code == cats_api::error::ErrorCode::Unavailable => {
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
            Err(error) => return Err(error),
        }
    }
}

async fn await_cat_create_before_deadline<T>(
    absolute_deadline: Instant,
    operation: impl Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(absolute_deadline), operation)
        .await
        .map_err(|_| ApiError::unavailable("Cat create deadline elapsed"))?
}

fn rounded_root_size(requested: u64) -> Result<u64> {
    let rounded = requested
        .checked_add(CHUNK_SIZE_BYTES - 1)
        .map(|value| value / CHUNK_SIZE_BYTES * CHUNK_SIZE_BYTES)
        .ok_or_else(|| ApiError::invalid("root_size_bytes cannot be rounded safely"))?;
    if rounded > CAT_CREATE_V2_MAX_ROOT_SIZE_BYTES {
        return Err(ApiError::invalid(
            "rounded root_size_bytes exceeds 1099511627776",
        ));
    }
    Ok(rounded)
}

fn validate_plan_evidence(
    plan: &CatCreatePlan,
    request: &CatCreatePlanRequest,
    active_guest_digest: &Sha256Digest,
) -> Result<()> {
    encode_node_placement_policy(&plan.target.policy)
        .map_err(|_| ApiError::internal("placement planner returned an invalid policy"))?;
    encode_node_identity(&plan.target.node_identity)
        .map_err(|_| ApiError::internal("placement planner returned an invalid NodeIdentity"))?;
    encode_agent_session(&plan.target.agent_session)
        .map_err(|_| ApiError::internal("placement planner returned an invalid AgentSession"))?;
    encode_runtime_inventory_report(&plan.target.full_inventory_report)
        .map_err(|_| ApiError::internal("placement planner returned an invalid full inventory"))?;
    let attestation = &plan.target.inventory_attestation;
    let report = &plan.target.full_inventory_report;
    let RuntimeInventoryBody::Full {
        inventory_epoch,
        scan_id,
        inventory_digest,
        ..
    } = &report.inventory
    else {
        return Err(ApiError::internal(
            "placement planner returned a Partial inventory",
        ));
    };
    let session = plan.target.session_binding();
    if plan.mutation.cat_id != request.cat_id
        || plan.mutation.placement_epoch != Epoch::new(1).expect("one is a valid Epoch")
        || plan.mutation.vcpus != request.vcpus
        || plan.mutation.memory_bytes != request.memory_bytes
        || runtime_network_id(&plan.mutation.network_config) != &request.network_id
        || plan.target.node_identity.state != NodeIdentityState::Provisioned
        || plan.target.policy.node_id != plan.target.node_identity.node_id
        || plan.target.policy.scheduling_state != RuntimeSchedulingState::Schedulable
        || plan.target.policy.capabilities.guest_config_digest != *active_guest_digest
        || plan.target.active_host_fence_event.is_some()
        || plan.target.node_identity.node_id != plan.target.agent_session.node_id
        || plan.target.node_identity.immutable_host_id
            != plan.target.agent_session.immutable_host_id
        || plan.target.agent_session.guest_config_digest != *active_guest_digest
        || plan.target.evaluated_at_unix_ms >= plan.target.agent_session.lease_deadline_unix_ms
        || attestation.version != ContractVersion::V1
        || attestation.session != session
        || report.session != session
        || attestation.inventory_epoch != *inventory_epoch
        || attestation.scan_id != *scan_id
        || attestation.inventory_digest != *inventory_digest
        || attestation.source_report_id != report.report_id
        || attestation.source_sequence != report.sequence
        || attestation.accepted_at_unix_ms > plan.target.evaluated_at_unix_ms
    {
        return Err(ApiError::internal(
            "placement planner evidence is not bound to one current compatible Node session",
        ));
    }
    let stale_at = attestation
        .accepted_at_unix_ms
        .get()
        .checked_add(PLACEMENT_INVENTORY_MAX_AGE_MS)
        .ok_or_else(|| ApiError::internal("placement inventory freshness overflow"))?;
    if plan.target.evaluated_at_unix_ms.get() >= stale_at {
        return Err(ApiError::internal(
            "placement planner returned stale admission inventory",
        ));
    }
    Ok(())
}

fn runtime_network_id(config: &RuntimeNetworkConfig) -> &Id {
    match config {
        RuntimeNetworkConfig::IsolatedIpv4 { network_id, .. } => network_id,
    }
}

fn prefixed_id(prefix: &str, random: &RandomId128) -> Result<Id> {
    Id::new(format!("{prefix}{}", random.as_str()))
        .ok_or_else(|| ApiError::internal("candidate identity is invalid"))
}

fn reserve_cat_create_api_key(
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

pub(super) fn lock_cat_create_text(
    transaction: &mut Transaction<'_>,
    domain: &'static str,
    first: &str,
    second: &str,
) -> AuthorityTxResult<()> {
    transaction.query_one(
        "SELECT pg_advisory_xact_lock(hashtextextended(
            current_schema() || ':atomic-cat-create:' || $1 || ':' || $2 || ':' || $3,
            0::BIGINT
         ))",
        &[&domain, &first, &second],
    )?;
    Ok(())
}

fn exact_cat_create_replay(
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

fn cat_create_api_result(
    request: &ApiIdempotencyRequest,
    status: u16,
    body: Vec<u8>,
    now: cats_api::runtime_reconciliation::UnixMillis,
) -> ApiIdempotencyResult {
    ApiIdempotencyResult {
        authenticated_workspace_id: request.authenticated_workspace_id.clone(),
        canonical_route: request.canonical_route.clone(),
        idempotency_key: request.idempotency_key.clone(),
        request_fingerprint: request.request_fingerprint.clone(),
        http_status: status,
        content_type: Some(ExactContentType::ApplicationJson),
        response_body: body,
        created_at: now,
    }
}

fn cat_create_candidates_exist(
    transaction: &mut Transaction<'_>,
    candidate: &AtomicCatCreateCandidate,
) -> AuthorityTxResult<bool> {
    let row = transaction.query_one(
        "SELECT
            EXISTS (SELECT 1 FROM cat_records WHERE cat_id=$1) AS cat_exists,
            EXISTS (SELECT 1 FROM disk_records WHERE disk_id=$2) AS disk_exists,
            EXISTS (SELECT 1 FROM volume_records WHERE volume_id=$3) AS volume_exists,
            EXISTS (SELECT 1 FROM endpoint_records WHERE endpoint_id=$4) AS endpoint_exists,
            EXISTS (SELECT 1 FROM runtime_operations WHERE operation_id=$5) AS operation_exists,
            EXISTS (SELECT 1 FROM cat_runtime_configs WHERE config_id=$6) AS config_exists,
            EXISTS (SELECT 1 FROM hostname_endpoint_lookups WHERE hostname=$7) AS hostname_exists",
        &[
            &candidate.cat_id.as_str(),
            &candidate.root_disk.disk_id.as_str(),
            &candidate.volume.volume_id.as_str(),
            &candidate.endpoint.endpoint_id.as_str(),
            &candidate.operation_id.as_str(),
            &candidate.runtime_config.config_id.as_str(),
            &candidate.hostname.as_str(),
        ],
    )?;
    Ok(row.try_get::<_, bool>("cat_exists")?
        || row.try_get::<_, bool>("disk_exists")?
        || row.try_get::<_, bool>("volume_exists")?
        || row.try_get::<_, bool>("endpoint_exists")?
        || row.try_get::<_, bool>("operation_exists")?
        || row.try_get::<_, bool>("config_exists")?
        || row.try_get::<_, bool>("hostname_exists")?)
}

fn insert_atomic_cat(
    transaction: &mut Transaction<'_>,
    candidate: &AtomicCatCreateCandidate,
    now: cats_api::runtime_reconciliation::UnixMillis,
) -> AuthorityTxResult<()> {
    let record = CatRecord {
        cat_id: candidate.cat_id.clone(),
        workspace_id: candidate.workspace_id.clone(),
        name: candidate.name.clone(),
        created_at: now,
    };
    let record_json = serde_json::to_string(&record)
        .map_err(|_| ApiError::internal("Cat record cannot be encoded"))?;
    let now_pg = i64::try_from(now.get())
        .map_err(|_| ApiError::internal("database time exceeds PostgreSQL BIGINT"))?;
    transaction.execute(
        "INSERT INTO cat_records (
            cat_id, record, workspace_id, name, cat_creation_id,
            lifecycle_head_operation_id, stable_state,
            effective_runtime_ready_operation_id, runtime_incarnation,
            current_runtime_config_id, current_runtime_config_sha256,
            created_at, deleted_at
         ) VALUES ($1,$2::TEXT::jsonb,$3,$4,$5,NULL,NULL,NULL,NULL,$6,$7,$8,NULL)",
        &[
            &candidate.cat_id.as_str(),
            &record_json,
            &candidate.workspace_id.as_str(),
            &candidate.name.as_str(),
            &candidate.cat_creation_id.as_str(),
            &candidate.runtime_config.config_id.as_str(),
            &candidate.runtime_config.config_digest.as_str(),
            &now_pg,
        ],
    )?;
    Ok(())
}

fn insert_atomic_runtime_config(
    transaction: &mut Transaction<'_>,
    candidate: &AtomicCatCreateCandidate,
    now: cats_api::runtime_reconciliation::UnixMillis,
) -> AuthorityTxResult<()> {
    let canonical = encode_immutable_runtime_config(&candidate.runtime_config)
        .map_err(|_| ApiError::internal("immutable runtime config cannot be encoded"))?;
    let claims = runtime_config_placement_claims(&candidate.runtime_config)?;
    let now_pg = i64::try_from(now.get())
        .map_err(|_| ApiError::internal("database time exceeds PostgreSQL BIGINT"))?;
    transaction.execute(
        "INSERT INTO cat_runtime_configs (
            config_id, workspace_id, cat_id, canonical_config_bytes,
            canonical_config_sha256, placement_vcpus,
            placement_memory_bytes, placement_network_id,
            placement_ipv4_pool_base, placement_ipv4_slot, placement_disk_ids,
            placement_volume_ids, created_at_unix_ms
         ) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)",
        &[
            &candidate.runtime_config.config_id.as_str(),
            &candidate.workspace_id.as_str(),
            &candidate.cat_id.as_str(),
            &canonical,
            &candidate.runtime_config.config_digest.as_str(),
            &claims.vcpus,
            &claims.memory_bytes,
            &claims.network_id.as_str(),
            &claims.ipv4_pool_base,
            &claims.isolated_ipv4_slot,
            &claims.disk_ids,
            &claims.volume_ids,
            &now_pg,
        ],
    )?;
    Ok(())
}

fn insert_atomic_cat_product_rows(
    transaction: &mut Transaction<'_>,
    candidate: &AtomicCatCreateCandidate,
    now: cats_api::runtime_reconciliation::UnixMillis,
) -> AuthorityTxResult<()> {
    insert_atomic_cat(transaction, candidate, now)?;
    insert_atomic_runtime_config(transaction, candidate, now)?;
    insert_volume(transaction, &candidate.volume)?;
    insert_disk(
        transaction,
        &DiskRecord {
            disk_id: candidate.root_disk.disk_id.clone(),
            workspace_id: candidate.root_disk.workspace_id.clone(),
            name: candidate.root_disk.name.clone(),
            volume_id: candidate.root_disk.volume_id.clone(),
            size_bytes: candidate.root_disk.size_bytes,
            durability: candidate.root_disk.durability,
            created_at: now,
            admin_state: candidate.root_disk.admin_state.clone(),
            role: candidate.root_disk.role.clone(),
        },
    )?;
    let endpoint = EndpointRecord {
        endpoint_id: candidate.endpoint.endpoint_id.clone(),
        workspace_id: candidate.endpoint.workspace_id.clone(),
        cat_id: candidate.endpoint.cat_id.clone(),
        name: candidate.endpoint.name.clone(),
        created_at: now,
    };
    let endpoint_json = serde_json::to_string(&endpoint)
        .map_err(|_| ApiError::internal("Endpoint record cannot be encoded"))?;
    let now_pg = i64::try_from(now.get())
        .map_err(|_| ApiError::internal("database time exceeds PostgreSQL BIGINT"))?;
    transaction.execute(
        "INSERT INTO endpoint_records (
            endpoint_id, record, workspace_id, cat_id, name,
            binding_state, hostname, protocol, target_port, route_epoch,
            route_head_operation_id, effective_serving_operation_id,
            created_at, updated_at_unix_ms
         ) VALUES (
            $1,$2::TEXT::jsonb,$3,$4,$5,
            'bound',$6,'http',8080,1,NULL,NULL,$7,$7
         )",
        &[
            &endpoint.endpoint_id.as_str(),
            &endpoint_json,
            &endpoint.workspace_id.as_str(),
            &endpoint.cat_id.as_str(),
            &endpoint.name.as_str(),
            &candidate.hostname.as_str(),
            &now_pg,
        ],
    )?;
    transaction.execute(
        "INSERT INTO hostname_endpoint_lookups (
            hostname, workspace_id, cat_id, endpoint_id
         ) VALUES ($1,$2,$3,$4)",
        &[
            &candidate.hostname.as_str(),
            &candidate.workspace_id.as_str(),
            &candidate.cat_id.as_str(),
            &candidate.endpoint.endpoint_id.as_str(),
        ],
    )?;
    Ok(())
}

fn build_genesis_start_command(
    candidate: &AtomicCatCreateCandidate,
    now: cats_api::runtime_reconciliation::UnixMillis,
) -> Result<LifecycleCommandEnvelope> {
    let effect_deadline_unix_ms = now
        .get()
        .checked_add(120_000)
        .and_then(cats_api::runtime_reconciliation::UnixMillis::new)
        .ok_or_else(|| ApiError::failed_precondition("Genesis Start deadline is exhausted"))?;
    let placement = PlacementIdentity {
        node_id: candidate.node_id.clone(),
        placement_epoch: candidate.placement_epoch,
    };
    LifecycleCommandEnvelope::new(
        candidate.operation_id.clone(),
        candidate.workspace_id.clone(),
        candidate.cat_id.clone(),
        candidate.node_id.clone(),
        placement.clone(),
        candidate.runtime_config.clone(),
        None,
        LifecyclePredecessor::Genesis {
            cat_creation_id: candidate.cat_creation_id.clone(),
            target_placement: placement,
        },
        LifecycleCommand::Start(Box::new(StartSpec {
            volume_authorities: candidate.start_volume_authorities.clone(),
            source: StartSource::Genesis,
            effect_deadline_unix_ms,
        })),
    )
    .map_err(|_| ApiError::internal("constructed Genesis Start violates the frozen contract"))
}

impl Store {
    fn create_atomic_cat_covered_with_placement(
        &self,
        request: &AtomicCatCreateRequest,
        planned_target: &PlacementTargetSnapshot,
        planned_mutation: &CatCreatePlacementMutation,
        active_guest_digest: &Sha256Digest,
        commit_state: &CoveredCommitState,
    ) -> std::result::Result<ApiIdempotencyResult, AtomicCatCreateError> {
        let mut candidate_collision = false;
        let outcome = self.authority_transaction_outcome_with_definite_retry(
            |transaction| {
                commit_state.checkpoint(transaction)?;
                reserve_cat_create_api_key(transaction, &request.idempotency)?;
                commit_state.checkpoint(transaction)?;
                if let Some(result) = load_api_result_for_update(transaction, &request.idempotency)?
                {
                    let result = exact_cat_create_replay(result, &request.idempotency)?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                require_production_product_mutation_admitted(
                    transaction,
                    &request.idempotency.authenticated_workspace_id,
                    ProductionQualificationMutationClass::CatCreate,
                )?;
                let now = database_now(transaction)?;
                let network_id =
                    runtime_network_id(&request.candidate.runtime_config.network_config);
                lock_cat_create_text(transaction, "network-id", network_id.as_str(), "candidate")?;
                if runtime_network_id_exists(transaction, network_id)? {
                    candidate_collision = true;
                    return Err(AuthorityTransactionError::CandidateCollision);
                }
                if revalidate_cat_create_placement(
                    transaction,
                    planned_target,
                    planned_mutation,
                    active_guest_digest,
                    now,
                    &mut |transaction| commit_state.checkpoint(transaction),
                )? != PlacementCommitLoad::Accepted
                {
                    return Err(AuthorityTransactionError::PlacementStale);
                }
                lock_cat_create_text(
                    transaction,
                    "cat-name",
                    request.candidate.workspace_id.as_str(),
                    request.candidate.name.as_str(),
                )?;
                if load_cat_by_name_unlocked(
                    transaction,
                    &request.candidate.workspace_id,
                    &request.candidate.name,
                )?
                .is_some()
                {
                    let result = cat_create_api_result(
                        &request.idempotency,
                        409,
                        request.name_conflict_response_body.clone(),
                        database_now(transaction)?,
                    );
                    insert_api_result(transaction, &result)?;
                    commit_state.begin_commit(transaction)?;
                    return Ok(result);
                }
                lock_disk_name(
                    transaction,
                    &request.candidate.workspace_id,
                    &request.candidate.root_disk.name,
                )?;
                for (domain, identity) in [
                    ("cat-id", request.candidate.cat_id.as_str()),
                    (
                        "config-id",
                        request.candidate.runtime_config.config_id.as_str(),
                    ),
                    ("disk-id", request.candidate.root_disk.disk_id.as_str()),
                    (
                        "endpoint-id",
                        request.candidate.endpoint.endpoint_id.as_str(),
                    ),
                    ("operation-id", request.candidate.operation_id.as_str()),
                    ("volume-id", request.candidate.volume.volume_id.as_str()),
                ] {
                    lock_cat_create_text(transaction, domain, identity, "candidate")?;
                }
                lock_cat_create_text(
                    transaction,
                    "hostname",
                    request.candidate.hostname.as_str(),
                    "candidate",
                )?;
                if cat_create_candidates_exist(transaction, &request.candidate)? {
                    candidate_collision = true;
                    return Err(AuthorityTransactionError::CandidateCollision);
                }
                insert_atomic_cat_product_rows(transaction, &request.candidate, now)?;
                let command = build_genesis_start_command(&request.candidate, now)?;
                let canonical = encode_lifecycle_command_envelope(&command)
                    .map_err(|_| ApiError::internal("Genesis Start cannot be encoded"))?;
                match admit_lifecycle_command_in(
                    transaction,
                    &request.candidate.workspace_id,
                    &command,
                    &canonical,
                )? {
                    LifecycleCommandAdmission::Admitted(_) => {}
                    LifecycleCommandAdmission::ExactReplay(_) => {
                        return Err(ApiError::internal(
                            "new Cat Genesis Start unexpectedly replayed an Operation",
                        )
                        .into());
                    }
                    LifecycleCommandAdmission::Rejected(
                        LifecycleAdmissionRejection::OperationIdentityConflict { .. },
                    ) => {
                        candidate_collision = true;
                        return Err(AuthorityTransactionError::CandidateCollision);
                    }
                    LifecycleCommandAdmission::Rejected(_) => {
                        return Err(ApiError::internal(
                            "new Cat Genesis Start was rejected after candidate validation",
                        )
                        .into());
                    }
                }
                let result = cat_create_api_result(
                    &request.idempotency,
                    202,
                    request.accepted_response_body.clone(),
                    database_now(transaction)?,
                );
                insert_api_result(transaction, &result)?;
                commit_state.begin_commit(transaction)?;
                Ok(result)
            },
            || commit_state.reset_after_definite_retry(),
        );
        match outcome {
            Ok(result) => Ok(result),
            Err(AuthorityExecutionError::CandidateCollision) if candidate_collision => {
                Err(AtomicCatCreateError::CandidateIdentityCollision)
            }
            Err(AuthorityExecutionError::PlacementStale) => {
                Err(AtomicCatCreateError::PlacementStale)
            }
            Err(AuthorityExecutionError::Store(error)) => Err(AtomicCatCreateError::Store(error)),
            Err(AuthorityExecutionError::CandidateCollision) => Err(AtomicCatCreateError::Store(
                ApiError::internal("Cat create lost its candidate collision marker"),
            )),
        }
    }
}

fn build_covered_request(
    ingress: AuthorizedCatCreateIngress,
    identities: CatCreateIdentities,
    plan: CatCreatePlan,
    guest_config_digest: Sha256Digest,
    root_size_bytes: u64,
) -> Result<AtomicCatCreateRequest> {
    let cat_id = prefixed_id("cat_", &identities.cat)?;
    let cat_creation_id = prefixed_id("creation_", &identities.cat_creation)?;
    let disk_id = prefixed_id("disk_", &identities.disk)?;
    let volume_id = prefixed_id("vol_", &identities.volume)?;
    let config_id = prefixed_id("cfg_", &identities.config)?;
    let operation_id = prefixed_id("op_", &identities.operation)?;
    let endpoint_id = prefixed_id("ep_", &identities.endpoint)?;
    let hostname = Hostname::new(format!(
        "{}-{}.cats.run",
        ingress.request.name,
        identities.endpoint.as_str()
    ))
    .ok_or_else(|| ApiError::internal("candidate default hostname is invalid"))?;
    let durability = match ingress.request.durability {
        Durability::Strict => VolumeDurability::Strict,
        Durability::Relaxed => VolumeDurability::Relaxed,
    };
    let volume = VolumeRecord {
        volume_id: volume_id.clone(),
        size_bytes: root_size_bytes,
        durability,
        admin_state: VolumeAdminState::Active,
        head: RemoteHead {
            generation: Generation::new(0).expect("zero is a valid Generation"),
            root_hash: None,
            root_object_id: None,
        },
        lease_owner: None,
        lease_epoch: FenceEpoch::new(0).expect("zero is a valid FenceEpoch"),
        lease_expires_at: None,
        last_transition: None,
    };
    let network_config = plan.mutation.network_config;
    let runtime_config = ImmutableRuntimeConfig::new(
        config_id,
        ingress.request.boot_image_digest,
        ingress.request.vcpus,
        ingress.request.memory_bytes,
        guest_config_digest,
        network_config,
        vec![RuntimeVolumeConfig {
            volume_id: volume_id.clone(),
            disk_id: disk_id.clone(),
            disk_role: LifecycleDiskRole::Root,
            size_bytes: root_size_bytes,
            durability: ingress.request.durability,
            guest_device_serial: Id::new("cats-root").expect("static Root serial is valid"),
            guest_device_slot: 0,
            guest_binding: RuntimeVolumeGuestBinding::RootBoot,
        }],
    )
    .map_err(|_| ApiError::internal("constructed immutable runtime config is invalid"))?;
    let start_volume_authorities = vec![StartVolumeAuthority {
        volume_id: volume_id.clone(),
        disk_id: disk_id.clone(),
        authority: RuntimeVolumeAuthorityInput::NormalUnowned {
            expected_unowned_epoch: FenceEpoch::new(0).expect("zero is a valid FenceEpoch"),
            transition_id: identities.acquire_transition,
        },
    }];
    let workspace_id = ingress.idempotency.authenticated_workspace_id.clone();
    Ok(AtomicCatCreateRequest {
        idempotency: ingress.idempotency,
        candidate: AtomicCatCreateCandidate {
            cat_id: cat_id.clone(),
            cat_creation_id,
            workspace_id: workspace_id.clone(),
            name: ingress.request.name,
            root_disk: DiskRecordCandidate {
                disk_id: disk_id.clone(),
                workspace_id: workspace_id.clone(),
                name: disk_id,
                volume_id,
                size_bytes: root_size_bytes,
                durability,
                admin_state: DiskAdminState::Active,
                role: DiskRole::Root {
                    cat_id: cat_id.clone(),
                },
            },
            volume,
            runtime_config,
            start_volume_authorities,
            endpoint: EndpointRecordCandidate {
                endpoint_id: endpoint_id.clone(),
                workspace_id: workspace_id.clone(),
                cat_id: cat_id.clone(),
                name: Id::new("web").expect("static Endpoint name is valid"),
            },
            hostname,
            operation_id: operation_id.clone(),
            node_id: plan.target.node_identity.node_id,
            placement_epoch: Epoch::new(1).expect("one is a valid Epoch"),
        },
        accepted_response_body: encode_cat_create_accepted_response(&cat_id, &operation_id)?,
        name_conflict_response_body: encode_cat_name_conflict_response(),
    })
}

fn http_result(result: ApiIdempotencyResult) -> CatCreateHttpResult {
    CatCreateHttpResult {
        http_status: result.http_status,
        content_type: result.content_type.map(ExactContentType::as_str),
        response_body: result.response_body,
    }
}
