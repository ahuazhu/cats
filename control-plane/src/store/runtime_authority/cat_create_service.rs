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

use cats_api::error::{ApiError, ErrorCode};
use cats_api::runtime_reconciliation::{
    encode_admission_inventory_attestation, encode_agent_session, encode_desired_runtime_spec,
    encode_node_identity, encode_node_observation, encode_node_placement_policy,
    guest_config_digest, spec_digest, AppliedDesiredEvidence, AsciiText, AssignedKind,
    AssignedPlacement, ContractVersion, DesiredRuntimeSpec, DiskKind, Durability, EndpointIntent,
    Epoch, FenceEpoch, Generation, GuestDeviceIdentity, GuestRuntimeProfileReceipt, Hostname,
    HttpProtocol, Id, NetworkConfig, NodeIdentityState, RandomId128, Revision, RuntimeConfig,
    RuntimeSchedulingState, RuntimeTarget, RuntimeTransition, Sha256Digest, VolumeAccess,
    VolumeAcquire, VolumeDisposition, VolumeIntent,
};
use cats_storage::authority::{RemoteHead, VolumeAdminState, VolumeDurability, VolumeRecord};
use serde::Deserialize;

use super::placement_planner::PlacementTargetSnapshot;
use super::product::{
    api_request_fingerprint, encode_cat_create_accepted_response,
    encode_cat_name_conflict_response, ApiIdempotencyRequest, ApiIdempotencyResult,
    CatCreateCandidate, CatCreateCommitCancellation, CatCreateEnvelopes, CoveredCatCreateError,
    CoveredCatCreateRequest, DiskAdminState, DiskRecordCandidate, DiskRole,
    EndpointRecordCandidate, ExactContentType, ExactHttpResponse, HostnameDesiredLookup,
    IfMatchFingerprint,
};
use super::runtime_spine::PLACEMENT_INVENTORY_MAX_AGE_MS;
use crate::store::{Result, Store};

pub(crate) const CAT_CREATE_MAX_BODY_BYTES: usize = 4096;
pub(crate) const CAT_CREATE_CANONICAL_ROUTE: &str = "POST /v1/workspaces/{workspace}/cats";
const CAT_CREATE_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const CHUNK_SIZE_BYTES: u64 = 4_194_304;
const MAX_VOLUME_BYTES: u64 = 1_099_511_627_776;
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

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CatCreateRequestBody {
    pub(crate) name: Id,
    pub(crate) boot_image_digest: Sha256Digest,
    pub(crate) vcpus: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) root_size_bytes: u64,
    pub(crate) durability: Durability,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedCatCreateIngress {
    request: CatCreateRequestBody,
    idempotency: ApiIdempotencyRequest,
    absolute_deadline: Instant,
}

impl AuthorizedCatCreateIngress {
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
    let name = request.name.as_str().as_bytes();
    if !(1..=30).contains(&name.len())
        || !name
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        || !name
            .first()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !name
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
    {
        return Err(ApiError::invalid(
            "Cat name must be 1..=30 lowercase ASCII letters, digits or interior hyphens",
        ));
    }
    if request.vcpus == 0 {
        return Err(ApiError::invalid("vcpus must be positive"));
    }
    if request.memory_bytes == 0 || request.memory_bytes > i64::MAX as u64 {
        return Err(ApiError::invalid(
            "memory_bytes must be in 1..=9223372036854775807",
        ));
    }
    if request.root_size_bytes == 0 || request.root_size_bytes > MAX_VOLUME_BYTES {
        return Err(ApiError::invalid(
            "root_size_bytes must be in 1..=1099511627776",
        ));
    }
    Ok(())
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
    pub(crate) desired_revision: Revision,
    pub(crate) placement_epoch: Epoch,
    pub(crate) vcpus: u32,
    pub(crate) memory_bytes: u64,
    pub(crate) network_config: NetworkConfig,
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

pub(crate) trait CatCreateIdentitySource: Send + Sync {
    fn random_id(&self) -> Result<RandomId128>;
}

#[derive(Debug, Default)]
pub(crate) struct UuidCatCreateIdentitySource;

impl CatCreateIdentitySource for UuidCatCreateIdentitySource {
    fn random_id(&self) -> Result<RandomId128> {
        // UUID v4 fixes non-zero version and variant bits, so the canonical
        // 128-bit random identity can never be the forbidden all-zero value.
        RandomId128::new(uuid::Uuid::new_v4().simple().to_string())
            .ok_or_else(|| ApiError::internal("UUID v4 did not form a RandomId128"))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CatCreateIdentities {
    cat: RandomId128,
    disk: RandomId128,
    volume: RandomId128,
    attachment: RandomId128,
    volume_intent: RandomId128,
    operation: RandomId128,
    endpoint: RandomId128,
    network: RandomId128,
    acquire_transition: RandomId128,
}

impl CatCreateIdentities {
    fn generate(source: &dyn CatCreateIdentitySource) -> Result<Self> {
        Ok(Self {
            cat: source.random_id()?,
            disk: source.random_id()?,
            volume: source.random_id()?,
            attachment: source.random_id()?,
            volume_intent: source.random_id()?,
            operation: source.random_id()?,
            endpoint: source.random_id()?,
            network: source.random_id()?,
            acquire_transition: source.random_id()?,
        })
    }
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

pub(crate) struct CatCreateService {
    store: Arc<Store>,
    manifests: Arc<dyn CatCreateManifestResolver>,
    planner: Arc<dyn CatCreatePlacementPlanner>,
    identities: Arc<dyn CatCreateIdentitySource>,
    guest_config_digest: Sha256Digest,
    commit_resolutions: Arc<CommitResolutionRegistry>,
    admission: tokio::sync::watch::Sender<bool>,
    #[cfg(test)]
    planner_calls: std::sync::atomic::AtomicUsize,
}

#[derive(Default)]
struct CommitResolutionRegistry {
    active: std::sync::atomic::AtomicUsize,
    changed: tokio::sync::Notify,
}

struct ActiveCommitResolution(Arc<CommitResolutionRegistry>);

impl CommitResolutionRegistry {
    fn begin(self: &Arc<Self>) -> ActiveCommitResolution {
        self.active
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        ActiveCommitResolution(Arc::clone(self))
    }

    async fn wait_empty(&self) {
        loop {
            let changed = self.changed.notified();
            if self.active.load(std::sync::atomic::Ordering::Acquire) == 0 {
                return;
            }
            changed.await;
        }
    }
}

impl Drop for ActiveCommitResolution {
    fn drop(&mut self) {
        self.0
            .active
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        self.0.changed.notify_waiters();
    }
}

impl CatCreateService {
    pub(crate) fn new(
        store: Arc<Store>,
        manifests: Arc<dyn CatCreateManifestResolver>,
        planner: Arc<dyn CatCreatePlacementPlanner>,
        identities: Arc<dyn CatCreateIdentitySource>,
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

    async fn create_before_deadline(
        &self,
        ingress: AuthorizedCatCreateIngress,
        absolute_deadline: Instant,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<CatCreateHttpResult, CatCreateServiceError> {
        let fast_request = ingress.idempotency.clone();
        if let Some(result) = await_cat_create_before_deadline(
            absolute_deadline,
            self.store
                .execute(move |store| store.cat_create_result_fast_lookup(&fast_request)),
        )
        .await
        .map_err(CatCreateServiceError::from_api)?
        {
            return Ok(http_result(result));
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
            CatCreateCommitCancellation::new(absolute_deadline);
        let commit_observer = commit_state.clone();
        let cancellation_observer = commit_state.clone();
        // Register an owner before the Store job starts. The request handler
        // owns only the receiver and the PRE_COMMIT cancellation token. If the
        // handler disappears after COMMIT_SENT, this task still consumes the
        // worker outcome and resolves any ambiguous commit while shutdown can
        // account for it.
        let store = Arc::clone(&self.store);
        let active = self.commit_resolutions.begin();
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store.execute(move |store| {
                Ok(store.create_cat_covered_with_placement(
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
                Ok(Err(CoveredCatCreateError::CandidateCollision(_))) => {
                    Ok(CatCreateCommitOutcome::CandidateIdentityCollision)
                }
                Ok(Err(CoveredCatCreateError::PlacementStale)) => {
                    Ok(CatCreateCommitOutcome::PlacementStale)
                }
                Ok(Err(CoveredCatCreateError::Store(error))) | Err(error)
                    if commit_observer.commit_was_sent() =>
                {
                    resolve_cat_create_commit_loop(store, resolution_request, error)
                        .await
                        .map(CatCreateCommitOutcome::Committed)
                }
                Ok(Err(CoveredCatCreateError::Store(error))) | Err(error) => Err(error),
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
                self.commit_resolutions
                    .active
                    .load(std::sync::atomic::Ordering::Acquire)
            ))
        })
    }

    #[cfg(test)]
    pub(crate) fn active_commit_resolutions(&self) -> usize {
        self.commit_resolutions
            .active
            .load(std::sync::atomic::Ordering::Acquire)
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
            .execute(move |store| store.cat_create_result_after_commit(&lookup))
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
    if rounded > MAX_VOLUME_BYTES {
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
    let admission = &plan.target.admission;
    encode_node_placement_policy(&plan.target.policy)
        .map_err(|_| ApiError::internal("placement planner returned an invalid policy"))?;
    encode_node_identity(&admission.node_identity)
        .map_err(|_| ApiError::internal("placement planner returned an invalid NodeIdentity"))?;
    encode_agent_session(&admission.agent_session)
        .map_err(|_| ApiError::internal("placement planner returned an invalid AgentSession"))?;
    encode_admission_inventory_attestation(&admission.inventory_attestation).map_err(|_| {
        ApiError::internal("placement planner returned an invalid admission inventory attestation")
    })?;
    encode_node_observation(&admission.full_inventory_observation).map_err(|_| {
        ApiError::internal("placement planner returned an invalid full inventory observation")
    })?;
    for desired in &admission.assigned_desired_specs {
        encode_desired_runtime_spec(desired).map_err(|_| {
            ApiError::internal("placement planner returned an invalid assigned Desired spec")
        })?;
    }
    let observation = &admission.full_inventory_observation;
    let attestation = &admission.inventory_attestation;
    if plan.mutation.cat_id != request.cat_id
        || plan.mutation.desired_revision != Revision::new(1).expect("one is a valid Revision")
        || plan.mutation.placement_epoch != Epoch::new(1).expect("one is a valid Epoch")
        || plan.mutation.vcpus != request.vcpus
        || plan.mutation.memory_bytes != request.memory_bytes
        || plan.mutation.network_config.network_id != request.network_id
        || admission.node_identity.state != NodeIdentityState::Provisioned
        || plan.target.policy.node_id != admission.node_identity.node_id
        || plan.target.policy.scheduling_state != RuntimeSchedulingState::Schedulable
        || plan.target.policy.capabilities.guest_config_digest != *active_guest_digest
        || plan.target.active_host_fence_event.is_some()
        || admission.node_identity.node_id != admission.agent_session.node_id
        || admission.node_identity.immutable_host_id != admission.agent_session.immutable_host_id
        || admission.agent_session.node_id != attestation.node_id
        || admission.agent_session.agent_session_epoch != attestation.agent_session_epoch
        || admission.agent_session.guest_config_digest != *active_guest_digest
        || admission.evaluated_at_unix_ms >= admission.agent_session.lease_deadline_unix_ms
        || !observation.complete_inventory
        || observation.node_id != admission.agent_session.node_id
        || observation.node_boot_id != admission.agent_session.node_boot_id
        || observation.agent_instance_id != admission.agent_session.agent_instance_id
        || observation.agent_session_epoch != admission.agent_session.agent_session_epoch
        || observation.inventory_epoch != attestation.inventory_epoch
        || observation.inventory_digest.as_ref() != Some(&attestation.inventory_digest)
        || observation.inventory_read_position != Some(attestation.inventory_read_position)
        || attestation.accepted_at_unix_ms > admission.evaluated_at_unix_ms
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
    if admission.evaluated_at_unix_ms.get() >= stale_at {
        return Err(ApiError::internal(
            "placement planner returned stale admission inventory",
        ));
    }
    for desired in &admission.assigned_desired_specs {
        if desired.placement.node_id != admission.node_identity.node_id {
            return Err(ApiError::internal(
                "placement planner assigned set contains another Node",
            ));
        }
        let expected = AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        };
        if !observation.runtimes.iter().any(|runtime| {
            runtime.cat_id == desired.cat_id && runtime.applied_desired.as_ref() == Some(&expected)
        }) {
            return Err(ApiError::internal(
                "placement planner full inventory omitted an assigned Cat binding",
            ));
        }
    }
    Ok(())
}

fn prefixed_id(prefix: &str, random: &RandomId128) -> Result<Id> {
    Id::new(format!("{prefix}{}", random.as_str()))
        .ok_or_else(|| ApiError::internal("candidate identity is invalid"))
}

fn build_covered_request(
    ingress: AuthorizedCatCreateIngress,
    identities: CatCreateIdentities,
    plan: CatCreatePlan,
    guest_config_digest: Sha256Digest,
    root_size_bytes: u64,
) -> Result<CoveredCatCreateRequest> {
    let cat_id = prefixed_id("cat_", &identities.cat)?;
    let disk_id = prefixed_id("disk_", &identities.disk)?;
    let volume_id = prefixed_id("vol_", &identities.volume)?;
    let attachment_id = prefixed_id("att_", &identities.attachment)?;
    let volume_intent_id = prefixed_id("vint_", &identities.volume_intent)?;
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
    let mut desired = DesiredRuntimeSpec {
        version: ContractVersion::V1,
        workspace_id: ingress.idempotency.authenticated_workspace_id.clone(),
        cat_id: cat_id.clone(),
        desired_revision: Revision::new(1).expect("one is a valid Revision"),
        target: RuntimeTarget::Running,
        placement: AssignedPlacement {
            kind: AssignedKind::Assigned,
            node_id: plan.target.admission.node_identity.node_id,
            placement_epoch: Epoch::new(1).expect("one is a valid Epoch"),
        },
        runtime: RuntimeConfig {
            vcpus: ingress.request.vcpus,
            memory_bytes: ingress.request.memory_bytes,
            boot_image_digest: ingress.request.boot_image_digest,
            guest_config_digest,
            network_config: plan.mutation.network_config,
        },
        volumes: vec![VolumeIntent {
            volume_intent_id,
            disk_id: disk_id.clone(),
            volume_id: volume_id.clone(),
            attachment_id,
            size_bytes: root_size_bytes,
            disk_kind: DiskKind::Root,
            access: VolumeAccess::ReadWriteOnce,
            durability: ingress.request.durability,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-root").expect("static Root serial is valid"),
                slot: 0,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: identities.acquire_transition,
                expected_unowned_epoch: FenceEpoch::new(0).expect("zero is a valid FenceEpoch"),
            },
            disposition: VolumeDisposition::Retain,
            mount: None,
        }],
        endpoints: vec![EndpointIntent {
            endpoint_id: endpoint_id.clone(),
            hostname: hostname.clone(),
            route_epoch: Epoch::new(1).expect("one is a valid Epoch"),
            protocol: HttpProtocol::Http,
            target_port: 8080,
        }],
        transition: RuntimeTransition::CancelAndDrain,
        spec_digest: Sha256Digest::from_bytes([0; 32]),
    };
    desired.spec_digest = spec_digest(&desired)
        .map_err(|_| ApiError::internal("constructed initial Desired is invalid"))?;

    let accepted = ExactHttpResponse::new(
        202,
        Some(ExactContentType::ApplicationJson),
        encode_cat_create_accepted_response(&cat_id, &operation_id)?,
    )?;
    let conflict = ExactHttpResponse::new(
        409,
        Some(ExactContentType::ApplicationJson),
        encode_cat_name_conflict_response(),
    )?;
    let envelopes =
        CatCreateEnvelopes::new(accepted, cat_id.clone(), operation_id.clone(), conflict)?;
    let workspace_id = ingress.idempotency.authenticated_workspace_id.clone();
    Ok(CoveredCatCreateRequest {
        idempotency: ingress.idempotency,
        candidate: CatCreateCandidate {
            cat_id: cat_id.clone(),
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
            desired,
            endpoint: EndpointRecordCandidate {
                endpoint_id: endpoint_id.clone(),
                workspace_id: workspace_id.clone(),
                cat_id: cat_id.clone(),
                name: Id::new("web").expect("static Endpoint name is valid"),
            },
            hostname_lookup: HostnameDesiredLookup {
                hostname,
                workspace_id,
                cat_id,
                endpoint_id,
                desired_revision: Revision::new(1).expect("one is a valid Revision"),
            },
            operation_id,
        },
        envelopes,
    })
}

fn http_result(result: ApiIdempotencyResult) -> CatCreateHttpResult {
    CatCreateHttpResult {
        http_status: result.http_status,
        content_type: result.content_type.map(ExactContentType::as_str),
        response_body: result.response_body,
    }
}
