//! Independent signed Route Grant v2 rotation ingress and public successor
//! discovery. Neither endpoint accepts a bearer, cookie, A19, A23, Gateway,
//! Workspace, WorkOS, or administrator principal.

use std::error::Error as _;
use std::future::Future;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use sha2::Digest as _;

use cats_api::error::{ApiError, ErrorCode};
use cats_api::route_grant_v2::RouteGrantV2SignerSelection;
use cats_api::route_signing_operator::{
    decode_signed_route_v2_signing_command, encode_route_v2_signing_authority_current,
    encode_route_v2_signing_command_receipt, verify_signed_route_v2_signing_command,
    RouteGrantV2SigningAuthorityCommandResult, RouteV2LoadedSignerState,
    RouteV2RotationOperatorTrust, RouteV2SigningAuthorityCurrent, RouteV2SigningCommandReceipt,
    SignedRouteV2SigningCommand, VerifiedRouteV2RotationOperatorPrincipal,
    ROUTE_V2_RING_SUCCESSOR_METHOD, ROUTE_V2_RING_SUCCESSOR_PATH,
    ROUTE_V2_ROTATION_OPERATOR_JSON_CONTENT_TYPE, ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES,
    ROUTE_V2_SIGNING_COMMAND_METHOD, ROUTE_V2_SIGNING_COMMAND_PATH,
    ROUTE_V2_SIGNING_COMMAND_RESPONSE_MAX_WIRE_BYTES, ROUTE_V2_SIGNING_CURRENT_METHOD,
    ROUTE_V2_SIGNING_CURRENT_PATH,
};
use cats_api::runtime_reconciliation::{Epoch, Id, Sha256Digest};

use crate::server::AppState;
use crate::store::runtime_authority::route_signing_authority::{
    AuthenticatedRouteV2SigningCommandOutcome, RouteV2PublicRingDelivery,
};
use crate::store::AuthorityRequestContext;

const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const DISCOVERY_DEADLINE: Duration = Duration::from_secs(5);
const RESOLUTION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const GLOBAL_IN_FLIGHT: usize = 8;
const OPERATOR_IN_FLIGHT: usize = 2;

const INVALID_TARGET: &[u8] =
    br#"{"code":"invalid_request_target","message":"Route v2 rotation request target is invalid"}"#;
const METHOD_NOT_ALLOWED: &[u8] =
    br#"{"code":"method_not_allowed","message":"Route v2 rotation request method is invalid"}"#;
const UNSUPPORTED_MEDIA_TYPE: &[u8] = br#"{"code":"unsupported_media_type","message":"Route v2 rotation requires an unencoded application/json body"}"#;
const NOT_ACCEPTABLE: &[u8] =
    br#"{"code":"not_acceptable","message":"Route v2 rotation response is application/json"}"#;
const REQUEST_TOO_LARGE: &[u8] =
    br#"{"code":"request_too_large","message":"Route v2 rotation request is too large"}"#;
const INVALID_REQUEST: &[u8] =
    br#"{"code":"invalid_request","message":"Route v2 rotation request is invalid"}"#;
const AUTHENTICATION_FAILED: &[u8] = br#"{"code":"authentication_failed","message":"Route v2 rotation operator authentication failed"}"#;
const COMMAND_ID_CONFLICT: &[u8] = br#"{"code":"command_id_conflict","message":"Route v2 rotation command ID conflicts with another request"}"#;
const COMMAND_OUTSIDE_WINDOW: &[u8] = br#"{"code":"command_outside_execution_window","message":"Route v2 rotation command is outside its execution window"}"#;
const TEMPORARILY_UNAVAILABLE: &[u8] = br#"{"code":"temporarily_unavailable","message":"Route v2 rotation authority is temporarily unavailable"}"#;

struct ResolutionRegistry {
    state: Mutex<ResolutionState>,
    changed: tokio::sync::Notify,
}

struct ResolutionState {
    accepting: bool,
    active: usize,
}

impl Default for ResolutionRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(ResolutionState {
                accepting: true,
                active: 0,
            }),
            changed: tokio::sync::Notify::new(),
        }
    }
}

impl ResolutionRegistry {
    fn try_begin(self: &Arc<Self>) -> Option<ActiveResolution> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting {
            return None;
        }
        state.active += 1;
        Some(ActiveResolution(Arc::clone(self)))
    }

    fn begin_shutdown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.accepting = false;
        self.changed.notify_waiters();
    }

    fn active_count(&self) -> usize {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .active
    }

    fn finish(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        debug_assert!(state.active > 0, "only an active resolution can finish");
        state.active -= 1;
        if state.active == 0 {
            self.changed.notify_waiters();
        }
    }

    async fn wait_empty(&self) {
        loop {
            let changed = self.changed.notified();
            if self.active_count() == 0 {
                return;
            }
            changed.await;
        }
    }
}

struct ActiveResolution(Arc<ResolutionRegistry>);

impl Drop for ActiveResolution {
    fn drop(&mut self) {
        self.0.finish();
    }
}

struct ApplyPermits {
    _global: tokio::sync::OwnedSemaphorePermit,
    _operator: tokio::sync::OwnedSemaphorePermit,
}

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) struct RouteV2SigningOperatorService {
    store: Arc<crate::store::Store>,
    trust: RouteV2RotationOperatorTrust,
    expected_release_commit_sha: String,
    readiness: Arc<crate::server::ReadinessLatch>,
    loaded_signer_binding:
        Arc<crate::store::runtime_authority::route_signing_authority::RouteGrantV2SignerBinding>,
    global: Arc<tokio::sync::Semaphore>,
    operator: Arc<tokio::sync::Semaphore>,
    accepting: tokio::sync::watch::Sender<bool>,
    resolutions: Arc<ResolutionRegistry>,
}

impl RouteV2SigningOperatorService {
    pub(crate) fn new(
        store: Arc<crate::store::Store>,
        trust: RouteV2RotationOperatorTrust,
        expected_release_commit_sha: String,
        readiness: Arc<crate::server::ReadinessLatch>,
        loaded_signer_binding: Arc<
            crate::store::runtime_authority::route_signing_authority::RouteGrantV2SignerBinding,
        >,
    ) -> anyhow::Result<Self> {
        trust.validate()?;
        anyhow::ensure!(
            trust.release_commit_sha == expected_release_commit_sha,
            "Route v2 rotation operator trust targets another release"
        );
        let (accepting, _) = tokio::sync::watch::channel(true);
        Ok(Self {
            store,
            trust,
            expected_release_commit_sha,
            readiness,
            loaded_signer_binding,
            global: Arc::new(tokio::sync::Semaphore::new(GLOBAL_IN_FLIGHT)),
            operator: Arc::new(tokio::sync::Semaphore::new(OPERATOR_IN_FLIGHT)),
            accepting,
            resolutions: Arc::new(ResolutionRegistry::default()),
        })
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.accepting.subscribe()
    }

    fn authenticate(
        &self,
        signed: &SignedRouteV2SigningCommand,
    ) -> Result<VerifiedRouteV2RotationOperatorPrincipal, ()> {
        verify_signed_route_v2_signing_command(
            &self.trust,
            &self.expected_release_commit_sha,
            signed,
        )
        .map_err(|_| ())
    }

    pub(crate) fn begin_shutdown(&self) {
        self.resolutions.begin_shutdown();
        self.global.close();
        self.operator.close();
        self.accepting.send_replace(false);
    }

    pub(crate) async fn shutdown_commit_resolutions(&self) -> anyhow::Result<()> {
        self.begin_shutdown();
        tokio::time::timeout(RESOLUTION_SHUTDOWN_DEADLINE, self.resolutions.wait_empty())
            .await
            .map_err(|_| {
                anyhow::anyhow!(
                    "{} Route v2 rotation commit resolutions remain after shutdown deadline",
                    self.resolutions.active_count()
                )
            })
    }

    async fn apply(
        &self,
        principal: VerifiedRouteV2RotationOperatorPrincipal,
        signed: SignedRouteV2SigningCommand,
        exact_bytes: Vec<u8>,
        deadline: Instant,
        permits: ApplyPermits,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<AuthenticatedRouteV2SigningCommandOutcome, ApiError> {
        let request = AuthorityRequestContext::new(deadline);
        let _cancel_on_drop = CancelRequestOnDrop(request.clone());
        let active = self.resolutions.try_begin().ok_or_else(|| {
            ApiError::unavailable("Route v2 rotation operator service is shutting down")
        })?;
        let worker_request = request.clone();
        let worker_observer = request.clone();
        let store = Arc::clone(&self.store);
        let resolution_store = Arc::clone(&self.store);
        let resolution_signed = signed.clone();
        let resolution_bytes = exact_bytes.clone();
        let readiness = Arc::clone(&self.readiness);
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _permits = permits;
            let apply_signed = signed;
            let apply_bytes = exact_bytes;
            let apply_principal = principal;
            let request_for_store = worker_request.clone();
            let outcome = store
                .execute_authority_request_owned(&worker_request, move |store| {
                    store.apply_authenticated_route_v2_signing_command(
                        &apply_principal,
                        &apply_signed,
                        &apply_bytes,
                        &request_for_store,
                    )
                })
                .await;
            let outcome = match outcome {
                Ok(outcome) => Ok(outcome),
                Err(error) if worker_observer.commit_was_attempted() => {
                    resolve_ambiguous_command(
                        resolution_store,
                        resolution_signed,
                        resolution_bytes,
                        error,
                        readiness,
                    )
                    .await
                }
                Err(error) => Err(error),
            };
            let _ = result_tx.send(outcome);
            drop(active);
        });

        let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(timeout);
        tokio::select! {
            biased;
            () = &mut timeout => {
                request.cancel();
                Err(ApiError::unavailable("Route v2 rotation request exceeded its deadline"))
            }
            () = wait_for_shutdown(&mut shutdown) => {
                request.cancel();
                Err(ApiError::unavailable("Route v2 rotation operator service is shutting down"))
            }
            result = &mut result_rx => result.map_err(|_| {
                ApiError::internal("Route v2 rotation commit owner stopped without a result")
            })?,
        }
    }

    async fn load_successor(
        &self,
        deployment_id: Id,
        current_ring_version: Epoch,
        current_ring_digest: Sha256Digest,
        deadline: Instant,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Option<Vec<u8>>, ApiError> {
        let store = Arc::clone(&self.store);
        let lookup_deployment = deployment_id.clone();
        let lookup_digest = current_ring_digest.clone();
        let read = store.execute(move |store| {
            store.load_route_v2_public_ring_successor(
                &lookup_deployment,
                current_ring_version,
                &lookup_digest,
            )
        });
        let delivery = match await_before_deadline_or_shutdown(deadline, &mut shutdown, read).await
        {
            AwaitOutcome::Completed(result) => result?,
            AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
                return Err(ApiError::unavailable(
                    "Route v2 ring successor discovery is temporarily unavailable",
                ));
            }
        };
        delivery
            .map(|delivery| {
                validate_delivery(
                    &self.trust,
                    &self.expected_release_commit_sha,
                    &deployment_id,
                    current_ring_version,
                    &current_ring_digest,
                    delivery,
                )
            })
            .transpose()
    }

    async fn load_current(
        &self,
        deadline: Instant,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<Vec<u8>, ApiError> {
        let store = Arc::clone(&self.store);
        let binding = Arc::clone(&self.loaded_signer_binding);
        let read = store.execute(move |store| store.route_grant_v2_signer_is_current(&binding));
        let database_current =
            match await_before_deadline_or_shutdown(deadline, &mut shutdown, read).await {
                AwaitOutcome::Completed(result) => result?,
                AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
                    return Err(ApiError::unavailable(
                        "Route v2 current-binding discovery is temporarily unavailable",
                    ));
                }
            };
        let reference = self.loaded_signer_binding.reference();
        let (loaded_signer_state, loaded_active_kid) = match &reference.signer {
            RouteGrantV2SignerSelection::Active { active_kid, .. } => {
                (RouteV2LoadedSignerState::Active, Some(active_kid.clone()))
            }
            RouteGrantV2SignerSelection::Disabled => (RouteV2LoadedSignerState::Disabled, None),
        };
        encode_route_v2_signing_authority_current(&RouteV2SigningAuthorityCurrent {
            version: cats_api::runtime_reconciliation::ContractVersion::V1,
            authority_id: self.trust.authority_id.clone(),
            route_deployment_id: self.trust.route_deployment_id.clone(),
            release_commit_sha: self.expected_release_commit_sha.clone(),
            rotation_operator_trust_sha256: self
                .trust
                .exact_digest()
                .map_err(|_| ApiError::internal("Route v2 operator trust digest failed"))?,
            loaded_signer_revision: reference.signer_revision,
            loaded_signer_reference_sha256: self.loaded_signer_binding.reference_sha256().clone(),
            loaded_signer_state,
            loaded_active_kid,
            loaded_public_key_ring_version: reference.public_key_ring_version,
            loaded_public_key_ring_digest: reference.public_key_ring_digest.clone(),
            database_current,
            process_ready: self.readiness.is_ready(),
        })
        .map_err(|_| ApiError::internal("encode Route v2 current-binding discovery"))
    }
}

async fn resolve_ambiguous_command(
    store: Arc<crate::store::Store>,
    signed: SignedRouteV2SigningCommand,
    exact_bytes: Vec<u8>,
    original_error: ApiError,
    readiness: Arc<crate::server::ReadinessLatch>,
) -> Result<AuthenticatedRouteV2SigningCommandOutcome, ApiError> {
    loop {
        let lookup_signed = signed.clone();
        let lookup_bytes = exact_bytes.clone();
        match store
            .execute(move |store| {
                store.resolve_authenticated_route_v2_signing_command(&lookup_signed, &lookup_bytes)
            })
            .await
        {
            Ok(Some(outcome)) => return Ok(outcome),
            Ok(None) => return Err(original_error),
            Err(error) => {
                if !matches!(
                    error.code,
                    ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
                ) {
                    readiness.poison();
                }
                tracing::warn!(
                    error = %error,
                    command_id = signed.payload.command_id.as_str(),
                    "Route v2 rotation commit resolution lookup failed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

fn validate_delivery(
    trust: &RouteV2RotationOperatorTrust,
    expected_release_commit_sha: &str,
    deployment_id: &Id,
    current_ring_version: Epoch,
    current_ring_digest: &Sha256Digest,
    delivery: RouteV2PublicRingDelivery,
) -> Result<Vec<u8>, ApiError> {
    let signed = decode_signed_route_v2_signing_command(&delivery.exact_signed_envelope_bytes)
        .map_err(|_| ApiError::internal("stored Route v2 ring delivery is invalid"))?;
    verify_signed_route_v2_signing_command(trust, expected_release_commit_sha, &signed)
        .map_err(|_| ApiError::internal("stored Route v2 ring delivery proof is invalid"))?;
    let ring = signed
        .payload
        .command
        .kind
        .successor_ring()
        .ok_or_else(|| ApiError::internal("stored Route v2 delivery has no successor ring"))?;
    let previous = ring
        .expected_previous
        .as_ref()
        .ok_or_else(|| ApiError::internal("stored Route v2 delivery has no predecessor binding"))?;
    let exact_digest = Sha256Digest::from_bytes(
        sha2::Sha256::digest(&delivery.exact_signed_envelope_bytes).into(),
    );
    let ring_digest = ring
        .digest()
        .map_err(|_| ApiError::internal("stored Route v2 delivery ring is invalid"))?;
    if signed.payload.command.successor.deployment_id != *deployment_id
        || previous.ring_version != current_ring_version
        || previous.key_ring_digest != *current_ring_digest
        || ring.ring_version != delivery.ring_version
        || ring_digest != delivery.key_ring_digest
        || exact_digest != delivery.exact_signed_envelope_sha256
    {
        return Err(ApiError::internal(
            "stored Route v2 delivery projection diverged",
        ));
    }
    Ok(delivery.exact_signed_envelope_bytes)
}

pub(super) async fn apply(State(state): State<AppState>, request: Request<Body>) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let Some(service) = state.route_v2_signing_operator.clone() else {
        return temporarily_unavailable();
    };
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow() {
        return temporarily_unavailable();
    }
    if request.uri().path() != ROUTE_V2_SIGNING_COMMAND_PATH || request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, INVALID_TARGET, &[]);
    }
    if request.method().as_str() != ROUTE_V2_SIGNING_COMMAND_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            METHOD_NOT_ALLOWED,
            &[(
                header::ALLOW,
                HeaderValue::from_static(ROUTE_V2_SIGNING_COMMAND_METHOD),
            )],
        );
    }
    if has_forbidden_auth(request.headers()) {
        return authentication_failed();
    }
    if !has_exact_json_content_type(request.headers())
        || request.headers().contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    if !accepts_json(request.headers()) {
        return error_response(StatusCode::NOT_ACCEPTABLE, NOT_ACCEPTABLE, &[]);
    }
    let global = match Arc::clone(&service.global).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    if declared_body_exceeds(request.headers(), ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
    }
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(request.into_body(), ROUTE_V2_SIGNING_COMMAND_MAX_WIRE_BYTES),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) => body,
        AwaitOutcome::Completed(Err(error))
            if error
                .source()
                .is_some_and(|source| source.is::<http_body_util::LengthLimitError>()) =>
        {
            return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
        }
        AwaitOutcome::Completed(Err(_)) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let signed = match decode_signed_route_v2_signing_command(&body) {
        Ok(signed) => signed,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]),
    };
    let principal = match service.authenticate(&signed) {
        Ok(principal) => principal,
        Err(()) => return authentication_failed(),
    };
    let operator = match Arc::clone(&service.operator).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return too_many_requests(),
    };
    let command_id = signed.payload.command_id.clone();
    let outcome = service
        .apply(
            principal,
            signed,
            body.to_vec(),
            deadline,
            ApplyPermits {
                _global: global,
                _operator: operator,
            },
            shutdown,
        )
        .await;
    match outcome {
        Ok(AuthenticatedRouteV2SigningCommandOutcome::Stored(receipt)) => {
            let status = match receipt.result {
                RouteGrantV2SigningAuthorityCommandResult::Applied { .. } => StatusCode::OK,
                RouteGrantV2SigningAuthorityCommandResult::AuthorityPreconditionFailed => {
                    StatusCode::CONFLICT
                }
            };
            receipt_response(status, &receipt)
        }
        Ok(AuthenticatedRouteV2SigningCommandOutcome::CommandIdConflict) => {
            error_response(StatusCode::CONFLICT, COMMAND_ID_CONFLICT, &[])
        }
        Ok(AuthenticatedRouteV2SigningCommandOutcome::AuthenticationFailed) => {
            authentication_failed()
        }
        Ok(AuthenticatedRouteV2SigningCommandOutcome::CommandOutsideExecutionWindow) => {
            error_response(StatusCode::CONFLICT, COMMAND_OUTSIDE_WINDOW, &[])
        }
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            temporarily_unavailable()
        }
        Err(error) => {
            tracing::error!(error = %error, command_id = command_id.as_str(), "Route v2 rotation Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
    }
}

pub(super) async fn discover_successor(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + DISCOVERY_DEADLINE;
    let Some(service) = state.route_v2_signing_operator.clone() else {
        return temporarily_unavailable();
    };
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow() {
        return temporarily_unavailable();
    }
    if request.uri().path() != ROUTE_V2_RING_SUCCESSOR_PATH {
        return error_response(StatusCode::BAD_REQUEST, INVALID_TARGET, &[]);
    }
    if request.method().as_str() != ROUTE_V2_RING_SUCCESSOR_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            METHOD_NOT_ALLOWED,
            &[(
                header::ALLOW,
                HeaderValue::from_static(ROUTE_V2_RING_SUCCESSOR_METHOD),
            )],
        );
    }
    if has_forbidden_auth(request.headers()) {
        return authentication_failed();
    }
    if !accepts_json(request.headers()) {
        return error_response(StatusCode::NOT_ACCEPTABLE, NOT_ACCEPTABLE, &[]);
    }
    if request.headers().contains_key(header::CONTENT_TYPE)
        || request.headers().contains_key(header::CONTENT_ENCODING)
        || declared_body_exceeds(request.headers(), 0)
    {
        return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
    }
    let Some((deployment_id, ring_version, ring_digest)) = request
        .uri()
        .query()
        .and_then(parse_canonical_discovery_query)
    else {
        return error_response(StatusCode::BAD_REQUEST, INVALID_TARGET, &[]);
    };
    let global = match Arc::clone(&service.global).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(request.into_body(), 0),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) if body.is_empty() => {}
        AwaitOutcome::Completed(_) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let result = service
        .load_successor(deployment_id, ring_version, ring_digest, deadline, shutdown)
        .await;
    drop(global);
    match result {
        Ok(Some(bytes)) => json_response(StatusCode::OK, bytes),
        Ok(None) => no_content_response(),
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            temporarily_unavailable()
        }
        Err(error) => {
            tracing::error!(error = %error, "Route v2 ring delivery Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
    }
}

pub(super) async fn discover_current(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + DISCOVERY_DEADLINE;
    let Some(service) = state.route_v2_signing_operator.clone() else {
        return temporarily_unavailable();
    };
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow() {
        return temporarily_unavailable();
    }
    if request.uri().path() != ROUTE_V2_SIGNING_CURRENT_PATH || request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, INVALID_TARGET, &[]);
    }
    if request.method().as_str() != ROUTE_V2_SIGNING_CURRENT_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            METHOD_NOT_ALLOWED,
            &[(
                header::ALLOW,
                HeaderValue::from_static(ROUTE_V2_SIGNING_CURRENT_METHOD),
            )],
        );
    }
    if has_forbidden_auth(request.headers()) {
        return authentication_failed();
    }
    if !accepts_json(request.headers()) {
        return error_response(StatusCode::NOT_ACCEPTABLE, NOT_ACCEPTABLE, &[]);
    }
    if request.headers().contains_key(header::CONTENT_TYPE)
        || request.headers().contains_key(header::CONTENT_ENCODING)
        || declared_body_exceeds(request.headers(), 0)
    {
        return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
    }
    let global = match Arc::clone(&service.global).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(request.into_body(), 0),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) if body.is_empty() => {}
        AwaitOutcome::Completed(_) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let result = service.load_current(deadline, shutdown).await;
    drop(global);
    match result {
        Ok(bytes) => json_response(StatusCode::OK, bytes),
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            temporarily_unavailable()
        }
        Err(error) => {
            tracing::error!(error = %error, "Route v2 current-binding Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
    }
}

fn parse_canonical_discovery_query(query: &str) -> Option<(Id, Epoch, Sha256Digest)> {
    let mut fields = query.split('&');
    let deployment = fields.next()?.strip_prefix("deployment_id=")?;
    let version = fields.next()?.strip_prefix("current_ring_version=")?;
    let digest = fields.next()?.strip_prefix("current_key_ring_sha256=")?;
    if fields.next().is_some()
        || version.is_empty()
        || (version.len() > 1 && version.starts_with('0'))
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    Some((
        Id::new(deployment.to_owned())?,
        Epoch::new(version.parse().ok()?)?,
        Sha256Digest::new(format!("sha256:{digest}"))?,
    ))
}

enum AwaitOutcome<T> {
    Completed(T),
    Deadline,
    Shutdown,
}

async fn await_before_deadline_or_shutdown<T>(
    deadline: Instant,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
    future: impl Future<Output = T>,
) -> AwaitOutcome<T> {
    if Instant::now() >= deadline {
        return AwaitOutcome::Deadline;
    }
    let timeout = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
    tokio::pin!(timeout);
    tokio::pin!(future);
    tokio::select! {
        biased;
        () = &mut timeout => AwaitOutcome::Deadline,
        () = wait_for_shutdown(shutdown) => AwaitOutcome::Shutdown,
        result = &mut future => AwaitOutcome::Completed(result),
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

fn has_forbidden_auth(headers: &HeaderMap) -> bool {
    headers.contains_key(header::AUTHORIZATION)
        || headers.contains_key(header::COOKIE)
        || headers
            .keys()
            .any(|name| name.as_str().starts_with("x-cats-"))
}

fn has_exact_json_content_type(headers: &HeaderMap) -> bool {
    single_header(headers, header::CONTENT_TYPE).is_some_and(|value| {
        value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(ROUTE_V2_ROTATION_OPERATOR_JSON_CONTENT_TYPE)
    })
}

fn accepts_json(headers: &HeaderMap) -> bool {
    if !headers.contains_key(header::ACCEPT) {
        return true;
    }
    single_header(headers, header::ACCEPT).is_some_and(|value| {
        value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(ROUTE_V2_ROTATION_OPERATOR_JSON_CONTENT_TYPE)
    })
}

fn single_header(headers: &HeaderMap, name: header::HeaderName) -> Option<&str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn declared_body_exceeds(headers: &HeaderMap, cap: usize) -> bool {
    let mut values = headers.get_all(header::CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .is_none_or(|length| length > cap as u64)
}

fn receipt_response(status: StatusCode, receipt: &RouteV2SigningCommandReceipt) -> Response {
    match encode_route_v2_signing_command_receipt(receipt) {
        Ok(body) if body.len() <= ROUTE_V2_SIGNING_COMMAND_RESPONSE_MAX_WIRE_BYTES => {
            json_response(status, body)
        }
        _ => temporarily_unavailable(),
    }
}

fn authentication_failed() -> Response {
    error_response(StatusCode::UNAUTHORIZED, AUTHENTICATION_FAILED, &[])
}

fn too_many_requests() -> Response {
    error_response(
        StatusCode::TOO_MANY_REQUESTS,
        TEMPORARILY_UNAVAILABLE,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        TEMPORARILY_UNAVAILABLE,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn no_content_response() -> Response {
    let mut response = StatusCode::NO_CONTENT.into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(ROUTE_V2_ROTATION_OPERATOR_JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

fn error_response(
    status: StatusCode,
    body: &'static [u8],
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    let mut response = json_response(status, body.to_vec());
    for (name, value) in extra_headers {
        response.headers_mut().append(name, value.clone());
    }
    response
}
