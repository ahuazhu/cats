//! Exact A23 administrator ingress for provisioner-owned Node authority.

use std::collections::BTreeMap;
use std::error::Error as _;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};

use cats_api::agent_registration::{
    JSON_CONTENT_TYPE, NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER,
    NODE_SIGNATURE_HEADER,
};
use cats_api::error::{ApiError, ErrorCode};
use cats_api::production_mutation_admission::{
    decode_production_mutation_admission_command,
    encode_production_mutation_admission_command_receipt,
    encode_production_mutation_admission_state,
    encode_production_qualification_product_inventory_receipt,
    verify_production_mutation_admission_command,
    verify_production_mutation_admission_command_discovery, ProductionCutoverOperatorPrincipal,
    ProductionMutationAdmissionStoredOutcome, PRODUCTION_CUTOVER_CREDENTIAL_ID_HEADER,
    PRODUCTION_CUTOVER_SIGNATURE_HEADER, PRODUCTION_MUTATION_ADMISSION_COMMANDS_PATH,
    PRODUCTION_MUTATION_ADMISSION_DISCOVERY_PATH,
    PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
    PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES,
    PRODUCTION_MUTATION_ADMISSION_STATE_PATH, PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_PATH,
};
use cats_api::runtime_node_authority::{
    verify_runtime_node_authority_request, NODE_AUTHORITY_APPLY_ID_HEADER,
    PROVISIONER_CREDENTIAL_ID_HEADER, PROVISIONER_SIGNATURE_HEADER,
    RUNTIME_NODE_AUTHORITY_ERROR_MAX_WIRE_BYTES, RUNTIME_NODE_AUTHORITY_METHOD,
    RUNTIME_NODE_AUTHORITY_PATH, RUNTIME_NODE_AUTHORITY_REQUEST_MAX_WIRE_BYTES,
    RUNTIME_NODE_AUTHORITY_SUCCESS_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    decode_runtime_node_authority_apply, encode_runtime_node_authority_apply_result,
    FleetPolicyPrincipal, RuntimeNodeAuthorityApply, RuntimeNodeAuthorityStoredOutcome,
    RuntimeProvisionerTrustBundle,
};

use crate::server::AppState;
use crate::store::runtime_authority::placement_policy::RuntimeNodeAuthorityApplyStoreOutcome;
use crate::store::runtime_authority::production_mutation_admission::{
    ProductionMutationAdmissionCommandStoreOutcome,
    ProductionQualificationProductInventoryStoreOutcome,
};
use crate::store::AuthorityRequestContext;

const REQUEST_DEADLINE: Duration = Duration::from_secs(10);
const RESOLUTION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const GLOBAL_IN_FLIGHT: usize = 32;
const PRINCIPAL_IN_FLIGHT: usize = 4;

const INVALID_REQUEST_TARGET: &[u8] =
    br#"{"code":"invalid_request_target","message":"runtime node authority request target is invalid"}"#;
const METHOD_NOT_ALLOWED: &[u8] =
    br#"{"code":"method_not_allowed","message":"runtime node authority requires POST"}"#;
const UNSUPPORTED_MEDIA_TYPE: &[u8] = br#"{"code":"unsupported_media_type","message":"runtime node authority requires an unencoded application/json body"}"#;
const REQUEST_TOO_LARGE: &[u8] =
    br#"{"code":"request_too_large","message":"runtime node authority request is too large"}"#;
const INVALID_REQUEST: &[u8] =
    br#"{"code":"invalid_request","message":"runtime node authority request is invalid"}"#;
const AUTHENTICATION_FAILED: &[u8] =
    br#"{"code":"authentication_failed","message":"runtime node authority authentication failed"}"#;
const PERMISSION_DENIED: &[u8] =
    br#"{"code":"permission_denied","message":"runtime node authority permission denied"}"#;
const TEMPORARILY_UNAVAILABLE: &[u8] = br#"{"code":"temporarily_unavailable","message":"runtime node authority is temporarily unavailable"}"#;
const PRINCIPAL_REQUEST_IN_FLIGHT: &[u8] = br#"{"code":"principal_request_in_flight","message":"runtime node authority request already in flight for this principal"}"#;
const APPLY_ID_CONFLICT: &[u8] = br#"{"code":"apply_id_conflict","message":"runtime node authority apply ID conflicts with another request"}"#;
const AUTHORITY_PRECONDITION_FAILED: &[u8] = br#"{"code":"authority_precondition_failed","message":"runtime node authority precondition failed"}"#;
const PRODUCTION_COMMAND_ID_CONFLICT: &[u8] = br#"{"code":"command_id_conflict","message":"production mutation admission command ID conflicts with another request"}"#;
const PRODUCTION_COMMAND_NOT_FOUND: &[u8] =
    br#"{"code":"not_found","message":"production mutation admission command was not found"}"#;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum PrincipalAdmissionKey {
    DeploymentProvisioner(String, String),
    WorkosFleetAdministrator(String, String),
    ProductionCutoverOperator(String),
}

impl PrincipalAdmissionKey {
    fn from_principal(principal: &FleetPolicyPrincipal) -> Self {
        match principal {
            FleetPolicyPrincipal::DeploymentProvisioner {
                deployment_id,
                credential_id,
                ..
            } => Self::DeploymentProvisioner(
                deployment_id.as_str().to_owned(),
                credential_id.as_str().to_owned(),
            ),
            FleetPolicyPrincipal::WorkosFleetAdministrator {
                subject,
                organization_id,
            } => Self::WorkosFleetAdministrator(
                subject.as_str().to_owned(),
                organization_id.as_str().to_owned(),
            ),
        }
    }

    fn from_production_cutover(principal: &ProductionCutoverOperatorPrincipal) -> Self {
        Self::ProductionCutoverOperator(principal.credential_id.to_string())
    }
}

struct RuntimeNodeAuthorityAdmission {
    global: Arc<tokio::sync::Semaphore>,
    principals: Mutex<BTreeMap<PrincipalAdmissionKey, Weak<tokio::sync::Semaphore>>>,
}

impl RuntimeNodeAuthorityAdmission {
    fn new() -> Self {
        Self {
            global: Arc::new(tokio::sync::Semaphore::new(GLOBAL_IN_FLIGHT)),
            principals: Mutex::new(BTreeMap::new()),
        }
    }

    fn try_global(
        &self,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        self.global.clone().try_acquire_owned()
    }

    fn try_principal(
        &self,
        principal: &FleetPolicyPrincipal,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        let key = PrincipalAdmissionKey::from_principal(principal);
        self.try_key(key)
    }

    fn try_production_cutover(
        &self,
        principal: &ProductionCutoverOperatorPrincipal,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        let key = PrincipalAdmissionKey::from_production_cutover(principal);
        self.try_key(key)
    }

    fn try_key(
        &self,
        key: PrincipalAdmissionKey,
    ) -> Result<tokio::sync::OwnedSemaphorePermit, tokio::sync::TryAcquireError> {
        let semaphore = {
            let mut principals = self
                .principals
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            principals.retain(|_, semaphore| semaphore.strong_count() != 0);
            match principals.get(&key).and_then(Weak::upgrade) {
                Some(semaphore) => semaphore,
                None => {
                    let semaphore = Arc::new(tokio::sync::Semaphore::new(PRINCIPAL_IN_FLIGHT));
                    principals.insert(key, Arc::downgrade(&semaphore));
                    semaphore
                }
            }
        };
        semaphore.try_acquire_owned()
    }
}

struct CommitResolutionRegistry {
    state: Mutex<CommitResolutionState>,
    changed: tokio::sync::Notify,
}

struct CommitResolutionState {
    accepting: bool,
    active: usize,
}

impl Default for CommitResolutionRegistry {
    fn default() -> Self {
        Self {
            state: Mutex::new(CommitResolutionState {
                accepting: true,
                active: 0,
            }),
            changed: tokio::sync::Notify::new(),
        }
    }
}

impl CommitResolutionRegistry {
    fn try_begin(self: &Arc<Self>) -> Option<ActiveCommitResolution> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !state.accepting {
            return None;
        }
        state.active += 1;
        Some(ActiveCommitResolution(Arc::clone(self)))
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
        debug_assert!(state.active > 0, "only an active commit owner can finish");
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

struct ActiveCommitResolution(Arc<CommitResolutionRegistry>);

impl Drop for ActiveCommitResolution {
    fn drop(&mut self) {
        self.0.finish();
    }
}

struct ApplyPermits {
    _global: tokio::sync::OwnedSemaphorePermit,
    _principal: tokio::sync::OwnedSemaphorePermit,
}

struct CancelRequestOnDrop(AuthorityRequestContext);

impl Drop for CancelRequestOnDrop {
    fn drop(&mut self) {
        self.0.cancel();
    }
}

pub(crate) struct RuntimeNodeAuthorityService {
    store: Arc<crate::store::Store>,
    trust_bundle: RuntimeProvisionerTrustBundle,
    production_cutover_trust:
        cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle,
    readiness: Arc<crate::server::ReadinessLatch>,
    admission: RuntimeNodeAuthorityAdmission,
    accepting: tokio::sync::watch::Sender<bool>,
    resolutions: Arc<CommitResolutionRegistry>,
    #[cfg(test)]
    pause_before_registration: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    registration_pause_entered: std::sync::atomic::AtomicBool,
    #[cfg(test)]
    registration_pause_changed: tokio::sync::Notify,
}

impl RuntimeNodeAuthorityService {
    pub(crate) fn new(
        store: Arc<crate::store::Store>,
        trust_bundle: RuntimeProvisionerTrustBundle,
        production_cutover_trust:
            cats_api::production_mutation_admission::ProductionCutoverOperatorTrustBundle,
        readiness: Arc<crate::server::ReadinessLatch>,
    ) -> Self {
        let (accepting, _) = tokio::sync::watch::channel(true);
        Self {
            store,
            trust_bundle,
            production_cutover_trust,
            readiness,
            admission: RuntimeNodeAuthorityAdmission::new(),
            accepting,
            resolutions: Arc::new(CommitResolutionRegistry::default()),
            #[cfg(test)]
            pause_before_registration: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            registration_pause_entered: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            registration_pause_changed: tokio::sync::Notify::new(),
        }
    }

    fn subscribe(&self) -> tokio::sync::watch::Receiver<bool> {
        self.accepting.subscribe()
    }

    pub(crate) fn begin_shutdown(&self) {
        self.resolutions.begin_shutdown();
        self.accepting.send_replace(false);
    }

    pub(crate) async fn shutdown_commit_resolutions(&self) -> Result<(), ApiError> {
        self.begin_shutdown();
        tokio::time::timeout(RESOLUTION_SHUTDOWN_DEADLINE, self.resolutions.wait_empty())
            .await
            .map_err(|_| {
                ApiError::unavailable(format!(
                    "{} runtime Node authority commit resolutions remain after shutdown deadline",
                    self.resolutions.active_count()
                ))
            })
    }

    #[cfg(test)]
    #[allow(dead_code, reason = "used by focused shutdown fault-injection tests")]
    pub(crate) fn active_commit_resolutions(&self) -> usize {
        self.resolutions.active_count()
    }

    #[cfg(test)]
    fn arm_pause_before_registration_for_test(&self) {
        self.registration_pause_entered
            .store(false, std::sync::atomic::Ordering::Release);
        self.pause_before_registration
            .store(true, std::sync::atomic::Ordering::Release);
    }

    #[cfg(test)]
    async fn pause_before_registration_for_test(&self) {
        if !self
            .pause_before_registration
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return;
        }
        self.registration_pause_entered
            .store(true, std::sync::atomic::Ordering::Release);
        self.registration_pause_changed.notify_waiters();
        loop {
            let changed = self.registration_pause_changed.notified();
            if !self
                .pause_before_registration
                .load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    async fn wait_for_registration_pause_for_test(&self) {
        loop {
            let changed = self.registration_pause_changed.notified();
            if self
                .registration_pause_entered
                .load(std::sync::atomic::Ordering::Acquire)
            {
                break;
            }
            changed.await;
        }
    }

    #[cfg(test)]
    fn release_registration_pause_for_test(&self) {
        self.pause_before_registration
            .store(false, std::sync::atomic::Ordering::Release);
        self.registration_pause_changed.notify_waiters();
    }

    async fn apply(
        &self,
        principal: FleetPolicyPrincipal,
        apply: RuntimeNodeAuthorityApply,
        deadline: Instant,
        permits: Arc<ApplyPermits>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<RuntimeNodeAuthorityApplyStoreOutcome, ApiError> {
        let request = AuthorityRequestContext::new(deadline);
        let _cancel_on_drop = CancelRequestOnDrop(request.clone());
        if Instant::now() >= deadline {
            return Err(ApiError::unavailable(
                "runtime Node authority request exceeded its deadline",
            ));
        }
        #[cfg(test)]
        self.pause_before_registration_for_test().await;
        let active = self.resolutions.try_begin().ok_or_else(|| {
            ApiError::unavailable("runtime Node authority service is shutting down")
        })?;
        let worker_request = request.clone();
        let worker_observer = request.clone();
        let store = Arc::clone(&self.store);
        let resolution_store = Arc::clone(&self.store);
        let resolution_apply = apply.clone();
        let readiness = Arc::clone(&self.readiness);
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _permits = permits;
            let apply_for_worker = apply;
            let principal_for_worker = principal;
            let outcome = store
                .execute(move |store| {
                    store.apply_runtime_node_authority_request(
                        &principal_for_worker,
                        &apply_for_worker,
                        &worker_request,
                    )
                })
                .await;
            let outcome = match outcome {
                Ok(outcome) => Ok(outcome),
                Err(error) if worker_observer.commit_was_attempted() => {
                    resolve_ambiguous_apply(resolution_store, resolution_apply, error, readiness)
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
                Err(ApiError::unavailable(
                    "runtime Node authority request exceeded its deadline",
                ))
            }
            () = wait_for_shutdown(&mut shutdown) => {
                request.cancel();
                Err(ApiError::unavailable(
                    "runtime Node authority service is shutting down",
                ))
            }
            result = &mut result_rx => {
                if Instant::now() >= deadline {
                    request.cancel();
                    Err(ApiError::unavailable(
                        "runtime Node authority request exceeded its deadline",
                    ))
                } else {
                    result.map_err(|_| {
                        ApiError::internal("runtime Node authority commit owner stopped without a result")
                    })?
                }
            },
        }
    }

    async fn apply_production_mutation_admission(
        &self,
        principal: ProductionCutoverOperatorPrincipal,
        command: cats_api::production_mutation_admission::ProductionMutationAdmissionCommand,
        deadline: Instant,
        permits: Arc<ApplyPermits>,
        mut shutdown: tokio::sync::watch::Receiver<bool>,
    ) -> Result<ProductionMutationAdmissionCommandStoreOutcome, ApiError> {
        let request = AuthorityRequestContext::new(deadline);
        let _cancel_on_drop = CancelRequestOnDrop(request.clone());
        if Instant::now() >= deadline {
            return Err(ApiError::unavailable(
                "production mutation admission request exceeded its deadline",
            ));
        }
        let active = self.resolutions.try_begin().ok_or_else(|| {
            ApiError::unavailable("production mutation admission service is shutting down")
        })?;
        let worker_request = request.clone();
        let worker_observer = request.clone();
        let store = Arc::clone(&self.store);
        let resolution_store = Arc::clone(&self.store);
        let resolution_command = command.clone();
        let readiness = Arc::clone(&self.readiness);
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let _permits = permits;
            let worker_command = command;
            let worker_principal = principal;
            let outcome = store
                .execute(move |store| {
                    store.apply_production_mutation_admission_command_request(
                        &worker_principal,
                        &worker_command,
                        &worker_request,
                    )
                })
                .await;
            let outcome = match outcome {
                Ok(outcome) => Ok(outcome),
                Err(error) if worker_observer.commit_was_attempted() => {
                    resolve_ambiguous_production_mutation_admission(
                        resolution_store,
                        resolution_command,
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
                Err(ApiError::unavailable(
                    "production mutation admission request exceeded its deadline",
                ))
            }
            () = wait_for_shutdown(&mut shutdown) => {
                request.cancel();
                Err(ApiError::unavailable(
                    "production mutation admission service is shutting down",
                ))
            }
            result = &mut result_rx => {
                if Instant::now() >= deadline {
                    request.cancel();
                    Err(ApiError::unavailable(
                        "production mutation admission request exceeded its deadline",
                    ))
                } else {
                    result.map_err(|_| ApiError::internal(
                        "production mutation admission commit owner stopped without a result"
                    ))?
                }
            },
        }
    }
}

async fn resolve_ambiguous_production_mutation_admission(
    store: Arc<crate::store::Store>,
    command: cats_api::production_mutation_admission::ProductionMutationAdmissionCommand,
    original_error: ApiError,
    readiness: Arc<crate::server::ReadinessLatch>,
) -> Result<ProductionMutationAdmissionCommandStoreOutcome, ApiError> {
    loop {
        let lookup = command.clone();
        match store
            .execute(move |store| store.resolve_production_mutation_admission_command(&lookup))
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
                    command_id = command.command_id.as_str(),
                    "production mutation admission commit resolution lookup failed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

async fn resolve_ambiguous_apply(
    store: Arc<crate::store::Store>,
    apply: RuntimeNodeAuthorityApply,
    original_error: ApiError,
    readiness: Arc<crate::server::ReadinessLatch>,
) -> Result<RuntimeNodeAuthorityApplyStoreOutcome, ApiError> {
    loop {
        let lookup_apply = apply.clone();
        match store
            .execute(move |store| store.resolve_runtime_node_authority_apply(&lookup_apply))
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
                    apply_id = apply.apply_id.as_str(),
                    "runtime Node authority commit resolution lookup failed"
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
}

pub(super) async fn apply_runtime_node_authority(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let service = Arc::clone(&state.runtime_node_authority);
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow() {
        return temporarily_unavailable();
    }
    if request.uri().path() != RUNTIME_NODE_AUTHORITY_PATH {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method().as_str() != RUNTIME_NODE_AUTHORITY_METHOD {
        return error_response(
            StatusCode::METHOD_NOT_ALLOWED,
            METHOD_NOT_ALLOWED,
            &[(
                header::ALLOW,
                HeaderValue::from_static(RUNTIME_NODE_AUTHORITY_METHOD),
            )],
        );
    }
    if request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST_TARGET, &[]);
    }
    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) || headers.contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    let auth = match classify_auth_envelope(&headers) {
        Some(auth) => auth,
        None => return authentication_failed(),
    };
    let global = match service.admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    if declared_body_exceeds_limit(&headers) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
    }
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(
            request.into_body(),
            RUNTIME_NODE_AUTHORITY_REQUEST_MAX_WIRE_BYTES,
        ),
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

    let principal = match authenticate(&state, &service, auth, &body, deadline, &mut shutdown).await
    {
        Ok(principal) => principal,
        Err(response) => return response,
    };
    let principal_permit = match service.admission.try_principal(&principal) {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                PRINCIPAL_REQUEST_IN_FLIGHT,
                &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
            );
        }
    };
    let apply = match decode_runtime_node_authority_apply(&body) {
        Ok(apply) => apply,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]),
    };
    let permits = Arc::new(ApplyPermits {
        _global: global,
        _principal: principal_permit,
    });
    let response_permits = Arc::clone(&permits);
    let outcome = service
        .apply(principal, apply.clone(), deadline, permits, shutdown)
        .await;
    let response = match outcome {
        Ok(RuntimeNodeAuthorityApplyStoreOutcome::Stored(
            RuntimeNodeAuthorityStoredOutcome::Applied { response },
        )) => match encode_runtime_node_authority_apply_result(&response) {
            Ok(body) if body.len() <= RUNTIME_NODE_AUTHORITY_SUCCESS_MAX_WIRE_BYTES => {
                success_response(body)
            }
            _ => {
                state.readiness.poison();
                temporarily_unavailable()
            }
        },
        Ok(RuntimeNodeAuthorityApplyStoreOutcome::Stored(
            RuntimeNodeAuthorityStoredOutcome::AuthorityPreconditionFailed,
        )) => error_response(
            StatusCode::CONFLICT,
            AUTHORITY_PRECONDITION_FAILED,
            &[(
                header::HeaderName::from_static(NODE_AUTHORITY_APPLY_ID_HEADER),
                HeaderValue::from_str(apply.apply_id.as_str())
                    .expect("RandomId128 is an HTTP header value"),
            )],
        ),
        Ok(RuntimeNodeAuthorityApplyStoreOutcome::ApplyIdConflict) => {
            error_response(StatusCode::CONFLICT, APPLY_ID_CONFLICT, &[])
        }
        Ok(RuntimeNodeAuthorityApplyStoreOutcome::AuthenticationFailed) => authentication_failed(),
        Err(error)
            if matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            temporarily_unavailable()
        }
        Err(error) => {
            tracing::error!(error = %error, "runtime Node authority Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
    };
    drop(response_permits);
    response
}

pub(super) async fn apply_production_mutation_admission(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let service = Arc::clone(&state.runtime_node_authority);
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow() {
        return temporarily_unavailable();
    }
    if request.uri().path() != PRODUCTION_MUTATION_ADMISSION_COMMANDS_PATH {
        return StatusCode::NOT_FOUND.into_response();
    }
    if request.method() != axum::http::Method::POST || request.uri().query().is_some() {
        return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST_TARGET, &[]);
    }
    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) || headers.contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    let (credential_id, signature) = match classify_production_cutover_signature(&headers) {
        Some(proof) => proof,
        None => return authentication_failed(),
    };
    let global = match service.admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    if declared_body_exceeds(
        &headers,
        PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
    ) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
    }
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(
            request.into_body(),
            PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
        ),
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
    let principal = match verify_production_mutation_admission_command(
        &service.production_cutover_trust,
        &credential_id,
        &signature,
        &body,
        system_now_unix_ms(),
    ) {
        Ok(principal) => principal,
        Err(_) => return authentication_failed(),
    };
    let principal_permit = match service.admission.try_production_cutover(&principal) {
        Ok(permit) => permit,
        Err(_) => {
            return error_response(
                StatusCode::TOO_MANY_REQUESTS,
                PRINCIPAL_REQUEST_IN_FLIGHT,
                &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
            );
        }
    };
    let command = match decode_production_mutation_admission_command(&body) {
        Ok(command) => command,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]),
    };
    let permits = Arc::new(ApplyPermits {
        _global: global,
        _principal: principal_permit,
    });
    let response_permits = Arc::clone(&permits);
    let outcome = service
        .apply_production_mutation_admission(principal, command, deadline, permits, shutdown)
        .await;
    let response = match outcome {
        Ok(ProductionMutationAdmissionCommandStoreOutcome::Stored(receipt)) => {
            let status = match &receipt.outcome {
                ProductionMutationAdmissionStoredOutcome::Applied { .. } => StatusCode::OK,
                ProductionMutationAdmissionStoredOutcome::AuthorityPreconditionFailed => {
                    StatusCode::CONFLICT
                }
            };
            match encode_production_mutation_admission_command_receipt(&receipt) {
                Ok(body) if body.len() <= PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES => {
                    json_response(status, body)
                }
                _ => {
                    state.readiness.poison();
                    temporarily_unavailable()
                }
            }
        }
        Ok(ProductionMutationAdmissionCommandStoreOutcome::CommandIdConflict) => {
            error_response(StatusCode::CONFLICT, PRODUCTION_COMMAND_ID_CONFLICT, &[])
        }
        Ok(ProductionMutationAdmissionCommandStoreOutcome::AuthenticationFailed) => {
            authentication_failed()
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
            tracing::error!(error = %error, "production mutation admission Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
    };
    drop(response_permits);
    response
}

pub(super) async fn discover_production_mutation_admission_command(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let service = Arc::clone(&state.runtime_node_authority);
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow()
        || request.uri().path() != PRODUCTION_MUTATION_ADMISSION_DISCOVERY_PATH
        || request.method() != axum::http::Method::POST
        || request.uri().query().is_some()
    {
        return temporarily_unavailable();
    }
    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) || headers.contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    let (credential_id, signature) = match classify_production_cutover_signature(&headers) {
        Some(proof) => proof,
        None => return authentication_failed(),
    };
    if declared_body_exceeds(
        &headers,
        PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
    ) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
    }
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(
            request.into_body(),
            PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
        ),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) => body,
        AwaitOutcome::Completed(Err(_)) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let principal = match verify_production_mutation_admission_command_discovery(
        &service.production_cutover_trust,
        &credential_id,
        &signature,
        &body,
    ) {
        Ok(principal) => principal,
        Err(_) => return authentication_failed(),
    };
    let command = match decode_production_mutation_admission_command(&body) {
        Ok(command) => command,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]),
    };
    let _principal_permit = match service.admission.try_production_cutover(&principal) {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    let store = Arc::clone(&service.store);
    let outcome = await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        store.execute(move |store| store.resolve_production_mutation_admission_command(&command)),
    )
    .await;
    match outcome {
        AwaitOutcome::Completed(Ok(Some(
            ProductionMutationAdmissionCommandStoreOutcome::Stored(receipt),
        ))) => match encode_production_mutation_admission_command_receipt(&receipt) {
            Ok(body) if body.len() <= PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES => {
                json_response(StatusCode::OK, body)
            }
            _ => {
                state.readiness.poison();
                temporarily_unavailable()
            }
        },
        AwaitOutcome::Completed(Ok(Some(
            ProductionMutationAdmissionCommandStoreOutcome::CommandIdConflict,
        ))) => error_response(StatusCode::CONFLICT, PRODUCTION_COMMAND_ID_CONFLICT, &[]),
        AwaitOutcome::Completed(Ok(Some(
            ProductionMutationAdmissionCommandStoreOutcome::AuthenticationFailed,
        ))) => authentication_failed(),
        AwaitOutcome::Completed(Ok(None)) => {
            error_response(StatusCode::NOT_FOUND, PRODUCTION_COMMAND_NOT_FOUND, &[])
        }
        AwaitOutcome::Completed(Err(error))
            if !matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            state.readiness.poison();
            temporarily_unavailable()
        }
        AwaitOutcome::Completed(Err(_)) | AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
            temporarily_unavailable()
        }
    }
}

pub(super) async fn get_production_mutation_admission_state(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let service = Arc::clone(&state.runtime_node_authority);
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow()
        || request.uri().path() != PRODUCTION_MUTATION_ADMISSION_STATE_PATH
        || request.method() != axum::http::Method::POST
        || request.uri().query().is_some()
    {
        return temporarily_unavailable();
    }
    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) || headers.contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    let (credential_id, signature) = match classify_production_cutover_signature(&headers) {
        Some(proof) => proof,
        None => return authentication_failed(),
    };
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(
            request.into_body(),
            PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
        ),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) => body,
        AwaitOutcome::Completed(Err(_)) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let principal = match verify_production_mutation_admission_command_discovery(
        &service.production_cutover_trust,
        &credential_id,
        &signature,
        &body,
    ) {
        Ok(principal) => principal,
        Err(_) => return authentication_failed(),
    };
    let _principal_permit = match service.admission.try_production_cutover(&principal) {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    let store = Arc::clone(&service.store);
    match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        store.execute(|store| store.production_mutation_admission_state()),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(admission)) => {
            match encode_production_mutation_admission_state(&admission) {
                Ok(body) if body.len() <= PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES => {
                    json_response(StatusCode::OK, body)
                }
                _ => {
                    state.readiness.poison();
                    temporarily_unavailable()
                }
            }
        }
        AwaitOutcome::Completed(Err(error))
            if !matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            state.readiness.poison();
            temporarily_unavailable()
        }
        AwaitOutcome::Completed(Err(_)) | AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
            temporarily_unavailable()
        }
    }
}

pub(super) async fn discover_production_qualification_product_inventory(
    State(state): State<AppState>,
    request: Request<Body>,
) -> Response {
    let deadline = Instant::now() + REQUEST_DEADLINE;
    let service = Arc::clone(&state.runtime_node_authority);
    let mut shutdown = service.subscribe();
    if !*shutdown.borrow()
        || request.uri().path() != PRODUCTION_QUALIFICATION_PRODUCT_INVENTORY_PATH
        || request.method() != axum::http::Method::POST
        || request.uri().query().is_some()
    {
        return temporarily_unavailable();
    }
    let headers = request.headers().clone();
    if single_header_text(&headers, header::CONTENT_TYPE.as_str()).is_none_or(|value| {
        !value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(JSON_CONTENT_TYPE)
    }) || headers.contains_key(header::CONTENT_ENCODING)
    {
        return error_response(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            UNSUPPORTED_MEDIA_TYPE,
            &[],
        );
    }
    let (credential_id, signature) = match classify_production_cutover_signature(&headers) {
        Some(proof) => proof,
        None => return authentication_failed(),
    };
    if declared_body_exceeds(
        &headers,
        PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
    ) {
        return error_response(StatusCode::PAYLOAD_TOO_LARGE, REQUEST_TOO_LARGE, &[]);
    }
    let body = match await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        to_bytes(
            request.into_body(),
            PRODUCTION_MUTATION_ADMISSION_REQUEST_MAX_WIRE_BYTES,
        ),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(body)) => body,
        AwaitOutcome::Completed(Err(_)) => {
            return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]);
        }
        AwaitOutcome::Deadline | AwaitOutcome::Shutdown => return temporarily_unavailable(),
    };
    let principal = match verify_production_mutation_admission_command_discovery(
        &service.production_cutover_trust,
        &credential_id,
        &signature,
        &body,
    ) {
        Ok(principal) => principal,
        Err(_) => return authentication_failed(),
    };
    let command = match decode_production_mutation_admission_command(&body) {
        Ok(command) => command,
        Err(_) => return error_response(StatusCode::BAD_REQUEST, INVALID_REQUEST, &[]),
    };
    let _global = match service.admission.try_global() {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    let _principal = match service.admission.try_production_cutover(&principal) {
        Ok(permit) => permit,
        Err(_) => return temporarily_unavailable(),
    };
    let request_context = AuthorityRequestContext::new(deadline);
    let _cancel_on_drop = CancelRequestOnDrop(request_context.clone());
    let store = Arc::clone(&service.store);
    let outcome = await_before_deadline_or_shutdown(
        deadline,
        &mut shutdown,
        store.execute(move |store| {
            store.production_qualification_product_inventory(&principal, &command, &request_context)
        }),
    )
    .await;
    match outcome {
        AwaitOutcome::Completed(Ok(
            ProductionQualificationProductInventoryStoreOutcome::Found(receipt),
        )) => match encode_production_qualification_product_inventory_receipt(&receipt) {
            Ok(body) if body.len() <= PRODUCTION_MUTATION_ADMISSION_RESPONSE_MAX_WIRE_BYTES => {
                json_response(StatusCode::OK, body)
            }
            _ => {
                state.readiness.poison();
                temporarily_unavailable()
            }
        },
        AwaitOutcome::Completed(Ok(
            ProductionQualificationProductInventoryStoreOutcome::CommandIdConflict,
        )) => error_response(StatusCode::CONFLICT, PRODUCTION_COMMAND_ID_CONFLICT, &[]),
        AwaitOutcome::Completed(Ok(
            ProductionQualificationProductInventoryStoreOutcome::AuthenticationFailed,
        )) => authentication_failed(),
        AwaitOutcome::Completed(Ok(
            ProductionQualificationProductInventoryStoreOutcome::NotFound,
        )) => error_response(StatusCode::NOT_FOUND, PRODUCTION_COMMAND_NOT_FOUND, &[]),
        AwaitOutcome::Completed(Err(error))
            if !matches!(
                error.code,
                ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
            ) =>
        {
            tracing::error!(error = %error, "qualification product inventory Store failed closed");
            state.readiness.poison();
            temporarily_unavailable()
        }
        AwaitOutcome::Completed(Err(_)) | AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
            temporarily_unavailable()
        }
    }
}

enum AuthEnvelope {
    Machine {
        credential_id: String,
        signature: String,
    },
    WorkosCookie {
        sealed: String,
    },
    WorkosJwt {
        token: String,
    },
}

fn classify_auth_envelope(headers: &HeaderMap) -> Option<AuthEnvelope> {
    let has_node_header = [
        NODE_CREDENTIAL_ID_HEADER,
        NODE_PUBLIC_KEY_SPKI_HEADER,
        NODE_SIGNATURE_HEADER,
    ]
    .into_iter()
    .any(|name| headers.contains_key(name));
    if has_node_header {
        return None;
    }
    let provisioner_id = single_header_text(headers, PROVISIONER_CREDENTIAL_ID_HEADER);
    let provisioner_signature = single_header_text(headers, PROVISIONER_SIGNATURE_HEADER);
    let authorization = single_header_text(headers, header::AUTHORIZATION.as_str());
    let cookie_values = headers.get_all(header::COOKIE).iter().collect::<Vec<_>>();
    let has_any_provisioner = headers.contains_key(PROVISIONER_CREDENTIAL_ID_HEADER)
        || headers.contains_key(PROVISIONER_SIGNATURE_HEADER);
    if provisioner_id.is_some()
        && provisioner_signature.is_some()
        && authorization.is_none()
        && !headers.contains_key(header::AUTHORIZATION)
        && cookie_values.is_empty()
    {
        return Some(AuthEnvelope::Machine {
            credential_id: provisioner_id?.to_owned(),
            signature: provisioner_signature?.to_owned(),
        });
    }
    if has_any_provisioner {
        return None;
    }
    if let Some(authorization) = authorization {
        if cookie_values.is_empty() {
            let token = authorization.strip_prefix("Bearer ")?;
            if !token.is_empty() && !token.bytes().any(|byte| byte.is_ascii_whitespace()) {
                return Some(AuthEnvelope::WorkosJwt {
                    token: token.to_owned(),
                });
            }
        }
        return None;
    }
    if headers.contains_key(header::AUTHORIZATION) || cookie_values.len() != 1 {
        return None;
    }
    let cookie = cookie_values[0].to_str().ok()?;
    let mut admin = Vec::new();
    let mut user_count = 0_usize;
    for part in cookie.split(';') {
        let (name, value) = part.trim().split_once('=')?;
        if name == crate::auth::ADMIN_SESSION_COOKIE {
            admin.push(value.to_owned());
        } else if name == crate::auth::USER_SESSION_COOKIE {
            user_count += 1;
        }
    }
    if admin.len() == 1 && user_count == 0 {
        Some(AuthEnvelope::WorkosCookie {
            sealed: admin.pop().expect("length was checked"),
        })
    } else {
        None
    }
}

fn classify_production_cutover_signature(headers: &HeaderMap) -> Option<(String, String)> {
    let forbidden = [
        NODE_CREDENTIAL_ID_HEADER,
        NODE_PUBLIC_KEY_SPKI_HEADER,
        NODE_SIGNATURE_HEADER,
        PROVISIONER_CREDENTIAL_ID_HEADER,
        PROVISIONER_SIGNATURE_HEADER,
        header::AUTHORIZATION.as_str(),
        header::COOKIE.as_str(),
    ];
    if forbidden.into_iter().any(|name| headers.contains_key(name)) {
        return None;
    }
    let credential_id = single_header_text(headers, PRODUCTION_CUTOVER_CREDENTIAL_ID_HEADER)?;
    let signature = single_header_text(headers, PRODUCTION_CUTOVER_SIGNATURE_HEADER)?;
    Some((credential_id.to_owned(), signature.to_owned()))
}

fn system_now_unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| u64::try_from(duration.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

async fn authenticate(
    state: &AppState,
    service: &RuntimeNodeAuthorityService,
    auth: AuthEnvelope,
    exact_body: &[u8],
    deadline: Instant,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<FleetPolicyPrincipal, Response> {
    match auth {
        AuthEnvelope::Machine {
            credential_id,
            signature,
        } => {
            let Some(credential) = service
                .trust_bundle
                .credentials
                .iter()
                .find(|candidate| candidate.credential_id.as_str() == credential_id)
            else {
                return Err(authentication_failed());
            };
            let principal = verify_runtime_node_authority_request(
                &service.trust_bundle.deployment_id,
                credential,
                exact_body,
                &signature,
            )
            .map_err(|_| authentication_failed())?;
            let lookup_principal = principal.clone();
            let store = Arc::clone(&service.store);
            match await_before_deadline_or_shutdown(
                deadline,
                shutdown,
                store.execute(move |store| {
                    store.authenticate_runtime_provisioner_principal(&lookup_principal)
                }),
            )
            .await
            {
                AwaitOutcome::Completed(Ok(true)) => Ok(principal),
                AwaitOutcome::Completed(Ok(false)) => Err(authentication_failed()),
                AwaitOutcome::Completed(Err(error)) => {
                    if !matches!(
                        error.code,
                        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
                    ) {
                        state.readiness.poison();
                    }
                    Err(temporarily_unavailable())
                }
                AwaitOutcome::Deadline | AwaitOutcome::Shutdown => Err(temporarily_unavailable()),
            }
        }
        AuthEnvelope::WorkosCookie { sealed } => {
            let workos = state
                .cfg
                .workos
                .clone()
                .ok_or_else(temporarily_unavailable)?;
            let candidate = crate::auth::sealed_admin_session_candidate(&workos, &sealed)
                .map_err(|_| authentication_failed())?;
            authenticate_workos(workos, candidate, deadline, shutdown).await
        }
        AuthEnvelope::WorkosJwt { token } => {
            // The legacy static control-plane credentials are never an A23
            // principal. Reject them before consulting WorkOS so an
            // unconfigured or unavailable WorkOS dependency cannot turn a
            // deterministic authentication failure into a retryable 503.
            if token == state.cfg.admin_token
                || token == state.cfg.auth_token
                || token.starts_with("cats_wst_")
            {
                return Err(authentication_failed());
            }
            let workos = state
                .cfg
                .workos
                .clone()
                .ok_or_else(temporarily_unavailable)?;
            let identity = match await_before_deadline_or_shutdown(
                deadline,
                shutdown,
                workos.verify_access_token(&token),
            )
            .await
            {
                AwaitOutcome::Completed(Ok(identity)) => identity,
                AwaitOutcome::Completed(Err(error))
                    if matches!(
                        error.code,
                        ErrorCode::Unavailable | ErrorCode::DeadlineExceeded
                    ) =>
                {
                    return Err(temporarily_unavailable());
                }
                AwaitOutcome::Completed(Err(_)) => return Err(authentication_failed()),
                AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
                    return Err(temporarily_unavailable());
                }
            };
            let candidate = crate::auth::FleetAdministratorIdentityCandidate {
                subject: identity.user_id,
                organization_id: identity.organization_id.unwrap_or_default(),
            };
            authenticate_workos(workos, candidate, deadline, shutdown).await
        }
    }
}

async fn authenticate_workos(
    workos: Arc<crate::auth::WorkOsConfig>,
    candidate: crate::auth::FleetAdministratorIdentityCandidate,
    deadline: Instant,
    shutdown: &mut tokio::sync::watch::Receiver<bool>,
) -> Result<FleetPolicyPrincipal, Response> {
    match await_before_deadline_or_shutdown(
        deadline,
        shutdown,
        workos.current_fleet_administrator_principal(&candidate),
    )
    .await
    {
        AwaitOutcome::Completed(Ok(Some(principal))) => Ok(principal),
        AwaitOutcome::Completed(Ok(None)) => Err(error_response(
            StatusCode::FORBIDDEN,
            PERMISSION_DENIED,
            &[],
        )),
        AwaitOutcome::Completed(Err(error))
            if matches!(
                error.code,
                ErrorCode::Unauthenticated | ErrorCode::PermissionDenied
            ) =>
        {
            Err(authentication_failed())
        }
        AwaitOutcome::Completed(Err(_)) | AwaitOutcome::Deadline | AwaitOutcome::Shutdown => {
            Err(temporarily_unavailable())
        }
    }
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
        result = &mut future => {
            if Instant::now() >= deadline {
                AwaitOutcome::Deadline
            } else {
                AwaitOutcome::Completed(result)
            }
        },
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

fn single_header_text<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn declared_body_exceeds_limit(headers: &HeaderMap) -> bool {
    declared_body_exceeds(headers, RUNTIME_NODE_AUTHORITY_REQUEST_MAX_WIRE_BYTES)
}

fn declared_body_exceeds(headers: &HeaderMap, maximum: usize) -> bool {
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
        .is_none_or(|length| length > maximum as u64)
}

fn authentication_failed() -> Response {
    error_response(StatusCode::UNAUTHORIZED, AUTHENTICATION_FAILED, &[])
}

fn temporarily_unavailable() -> Response {
    error_response(
        StatusCode::SERVICE_UNAVAILABLE,
        TEMPORARILY_UNAVAILABLE,
        &[(header::RETRY_AFTER, HeaderValue::from_static("1"))],
    )
}

fn success_response(body: Vec<u8>) -> Response {
    json_response(StatusCode::OK, body)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn error_response(
    status: StatusCode,
    body: &'static [u8],
    extra_headers: &[(header::HeaderName, HeaderValue)],
) -> Response {
    debug_assert!(body.len() <= RUNTIME_NODE_AUTHORITY_ERROR_MAX_WIRE_BYTES);
    let mut response = (status, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(JSON_CONTENT_TYPE),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in extra_headers {
        headers.append(name, value.clone());
    }
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use cats_metering::SqliteUsageStore;
    use ring::signature::Ed25519KeyPair;

    const UPDATE: &[u8] = br#"{"apply_id":"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee","mutation":{"expected_policy_revision":1,"kind":"update_policy","placement_policy":{"allocatable_memory_bytes":17179869184,"allocatable_vcpus":8,"capabilities":{"block_frontend":"kernel_nbd","guest_agent_protocol_version":1,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","guest_network":"isolated_ipv4","guest_transport":"vsock","vmm":"cloud_hypervisor"},"guest_ipv4_pool":{"kind":"private_ipv4_16","network_address":"10.240.0.0","prefix_length":16},"node_id":"node_a","node_transport_target":"https://node-a.internal:7301","policy_revision":2,"scheduling_state":"schedulable","version":1}},"node_id":"node_a","version":1}"#;
    const TEST_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    struct TestPgClient(Option<postgres::Client>);

    impl TestPgClient {
        fn connect(dsn: &str) -> Self {
            Self(Some(std::thread::scope(|scope| {
                scope
                    .spawn(|| postgres::Client::connect(dsn, postgres::NoTls).unwrap())
                    .join()
                    .unwrap()
            })))
        }

        fn with<T: Send>(
            &mut self,
            operation: impl FnOnce(&mut postgres::Client) -> T + Send,
        ) -> T {
            let client = self.0.as_mut().expect("test PostgreSQL client is open");
            std::thread::scope(|scope| scope.spawn(|| operation(client)).join().unwrap())
        }
    }

    impl Drop for TestPgClient {
        fn drop(&mut self) {
            if let Some(client) = self.0.take() {
                std::thread::scope(|scope| scope.spawn(move || drop(client)).join().unwrap());
            }
        }
    }

    async fn test_server_with_dsn() -> (tempfile::TempDir, crate::server::Handle, String) {
        let dir = tempfile::tempdir().unwrap();
        let usage = Arc::new(SqliteUsageStore::open(&dir.path().join("usage.db")).unwrap());
        let dsn = crate::testsupport::isolated_control_store_url();
        let server = crate::testsupport::spawn_control_plane_for_test(crate::server::Config {
            listen: "127.0.0.1:0".into(),
            control_store_dsn: crate::store::DsnSource::Literal(dsn.clone()),
            control_store_ca_file: None,
            usage_store: usage.clone(),
            credit_store: usage,
            image_blob: crate::testsupport::unavailable_image_blob(),
            auth_token: "runtime-node-authority-unit-service-token".into(),
            guest_runtime_profile_receipt: crate::testsupport::test_guest_runtime_profile_receipt(),
            runtime_provisioner_trust_bundle:
                crate::testsupport::test_runtime_provisioner_trust_bundle(),
            production_cutover_operator_trust_bundle:
                crate::testsupport::test_production_cutover_operator_trust_bundle(),
            admin_token: "runtime-node-authority-unit-admin-token".into(),
            workos: None,
            stripe: None,
            billing_enforcement_enabled: false,
            oci_deploy_sync_wait_ms: 5_000,
        })
        .await
        .unwrap();
        (dir, server, dsn)
    }

    async fn test_server() -> (tempfile::TempDir, crate::server::Handle) {
        let (dir, server, _) = test_server_with_dsn().await;
        (dir, server)
    }

    fn signed_request(server: &crate::server::Handle) -> reqwest::RequestBuilder {
        let signer = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
        let signed = cats_api::runtime_node_authority::runtime_node_authority_signed_request(
            "deployment_a",
            "provisioner_a",
            UPDATE,
        );
        let signature = URL_SAFE_NO_PAD.encode(signer.sign(&signed).as_ref());
        reqwest::Client::new()
            .post(format!(
                "{}{RUNTIME_NODE_AUTHORITY_PATH}",
                server.base_url()
            ))
            .header(reqwest::header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(PROVISIONER_CREDENTIAL_ID_HEADER, "provisioner_a")
            .header(PROVISIONER_SIGNATURE_HEADER, signature)
            .body(UPDATE)
    }

    fn signed_axum_request() -> Request<Body> {
        let signer = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
        let signed = cats_api::runtime_node_authority::runtime_node_authority_signed_request(
            "deployment_a",
            "provisioner_a",
            UPDATE,
        );
        let signature = URL_SAFE_NO_PAD.encode(signer.sign(&signed).as_ref());
        Request::builder()
            .method(RUNTIME_NODE_AUTHORITY_METHOD)
            .uri(RUNTIME_NODE_AUTHORITY_PATH)
            .header(header::CONTENT_TYPE, JSON_CONTENT_TYPE)
            .header(PROVISIONER_CREDENTIAL_ID_HEADER, "provisioner_a")
            .header(PROVISIONER_SIGNATURE_HEADER, signature)
            .body(Body::from(UPDATE))
            .unwrap()
    }

    async fn wait_for_store_advisory_lock_wait(dsn: &str, backend_pid: i32) {
        let mut monitor = TestPgClient::connect(dsn);
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            loop {
                let waiting = monitor.with(|monitor| {
                    monitor
                        .query_one(
                            "SELECT EXISTS (
                               SELECT 1 FROM pg_locks
                                WHERE pid=$1 AND locktype='advisory' AND NOT granted
                             )",
                            &[&backend_pid],
                        )
                        .unwrap()
                        .get::<_, bool>(0)
                });
                if waiting {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("runtime Node authority worker did not reach its pre-COMMIT barrier");
    }

    #[test]
    fn frozen_error_vectors_are_exact() {
        assert_eq!(AUTHORITY_PRECONDITION_FAILED.len(), 95);
        assert_eq!(PRINCIPAL_REQUEST_IN_FLIGHT.len(), 118);
        assert_eq!(TEMPORARILY_UNAVAILABLE.len(), 96);
    }

    #[test]
    fn credential_envelopes_are_mutually_exclusive() {
        let mut headers = HeaderMap::new();
        headers.insert(
            PROVISIONER_CREDENTIAL_ID_HEADER,
            HeaderValue::from_static("provisioner_a"),
        );
        headers.insert(
            PROVISIONER_SIGNATURE_HEADER,
            HeaderValue::from_static("signature"),
        );
        assert!(matches!(
            classify_auth_envelope(&headers),
            Some(AuthEnvelope::Machine { .. })
        ));
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_static("Bearer token"),
        );
        assert!(classify_auth_envelope(&headers).is_none());

        let mut headers = HeaderMap::new();
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("cats_admin_session=sealed"),
        );
        assert!(matches!(
            classify_auth_envelope(&headers),
            Some(AuthEnvelope::WorkosCookie { .. })
        ));
        headers.insert(
            header::COOKIE,
            HeaderValue::from_static("cats_admin_session=sealed; cats_user_session=user"),
        );
        assert!(classify_auth_envelope(&headers).is_none());
    }

    #[test]
    fn admission_caps_are_exact_and_never_wait() {
        let admission = RuntimeNodeAuthorityAdmission::new();
        let globals = (0..GLOBAL_IN_FLIGHT)
            .map(|_| admission.try_global().unwrap())
            .collect::<Vec<_>>();
        assert!(admission.try_global().is_err());
        drop(globals);
        assert!(admission.try_global().is_ok());

        let principal = FleetPolicyPrincipal::WorkosFleetAdministrator {
            subject: cats_api::runtime_reconciliation::Id::new("user_fleet_admin").unwrap(),
            organization_id: cats_api::runtime_reconciliation::Id::new("org_admin").unwrap(),
        };
        let principals = (0..PRINCIPAL_IN_FLIGHT)
            .map(|_| admission.try_principal(&principal).unwrap())
            .collect::<Vec<_>>();
        assert!(admission.try_principal(&principal).is_err());
        drop(principals);
        assert!(admission.try_principal(&principal).is_ok());
    }

    #[tokio::test]
    async fn expired_absolute_deadline_wins_over_an_already_ready_result() {
        let (_, mut shutdown) = tokio::sync::watch::channel(true);
        assert!(matches!(
            await_before_deadline_or_shutdown(
                Instant::now() - Duration::from_millis(1),
                &mut shutdown,
                std::future::ready(42_u8),
            )
            .await,
            AwaitOutcome::Deadline
        ));
    }

    #[tokio::test]
    async fn completion_that_becomes_ready_after_the_absolute_deadline_is_rejected() {
        let (_accepting, mut shutdown) = tokio::sync::watch::channel(true);
        let deadline = Instant::now() + Duration::from_millis(100);
        let result = await_before_deadline_or_shutdown(deadline, &mut shutdown, async {
            // This deliberately becomes Ready in the same poll that crosses
            // the deadline. A select ordering preference alone cannot reject
            // it; the Completed edge needs an explicit absolute-clock check.
            std::thread::sleep(Duration::from_millis(200));
            42_u8
        })
        .await;
        assert!(matches!(result, AwaitOutcome::Deadline));
    }

    #[tokio::test]
    async fn aborting_the_handler_before_commit_rolls_back_every_write() {
        const PRECOMMIT_BARRIER: i64 = 8_023_004_023_773;
        let (_dir, server, dsn) = test_server_with_dsn().await;
        let backend_pid = server
            .state
            .store
            .with(|client| Ok(client.query_one("SELECT pg_backend_pid()", &[])?.get(0)))
            .unwrap();
        let mut setup = TestPgClient::connect(&dsn);
        setup.with(|setup| {
            setup
                .batch_execute(&format!(
                    "CREATE FUNCTION runtime_node_authority_pause_before_insert_for_test()
                   RETURNS trigger LANGUAGE plpgsql AS $$
                   BEGIN
                     PERFORM pg_advisory_lock({PRECOMMIT_BARRIER});
                     PERFORM pg_advisory_unlock({PRECOMMIT_BARRIER});
                     RETURN NEW;
                   END
                   $$;
                 CREATE TRIGGER runtime_node_authority_pause_before_insert_for_test
                   BEFORE INSERT ON runtime_node_authority_apply_records
                   FOR EACH ROW EXECUTE FUNCTION
                     runtime_node_authority_pause_before_insert_for_test()"
                ))
                .unwrap()
        });
        setup.with(|setup| {
            setup
                .query_one("SELECT pg_advisory_lock($1)", &[&PRECOMMIT_BARRIER])
                .unwrap()
        });

        let state = server.state.clone();
        let handler = tokio::spawn(async move {
            apply_runtime_node_authority(State(state), signed_axum_request()).await
        });
        wait_for_store_advisory_lock_wait(&dsn, backend_pid).await;
        handler.abort();
        assert!(handler.await.unwrap_err().is_cancelled());
        assert!(setup.with(|setup| {
            setup
                .query_one("SELECT pg_advisory_unlock($1)", &[&PRECOMMIT_BARRIER])
                .unwrap()
                .get::<_, bool>(0)
        }));

        tokio::time::timeout(cats_test_support::poll_bound(), async {
            while server
                .state
                .runtime_node_authority
                .active_commit_resolutions()
                != 0
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("cancelled pre-COMMIT worker did not roll back");
        assert_eq!(
            setup.with(|setup| {
                setup
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )
                    .unwrap()
                    .get::<_, i64>(0)
            }),
            0
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_closes_commit_owner_registration_before_waiting_for_empty() {
        let (_dir, server, dsn) = test_server_with_dsn().await;
        let service = Arc::clone(&server.state.runtime_node_authority);
        service.arm_pause_before_registration_for_test();
        let response = tokio::spawn({
            let request = signed_request(&server);
            async move { request.send().await }
        });
        tokio::time::timeout(
            cats_test_support::poll_bound(),
            service.wait_for_registration_pause_for_test(),
        )
        .await
        .expect("request did not pause before commit-owner registration");

        service.shutdown_commit_resolutions().await.unwrap();
        assert_eq!(service.active_commit_resolutions(), 0);
        service.release_registration_pause_for_test();

        let response = response.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(service.active_commit_resolutions(), 0);
        let mut observer = TestPgClient::connect(&dsn);
        assert_eq!(
            observer.with(|observer| {
                observer
                    .query_one(
                        "SELECT count(*) FROM runtime_node_authority_apply_records",
                        &[],
                    )
                    .unwrap()
                    .get::<_, i64>(0)
            }),
            0,
            "shutdown must reject the late request before any Store apply"
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn committed_response_loss_is_resolved_to_the_persisted_http_result() {
        let (_dir, server) = test_server().await;
        server
            .state
            .store
            .inject_request_committed_response_loss_once_after(Duration::from_millis(20));
        let response = signed_request(&server).send().await.unwrap();
        assert_eq!(response.status(), StatusCode::CONFLICT);
        assert_eq!(
            response.headers()[NODE_AUTHORITY_APPLY_ID_HEADER],
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
        );
        assert_eq!(
            response.bytes().await.unwrap().as_ref(),
            AUTHORITY_PRECONDITION_FAILED
        );
        assert!(!server
            .state
            .store
            .request_committed_response_loss_is_armed());
        assert_eq!(
            server
                .state
                .runtime_node_authority
                .active_commit_resolutions(),
            0
        );
        server.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn shutdown_joins_a_commit_owner_after_the_handler_is_cancelled() {
        let (_dir, server) = test_server().await;
        server
            .state
            .store
            .inject_request_committed_response_loss_once_after(Duration::from_millis(500));
        let request = signed_request(&server);
        let response = tokio::spawn(async move { request.send().await });
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            while server
                .state
                .store
                .request_committed_response_loss_is_armed()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(
            server
                .state
                .runtime_node_authority
                .active_commit_resolutions(),
            1
        );
        let started = Instant::now();
        server.shutdown().await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(300));
        assert_eq!(
            server
                .state
                .runtime_node_authority
                .active_commit_resolutions(),
            0
        );
        let response = response.await.unwrap().unwrap();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    #[tokio::test]
    async fn corrupt_ambiguous_result_poisons_readiness_and_keeps_resolution_ownership() {
        let (_dir, server, dsn) = test_server_with_dsn().await;
        server
            .state
            .store
            .inject_request_committed_response_loss_once_after(Duration::from_millis(300));
        let response = tokio::spawn({
            let request = signed_request(&server);
            async move { request.send().await }
        });
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            while server
                .state
                .store
                .request_committed_response_loss_is_armed()
            {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("request did not cross COMMIT");

        let corrupt_digest = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            std::thread::scope(|scope| {
                scope
                    .spawn(|| {
                        let mut corruptor =
                            postgres::Client::connect(&dsn, postgres::NoTls).unwrap();
                        corruptor
                            .batch_execute(
                                "ALTER TABLE runtime_node_authority_apply_records
                                   DISABLE TRIGGER runtime_node_apply_is_immutable",
                            )
                            .unwrap();
                        let updated = corruptor
                            .execute(
                                "UPDATE runtime_node_authority_apply_records
                        SET request_sha256=$2
                      WHERE apply_id=$1",
                                &[&"eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", &corrupt_digest],
                            )
                            .unwrap();
                        corruptor
                            .batch_execute(
                                "ALTER TABLE runtime_node_authority_apply_records
                                   ENABLE TRIGGER runtime_node_apply_is_immutable",
                            )
                            .unwrap();
                        updated
                    })
                    .join()
                    .unwrap()
            }),
            1
        );
        tokio::time::timeout(cats_test_support::poll_bound(), async {
            while server.state.readiness.is_ready() {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("fatal stored apply corruption did not poison readiness");
        assert_eq!(
            server
                .state
                .runtime_node_authority
                .active_commit_resolutions(),
            1
        );

        let credential = &server
            .state
            .cfg
            .runtime_provisioner_trust_bundle
            .credentials[0];
        let signer = Ed25519KeyPair::from_seed_unchecked(&TEST_SEED).unwrap();
        let signed = cats_api::runtime_node_authority::runtime_node_authority_signed_request(
            "deployment_a",
            "provisioner_a",
            UPDATE,
        );
        let principal = verify_runtime_node_authority_request(
            &server
                .state
                .cfg
                .runtime_provisioner_trust_bundle
                .deployment_id,
            credential,
            UPDATE,
            &URL_SAFE_NO_PAD.encode(signer.sign(&signed).as_ref()),
        )
        .unwrap();
        let remaining_principal_permits = (0..PRINCIPAL_IN_FLIGHT - 1)
            .map(|_| {
                server
                    .state
                    .runtime_node_authority
                    .admission
                    .try_principal(&principal)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert!(server
            .state
            .runtime_node_authority
            .admission
            .try_principal(&principal)
            .is_err());
        drop(remaining_principal_permits);

        let health = reqwest::get(format!("{}/healthz", server.base_url()))
            .await
            .unwrap();
        assert_eq!(health.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(RESOLUTION_SHUTDOWN_DEADLINE, Duration::from_secs(30));
        assert!(
            tokio::time::timeout(
                Duration::from_millis(100),
                server
                    .state
                    .runtime_node_authority
                    .shutdown_commit_resolutions(),
            )
            .await
            .is_err(),
            "fatal unresolved COMMIT was incorrectly reported as a clean shutdown"
        );
        response.abort();
    }
}
