//! Attachment-authenticated, crash-recoverable object-write gateway.
//!
//! This service is the only production process that owns object-store PUT
//! authority. It authenticates a per-attachment Ed25519 key, persists a
//! provisional descriptor, streams the body to a cross-replica durable spool,
//! and only then asks PostgreSQL to assign an accepted sequence.

mod listener;
mod spool;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::{to_bytes, Body};
use axum::extract::State;
use axum::http::{header, HeaderMap, HeaderValue, Request, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use cats_api::agent_registration::{
    NodeRequestProof, NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER, NODE_SIGNATURE_HEADER,
};
use cats_api::error::{ApiError, ErrorBody, ErrorCode};
use cats_api::object_write_gateway::{
    encode_object_write_credential_registration_receipt, encode_object_write_gateway_receipt,
    verify_object_write_credential_registration, verify_object_write_request,
    ObjectWriteGatewayReceipt, ObjectWriteGatewayTerminalReceipt, OBJECT_WRITE_BODY_MAX_BYTES,
    OBJECT_WRITE_CREDENTIAL_ID_HEADER, OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
    OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH, OBJECT_WRITE_DESCRIPTOR_HEADER,
    OBJECT_WRITE_GATEWAY_CONTENT_TYPE, OBJECT_WRITE_GATEWAY_PATH,
    OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER, OBJECT_WRITE_SIGNATURE_HEADER,
};
use cats_api::runtime_reconciliation::{ContractVersion, Sha256Digest};
use cats_storage::object_write_authority::{
    DurableObjectWriteSpoolReceipt, ObjectPutAttempt, ObjectPutState, ObjectPutTerminalState,
    ObjectWriteAcceptanceOutcome, ObjectWriteDownstreamError, ObjectWriteDownstreamPut,
    ObjectWriteDownstreamPutOutcome, ObjectWriteGatewayDownstream, ObjectWriteIngress,
    ObjectWriteIngressState, ObjectWriteVisibilityOutcome, StoredObjectWriteAttempt,
    TerminalObjectWriteSpool,
};
use serde::Serialize;
use tokio::sync::{watch, Semaphore};

use crate::store::Store;

use self::spool::{DurableSpool, DurableSpoolError};

pub const OBJECT_WRITE_GATEWAY_CONNECTION_LIMIT: usize = 64;
pub const OBJECT_WRITE_GATEWAY_RECEIVING_LIMIT: usize = 16;
pub const OBJECT_WRITE_GATEWAY_PROVIDER_LIMIT: usize = 16;
pub const OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE: Duration = Duration::from_secs(60);
const REGISTRATION_MAX_BYTES: usize = 16 * 1024;
const RECOVERY_INTERVAL: Duration = Duration::from_secs(1);
const RETRY_INTERVAL: Duration = Duration::from_millis(100);

#[derive(Debug, Clone)]
pub struct ObjectWriteGatewayConfig {
    pub listen: String,
    pub server_certificate_file: std::path::PathBuf,
    pub server_private_key_file: std::path::PathBuf,
    pub durable_spool_root: std::path::PathBuf,
}

struct GatewayService {
    store: Arc<Store>,
    downstream: Arc<dyn ObjectWriteGatewayDownstream>,
    spool: DurableSpool,
    receiving: Arc<Semaphore>,
    provider: Arc<Semaphore>,
    ready: AtomicBool,
}

#[derive(Serialize)]
struct HealthReceipt {
    version: u8,
    status: &'static str,
    connection_limit: usize,
    receiving_limit: usize,
    provider_limit: usize,
    body_max_bytes: usize,
    request_deadline_seconds: u64,
}

/// Validate all local and external authority bindings, recover one bounded
/// pass, and only then open the production listener.
pub async fn run_object_write_gateway(
    config: ObjectWriteGatewayConfig,
    store: Arc<Store>,
    downstream: Arc<dyn ObjectWriteGatewayDownstream>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let service = Arc::new(GatewayService {
        store,
        downstream,
        spool: DurableSpool::open(config.durable_spool_root)
            .map_err(|error| anyhow::anyhow!(error))?,
        receiving: Arc::new(Semaphore::new(OBJECT_WRITE_GATEWAY_RECEIVING_LIMIT)),
        provider: Arc::new(Semaphore::new(OBJECT_WRITE_GATEWAY_PROVIDER_LIMIT)),
        ready: AtomicBool::new(false),
    });
    recover_once(&service, true).await?;
    service.ready.store(true, Ordering::Release);

    let app = Router::new()
        .route(OBJECT_WRITE_GATEWAY_PATH, post(write_object))
        .route(
            OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH,
            post(register_credential),
        )
        .route("/healthz", get(health))
        .fallback(not_found)
        .with_state(Arc::clone(&service));
    let recovery_service = Arc::clone(&service);
    let recovery_shutdown = shutdown.clone();
    let recovery = run_recovery(recovery_service, recovery_shutdown);
    let listener = listener::serve(
        &config.listen,
        &config.server_certificate_file,
        &config.server_private_key_file,
        app,
        shutdown,
    );
    tokio::pin!(listener);
    tokio::pin!(recovery);
    tokio::select! {
        result = &mut listener => result,
        result = &mut recovery => {
            result?;
            listener.await
        }
    }
}

async fn health(State(service): State<Arc<GatewayService>>) -> Response {
    let ready = service.ready.load(Ordering::Acquire);
    let receipt = HealthReceipt {
        version: 1,
        status: if ready { "ready" } else { "recovering" },
        connection_limit: OBJECT_WRITE_GATEWAY_CONNECTION_LIMIT,
        receiving_limit: OBJECT_WRITE_GATEWAY_RECEIVING_LIMIT,
        provider_limit: OBJECT_WRITE_GATEWAY_PROVIDER_LIMIT,
        body_max_bytes: OBJECT_WRITE_BODY_MAX_BYTES,
        request_deadline_seconds: OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE.as_secs(),
    };
    json_response(
        if ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        &receipt,
    )
}

async fn not_found() -> Response {
    error_response(ApiError::not_found("object-write gateway route"))
}

async fn register_credential(
    State(service): State<Arc<GatewayService>>,
    request: Request<Body>,
) -> Response {
    if !service.ready.load(Ordering::Acquire) {
        return unavailable_response();
    }
    let deadline = Instant::now() + OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE;
    if request.uri().query().is_some()
        || !content_type_is(
            request.headers(),
            OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
        )
        || request.headers().contains_key(header::CONTENT_ENCODING)
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::AUTHORIZATION)
    {
        return error_response(ApiError::invalid(
            "invalid object-write credential registration transport",
        ));
    }
    let Some(length) = exact_content_length(request.headers()) else {
        return error_response(ApiError::invalid(
            "object-write credential registration requires one Content-Length",
        ));
    };
    if length > REGISTRATION_MAX_BYTES as u64 {
        return error_response(ApiError::invalid(
            "object-write credential registration exceeds its bound",
        ));
    }
    let headers = request.headers().clone();
    let body = match tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline),
        to_bytes(request.into_body(), REGISTRATION_MAX_BYTES),
    )
    .await
    {
        Ok(Ok(body)) if body.len() as u64 == length => body,
        Ok(Ok(_)) => return error_response(ApiError::invalid("Content-Length mismatch")),
        Ok(Err(_)) => {
            return error_response(ApiError::invalid(
                "object-write credential registration body is invalid",
            ));
        }
        Err(_) => return deadline_response(),
    };
    let Some(node) = proof_from_headers(
        &headers,
        NODE_CREDENTIAL_ID_HEADER,
        NODE_PUBLIC_KEY_SPKI_HEADER,
        NODE_SIGNATURE_HEADER,
    ) else {
        return authentication_response();
    };
    let Some(attachment) = proof_from_headers(
        &headers,
        OBJECT_WRITE_CREDENTIAL_ID_HEADER,
        OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER,
        OBJECT_WRITE_SIGNATURE_HEADER,
    ) else {
        return authentication_response();
    };
    let (node, attachment, registration) =
        match verify_object_write_credential_registration(&body, &node, &attachment) {
            Ok(value) => value,
            Err(_) => return authentication_response(),
        };
    let result = service
        .store
        .execute(move |store| {
            store.register_object_write_credential(&node, &attachment, &registration)
        })
        .await;
    match result {
        Ok(receipt) => match encode_object_write_credential_registration_receipt(&receipt) {
            Ok(body) => bytes_response(StatusCode::OK, body),
            Err(_) => internal_response(),
        },
        Err(error) => error_response(error),
    }
}

async fn write_object(
    State(service): State<Arc<GatewayService>>,
    request: Request<Body>,
) -> Response {
    if !service.ready.load(Ordering::Acquire) {
        return unavailable_response();
    }
    let deadline = Instant::now() + OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE;
    if request.uri().query().is_some()
        || !content_type_is(request.headers(), OBJECT_WRITE_GATEWAY_CONTENT_TYPE)
        || request.headers().contains_key(header::CONTENT_ENCODING)
        || request.headers().contains_key(header::TRANSFER_ENCODING)
        || request.headers().contains_key(header::AUTHORIZATION)
    {
        return error_response(ApiError::invalid("invalid object-write transport"));
    }
    let Some(content_length) = exact_content_length(request.headers()) else {
        return error_response(ApiError::invalid(
            "object write requires one Content-Length",
        ));
    };
    if content_length > OBJECT_WRITE_BODY_MAX_BYTES as u64 {
        return error_response(ApiError::invalid("object-write body exceeds its bound"));
    }
    let proof = (
        single_header(request.headers(), OBJECT_WRITE_DESCRIPTOR_HEADER),
        single_header(request.headers(), OBJECT_WRITE_CREDENTIAL_ID_HEADER),
        single_header(request.headers(), OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER),
        single_header(request.headers(), OBJECT_WRITE_SIGNATURE_HEADER),
    );
    let (authenticated, descriptor) = match proof {
        (Some(descriptor), Some(credential), Some(public_key), Some(signature)) => {
            match verify_object_write_request(descriptor, credential, public_key, signature) {
                Ok(value) => value,
                Err(_) => return authentication_response(),
            }
        }
        _ => return authentication_response(),
    };
    if descriptor.content_length.get() != content_length {
        return error_response(ApiError::invalid("Content-Length mismatch"));
    }
    let _receiving = match Arc::clone(&service.receiving).try_acquire_owned() {
        Ok(permit) => permit,
        Err(_) => return unavailable_response(),
    };
    let descriptor_for_store = descriptor.clone();
    let stored = service
        .store
        .execute(move |store| {
            store.begin_object_write_ingress(&authenticated, &descriptor_for_store)
        })
        .await;
    let stored = match stored {
        Ok(stored) => stored,
        Err(error) => return error_response(error),
    };
    let body = request.into_body();
    match process_incoming(&service, stored, body, deadline).await {
        Ok(attempt) => terminal_response(&attempt),
        Err(error) => error_response(error),
    }
}

async fn process_incoming(
    service: &Arc<GatewayService>,
    stored: StoredObjectWriteAttempt,
    body: Body,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    let stored = match stored {
        StoredObjectWriteAttempt::Ingress(attempt) => match &attempt.state {
            ObjectWriteIngressState::Receiving => {
                let receipt = service
                    .spool
                    .receive(&attempt.ingress, body, deadline)
                    .await
                    .map_err(spool_error)?;
                persist_spool(service, &attempt.ingress.request_id, &receipt).await?
            }
            ObjectWriteIngressState::DurableSpooled { .. }
            | ObjectWriteIngressState::RejectedBeforeAccept { .. } => {
                service
                    .spool
                    .validate_body(
                        &attempt.ingress.content_sha256,
                        attempt.ingress.content_length,
                        body,
                        deadline,
                    )
                    .await
                    .map_err(spool_error)?;
                StoredObjectWriteAttempt::Ingress(attempt)
            }
        },
        StoredObjectWriteAttempt::Accepted(attempt) => {
            service
                .spool
                .validate_body(
                    &attempt.descriptor.content_sha256,
                    attempt.descriptor.content_length,
                    body,
                    deadline,
                )
                .await
                .map_err(spool_error)?;
            StoredObjectWriteAttempt::Accepted(attempt)
        }
    };
    accept_or_reject(service, stored, deadline).await
}

async fn persist_spool(
    service: &Arc<GatewayService>,
    request_id: &Sha256Digest,
    receipt: &DurableObjectWriteSpoolReceipt,
) -> Result<StoredObjectWriteAttempt, ApiError> {
    let request_id = request_id.clone();
    let receipt = receipt.clone();
    service
        .store
        .execute(move |store| store.mark_object_write_spool_durable(&request_id, &receipt))
        .await
}

async fn accept_or_reject(
    service: &Arc<GatewayService>,
    stored: StoredObjectWriteAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    match stored {
        StoredObjectWriteAttempt::Accepted(attempt) => {
            drive_accepted(service, attempt, deadline).await
        }
        StoredObjectWriteAttempt::Ingress(attempt) => match &attempt.state {
            ObjectWriteIngressState::Receiving => Err(ApiError::failed_precondition(
                "object-write body is not durably spooled",
            )),
            ObjectWriteIngressState::RejectedBeforeAccept { .. } => {
                let _ = service.spool.remove(&attempt.ingress, deadline).await;
                Err(ApiError::conflict(
                    "object-write request was rejected before acceptance",
                ))
            }
            ObjectWriteIngressState::DurableSpooled { .. } => {
                // This is the final filesystem oracle immediately before the
                // transaction allocates a writer sequence. No accepted path
                // may repair mode, ownership, link topology, length or bytes.
                service
                    .spool
                    .validate_before_accept(&attempt.ingress, deadline)
                    .await
                    .map_err(spool_error)?;
                let request_id = attempt.ingress.request_id.clone();
                let outcome = service
                    .store
                    .execute(move |store| store.accept_durable_object_write(&request_id))
                    .await?;
                match outcome {
                    ObjectWriteAcceptanceOutcome::Accepted(attempt) => {
                        drive_accepted(service, attempt, deadline).await
                    }
                    ObjectWriteAcceptanceOutcome::RejectedBeforeAccept(rejected) => {
                        let _ = service.spool.remove(&rejected.ingress, deadline).await;
                        Err(ApiError::conflict(
                            "object-write request was rejected before acceptance",
                        ))
                    }
                }
            }
        },
    }
}

async fn drive_accepted(
    service: &Arc<GatewayService>,
    attempt: ObjectPutAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    if matches!(attempt.state, ObjectPutState::Terminal { .. }) {
        return cleanup_terminal(service, attempt, deadline).await;
    }
    let request_id = attempt.descriptor.request_id.clone();
    let mut attempt = service
        .store
        .execute(move |store| store.mark_object_write_provider_issued(&request_id))
        .await?;
    if matches!(attempt.state, ObjectPutState::Terminal { .. }) {
        return cleanup_terminal(service, attempt, deadline).await;
    }
    let spool = retained_spool(&attempt)
        .cloned()
        .ok_or_else(|| ApiError::internal("provider-issued object write lost its durable spool"))?;
    let _provider = acquire_until(&service.provider, deadline).await?;
    loop {
        if Instant::now() >= deadline {
            return Err(deadline_error());
        }
        let put = service
            .downstream
            .put_exact(
                ObjectWriteDownstreamPut {
                    descriptor: attempt.descriptor.clone(),
                    spool: spool.clone(),
                },
                deadline,
            )
            .await;
        match put {
            Ok(ObjectWriteDownstreamPutOutcome::PermanentlyFailed {
                provider_attempt_id,
                failure_receipt_id,
                failed_at_unix_ms,
            }) => {
                if provider_attempt_id != attempt.descriptor.provider_attempt_id {
                    return Err(ApiError::internal(
                        "provider returned a mismatched attempt ID",
                    ));
                }
                let terminal = ObjectPutTerminalState::PermanentlyFailed {
                    failure_receipt_id,
                    failed_at_unix_ms,
                };
                attempt =
                    settle_terminal(service, &attempt.descriptor.request_id, terminal).await?;
                return cleanup_terminal(service, attempt, deadline).await;
            }
            Ok(ObjectWriteDownstreamPutOutcome::Succeeded {
                provider_attempt_id,
                put_receipt_id,
                completed_at_unix_ms,
            }) => {
                if provider_attempt_id != attempt.descriptor.provider_attempt_id {
                    return Err(ApiError::internal(
                        "provider returned a mismatched attempt ID",
                    ));
                }
                loop {
                    match service
                        .downstream
                        .discover_visibility(&attempt.descriptor, deadline)
                        .await
                    {
                        Ok(ObjectWriteVisibilityOutcome::VisibleExact {
                            provider_attempt_id,
                            visibility_receipt_id,
                            observed_at_unix_ms,
                        }) if provider_attempt_id == attempt.descriptor.provider_attempt_id => {
                            let terminal = ObjectPutTerminalState::SucceededVisible {
                                put_receipt_id,
                                put_completed_at_unix_ms: completed_at_unix_ms,
                                visibility_receipt_id,
                                visible_at_unix_ms: observed_at_unix_ms,
                            };
                            attempt =
                                settle_terminal(service, &attempt.descriptor.request_id, terminal)
                                    .await?;
                            return cleanup_terminal(service, attempt, deadline).await;
                        }
                        Ok(ObjectWriteVisibilityOutcome::VisibleExact { .. }) => {
                            return Err(ApiError::internal(
                                "provider visibility returned a mismatched attempt ID",
                            ));
                        }
                        Ok(ObjectWriteVisibilityOutcome::ConflictingObject) => {
                            return Err(ApiError::failed_precondition(
                                "provider reported a conflicting immutable object",
                            ));
                        }
                        Ok(ObjectWriteVisibilityOutcome::NotVisible)
                        | Err(ObjectWriteDownstreamError::Ambiguous)
                        | Err(ObjectWriteDownstreamError::Unavailable) => {
                            retry_delay(deadline).await?;
                        }
                        Err(ObjectWriteDownstreamError::DeadlineExceeded) => {
                            return Err(deadline_error());
                        }
                        Err(ObjectWriteDownstreamError::ConflictingObject) => {
                            return Err(ApiError::failed_precondition(
                                "provider reported a conflicting immutable object",
                            ));
                        }
                        Err(ObjectWriteDownstreamError::InvalidRequest) => {
                            return Err(ApiError::internal(
                                "provider rejected the sealed object-write request",
                            ));
                        }
                    }
                }
            }
            Err(ObjectWriteDownstreamError::Ambiguous)
            | Err(ObjectWriteDownstreamError::Unavailable) => {
                // Discovery is mandatory after an ambiguous PUT. Reissuing is
                // conditional and occurs only after this exact HEAD oracle.
                let _ = service
                    .downstream
                    .discover_visibility(&attempt.descriptor, deadline)
                    .await;
                retry_delay(deadline).await?;
            }
            Err(ObjectWriteDownstreamError::DeadlineExceeded) => return Err(deadline_error()),
            Err(ObjectWriteDownstreamError::ConflictingObject) => {
                return Err(ApiError::failed_precondition(
                    "provider reported a conflicting immutable object",
                ));
            }
            Err(ObjectWriteDownstreamError::InvalidRequest) => {
                return Err(ApiError::internal(
                    "provider rejected the sealed object-write request",
                ));
            }
        }
    }
}

async fn settle_terminal(
    service: &Arc<GatewayService>,
    request_id: &Sha256Digest,
    terminal: ObjectPutTerminalState,
) -> Result<ObjectPutAttempt, ApiError> {
    let request_id = request_id.clone();
    service
        .store
        .execute(move |store| store.complete_object_write_terminal(&request_id, &terminal))
        .await
}

async fn cleanup_terminal(
    service: &Arc<GatewayService>,
    attempt: ObjectPutAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    let ObjectPutState::Terminal { spool, .. } = &attempt.state else {
        return Ok(attempt);
    };
    if matches!(spool, TerminalObjectWriteSpool::Removed { .. }) {
        return Ok(attempt);
    }
    let ingress = descriptor_ingress(&attempt);
    let Ok(removal_receipt_id) = service.spool.remove(&ingress, deadline).await else {
        // Terminal authority is already durable; recovery retains the row and
        // retries cleanup without weakening the successful PUT receipt.
        return Ok(attempt);
    };
    let request_id = attempt.descriptor.request_id.clone();
    service
        .store
        .execute(move |store| {
            store.mark_terminal_object_write_spool_removed(&request_id, &removal_receipt_id)
        })
        .await
}

fn descriptor_ingress(attempt: &ObjectPutAttempt) -> ObjectWriteIngress {
    ObjectWriteIngress {
        writer_authority_id: attempt.descriptor.writer_authority_id.clone(),
        request_id: attempt.descriptor.request_id.clone(),
        volume_id: attempt.descriptor.volume_id.clone(),
        key: attempt.descriptor.key.clone(),
        target: attempt.descriptor.target.clone(),
        content_sha256: attempt.descriptor.content_sha256.clone(),
        content_length: attempt.descriptor.content_length,
        receiving_started_at_unix_ms: attempt.descriptor.accepted_at_unix_ms,
    }
}

fn retained_spool(attempt: &ObjectPutAttempt) -> Option<&DurableObjectWriteSpoolReceipt> {
    match &attempt.state {
        ObjectPutState::AcceptedSpooled { spool }
        | ObjectPutState::ProviderIssued { spool, .. } => Some(spool),
        ObjectPutState::Terminal {
            spool: TerminalObjectWriteSpool::Retained { spool },
            ..
        } => Some(spool),
        ObjectPutState::Terminal {
            spool: TerminalObjectWriteSpool::Removed { .. },
            ..
        } => None,
    }
}

async fn run_recovery(
    service: Arc<GatewayService>,
    mut shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let mut interval = tokio::time::interval(RECOVERY_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    return Ok(());
                }
            }
            _ = interval.tick() => {
                match recover_once(&service, false).await {
                    Ok(()) => service.ready.store(true, Ordering::Release),
                    Err(error) => {
                        service.ready.store(false, Ordering::Release);
                        tracing::warn!(%error, "object-write recovery pass remains incomplete");
                    }
                }
            }
        }
    }
}

async fn recover_once(
    service: &Arc<GatewayService>,
    startup_has_no_receivers: bool,
) -> anyhow::Result<()> {
    let mut after = None;
    loop {
        let cursor = after.clone();
        let attempts = service
            .store
            .execute(move |store| store.recoverable_object_write_ingress_attempts(cursor.as_ref()))
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        if attempts.is_empty() {
            break;
        }
        for attempt in attempts {
            after = Some(attempt.ingress.request_id.clone());
            let deadline = Instant::now() + OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE;
            let stored = match &attempt.state {
                ObjectWriteIngressState::Receiving => {
                    match service
                        .spool
                        .recover_receipt(&attempt.ingress, startup_has_no_receivers, deadline)
                        .await
                    {
                        Ok(receipt) => {
                            persist_spool(service, &attempt.ingress.request_id, &receipt).await?
                        }
                        Err(DurableSpoolError::NotFound) => continue,
                        Err(error) => return Err(anyhow::anyhow!(error)),
                    }
                }
                ObjectWriteIngressState::DurableSpooled { .. } => {
                    StoredObjectWriteAttempt::Ingress(attempt.clone())
                }
                ObjectWriteIngressState::RejectedBeforeAccept { .. } => {
                    service.spool.remove(&attempt.ingress, deadline).await.ok();
                    continue;
                }
            };
            if let Err(error) = accept_or_reject(service, stored, deadline).await {
                if error.code != ErrorCode::Conflict {
                    return Err(anyhow::anyhow!(error));
                }
            }
        }
    }

    let mut after = None;
    loop {
        let cursor = after.clone();
        let attempts = service
            .store
            .execute(move |store| store.recoverable_object_write_attempts(cursor.as_ref()))
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        if attempts.is_empty() {
            break;
        }
        for attempt in attempts {
            after = Some(attempt.descriptor.request_id.clone());
            let deadline = Instant::now() + OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE;
            drive_accepted(service, attempt, deadline)
                .await
                .map_err(|error| anyhow::anyhow!(error))?;
        }
    }
    Ok(())
}

async fn acquire_until(
    semaphore: &Arc<Semaphore>,
    deadline: Instant,
) -> Result<tokio::sync::OwnedSemaphorePermit, ApiError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(deadline_error)?;
    tokio::time::timeout(remaining, Arc::clone(semaphore).acquire_owned())
        .await
        .map_err(|_| deadline_error())?
        .map_err(|_| ApiError::unavailable("object-write gateway is shutting down"))
}

async fn retry_delay(deadline: Instant) -> Result<(), ApiError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(deadline_error)?;
    tokio::time::sleep(std::cmp::min(RETRY_INTERVAL, remaining)).await;
    if Instant::now() >= deadline {
        return Err(deadline_error());
    }
    Ok(())
}

fn proof_from_headers(
    headers: &HeaderMap,
    credential_name: &str,
    public_key_name: &str,
    signature_name: &str,
) -> Option<NodeRequestProof> {
    let credential_id = single_header(headers, credential_name)?;
    let public_key_spki = single_header(headers, public_key_name)?;
    let signature = single_header(headers, signature_name)?;
    if credential_id.len() > 128 || public_key_spki.len() > 512 || signature.len() > 512 {
        return None;
    }
    Some(NodeRequestProof {
        credential_id: credential_id.to_owned(),
        public_key_spki: public_key_spki.to_owned(),
        signature: signature.to_owned(),
    })
}

fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.to_str().ok()
}

fn exact_content_length(headers: &HeaderMap) -> Option<u64> {
    single_header(headers, header::CONTENT_LENGTH.as_str())?
        .parse()
        .ok()
}

fn content_type_is(headers: &HeaderMap, expected: &str) -> bool {
    single_header(headers, header::CONTENT_TYPE.as_str()).is_some_and(|value| {
        value
            .trim_matches([' ', '\t'])
            .eq_ignore_ascii_case(expected)
    })
}

fn terminal_response(attempt: &ObjectPutAttempt) -> Response {
    let Some(receipt) = gateway_receipt(attempt) else {
        return internal_response();
    };
    match encode_object_write_gateway_receipt(&receipt) {
        Ok(body) => bytes_response(StatusCode::OK, body),
        Err(_) => internal_response(),
    }
}

fn gateway_receipt(attempt: &ObjectPutAttempt) -> Option<ObjectWriteGatewayReceipt> {
    let ObjectPutState::Terminal { outcome, .. } = &attempt.state else {
        return None;
    };
    let terminal = match outcome {
        ObjectPutTerminalState::SucceededVisible {
            put_receipt_id,
            put_completed_at_unix_ms,
            visibility_receipt_id,
            visible_at_unix_ms,
        } => ObjectWriteGatewayTerminalReceipt::SucceededVisible {
            put_receipt_id: put_receipt_id.clone(),
            put_completed_at_unix_ms: *put_completed_at_unix_ms,
            visibility_receipt_id: visibility_receipt_id.clone(),
            visible_at_unix_ms: *visible_at_unix_ms,
        },
        ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id,
            failed_at_unix_ms,
        } => ObjectWriteGatewayTerminalReceipt::PermanentlyFailed {
            failure_receipt_id: failure_receipt_id.clone(),
            failed_at_unix_ms: *failed_at_unix_ms,
        },
    };
    Some(ObjectWriteGatewayReceipt {
        version: ContractVersion::V1,
        writer_authority_id: attempt.descriptor.writer_authority_id.clone(),
        request_id: attempt.descriptor.request_id.clone(),
        accepted_sequence: attempt.descriptor.accepted_sequence,
        terminal,
    })
}

fn spool_error(error: DurableSpoolError) -> ApiError {
    match error {
        DurableSpoolError::BodyMismatch => ApiError::invalid("object-write body mismatch"),
        DurableSpoolError::DeadlineExceeded => deadline_error(),
        DurableSpoolError::Unavailable | DurableSpoolError::NotFound => {
            ApiError::unavailable("durable object-write spool is unavailable")
        }
        DurableSpoolError::Invalid => ApiError::internal("durable object-write spool is invalid"),
    }
}

fn deadline_error() -> ApiError {
    ApiError::new(
        ErrorCode::DeadlineExceeded,
        "object-write gateway request deadline exceeded",
    )
}

fn authentication_response() -> Response {
    let mut response = error_response(ApiError::unauthenticated(
        "object-write attachment authentication failed",
    ));
    response.headers_mut().insert(
        header::WWW_AUTHENTICATE,
        HeaderValue::from_static("Cats-Object-Write-Ed25519"),
    );
    response
}

fn unavailable_response() -> Response {
    let mut response = error_response(ApiError::unavailable(
        "object-write gateway admission is full",
    ));
    response
        .headers_mut()
        .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
    response
}

fn deadline_response() -> Response {
    error_response(deadline_error())
}

fn internal_response() -> Response {
    error_response(ApiError::internal("object-write gateway failed internally"))
}

fn error_response(error: ApiError) -> Response {
    let status =
        StatusCode::from_u16(error.code.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    json_response(status, &ErrorBody::new(error.code, error.message))
}

fn json_response<T: Serialize>(status: StatusCode, value: &T) -> Response {
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn bytes_response(status: StatusCode, body: Vec<u8>) -> Response {
    let mut response = (status, body).into_response();
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
