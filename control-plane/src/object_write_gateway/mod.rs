//! Attachment-authenticated, crash-recoverable object-write gateway.
//!
//! This service is the only production process that owns object-store PUT
//! authority. It authenticates a per-attachment Ed25519 key, persists a
//! provisional descriptor, streams the body to a cross-replica durable spool,
//! and only then asks PostgreSQL to assign an accepted sequence.

mod listener;
mod spool;

use std::future::Future;
use std::pin::Pin;
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
    adopt_object_write_qualification_ambiguity, adopt_object_write_qualification_response_lost,
    adopt_object_write_qualification_unproven_visible,
    commit_object_write_qualification_put_outcome, prepare_object_write_qualification,
    resolve_object_write_qualification_after_head, seal_object_write_qualification_ambiguity,
    seal_object_write_qualification_put, DurableObjectWriteSpoolReceipt, ObjectPutAttempt,
    ObjectPutState, ObjectPutTerminalState, ObjectWriteAcceptanceOutcome, ObjectWriteAuthority,
    ObjectWriteDownstreamError, ObjectWriteDownstreamPut, ObjectWriteDownstreamPutOutcome,
    ObjectWriteGatewayDownstream, ObjectWriteIngress, ObjectWriteIngressState,
    ObjectWriteQualificationHeadProbe, ObjectWriteQualificationHeadResolution,
    ObjectWriteQualificationPreparation, ObjectWriteQualificationPutDispatch,
    ObjectWriteVisibilityOutcome, QualificationFaultAuthorityError, StoredObjectWriteAttempt,
    TerminalObjectWriteSpool,
};
use serde::Serialize;
use tokio::sync::{watch, Semaphore};

use crate::store::ObjectWriteGatewayClient;

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
    authority: Arc<ObjectWriteGatewayClient>,
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

enum QualificationProviderResolution<'a> {
    Terminal(Box<ObjectPutAttempt>),
    Authorized(Box<ObjectWriteQualificationPutDispatch<'a>>),
}

/// Validate all local and external authority bindings, recover one bounded
/// pass, and only then open the production listener.
pub async fn run_object_write_gateway(
    config: ObjectWriteGatewayConfig,
    authority: Arc<ObjectWriteGatewayClient>,
    downstream: Arc<dyn ObjectWriteGatewayDownstream>,
    shutdown: watch::Receiver<bool>,
) -> anyhow::Result<()> {
    let service = Arc::new(GatewayService {
        authority,
        downstream,
        spool: DurableSpool::open(config.durable_spool_root)
            .map_err(|error| anyhow::anyhow!(error))?,
        receiving: Arc::new(Semaphore::new(OBJECT_WRITE_GATEWAY_RECEIVING_LIMIT)),
        provider: Arc::new(Semaphore::new(OBJECT_WRITE_GATEWAY_PROVIDER_LIMIT)),
        ready: AtomicBool::new(false),
    });
    Box::pin(recover_once(&service, true)).await?;
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
    let result = tokio::select! {
        result = &mut listener => result,
        result = &mut recovery => {
            result?;
            listener.await
        }
    };
    service.authority.shutdown().await;
    result
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
        .authority
        .register_object_write_credential(&node, &attachment, &registration)
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
    let stored = service
        .authority
        .begin_object_write_ingress(&authenticated, &descriptor)
        .await;
    let stored = match stored {
        Ok(stored) => stored,
        Err(error) => return error_response(error),
    };
    let body = request.into_body();
    match Box::pin(process_incoming(&service, stored, body, deadline)).await {
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
    Box::pin(accept_or_reject(service, stored, deadline)).await
}

async fn persist_spool(
    service: &Arc<GatewayService>,
    request_id: &Sha256Digest,
    receipt: &DurableObjectWriteSpoolReceipt,
) -> Result<StoredObjectWriteAttempt, ApiError> {
    service
        .authority
        .mark_object_write_spool_durable(request_id, receipt)
        .await
}

async fn accept_or_reject(
    service: &Arc<GatewayService>,
    stored: StoredObjectWriteAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    match stored {
        StoredObjectWriteAttempt::Accepted(attempt) => {
            Box::pin(drive_accepted(service, attempt, deadline)).await
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
                let outcome = service
                    .authority
                    .accept_durable_object_write(&attempt.ingress.request_id)
                    .await?;
                match outcome {
                    ObjectWriteAcceptanceOutcome::Accepted(attempt) => {
                        Box::pin(drive_accepted(service, attempt, deadline)).await
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
    if attempt.descriptor.qualification_fault.is_some() {
        let _provider = acquire_until(&service.provider, deadline).await?;
        return Box::pin(drive_qualification_put(service, attempt, deadline)).await;
    }
    let (attempt, _) = service
        .authority
        .mark_object_write_provider_issued(&attempt.descriptor.request_id)
        .await?;
    if matches!(attempt.state, ObjectPutState::Terminal { .. }) {
        return cleanup_terminal(service, attempt, deadline).await;
    }
    let spool = retained_spool(&attempt)
        .cloned()
        .ok_or_else(|| ApiError::internal("provider-issued object write lost its durable spool"))?;
    let _provider = acquire_until(&service.provider, deadline).await?;
    drive_ordinary_put(service, attempt, spool, deadline).await
}

async fn drive_ordinary_put(
    service: &Arc<GatewayService>,
    mut attempt: ObjectPutAttempt,
    spool: DurableObjectWriteSpoolReceipt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
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
                    settle_terminal(&service.authority, &attempt.descriptor.request_id, terminal)
                        .await?;
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
                            provider_request: _,
                            observed_at_unix_ms,
                            ..
                        }) if provider_attempt_id == attempt.descriptor.provider_attempt_id => {
                            let terminal = ObjectPutTerminalState::SucceededVisible {
                                put_receipt_id,
                                put_completed_at_unix_ms: completed_at_unix_ms,
                                visibility_receipt_id,
                                visible_at_unix_ms: observed_at_unix_ms,
                                qualification_ambiguity: None,
                            };
                            attempt = settle_terminal(
                                &service.authority,
                                &attempt.descriptor.request_id,
                                terminal,
                            )
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

async fn drive_qualification_put(
    service: &Arc<GatewayService>,
    mut attempt: ObjectPutAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    loop {
        if Instant::now() >= deadline {
            return Err(deadline_error());
        }
        if matches!(
            attempt.state,
            ObjectPutState::QualificationResponseLost { .. }
        ) {
            let (_, authority) = service
                .authority
                .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                .await?;
            return drive_qualification_head_only(service, authority, attempt.clone(), deadline)
                .await;
        }
        if matches!(attempt.state, ObjectPutState::Terminal { .. }) {
            return cleanup_terminal(service, attempt, deadline).await;
        }
        let preparation =
            prepare_object_write_qualification(service.authority.as_ref(), &attempt, deadline)
                .await
                .map_err(qualification_error)?;
        let (dispatch, authority) = match preparation {
            ObjectWriteQualificationPreparation::StoredResponseLoss(committed) => {
                let (persisted, authority) = service
                    .authority
                    .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                    .await?;
                let expected =
                    adopt_object_write_qualification_response_lost(&authority, &attempt, committed)
                        .map_err(|_| {
                            ApiError::internal(
                                "qualification replay response-loss evidence changed its request",
                            )
                        })?;
                if !same_qualification_progress(&persisted, &expected) {
                    return Err(ApiError::conflict(
                        "qualification response-loss replay disagreed with persisted state",
                    ));
                }
                if matches!(persisted.state, ObjectPutState::Terminal { .. }) {
                    return cleanup_terminal(service, persisted, deadline).await;
                }
                attempt = persisted;
                continue;
            }
            ObjectWriteQualificationPreparation::StoredUnprovenVisible(committed) => {
                let (persisted, authority) = service
                    .authority
                    .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                    .await?;
                let expected = adopt_object_write_qualification_unproven_visible(
                    &authority, &attempt, committed,
                )
                .map_err(|_| {
                    ApiError::internal("qualification replay unproven evidence changed its request")
                })?;
                if !same_terminal_evidence(&persisted, &expected) {
                    return Err(ApiError::conflict(
                        "qualification unproven replay disagreed with persisted state",
                    ));
                }
                attempt = persisted;
                return cleanup_terminal(service, attempt, deadline).await;
            }
            ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(probe) => {
                let (persisted, authority) = service
                    .authority
                    .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                    .await?;
                if persisted != attempt {
                    return Err(ApiError::conflict(
                        "qualification ProviderIssued state changed while request lock was held",
                    ));
                }
                match resolve_issued_qualification_provider(
                    service.downstream.as_ref(),
                    &authority,
                    &attempt,
                    probe,
                )
                .await?
                {
                    QualificationProviderResolution::Terminal(resolved) => {
                        attempt = *resolved;
                        return cleanup_terminal(service, attempt, deadline).await;
                    }
                    QualificationProviderResolution::Authorized(dispatch) => (dispatch, authority),
                }
            }
            ObjectWriteQualificationPreparation::Authorized(capability) => {
                let (issued, authority) = service
                    .authority
                    .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                    .await?;
                attempt = issued;
                (
                    Box::new(
                        seal_object_write_qualification_put(&attempt, capability).map_err(
                            |_| {
                                ApiError::internal(
                                    "qualification authorization could not seal ProviderIssued",
                                )
                            },
                        )?,
                    ),
                    authority,
                )
            }
            ObjectWriteQualificationPreparation::Ordinary => {
                return Err(ApiError::internal(
                    "qualification preparation downgraded a signed fault",
                ));
            }
        };
        let put = service
            .downstream
            .put_qualification_exact(dispatch.request())
            .await;
        match put {
            Ok(outcome) => {
                attempt = commit_object_write_qualification_put_outcome(
                    &authority, &attempt, *dispatch, outcome,
                )
                .await
                .map_err(qualification_error)?;
                let (persisted, current_authority) = service
                    .authority
                    .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                    .await?;
                if !same_qualification_progress(&persisted, &attempt) {
                    return Err(ApiError::conflict(
                        "qualification commit disagreed with persisted state",
                    ));
                }
                attempt = persisted;
                if matches!(
                    attempt.state,
                    ObjectPutState::QualificationResponseLost { .. }
                ) {
                    return drive_qualification_head_only(
                        service,
                        current_authority,
                        attempt.clone(),
                        deadline,
                    )
                    .await;
                }
                return cleanup_terminal(service, attempt, deadline).await;
            }
            Err(ObjectWriteDownstreamError::Ambiguous)
            | Err(ObjectWriteDownstreamError::Unavailable) => {
                drop(dispatch);
                retry_delay(deadline).await?;
            }
            Err(ObjectWriteDownstreamError::DeadlineExceeded) => {
                drop(dispatch);
                return Err(deadline_error());
            }
            Err(ObjectWriteDownstreamError::ConflictingObject) => {
                drop(dispatch);
                return Err(ApiError::failed_precondition(
                    "provider reported a conflicting immutable object",
                ));
            }
            Err(ObjectWriteDownstreamError::InvalidRequest) => {
                drop(dispatch);
                return Err(ApiError::internal(
                    "provider rejected the sealed qualification write",
                ));
            }
        }
    }
}

async fn discover_until_conclusive(
    downstream: &dyn ObjectWriteGatewayDownstream,
    attempt: &ObjectPutAttempt,
    deadline: Instant,
) -> Result<ObjectWriteVisibilityOutcome, ApiError> {
    loop {
        match downstream
            .discover_visibility(&attempt.descriptor, deadline)
            .await
        {
            Ok(outcome) => return Ok(outcome),
            Err(ObjectWriteDownstreamError::Ambiguous)
            | Err(ObjectWriteDownstreamError::Unavailable) => retry_delay(deadline).await?,
            Err(ObjectWriteDownstreamError::DeadlineExceeded) => return Err(deadline_error()),
            Err(ObjectWriteDownstreamError::ConflictingObject) => {
                return Ok(ObjectWriteVisibilityOutcome::ConflictingObject);
            }
            Err(ObjectWriteDownstreamError::InvalidRequest) => {
                return Err(ApiError::internal(
                    "provider rejected the sealed object-write discovery",
                ));
            }
        }
    }
}

async fn resolve_issued_qualification_provider<'a>(
    downstream: &dyn ObjectWriteGatewayDownstream,
    authority: &ObjectWriteAuthority,
    attempt: &ObjectPutAttempt,
    probe: Box<ObjectWriteQualificationHeadProbe<'a>>,
) -> Result<QualificationProviderResolution<'a>, ApiError> {
    let probe_deadline = probe.absolute_deadline();
    let visibility = discover_until_conclusive(downstream, attempt, probe_deadline).await?;
    match resolve_object_write_qualification_after_head(attempt, probe, visibility)
        .await
        .map_err(qualification_error)?
    {
        ObjectWriteQualificationHeadResolution::QualificationUnprovenVisible(committed) => {
            let terminal =
                adopt_object_write_qualification_unproven_visible(authority, attempt, *committed)
                    .map_err(|_| {
                    ApiError::internal("qualification HEAD resolution changed its sealed request")
                })?;
            Ok(QualificationProviderResolution::Terminal(Box::new(
                terminal,
            )))
        }
        ObjectWriteQualificationHeadResolution::Authorized(dispatch) => {
            Ok(QualificationProviderResolution::Authorized(dispatch))
        }
        ObjectWriteQualificationHeadResolution::ConflictingObject => Err(
            ApiError::failed_precondition("provider reported a conflicting immutable object"),
        ),
    }
}

async fn drive_qualification_head_only(
    service: &Arc<GatewayService>,
    authority: ObjectWriteAuthority,
    mut attempt: ObjectPutAttempt,
    deadline: Instant,
) -> Result<ObjectPutAttempt, ApiError> {
    loop {
        match discover_until_conclusive(service.downstream.as_ref(), &attempt, deadline).await? {
            ObjectWriteVisibilityOutcome::VisibleExact {
                provider_attempt_id,
                visibility_receipt_id,
                provider_request,
                preceding_conditional_request,
                observed_at_unix_ms,
            } => {
                let committed = seal_object_write_qualification_ambiguity(
                    &attempt,
                    ObjectWriteVisibilityOutcome::VisibleExact {
                        provider_attempt_id,
                        visibility_receipt_id,
                        provider_request,
                        preceding_conditional_request,
                        observed_at_unix_ms,
                    },
                )
                .map_err(|_| {
                    ApiError::internal("qualification HEAD changed durable response-loss evidence")
                })?;
                let expected =
                    adopt_object_write_qualification_ambiguity(&authority, &attempt, committed)
                        .map_err(|_| {
                            ApiError::internal(
                                "qualification terminal could not adopt sealed evidence",
                            )
                        })?;
                attempt = match service
                    .authority
                    .complete_object_write_qualification_terminal(&authority, &expected)
                    .await
                {
                    Ok(attempt) => attempt,
                    Err(error) if error.code == ErrorCode::Conflict => {
                        let (stored, _) = service
                            .authority
                            .mark_object_write_provider_issued(&attempt.descriptor.request_id)
                            .await?;
                        if !same_qualification_terminal_response_loss(&stored, &expected) {
                            return Err(error);
                        }
                        stored
                    }
                    Err(error) => return Err(error),
                };
                return cleanup_terminal(service, attempt, deadline).await;
            }
            ObjectWriteVisibilityOutcome::NotVisible => retry_delay(deadline).await?,
            ObjectWriteVisibilityOutcome::ConflictingObject => {
                return Err(ApiError::failed_precondition(
                    "qualification HEAD reported a conflicting immutable object",
                ));
            }
        }
    }
}

fn qualification_error(error: QualificationFaultAuthorityError) -> ApiError {
    match error {
        QualificationFaultAuthorityError::DeadlineExceeded => deadline_error(),
        QualificationFaultAuthorityError::NotAuthorized => ApiError::failed_precondition(
            "qualification fault is not authorized by current exact admission",
        ),
        QualificationFaultAuthorityError::Unavailable => {
            ApiError::unavailable("qualification fault authority is unavailable")
        }
        QualificationFaultAuthorityError::Conflict => {
            ApiError::conflict("qualification fault conflicts with durable evidence")
        }
        QualificationFaultAuthorityError::InvalidEvidence => {
            ApiError::internal("qualification fault authority returned invalid evidence")
        }
    }
}

type ObjectWriteTerminalSettlementFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, ApiError>> + Send + 'a>>;

trait ObjectWriteTerminalSettlementAuthority: Send + Sync {
    fn complete_terminal<'a>(
        &'a self,
        request_id: &'a Sha256Digest,
        terminal: &'a ObjectPutTerminalState,
    ) -> ObjectWriteTerminalSettlementFuture<'a, ObjectPutAttempt>;

    fn reread_attempt<'a>(
        &'a self,
        request_id: &'a Sha256Digest,
    ) -> ObjectWriteTerminalSettlementFuture<'a, (ObjectPutAttempt, ObjectWriteAuthority)>;
}

impl ObjectWriteTerminalSettlementAuthority for Arc<ObjectWriteGatewayClient> {
    fn complete_terminal<'a>(
        &'a self,
        request_id: &'a Sha256Digest,
        terminal: &'a ObjectPutTerminalState,
    ) -> ObjectWriteTerminalSettlementFuture<'a, ObjectPutAttempt> {
        Box::pin(self.complete_object_write_terminal(request_id, terminal))
    }

    fn reread_attempt<'a>(
        &'a self,
        request_id: &'a Sha256Digest,
    ) -> ObjectWriteTerminalSettlementFuture<'a, (ObjectPutAttempt, ObjectWriteAuthority)> {
        Box::pin(self.mark_object_write_provider_issued(request_id))
    }
}

async fn settle_terminal<A: ObjectWriteTerminalSettlementAuthority + ?Sized>(
    authority: &A,
    request_id: &Sha256Digest,
    terminal: ObjectPutTerminalState,
) -> Result<ObjectPutAttempt, ApiError> {
    let error = match authority.complete_terminal(request_id, &terminal).await {
        Ok(attempt) => return Ok(attempt),
        Err(error) => error,
    };
    if error.code != ErrorCode::Conflict {
        return Err(error);
    }
    // Two drivers of one accepted attempt are legal: the request path and a
    // replica's recovery sweep both re-drive the identical signed bytes, but
    // each embeds its own receipt ids and timestamps in the terminal outcome,
    // so the slower driver fails the exact-replay guard even though its PUT
    // is durably visible. Surfacing that Conflict turned one durably
    // published strict FLUSH into a Guest-fatal write error. Adopt the stored
    // terminal when it proves the same semantic outcome; a cross-kind
    // divergence stays a loud conflict.
    let (attempt, _) = authority.reread_attempt(request_id).await?;
    adopt_equivalent_terminal(attempt, &terminal, error)
}

/// Answers the stored attempt when its terminal outcome is semantically the
/// one this driver just proved (only driver-local receipt ids and timestamps
/// differ); otherwise returns the original replay conflict unchanged.
fn adopt_equivalent_terminal(
    attempt: ObjectPutAttempt,
    attempted: &ObjectPutTerminalState,
    error: ApiError,
) -> Result<ObjectPutAttempt, ApiError> {
    let ObjectPutState::Terminal { outcome, .. } = &attempt.state else {
        return Err(error);
    };
    let equivalent = matches!(
        (outcome, attempted),
        (
            ObjectPutTerminalState::SucceededVisible {
                qualification_ambiguity: None,
                ..
            },
            ObjectPutTerminalState::SucceededVisible {
                qualification_ambiguity: None,
                ..
            },
        ) | (
            ObjectPutTerminalState::PermanentlyFailed { .. },
            ObjectPutTerminalState::PermanentlyFailed { .. },
        )
    );
    if equivalent {
        return Ok(attempt);
    }
    Err(error)
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
    service
        .authority
        .mark_terminal_object_write_spool_removed(
            &attempt.descriptor.request_id,
            &removal_receipt_id,
        )
        .await
}

fn descriptor_ingress(attempt: &ObjectPutAttempt) -> ObjectWriteIngress {
    ObjectWriteIngress {
        writer_authority_id: attempt.descriptor.writer_authority_id.clone(),
        request_id: attempt.descriptor.request_id.clone(),
        credential: attempt.descriptor.credential.clone(),
        volume_id: attempt.descriptor.volume_id.clone(),
        key: attempt.descriptor.key.clone(),
        target: attempt.descriptor.target.clone(),
        content_sha256: attempt.descriptor.content_sha256.clone(),
        content_length: attempt.descriptor.content_length,
        qualification_fault: attempt.descriptor.qualification_fault.clone(),
        receiving_started_at_unix_ms: attempt.descriptor.accepted_at_unix_ms,
    }
}

fn retained_spool(attempt: &ObjectPutAttempt) -> Option<&DurableObjectWriteSpoolReceipt> {
    match &attempt.state {
        ObjectPutState::AcceptedSpooled { spool }
        | ObjectPutState::ProviderIssued { spool, .. }
        | ObjectPutState::QualificationResponseLost { spool, .. } => Some(spool),
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

fn same_terminal_evidence(stored: &ObjectPutAttempt, expected: &ObjectPutAttempt) -> bool {
    if stored.descriptor != expected.descriptor {
        return false;
    }
    match (&stored.state, &expected.state) {
        (
            ObjectPutState::Terminal {
                outcome: stored, ..
            },
            ObjectPutState::Terminal {
                outcome: expected, ..
            },
        ) => stored == expected,
        _ => false,
    }
}

fn same_qualification_progress(stored: &ObjectPutAttempt, expected: &ObjectPutAttempt) -> bool {
    if stored.descriptor != expected.descriptor {
        return false;
    }
    match (&stored.state, &expected.state) {
        (
            ObjectPutState::QualificationResponseLost {
                response_loss: stored,
                ..
            },
            ObjectPutState::QualificationResponseLost {
                response_loss: expected,
                ..
            },
        ) => stored == expected,
        (
            ObjectPutState::Terminal {
                outcome:
                    ObjectPutTerminalState::SucceededVisible {
                        qualification_ambiguity: Some(stored),
                        ..
                    },
                ..
            },
            ObjectPutState::QualificationResponseLost {
                response_loss: expected,
                ..
            },
        ) => stored.response_loss == **expected,
        (ObjectPutState::Terminal { .. }, ObjectPutState::Terminal { .. }) => {
            same_terminal_evidence(stored, expected)
        }
        _ => false,
    }
}

fn same_qualification_terminal_response_loss(
    stored: &ObjectPutAttempt,
    expected: &ObjectPutAttempt,
) -> bool {
    if stored.descriptor != expected.descriptor {
        return false;
    }
    match (&stored.state, &expected.state) {
        (
            ObjectPutState::Terminal {
                outcome:
                    ObjectPutTerminalState::SucceededVisible {
                        qualification_ambiguity: Some(stored),
                        ..
                    },
                ..
            },
            ObjectPutState::Terminal {
                outcome:
                    ObjectPutTerminalState::SucceededVisible {
                        qualification_ambiguity: Some(expected),
                        ..
                    },
                ..
            },
        ) => stored.response_loss == expected.response_loss,
        _ => false,
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
                match Box::pin(recover_once(&service, false)).await {
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
        let attempts = service
            .authority
            .recoverable_object_write_ingress_attempts(after.as_ref())
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
            if let Err(error) = Box::pin(accept_or_reject(service, stored, deadline)).await {
                if error.code != ErrorCode::Conflict {
                    return Err(anyhow::anyhow!(error));
                }
            }
        }
    }

    let mut after = None;
    loop {
        let attempts = service
            .authority
            .recoverable_object_write_attempts(after.as_ref())
            .await
            .map_err(|error| anyhow::anyhow!(error))?;
        if attempts.is_empty() {
            break;
        }
        for attempt in attempts {
            after = Some(attempt.descriptor.request_id.clone());
            let deadline = Instant::now() + OBJECT_WRITE_GATEWAY_REQUEST_DEADLINE;
            Box::pin(drive_accepted(service, attempt, deadline))
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
            qualification_ambiguity,
        } => ObjectWriteGatewayTerminalReceipt::SucceededVisible {
            put_receipt_id: put_receipt_id.clone(),
            put_completed_at_unix_ms: *put_completed_at_unix_ms,
            visibility_receipt_id: visibility_receipt_id.clone(),
            visible_at_unix_ms: *visible_at_unix_ms,
            qualification_ambiguity: qualification_ambiguity.clone(),
        },
        ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id,
            failed_at_unix_ms,
        } => ObjectWriteGatewayTerminalReceipt::PermanentlyFailed {
            failure_receipt_id: failure_receipt_id.clone(),
            failed_at_unix_ms: *failed_at_unix_ms,
        },
        ObjectPutTerminalState::QualificationUnprovenVisible { receipt } => {
            ObjectWriteGatewayTerminalReceipt::QualificationUnprovenVisible {
                receipt: receipt.clone(),
            }
        }
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

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};

    use cats_api::object_write_gateway::{
        object_write_key, object_write_qualification_unproven_resolution_receipt_id,
        ObjectWriteCredentialReference, ObjectWriteImmutableKey,
        ObjectWriteProviderRequestObservationV1, ObjectWriteQualificationAuthorizationRequestV1,
        ObjectWriteQualificationFaultV1, ObjectWriteQualificationHeadEvidenceV1,
        ObjectWriteQualificationSealedRequestV1, ObjectWriteQualificationUnprovenReasonV1,
        ObjectWriteQualificationUnprovenVisibleReceiptV1,
    };
    use cats_api::runtime_reconciliation::{
        AsciiText, Id, ProviderScope, RandomId128, Sha256Digest, UnixMillis, WireU64,
    };
    use cats_storage::object_write_authority::{
        empty_terminal_prefix_sha256, object_put_provider_attempt_id, object_put_request_id,
        object_write_spool_id, DurableObjectWriteSpoolReceipt, ObjectPutDescriptor,
        ObjectWriteAuthorityState, ObjectWriteDownstreamFuture, ObjectWriteQualificationPut,
        ObjectWriteQualificationPutOutcome, ObjectWriteTarget, ObjectWriterIdentity,
        QualificationFaultAuthority, QualificationFaultAuthorityFuture,
        QualificationFaultAuthorizationGuard, QualificationFaultRequestGuard,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn ascii(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn scope() -> ProviderScope {
        ProviderScope {
            provider: id("object-provider"),
            partition: id("partition-a"),
            account_id: id("account-a"),
            region: id("region-a"),
        }
    }

    fn authority() -> ObjectWriteAuthority {
        ObjectWriteAuthority {
            writer: ObjectWriterIdentity {
                authority_id: id("writer-a"),
                host_provider_scope: scope(),
                immutable_host_id: id("host-a"),
                node_id: id("node-a"),
                object_provider_scope: scope(),
                workload_principal_id: ascii("gateway-role-a"),
                object_store_scope_id: ascii("object-store-scope-a"),
            },
            state: ObjectWriteAuthorityState::Open,
            max_accepted_sequence: WireU64::new(1).unwrap(),
            terminal_prefix_sequence: WireU64::new(0).unwrap(),
            terminal_prefix_sha256: empty_terminal_prefix_sha256(),
        }
    }

    fn issued_fault_attempt(authority: &ObjectWriteAuthority) -> ObjectPutAttempt {
        let volume_id = id("volume-a");
        let key = ObjectWriteImmutableKey::VolumeMap;
        let content_sha256 = Sha256Digest::from_bytes([5; 32]);
        let target = ObjectWriteTarget {
            object_provider_scope: authority.writer.object_provider_scope.clone(),
            object_store_scope_id: authority.writer.object_store_scope_id.clone(),
            canonical_logical_key: object_write_key(&volume_id, &key, &content_sha256).unwrap(),
        };
        let credential = ObjectWriteCredentialReference {
            credential_id: id("credential-a"),
            public_key_spki_sha256: Sha256Digest::from_bytes([2; 32]),
        };
        let fault = ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
            qualification_id: id("qualification-a"),
            fault_id: RandomId128::new("3".repeat(32)).unwrap(),
            qualification_catalog_sha256: Sha256Digest::from_bytes([4; 32]),
        };
        let content_length = WireU64::new(64).unwrap();
        let request_id = object_put_request_id(
            &authority.writer.authority_id,
            &target,
            &volume_id,
            &key,
            &content_sha256,
            content_length,
            Some((&credential, &fault)),
        )
        .unwrap();
        let provider_attempt_id = object_put_provider_attempt_id(&request_id).unwrap();
        let spool = DurableObjectWriteSpoolReceipt {
            spool_id: object_write_spool_id(&request_id).unwrap(),
            request_id: request_id.clone(),
            content_sha256: content_sha256.clone(),
            content_length,
            file_fsync_receipt_id: ascii("file-fsync-a"),
            directory_fsync_receipt_id: ascii("directory-fsync-a"),
            durable_at_unix_ms: millis(10),
        };
        ObjectPutAttempt {
            descriptor: ObjectPutDescriptor {
                writer_authority_id: authority.writer.authority_id.clone(),
                accepted_sequence: WireU64::new(1).unwrap(),
                request_id,
                credential,
                volume_id,
                key,
                target,
                content_sha256,
                content_length,
                qualification_fault: Some(fault),
                provider_attempt_id,
                accepted_at_unix_ms: millis(11),
            },
            state: ObjectPutState::ProviderIssued {
                spool,
                issued_at_unix_ms: millis(12),
            },
        }
    }

    struct VisibleRequestGuard {
        request: ObjectWriteQualificationAuthorizationRequestV1,
        deadline: Instant,
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl QualificationFaultRequestGuard for VisibleRequestGuard {
        fn request(&self) -> &ObjectWriteQualificationAuthorizationRequestV1 {
            &self.request
        }

        fn absolute_deadline(&self) -> Instant {
            self.deadline
        }

        fn durable_resolution(
            &self,
        ) -> Option<&cats_storage::object_write_authority::ObjectWriteQualificationDurableResolution>
        {
            None
        }

        fn commit_unproven_visible<'a>(
            self: Box<Self>,
            sealed_request: ObjectWriteQualificationSealedRequestV1,
            head_evidence: ObjectWriteQualificationHeadEvidenceV1,
        ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
        where
            Self: 'a,
        {
            Box::pin(async move {
                self.events.lock().unwrap().push("commit_unproven");
                let reason = ObjectWriteQualificationUnprovenReasonV1::ResponseLossReceiptAbsent;
                let resolved_at_unix_ms = millis(head_evidence.observed_at_unix_ms.get() + 1);
                let resolution_receipt_id =
                    object_write_qualification_unproven_resolution_receipt_id(
                        &sealed_request,
                        reason,
                        &head_evidence,
                        resolved_at_unix_ms,
                    )
                    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
                Ok(ObjectWriteQualificationUnprovenVisibleReceiptV1 {
                    version: ContractVersion::V1,
                    sealed_request,
                    reason,
                    head_evidence,
                    resolution_receipt_id,
                    resolved_at_unix_ms,
                })
            })
        }

        fn authorize_put<'a>(
            self: Box<Self>,
        ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultAuthorizationGuard + 'a>>
        where
            Self: 'a,
        {
            Box::pin(async { Err(QualificationFaultAuthorityError::NotAuthorized) })
        }
    }

    struct VisibleAuthority {
        events: Arc<Mutex<Vec<&'static str>>>,
    }

    impl QualificationFaultAuthority for VisibleAuthority {
        fn lock_request<'a>(
            &'a self,
            request: ObjectWriteQualificationAuthorizationRequestV1,
            absolute_deadline: Instant,
        ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultRequestGuard + 'a>>
        {
            let events = Arc::clone(&self.events);
            Box::pin(async move {
                events.lock().unwrap().push("resolution_discovery");
                Ok(Box::new(VisibleRequestGuard {
                    request,
                    deadline: absolute_deadline,
                    events,
                })
                    as Box<dyn QualificationFaultRequestGuard>)
            })
        }
    }

    struct VisibleDownstream {
        events: Arc<Mutex<Vec<&'static str>>>,
        visibility: ObjectWriteVisibilityOutcome,
        ordinary_puts: AtomicUsize,
        qualification_puts: AtomicUsize,
    }

    impl ObjectWriteGatewayDownstream for VisibleDownstream {
        fn put_exact<'a>(
            &'a self,
            _request: ObjectWriteDownstreamPut,
            _absolute_deadline: Instant,
        ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteDownstreamPutOutcome> {
            self.ordinary_puts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ObjectWriteDownstreamError::InvalidRequest) })
        }

        fn put_qualification_exact<'a>(
            &'a self,
            _request: &'a ObjectWriteQualificationPut,
        ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteQualificationPutOutcome> {
            self.qualification_puts.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(ObjectWriteDownstreamError::InvalidRequest) })
        }

        fn discover_visibility<'a>(
            &'a self,
            _descriptor: &'a ObjectPutDescriptor,
            _absolute_deadline: Instant,
        ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteVisibilityOutcome> {
            self.events.lock().unwrap().push("head");
            let visibility = self.visibility.clone();
            Box::pin(async move { Ok(visibility) })
        }
    }

    #[tokio::test]
    async fn provider_issued_visible_exact_heads_and_never_reputs() {
        let authority = authority();
        let attempt = issued_fault_attempt(&authority);
        let events = Arc::new(Mutex::new(Vec::new()));
        let fault_authority = VisibleAuthority {
            events: Arc::clone(&events),
        };
        let head = ObjectWriteProviderRequestObservationV1 {
            request_id: ascii("provider-head-request-a"),
            extended_request_id: Some(ascii("provider-head-extended-a")),
            content_sha256: attempt.descriptor.content_sha256.clone(),
            content_length: Some(attempt.descriptor.content_length),
            entity_tag: Some(ascii("entity-tag-a")),
            version_id: Some(ascii("version-a")),
        };
        let downstream = VisibleDownstream {
            events: Arc::clone(&events),
            visibility: ObjectWriteVisibilityOutcome::VisibleExact {
                provider_attempt_id: attempt.descriptor.provider_attempt_id.clone(),
                visibility_receipt_id: ascii("visibility-unproven-a"),
                provider_request: Box::new(head),
                preceding_conditional_request: None,
                observed_at_unix_ms: millis(30),
            },
            ordinary_puts: AtomicUsize::new(0),
            qualification_puts: AtomicUsize::new(0),
        };
        let preparation = prepare_object_write_qualification(
            &fault_authority,
            &attempt,
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();
        let ObjectWriteQualificationPreparation::DiscoverIssuedVisibility(probe) = preparation
        else {
            panic!("ProviderIssued fault skipped mandatory discovery");
        };

        let resolution =
            resolve_issued_qualification_provider(&downstream, &authority, &attempt, probe)
                .await
                .unwrap();
        let QualificationProviderResolution::Terminal(terminal) = resolution else {
            panic!("exact visibility authorized an unexpected re-PUT");
        };
        assert!(matches!(
            terminal.state,
            ObjectPutState::Terminal {
                outcome: ObjectPutTerminalState::QualificationUnprovenVisible { .. },
                ..
            }
        ));
        assert_eq!(
            *events.lock().unwrap(),
            ["resolution_discovery", "head", "commit_unproven"]
        );
        assert_eq!(downstream.ordinary_puts.load(Ordering::SeqCst), 0);
        assert_eq!(downstream.qualification_puts.load(Ordering::SeqCst), 0);
    }

    fn succeeded_visible(tag: &str, at: u64) -> ObjectPutTerminalState {
        ObjectPutTerminalState::SucceededVisible {
            put_receipt_id: ascii(&format!("put-{tag}")),
            put_completed_at_unix_ms: millis(at),
            visibility_receipt_id: ascii(&format!("visibility-{tag}")),
            visible_at_unix_ms: millis(at + 1),
            qualification_ambiguity: None,
        }
    }

    fn terminal_attempt(outcome: ObjectPutTerminalState) -> ObjectPutAttempt {
        let mut attempt = issued_fault_attempt(&authority());
        let spool = match &attempt.state {
            ObjectPutState::ProviderIssued { spool, .. }
            | ObjectPutState::AcceptedSpooled { spool } => spool.clone(),
            other => panic!("fixture state changed: {other:?}"),
        };
        attempt.state = ObjectPutState::Terminal {
            outcome,
            spool: cats_storage::object_write_authority::TerminalObjectWriteSpool::Retained {
                spool,
            },
        };
        attempt
    }

    struct ScriptedTerminalSettlementAuthority {
        completion: Mutex<Option<Result<ObjectPutAttempt, ApiError>>>,
        reread: Mutex<Option<Result<(ObjectPutAttempt, ObjectWriteAuthority), ApiError>>>,
        completion_calls: AtomicUsize,
        reread_calls: AtomicUsize,
    }

    impl ObjectWriteTerminalSettlementAuthority for ScriptedTerminalSettlementAuthority {
        fn complete_terminal<'a>(
            &'a self,
            _request_id: &'a Sha256Digest,
            _terminal: &'a ObjectPutTerminalState,
        ) -> ObjectWriteTerminalSettlementFuture<'a, ObjectPutAttempt> {
            self.completion_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .completion
                .lock()
                .unwrap()
                .take()
                .expect("unexpected second terminal completion");
            Box::pin(async move { result })
        }

        fn reread_attempt<'a>(
            &'a self,
            _request_id: &'a Sha256Digest,
        ) -> ObjectWriteTerminalSettlementFuture<'a, (ObjectPutAttempt, ObjectWriteAuthority)>
        {
            self.reread_calls.fetch_add(1, Ordering::SeqCst);
            let result = self
                .reread
                .lock()
                .unwrap()
                .take()
                .expect("unexpected terminal reread");
            Box::pin(async move { result })
        }
    }

    #[tokio::test]
    async fn settlement_conflict_rereads_and_adopts_the_stored_equivalent_terminal() {
        let stored = terminal_attempt(succeeded_visible("winner", 20));
        let request_id = stored.descriptor.request_id.clone();
        let scripted = ScriptedTerminalSettlementAuthority {
            completion: Mutex::new(Some(Err(ApiError::conflict(
                "object-write gateway state or binding is stale",
            )))),
            reread: Mutex::new(Some(Ok((stored.clone(), authority())))),
            completion_calls: AtomicUsize::new(0),
            reread_calls: AtomicUsize::new(0),
        };

        let adopted = settle_terminal(
            &scripted,
            &request_id,
            succeeded_visible("slower-driver", 25),
        )
        .await
        .expect("equivalent stored terminal must settle the conflict");

        assert_eq!(adopted, stored);
        assert_eq!(scripted.completion_calls.load(Ordering::SeqCst), 1);
        assert_eq!(scripted.reread_calls.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn settlement_preserves_non_conflict_and_reread_authority_errors() {
        let attempt = terminal_attempt(succeeded_visible("stored", 20));
        let request_id = attempt.descriptor.request_id.clone();
        let non_conflict = ScriptedTerminalSettlementAuthority {
            completion: Mutex::new(Some(Err(ApiError::unavailable(
                "terminal authority is unavailable",
            )))),
            reread: Mutex::new(None),
            completion_calls: AtomicUsize::new(0),
            reread_calls: AtomicUsize::new(0),
        };
        let error = settle_terminal(
            &non_conflict,
            &request_id,
            succeeded_visible("attempted", 25),
        )
        .await
        .expect_err("non-conflict completion errors must propagate");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(non_conflict.reread_calls.load(Ordering::SeqCst), 0);

        let reread_failure = ScriptedTerminalSettlementAuthority {
            completion: Mutex::new(Some(Err(ApiError::conflict(
                "object-write gateway state or binding is stale",
            )))),
            reread: Mutex::new(Some(Err(ApiError::unavailable(
                "terminal reread is unavailable",
            )))),
            completion_calls: AtomicUsize::new(0),
            reread_calls: AtomicUsize::new(0),
        };
        let error = settle_terminal(
            &reread_failure,
            &request_id,
            succeeded_visible("attempted", 25),
        )
        .await
        .expect_err("reread authority errors must propagate");
        assert_eq!(error.code, ErrorCode::Unavailable);
        assert_eq!(reread_failure.reread_calls.load(Ordering::SeqCst), 1);
    }

    /// Two drivers of one accepted attempt publish identical bytes but embed
    /// their own receipt ids and timestamps. The slower driver's replay
    /// conflict must adopt the stored equivalent terminal instead of handing
    /// a durably published write back to the writer as a failure.
    #[test]
    fn replayed_terminal_with_equivalent_outcome_adopts_the_stored_receipt() {
        let stored = terminal_attempt(succeeded_visible("winner", 20));
        let adopted = adopt_equivalent_terminal(
            stored.clone(),
            &succeeded_visible("loser", 25),
            ApiError::conflict("object-write gateway state or binding is stale"),
        )
        .expect("equivalent success terminal must be adopted");
        assert_eq!(adopted, stored);

        let failed = terminal_attempt(ObjectPutTerminalState::PermanentlyFailed {
            failure_receipt_id: ascii("failure-winner"),
            failed_at_unix_ms: millis(20),
        });
        let adopted = adopt_equivalent_terminal(
            failed.clone(),
            &ObjectPutTerminalState::PermanentlyFailed {
                failure_receipt_id: ascii("failure-loser"),
                failed_at_unix_ms: millis(26),
            },
            ApiError::conflict("object-write gateway state or binding is stale"),
        )
        .expect("equivalent permanent-failure terminal must be adopted");
        assert_eq!(adopted, failed);
    }

    /// A cross-kind divergence is a real integrity problem and must keep the
    /// loud replay conflict, as must a row that is not terminal at all.
    #[test]
    fn divergent_or_nonterminal_replay_keeps_the_conflict() {
        let conflict = || ApiError::conflict("object-write gateway state or binding is stale");
        let stored = terminal_attempt(succeeded_visible("winner", 20));
        adopt_equivalent_terminal(
            stored,
            &ObjectPutTerminalState::PermanentlyFailed {
                failure_receipt_id: ascii("failure-loser"),
                failed_at_unix_ms: millis(26),
            },
            conflict(),
        )
        .expect_err("cross-kind terminal divergence must stay a conflict");

        let nonterminal = issued_fault_attempt(&authority());
        adopt_equivalent_terminal(nonterminal, &succeeded_visible("loser", 25), conflict())
            .expect_err("a non-terminal row cannot answer a terminal replay");
    }
}
