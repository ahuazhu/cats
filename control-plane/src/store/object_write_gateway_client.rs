//! Dedicated least-privilege PostgreSQL client for the object-write gateway.
//!
//! Production gateway replicas never construct [`super::Store`], run schema
//! DDL, or receive table privileges. Each fresh connection proves the exact
//! login, schema, protocol, and closed function catalog before it is admitted
//! to the bounded synchronous lane below.

use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cats_api::agent_registration::AuthenticatedNodeCredential;
use cats_api::error::ApiError;
use cats_api::object_write_gateway::{
    decode_object_write_qualification_authorization,
    decode_object_write_qualification_response_loss,
    decode_object_write_qualification_unproven_visible_receipt,
    encode_object_write_qualification_authorization, ObjectWriteCredentialReference,
    ObjectWriteCredentialRegistration, ObjectWriteCredentialRegistrationReceipt,
    ObjectWriteIngressDescriptor, ObjectWriteQualificationAuthorizationRequestV1,
    ObjectWriteQualificationAuthorizationV1, ObjectWriteQualificationFaultV1,
    ObjectWriteQualificationHeadEvidenceV1, ObjectWriteQualificationMutationClassV1,
    ObjectWriteQualificationResponseLossV1, ObjectWriteQualificationSealedRequestV1,
    ObjectWriteQualificationUnprovenVisibleReceiptV1, ObjectWriteSuccessfulPutV1,
    OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES,
};
use cats_api::runtime_reconciliation::{
    ContractVersion, CredentialBinding, Epoch, Id, Sha256Digest, UnixMillis, WireU64,
};
use cats_storage::object_write_authority::{
    object_write_qualification_authorization_request, validate_object_put_attempt,
    validate_object_write_authority, validate_object_write_ingress_attempt,
    DurableObjectWriteSpoolReceipt, ObjectPutAttempt, ObjectPutState, ObjectPutTerminalState,
    ObjectWriteAcceptanceOutcome, ObjectWriteAuthority, ObjectWriteIngressAttempt,
    ObjectWriteQualificationDurableResolution, QualificationFaultAuthority,
    QualificationFaultAuthorityError, QualificationFaultAuthorityFuture,
    QualificationFaultAuthorizationGuard, QualificationFaultRequestGuard, StoredObjectWriteAttempt,
};
use postgres::{Client, Row};
use sha2::{Digest, Sha256};

use super::executor::{BlockingExecutor, ExecutionError, Limits, SubmitError};
use super::{internal, schema, DsnSource};

pub const OBJECT_WRITE_GATEWAY_PROTOCOL_VERSION_V1: u16 = 1;
pub const OBJECT_WRITE_GATEWAY_POSTGRES_ROLE: &str = "cats_object_write_gateway";
const OBJECT_WRITE_GATEWAY_INSTALLED_EXECUTABLE_ROUTINES: i64 = 11;
const OBJECT_WRITE_GATEWAY_REQUIRED_EXECUTABLE_ROUTINES: i64 = 12;

const OBJECT_WRITE_GATEWAY_POSTGRES_WORKERS: usize = 2;
const OBJECT_WRITE_GATEWAY_POSTGRES_QUEUE_CAPACITY: usize = 62;
const OBJECT_WRITE_GATEWAY_POSTGRES_IN_FLIGHT: usize =
    OBJECT_WRITE_GATEWAY_POSTGRES_WORKERS + OBJECT_WRITE_GATEWAY_POSTGRES_QUEUE_CAPACITY;

/// One separately authenticated PostgreSQL lane for object-write gateway
/// replicas. This pre-composition leaf attests the installed eleven-routine
/// surface and refuses startup until E13 installs the twelfth qualification
/// lock routine and closes the final catalog.
pub struct ObjectWriteGatewayClient {
    connection: Mutex<Option<OffRuntimeOwned<Client>>>,
    dsn: DsnSource,
    ca_file: Option<String>,
    expected_schema: String,
    executor: Mutex<Option<BlockingExecutor>>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl ObjectWriteGatewayClient {
    pub async fn connect_from_async(
        dsn: DsnSource,
        ca_file: Option<String>,
        expected_schema: String,
    ) -> super::Result<Arc<Self>> {
        validate_schema_name(&expected_schema)?;
        let executor = BlockingExecutor::new(
            "cats-object-write-gateway-pg",
            Limits {
                workers: OBJECT_WRITE_GATEWAY_POSTGRES_WORKERS,
                queue_capacity: OBJECT_WRITE_GATEWAY_POSTGRES_QUEUE_CAPACITY,
                cleanup_capacity: 1,
            },
        )
        .map_err(|error| {
            ApiError::unavailable(format!(
                "start object-write gateway PostgreSQL lane: {error}"
            ))
        })?;
        let startup_dsn = dsn.clone();
        let startup_ca = ca_file.clone();
        let startup_schema = expected_schema.clone();
        let execution = executor
            .try_execute(move || {
                connect_verified_client(&startup_dsn, startup_ca.as_deref(), &startup_schema)
                    .map(OffRuntimeOwned::new)
            })
            .map_err(map_submit_error)?;
        let connection = execution.await.map_err(map_execution_error)??;
        Ok(Arc::new(Self {
            connection: Mutex::new(Some(connection)),
            dsn,
            ca_file,
            expected_schema,
            executor: Mutex::new(Some(executor)),
            admission: Arc::new(tokio::sync::Semaphore::new(
                OBJECT_WRITE_GATEWAY_POSTGRES_IN_FLIGHT,
            )),
        }))
    }

    async fn execute<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut Client, &str) -> super::Result<T> + Send + 'static,
    ) -> super::Result<T> {
        let admission =
            self.admission.clone().try_acquire_owned().map_err(|_| {
                ApiError::unavailable("object-write gateway PostgreSQL queue is full")
            })?;
        let this = Arc::clone(self);
        let execution = {
            let executor = match self.executor.lock() {
                Ok(executor) => executor,
                Err(poisoned) => poisoned.into_inner(),
            };
            let executor = executor.as_ref().ok_or_else(|| {
                ApiError::unavailable("object-write gateway PostgreSQL lane is shutting down")
            })?;
            executor
                .try_execute(move || {
                    let _admission = admission;
                    this.with_connection(operation)
                })
                .map_err(map_submit_error)?
        };
        execution.await.map_err(map_execution_error)?
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Client, &str) -> super::Result<T>,
    ) -> super::Result<T> {
        let mut guard = match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.as_ref().is_none_or(|client| client.is_closed()) {
            drop(guard.take());
            *guard = Some(OffRuntimeOwned::new(connect_verified_client(
                &self.dsn,
                self.ca_file.as_deref(),
                &self.expected_schema,
            )?));
        }
        let client = guard
            .as_mut()
            .ok_or_else(|| internal("object-write PostgreSQL reconnect returned no client"))?;
        let result = operation(client, &self.expected_schema);
        if client.is_closed() {
            drop(guard.take());
        }
        result
    }

    pub async fn register_object_write_credential(
        self: &Arc<Self>,
        authenticated_node: &AuthenticatedNodeCredential,
        authenticated_attachment: &AuthenticatedNodeCredential,
        registration: &ObjectWriteCredentialRegistration,
    ) -> super::Result<ObjectWriteCredentialRegistrationReceipt> {
        let node_credential_id = authenticated_node.credential_id().to_string();
        let node_public_key_sha256 = public_key_digest(authenticated_node)?.to_string();
        let attachment = attachment_reference(authenticated_attachment)?;
        let attachment_json = encode(&attachment, "attachment credential")?;
        let registration_json = encode(registration, "credential registration")?;
        let expected = registration.clone();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT {}.control_object_write_gateway_register_v1($1,$2,$3::TEXT::jsonb,$4::TEXT::jsonb)::TEXT",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(
                    &sql,
                    &[
                        &node_credential_id,
                        &node_public_key_sha256,
                        &attachment_json,
                        &registration_json,
                    ],
                )
                .map_err(map_gateway_postgres_error)?;
            let receipt: ObjectWriteCredentialRegistrationReceipt =
                decode(row.try_get(0).map_err(internal)?, "registration receipt")?;
            if receipt.writer_authority_id != expected.writer_authority_id
                || receipt.volume_id != expected.volume_id
                || receipt.attachment_id != expected.attachment_id
                || receipt.attachment_epoch != expected.attachment_epoch
                || receipt.credential != expected.credential
            {
                return Err(ApiError::failed_precondition(
                    "object-write registration receipt changed its exact binding",
                ));
            }
            Ok(receipt)
        })
        .await
    }

    pub async fn begin_object_write_ingress(
        self: &Arc<Self>,
        authenticated_attachment: &AuthenticatedNodeCredential,
        descriptor: &ObjectWriteIngressDescriptor,
    ) -> super::Result<StoredObjectWriteAttempt> {
        let attachment = attachment_reference(authenticated_attachment)?;
        let attachment_json = encode(&attachment, "attachment credential")?;
        let descriptor_json = encode(descriptor, "object-write ingress descriptor")?;
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_begin_ingress_v1($1::TEXT::jsonb,$2::TEXT::jsonb)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&attachment_json, &descriptor_json])
                .map_err(map_gateway_postgres_error)?;
            decode_stored_attempt(&row)
        })
        .await
    }

    pub async fn mark_object_write_spool_durable(
        self: &Arc<Self>,
        request_id: &Sha256Digest,
        spool: &DurableObjectWriteSpoolReceipt,
    ) -> super::Result<StoredObjectWriteAttempt> {
        let request_id = request_id.to_string();
        let spool_json = encode(spool, "durable spool receipt")?;
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_spool_durable_v1($1,$2::TEXT::jsonb)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&request_id, &spool_json])
                .map_err(map_gateway_postgres_error)?;
            decode_stored_attempt(&row)
        })
        .await
    }

    pub async fn accept_durable_object_write(
        self: &Arc<Self>,
        request_id: &Sha256Digest,
    ) -> super::Result<ObjectWriteAcceptanceOutcome> {
        let request_id = request_id.to_string();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_accept_v1($1)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&request_id])
                .map_err(map_gateway_postgres_error)?;
            match decode_stored_attempt_with_authority(&row)? {
                StoredObjectWriteAttempt::Ingress(attempt) => {
                    Ok(ObjectWriteAcceptanceOutcome::RejectedBeforeAccept(attempt))
                }
                StoredObjectWriteAttempt::Accepted(attempt) => {
                    Ok(ObjectWriteAcceptanceOutcome::Accepted(attempt))
                }
            }
        })
        .await
    }

    pub async fn mark_object_write_provider_issued(
        self: &Arc<Self>,
        request_id: &Sha256Digest,
    ) -> super::Result<(ObjectPutAttempt, ObjectWriteAuthority)> {
        let request_id = request_id.to_string();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_provider_issued_v1($1)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&request_id])
                .map_err(map_gateway_postgres_error)?;
            decode_accepted_attempt_and_authority(&row)
        })
        .await
    }

    pub async fn complete_object_write_terminal(
        self: &Arc<Self>,
        request_id: &Sha256Digest,
        outcome: &ObjectPutTerminalState,
    ) -> super::Result<ObjectPutAttempt> {
        if matches!(
            outcome,
            ObjectPutTerminalState::SucceededVisible {
                qualification_ambiguity: Some(_),
                ..
            } | ObjectPutTerminalState::QualificationUnprovenVisible { .. }
        ) {
            return Err(ApiError::failed_precondition(
                "qualified object-write terminal requires a sealed authority capability",
            ));
        }
        let request_id = request_id.to_string();
        let outcome_canonical = serde_json::to_vec(outcome)
            .map_err(|error| internal(format!("encode object-write terminal outcome: {error}")))?;
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_terminal_v1($1,$2)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&request_id, &outcome_canonical])
                .map_err(map_gateway_postgres_error)?;
            decode_accepted_attempt(&row)
        })
        .await
    }

    pub(crate) async fn complete_object_write_qualification_terminal(
        self: &Arc<Self>,
        expected_authority: &ObjectWriteAuthority,
        expected_attempt: &ObjectPutAttempt,
    ) -> super::Result<ObjectPutAttempt> {
        let ObjectPutState::Terminal {
            outcome:
                ObjectPutTerminalState::SucceededVisible {
                    qualification_ambiguity: Some(_),
                    ..
                },
            ..
        } = &expected_attempt.state
        else {
            return Err(ApiError::failed_precondition(
                "qualified object-write terminal is not sealed success evidence",
            ));
        };
        let request_id = expected_attempt.descriptor.request_id.to_string();
        let outcome = match &expected_attempt.state {
            ObjectPutState::Terminal { outcome, .. } => outcome,
            _ => unreachable!("terminal state matched above"),
        };
        let outcome_canonical = serde_json::to_vec(outcome).map_err(|error| {
            internal(format!("encode qualified object-write terminal: {error}"))
        })?;
        let expected_attempt = expected_attempt.clone();
        let expected_authority = expected_authority.clone();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_terminal_v1($1,$2)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(&sql, &[&request_id, &outcome_canonical])
                .map_err(map_gateway_postgres_error)?;
            let (attempt, authority) = decode_accepted_attempt_and_authority(&row)?;
            let authority_matches = authority.writer == expected_authority.writer
                && authority.state == expected_authority.state
                && authority.max_accepted_sequence == expected_authority.max_accepted_sequence
                && authority.terminal_prefix_sequence
                    >= expected_authority.terminal_prefix_sequence
                && (authority.terminal_prefix_sequence
                    != expected_authority.terminal_prefix_sequence
                    || authority.terminal_prefix_sha256
                        == expected_authority.terminal_prefix_sha256);
            if attempt != expected_attempt || !authority_matches {
                return Err(ApiError::failed_precondition(
                    "qualified object-write terminal persistence changed sealed evidence",
                ));
            }
            Ok(attempt)
        })
        .await
    }

    pub async fn mark_terminal_object_write_spool_removed(
        self: &Arc<Self>,
        request_id: &Sha256Digest,
        removal_receipt_id: &cats_api::runtime_reconciliation::AsciiText,
    ) -> super::Result<ObjectPutAttempt> {
        self.accepted_operation(
            "control_object_write_gateway_spool_removed_v1",
            request_id,
            Some(removal_receipt_id.to_string()),
        )
        .await
    }

    async fn accepted_operation(
        self: &Arc<Self>,
        function: &'static str,
        request_id: &Sha256Digest,
        argument: Option<String>,
    ) -> super::Result<ObjectPutAttempt> {
        let request_id = request_id.to_string();
        self.execute(move |client, schema_name| {
            let schema = quote_schema(schema_name);
            let (sql, parameters): (String, Vec<&(dyn postgres::types::ToSql + Sync)>) =
                match argument.as_ref() {
                    Some(argument) => (
                        format!("SELECT * FROM {schema}.{function}($1,$2)"),
                        vec![&request_id, argument],
                    ),
                    None => (
                        format!("SELECT * FROM {schema}.{function}($1)"),
                        vec![&request_id],
                    ),
                };
            let row = client
                .query_one(&sql, &parameters)
                .map_err(map_gateway_postgres_error)?;
            decode_accepted_attempt(&row)
        })
        .await
    }

    pub async fn recoverable_object_write_ingress_attempts(
        self: &Arc<Self>,
        after_request_id: Option<&Sha256Digest>,
    ) -> super::Result<Vec<ObjectWriteIngressAttempt>> {
        let after = after_request_id.map(ToString::to_string);
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_recover_ingress_v1($1)",
                quote_schema(schema_name)
            );
            client
                .query(&sql, &[&after])
                .map_err(map_gateway_postgres_error)?
                .iter()
                .map(|row| {
                    let attempt: ObjectWriteIngressAttempt = decode(
                        row.try_get("record_json").map_err(internal)?,
                        "ingress attempt",
                    )?;
                    validate_object_write_ingress_attempt(&attempt).map_err(|error| {
                        ApiError::failed_precondition(format!(
                            "object-write recovery returned invalid ingress: {error}"
                        ))
                    })?;
                    Ok(attempt)
                })
                .collect()
        })
        .await
    }

    pub async fn recoverable_object_write_attempts(
        self: &Arc<Self>,
        after_request_id: Option<&Sha256Digest>,
    ) -> super::Result<Vec<ObjectPutAttempt>> {
        let after = after_request_id.map(ToString::to_string);
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_object_write_gateway_recover_accepted_v1($1)",
                quote_schema(schema_name)
            );
            client
                .query(&sql, &[&after])
                .map_err(map_gateway_postgres_error)?
                .iter()
                .map(decode_accepted_attempt)
                .collect()
        })
        .await
    }

    pub fn begin_shutdown(&self) {
        self.admission.close();
        let executor = match self.executor.lock() {
            Ok(executor) => executor,
            Err(poisoned) => poisoned.into_inner(),
        };
        if let Some(executor) = executor.as_ref() {
            executor.begin_shutdown();
        }
    }

    pub async fn shutdown(self: &Arc<Self>) {
        self.begin_shutdown();
        let executor = match self.executor.lock() {
            Ok(mut executor) => executor.take(),
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let this = Arc::clone(self);
        if let Err(error) = tokio::task::spawn_blocking(move || {
            drop(executor);
            let connection = match this.connection.lock() {
                Ok(mut connection) => connection.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            drop(connection);
        })
        .await
        {
            tracing::error!(%error, "join object-write gateway PostgreSQL lane");
        }
    }
}

/// A synchronous owner that can cross an async boundary without ever running
/// its destructor on a Tokio worker. `postgres::Client` owns a private runtime
/// whose destructor blocks; cancellation therefore schedules the final drop
/// on the permanently bounded control PostgreSQL executor.
struct OffRuntimeOwned<T: Send + 'static> {
    value: Option<T>,
}

impl<T: Send + 'static> OffRuntimeOwned<T> {
    fn new(value: T) -> Self {
        Self { value: Some(value) }
    }
}

impl<T: Send + 'static> Deref for OffRuntimeOwned<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.value
            .as_ref()
            .expect("off-runtime owner retains its value until drop")
    }
}

impl<T: Send + 'static> DerefMut for OffRuntimeOwned<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.value
            .as_mut()
            .expect("off-runtime owner retains its value until drop")
    }
}

impl<T: Send + 'static> Drop for OffRuntimeOwned<T> {
    fn drop(&mut self) {
        if let Some(value) = self.value.take() {
            super::drop_on_normal_executor(value);
        }
    }
}

struct QualificationSession {
    client: Client,
    // Keep the connection budget until the off-runtime destructor has
    // actually closed the PostgreSQL session and released its transaction
    // locks, not merely until an async guard has queued that destructor.
    _admission: tokio::sync::OwnedSemaphorePermit,
}

impl Deref for QualificationSession {
    type Target = Client;

    fn deref(&self) -> &Self::Target {
        &self.client
    }
}

impl DerefMut for QualificationSession {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.client
    }
}

struct PostgresQualificationTransaction {
    client: Option<OffRuntimeOwned<QualificationSession>>,
    schema_name: String,
    request: ObjectWriteQualificationAuthorizationRequestV1,
    request_canonical: Vec<u8>,
    absolute_deadline: Instant,
}

struct PostgresQualificationRequestGuard {
    transaction: PostgresQualificationTransaction,
    durable_resolution: Option<ObjectWriteQualificationDurableResolution>,
}

struct PostgresQualificationAuthorizationGuard {
    transaction: PostgresQualificationTransaction,
    authorization: ObjectWriteQualificationAuthorizationV1,
}

impl QualificationFaultRequestGuard for PostgresQualificationRequestGuard {
    fn request(&self) -> &ObjectWriteQualificationAuthorizationRequestV1 {
        &self.transaction.request
    }

    fn absolute_deadline(&self) -> Instant {
        self.transaction.absolute_deadline
    }

    fn durable_resolution(&self) -> Option<&ObjectWriteQualificationDurableResolution> {
        self.durable_resolution.as_ref()
    }

    fn commit_unproven_visible<'a>(
        self: Box<Self>,
        sealed_request: ObjectWriteQualificationSealedRequestV1,
        head_evidence: ObjectWriteQualificationHeadEvidenceV1,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
    where
        Self: 'a,
    {
        let Self {
            transaction,
            durable_resolution,
        } = *self;
        Box::pin(async move {
            if durable_resolution.is_some() {
                return Err(QualificationFaultAuthorityError::Conflict);
            }
            commit_qualification_unproven(
                transaction,
                sealed_request,
                head_evidence,
                QualificationUnprovenSource::IssuedVisibility,
                None,
            )
            .await
        })
    }

    fn authorize_put<'a>(
        self: Box<Self>,
    ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultAuthorizationGuard + 'a>>
    where
        Self: 'a,
    {
        let Self {
            mut transaction,
            durable_resolution,
        } = *self;
        Box::pin(async move {
            if durable_resolution.is_some() {
                return Err(QualificationFaultAuthorityError::Conflict);
            }
            let mut client = transaction
                .client
                .take()
                .ok_or(QualificationFaultAuthorityError::Unavailable)?;
            let schema_name = transaction.schema_name.clone();
            let request = transaction.request.clone();
            let request_canonical = transaction.request_canonical.clone();
            let request_deadline = transaction.absolute_deadline;
            let result = tokio::task::spawn_blocking(move || {
                configure_qualification_transaction_deadline(&mut client, request_deadline)?;
                let authorization = match query_qualification_lock(
                    &mut client,
                    &schema_name,
                    &request,
                    &request_canonical,
                ) {
                    Ok(authorization) => authorization,
                    Err(error) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(error);
                    }
                };
                let database_clock_anchor = Instant::now();
                let database_now = match qualification_database_now(&mut client) {
                    Ok(now) => now,
                    Err(error) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(error);
                    }
                };
                let absolute_deadline = match clamp_qualification_deadline(
                    request_deadline,
                    authorization.qualification_expires_at_unix_ms,
                    database_now,
                    database_clock_anchor,
                ) {
                    Ok(deadline) => deadline,
                    Err(error) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(error);
                    }
                };
                configure_qualification_transaction_deadline(&mut client, absolute_deadline)?;
                Ok((client, authorization, absolute_deadline))
            })
            .await
            .map_err(|_| QualificationFaultAuthorityError::Unavailable)?;
            let (client, authorization, absolute_deadline) = result?;
            transaction.client = Some(client);
            transaction.absolute_deadline = absolute_deadline;
            Ok(Box::new(PostgresQualificationAuthorizationGuard {
                transaction,
                authorization,
            })
                as Box<dyn QualificationFaultAuthorizationGuard>)
        })
    }
}

impl QualificationFaultAuthorizationGuard for PostgresQualificationAuthorizationGuard {
    fn authorization(&self) -> &ObjectWriteQualificationAuthorizationV1 {
        &self.authorization
    }

    fn absolute_deadline(&self) -> Instant {
        self.transaction.absolute_deadline
    }

    fn commit_response_loss<'a>(
        self: Box<Self>,
        successful_put: ObjectWriteSuccessfulPutV1,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationResponseLossV1>
    where
        Self: 'a,
    {
        let Self {
            mut transaction,
            authorization: expected_authorization,
        } = *self;
        Box::pin(async move {
            let mut client = transaction
                .client
                .take()
                .ok_or(QualificationFaultAuthorityError::Unavailable)?;
            let schema_name = transaction.schema_name;
            let request_canonical = transaction.request_canonical;
            let absolute_deadline = transaction.absolute_deadline;
            tokio::task::spawn_blocking(move || {
                configure_qualification_transaction_deadline(&mut client, absolute_deadline)?;
                let successful_put_canonical = serde_json::to_vec(&successful_put)
                    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
                let row = match query_qualification_response_loss(
                    &mut client,
                    &schema_name,
                    &request_canonical,
                    Some(&successful_put_canonical),
                ) {
                    Ok(row) => row,
                    Err(error) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(error);
                    }
                };
                let resolution = match decode_qualification_resolution_row(row) {
                    Ok(Some(resolution)) => resolution,
                    Ok(None) | Err(_) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(QualificationFaultAuthorityError::InvalidEvidence);
                    }
                };
                let ObjectWriteQualificationResolution::ResponseLoss {
                    attempt,
                    authorization,
                    response_loss,
                } = resolution
                else {
                    rollback_qualification_transaction(&mut client);
                    return Err(QualificationFaultAuthorityError::Conflict);
                };
                if *authorization != expected_authorization
                    || response_loss.authorization != expected_authorization
                    || response_loss.successful_put != successful_put
                    || !attempt_contains_response_loss(&attempt, &response_loss)
                {
                    rollback_qualification_transaction(&mut client);
                    return Err(QualificationFaultAuthorityError::InvalidEvidence);
                }
                commit_qualification_transaction(
                    &mut client,
                    absolute_deadline,
                    Some(expected_authorization.qualification_expires_at_unix_ms),
                )?;
                Ok(*response_loss)
            })
            .await
            .map_err(|_| QualificationFaultAuthorityError::Unavailable)?
        })
    }

    fn commit_unproven_visible<'a>(
        self: Box<Self>,
        sealed_request: ObjectWriteQualificationSealedRequestV1,
        head_evidence: ObjectWriteQualificationHeadEvidenceV1,
    ) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1>
    where
        Self: 'a,
    {
        let Self {
            transaction,
            authorization,
        } = *self;
        commit_qualification_unproven(
            transaction,
            sealed_request,
            head_evidence,
            QualificationUnprovenSource::AuthorizedPrecondition,
            Some(authorization.qualification_expires_at_unix_ms),
        )
    }
}

impl QualificationFaultAuthority for ObjectWriteGatewayClient {
    fn lock_request<'a>(
        &'a self,
        request: ObjectWriteQualificationAuthorizationRequestV1,
        absolute_deadline: Instant,
    ) -> QualificationFaultAuthorityFuture<'a, Box<dyn QualificationFaultRequestGuard + 'a>> {
        Box::pin(async move {
            if Instant::now() >= absolute_deadline {
                return Err(QualificationFaultAuthorityError::DeadlineExceeded);
            }
            let request_canonical = encode_qualification_request(&request)?;
            let expected_request = request.clone();
            let admission = self
                .admission
                .clone()
                .try_acquire_owned()
                .map_err(|_| QualificationFaultAuthorityError::Unavailable)?;
            let dsn = self.dsn.clone();
            let ca_file = self.ca_file.clone();
            let schema_name = self.expected_schema.clone();
            let guard = tokio::task::spawn_blocking(move || {
                let mut client = OffRuntimeOwned::new(QualificationSession {
                    client: connect_verified_client(&dsn, ca_file.as_deref(), &schema_name)
                        .map_err(map_api_qualification_error)?,
                    _admission: admission,
                });
                client
                    .batch_execute("BEGIN ISOLATION LEVEL READ COMMITTED")
                    .map_err(|error| map_qualification_postgres_error(&error))?;
                configure_qualification_transaction_deadline(&mut client, absolute_deadline)?;
                if let Err(error) =
                    lock_qualification_request(&mut client, expected_request.request_id.as_str())
                {
                    rollback_qualification_transaction(&mut client);
                    return Err(error);
                }
                let row = query_qualification_response_loss(
                    &mut client,
                    &schema_name,
                    &request_canonical,
                    None,
                )?;
                let resolution = match decode_qualification_resolution_row(row) {
                    Ok(resolution) => resolution,
                    Err(error) => {
                        rollback_qualification_transaction(&mut client);
                        return Err(error);
                    }
                };
                if resolution
                    .as_ref()
                    .is_some_and(|resolution| resolution.request() != &expected_request)
                {
                    rollback_qualification_transaction(&mut client);
                    return Err(QualificationFaultAuthorityError::InvalidEvidence);
                }
                if Instant::now() >= absolute_deadline {
                    rollback_qualification_transaction(&mut client);
                    return Err(QualificationFaultAuthorityError::DeadlineExceeded);
                }
                Ok(PostgresQualificationRequestGuard {
                    transaction: PostgresQualificationTransaction {
                        client: Some(client),
                        schema_name,
                        request: expected_request,
                        request_canonical,
                        absolute_deadline,
                    },
                    durable_resolution: resolution.map(|resolution| resolution.into_durable()),
                })
            })
            .await
            .map_err(|_| QualificationFaultAuthorityError::Unavailable)??;
            Ok(Box::new(guard) as Box<dyn QualificationFaultRequestGuard>)
        })
    }
}

enum ObjectWriteQualificationResolution {
    ResponseLoss {
        attempt: Box<ObjectPutAttempt>,
        authorization: Box<ObjectWriteQualificationAuthorizationV1>,
        response_loss: Box<ObjectWriteQualificationResponseLossV1>,
    },
    UnprovenVisible {
        receipt: Box<ObjectWriteQualificationUnprovenVisibleReceiptV1>,
    },
}

impl ObjectWriteQualificationResolution {
    fn request(&self) -> &ObjectWriteQualificationAuthorizationRequestV1 {
        match self {
            Self::ResponseLoss { authorization, .. } => &authorization.request,
            Self::UnprovenVisible { receipt, .. } => &receipt.sealed_request.authorization_request,
        }
    }

    fn into_durable(self) -> ObjectWriteQualificationDurableResolution {
        match self {
            Self::ResponseLoss { response_loss, .. } => {
                ObjectWriteQualificationDurableResolution::ResponseLoss(response_loss)
            }
            Self::UnprovenVisible { receipt, .. } => {
                ObjectWriteQualificationDurableResolution::UnprovenVisible(receipt)
            }
        }
    }
}

fn commit_qualification_unproven<'a>(
    mut transaction: PostgresQualificationTransaction,
    sealed_request: ObjectWriteQualificationSealedRequestV1,
    head_evidence: ObjectWriteQualificationHeadEvidenceV1,
    source: QualificationUnprovenSource,
    qualification_expires_at: Option<UnixMillis>,
) -> QualificationFaultAuthorityFuture<'a, ObjectWriteQualificationUnprovenVisibleReceiptV1> {
    Box::pin(async move {
        if transaction.request != sealed_request.authorization_request {
            return Err(QualificationFaultAuthorityError::InvalidEvidence);
        }
        let mut client = transaction
            .client
            .take()
            .ok_or(QualificationFaultAuthorityError::Unavailable)?;
        let schema_name = transaction.schema_name;
        let request_id = transaction.request.request_id.to_string();
        let absolute_deadline = transaction.absolute_deadline;
        tokio::task::spawn_blocking(move || {
            configure_qualification_transaction_deadline(&mut client, absolute_deadline)?;
            let intent = QualificationUnprovenVisibleIntent {
                kind: "qualification_unproven_visible_intent",
                source,
                sealed_request: &sealed_request,
                head_evidence: &head_evidence,
            };
            let intent_canonical = serde_json::to_vec(&intent)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            let row = match query_qualification_terminal(
                &mut client,
                &schema_name,
                &request_id,
                &intent_canonical,
            ) {
                Ok(row) => row,
                Err(error) => {
                    rollback_qualification_transaction(&mut client);
                    return Err(error);
                }
            };
            let (attempt, _) = decode_accepted_attempt_and_authority(&row)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            let ObjectPutState::Terminal {
                outcome: ObjectPutTerminalState::QualificationUnprovenVisible { receipt },
                ..
            } = attempt.state
            else {
                rollback_qualification_transaction(&mut client);
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            };
            if receipt.sealed_request != sealed_request || receipt.head_evidence != head_evidence {
                rollback_qualification_transaction(&mut client);
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            }
            let canonical = serde_json::to_vec(receipt.as_ref())
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            let receipt = decode_object_write_qualification_unproven_visible_receipt(&canonical)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            commit_qualification_transaction(
                &mut client,
                absolute_deadline,
                qualification_expires_at,
            )?;
            Ok(receipt)
        })
        .await
        .map_err(|_| QualificationFaultAuthorityError::Unavailable)?
    })
}

#[derive(serde::Serialize)]
struct QualificationUnprovenVisibleIntent<'a> {
    kind: &'static str,
    source: QualificationUnprovenSource,
    sealed_request: &'a ObjectWriteQualificationSealedRequestV1,
    head_evidence: &'a ObjectWriteQualificationHeadEvidenceV1,
}

#[derive(Clone, Copy, serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum QualificationUnprovenSource {
    IssuedVisibility,
    AuthorizedPrecondition,
}

struct QualificationResponseRow {
    found: bool,
    attempt_canonical: Option<Vec<u8>>,
    authorization_canonical: Option<Vec<u8>>,
    response_loss_canonical: Option<Vec<u8>>,
}

fn query_qualification_response_loss(
    client: &mut Client,
    schema_name: &str,
    request_canonical: &[u8],
    successful_put_canonical: Option<&[u8]>,
) -> Result<QualificationResponseRow, QualificationFaultAuthorityError> {
    let sql = format!(
        "SELECT * FROM {}.control_object_write_gateway_qualification_response_lost_v1($1,$2)",
        quote_schema(schema_name)
    );
    let row = client
        .query_one(&sql, &[&request_canonical, &successful_put_canonical])
        .map_err(|error| map_qualification_postgres_error(&error))?;
    Ok(QualificationResponseRow {
        found: row
            .try_get("found")
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
        attempt_canonical: row
            .try_get("attempt_canonical")
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
        authorization_canonical: row
            .try_get("authorization_canonical")
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
        response_loss_canonical: row
            .try_get("response_loss_canonical")
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
    })
}

fn decode_qualification_resolution_row(
    row: QualificationResponseRow,
) -> Result<Option<ObjectWriteQualificationResolution>, QualificationFaultAuthorityError> {
    if !row.found {
        if row.attempt_canonical.is_some()
            || row.authorization_canonical.is_some()
            || row.response_loss_canonical.is_some()
        {
            return Err(QualificationFaultAuthorityError::InvalidEvidence);
        }
        return Ok(None);
    }
    let attempt_bytes = row
        .attempt_canonical
        .ok_or(QualificationFaultAuthorityError::InvalidEvidence)?;
    let attempt: ObjectPutAttempt = serde_json::from_slice(&attempt_bytes)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if serde_json::to_vec(&attempt)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?
        != attempt_bytes
    {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    match (row.authorization_canonical, row.response_loss_canonical) {
        (Some(authorization_bytes), Some(response_loss_bytes)) => {
            let authorization =
                decode_object_write_qualification_authorization(&authorization_bytes)
                    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            let response_loss =
                decode_object_write_qualification_response_loss(&response_loss_bytes)
                    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            if response_loss.authorization != authorization
                || !attempt_contains_response_loss(&attempt, &response_loss)
            {
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            }
            Ok(Some(ObjectWriteQualificationResolution::ResponseLoss {
                attempt: Box::new(attempt),
                authorization: Box::new(authorization),
                response_loss: Box::new(response_loss),
            }))
        }
        (None, None) => {
            let ObjectPutState::Terminal {
                outcome: ObjectPutTerminalState::QualificationUnprovenVisible { receipt },
                ..
            } = &attempt.state
            else {
                return Err(QualificationFaultAuthorityError::InvalidEvidence);
            };
            let canonical = serde_json::to_vec(receipt.as_ref())
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            let receipt = decode_object_write_qualification_unproven_visible_receipt(&canonical)
                .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
            Ok(Some(ObjectWriteQualificationResolution::UnprovenVisible {
                receipt: Box::new(receipt),
            }))
        }
        _ => Err(QualificationFaultAuthorityError::InvalidEvidence),
    }
}

fn query_qualification_terminal(
    client: &mut Client,
    schema_name: &str,
    request_id: &str,
    intent_canonical: &[u8],
) -> Result<Row, QualificationFaultAuthorityError> {
    let sql = format!(
        "SELECT * FROM {}.control_object_write_gateway_terminal_v1($1,$2)",
        quote_schema(schema_name)
    );
    client
        .query_one(&sql, &[&request_id, &intent_canonical])
        .map_err(|error| map_qualification_postgres_error(&error))
}

fn query_qualification_lock(
    client: &mut Client,
    schema_name: &str,
    request: &ObjectWriteQualificationAuthorizationRequestV1,
    request_canonical: &[u8],
) -> Result<ObjectWriteQualificationAuthorizationV1, QualificationFaultAuthorityError> {
    let ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
        qualification_id,
        fault_id,
        qualification_catalog_sha256,
    } = &request.fault;
    let version = 1_i64;
    let mutation_class = "object_write_ambiguity";
    let fault_kind = "successful_put_response_loss";
    let request_id = request.request_id.to_string();
    let writer_authority_id = request.writer_authority_id.to_string();
    let credential_id = request.credential.credential_id.to_string();
    let credential_public_key_spki_sha256 = request.credential.public_key_spki_sha256.to_string();
    let provider_attempt_id = request.provider_attempt_id.to_string();
    let qualification_id = qualification_id.to_string();
    let fault_id = fault_id.to_string();
    let fault_catalog = qualification_catalog_sha256.to_string();
    let provider = request.object_provider_scope.provider.to_string();
    let partition = request.object_provider_scope.partition.to_string();
    let account_id = request.object_provider_scope.account_id.to_string();
    let region = request.object_provider_scope.region.to_string();
    let object_store_scope_id = request.object_store_scope_id.to_string();
    let content_sha256 = request.content_sha256.to_string();
    let content_length = i64::try_from(request.content_length.get())
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    let sql = format!(
        "SELECT * FROM {}.control_object_write_gateway_qualification_lock_v1(\
         $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20)",
        quote_schema(schema_name)
    );
    let row = client
        .query_one(
            &sql,
            &[
                &request_canonical,
                &version,
                &mutation_class,
                &request_id,
                &writer_authority_id,
                &credential_id,
                &credential_public_key_spki_sha256,
                &provider_attempt_id,
                &fault_kind,
                &qualification_id,
                &fault_id,
                &fault_catalog,
                &provider,
                &partition,
                &account_id,
                &region,
                &object_store_scope_id,
                &request.canonical_logical_key,
                &content_sha256,
                &content_length,
            ],
        )
        .map_err(|error| map_qualification_postgres_error(&error))?;
    decode_qualification_authorization_row(&row, request, request_canonical)
}

fn decode_qualification_authorization_row(
    row: &Row,
    request: &ObjectWriteQualificationAuthorizationRequestV1,
    request_canonical: &[u8],
) -> Result<ObjectWriteQualificationAuthorizationV1, QualificationFaultAuthorityError> {
    let returned_request: Vec<u8> = row
        .try_get("request_canonical")
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    let canonical: Vec<u8> = row
        .try_get("authorization_canonical")
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if returned_request != request_canonical {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    let authorization = ObjectWriteQualificationAuthorizationV1 {
        version: parse_contract_version(row, "authorization_version")?,
        mutation_class: parse_mutation_class(row, "authorization_mutation_class")?,
        qualification_id: parse_id(row, "qualification_id")?,
        workspace_id: parse_id(row, "workspace_id")?,
        deployment_id: parse_id(row, "deployment_id")?,
        release_id: parse_id(row, "release_id")?,
        source_commit_sha: row
            .try_get("source_commit_sha")
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
        control_schema_version: parse_wire_u64(row, "control_schema_version")?,
        qualification_catalog_sha256: parse_sha256(row, "qualification_catalog_sha256")?,
        admission_binding_sha256: parse_sha256(row, "admission_binding_sha256")?,
        admission_revision: parse_epoch(row, "admission_revision")?,
        request: request.clone(),
        authorized_at_unix_ms: parse_unix_millis(row, "authorized_at_unix_ms")?,
        qualification_expires_at_unix_ms: parse_unix_millis(
            row,
            "qualification_expires_at_unix_ms",
        )?,
    };
    let decoded = decode_object_write_qualification_authorization(&canonical)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if decoded != authorization
        || encode_object_write_qualification_authorization(&authorization)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?
            != canonical
    {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    Ok(authorization)
}

fn encode_qualification_request(
    request: &ObjectWriteQualificationAuthorizationRequestV1,
) -> Result<Vec<u8>, QualificationFaultAuthorityError> {
    let bytes = serde_json::to_vec(request)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    if bytes.len() > OBJECT_WRITE_QUALIFICATION_AUTHORIZATION_MAX_BYTES {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    Ok(bytes)
}

fn configure_qualification_transaction_deadline(
    client: &mut Client,
    absolute_deadline: Instant,
) -> Result<(), QualificationFaultAuthorityError> {
    let remaining = absolute_deadline
        .checked_duration_since(Instant::now())
        .ok_or(QualificationFaultAuthorityError::DeadlineExceeded)?;
    let milliseconds = qualification_timeout_millis(remaining)?;
    set_qualification_transaction_timeouts(client, milliseconds)
}

fn configure_qualification_commit_deadline(
    client: &mut Client,
    absolute_deadline: Instant,
) -> Result<(), QualificationFaultAuthorityError> {
    let remaining = absolute_deadline
        .checked_duration_since(Instant::now())
        .ok_or(QualificationFaultAuthorityError::DeadlineExceeded)?;
    let milliseconds = qualification_commit_timeout_millis(remaining)?;
    set_qualification_transaction_timeouts(client, milliseconds)?;
    let remaining_after_configuration = absolute_deadline
        .checked_duration_since(Instant::now())
        .ok_or(QualificationFaultAuthorityError::DeadlineExceeded)?;
    if remaining_after_configuration.as_millis() <= milliseconds as u128 {
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    Ok(())
}

fn set_qualification_transaction_timeouts(
    client: &mut Client,
    milliseconds: i64,
) -> Result<(), QualificationFaultAuthorityError> {
    let timeout = format!("{milliseconds}ms");
    client
        .query_one(
            "SELECT pg_catalog.set_config('statement_timeout',$1,TRUE),
                    pg_catalog.set_config('lock_timeout',$1,TRUE),
                    pg_catalog.set_config('idle_in_transaction_session_timeout',$1,TRUE)",
            &[&timeout],
        )
        .map_err(|error| map_qualification_postgres_error(&error))?;
    Ok(())
}

fn qualification_timeout_millis(
    remaining: Duration,
) -> Result<i64, QualificationFaultAuthorityError> {
    let milliseconds = remaining.as_millis();
    if milliseconds == 0 {
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    Ok(milliseconds.min(i64::MAX as u128) as i64)
}

fn qualification_commit_timeout_millis(
    remaining: Duration,
) -> Result<i64, QualificationFaultAuthorityError> {
    let milliseconds = qualification_timeout_millis(remaining)? / 2;
    if milliseconds == 0 {
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    Ok(milliseconds)
}

/// Recheck both clocks after the resolution routine has returned, then give
/// COMMIT only the newly measured remainder. A successful COMMIT whose reply
/// arrives after the sealed bound is deliberately reported as ambiguous; the
/// next request discovers the durable resolution under the request lock.
fn commit_qualification_transaction(
    client: &mut Client,
    absolute_deadline: Instant,
    qualification_expires_at: Option<UnixMillis>,
) -> Result<(), QualificationFaultAuthorityError> {
    let mut commit_deadline = absolute_deadline;
    if let Some(qualification_expires_at) = qualification_expires_at {
        if let Err(error) = configure_qualification_transaction_deadline(client, commit_deadline) {
            rollback_qualification_transaction(client);
            return Err(error);
        }
        let database_clock_anchor = Instant::now();
        let database_now = match qualification_database_now(client) {
            Ok(database_now) => database_now,
            Err(error) => {
                rollback_qualification_transaction(client);
                return Err(error);
            }
        };
        commit_deadline = match clamp_qualification_deadline(
            commit_deadline,
            qualification_expires_at,
            database_now,
            database_clock_anchor,
        ) {
            Ok(deadline) => deadline,
            Err(error) => {
                rollback_qualification_transaction(client);
                return Err(error);
            }
        };
    }
    if let Err(error) = configure_qualification_commit_deadline(client, commit_deadline) {
        rollback_qualification_transaction(client);
        return Err(error);
    }
    if Instant::now() >= commit_deadline {
        rollback_qualification_transaction(client);
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    client
        .batch_execute("COMMIT")
        .map_err(|error| map_qualification_postgres_error(&error))?;
    if Instant::now() >= commit_deadline {
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    Ok(())
}

fn lock_qualification_request(
    client: &mut Client,
    request_id: &str,
) -> Result<(), QualificationFaultAuthorityError> {
    let lock_key = qualification_request_lock_key(request_id)?;
    client
        .query_one("SELECT pg_catalog.pg_advisory_xact_lock($1)", &[&lock_key])
        .map_err(|error| map_qualification_postgres_error(&error))?;
    Ok(())
}

fn qualification_request_lock_key(
    request_id: &str,
) -> Result<i64, QualificationFaultAuthorityError> {
    if !request_id.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    }) {
        return Err(QualificationFaultAuthorityError::InvalidEvidence);
    }
    let mut hasher = Sha256::new();
    hasher.update(b"cats.object-write-qualification-request-lock.v1");
    hasher.update([0]);
    hasher.update(request_id.as_bytes());
    let digest = hasher.finalize();
    let mut key = [0_u8; 8];
    key.copy_from_slice(&digest[..8]);
    Ok(i64::from_be_bytes(key))
}

fn qualification_database_now(
    client: &mut Client,
) -> Result<UnixMillis, QualificationFaultAuthorityError> {
    let value: i64 = client
        .query_one(
            "SELECT pg_catalog.floor(
                pg_catalog.extract(epoch FROM pg_catalog.clock_timestamp()) * 1000
            )::BIGINT",
            &[],
        )
        .map_err(|error| map_qualification_postgres_error(&error))?
        .try_get(0)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    let value =
        u64::try_from(value).map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?;
    UnixMillis::new(value).ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn clamp_qualification_deadline(
    request_deadline: Instant,
    qualification_expires_at: UnixMillis,
    database_now: UnixMillis,
    database_clock_anchor: Instant,
) -> Result<Instant, QualificationFaultAuthorityError> {
    let remaining_millis = qualification_expires_at
        .get()
        .checked_sub(database_now.get())
        .filter(|remaining| *remaining > 0)
        .ok_or(QualificationFaultAuthorityError::NotAuthorized)?;
    let expiry_deadline = database_clock_anchor
        .checked_add(Duration::from_millis(remaining_millis))
        .ok_or(QualificationFaultAuthorityError::InvalidEvidence)?;
    let deadline = std::cmp::min(request_deadline, expiry_deadline);
    let now = Instant::now();
    if now >= deadline {
        return Err(QualificationFaultAuthorityError::DeadlineExceeded);
    }
    Ok(deadline)
}

fn attempt_contains_response_loss(
    attempt: &ObjectPutAttempt,
    expected: &ObjectWriteQualificationResponseLossV1,
) -> bool {
    if object_write_qualification_authorization_request(&attempt.descriptor)
        .ok()
        .flatten()
        .as_ref()
        != Some(&expected.authorization.request)
    {
        return false;
    }
    match &attempt.state {
        cats_storage::object_write_authority::ObjectPutState::QualificationResponseLost {
            response_loss,
            ..
        } => response_loss.as_ref() == expected,
        cats_storage::object_write_authority::ObjectPutState::Terminal {
            outcome:
                ObjectPutTerminalState::SucceededVisible {
                    qualification_ambiguity: Some(receipt),
                    ..
                },
            ..
        } => receipt.response_loss == *expected,
        _ => false,
    }
}

fn parse_contract_version(
    row: &Row,
    column: &str,
) -> Result<ContractVersion, QualificationFaultAuthorityError> {
    match row
        .try_get::<_, i64>(column)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?
    {
        1 => Ok(ContractVersion::V1),
        _ => Err(QualificationFaultAuthorityError::InvalidEvidence),
    }
}

fn parse_mutation_class(
    row: &Row,
    column: &str,
) -> Result<ObjectWriteQualificationMutationClassV1, QualificationFaultAuthorityError> {
    match row
        .try_get::<_, String>(column)
        .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?
        .as_str()
    {
        "object_write_ambiguity" => {
            Ok(ObjectWriteQualificationMutationClassV1::ObjectWriteAmbiguity)
        }
        _ => Err(QualificationFaultAuthorityError::InvalidEvidence),
    }
}

fn parse_id(row: &Row, column: &str) -> Result<Id, QualificationFaultAuthorityError> {
    Id::new(
        row.try_get::<_, String>(column)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
    )
    .ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn parse_sha256(row: &Row, column: &str) -> Result<Sha256Digest, QualificationFaultAuthorityError> {
    Sha256Digest::new(
        row.try_get::<_, String>(column)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
    )
    .ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn parse_u64(row: &Row, column: &str) -> Result<u64, QualificationFaultAuthorityError> {
    u64::try_from(
        row.try_get::<_, i64>(column)
            .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)?,
    )
    .map_err(|_| QualificationFaultAuthorityError::InvalidEvidence)
}

fn parse_wire_u64(row: &Row, column: &str) -> Result<WireU64, QualificationFaultAuthorityError> {
    WireU64::new(parse_u64(row, column)?).ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn parse_epoch(row: &Row, column: &str) -> Result<Epoch, QualificationFaultAuthorityError> {
    Epoch::new(parse_u64(row, column)?).ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn parse_unix_millis(
    row: &Row,
    column: &str,
) -> Result<UnixMillis, QualificationFaultAuthorityError> {
    UnixMillis::new(parse_u64(row, column)?)
        .ok_or(QualificationFaultAuthorityError::InvalidEvidence)
}

fn rollback_qualification_transaction(client: &mut Client) {
    let _ = client.batch_execute("ROLLBACK");
}

fn map_api_qualification_error(error: ApiError) -> QualificationFaultAuthorityError {
    match error.code {
        cats_api::error::ErrorCode::DeadlineExceeded => {
            QualificationFaultAuthorityError::DeadlineExceeded
        }
        cats_api::error::ErrorCode::Unauthenticated
        | cats_api::error::ErrorCode::PermissionDenied => {
            QualificationFaultAuthorityError::NotAuthorized
        }
        cats_api::error::ErrorCode::Conflict
        | cats_api::error::ErrorCode::FailedPrecondition
        | cats_api::error::ErrorCode::AlreadyExists
        | cats_api::error::ErrorCode::StaleEpoch => QualificationFaultAuthorityError::Conflict,
        cats_api::error::ErrorCode::Unavailable => QualificationFaultAuthorityError::Unavailable,
        _ => QualificationFaultAuthorityError::InvalidEvidence,
    }
}

fn map_qualification_postgres_error(error: &postgres::Error) -> QualificationFaultAuthorityError {
    match error.code().map(postgres::error::SqlState::code) {
        Some("42501") => QualificationFaultAuthorityError::NotAuthorized,
        Some("22023") => QualificationFaultAuthorityError::InvalidEvidence,
        Some("55000") | Some("23505") | Some("23514") | Some("P0002") => {
            QualificationFaultAuthorityError::Conflict
        }
        Some("57014") | Some("55P03") => QualificationFaultAuthorityError::DeadlineExceeded,
        _ => QualificationFaultAuthorityError::Unavailable,
    }
}

fn public_key_digest(authenticated: &AuthenticatedNodeCredential) -> super::Result<&Sha256Digest> {
    match authenticated.binding() {
        CredentialBinding::PublicKey {
            public_key_spki_sha256,
        } => Ok(public_key_spki_sha256),
        CredentialBinding::ProviderPrincipal { .. } => Err(ApiError::unauthenticated(
            "object-write gateway requires an Ed25519 credential",
        )),
    }
}

fn attachment_reference(
    authenticated: &AuthenticatedNodeCredential,
) -> super::Result<ObjectWriteCredentialReference> {
    Ok(ObjectWriteCredentialReference {
        credential_id: authenticated.credential_id().clone(),
        public_key_spki_sha256: public_key_digest(authenticated)?.clone(),
    })
}

fn decode_stored_attempt(row: &Row) -> super::Result<StoredObjectWriteAttempt> {
    let accepted: bool = row.try_get("accepted").map_err(internal)?;
    let record: String = row.try_get("record_json").map_err(internal)?;
    if accepted {
        Ok(StoredObjectWriteAttempt::Accepted(decode(
            record,
            "accepted object-write attempt",
        )?))
    } else {
        let attempt: ObjectWriteIngressAttempt = decode(record, "object-write ingress attempt")?;
        validate_object_write_ingress_attempt(&attempt).map_err(|error| {
            ApiError::failed_precondition(format!(
                "object-write function returned invalid ingress: {error}"
            ))
        })?;
        Ok(StoredObjectWriteAttempt::Ingress(attempt))
    }
}

fn decode_stored_attempt_with_authority(row: &Row) -> super::Result<StoredObjectWriteAttempt> {
    let stored = decode_stored_attempt(row)?;
    if let StoredObjectWriteAttempt::Accepted(attempt) = &stored {
        validate_accepted_row(row, attempt)?;
    }
    Ok(stored)
}

fn decode_accepted_attempt(row: &Row) -> super::Result<ObjectPutAttempt> {
    decode_accepted_attempt_and_authority(row).map(|(attempt, _)| attempt)
}

fn decode_accepted_attempt_and_authority(
    row: &Row,
) -> super::Result<(ObjectPutAttempt, ObjectWriteAuthority)> {
    let attempt: ObjectPutAttempt = decode(
        row.try_get("record_json").map_err(internal)?,
        "accepted object-write attempt",
    )?;
    let authority: ObjectWriteAuthority = decode(
        row.try_get("authority_json").map_err(internal)?,
        "object-write authority",
    )?;
    validate_object_write_authority(&authority).map_err(|error| {
        ApiError::failed_precondition(format!(
            "object-write function returned invalid authority: {error}"
        ))
    })?;
    validate_object_put_attempt(&authority, &attempt).map_err(|error| {
        ApiError::failed_precondition(format!(
            "object-write function returned invalid accepted attempt: {error}"
        ))
    })?;
    Ok((attempt, authority))
}

fn validate_accepted_row(row: &Row, attempt: &ObjectPutAttempt) -> super::Result<()> {
    let (decoded, _) = decode_accepted_attempt_and_authority(row)?;
    if decoded != *attempt {
        return Err(ApiError::failed_precondition(
            "object-write function changed its accepted record while decoding authority",
        ));
    }
    Ok(())
}

fn encode<T: serde::Serialize>(value: &T, label: &str) -> super::Result<String> {
    serde_json::to_string(value)
        .map_err(|error| internal(format!("encode {label} for PostgreSQL: {error}")))
}

fn decode<T: serde::de::DeserializeOwned>(value: String, label: &str) -> super::Result<T> {
    serde_json::from_str(&value)
        .map_err(|error| ApiError::failed_precondition(format!("decode stored {label}: {error}")))
}

fn map_submit_error(error: SubmitError) -> ApiError {
    match error {
        SubmitError::Full => ApiError::unavailable("object-write gateway PostgreSQL queue is full"),
        SubmitError::Shutdown => {
            ApiError::unavailable("object-write gateway PostgreSQL lane is shutting down")
        }
    }
}

fn map_execution_error(error: ExecutionError) -> ApiError {
    match error {
        ExecutionError::Panicked => internal("object-write gateway PostgreSQL lane job panicked"),
        ExecutionError::Shutdown => {
            ApiError::unavailable("object-write gateway PostgreSQL lane stopped")
        }
    }
}

fn validate_schema_name(schema_name: &str) -> super::Result<()> {
    if schema_name.is_empty() || schema_name.len() > 63 || schema_name.as_bytes().contains(&0) {
        return Err(ApiError::invalid(
            "object-write gateway PostgreSQL schema name is invalid",
        ));
    }
    Ok(())
}

fn quote_schema(schema_name: &str) -> String {
    format!("\"{}\"", schema_name.replace('"', "\"\""))
}

fn connect_verified_client(
    dsn: &DsnSource,
    ca_file: Option<&str>,
    expected_schema: &str,
) -> super::Result<Client> {
    let mut client = schema::connect_client(dsn, ca_file)?;
    client
        .batch_execute("SET statement_timeout='5s'; SET lock_timeout='2s'")
        .map_err(map_gateway_postgres_error)?;
    let identity = client
        .query_one(
            "SELECT current_user::TEXT, session_user::TEXT, current_schema()::TEXT",
            &[],
        )
        .map_err(map_gateway_postgres_error)?;
    let current_user: String = identity.try_get(0).map_err(internal)?;
    let session_user: String = identity.try_get(1).map_err(internal)?;
    let current_schema: String = identity.try_get(2).map_err(internal)?;
    if current_user != OBJECT_WRITE_GATEWAY_POSTGRES_ROLE
        || session_user != OBJECT_WRITE_GATEWAY_POSTGRES_ROLE
        || current_schema != expected_schema
    {
        return Err(ApiError::unauthenticated(
            "object-write gateway PostgreSQL login role or schema is not exact",
        ));
    }
    let startup = format!(
        "SELECT * FROM {}.control_object_write_gateway_startup_v1()",
        quote_schema(expected_schema)
    );
    let row = client
        .query_one(&startup, &[])
        .map_err(map_gateway_postgres_error)?;
    let expected_contract = schema::object_write_gateway_contract_sha256()?;
    let expected_catalog = schema::object_write_gateway_catalog_sha256()?;
    if row
        .try_get::<_, i64>("protocol_version")
        .map_err(internal)?
        != i64::from(OBJECT_WRITE_GATEWAY_PROTOCOL_VERSION_V1)
        || row.try_get::<_, i64>("schema_version").map_err(internal)? != schema::SCHEMA_VERSION
        || row.try_get::<_, String>("schema_name").map_err(internal)? != expected_schema
        || row
            .try_get::<_, String>("expected_role")
            .map_err(internal)?
            != OBJECT_WRITE_GATEWAY_POSTGRES_ROLE
        || row.try_get::<_, i64>("routine_count").map_err(internal)?
            != OBJECT_WRITE_GATEWAY_INSTALLED_EXECUTABLE_ROUTINES
        || row
            .try_get::<_, String>("contract_sha256")
            .map_err(internal)?
            != expected_contract
        || row
            .try_get::<_, String>("catalog_sha256")
            .map_err(internal)?
            != expected_catalog
        || row
            .try_get::<_, bool>("qualification_lock_available")
            .map_err(internal)?
    {
        return Err(ApiError::failed_precondition(
            "object-write gateway PostgreSQL startup contract mismatch",
        ));
    }
    verify_direct_routine_catalog(
        &mut client,
        expected_schema,
        &expected_contract,
        &expected_catalog,
    )?;
    verify_least_privilege_catalog(&mut client, expected_schema)?;
    Err(ApiError::failed_precondition(format!(
        "object-write gateway PostgreSQL production surface is unavailable: installed {} of {} routines; E13 qualification lock is absent",
        OBJECT_WRITE_GATEWAY_INSTALLED_EXECUTABLE_ROUTINES,
        OBJECT_WRITE_GATEWAY_REQUIRED_EXECUTABLE_ROUTINES,
    )))
}

fn verify_direct_routine_catalog(
    client: &mut Client,
    expected_schema: &str,
    expected_contract: &str,
    expected_catalog: &str,
) -> super::Result<()> {
    let names = schema::object_write_gateway_catalog_function_names();
    let contract_hex = expected_contract
        .strip_prefix("sha256:")
        .ok_or_else(|| internal("object-write gateway contract digest lost its prefix"))?;
    let row = client
        .query_one(
            "SELECT COUNT(*),
                    'sha256:' || pg_catalog.encode(pg_catalog.sha256(
                        pg_catalog.convert_to(COALESCE(pg_catalog.string_agg(
                            function.proname || pg_catalog.chr(0) ||
                            pg_catalog.pg_get_function_identity_arguments(function.oid) ||
                            pg_catalog.chr(0) ||
                            pg_catalog.pg_get_function_result(function.oid) ||
                            pg_catalog.chr(0) || function.prosecdef::TEXT ||
                            pg_catalog.chr(0) || function.proisstrict::TEXT ||
                            pg_catalog.chr(0) || function.provolatile::TEXT ||
                            pg_catalog.chr(0) || language.lanname ||
                            pg_catalog.chr(0) || COALESCE(
                                pg_catalog.array_to_string(function.proconfig, ','), '') ||
                            pg_catalog.chr(0) ||
                                (function.proowner=namespace.nspowner)::TEXT ||
                            pg_catalog.chr(0) || (NOT EXISTS (
                                SELECT 1
                                  FROM pg_catalog.aclexplode(COALESCE(
                                       function.proacl,
                                       pg_catalog.acldefault('f', function.proowner)
                                  )) privilege
                                 WHERE privilege.grantee=0
                                   AND privilege.privilege_type='EXECUTE'
                            ))::TEXT ||
                            pg_catalog.chr(0) || pg_catalog.has_function_privilege(
                                session_user, function.oid, 'EXECUTE')::TEXT ||
                            pg_catalog.chr(0) || pg_catalog.encode(pg_catalog.sha256(
                                pg_catalog.convert_to(pg_catalog.replace(
                                    pg_catalog.replace(pg_catalog.replace(
                                        function.prosrc,
                                        pg_catalog.chr(34) || $1 || pg_catalog.chr(34),
                                        '__CATS_SCHEMA_IDENT__'
                                    ), pg_catalog.quote_literal($1),
                                       '__CATS_SCHEMA_LITERAL__'),
                                    $3,
                                    '__CATS_OBJECT_WRITE_GATEWAY_' ||
                                        'CONTRACT_SHA256_VALUE__'
                                ), 'UTF8')), 'hex'),
                            pg_catalog.chr(10)
                            ORDER BY function.proname
                        ), ''), 'UTF8')), 'hex')
               FROM pg_catalog.pg_proc function
               JOIN pg_catalog.pg_namespace namespace
                 ON namespace.oid=function.pronamespace
               JOIN pg_catalog.pg_language language ON language.oid=function.prolang
              WHERE namespace.nspname=$1
                AND function.proname=ANY($2::TEXT[])",
            &[&expected_schema, &names, &contract_hex],
        )
        .map_err(map_gateway_postgres_error)?;
    let count: i64 = row.try_get(0).map_err(internal)?;
    let catalog: String = row.try_get(1).map_err(internal)?;
    if usize::try_from(count).ok() != Some(schema::object_write_gateway_catalog_function_count())
        || catalog != expected_catalog
    {
        return Err(ApiError::failed_precondition(
            "object-write gateway direct PostgreSQL routine catalog mismatch",
        ));
    }
    Ok(())
}

fn verify_least_privilege_catalog(client: &mut Client, expected_schema: &str) -> super::Result<()> {
    let row = client
        .query_one(
            "SELECT
                has_schema_privilege(session_user, $1, 'USAGE'),
                has_schema_privilege(session_user, $1, 'CREATE'),
                NOT EXISTS (
                    SELECT 1
                      FROM pg_catalog.pg_auth_members membership
                     WHERE membership.member=(
                         SELECT role.oid FROM pg_catalog.pg_roles role
                          WHERE role.rolname=session_user
                     )
                ),
                NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_class relation
                    JOIN pg_catalog.pg_namespace namespace
                      ON namespace.oid=relation.relnamespace
                    WHERE namespace.nspname=$1
                      AND relation.relkind IN ('r','p','v','m','f')
                      AND (has_any_column_privilege(
                              session_user, relation.oid,
                              'SELECT,INSERT,UPDATE,REFERENCES')
                           OR has_table_privilege(session_user, relation.oid,
                              'INSERT,UPDATE,DELETE,TRUNCATE,REFERENCES,TRIGGER'))
                ),
                NOT EXISTS (
                    SELECT 1 FROM pg_catalog.pg_class sequence
                    JOIN pg_catalog.pg_namespace namespace
                      ON namespace.oid=sequence.relnamespace
                    WHERE namespace.nspname=$1
                      AND sequence.relkind='S'
                      AND has_sequence_privilege(
                          session_user, sequence.oid, 'USAGE,SELECT,UPDATE')
                ),
                (
                    SELECT COUNT(*)
                      FROM pg_catalog.pg_proc function
                      JOIN pg_catalog.pg_namespace namespace
                        ON namespace.oid=function.pronamespace
                     WHERE namespace.nspname=$1
                       AND has_function_privilege(
                           session_user, function.oid, 'EXECUTE')
                ),
                EXISTS (
                    SELECT 1
                      FROM pg_catalog.pg_roles role
                     WHERE role.rolname=session_user
                       AND role.rolcanlogin
                       AND NOT role.rolsuper
                       AND NOT role.rolinherit
                       AND NOT role.rolcreaterole
                       AND NOT role.rolcreatedb
                       AND NOT role.rolreplication
                       AND NOT role.rolbypassrls
                ),
                has_database_privilege(session_user, current_database(), 'CONNECT'),
                has_database_privilege(session_user, current_database(), 'CREATE'),
                has_database_privilege(session_user, current_database(), 'TEMPORARY')",
            &[&expected_schema],
        )
        .map_err(map_gateway_postgres_error)?;
    let usage: bool = row.try_get(0).map_err(internal)?;
    let create: bool = row.try_get(1).map_err(internal)?;
    let no_memberships: bool = row.try_get(2).map_err(internal)?;
    let no_relation_privileges: bool = row.try_get(3).map_err(internal)?;
    let no_sequence_privileges: bool = row.try_get(4).map_err(internal)?;
    let executable_functions: i64 = row.try_get(5).map_err(internal)?;
    let exact_role_attributes: bool = row.try_get(6).map_err(internal)?;
    let database_connect: bool = row.try_get(7).map_err(internal)?;
    let database_create: bool = row.try_get(8).map_err(internal)?;
    let database_temporary: bool = row.try_get(9).map_err(internal)?;
    if !usage
        || create
        || !no_memberships
        || !no_relation_privileges
        || !no_sequence_privileges
        || executable_functions != OBJECT_WRITE_GATEWAY_INSTALLED_EXECUTABLE_ROUTINES
        || !exact_role_attributes
        || !database_connect
        || database_create
        || database_temporary
    {
        return Err(ApiError::unauthenticated(
            "object-write gateway PostgreSQL privilege catalog is not exact",
        ));
    }
    Ok(())
}

fn map_gateway_postgres_error(error: postgres::Error) -> ApiError {
    match error.code().map(postgres::error::SqlState::code) {
        Some("22023") => ApiError::invalid("object-write gateway request was rejected"),
        Some("42501") => ApiError::unauthenticated(
            "object-write gateway PostgreSQL privilege boundary rejected the session",
        ),
        Some("P0002") => ApiError::not_found("ObjectWriteAuthority"),
        Some("55000") | Some("23505") | Some("23514") => {
            ApiError::conflict("object-write gateway state or binding is stale")
        }
        Some("57014") | Some("55P03") => {
            ApiError::unavailable("object-write gateway PostgreSQL operation timed out")
        }
        _ if error.is_closed() => {
            ApiError::unavailable("object-write gateway PostgreSQL connection closed")
        }
        _ => internal(error),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{
        qualification_commit_timeout_millis, qualification_request_lock_key,
        qualification_timeout_millis, OffRuntimeOwned,
    };

    struct RuntimeSensitiveDrop(Option<tokio::sync::oneshot::Sender<bool>>);

    impl Drop for RuntimeSensitiveDrop {
        fn drop(&mut self) {
            if let Some(dropped) = self.0.take() {
                let _ = dropped.send(tokio::runtime::Handle::try_current().is_err());
            }
        }
    }

    struct BlockingSessionDrop {
        permit: Option<tokio::sync::OwnedSemaphorePermit>,
        entered: Option<tokio::sync::oneshot::Sender<bool>>,
        release: std::sync::mpsc::Receiver<()>,
    }

    impl Drop for BlockingSessionDrop {
        fn drop(&mut self) {
            if let Some(entered) = self.entered.take() {
                let _ = entered.send(tokio::runtime::Handle::try_current().is_err());
            }
            let _ = self.release.recv_timeout(Duration::from_secs(2));
            drop(self.permit.take());
        }
    }

    #[test]
    fn qualification_request_advisory_key_is_domain_separated_and_fixed() {
        let request_id = format!("sha256:{}", "0".repeat(64));
        assert_eq!(
            qualification_request_lock_key(&request_id).unwrap(),
            4_051_514_043_169_727_851
        );
        assert!(qualification_request_lock_key(&format!("sha256:{}", "A".repeat(64))).is_err());
        assert!(qualification_request_lock_key("sha256:00").is_err());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn synchronous_guard_owner_is_destroyed_off_the_async_runtime() {
        let (dropped, observed) = tokio::sync::oneshot::channel();
        drop(OffRuntimeOwned::new(RuntimeSensitiveDrop(Some(dropped))));
        assert!(tokio::time::timeout(Duration::from_secs(2), observed)
            .await
            .expect("off-runtime destructor did not run")
            .expect("off-runtime destructor lost its observation"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn guard_capacity_is_held_until_the_off_runtime_session_is_closed() {
        let capacity = std::sync::Arc::new(tokio::sync::Semaphore::new(1));
        let permit = capacity
            .clone()
            .try_acquire_owned()
            .expect("fixture capacity is available");
        let (entered, observed) = tokio::sync::oneshot::channel();
        let (release, released) = std::sync::mpsc::channel();
        drop(OffRuntimeOwned::new(BlockingSessionDrop {
            permit: Some(permit),
            entered: Some(entered),
            release: released,
        }));
        assert!(tokio::time::timeout(Duration::from_secs(2), observed)
            .await
            .expect("off-runtime destructor did not start")
            .expect("off-runtime destructor lost its observation"));
        assert!(capacity.clone().try_acquire_owned().is_err());
        tokio::time::timeout(
            Duration::from_millis(100),
            tokio::time::sleep(Duration::from_millis(1)),
        )
        .await
        .expect("blocking session destructor stopped the Tokio heartbeat");
        release.send(()).expect("release blocking destructor");
        let _permit = tokio::time::timeout(Duration::from_secs(2), capacity.acquire_owned())
            .await
            .expect("off-runtime destructor did not release capacity")
            .expect("fixture semaphore remained open");
    }

    #[test]
    fn qualification_timeout_never_extends_a_sub_millisecond_remainder() {
        assert!(qualification_timeout_millis(Duration::ZERO).is_err());
        assert!(qualification_timeout_millis(Duration::from_micros(999)).is_err());
        assert_eq!(
            qualification_timeout_millis(Duration::from_millis(1)).unwrap(),
            1
        );
        assert!(qualification_commit_timeout_millis(Duration::from_millis(1)).is_err());
        assert_eq!(
            qualification_commit_timeout_millis(Duration::from_millis(2)).unwrap(),
            1
        );
    }
}
