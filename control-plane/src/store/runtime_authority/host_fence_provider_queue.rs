//! Sealed PostgreSQL queue for the out-of-process Host-fence provider.
//!
//! Control is the only producer.  It closes the exact object-writer parent
//! and inserts the immutable request in one transaction.  The provider login
//! has no table privileges; its client can only use the fixed
//! `SECURITY DEFINER` claim/renew/cutoff/complete/read surface installed by
//! the schema.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use cats_api::error::ApiError;
use cats_api::runtime_reconciliation::{Id, RandomId128, Sha256Digest, UnixMillis};
use cats_storage::host_fence::{
    host_fence_effect_token, host_fence_provider_attempt_id, validate_host_fence_provider_evidence,
    HostFenceAttemptRequest, HostFencePortFuture, HostFenceProviderError,
    HostFenceProviderEvidence, ObjectWriteCutoffEvidence, ObjectWriteCutoffPort,
    ObjectWriterFenceTarget,
};
use cats_storage::object_write_authority::{ObjectWriteAuthorityState, ObjectWriteCutoffReceipt};
use postgres::{Client, Row, Transaction};
use sha2::{Digest, Sha256};

use super::object_write::begin_object_writer_cutoff_in;
use super::rows::database_now;
use crate::store::executor::{BlockingExecutor, ExecutionError, Limits, SubmitError};
use crate::store::transaction::{AuthorityTransactionError, AuthorityTxResult};
use crate::store::{internal, schema, DsnSource, Store};

pub const HOST_FENCE_PROVIDER_QUEUE_VERSION_V1: u16 = 1;
pub const HOST_FENCE_PROVIDER_POSTGRES_ROLE: &str = "cats_host_fence_provider";
pub const HOST_FENCE_PROVIDER_REQUEST_MAX_BYTES: usize = 1024 * 1024;
pub const HOST_FENCE_PROVIDER_EVIDENCE_MAX_BYTES: usize = 4 * 1024 * 1024;
pub const HOST_FENCE_PROVIDER_LEASE_MAX_MS: u64 = 60_000;

const HOST_FENCE_PROVIDER_POSTGRES_WORKERS: usize = 1;
const HOST_FENCE_PROVIDER_POSTGRES_QUEUE_CAPACITY: usize = 1;
const HOST_FENCE_PROVIDER_POSTGRES_IN_FLIGHT: usize =
    HOST_FENCE_PROVIDER_POSTGRES_WORKERS + HOST_FENCE_PROVIDER_POSTGRES_QUEUE_CAPACITY;

const REQUEST_DIGEST_DOMAIN: &[u8] = b"cats.host-fence-provider-queue-request.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFenceProviderQueueStateV1 {
    Pending,
    Claimed {
        worker_id: Id,
        claim_attempt_token: RandomId128,
        claim_generation: u64,
        lease_expires_at_unix_ms: UnixMillis,
    },
    Terminal {
        worker_id: Id,
        claim_attempt_token: RandomId128,
        claim_generation: u64,
        evidence: Box<HostFenceProviderEvidence>,
        evidence_sha256: Sha256Digest,
        completed_at_unix_ms: UnixMillis,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFenceProviderQueueRecordV1 {
    pub request: HostFenceAttemptRequest,
    pub request_sha256: Sha256Digest,
    pub enqueued_at_unix_ms: UnixMillis,
    pub state: HostFenceProviderQueueStateV1,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFenceProviderClaimV1 {
    pub request: HostFenceAttemptRequest,
    pub request_sha256: Sha256Digest,
    pub worker_id: Id,
    pub claim_attempt_token: RandomId128,
    pub claim_generation: u64,
    pub lease_expires_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostFenceProviderObjectCutoffV1 {
    Pending,
    Complete(Box<ObjectWriteCutoffEvidence>),
}

fn application(error: ApiError) -> AuthorityTransactionError {
    AuthorityTransactionError::Application(error)
}

fn corrupt(message: impl Into<String>) -> AuthorityTransactionError {
    application(ApiError::failed_precondition(message.into()))
}

#[allow(dead_code, reason = "also used by the gated C3 batch producer")]
fn pg(value: u64) -> AuthorityTxResult<i64> {
    i64::try_from(value).map_err(|_| corrupt("Host-fence queue integer exceeds PostgreSQL BIGINT"))
}

fn wire(value: i64, label: &str) -> AuthorityTxResult<u64> {
    u64::try_from(value).map_err(|_| corrupt(format!("stored {label} is negative")))
}

fn time(value: i64, label: &str) -> AuthorityTxResult<UnixMillis> {
    UnixMillis::new(wire(value, label)?)
        .ok_or_else(|| corrupt(format!("stored {label} is invalid")))
}

fn canonical_request_bytes(request: &HostFenceAttemptRequest) -> AuthorityTxResult<Vec<u8>> {
    let bytes = serde_json::to_vec(request)
        .map_err(|error| corrupt(format!("encode Host-fence provider request: {error}")))?;
    if bytes.len() > HOST_FENCE_PROVIDER_REQUEST_MAX_BYTES {
        return Err(application(ApiError::invalid(
            "Host-fence provider request exceeds its hard byte limit",
        )));
    }
    Ok(bytes)
}

fn decode_canonical_request(bytes: &[u8]) -> AuthorityTxResult<HostFenceAttemptRequest> {
    let request: HostFenceAttemptRequest = serde_json::from_slice(bytes)
        .map_err(|error| corrupt(format!("decode Host-fence provider request: {error}")))?;
    if canonical_request_bytes(&request)? != bytes {
        return Err(corrupt(
            "stored Host-fence provider request is not canonical JSON",
        ));
    }
    Ok(request)
}

fn request_sha256(bytes: &[u8]) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(bytes);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

pub(super) fn evidence_sha256(bytes: &[u8]) -> Sha256Digest {
    // This is deliberately the same digest consumed by TrustedHostFenceEventV1.
    let mut hasher = Sha256::new();
    hasher.update(b"cats.trusted-host-fence-event.v1");
    hasher.update([0]);
    hasher.update(bytes);
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn decode_canonical_evidence(bytes: &[u8]) -> AuthorityTxResult<HostFenceProviderEvidence> {
    let evidence: HostFenceProviderEvidence = serde_json::from_slice(bytes)
        .map_err(|error| corrupt(format!("decode Host-fence provider evidence: {error}")))?;
    let canonical = serde_json::to_vec(&evidence)
        .map_err(|error| corrupt(format!("encode Host-fence provider evidence: {error}")))?;
    if canonical != bytes {
        return Err(corrupt(
            "stored Host-fence provider evidence is not canonical JSON",
        ));
    }
    Ok(evidence)
}

#[allow(dead_code, reason = "used by the gated C3 batch producer")]
fn validate_request_binding(request: &HostFenceAttemptRequest) -> AuthorityTxResult<()> {
    if request.binding.provider_scope != request.object_writer.provider_scope {
        return Err(application(ApiError::invalid(
            "Host-fence and object-writer provider scopes differ",
        )));
    }
    Ok(())
}

#[allow(dead_code, reason = "used by the gated C3 batch authority")]
pub(super) fn load_queue_for_update(
    transaction: &mut Transaction<'_>,
    fence_attempt_id: &Id,
) -> AuthorityTxResult<Option<HostFenceProviderQueueRecordV1>> {
    transaction
        .query_opt(
            "SELECT request_bytes, request_sha256, enqueued_at_unix_ms, state,
                    worker_id, claim_attempt_token, claim_generation,
                    claim_lease_expires_at_unix_ms, evidence_bytes,
                    evidence_sha256, completed_at_unix_ms
               FROM host_fence_provider_queue_v1
              WHERE fence_attempt_id=$1 FOR UPDATE",
            &[&fence_attempt_id.as_str()],
        )?
        .as_ref()
        .map(decode_queue_row)
        .transpose()
}

/// Transaction-local queue producer used by the Host-scoped recovery seal.
///
/// Keeping the object-writer cutoff and queue insert in the caller's
/// transaction lets Control add its immutable assigned-set barrier without a
/// window in which the provider can act on an attempt that has no product
/// recovery authority. Exact queue replay remains available to the legacy
/// owner-side seam, but a batch producer must reject an existing queue row
/// when its corresponding recovery-attempt row is absent.
#[allow(
    dead_code,
    reason = "only the gated C3 batch authority may enqueue in production"
)]
pub(super) fn enqueue_host_fence_provider_attempt_in(
    transaction: &mut Transaction<'_>,
    request: &HostFenceAttemptRequest,
) -> AuthorityTxResult<HostFenceProviderQueueRecordV1> {
    validate_request_binding(request)?;
    let bytes = canonical_request_bytes(request)?;
    let digest = request_sha256(&bytes);
    if let Some(existing) = load_queue_for_update(transaction, &request.binding.fence_attempt_id)? {
        return exact_replay_or_conflict(existing, request, &digest);
    }

    lock_current_source(transaction, request)?;
    // A missing-row SELECT has no PostgreSQL gap lock. The exact NodeIdentity
    // lock above serializes concurrent attempts for one source, so recheck
    // after acquiring it before starting a second cutoff or racing the
    // immutable queue primary key.
    if let Some(existing) = load_queue_for_update(transaction, &request.binding.fence_attempt_id)? {
        return exact_replay_or_conflict(existing, request, &digest);
    }
    let now = database_now(transaction)?;
    let authority = begin_object_writer_cutoff_in(
        transaction,
        &request.object_writer.writer_authority_id,
        &request.binding.fence_attempt_id,
        now,
    )?;
    validate_cutoff_authority(request, &authority)?;
    let inserted = transaction.execute(
        "INSERT INTO host_fence_provider_queue_v1 (
            fence_attempt_id, request_bytes, request_sha256,
            provider, host_partition, host_account_id, host_region,
            immutable_host_id, node_id, expected_node_boot_id,
            expected_agent_session_epoch, writer_authority_id,
            workload_principal_id, object_store_scope_id,
            network_quarantine_boundary_id, state,
            claim_generation, renew_generation, enqueued_at_unix_ms
         ) VALUES (
            $1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,
            'pending',0,0,$16
         )",
        &[
            &request.binding.fence_attempt_id.as_str(),
            &bytes,
            &digest.as_str(),
            &request.binding.provider_scope.provider.as_str(),
            &request.binding.provider_scope.partition.as_str(),
            &request.binding.provider_scope.account_id.as_str(),
            &request.binding.provider_scope.region.as_str(),
            &request.binding.immutable_host_id.as_str(),
            &request.binding.node_id.as_str(),
            &request.binding.expected_node_boot_id.as_str(),
            &pg(request.binding.expected_agent_session_epoch.get())?,
            &request.object_writer.writer_authority_id.as_str(),
            &request.object_writer.workload_principal_id.as_str(),
            &request.object_writer.object_store_scope_id.as_str(),
            &request.network_quarantine_boundary_id.as_str(),
            &pg(now.get())?,
        ],
    )?;
    if inserted != 1 {
        return Err(corrupt("Host-fence provider queue insert changed no row"));
    }
    load_queue_for_update(transaction, &request.binding.fence_attempt_id)?
        .ok_or_else(|| corrupt("Host-fence provider queue row disappeared after insert"))
}

#[allow(dead_code, reason = "used by the gated C3 batch producer")]
fn exact_replay_or_conflict(
    existing: HostFenceProviderQueueRecordV1,
    request: &HostFenceAttemptRequest,
    digest: &Sha256Digest,
) -> AuthorityTxResult<HostFenceProviderQueueRecordV1> {
    if existing.request == *request && existing.request_sha256 == *digest {
        Ok(existing)
    } else {
        Err(application(ApiError::conflict(
            "Host-fence attempt replay changed its sealed request",
        )))
    }
}

fn decode_queue_row(row: &Row) -> AuthorityTxResult<HostFenceProviderQueueRecordV1> {
    let request_bytes: Vec<u8> = row.try_get("request_bytes")?;
    let request = decode_canonical_request(&request_bytes)?;
    let stored_request_sha: String = row.try_get("request_sha256")?;
    let derived_request_sha = request_sha256(&request_bytes);
    if stored_request_sha != derived_request_sha.as_str() {
        return Err(corrupt("stored Host-fence request digest is inconsistent"));
    }
    let state: String = row.try_get("state")?;
    let worker_id = row.try_get::<_, Option<String>>("worker_id")?;
    let claim_token = row.try_get::<_, Option<String>>("claim_attempt_token")?;
    let claim_generation = row.try_get::<_, i64>("claim_generation")?;
    let lease = row.try_get::<_, Option<i64>>("claim_lease_expires_at_unix_ms")?;
    let state = match state.as_str() {
        "pending" => HostFenceProviderQueueStateV1::Pending,
        "claimed" => HostFenceProviderQueueStateV1::Claimed {
            worker_id: Id::new(
                worker_id.ok_or_else(|| corrupt("claimed queue row has no worker"))?,
            )
            .ok_or_else(|| corrupt("claimed queue worker ID is invalid"))?,
            claim_attempt_token: RandomId128::new(
                claim_token.ok_or_else(|| corrupt("claimed queue row has no token"))?,
            )
            .ok_or_else(|| corrupt("claimed queue token is invalid"))?,
            claim_generation: wire(claim_generation, "claim generation")?,
            lease_expires_at_unix_ms: time(
                lease.ok_or_else(|| corrupt("claimed queue row has no lease"))?,
                "claim lease",
            )?,
        },
        "terminal" => {
            let evidence_bytes: Vec<u8> = row
                .try_get::<_, Option<Vec<u8>>>("evidence_bytes")?
                .ok_or_else(|| corrupt("terminal queue row has no evidence"))?;
            let evidence = decode_canonical_evidence(&evidence_bytes)?;
            validate_host_fence_provider_evidence(&request, &evidence).map_err(|error| {
                corrupt(format!("stored provider evidence is invalid: {error}"))
            })?;
            let digest = evidence_sha256(&evidence_bytes);
            if row
                .try_get::<_, Option<String>>("evidence_sha256")?
                .as_deref()
                != Some(digest.as_str())
            {
                return Err(corrupt("stored Host-fence evidence digest is inconsistent"));
            }
            HostFenceProviderQueueStateV1::Terminal {
                worker_id: Id::new(
                    worker_id.ok_or_else(|| corrupt("terminal queue row has no worker"))?,
                )
                .ok_or_else(|| corrupt("terminal queue worker ID is invalid"))?,
                claim_attempt_token: RandomId128::new(
                    claim_token.ok_or_else(|| corrupt("terminal queue row has no token"))?,
                )
                .ok_or_else(|| corrupt("terminal queue token is invalid"))?,
                claim_generation: wire(claim_generation, "claim generation")?,
                completed_at_unix_ms: time(
                    row.try_get::<_, Option<i64>>("completed_at_unix_ms")?
                        .ok_or_else(|| corrupt("terminal queue row has no completion time"))?,
                    "queue completion time",
                )?,
                evidence: Box::new(evidence),
                evidence_sha256: digest,
            }
        }
        _ => return Err(corrupt("stored Host-fence provider queue state is unknown")),
    };
    Ok(HostFenceProviderQueueRecordV1 {
        request,
        request_sha256: derived_request_sha,
        enqueued_at_unix_ms: time(row.try_get("enqueued_at_unix_ms")?, "enqueue time")?,
        state,
    })
}

#[allow(dead_code, reason = "used by the gated C3 batch producer")]
fn lock_current_source(
    transaction: &mut Transaction<'_>,
    request: &HostFenceAttemptRequest,
) -> AuthorityTxResult<()> {
    let binding = &request.binding;
    let Some(identity) = transaction.query_opt(
        "SELECT host_provider, host_partition, host_account_id, host_region,
                immutable_host_id, state
           FROM node_identities WHERE node_id=$1 FOR UPDATE",
        &[&binding.node_id.as_str()],
    )?
    else {
        return Err(application(ApiError::not_found("NodeIdentity")));
    };
    if identity.try_get::<_, String>("state")? != "provisioned"
        || identity.try_get::<_, String>("host_provider")?
            != binding.provider_scope.provider.as_str()
        || identity.try_get::<_, String>("host_partition")?
            != binding.provider_scope.partition.as_str()
        || identity.try_get::<_, String>("host_account_id")?
            != binding.provider_scope.account_id.as_str()
        || identity.try_get::<_, String>("host_region")? != binding.provider_scope.region.as_str()
        || identity.try_get::<_, String>("immutable_host_id")? != binding.immutable_host_id.as_str()
    {
        return Err(application(ApiError::conflict(
            "Host-fence request does not bind the current provisioned NodeIdentity",
        )));
    }
    let Some(session) = transaction.query_opt(
        "SELECT immutable_host_id, node_boot_id, agent_session_epoch
           FROM current_agent_sessions WHERE node_id=$1 FOR UPDATE",
        &[&binding.node_id.as_str()],
    )?
    else {
        return Err(application(ApiError::conflict(
            "Host-fence request has no current AgentSession",
        )));
    };
    if session.try_get::<_, String>("immutable_host_id")? != binding.immutable_host_id.as_str()
        || session.try_get::<_, String>("node_boot_id")? != binding.expected_node_boot_id.as_str()
        || session.try_get::<_, i64>("agent_session_epoch")?
            != pg(binding.expected_agent_session_epoch.get())?
    {
        return Err(application(ApiError::conflict(
            "Host-fence request does not bind the current AgentSession",
        )));
    }
    Ok(())
}

#[allow(dead_code, reason = "used by the gated C3 batch producer")]
fn validate_cutoff_authority(
    request: &HostFenceAttemptRequest,
    authority: &cats_storage::object_write_authority::ObjectWriteAuthority,
) -> AuthorityTxResult<()> {
    let binding = &request.binding;
    let writer = &authority.writer;
    if writer.authority_id != request.object_writer.writer_authority_id
        || writer.host_provider_scope != binding.provider_scope
        || writer.immutable_host_id != binding.immutable_host_id
        || writer.node_id != binding.node_id
        || writer.object_provider_scope != request.object_writer.provider_scope
        || writer.workload_principal_id != request.object_writer.workload_principal_id
        || writer.object_store_scope_id != request.object_writer.object_store_scope_id
    {
        return Err(application(ApiError::conflict(
            "Host-fence request does not bind the exact object-writer authority",
        )));
    }
    match &authority.state {
        ObjectWriteAuthorityState::CutoffPending {
            fence_attempt_id, ..
        }
        | ObjectWriteAuthorityState::CutoffComplete {
            receipt: ObjectWriteCutoffReceipt {
                fence_attempt_id, ..
            },
        } if fence_attempt_id == &binding.fence_attempt_id => Ok(()),
        _ => Err(corrupt(
            "object-writer cutoff did not bind the enqueued fence attempt",
        )),
    }
}

impl Store {
    /// Queue-only harness retained for the least-privilege worker protocol
    /// tests. Production can enqueue only through the Host-scoped recovery
    /// attempt transaction, which adds the assigned-set mutation barrier.
    #[cfg(test)]
    pub(crate) fn enqueue_host_fence_provider_attempt_for_test(
        &self,
        request: &HostFenceAttemptRequest,
    ) -> crate::store::Result<HostFenceProviderQueueRecordV1> {
        self.authority_transaction(|transaction| {
            enqueue_host_fence_provider_attempt_in(transaction, request)
        })
    }

    /// Read one sealed attempt through its complete Host/Node/session scope.
    /// This is the owner-side discovery seam for authenticated Control APIs;
    /// it neither accepts an attempt ID alone nor exposes the provider DSN.
    pub fn get_host_fence_provider_attempt_v1(
        &self,
        binding: &cats_storage::host_fence::HostFenceBinding,
    ) -> crate::store::Result<Option<HostFenceProviderQueueRecordV1>> {
        let expected_agent_session_epoch =
            i64::try_from(binding.expected_agent_session_epoch.get())
                .map_err(|_| ApiError::invalid("AgentSession epoch exceeds PostgreSQL BIGINT"))?;
        let row = self.with(|client| {
            client.query_opt(
                "SELECT request_bytes, request_sha256, enqueued_at_unix_ms, state,
                        worker_id, claim_attempt_token, claim_generation,
                        claim_lease_expires_at_unix_ms, evidence_bytes,
                        evidence_sha256, completed_at_unix_ms
                   FROM host_fence_provider_queue_v1
                  WHERE fence_attempt_id=$1
                    AND provider=$2 AND host_partition=$3
                    AND host_account_id=$4 AND host_region=$5
                    AND immutable_host_id=$6 AND node_id=$7
                    AND expected_node_boot_id=$8
                    AND expected_agent_session_epoch=$9",
                &[
                    &binding.fence_attempt_id.as_str(),
                    &binding.provider_scope.provider.as_str(),
                    &binding.provider_scope.partition.as_str(),
                    &binding.provider_scope.account_id.as_str(),
                    &binding.provider_scope.region.as_str(),
                    &binding.immutable_host_id.as_str(),
                    &binding.node_id.as_str(),
                    &binding.expected_node_boot_id.as_str(),
                    &expected_agent_session_epoch,
                ],
            )
        })?;
        row.as_ref()
            .map(decode_queue_row)
            .transpose()
            .map_err(map_authority_decode_error)
            .and_then(|record| match record {
                Some(record) if record.request.binding != *binding => {
                    Err(ApiError::failed_precondition(
                        "stored Host-fence queue request changed its scope projection",
                    ))
                }
                record => Ok(record),
            })
    }
}

fn object_writer_target_bytes(target: &ObjectWriterFenceTarget) -> Vec<u8> {
    let mut bytes = Vec::new();
    for value in [
        target.writer_authority_id.as_str(),
        target.provider_scope.provider.as_str(),
        target.provider_scope.partition.as_str(),
        target.provider_scope.account_id.as_str(),
        target.provider_scope.region.as_str(),
        target.workload_principal_id.as_str(),
        target.object_store_scope_id.as_str(),
    ] {
        bytes.extend_from_slice(&(value.len() as u64).to_be_bytes());
        bytes.extend_from_slice(value.as_bytes());
    }
    bytes
}

pub(super) fn cutoff_evidence(
    request: &HostFenceAttemptRequest,
    receipt: ObjectWriteCutoffReceipt,
) -> Result<ObjectWriteCutoffEvidence, HostFenceProviderError> {
    let target = object_writer_target_bytes(&request.object_writer);
    Ok(
        ObjectWriteCutoffEvidence::PrincipalCutoffWithAcceptedPutTerminalBarrier {
            binding: request.binding.clone(),
            object_writer: request.object_writer.clone(),
            effect_token: host_fence_effect_token(
                &request.binding,
                b"object-write-cutoff",
                &target,
            )?,
            provider_attempt_id: host_fence_provider_attempt_id(
                &request.binding,
                b"object-write-cutoff",
                &target,
            )?,
            cutoff_receipt_id: receipt.cutoff_receipt_id,
            cutoff_effective_at_unix_ms: receipt.cutoff_effective_at_unix_ms,
            cutoff_sequence: receipt.cutoff_sequence,
            accepted_put_terminal_receipt_id: receipt.accepted_put_terminal_receipt_id,
            accepted_puts_terminal_at_unix_ms: receipt.accepted_puts_terminal_at_unix_ms,
            terminal_sequence: receipt.terminal_sequence,
            terminal_prefix_sha256: receipt.terminal_prefix_sha256,
            successful_put_visibility_receipt_id: receipt.successful_put_visibility_receipt_id,
            successful_puts_visible_at_unix_ms: receipt.successful_puts_visible_at_unix_ms,
        },
    )
}

/// Implemented below after the least-privilege PostgreSQL client; the type is
/// declared here so the AWS composition never needs another cutoff protocol.
pub struct PgObjectWriteCutoffPort {
    client: std::sync::Arc<HostFenceProviderQueueClient>,
    claim: HostFenceProviderClaimV1,
}

impl PgObjectWriteCutoffPort {
    pub fn new(
        client: std::sync::Arc<HostFenceProviderQueueClient>,
        claim: HostFenceProviderClaimV1,
    ) -> Self {
        Self { client, claim }
    }
}

impl ObjectWriteCutoffPort for PgObjectWriteCutoffPort {
    fn establish_cutoff<'a>(
        &'a self,
        request: &'a HostFenceAttemptRequest,
        absolute_deadline: Instant,
    ) -> HostFencePortFuture<'a, ObjectWriteCutoffEvidence> {
        Box::pin(async move {
            if request != &self.claim.request {
                return Err(HostFenceProviderError::InvalidRequest);
            }
            loop {
                if Instant::now() >= absolute_deadline {
                    return Err(HostFenceProviderError::DeadlineExceeded);
                }
                match self
                    .client
                    .object_write_cutoff(&self.claim)
                    .await
                    .map_err(|_| HostFenceProviderError::ObjectWriteBarrierUnavailable)?
                {
                    HostFenceProviderObjectCutoffV1::Pending => {
                        let remaining = absolute_deadline
                            .checked_duration_since(Instant::now())
                            .ok_or(HostFenceProviderError::DeadlineExceeded)?;
                        tokio::time::sleep(remaining.min(Duration::from_millis(100))).await;
                    }
                    HostFenceProviderObjectCutoffV1::Complete(evidence) => return Ok(*evidence),
                }
            }
        })
    }
}

/// One separately authenticated PostgreSQL lane for the provider worker.
///
/// It never runs schema DDL and never obtains a [`Store`].  Every connect and
/// reconnect first proves the login role and selected schema with a direct
/// query, then proves the installed protocol through the sole startup
/// function.  The one worker plus one queued operation is a hard bound around
/// the synchronous PostgreSQL driver.
pub struct HostFenceProviderQueueClient {
    connection: Mutex<Option<Client>>,
    dsn: DsnSource,
    ca_file: Option<String>,
    expected_schema: String,
    executor: Mutex<Option<BlockingExecutor>>,
    admission: Arc<tokio::sync::Semaphore>,
}

impl HostFenceProviderQueueClient {
    pub async fn connect_from_async(
        dsn: DsnSource,
        ca_file: Option<String>,
        expected_schema: String,
    ) -> crate::store::Result<Arc<Self>> {
        validate_schema_name(&expected_schema)?;
        let executor = BlockingExecutor::new(
            "cats-host-fence-provider-pg",
            Limits {
                workers: HOST_FENCE_PROVIDER_POSTGRES_WORKERS,
                queue_capacity: HOST_FENCE_PROVIDER_POSTGRES_QUEUE_CAPACITY,
                cleanup_capacity: 1,
            },
        )
        .map_err(|error| {
            ApiError::unavailable(format!(
                "start Host-fence provider PostgreSQL lane: {error}"
            ))
        })?;
        let startup_dsn = dsn.clone();
        let startup_ca = ca_file.clone();
        let startup_schema = expected_schema.clone();
        let execution = executor
            .try_execute(move || {
                connect_verified_client(&startup_dsn, startup_ca.as_deref(), &startup_schema)
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
                HOST_FENCE_PROVIDER_POSTGRES_IN_FLIGHT,
            )),
        }))
    }

    async fn execute<T: Send + 'static>(
        self: &Arc<Self>,
        operation: impl FnOnce(&mut Client, &str) -> crate::store::Result<T> + Send + 'static,
    ) -> crate::store::Result<T> {
        let admission =
            self.admission.clone().try_acquire_owned().map_err(|_| {
                ApiError::unavailable("Host-fence provider PostgreSQL queue is full")
            })?;
        let this = Arc::clone(self);
        let execution = {
            let executor = match self.executor.lock() {
                Ok(executor) => executor,
                Err(poisoned) => poisoned.into_inner(),
            };
            let executor = executor.as_ref().ok_or_else(|| {
                ApiError::unavailable("Host-fence provider PostgreSQL lane is shutting down")
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
        operation: impl FnOnce(&mut Client, &str) -> crate::store::Result<T>,
    ) -> crate::store::Result<T> {
        let mut guard = match self.connection.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if guard.as_ref().is_none_or(Client::is_closed) {
            drop(guard.take());
            *guard = Some(connect_verified_client(
                &self.dsn,
                self.ca_file.as_deref(),
                &self.expected_schema,
            )?);
        }
        let client = guard
            .as_mut()
            .ok_or_else(|| internal("provider PostgreSQL reconnect returned no client"))?;
        let result = operation(client, &self.expected_schema);
        if client.is_closed() {
            drop(guard.take());
        }
        result
    }

    pub async fn claim(
        self: &Arc<Self>,
        provider_scope: cats_api::runtime_reconciliation::ProviderScope,
        worker_id: Id,
        claim_attempt_token: RandomId128,
        lease_duration: Duration,
    ) -> crate::store::Result<Option<HostFenceProviderClaimV1>> {
        let lease_ms = duration_ms(lease_duration)?;
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_host_fence_provider_claim_v1($1,$2,$3,$4,$5,$6,$7)",
                quote_schema(schema_name)
            );
            let rows = client
                .query(
                    &sql,
                    &[
                        &provider_scope.provider.as_str(),
                        &provider_scope.partition.as_str(),
                        &provider_scope.account_id.as_str(),
                        &provider_scope.region.as_str(),
                        &worker_id.as_str(),
                        &claim_attempt_token.as_str(),
                        &pg_client(lease_ms)?,
                    ],
                )
                .map_err(map_provider_postgres_error)?;
            if rows.len() > 1 {
                return Err(ApiError::failed_precondition(
                    "Host-fence provider claim returned more than one queue row",
                ));
            }
            rows.first()
                .map(|row| {
                    let bytes: Vec<u8> = row.try_get("request_bytes").map_err(internal)?;
                    let request = decode_client_request(&bytes)?;
                    let digest = request_sha256(&bytes);
                    if request.binding.provider_scope != provider_scope
                        || row
                            .try_get::<_, String>("request_sha256")
                            .map_err(internal)?
                            != digest.as_str()
                        || row.try_get::<_, String>("worker_id").map_err(internal)?
                            != worker_id.as_str()
                        || row
                            .try_get::<_, String>("claim_attempt_token")
                            .map_err(internal)?
                            != claim_attempt_token.as_str()
                    {
                        return Err(ApiError::failed_precondition(
                            "Host-fence provider claim result changed its exact binding",
                        ));
                    }
                    Ok(HostFenceProviderClaimV1 {
                        request,
                        request_sha256: digest,
                        worker_id,
                        claim_attempt_token,
                        claim_generation: wire_client(
                            row.try_get("claim_generation").map_err(internal)?,
                            "claim generation",
                        )?,
                        lease_expires_at_unix_ms: time_client(
                            row.try_get("claim_lease_expires_at_unix_ms")
                                .map_err(internal)?,
                            "claim lease",
                        )?,
                    })
                })
                .transpose()
        })
        .await
    }

    pub async fn renew(
        self: &Arc<Self>,
        claim: &HostFenceProviderClaimV1,
        renew_attempt_token: RandomId128,
        lease_duration: Duration,
    ) -> crate::store::Result<UnixMillis> {
        let claim = claim.clone();
        let lease_ms = duration_ms(lease_duration)?;
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT {}.control_host_fence_provider_renew_v1($1,$2,$3,$4)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(
                    &sql,
                    &[
                        &claim.request.binding.fence_attempt_id.as_str(),
                        &claim.claim_attempt_token.as_str(),
                        &renew_attempt_token.as_str(),
                        &pg_client(lease_ms)?,
                    ],
                )
                .map_err(map_provider_postgres_error)?;
            time_client(row.try_get(0).map_err(internal)?, "renewed claim lease")
        })
        .await
    }

    pub async fn read(
        self: &Arc<Self>,
        claim: &HostFenceProviderClaimV1,
    ) -> crate::store::Result<HostFenceProviderQueueRecordV1> {
        let claim = claim.clone();
        self.execute(move |client, schema_name| read_claimed_queue(client, schema_name, &claim))
            .await
    }

    pub async fn object_write_cutoff(
        self: &Arc<Self>,
        claim: &HostFenceProviderClaimV1,
    ) -> crate::store::Result<HostFenceProviderObjectCutoffV1> {
        let claim = claim.clone();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT result_kind, cutoff_receipt::TEXT AS cutoff_receipt_json \
                   FROM {}.control_host_fence_provider_object_cutoff_v1($1,$2)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(
                    &sql,
                    &[
                        &claim.request.binding.fence_attempt_id.as_str(),
                        &claim.claim_attempt_token.as_str(),
                    ],
                )
                .map_err(map_provider_postgres_error)?;
            let kind: String = row.try_get("result_kind").map_err(internal)?;
            let receipt: Option<String> = row.try_get("cutoff_receipt_json").map_err(internal)?;
            match (kind.as_str(), receipt) {
                ("pending", None) => Ok(HostFenceProviderObjectCutoffV1::Pending),
                ("complete", Some(receipt)) => {
                    let receipt: ObjectWriteCutoffReceipt = serde_json::from_str(&receipt)
                        .map_err(|error| {
                            ApiError::failed_precondition(format!(
                                "decode object-write cutoff receipt: {error}"
                            ))
                        })?;
                    if receipt.writer_authority_id
                        != claim.request.object_writer.writer_authority_id
                        || receipt.fence_attempt_id != claim.request.binding.fence_attempt_id
                    {
                        return Err(ApiError::failed_precondition(
                            "object-write cutoff receipt changed its sealed binding",
                        ));
                    }
                    Ok(HostFenceProviderObjectCutoffV1::Complete(Box::new(
                        cutoff_evidence(&claim.request, receipt).map_err(|error| {
                            ApiError::failed_precondition(format!(
                                "construct object-write cutoff evidence: {error}"
                            ))
                        })?,
                    )))
                }
                _ => Err(ApiError::failed_precondition(
                    "Host-fence provider cutoff returned an invalid result shape",
                )),
            }
        })
        .await
    }

    pub async fn complete(
        self: &Arc<Self>,
        claim: &HostFenceProviderClaimV1,
        evidence: &HostFenceProviderEvidence,
    ) -> crate::store::Result<HostFenceProviderQueueRecordV1> {
        validate_host_fence_provider_evidence(&claim.request, evidence).map_err(|error| {
            ApiError::invalid(format!("Host-fence provider evidence is invalid: {error}"))
        })?;
        let evidence_bytes = serde_json::to_vec(evidence)
            .map_err(|error| internal(format!("encode Host-fence provider evidence: {error}")))?;
        if evidence_bytes.len() > HOST_FENCE_PROVIDER_EVIDENCE_MAX_BYTES {
            return Err(ApiError::invalid(
                "Host-fence provider evidence exceeds its hard byte limit",
            ));
        }
        let digest = evidence_sha256(&evidence_bytes);
        let claim = claim.clone();
        self.execute(move |client, schema_name| {
            let sql = format!(
                "SELECT * FROM {}.control_host_fence_provider_complete_v1($1,$2,$3,$4)",
                quote_schema(schema_name)
            );
            let row = client
                .query_one(
                    &sql,
                    &[
                        &claim.request.binding.fence_attempt_id.as_str(),
                        &claim.claim_attempt_token.as_str(),
                        &evidence_bytes,
                        &digest.as_str(),
                    ],
                )
                .map_err(map_provider_postgres_error)?;
            if row
                .try_get::<_, Vec<u8>>("evidence_bytes")
                .map_err(internal)?
                != evidence_bytes
                || row
                    .try_get::<_, String>("evidence_sha256")
                    .map_err(internal)?
                    != digest.as_str()
            {
                return Err(ApiError::failed_precondition(
                    "Host-fence provider completion changed terminal evidence",
                ));
            }
            read_claimed_queue(client, schema_name, &claim)
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
            // Join the sole worker before touching its connection mutex. No
            // synchronous mutex wait or Client destructor runs on Tokio.
            drop(executor);
            let connection = match this.connection.lock() {
                Ok(mut connection) => connection.take(),
                Err(poisoned) => poisoned.into_inner().take(),
            };
            drop(connection);
        })
        .await
        {
            tracing::error!(%error, "join Host-fence provider PostgreSQL lane");
        }
    }
}

fn map_submit_error(error: SubmitError) -> ApiError {
    match error {
        SubmitError::Full => ApiError::unavailable("Host-fence provider PostgreSQL queue is full"),
        SubmitError::Shutdown => {
            ApiError::unavailable("Host-fence provider PostgreSQL lane is shutting down")
        }
    }
}

fn map_execution_error(error: ExecutionError) -> ApiError {
    match error {
        ExecutionError::Panicked => internal("Host-fence provider PostgreSQL lane job panicked"),
        ExecutionError::Shutdown => {
            ApiError::unavailable("Host-fence provider PostgreSQL lane stopped")
        }
    }
}

fn validate_schema_name(schema_name: &str) -> crate::store::Result<()> {
    if schema_name.is_empty() || schema_name.len() > 63 || schema_name.as_bytes().contains(&0) {
        return Err(ApiError::invalid(
            "Host-fence provider PostgreSQL schema name is invalid",
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
) -> crate::store::Result<Client> {
    let mut client = schema::connect_client(dsn, ca_file)?;
    client
        .batch_execute("SET statement_timeout='5s'; SET lock_timeout='2s'")
        .map_err(map_provider_postgres_error)?;
    let identity = client
        .query_one(
            "SELECT current_user::TEXT, session_user::TEXT, current_schema()::TEXT",
            &[],
        )
        .map_err(map_provider_postgres_error)?;
    let current_user: String = identity.try_get(0).map_err(internal)?;
    let session_user: String = identity.try_get(1).map_err(internal)?;
    let current_schema: String = identity.try_get(2).map_err(internal)?;
    if current_user != HOST_FENCE_PROVIDER_POSTGRES_ROLE
        || session_user != HOST_FENCE_PROVIDER_POSTGRES_ROLE
        || current_schema != expected_schema
    {
        return Err(ApiError::unauthenticated(
            "Host-fence provider PostgreSQL login role or schema is not exact",
        ));
    }
    let startup = format!(
        "SELECT * FROM {}.control_host_fence_provider_startup_v1()",
        quote_schema(expected_schema)
    );
    let row = client
        .query_one(&startup, &[])
        .map_err(map_provider_postgres_error)?;
    if row
        .try_get::<_, i64>("protocol_version")
        .map_err(internal)?
        != i64::from(HOST_FENCE_PROVIDER_QUEUE_VERSION_V1)
        || row.try_get::<_, String>("schema_name").map_err(internal)? != expected_schema
        || row
            .try_get::<_, String>("expected_role")
            .map_err(internal)?
            != HOST_FENCE_PROVIDER_POSTGRES_ROLE
    {
        return Err(ApiError::failed_precondition(
            "Host-fence provider PostgreSQL startup contract mismatch",
        ));
    }
    Ok(client)
}

fn duration_ms(duration: Duration) -> crate::store::Result<u64> {
    let millis = u64::try_from(duration.as_millis())
        .map_err(|_| ApiError::invalid("Host-fence provider lease exceeds its integer bound"))?;
    if !(1..=HOST_FENCE_PROVIDER_LEASE_MAX_MS).contains(&millis) {
        return Err(ApiError::invalid(
            "Host-fence provider lease is outside 1..=60000 milliseconds",
        ));
    }
    Ok(millis)
}

fn pg_client(value: u64) -> crate::store::Result<i64> {
    i64::try_from(value).map_err(|_| ApiError::invalid("PostgreSQL integer exceeds BIGINT"))
}

fn wire_client(value: i64, label: &str) -> crate::store::Result<u64> {
    u64::try_from(value)
        .map_err(|_| ApiError::failed_precondition(format!("stored {label} is negative")))
}

fn time_client(value: i64, label: &str) -> crate::store::Result<UnixMillis> {
    UnixMillis::new(wire_client(value, label)?)
        .ok_or_else(|| ApiError::failed_precondition(format!("stored {label} is invalid")))
}

fn map_authority_decode_error(error: AuthorityTransactionError) -> ApiError {
    match error {
        AuthorityTransactionError::Application(error) => error,
        AuthorityTransactionError::Postgres(error) => internal(error),
        AuthorityTransactionError::Domain(_)
        | AuthorityTransactionError::CandidateCollision
        | AuthorityTransactionError::PlacementStale => ApiError::failed_precondition(
            "stored Host-fence provider record failed domain validation",
        ),
    }
}

fn decode_client_request(bytes: &[u8]) -> crate::store::Result<HostFenceAttemptRequest> {
    decode_canonical_request(bytes).map_err(map_authority_decode_error)
}

fn read_claimed_queue(
    client: &mut Client,
    schema_name: &str,
    claim: &HostFenceProviderClaimV1,
) -> crate::store::Result<HostFenceProviderQueueRecordV1> {
    let sql = format!(
        "SELECT * FROM {}.control_host_fence_provider_read_v1($1,$2)",
        quote_schema(schema_name)
    );
    let row = client
        .query_opt(
            &sql,
            &[
                &claim.request.binding.fence_attempt_id.as_str(),
                &claim.claim_attempt_token.as_str(),
            ],
        )
        .map_err(map_provider_postgres_error)?
        .ok_or_else(|| ApiError::conflict("Host-fence provider claim is stale"))?;
    decode_queue_row(&row).map_err(map_authority_decode_error)
}

fn map_provider_postgres_error(error: postgres::Error) -> ApiError {
    match error.code().map(postgres::error::SqlState::code) {
        Some("22023") => ApiError::invalid("Host-fence provider request was rejected"),
        Some("42501") => ApiError::unauthenticated(
            "Host-fence provider PostgreSQL privilege boundary rejected the session",
        ),
        Some("55000") | Some("23505") | Some("23514") => {
            ApiError::conflict("Host-fence provider claim or binding is stale")
        }
        Some("57014") | Some("55P03") => {
            ApiError::unavailable("Host-fence provider PostgreSQL operation timed out")
        }
        _ if error.is_closed() => {
            ApiError::unavailable("Host-fence provider PostgreSQL connection closed")
        }
        _ => internal(error),
    }
}
