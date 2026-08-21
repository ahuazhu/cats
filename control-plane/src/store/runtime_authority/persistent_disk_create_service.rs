//! Strict synchronous PersistentDisk-create ingress and commit owner.
//!
//! This service has no runtime Operation or external storage side effect. A
//! first request publishes one blank Volume, one uninitialized PersistentDisk
//! and its exact HTTP result in a single PostgreSQL commit. Replay reads only
//! the stored result.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::time::{Duration, Instant};

use cats_api::error::{ApiError, ErrorCode};
use cats_api::persistent_disk::{
    encode_persistent_disk_name_conflict_response, DiskDurability, PersistentDiskCreateV1Error,
    PersistentDiskCreateV1Request,
};
use cats_api::runtime_reconciliation::{AsciiText, Id, RandomId128};
use cats_storage::authority::VolumeDurability;
use serde::Deserialize;

use super::covered_commit::{CommitResolutionRegistry, CoveredCommitCancellation};
use super::product::{
    api_request_fingerprint, ApiIdempotencyRequest, ApiIdempotencyResult, CandidateCollision,
    CoveredPersistentDiskCreateError, CoveredPersistentDiskCreateRequest, ExactContentType,
    ExactHttpResponse, IfMatchFingerprint, PersistentDiskCreateCandidate,
};
use super::product_identity::ProductIdentitySource;
use crate::store::{Result, Store};

pub(crate) const PERSISTENT_DISK_CREATE_MAX_BODY_BYTES: usize = 4096;
pub(crate) const PERSISTENT_DISK_CREATE_CANONICAL_ROUTE: &str =
    "POST /v1/workspaces/{workspace}/disks";
const PERSISTENT_DISK_CREATE_CONTENT_TYPE: &[u8] = b"application/json";
const IDENTITY_CONTENT_ENCODING: &[u8] = b"identity";
const PERSISTENT_DISK_CREATE_TOTAL_DEADLINE: Duration = Duration::from_secs(10);
const PERSISTENT_DISK_CREATE_RESOLUTION_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(30);
const MAX_CANDIDATE_BUNDLES: usize = 32;

pub(crate) fn persistent_disk_create_absolute_deadline(
    headers_received_at: Instant,
) -> Result<Instant> {
    headers_received_at
        .checked_add(PERSISTENT_DISK_CREATE_TOTAL_DEADLINE)
        .ok_or_else(|| ApiError::unavailable("PersistentDisk create deadline overflow"))
}

#[derive(Debug, Clone, Default)]
pub(crate) struct PersistentDiskCreateHttpFields {
    pub(crate) content_type: Vec<Vec<u8>>,
    pub(crate) content_encoding: Vec<Vec<u8>>,
    pub(crate) if_match: Vec<Vec<u8>>,
    pub(crate) idempotency_key: Vec<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct AuthorizedPersistentDiskCreateIngress {
    request: PersistentDiskCreateV1Request,
    idempotency: ApiIdempotencyRequest,
    absolute_deadline: Instant,
}

impl AuthorizedPersistentDiskCreateIngress {
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

pub(crate) fn parse_authorized_persistent_disk_create(
    authenticated_workspace_id: &Id,
    headers_received_at: Instant,
    raw_path_and_query: &[u8],
    fields: &PersistentDiskCreateHttpFields,
    raw_body: &[u8],
) -> Result<AuthorizedPersistentDiskCreateIngress> {
    let absolute_deadline = persistent_disk_create_absolute_deadline(headers_received_at)?;
    if Instant::now() >= absolute_deadline {
        return Err(ApiError::unavailable(
            "PersistentDisk create deadline elapsed",
        ));
    }
    if raw_body.len() > PERSISTENT_DISK_CREATE_MAX_BODY_BYTES {
        return Err(ApiError::invalid(
            "PersistentDisk create body exceeds 4096 bytes",
        ));
    }
    match fields.content_type.as_slice() {
        [value] if value.as_slice() == PERSISTENT_DISK_CREATE_CONTENT_TYPE => {}
        _ => {
            return Err(ApiError::invalid(
                "Content-Type must occur once and equal application/json",
            ));
        }
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
    if !fields.if_match.is_empty() {
        return Err(ApiError::invalid(
            "If-Match is not allowed for PersistentDisk create",
        ));
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

    let expected_path = format!("/v1/workspaces/{authenticated_workspace_id}/disks");
    if raw_path_and_query != expected_path.as_bytes() {
        return Err(ApiError::invalid(
            "PersistentDisk create path must use the canonical workspace ID and no query",
        ));
    }

    let mut decoder = serde_json::Deserializer::from_slice(raw_body);
    let request = PersistentDiskCreateV1Request::deserialize(&mut decoder)
        .map_err(|_| ApiError::invalid("PersistentDisk create body is malformed"))?;
    decoder
        .end()
        .map_err(|_| ApiError::invalid("PersistentDisk create body has a non-whitespace tail"))?;
    request.validate().map_err(|error| match error {
        PersistentDiskCreateV1Error::SizeBytes => ApiError::invalid(error.to_string()),
    })?;

    let canonical_route = AsciiText::new(PERSISTENT_DISK_CREATE_CANONICAL_ROUTE)
        .expect("the canonical PersistentDisk-create route is valid ASCII");
    let request_fingerprint = api_request_fingerprint(
        authenticated_workspace_id,
        &canonical_route,
        raw_path_and_query,
        IfMatchFingerprint::Absent,
        raw_body,
    )?;
    Ok(AuthorizedPersistentDiskCreateIngress {
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
struct PersistentDiskCreateIdentities {
    disk: RandomId128,
    volume: RandomId128,
    initialization_token: RandomId128,
    filesystem_uuid: RandomId128,
}

impl PersistentDiskCreateIdentities {
    fn generate(source: &dyn ProductIdentitySource) -> Result<Option<Self>> {
        let identities = Self {
            disk: source.random_id()?,
            volume: source.random_id()?,
            initialization_token: source.random_id()?,
            filesystem_uuid: source.random_id()?,
        };
        let distinct = BTreeSet::from([
            identities.disk.as_str(),
            identities.volume.as_str(),
            identities.initialization_token.as_str(),
            identities.filesystem_uuid.as_str(),
        ]);
        Ok((distinct.len() == 4).then_some(identities))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct PersistentDiskCreateHttpResult {
    pub(crate) http_status: u16,
    pub(crate) content_type: Option<&'static str>,
    pub(crate) response_body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) enum PersistentDiskCreateServiceError {
    Request(ApiError),
    TemporarilyUnavailable,
    Fatal(ApiError),
}

impl PersistentDiskCreateServiceError {
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
            Self::TemporarilyUnavailable => ErrorCode::Unavailable,
        }
    }
}

impl From<ApiError> for PersistentDiskCreateServiceError {
    fn from(error: ApiError) -> Self {
        Self::from_api(error)
    }
}

enum PersistentDiskCommitOutcome {
    Committed(ApiIdempotencyResult),
    CandidateIdentityCollision,
}

pub(crate) struct PersistentDiskCreateService {
    store: Arc<Store>,
    identities: Arc<dyn ProductIdentitySource>,
    commit_resolutions: Arc<CommitResolutionRegistry>,
    admission: tokio::sync::watch::Sender<bool>,
}

impl PersistentDiskCreateService {
    pub(crate) fn new(store: Arc<Store>, identities: Arc<dyn ProductIdentitySource>) -> Self {
        let (admission, _) = tokio::sync::watch::channel(true);
        Self {
            store,
            identities,
            commit_resolutions: Arc::new(CommitResolutionRegistry::default()),
            admission,
        }
    }

    pub(crate) async fn create(
        &self,
        ingress: AuthorizedPersistentDiskCreateIngress,
    ) -> std::result::Result<PersistentDiskCreateHttpResult, PersistentDiskCreateServiceError> {
        let shutdown = self.admission.subscribe();
        if !*shutdown.borrow() {
            return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
        }
        let absolute_deadline = ingress.absolute_deadline;
        if let Some(result) = self.fast_replay(&ingress).await? {
            return Ok(result);
        }

        let mut shutdown = shutdown;
        for _ in 0..MAX_CANDIDATE_BUNDLES {
            if Instant::now() >= absolute_deadline || !*shutdown.borrow() {
                return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
            }
            let Some(identities) =
                PersistentDiskCreateIdentities::generate(self.identities.as_ref())
                    .map_err(PersistentDiskCreateServiceError::from_api)?
            else {
                continue;
            };
            let covered = build_covered_request(&ingress, identities)
                .map_err(PersistentDiskCreateServiceError::from_api)?;
            match self
                .commit_candidate(covered, absolute_deadline, &mut shutdown)
                .await?
            {
                PersistentDiskCommitOutcome::Committed(result) => {
                    return Ok(http_result(result));
                }
                PersistentDiskCommitOutcome::CandidateIdentityCollision => continue,
            }
        }
        Err(PersistentDiskCreateServiceError::TemporarilyUnavailable)
    }

    /// Reads an authenticated request's exact durable result without any
    /// mutable create admission. This is the response-loss recovery boundary:
    /// billing may change after the original atomic commit, but it cannot hide
    /// the already-covered result from the same Workspace/key/fingerprint.
    pub(crate) async fn replay(
        &self,
        ingress: &AuthorizedPersistentDiskCreateIngress,
    ) -> std::result::Result<Option<PersistentDiskCreateHttpResult>, PersistentDiskCreateServiceError>
    {
        if !*self.admission.borrow() {
            return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
        }
        self.fast_replay(ingress).await
    }

    async fn fast_replay(
        &self,
        ingress: &AuthorizedPersistentDiskCreateIngress,
    ) -> std::result::Result<Option<PersistentDiskCreateHttpResult>, PersistentDiskCreateServiceError>
    {
        let fast_request = ingress.idempotency.clone();
        await_before_deadline(
            ingress.absolute_deadline,
            self.store
                .execute(move |store| store.covered_api_result_fast_lookup(&fast_request)),
        )
        .await
        .map(|result| result.map(http_result))
        .map_err(PersistentDiskCreateServiceError::from_api)
    }

    async fn commit_candidate(
        &self,
        covered: CoveredPersistentDiskCreateRequest,
        absolute_deadline: Instant,
        shutdown: &mut tokio::sync::watch::Receiver<bool>,
    ) -> std::result::Result<PersistentDiskCommitOutcome, PersistentDiskCreateServiceError> {
        let resolution_request = covered.idempotency.clone();
        let (commit_cancellation, commit_state) =
            CoveredCommitCancellation::new("PersistentDisk create", absolute_deadline);
        let commit_observer = commit_state.clone();
        let cancellation_observer = commit_state.clone();
        let store = Arc::clone(&self.store);
        let Some(active) = self.commit_resolutions.begin() else {
            return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
        };
        let (result_tx, mut result_rx) = tokio::sync::oneshot::channel();
        tokio::spawn(async move {
            let execution_store = Arc::clone(&store);
            let execution = execution_store.execute(move |store| {
                Ok(store.create_persistent_disk_covered(&covered, &commit_state))
            });
            tokio::pin!(execution);
            let execution_outcome = tokio::select! {
                outcome = &mut execution => outcome,
                () = cancellation_observer.cancelled_before_commit() => {
                    Err(ApiError::unavailable(
                        "PersistentDisk create was cancelled before PostgreSQL commit",
                    ))
                }
            };
            let outcome = match execution_outcome {
                Ok(Ok(result)) => Ok(PersistentDiskCommitOutcome::Committed(result)),
                Ok(Err(CoveredPersistentDiskCreateError::CandidateCollision(kind))) => {
                    debug_assert!(matches!(
                        kind,
                        CandidateCollision::DiskIdOrName
                            | CandidateCollision::VolumeId
                            | CandidateCollision::InitializationToken
                            | CandidateCollision::FilesystemUuid
                    ));
                    Ok(PersistentDiskCommitOutcome::CandidateIdentityCollision)
                }
                Ok(Err(CoveredPersistentDiskCreateError::Store(error))) | Err(error)
                    if commit_observer.commit_was_sent() =>
                {
                    resolve_commit_loop(store, resolution_request, error)
                        .await
                        .map(PersistentDiskCommitOutcome::Committed)
                }
                Ok(Err(CoveredPersistentDiskCreateError::Store(error))) | Err(error) => Err(error),
            };
            let _ = result_tx.send(outcome);
            drop(active);
        });

        let deadline = tokio::time::sleep_until(tokio::time::Instant::from_std(absolute_deadline));
        tokio::pin!(deadline);
        let outcome = tokio::select! {
            result = &mut result_rx => result.map_err(|_| {
                ApiError::internal("PersistentDisk create commit owner stopped without a result")
            })?,
            () = &mut deadline => {
                if commit_cancellation.cancel_before_commit() {
                    return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
                }
                result_rx.await.map_err(|_| {
                    ApiError::internal("PersistentDisk create commit owner stopped without a result")
                })?
            },
            () = wait_for_shutdown(shutdown) => {
                if commit_cancellation.cancel_before_commit() {
                    return Err(PersistentDiskCreateServiceError::TemporarilyUnavailable);
                }
                result_rx.await.map_err(|_| {
                    ApiError::internal("PersistentDisk create commit owner stopped without a result")
                })?
            }
        };
        outcome.map_err(PersistentDiskCreateServiceError::from_api)
    }

    pub(crate) fn begin_shutdown(&self) {
        self.commit_resolutions.close();
        self.admission.send_replace(false);
    }

    pub(crate) async fn shutdown_commit_resolutions(&self) -> Result<()> {
        self.begin_shutdown();
        tokio::time::timeout(
            PERSISTENT_DISK_CREATE_RESOLUTION_SHUTDOWN_DEADLINE,
            self.commit_resolutions.wait_empty(),
        )
        .await
        .map_err(|_| {
            ApiError::unavailable(format!(
                "{} PersistentDisk create commit resolutions remain after shutdown deadline",
                self.commit_resolutions.active()
            ))
        })
    }

    #[cfg(test)]
    pub(super) fn active_commit_resolutions(&self) -> usize {
        self.commit_resolutions.active()
    }
}

fn build_covered_request(
    ingress: &AuthorizedPersistentDiskCreateIngress,
    identities: PersistentDiskCreateIdentities,
) -> Result<CoveredPersistentDiskCreateRequest> {
    let disk_id = prefixed_id("disk_", &identities.disk)?;
    let volume_id = prefixed_id("vol_", &identities.volume)?;
    let durability = match ingress.request.durability {
        DiskDurability::Strict => VolumeDurability::Strict,
        DiskDurability::Relaxed => VolumeDurability::Relaxed,
    };
    Ok(CoveredPersistentDiskCreateRequest {
        idempotency: ingress.idempotency.clone(),
        candidate: PersistentDiskCreateCandidate {
            disk_id,
            workspace_id: ingress.idempotency.authenticated_workspace_id.clone(),
            name: ingress.request.name.clone(),
            volume_id,
            size_bytes: ingress.request.size_bytes,
            durability,
            initialization_token: identities.initialization_token,
            filesystem_uuid: identities.filesystem_uuid,
        },
        name_conflict: ExactHttpResponse::new(
            409,
            Some(ExactContentType::ApplicationJson),
            encode_persistent_disk_name_conflict_response(),
        )?,
    })
}

fn prefixed_id(prefix: &str, random: &RandomId128) -> Result<Id> {
    Id::new(format!("{prefix}{}", random.as_str()))
        .ok_or_else(|| ApiError::internal("PersistentDisk candidate identity is invalid"))
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
    absolute_deadline: Instant,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    tokio::time::timeout_at(tokio::time::Instant::from_std(absolute_deadline), operation)
        .await
        .map_err(|_| ApiError::unavailable("PersistentDisk create deadline elapsed"))?
}

fn http_result(result: ApiIdempotencyResult) -> PersistentDiskCreateHttpResult {
    PersistentDiskCreateHttpResult {
        http_status: result.http_status,
        content_type: result.content_type.map(ExactContentType::as_str),
        response_body: result.response_body,
    }
}
