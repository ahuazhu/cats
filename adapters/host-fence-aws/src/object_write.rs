use std::collections::BTreeMap;
use std::future::Future;
use std::io::SeekFrom;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use aws_sdk_s3::config::retry::RetryConfig;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::{RequestId as _, RequestIdExt as _};
use aws_sdk_s3::primitives::{ByteStream, Length};
use aws_sdk_s3::types::{ChecksumAlgorithm, ChecksumMode};
use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use cats_api::object_write_gateway::object_write_key;
use cats_api::object_write_gateway::{
    ObjectWriteConditionalRequestEvidenceV1, ObjectWriteConditionalRequestOutcomeV1,
    ObjectWriteProviderRequestObservationV1, ObjectWriteQualificationHeadEvidenceV1,
    ObjectWriteSuccessfulPutV1,
};
#[cfg(test)]
use cats_api::runtime_reconciliation::Id;
use cats_api::runtime_reconciliation::{AsciiText, ProviderScope, Sha256Digest, UnixMillis};
use cats_storage::object_write_authority::{
    object_put_provider_attempt_id, object_put_request_id, validate_downstream_put,
    validate_qualification_downstream_put, ObjectPutDescriptor, ObjectWriteDownstreamError,
    ObjectWriteDownstreamFuture, ObjectWriteDownstreamPut, ObjectWriteDownstreamPutOutcome,
    ObjectWriteGatewayDownstream, ObjectWriteQualificationPut, ObjectWriteQualificationPutOutcome,
    ObjectWriteVisibilityOutcome,
};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};

use crate::VerifiedAwsProviderBinding;

const SPOOL_FILE_SUFFIX: &str = ".body";
const SPOOL_READ_BUFFER_BYTES: usize = 64 * 1024;
const CONTENT_SHA256_METADATA: &str = "cats-content-sha256";
const CONTENT_LENGTH_METADATA: &str = "cats-content-length";

fn put_retry_config() -> RetryConfig {
    // The outer accepted-write state machine performs HEAD discovery before
    // every conditional PUT retry and revalidates a fresh pinned EFS handle.
    // One adapter invocation is deliberately one provider request attempt;
    // the SDK must never replay its consumed handle behind that state machine.
    RetryConfig::disabled()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsObjectWriteConfig {
    provider_scope: ProviderScope,
    bucket: String,
    object_store_prefix: String,
    object_store_scope_id: AsciiText,
    durable_spool_root: PathBuf,
    durable_spool_root_uid: u32,
}

impl AwsObjectWriteConfig {
    pub fn new(
        provider_scope: ProviderScope,
        bucket: String,
        object_store_prefix: String,
        object_store_scope_id: AsciiText,
        durable_spool_root: PathBuf,
    ) -> Result<Self, ObjectWriteDownstreamError> {
        let expected_object_store_scope_id = format!(
            "arn:{}:s3:::{}/{}",
            provider_scope.partition, bucket, object_store_prefix
        );
        if provider_scope.provider.as_str() != "aws"
            || !valid_bucket_name(&bucket)
            || !valid_provider_prefix(&object_store_prefix)
            || object_store_scope_id.as_str() != expected_object_store_scope_id
            || !durable_spool_root.is_absolute()
        {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        let metadata = std::fs::symlink_metadata(&durable_spool_root)
            .map_err(|_| ObjectWriteDownstreamError::Unavailable)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        let canonical_spool_root = std::fs::canonicalize(&durable_spool_root)
            .map_err(|_| ObjectWriteDownstreamError::Unavailable)?;
        if canonical_spool_root != durable_spool_root {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        Ok(Self {
            provider_scope,
            bucket,
            object_store_prefix,
            object_store_scope_id,
            durable_spool_root: canonical_spool_root,
            durable_spool_root_uid: metadata.uid(),
        })
    }

    pub fn provider_scope(&self) -> &ProviderScope {
        &self.provider_scope
    }

    pub fn bucket(&self) -> &str {
        &self.bucket
    }

    pub fn object_store_prefix(&self) -> &str {
        &self.object_store_prefix
    }

    pub fn object_store_scope_id(&self) -> &AsciiText {
        &self.object_store_scope_id
    }

    fn provider_key(
        &self,
        descriptor: &ObjectPutDescriptor,
    ) -> Result<String, ObjectWriteDownstreamError> {
        self.validate_provider_descriptor(descriptor)?;
        Ok(format!(
            "{}/{}",
            self.object_store_prefix, descriptor.target.canonical_logical_key
        ))
    }

    fn validate_provider_descriptor(
        &self,
        descriptor: &ObjectPutDescriptor,
    ) -> Result<(), ObjectWriteDownstreamError> {
        let expected_key = object_write_key(
            &descriptor.volume_id,
            &descriptor.key,
            &descriptor.content_sha256,
        )
        .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?;
        if descriptor.target.object_provider_scope != self.provider_scope
            || descriptor.target.object_store_scope_id != self.object_store_scope_id
            || descriptor.target.canonical_logical_key != expected_key
        {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        Ok(())
    }

    fn spool_path(&self, spool_id: &AsciiText) -> Result<PathBuf, ObjectWriteDownstreamError> {
        let value = spool_id.as_str();
        let digest = value
            .strip_prefix("owsp1_")
            .ok_or(ObjectWriteDownstreamError::InvalidRequest)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        Ok(self
            .durable_spool_root
            .join(format!("{value}{SPOOL_FILE_SUFFIX}")))
    }
}

pub struct AwsObjectWriteGatewayDownstream {
    config: AwsObjectWriteConfig,
    s3: Arc<dyn ExactS3Api>,
}

impl AwsObjectWriteGatewayDownstream {
    pub fn from_verified_binding(
        config: AwsObjectWriteConfig,
        binding: &VerifiedAwsProviderBinding,
    ) -> Result<Self, ObjectWriteDownstreamError> {
        if binding.provider_scope() != config.provider_scope() {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        Ok(Self {
            config,
            s3: Arc::new(SdkExactS3Api {
                client: binding.s3_client(),
            }),
        })
    }

    #[cfg(test)]
    fn with_api(config: AwsObjectWriteConfig, s3: Arc<dyn ExactS3Api>) -> Self {
        Self { config, s3 }
    }

    async fn put(
        &self,
        request: ObjectWriteDownstreamPut,
        absolute_deadline: Instant,
    ) -> Result<ObjectWriteDownstreamPutOutcome, ObjectWriteDownstreamError> {
        // Flattening every authority verdict into one downstream error made a
        // production refusal unreadable: the Gateway could only report that the
        // provider rejected a request it had in fact never sent. Name the exact
        // rule, and separate "the caller's deadline is already spent" from "this
        // request or receipt is malformed" — the first is a timeout the caller
        // can retry, the second never becomes valid.
        if let Err(error) = validate_downstream_put(&request, absolute_deadline) {
            tracing::warn!(
                verdict = %error,
                key = %request.descriptor.target.canonical_logical_key,
                request_id = %request.descriptor.request_id.as_str(),
                deadline_spent = Instant::now() >= absolute_deadline,
                "object-write downstream refused the sealed request before any provider call",
            );
            return Err(if Instant::now() >= absolute_deadline {
                ObjectWriteDownstreamError::DeadlineExceeded
            } else {
                ObjectWriteDownstreamError::InvalidRequest
            });
        }
        match self
            .conditional_put(&request.descriptor, &request.spool, absolute_deadline)
            .await?
        {
            AwsConditionalPutOutcome::Created(successful_put) => {
                Ok(ObjectWriteDownstreamPutOutcome::Succeeded {
                    provider_attempt_id: successful_put.provider_attempt_id,
                    put_receipt_id: successful_put.put_receipt_id,
                    completed_at_unix_ms: successful_put.completed_at_unix_ms,
                })
            }
            AwsConditionalPutOutcome::PreconditionFailedExactVisible(head) => {
                Ok(ObjectWriteDownstreamPutOutcome::Succeeded {
                    provider_attempt_id: head.provider_attempt_id,
                    put_receipt_id: replay_put_receipt_id(
                        &request.descriptor,
                        &head.visibility_receipt_id,
                    )?,
                    completed_at_unix_ms: head.observed_at_unix_ms,
                })
            }
            AwsConditionalPutOutcome::Conflicting {
                failure_receipt_id,
                failed_at_unix_ms,
            } => Ok(ObjectWriteDownstreamPutOutcome::PermanentlyFailed {
                provider_attempt_id: request.descriptor.provider_attempt_id,
                failure_receipt_id,
                failed_at_unix_ms,
            }),
        }
    }

    async fn put_qualification(
        &self,
        request: &ObjectWriteQualificationPut,
    ) -> Result<ObjectWriteQualificationPutOutcome, ObjectWriteDownstreamError> {
        validate_qualification_downstream_put(request)
            .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?;
        let absolute_deadline = request.absolute_deadline();
        match self
            .conditional_put(request.descriptor(), request.spool(), absolute_deadline)
            .await?
        {
            AwsConditionalPutOutcome::Created(successful_put) => Ok(
                ObjectWriteQualificationPutOutcome::SuccessfulPut(Box::new(successful_put)),
            ),
            AwsConditionalPutOutcome::PreconditionFailedExactVisible(head) => Ok(
                ObjectWriteQualificationPutOutcome::PreconditionFailedExactVisible(Box::new(head)),
            ),
            AwsConditionalPutOutcome::Conflicting { .. } => {
                Err(ObjectWriteDownstreamError::ConflictingObject)
            }
        }
    }

    async fn conditional_put(
        &self,
        descriptor: &ObjectPutDescriptor,
        spool: &cats_storage::object_write_authority::DurableObjectWriteSpoolReceipt,
        absolute_deadline: Instant,
    ) -> Result<AwsConditionalPutOutcome, ObjectWriteDownstreamError> {
        let provider_key = self.config.provider_key(descriptor)?;
        let spool_path = self.config.spool_path(&spool.spool_id)?;
        let spool_file = validate_spool_file(
            &spool_path,
            descriptor,
            self.config.durable_spool_root_uid,
            absolute_deadline,
        )
        .await?;

        let checksum_sha256 = STANDARD.encode(descriptor.content_sha256.as_bytes());
        let metadata = BTreeMap::from([
            (
                CONTENT_SHA256_METADATA.to_owned(),
                descriptor.content_sha256.as_str().to_owned(),
            ),
            (
                CONTENT_LENGTH_METADATA.to_owned(),
                descriptor.content_length.get().to_string(),
            ),
        ]);
        let put = ExactPutRequest {
            bucket: self.config.bucket.clone(),
            key: provider_key.clone(),
            spool_file,
            content_length: descriptor.content_length.get(),
            checksum_sha256,
            metadata,
        };

        match self.s3.put_exact(put, absolute_deadline).await {
            Ok(observation) => {
                if observation.checksum_sha256
                    != STANDARD.encode(descriptor.content_sha256.as_bytes())
                {
                    return Err(ObjectWriteDownstreamError::Ambiguous);
                }
                Ok(AwsConditionalPutOutcome::Created(
                    ObjectWriteSuccessfulPutV1 {
                        provider_attempt_id: descriptor.provider_attempt_id.clone(),
                        put_receipt_id: put_receipt_id(descriptor, &observation, b"created")?,
                        provider_request: put_provider_request_observation(
                            descriptor,
                            &observation,
                        ),
                        completed_at_unix_ms: observation.completed_at_unix_ms,
                    },
                ))
            }
            Err(S3CallError::PreconditionFailed(conditional)) => match self
                .s3
                .head_exact(&self.config.bucket, &provider_key, absolute_deadline)
                .await
            {
                Ok(observation) if head_matches(descriptor, &observation) => {
                    Ok(AwsConditionalPutOutcome::PreconditionFailedExactVisible(
                        ObjectWriteQualificationHeadEvidenceV1 {
                            provider_attempt_id: descriptor.provider_attempt_id.clone(),
                            visibility_receipt_id: visibility_receipt_id(descriptor, &observation)?,
                            preceding_conditional_request: Some(Box::new(
                                conditional_request_evidence(descriptor, &conditional),
                            )),
                            provider_request: head_provider_request_observation(
                                descriptor,
                                &observation,
                            )?,
                            observed_at_unix_ms: observation.observed_at_unix_ms,
                        },
                    ))
                }
                Ok(observation) => Ok(AwsConditionalPutOutcome::Conflicting {
                    failure_receipt_id: conflict_failure_receipt_id(descriptor, &observation)?,
                    failed_at_unix_ms: observation.observed_at_unix_ms,
                }),
                Err(S3CallError::NotFound) => Err(ObjectWriteDownstreamError::Ambiguous),
                Err(error) => Err(map_read_error(error)),
            },
            Err(error) => Err(map_put_error(error)),
        }
    }

    async fn discover(
        &self,
        descriptor: &ObjectPutDescriptor,
        absolute_deadline: Instant,
    ) -> Result<ObjectWriteVisibilityOutcome, ObjectWriteDownstreamError> {
        validate_descriptor_for_discovery(descriptor, absolute_deadline)?;
        let provider_key = self.config.provider_key(descriptor)?;
        match self
            .s3
            .head_exact(&self.config.bucket, &provider_key, absolute_deadline)
            .await
        {
            Ok(observation) => {
                if !head_matches(descriptor, &observation) {
                    return Ok(ObjectWriteVisibilityOutcome::ConflictingObject);
                }
                Ok(ObjectWriteVisibilityOutcome::VisibleExact {
                    provider_attempt_id: descriptor.provider_attempt_id.clone(),
                    visibility_receipt_id: visibility_receipt_id(descriptor, &observation)?,
                    provider_request: Box::new(head_provider_request_observation(
                        descriptor,
                        &observation,
                    )?),
                    preceding_conditional_request: None,
                    observed_at_unix_ms: observation.observed_at_unix_ms,
                })
            }
            Err(S3CallError::NotFound) => Ok(ObjectWriteVisibilityOutcome::NotVisible),
            Err(S3CallError::PreconditionFailed(_)) => Err(ObjectWriteDownstreamError::Ambiguous),
            Err(error) => Err(map_read_error(error)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum AwsConditionalPutOutcome {
    Created(ObjectWriteSuccessfulPutV1),
    PreconditionFailedExactVisible(ObjectWriteQualificationHeadEvidenceV1),
    Conflicting {
        failure_receipt_id: AsciiText,
        failed_at_unix_ms: UnixMillis,
    },
}

impl ObjectWriteGatewayDownstream for AwsObjectWriteGatewayDownstream {
    fn put_exact<'a>(
        &'a self,
        request: ObjectWriteDownstreamPut,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteDownstreamPutOutcome> {
        Box::pin(async move { self.put(request, absolute_deadline).await })
    }

    fn put_qualification_exact<'a>(
        &'a self,
        request: &'a ObjectWriteQualificationPut,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteQualificationPutOutcome> {
        Box::pin(async move { self.put_qualification(request).await })
    }

    fn discover_visibility<'a>(
        &'a self,
        descriptor: &'a ObjectPutDescriptor,
        absolute_deadline: Instant,
    ) -> ObjectWriteDownstreamFuture<'a, ObjectWriteVisibilityOutcome> {
        Box::pin(async move { self.discover(descriptor, absolute_deadline).await })
    }
}

fn validate_descriptor_for_discovery(
    descriptor: &ObjectPutDescriptor,
    absolute_deadline: Instant,
) -> Result<(), ObjectWriteDownstreamError> {
    if Instant::now() >= absolute_deadline
        || object_put_request_id(
            &descriptor.writer_authority_id,
            &descriptor.target,
            &descriptor.volume_id,
            &descriptor.key,
            &descriptor.content_sha256,
            descriptor.content_length,
            descriptor
                .qualification_fault
                .as_ref()
                .map(|fault| (&descriptor.credential, fault)),
        )
        .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?
            != descriptor.request_id
        || object_put_provider_attempt_id(&descriptor.request_id)
            .map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?
            != descriptor.provider_attempt_id
    {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }
    Ok(())
}

fn put_provider_request_observation(
    descriptor: &ObjectPutDescriptor,
    observation: &PutObservation,
) -> ObjectWriteProviderRequestObservationV1 {
    ObjectWriteProviderRequestObservationV1 {
        request_id: observation.request_id.clone(),
        extended_request_id: observation.extended_request_id.clone(),
        content_sha256: descriptor.content_sha256.clone(),
        content_length: None,
        entity_tag: observation.e_tag.clone(),
        version_id: observation.version_id.clone(),
    }
}

fn head_provider_request_observation(
    descriptor: &ObjectPutDescriptor,
    observation: &HeadObservation,
) -> Result<ObjectWriteProviderRequestObservationV1, ObjectWriteDownstreamError> {
    Ok(ObjectWriteProviderRequestObservationV1 {
        request_id: observation.request_id.clone(),
        extended_request_id: observation.extended_request_id.clone(),
        content_sha256: descriptor.content_sha256.clone(),
        content_length: Some(
            cats_api::runtime_reconciliation::WireU64::new(observation.content_length)
                .ok_or(ObjectWriteDownstreamError::InvalidRequest)?,
        ),
        entity_tag: observation.e_tag.clone(),
        version_id: observation.version_id.clone(),
    })
}

fn conditional_request_evidence(
    descriptor: &ObjectPutDescriptor,
    observation: &ConditionalObservation,
) -> ObjectWriteConditionalRequestEvidenceV1 {
    ObjectWriteConditionalRequestEvidenceV1 {
        provider_attempt_id: descriptor.provider_attempt_id.clone(),
        outcome: ObjectWriteConditionalRequestOutcomeV1::PreconditionFailed,
        provider_request: ObjectWriteProviderRequestObservationV1 {
            request_id: observation.request_id.clone(),
            extended_request_id: observation.extended_request_id.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            content_length: Some(descriptor.content_length),
            entity_tag: None,
            version_id: None,
        },
        observed_at_unix_ms: observation.observed_at_unix_ms,
    }
}

fn valid_bucket_name(bucket: &str) -> bool {
    (3..=63).contains(&bucket.len())
        && bucket.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'.' | b'-')
        })
        && bucket
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphanumeric)
        && bucket
            .as_bytes()
            .last()
            .is_some_and(u8::is_ascii_alphanumeric)
        && !bucket.contains("..")
        && !bucket.contains(".-")
        && !bucket.contains("-.")
}

fn valid_provider_prefix(prefix: &str) -> bool {
    !prefix.is_empty()
        && !prefix.starts_with('/')
        && !prefix.ends_with('/')
        && prefix.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    links: u64,
    owner_uid: u32,
    mode: u32,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        links: metadata.nlink(),
        owner_uid: metadata.uid(),
        mode: metadata.mode(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
    }
}

fn valid_spool_metadata(
    metadata: &std::fs::Metadata,
    expected_length: u64,
    expected_owner_uid: u32,
) -> bool {
    metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.mode() & 0o7777 == 0o600
        && metadata.nlink() == 1
        && metadata.uid() == expected_owner_uid
        && metadata.len() == expected_length
}

async fn validate_spool_file(
    path: &Path,
    descriptor: &ObjectPutDescriptor,
    expected_owner_uid: u32,
    deadline: Instant,
) -> Result<tokio::fs::File, ObjectWriteDownstreamError> {
    let metadata = timeout_read(tokio::fs::symlink_metadata(path), deadline).await?;
    if !valid_spool_metadata(
        &metadata,
        descriptor.content_length.get(),
        expected_owner_uid,
    ) {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }
    let before = file_identity(&metadata);
    let mut file = timeout_read(tokio::fs::File::open(path), deadline).await?;
    let opened = timeout_read(file.metadata(), deadline).await?;
    if file_identity(&opened) != before
        || !valid_spool_metadata(&opened, descriptor.content_length.get(), expected_owner_uid)
    {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }

    let mut hasher = Sha256::new();
    let mut observed_length = 0_u64;
    let mut buffer = vec![0_u8; SPOOL_READ_BUFFER_BYTES];
    loop {
        let count = timeout_read(file.read(&mut buffer), deadline).await?;
        if count == 0 {
            break;
        }
        observed_length = observed_length
            .checked_add(
                u64::try_from(count).map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?,
            )
            .ok_or(ObjectWriteDownstreamError::InvalidRequest)?;
        if observed_length > descriptor.content_length.get() {
            return Err(ObjectWriteDownstreamError::InvalidRequest);
        }
        hasher.update(&buffer[..count]);
    }
    if observed_length != descriptor.content_length.get()
        || Sha256Digest::from_bytes(hasher.finalize().into()) != descriptor.content_sha256
    {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }
    let after = timeout_read(tokio::fs::symlink_metadata(path), deadline).await?;
    if file_identity(&after) != before
        || !valid_spool_metadata(&after, descriptor.content_length.get(), expected_owner_uid)
    {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }
    timeout_read(file.seek(SeekFrom::Start(0)), deadline).await?;
    let rewound = timeout_read(file.metadata(), deadline).await?;
    if file_identity(&rewound) != before
        || !valid_spool_metadata(
            &rewound,
            descriptor.content_length.get(),
            expected_owner_uid,
        )
    {
        return Err(ObjectWriteDownstreamError::InvalidRequest);
    }
    Ok(file)
}

async fn timeout_read<T>(
    future: impl Future<Output = std::io::Result<T>>,
    deadline: Instant,
) -> Result<T, ObjectWriteDownstreamError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(ObjectWriteDownstreamError::DeadlineExceeded)?;
    match tokio::time::timeout(remaining, future).await {
        Err(_) => Err(ObjectWriteDownstreamError::DeadlineExceeded),
        Ok(Err(_)) => Err(ObjectWriteDownstreamError::Unavailable),
        Ok(Ok(value)) => Ok(value),
    }
}

struct ExactPutRequest {
    bucket: String,
    key: String,
    spool_file: tokio::fs::File,
    content_length: u64,
    checksum_sha256: String,
    metadata: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PutObservation {
    request_id: AsciiText,
    extended_request_id: Option<AsciiText>,
    checksum_sha256: String,
    e_tag: Option<AsciiText>,
    version_id: Option<AsciiText>,
    completed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct HeadObservation {
    request_id: AsciiText,
    extended_request_id: Option<AsciiText>,
    checksum_sha256: String,
    content_length: u64,
    metadata: BTreeMap<String, String>,
    e_tag: Option<AsciiText>,
    version_id: Option<AsciiText>,
    observed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ConditionalObservation {
    request_id: AsciiText,
    extended_request_id: Option<AsciiText>,
    observed_at_unix_ms: UnixMillis,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum S3CallError {
    Deadline,
    Ambiguous,
    Unavailable,
    InvalidResponse,
    PreconditionFailed(ConditionalObservation),
    NotFound,
}

type S3Future<'a, T> = Pin<Box<dyn Future<Output = Result<T, S3CallError>> + Send + 'a>>;

trait ExactS3Api: Send + Sync {
    fn put_exact<'a>(
        &'a self,
        request: ExactPutRequest,
        deadline: Instant,
    ) -> S3Future<'a, PutObservation>;

    fn head_exact<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        deadline: Instant,
    ) -> S3Future<'a, HeadObservation>;
}

struct SdkExactS3Api {
    client: aws_sdk_s3::Client,
}

impl ExactS3Api for SdkExactS3Api {
    fn put_exact<'a>(
        &'a self,
        request: ExactPutRequest,
        deadline: Instant,
    ) -> S3Future<'a, PutObservation> {
        Box::pin(async move {
            let content_length =
                i64::try_from(request.content_length).map_err(|_| S3CallError::InvalidResponse)?;
            // Keep the exact inode opened, hashed and rewound by
            // validate_spool_file. Reopening its pathname here would permit a
            // same-UID recovery/cleanup race to substitute different bytes
            // after validation. SDK mutation retries are disabled, so this
            // non-retryable handle is consumed by exactly one provider call.
            let body = ByteStream::read_from()
                .file(request.spool_file)
                .length(Length::Exact(request.content_length))
                .buffer_size(SPOOL_READ_BUFFER_BYTES)
                .build()
                .await
                .map_err(|_| S3CallError::InvalidResponse)?;
            let mut put = self
                .client
                .put_object()
                .bucket(&request.bucket)
                .key(&request.key)
                .if_none_match("*")
                .content_length(content_length)
                .checksum_algorithm(ChecksumAlgorithm::Sha256)
                .checksum_sha256(&request.checksum_sha256)
                .body(body);
            for (key, value) in &request.metadata {
                put = put.metadata(key, value);
            }
            let output = Box::pin(mutate_with_deadline(
                put.customize()
                    .config_override(
                        aws_sdk_s3::config::Builder::new().retry_config(put_retry_config()),
                    )
                    .send(),
                deadline,
            ))
            .await?;
            let checksum_sha256 = output
                .checksum_sha256()
                .ok_or(S3CallError::InvalidResponse)?
                .to_owned();
            Ok(PutObservation {
                request_id: required_ascii(output.request_id())?,
                extended_request_id: optional_ascii(output.extended_request_id())?,
                checksum_sha256,
                e_tag: optional_ascii(output.e_tag())?,
                version_id: optional_ascii(output.version_id())?,
                completed_at_unix_ms: now_unix_millis()?,
            })
        })
    }

    fn head_exact<'a>(
        &'a self,
        bucket: &'a str,
        key: &'a str,
        deadline: Instant,
    ) -> S3Future<'a, HeadObservation> {
        Box::pin(async move {
            let output = read_with_deadline(
                self.client
                    .head_object()
                    .bucket(bucket)
                    .key(key)
                    .checksum_mode(ChecksumMode::Enabled)
                    .send(),
                deadline,
            )
            .await?;
            let length = output
                .content_length()
                .and_then(|value| u64::try_from(value).ok())
                .ok_or(S3CallError::InvalidResponse)?;
            let checksum_sha256 = output
                .checksum_sha256()
                .ok_or(S3CallError::InvalidResponse)?
                .to_owned();
            let metadata = output
                .metadata()
                .ok_or(S3CallError::InvalidResponse)?
                .iter()
                .map(|(key, value)| (key.clone(), value.clone()))
                .collect();
            Ok(HeadObservation {
                request_id: required_ascii(output.request_id())?,
                extended_request_id: optional_ascii(output.extended_request_id())?,
                checksum_sha256,
                content_length: length,
                metadata,
                e_tag: optional_ascii(output.e_tag())?,
                version_id: optional_ascii(output.version_id())?,
                observed_at_unix_ms: now_unix_millis()?,
            })
        })
    }
}

async fn read_with_deadline<T, E>(
    future: impl Future<Output = Result<T, SdkError<E>>>,
    deadline: Instant,
) -> Result<T, S3CallError>
where
    E: ProvideErrorMetadata,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(S3CallError::Deadline)?;
    match tokio::time::timeout(remaining, future).await {
        Err(_) => Err(S3CallError::Deadline),
        Ok(Ok(output)) => Ok(output),
        Ok(Err(SdkError::ServiceError(error)))
            if matches!(error.err().code(), Some("NoSuchKey" | "NotFound" | "404")) =>
        {
            Err(S3CallError::NotFound)
        }
        Ok(Err(SdkError::ConstructionFailure(_))) => Err(S3CallError::InvalidResponse),
        Ok(Err(_)) => Err(S3CallError::Unavailable),
    }
}

async fn mutate_with_deadline<T, E>(
    future: impl Future<Output = Result<T, SdkError<E>>>,
    deadline: Instant,
) -> Result<T, S3CallError>
where
    E: ProvideErrorMetadata,
{
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(S3CallError::Deadline)?;
    match tokio::time::timeout(remaining, future).await {
        // A timeout after issuing PutObject is ambiguous even when it consumed
        // the caller deadline: S3 may have durably accepted the object.
        Err(_) => Err(S3CallError::Ambiguous),
        Ok(Ok(output)) => Ok(output),
        Ok(Err(SdkError::ConstructionFailure(_))) => Err(S3CallError::InvalidResponse),
        Ok(Err(
            SdkError::TimeoutError(_) | SdkError::DispatchFailure(_) | SdkError::ResponseError(_),
        )) => Err(S3CallError::Ambiguous),
        Ok(Err(SdkError::ServiceError(error))) => match error.err().code().unwrap_or_default() {
            "PreconditionFailed" | "ConditionalRequestConflict" | "412" => {
                Err(S3CallError::PreconditionFailed(ConditionalObservation {
                    request_id: required_ascii(error.raw().request_id())?,
                    extended_request_id: optional_ascii(error.raw().extended_request_id())?,
                    observed_at_unix_ms: now_unix_millis()?,
                }))
            }
            "InternalError" | "ServiceUnavailable" | "SlowDown" | "503" => {
                Err(S3CallError::Ambiguous)
            }
            _ => Err(S3CallError::Unavailable),
        },
        Ok(Err(_)) => Err(S3CallError::Ambiguous),
    }
}

fn map_put_error(error: S3CallError) -> ObjectWriteDownstreamError {
    match error {
        S3CallError::Deadline => ObjectWriteDownstreamError::DeadlineExceeded,
        S3CallError::Ambiguous | S3CallError::InvalidResponse => {
            ObjectWriteDownstreamError::Ambiguous
        }
        S3CallError::Unavailable => ObjectWriteDownstreamError::Unavailable,
        S3CallError::PreconditionFailed(_) | S3CallError::NotFound => {
            ObjectWriteDownstreamError::Ambiguous
        }
    }
}

fn map_read_error(error: S3CallError) -> ObjectWriteDownstreamError {
    match error {
        S3CallError::Deadline => ObjectWriteDownstreamError::DeadlineExceeded,
        S3CallError::Ambiguous | S3CallError::InvalidResponse => {
            ObjectWriteDownstreamError::Ambiguous
        }
        S3CallError::Unavailable => ObjectWriteDownstreamError::Unavailable,
        S3CallError::PreconditionFailed(_) | S3CallError::NotFound => {
            ObjectWriteDownstreamError::Ambiguous
        }
    }
}

fn head_matches(descriptor: &ObjectPutDescriptor, observation: &HeadObservation) -> bool {
    observation.content_length == descriptor.content_length.get()
        && observation.checksum_sha256 == STANDARD.encode(descriptor.content_sha256.as_bytes())
}

fn put_receipt_id(
    descriptor: &ObjectPutDescriptor,
    observation: &PutObservation,
    disposition: &[u8],
) -> Result<AsciiText, ObjectWriteDownstreamError> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.aws-s3-exact-put-receipt.v1")?;
    hash_frame(
        &mut hasher,
        descriptor.provider_attempt_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        descriptor.target.canonical_logical_key.as_bytes(),
    )?;
    hash_frame(&mut hasher, descriptor.content_sha256.as_str().as_bytes())?;
    hash_frame(&mut hasher, &descriptor.content_length.get().to_be_bytes())?;
    hash_frame(&mut hasher, observation.request_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, observation.checksum_sha256.as_bytes())?;
    hash_frame(
        &mut hasher,
        observation
            .e_tag
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    hash_frame(
        &mut hasher,
        observation
            .version_id
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    hash_frame(&mut hasher, disposition)?;
    ascii_digest("awss3put1_", hasher.finalize())
}

fn visibility_receipt_id(
    descriptor: &ObjectPutDescriptor,
    observation: &HeadObservation,
) -> Result<AsciiText, ObjectWriteDownstreamError> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.aws-s3-exact-head-receipt.v1")?;
    hash_frame(
        &mut hasher,
        descriptor.provider_attempt_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        descriptor.target.canonical_logical_key.as_bytes(),
    )?;
    hash_frame(&mut hasher, descriptor.content_sha256.as_str().as_bytes())?;
    hash_frame(&mut hasher, &descriptor.content_length.get().to_be_bytes())?;
    hash_frame(&mut hasher, observation.request_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, observation.checksum_sha256.as_bytes())?;
    hash_frame(
        &mut hasher,
        observation
            .e_tag
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    hash_frame(
        &mut hasher,
        observation
            .version_id
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    ascii_digest("awss3head1_", hasher.finalize())
}

fn replay_put_receipt_id(
    descriptor: &ObjectPutDescriptor,
    visibility_receipt_id: &AsciiText,
) -> Result<AsciiText, ObjectWriteDownstreamError> {
    let mut hasher = Sha256::new();
    hash_frame(&mut hasher, b"cats.aws-s3-replay-put-receipt.v1")?;
    hash_frame(
        &mut hasher,
        descriptor.provider_attempt_id.as_str().as_bytes(),
    )?;
    hash_frame(&mut hasher, visibility_receipt_id.as_str().as_bytes())?;
    ascii_digest("awss3replay1_", hasher.finalize())
}

fn conflict_failure_receipt_id(
    descriptor: &ObjectPutDescriptor,
    observation: &HeadObservation,
) -> Result<AsciiText, ObjectWriteDownstreamError> {
    let mut hasher = Sha256::new();
    hash_frame(
        &mut hasher,
        b"cats.aws-s3-conflicting-object-failure-receipt.v1",
    )?;
    hash_frame(&mut hasher, descriptor.request_id.as_str().as_bytes())?;
    hash_frame(
        &mut hasher,
        descriptor.provider_attempt_id.as_str().as_bytes(),
    )?;
    for scope in [
        &descriptor.target.object_provider_scope.provider,
        &descriptor.target.object_provider_scope.partition,
        &descriptor.target.object_provider_scope.account_id,
        &descriptor.target.object_provider_scope.region,
    ] {
        hash_frame(&mut hasher, scope.as_str().as_bytes())?;
    }
    hash_frame(
        &mut hasher,
        descriptor.target.object_store_scope_id.as_str().as_bytes(),
    )?;
    hash_frame(
        &mut hasher,
        descriptor.target.canonical_logical_key.as_bytes(),
    )?;
    hash_frame(&mut hasher, descriptor.content_sha256.as_str().as_bytes())?;
    hash_frame(&mut hasher, &descriptor.content_length.get().to_be_bytes())?;
    hash_frame(&mut hasher, observation.request_id.as_str().as_bytes())?;
    hash_frame(&mut hasher, observation.checksum_sha256.as_bytes())?;
    hash_frame(&mut hasher, &observation.content_length.to_be_bytes())?;
    for (key, value) in &observation.metadata {
        hash_frame(&mut hasher, key.as_bytes())?;
        hash_frame(&mut hasher, value.as_bytes())?;
    }
    hash_frame(
        &mut hasher,
        observation
            .e_tag
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    hash_frame(
        &mut hasher,
        observation
            .version_id
            .as_ref()
            .map_or(b"", |value| value.as_str().as_bytes()),
    )?;
    hash_frame(
        &mut hasher,
        &observation.observed_at_unix_ms.get().to_be_bytes(),
    )?;
    ascii_digest("awss3conflict1_", hasher.finalize())
}

fn hash_frame(hasher: &mut Sha256, value: &[u8]) -> Result<(), ObjectWriteDownstreamError> {
    let length =
        u64::try_from(value.len()).map_err(|_| ObjectWriteDownstreamError::InvalidRequest)?;
    hasher.update(length.to_be_bytes());
    hasher.update(value);
    Ok(())
}

fn ascii_digest(
    prefix: &str,
    digest: impl AsRef<[u8]>,
) -> Result<AsciiText, ObjectWriteDownstreamError> {
    AsciiText::new(format!("{prefix}{}", hex_lower(digest.as_ref())))
        .ok_or(ObjectWriteDownstreamError::InvalidRequest)
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

fn required_ascii(value: Option<&str>) -> Result<AsciiText, S3CallError> {
    value
        .and_then(|value| AsciiText::new(value.to_owned()))
        .ok_or(S3CallError::InvalidResponse)
}

fn optional_ascii(value: Option<&str>) -> Result<Option<AsciiText>, S3CallError> {
    value
        .map(|value| AsciiText::new(value.to_owned()).ok_or(S3CallError::InvalidResponse))
        .transpose()
}

fn now_unix_millis() -> Result<UnixMillis, S3CallError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| S3CallError::InvalidResponse)?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| S3CallError::InvalidResponse)?;
    UnixMillis::new(millis).ok_or(S3CallError::InvalidResponse)
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::Mutex;
    use std::time::Duration;

    use cats_api::object_write_gateway::{
        object_write_key, ObjectWriteCredentialReference, ObjectWriteImmutableKey,
        ObjectWriteQualificationFaultV1, VolumeDataObjectKind,
    };
    use cats_api::runtime_reconciliation::RandomId128;
    use cats_api::runtime_reconciliation::WireU64;
    use cats_storage::object_write_authority::{
        object_write_spool_id, DurableObjectWriteSpoolReceipt, ObjectWriteTarget,
    };

    use super::*;

    struct FakeS3 {
        puts: Mutex<Vec<ExactPutRequest>>,
        put_results: Mutex<VecDeque<Result<PutObservation, S3CallError>>>,
        head_results: Mutex<VecDeque<Result<HeadObservation, S3CallError>>>,
    }

    impl FakeS3 {
        fn new(
            put_results: Vec<Result<PutObservation, S3CallError>>,
            head_results: Vec<Result<HeadObservation, S3CallError>>,
        ) -> Self {
            Self {
                puts: Mutex::new(Vec::new()),
                put_results: Mutex::new(put_results.into()),
                head_results: Mutex::new(head_results.into()),
            }
        }
    }

    impl ExactS3Api for FakeS3 {
        fn put_exact<'a>(
            &'a self,
            request: ExactPutRequest,
            _deadline: Instant,
        ) -> S3Future<'a, PutObservation> {
            Box::pin(async move {
                self.puts.lock().unwrap().push(request);
                self.put_results
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("queued put result")
            })
        }

        fn head_exact<'a>(
            &'a self,
            _bucket: &'a str,
            _key: &'a str,
            _deadline: Instant,
        ) -> S3Future<'a, HeadObservation> {
            Box::pin(async move {
                self.head_results
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("queued head result")
            })
        }
    }

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn ascii(value: &str) -> AsciiText {
        AsciiText::new(value).unwrap()
    }

    fn millis(value: u64) -> UnixMillis {
        UnixMillis::new(value).unwrap()
    }

    fn provider_scope() -> ProviderScope {
        ProviderScope {
            provider: id("aws"),
            partition: id("aws"),
            account_id: id("123456789012"),
            region: id("us-east-1"),
        }
    }

    fn descriptor(body: &[u8]) -> ObjectPutDescriptor {
        let content_sha256 = Sha256Digest::from_bytes(Sha256::digest(body).into());
        let content_length = WireU64::new(u64::try_from(body.len()).unwrap()).unwrap();
        let writer_authority_id = id("writer-authority-1");
        let volume_id = id("vol-1");
        let key = ObjectWriteImmutableKey::VolumeData {
            transaction_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
            chunk_index: WireU64::new(0).unwrap(),
            object_kind: VolumeDataObjectKind::Base,
        };
        let target = ObjectWriteTarget {
            object_provider_scope: provider_scope(),
            object_store_scope_id: ascii("arn:aws:s3:::cats-chunks-test/production/chunks"),
            canonical_logical_key: object_write_key(&volume_id, &key, &content_sha256).unwrap(),
        };
        let request_id = object_put_request_id(
            &writer_authority_id,
            &target,
            &volume_id,
            &key,
            &content_sha256,
            content_length,
            None,
        )
        .unwrap();
        ObjectPutDescriptor {
            writer_authority_id,
            accepted_sequence: WireU64::new(7).unwrap(),
            provider_attempt_id: object_put_provider_attempt_id(&request_id).unwrap(),
            request_id,
            credential: ObjectWriteCredentialReference {
                credential_id: id("object-write-credential-1"),
                public_key_spki_sha256: Sha256Digest::from_bytes([7_u8; 32]),
            },
            volume_id,
            key,
            target,
            content_sha256,
            content_length,
            qualification_fault: None,
            accepted_at_unix_ms: millis(20),
        }
    }

    fn qualification_descriptor(body: &[u8]) -> ObjectPutDescriptor {
        let mut descriptor = descriptor(body);
        descriptor.qualification_fault =
            Some(ObjectWriteQualificationFaultV1::SuccessfulPutResponseLoss {
                qualification_id: id("qualification-1"),
                fault_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
                qualification_catalog_sha256: Sha256Digest::from_bytes([8_u8; 32]),
            });
        descriptor.request_id = object_put_request_id(
            &descriptor.writer_authority_id,
            &descriptor.target,
            &descriptor.volume_id,
            &descriptor.key,
            &descriptor.content_sha256,
            descriptor.content_length,
            descriptor
                .qualification_fault
                .as_ref()
                .map(|fault| (&descriptor.credential, fault)),
        )
        .unwrap();
        descriptor.provider_attempt_id =
            object_put_provider_attempt_id(&descriptor.request_id).unwrap();
        descriptor
    }

    fn write_spool(
        root: &Path,
        descriptor: &ObjectPutDescriptor,
        body: &[u8],
    ) -> DurableObjectWriteSpoolReceipt {
        let spool_id = object_write_spool_id(&descriptor.request_id).unwrap();
        let path = root.join(format!("{}{SPOOL_FILE_SUFFIX}", spool_id.as_str()));
        std::fs::write(&path, body).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        DurableObjectWriteSpoolReceipt {
            spool_id,
            request_id: descriptor.request_id.clone(),
            content_sha256: descriptor.content_sha256.clone(),
            content_length: descriptor.content_length,
            file_fsync_receipt_id: ascii("fsync-file-1"),
            directory_fsync_receipt_id: ascii("fsync-dir-1"),
            durable_at_unix_ms: millis(10),
        }
    }

    fn config(root: &Path) -> AwsObjectWriteConfig {
        std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let canonical_root = std::fs::canonicalize(root).unwrap();
        AwsObjectWriteConfig::new(
            provider_scope(),
            "cats-chunks-test".to_owned(),
            "production/chunks".to_owned(),
            ascii("arn:aws:s3:::cats-chunks-test/production/chunks"),
            canonical_root,
        )
        .unwrap()
    }

    fn put_observation(descriptor: &ObjectPutDescriptor) -> PutObservation {
        PutObservation {
            request_id: ascii("aws-request-put-1"),
            extended_request_id: Some(ascii("aws-extended-put-1")),
            checksum_sha256: STANDARD.encode(descriptor.content_sha256.as_bytes()),
            e_tag: Some(ascii("etag-1")),
            version_id: Some(ascii("version-1")),
            completed_at_unix_ms: millis(30),
        }
    }

    fn head_observation(descriptor: &ObjectPutDescriptor) -> HeadObservation {
        HeadObservation {
            request_id: ascii("aws-request-head-1"),
            extended_request_id: Some(ascii("aws-extended-head-1")),
            checksum_sha256: STANDARD.encode(descriptor.content_sha256.as_bytes()),
            content_length: descriptor.content_length.get(),
            metadata: BTreeMap::from([
                (
                    CONTENT_SHA256_METADATA.to_owned(),
                    descriptor.content_sha256.as_str().to_owned(),
                ),
                (
                    CONTENT_LENGTH_METADATA.to_owned(),
                    descriptor.content_length.get().to_string(),
                ),
            ]),
            e_tag: Some(ascii("etag-1")),
            version_id: Some(ascii("version-1")),
            observed_at_unix_ms: millis(31),
        }
    }

    fn precondition_observation() -> ConditionalObservation {
        ConditionalObservation {
            request_id: ascii("aws-request-precondition-1"),
            extended_request_id: Some(ascii("aws-extended-precondition-1")),
            observed_at_unix_ms: millis(30),
        }
    }

    #[test]
    fn configuration_binds_bucket_prefix_and_private_spool_root() {
        let temporary = tempfile::tempdir().unwrap();
        assert_eq!(
            AwsObjectWriteConfig::new(
                provider_scope(),
                "cats-chunks-test".to_owned(),
                "production/chunks".to_owned(),
                ascii("arn:aws:s3:::another-bucket/production/chunks"),
                temporary.path().to_owned(),
            ),
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );

        std::fs::set_permissions(temporary.path(), std::fs::Permissions::from_mode(0o750)).unwrap();
        assert_eq!(
            AwsObjectWriteConfig::new(
                provider_scope(),
                "cats-chunks-test".to_owned(),
                "production/chunks".to_owned(),
                ascii("arn:aws:s3:::cats-chunks-test/production/chunks"),
                temporary.path().to_owned(),
            ),
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
    }

    #[test]
    fn conditional_put_retries_are_owned_by_the_validating_outer_state_machine() {
        assert_eq!(put_retry_config().max_attempts(), 1);
    }

    #[test]
    fn configuration_rejects_a_spool_root_reached_through_an_aliased_parent() {
        let temporary = tempfile::tempdir().unwrap();
        let real_parent = temporary.path().join("real-parent");
        let real_spool_root = real_parent.join("spool");
        std::fs::create_dir(&real_parent).unwrap();
        std::fs::create_dir(&real_spool_root).unwrap();
        std::fs::set_permissions(&real_spool_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let aliased_parent = temporary.path().join("aliased-parent");
        std::os::unix::fs::symlink(&real_parent, &aliased_parent).unwrap();
        let configured_spool_root = aliased_parent.join("spool");
        assert_ne!(
            std::fs::canonicalize(&configured_spool_root).unwrap(),
            configured_spool_root
        );

        assert_eq!(
            AwsObjectWriteConfig::new(
                provider_scope(),
                "cats-chunks-test".to_owned(),
                "production/chunks".to_owned(),
                ascii("arn:aws:s3:::cats-chunks-test/production/chunks"),
                configured_spool_root,
            ),
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
    }

    #[tokio::test]
    async fn streams_exact_durable_spool_to_scoped_conditional_put() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"durable body";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let s3 = Arc::new(FakeS3::new(vec![Ok(put_observation(&descriptor))], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        let outcome = downstream
            .put_exact(
                ObjectWriteDownstreamPut {
                    descriptor: descriptor.clone(),
                    spool,
                },
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ObjectWriteDownstreamPutOutcome::Succeeded { .. }
        ));
        let puts = s3.puts.lock().unwrap();
        assert_eq!(puts.len(), 1);
        assert_eq!(
            puts[0].key,
            "production/chunks/volumes/vol-1/data/11111111111111111111111111111111-c0"
        );
        assert_eq!(puts[0].content_length, u64::try_from(body.len()).unwrap());
        assert_eq!(
            puts[0].checksum_sha256,
            STANDARD.encode(descriptor.content_sha256.as_bytes())
        );
    }

    #[tokio::test]
    async fn qualification_marker_classifies_only_a_real_successful_put() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"qualified response loss";
        let descriptor = qualification_descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let observation = put_observation(&descriptor);
        let s3 = Arc::new(FakeS3::new(vec![Ok(observation.clone())], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        let outcome = downstream
            .conditional_put(&descriptor, &spool, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AwsConditionalPutOutcome::Created(ObjectWriteSuccessfulPutV1 {
                    provider_attempt_id,
                    provider_request: ObjectWriteProviderRequestObservationV1 {
                        request_id,
                        content_length: None,
                        ..
                    },
                    completed_at_unix_ms,
                    ..
                }) if provider_attempt_id == descriptor.provider_attempt_id
                && request_id == observation.request_id
                && completed_at_unix_ms == observation.completed_at_unix_ms
        ));
        assert_eq!(s3.puts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ordinary_put_capability_rejects_a_qualification_marker_before_s3() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"qualification cannot cross ordinary dispatch";
        let descriptor = qualification_descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let s3 = Arc::new(FakeS3::new(vec![Ok(put_observation(&descriptor))], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        assert_eq!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
        assert!(s3.puts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn qualification_marker_does_not_reclassify_an_ambiguous_provider_result() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"provider timeout";
        let descriptor = qualification_descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let s3 = Arc::new(FakeS3::new(vec![Err(S3CallError::Ambiguous)], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        assert_eq!(
            downstream
                .conditional_put(&descriptor, &spool, Instant::now() + Duration::from_secs(2),)
                .await,
            Err(ObjectWriteDownstreamError::Ambiguous)
        );
        assert_eq!(s3.puts.lock().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn ambiguous_put_is_never_reported_as_permanent_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"response lost";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let s3 = Arc::new(FakeS3::new(
            vec![Err(S3CallError::Ambiguous)],
            vec![Ok(head_observation(&descriptor))],
        ));
        let downstream = AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3);

        assert_eq!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut {
                        descriptor: descriptor.clone(),
                        spool,
                    },
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Err(ObjectWriteDownstreamError::Ambiguous)
        );
        assert!(matches!(
            downstream
                .discover_visibility(&descriptor, Instant::now() + Duration::from_secs(2))
                .await
                .unwrap(),
            ObjectWriteVisibilityOutcome::VisibleExact { .. }
        ));
    }

    #[tokio::test]
    async fn precondition_replay_requires_exact_checksum_head() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"already visible";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let downstream = AwsObjectWriteGatewayDownstream::with_api(
            config(temporary.path()),
            Arc::new(FakeS3::new(
                vec![Err(S3CallError::PreconditionFailed(
                    precondition_observation(),
                ))],
                vec![Ok(head_observation(&descriptor))],
            )),
        );

        assert!(matches!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap(),
            ObjectWriteDownstreamPutOutcome::Succeeded { .. }
        ));
    }

    #[tokio::test]
    async fn qualification_precondition_and_exact_head_is_unproven_not_success() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"committed before response-loss receipt";
        let descriptor = qualification_descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let conditional = precondition_observation();
        let head = head_observation(&descriptor);
        let s3 = Arc::new(FakeS3::new(
            vec![Err(S3CallError::PreconditionFailed(conditional.clone()))],
            vec![Ok(head.clone())],
        ));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        let outcome = downstream
            .conditional_put(&descriptor, &spool, Instant::now() + Duration::from_secs(2))
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            AwsConditionalPutOutcome::PreconditionFailedExactVisible(head_evidence)
                if head_evidence.provider_attempt_id == descriptor.provider_attempt_id
                && head_evidence.provider_request.request_id == head.request_id
                && head_evidence
                    .preceding_conditional_request
                    .as_ref()
                    .is_some_and(|evidence| {
                        evidence.provider_request.request_id == conditional.request_id
                            && evidence.outcome
                                == ObjectWriteConditionalRequestOutcomeV1::PreconditionFailed
                    })
        ));
        assert_eq!(s3.puts.lock().unwrap().len(), 1);
        assert!(s3.head_results.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn exact_key_with_different_bytes_is_a_permanent_provider_failure() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"new bytes";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let mut conflicting = head_observation(&descriptor);
        conflicting.checksum_sha256 = STANDARD.encode([9_u8; 32]);
        let downstream = AwsObjectWriteGatewayDownstream::with_api(
            config(temporary.path()),
            Arc::new(FakeS3::new(
                vec![Err(S3CallError::PreconditionFailed(
                    precondition_observation(),
                ))],
                vec![Ok(conflicting)],
            )),
        );

        let outcome = downstream
            .put_exact(
                ObjectWriteDownstreamPut { descriptor, spool },
                Instant::now() + Duration::from_secs(2),
            )
            .await
            .unwrap();
        assert!(matches!(
            outcome,
            ObjectWriteDownstreamPutOutcome::PermanentlyFailed {
                failure_receipt_id,
                failed_at_unix_ms,
                ..
            } if failure_receipt_id.as_str().starts_with("awss3conflict1_")
                && failed_at_unix_ms == millis(31)
        ));
    }

    #[tokio::test]
    async fn same_checksum_and_length_replay_does_not_depend_on_user_metadata() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"same immutable bytes";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let mut existing = head_observation(&descriptor);
        existing.metadata.clear();
        let downstream = AwsObjectWriteGatewayDownstream::with_api(
            config(temporary.path()),
            Arc::new(FakeS3::new(
                vec![Err(S3CallError::PreconditionFailed(
                    precondition_observation(),
                ))],
                vec![Ok(existing)],
            )),
        );

        assert!(matches!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await
                .unwrap(),
            ObjectWriteDownstreamPutOutcome::Succeeded { .. }
        ));
    }

    #[tokio::test]
    async fn spool_digest_mismatch_is_rejected_before_s3() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"expected";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, b"tampered");
        let s3 = Arc::new(FakeS3::new(vec![], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        assert_eq!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
        assert!(s3.puts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn spool_with_an_extra_hard_link_is_rejected_before_s3() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"linked spool";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let spool_path = temporary
            .path()
            .join(format!("{}{SPOOL_FILE_SUFFIX}", spool.spool_id.as_str()));
        std::fs::hard_link(&spool_path, temporary.path().join("unexpected-link")).unwrap();
        let s3 = Arc::new(FakeS3::new(vec![], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        assert_eq!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
        assert!(s3.puts.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn spool_with_the_wrong_owner_uid_is_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"owner-bound spool";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let spool_path = temporary
            .path()
            .join(format!("{}{SPOOL_FILE_SUFFIX}", spool.spool_id.as_str()));
        let actual_uid = std::fs::symlink_metadata(&spool_path).unwrap().uid();
        let different_uid = if actual_uid == u32::MAX {
            actual_uid - 1
        } else {
            actual_uid + 1
        };

        assert!(matches!(
            validate_spool_file(
                &spool_path,
                &descriptor,
                different_uid,
                Instant::now() + Duration::from_secs(2),
            )
            .await,
            Err(ObjectWriteDownstreamError::InvalidRequest)
        ));
    }

    #[tokio::test]
    async fn validated_spool_handle_survives_a_path_replacement_without_changing_bytes() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"accepted immutable bytes";
        let descriptor = descriptor(body);
        let spool = write_spool(temporary.path(), &descriptor, body);
        let spool_path = temporary
            .path()
            .join(format!("{}{SPOOL_FILE_SUFFIX}", spool.spool_id.as_str()));
        let owner_uid = std::fs::symlink_metadata(&spool_path).unwrap().uid();
        let mut validated = validate_spool_file(
            &spool_path,
            &descriptor,
            owner_uid,
            Instant::now() + Duration::from_secs(2),
        )
        .await
        .unwrap();

        let retained = temporary.path().join("retained-validated-inode");
        std::fs::rename(&spool_path, &retained).unwrap();
        std::fs::write(&spool_path, b"substituted pathname bytes").unwrap();
        std::fs::set_permissions(&spool_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let mut observed = Vec::new();
        validated.read_to_end(&mut observed).await.unwrap();
        assert_eq!(observed, body);
    }

    #[tokio::test]
    async fn wrong_provider_scope_is_rejected_before_s3() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"scoped body";
        let mut descriptor = descriptor(body);
        descriptor.target.object_provider_scope.region = id("us-west-2");
        descriptor.request_id = object_put_request_id(
            &descriptor.writer_authority_id,
            &descriptor.target,
            &descriptor.volume_id,
            &descriptor.key,
            &descriptor.content_sha256,
            descriptor.content_length,
            descriptor
                .qualification_fault
                .as_ref()
                .map(|fault| (&descriptor.credential, fault)),
        )
        .unwrap();
        descriptor.provider_attempt_id =
            object_put_provider_attempt_id(&descriptor.request_id).unwrap();
        let spool = write_spool(temporary.path(), &descriptor, body);
        let s3 = Arc::new(FakeS3::new(vec![], vec![]));
        let downstream =
            AwsObjectWriteGatewayDownstream::with_api(config(temporary.path()), s3.clone());

        assert_eq!(
            downstream
                .put_exact(
                    ObjectWriteDownstreamPut { descriptor, spool },
                    Instant::now() + Duration::from_secs(2),
                )
                .await,
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
        assert!(s3.puts.lock().unwrap().is_empty());
    }

    #[test]
    fn caller_supplied_cross_volume_key_is_rederived_and_rejected() {
        let temporary = tempfile::tempdir().unwrap();
        let body = b"sealed target";
        let mut descriptor = descriptor(body);
        descriptor.target.canonical_logical_key =
            "volumes/vol-victim/data/11111111111111111111111111111111-c0".to_owned();
        assert_eq!(
            config(temporary.path()).provider_key(&descriptor),
            Err(ObjectWriteDownstreamError::InvalidRequest)
        );
    }
}
