use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use axum::body::Body;
use cats_api::runtime_reconciliation::{AsciiText, Sha256Digest};
use cats_storage::object_write_authority::{
    object_write_spool_id, DurableObjectWriteSpoolReceipt, ObjectWriteIngress,
};
use http_body_util::BodyExt as _;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

const TEMP_PREFIX: &str = ".owtmp1_";
const TEMP_SUFFIX: &str = ".receiving";
const BODY_SUFFIX: &str = ".body";
const ORPHAN_TEMP_MINIMUM_AGE: Duration = Duration::from_secs(10 * 60);
const ORPHAN_SCAN_LIMIT: usize = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DurableSpoolError {
    Invalid,
    BodyMismatch,
    DeadlineExceeded,
    Unavailable,
    NotFound,
}

impl std::fmt::Display for DurableSpoolError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Invalid => "durable spool path or object is invalid",
            Self::BodyMismatch => "durable spool body does not match its descriptor",
            Self::DeadlineExceeded => "durable spool operation exceeded its deadline",
            Self::Unavailable => "durable spool is unavailable",
            Self::NotFound => "durable spool body is not present",
        })
    }
}

impl std::error::Error for DurableSpoolError {}

#[derive(Debug)]
pub(super) struct DurableSpool {
    root: PathBuf,
    owner_uid: u32,
}

impl DurableSpool {
    pub(super) fn open(root: PathBuf) -> Result<Self, DurableSpoolError> {
        if !root.is_absolute() {
            return Err(DurableSpoolError::Invalid);
        }
        let metadata = std::fs::symlink_metadata(&root).map_err(map_io)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o777 != 0o700
        {
            return Err(DurableSpoolError::Invalid);
        }
        let owner_uid = metadata.uid();
        let canonical = std::fs::canonicalize(&root).map_err(map_io)?;
        if canonical != root {
            return Err(DurableSpoolError::Invalid);
        }
        let root = canonical;
        Ok(Self { root, owner_uid })
    }

    pub(super) async fn receive(
        &self,
        ingress: &ObjectWriteIngress,
        mut body: Body,
        absolute_deadline: Instant,
    ) -> Result<DurableObjectWriteSpoolReceipt, DurableSpoolError> {
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        let temp_path = self.temporary_path();
        let std_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(map_io)?;
        let mut file = tokio::fs::File::from_std(std_file);
        let mut observed_length = 0_u64;
        let mut hasher = Sha256::new();
        loop {
            let frame = timeout(absolute_deadline, body.frame()).await?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|_| DurableSpoolError::Unavailable)?;
            let data = frame
                .into_data()
                .map_err(|_| DurableSpoolError::BodyMismatch)?;
            let count = u64::try_from(data.len()).map_err(|_| DurableSpoolError::BodyMismatch)?;
            observed_length = observed_length
                .checked_add(count)
                .ok_or(DurableSpoolError::BodyMismatch)?;
            if observed_length > ingress.content_length.get() {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(DurableSpoolError::BodyMismatch);
            }
            hasher.update(&data);
            timeout(absolute_deadline, file.write_all(&data))
                .await?
                .map_err(map_io)?;
        }
        if observed_length != ingress.content_length.get()
            || Sha256Digest::from_bytes(hasher.finalize().into()) != ingress.content_sha256
        {
            let _ = tokio::fs::remove_file(&temp_path).await;
            return Err(DurableSpoolError::BodyMismatch);
        }
        timeout(absolute_deadline, file.sync_all())
            .await?
            .map_err(map_io)?;
        drop(file);

        let canonical_path = self.body_path(&spool_id)?;
        let linked = match timeout(
            absolute_deadline,
            tokio::fs::hard_link(&temp_path, &canonical_path),
        )
        .await?
        {
            Ok(()) => true,
            Err(error) if error.kind() == ErrorKind::AlreadyExists => false,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temp_path).await;
                return Err(map_io(error));
            }
        };
        self.sync_directory(absolute_deadline).await?;
        if linked {
            timeout(absolute_deadline, tokio::fs::remove_file(&temp_path))
                .await?
                .map_err(map_io)?;
            self.sync_directory(absolute_deadline).await?;
        } else {
            let _ = tokio::fs::remove_file(&temp_path).await;
            self.finalize_provisional_link(&canonical_path, ingress, absolute_deadline)
                .await?;
        }
        // Receipt issuance requires the canonical body to be the sole link.
        self.validate_exact(&canonical_path, ingress, absolute_deadline)
            .await?;
        self.receipt(ingress, spool_id)
    }

    /// Validate a replayed request body without replacing the already
    /// authoritative durable spool object.
    pub(super) async fn validate_body(
        &self,
        content_sha256: &Sha256Digest,
        content_length: cats_api::runtime_reconciliation::WireU64,
        mut body: Body,
        absolute_deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        let mut observed_length = 0_u64;
        let mut hasher = Sha256::new();
        loop {
            let frame = timeout(absolute_deadline, body.frame()).await?;
            let Some(frame) = frame else { break };
            let frame = frame.map_err(|_| DurableSpoolError::Unavailable)?;
            let data = frame
                .into_data()
                .map_err(|_| DurableSpoolError::BodyMismatch)?;
            let count = u64::try_from(data.len()).map_err(|_| DurableSpoolError::BodyMismatch)?;
            observed_length = observed_length
                .checked_add(count)
                .ok_or(DurableSpoolError::BodyMismatch)?;
            if observed_length > content_length.get() {
                return Err(DurableSpoolError::BodyMismatch);
            }
            hasher.update(&data);
        }
        if observed_length != content_length.get()
            || Sha256Digest::from_bytes(hasher.finalize().into()) != *content_sha256
        {
            return Err(DurableSpoolError::BodyMismatch);
        }
        Ok(())
    }

    /// Recover a crash after the canonical link became durable but before its
    /// receipt reached PostgreSQL. Missing means the original caller has to
    /// retry the body; a partial file can never occupy the canonical name.
    pub(super) async fn recover_receipt(
        &self,
        ingress: &ObjectWriteIngress,
        absolute_deadline: Instant,
    ) -> Result<DurableObjectWriteSpoolReceipt, DurableSpoolError> {
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        let path = self.body_path(&spool_id)?;
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(DurableSpoolError::NotFound);
            }
            Err(error) => return Err(map_io(error)),
            Ok(_) => {}
        }
        self.finalize_provisional_link(&path, ingress, absolute_deadline)
            .await?;
        self.validate_exact(&path, ingress, absolute_deadline)
            .await?;
        let file = timeout(
            absolute_deadline,
            tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path),
        )
        .await?
        .map_err(map_io)?;
        timeout(absolute_deadline, file.sync_all())
            .await?
            .map_err(map_io)?;
        self.sync_directory(absolute_deadline).await?;
        self.receipt(ingress, spool_id)
    }

    pub(super) async fn remove(
        &self,
        ingress: &ObjectWriteIngress,
        absolute_deadline: Instant,
    ) -> Result<AsciiText, DurableSpoolError> {
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        let path = self.body_path(&spool_id)?;
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(map_io(error)),
            Ok(_) => {
                self.validate_exact(&path, ingress, absolute_deadline)
                    .await?;
                timeout(absolute_deadline, tokio::fs::remove_file(&path))
                    .await?
                    .map_err(map_io)?;
            }
        }
        self.sync_directory(absolute_deadline).await?;
        receipt_id("owrm1_", b"cats.object-write-spool-removed.v1", ingress)
    }

    /// Fresh pre-accept verification. Accepted rows never use this to repair
    /// metadata; their provider adapter independently reopens the same sole
    /// canonical link before every PUT retry.
    pub(super) async fn validate_before_accept(
        &self,
        ingress: &ObjectWriteIngress,
        absolute_deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        self.validate_exact(&self.body_path(&spool_id)?, ingress, absolute_deadline)
            .await
    }

    pub(super) async fn cleanup_old_temporary_files(&self) {
        let Ok(mut entries) = tokio::fs::read_dir(&self.root).await else {
            return;
        };
        let now = SystemTime::now();
        for _ in 0..ORPHAN_SCAN_LIMIT {
            let Ok(Some(entry)) = entries.next_entry().await else {
                break;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(TEMP_PREFIX) || !name.ends_with(TEMP_SUFFIX) {
                continue;
            }
            let Ok(metadata) = tokio::fs::symlink_metadata(entry.path()).await else {
                continue;
            };
            let old_enough = metadata
                .modified()
                .ok()
                .and_then(|modified| now.duration_since(modified).ok())
                .is_some_and(|age| age >= ORPHAN_TEMP_MINIMUM_AGE);
            if metadata.file_type().is_file()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o777 == 0o600
                && metadata.uid() == self.owner_uid
                && metadata.nlink() == 1
                && old_enough
            {
                let _ = tokio::fs::remove_file(entry.path()).await;
            }
        }
    }

    async fn validate_exact(
        &self,
        path: &Path,
        ingress: &ObjectWriteIngress,
        absolute_deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        self.validate_material(path, ingress, 1, absolute_deadline)
            .await
    }

    async fn validate_material(
        &self,
        path: &Path,
        ingress: &ObjectWriteIngress,
        expected_links: u64,
        absolute_deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        let before = timeout(absolute_deadline, tokio::fs::symlink_metadata(path))
            .await?
            .map_err(map_io)?;
        if !before.file_type().is_file()
            || before.file_type().is_symlink()
            || before.permissions().mode() & 0o777 != 0o600
            || before.uid() != self.owner_uid
            || before.nlink() != expected_links
            || before.len() != ingress.content_length.get()
        {
            return Err(DurableSpoolError::Invalid);
        }
        let identity = file_identity(&before);
        let mut file = timeout(absolute_deadline, tokio::fs::File::open(path))
            .await?
            .map_err(map_io)?;
        let mut hasher = Sha256::new();
        let mut length = 0_u64;
        let mut buffer = vec![0_u8; 64 * 1024];
        loop {
            let count = timeout(absolute_deadline, file.read(&mut buffer))
                .await?
                .map_err(map_io)?;
            if count == 0 {
                break;
            }
            length = length
                .checked_add(u64::try_from(count).map_err(|_| DurableSpoolError::Invalid)?)
                .ok_or(DurableSpoolError::Invalid)?;
            if length > ingress.content_length.get() {
                return Err(DurableSpoolError::BodyMismatch);
            }
            hasher.update(&buffer[..count]);
        }
        let after = timeout(absolute_deadline, tokio::fs::symlink_metadata(path))
            .await?
            .map_err(map_io)?;
        if length != ingress.content_length.get()
            || Sha256Digest::from_bytes(hasher.finalize().into()) != ingress.content_sha256
            || after.nlink() != expected_links
            || file_identity(&after) != identity
        {
            return Err(DurableSpoolError::BodyMismatch);
        }
        Ok(())
    }

    async fn finalize_provisional_link(
        &self,
        canonical_path: &Path,
        ingress: &ObjectWriteIngress,
        deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        let canonical = timeout(deadline, tokio::fs::symlink_metadata(canonical_path))
            .await?
            .map_err(map_io)?;
        if canonical.nlink() == 1 {
            return Ok(());
        }
        if canonical.nlink() != 2
            || !canonical.file_type().is_file()
            || canonical.file_type().is_symlink()
            || canonical.permissions().mode() & 0o777 != 0o600
            || canonical.uid() != self.owner_uid
            || canonical.len() != ingress.content_length.get()
        {
            return Err(DurableSpoolError::Invalid);
        }
        let identity = file_identity(&canonical);
        let mut entries = timeout(deadline, tokio::fs::read_dir(&self.root))
            .await?
            .map_err(map_io)?;
        let mut matching_temp = None;
        for _ in 0..ORPHAN_SCAN_LIMIT {
            let Some(entry) = timeout(deadline, entries.next_entry())
                .await?
                .map_err(map_io)?
            else {
                break;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if !name.starts_with(TEMP_PREFIX) || !name.ends_with(TEMP_SUFFIX) {
                continue;
            }
            let metadata = timeout(deadline, tokio::fs::symlink_metadata(entry.path()))
                .await?
                .map_err(map_io)?;
            if file_identity(&metadata) == identity && matching_temp.replace(entry.path()).is_some()
            {
                return Err(DurableSpoolError::Invalid);
            }
        }
        let temp = matching_temp.ok_or(DurableSpoolError::Invalid)?;
        // Link topology alone is not authority. Prove that the exact linked
        // inode has the signed bytes before deleting its recovery marker.
        self.validate_material(canonical_path, ingress, 2, deadline)
            .await?;
        timeout(deadline, tokio::fs::remove_file(temp))
            .await?
            .map_err(map_io)?;
        self.sync_directory(deadline).await?;
        Ok(())
    }

    async fn sync_directory(&self, deadline: Instant) -> Result<(), DurableSpoolError> {
        let root = self.root.clone();
        let task = tokio::task::spawn_blocking(move || {
            let directory = std::fs::File::open(root)?;
            directory.sync_all()
        });
        timeout(deadline, task)
            .await?
            .map_err(|_| DurableSpoolError::Unavailable)?
            .map_err(map_io)
    }

    fn receipt(
        &self,
        ingress: &ObjectWriteIngress,
        spool_id: AsciiText,
    ) -> Result<DurableObjectWriteSpoolReceipt, DurableSpoolError> {
        Ok(DurableObjectWriteSpoolReceipt {
            spool_id,
            request_id: ingress.request_id.clone(),
            content_sha256: ingress.content_sha256.clone(),
            content_length: ingress.content_length,
            file_fsync_receipt_id: receipt_id(
                "owfs1_",
                b"cats.object-write-spool-file-fsync.v1",
                ingress,
            )?,
            directory_fsync_receipt_id: receipt_id(
                "owds1_",
                b"cats.object-write-spool-directory-fsync.v1",
                ingress,
            )?,
            durable_at_unix_ms: unix_millis_now()?,
        })
    }

    fn body_path(&self, spool_id: &AsciiText) -> Result<PathBuf, DurableSpoolError> {
        let value = spool_id.as_str();
        let digest = value
            .strip_prefix("owsp1_")
            .ok_or(DurableSpoolError::Invalid)?;
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(DurableSpoolError::Invalid);
        }
        Ok(self.root.join(format!("{value}{BODY_SUFFIX}")))
    }

    fn temporary_path(&self) -> PathBuf {
        self.root.join(format!(
            "{TEMP_PREFIX}{}{TEMP_SUFFIX}",
            uuid::Uuid::new_v4().simple()
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
    }
}

async fn timeout<T>(
    deadline: Instant,
    future: impl std::future::Future<Output = T>,
) -> Result<T, DurableSpoolError> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or(DurableSpoolError::DeadlineExceeded)?;
    tokio::time::timeout(remaining, future)
        .await
        .map_err(|_| DurableSpoolError::DeadlineExceeded)
}

fn receipt_id(
    prefix: &str,
    domain: &[u8],
    ingress: &ObjectWriteIngress,
) -> Result<AsciiText, DurableSpoolError> {
    let mut hasher = Sha256::new();
    let content_length = ingress.content_length.get().to_be_bytes();
    for value in [
        domain,
        ingress.request_id.as_str().as_bytes(),
        ingress.content_sha256.as_str().as_bytes(),
        &content_length,
    ] {
        let length = u64::try_from(value.len()).map_err(|_| DurableSpoolError::Invalid)?;
        hasher.update(length.to_be_bytes());
        hasher.update(value);
    }
    AsciiText::new(format!("{prefix}{}", hex::encode(hasher.finalize())))
        .ok_or(DurableSpoolError::Invalid)
}

fn unix_millis_now() -> Result<cats_api::runtime_reconciliation::UnixMillis, DurableSpoolError> {
    let millis = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|_| DurableSpoolError::Unavailable)?
        .as_millis();
    let millis = u64::try_from(millis).map_err(|_| DurableSpoolError::Unavailable)?;
    cats_api::runtime_reconciliation::UnixMillis::new(millis).ok_or(DurableSpoolError::Unavailable)
}

fn map_io(error: std::io::Error) -> DurableSpoolError {
    if error.kind() == ErrorKind::NotFound {
        DurableSpoolError::NotFound
    } else {
        DurableSpoolError::Unavailable
    }
}
