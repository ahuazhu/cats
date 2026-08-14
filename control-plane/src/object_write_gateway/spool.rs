use std::io::ErrorKind;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Instant, SystemTime};

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
    root_identity: DirectoryIdentity,
}

impl DurableSpool {
    pub(super) fn open(root: PathBuf) -> Result<Self, DurableSpoolError> {
        if !root.is_absolute() {
            return Err(DurableSpoolError::Invalid);
        }
        let metadata = std::fs::symlink_metadata(&root).map_err(map_io)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != 0o700
        {
            return Err(DurableSpoolError::Invalid);
        }
        let canonical = std::fs::canonicalize(&root).map_err(map_io)?;
        if canonical != root {
            return Err(DurableSpoolError::Invalid);
        }
        let root = canonical;
        Ok(Self {
            root,
            root_identity: directory_identity(&metadata),
        })
    }

    pub(super) async fn receive(
        &self,
        ingress: &ObjectWriteIngress,
        mut body: Body,
        absolute_deadline: Instant,
    ) -> Result<DurableObjectWriteSpoolReceipt, DurableSpoolError> {
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        self.validate_root()?;
        let temp_path = self.temporary_path(&spool_id)?;
        let std_file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temp_path)
            .map_err(map_io)?;
        let mut temporary_guard = TemporaryMarkerGuard::new(temp_path.clone());
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
            temporary_guard.disarm();
            self.sync_directory(absolute_deadline).await?;
        } else {
            let _ = tokio::fs::remove_file(&temp_path).await;
            temporary_guard.disarm();
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
        startup_has_no_receivers: bool,
        absolute_deadline: Instant,
    ) -> Result<DurableObjectWriteSpoolReceipt, DurableSpoolError> {
        self.validate_root()?;
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        let path = self.body_path(&spool_id)?;
        match tokio::fs::symlink_metadata(&path).await {
            Err(error) if error.kind() == ErrorKind::NotFound && startup_has_no_receivers => {
                self.recover_unlinked_provisional(&spool_id, ingress, absolute_deadline)
                    .await?;
            }
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

    /// Startup runs before the listener exists, so an exact sole provisional
    /// marker cannot belong to a live receiver. A complete fsynced marker is
    /// published; a safely owned partial marker is removed so the caller can
    /// resend. Periodic recovery never enters this path while receivers run.
    async fn recover_unlinked_provisional(
        &self,
        spool_id: &AsciiText,
        ingress: &ObjectWriteIngress,
        deadline: Instant,
    ) -> Result<(), DurableSpoolError> {
        let marker = self.temporary_path(spool_id)?;
        let metadata = match timeout(deadline, tokio::fs::symlink_metadata(&marker)).await? {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Err(DurableSpoolError::NotFound);
            }
            Err(error) => return Err(map_io(error)),
        };
        if !metadata.file_type().is_file()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.uid() != self.root_identity.uid
            || metadata.nlink() != 1
        {
            return Err(DurableSpoolError::Invalid);
        }
        let identity = file_identity(&metadata);
        if metadata.len() != ingress.content_length.get()
            || matches!(
                self.validate_material(&marker, ingress, 1, deadline).await,
                Err(DurableSpoolError::BodyMismatch)
            )
        {
            let fresh = timeout(deadline, tokio::fs::symlink_metadata(&marker))
                .await?
                .map_err(map_io)?;
            if file_identity(&fresh) != identity {
                return Err(DurableSpoolError::Invalid);
            }
            timeout(deadline, tokio::fs::remove_file(&marker))
                .await?
                .map_err(map_io)?;
            self.sync_directory(deadline).await?;
            return Err(DurableSpoolError::NotFound);
        }
        self.validate_material(&marker, ingress, 1, deadline)
            .await?;
        let file = timeout(
            deadline,
            tokio::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&marker),
        )
        .await?
        .map_err(map_io)?;
        if file_identity(&file.metadata().await.map_err(map_io)?) != identity {
            return Err(DurableSpoolError::Invalid);
        }
        timeout(deadline, file.sync_all()).await?.map_err(map_io)?;
        self.sync_directory(deadline).await?;
        let canonical = self.body_path(spool_id)?;
        match timeout(deadline, tokio::fs::hard_link(&marker, &canonical)).await? {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
            Err(error) => return Err(map_io(error)),
        }
        self.sync_directory(deadline).await?;
        self.finalize_provisional_link(&canonical, ingress, deadline)
            .await
    }

    pub(super) async fn remove(
        &self,
        ingress: &ObjectWriteIngress,
        absolute_deadline: Instant,
    ) -> Result<AsciiText, DurableSpoolError> {
        self.validate_root()?;
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
        self.validate_root()?;
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        self.validate_exact(&self.body_path(&spool_id)?, ingress, absolute_deadline)
            .await
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
            || before.permissions().mode() & 0o7777 != 0o600
            || before.uid() != self.root_identity.uid
            || before.nlink() != expected_links
            || before.len() != ingress.content_length.get()
        {
            return Err(DurableSpoolError::Invalid);
        }
        let identity = file_identity(&before);
        let mut file = timeout(absolute_deadline, tokio::fs::File::open(path))
            .await?
            .map_err(map_io)?;
        let opened = timeout(absolute_deadline, file.metadata())
            .await?
            .map_err(map_io)?;
        if file_identity(&opened) != identity {
            return Err(DurableSpoolError::Invalid);
        }
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
        let opened_after = timeout(absolute_deadline, file.metadata())
            .await?
            .map_err(map_io)?;
        if length != ingress.content_length.get()
            || Sha256Digest::from_bytes(hasher.finalize().into()) != ingress.content_sha256
            || file_identity(&after) != identity
            || file_identity(&opened_after) != identity
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
            || canonical.permissions().mode() & 0o7777 != 0o600
            || canonical.uid() != self.root_identity.uid
            || canonical.len() != ingress.content_length.get()
        {
            return Err(DurableSpoolError::Invalid);
        }
        let spool_id =
            object_write_spool_id(&ingress.request_id).map_err(|_| DurableSpoolError::Invalid)?;
        let temp = self.temporary_path(&spool_id)?;
        let temporary = timeout(deadline, tokio::fs::symlink_metadata(&temp))
            .await?
            .map_err(map_io)?;
        if file_identity(&temporary) != file_identity(&canonical) {
            return Err(DurableSpoolError::Invalid);
        }
        // Link topology alone is not authority. Prove that the exact linked
        // inode has the signed bytes before deleting its recovery marker.
        self.validate_material(canonical_path, ingress, 2, deadline)
            .await?;
        match timeout(deadline, tokio::fs::remove_file(temp)).await? {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {
                // Another startup replica may have removed the same exact
                // marker. Only its completed nlink=1 postcondition is success.
                self.validate_material(canonical_path, ingress, 1, deadline)
                    .await?;
                self.sync_directory(deadline).await?;
                return Ok(());
            }
            Err(error) => return Err(map_io(error)),
        }
        self.sync_directory(deadline).await?;
        Ok(())
    }

    async fn sync_directory(&self, deadline: Instant) -> Result<(), DurableSpoolError> {
        self.validate_root()?;
        let root = self.root.clone();
        let expected = self.root_identity;
        let task = tokio::task::spawn_blocking(move || {
            let directory = std::fs::File::open(root)?;
            if directory_identity(&directory.metadata()?) != expected {
                return Err(std::io::Error::other("durable spool root identity changed"));
            }
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
        let _ = spool_digest(spool_id)?;
        Ok(self.root.join(format!("{value}{BODY_SUFFIX}")))
    }

    fn temporary_path(&self, spool_id: &AsciiText) -> Result<PathBuf, DurableSpoolError> {
        let digest = spool_digest(spool_id)?;
        Ok(self
            .root
            .join(format!("{TEMP_PREFIX}{digest}{TEMP_SUFFIX}")))
    }

    fn validate_root(&self) -> Result<(), DurableSpoolError> {
        let metadata = std::fs::symlink_metadata(&self.root).map_err(map_io)?;
        if !metadata.file_type().is_dir()
            || metadata.file_type().is_symlink()
            || metadata.permissions().mode() & 0o7777 != 0o700
            || directory_identity(&metadata) != self.root_identity
            || std::fs::canonicalize(&self.root).map_err(map_io)? != self.root
        {
            return Err(DurableSpoolError::Invalid);
        }
        Ok(())
    }
}

struct TemporaryMarkerGuard {
    path: PathBuf,
    armed: bool,
}

impl TemporaryMarkerGuard {
    fn new(path: PathBuf) -> Self {
        Self { path, armed: true }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryMarkerGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
    uid: u32,
    mode: u32,
}

fn directory_identity(metadata: &std::fs::Metadata) -> DirectoryIdentity {
    DirectoryIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    uid: u32,
    mode: u32,
    links: u64,
}

fn file_identity(metadata: &std::fs::Metadata) -> FileIdentity {
    FileIdentity {
        device: metadata.dev(),
        inode: metadata.ino(),
        length: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        uid: metadata.uid(),
        mode: metadata.mode() & 0o7777,
        links: metadata.nlink(),
    }
}

fn spool_digest(spool_id: &AsciiText) -> Result<&str, DurableSpoolError> {
    let digest = spool_id
        .as_str()
        .strip_prefix("owsp1_")
        .ok_or(DurableSpoolError::Invalid)?;
    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(DurableSpoolError::Invalid);
    }
    Ok(digest)
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

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::Write as _;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    use std::time::{Duration, Instant};

    use cats_api::object_write_gateway::{ObjectWriteCredentialReference, ObjectWriteImmutableKey};
    use cats_api::runtime_reconciliation::{
        AsciiText, Id, ProviderScope, Sha256Digest, UnixMillis, WireU64,
    };
    use cats_storage::object_write_authority::{
        object_write_spool_id, ObjectWriteIngress, ObjectWriteTarget,
    };
    use sha2::{Digest as _, Sha256};

    use super::DurableSpool;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn ingress(body: &[u8]) -> ObjectWriteIngress {
        ObjectWriteIngress {
            writer_authority_id: id("writer_a"),
            request_id: Sha256Digest::from_bytes(Sha256::digest(b"request-a").into()),
            credential: ObjectWriteCredentialReference {
                credential_id: id("credential_a"),
                public_key_spki_sha256: Sha256Digest::from_bytes([7_u8; 32]),
            },
            volume_id: id("volume_a"),
            key: ObjectWriteImmutableKey::VolumeMap,
            target: ObjectWriteTarget {
                object_provider_scope: ProviderScope {
                    provider: id("aws"),
                    partition: id("aws"),
                    account_id: id("123456789012"),
                    region: id("us-east-1"),
                },
                object_store_scope_id: AsciiText::new("arn:aws:s3:::bucket/chunks").unwrap(),
                canonical_logical_key: "volumes/volume_a/maps/root".to_owned(),
            },
            content_sha256: Sha256Digest::from_bytes(Sha256::digest(body).into()),
            content_length: WireU64::new(body.len() as u64).unwrap(),
            qualification_fault: None,
            receiving_started_at_unix_ms: UnixMillis::new(1).unwrap(),
        }
    }

    fn private_root() -> tempfile::TempDir {
        // The spool rejects roots whose canonical path differs (macOS tempdirs
        // live behind the /var -> /private/var symlink), so create the
        // directory under the canonicalized temp base.
        let base = std::fs::canonicalize(std::env::temp_dir()).unwrap();
        let root = tempfile::tempdir_in(base).unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    fn write_private(path: &std::path::Path, body: &[u8]) {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(body).unwrap();
        file.sync_all().unwrap();
    }

    #[tokio::test]
    async fn deterministic_marker_recovers_past_more_than_one_scan_page_and_replays() {
        let root = private_root();
        let spool = DurableSpool::open(root.path().to_path_buf()).unwrap();
        let body = b"durable-volume-object";
        let ingress = ingress(body);
        let spool_id = object_write_spool_id(&ingress.request_id).unwrap();
        let marker = spool.temporary_path(&spool_id).unwrap();
        let canonical = spool.body_path(&spool_id).unwrap();

        for index in 0..300 {
            write_private(
                &root.path().join(format!("owsp1_{index:064x}.body")),
                b"unrelated",
            );
        }
        write_private(&marker, body);
        std::fs::hard_link(&marker, &canonical).unwrap();
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();
        assert_eq!(std::fs::metadata(&canonical).unwrap().nlink(), 2);

        drop(spool);
        let restarted = DurableSpool::open(root.path().to_path_buf()).unwrap();
        let first = restarted
            .recover_receipt(&ingress, true, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert!(!marker.exists());
        assert_eq!(std::fs::metadata(&canonical).unwrap().nlink(), 1);

        let replay = restarted
            .recover_receipt(&ingress, true, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(replay.spool_id, first.spool_id);
        assert_eq!(replay.request_id, first.request_id);
        assert_eq!(replay.file_fsync_receipt_id, first.file_fsync_receipt_id);
        assert_eq!(
            replay.directory_fsync_receipt_id,
            first.directory_fsync_receipt_id
        );
        assert_eq!(std::fs::metadata(&canonical).unwrap().nlink(), 1);
    }

    #[tokio::test]
    async fn startup_publishes_complete_marker_and_discards_partial_marker() {
        let root = private_root();
        let complete_body = b"complete-before-link";
        let complete = ingress(complete_body);
        let spool = DurableSpool::open(root.path().to_path_buf()).unwrap();
        let complete_id = object_write_spool_id(&complete.request_id).unwrap();
        let complete_marker = spool.temporary_path(&complete_id).unwrap();
        let complete_canonical = spool.body_path(&complete_id).unwrap();
        write_private(&complete_marker, complete_body);
        std::fs::File::open(root.path())
            .unwrap()
            .sync_all()
            .unwrap();

        let receipt = spool
            .recover_receipt(&complete, true, Instant::now() + Duration::from_secs(10))
            .await
            .unwrap();
        assert_eq!(receipt.spool_id, complete_id);
        assert!(complete_canonical.exists());
        assert!(!complete_marker.exists());
        assert_eq!(std::fs::metadata(&complete_canonical).unwrap().nlink(), 1);

        let mut partial = ingress(b"expected-complete-body");
        partial.request_id = Sha256Digest::from_bytes(Sha256::digest(b"request-partial").into());
        let partial_id = object_write_spool_id(&partial.request_id).unwrap();
        let partial_marker = spool.temporary_path(&partial_id).unwrap();
        write_private(&partial_marker, b"partial");
        assert_eq!(
            spool
                .recover_receipt(&partial, true, Instant::now() + Duration::from_secs(10),)
                .await,
            Err(super::DurableSpoolError::NotFound)
        );
        assert!(!partial_marker.exists());
        assert!(!spool.body_path(&partial_id).unwrap().exists());
    }
}
