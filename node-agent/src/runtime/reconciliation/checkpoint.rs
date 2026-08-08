use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, decode_runtime_checkpoint, encode_runtime_checkpoint, Id,
    RuntimeCheckpoint, Sha256Digest, RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};
use thiserror::Error;

use super::admission_port::AdmissionSnapshot;

/// A decoded checkpoint together with the exact filesystem identity that was
/// observed while reading it.
///
/// Callers must pass this value back when replacing a checkpoint. That makes a
/// target-file replacement between planning and publication a conflict rather
/// than silently overwriting an ABA state.
#[derive(Debug, Clone)]
pub struct StoredCheckpoint {
    checkpoint: RuntimeCheckpoint,
    content_digest: Sha256Digest,
    file_identity: FileIdentity,
}

impl StoredCheckpoint {
    pub fn checkpoint(&self) -> &RuntimeCheckpoint {
        &self.checkpoint
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }
}

#[derive(Debug, Error)]
pub enum CheckpointStoreError {
    #[error("runtime checkpoint contract rejected: {0}")]
    Contract(#[from] cats_api::runtime_reconciliation::ContractError),
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe checkpoint filesystem entry at {path}: {reason}")]
    UnsafeEntry { path: PathBuf, reason: &'static str },
    #[error("checkpoint target changed after it was read: {path}")]
    ConcurrentUpdate { path: PathBuf },
    #[error("checkpoint belongs to Cat {presented}, expected {expected}")]
    WrongCat { expected: Id, presented: Id },
    #[error("another checkpoint writer already owns {path}")]
    WriterAlreadyActive { path: PathBuf },
    #[error("checkpoint writer serialization lock is poisoned: {path}")]
    WriterSerializationPoisoned { path: PathBuf },
    #[error("checkpoint session continuity lock is poisoned: {path}")]
    SessionContinuityPoisoned { path: PathBuf },
    #[cfg(test)]
    #[error("injected checkpoint publication crash")]
    InjectedCrash,
}

/// Concrete, single-writer file store for one Cat checkpoint.
///
/// All target operations are relative to an already-open, non-symlink
/// directory descriptor. The per-Cat `flock` excludes a second legitimate
/// writer. The directory is a protected Host state path; a process capable of
/// bypassing that lock and mutating the directory is outside the Node trust
/// boundary, but a change observed before publication is still rejected.
pub struct FileCheckpointStore {
    directory: File,
    _writer_lock: File,
    directory_path: PathBuf,
    target_name: CString,
    target_path: PathBuf,
    temporary_name: CString,
    temporary_path: PathBuf,
    cat_id: Id,
    writer_serialization: Mutex<()>,
    // Deliberately process-memory-only. Every `open` starts empty, so a disk
    // checkpoint can never reconstruct authority to execute an Endpoint
    // effect from its predecessor.
    endpoint_effect_edges: Mutex<Vec<EndpointEffectEdge>>,
    #[cfg(test)]
    faults: Mutex<TestFaults>,
}

impl FileCheckpointStore {
    /// Opens (and, when absent, creates) the protected checkpoint directory.
    /// The final directory component and the per-Cat lock file must not be
    /// symlinks.
    pub fn open(directory: &Path, cat_id: &Id) -> Result<Self, CheckpointStoreError> {
        std::fs::create_dir_all(directory)
            .map_err(|source| io_error("create checkpoint directory", directory, source))?;

        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let directory_file = options
            .open(directory)
            .map_err(|source| io_error("open checkpoint directory", directory, source))?;
        if !directory_file
            .metadata()
            .map_err(|source| io_error("inspect checkpoint directory", directory, source))?
            .is_dir()
        {
            return Err(CheckpointStoreError::UnsafeEntry {
                path: directory.to_path_buf(),
                reason: "not a directory",
            });
        }

        let target_file_name = format!("cat-{}.checkpoint.json", cat_id.as_str());
        let lock_file_name = format!("cat-{}.checkpoint.lock", cat_id.as_str());
        let temporary_file_name = format!(".cat-{}.checkpoint.tmp", cat_id.as_str());
        let target_name = c_string(&target_file_name, directory)?;
        let lock_name = c_string(&lock_file_name, directory)?;
        let temporary_name = c_string(&temporary_file_name, directory)?;
        let lock_path = directory.join(&lock_file_name);
        let temporary_path = directory.join(&temporary_file_name);
        let writer_lock = open_at(
            &directory_file,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|source| map_open_error("open checkpoint writer lock", &lock_path, source))?;
        verify_regular_single_link(&writer_lock, &lock_path)?;
        loop {
            // SAFETY: `writer_lock` is a live file descriptor. `flock`
            // neither takes ownership of it nor retains a pointer.
            let lock_result =
                unsafe { libc::flock(writer_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if lock_result == 0 {
                break;
            }
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if source.raw_os_error() == Some(libc::EWOULDBLOCK)
                || source.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(CheckpointStoreError::WriterAlreadyActive { path: lock_path });
            }
            return Err(io_error("lock checkpoint writer", &lock_path, source));
        }

        // The held per-Cat lock makes this exact deterministic basename ours.
        // A crashed predecessor is never opened, inspected, scanned for, or
        // adopted; unlinkat removes only this one directory-relative entry.
        unlink_at_if_exists(&directory_file, &temporary_name).map_err(|source| {
            io_error("remove stale checkpoint temp file", &temporary_path, source)
        })?;

        Ok(Self {
            directory: directory_file,
            _writer_lock: writer_lock,
            directory_path: directory.to_path_buf(),
            target_name,
            target_path: directory.join(target_file_name),
            temporary_name,
            temporary_path,
            cat_id: cat_id.clone(),
            writer_serialization: Mutex::new(()),
            endpoint_effect_edges: Mutex::new(Vec::new()),
            #[cfg(test)]
            faults: Mutex::new(TestFaults::default()),
        })
    }

    pub fn path(&self) -> &Path {
        &self.target_path
    }

    pub(super) fn arm_endpoint_effect_edge(
        &self,
        candidate: &EndpointEffectEdge,
    ) -> Result<bool, CheckpointStoreError> {
        let mut edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        if edges.iter().any(|present| present == candidate) {
            return Ok(true);
        }
        if edges
            .iter()
            .any(|present| present.endpoint_id == candidate.endpoint_id)
            || edges.len() >= 256
        {
            return Ok(false);
        }
        edges.push(candidate.clone());
        Ok(true)
    }

    pub(super) fn endpoint_effect_edge_status(
        &self,
        candidate: &EndpointEffectEdge,
    ) -> Result<EndpointEffectEdgeStatus, CheckpointStoreError> {
        let edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        if edges.iter().any(|present| present == candidate) {
            Ok(EndpointEffectEdgeStatus::Exact)
        } else if edges
            .iter()
            .any(|present| present.endpoint_id == candidate.endpoint_id)
        {
            Ok(EndpointEffectEdgeStatus::Mismatch)
        } else {
            Ok(EndpointEffectEdgeStatus::Missing)
        }
    }

    /// Consumes the process-local edge whose exact replacement was observed
    /// and optionally installs the next exact Endpoint edge atomically. A
    /// missing current edge is accepted because an exact live postcondition
    /// is independently sufficient after restart. A conflicting current or
    /// next edge leaves the set unchanged.
    pub(super) fn transition_confirmed_endpoint_effect(
        &self,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
        next: Option<&EndpointEffectEdge>,
    ) -> Result<bool, CheckpointStoreError> {
        let mut edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        let mut updated = edges.clone();
        match updated
            .iter()
            .position(|present| present.endpoint_id == *endpoint_id)
        {
            Some(index) if updated[index].replacement == *replacement => {
                updated.remove(index);
            }
            Some(_) => return Ok(false),
            None => {}
        }
        if let Some(next) = next {
            if next.predecessor != *replacement {
                return Ok(false);
            }
            if !updated.iter().any(|present| present == next) {
                if updated
                    .iter()
                    .any(|present| present.endpoint_id == next.endpoint_id)
                    || updated.len() >= 256
                {
                    return Ok(false);
                }
                updated.push(next.clone());
            }
        }
        *edges = updated;
        Ok(true)
    }

    pub(super) fn clear_endpoint_effect_edge(
        &self,
        candidate: &EndpointEffectEdge,
    ) -> Result<(), CheckpointStoreError> {
        let mut edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        edges.retain(|present| present != candidate);
        Ok(())
    }

    /// Reads at most the public wire cap plus one byte before invoking the
    /// shared explicit decoder. Temp files are never inspected or adopted.
    pub fn load(&self) -> Result<Option<StoredCheckpoint>, CheckpointStoreError> {
        self.load_target()
    }

    /// Publishes the first checkpoint only when the target is still absent.
    pub fn create(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<StoredCheckpoint, CheckpointStoreError> {
        self.persist(ExpectedTarget::Missing, checkpoint)
    }

    /// Atomically replaces the exact checkpoint returned by [`Self::load`],
    /// [`Self::create`], or an earlier successful replacement.
    pub fn replace(
        &self,
        expected: &StoredCheckpoint,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<StoredCheckpoint, CheckpointStoreError> {
        self.persist(ExpectedTarget::Exact(expected), checkpoint)
    }

    /// Re-establishes the directory durability barrier after a caller lost a
    /// publication acknowledgement, then confirms the exact visible value.
    /// This never adopts a temp file or treats visibility alone as durable.
    pub(super) fn confirm_durable_checkpoint(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<bool, CheckpointStoreError> {
        self.directory.sync_all().map_err(|source| {
            io_error("sync checkpoint directory", &self.directory_path, source)
        })?;
        Ok(self
            .load_target()?
            .is_some_and(|stored| stored.checkpoint == *checkpoint))
    }

    fn persist(
        &self,
        expected: ExpectedTarget<'_>,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<StoredCheckpoint, CheckpointStoreError> {
        let _writer = self.writer_serialization.lock().map_err(|_| {
            CheckpointStoreError::WriterSerializationPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        if checkpoint.cat_id != self.cat_id {
            return Err(CheckpointStoreError::WrongCat {
                expected: self.cat_id.clone(),
                presented: checkpoint.cat_id.clone(),
            });
        }
        let bytes = encode_runtime_checkpoint(checkpoint)?;
        let expected_digest = checkpoint_content_digest(checkpoint)?;

        self.verify_expected(expected)?;
        let mut temporary = self.create_temporary()?;
        self.maybe_crash(WriteStage::Write)?;
        temporary.file.write_all(&bytes).map_err(|source| {
            io_error("write checkpoint temp file", &self.temporary_path, source)
        })?;
        self.maybe_crash(WriteStage::TempWritten)?;
        temporary.file.sync_all().map_err(|source| {
            io_error("sync checkpoint temp file", &self.temporary_path, source)
        })?;
        self.maybe_crash(WriteStage::FileSynced)?;

        self.run_before_publish_hook();
        // Recheck immediately before rename. Together with the held per-Cat
        // writer lock this rejects target ABA by another conforming writer.
        self.verify_expected(expected)?;
        rename_at(
            &self.directory,
            &self.temporary_name,
            &self.directory,
            &self.target_name,
        )
        .map_err(|source| io_error("publish runtime checkpoint", &self.target_path, source))?;
        // The temp basename no longer exists as soon as rename succeeds.
        // Disarm before any later injected or real error so Drop cannot unlink
        // a subsequent writer's basename.
        temporary.disarm();
        self.maybe_crash(WriteStage::Renamed)?;
        self.directory.sync_all().map_err(|source| {
            io_error("sync checkpoint directory", &self.directory_path, source)
        })?;
        self.maybe_crash(WriteStage::DirectorySynced)?;

        let stored = self
            .load_target()?
            .ok_or_else(|| CheckpointStoreError::ConcurrentUpdate {
                path: self.target_path.clone(),
            })?;
        if stored.checkpoint != *checkpoint || stored.content_digest != expected_digest {
            return Err(CheckpointStoreError::ConcurrentUpdate {
                path: self.target_path.clone(),
            });
        }
        Ok(stored)
    }

    fn verify_expected(&self, expected: ExpectedTarget<'_>) -> Result<(), CheckpointStoreError> {
        let current = self.load_target()?;
        match (expected, current) {
            (ExpectedTarget::Missing, None) => Ok(()),
            (ExpectedTarget::Exact(expected), Some(current))
                if current.file_identity == expected.file_identity
                    && current.content_digest == expected.content_digest
                    && current.checkpoint == expected.checkpoint =>
            {
                Ok(())
            }
            _ => Err(CheckpointStoreError::ConcurrentUpdate {
                path: self.target_path.clone(),
            }),
        }
    }

    fn load_target(&self) -> Result<Option<StoredCheckpoint>, CheckpointStoreError> {
        let file = match open_at(
            &self.directory,
            &self.target_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(map_open_error(
                    "open runtime checkpoint",
                    &self.target_path,
                    source,
                ))
            }
        };
        verify_regular_single_link(&file, &self.target_path)?;
        let before =
            FileIdentity::from_metadata(&file.metadata().map_err(|source| {
                io_error("inspect runtime checkpoint", &self.target_path, source)
            })?);
        let capacity = usize::try_from(before.len)
            .unwrap_or(usize::MAX)
            .min(RUNTIME_CHECKPOINT_MAX_WIRE_BYTES.saturating_add(1));
        let mut bytes = Vec::with_capacity(capacity);
        let read_limit = u64::try_from(RUNTIME_CHECKPOINT_MAX_WIRE_BYTES)
            .map_err(|source| {
                io_error(
                    "convert checkpoint wire limit",
                    &self.target_path,
                    io::Error::new(io::ErrorKind::InvalidInput, source),
                )
            })?
            .saturating_add(1);
        let mut bounded = (&file).take(read_limit);
        bounded
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read runtime checkpoint", &self.target_path, source))?;
        let after = FileIdentity::from_metadata(&file.metadata().map_err(|source| {
            io_error("reinspect runtime checkpoint", &self.target_path, source)
        })?);
        if before != after {
            return Err(CheckpointStoreError::ConcurrentUpdate {
                path: self.target_path.clone(),
            });
        }
        let checkpoint = decode_runtime_checkpoint(&bytes)?;
        if checkpoint.cat_id != self.cat_id {
            return Err(CheckpointStoreError::WrongCat {
                expected: self.cat_id.clone(),
                presented: checkpoint.cat_id,
            });
        }
        let content_digest = checkpoint_content_digest(&checkpoint)?;
        Ok(Some(StoredCheckpoint {
            checkpoint,
            content_digest,
            file_identity: before,
        }))
    }

    fn create_temporary(&self) -> Result<TemporaryCheckpoint<'_>, CheckpointStoreError> {
        unlink_at_if_exists(&self.directory, &self.temporary_name).map_err(|source| {
            io_error(
                "remove stale checkpoint temp file",
                &self.temporary_path,
                source,
            )
        })?;
        let file = open_at(
            &self.directory,
            &self.temporary_name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|source| {
            map_open_error("create checkpoint temp file", &self.temporary_path, source)
        })?;
        let temporary = TemporaryCheckpoint {
            directory: &self.directory,
            name: &self.temporary_name,
            file,
            armed: true,
        };
        verify_regular_single_link(&temporary.file, &self.temporary_path)?;
        Ok(temporary)
    }

    #[cfg(not(test))]
    fn maybe_crash(&self, _stage: WriteStage) -> Result<(), CheckpointStoreError> {
        Ok(())
    }

    #[cfg(test)]
    fn maybe_crash(&self, stage: WriteStage) -> Result<(), CheckpointStoreError> {
        let mut faults = self.faults.lock().expect("test fault lock");
        if let Some(exit) = &mut faults.exit_once {
            if exit.stage == stage {
                exit.remaining -= 1;
                if exit.remaining == 0 {
                    // SAFETY: this test-only fault deliberately models an
                    // abrupt process death without running Rust destructors.
                    // `_exit` never returns and retains no Rust pointers.
                    unsafe { libc::_exit(TEST_PROCESS_EXIT_CODE) };
                }
            }
        }
        if let Some(crash) = &mut faults.crash_once {
            if crash.stage == stage {
                crash.remaining -= 1;
                if crash.remaining == 0 {
                    faults.crash_once = None;
                    return Err(CheckpointStoreError::InjectedCrash);
                }
            }
        }
        Ok(())
    }

    #[cfg(not(test))]
    fn run_before_publish_hook(&self) {}

    #[cfg(test)]
    fn run_before_publish_hook(&self) {
        let hook = self
            .faults
            .lock()
            .expect("test fault lock")
            .before_publish
            .take();
        if let Some(hook) = hook {
            hook(&self.target_path);
        }
    }

    #[cfg(test)]
    pub(super) fn inject_crash_once(&self, stage: WriteStage) {
        self.inject_crash_on_nth(stage, 1);
    }

    #[cfg(test)]
    pub(super) fn inject_crash_on_nth(&self, stage: WriteStage, occurrence: usize) {
        assert!(occurrence > 0, "crash occurrence must be positive");
        self.faults.lock().expect("test fault lock").crash_once = Some(TestCrash {
            stage,
            remaining: occurrence,
        });
    }

    #[cfg(test)]
    pub(super) fn inject_process_exit_once(&self, stage: WriteStage) {
        self.faults.lock().expect("test fault lock").exit_once = Some(TestCrash {
            stage,
            remaining: 1,
        });
    }

    #[cfg(test)]
    pub(super) fn before_publish_once(&self, hook: impl FnOnce(&Path) + Send + 'static) {
        self.faults.lock().expect("test fault lock").before_publish = Some(Box::new(hook));
    }
}

#[derive(Clone, Copy)]
enum ExpectedTarget<'a> {
    Missing,
    Exact(&'a StoredCheckpoint),
}

/// Exact in-session proof captured from the live AdmissionCell before a
/// corresponding Endpoint-scoped effect token is published. It is shared by
/// CloseGate and InstallGate and has no wire or persistence representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct EndpointEffectEdge {
    predecessor: AdmissionSnapshot,
    replacement: AdmissionSnapshot,
    endpoint_id: Id,
}

impl EndpointEffectEdge {
    pub(super) fn new(
        predecessor: AdmissionSnapshot,
        replacement: AdmissionSnapshot,
        endpoint_id: Id,
    ) -> Self {
        Self {
            predecessor,
            replacement,
            endpoint_id,
        }
    }

    pub(super) fn endpoint_id(&self) -> &Id {
        &self.endpoint_id
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointEffectEdgeStatus {
    Exact,
    Missing,
    Mismatch,
}

struct TemporaryCheckpoint<'a> {
    directory: &'a File,
    name: &'a CStr,
    file: File,
    armed: bool,
}

impl TemporaryCheckpoint<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryCheckpoint<'_> {
    fn drop(&mut self) {
        if self.armed {
            // Cleanup is deliberately best-effort in Drop: the deterministic
            // basename keeps space bounded even if the filesystem itself is
            // failing, and the next persist/restart retries this exact unlink.
            let _ = unlink_at_if_exists(self.directory, self.name);
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WriteStage {
    Write,
    TempWritten,
    FileSynced,
    Renamed,
    DirectorySynced,
}

#[cfg(test)]
pub(super) const TEST_PROCESS_EXIT_CODE: i32 = 86;

#[cfg(test)]
#[derive(Default)]
struct TestFaults {
    crash_once: Option<TestCrash>,
    exit_once: Option<TestCrash>,
    before_publish: Option<BeforePublishHook>,
}

#[cfg(test)]
type BeforePublishHook = Box<dyn FnOnce(&Path) + Send>;

#[cfg(test)]
struct TestCrash {
    stage: WriteStage,
    remaining: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn verify_regular_single_link(file: &File, path: &Path) -> Result<(), CheckpointStoreError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect checkpoint entry", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(CheckpointStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "not a regular file",
        });
    }
    if metadata.nlink() != 1 {
        return Err(CheckpointStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "hard-linked file",
        });
    }
    Ok(())
}

fn c_string(value: &str, path: &Path) -> Result<CString, CheckpointStoreError> {
    CString::new(value).map_err(|_| CheckpointStoreError::UnsafeEntry {
        path: path.to_path_buf(),
        reason: "NUL byte in checkpoint path",
    })
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: `directory` remains open for the call, `name` is
        // NUL-terminated, and a successful returned descriptor is transferred
        // exactly once to `File`. `openat` does not retain the string pointer.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::mode_t as libc::c_uint,
            )
        };
        if descriptor >= 0 {
            // SAFETY: `descriptor` is a new owned descriptor returned by
            // `openat`.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both directory descriptors remain live for the call, both
        // names are NUL-terminated, and `renameat` retains neither pointer.
        let result = unsafe {
            libc::renameat(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn unlink_at_if_exists(directory: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: `directory` and `name` remain live for the call. The name is
        // directory-relative and NUL-terminated; unlinkat retains no pointer.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn map_open_error(operation: &'static str, path: &Path, source: io::Error) -> CheckpointStoreError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        CheckpointStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "symbolic link",
        }
    } else {
        io_error(operation, path, source)
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> CheckpointStoreError {
    CheckpointStoreError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}
