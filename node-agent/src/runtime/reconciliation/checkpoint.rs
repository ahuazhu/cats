use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, decode_runtime_checkpoint, decode_runtime_volume_transition_request,
    encode_runtime_checkpoint, encode_runtime_volume_transition_request, ContractVersion, Id,
    ReconcileStep, RuntimeCheckpoint, RuntimeVolumeTransition,
    RuntimeVolumeTransitionPreconditionProblem, RuntimeVolumeTransitionRequest, Sha256Digest,
    RUNTIME_CHECKPOINT_MAX_WIRE_BYTES, RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES,
};
use serde::{Deserialize, Serialize};
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

/// Provider-private durable evidence that Control definitively rejected one
/// exact checkpointed A22 release. It is never projected as a terminal
/// `QuarantineReason`: frozen V1 has no persisted reason slot for that claim.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DefiniteReleaseRejection {
    pub(super) version: ContractVersion,
    pub(super) http_status: u16,
    pub(super) cat_id: Id,
    pub(super) checkpoint_content_digest: Sha256Digest,
    pub(super) request: RuntimeVolumeTransitionRequest,
    pub(super) problem: RuntimeVolumeTransitionPreconditionProblem,
}

pub(super) const RELEASE_REJECTION_MAX_BYTES: usize =
    RUNTIME_VOLUME_TRANSITION_REQUEST_MAX_WIRE_BYTES + 2_048;

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
    #[error("definite release rejection marker at {path} is invalid: {reason}")]
    InvalidReleaseRejection { path: PathBuf, reason: String },
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
    release_rejection_name: CString,
    release_rejection_path: PathBuf,
    release_rejection_temporary_name: CString,
    release_rejection_temporary_path: PathBuf,
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

        let target_path = runtime_checkpoint_path(directory, cat_id);
        let target_file_name = target_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a runtime checkpoint basename is canonical ASCII")
            .to_owned();
        let lock_file_name = format!("cat-{}.checkpoint.lock", cat_id.as_str());
        let temporary_file_name = format!(".cat-{}.checkpoint.tmp", cat_id.as_str());
        let release_rejection_path = release_rejection_path(directory, cat_id);
        let release_rejection_file_name = release_rejection_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a release rejection basename is canonical ASCII")
            .to_owned();
        let release_rejection_temporary_path = release_rejection_temporary_path(directory, cat_id);
        let release_rejection_temporary_file_name = release_rejection_temporary_path
            .file_name()
            .and_then(|name| name.to_str())
            .expect("a release rejection temp basename is canonical ASCII")
            .to_owned();
        let target_name = c_string(&target_file_name, directory)?;
        let lock_name = c_string(&lock_file_name, directory)?;
        let temporary_name = c_string(&temporary_file_name, directory)?;
        let release_rejection_name = c_string(&release_rejection_file_name, directory)?;
        let release_rejection_temporary_name =
            c_string(&release_rejection_temporary_file_name, directory)?;
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
            target_path,
            temporary_name,
            temporary_path,
            release_rejection_name,
            release_rejection_path,
            release_rejection_temporary_name,
            release_rejection_temporary_path,
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

    #[cfg(test)]
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

    /// Locks and validates the complete in-memory edge transition before the
    /// local Endpoint effect. The returned transaction performs no mutation
    /// until the caller confirms the exact postcondition. It then consumes
    /// the current edge permanently and keeps a newly armed next edge only if
    /// the matching checkpoint is subsequently confirmed durable.
    pub(super) fn prepare_endpoint_effect_transition<'a>(
        &'a self,
        current: Option<&EndpointEffectEdge>,
        replacement: &AdmissionSnapshot,
        endpoint_id: &Id,
        next: Option<&EndpointEffectEdge>,
    ) -> Result<EndpointEffectTransitionPreparation<'a>, CheckpointStoreError> {
        let edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;

        let current_index = match current {
            Some(candidate)
                if candidate.endpoint_id == *endpoint_id
                    && candidate.replacement == *replacement =>
            {
                match edges.iter().position(|present| present == candidate) {
                    Some(index) => Some(index),
                    None if edges
                        .iter()
                        .any(|present| present.endpoint_id == *endpoint_id) =>
                    {
                        return Ok(EndpointEffectTransitionPreparation::Mismatch)
                    }
                    None => return Ok(EndpointEffectTransitionPreparation::Missing),
                }
            }
            Some(_) => return Ok(EndpointEffectTransitionPreparation::Mismatch),
            None => match edges
                .iter()
                .position(|present| present.endpoint_id == *endpoint_id)
            {
                Some(index) if edges[index].replacement == *replacement => Some(index),
                Some(_) => return Ok(EndpointEffectTransitionPreparation::Mismatch),
                None => None,
            },
        };

        let mut next_already_present = false;
        if let Some(next) = next {
            if next.predecessor != *replacement {
                return Ok(EndpointEffectTransitionPreparation::Mismatch);
            }
            for (index, present) in edges.iter().enumerate() {
                if Some(index) == current_index || present.endpoint_id != next.endpoint_id {
                    continue;
                }
                if present == next {
                    next_already_present = true;
                    break;
                }
                return Ok(EndpointEffectTransitionPreparation::Mismatch);
            }
            if !next_already_present && edges.len() - usize::from(current_index.is_some()) >= 256 {
                return Ok(EndpointEffectTransitionPreparation::Mismatch);
            }
        }

        Ok(EndpointEffectTransitionPreparation::Ready(
            EndpointEffectTransition {
                edges,
                current_index,
                next: next.cloned().map(Box::new),
                next_already_present,
                confirmed: false,
                retain_next: false,
            },
        ))
    }

    /// Locks all process-local Endpoint edges across one global gate result.
    /// Busy drops the guard unchanged; actual or ambiguous global close calls
    /// `confirm` and clears the set without another fallible lock acquisition.
    pub(super) fn prepare_endpoint_effect_revocation(
        &self,
    ) -> Result<EndpointEffectRevocation<'_>, CheckpointStoreError> {
        let edges = self.endpoint_effect_edges.lock().map_err(|_| {
            CheckpointStoreError::SessionContinuityPoisoned {
                path: self.target_path.clone(),
            }
        })?;
        Ok(EndpointEffectRevocation { edges })
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

    /// Load a durable definite-release rejection only when it binds the exact
    /// current checkpoint. A partial temp publication is residue and is never
    /// removed or adopted here.
    pub(super) fn load_definite_release_rejection(
        &self,
        expected: &StoredCheckpoint,
    ) -> Result<Option<DefiniteReleaseRejection>, CheckpointStoreError> {
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        self.ensure_release_rejection_temporary_absent()?;
        self.load_release_rejection_target(expected.checkpoint())
    }

    /// Rebuilds the directory durability acknowledgement for an exact visible
    /// target. This closes the response-loss window where `linkat` became
    /// visible but the following directory fsync acknowledgement was lost.
    pub(super) fn confirm_durable_definite_release_rejection(
        &self,
        expected: &StoredCheckpoint,
    ) -> Result<bool, CheckpointStoreError> {
        let _writer = self.writer_serialization.lock().map_err(|_| {
            CheckpointStoreError::WriterSerializationPoisoned {
                path: self.release_rejection_path.clone(),
            }
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        self.ensure_release_rejection_temporary_absent()?;
        let Some(before) = self.load_release_rejection_target(expected.checkpoint())? else {
            return Ok(false);
        };
        self.directory.sync_all().map_err(|source| {
            io_error(
                "confirm release rejection directory durability",
                &self.directory_path,
                source,
            )
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        self.ensure_release_rejection_temporary_absent()?;
        Ok(self
            .load_release_rejection_target(expected.checkpoint())?
            .is_some_and(|after| after == before))
    }

    /// Durably publish the exact typed 409 which makes one checkpointed A22
    /// release non-replayable. The target is no-replace; an existing exact
    /// marker is an idempotent replay, while any mismatch or partial publish
    /// remains untouched and fails closed.
    pub(super) fn persist_definite_release_rejection(
        &self,
        expected: &StoredCheckpoint,
        request: &RuntimeVolumeTransitionRequest,
        problem: RuntimeVolumeTransitionPreconditionProblem,
    ) -> Result<DefiniteReleaseRejection, CheckpointStoreError> {
        let _writer = self.writer_serialization.lock().map_err(|_| {
            CheckpointStoreError::WriterSerializationPoisoned {
                path: self.release_rejection_path.clone(),
            }
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        self.ensure_release_rejection_temporary_absent()?;
        let marker = DefiniteReleaseRejection {
            version: ContractVersion::V1,
            http_status: 409,
            cat_id: self.cat_id.clone(),
            checkpoint_content_digest: expected.content_digest().clone(),
            request: request.clone(),
            problem,
        };
        let bytes = encode_definite_release_rejection(
            &marker,
            expected.checkpoint(),
            &self.release_rejection_path,
        )?;
        if let Some(existing) = self.load_release_rejection_target(expected.checkpoint())? {
            if existing == marker {
                return Ok(existing);
            }
            return Err(invalid_release_rejection(
                &self.release_rejection_path,
                "a different durable rejection already binds this checkpoint",
            ));
        }

        let mut temporary = open_at(
            &self.directory,
            &self.release_rejection_temporary_name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|source| {
            map_open_error(
                "create release rejection temp file",
                &self.release_rejection_temporary_path,
                source,
            )
        })?;
        verify_regular_single_link(&temporary, &self.release_rejection_temporary_path)?;
        temporary.write_all(&bytes).map_err(|source| {
            io_error(
                "write release rejection temp file",
                &self.release_rejection_temporary_path,
                source,
            )
        })?;
        temporary.sync_all().map_err(|source| {
            io_error(
                "sync release rejection temp file",
                &self.release_rejection_temporary_path,
                source,
            )
        })?;
        // Once the closed 409 has been observed, a crash must leave either a
        // durable exact target or durable residue which blocks replay. Sync
        // the temp directory entry before linking the no-replace target.
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync release rejection temp link",
                &self.directory_path,
                source,
            )
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        link_at(
            &self.directory,
            &self.release_rejection_temporary_name,
            &self.directory,
            &self.release_rejection_name,
        )
        .map_err(|source| {
            io_error(
                "publish release rejection marker without replacement",
                &self.release_rejection_path,
                source,
            )
        })?;
        // Make the target link durable before removing the temp link. A crash
        // between these barriers leaves either the exact target or a visible
        // partial two-link publication, never silent absence after the 409.
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync release rejection target link",
                &self.directory_path,
                source,
            )
        })?;
        unlink_at_if_exists(&self.directory, &self.release_rejection_temporary_name).map_err(
            |source| {
                io_error(
                    "remove published release rejection temp link",
                    &self.release_rejection_temporary_path,
                    source,
                )
            },
        )?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync release rejection directory",
                &self.directory_path,
                source,
            )
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        let visible = self
            .load_release_rejection_target(expected.checkpoint())?
            .ok_or_else(|| {
                invalid_release_rejection(
                    &self.release_rejection_path,
                    "durable target disappeared after publication",
                )
            })?;
        if visible != marker {
            return Err(invalid_release_rejection(
                &self.release_rejection_path,
                "durable target differs from the published rejection",
            ));
        }
        Ok(visible)
    }

    /// Completes an interrupted durable rejection publication. Only the two
    /// exact states produced by `persist_definite_release_rejection` are
    /// recoverable: a single-link canonical temp with no target, or the same
    /// canonical inode linked at both temp and target. Every other shape is
    /// left byte-for-byte intact and rejected.
    pub(super) fn recover_definite_release_rejection_publication(
        &self,
        expected: &StoredCheckpoint,
    ) -> Result<bool, CheckpointStoreError> {
        let _writer = self.writer_serialization.lock().map_err(|_| {
            CheckpointStoreError::WriterSerializationPoisoned {
                path: self.release_rejection_path.clone(),
            }
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        let temporary = match open_at(
            &self.directory,
            &self.release_rejection_temporary_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(false),
            Err(source) => {
                return Err(map_open_error(
                    "open release rejection temp for recovery",
                    &self.release_rejection_temporary_path,
                    source,
                ))
            }
        };
        let (marker, temporary_identity, temporary_links) = read_definite_release_rejection_file(
            &temporary,
            &self.release_rejection_temporary_path,
            expected.checkpoint(),
            &[1, 2],
        )?;

        let target = match open_at(
            &self.directory,
            &self.release_rejection_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => Some(file),
            Err(source) if source.kind() == io::ErrorKind::NotFound => None,
            Err(source) => {
                return Err(map_open_error(
                    "open release rejection target for recovery",
                    &self.release_rejection_path,
                    source,
                ))
            }
        };
        match target {
            None if temporary_links == 1 => {
                link_at(
                    &self.directory,
                    &self.release_rejection_temporary_name,
                    &self.directory,
                    &self.release_rejection_name,
                )
                .map_err(|source| {
                    io_error(
                        "recover release rejection target link",
                        &self.release_rejection_path,
                        source,
                    )
                })?;
            }
            Some(target) if temporary_links == 2 => {
                let (target_marker, target_identity, target_links) =
                    read_definite_release_rejection_file(
                        &target,
                        &self.release_rejection_path,
                        expected.checkpoint(),
                        &[2],
                    )?;
                if target_links != 2
                    || target_identity.device != temporary_identity.device
                    || target_identity.inode != temporary_identity.inode
                    || target_marker != marker
                {
                    return Err(invalid_release_rejection(
                        &self.release_rejection_temporary_path,
                        "temp and target are not the same exact publication inode",
                    ));
                }
            }
            None => {
                return Err(invalid_release_rejection(
                    &self.release_rejection_temporary_path,
                    "two-link rejection temp lacks its exact target",
                ))
            }
            Some(_) => {
                return Err(invalid_release_rejection(
                    &self.release_rejection_temporary_path,
                    "single-link rejection temp conflicts with an existing target",
                ))
            }
        }
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync recovered release rejection target",
                &self.directory_path,
                source,
            )
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        unlink_at_if_exists(&self.directory, &self.release_rejection_temporary_name).map_err(
            |source| {
                io_error(
                    "remove recovered release rejection temp",
                    &self.release_rejection_temporary_path,
                    source,
                )
            },
        )?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync recovered release rejection directory",
                &self.directory_path,
                source,
            )
        })?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        let visible = self
            .load_release_rejection_target(expected.checkpoint())?
            .ok_or_else(|| {
                invalid_release_rejection(
                    &self.release_rejection_path,
                    "recovered rejection target disappeared",
                )
            })?;
        if visible != marker {
            return Err(invalid_release_rejection(
                &self.release_rejection_path,
                "recovered rejection target changed",
            ));
        }
        Ok(true)
    }

    fn ensure_release_rejection_temporary_absent(&self) -> Result<(), CheckpointStoreError> {
        match open_at(
            &self.directory,
            &self.release_rejection_temporary_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => {
                verify_regular_single_link(&file, &self.release_rejection_temporary_path)?;
                Err(CheckpointStoreError::UnsafeEntry {
                    path: self.release_rejection_temporary_path.clone(),
                    reason: "partial definite release rejection publication",
                })
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(map_open_error(
                "inspect release rejection temp file",
                &self.release_rejection_temporary_path,
                source,
            )),
        }
    }

    fn load_release_rejection_target(
        &self,
        checkpoint: &RuntimeCheckpoint,
    ) -> Result<Option<DefiniteReleaseRejection>, CheckpointStoreError> {
        let file = match open_at(
            &self.directory,
            &self.release_rejection_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(map_open_error(
                    "open definite release rejection marker",
                    &self.release_rejection_path,
                    source,
                ))
            }
        };
        let (marker, _, _) = read_definite_release_rejection_file(
            &file,
            &self.release_rejection_path,
            checkpoint,
            &[1],
        )?;
        Ok(Some(marker))
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

/// The single deterministic path used by both the read-only inventory pass
/// and the per-Cat checkpoint writer. The `cat-` prefix makes even the valid
/// F0 `Id` values `.` and `..` ordinary basenames; `Id` rejects `/` and NUL.
pub fn runtime_checkpoint_path(directory: &Path, cat_id: &Id) -> PathBuf {
    directory.join(format!("cat-{}.checkpoint.json", cat_id.as_str()))
}

pub(super) fn release_rejection_path(directory: &Path, cat_id: &Id) -> PathBuf {
    directory.join(format!("cat-{}.release-rejection.json", cat_id.as_str()))
}

pub(super) fn release_rejection_temporary_path(directory: &Path, cat_id: &Id) -> PathBuf {
    directory.join(format!(".cat-{}.release-rejection.tmp", cat_id.as_str()))
}

pub(super) fn decode_definite_release_rejection(
    bytes: &[u8],
    path: &Path,
) -> Result<DefiniteReleaseRejection, CheckpointStoreError> {
    if bytes.len() > RELEASE_REJECTION_MAX_BYTES {
        return Err(invalid_release_rejection(
            path,
            "marker exceeds its byte cap",
        ));
    }
    let marker: DefiniteReleaseRejection = serde_json::from_slice(bytes).map_err(|source| {
        invalid_release_rejection(path, format!("JSON decode failed: {source}"))
    })?;
    let canonical = serde_json::to_vec(&marker).map_err(|source| {
        invalid_release_rejection(path, format!("canonical JSON encode failed: {source}"))
    })?;
    if canonical != bytes {
        return Err(invalid_release_rejection(
            path,
            "marker is not canonical JSON",
        ));
    }
    Ok(marker)
}

pub(super) fn validate_definite_release_rejection(
    marker: &DefiniteReleaseRejection,
    checkpoint: &RuntimeCheckpoint,
    path: &Path,
) -> Result<(), CheckpointStoreError> {
    let request_bytes = encode_runtime_volume_transition_request(&marker.request)?;
    let decoded_request = decode_runtime_volume_transition_request(&request_bytes)?;
    let ReconcileStep::CleanupRelease {
        cleanup: checkpoint_cleanup,
    } = &checkpoint.step
    else {
        return Err(invalid_release_rejection(
            path,
            "bound checkpoint is not CleanupRelease",
        ));
    };
    let RuntimeVolumeTransition::Release {
        cleanup: request_cleanup,
    } = &marker.request.transition
    else {
        return Err(invalid_release_rejection(
            path,
            "bound request is not Release",
        ));
    };
    let digest = checkpoint_content_digest(checkpoint)?;
    let supported_problem = matches!(
        &marker.problem,
        RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch
            | RuntimeVolumeTransitionPreconditionProblem::AuthorizationBranchConflict
    );
    if marker.version != ContractVersion::V1
        || marker.http_status != 409
        || marker.cat_id != checkpoint.cat_id
        || marker.checkpoint_content_digest != digest
        || decoded_request != marker.request
        || marker.request.version != checkpoint.version
        || marker.request.cat_id != checkpoint.cat_id
        || marker.request.desired_revision != checkpoint.desired_revision
        || marker.request.spec_digest != checkpoint.spec_digest
        || marker.request.placement.node_id != checkpoint.node_id
        || marker.request.placement.placement_epoch != checkpoint.placement_epoch
        || marker.request.session.node_id != checkpoint.node_id
        || request_cleanup != checkpoint_cleanup
        || request_cleanup.inventory_session != marker.request.session
        || !supported_problem
    {
        return Err(invalid_release_rejection(
            path,
            "marker does not bind the exact checkpointed release rejection",
        ));
    }
    Ok(())
}

fn read_definite_release_rejection_file(
    file: &File,
    path: &Path,
    checkpoint: &RuntimeCheckpoint,
    allowed_link_counts: &[u64],
) -> Result<(DefiniteReleaseRejection, FileIdentity, u64), CheckpointStoreError> {
    let before_metadata = file
        .metadata()
        .map_err(|source| io_error("inspect definite release rejection marker", path, source))?;
    let before = FileIdentity::from_metadata(&before_metadata);
    let link_count = before_metadata.nlink();
    if !before_metadata.file_type().is_file() || !allowed_link_counts.contains(&link_count) {
        return Err(CheckpointStoreError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "release rejection is not a regular file with the expected link count",
        });
    }
    let mut bytes = Vec::new();
    let cap = u64::try_from(RELEASE_REJECTION_MAX_BYTES)
        .expect("release rejection byte cap fits u64")
        .saturating_add(1);
    file.take(cap)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read definite release rejection marker", path, source))?;
    let after_metadata = file
        .metadata()
        .map_err(|source| io_error("reinspect definite release rejection marker", path, source))?;
    if before != FileIdentity::from_metadata(&after_metadata)
        || link_count != after_metadata.nlink()
    {
        return Err(CheckpointStoreError::ConcurrentUpdate {
            path: path.to_path_buf(),
        });
    }
    let marker = decode_definite_release_rejection(&bytes, path)?;
    validate_definite_release_rejection(&marker, checkpoint, path)?;
    Ok((marker, before, link_count))
}

fn encode_definite_release_rejection(
    marker: &DefiniteReleaseRejection,
    checkpoint: &RuntimeCheckpoint,
    path: &Path,
) -> Result<Vec<u8>, CheckpointStoreError> {
    validate_definite_release_rejection(marker, checkpoint, path)?;
    let bytes = serde_json::to_vec(marker).map_err(|source| {
        invalid_release_rejection(path, format!("canonical JSON encode failed: {source}"))
    })?;
    if bytes.len() > RELEASE_REJECTION_MAX_BYTES {
        return Err(invalid_release_rejection(
            path,
            "marker exceeds its byte cap",
        ));
    }
    Ok(bytes)
}

fn invalid_release_rejection(path: &Path, reason: impl Into<String>) -> CheckpointStoreError {
    CheckpointStoreError::InvalidReleaseRejection {
        path: path.to_path_buf(),
        reason: reason.into(),
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

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EndpointEffectEdgeStatus {
    Exact,
    Missing,
    Mismatch,
}

pub(super) enum EndpointEffectTransitionPreparation<'a> {
    Ready(EndpointEffectTransition<'a>),
    Missing,
    Mismatch,
}

/// A prevalidated, process-local Endpoint effect transition. The mutex guard
/// stays held across the short AdmissionCell effect and final checkpoint
/// publication, so no second in-process planner can invalidate the edge set
/// between validation and confirmation.
pub(super) struct EndpointEffectTransition<'a> {
    edges: MutexGuard<'a, Vec<EndpointEffectEdge>>,
    current_index: Option<usize>,
    next: Option<Box<EndpointEffectEdge>>,
    next_already_present: bool,
    confirmed: bool,
    retain_next: bool,
}

impl EndpointEffectTransition<'_> {
    /// Called only after the complete live AdmissionSnapshot equals the
    /// precomputed replacement. This is infallible because every edge and
    /// capacity check happened while the same mutex guard was held.
    pub(super) fn confirm(&mut self) {
        if self.confirmed {
            return;
        }
        if let Some(index) = self.current_index {
            self.edges.remove(index);
        }
        if !self.next_already_present {
            if let Some(next) = &self.next {
                self.edges.push((**next).clone());
            }
        }
        self.confirmed = true;
    }

    /// Retains the next edge after the exact matching checkpoint has crossed
    /// the directory durability barrier. The consumed current edge is never
    /// restored, regardless of this flag.
    pub(super) fn checkpoint_is_durable(&mut self) {
        debug_assert!(self.confirmed);
        self.retain_next = true;
    }
}

impl Drop for EndpointEffectTransition<'_> {
    fn drop(&mut self) {
        if !self.confirmed || self.retain_next {
            return;
        }
        if let Some(next) = &self.next {
            self.edges.retain(|present| present != next.as_ref());
        }
    }
}

pub(super) struct EndpointEffectRevocation<'a> {
    edges: MutexGuard<'a, Vec<EndpointEffectEdge>>,
}

impl EndpointEffectRevocation<'_> {
    pub(super) fn confirm(mut self) {
        self.edges.clear();
    }
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

fn link_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both directory descriptors and NUL-terminated names remain
        // live for the call. `linkat` retains neither pointer and does not
        // replace an existing destination name.
        let result = unsafe {
            libc::linkat(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
                0,
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
