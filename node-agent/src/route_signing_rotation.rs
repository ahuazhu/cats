//! Durable Node installation of one exact Route Grant v2 public-ring successor.
//!
//! The deployment transport is deliberately outside this module. Its only
//! production entry accepts canonical public bytes, opens the frozen path from
//! filesystem root without following links, and ACKs by changing the same
//! in-process verifier consumed by the inventory scanner.

use std::ffi::{CStr, CString, OsStr};
use std::fs::{File, Metadata};
use std::io::{self, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{FileExt as _, MetadataExt as _};
use std::path::{Path, PathBuf};
#[cfg(test)]
use std::sync::atomic::AtomicBool;
use std::sync::atomic::{AtomicU8, Ordering};
#[cfg(test)]
use std::sync::Condvar;
use std::sync::{Arc, Mutex};

use cats_api::route_grant_v2::{
    decode_route_grant_v2_public_key_ring, RouteGrantV2PublicKeyRingArtifact,
    ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES, ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH,
};
use thiserror::Error;

use crate::route_grant_v2::{
    RouteGrantV2KeyRing, RouteGrantV2RingInstallError, RouteGrantV2Verifier,
};

const ROUTE_DIRECTORY_COMPONENTS: &[&str] = &["etc", "cats", "route-v2"];
const RING_BASENAME: &str = "public-key-ring.v1.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteGrantV2DurableInstallOutcome {
    Installed,
    RecoveredAfterDurableRename,
    Replay,
}

#[derive(Debug, Error)]
pub enum RouteGrantV2DurableInstallError {
    #[error("Route Grant v2 ring candidate is not exact canonical wire")]
    InvalidCandidate,
    #[error("Route Grant v2 installed ring is unavailable or unsafe")]
    InstalledRingUnavailable,
    #[error("Route Grant v2 ring candidate is stale")]
    Stale,
    #[error("Route Grant v2 ring candidate conflicts with the current version")]
    Conflict,
    #[error("Route Grant v2 ring candidate does not name the exact current predecessor")]
    WrongPrevious,
    #[error("Route Grant v2 durable ring and in-process verifier diverged")]
    VerifierDiverged,
    #[error("Route Grant v2 ring installation was cancelled before publication")]
    Cancelled,
    #[error("Route Grant v2 fixed-path filesystem contract failed")]
    Filesystem,
    #[cfg(test)]
    #[error("injected crash after durable rename")]
    InjectedCrashAfterRename,
}

/// Cancellation can stop work only before the durable rename. Once rename
/// linearizes the new artifact, the installer must finish the verifier swap
/// (or be recovered by the exact disk-ahead branch after process restart).
#[derive(Debug, Clone, Default)]
pub struct RouteGrantV2RingInstallContext {
    publication: Arc<AtomicU8>,
}

impl RouteGrantV2RingInstallContext {
    pub fn cancel(&self) {
        let _ = self.publication.compare_exchange(
            PUBLICATION_ACTIVE,
            PUBLICATION_CANCELLED,
            Ordering::AcqRel,
            Ordering::Acquire,
        );
    }

    fn check_active(&self) -> Result<(), RouteGrantV2DurableInstallError> {
        if self.publication.load(Ordering::Acquire) == PUBLICATION_ACTIVE {
            Ok(())
        } else {
            Err(RouteGrantV2DurableInstallError::Cancelled)
        }
    }

    fn begin_publication(&self) -> Result<(), RouteGrantV2DurableInstallError> {
        self.publication
            .compare_exchange(
                PUBLICATION_ACTIVE,
                PUBLICATION_OWNED,
                Ordering::AcqRel,
                Ordering::Acquire,
            )
            .map(|_| ())
            .map_err(|_| RouteGrantV2DurableInstallError::Cancelled)
    }
}

const PUBLICATION_ACTIVE: u8 = 0;
const PUBLICATION_CANCELLED: u8 = 1;
const PUBLICATION_OWNED: u8 = 2;

pub struct RouteGrantV2RingInstaller {
    verifier: Arc<RouteGrantV2Verifier>,
    filesystem: RingFilesystem,
    serialized: Arc<Mutex<()>>,
    emergency_close: Arc<dyn Fn() + Send + Sync>,
    #[cfg(test)]
    crash_after_rename: AtomicBool,
    #[cfg(test)]
    post_ownership_filesystem_failure: AtomicBool,
    #[cfg(test)]
    pre_publication_gate: Mutex<Option<Arc<PrePublicationGate>>>,
    #[cfg(test)]
    post_rename_gate: Mutex<Option<Arc<PrePublicationGate>>>,
}

impl std::fmt::Debug for RouteGrantV2RingInstaller {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RouteGrantV2RingInstaller")
            .field("path", &ROUTE_GRANT_V2_PUBLIC_KEY_RING_PATH)
            .field("verifier", &self.verifier)
            .finish()
    }
}

impl RouteGrantV2RingInstaller {
    pub(crate) fn for_production(
        verifier: Arc<RouteGrantV2Verifier>,
        serialized: Arc<Mutex<()>>,
        emergency_close: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self {
            verifier,
            filesystem: RingFilesystem::production(),
            serialized,
            emergency_close,
            #[cfg(test)]
            crash_after_rename: AtomicBool::new(false),
            #[cfg(test)]
            post_ownership_filesystem_failure: AtomicBool::new(false),
            #[cfg(test)]
            pre_publication_gate: Mutex::new(None),
            #[cfg(test)]
            post_rename_gate: Mutex::new(None),
        }
    }

    pub fn install(
        &self,
        candidate_bytes: &[u8],
        context: &RouteGrantV2RingInstallContext,
    ) -> Result<RouteGrantV2DurableInstallOutcome, RouteGrantV2DurableInstallError> {
        let candidate = decode_route_grant_v2_public_key_ring(candidate_bytes)
            .map_err(|_| RouteGrantV2DurableInstallError::InvalidCandidate)?;
        let candidate_ring = RouteGrantV2KeyRing::from_artifact(&candidate)
            .map_err(|_| RouteGrantV2DurableInstallError::InvalidCandidate)?;
        let _serialized = self
            .serialized
            .lock()
            .map_err(|_| RouteGrantV2DurableInstallError::VerifierDiverged)?;
        context.check_active()?;

        let mut opened = self.filesystem.open()?;
        let _directory_lock = opened.lock_final_directory()?;
        context.check_active()?;
        let current_file = opened.read_current()?;
        let current = decode_route_grant_v2_public_key_ring(&current_file.exact_bytes)
            .map_err(|_| RouteGrantV2DurableInstallError::InstalledRingUnavailable)?;
        let current_ring = RouteGrantV2KeyRing::from_artifact(&current)
            .map_err(|_| RouteGrantV2DurableInstallError::InstalledRingUnavailable)?;
        let verifier = self
            .verifier
            .current_ring()
            .map_err(|_| RouteGrantV2DurableInstallError::VerifierDiverged)?;

        if current_file.exact_bytes == candidate_bytes {
            if same_ring(&verifier, &candidate_ring) {
                context.begin_publication()?;
                self.fail_close_if_empty(&candidate);
                opened.revalidate_current(&current_file, false)?;
                return Ok(RouteGrantV2DurableInstallOutcome::Replay);
            }
            if !same_ring(&verifier, &current_ring) && exact_predecessor(&candidate, &verifier) {
                context.begin_publication()?;
                self.fail_close_if_empty(&candidate);
                opened.revalidate_current(&current_file, false)?;
                self.verifier
                    .replace_artifact(&candidate)
                    .map_err(map_verifier_error)?;
                return Ok(RouteGrantV2DurableInstallOutcome::RecoveredAfterDurableRename);
            }
            return Err(RouteGrantV2DurableInstallError::VerifierDiverged);
        }

        if candidate.ring_version < current.ring_version {
            return Err(RouteGrantV2DurableInstallError::Stale);
        }
        if candidate.ring_version == current.ring_version {
            return Err(RouteGrantV2DurableInstallError::Conflict);
        }
        if !exact_predecessor(&candidate, &current_ring) {
            return Err(RouteGrantV2DurableInstallError::WrongPrevious);
        }
        if !same_ring(&verifier, &current_ring) {
            return Err(RouteGrantV2DurableInstallError::VerifierDiverged);
        }

        context.check_active()?;
        #[cfg(test)]
        self.wait_at_pre_publication_gate();
        opened.publish(
            &current_file,
            &candidate,
            candidate_bytes,
            context,
            || {
                self.fail_close_if_empty(&candidate);
                #[cfg(test)]
                if self
                    .post_ownership_filesystem_failure
                    .swap(false, Ordering::AcqRel)
                {
                    return Err(RouteGrantV2DurableInstallError::Filesystem);
                }
                Ok(())
            },
            || {
                #[cfg(test)]
                self.wait_at_post_rename_gate();
            },
        )?;
        #[cfg(test)]
        if self.crash_after_rename.swap(false, Ordering::AcqRel) {
            return Err(RouteGrantV2DurableInstallError::InjectedCrashAfterRename);
        }
        self.verifier
            .replace_artifact(&candidate)
            .map_err(map_verifier_error)?;
        Ok(RouteGrantV2DurableInstallOutcome::Installed)
    }

    /// Empty rings are the accepted emergency-disable verifier artifact. The
    /// installer cannot ACK one until every process-local Route gate has been
    /// fail-closed; active guards then drain through their existing
    /// cancellation edge and are proven by the next full inventory.
    fn fail_close_if_empty(&self, candidate: &RouteGrantV2PublicKeyRingArtifact) {
        if candidate.keys.is_empty() {
            (self.emergency_close)();
        }
    }

    #[cfg(test)]
    fn for_test(root: &Path, verifier: Arc<RouteGrantV2Verifier>) -> Self {
        Self::for_test_with_parts(root, verifier, Arc::new(Mutex::new(())), Arc::new(|| {}))
    }

    #[cfg(test)]
    fn for_test_with_emergency_close(
        root: &Path,
        verifier: Arc<RouteGrantV2Verifier>,
        emergency_close: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        Self::for_test_with_parts(root, verifier, Arc::new(Mutex::new(())), emergency_close)
    }

    #[cfg(test)]
    fn for_test_with_parts(
        root: &Path,
        verifier: Arc<RouteGrantV2Verifier>,
        serialized: Arc<Mutex<()>>,
        emergency_close: Arc<dyn Fn() + Send + Sync>,
    ) -> Self {
        // SAFETY: geteuid/getegid have no pointer arguments or failure mode.
        let (uid, gid) = unsafe { (libc::geteuid(), libc::getegid()) };
        Self {
            verifier,
            filesystem: RingFilesystem {
                canonical_root: root.to_path_buf(),
                components: vec!["route-v2".to_owned()],
                owner: Owner { uid, gid },
            },
            serialized,
            emergency_close,
            crash_after_rename: AtomicBool::new(false),
            post_ownership_filesystem_failure: AtomicBool::new(false),
            pre_publication_gate: Mutex::new(None),
            post_rename_gate: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn inject_crash_after_rename_once(&self) {
        self.crash_after_rename.store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn inject_post_ownership_filesystem_failure_once(&self) {
        self.post_ownership_filesystem_failure
            .store(true, Ordering::Release);
    }

    #[cfg(test)]
    fn set_pre_publication_gate(&self, gate: Arc<PrePublicationGate>) {
        *self.pre_publication_gate.lock().unwrap() = Some(gate);
    }

    #[cfg(test)]
    fn set_post_rename_gate(&self, gate: Arc<PrePublicationGate>) {
        *self.post_rename_gate.lock().unwrap() = Some(gate);
    }

    #[cfg(test)]
    fn wait_at_pre_publication_gate(&self) {
        let gate = self.pre_publication_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.wait();
        }
    }

    #[cfg(test)]
    fn wait_at_post_rename_gate(&self) {
        let gate = self.post_rename_gate.lock().unwrap().clone();
        if let Some(gate) = gate {
            gate.wait();
        }
    }

    #[cfg(test)]
    pub(crate) fn shares_process_lock_with(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.serialized, &other.serialized)
    }
}

fn same_ring(left: &RouteGrantV2KeyRing, right: &RouteGrantV2KeyRing) -> bool {
    left.version() == right.version()
        && left.digest() == right.digest()
        && left.loaded_kids() == right.loaded_kids()
}

fn exact_predecessor(
    candidate: &RouteGrantV2PublicKeyRingArtifact,
    current: &RouteGrantV2KeyRing,
) -> bool {
    candidate
        .expected_previous
        .as_ref()
        .is_some_and(|previous| {
            current.version().get().checked_add(1) == Some(candidate.ring_version.get())
                && previous.ring_version == current.version()
                && &previous.key_ring_digest == current.digest()
        })
}

fn map_verifier_error(error: RouteGrantV2RingInstallError) -> RouteGrantV2DurableInstallError {
    match error {
        RouteGrantV2RingInstallError::StaleVersion => RouteGrantV2DurableInstallError::Stale,
        RouteGrantV2RingInstallError::VersionConflict => RouteGrantV2DurableInstallError::Conflict,
        RouteGrantV2RingInstallError::LineageMismatch => {
            RouteGrantV2DurableInstallError::WrongPrevious
        }
        RouteGrantV2RingInstallError::Unavailable => {
            RouteGrantV2DurableInstallError::VerifierDiverged
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Owner {
    uid: u32,
    gid: u32,
}

struct RingFilesystem {
    canonical_root: PathBuf,
    components: Vec<String>,
    owner: Owner,
}

impl RingFilesystem {
    fn production() -> Self {
        Self {
            canonical_root: PathBuf::from("/"),
            components: ROUTE_DIRECTORY_COMPONENTS
                .iter()
                .map(|component| (*component).to_owned())
                .collect(),
            owner: Owner { uid: 0, gid: 0 },
        }
    }

    fn open(&self) -> Result<OpenedRingDirectory, RouteGrantV2DurableInstallError> {
        let mut retained = Vec::with_capacity(self.components.len() + 1);
        let root = open_directory_path(&self.canonical_root)?;
        let root_metadata = StableMetadata::from_metadata(&root.metadata().map_err(fs_error)?);
        if !root_metadata.safe_directory(self.owner, false) {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        retained.push(RetainedDirectory {
            name: None,
            metadata: root_metadata,
            descriptor: root,
        });
        for (index, component) in self.components.iter().enumerate() {
            let parent = &retained
                .last()
                .expect("the retained path always contains its root")
                .descriptor;
            let descriptor = open_directory_at(parent, component)?;
            let metadata = StableMetadata::from_metadata(&descriptor.metadata().map_err(fs_error)?);
            let final_directory = index + 1 == self.components.len();
            if !metadata.safe_directory(self.owner, final_directory) {
                return Err(RouteGrantV2DurableInstallError::Filesystem);
            }
            retained.push(RetainedDirectory {
                name: Some(component.clone()),
                metadata,
                descriptor,
            });
        }
        Ok(OpenedRingDirectory {
            canonical_root: self.canonical_root.clone(),
            retained,
            owner: self.owner,
        })
    }
}

struct RetainedDirectory {
    name: Option<String>,
    metadata: StableMetadata,
    descriptor: File,
}

struct OpenedRingDirectory {
    canonical_root: PathBuf,
    retained: Vec<RetainedDirectory>,
    owner: Owner,
}

impl OpenedRingDirectory {
    fn parent_descriptor(&self) -> &File {
        &self.retained[self.retained.len() - 2].descriptor
    }

    fn final_descriptor(&self) -> &File {
        &self
            .retained
            .last()
            .expect("the retained path always contains its root")
            .descriptor
    }

    fn lock_final_directory(&mut self) -> Result<DirectoryFlock, RouteGrantV2DurableInstallError> {
        let lock = DirectoryFlock::lock_exclusive(self.final_descriptor())?;
        for index in [self.retained.len() - 2, self.retained.len() - 1] {
            let refreshed = StableMetadata::from_metadata(
                &self.retained[index]
                    .descriptor
                    .metadata()
                    .map_err(fs_error)?,
            );
            let final_directory = index + 1 == self.retained.len();
            if !refreshed.safe_directory(self.owner, final_directory)
                || !refreshed.same_directory_identity(self.retained[index].metadata)
            {
                return Err(RouteGrantV2DurableInstallError::Filesystem);
            }
            self.retained[index].metadata = refreshed;
        }
        Ok(lock)
    }

    fn reopen(
        &self,
        parent_directory_mutated: bool,
        final_directory_mutated: bool,
    ) -> Result<ReopenedRingPath, RouteGrantV2DurableInstallError> {
        let mut fresh = Vec::with_capacity(self.retained.len());
        fresh.push(open_directory_path(&self.canonical_root)?);
        for (index, retained) in self.retained.iter().enumerate() {
            if index > 0 {
                let current = open_directory_at(
                    fresh
                        .last()
                        .expect("the reopened path always contains its root"),
                    retained
                        .name
                        .as_deref()
                        .expect("only the root has no basename"),
                )?;
                fresh.push(current);
            }
            let retained_metadata =
                StableMetadata::from_metadata(&retained.descriptor.metadata().map_err(fs_error)?);
            let fresh_metadata =
                StableMetadata::from_metadata(&fresh[index].metadata().map_err(fs_error)?);
            let final_directory = index + 1 == self.retained.len();
            let parent_directory = index + 2 == self.retained.len();
            let expected_metadata_may_change = (parent_directory && parent_directory_mutated)
                || (final_directory && final_directory_mutated);
            if retained_metadata != fresh_metadata
                || !fresh_metadata.same_directory_identity(retained.metadata)
                || !fresh_metadata.safe_directory(self.owner, final_directory)
                || (!expected_metadata_may_change && fresh_metadata != retained.metadata)
            {
                return Err(RouteGrantV2DurableInstallError::Filesystem);
            }
        }
        Ok(ReopenedRingPath { retained: fresh })
    }

    fn read_current(&self) -> Result<PinnedRingFile, RouteGrantV2DurableInstallError> {
        let descriptor = open_file_at(self.final_descriptor(), RING_BASENAME, libc::O_RDONLY)?;
        let (metadata, exact_bytes) = read_stable_ring(&descriptor, self.owner)?;
        let fresh = self.reopen(false, false)?;
        let fresh_descriptor =
            open_file_at(fresh.final_descriptor(), RING_BASENAME, libc::O_RDONLY)?;
        let (fresh_metadata, fresh_bytes) = read_stable_ring(&fresh_descriptor, self.owner)?;
        if fresh_metadata != metadata || fresh_bytes != exact_bytes {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        Ok(PinnedRingFile {
            descriptor,
            metadata,
            exact_bytes,
        })
    }

    fn publish<F, G>(
        &self,
        current: &PinnedRingFile,
        candidate: &RouteGrantV2PublicKeyRingArtifact,
        candidate_bytes: &[u8],
        context: &RouteGrantV2RingInstallContext,
        after_publication_owned: F,
        after_durable_rename: G,
    ) -> Result<(), RouteGrantV2DurableInstallError>
    where
        F: FnOnce() -> Result<(), RouteGrantV2DurableInstallError>,
        G: FnOnce(),
    {
        context.check_active()?;
        self.revalidate_current(current, false)?;
        let parent_metadata =
            StableMetadata::from_metadata(&self.parent_descriptor().metadata().map_err(fs_error)?);
        let final_metadata =
            StableMetadata::from_metadata(&self.final_descriptor().metadata().map_err(fs_error)?);
        if parent_metadata.device != final_metadata.device {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        let temp_basename = format!(
            ".route-v2.public-key-ring.v1.{}.{}.tmp",
            candidate.ring_version.get(),
            candidate
                .digest()
                .map_err(|_| RouteGrantV2DurableInstallError::InvalidCandidate)?
                .as_str()
                .strip_prefix("sha256:")
                .ok_or(RouteGrantV2DurableInstallError::InvalidCandidate)?
        );
        let temp_name = c_string(&temp_basename)?;
        let mut temporary = match open_file_at(
            self.parent_descriptor(),
            &temp_basename,
            libc::O_RDWR | libc::O_CREAT | libc::O_EXCL,
        ) {
            Ok(file) => {
                // SAFETY: `file` owns a live descriptor; fchmod neither
                // retains the descriptor nor dereferences Rust memory.
                if unsafe { libc::fchmod(file.as_raw_fd(), 0o644) } != 0 {
                    return Err(RouteGrantV2DurableInstallError::Filesystem);
                }
                file
            }
            Err(RouteGrantV2DurableInstallError::Filesystem) => {
                open_file_at(self.parent_descriptor(), &temp_basename, libc::O_RDWR)?
            }
            Err(error) => return Err(error),
        };
        let metadata = StableMetadata::from_metadata(&temporary.metadata().map_err(fs_error)?);
        if !metadata.safe_ring(self.owner) {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        let (_, existing) = read_stable_ring(&temporary, self.owner)?;
        if existing != candidate_bytes {
            // A crash while writing this candidate can leave its deterministic
            // temporary file empty or partial. It is safe to repair only this
            // exact, validated candidate basename after proving the inode is a
            // single-link regular file owned by the installer.
            context.check_active()?;
            temporary.set_len(0).map_err(fs_error)?;
            temporary.write_all(candidate_bytes).map_err(fs_error)?;
        }
        temporary.sync_all().map_err(fs_error)?;
        let (stable_temp_metadata, stable_temp) = read_stable_ring(&temporary, self.owner)?;
        if stable_temp != candidate_bytes {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        context.check_active()?;
        let fresh = self.revalidate_current(current, true)?;
        let ring_name = c_string(RING_BASENAME)?;
        // This CAS is the cancellation/publication linearization point. A
        // cancellation that wins leaves the current artifact untouched; once
        // publication wins, cancellation cannot interrupt rename, directory
        // fsync, verification, or the caller-visible ACK.
        context.begin_publication()?;
        after_publication_owned()?;
        rename_at(
            fresh.parent_descriptor(),
            &temp_name,
            fresh.final_descriptor(),
            &ring_name,
        )?;
        fresh.final_descriptor().sync_all().map_err(fs_error)?;
        fresh.parent_descriptor().sync_all().map_err(fs_error)?;
        after_durable_rename();
        // Publication through retained descriptors is not enough: another
        // privileged installer can rename-recreate the fixed directory after
        // the last pre-publication validation. Reopen the canonical path and
        // prove both its retained directory identity and the exact renamed
        // file before the in-process verifier may swap or ACK.
        let canonical = self.reopen(true, true)?;
        let published = open_file_at(canonical.final_descriptor(), RING_BASENAME, libc::O_RDONLY)?;
        let (published_metadata, published_bytes) = read_stable_ring(&published, self.owner)?;
        if !published_metadata.same_file_identity(stable_temp_metadata)
            || published_bytes != candidate_bytes
        {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        Ok(())
    }

    fn revalidate_current(
        &self,
        current: &PinnedRingFile,
        parent_directory_mutated: bool,
    ) -> Result<ReopenedRingPath, RouteGrantV2DurableInstallError> {
        let (retained_metadata, retained_bytes) =
            read_stable_ring(&current.descriptor, self.owner)?;
        let fresh = self.reopen(parent_directory_mutated, false)?;
        let descriptor = open_file_at(fresh.final_descriptor(), RING_BASENAME, libc::O_RDONLY)?;
        let (fresh_metadata, fresh_bytes) = read_stable_ring(&descriptor, self.owner)?;
        if retained_metadata != current.metadata
            || fresh_metadata != current.metadata
            || retained_bytes != current.exact_bytes
            || fresh_bytes != current.exact_bytes
        {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        Ok(fresh)
    }
}

struct ReopenedRingPath {
    retained: Vec<File>,
}

impl ReopenedRingPath {
    fn parent_descriptor(&self) -> &File {
        &self.retained[self.retained.len() - 2]
    }

    fn final_descriptor(&self) -> &File {
        self.retained
            .last()
            .expect("the reopened path always contains its root")
    }
}

struct PinnedRingFile {
    descriptor: File,
    metadata: StableMetadata,
    exact_bytes: Vec<u8>,
}

struct DirectoryFlock {
    descriptor: i32,
}

impl DirectoryFlock {
    fn lock_exclusive(descriptor: &File) -> Result<Self, RouteGrantV2DurableInstallError> {
        loop {
            // SAFETY: flock operates only on the live directory descriptor.
            let result = unsafe { libc::flock(descriptor.as_raw_fd(), libc::LOCK_EX) };
            if result == 0 {
                return Ok(Self {
                    descriptor: descriptor.as_raw_fd(),
                });
            }
            let error = io::Error::last_os_error();
            if error.kind() != io::ErrorKind::Interrupted {
                return Err(RouteGrantV2DurableInstallError::Filesystem);
            }
        }
    }
}

impl Drop for DirectoryFlock {
    fn drop(&mut self) {
        // SAFETY: best-effort unlock of the live descriptor; install already
        // completed or failed closed if this point is reached.
        let _ = unsafe { libc::flock(self.descriptor, libc::LOCK_UN) };
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StableMetadata {
    device: u64,
    inode: u64,
    uid: u32,
    gid: u32,
    mode: u32,
    links: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanos: i64,
    changed_seconds: i64,
    changed_nanos: i64,
    is_file: bool,
    is_directory: bool,
}

impl StableMetadata {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            len: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanos: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanos: metadata.ctime_nsec(),
            is_file: metadata.is_file(),
            is_directory: metadata.is_dir(),
        }
    }

    fn safe_directory(self, owner: Owner, final_directory: bool) -> bool {
        self.is_directory
            && self.uid == owner.uid
            && self.gid == owner.gid
            && if final_directory {
                self.mode & 0o7777 == 0o700
            } else {
                self.mode & 0o022 == 0
            }
    }

    fn safe_ring(self, owner: Owner) -> bool {
        self.is_file
            && self.links == 1
            && self.uid == owner.uid
            && self.gid == owner.gid
            && self.mode & 0o7777 == 0o644
            && self.len <= ROUTE_GRANT_V2_ARTIFACT_MAX_WIRE_BYTES as u64
    }

    fn same_directory_identity(self, expected: Self) -> bool {
        self.device == expected.device
            && self.inode == expected.inode
            && self.uid == expected.uid
            && self.gid == expected.gid
            && self.mode == expected.mode
            && self.is_directory
            && expected.is_directory
    }

    fn same_file_identity(self, expected: Self) -> bool {
        self.device == expected.device
            && self.inode == expected.inode
            && self.uid == expected.uid
            && self.gid == expected.gid
            && self.mode == expected.mode
            && self.links == expected.links
            && self.is_file
            && expected.is_file
    }
}

fn read_stable_ring(
    descriptor: &File,
    owner: Owner,
) -> Result<(StableMetadata, Vec<u8>), RouteGrantV2DurableInstallError> {
    let before = StableMetadata::from_metadata(&descriptor.metadata().map_err(fs_error)?);
    if !before.safe_ring(owner) {
        return Err(RouteGrantV2DurableInstallError::Filesystem);
    }
    let mut bytes = vec![0_u8; before.len as usize];
    let mut offset = 0_usize;
    while offset < bytes.len() {
        let count = descriptor
            .read_at(&mut bytes[offset..], offset as u64)
            .map_err(fs_error)?;
        if count == 0 {
            return Err(RouteGrantV2DurableInstallError::Filesystem);
        }
        offset = offset
            .checked_add(count)
            .ok_or(RouteGrantV2DurableInstallError::Filesystem)?;
    }
    let mut extra = [0_u8; 1];
    if descriptor
        .read_at(&mut extra, offset as u64)
        .map_err(fs_error)?
        != 0
    {
        return Err(RouteGrantV2DurableInstallError::Filesystem);
    }
    let after = StableMetadata::from_metadata(&descriptor.metadata().map_err(fs_error)?);
    if before != after {
        return Err(RouteGrantV2DurableInstallError::Filesystem);
    }
    Ok((after, bytes))
}

fn open_directory_path(path: &Path) -> Result<File, RouteGrantV2DurableInstallError> {
    let path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| RouteGrantV2DurableInstallError::Filesystem)?;
    // SAFETY: path is NUL-terminated and a successful descriptor is moved
    // exactly once into File.
    let descriptor = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_descriptor(descriptor)
}

fn open_directory_at(parent: &File, name: &str) -> Result<File, RouteGrantV2DurableInstallError> {
    let name = c_string(name)?;
    // SAFETY: parent and name remain live; a successful descriptor is moved
    // exactly once into File.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    owned_descriptor(descriptor)
}

fn open_file_at(
    directory: &File,
    name: &str,
    flags: i32,
) -> Result<File, RouteGrantV2DurableInstallError> {
    let name = c_string(name)?;
    // SAFETY: directory and name remain live; O_NOFOLLOW rejects final-entry
    // symlinks and a successful descriptor is moved exactly once into File.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o644,
        )
    };
    owned_descriptor(descriptor)
}

fn owned_descriptor(descriptor: i32) -> Result<File, RouteGrantV2DurableInstallError> {
    if descriptor < 0 {
        Err(RouteGrantV2DurableInstallError::Filesystem)
    } else {
        // SAFETY: the descriptor was just returned to this call and has not
        // been transferred elsewhere.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> Result<(), RouteGrantV2DurableInstallError> {
    // SAFETY: both descriptors and names remain live for the call.
    let result = unsafe {
        libc::renameat(
            old_directory.as_raw_fd(),
            old_name.as_ptr(),
            new_directory.as_raw_fd(),
            new_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(RouteGrantV2DurableInstallError::Filesystem)
    }
}

fn c_string(value: &str) -> Result<CString, RouteGrantV2DurableInstallError> {
    CString::new(OsStr::new(value).as_bytes())
        .map_err(|_| RouteGrantV2DurableInstallError::Filesystem)
}

fn fs_error(_error: io::Error) -> RouteGrantV2DurableInstallError {
    RouteGrantV2DurableInstallError::Filesystem
}

#[cfg(test)]
#[derive(Default)]
struct PrePublicationGate {
    state: Mutex<PrePublicationGateState>,
    changed: Condvar,
}

#[cfg(test)]
#[derive(Default)]
struct PrePublicationGateState {
    reached: bool,
    released: bool,
}

#[cfg(test)]
impl PrePublicationGate {
    fn wait(&self) {
        let mut state = self.state.lock().unwrap();
        state.reached = true;
        self.changed.notify_all();
        while !state.released {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn wait_until_reached(&self) {
        let mut state = self.state.lock().unwrap();
        while !state.reached {
            state = self.changed.wait(state).unwrap();
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap();
        state.released = true;
        self.changed.notify_all();
    }
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::sync::atomic::AtomicUsize;

    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine as _;
    use cats_api::route_grant_v2::{
        encode_route_grant_v2_public_key_ring, RouteGrantV2PublicKey, RouteGrantV2PublicKeyEntry,
        RouteGrantV2PublicKeyRingExpectedPrevious,
    };
    use cats_api::runtime_reconciliation::{Base64UrlNoPad, ContractVersion, Epoch};
    use ring::rand::SystemRandom;
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    const SPKI_PREFIX: [u8; 12] = [
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];

    fn public_entry() -> RouteGrantV2PublicKeyEntry {
        let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new()).unwrap();
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut spki = SPKI_PREFIX.to_vec();
        spki.extend_from_slice(pair.public_key().as_ref());
        let key = RouteGrantV2PublicKey::from_spki_der(&spki).unwrap();
        RouteGrantV2PublicKeyEntry {
            kid: key.kid().clone(),
            public_key_spki: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(&spki)).unwrap(),
        }
    }

    fn distinct_public_entry(
        existing: &[RouteGrantV2PublicKeyEntry],
    ) -> RouteGrantV2PublicKeyEntry {
        loop {
            let candidate = public_entry();
            if existing.iter().all(|entry| entry.kid != candidate.kid) {
                return candidate;
            }
        }
    }

    fn rings() -> (
        RouteGrantV2PublicKeyRingArtifact,
        RouteGrantV2PublicKeyRingArtifact,
    ) {
        let old = public_entry();
        let mut keys = vec![old.clone(), public_entry()];
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        let first = RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(1).unwrap(),
            expected_previous: None,
            keys: vec![old],
        };
        let second = RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(2).unwrap(),
            expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
                ring_version: first.ring_version,
                key_ring_digest: first.digest().unwrap(),
            }),
            keys,
        };
        (first, second)
    }

    fn empty_successor(
        first: &RouteGrantV2PublicKeyRingArtifact,
    ) -> RouteGrantV2PublicKeyRingArtifact {
        RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(first.ring_version.get() + 1).unwrap(),
            expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
                ring_version: first.ring_version,
                key_ring_digest: first.digest().unwrap(),
            }),
            keys: Vec::new(),
        }
    }

    fn fixture(
        first: &RouteGrantV2PublicKeyRingArtifact,
    ) -> (tempfile::TempDir, Arc<RouteGrantV2Verifier>) {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = root.path().join("route-v2");
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.join(RING_BASENAME);
        std::fs::write(&path, encode_route_grant_v2_public_key_ring(first).unwrap()).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let verifier = Arc::new(RouteGrantV2Verifier::new(
            RouteGrantV2KeyRing::from_artifact(first).unwrap(),
        ));
        (root, verifier)
    }

    #[test]
    fn exact_successor_is_durable_before_swap_and_replays_without_write() {
        let (first, second) = rings();
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        let bytes = encode_route_grant_v2_public_key_ring(&second).unwrap();
        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Installed
        );
        let metadata_before =
            std::fs::metadata(root.path().join("route-v2").join(RING_BASENAME)).unwrap();
        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Replay
        );
        let metadata_after =
            std::fs::metadata(root.path().join("route-v2").join(RING_BASENAME)).unwrap();
        assert_eq!(metadata_before.ino(), metadata_after.ino());
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            second.ring_version
        );
    }

    #[test]
    fn crash_after_rename_recovers_only_the_exact_disk_ahead_successor() {
        let (first, second) = rings();
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        let bytes = encode_route_grant_v2_public_key_ring(&second).unwrap();
        installer.inject_crash_after_rename_once();
        assert!(matches!(
            installer.install(&bytes, &RouteGrantV2RingInstallContext::default()),
            Err(RouteGrantV2DurableInstallError::InjectedCrashAfterRename)
        ));
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );
        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::RecoveredAfterDurableRename
        );
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            second.ring_version
        );
    }

    #[test]
    fn empty_successor_closes_admission_before_ack_and_on_replay() {
        let (first, _) = rings();
        let empty = empty_successor(&first);
        let (root, verifier) = fixture(&first);
        let closes = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&closes);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&observed);
        let callback_verifier = Arc::clone(&verifier);
        let installer = RouteGrantV2RingInstaller::for_test_with_emergency_close(
            root.path(),
            Arc::clone(&verifier),
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                let current = callback_verifier.current_ring().unwrap();
                recorded
                    .lock()
                    .unwrap()
                    .push((current.version().get(), current.loaded_kids().is_empty()));
            }),
        );
        let bytes = encode_route_grant_v2_public_key_ring(&empty).unwrap();
        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Installed
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(*observed.lock().unwrap(), vec![(1, false)]);
        assert!(verifier.current_ring().unwrap().loaded_kids().is_empty());

        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Replay
        );
        assert_eq!(closes.load(Ordering::SeqCst), 2);
        assert_eq!(*observed.lock().unwrap(), vec![(1, false), (2, true)]);
    }

    #[test]
    fn post_ownership_filesystem_failure_closes_empty_successor_without_ack() {
        let (first, _) = rings();
        let empty = empty_successor(&first);
        let (root, verifier) = fixture(&first);
        let ring_path = root.path().join("route-v2").join(RING_BASENAME);
        let before = std::fs::read(&ring_path).unwrap();
        let closes = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&closes);
        let installer = RouteGrantV2RingInstaller::for_test_with_emergency_close(
            root.path(),
            Arc::clone(&verifier),
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
            }),
        );
        let context = RouteGrantV2RingInstallContext::default();
        installer.inject_post_ownership_filesystem_failure_once();

        assert!(matches!(
            installer.install(
                &encode_route_grant_v2_public_key_ring(&empty).unwrap(),
                &context,
            ),
            Err(RouteGrantV2DurableInstallError::Filesystem)
        ));
        assert_eq!(
            context.publication.load(Ordering::Acquire),
            PUBLICATION_OWNED
        );
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(ring_path).unwrap(), before);
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );
    }

    #[test]
    fn empty_successor_recovery_closes_before_verifier_swap() {
        let (first, _) = rings();
        let empty = empty_successor(&first);
        let (root, verifier) = fixture(&first);
        let closes = Arc::new(AtomicUsize::new(0));
        let counted = Arc::clone(&closes);
        let observed = Arc::new(Mutex::new(Vec::new()));
        let recorded = Arc::clone(&observed);
        let callback_verifier = Arc::clone(&verifier);
        let installer = RouteGrantV2RingInstaller::for_test_with_emergency_close(
            root.path(),
            Arc::clone(&verifier),
            Arc::new(move || {
                counted.fetch_add(1, Ordering::SeqCst);
                let current = callback_verifier.current_ring().unwrap();
                recorded
                    .lock()
                    .unwrap()
                    .push((current.version().get(), current.loaded_kids().is_empty()));
            }),
        );
        let bytes = encode_route_grant_v2_public_key_ring(&empty).unwrap();
        installer.inject_crash_after_rename_once();
        assert!(matches!(
            installer.install(&bytes, &RouteGrantV2RingInstallContext::default()),
            Err(RouteGrantV2DurableInstallError::InjectedCrashAfterRename)
        ));
        assert_eq!(closes.load(Ordering::SeqCst), 1);
        assert_eq!(*observed.lock().unwrap(), vec![(1, false)]);
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );

        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::RecoveredAfterDurableRename
        );
        assert_eq!(closes.load(Ordering::SeqCst), 2);
        assert_eq!(*observed.lock().unwrap(), vec![(1, false), (1, false)]);
        assert!(verifier.current_ring().unwrap().loaded_kids().is_empty());
    }

    #[test]
    fn stale_gap_conflict_and_cancel_leave_file_and_verifier_unchanged() {
        let (first, second) = rings();
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        let path = root.path().join("route-v2").join(RING_BASENAME);
        let before = std::fs::read(&path).unwrap();

        let mut conflict = first.clone();
        conflict.keys = second.keys.clone();
        assert!(matches!(
            installer.install(
                &encode_route_grant_v2_public_key_ring(&conflict).unwrap(),
                &RouteGrantV2RingInstallContext::default()
            ),
            Err(RouteGrantV2DurableInstallError::Conflict)
        ));

        let mut gap = second.clone();
        gap.ring_version = Epoch::new(3).unwrap();
        gap.expected_previous = Some(RouteGrantV2PublicKeyRingExpectedPrevious {
            ring_version: Epoch::new(2).unwrap(),
            key_ring_digest: second.digest().unwrap(),
        });
        assert!(matches!(
            installer.install(
                &encode_route_grant_v2_public_key_ring(&gap).unwrap(),
                &RouteGrantV2RingInstallContext::default()
            ),
            Err(RouteGrantV2DurableInstallError::WrongPrevious)
        ));

        let cancelled = RouteGrantV2RingInstallContext::default();
        cancelled.cancel();
        assert!(matches!(
            installer.install(
                &encode_route_grant_v2_public_key_ring(&second).unwrap(),
                &cancelled
            ),
            Err(RouteGrantV2DurableInstallError::Cancelled)
        ));
        assert_eq!(std::fs::read(path).unwrap(), before);
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );
    }

    #[test]
    fn unsafe_current_or_temporary_file_fails_closed() {
        let (first, second) = rings();
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), verifier);
        let path = root.path().join("route-v2").join(RING_BASENAME);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        assert!(matches!(
            installer.install(
                &encode_route_grant_v2_public_key_ring(&second).unwrap(),
                &RouteGrantV2RingInstallContext::default()
            ),
            Err(RouteGrantV2DurableInstallError::InstalledRingUnavailable)
                | Err(RouteGrantV2DurableInstallError::Filesystem)
        ));
    }

    #[test]
    fn crash_partial_temporary_file_is_repaired_but_unsafe_temp_is_rejected() {
        let (first, second) = rings();
        let bytes = encode_route_grant_v2_public_key_ring(&second).unwrap();
        let temp_basename = format!(
            ".route-v2.public-key-ring.v1.{}.{}.tmp",
            second.ring_version.get(),
            second
                .digest()
                .unwrap()
                .as_str()
                .strip_prefix("sha256:")
                .unwrap()
        );

        let (root, verifier) = fixture(&first);
        let temp = root.path().join(&temp_basename);
        std::fs::write(&temp, &bytes[..bytes.len() / 2]).unwrap();
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o644)).unwrap();
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        assert_eq!(
            installer
                .install(&bytes, &RouteGrantV2RingInstallContext::default())
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Installed
        );
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            second.ring_version
        );
        assert!(!temp.exists());

        let (root, verifier) = fixture(&first);
        let temp = root.path().join(&temp_basename);
        std::fs::write(&temp, &bytes[..bytes.len() / 2]).unwrap();
        std::fs::set_permissions(&temp, std::fs::Permissions::from_mode(0o666)).unwrap();
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        assert!(installer
            .install(&bytes, &RouteGrantV2RingInstallContext::default())
            .is_err());
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );
    }

    #[test]
    fn cancellation_and_publication_share_one_linearization_cas() {
        let cancelled = RouteGrantV2RingInstallContext::default();
        cancelled.cancel();
        assert!(matches!(
            cancelled.begin_publication(),
            Err(RouteGrantV2DurableInstallError::Cancelled)
        ));

        let owned = RouteGrantV2RingInstallContext::default();
        owned.begin_publication().unwrap();
        owned.cancel();
        assert_eq!(owned.publication.load(Ordering::Acquire), PUBLICATION_OWNED);
    }

    #[test]
    fn maximum_eight_key_successor_installs_atomically() {
        let first_entry = public_entry();
        let first = RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(1).unwrap(),
            expected_previous: None,
            keys: vec![first_entry.clone()],
        };
        let mut keys = vec![first_entry];
        keys.extend((1..8).map(|_| public_entry()));
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        let successor = RouteGrantV2PublicKeyRingArtifact {
            version: ContractVersion::V1,
            ring_version: Epoch::new(2).unwrap(),
            expected_previous: Some(RouteGrantV2PublicKeyRingExpectedPrevious {
                ring_version: first.ring_version,
                key_ring_digest: first.digest().unwrap(),
            }),
            keys,
        };
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), Arc::clone(&verifier));
        assert_eq!(
            installer
                .install(
                    &encode_route_grant_v2_public_key_ring(&successor).unwrap(),
                    &RouteGrantV2RingInstallContext::default(),
                )
                .unwrap(),
            RouteGrantV2DurableInstallOutcome::Installed
        );
        assert_eq!(verifier.current_ring().unwrap().loaded_kids().len(), 8);
    }

    #[test]
    fn symlink_and_hardlink_current_artifacts_fail_closed() {
        use std::os::unix::fs::symlink;

        let (first, second) = rings();
        let (hardlink_root, verifier) = fixture(&first);
        let hardlink_path = hardlink_root.path().join("route-v2").join(RING_BASENAME);
        std::fs::hard_link(
            &hardlink_path,
            hardlink_root.path().join("route-v2").join("ring-copy"),
        )
        .unwrap();
        let installer = RouteGrantV2RingInstaller::for_test(hardlink_root.path(), verifier);
        assert!(installer
            .install(
                &encode_route_grant_v2_public_key_ring(&second).unwrap(),
                &RouteGrantV2RingInstallContext::default(),
            )
            .is_err());

        let (symlink_root, verifier) = fixture(&first);
        let symlink_path = symlink_root.path().join("route-v2").join(RING_BASENAME);
        let target = symlink_root.path().join("route-v2").join("ring-target");
        std::fs::rename(&symlink_path, &target).unwrap();
        symlink(&target, &symlink_path).unwrap();
        let installer = RouteGrantV2RingInstaller::for_test(symlink_root.path(), verifier);
        assert!(installer
            .install(
                &encode_route_grant_v2_public_key_ring(&second).unwrap(),
                &RouteGrantV2RingInstallContext::default(),
            )
            .is_err());
    }

    #[test]
    fn fixed_directory_replacement_after_rename_is_rejected_before_verifier_swap() {
        let (first, second) = rings();
        let first_bytes = encode_route_grant_v2_public_key_ring(&first).unwrap();
        let second_bytes = encode_route_grant_v2_public_key_ring(&second).unwrap();
        let (root, verifier) = fixture(&first);
        let gate = Arc::new(PrePublicationGate::default());
        let installer = Arc::new(RouteGrantV2RingInstaller::for_test(
            root.path(),
            Arc::clone(&verifier),
        ));
        installer.set_post_rename_gate(Arc::clone(&gate));
        let install = {
            let installer = Arc::clone(&installer);
            std::thread::spawn(move || {
                installer.install(&second_bytes, &RouteGrantV2RingInstallContext::default())
            })
        };

        gate.wait_until_reached();
        let fixed = root.path().join("route-v2");
        std::fs::rename(&fixed, root.path().join("detached-route-v2")).unwrap();
        std::fs::create_dir(&fixed).unwrap();
        std::fs::set_permissions(&fixed, std::fs::Permissions::from_mode(0o700)).unwrap();
        let replacement_ring = fixed.join(RING_BASENAME);
        std::fs::write(&replacement_ring, &first_bytes).unwrap();
        std::fs::set_permissions(&replacement_ring, std::fs::Permissions::from_mode(0o644))
            .unwrap();
        gate.release();

        assert!(matches!(
            install.join().unwrap(),
            Err(RouteGrantV2DurableInstallError::Filesystem)
        ));
        assert_eq!(std::fs::read(replacement_ring).unwrap(), first_bytes);
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            first.ring_version
        );
    }

    #[test]
    fn concurrent_exact_installs_have_one_publication_and_one_zero_write_replay() {
        use std::sync::Barrier;

        let (first, second) = rings();
        let (root, verifier) = fixture(&first);
        let installer = Arc::new(RouteGrantV2RingInstaller::for_test(
            root.path(),
            Arc::clone(&verifier),
        ));
        let bytes = Arc::new(encode_route_grant_v2_public_key_ring(&second).unwrap());
        let barrier = Arc::new(Barrier::new(3));
        let workers = (0..2)
            .map(|_| {
                let installer = Arc::clone(&installer);
                let bytes = Arc::clone(&bytes);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    installer
                        .install(&bytes, &RouteGrantV2RingInstallContext::default())
                        .unwrap()
                })
            })
            .collect::<Vec<_>>();
        barrier.wait();
        let outcomes = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RouteGrantV2DurableInstallOutcome::Installed)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == RouteGrantV2DurableInstallOutcome::Replay)
                .count(),
            1
        );
        assert_eq!(
            verifier.current_ring().unwrap().version(),
            second.ring_version
        );
    }

    #[test]
    fn conflicting_successors_from_independent_installers_do_not_split_disk_and_live_ring() {
        let (first, installed_successor) = rings();
        let mut conflicting_successor = installed_successor.clone();
        conflicting_successor.keys[0] = distinct_public_entry(&conflicting_successor.keys[1..]);
        conflicting_successor
            .keys
            .sort_by(|left, right| left.kid.cmp(&right.kid));
        let installed_bytes = encode_route_grant_v2_public_key_ring(&installed_successor).unwrap();
        let conflicting_bytes =
            encode_route_grant_v2_public_key_ring(&conflicting_successor).unwrap();
        let (root, verifier) = fixture(&first);
        let gate = Arc::new(PrePublicationGate::default());
        let first_installer = Arc::new(RouteGrantV2RingInstaller::for_test(
            root.path(),
            Arc::clone(&verifier),
        ));
        first_installer.set_pre_publication_gate(Arc::clone(&gate));
        let second_installer = Arc::new(RouteGrantV2RingInstaller::for_test(
            root.path(),
            Arc::clone(&verifier),
        ));

        let installed_thread = {
            let installer = Arc::clone(&first_installer);
            let bytes = installed_bytes.clone();
            std::thread::spawn(move || {
                installer.install(&bytes, &RouteGrantV2RingInstallContext::default())
            })
        };
        gate.wait_until_reached();
        let conflicting_thread = {
            let installer = Arc::clone(&second_installer);
            std::thread::spawn(move || {
                installer.install(
                    &conflicting_bytes,
                    &RouteGrantV2RingInstallContext::default(),
                )
            })
        };
        gate.release();

        assert_eq!(
            installed_thread.join().unwrap().unwrap(),
            RouteGrantV2DurableInstallOutcome::Installed
        );
        let conflicting_result = conflicting_thread.join().unwrap();
        assert!(
            matches!(
                conflicting_result,
                Err(RouteGrantV2DurableInstallError::Conflict)
            ),
            "unexpected conflicting successor result: {conflicting_result:?}"
        );
        let on_disk = std::fs::read(root.path().join("route-v2").join(RING_BASENAME)).unwrap();
        assert_eq!(on_disk, installed_bytes);
        let live = verifier.current_ring().unwrap();
        let installed_ring = RouteGrantV2KeyRing::from_artifact(&installed_successor).unwrap();
        assert!(same_ring(live.as_ref(), &installed_ring));
    }

    #[test]
    fn directory_flock_serializes_independent_opens() {
        let (first, _) = rings();
        let (root, verifier) = fixture(&first);
        let installer = RouteGrantV2RingInstaller::for_test(root.path(), verifier);
        let mut first_open = installer.filesystem.open().unwrap();
        let second_open = installer.filesystem.open().unwrap();
        let _lock = first_open.lock_final_directory().unwrap();
        // SAFETY: the descriptor stays live for this non-blocking probe.
        let result = unsafe {
            libc::flock(
                second_open.final_descriptor().as_raw_fd(),
                libc::LOCK_EX | libc::LOCK_NB,
            )
        };
        assert_eq!(result, -1);
        assert_eq!(io::Error::last_os_error().kind(), io::ErrorKind::WouldBlock);
    }
}
