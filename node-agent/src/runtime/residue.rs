//! Reclaiming the per-Cat runtime directories no live Cat owns (issue #99).
//!
//! `<state_dir>/cats/<cat_id>` holds three kinds of bytes: the Guest memory
//! backing (`guest-memory.bin`), one `vol-<disk>` directory per attached disk
//! holding blockd's chunk cache and its pending-pack journal, and a Warm
//! snapshot. `stop_cat` removes the whole directory only after a teardown that
//! fully succeeded, and teardowns fail routinely for reasons that have nothing
//! to do with the disk: a fenced drain, an unreachable object store, a launch
//! that never reached Running. Each of those left the whole directory behind
//! for good — 49 abandoned directories holding 104 GiB against 2 live Cats on
//! `metal-1`, with no counter, no reclamation, and no symptom until the local
//! NVMe ran out (issue #99).
//!
//! The fail-closed rule in `stop_cat` — never discard an unsupervised runtime
//! directory — is correct and stays. What this module adds is the counterpart
//! it never had: something that comes back, reclaims only what is provably not
//! durability state, and reports whatever it had to leave.
//!
//! Provably not durability state means exactly two things:
//!
//! - `guest-memory.bin` is Guest RAM backing. The only path that reads one back
//!   is a Warm restore, which needs the snapshot beside it; with no snapshot a
//!   Cold start rebuilds the file from scratch. Half the leaked bytes were
//!   this.
//! - a `vol-<disk>` directory whose `pending/` holds no pack. Acknowledged
//!   writes that are not yet published live in the pending-pack journal
//!   (ADR-0021/0022); with no pack there, what is left is `cache.data` and
//!   `dirty.bitmap`, which the non-negotiable invariant makes a deletable
//!   cache.
//!
//! Everything else is left exactly as found and counted into the node's
//! telemetry. A pending pack may be the only authoritative copy of a relaxed
//! volume's writes, and the check that would settle it — is this pack's
//! lineage superseded? — needs the volume's head generation from the metadata
//! store, which blockd holds and this agent deliberately does not (ADR-0005).

use super::*;

use cats_api::blockd::{PACK_FILE_SUFFIX, PENDING_PACK_DIR};

/// What one [`NodeRuntime::sweep_runtime_residue`] pass concluded.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct RuntimeResidue {
    /// Unsupervised per-Cat runtime directories still on disk afterwards.
    pub dirs: u64,
    /// Allocated bytes those directories hold.
    ///
    /// Allocated, not apparent: `prepare_memory_backing` writes a sparse file,
    /// and the same 51 directories measured 348 GiB apparent against ~53 GiB
    /// actually on the medium. An alarm on the apparent size would fire on
    /// bytes the disk never spent.
    pub bytes: u64,
    /// Allocated bytes this pass freed.
    pub reclaimed_bytes: u64,
}

impl NodeRuntime {
    /// Reclaim what unsupervised per-Cat runtime directories provably do not
    /// need, and record what is left for [`NodeRuntime::telemetry`].
    ///
    /// Runs at startup after re-adoption has decided what this node still
    /// supervises, and periodically after that: a failed teardown strands a
    /// directory while the agent is up, and an agent that only swept at boot
    /// would hold those bytes until someone restarted it.
    ///
    /// Blocking: walks the state directory and probes Unix sockets. Never
    /// fails — an unreadable directory is one this pass does not resolve, not
    /// a reason to stop the agent.
    pub(crate) fn sweep_runtime_residue(&self) -> RuntimeResidue {
        let root = self.cfg.state_dir.join("cats");
        let entries = match std::fs::read_dir(&root) {
            Ok(entries) => entries,
            // No Cat has ever started here, so there is nothing to hold.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return self.publish_residue(RuntimeResidue::default());
            }
            Err(error) => {
                tracing::warn!(
                    dir = %root.display(),
                    "could not scan per-Cat runtime directories: {error}"
                );
                return self.last_runtime_residue().unwrap_or_default();
            }
        };
        let mut report = RuntimeResidue::default();
        for entry in entries.flatten() {
            // `DirEntry::file_type` does not follow symlinks on Unix, so a
            // symlinked name can never send the sweep somewhere else.
            if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
                continue;
            }
            let cat_id = entry.file_name().to_string_lossy().into_owned();
            let dir = entry.path();
            // A supervised Cat owns its directory; the sweep never touches one.
            if self.is_supervised(&cat_id) {
                continue;
            }
            // A job may be mid-launch: `start_cat` creates the directory and
            // its memory backing before it publishes the runtime, so an
            // unsupervised directory is not evidence of residue while its Cat's
            // execution lock is held. Skipping is right — blocking would put
            // the sweep behind a remote drain, and the directory will still be
            // here next pass.
            let per_cat = self.cat_lock(&cat_id);
            let Ok(_guard) = per_cat.try_lock() else {
                continue;
            };
            // Re-check under the lock: the job that just finished may have
            // published a runtime for exactly this directory.
            if self.is_supervised(&cat_id) {
                continue;
            }
            report.reclaimed_bytes = report
                .reclaimed_bytes
                .saturating_add(self.reclaim_residue_dir(&cat_id, &dir));
            if dir.exists() {
                report.dirs = report.dirs.saturating_add(1);
                report.bytes = report
                    .bytes
                    .saturating_add(allocated_tree_bytes(&dir).unwrap_or(0));
            }
        }
        // Only when there is something to say: this runs every few minutes for
        // the life of the node, and a clean sweep is the normal case.
        if report.reclaimed_bytes > 0 || report.dirs > 0 {
            tracing::info!(
                node = %self.cfg.node_id,
                reclaimed_bytes = report.reclaimed_bytes,
                residue_dirs = report.dirs,
                residue_bytes = report.bytes,
                "swept per-Cat runtime directories no live Cat owns"
            );
        }
        self.publish_residue(report)
    }

    /// The last sweep's conclusion, or `None` before the first one lands.
    pub(crate) fn last_runtime_residue(&self) -> Option<RuntimeResidue> {
        *self
            .residue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn publish_residue(&self, report: RuntimeResidue) -> RuntimeResidue {
        *self
            .residue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(report);
        report
    }

    fn is_supervised(&self, cat_id: &str) -> bool {
        self.cats
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .contains_key(cat_id)
    }

    /// Reclaim what one unsupervised runtime directory provably does not need,
    /// returning the allocated bytes freed.
    fn reclaim_residue_dir(&self, cat_id: &str, dir: &Path) -> u64 {
        if holds_warm_state(dir) {
            tracing::info!(
                cat = %cat_id,
                dir = %dir.display(),
                "leaving an unsupervised runtime directory alone: it holds a Warm snapshot, whose Guest memory backing is the snapshot"
            );
            return 0;
        }
        if let Some(socket) = self.serving_socket(cat_id, dir) {
            tracing::info!(
                cat = %cat_id,
                dir = %dir.display(),
                socket = %socket.display(),
                "leaving an unsupervised runtime directory alone: a process is still serving it"
            );
            return 0;
        }
        let mut freed = remove_file_bytes(&dir.join(ch::GUEST_MEMORY_FILE));
        let mut retained = Vec::new();
        for (disk_id, volume_dir) in volume_dirs(dir) {
            if has_pending_packs(&volume_dir) {
                retained.push(disk_id);
                continue;
            }
            freed = freed.saturating_add(remove_tree_bytes(&volume_dir));
        }
        if retained.is_empty() {
            // Nothing durability-bearing is left, so the sockets, disk map and
            // blockd logs still in here describe a Cat that no longer exists.
            freed = freed.saturating_add(remove_tree_bytes(dir));
        } else {
            tracing::warn!(
                cat = %cat_id,
                dir = %dir.display(),
                disks = ?retained,
                "keeping unpublished pending packs from an unsupervised runtime; only blockd can decide whether their lineage is superseded"
            );
        }
        freed
    }

    /// A socket of this Cat's runtime that still has a listener, if any.
    ///
    /// Most of this residue predates the runtime ledger, and the ledger would
    /// not settle it anyway: `execute` forgets a Cat's record the moment it is
    /// no longer supervised, which is exactly when a failed launch leaves its
    /// directory behind. What every runtime does have is its sockets, and their
    /// paths are *derived* from `(state_dir, cat_id, kind)` rather than
    /// remembered — so they can be reconstructed for a directory nothing else
    /// knows anything about.
    ///
    /// AF_UNIX answers the question exactly: a bound socket with a live server
    /// accepts, the stale file a crashed server left refuses, and a removed one
    /// is not found. Anything else — a full backlog, a permission error — is
    /// ambiguous and counts as serving, because what this decides is whether to
    /// delete state out from under a running process.
    fn serving_socket(&self, cat_id: &str, dir: &Path) -> Option<PathBuf> {
        // The VMM's API socket and the FakeVmm guest's control socket, then one
        // blockd control socket per volume. Deliberately not the NBD or
        // vhost-user sockets: those are the Guest's data path, served by the
        // same blockd process the control socket already answers for.
        let mut kinds = vec!["chapi".to_string(), "ctl".to_string()];
        kinds.extend(
            volume_dirs(dir)
                .into_iter()
                .map(|(disk_id, _)| format!("ctl-{disk_id}")),
        );
        kinds
            .into_iter()
            .map(|kind| short_socket_path(&self.cfg.state_dir, cat_id, &kind))
            .find(|path| socket_has_listener(path))
    }
}

/// Whether this directory holds state a restore would read Guest RAM back from.
///
/// Cloud Hypervisor's `vm.snapshot` writes the device and config state into
/// `snapshot/` and leaves the Guest pages in the memory backing beside it, so
/// the two are one artifact: the snapshot is the evidence that the memory
/// backing is a restorable image rather than a dead VMM's scratch space.
/// FakeVmm's whole snapshot is its saved guest state file.
fn holds_warm_state(dir: &Path) -> bool {
    dir.join("snapshot").is_dir() || warm_state_file(dir).exists()
}

/// The `(disk_id, path)` of every volume directory under a runtime directory.
fn volume_dirs(dir: &Path) -> Vec<(String, PathBuf)> {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return Vec::new();
    };
    entries
        .flatten()
        .filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
        .filter_map(|entry| {
            let name = entry.file_name().to_string_lossy().into_owned();
            let disk_id = name.strip_prefix(VOLUME_DIR_PREFIX)?.to_string();
            Some((disk_id, entry.path()))
        })
        .collect()
}

/// Whether a volume directory still holds locally durable, unpublished writes.
///
/// The same `pending/*.pack` set `ChunkEngine::recover_pending_packs` reads
/// back. A directory that cannot be read counts as holding packs: this decides
/// whether bytes that may be a relaxed volume's only authoritative copy get
/// deleted, so ambiguity has to fail closed.
fn has_pending_packs(volume_dir: &Path) -> bool {
    match std::fs::read_dir(volume_dir.join(PENDING_PACK_DIR)) {
        Ok(entries) => entries.flatten().any(|entry| {
            entry
                .file_name()
                .to_string_lossy()
                .ends_with(PACK_FILE_SUFFIX)
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            tracing::warn!(
                dir = %volume_dir.display(),
                "cannot read a pending-pack journal, so treating it as holding unpublished writes: {error}"
            );
            true
        }
    }
}

fn socket_has_listener(path: &Path) -> bool {
    match std::os::unix::net::UnixStream::connect(path) {
        Ok(_) => true,
        Err(error) => !matches!(
            error.kind(),
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
        ),
    }
}

/// Remove one file, returning the allocated bytes that frees.
pub(super) fn remove_file_bytes(path: &Path) -> u64 {
    let bytes = allocated_tree_bytes(path).unwrap_or(0);
    match std::fs::remove_file(path) {
        Ok(()) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            tracing::warn!(path = %path.display(), "could not remove {}: {error}", path.display());
            0
        }
    }
}

fn remove_tree_bytes(path: &Path) -> u64 {
    let bytes = allocated_tree_bytes(path).unwrap_or(0);
    match std::fs::remove_dir_all(path) {
        Ok(()) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => {
            tracing::warn!(path = %path.display(), "could not remove {}: {error}", path.display());
            0
        }
    }
}

/// Bytes a path actually occupies on the medium, including everything under it.
///
/// Allocated blocks rather than apparent length, and `symlink_metadata` rather
/// than `metadata`: a runtime directory is full of sparse files and of symlinks
/// pointing outside itself, and following either would report space that is not
/// there.
pub(crate) fn allocated_tree_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    let metadata = std::fs::symlink_metadata(path).ok()?;
    let mut total = metadata.blocks().saturating_mul(512);
    if metadata.file_type().is_dir() {
        for entry in std::fs::read_dir(path).ok()? {
            let Ok(entry) = entry else { continue };
            total = total.saturating_add(allocated_tree_bytes(&entry.path()).unwrap_or(0));
        }
    }
    Some(total)
}
