//! Read-only production probes for the first Running inventory vertical.
//!
//! These probes recognize an otherwise-empty Host; the typed test seam can
//! also compose a complete per-Node authority-index snapshot for a root-only
//! Running Desired. Production reads the schema-v11 owner index and the exact
//! Desired candidate set in one bounded repeatable-read snapshot, then pages
//! that immutable result locally. The one recognized local fact is a complete, canonical
//! `AuthorizedBlockdStore` lineage bound to the current Desired, checkpoint and
//! authority record; partial, foreign or conflicting facts remain unavailable
//! or residue and are never cleaned here. A source that cannot be enumerated
//! exhaustively reports `Unavailable`; it never turns an I/O failure into
//! absence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use cats_api::chunk;
use cats_api::runtime_reconciliation::{
    decode_runtime_checkpoint, DesiredRuntimeSpec, DiskKind, HostPath, Id, InventorySource,
    ObservedDiskKind, ObservedVolume, ReconcileStep, RuntimeCheckpoint, Sequence, Sha256Digest,
    VolumeAcquire, VolumeAdminState, VolumeAuthorityEvidence, VolumeIntent, WireU64,
    RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
};
use cats_blockd::format::{decode_bitmap_header, BITMAP_HEADER_LEN};
use cats_blockd::target_control::TARGET_CONTROL_AUTHORIZATION_MAX_BYTES;
#[cfg(test)]
use cats_storage::authority::VolumeDataAuthority;
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, AttachmentLineageIdentity,
    AuthorizedServingAttachment, NodeVolumeInventorySnapshot, RuntimeVolumeInventoryAuthority,
    VolumeRecord,
};
use cats_storage::BlobStore;
use sha2::{Digest as _, Sha256};

use crate::runtime_spine::{
    RuntimeInventoryScanContext, RuntimeInventoryScanner, RuntimePhysicalReadContext,
    RuntimePreScanRecoveryContext,
};
use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    validate_authorized_blockd_checkpoint, AUTHORIZED_SERVING_FILE, AUTHORIZED_SERVING_TEMP,
    IDENTITY_FILE, IDENTITY_TEMP, LAUNCH_CHECKPOINT_FILE, LAUNCH_CHECKPOINT_TEMP,
    MAX_AUTHORIZED_SERVING_BYTES, MAX_IDENTITY_BYTES, MAX_LAUNCH_CHECKPOINT_BYTES,
};
use super::checkpoint::{
    decode_definite_release_rejection, validate_definite_release_rejection,
    DefiniteReleaseRejection, RELEASE_REJECTION_MAX_BYTES,
};
use super::inventory::{
    AuthorityVolumeInventoryEvidence, AuthorizedBlockdControlState,
    AuthorizedBlockdInventoryEvidence, DesiredCheckpointBinding,
    RuntimeCheckpointInventoryEvidence,
};
use super::root_provision_process::inspect_exact_root_provision_process;
use super::serving_handoff::{
    validate_scanned_serving_handoff_artifacts, ScannedServingHandoffArtifact,
    ServingHandoffTempKind, SERVING_HANDOFF_RECORD_FILE, SERVING_HANDOFF_RECORD_MAX_BYTES,
    SERVING_HANDOFF_RETIREMENT_FILE, SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
};
use super::{
    inventory::{
        root_process_inventory_bridge_sealed, InstalledRuntimeInventoryKeyRingReader,
        RootProcessInventoryBridge, RootProcessInventoryBridgeOutcome,
    },
    AuthorizedBlockdCheckpoint, CleanSlateInventoryScanner, InventoryAbsence,
    InventoryAbsenceProbe, PlatformSystemdRootProvisionProcessPort, RootProvisionProcessConflict,
    RootProvisionProcessExpectation, RootProvisionProcessInspection, RootProvisionProcessPort,
    RootProvisionProcessRetirementPort, RootProvisionSystemdConfig,
};

pub(crate) const CHECKPOINT_NAMESPACE: &str = "checkpoints";
const CONTROL_SOCKET_NAMESPACE: &str = "control-sockets";
const VHOST_NAMESPACE: &str = "vhost-user";
const NETWORK_NAMESPACE: &str = "network";
const RUNTIME_EFFECTS_NAMESPACE: &str = "runtime-effects";
const DATA_NAMESPACE: &str = "data";
const PENDING_PACK_NAMESPACE: &str = "pending-packs";
const WARM_SNAPSHOT_NAMESPACE: &str = "warm-snapshots";
const GUEST_MOUNT_NAMESPACE: &str = "guest-mounts";
const RUNTIME_V1_MAX_ASSIGNED_CATS: usize = 1_024;
const RUNTIME_STATE_ENTRIES_PER_ASSIGNED_CAT: usize = 32;

fn is_release_rejection_entry(name: &str) -> bool {
    (name.starts_with("cat-") && name.ends_with(".release-rejection.json"))
        || (name.starts_with(".cat-") && name.ends_with(".release-rejection.tmp"))
}

const LEGACY_LEDGER: &str = "runtime-ledger";
const LEGACY_CATS_DIRECTORY: &str = "cats";
const DEFAULT_LEGACY_SOCKET_ROOT: &str = "/tmp/cats-sock";
const DEFAULT_SYSTEMD_CGROUP_ROOT: &str = "/sys/fs/cgroup/system.slice";
const DEFAULT_PROC_ROOT: &str = "/proc";
const DEFAULT_BLOCK_CLASS_ROOT: &str = "/sys/class/block";
const DEFAULT_NETWORK_CLASS_ROOT: &str = "/sys/class/net";

/// Read-only classification consumed by the serialized pre-scan mutation
/// lane. Classification never repairs, removes, or rewrites an entry.
pub(crate) enum LocalPublicationRecoveryEvidence {
    None,
    CheckpointTemp {
        cat_id: Id,
    },
    DefiniteReleaseRejectionTarget {
        cat_id: Id,
    },
    DefiniteReleaseRejectionTemp {
        cat_id: Id,
    },
    AuthorizedBlockd {
        cat_id: Id,
    },
    SupersededCheckpoint {
        cat_id: Id,
    },
    ServingHandoffTemp {
        cat_id: Id,
        kind: ServingHandoffTempKind,
        authorized: Box<AuthorizedBlockdCheckpoint>,
    },
}

mod metadata_authority_reader_sealed {
    pub(super) trait Sealed {}
}

const METADATA_AUTHORITY_PAGE_LIMIT: usize = 256;
// Runtime v1 bounds one Node at 1,024 assigned Cats and each Desired at 64
// volumes. The authority adapter reads at most this closed set plus one row to
// prove overflow; Node-side publication never accepts the +1 row.
const METADATA_AUTHORITY_MAX_RECORDS: usize = 65_536;

/// One page of the future provider-neutral Node-owner index. The persisted
/// authority must bind every live writer to `owner_node_id` in the same
/// transaction that changes `lease_owner`; a point load of Desired/local
/// candidates cannot synthesize this proof after the Desired row disappears.
#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataAuthorityPageRequest {
    node_id: Id,
    desired_read_position: Sequence,
    /// Present only on the first page. The port binds this complete set to its
    /// immutable cached snapshot; continuation pages use the returned read
    /// position instead of cloning up to 65,536 IDs again.
    candidate_volume_ids: Option<BTreeSet<Id>>,
    snapshot_read_position: Option<Sequence>,
    after_volume_id: Option<Id>,
    limit: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataAuthorityIndexedRecord {
    record: VolumeRecord,
    owner_node_id: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MetadataAuthorityPage {
    node_id: Id,
    desired_read_position: Sequence,
    snapshot_read_position: Sequence,
    records: Vec<MetadataAuthorityIndexedRecord>,
    next_after_volume_id: Option<Id>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetadataAuthorityPageRead {
    Page(MetadataAuthorityPage),
    Unavailable,
}

/// Descriptor for the only metadata listing shape the scanner may trust.
/// Each page belongs to one bounded immutable read position, contains all
/// candidate rows plus every authority row whose persisted owner is this
/// Node, and never infers ownership from attachment spelling or current
/// Desired membership.
trait MetadataAuthorityInventoryPort:
    metadata_authority_reader_sealed::Sealed + std::fmt::Debug + Send + Sync + 'static
{
    fn read_page(
        &self,
        request: &MetadataAuthorityPageRequest,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityPageRead>;
}

#[cfg(test)]
#[derive(Debug)]
struct UnavailableMetadataAuthorityInventoryPort;

#[cfg(test)]
impl metadata_authority_reader_sealed::Sealed for UnavailableMetadataAuthorityInventoryPort {}

#[cfg(test)]
impl MetadataAuthorityInventoryPort for UnavailableMetadataAuthorityInventoryPort {
    fn read_page(
        &self,
        _request: &MetadataAuthorityPageRequest,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityPageRead> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        Ok(MetadataAuthorityPageRead::Unavailable)
    }
}

enum MetadataAuthoritySnapshotRead {
    Complete(NodeVolumeInventorySnapshot),
    Unavailable,
}

struct MetadataAuthoritySnapshotRequest {
    node_id: Id,
    candidate_volume_ids: BTreeSet<Id>,
    reply: mpsc::SyncSender<MetadataAuthoritySnapshotRead>,
}

struct CachedMetadataAuthoritySnapshot {
    node_id: Id,
    desired_read_position: Sequence,
    snapshot_read_position: Sequence,
    records: Vec<MetadataAuthorityIndexedRecord>,
}

/// Owns the one blocking authority read outside the Runtime scan lane, then
/// serves bounded pages from that immutable in-memory result. A timed-out
/// backend read is never overlapped by a successor and is never installed in
/// the cache after its receiver has gone away.
struct RuntimeVolumeInventoryPagePort {
    requests: Mutex<Option<mpsc::SyncSender<MetadataAuthoritySnapshotRequest>>>,
    in_flight: Arc<AtomicBool>,
    operation: Mutex<()>,
    cache: Mutex<Option<CachedMetadataAuthoritySnapshot>>,
    next_snapshot_read_position: AtomicU64,
    worker: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl std::fmt::Debug for RuntimeVolumeInventoryPagePort {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeVolumeInventoryPagePort")
            .finish_non_exhaustive()
    }
}

impl RuntimeVolumeInventoryPagePort {
    fn start(authority: Arc<dyn RuntimeVolumeInventoryAuthority>) -> anyhow::Result<Self> {
        let (requests, receiver) = mpsc::sync_channel::<MetadataAuthoritySnapshotRequest>(1);
        let in_flight = Arc::new(AtomicBool::new(false));
        let worker_in_flight = Arc::clone(&in_flight);
        let worker = std::thread::Builder::new()
            .name("cats-runtime-volume-inventory".to_owned())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let result = authority
                        .load_node_volume_inventory(&request.node_id, &request.candidate_volume_ids)
                        .map(MetadataAuthoritySnapshotRead::Complete)
                        .unwrap_or(MetadataAuthoritySnapshotRead::Unavailable);
                    let _ = request.reply.send(result);
                    worker_in_flight.store(false, Ordering::Release);
                }
            })
            .context("start Runtime Volume inventory reader")?;
        Ok(Self {
            requests: Mutex::new(Some(requests)),
            in_flight,
            operation: Mutex::new(()),
            cache: Mutex::new(None),
            next_snapshot_read_position: AtomicU64::new(1),
            worker: Mutex::new(Some(worker)),
        })
    }

    fn unavailable() -> anyhow::Result<MetadataAuthorityPageRead> {
        Ok(MetadataAuthorityPageRead::Unavailable)
    }

    fn allocate_snapshot_read_position(&self) -> Option<Sequence> {
        self.next_snapshot_read_position
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .and_then(Sequence::new)
    }

    fn first_page(
        &self,
        request: &MetadataAuthorityPageRequest,
        _deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityPageRead> {
        let Some(candidate_volume_ids) = request.candidate_volume_ids.as_ref() else {
            return Self::unavailable();
        };
        if request.snapshot_read_position.is_some()
            || request.after_volume_id.is_some()
            || candidate_volume_ids.len() > METADATA_AUTHORITY_MAX_RECORDS
        {
            return Self::unavailable();
        }
        match self.cache.lock() {
            Ok(mut cache) => *cache = None,
            Err(_) => return Self::unavailable(),
        }
        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Self::unavailable();
        }

        let requests = match self.requests.lock() {
            Ok(requests) => requests.as_ref().cloned(),
            Err(_) => None,
        };
        let Some(requests) = requests else {
            self.in_flight.store(false, Ordering::Release);
            return Self::unavailable();
        };
        let (reply, received) = mpsc::sync_channel(1);
        match requests.try_send(MetadataAuthoritySnapshotRequest {
            node_id: request.node_id.clone(),
            candidate_volume_ids: candidate_volume_ids.clone(),
            reply,
        }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                self.in_flight.store(false, Ordering::Release);
                return Self::unavailable();
            }
        }

        const DEADLINE_RESERVE: Duration = Duration::from_millis(10);
        let wait = context.remaining()?.saturating_sub(DEADLINE_RESERVE);
        if wait.is_zero() {
            return Self::unavailable();
        }
        let snapshot = match received.recv_timeout(wait) {
            Ok(MetadataAuthoritySnapshotRead::Complete(snapshot)) => snapshot,
            Ok(MetadataAuthoritySnapshotRead::Unavailable)
            | Err(mpsc::RecvTimeoutError::Timeout)
            | Err(mpsc::RecvTimeoutError::Disconnected) => return Self::unavailable(),
        };
        context.check_active()?;
        if snapshot.node_id != request.node_id
            || snapshot.records.len() > METADATA_AUTHORITY_MAX_RECORDS
        {
            return Self::unavailable();
        }
        let Some(snapshot_read_position) = self.allocate_snapshot_read_position() else {
            return Self::unavailable();
        };
        let mut records = Vec::with_capacity(snapshot.records.len());
        let mut previous_volume_id: Option<Id> = None;
        for indexed in snapshot.records {
            if previous_volume_id
                .as_ref()
                .is_some_and(|previous| previous >= &indexed.volume.volume_id)
                || validate_volume_record(&indexed.volume).is_err()
            {
                return Self::unavailable();
            }
            let owner_node_id = match indexed.binding {
                Some(binding) => {
                    if validate_volume_owner_binding(&binding, &indexed.volume).is_err() {
                        return Self::unavailable();
                    }
                    Some(binding.owner_node_id)
                }
                None if indexed.volume.lease_owner.is_none() => None,
                None => return Self::unavailable(),
            };
            previous_volume_id = Some(indexed.volume.volume_id.clone());
            records.push(MetadataAuthorityIndexedRecord {
                owner_node_id,
                record: indexed.volume,
            });
        }
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(_) => return Self::unavailable(),
        };
        *cache = Some(CachedMetadataAuthoritySnapshot {
            node_id: request.node_id.clone(),
            desired_read_position: request.desired_read_position,
            snapshot_read_position,
            records,
        });
        drop(cache);
        self.page_from_cache(request, snapshot_read_position)
    }

    fn continuation_page(
        &self,
        request: &MetadataAuthorityPageRequest,
        snapshot_read_position: Sequence,
    ) -> anyhow::Result<MetadataAuthorityPageRead> {
        if request.candidate_volume_ids.is_some() || request.after_volume_id.is_none() {
            return Self::unavailable();
        }
        self.page_from_cache(request, snapshot_read_position)
    }

    fn page_from_cache(
        &self,
        request: &MetadataAuthorityPageRequest,
        snapshot_read_position: Sequence,
    ) -> anyhow::Result<MetadataAuthorityPageRead> {
        let mut cache = match self.cache.lock() {
            Ok(cache) => cache,
            Err(_) => return Self::unavailable(),
        };
        let Some(snapshot) = cache.as_ref() else {
            return Self::unavailable();
        };
        if snapshot.node_id != request.node_id
            || snapshot.desired_read_position != request.desired_read_position
            || snapshot.snapshot_read_position != snapshot_read_position
        {
            *cache = None;
            return Self::unavailable();
        }
        let start = match request.after_volume_id.as_ref() {
            None => 0,
            Some(after) => match snapshot
                .records
                .binary_search_by(|record| record.record.volume_id.cmp(after))
            {
                Ok(index) => index + 1,
                Err(_) => {
                    *cache = None;
                    return Self::unavailable();
                }
            },
        };
        let end = start
            .saturating_add(request.limit)
            .min(snapshot.records.len());
        let records = snapshot.records[start..end].to_vec();
        // Every nonempty page carries a cursor, including the last record in
        // the cached vector. Only a subsequent explicit empty page proves
        // exhaustion; a truncated provider cannot turn a short nonempty page
        // into a complete inventory.
        let next_after_volume_id = records.last().map(|record| record.record.volume_id.clone());
        let page = MetadataAuthorityPage {
            node_id: snapshot.node_id.clone(),
            desired_read_position: snapshot.desired_read_position,
            snapshot_read_position,
            records,
            next_after_volume_id,
        };
        if page.records.is_empty() {
            *cache = None;
        }
        Ok(MetadataAuthorityPageRead::Page(page))
    }
}

impl Drop for RuntimeVolumeInventoryPagePort {
    fn drop(&mut self) {
        let requests = self
            .requests
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        drop(requests.take());
        let worker = self
            .worker
            .get_mut()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(worker) = worker.take() {
            let _ = worker.join();
        }
    }
}

impl metadata_authority_reader_sealed::Sealed for RuntimeVolumeInventoryPagePort {}

impl MetadataAuthorityInventoryPort for RuntimeVolumeInventoryPagePort {
    fn read_page(
        &self,
        request: &MetadataAuthorityPageRequest,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityPageRead> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        if request.node_id != context.coordinates().session.node_id
            || request.limit == 0
            || request.limit > METADATA_AUTHORITY_PAGE_LIMIT
        {
            return Self::unavailable();
        }
        let _operation = match self.operation.try_lock() {
            Ok(operation) => operation,
            Err(_) => return Self::unavailable(),
        };
        let result = match request.snapshot_read_position {
            Some(snapshot_read_position) => self.continuation_page(request, snapshot_read_position),
            None => self.first_page(request, deadline, context),
        }?;
        context.check_active()?;
        Ok(result)
    }
}

#[derive(Debug)]
struct PagedMetadataAuthorityReader {
    port: Arc<dyn MetadataAuthorityInventoryPort>,
}

impl PagedMetadataAuthorityReader {
    fn new(port: Arc<dyn MetadataAuthorityInventoryPort>) -> Self {
        Self { port }
    }
}

impl metadata_authority_reader_sealed::Sealed for PagedMetadataAuthorityReader {}

impl MetadataAuthorityAbsenceReader for PagedMetadataAuthorityReader {
    fn read_candidates(
        &self,
        node_id: &Id,
        candidate_volume_ids: &BTreeSet<Id>,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        if node_id != &context.coordinates().session.node_id
            || candidate_volume_ids.len() > METADATA_AUTHORITY_MAX_RECORDS
        {
            return Ok(MetadataAuthorityCandidateInventory::Unavailable);
        }

        let desired_read_position = context.coordinates().desired.read_position;
        let mut snapshot_read_position = None;
        let mut after_volume_id = None;
        let mut records = BTreeMap::new();
        let max_pages = METADATA_AUTHORITY_MAX_RECORDS.div_ceil(METADATA_AUTHORITY_PAGE_LIMIT) + 1;

        for _ in 0..max_pages {
            let request = MetadataAuthorityPageRequest {
                node_id: node_id.clone(),
                desired_read_position,
                candidate_volume_ids: snapshot_read_position
                    .is_none()
                    .then(|| candidate_volume_ids.clone()),
                snapshot_read_position,
                after_volume_id: after_volume_id.clone(),
                limit: METADATA_AUTHORITY_PAGE_LIMIT,
            };
            let MetadataAuthorityPageRead::Page(page) =
                self.port.read_page(&request, deadline, context)?
            else {
                return Ok(MetadataAuthorityCandidateInventory::Unavailable);
            };
            context.check_active()?;

            if page.node_id != request.node_id
                || page.desired_read_position != request.desired_read_position
                || request
                    .snapshot_read_position
                    .is_some_and(|position| position != page.snapshot_read_position)
                || page.records.len() > request.limit
            {
                return Ok(MetadataAuthorityCandidateInventory::Unavailable);
            }
            snapshot_read_position = Some(page.snapshot_read_position);

            let mut previous_volume_id = request.after_volume_id.as_ref();
            for indexed in &page.records {
                let volume_id = &indexed.record.volume_id;
                if previous_volume_id.is_some_and(|previous| volume_id <= previous)
                    || validate_volume_record(&indexed.record).is_err()
                    || !matches!(
                        (&indexed.record.lease_owner, &indexed.owner_node_id),
                        (None, None) | (Some(_), Some(_))
                    )
                    || (indexed.record.lease_owner.is_some()
                        && indexed.owner_node_id.as_ref() != Some(node_id))
                    || (!candidate_volume_ids.contains(volume_id)
                        && indexed.owner_node_id.as_ref() != Some(node_id))
                    || records
                        .insert(volume_id.clone(), indexed.record.clone())
                        .is_some()
                {
                    return Ok(MetadataAuthorityCandidateInventory::Unavailable);
                }
                previous_volume_id = Some(volume_id);
            }
            if records.len() > METADATA_AUTHORITY_MAX_RECORDS {
                return Ok(MetadataAuthorityCandidateInventory::Unavailable);
            }

            match page.next_after_volume_id {
                Some(next)
                    if page.records.last().map(|indexed| &indexed.record.volume_id)
                        == Some(&next) =>
                {
                    after_volume_id = Some(next);
                }
                Some(_) => return Ok(MetadataAuthorityCandidateInventory::Unavailable),
                None if page.records.is_empty() => {
                    if candidate_volume_ids
                        .iter()
                        .any(|volume_id| !records.contains_key(volume_id))
                    {
                        return Ok(MetadataAuthorityCandidateInventory::Unavailable);
                    }
                    return Ok(MetadataAuthorityCandidateInventory::Records(records));
                }
                None => return Ok(MetadataAuthorityCandidateInventory::Unavailable),
            }
        }

        Ok(MetadataAuthorityCandidateInventory::Unavailable)
    }
}

/// A bounded read-only proof over the complete set of volume candidates seen
/// by the scan. Implementations must use the supplied absolute deadline and
/// consult `context.check_active()` around every potentially blocking
/// operation.
trait MetadataAuthorityAbsenceReader:
    metadata_authority_reader_sealed::Sealed + std::fmt::Debug + Send + Sync + 'static
{
    fn read_candidates(
        &self,
        node_id: &Id,
        candidate_volume_ids: &BTreeSet<Id>,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityCandidateInventory>;
}

#[cfg(test)]
enum MetadataAuthorityRead {
    Complete { records: BTreeMap<Id, VolumeRecord> },
    Incomplete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum MetadataAuthorityCandidateInventory {
    /// An empty map is a complete per-Node authority-index proof only when the
    /// requested candidate set is also empty.
    Records(BTreeMap<Id, VolumeRecord>),
    Unavailable,
}

#[cfg(test)]
struct MetadataAuthorityReadRequest {
    candidate_volume_ids: BTreeSet<Id>,
    reply: mpsc::SyncSender<MetadataAuthorityRead>,
}

/// Adapts the provider-neutral strict authority reader to the scanner's one
/// absolute deadline. `VolumeDataAuthority` is synchronous and has no
/// cancellation argument, so a single rendezvous worker owns possibly slow
/// reads. The scan lane can stop waiting at its deadline without starting a
/// second overlapping metadata read; while the worker is occupied, later
/// scans report the source unavailable.
#[cfg(test)]
struct VolumeDataAuthorityMetadataReader {
    requests: mpsc::SyncSender<MetadataAuthorityReadRequest>,
    in_flight: Arc<AtomicBool>,
}

#[cfg(test)]
impl std::fmt::Debug for VolumeDataAuthorityMetadataReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("VolumeDataAuthorityMetadataReader")
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
impl VolumeDataAuthorityMetadataReader {
    fn start(authority: Arc<dyn VolumeDataAuthority>) -> anyhow::Result<Self> {
        // `in_flight` admits work only while the single reader is idle. The
        // one-slot channel is solely the handoff to that worker; it can never
        // become a backlog behind an uncooperative backend.
        let (requests, receiver) = mpsc::sync_channel::<MetadataAuthorityReadRequest>(1);
        let in_flight = Arc::new(AtomicBool::new(false));
        let worker_in_flight = Arc::clone(&in_flight);
        std::thread::Builder::new()
            .name("cats-runtime-metadata-authority".to_owned())
            .spawn(move || {
                while let Ok(request) = receiver.recv() {
                    let was_empty = request.candidate_volume_ids.is_empty();
                    let mut records = BTreeMap::new();
                    let mut incomplete = false;
                    for volume_id in request.candidate_volume_ids {
                        match authority.load_volume(&volume_id) {
                            Ok(record) => {
                                if record.volume_id != volume_id
                                    || validate_volume_record(&record).is_err()
                                    || records.insert(volume_id, record).is_some()
                                {
                                    incomplete = true;
                                }
                            }
                            Err(_error) => incomplete = true,
                        }
                    }
                    let result = if was_empty || incomplete {
                        MetadataAuthorityRead::Incomplete
                    } else if !records.is_empty() {
                        MetadataAuthorityRead::Complete { records }
                    } else {
                        // Defensive future-proofing: a nonempty input that
                        // produced neither a record nor an error is not a
                        // complete authority read.
                        MetadataAuthorityRead::Incomplete
                    };
                    worker_in_flight.store(false, Ordering::Release);
                    let _ = request.reply.send(result);
                }
            })
            .context("start Runtime metadata-authority reader")?;
        Ok(Self {
            requests,
            in_flight,
        })
    }
}

#[cfg(test)]
impl metadata_authority_reader_sealed::Sealed for VolumeDataAuthorityMetadataReader {}

#[cfg(test)]
impl MetadataAuthorityAbsenceReader for VolumeDataAuthorityMetadataReader {
    fn read_candidates(
        &self,
        _node_id: &Id,
        candidate_volume_ids: &BTreeSet<Id>,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        if candidate_volume_ids.is_empty() {
            // Point reads cannot prove that no authority-only orphan or owner
            // exists outside Desired and local namespaces. Until a frozen,
            // bounded authoritative absence/listing port exists, local
            // emptiness must remain incomplete without issuing a meaningless
            // synthetic point read.
            return Ok(MetadataAuthorityCandidateInventory::Unavailable);
        }

        if self
            .in_flight
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Ok(MetadataAuthorityCandidateInventory::Unavailable);
        }

        let (reply, received) = mpsc::sync_channel(1);
        match self.requests.try_send(MetadataAuthorityReadRequest {
            candidate_volume_ids: candidate_volume_ids.clone(),
            reply,
        }) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) | Err(mpsc::TrySendError::Disconnected(_)) => {
                self.in_flight.store(false, Ordering::Release);
                return Ok(MetadataAuthorityCandidateInventory::Unavailable);
            }
        }

        // Preserve a small interval for the enclosing probe and coverage
        // aggregator to observe the result before the shared scan deadline.
        const DEADLINE_RESERVE: Duration = Duration::from_millis(10);
        let wait = context.remaining()?.saturating_sub(DEADLINE_RESERVE);
        if wait.is_zero() {
            return Ok(MetadataAuthorityCandidateInventory::Unavailable);
        }
        let result = match received.recv_timeout(wait) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) | Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Ok(MetadataAuthorityCandidateInventory::Unavailable);
            }
        };
        context.check_active()?;
        match result {
            MetadataAuthorityRead::Incomplete => {
                Ok(MetadataAuthorityCandidateInventory::Unavailable)
            }
            MetadataAuthorityRead::Complete { records } => {
                Ok(MetadataAuthorityCandidateInventory::Records(records))
            }
        }
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestAuthoritativeEmptyMetadataReader;

#[cfg(test)]
impl metadata_authority_reader_sealed::Sealed for TestAuthoritativeEmptyMetadataReader {}

#[cfg(test)]
impl MetadataAuthorityAbsenceReader for TestAuthoritativeEmptyMetadataReader {
    fn read_candidates(
        &self,
        _node_id: &Id,
        _candidate_volume_ids: &BTreeSet<Id>,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        Ok(MetadataAuthorityCandidateInventory::Records(BTreeMap::new()))
    }
}

#[cfg(test)]
#[derive(Debug)]
struct TestUnavailableMetadataReader;

#[cfg(test)]
impl metadata_authority_reader_sealed::Sealed for TestUnavailableMetadataReader {}

#[cfg(test)]
impl MetadataAuthorityAbsenceReader for TestUnavailableMetadataReader {
    fn read_candidates(
        &self,
        _node_id: &Id,
        _candidate_volume_ids: &BTreeSet<Id>,
        deadline: Instant,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
        debug_assert_eq!(deadline, context.deadline());
        context.check_active()?;
        Ok(MetadataAuthorityCandidateInventory::Unavailable)
    }
}

#[derive(Debug, Clone, Copy)]
struct ProbeLimits {
    state_entries: usize,
    os_entries: usize,
    recursion_depth: usize,
    process_cmdline_bytes: usize,
}

impl Default for ProbeLimits {
    fn default() -> Self {
        Self {
            // One current Cat may contribute a checkpoint/lock pair, four
            // data-directory levels, the three immutable authorization files,
            // control-only state, and bounded handoff publications. Keep the
            // cap proportional to the wire-level 1,024-Cat bound.
            state_entries: RUNTIME_V1_MAX_ASSIGNED_CATS * RUNTIME_STATE_ENTRIES_PER_ASSIGNED_CAT,
            os_entries: 131_072,
            recursion_depth: 16,
            process_cmdline_bytes: 64 * 1024,
        }
    }
}

#[derive(Clone)]
pub(crate) struct InstalledCleanSlateProbeConfig {
    pub state_directory: StateDirectory,
    pub cloud_hypervisor_binary: PathBuf,
    pub blockd_binary: PathBuf,
    pub guest_agent_binary: PathBuf,
    pub metering_cgroup_root: Option<PathBuf>,
    pub volume_inventory_authority: Arc<dyn RuntimeVolumeInventoryAuthority>,
    pub blob_store: Arc<dyn BlobStore>,
    pub root_provision_systemd: RootProvisionSystemdConfig,
}

impl std::fmt::Debug for InstalledCleanSlateProbeConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("InstalledCleanSlateProbeConfig")
            .field("state_directory", &self.state_directory)
            .field("cloud_hypervisor_binary", &self.cloud_hypervisor_binary)
            .field("blockd_binary", &self.blockd_binary)
            .field("guest_agent_binary", &self.guest_agent_binary)
            .field("metering_cgroup_root", &self.metering_cgroup_root)
            .field(
                "volume_inventory_authority",
                &"<provider-neutral authority>",
            )
            .field("root_provision_systemd", &self.root_provision_systemd)
            .finish()
    }
}

#[derive(Clone)]
struct ProbeConfig {
    state_directory: StateDirectory,
    checkpoint_directory: PathBuf,
    proc_root: PathBuf,
    systemd_cgroup_root: PathBuf,
    metering_cgroup_root: Option<PathBuf>,
    block_class_root: PathBuf,
    network_class_root: PathBuf,
    legacy_socket_root: PathBuf,
    cloud_hypervisor_binary: PathBuf,
    blockd_binary: PathBuf,
    guest_agent_binary: PathBuf,
    linux_sources_supported: bool,
    limits: ProbeLimits,
    root_process_port: Option<Arc<dyn RootProvisionProcessPort>>,
}

impl ProbeConfig {
    fn installed(config: InstalledCleanSlateProbeConfig) -> anyhow::Result<Self> {
        for (role, binary) in [
            ("Cloud Hypervisor", &config.cloud_hypervisor_binary),
            ("cats-blockd", &config.blockd_binary),
            ("cats-guest-agent", &config.guest_agent_binary),
        ] {
            anyhow::ensure!(
                binary.is_absolute(),
                "installed {role} binary path must be absolute: {}",
                binary.display()
            );
        }
        let checkpoint_directory = config.state_directory.path().join(CHECKPOINT_NAMESPACE);
        Ok(Self {
            state_directory: config.state_directory,
            checkpoint_directory,
            proc_root: PathBuf::from(DEFAULT_PROC_ROOT),
            systemd_cgroup_root: PathBuf::from(DEFAULT_SYSTEMD_CGROUP_ROOT),
            metering_cgroup_root: config.metering_cgroup_root,
            block_class_root: PathBuf::from(DEFAULT_BLOCK_CLASS_ROOT),
            network_class_root: PathBuf::from(DEFAULT_NETWORK_CLASS_ROOT),
            legacy_socket_root: PathBuf::from(DEFAULT_LEGACY_SOCKET_ROOT),
            cloud_hypervisor_binary: config.cloud_hypervisor_binary,
            blockd_binary: config.blockd_binary,
            guest_agent_binary: config.guest_agent_binary,
            linux_sources_supported: cfg!(target_os = "linux"),
            limits: ProbeLimits::default(),
            root_process_port: Some(Arc::new(PlatformSystemdRootProvisionProcessPort::platform(
                config.root_provision_systemd,
            ))),
        })
    }
}

pub(crate) fn installed_clean_slate_scanner(
    config: InstalledCleanSlateProbeConfig,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    let metadata_authority = Arc::new(PagedMetadataAuthorityReader::new(Arc::new(
        RuntimeVolumeInventoryPagePort::start(Arc::clone(&config.volume_inventory_authority))?,
    )));
    let blob_store = Arc::clone(&config.blob_store);
    let config = ProbeConfig::installed(config)?;
    let scanner =
        scanner_with_metadata_authority_and_blob(config, metadata_authority, Some(blob_store))?
            .with_key_ring_reader(Arc::new(InstalledRuntimeInventoryKeyRingReader));
    Ok(Arc::new(scanner))
}

#[cfg(test)]
pub(crate) struct TestCleanSlateProbeConfig {
    pub state_directory: StateDirectory,
    pub proc_root: PathBuf,
    pub systemd_cgroup_root: PathBuf,
    pub block_class_root: PathBuf,
    pub network_class_root: PathBuf,
    pub legacy_socket_root: PathBuf,
    pub cloud_hypervisor_binary: PathBuf,
    pub blockd_binary: PathBuf,
    pub guest_agent_binary: PathBuf,
}

#[cfg(test)]
pub(crate) fn clean_slate_scanner_for_test(
    config: TestCleanSlateProbeConfig,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    clean_slate_scanner_with_metadata_for_test(
        config,
        Arc::new(TestAuthoritativeEmptyMetadataReader),
        None,
    )
}

#[cfg(test)]
pub(crate) fn clean_slate_scanner_with_volume_authority_for_test(
    config: TestCleanSlateProbeConfig,
    authority: Arc<dyn VolumeDataAuthority>,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    clean_slate_scanner_with_metadata_for_test(
        config,
        Arc::new(VolumeDataAuthorityMetadataReader::start(authority)?),
        None,
    )
}

#[cfg(test)]
pub(crate) fn clean_slate_scanner_with_volume_authority_and_blob_for_test(
    config: TestCleanSlateProbeConfig,
    authority: Arc<dyn VolumeDataAuthority>,
    blob_store: Arc<dyn BlobStore>,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    clean_slate_scanner_with_metadata_for_test(
        config,
        Arc::new(VolumeDataAuthorityMetadataReader::start(authority)?),
        Some(blob_store),
    )
}

#[cfg(test)]
fn clean_slate_scanner_with_metadata_for_test(
    config: TestCleanSlateProbeConfig,
    metadata_authority: Arc<dyn MetadataAuthorityAbsenceReader>,
    blob_store: Option<Arc<dyn BlobStore>>,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    let checkpoint_directory = config.state_directory.path().join(CHECKPOINT_NAMESPACE);
    Ok(Arc::new(scanner_with_metadata_authority_and_blob(
        ProbeConfig {
            state_directory: config.state_directory,
            checkpoint_directory,
            proc_root: config.proc_root,
            systemd_cgroup_root: config.systemd_cgroup_root,
            metering_cgroup_root: None,
            block_class_root: config.block_class_root,
            network_class_root: config.network_class_root,
            legacy_socket_root: config.legacy_socket_root.clone(),
            cloud_hypervisor_binary: config.cloud_hypervisor_binary,
            blockd_binary: config.blockd_binary,
            guest_agent_binary: config.guest_agent_binary,
            linux_sources_supported: true,
            limits: ProbeLimits::default(),
            root_process_port: None,
        },
        metadata_authority,
        blob_store,
    )?))
}

#[cfg(test)]
fn scanner(config: ProbeConfig) -> anyhow::Result<CleanSlateInventoryScanner> {
    scanner_with_metadata_authority(config, Arc::new(TestAuthoritativeEmptyMetadataReader))
}

#[cfg(test)]
fn scanner_with_metadata_authority(
    config: ProbeConfig,
    metadata_authority: Arc<dyn MetadataAuthorityAbsenceReader>,
) -> anyhow::Result<CleanSlateInventoryScanner> {
    scanner_with_metadata_authority_and_blob(config, metadata_authority, None)
}

fn scanner_with_metadata_authority_and_blob(
    config: ProbeConfig,
    metadata_authority: Arc<dyn MetadataAuthorityAbsenceReader>,
    blob_store: Option<Arc<dyn BlobStore>>,
) -> anyhow::Result<CleanSlateInventoryScanner> {
    let state = config.state_directory.clone();
    let process_paths = ProcessPaths {
        root: config.proc_root.clone(),
        binaries: vec![
            config.cloud_hypervisor_binary.clone(),
            config.blockd_binary.clone(),
            config.guest_agent_binary.clone(),
        ],
        supported: config.linux_sources_supported,
        limits: config.limits,
    };
    let probes: Vec<Arc<dyn InventoryAbsenceProbe>> = vec![
        Arc::new(RuntimeCheckpointProbe {
            state_directory: state.clone(),
            reject_legacy_root: true,
            limits: config.limits,
        }),
        Arc::new(SystemdProbe {
            systemd_root: config.systemd_cgroup_root.clone(),
            metering_root: config.metering_cgroup_root.clone(),
            supported: config.linux_sources_supported,
            limits: config.limits,
        }),
        Arc::new(ProcessProbe {
            paths: process_paths.clone(),
        }),
        Arc::new(ControlSocketProbe {
            state_directory: state.clone(),
            legacy_socket_root: config.legacy_socket_root.clone(),
            limits: config.limits,
        }),
        Arc::new(BlockFrontendProbe {
            state_directory: state.clone(),
            block_class_root: config.block_class_root,
            legacy_socket_root: config.legacy_socket_root.clone(),
            supported: config.linux_sources_supported,
            limits: config.limits,
        }),
        Arc::new(NetworkProbe {
            state_directory: state.clone(),
            network_class_root: config.network_class_root,
            supported: config.linux_sources_supported,
            limits: config.limits,
        }),
        Arc::new(AuthorizedBlockdDataProbe {
            state_directory: state.clone(),
            reject_legacy_root: true,
            limits: config.limits,
        }),
        Arc::new(StateNamespaceProbe {
            source: InventorySource::PendingPack,
            state_directory: state.clone(),
            namespace: PENDING_PACK_NAMESPACE,
            reject_legacy_root: true,
            limits: config.limits,
        }),
        Arc::new(StateNamespaceProbe {
            source: InventorySource::WarmSnapshot,
            state_directory: state.clone(),
            namespace: WARM_SNAPSHOT_NAMESPACE,
            reject_legacy_root: true,
            limits: config.limits,
        }),
        Arc::new(MetadataStoreProbe {
            state_directory: state.clone(),
            authority: metadata_authority,
            limits: config.limits,
        }),
        Arc::new(GuestMountProbe {
            state_directory: state,
            legacy_socket_root: config.legacy_socket_root.clone(),
            guest_process_paths: ProcessPaths {
                root: config.proc_root,
                binaries: vec![config.guest_agent_binary],
                supported: config.linux_sources_supported,
                limits: config.limits,
            },
            limits: config.limits,
        }),
    ];
    match blob_store {
        Some(blob_store) if config.root_process_port.is_some() => {
            let executable_path =
                HostPath::new(config.blockd_binary.to_string_lossy().into_owned())
                    .context("installed blockd binary is not a canonical HostPath")?;
            let bridge = Arc::new(PlatformRootProcessInventoryBridge {
                port: config.root_process_port.expect("presence checked above"),
                executable_path,
                state_directory: config.state_directory,
                process_paths,
                systemd_root: config.systemd_cgroup_root,
                metering_root: config.metering_cgroup_root,
                legacy_socket_root: config.legacy_socket_root,
                limits: config.limits,
            });
            CleanSlateInventoryScanner::new_with_blob_and_root_process_bridge(
                config.checkpoint_directory,
                probes,
                blob_store,
                bridge,
            )
        }
        Some(blob_store) => CleanSlateInventoryScanner::new_with_blob(
            config.checkpoint_directory,
            probes,
            blob_store,
        ),
        None => CleanSlateInventoryScanner::new(config.checkpoint_directory, probes),
    }
    .map_err(anyhow::Error::from)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProbeFact {
    Empty,
    Present,
    Unavailable,
}

fn finish_absence(
    source: InventorySource,
    facts: &[ProbeFact],
) -> anyhow::Result<InventoryAbsence> {
    if facts.contains(&ProbeFact::Present) {
        bail!("clean-slate {source:?} residue is present");
    }
    if facts.contains(&ProbeFact::Unavailable) {
        Ok(InventoryAbsence::Unavailable)
    } else {
        Ok(InventoryAbsence::Empty)
    }
}

struct RuntimeCheckpointProbe {
    state_directory: StateDirectory,
    reject_legacy_root: bool,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for RuntimeCheckpointProbe {}

impl InventoryAbsenceProbe for RuntimeCheckpointProbe {
    fn source(&self) -> InventorySource {
        InventorySource::Checkpoint
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        if self.reject_legacy_root {
            let facts = [LEGACY_LEDGER, LEGACY_CATS_DIRECTORY]
                .into_iter()
                .map(|name| state_entry_fact(&root, name, context))
                .collect::<anyhow::Result<Vec<_>>>()?;
            match finish_absence(InventorySource::Checkpoint, &facts)? {
                InventoryAbsence::Empty => {}
                InventoryAbsence::Unavailable => return Ok(InventoryAbsence::Unavailable),
                _ => unreachable!("legacy facts only project empty or unavailable"),
            }
        }
        scan_runtime_checkpoints(&root, context, self.limits)
    }
}

fn scan_runtime_checkpoints(
    root: &File,
    context: &RuntimeInventoryScanContext,
    limits: ProbeLimits,
) -> anyhow::Result<InventoryAbsence> {
    let directory = match open_state_namespace(root, CHECKPOINT_NAMESPACE)? {
        ManagedDirectory::Missing => return Ok(InventoryAbsence::Empty),
        ManagedDirectory::Unavailable => return Ok(InventoryAbsence::Unavailable),
        ManagedDirectory::Open(directory) => directory,
    };
    let mut budget = limits.state_entries;
    let Some(entries) = strict_checkpoint_directory_entries(&directory, &mut budget, context)?
    else {
        return Ok(InventoryAbsence::Unavailable);
    };
    if entries.is_empty() {
        return Ok(InventoryAbsence::Empty);
    }

    let desired_by_target = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}.checkpoint.json", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_lock = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}.checkpoint.lock", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_temp = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!(".cat-{}.checkpoint.tmp", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!("cat-{}.release-rejection.json", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection_temp = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!(".cat-{}.release-rejection.tmp", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();

    let mut checkpoints = BTreeMap::new();
    let mut release_rejections = BTreeMap::<Id, (DefiniteReleaseRejection, PathBuf)>::new();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            bail!("checkpoint namespace contains a non-UTF-8 entry")
        };
        if desired_by_lock.contains_key(name) {
            validate_strict_regular_entry(&entry, root, 0o600)?;
            continue;
        }
        if desired_by_temp.contains_key(name) {
            // A checkpoint temp is never inventory evidence. Its writer (or a
            // later exact writer recovery) must settle it before a full scan.
            return Ok(InventoryAbsence::Unavailable);
        }
        if desired_by_release_rejection_temp.contains_key(name) {
            // A durable temp entry proves publication was interrupted after
            // Control answered. It is intentionally preserved and blocks
            // both observation and effect replay.
            let _ = read_release_rejection_publication_at(&directory, &entry, root, context)?;
            return Ok(InventoryAbsence::Unavailable);
        }
        if let Some(desired) = desired_by_release_rejection.get(name) {
            if entry.metadata.st_nlink != 1 {
                let _ = read_release_rejection_publication_at(&directory, &entry, root, context)?;
                return Ok(InventoryAbsence::Unavailable);
            }
            let Some(bytes) = read_strict_regular_at(
                &directory,
                &entry,
                root,
                RELEASE_REJECTION_MAX_BYTES,
                context,
            )?
            else {
                return Ok(InventoryAbsence::Unavailable);
            };
            let diagnostic_path = PathBuf::from(CHECKPOINT_NAMESPACE).join(name);
            let marker = decode_definite_release_rejection(&bytes, &diagnostic_path)?;
            anyhow::ensure!(
                marker.cat_id == desired.cat_id,
                "release rejection filename and Cat identity disagree"
            );
            anyhow::ensure!(
                release_rejections
                    .insert(desired.cat_id.clone(), (marker, diagnostic_path))
                    .is_none(),
                "release rejection inventory duplicated one Cat"
            );
            continue;
        }
        let Some(desired) = desired_by_target.get(name) else {
            if is_release_rejection_entry(name) {
                return Ok(InventoryAbsence::Unavailable);
            }
            bail!("checkpoint namespace retains foreign entry {name}")
        };
        let Some(bytes) = read_strict_regular_at(
            &directory,
            &entry,
            root,
            RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
            context,
        )?
        else {
            return Ok(InventoryAbsence::Unavailable);
        };
        let checkpoint =
            decode_runtime_checkpoint(&bytes).context("decode scanned Runtime checkpoint")?;
        anyhow::ensure!(
            checkpoint.cat_id == desired.cat_id,
            "checkpoint filename and Cat identity disagree"
        );
        let binding = checkpoint_binding(desired, &checkpoint)?;
        anyhow::ensure!(
            checkpoints
                .insert(
                    desired.cat_id.clone(),
                    RuntimeCheckpointInventoryEvidence {
                        checkpoint,
                        binding,
                        definite_release_rejected: false,
                    },
                )
                .is_none(),
            "checkpoint inventory duplicated one Cat"
        );
    }
    for (cat_id, (marker, path)) in release_rejections {
        let evidence = checkpoints
            .get_mut(&cat_id)
            .context("definite release rejection lacks its Runtime checkpoint")?;
        validate_definite_release_rejection(&marker, &evidence.checkpoint, &path)?;
        evidence.definite_release_rejected = true;
    }
    if checkpoints.is_empty() {
        Ok(InventoryAbsence::Empty)
    } else {
        Ok(InventoryAbsence::RuntimeCheckpoints(checkpoints))
    }
}

fn checkpoint_binding(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
) -> anyhow::Result<DesiredCheckpointBinding> {
    anyhow::ensure!(
        checkpoint.cat_id == desired.cat_id && checkpoint.node_id == desired.placement.node_id,
        "checkpoint is not attributable to the current same-Node Desired"
    );
    if checkpoint.desired_revision == desired.desired_revision {
        anyhow::ensure!(
            checkpoint.spec_digest == desired.spec_digest
                && checkpoint.placement_epoch == desired.placement.placement_epoch,
            "same-revision checkpoint conflicts with current Desired"
        );
        return Ok(DesiredCheckpointBinding::Current);
    }
    anyhow::ensure!(
        checkpoint.desired_revision < desired.desired_revision
            && checkpoint.placement_epoch <= desired.placement.placement_epoch,
        "checkpoint revision or placement is ahead of current Desired"
    );
    Ok(DesiredCheckpointBinding::Superseded)
}

/// Classify one publication or superseded-checkpoint recovery candidate
/// without mutating the filesystem. Every sibling is validated before a
/// candidate is returned, so a recoverable entry cannot hide foreign residue.
pub(crate) fn classify_local_publication_recovery(
    context: &RuntimePreScanRecoveryContext,
) -> anyhow::Result<LocalPublicationRecoveryEvidence> {
    context.check_active()?;
    let scan_context = context.inventory_context();
    let Some(root) = clone_state_root(context.state_directory())? else {
        return Ok(LocalPublicationRecoveryEvidence::None);
    };
    let directory = match open_state_namespace(&root, CHECKPOINT_NAMESPACE)? {
        ManagedDirectory::Missing | ManagedDirectory::Unavailable => {
            return Ok(LocalPublicationRecoveryEvidence::None)
        }
        ManagedDirectory::Open(directory) => directory,
    };
    let mut budget = ProbeLimits::default().state_entries;
    let Some(entries) =
        strict_checkpoint_directory_entries(&directory, &mut budget, &scan_context)?
    else {
        return Ok(LocalPublicationRecoveryEvidence::None);
    };
    let desired_by_target = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}.checkpoint.json", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_lock = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}.checkpoint.lock", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_temp = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!(".cat-{}.checkpoint.tmp", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!("cat-{}.release-rejection.json", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection_temp = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!(".cat-{}.release-rejection.tmp", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut temps = BTreeSet::new();
    let mut checkpoints = BTreeMap::new();
    let mut all_checkpoints = BTreeMap::new();
    let mut release_rejections = BTreeMap::<Id, (DefiniteReleaseRejection, PathBuf)>::new();
    let mut release_rejection_temps = BTreeMap::<Id, (DefiniteReleaseRejection, PathBuf)>::new();
    let mut superseded = BTreeSet::new();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            bail!("checkpoint namespace contains a non-UTF-8 entry")
        };
        if desired_by_lock.contains_key(name) {
            validate_strict_regular_entry(&entry, &root, 0o600)?;
            continue;
        }
        if let Some(desired) = desired_by_temp.get(name) {
            validate_strict_regular_entry(&entry, &root, 0o600)?;
            temps.insert(desired.cat_id.clone());
            continue;
        }
        if let Some(desired) = desired_by_release_rejection_temp.get(name) {
            let Some(bytes) =
                read_release_rejection_publication_at(&directory, &entry, &root, &scan_context)?
            else {
                return Ok(LocalPublicationRecoveryEvidence::None);
            };
            let diagnostic_path = PathBuf::from(CHECKPOINT_NAMESPACE).join(name);
            let Ok(marker) = decode_definite_release_rejection(&bytes, &diagnostic_path) else {
                return Ok(LocalPublicationRecoveryEvidence::None);
            };
            if marker.cat_id != desired.cat_id
                || release_rejection_temps
                    .insert(desired.cat_id.clone(), (marker, diagnostic_path))
                    .is_some()
            {
                return Ok(LocalPublicationRecoveryEvidence::None);
            }
            continue;
        }
        if let Some(desired) = desired_by_release_rejection.get(name) {
            let Some(bytes) =
                read_release_rejection_publication_at(&directory, &entry, &root, &scan_context)?
            else {
                return Ok(LocalPublicationRecoveryEvidence::None);
            };
            let diagnostic_path = PathBuf::from(CHECKPOINT_NAMESPACE).join(name);
            let Ok(marker) = decode_definite_release_rejection(&bytes, &diagnostic_path) else {
                return Ok(LocalPublicationRecoveryEvidence::None);
            };
            if marker.cat_id != desired.cat_id
                || release_rejections
                    .insert(desired.cat_id.clone(), (marker, diagnostic_path))
                    .is_some()
            {
                return Ok(LocalPublicationRecoveryEvidence::None);
            }
            continue;
        }
        let Some(desired) = desired_by_target.get(name) else {
            if is_release_rejection_entry(name) {
                return Ok(LocalPublicationRecoveryEvidence::None);
            }
            bail!("checkpoint namespace retains foreign entry {name}")
        };
        let Some(bytes) = read_strict_regular_at(
            &directory,
            &entry,
            &root,
            RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
            &scan_context,
        )?
        else {
            return Ok(LocalPublicationRecoveryEvidence::None);
        };
        let checkpoint =
            decode_runtime_checkpoint(&bytes).context("decode recovery Runtime checkpoint")?;
        anyhow::ensure!(
            checkpoint.cat_id == desired.cat_id,
            "checkpoint filename and Cat identity disagree"
        );
        anyhow::ensure!(
            all_checkpoints
                .insert(desired.cat_id.clone(), checkpoint.clone())
                .is_none(),
            "checkpoint recovery inventory duplicated one Cat"
        );
        if checkpoint.desired_revision != desired.desired_revision
            || checkpoint.spec_digest != desired.spec_digest
            || checkpoint.node_id != desired.placement.node_id
            || checkpoint.placement_epoch != desired.placement.placement_epoch
        {
            superseded.insert(desired.cat_id.clone());
            continue;
        }
        anyhow::ensure!(
            checkpoints
                .insert(desired.cat_id.clone(), checkpoint)
                .is_none(),
            "checkpoint recovery inventory duplicated one Cat"
        );
    }
    for (cat_id, (marker, path)) in &release_rejections {
        let Some(checkpoint) = all_checkpoints.get(cat_id) else {
            return Ok(LocalPublicationRecoveryEvidence::None);
        };
        if validate_definite_release_rejection(marker, checkpoint, path).is_err() {
            return Ok(LocalPublicationRecoveryEvidence::None);
        }
    }
    for (cat_id, (marker, path)) in &release_rejection_temps {
        let Some(checkpoint) = all_checkpoints.get(cat_id) else {
            return Ok(LocalPublicationRecoveryEvidence::None);
        };
        if validate_definite_release_rejection(marker, checkpoint, path).is_err() {
            return Ok(LocalPublicationRecoveryEvidence::None);
        }
    }
    if temps.iter().any(|cat_id| {
        release_rejections.contains_key(cat_id) || release_rejection_temps.contains_key(cat_id)
    }) {
        // Opening a same-Cat checkpoint store owns and removes its generic
        // checkpoint temp. Never do that while either form of durable release
        // rejection evidence is present for that Cat.
        return Ok(LocalPublicationRecoveryEvidence::None);
    }
    if let Some(cat_id) = release_rejection_temps.keys().next().cloned() {
        return Ok(LocalPublicationRecoveryEvidence::DefiniteReleaseRejectionTemp { cat_id });
    }
    if let Some(cat_id) = temps.iter().next().cloned() {
        return Ok(LocalPublicationRecoveryEvidence::CheckpointTemp { cat_id });
    }

    // Stable target durability confirmation is deliberately last among local
    // publication work. A target fsync is not allowed to hide a recoverable
    // checkpoint or authorized-blockd temp for another Cat on the same Node.
    let data = scan_authorized_blockd_data(
        &root,
        context.state_directory().path(),
        &scan_context,
        ProbeLimits::default(),
    )?;
    if data.handoff_temps.len() == 1
        && data.evidence.len() + data.handoff_temps.len() == data.leaf_count
    {
        let (cat_id, kind, authorized) = data.handoff_temps[0].clone();
        return Ok(LocalPublicationRecoveryEvidence::ServingHandoffTemp {
            cat_id,
            kind,
            authorized: Box::new(authorized),
        });
    }
    if !data.handoff_temps.is_empty() {
        return Ok(LocalPublicationRecoveryEvidence::None);
    }
    let authorized_recovery = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .filter_map(|desired| {
            let checkpoint = checkpoints.get(&desired.cat_id)?;
            (matches!(
                checkpoint.step,
                cats_api::runtime_reconciliation::ReconcileStep::AcquireVolume { .. }
            ) && !data.evidence.contains_key(&desired.cat_id))
            .then(|| desired.cat_id.clone())
        })
        .collect::<BTreeSet<_>>();
    if let Some(cat_id) = authorized_recovery.into_iter().next() {
        return Ok(LocalPublicationRecoveryEvidence::AuthorizedBlockd { cat_id });
    }
    if !data.complete {
        // An unsupported, racing or foreign authorized publication remains
        // unstable evidence even when no current Acquire can recover it.
        // Do not let a stable rejection-target fsync jump ahead of it.
        return Ok(LocalPublicationRecoveryEvidence::None);
    }
    if let Some(cat_id) = release_rejections.keys().next().cloned() {
        return Ok(LocalPublicationRecoveryEvidence::DefiniteReleaseRejectionTarget { cat_id });
    }
    if let Some(cat_id) = superseded.into_iter().next() {
        return Ok(LocalPublicationRecoveryEvidence::SupersededCheckpoint { cat_id });
    }
    Ok(LocalPublicationRecoveryEvidence::None)
}

struct AuthorizedBlockdDataProbe {
    state_directory: StateDirectory,
    reject_legacy_root: bool,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for AuthorizedBlockdDataProbe {}

impl InventoryAbsenceProbe for AuthorizedBlockdDataProbe {
    fn source(&self) -> InventorySource {
        InventorySource::DataDirectory
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        if self.reject_legacy_root {
            let facts = [LEGACY_LEDGER, LEGACY_CATS_DIRECTORY]
                .into_iter()
                .map(|name| state_entry_fact(&root, name, context))
                .collect::<anyhow::Result<Vec<_>>>()?;
            match finish_absence(InventorySource::DataDirectory, &facts)? {
                InventoryAbsence::Empty => {}
                InventoryAbsence::Unavailable => return Ok(InventoryAbsence::Unavailable),
                _ => unreachable!("legacy facts only project empty or unavailable"),
            }
        }
        let scan =
            scan_authorized_blockd_data(&root, self.state_directory.path(), context, self.limits)?;
        if !scan.complete {
            return Ok(InventoryAbsence::Unavailable);
        }
        if scan.evidence.is_empty() {
            Ok(InventoryAbsence::Empty)
        } else {
            Ok(InventoryAbsence::AuthorizedBlockd(scan.evidence))
        }
    }
}

struct AuthorizedBlockdDataScan {
    evidence: BTreeMap<Id, AuthorizedBlockdInventoryEvidence>,
    candidate_volume_ids: BTreeSet<Id>,
    leaf_count: usize,
    complete: bool,
    handoff_temps: Vec<(Id, ServingHandoffTempKind, AuthorizedBlockdCheckpoint)>,
}

/// One immutable checkpoint-namespace join for the whole data-directory
/// scan. Re-enumerating this namespace once per Cat is both racy and
/// quadratic; this index validates every name and target exactly once, then
/// all handoff leaves use an in-memory Cat lookup from the same snapshot.
fn snapshot_runtime_checkpoints_for_handoff(
    root: &File,
    context: &RuntimeInventoryScanContext,
    limit: usize,
) -> anyhow::Result<Option<BTreeMap<Id, RuntimeCheckpoint>>> {
    let directory = match open_state_namespace(root, CHECKPOINT_NAMESPACE)? {
        ManagedDirectory::Open(directory) => directory,
        ManagedDirectory::Missing | ManagedDirectory::Unavailable => return Ok(None),
    };
    let mut budget = limit;
    let Some(entries) = strict_checkpoint_directory_entries(&directory, &mut budget, context)?
    else {
        return Ok(None);
    };
    let desired_by_target = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}.checkpoint.json", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let desired_locks = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| format!("cat-{}.checkpoint.lock", desired.cat_id))
        .collect::<BTreeSet<_>>();
    let desired_checkpoint_temps = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| format!(".cat-{}.checkpoint.tmp", desired.cat_id))
        .collect::<BTreeSet<_>>();
    let desired_by_release_rejection = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!("cat-{}.release-rejection.json", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection_temp = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| {
            (
                format!(".cat-{}.release-rejection.tmp", desired.cat_id),
                desired,
            )
        })
        .collect::<BTreeMap<_, _>>();
    let mut checkpoints = BTreeMap::new();
    let mut release_rejections = BTreeMap::<Id, (DefiniteReleaseRejection, PathBuf)>::new();
    for entry in entries {
        let Some(name) = entry.name.to_str() else {
            bail!("checkpoint namespace contains a non-UTF-8 entry")
        };
        if desired_locks.contains(name) {
            validate_strict_regular_entry(&entry, root, 0o600)?;
            continue;
        }
        if desired_checkpoint_temps.contains(name) {
            // A generic checkpoint temp has its own serialized pre-scan
            // recovery. It cannot share a handoff snapshot.
            return Ok(None);
        }
        if desired_by_release_rejection_temp.contains_key(name) {
            // Validate the bounded typed publication before withholding the
            // snapshot. A safe temp is still an interrupted publication and
            // cannot coexist with a handoff join; unsafe/corrupt residue is a
            // hard scan error and is never normalized to ordinary absence.
            let _ = read_release_rejection_publication_at(&directory, &entry, root, context)?;
            return Ok(None);
        }
        if let Some(desired) = desired_by_release_rejection.get(name) {
            if entry.metadata.st_nlink != 1 {
                // During the no-replace link publication both deterministic
                // names refer to one inode. Preserve that bounded window for
                // serialized recovery and refuse to form a mixed snapshot.
                let _ = read_release_rejection_publication_at(&directory, &entry, root, context)?;
                return Ok(None);
            }
            let Some(bytes) = read_strict_regular_at(
                &directory,
                &entry,
                root,
                RELEASE_REJECTION_MAX_BYTES,
                context,
            )?
            else {
                return Ok(None);
            };
            let diagnostic_path = PathBuf::from(CHECKPOINT_NAMESPACE).join(name);
            let marker = decode_definite_release_rejection(&bytes, &diagnostic_path)?;
            anyhow::ensure!(
                marker.cat_id == desired.cat_id,
                "handoff index release rejection filename and Cat identity disagree"
            );
            anyhow::ensure!(
                release_rejections
                    .insert(desired.cat_id.clone(), (marker, diagnostic_path))
                    .is_none(),
                "handoff index contains duplicate release rejections for one Cat"
            );
            continue;
        }
        let Some(desired) = desired_by_target.get(name) else {
            bail!("checkpoint namespace retains foreign entry {name}")
        };
        let Some(bytes) = read_strict_regular_at(
            &directory,
            &entry,
            root,
            RUNTIME_CHECKPOINT_MAX_WIRE_BYTES,
            context,
        )?
        else {
            return Ok(None);
        };
        let checkpoint =
            decode_runtime_checkpoint(&bytes).context("decode handoff-index Runtime checkpoint")?;
        anyhow::ensure!(
            checkpoint.cat_id == desired.cat_id,
            "handoff index checkpoint filename and Cat identity disagree"
        );
        anyhow::ensure!(
            checkpoints
                .insert(desired.cat_id.clone(), checkpoint)
                .is_none(),
            "handoff index contains duplicate Runtime checkpoints for one Cat"
        );
    }
    for (cat_id, (marker, path)) in release_rejections {
        let checkpoint = checkpoints
            .get(&cat_id)
            .context("handoff index release rejection lacks its Runtime checkpoint")?;
        validate_definite_release_rejection(&marker, checkpoint, &path)?;
    }
    anyhow::ensure!(
        checkpoints.len() <= RUNTIME_V1_MAX_ASSIGNED_CATS,
        "handoff checkpoint index exceeds the assigned-Cat cap"
    );
    Ok(Some(checkpoints))
}

fn scan_authorized_blockd_data(
    root: &File,
    state_path: &Path,
    context: &RuntimeInventoryScanContext,
    limits: ProbeLimits,
) -> anyhow::Result<AuthorizedBlockdDataScan> {
    let directory = match open_state_namespace(root, DATA_NAMESPACE)? {
        ManagedDirectory::Missing => {
            return Ok(AuthorizedBlockdDataScan {
                evidence: BTreeMap::new(),
                candidate_volume_ids: BTreeSet::new(),
                leaf_count: 0,
                complete: true,
                handoff_temps: Vec::new(),
            })
        }
        ManagedDirectory::Unavailable => {
            return Ok(AuthorizedBlockdDataScan {
                evidence: BTreeMap::new(),
                candidate_volume_ids: BTreeSet::new(),
                leaf_count: 0,
                complete: false,
                handoff_temps: Vec::new(),
            })
        }
        ManagedDirectory::Open(directory) => directory,
    };
    let desired_by_directory = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (format!("cat-{}", desired.cat_id), desired))
        .collect::<BTreeMap<_, _>>();
    let handoff_checkpoints =
        snapshot_runtime_checkpoints_for_handoff(root, context, limits.state_entries)?;
    let mut budget = limits.state_entries;
    let Some(cat_entries) = strict_directory_entries(&directory, &mut budget, context)? else {
        return Ok(AuthorizedBlockdDataScan {
            evidence: BTreeMap::new(),
            candidate_volume_ids: BTreeSet::new(),
            leaf_count: 0,
            complete: false,
            handoff_temps: Vec::new(),
        });
    };
    let mut scan = AuthorizedBlockdDataScan {
        evidence: BTreeMap::new(),
        candidate_volume_ids: BTreeSet::new(),
        leaf_count: 0,
        complete: true,
        handoff_temps: Vec::new(),
    };

    for cat_entry in cat_entries {
        let Some(cat_name) = cat_entry.name.to_str() else {
            bail!("authorized blockd data namespace contains non-UTF-8 Cat entry")
        };
        let Some(desired) = desired_by_directory.get(cat_name) else {
            bail!("authorized blockd data namespace retains foreign Cat {cat_name}")
        };
        scan.leaf_count += 1;

        let Some(cat_directory) =
            open_exact_only_child_directory(&directory, &cat_entry, root, context)?
        else {
            scan.complete = false;
            continue;
        };
        let Some((volume_name, volume_directory)) =
            descend_only_directory(&cat_directory, root, &mut budget, context, "volume")?
        else {
            scan.complete = false;
            continue;
        };
        let Some((attachment_name, attachment_directory)) =
            descend_only_directory(&volume_directory, root, &mut budget, context, "attachment")?
        else {
            scan.complete = false;
            continue;
        };
        let Some((epoch_name, epoch_directory)) =
            descend_only_directory(&attachment_directory, root, &mut budget, context, "epoch")?
        else {
            scan.complete = false;
            continue;
        };
        let Some(leaf_entries) = strict_directory_entries(&epoch_directory, &mut budget, context)?
        else {
            scan.complete = false;
            continue;
        };
        let by_name = leaf_entries
            .into_iter()
            .map(|entry| {
                let name = entry
                    .name
                    .to_str()
                    .context("authorized blockd leaf contains non-UTF-8 entry")?
                    .to_owned();
                Ok((name, entry))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
        let has_unvalidated_handoff_artifact = by_name
            .keys()
            .any(|name| is_serving_handoff_artifact_name(name));
        let allowed = [
            IDENTITY_FILE,
            IDENTITY_TEMP,
            AUTHORIZED_SERVING_FILE,
            AUTHORIZED_SERVING_TEMP,
            LAUNCH_CHECKPOINT_FILE,
            LAUNCH_CHECKPOINT_TEMP,
            "root-provision.sock",
            "cache.data",
            ".cache.data.init",
            "dirty.bitmap",
            ".dirty.bitmap.init",
            "pending-packs",
        ];
        if let Some(foreign) = by_name.keys().find(|name| {
            !allowed.contains(&name.as_str()) && !is_serving_handoff_artifact_name(name)
        }) {
            bail!("authorized blockd leaf retains foreign entry {foreign}")
        }
        if [
            IDENTITY_TEMP,
            AUTHORIZED_SERVING_TEMP,
            LAUNCH_CHECKPOINT_TEMP,
            ".cache.data.init",
            ".dirty.bitmap.init",
        ]
        .into_iter()
        .any(|name| by_name.contains_key(name))
            || [
                IDENTITY_FILE,
                AUTHORIZED_SERVING_FILE,
                LAUNCH_CHECKPOINT_FILE,
            ]
            .into_iter()
            .any(|name| !by_name.contains_key(name))
        {
            scan.complete = false;
            continue;
        }
        if let Some(socket) = by_name.get("root-provision.sock") {
            let root_metadata = root.metadata().context("inspect retained state root")?;
            anyhow::ensure!(
                socket.metadata.st_mode & libc::S_IFMT == libc::S_IFSOCK
                    && socket.metadata.st_nlink == 1
                    && socket.metadata.st_uid == root_metadata.uid()
                    && socket.metadata.st_mode & 0o077 == 0,
                "root-provision control socket has unsafe type or identity"
            );
        }

        let Some(identity_bytes) = read_strict_regular_at(
            &epoch_directory,
            &by_name[IDENTITY_FILE],
            root,
            MAX_IDENTITY_BYTES,
            context,
        )?
        else {
            scan.complete = false;
            continue;
        };
        let Some(attachment_bytes) = read_strict_regular_at(
            &epoch_directory,
            &by_name[AUTHORIZED_SERVING_FILE],
            root,
            MAX_AUTHORIZED_SERVING_BYTES,
            context,
        )?
        else {
            scan.complete = false;
            continue;
        };
        let Some(checkpoint_bytes) = read_strict_regular_at(
            &epoch_directory,
            &by_name[LAUNCH_CHECKPOINT_FILE],
            root,
            MAX_LAUNCH_CHECKPOINT_BYTES,
            context,
        )?
        else {
            scan.complete = false;
            continue;
        };

        let identity: AttachmentLineageIdentity =
            decode_exact_json(&identity_bytes, "attachment identity")?;
        let attachment: AuthorizedServingAttachment =
            decode_exact_json(&attachment_bytes, "authorized serving attachment")?;
        let checkpoint: AuthorizedBlockdCheckpoint =
            decode_exact_json(&checkpoint_bytes, "authorized blockd checkpoint")?;
        validate_authorized_blockd_checkpoint(&checkpoint)?;
        anyhow::ensure!(
            identity == attachment.identity && attachment == checkpoint.attachment,
            "authorized blockd files do not form one exact lineage"
        );
        let control_files = ["cache.data", "dirty.bitmap", "pending-packs"];
        let present_control_files = control_files
            .into_iter()
            .filter(|name| by_name.contains_key(*name))
            .count();
        let control_state = if present_control_files == 0 {
            AuthorizedBlockdControlState::NotStarted
        } else if present_control_files == control_files.len() {
            let root_metadata = root.metadata().context("inspect retained state root")?;
            let cache = &by_name["cache.data"].metadata;
            anyhow::ensure!(
                cache.st_mode & libc::S_IFMT == libc::S_IFREG
                    && cache.st_nlink == 1
                    && cache.st_uid == root_metadata.uid()
                    && cache.st_mode & 0o777 == 0o600
                    && u64::try_from(cache.st_size).ok() == Some(attachment.size_bytes),
                "root-provision control-only cache has unsafe identity or size"
            );
            if inspect_empty_dirty_bitmap_at(
                &epoch_directory,
                &by_name["dirty.bitmap"],
                root,
                attachment.size_bytes,
                context,
            )?
            .is_none()
            {
                scan.complete = false;
                continue;
            }
            let Some(pending) =
                open_strict_child_directory(&epoch_directory, &by_name["pending-packs"], root)?
            else {
                scan.complete = false;
                continue;
            };
            let Some(pending_entries) = strict_directory_entries(&pending, &mut budget, context)?
            else {
                scan.complete = false;
                continue;
            };
            anyhow::ensure!(
                pending_entries.is_empty(),
                "root-provision control-only blockd retains a pending pack"
            );
            AuthorizedBlockdControlState::ExactControlOnlyEmpty
        } else {
            scan.complete = false;
            continue;
        };
        let binding = authorized_blockd_binding(desired, &checkpoint)?;
        anyhow::ensure!(
            cat_name == format!("cat-{}", checkpoint.desired.cat_id)
                && volume_name == format!("volume-{}", identity.volume_id)
                && attachment_name == format!("attachment-{}", identity.attachment_id)
                && epoch_name == format!("epoch-{}", identity.attachment_epoch.get()),
            "authorized blockd physical path and checkpoint identity disagree"
        );
        let data_directory_path = state_path
            .join(DATA_NAMESPACE)
            .join(cat_name)
            .join(&volume_name)
            .join(&attachment_name)
            .join(&epoch_name);
        let data_directory = HostPath::new(
            data_directory_path
                .to_str()
                .context("authorized blockd data directory is not UTF-8")?
                .to_owned(),
        )
        .context("authorized blockd data directory is not a HostPath")?;
        let mut retained_root_process = None;
        if !has_unvalidated_handoff_artifact {
            if let Some(runtime_checkpoint) = handoff_checkpoints
                .as_ref()
                .and_then(|checkpoints| checkpoints.get(&desired.cat_id))
            {
                anyhow::ensure!(
                    !matches!(
                        &runtime_checkpoint.step,
                        ReconcileStep::PrepareDevice {
                            serving_authority,
                            ..
                        } if matches!(
                            serving_authority.as_ref(),
                            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
                        )
                    ),
                    "after-root-provision checkpoint lacks its durable handoff artifacts"
                );
            }
        }
        if has_unvalidated_handoff_artifact {
            let Some(runtime_checkpoint) = handoff_checkpoints
                .as_ref()
                .and_then(|checkpoints| checkpoints.get(&desired.cat_id))
                .cloned()
            else {
                scan.complete = false;
                continue;
            };
            let provision_transition_id = match &runtime_checkpoint.step {
                ReconcileStep::ProvisionRootImage {
                    provision_transition_id,
                    ..
                } => provision_transition_id.clone(),
                ReconcileStep::PrepareDevice {
                    serving_authority, ..
                } => {
                    let cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision {
                        handoff,
                    } = serving_authority.as_ref()
                    else {
                        bail!(
                            "direct authorized attachment cannot retain root-provision handoff artifacts"
                        )
                    };
                    let Some(entry) = by_name.get(SERVING_HANDOFF_RECORD_FILE) else {
                        bail!("after-root-provision checkpoint lacks its sealed handoff record")
                    };
                    let Some(record_file) = read_scanned_handoff_artifact(
                        &epoch_directory,
                        entry,
                        root,
                        data_directory_path.join(SERVING_HANDOFF_RECORD_FILE),
                        SERVING_HANDOFF_RECORD_MAX_BYTES,
                        context,
                    )? else {
                        scan.complete = false;
                        continue;
                    };
                    let record = super::serving_handoff::decode_serving_handoff_record(
                        &record_file.bytes,
                    )?;
                    anyhow::ensure!(
                        record_file.path == handoff.record.path
                            && record_file.device == handoff.record.device
                            && record_file.inode == handoff.record.inode
                            && record_file.length == handoff.record.length
                            && record_file.content_sha256 == handoff.record.content_sha256
                            && record.checkpoint_content_digest
                                == handoff.predecessor_checkpoint_content_digest,
                        "after-root-provision handoff record changed physical identity or predecessor"
                    );
                    record.provision_transition_id
                }
                _ => bail!(
                    "serving handoff artifacts require provision_root_image or after-root-provision PrepareDevice"
                ),
            };
            let target_name = format!(
                "authorized-target-control-{}.json",
                provision_transition_id.as_str()
            );
            let target_temp = format!(".{target_name}.tmp");
            let expected_reserved = [
                target_name.as_str(),
                target_temp.as_str(),
                SERVING_HANDOFF_RECORD_FILE,
                ".serving-handoff.json.tmp",
                SERVING_HANDOFF_RETIREMENT_FILE,
                ".serving-handoff-retirement.json.tmp",
            ];
            if let Some(foreign) = by_name.keys().find(|name| {
                is_serving_handoff_artifact_name(name)
                    && !expected_reserved.contains(&name.as_str())
            }) {
                bail!("authorized blockd leaf retains foreign handoff artifact {foreign}")
            }
            let present_temps = [
                (
                    target_temp.as_str(),
                    ServingHandoffTempKind::TargetAuthorization,
                    TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
                ),
                (
                    ".serving-handoff.json.tmp",
                    ServingHandoffTempKind::Record,
                    SERVING_HANDOFF_RECORD_MAX_BYTES,
                ),
                (
                    ".serving-handoff-retirement.json.tmp",
                    ServingHandoffTempKind::RetirementReceipt,
                    SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
                ),
            ]
            .into_iter()
            .filter(|(name, _, _)| by_name.contains_key(*name))
            .collect::<Vec<_>>();
            if !present_temps.is_empty() {
                if present_temps.len() == 1 {
                    let (name, kind, maximum) = present_temps[0];
                    if read_scanned_handoff_artifact(
                        &epoch_directory,
                        &by_name[name],
                        root,
                        data_directory_path.join(name),
                        maximum,
                        context,
                    )?
                    .is_some()
                    {
                        scan.handoff_temps
                            .push((desired.cat_id.clone(), kind, checkpoint.clone()));
                    }
                }
                scan.complete = false;
                continue;
            }
            let Some(target_entry) = by_name.get(&target_name) else {
                bail!("serving handoff artifact set lacks target-control authority")
            };
            let Some(target) = read_scanned_handoff_artifact(
                &epoch_directory,
                target_entry,
                root,
                data_directory_path.join(&target_name),
                TARGET_CONTROL_AUTHORIZATION_MAX_BYTES,
                context,
            )?
            else {
                scan.complete = false;
                continue;
            };
            let record = if let Some(entry) = by_name.get(SERVING_HANDOFF_RECORD_FILE) {
                let Some(record) = read_scanned_handoff_artifact(
                    &epoch_directory,
                    entry,
                    root,
                    data_directory_path.join(SERVING_HANDOFF_RECORD_FILE),
                    SERVING_HANDOFF_RECORD_MAX_BYTES,
                    context,
                )?
                else {
                    scan.complete = false;
                    continue;
                };
                Some(record)
            } else {
                None
            };
            let retirement = if let Some(entry) = by_name.get(SERVING_HANDOFF_RETIREMENT_FILE) {
                let Some(retirement) = read_scanned_handoff_artifact(
                    &epoch_directory,
                    entry,
                    root,
                    data_directory_path.join(SERVING_HANDOFF_RETIREMENT_FILE),
                    SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
                    context,
                )?
                else {
                    scan.complete = false;
                    continue;
                };
                Some(retirement)
            } else {
                None
            };
            let target = target.borrowed();
            let record = record.as_ref().map(OwnedScannedHandoffArtifact::borrowed);
            let retirement = retirement
                .as_ref()
                .map(OwnedScannedHandoffArtifact::borrowed);
            retained_root_process = validate_scanned_serving_handoff_artifacts(
                &runtime_checkpoint,
                &checkpoint,
                &target,
                record.as_ref(),
                retirement.as_ref(),
            )?;
        }
        scan.candidate_volume_ids.insert(identity.volume_id.clone());
        anyhow::ensure!(
            scan.evidence
                .insert(
                    desired.cat_id.clone(),
                    AuthorizedBlockdInventoryEvidence {
                        data_directory,
                        checkpoint,
                        binding,
                        control_state,
                        retained_root_process,
                    },
                )
                .is_none(),
            "authorized blockd inventory duplicated one Cat"
        );
    }
    Ok(scan)
}

fn is_serving_handoff_artifact_name(name: &str) -> bool {
    name.starts_with("authorized-target-control-")
        || name.starts_with(".authorized-target-control-")
        || name.starts_with("serving-handoff")
        || name.starts_with(".serving-handoff")
}

struct OwnedScannedHandoffArtifact {
    path: HostPath,
    device: WireU64,
    inode: WireU64,
    length: WireU64,
    content_sha256: Sha256Digest,
    bytes: Vec<u8>,
}

impl OwnedScannedHandoffArtifact {
    fn borrowed(&self) -> ScannedServingHandoffArtifact<'_> {
        ScannedServingHandoffArtifact {
            path: self.path.clone(),
            device: self.device,
            inode: self.inode,
            length: self.length,
            content_sha256: self.content_sha256.clone(),
            bytes: &self.bytes,
        }
    }
}

fn read_scanned_handoff_artifact(
    directory: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
    path: PathBuf,
    maximum: usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<OwnedScannedHandoffArtifact>> {
    let Some(bytes) = read_strict_regular_at(directory, entry, root, maximum, context)? else {
        return Ok(None);
    };
    let device = u64::try_from(entry.metadata.st_dev)
        .ok()
        .and_then(WireU64::new)
        .context("handoff artifact device is outside the wire range")?;
    let inode = WireU64::new(entry.metadata.st_ino)
        .context("handoff artifact inode is outside the wire range")?;
    let length = u64::try_from(bytes.len())
        .ok()
        .and_then(WireU64::new)
        .context("handoff artifact length is outside the wire range")?;
    Ok(Some(OwnedScannedHandoffArtifact {
        path: HostPath::new(
            path.to_str()
                .context("handoff artifact path is not UTF-8")?
                .to_owned(),
        )
        .context("handoff artifact path is not canonical")?,
        device,
        inode,
        length,
        content_sha256: Sha256Digest::from_bytes(Sha256::digest(&bytes).into()),
        bytes,
    }))
}

fn descend_only_directory(
    parent: &File,
    root: &File,
    budget: &mut usize,
    context: &RuntimeInventoryScanContext,
    label: &str,
) -> anyhow::Result<Option<(String, File)>> {
    let Some(entries) = strict_directory_entries(parent, budget, context)? else {
        return Ok(None);
    };
    if entries.is_empty() {
        return Ok(None);
    }
    anyhow::ensure!(
        entries.len() == 1,
        "authorized blockd {label} directory contains duplicate or foreign entries"
    );
    let name = entries[0]
        .name
        .to_str()
        .with_context(|| format!("authorized blockd {label} path is not UTF-8"))?
        .to_owned();
    let Some(directory) = open_strict_child_directory(parent, &entries[0], root)? else {
        return Ok(None);
    };
    Ok(Some((name, directory)))
}

fn authorized_blockd_binding(
    desired: &DesiredRuntimeSpec,
    checkpoint: &AuthorizedBlockdCheckpoint,
) -> anyhow::Result<DesiredCheckpointBinding> {
    let stored = &checkpoint.desired;
    anyhow::ensure!(
        stored.cat_id == desired.cat_id && stored.placement.node_id == desired.placement.node_id,
        "authorized blockd checkpoint is not attributable to current same-Node Desired"
    );
    if stored.desired_revision == desired.desired_revision {
        anyhow::ensure!(
            stored == desired,
            "same-revision authorized blockd checkpoint conflicts with current Desired"
        );
        return Ok(DesiredCheckpointBinding::Current);
    }
    anyhow::ensure!(
        stored.desired_revision < desired.desired_revision
            && stored.placement.placement_epoch <= desired.placement.placement_epoch,
        "authorized blockd checkpoint revision or placement is ahead of current Desired"
    );
    Ok(DesiredCheckpointBinding::Superseded)
}

fn decode_exact_json<T>(bytes: &[u8], label: &str) -> anyhow::Result<T>
where
    T: serde::de::DeserializeOwned + serde::Serialize,
{
    let value = serde_json::from_slice(bytes).with_context(|| format!("decode {label}"))?;
    anyhow::ensure!(
        serde_json::to_vec(&value).with_context(|| format!("encode {label}"))? == bytes,
        "{label} is not canonical"
    );
    Ok(value)
}

struct StateNamespaceProbe {
    source: InventorySource,
    state_directory: StateDirectory,
    namespace: &'static str,
    reject_legacy_root: bool,
    limits: ProbeLimits,
}

struct PlatformRootProcessInventoryBridge {
    port: Arc<dyn RootProvisionProcessPort>,
    executable_path: HostPath,
    state_directory: StateDirectory,
    process_paths: ProcessPaths,
    systemd_root: PathBuf,
    metering_root: Option<PathBuf>,
    legacy_socket_root: PathBuf,
    limits: ProbeLimits,
}

impl PlatformRootProcessInventoryBridge {
    /// One shared sealed sweep for both full-inventory projection and
    /// retirement absence. Every managed service, Cats binary process, and
    /// managed socket must be accounted for by the exact identities supplied
    /// by the caller; an empty allowlist therefore proves Node-global absence.
    fn sweep_node_global_inventory(
        &self,
        allowed_units: &BTreeSet<Id>,
        allowed_pids: &BTreeSet<u32>,
        allowed_sockets: &BTreeSet<PathBuf>,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ProbeFact> {
        let mut budget = self.limits.os_entries;
        let systemd = scan_cgroup_tree_allowing(
            &self.systemd_root,
            CgroupKind::Systemd,
            0,
            &mut budget,
            self.limits.recursion_depth,
            allowed_units,
            context,
        )?;
        let metering = if let Some(root) = &self.metering_root {
            scan_cgroup_tree_allowing(
                root,
                CgroupKind::DedicatedMeteringRoot,
                0,
                &mut budget,
                self.limits.recursion_depth,
                &BTreeSet::new(),
                context,
            )?
        } else {
            ProbeFact::Empty
        };
        let processes = scan_processes_allowing(&self.process_paths, allowed_pids, context)?;
        let sockets = scan_root_process_sockets(
            &self.state_directory,
            &self.legacy_socket_root,
            allowed_sockets,
            self.limits,
            context,
        )?;
        Ok(
            if [systemd, metering, processes, sockets].contains(&ProbeFact::Present) {
                ProbeFact::Present
            } else if [systemd, metering, processes, sockets].contains(&ProbeFact::Unavailable) {
                ProbeFact::Unavailable
            } else {
                ProbeFact::Empty
            },
        )
    }
}

impl root_process_inventory_bridge_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl RootProcessInventoryBridge for PlatformRootProcessInventoryBridge {
    fn executable_path(&self) -> &HostPath {
        &self.executable_path
    }

    fn inspect_all(
        &self,
        expected: BTreeMap<Id, RootProvisionProcessExpectation>,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
        let first = inspect_root_process_set(self.port.as_ref(), &expected, context)?;
        let Some(first) = first else {
            return Ok(RootProcessInventoryBridgeOutcome::Unavailable);
        };

        let allowed_units = first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => Some(evidence.scope_id.clone()),
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        let allowed_pids = first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => Some(evidence.process_id),
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        let allowed_sockets = first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => {
                    Some(PathBuf::from(evidence.control_socket_path.as_str()))
                }
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        anyhow::ensure!(
            allowed_units.len() == allowed_pids.len()
                && allowed_pids.len() == allowed_sockets.len(),
            "root-provision process inventory contains duplicate physical identity"
        );

        match self.sweep_node_global_inventory(
            &allowed_units,
            &allowed_pids,
            &allowed_sockets,
            context,
        )? {
            ProbeFact::Present => {
                bail!("root-provision process inventory found foreign or duplicate managed residue")
            }
            ProbeFact::Unavailable => return Ok(RootProcessInventoryBridgeOutcome::Unavailable),
            ProbeFact::Empty => {}
        }

        let Some(second) = inspect_root_process_set(self.port.as_ref(), &expected, context)? else {
            return Ok(RootProcessInventoryBridgeOutcome::Unavailable);
        };
        anyhow::ensure!(
            first == second,
            "root-provision process identity changed across the global inventory sweep"
        );
        let mut proofs = BTreeMap::new();
        for (cat_id, inspection) in second {
            if let RootProvisionProcessInspection::Exact(evidence) = inspection {
                let expectation = expected
                    .get(&cat_id)
                    .expect("inspection keys originate from expectations")
                    .clone();
                let proof = expectation.prove_exact_process(*evidence)?;
                proofs.insert(cat_id, proof);
            }
        }
        Ok(RootProcessInventoryBridgeOutcome::Complete(proofs))
    }
}

impl super::root_provision_process::retirement_sealed::Sealed
    for PlatformRootProcessInventoryBridge
{
}

impl RootProvisionProcessRetirementPort for PlatformRootProcessInventoryBridge {
    fn inspect_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        match inspect_exact_root_provision_process(self.port.as_ref(), expected, context)? {
            RootProvisionProcessInspection::Absent => {}
            present_or_conflict => return Ok(present_or_conflict),
        }
        let sweep = match self.sweep_node_global_inventory(
            &BTreeSet::new(),
            &BTreeSet::new(),
            &BTreeSet::new(),
            context,
        ) {
            Ok(sweep) => sweep,
            Err(_) => {
                // Preserve cancellation/deadline as an unavailable effect,
                // while classifying any still-active malformed/foreign
                // managed namespace as a typed physical conflict.
                context.check_active()?;
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                ));
            }
        };
        match sweep {
            ProbeFact::Present => {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                ));
            }
            ProbeFact::Unavailable => return Ok(RootProvisionProcessInspection::Unavailable),
            ProbeFact::Empty => {}
        }
        match inspect_exact_root_provision_process(self.port.as_ref(), expected, context)? {
            RootProvisionProcessInspection::Absent => Ok(RootProvisionProcessInspection::Absent),
            RootProvisionProcessInspection::Unavailable => {
                Ok(RootProvisionProcessInspection::Unavailable)
            }
            RootProvisionProcessInspection::Exact(_)
            | RootProvisionProcessInspection::Conflict(_) => {
                Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ))
            }
        }
    }
}

fn inspect_root_process_set(
    port: &dyn RootProvisionProcessPort,
    expected: &BTreeMap<Id, RootProvisionProcessExpectation>,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<BTreeMap<Id, RootProvisionProcessInspection>>> {
    let mut inspected = BTreeMap::new();
    for (cat_id, expectation) in expected {
        let inspection = inspect_exact_root_provision_process(port, expectation, context)?;
        match inspection {
            RootProvisionProcessInspection::Absent | RootProvisionProcessInspection::Exact(_) => {}
            RootProvisionProcessInspection::Unavailable => return Ok(None),
            RootProvisionProcessInspection::Conflict(problem) => {
                let problem = match problem {
                    RootProvisionProcessConflict::DuplicateIdentity => "duplicate identity",
                    RootProvisionProcessConflict::IdentityMismatch => "identity mismatch",
                };
                bail!("root-provision process conflict for {cat_id}: {problem}")
            }
        }
        inspected.insert(cat_id.clone(), inspection);
    }
    Ok(Some(inspected))
}

impl super::inventory_probe_sealed::Sealed for StateNamespaceProbe {}

impl InventoryAbsenceProbe for StateNamespaceProbe {
    fn source(&self) -> InventorySource {
        self.source
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        let mut facts = vec![scan_state_namespace(
            &root,
            self.namespace,
            self.limits.state_entries,
            context,
        )?];
        if self.source == InventorySource::Checkpoint {
            facts.push(scan_state_namespace(
                &root,
                RUNTIME_EFFECTS_NAMESPACE,
                self.limits.state_entries,
                context,
            )?);
        }
        if self.reject_legacy_root {
            facts.push(state_entry_fact(&root, LEGACY_LEDGER, context)?);
            facts.push(state_entry_fact(&root, LEGACY_CATS_DIRECTORY, context)?);
        }
        finish_absence(self.source, &facts)
    }
}

#[derive(Clone)]
struct ProcessPaths {
    root: PathBuf,
    binaries: Vec<PathBuf>,
    supported: bool,
    limits: ProbeLimits,
}

struct ProcessProbe {
    paths: ProcessPaths,
}

impl super::inventory_probe_sealed::Sealed for ProcessProbe {}

impl InventoryAbsenceProbe for ProcessProbe {
    fn source(&self) -> InventorySource {
        InventorySource::Process
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        finish_absence(self.source(), &[scan_processes(&self.paths, context)?])
    }
}

struct SystemdProbe {
    systemd_root: PathBuf,
    metering_root: Option<PathBuf>,
    supported: bool,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for SystemdProbe {}

impl InventoryAbsenceProbe for SystemdProbe {
    fn source(&self) -> InventorySource {
        InventorySource::Systemd
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        if !self.supported {
            return Ok(InventoryAbsence::Unavailable);
        }
        let mut budget = self.limits.os_entries;
        let mut facts = vec![scan_cgroup_tree(
            &self.systemd_root,
            CgroupKind::Systemd,
            0,
            &mut budget,
            self.limits.recursion_depth,
            context,
        )?];
        if let Some(root) = &self.metering_root {
            facts.push(scan_cgroup_tree(
                root,
                CgroupKind::DedicatedMeteringRoot,
                0,
                &mut budget,
                self.limits.recursion_depth,
                context,
            )?);
        }
        finish_absence(self.source(), &facts)
    }
}

struct ControlSocketProbe {
    state_directory: StateDirectory,
    legacy_socket_root: PathBuf,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for ControlSocketProbe {}

impl InventoryAbsenceProbe for ControlSocketProbe {
    fn source(&self) -> InventorySource {
        InventorySource::ControlSocket
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        finish_absence(
            self.source(),
            &[
                scan_state_namespace(
                    &root,
                    CONTROL_SOCKET_NAMESPACE,
                    self.limits.state_entries,
                    context,
                )?,
                scan_managed_path_namespace(
                    &self.legacy_socket_root,
                    self.limits.state_entries,
                    context,
                )?,
            ],
        )
    }
}

struct BlockFrontendProbe {
    state_directory: StateDirectory,
    block_class_root: PathBuf,
    legacy_socket_root: PathBuf,
    supported: bool,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for BlockFrontendProbe {}

impl InventoryAbsenceProbe for BlockFrontendProbe {
    fn source(&self) -> InventorySource {
        InventorySource::BlockFrontend
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        let nbd = if self.supported {
            scan_nbd(&self.block_class_root, self.limits.os_entries, context)?
        } else {
            ProbeFact::Unavailable
        };
        finish_absence(
            self.source(),
            &[
                nbd,
                scan_state_namespace(&root, VHOST_NAMESPACE, self.limits.state_entries, context)?,
                scan_managed_path_namespace_matching(
                    &self.legacy_socket_root,
                    self.limits.state_entries,
                    context,
                    socket_candidate,
                )?,
            ],
        )
    }
}

struct NetworkProbe {
    state_directory: StateDirectory,
    network_class_root: PathBuf,
    supported: bool,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for NetworkProbe {}

impl InventoryAbsenceProbe for NetworkProbe {
    fn source(&self) -> InventorySource {
        InventorySource::Network
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        let interfaces = if self.supported {
            scan_network_interfaces(&self.network_class_root, self.limits.os_entries, context)?
        } else {
            ProbeFact::Unavailable
        };
        finish_absence(
            self.source(),
            &[
                interfaces,
                scan_state_namespace(&root, NETWORK_NAMESPACE, self.limits.state_entries, context)?,
                scan_state_namespace(
                    &root,
                    RUNTIME_EFFECTS_NAMESPACE,
                    self.limits.state_entries,
                    context,
                )?,
            ],
        )
    }
}

struct MetadataStoreProbe {
    state_directory: StateDirectory,
    authority: Arc<dyn MetadataAuthorityAbsenceReader>,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for MetadataStoreProbe {}

impl InventoryAbsenceProbe for MetadataStoreProbe {
    fn source(&self) -> InventorySource {
        InventorySource::MetadataStore
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        context.check_active()?;
        let Some(desired_volumes) = supported_desired_volumes(context)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        let desired_volume_ids: BTreeSet<Id> = desired_volumes.keys().cloned().collect();
        let mut candidate_volume_ids = desired_volume_ids.clone();
        let mut stale_volumes: BTreeMap<Id, StaleVolumeProjection> = BTreeMap::new();
        let mut cleanup_replays = BTreeMap::new();

        let mut local_candidates_complete = true;
        if let Some(root) = clone_state_root(&self.state_directory)? {
            match scan_runtime_checkpoints(&root, context, self.limits)? {
                InventoryAbsence::RuntimeCheckpoints(checkpoints) => {
                    for (cat_id, evidence) in checkpoints {
                        if evidence.binding == DesiredCheckpointBinding::Current {
                            if let cats_api::runtime_reconciliation::ReconcileStep::CleanupRelease {
                                cleanup,
                            } = &evidence.checkpoint.step
                            {
                                if let cats_api::runtime_reconciliation::CleanupTarget::Volume {
                                    volume_id,
                                    ..
                                } = &cleanup.target
                                {
                                    anyhow::ensure!(
                                        cleanup_replays
                                            .insert(volume_id.clone(), cleanup.clone())
                                            .is_none(),
                                        "multiple current cleanups name one Volume"
                                    );
                                }
                            }
                        }
                        let carries_superseded_acquire = matches!(
                            &evidence.checkpoint.step,
                            cats_api::runtime_reconciliation::ReconcileStep::AcquireVolume {
                                request: cats_api::runtime_reconciliation::VolumeAcquireRequest::Normal {
                                    desired_revision,
                                    ..
                                },
                            } if *desired_revision < evidence.checkpoint.desired_revision
                        );
                        let carries_owned_adoption = evidence.binding
                            == DesiredCheckpointBinding::Current
                            && matches!(
                                evidence.checkpoint.step,
                                cats_api::runtime_reconciliation::ReconcileStep::AcquireVolume { .. }
                            )
                            && evidence.checkpoint.volumes.iter().any(|volume| {
                                matches!(volume.authority, VolumeAuthorityEvidence::Owned { .. })
                            });
                        let carries_quarantined_lineage = evidence.binding
                            == DesiredCheckpointBinding::Current
                            && matches!(
                                evidence.checkpoint.step,
                                cats_api::runtime_reconciliation::ReconcileStep::Quarantined
                            );
                        if evidence.binding != DesiredCheckpointBinding::Superseded
                            && !carries_superseded_acquire
                            && !carries_owned_adoption
                            && !carries_quarantined_lineage
                        {
                            continue;
                        }
                        for observed in &evidence.checkpoint.volumes {
                            insert_stale_volume_projection(
                                &mut stale_volumes,
                                StaleVolumeProjection {
                                    cat_id: cat_id.clone(),
                                    observed: observed.clone(),
                                    conflict_only: carries_quarantined_lineage
                                        || carries_owned_adoption,
                                    acquire_request: match &evidence.checkpoint.step {
                                        cats_api::runtime_reconciliation::ReconcileStep::AcquireVolume {
                                            request,
                                        } => Some(request.clone()),
                                        _ => None,
                                    },
                                },
                            )?;
                        }
                    }
                }
                InventoryAbsence::Empty => {}
                InventoryAbsence::Unavailable => local_candidates_complete = false,
                _ => unreachable!("checkpoint scan returns only checkpoint evidence"),
            }
            match scan_authorized_blockd_data(
                &root,
                self.state_directory.path(),
                context,
                self.limits,
            ) {
                Ok(data) => {
                    candidate_volume_ids.extend(data.candidate_volume_ids);
                    for (cat_id, evidence) in &data.evidence {
                        let carries_superseded_receipt = evidence
                            .checkpoint
                            .attachment
                            .acquire_request
                            .desired_revision
                            < evidence.checkpoint.desired.desired_revision;
                        if evidence.binding != DesiredCheckpointBinding::Superseded
                            && !carries_superseded_receipt
                        {
                            continue;
                        }
                        let volume = &evidence.checkpoint.volume;
                        insert_stale_volume_projection(
                            &mut stale_volumes,
                            StaleVolumeProjection {
                                cat_id: cat_id.clone(),
                                conflict_only: false,
                                observed: ObservedVolume {
                                    volume_intent_id: Some(volume.volume_intent_id.clone()),
                                    disk_id: Some(volume.disk_id.clone()),
                                    volume_id: volume.volume_id.clone(),
                                    disk_kind: cats_api::runtime_reconciliation::ObservedDiskKind::Root,
                                    size_bytes: Some(volume.size_bytes),
                                    durability: Some(volume.durability),
                                    authority: VolumeAuthorityEvidence::Unavailable,
                                    local_lineages: Vec::new(),
                                    devices: Vec::new(),
                                },
                                acquire_request: Some(
                                    cats_api::runtime_reconciliation::VolumeAcquireRequest::Normal {
                                        volume_id: evidence.checkpoint.attachment.acquire_request.volume_id.clone(),
                                        transition_id: evidence.checkpoint.attachment.acquire_request.transition_id.clone(),
                                        attachment_id: evidence.checkpoint.attachment.acquire_request.attachment_id.clone(),
                                        expected_unowned_epoch: evidence.checkpoint.attachment.acquire_request.expected_unowned_epoch,
                                        desired_revision: evidence.checkpoint.attachment.acquire_request.desired_revision,
                                        placement_epoch: evidence.checkpoint.attachment.acquire_request.placement_epoch,
                                        lease_duration_ms: evidence.checkpoint.attachment.acquire_request.lease_duration_ms,
                                    },
                                ),
                            },
                        )?;
                    }
                    local_candidates_complete &= data.complete;
                }
                Err(_) => {
                    // Metadata discovery remains read-only and conservative
                    // when the data probe has already classified foreign
                    // layout as residue. Retain any legacy direct candidate
                    // names for authority fencing and outside-Desired checks;
                    // only the strict data probe can form typed local lineage.
                    let discovered = scan_state_volume_candidates(
                        &root,
                        DATA_NAMESPACE,
                        self.limits.state_entries,
                        context,
                    )?;
                    candidate_volume_ids.extend(discovered.volume_ids);
                    local_candidates_complete &= discovered.complete;
                }
            }
            let discovered = scan_state_volume_candidates(
                &root,
                PENDING_PACK_NAMESPACE,
                self.limits.state_entries,
                context,
            )?;
            candidate_volume_ids.extend(discovered.volume_ids);
            local_candidates_complete &= discovered.complete;
            local_candidates_complete &= matches!(
                state_entry_fact(&root, LEGACY_CATS_DIRECTORY, context)?,
                ProbeFact::Empty
            );
        } else {
            local_candidates_complete = false;
        }
        candidate_volume_ids.extend(stale_volumes.keys().cloned());

        // Every nonempty candidate is read through the strict authority port.
        // An empty candidate set is still unavailable because point reads
        // cannot prove global authority absence. The exact scan deadline is
        // passed through rather than recomputed per source.
        let authority_inventory = self.authority.read_candidates(
            &context.coordinates().session.node_id,
            &candidate_volume_ids,
            context.deadline(),
            context,
        )?;
        context.check_active()?;

        if !local_candidates_complete {
            return Ok(InventoryAbsence::Unavailable);
        }
        match authority_inventory {
            MetadataAuthorityCandidateInventory::Unavailable => Ok(InventoryAbsence::Unavailable),
            MetadataAuthorityCandidateInventory::Records(records) => {
                if candidate_volume_ids.is_empty() && records.is_empty() {
                    return Ok(InventoryAbsence::Empty);
                }
                if let Some(authority_only) =
                    records.keys().find(|id| !candidate_volume_ids.contains(id))
                {
                    bail!(
                        "metadata authority retains Node-owned volume outside scan candidates: {authority_only}"
                    );
                }
                if records.len() != candidate_volume_ids.len() {
                    return Ok(InventoryAbsence::Unavailable);
                }
                if let Some(local_only) = candidate_volume_ids
                    .difference(&desired_volume_ids)
                    .find(|volume_id| !stale_volumes.contains_key(*volume_id))
                {
                    bail!(
                        "metadata authority/local namespaces retain volume outside Desired: {local_only}"
                    );
                }

                let mut by_cat: BTreeMap<Id, Vec<AuthorityVolumeInventoryEvidence>> =
                    BTreeMap::new();
                for (volume_id, (desired, intent)) in desired_volumes {
                    let Some(record) = records.get(&volume_id) else {
                        return Ok(InventoryAbsence::Unavailable);
                    };
                    let stale_request = stale_volumes
                        .get(&volume_id)
                        .and_then(|projection| projection.acquire_request.as_ref());
                    let conflict_only = stale_volumes
                        .get(&volume_id)
                        .is_some_and(|projection| projection.conflict_only);
                    let observed = observe_desired_volume(
                        desired,
                        intent,
                        record,
                        stale_request,
                        cleanup_replays.get(&volume_id),
                        conflict_only,
                    )?;
                    by_cat.entry(desired.cat_id.clone()).or_default().push(
                        AuthorityVolumeInventoryEvidence {
                            observed,
                            record: record.clone(),
                        },
                    );
                }
                for (volume_id, projection) in stale_volumes {
                    if desired_volume_ids.contains(&volume_id) {
                        continue;
                    }
                    let Some(record) = records.get(&volume_id) else {
                        return Ok(InventoryAbsence::Unavailable);
                    };
                    let observed = observe_stale_volume(&projection, record)?;
                    by_cat.entry(projection.cat_id).or_default().push(
                        AuthorityVolumeInventoryEvidence {
                            observed,
                            record: record.clone(),
                        },
                    );
                }
                for volumes in by_cat.values_mut() {
                    volumes.sort_by(|left, right| {
                        left.observed.volume_id.cmp(&right.observed.volume_id)
                    });
                }
                Ok(InventoryAbsence::DesiredVolumes(by_cat))
            }
        }
    }
}

#[derive(Debug, Clone)]
struct StaleVolumeProjection {
    cat_id: Id,
    observed: ObservedVolume,
    acquire_request: Option<cats_api::runtime_reconciliation::VolumeAcquireRequest>,
    conflict_only: bool,
}

fn insert_stale_volume_projection(
    projections: &mut BTreeMap<Id, StaleVolumeProjection>,
    projection: StaleVolumeProjection,
) -> anyhow::Result<()> {
    let volume_id = projection.observed.volume_id.clone();
    if let Some(existing) = projections.get_mut(&volume_id) {
        anyhow::ensure!(
            existing.cat_id == projection.cat_id
                && existing.observed.volume_intent_id == projection.observed.volume_intent_id
                && existing.observed.disk_id == projection.observed.disk_id
                && existing.observed.disk_kind == projection.observed.disk_kind
                && existing.observed.size_bytes == projection.observed.size_bytes
                && existing.observed.durability == projection.observed.durability
                && (existing.acquire_request.is_none()
                    || projection.acquire_request.is_none()
                    || existing.acquire_request == projection.acquire_request),
            "stale checkpoint sources disagree on one Volume identity"
        );
        existing.conflict_only |= projection.conflict_only;
        if existing.acquire_request.is_none() && projection.acquire_request.is_some() {
            existing.acquire_request = projection.acquire_request;
        }
        return Ok(());
    }
    projections.insert(volume_id, projection);
    Ok(())
}

fn supported_desired_volumes(
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<BTreeMap<Id, (&DesiredRuntimeSpec, &VolumeIntent)>>> {
    let mut volumes = BTreeMap::new();
    for desired in &context.coordinates().desired.desired_specs {
        if desired.target != cats_api::runtime_reconciliation::RuntimeTarget::Running {
            return Ok(None);
        }
        if desired.volumes.is_empty() {
            continue;
        }
        if desired.volumes.len() != 1 {
            return Ok(None);
        }
        let intent = &desired.volumes[0];
        if intent.disk_kind != DiskKind::Root
            || intent.mount.is_some()
            || !matches!(intent.acquire, VolumeAcquire::Normal { .. })
        {
            return Ok(None);
        }
        anyhow::ensure!(
            volumes
                .insert(intent.volume_id.clone(), (desired, intent))
                .is_none(),
            "one authority Volume is referenced by multiple Desired Runtimes"
        );
    }
    Ok(Some(volumes))
}

fn observe_desired_volume(
    desired: &DesiredRuntimeSpec,
    intent: &VolumeIntent,
    record: &VolumeRecord,
    stale_request: Option<&cats_api::runtime_reconciliation::VolumeAcquireRequest>,
    cleanup: Option<&cats_api::runtime_reconciliation::CleanupRelease>,
    conflict_only: bool,
) -> anyhow::Result<ObservedVolume> {
    validate_volume_record(record).context("validate Desired-bound authority Volume")?;
    anyhow::ensure!(
        record.volume_id == intent.volume_id,
        "authority Volume ID mismatch"
    );
    anyhow::ensure!(
        record.size_bytes == intent.size_bytes,
        "authority Volume size does not match Desired"
    );
    anyhow::ensure!(
        record.durability == intent.durability,
        "authority Volume durability does not match Desired"
    );

    if record.lease_owner.is_none() {
        if let Some(cleanup) = cleanup {
            validate_completed_cleanup(record, cleanup)?;
        }
    }

    if let Some(owner) = &record.lease_owner {
        if owner != &intent.attachment_id {
            anyhow::ensure!(
                conflict_only
                    || stale_request
                        .is_some_and(|stale| stale_normal_marker_matches(record, stale)),
                "Desired Volume is owned by an untyped foreign attachment"
            );
        } else {
            let VolumeAcquire::Normal {
                transition_id,
                expected_unowned_epoch,
            } = &intent.acquire
            else {
                anyhow::bail!("the first Running slice supports only normal acquire")
            };
            let Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
                request,
                result,
            }) = &record.last_transition
            else {
                anyhow::bail!("Desired attachment owner lacks its exact normal-acquire receipt")
            };
            let current_marker_matches = request.volume_id == intent.volume_id
                && request.transition_id == *transition_id
                && request.attachment_id == intent.attachment_id
                && request.expected_unowned_epoch == *expected_unowned_epoch
                && request.desired_revision == desired.desired_revision
                && request.placement_epoch == desired.placement.placement_epoch
                && result.volume_id == intent.volume_id
                && result.transition_id == *transition_id
                && result.attachment_id == intent.attachment_id
                && result.resulting_epoch == record.lease_epoch;
            let stale_marker_matches =
                stale_request.is_some_and(|stale| stale_normal_marker_matches(record, stale));
            anyhow::ensure!(
                current_marker_matches || stale_marker_matches || conflict_only,
                "Desired attachment owner lacks current, typed stale, or quarantined evidence"
            );
        }
    }

    let authority = match &record.admin_state {
        VolumeAdminState::Active => match &record.lease_owner {
            Some(attachment_id) => VolumeAuthorityEvidence::Owned {
                attachment_id: attachment_id.clone(),
                attachment_epoch: record.lease_epoch,
                head: record.head.clone(),
            },
            None => VolumeAuthorityEvidence::Unowned {
                attachment_epoch: record.lease_epoch,
                head: record.head.clone(),
            },
        },
        VolumeAdminState::Deleting { delete_id } => VolumeAuthorityEvidence::Deleting {
            delete_id: delete_id.clone(),
            attachment_epoch: record.lease_epoch,
            head: record.head.clone(),
        },
    };
    Ok(ObservedVolume {
        volume_intent_id: Some(intent.volume_intent_id.clone()),
        disk_id: Some(intent.disk_id.clone()),
        volume_id: intent.volume_id.clone(),
        disk_kind: ObservedDiskKind::Root,
        size_bytes: Some(record.size_bytes),
        durability: Some(record.durability),
        authority,
        local_lineages: Vec::new(),
        devices: Vec::new(),
    })
}

fn stale_normal_marker_matches(
    record: &VolumeRecord,
    stale: &cats_api::runtime_reconciliation::VolumeAcquireRequest,
) -> bool {
    let cats_api::runtime_reconciliation::VolumeAcquireRequest::Normal {
        volume_id,
        transition_id,
        attachment_id,
        expected_unowned_epoch,
        desired_revision,
        placement_epoch,
        lease_duration_ms,
    } = stale
    else {
        return false;
    };
    let Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
        request,
        result,
    }) = &record.last_transition
    else {
        return false;
    };
    record.lease_owner.as_ref() == Some(attachment_id)
        && request.volume_id == *volume_id
        && request.transition_id == *transition_id
        && request.attachment_id == *attachment_id
        && request.expected_unowned_epoch == *expected_unowned_epoch
        && request.desired_revision == *desired_revision
        && request.placement_epoch == *placement_epoch
        && request.lease_duration_ms == *lease_duration_ms
        && result.volume_id == *volume_id
        && result.transition_id == *transition_id
        && result.attachment_id == *attachment_id
        && result.resulting_epoch == record.lease_epoch
}

fn validate_completed_cleanup(
    record: &VolumeRecord,
    cleanup: &cats_api::runtime_reconciliation::CleanupRelease,
) -> anyhow::Result<()> {
    let (
        cats_api::runtime_reconciliation::CleanupTarget::Volume {
            volume_id,
            attachment_id,
            attachment_epoch,
        },
        Some(replay),
        Some(cats_api::runtime_reconciliation::LastVolumeTransition::Release { request, result }),
    ) = (
        &cleanup.target,
        &cleanup.volume_release,
        &record.last_transition,
    )
    else {
        anyhow::bail!("Unowned cleanup Volume lacks its exact release marker")
    };
    let resulting_epoch = attachment_epoch
        .get()
        .checked_add(1)
        .and_then(cats_api::runtime_reconciliation::FenceEpoch::new)
        .context("cleanup release epoch overflowed")?;
    anyhow::ensure!(
        volume_id == &record.volume_id
            && request.volume_id == *volume_id
            && request.transition_id == replay.release_transition_id
            && request.attachment_id == *attachment_id
            && request.expected_epoch == *attachment_epoch
            && result.volume_id == *volume_id
            && result.transition_id == replay.release_transition_id
            && result.released_attachment_id == *attachment_id
            && result.resulting_epoch == resulting_epoch
            && result.resulting_head == record.head
            && record.lease_epoch == resulting_epoch
            && record.lease_expires_at.is_none()
            && replay.generation == record.head.generation,
        "Unowned cleanup Volume does not match its exact release replay"
    );
    Ok(())
}

fn observe_stale_volume(
    projection: &StaleVolumeProjection,
    record: &VolumeRecord,
) -> anyhow::Result<ObservedVolume> {
    validate_volume_record(record).context("validate stale-checkpoint authority Volume")?;
    anyhow::ensure!(
        record.volume_id == projection.observed.volume_id
            && projection.observed.size_bytes == Some(record.size_bytes)
            && projection.observed.durability == Some(record.durability),
        "stale checkpoint Volume projection conflicts with authority"
    );
    if let (Some(owner), Some(stale)) = (&record.lease_owner, &projection.acquire_request) {
        let cats_api::runtime_reconciliation::VolumeAcquireRequest::Normal {
            volume_id,
            transition_id,
            attachment_id,
            expected_unowned_epoch,
            desired_revision,
            placement_epoch,
            lease_duration_ms,
        } = stale
        else {
            anyhow::bail!("stale first-slice acquire is not normal")
        };
        let Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
            request,
            result,
        }) = &record.last_transition
        else {
            anyhow::bail!("stale owned Volume lacks its exact acquire marker")
        };
        anyhow::ensure!(
            owner == attachment_id
                && request.volume_id == *volume_id
                && request.transition_id == *transition_id
                && request.attachment_id == *attachment_id
                && request.expected_unowned_epoch == *expected_unowned_epoch
                && request.desired_revision == *desired_revision
                && request.placement_epoch == *placement_epoch
                && request.lease_duration_ms == *lease_duration_ms
                && result.volume_id == *volume_id
                && result.transition_id == *transition_id
                && result.attachment_id == *attachment_id
                && result.resulting_epoch == record.lease_epoch,
            "stale owned Volume marker does not match its checkpoint"
        );
    } else if record.lease_owner.is_some() {
        anyhow::ensure!(
            projection.conflict_only,
            "owned stale Volume lacks typed acquire or quarantine evidence"
        );
    }
    let mut observed = projection.observed.clone();
    observed.authority = match &record.admin_state {
        VolumeAdminState::Active => match &record.lease_owner {
            Some(attachment_id) => VolumeAuthorityEvidence::Owned {
                attachment_id: attachment_id.clone(),
                attachment_epoch: record.lease_epoch,
                head: record.head.clone(),
            },
            None => VolumeAuthorityEvidence::Unowned {
                attachment_epoch: record.lease_epoch,
                head: record.head.clone(),
            },
        },
        VolumeAdminState::Deleting { delete_id } => VolumeAuthorityEvidence::Deleting {
            delete_id: delete_id.clone(),
            attachment_epoch: record.lease_epoch,
            head: record.head.clone(),
        },
    };
    observed.local_lineages.clear();
    observed.devices.clear();
    Ok(observed)
}

struct LocalVolumeCandidates {
    volume_ids: BTreeSet<Id>,
    complete: bool,
}

struct GuestMountProbe {
    state_directory: StateDirectory,
    legacy_socket_root: PathBuf,
    guest_process_paths: ProcessPaths,
    limits: ProbeLimits,
}

impl super::inventory_probe_sealed::Sealed for GuestMountProbe {}

impl InventoryAbsenceProbe for GuestMountProbe {
    fn source(&self) -> InventorySource {
        InventorySource::GuestMount
    }

    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence> {
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(InventoryAbsence::Unavailable);
        };
        finish_absence(
            self.source(),
            &[
                scan_processes(&self.guest_process_paths, context)?,
                scan_state_namespace(
                    &root,
                    CONTROL_SOCKET_NAMESPACE,
                    self.limits.state_entries,
                    context,
                )?,
                scan_managed_path_namespace(
                    &self.legacy_socket_root,
                    self.limits.state_entries,
                    context,
                )?,
                scan_state_namespace(
                    &root,
                    GUEST_MOUNT_NAMESPACE,
                    self.limits.state_entries,
                    context,
                )?,
            ],
        )
    }
}

fn clone_state_root(state: &StateDirectory) -> anyhow::Result<Option<File>> {
    match state.try_clone_directory() {
        Ok(root) => Ok(Some(root)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(source) if unavailable_io(&source) => Ok(None),
        Err(source) => Err(source).context("open retained clean-slate state directory"),
    }
}

fn state_entry_fact(
    root: &File,
    name: &str,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<ProbeFact> {
    context.check_active()?;
    let name = CString::new(name).expect("fixed state entry has no NUL");
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `root` and `name` stay live for the call, `metadata` points to
    // writable storage, and AT_SYMLINK_NOFOLLOW prevents path traversal.
    let result = unsafe {
        libc::fstatat(
            root.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        context.check_active()?;
        return Ok(ProbeFact::Present);
    }
    let source = io::Error::last_os_error();
    if source.kind() == io::ErrorKind::NotFound {
        Ok(ProbeFact::Empty)
    } else if unavailable_io(&source) {
        Ok(ProbeFact::Unavailable)
    } else {
        Err(source).with_context(|| format!("inspect state entry {name:?}"))
    }
}

fn scan_state_namespace(
    root: &File,
    name: &str,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    context.check_active()?;
    let directory = match open_state_namespace(root, name)? {
        ManagedDirectory::Missing => return Ok(ProbeFact::Empty),
        ManagedDirectory::Unavailable => return Ok(ProbeFact::Unavailable),
        ManagedDirectory::Open(directory) => directory,
    };
    scan_open_managed_directory(&directory, cap, context, |_| true)
        .with_context(|| format!("scan state namespace {name}"))
}

fn open_state_namespace(root: &File, name: &str) -> anyhow::Result<ManagedDirectory> {
    let name_c = CString::new(name).expect("fixed state namespace has no NUL");
    let flags =
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK;
    // SAFETY: the parent descriptor and C string are live; successful openat
    // returns one descriptor owned by this call.
    let descriptor = unsafe { libc::openat(root.as_raw_fd(), name_c.as_ptr(), flags) };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return if source.kind() == io::ErrorKind::NotFound {
            Ok(ManagedDirectory::Missing)
        } else if source.raw_os_error() == Some(libc::ELOOP)
            || source.raw_os_error() == Some(libc::ENOTDIR)
        {
            bail!("unsafe clean-slate state namespace {name}");
        } else if unavailable_io(&source) {
            Ok(ManagedDirectory::Unavailable)
        } else {
            Err(source).with_context(|| format!("open state namespace {name}"))
        };
    }
    // SAFETY: `descriptor` is newly owned after successful openat.
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let root_metadata = root.metadata().context("inspect retained state root")?;
    let namespace_metadata = directory
        .metadata()
        .with_context(|| format!("inspect state namespace {name}"))?;
    anyhow::ensure!(
        namespace_metadata.is_dir()
            && namespace_metadata.uid() == root_metadata.uid()
            && namespace_metadata.mode() & 0o022 == 0,
        "unsafe owner or mode on clean-slate state namespace {name}"
    );
    Ok(ManagedDirectory::Open(directory))
}

fn scan_state_volume_candidates(
    root: &File,
    name: &str,
    cap: usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<LocalVolumeCandidates> {
    context.check_active()?;
    let directory = match open_state_namespace(root, name)? {
        ManagedDirectory::Missing => {
            return Ok(LocalVolumeCandidates {
                volume_ids: BTreeSet::new(),
                complete: true,
            });
        }
        ManagedDirectory::Unavailable => {
            return Ok(LocalVolumeCandidates {
                volume_ids: BTreeSet::new(),
                complete: false,
            });
        }
        ManagedDirectory::Open(directory) => directory,
    };

    let mut volume_ids = BTreeSet::new();
    let mut all_names_are_volume_ids = true;
    let scan = inspect_open_managed_directory(&directory, cap, context, |name| {
        let volume_id = name.to_str().and_then(Id::new);
        if let Some(volume_id) = volume_id {
            volume_ids.insert(volume_id);
        } else {
            // Unknown local state is retained as residue, but cannot be used
            // to form a complete authority candidate set.
            all_names_are_volume_ids = false;
        }
        Ok(())
    })
    .with_context(|| format!("discover volume candidates in state namespace {name}"))?;

    Ok(LocalVolumeCandidates {
        volume_ids,
        complete: all_names_are_volume_ids && scan != ProbeFact::Unavailable,
    })
}

fn scan_managed_path_namespace(
    path: &Path,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    scan_managed_path_namespace_matching(path, cap, context, |_| true)
}

fn scan_managed_path_namespace_matching(
    path: &Path,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
    predicate: impl Fn(&OsStr) -> bool,
) -> anyhow::Result<ProbeFact> {
    context.check_active()?;
    let directory = match open_managed_directory(path)? {
        ManagedDirectory::Missing => return Ok(ProbeFact::Empty),
        ManagedDirectory::Unavailable => return Ok(ProbeFact::Unavailable),
        ManagedDirectory::Open(directory) => directory,
    };
    scan_open_managed_directory(&directory, cap, context, predicate)
        .with_context(|| format!("scan managed namespace {}", path.display()))
}

enum ManagedDirectory {
    Missing,
    Unavailable,
    Open(File),
}

struct StrictDirectoryEntry {
    name: OsString,
    metadata: libc::stat,
}

fn strict_directory_entries(
    directory: &File,
    budget: &mut usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<Vec<StrictDirectoryEntry>>> {
    strict_directory_entries_with_release_links(directory, budget, context, false)
}

fn strict_checkpoint_directory_entries(
    directory: &File,
    budget: &mut usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<Vec<StrictDirectoryEntry>>> {
    strict_directory_entries_with_release_links(directory, budget, context, true)
}

fn strict_directory_entries_with_release_links(
    directory: &File,
    budget: &mut usize,
    context: &RuntimeInventoryScanContext,
    allow_release_publication_links: bool,
) -> anyhow::Result<Option<Vec<StrictDirectoryEntry>>> {
    let mut stream = match DirectoryStream::open(directory) {
        Ok(stream) => stream,
        Err(source) if unavailable_io(&source) => return Ok(None),
        Err(source) => return Err(source).context("open strict directory stream"),
    };
    let mut entries = Vec::new();
    loop {
        let name = match stream.next() {
            Ok(Some(name)) => name,
            Ok(None) => break,
            Err(source) if unavailable_io(&source) => return Ok(None),
            Err(source) => return Err(source).context("enumerate strict directory"),
        };
        context.check_active()?;
        *budget = match budget.checked_sub(1) {
            Some(remaining) => remaining,
            None => bail!("authorized Runtime namespace exceeds entry cap"),
        };
        let metadata = match stat_at(directory, &name) {
            Ok(metadata) => metadata,
            Err(source) if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound => {
                return Ok(None)
            }
            Err(source) => return Err(source).context("inspect strict directory entry"),
        };
        let file_type = metadata.st_mode & libc::S_IFMT;
        anyhow::ensure!(
            matches!(file_type, libc::S_IFREG | libc::S_IFDIR | libc::S_IFSOCK),
            "authorized Runtime namespace contains an unsafe entry: {:?}",
            name
        );
        let recoverable_release_link = allow_release_publication_links
            && metadata.st_nlink == 2
            && name.to_str().is_some_and(is_release_rejection_entry);
        anyhow::ensure!(
            file_type != libc::S_IFREG || metadata.st_nlink == 1 || recoverable_release_link,
            "authorized Runtime namespace contains a multiply-linked file: {:?}",
            name
        );
        entries.push(StrictDirectoryEntry { name, metadata });
    }
    context.check_active()?;
    entries.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(Some(entries))
}

fn open_exact_only_child_directory(
    parent: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<File>> {
    context.check_active()?;
    open_strict_child_directory(parent, entry, root)
}

fn open_strict_child_directory(
    parent: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
) -> anyhow::Result<Option<File>> {
    anyhow::ensure!(
        entry.metadata.st_mode & libc::S_IFMT == libc::S_IFDIR,
        "authorized blockd path component is not a directory: {:?}",
        entry.name
    );
    let name = CString::new(entry.name.as_bytes()).context("directory name contains NUL")?;
    // SAFETY: `parent` and `name` remain live for the call. On success this
    // returns one new descriptor owned by this function; O_NOFOLLOW and the
    // post-open identity check close path replacement and symlink traversal.
    let descriptor = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY
                | libc::O_DIRECTORY
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else if source.raw_os_error() == Some(libc::ELOOP)
            || source.raw_os_error() == Some(libc::ENOTDIR)
        {
            bail!("authorized blockd path component changed type")
        } else {
            Err(source).context("open authorized blockd directory")
        };
    }
    // SAFETY: successful `openat` returned this newly owned descriptor and no
    // other `File` has been constructed from it.
    let directory = unsafe { File::from_raw_fd(descriptor) };
    let metadata = directory
        .metadata()
        .context("inspect authorized blockd directory")?;
    let root_metadata = root.metadata().context("inspect retained state root")?;
    anyhow::ensure!(
        metadata.is_dir()
            && u64::try_from(entry.metadata.st_dev).ok() == Some(metadata.dev())
            && metadata.ino() == entry.metadata.st_ino
            && metadata.uid() == root_metadata.uid()
            && metadata.mode() & 0o777 == 0o700,
        "authorized blockd directory identity, owner or mode is unsafe"
    );
    Ok(Some(directory))
}

fn validate_strict_regular_entry(
    entry: &StrictDirectoryEntry,
    root: &File,
    mode: libc::mode_t,
) -> anyhow::Result<()> {
    let root_metadata = root.metadata().context("inspect retained state root")?;
    anyhow::ensure!(
        entry.metadata.st_mode & libc::S_IFMT == libc::S_IFREG
            && entry.metadata.st_nlink == 1
            && entry.metadata.st_uid == root_metadata.uid()
            && entry.metadata.st_mode & 0o777 == mode,
        "authorized Runtime file owner, mode or identity is unsafe: {:?}",
        entry.name
    );
    Ok(())
}

fn read_strict_regular_at(
    directory: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
    cap: usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<Vec<u8>>> {
    validate_strict_regular_entry(entry, root, 0o600)?;
    context.check_active()?;
    let name = CString::new(entry.name.as_bytes()).context("file name contains NUL")?;
    // SAFETY: `directory` and `name` remain live for the call. On success this
    // returns one new descriptor owned by this function; O_NOFOLLOW and the
    // before-read identity check reject path replacement and symlink traversal.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else if source.raw_os_error() == Some(libc::ELOOP) {
            bail!("authorized Runtime file changed to a symlink")
        } else {
            Err(source).context("open authorized Runtime file")
        };
    }
    // SAFETY: successful `openat` returned this newly owned descriptor and no
    // other `File` has been constructed from it.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .context("inspect authorized Runtime file before read")?;
    anyhow::ensure!(
        before.is_file()
            && u64::try_from(entry.metadata.st_dev).ok() == Some(before.dev())
            && before.ino() == entry.metadata.st_ino
            && before.nlink() == 1,
        "authorized Runtime file identity changed before read"
    );
    let mut bytes = Vec::new();
    (&file)
        .take(u64::try_from(cap)?.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read authorized Runtime file")?;
    context.check_active()?;
    let after = file
        .metadata()
        .context("inspect authorized Runtime file after read")?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Ok(None);
    }
    anyhow::ensure!(
        bytes.len() <= cap,
        "authorized Runtime file exceeds byte cap {cap}"
    );
    Ok(Some(bytes))
}

/// Proves the control-only engine has the exact frozen bitmap for this volume
/// and that no dirty page survived. The file remains descriptor-relative and
/// no-follow throughout; malformed/racing contents are incomplete inventory,
/// never absence or verified process evidence.
fn inspect_empty_dirty_bitmap_at(
    directory: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
    size_bytes: u64,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<()>> {
    validate_strict_regular_entry(entry, root, 0o600)?;
    let root_uid = root
        .metadata()
        .context("inspect retained state root for dirty bitmap")?
        .uid();
    let chunk_count = chunk::chunk_count(size_bytes);
    let expected_len = BITMAP_HEADER_LEN
        .checked_add(
            chunk_count
                .checked_mul(u64::try_from(std::mem::size_of::<u64>())?)
                .context("root-provision dirty bitmap length overflow")?,
        )
        .context("root-provision dirty bitmap length overflow")?;
    if u64::try_from(entry.metadata.st_size).ok() != Some(expected_len) {
        return Ok(None);
    }

    context.check_active()?;
    let name = CString::new(entry.name.as_bytes()).context("bitmap file name contains NUL")?;
    // SAFETY: `directory` and `name` remain live for the call. A successful
    // open returns one new descriptor owned below; O_NOFOLLOW closes symlink
    // traversal and the descriptor metadata is compared with the enumerated
    // entry before any bytes become evidence.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else if source.raw_os_error() == Some(libc::ELOOP) {
            bail!("root-provision dirty bitmap changed to a symlink")
        } else {
            Err(source).context("open root-provision dirty bitmap")
        };
    }
    // SAFETY: successful `openat` returned this newly owned descriptor and no
    // other `File` has been constructed from it.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .context("inspect root-provision dirty bitmap before read")?;
    if !exact_dirty_bitmap_descriptor_metadata(&before, entry, root_uid, expected_len) {
        return Ok(None);
    }

    let mut reader = &file;
    let mut header = vec![0_u8; usize::try_from(BITMAP_HEADER_LEN)?];
    if let Err(source) = reader.read_exact(&mut header) {
        return if unavailable_io(&source) || source.kind() == io::ErrorKind::UnexpectedEof {
            Ok(None)
        } else {
            Err(source).context("read root-provision dirty bitmap header")
        };
    }
    if decode_bitmap_header(&header).ok() != Some(chunk_count) {
        return Ok(None);
    }

    let mut remaining = chunk_count
        .checked_mul(u64::try_from(std::mem::size_of::<u64>())?)
        .context("root-provision dirty bitmap body length overflow")?;
    let mut buffer = [0_u8; 4096];
    while remaining != 0 {
        context.check_active()?;
        let take = usize::try_from(remaining.min(u64::try_from(buffer.len())?))?;
        if let Err(source) = reader.read_exact(&mut buffer[..take]) {
            return if unavailable_io(&source) || source.kind() == io::ErrorKind::UnexpectedEof {
                Ok(None)
            } else {
                Err(source).context("stream root-provision dirty bitmap words")
            };
        }
        if buffer[..take].iter().any(|byte| *byte != 0) {
            return Ok(None);
        }
        remaining -= u64::try_from(take)?;
    }
    context.check_active()?;
    let after = file
        .metadata()
        .context("inspect root-provision dirty bitmap after read")?;
    if !exact_dirty_bitmap_descriptor_metadata(&after, entry, root_uid, expected_len)
        || before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
    {
        return Ok(None);
    }
    Ok(Some(()))
}

fn exact_dirty_bitmap_descriptor_metadata(
    metadata: &std::fs::Metadata,
    entry: &StrictDirectoryEntry,
    root_uid: u32,
    expected_len: u64,
) -> bool {
    metadata.is_file()
        && u64::try_from(entry.metadata.st_dev).ok() == Some(metadata.dev())
        && metadata.ino() == entry.metadata.st_ino
        && metadata.uid() == root_uid
        && metadata.mode() & 0o777 == 0o600
        && metadata.nlink() == 1
        && metadata.len() == expected_len
}

/// Reads the only recoverable hard-link shapes of a definite-release temp.
/// Unlike ordinary evidence, the temp legitimately has two links after the
/// no-replace target link is created and before its final directory barrier.
fn read_release_rejection_publication_at(
    directory: &File,
    entry: &StrictDirectoryEntry,
    root: &File,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<Option<Vec<u8>>> {
    let root_metadata = root.metadata().context("inspect retained state root")?;
    anyhow::ensure!(
        entry.metadata.st_mode & libc::S_IFMT == libc::S_IFREG
            && matches!(entry.metadata.st_nlink, 1 | 2)
            && entry.metadata.st_uid == root_metadata.uid()
            && entry.metadata.st_mode & 0o777 == 0o600,
        "release rejection temp owner, mode or identity is unsafe: {:?}",
        entry.name
    );
    context.check_active()?;
    let name = CString::new(entry.name.as_bytes()).context("file name contains NUL")?;
    // SAFETY: the retained directory descriptor and NUL-terminated name stay
    // live for the call. O_NOFOLLOW rejects replacement by a symlink.
    let descriptor = unsafe {
        libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
    };
    if descriptor < 0 {
        let source = io::Error::last_os_error();
        return if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound {
            Ok(None)
        } else if source.raw_os_error() == Some(libc::ELOOP) {
            bail!("release rejection temp changed to a symlink")
        } else {
            Err(source).context("open release rejection temp")
        };
    }
    // SAFETY: successful `openat` returned this newly owned descriptor.
    let file = unsafe { File::from_raw_fd(descriptor) };
    let before = file
        .metadata()
        .context("inspect release rejection temp before read")?;
    anyhow::ensure!(
        before.is_file()
            && u64::try_from(entry.metadata.st_dev).ok() == Some(before.dev())
            && before.ino() == entry.metadata.st_ino
            && before.nlink() == u64::from(entry.metadata.st_nlink),
        "release rejection temp identity changed before read"
    );
    let mut bytes = Vec::new();
    (&file)
        .take(u64::try_from(RELEASE_REJECTION_MAX_BYTES)?.saturating_add(1))
        .read_to_end(&mut bytes)
        .context("read release rejection temp")?;
    context.check_active()?;
    let after = file
        .metadata()
        .context("inspect release rejection temp after read")?;
    if before.len() != after.len()
        || before.modified().ok() != after.modified().ok()
        || before.ctime() != after.ctime()
        || before.ctime_nsec() != after.ctime_nsec()
        || before.nlink() != after.nlink()
    {
        return Ok(None);
    }
    if bytes.len() > RELEASE_REJECTION_MAX_BYTES {
        return Ok(None);
    }
    Ok(Some(bytes))
}

fn open_managed_directory(path: &Path) -> anyhow::Result<ManagedDirectory> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    match options.open(path) {
        Ok(directory) => Ok(ManagedDirectory::Open(directory)),
        Err(source) if source.kind() == io::ErrorKind::NotFound => Ok(ManagedDirectory::Missing),
        Err(source)
            if source.raw_os_error() == Some(libc::ELOOP)
                || source.raw_os_error() == Some(libc::ENOTDIR) =>
        {
            bail!("unsafe managed namespace {}", path.display())
        }
        Err(source) if unavailable_io(&source) => Ok(ManagedDirectory::Unavailable),
        Err(source) => Err(source).with_context(|| format!("open namespace {}", path.display())),
    }
}

fn scan_open_managed_directory(
    directory: &File,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
    predicate: impl Fn(&OsStr) -> bool,
) -> anyhow::Result<ProbeFact> {
    let mut matched = false;
    let scan = inspect_open_managed_directory(directory, cap, context, |name| {
        matched |= predicate(name);
        Ok(())
    })?;
    Ok(match scan {
        ProbeFact::Unavailable => ProbeFact::Unavailable,
        ProbeFact::Empty | ProbeFact::Present if matched => ProbeFact::Present,
        ProbeFact::Empty | ProbeFact::Present => ProbeFact::Empty,
    })
}

fn inspect_open_managed_directory(
    directory: &File,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
    mut inspect: impl FnMut(&OsStr) -> anyhow::Result<()>,
) -> anyhow::Result<ProbeFact> {
    let mut stream = match DirectoryStream::open(directory) {
        Ok(stream) => stream,
        Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
        Err(source) => return Err(source).context("open managed directory stream"),
    };
    let mut count = 0_usize;
    loop {
        let name = match stream.next() {
            Ok(Some(name)) => name,
            Ok(None) => break,
            Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
            Err(source) => return Err(source).context("enumerate managed directory"),
        };
        context.check_active()?;
        count = count
            .checked_add(1)
            .context("clean-slate namespace entry counter overflow")?;
        anyhow::ensure!(
            count <= cap,
            "clean-slate namespace exceeds entry cap {cap}"
        );
        let metadata = match stat_at(directory, &name) {
            Ok(metadata) => metadata,
            Err(source) if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound => {
                return Ok(ProbeFact::Unavailable);
            }
            Err(source) => return Err(source).context("inspect managed namespace entry"),
        };
        let file_type = metadata.st_mode & libc::S_IFMT;
        anyhow::ensure!(
            file_type != libc::S_IFLNK,
            "clean-slate namespace contains a symlink: {:?}",
            name
        );
        anyhow::ensure!(
            matches!(file_type, libc::S_IFREG | libc::S_IFDIR | libc::S_IFSOCK),
            "clean-slate namespace contains an unsafe file type: {:?}",
            name
        );
        anyhow::ensure!(
            file_type != libc::S_IFREG || metadata.st_nlink == 1,
            "clean-slate namespace contains a multiply-linked file: {:?}",
            name
        );
        inspect(&name)?;
    }
    context.check_active()?;
    Ok(if count > 0 {
        ProbeFact::Present
    } else {
        ProbeFact::Empty
    })
}

struct DirectoryStream(*mut libc::DIR);

impl DirectoryStream {
    fn open(directory: &File) -> io::Result<Self> {
        // SAFETY: F_DUPFD_CLOEXEC duplicates a live descriptor and retains no
        // Rust memory. The duplicate is transferred to fdopendir below.
        let duplicate = unsafe { libc::fcntl(directory.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
        if duplicate < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `duplicate` is a valid directory descriptor owned here.
        let stream = unsafe { libc::fdopendir(duplicate) };
        if stream.is_null() {
            let error = io::Error::last_os_error();
            // SAFETY: fdopendir failed and did not take ownership.
            unsafe { libc::close(duplicate) };
            return Err(error);
        }
        Ok(Self(stream))
    }

    fn next(&mut self) -> io::Result<Option<OsString>> {
        loop {
            set_errno(0);
            // SAFETY: the DIR pointer is exclusively owned by this value.
            let entry = unsafe { libc::readdir(self.0) };
            if entry.is_null() {
                let error = errno();
                return if error == 0 {
                    Ok(None)
                } else {
                    Err(io::Error::from_raw_os_error(error))
                };
            }
            // SAFETY: readdir returned a live dirent whose NUL-terminated name
            // remains valid until the next call on this DIR.
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) }.to_bytes();
            if name == b"." || name == b".." {
                continue;
            }
            return Ok(Some(OsString::from_vec(name.to_vec())));
        }
    }
}

impl Drop for DirectoryStream {
    fn drop(&mut self) {
        // SAFETY: this value owns the non-null DIR pointer exactly once.
        unsafe { libc::closedir(self.0) };
    }
}

fn stat_at(directory: &File, name: &OsStr) -> io::Result<libc::stat> {
    let name = CString::new(name.as_bytes())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "entry name contains NUL"))?;
    let mut metadata = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: all pointers are valid for this call; no symlink is followed.
    let result = unsafe {
        libc::fstatat(
            directory.as_raw_fd(),
            name.as_ptr(),
            metadata.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if result == 0 {
        // SAFETY: successful fstatat initialized the output.
        Ok(unsafe { metadata.assume_init() })
    } else {
        Err(io::Error::last_os_error())
    }
}

#[derive(Clone, Copy)]
enum CgroupKind {
    Systemd,
    DedicatedMeteringRoot,
}

fn scan_cgroup_tree(
    root: &Path,
    kind: CgroupKind,
    depth: usize,
    budget: &mut usize,
    depth_cap: usize,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    scan_cgroup_tree_allowing(
        root,
        kind,
        depth,
        budget,
        depth_cap,
        &BTreeSet::new(),
        context,
    )
}

fn scan_cgroup_tree_allowing(
    root: &Path,
    kind: CgroupKind,
    depth: usize,
    budget: &mut usize,
    depth_cap: usize,
    allowed_systemd_units: &BTreeSet<Id>,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    context.check_active()?;
    if depth > depth_cap {
        bail!("cgroup scan exceeds recursion depth cap {depth_cap}");
    }
    let metadata = match std::fs::symlink_metadata(root) {
        Ok(metadata) => metadata,
        Err(source) if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound => {
            return Ok(ProbeFact::Unavailable);
        }
        Err(source) => return Err(source).with_context(|| format!("inspect {}", root.display())),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "unsafe cgroup root {}",
        root.display()
    );
    let entries = match std::fs::read_dir(root) {
        Ok(entries) => entries,
        Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
        Err(source) => return Err(source).with_context(|| format!("read {}", root.display())),
    };
    let mut unavailable = false;
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if unavailable_io(&source) => {
                unavailable = true;
                continue;
            }
            Err(source) => return Err(source).context("enumerate cgroup entry"),
        };
        *budget = budget
            .checked_sub(1)
            .context("cgroup scan exceeds entry cap")?;
        let metadata = match entry.file_type() {
            Ok(metadata) => metadata,
            Err(source) if unavailable_io(&source) => {
                unavailable = true;
                continue;
            }
            Err(source) => {
                return Err(source)
                    .with_context(|| format!("inspect cgroup entry {}", entry.path().display()));
            }
        };
        anyhow::ensure!(
            !metadata.is_symlink(),
            "cgroup scan encountered symlink {}",
            entry.path().display()
        );
        if !metadata.is_dir() {
            continue;
        }
        let name = entry.file_name();
        let candidate = match kind {
            CgroupKind::Systemd => is_cats_unit(&name),
            CgroupKind::DedicatedMeteringRoot => true,
        };
        if candidate {
            let allowed = matches!(kind, CgroupKind::Systemd)
                && name
                    .to_str()
                    .and_then(Id::new)
                    .is_some_and(|unit| allowed_systemd_units.contains(&unit));
            if !allowed {
                return Ok(ProbeFact::Present);
            }
            match scan_cgroup_tree_allowing(
                &entry.path(),
                kind,
                depth + 1,
                budget,
                depth_cap,
                allowed_systemd_units,
                context,
            )? {
                ProbeFact::Present => return Ok(ProbeFact::Present),
                ProbeFact::Unavailable => unavailable = true,
                ProbeFact::Empty => {}
            }
            continue;
        }
        match scan_cgroup_tree_allowing(
            &entry.path(),
            kind,
            depth + 1,
            budget,
            depth_cap,
            allowed_systemd_units,
            context,
        )? {
            ProbeFact::Present => return Ok(ProbeFact::Present),
            ProbeFact::Unavailable => unavailable = true,
            ProbeFact::Empty => {}
        }
    }
    Ok(if unavailable {
        ProbeFact::Unavailable
    } else {
        ProbeFact::Empty
    })
}

fn is_cats_unit(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.starts_with("cats-") && (name.ends_with(".scope") || name.ends_with(".service"))
}

fn scan_processes(
    paths: &ProcessPaths,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    scan_processes_allowing(paths, &BTreeSet::new(), context)
}

fn scan_processes_allowing(
    paths: &ProcessPaths,
    allowed_pids: &BTreeSet<u32>,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    if !paths.supported {
        return Ok(ProbeFact::Unavailable);
    }
    context.check_active()?;
    let metadata = match std::fs::symlink_metadata(&paths.root) {
        Ok(metadata) => metadata,
        Err(source) if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound => {
            return Ok(ProbeFact::Unavailable);
        }
        Err(source) => return Err(source).context("inspect proc root"),
    };
    anyhow::ensure!(metadata.is_dir(), "proc root is not a directory");
    let entries = match std::fs::read_dir(&paths.root) {
        Ok(entries) => entries,
        Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
        Err(source) => return Err(source).context("read proc root"),
    };
    let mut count = 0_usize;
    let mut unavailable = false;
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if unavailable_io(&source) => {
                unavailable = true;
                continue;
            }
            Err(source) => return Err(source).context("enumerate proc root"),
        };
        let name = entry.file_name();
        if !name.as_bytes().iter().all(u8::is_ascii_digit) || name.is_empty() {
            continue;
        }
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) if unavailable_io(&source) => {
                unavailable = true;
                continue;
            }
            Err(source) => return Err(source).context("inspect proc entry"),
        };
        anyhow::ensure!(
            file_type.is_dir() && !file_type.is_symlink(),
            "unsafe numeric proc entry {:?}",
            name
        );
        count += 1;
        anyhow::ensure!(
            count <= paths.limits.os_entries,
            "proc scan exceeds entry cap {}",
            paths.limits.os_entries
        );
        let pid_path = entry.path();
        let process_id = name.to_str().and_then(|value| value.parse::<u32>().ok());
        let exe = std::fs::read_link(pid_path.join("exe"));
        let exe_matches = exe
            .as_ref()
            .is_ok_and(|exe| paths.binaries.iter().any(|binary| binary == exe));
        let cmdline = read_bounded_optional(
            &pid_path.join("cmdline"),
            paths.limits.process_cmdline_bytes,
            context,
        )?;
        let cmdline_matches = if let OptionalBytes::Bytes(cmdline) = &cmdline {
            let first = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
            paths
                .binaries
                .iter()
                .any(|binary| binary.as_os_str().as_bytes() == first)
        } else {
            false
        };
        if (exe_matches || cmdline_matches)
            && !process_id.is_some_and(|process_id| allowed_pids.contains(&process_id))
        {
            return Ok(ProbeFact::Present);
        }
        if let Err(source) = exe {
            unavailable |= source.kind() != io::ErrorKind::NotFound
                || (matches!(cmdline, OptionalBytes::Missing) && pid_path.exists());
        }
        if matches!(cmdline, OptionalBytes::Unavailable) {
            unavailable = true;
        }
    }
    context.check_active()?;
    Ok(if unavailable {
        ProbeFact::Unavailable
    } else {
        ProbeFact::Empty
    })
}

enum OptionalBytes {
    Missing,
    Unavailable,
    Bytes(Vec<u8>),
}

fn read_bounded_optional(
    path: &Path,
    cap: usize,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<OptionalBytes> {
    context.check_active()?;
    let file = match File::open(path) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            return Ok(OptionalBytes::Missing);
        }
        Err(source) if unavailable_io(&source) => return Ok(OptionalBytes::Unavailable),
        Err(source) => return Err(source).with_context(|| format!("open {}", path.display())),
    };
    let mut bytes = Vec::new();
    let mut reader = file.take(u64::try_from(cap)?.saturating_add(1));
    let mut buffer = [0_u8; 8 * 1024];
    loop {
        context.check_active()?;
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => bytes.extend_from_slice(&buffer[..read]),
            Err(source) if unavailable_io(&source) => return Ok(OptionalBytes::Unavailable),
            Err(source) => {
                return Err(source).with_context(|| format!("read {}", path.display()));
            }
        }
    }
    context.check_active()?;
    anyhow::ensure!(
        bytes.len() <= cap,
        "{} exceeds byte cap {cap}",
        path.display()
    );
    Ok(OptionalBytes::Bytes(bytes))
}

fn scan_nbd(
    root: &Path,
    cap: usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<ProbeFact> {
    let Some(entries) = required_directory_entries(root)? else {
        return Ok(ProbeFact::Unavailable);
    };
    let mut count = 0_usize;
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
            Err(source) => return Err(source).context("enumerate block class"),
        };
        count += 1;
        anyhow::ensure!(count <= cap, "block class exceeds entry cap {cap}");
        let name = entry.file_name();
        if !is_nbd_name(&name) {
            continue;
        }
        let pid = read_kernel_u64(&entry.path().join("pid"), context)?;
        let size = read_kernel_u64(&entry.path().join("size"), context)?;
        match (pid, size) {
            (_, KernelInteger::Value(size)) if size > 0 => {
                return Ok(ProbeFact::Present);
            }
            (KernelInteger::Value(pid), KernelInteger::Value(0)) if pid > 0 => {
                return Ok(ProbeFact::Present);
            }
            (KernelInteger::Missing | KernelInteger::Value(0), KernelInteger::Value(0)) => {}
            _ => return Ok(ProbeFact::Unavailable),
        }
    }
    Ok(ProbeFact::Empty)
}

fn is_nbd_name(name: &OsStr) -> bool {
    let bytes = name.as_bytes();
    bytes.starts_with(b"nbd") && bytes.len() > 3 && bytes[3..].iter().all(u8::is_ascii_digit)
}

enum KernelInteger {
    Missing,
    Unavailable,
    Value(u64),
}

fn read_kernel_u64(
    path: &Path,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<KernelInteger> {
    let bytes = match read_bounded_optional(path, 64, context)? {
        OptionalBytes::Missing => return Ok(KernelInteger::Missing),
        OptionalBytes::Unavailable => return Ok(KernelInteger::Unavailable),
        OptionalBytes::Bytes(bytes) => bytes,
    };
    let text = std::str::from_utf8(&bytes).context("kernel integer is not UTF-8")?;
    Ok(KernelInteger::Value(text.trim().parse().with_context(
        || format!("parse kernel integer {}", path.display()),
    )?))
}

fn scan_network_interfaces(
    root: &Path,
    cap: usize,
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<ProbeFact> {
    let Some(entries) = required_directory_entries(root)? else {
        return Ok(ProbeFact::Unavailable);
    };
    let mut count = 0_usize;
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
            Err(source) => return Err(source).context("enumerate network class"),
        };
        count += 1;
        anyhow::ensure!(count <= cap, "network class exceeds entry cap {cap}");
        if network_candidate(&entry.file_name()) {
            return Ok(ProbeFact::Present);
        }
    }
    Ok(ProbeFact::Empty)
}

fn network_candidate(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    let legacy = name.len() == 14
        && name.starts_with("cat")
        && name.as_bytes()[3..].iter().all(u8::is_ascii_hexdigit);
    legacy
        || name.starts_with("cats-tap")
        || name.starts_with("cats-tun")
        || name.starts_with("tap-cats")
        || name.starts_with("tun-cats")
}

fn socket_candidate(name: &OsStr) -> bool {
    name.as_bytes().ends_with(b".sock")
}

fn scan_root_process_sockets(
    state_directory: &StateDirectory,
    legacy_socket_root: &Path,
    allowed: &BTreeSet<PathBuf>,
    limits: ProbeLimits,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<ProbeFact> {
    let Some(root) = clone_state_root(state_directory)? else {
        return Ok(ProbeFact::Unavailable);
    };
    let ordinary = [
        scan_state_namespace(
            &root,
            CONTROL_SOCKET_NAMESPACE,
            limits.state_entries,
            context,
        )?,
        scan_managed_path_namespace(legacy_socket_root, limits.state_entries, context)?,
    ];
    if ordinary.contains(&ProbeFact::Present) {
        return Ok(ProbeFact::Present);
    }
    if ordinary.contains(&ProbeFact::Unavailable) {
        return Ok(ProbeFact::Unavailable);
    }

    let data_root = state_directory.path().join(DATA_NAMESPACE);
    let mut discovered = BTreeSet::new();
    let mut budget = limits.state_entries;
    match collect_managed_sockets(
        &data_root,
        0,
        limits.recursion_depth,
        &mut budget,
        context,
        &mut discovered,
    )? {
        ProbeFact::Unavailable => return Ok(ProbeFact::Unavailable),
        ProbeFact::Empty | ProbeFact::Present => {}
    }
    Ok(if discovered == *allowed {
        ProbeFact::Empty
    } else {
        ProbeFact::Present
    })
}

fn collect_managed_sockets(
    path: &Path,
    depth: usize,
    depth_cap: usize,
    budget: &mut usize,
    context: &dyn RuntimePhysicalReadContext,
    sockets: &mut BTreeSet<PathBuf>,
) -> anyhow::Result<ProbeFact> {
    context.check_active()?;
    if depth > depth_cap {
        bail!("root-provision socket scan exceeds recursion depth cap {depth_cap}")
    }
    let entries = match std::fs::read_dir(path) {
        Ok(entries) => entries,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(ProbeFact::Empty),
        Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
        Err(source) => return Err(source).with_context(|| format!("read {}", path.display())),
    };
    for entry in entries {
        context.check_active()?;
        let entry = match entry {
            Ok(entry) => entry,
            Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
            Err(source) => return Err(source).context("enumerate root-provision socket tree"),
        };
        *budget = budget
            .checked_sub(1)
            .context("root-provision socket tree exceeds entry cap")?;
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(source) if unavailable_io(&source) => return Ok(ProbeFact::Unavailable),
            Err(source) => return Err(source).context("inspect root-provision socket entry"),
        };
        anyhow::ensure!(
            !file_type.is_symlink(),
            "root-provision socket tree contains a symlink"
        );
        if file_type.is_dir() {
            if collect_managed_sockets(
                &entry.path(),
                depth + 1,
                depth_cap,
                budget,
                context,
                sockets,
            )? == ProbeFact::Unavailable
            {
                return Ok(ProbeFact::Unavailable);
            }
        } else if file_type.is_socket() {
            anyhow::ensure!(
                entry.file_name() == OsStr::new("root-provision.sock"),
                "authorized blockd data contains a foreign socket"
            );
            anyhow::ensure!(
                sockets.insert(entry.path()),
                "root-provision socket inventory duplicated one path"
            );
        }
    }
    Ok(if sockets.is_empty() {
        ProbeFact::Empty
    } else {
        ProbeFact::Present
    })
}

fn required_directory_entries(path: &Path) -> anyhow::Result<Option<std::fs::ReadDir>> {
    let metadata = match std::fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(source) if unavailable_io(&source) || source.kind() == io::ErrorKind::NotFound => {
            return Ok(None);
        }
        Err(source) => return Err(source).with_context(|| format!("inspect {}", path.display())),
    };
    anyhow::ensure!(
        metadata.is_dir() && !metadata.file_type().is_symlink(),
        "unsafe source root {}",
        path.display()
    );
    match std::fs::read_dir(path) {
        Ok(entries) => Ok(Some(entries)),
        Err(source) if unavailable_io(&source) => Ok(None),
        Err(source) => Err(source).with_context(|| format!("read {}", path.display())),
    }
}

fn unavailable_io(source: &io::Error) -> bool {
    matches!(
        source.kind(),
        io::ErrorKind::PermissionDenied
            | io::ErrorKind::TimedOut
            | io::ErrorKind::Interrupted
            | io::ErrorKind::WouldBlock
            | io::ErrorKind::UnexpectedEof
    ) || matches!(
        source.raw_os_error(),
        Some(libc::EIO) | Some(libc::ENXIO) | Some(libc::ESTALE)
    )
}

#[cfg(target_os = "linux")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() = value };
}

#[cfg(target_os = "linux")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn set_errno(value: libc::c_int) {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() = value };
}

#[cfg(target_os = "macos")]
fn errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's errno cell.
    unsafe { *libc::__error() }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, spec_digest, AcquireOrigin, AsciiText, AssignedKind,
        AssignedPlacement, CheckpointEvidence, CleanupRelease, CleanupTarget, ContractVersion,
        DesiredRuntimeSpec, DirectAuthorizedAttachmentIdentity, DirectAuthorizedAttachmentPurpose,
        DiskKind, Durability, Epoch, FenceEpoch, Generation, GuestDeviceIdentity, HostPath, Id,
        Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress, NetworkConfig, NodeBootId,
        NormalAcquireRequest, PrepareDeviceFrontend, RandomId128, ReconcileStep, RemoteHead,
        Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, RuntimeVolumeTransition,
        RuntimeVolumeTransitionPreconditionProblem, RuntimeVolumeTransitionRequest,
        ServingAuthorityProvenance, ServingBlockdIdentity, SessionBinding, Sha256Digest,
        UnixMillis, VolumeAccess, VolumeAcquire, VolumeAcquireRequest, VolumeDisposition,
        VolumeIntent, VolumeReleaseReplay, WireU64,
    };
    use cats_storage::{
        encode_image_manifest, AdapterConfig, AdapterSelection, BlobError, ImageManifestV1,
        LowerHexSha256,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::{
        RuntimeInventoryScanOutcome, RuntimeInventoryScanner, RuntimePreScanRecovery,
        RuntimePreScanRecoveryContext, RuntimePreScanRecoveryOutcome, RuntimeSpineFullScan,
    };

    use super::super::signed_running::{
        acquire_checkpoint, expected_provision_heads, prepared_owned_observed_volume,
        ProvisionHeadRead, SignedRunningPublicationRecovery,
    };
    use super::super::{AuthorizedBlockdStore, FileCheckpointStore, StoredCheckpoint};

    use super::*;

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    struct TestUnavailableBlobStore;

    impl BlobStore for TestUnavailableBlobStore {
        fn put_immutable(&self, key: &str, _data: &[u8]) -> Result<(), BlobError> {
            Err(test_blob_error(key))
        }

        fn get(&self, key: &str) -> Result<Vec<u8>, BlobError> {
            Err(test_blob_error(key))
        }

        fn exists(&self, key: &str) -> Result<bool, BlobError> {
            Err(test_blob_error(key))
        }

        fn delete(&self, key: &str) -> Result<(), BlobError> {
            Err(test_blob_error(key))
        }

        fn list(&self, prefix: &str) -> Result<Vec<String>, BlobError> {
            Err(test_blob_error(prefix))
        }
    }

    struct ExactManifestBlobStore(Vec<u8>);

    impl ExactManifestBlobStore {
        fn for_desired(desired: &DesiredRuntimeSpec) -> Self {
            Self(
                encode_image_manifest(&ImageManifestV1 {
                    version: 1,
                    image_id: LowerHexSha256::from_digest(&desired.runtime.boot_image_digest),
                    size_bytes: desired.volumes[0].size_bytes,
                    chunks: Vec::new(),
                })
                .unwrap(),
            )
        }
    }

    impl BlobStore for ExactManifestBlobStore {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> Result<(), BlobError> {
            unreachable!("inventory manifest fixture is read-only")
        }

        fn get(&self, _key: &str) -> Result<Vec<u8>, BlobError> {
            Ok(self.0.clone())
        }

        fn exists(&self, _key: &str) -> Result<bool, BlobError> {
            Ok(true)
        }

        fn delete(&self, _key: &str) -> Result<(), BlobError> {
            unreachable!("inventory manifest fixture is read-only")
        }

        fn list(&self, _prefix: &str) -> Result<Vec<String>, BlobError> {
            Ok(Vec::new())
        }
    }

    fn test_blob_error(key: &str) -> BlobError {
        BlobError::Backend {
            key: key.to_owned(),
            message: "test blob store unavailable".to_owned(),
        }
    }

    struct TestVolumeDataAuthority {
        present: bool,
        exact_record: Option<cats_storage::authority::VolumeRecord>,
        delay: Duration,
        calls: Arc<Mutex<Vec<Id>>>,
    }

    impl TestVolumeDataAuthority {
        fn missing() -> (Arc<dyn VolumeDataAuthority>, Arc<Mutex<Vec<Id>>>) {
            Self::with_behavior(false, Duration::ZERO)
        }

        fn present() -> (Arc<dyn VolumeDataAuthority>, Arc<Mutex<Vec<Id>>>) {
            Self::with_behavior(true, Duration::ZERO)
        }

        fn delayed(delay: Duration) -> (Arc<dyn VolumeDataAuthority>, Arc<Mutex<Vec<Id>>>) {
            Self::with_behavior(false, delay)
        }

        fn exact(
            record: cats_storage::authority::VolumeRecord,
        ) -> (Arc<dyn VolumeDataAuthority>, Arc<Mutex<Vec<Id>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Arc::new(Self {
                    present: false,
                    exact_record: Some(record),
                    delay: Duration::ZERO,
                    calls: Arc::clone(&calls),
                }),
                calls,
            )
        }

        fn with_behavior(
            present: bool,
            delay: Duration,
        ) -> (Arc<dyn VolumeDataAuthority>, Arc<Mutex<Vec<Id>>>) {
            let calls = Arc::new(Mutex::new(Vec::new()));
            (
                Arc::new(Self {
                    present,
                    exact_record: None,
                    delay,
                    calls: Arc::clone(&calls),
                }),
                calls,
            )
        }
    }

    impl VolumeDataAuthority for TestVolumeDataAuthority {
        fn load_volume(
            &self,
            volume_id: &Id,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeRecord> {
            self.calls.lock().unwrap().push(volume_id.clone());
            std::thread::sleep(self.delay);
            if let Some(record) = &self.exact_record {
                return if record.volume_id == *volume_id {
                    Ok(record.clone())
                } else {
                    Err(cats_storage::authority::AuthorityError::NotFound)
                };
            }
            if !self.present {
                return Err(cats_storage::authority::AuthorityError::NotFound);
            }
            Ok(cats_storage::authority::VolumeRecord {
                volume_id: volume_id.clone(),
                size_bytes: 4096,
                durability: cats_storage::authority::VolumeDurability::Strict,
                admin_state: cats_storage::authority::VolumeAdminState::Active,
                head: cats_storage::authority::RemoteHead {
                    generation: cats_storage::authority::Generation::new(0).unwrap(),
                    root_hash: None,
                    root_object_id: None,
                },
                lease_owner: None,
                lease_epoch: FenceEpoch::new(0).unwrap(),
                lease_expires_at: None,
                last_transition: None,
            })
        }

        fn renew_lease(
            &self,
            _request: &cats_storage::authority::RenewLeaseRequest,
        ) -> cats_storage::authority::Result<cats_storage::authority::RenewLeaseResult> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }

        fn compare_and_swap_head(
            &self,
            _request: &cats_storage::authority::VolumeHeadCasRequest,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeHeadCasResult> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }
    }

    struct TestUnavailableRuntimeVolumeInventoryAuthority;

    impl RuntimeVolumeInventoryAuthority for TestUnavailableRuntimeVolumeInventoryAuthority {
        fn load_node_volume_inventory(
            &self,
            _node_id: &Id,
            _candidate_volume_ids: &BTreeSet<Id>,
        ) -> cats_storage::authority::Result<NodeVolumeInventorySnapshot> {
            Err(cats_storage::authority::AuthorityError::BackendUnknown)
        }
    }

    struct TestRuntimeVolumeInventoryAuthority {
        snapshot: NodeVolumeInventorySnapshot,
        delay: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl RuntimeVolumeInventoryAuthority for TestRuntimeVolumeInventoryAuthority {
        fn load_node_volume_inventory(
            &self,
            node_id: &Id,
            _candidate_volume_ids: &BTreeSet<Id>,
        ) -> cats_storage::authority::Result<NodeVolumeInventorySnapshot> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            std::thread::sleep(self.delay);
            let mut snapshot = self.snapshot.clone();
            snapshot.node_id = node_id.clone();
            Ok(snapshot)
        }
    }

    #[derive(Debug, Clone, Copy)]
    enum MetadataReaderBehavior {
        AuthoritativeEmpty,
        Unavailable,
        TimedOut,
        Cancelled,
        Orphan,
        WrongOwner,
        ReturnAfterDeadline,
        CancelDuringRead,
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    struct MetadataReadCall {
        node_id: Id,
        candidate_volume_ids: BTreeSet<Id>,
        deadline: Instant,
    }

    #[derive(Debug)]
    struct RecordingMetadataAuthorityReader {
        behavior: MetadataReaderBehavior,
        calls: Arc<Mutex<Vec<MetadataReadCall>>>,
    }

    #[derive(Debug)]
    struct ScriptedMetadataAuthorityInventoryPort {
        reads: Mutex<VecDeque<MetadataAuthorityPageRead>>,
        calls: Arc<Mutex<Vec<MetadataAuthorityPageRequest>>>,
    }

    #[derive(Debug)]
    struct BoundaryMetadataAuthorityInventoryPort {
        total_records: usize,
        calls: Arc<AtomicUsize>,
    }

    impl metadata_authority_reader_sealed::Sealed for ScriptedMetadataAuthorityInventoryPort {}

    impl MetadataAuthorityInventoryPort for ScriptedMetadataAuthorityInventoryPort {
        fn read_page(
            &self,
            request: &MetadataAuthorityPageRequest,
            deadline: Instant,
            context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<MetadataAuthorityPageRead> {
            assert_eq!(deadline, context.deadline());
            context.check_active()?;
            self.calls.lock().unwrap().push(request.clone());
            Ok(self
                .reads
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(MetadataAuthorityPageRead::Unavailable))
        }
    }

    impl metadata_authority_reader_sealed::Sealed for BoundaryMetadataAuthorityInventoryPort {}

    impl MetadataAuthorityInventoryPort for BoundaryMetadataAuthorityInventoryPort {
        fn read_page(
            &self,
            request: &MetadataAuthorityPageRequest,
            deadline: Instant,
            context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<MetadataAuthorityPageRead> {
            assert_eq!(deadline, context.deadline());
            context.check_active()?;
            assert_eq!(request.limit, METADATA_AUTHORITY_PAGE_LIMIT);
            let start = request.after_volume_id.as_ref().map_or(0, |volume_id| {
                volume_id
                    .as_str()
                    .strip_prefix("vol_")
                    .unwrap()
                    .parse::<usize>()
                    .unwrap()
                    + 1
            });
            let end = start.saturating_add(request.limit).min(self.total_records);
            let records = (start..end)
                .map(|index| MetadataAuthorityIndexedRecord {
                    record: unowned_record(&boundary_volume_id(index), 4_096),
                    owner_node_id: None,
                })
                .collect::<Vec<_>>();
            let next_after_volume_id =
                (!records.is_empty()).then(|| Id::new(boundary_volume_id(end - 1)).unwrap());
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(MetadataAuthorityPageRead::Page(MetadataAuthorityPage {
                node_id: request.node_id.clone(),
                desired_read_position: request.desired_read_position,
                snapshot_read_position: Sequence::new(77).unwrap(),
                records,
                next_after_volume_id,
            }))
        }
    }

    fn boundary_volume_id(index: usize) -> String {
        format!("vol_{index:05}")
    }

    fn boundary_volume_ids(count: usize) -> BTreeSet<Id> {
        (0..count)
            .map(|index| Id::new(boundary_volume_id(index)).unwrap())
            .collect()
    }

    fn boundary_metadata_inventory_port(
        total_records: usize,
    ) -> (Arc<dyn MetadataAuthorityInventoryPort>, Arc<AtomicUsize>) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Arc::new(BoundaryMetadataAuthorityInventoryPort {
                total_records,
                calls: calls.clone(),
            }),
            calls,
        )
    }

    fn scripted_metadata_inventory_port(
        reads: impl IntoIterator<Item = MetadataAuthorityPageRead>,
    ) -> (
        Arc<dyn MetadataAuthorityInventoryPort>,
        Arc<Mutex<Vec<MetadataAuthorityPageRequest>>>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(ScriptedMetadataAuthorityInventoryPort {
                reads: Mutex::new(reads.into_iter().collect()),
                calls: calls.clone(),
            }),
            calls,
        )
    }

    impl metadata_authority_reader_sealed::Sealed for RecordingMetadataAuthorityReader {}

    impl MetadataAuthorityAbsenceReader for RecordingMetadataAuthorityReader {
        fn read_candidates(
            &self,
            node_id: &Id,
            candidate_volume_ids: &BTreeSet<Id>,
            deadline: Instant,
            context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
            assert_eq!(deadline, context.deadline());
            context.check_active()?;
            self.calls.lock().unwrap().push(MetadataReadCall {
                node_id: node_id.clone(),
                candidate_volume_ids: candidate_volume_ids.clone(),
                deadline,
            });
            match self.behavior {
                MetadataReaderBehavior::AuthoritativeEmpty => {
                    Ok(MetadataAuthorityCandidateInventory::Records(BTreeMap::new()))
                }
                MetadataReaderBehavior::Unavailable
                | MetadataReaderBehavior::TimedOut
                | MetadataReaderBehavior::Cancelled
                | MetadataReaderBehavior::Orphan
                | MetadataReaderBehavior::WrongOwner => {
                    Ok(MetadataAuthorityCandidateInventory::Unavailable)
                }
                MetadataReaderBehavior::ReturnAfterDeadline => {
                    while Instant::now() < deadline {
                        std::thread::yield_now();
                    }
                    Ok(MetadataAuthorityCandidateInventory::Records(BTreeMap::new()))
                }
                MetadataReaderBehavior::CancelDuringRead => {
                    context.cancel_for_test();
                    Ok(MetadataAuthorityCandidateInventory::Records(BTreeMap::new()))
                }
            }
        }
    }

    fn recording_metadata_reader(
        behavior: MetadataReaderBehavior,
    ) -> (
        Arc<dyn MetadataAuthorityAbsenceReader>,
        Arc<Mutex<Vec<MetadataReadCall>>>,
    ) {
        let calls = Arc::new(Mutex::new(Vec::new()));
        (
            Arc::new(RecordingMetadataAuthorityReader {
                behavior,
                calls: calls.clone(),
            }),
            calls,
        )
    }

    struct TestEnvironment {
        _root: TempDir,
        state: PathBuf,
        proc_root: PathBuf,
        systemd_root: PathBuf,
        block_root: PathBuf,
        network_root: PathBuf,
        socket_root: PathBuf,
        ch_binary: PathBuf,
        blockd_binary: PathBuf,
        guest_binary: PathBuf,
    }

    impl TestEnvironment {
        fn new() -> Self {
            // Root-provision control sockets are deliberately nested below
            // the exact attachment lineage. Keep this fixture under /tmp so
            // the real Unix-domain pathname remains below SUN_LEN on macOS.
            let root = tempfile::Builder::new()
                .prefix("c")
                .tempdir_in("/tmp")
                .unwrap();
            let state = root.path().join("state");
            let proc_root = root.path().join("proc");
            let systemd_root = root.path().join("system.slice");
            let block_root = root.path().join("block");
            let network_root = root.path().join("net");
            let socket_root = root.path().join("sockets");
            for directory in [
                &state,
                &proc_root,
                &systemd_root,
                &block_root,
                &network_root,
                &socket_root,
            ] {
                std::fs::create_dir(directory).unwrap();
            }
            Self {
                ch_binary: root.path().join("bin/cloud-hypervisor"),
                blockd_binary: root.path().join("bin/cats-blockd"),
                guest_binary: root.path().join("bin/cats-guest-agent"),
                _root: root,
                state,
                proc_root,
                systemd_root,
                block_root,
                network_root,
                socket_root,
            }
        }

        fn config(&self) -> ProbeConfig {
            ProbeConfig {
                state_directory: StateDirectory::unanchored(self.state.clone()),
                checkpoint_directory: self.state.join(CHECKPOINT_NAMESPACE),
                proc_root: self.proc_root.clone(),
                systemd_cgroup_root: self.systemd_root.clone(),
                metering_cgroup_root: None,
                block_class_root: self.block_root.clone(),
                network_class_root: self.network_root.clone(),
                legacy_socket_root: self.socket_root.clone(),
                cloud_hypervisor_binary: self.ch_binary.clone(),
                blockd_binary: self.blockd_binary.clone(),
                guest_agent_binary: self.guest_binary.clone(),
                linux_sources_supported: true,
                limits: ProbeLimits::default(),
                root_process_port: None,
            }
        }
    }

    fn metadata_probe(
        environment: &TestEnvironment,
        authority: Arc<dyn MetadataAuthorityAbsenceReader>,
    ) -> MetadataStoreProbe {
        MetadataStoreProbe {
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            authority,
            limits: ProbeLimits::default(),
        }
    }

    fn context() -> RuntimeInventoryScanContext {
        context_until(Instant::now() + Duration::from_secs(5))
    }

    fn context_until(deadline: Instant) -> RuntimeInventoryScanContext {
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        RuntimeInventoryScanContext::for_test(
            RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: desired.session.node_id.clone(),
                    node_boot_id: desired.session.node_boot_id.clone(),
                    agent_instance_id: desired.session.agent_instance_id.clone(),
                    agent_session_epoch: desired.session.agent_session_epoch,
                },
                heartbeat_sequence: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            deadline,
        )
    }

    fn assigned_context(with_volume: bool) -> RuntimeInventoryScanContext {
        let mut context = context();
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: Id::new("ws_01").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: Id::new("node_a").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2_147_483_648,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: Id::new("net_01").unwrap(),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: Vec::new(),
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        if with_volume {
            desired.volumes.push(VolumeIntent {
                volume_intent_id: Id::new("vint_root").unwrap(),
                disk_id: Id::new("disk_root").unwrap(),
                volume_id: Id::new("vol_root").unwrap(),
                attachment_id: Id::new("att_root").unwrap(),
                size_bytes: 4_294_967_296,
                disk_kind: DiskKind::Root,
                access: VolumeAccess::ReadWriteOnce,
                durability: Durability::Strict,
                guest_device: GuestDeviceIdentity {
                    serial: Id::new("cats-root").unwrap(),
                    slot: 0,
                },
                acquire: VolumeAcquire::Normal {
                    transition_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
                    expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                },
                disposition: VolumeDisposition::Retain,
                mount: None,
            });
        }
        desired.spec_digest = spec_digest(&desired).unwrap();
        context
            .coordinates_mut()
            .desired
            .desired_specs
            .push(desired);
        context
    }

    fn unowned_record(volume_id: &str, size_bytes: u64) -> VolumeRecord {
        VolumeRecord {
            volume_id: Id::new(volume_id).unwrap(),
            size_bytes,
            durability: Durability::Strict,
            admin_state: VolumeAdminState::Active,
            head: cats_storage::authority::RemoteHead {
                generation: cats_storage::authority::Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            lease_owner: None,
            lease_epoch: FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        }
    }

    fn exact_owned_record_and_attachment(
        desired: &DesiredRuntimeSpec,
    ) -> (VolumeRecord, AuthorizedServingAttachment) {
        let volume = &desired.volumes[0];
        let VolumeAcquire::Normal {
            transition_id,
            expected_unowned_epoch,
        } = &volume.acquire
        else {
            unreachable!("the fixture has one normal-acquire root")
        };
        let request = NormalAcquireRequest {
            volume_id: volume.volume_id.clone(),
            transition_id: transition_id.clone(),
            attachment_id: volume.attachment_id.clone(),
            expected_unowned_epoch: *expected_unowned_epoch,
            desired_revision: desired.desired_revision,
            placement_epoch: desired.placement.placement_epoch,
            lease_duration_ms: 60_000,
        };
        let (record, result) = cats_storage::authority::normal_acquire(
            &unowned_record(volume.volume_id.as_str(), volume.size_bytes),
            &request,
            cats_storage::authority::UnixMillis::new(10_000).unwrap(),
        )
        .unwrap();
        let attachment = AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: volume.volume_id.clone(),
                attachment_id: volume.attachment_id.clone(),
                attachment_epoch: result.resulting_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition_id.clone(),
                },
                node_id: desired.placement.node_id.clone(),
                placement_epoch: desired.placement.placement_epoch,
            },
            size_bytes: volume.size_bytes,
            durability: volume.durability,
            head: record.head.clone(),
            lease_expires_at: result.lease_expires_at,
            acquire_request: request,
            acquire_result: result,
        };
        (record, attachment)
    }

    fn prepare_exact_lineage(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) -> PathBuf {
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                .prepare(desired, &desired.volumes[0], attachment)
                .unwrap();
        prepared.data_directory().to_path_buf()
    }

    struct FakeRootProcessPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
    }

    impl super::super::root_provision_process::sealed::Sealed for FakeRootProcessPort {}

    impl RootProvisionProcessPort for FakeRootProcessPort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            self.inspections
                .lock()
                .unwrap()
                .pop_front()
                .context("fake root-process inspection exhausted")
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::root_provision_process::CheckpointedRootProvisionProcess<
                '_,
            >,
            _context: &crate::runtime_spine::RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::root_provision_process::RootProvisionProcessStart>
        {
            unreachable!("inventory bridge is read-only")
        }
    }

    fn root_process_expectation(
        environment: &TestEnvironment,
    ) -> (RootProvisionProcessExpectation, PathBuf) {
        let scan_context = assigned_context(true);
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (record, attachment) = exact_owned_record_and_attachment(desired);
        let data_directory = prepare_exact_lineage(environment, desired, &attachment);
        let mut checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: attachment.acquire_request.volume_id.clone(),
                    transition_id: attachment.acquire_request.transition_id.clone(),
                    attachment_id: attachment.acquire_request.attachment_id.clone(),
                    expected_unowned_epoch: attachment.acquire_request.expected_unowned_epoch,
                    desired_revision: attachment.acquire_request.desired_revision,
                    placement_epoch: attachment.acquire_request.placement_epoch,
                    lease_duration_ms: attachment.acquire_request.lease_duration_ms,
                },
            },
            cats_api::runtime_reconciliation::UnixMillis::new(9_000).unwrap(),
        );
        let token = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let scope_id = Id::new("cats-root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service").unwrap();
        let data = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
        checkpoint.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            scope_id,
            control_socket_path: HostPath::new(
                data_directory
                    .join("root-provision.sock")
                    .to_string_lossy()
                    .into_owned(),
            )
            .unwrap(),
            data_directory: data,
            process_identity_token: token,
            size_bytes: attachment.size_bytes,
            boot_image_digest: desired.runtime.boot_image_digest.clone(),
            expected_blank_head: attachment.head.clone(),
            expected_provisioned_head: RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes([7; 32])),
                root_object_id: Some(AsciiText::new("roots/test").unwrap()),
            },
        };
        let expectation = RootProvisionProcessExpectation::from_checkpoint(
            &checkpoint,
            super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                attachment,
                volume: &record,
            },
            HostPath::new(environment.blockd_binary.to_string_lossy().into_owned()).unwrap(),
        )
        .unwrap();
        (expectation, data_directory)
    }

    fn exact_process_evidence(
        expected: &RootProvisionProcessExpectation,
        process_id: u32,
    ) -> super::super::root_provision_process::RootProvisionProcessEvidence {
        super::super::root_provision_process::RootProvisionProcessEvidence {
            process_id,
            unit_main_process_id: process_id,
            process_start_time_ticks: WireU64::new(123).unwrap(),
            executable_path: expected.executable_path.clone(),
            scope_id: expected.scope_id.clone(),
            cgroup_path: expected.cgroup_path.clone(),
            cgroup_process_ids: vec![process_id],
            control_socket_path: expected.control_socket_path.clone(),
            data_directory: expected.data_directory.clone(),
            ownership_token: expected.process_identity_token.clone(),
            handshake: super::super::root_provision_process::RootProvisionBlockdHandshake {
                peer_process_id: process_id,
                identity: expected.attachment.identity.clone(),
                size_bytes: expected.size_bytes,
                durability: expected.attachment.durability,
                remote_head: expected.expected_remote_head().clone(),
                process_identity_token: expected.process_identity_token.clone(),
                control_only: true,
                guest_io_enabled: false,
            },
        }
    }

    fn root_process_bridge(
        environment: &TestEnvironment,
        inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
    ) -> PlatformRootProcessInventoryBridge {
        PlatformRootProcessInventoryBridge {
            port: Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(inspections.into_iter().collect()),
            }),
            executable_path: HostPath::new(
                environment.blockd_binary.to_string_lossy().into_owned(),
            )
            .unwrap(),
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            process_paths: ProcessPaths {
                root: environment.proc_root.clone(),
                binaries: vec![environment.blockd_binary.clone()],
                supported: true,
                limits: ProbeLimits::default(),
            },
            systemd_root: environment.systemd_root.clone(),
            metering_root: None,
            legacy_socket_root: environment.socket_root.clone(),
            limits: ProbeLimits::default(),
        }
    }

    fn persist_acquire_checkpoint(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) {
        let request = &attachment.acquire_request;
        let checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: request.volume_id.clone(),
                    transition_id: request.transition_id.clone(),
                    attachment_id: request.attachment_id.clone(),
                    expected_unowned_epoch: request.expected_unowned_epoch,
                    desired_revision: request.desired_revision,
                    placement_epoch: request.placement_epoch,
                    lease_duration_ms: request.lease_duration_ms,
                },
            },
            cats_api::runtime_reconciliation::UnixMillis::new(9_000).unwrap(),
        );
        FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap()
        .create(&checkpoint)
        .unwrap();
    }

    fn authorized_data_probe(environment: &TestEnvironment) -> AuthorizedBlockdDataProbe {
        AuthorizedBlockdDataProbe {
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            reject_legacy_root: true,
            limits: ProbeLimits::default(),
        }
    }

    fn write_empty_dirty_bitmap(path: &Path, size_bytes: u64) {
        use std::os::unix::fs::PermissionsExt as _;

        let chunk_count = chunk::chunk_count(size_bytes);
        let mut bytes = cats_blockd::format::encode_bitmap_header(chunk_count);
        bytes.resize(
            usize::try_from(BITMAP_HEADER_LEN + chunk_count * 8).unwrap(),
            0,
        );
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn install_exact_control_only_files(data_directory: &Path, size_bytes: u64) {
        use std::os::unix::fs::PermissionsExt as _;

        let cache = std::fs::File::create(data_directory.join("cache.data")).unwrap();
        cache.set_len(size_bytes).unwrap();
        std::fs::set_permissions(
            data_directory.join("cache.data"),
            std::fs::Permissions::from_mode(0o600),
        )
        .unwrap();
        write_empty_dirty_bitmap(&data_directory.join("dirty.bitmap"), size_bytes);
        std::fs::create_dir(data_directory.join("pending-packs")).unwrap();
        std::fs::set_permissions(
            data_directory.join("pending-packs"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn authorized_data_probe_accepts_exact_control_only_engine_files_and_socket() {
        use std::os::unix::fs::PermissionsExt as _;

        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (_record, attachment) = exact_owned_record_and_attachment(desired);
        let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
        install_exact_control_only_files(&data_directory, attachment.size_bytes);
        let _socket =
            std::os::unix::net::UnixListener::bind(data_directory.join("root-provision.sock"))
                .unwrap();
        std::fs::set_permissions(
            data_directory.join("root-provision.sock"),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();

        assert!(matches!(
            authorized_data_probe(&environment)
                .prove_absent(&scan_context)
                .unwrap(),
            InventoryAbsence::AuthorizedBlockd(evidence)
                if matches!(
                    evidence.get(&desired.cat_id).map(|item| &item.control_state),
                    Some(AuthorizedBlockdControlState::ExactControlOnlyEmpty)
                )
        ));
    }

    #[test]
    fn authorized_data_probe_rejects_nonempty_malformed_or_wrong_length_dirty_bitmap() {
        use std::os::unix::fs::PermissionsExt as _;

        for mutation in ["nonzero", "bad-header", "wrong-length"] {
            let environment = TestEnvironment::new();
            let scan_context = assigned_context(true);
            let desired = &scan_context.coordinates().desired.desired_specs[0];
            let (_record, attachment) = exact_owned_record_and_attachment(desired);
            let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
            let cache = std::fs::File::create(data_directory.join("cache.data")).unwrap();
            cache.set_len(attachment.size_bytes).unwrap();
            std::fs::set_permissions(
                data_directory.join("cache.data"),
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();
            let bitmap_path = data_directory.join("dirty.bitmap");
            write_empty_dirty_bitmap(&bitmap_path, attachment.size_bytes);
            let mut before = std::fs::read(&bitmap_path).unwrap();
            match mutation {
                "nonzero" => *before.last_mut().unwrap() = 1,
                "bad-header" => before[0] ^= 0xff,
                "wrong-length" => {
                    before.pop();
                }
                _ => unreachable!(),
            }
            std::fs::write(&bitmap_path, &before).unwrap();
            std::fs::set_permissions(&bitmap_path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::create_dir(data_directory.join("pending-packs")).unwrap();
            std::fs::set_permissions(
                data_directory.join("pending-packs"),
                std::fs::Permissions::from_mode(0o700),
            )
            .unwrap();

            assert_eq!(
                authorized_data_probe(&environment)
                    .prove_absent(&scan_context)
                    .unwrap(),
                InventoryAbsence::Unavailable,
                "{mutation}"
            );
            assert_eq!(std::fs::read(&bitmap_path).unwrap(), before, "{mutation}");
        }
    }

    #[test]
    fn dirty_bitmap_descriptor_rejects_chmod_after_enumeration_without_cleanup() {
        use std::os::unix::fs::PermissionsExt as _;

        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (_record, attachment) = exact_owned_record_and_attachment(desired);
        let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
        install_exact_control_only_files(&data_directory, attachment.size_bytes);
        let bitmap_path = data_directory.join("dirty.bitmap");
        let before = std::fs::read(&bitmap_path).unwrap();
        let root = File::open(&environment.state).unwrap();
        let directory = File::open(&data_directory).unwrap();
        let entry = StrictDirectoryEntry {
            name: OsString::from("dirty.bitmap"),
            metadata: stat_at(&directory, OsStr::new("dirty.bitmap")).unwrap(),
        };

        std::fs::set_permissions(&bitmap_path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(inspect_empty_dirty_bitmap_at(
            &directory,
            &entry,
            &root,
            attachment.size_bytes,
            &scan_context,
        )
        .unwrap()
        .is_none());
        assert_eq!(std::fs::read(&bitmap_path).unwrap(), before);
        assert_eq!(
            std::fs::metadata(&bitmap_path).unwrap().mode() & 0o777,
            0o644
        );
    }

    #[test]
    fn unvalidated_target_control_and_handoff_artifacts_are_preserved_as_unavailable() {
        use std::os::unix::fs::PermissionsExt as _;

        for name in [
            "authorized-target-control-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json",
            ".authorized-target-control-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.json.tmp",
            "serving-handoff.json",
            ".serving-handoff.json.tmp",
        ] {
            let environment = TestEnvironment::new();
            let scan_context = assigned_context(true);
            let desired = &scan_context.coordinates().desired.desired_specs[0];
            let (_record, attachment) = exact_owned_record_and_attachment(desired);
            let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
            let path = data_directory.join(name);
            std::fs::write(&path, b"retained-unvalidated-artifact").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

            assert_eq!(
                authorized_data_probe(&environment)
                    .prove_absent(&scan_context)
                    .unwrap(),
                InventoryAbsence::Unavailable,
                "{name}"
            );
            assert_eq!(
                std::fs::read(path).unwrap(),
                b"retained-unvalidated-artifact",
                "{name}"
            );
        }
    }

    fn leaf_snapshot(directory: &Path) -> Vec<(OsString, Vec<u8>)> {
        let mut entries = std::fs::read_dir(directory)
            .unwrap()
            .map(|entry| {
                let entry = entry.unwrap();
                (entry.file_name(), std::fs::read(entry.path()).unwrap())
            })
            .collect::<Vec<_>>();
        entries.sort_by(|left, right| left.0.cmp(&right.0));
        entries
    }

    fn owned_record(volume_id: &str, attachment_id: &str) -> VolumeRecord {
        let predecessor = unowned_record(volume_id, 4_096);
        cats_storage::authority::normal_acquire(
            &predecessor,
            &cats_storage::authority::NormalAcquireRequest {
                volume_id: predecessor.volume_id.clone(),
                transition_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
                attachment_id: Id::new(attachment_id).unwrap(),
                expected_unowned_epoch: predecessor.lease_epoch,
                desired_revision: Revision::new(1).unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
                lease_duration_ms: 5_000,
            },
            cats_storage::authority::UnixMillis::new(10_000).unwrap(),
        )
        .unwrap()
        .0
    }

    fn inventory_snapshot(
        records: Vec<(VolumeRecord, Option<&str>)>,
    ) -> NodeVolumeInventorySnapshot {
        let mut records = records
            .into_iter()
            .map(|(volume, owner_node_id)| {
                let binding = match (&volume.lease_owner, owner_node_id) {
                    (Some(attachment_id), Some(owner_node_id)) => {
                        Some(cats_storage::authority::VolumeOwnerBinding {
                            volume_id: volume.volume_id.clone(),
                            owner_node_id: Id::new(owner_node_id).unwrap(),
                            attachment_id: attachment_id.clone(),
                            attachment_epoch: volume.lease_epoch,
                        })
                    }
                    (None, None) => None,
                    _ => panic!("test owner binding must match the Volume record"),
                };
                cats_storage::authority::NodeVolumeInventoryRecord { binding, volume }
            })
            .collect::<Vec<_>>();
        records.sort_by(|left, right| left.volume.volume_id.cmp(&right.volume.volume_id));
        NodeVolumeInventorySnapshot {
            node_id: Id::new("node_a").unwrap(),
            read_at_unix_ms: cats_storage::authority::UnixMillis::new(1).unwrap(),
            records,
        }
    }

    fn metadata_page(
        records: Vec<MetadataAuthorityIndexedRecord>,
        next_after_volume_id: Option<&str>,
    ) -> MetadataAuthorityPageRead {
        MetadataAuthorityPageRead::Page(MetadataAuthorityPage {
            node_id: Id::new("node_a").unwrap(),
            desired_read_position: Sequence::new(12).unwrap(),
            snapshot_read_position: Sequence::new(77).unwrap(),
            records,
            next_after_volume_id: next_after_volume_id.map(|value| Id::new(value).unwrap()),
        })
    }

    #[test]
    fn explicit_unavailable_metadata_port_never_completes_inventory() {
        let environment = TestEnvironment::new();
        let reader = Arc::new(PagedMetadataAuthorityReader::new(Arc::new(
            UnavailableMetadataAuthorityInventoryPort,
        )));
        assert_eq!(
            metadata_probe(&environment, reader)
                .prove_absent(&assigned_context(true))
                .unwrap(),
            InventoryAbsence::Unavailable
        );
    }

    #[test]
    fn every_authorized_blockd_partial_publish_window_is_unavailable_then_recovers_exactly() {
        #[derive(Debug, Clone, Copy)]
        enum Window {
            DirectoryOnly,
            IdentityTemp,
            IdentityTarget,
            AuthorizedServingTemp,
            AuthorizedServingTarget,
            LaunchCheckpointTemp,
        }

        for window in [
            Window::DirectoryOnly,
            Window::IdentityTemp,
            Window::IdentityTarget,
            Window::AuthorizedServingTemp,
            Window::AuthorizedServingTarget,
            Window::LaunchCheckpointTemp,
        ] {
            let environment = TestEnvironment::new();
            let scan_context = assigned_context(true);
            let desired = scan_context.coordinates().desired.desired_specs[0].clone();
            let (_record, attachment) = exact_owned_record_and_attachment(&desired);
            let data_directory = prepare_exact_lineage(&environment, &desired, &attachment);
            let target = |name: &str| data_directory.join(name);

            match window {
                Window::DirectoryOnly => {
                    for name in [
                        IDENTITY_FILE,
                        AUTHORIZED_SERVING_FILE,
                        LAUNCH_CHECKPOINT_FILE,
                    ] {
                        std::fs::remove_file(target(name)).unwrap();
                    }
                }
                Window::IdentityTemp => {
                    std::fs::remove_file(target(AUTHORIZED_SERVING_FILE)).unwrap();
                    std::fs::remove_file(target(LAUNCH_CHECKPOINT_FILE)).unwrap();
                    std::fs::rename(target(IDENTITY_FILE), target(IDENTITY_TEMP)).unwrap();
                }
                Window::IdentityTarget => {
                    std::fs::remove_file(target(AUTHORIZED_SERVING_FILE)).unwrap();
                    std::fs::remove_file(target(LAUNCH_CHECKPOINT_FILE)).unwrap();
                }
                Window::AuthorizedServingTemp => {
                    std::fs::remove_file(target(LAUNCH_CHECKPOINT_FILE)).unwrap();
                    std::fs::rename(
                        target(AUTHORIZED_SERVING_FILE),
                        target(AUTHORIZED_SERVING_TEMP),
                    )
                    .unwrap();
                }
                Window::AuthorizedServingTarget => {
                    std::fs::remove_file(target(LAUNCH_CHECKPOINT_FILE)).unwrap();
                }
                Window::LaunchCheckpointTemp => {
                    std::fs::rename(
                        target(LAUNCH_CHECKPOINT_FILE),
                        target(LAUNCH_CHECKPOINT_TEMP),
                    )
                    .unwrap();
                }
            }

            let before = leaf_snapshot(&data_directory);
            assert_eq!(
                authorized_data_probe(&environment)
                    .prove_absent(&scan_context)
                    .unwrap(),
                InventoryAbsence::Unavailable,
                "partial window {window:?} must not project a lineage"
            );
            assert_eq!(leaf_snapshot(&data_directory), before);

            let recovered = prepare_exact_lineage(&environment, &desired, &attachment);
            assert_eq!(recovered, data_directory);
            let InventoryAbsence::AuthorizedBlockd(evidence) = authorized_data_probe(&environment)
                .prove_absent(&scan_context)
                .unwrap()
            else {
                panic!("exact writer recovery must close partial window {window:?}")
            };
            assert_eq!(evidence.len(), 1);
            assert_eq!(evidence[&desired.cat_id].checkpoint.attachment, attachment);
        }
    }

    #[test]
    fn foreign_unsafe_and_duplicate_authorized_lineages_fail_closed_without_cleanup() {
        enum Residue {
            ForeignCat,
            DuplicateEpoch,
            Symlink,
            Hardlink,
        }

        for residue in [
            Residue::ForeignCat,
            Residue::DuplicateEpoch,
            Residue::Symlink,
            Residue::Hardlink,
        ] {
            let environment = TestEnvironment::new();
            let scan_context = assigned_context(true);
            let desired = scan_context.coordinates().desired.desired_specs[0].clone();
            let (_record, attachment) = exact_owned_record_and_attachment(&desired);
            let data_directory = prepare_exact_lineage(&environment, &desired, &attachment);

            let retained_path = match residue {
                Residue::ForeignCat => {
                    let path = environment.state.join(DATA_NAMESPACE).join("cat-foreign");
                    std::fs::create_dir(&path).unwrap();
                    path
                }
                Residue::DuplicateEpoch => {
                    let path = data_directory.parent().unwrap().join("epoch-2");
                    std::fs::create_dir(&path).unwrap();
                    path
                }
                Residue::Symlink => {
                    let identity = data_directory.join(IDENTITY_FILE);
                    let backing = environment.state.join("foreign-identity.json");
                    std::fs::rename(&identity, &backing).unwrap();
                    std::os::unix::fs::symlink(&backing, &identity).unwrap();
                    identity
                }
                Residue::Hardlink => {
                    let path = data_directory.join(IDENTITY_TEMP);
                    std::fs::hard_link(data_directory.join(IDENTITY_FILE), &path).unwrap();
                    path
                }
            };

            authorized_data_probe(&environment)
                .prove_absent(&scan_context)
                .expect_err("foreign, unsafe or duplicate lineage must be residue");
            assert!(
                std::fs::symlink_metadata(&retained_path).is_ok(),
                "the read-only probe must preserve residue"
            );
        }
    }

    #[test]
    fn duplicate_cat_checkpoint_representation_is_residue_and_is_preserved() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = scan_context.coordinates().desired.desired_specs[0].clone();
        let (_record, attachment) = exact_owned_record_and_attachment(&desired);
        persist_acquire_checkpoint(&environment, &desired, &attachment);
        let checkpoint_directory = environment.state.join(CHECKPOINT_NAMESPACE);
        let target = super::super::runtime_checkpoint_path(&checkpoint_directory, &desired.cat_id);
        let duplicate = checkpoint_directory.join("cat-cat_01.duplicate.checkpoint.json");
        std::fs::copy(&target, &duplicate).unwrap();
        std::fs::set_permissions(
            &duplicate,
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o600),
        )
        .unwrap();
        let before = std::fs::read(&duplicate).unwrap();

        RuntimeCheckpointProbe {
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            reject_legacy_root: true,
            limits: ProbeLimits::default(),
        }
        .prove_absent(&scan_context)
        .expect_err("a second representation for one Cat checkpoint is residue");
        assert_eq!(std::fs::read(duplicate).unwrap(), before);
    }

    #[test]
    fn incomplete_authority_marker_never_projects_a_prepared_local_lineage() {
        enum Drift {
            Owner,
            Head,
            LeaseExpiry,
            AcquireMarker,
        }

        for drift in [
            Drift::Owner,
            Drift::Head,
            Drift::LeaseExpiry,
            Drift::AcquireMarker,
        ] {
            let environment = TestEnvironment::new();
            let scan_context = assigned_context(true);
            let desired = scan_context.coordinates().desired.desired_specs[0].clone();
            let (mut record, attachment) = exact_owned_record_and_attachment(&desired);
            let data_directory = prepare_exact_lineage(&environment, &desired, &attachment);
            persist_acquire_checkpoint(&environment, &desired, &attachment);
            match drift {
                Drift::Owner => {
                    record.lease_owner = Some(Id::new("att_foreign").unwrap());
                }
                Drift::Head => {
                    record.head = RemoteHead {
                        generation: Generation::new(1).unwrap(),
                        root_hash: Some(Sha256Digest::from_bytes([3; 32])),
                        root_object_id: Some(AsciiText::new("roots/drift").unwrap()),
                    };
                }
                Drift::LeaseExpiry => {
                    record.lease_expires_at = Some(
                        cats_storage::authority::UnixMillis::new(
                            attachment.lease_expires_at.get() + 1,
                        )
                        .unwrap(),
                    );
                }
                Drift::AcquireMarker => {
                    let Some(cats_storage::authority::LastVolumeTransition::NormalAcquire {
                        request,
                        ..
                    }) = &mut record.last_transition
                    else {
                        unreachable!("fixture has a normal-acquire marker")
                    };
                    request.lease_duration_ms += 1;
                }
            }
            let before = leaf_snapshot(&data_directory);
            let (authority, _calls) = TestVolumeDataAuthority::exact(record);
            let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
            let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
            match scanner.scan_complete(scan_context) {
                Ok(RuntimeInventoryScanOutcome::Complete(_)) => {
                    panic!("authority drift must never project typed local lineage")
                }
                Ok(RuntimeInventoryScanOutcome::Incomplete { .. }) | Err(_) => {}
            }
            assert_eq!(leaf_snapshot(&data_directory), before);
        }
    }

    #[test]
    fn superseded_checkpoint_revision_spec_or_placement_is_typed_physical_evidence() {
        enum Supersede {
            Revision,
            Spec,
            Placement,
        }

        for supersede in [Supersede::Revision, Supersede::Spec, Supersede::Placement] {
            let environment = TestEnvironment::new();
            let mut scan_context = assigned_context(true);
            let stored_desired = scan_context.coordinates().desired.desired_specs[0].clone();
            let (record, attachment) = exact_owned_record_and_attachment(&stored_desired);
            let data_directory = prepare_exact_lineage(&environment, &stored_desired, &attachment);
            persist_acquire_checkpoint(&environment, &stored_desired, &attachment);

            let current = &mut scan_context.coordinates_mut().desired.desired_specs[0];
            match supersede {
                Supersede::Revision => current.desired_revision = Revision::new(2).unwrap(),
                Supersede::Spec => {
                    current.desired_revision = Revision::new(2).unwrap();
                    current.runtime.guest_config_digest = Sha256Digest::from_bytes([4; 32]);
                }
                Supersede::Placement => {
                    current.desired_revision = Revision::new(2).unwrap();
                    current.placement.placement_epoch = Epoch::new(2).unwrap();
                }
            }
            current.spec_digest = spec_digest(current).unwrap();

            let before = leaf_snapshot(&data_directory);
            let (authority, _calls) = TestVolumeDataAuthority::exact(record);
            let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
            let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
            let RuntimeInventoryScanOutcome::Complete(inventory) =
                scanner.scan_complete(scan_context).unwrap()
            else {
                panic!("superseded checkpoint must remain typed full-inventory evidence")
            };
            let runtime = &inventory.runtimes()[0];
            assert_eq!(
                runtime
                    .applied_desired
                    .as_ref()
                    .expect("assigned Cat has current applied evidence")
                    .desired_revision,
                Revision::new(2).unwrap()
            );
            assert!(matches!(
                &runtime.checkpoint,
                cats_api::runtime_reconciliation::CheckpointEvidence::Valid {
                    desired_revision,
                    ..
                } if *desired_revision == Revision::new(1).unwrap()
            ));
            assert_eq!(runtime.volumes[0].local_lineages.len(), 1);
            assert_eq!(leaf_snapshot(&data_directory), before);
        }
    }

    #[test]
    fn paged_node_snapshot_can_prove_the_exact_desired_candidate() {
        let environment = TestEnvironment::new();
        let record = unowned_record("vol_root", 4_294_967_296);
        let (port, calls) = scripted_metadata_inventory_port([
            metadata_page(
                vec![MetadataAuthorityIndexedRecord {
                    record: record.clone(),
                    owner_node_id: None,
                }],
                Some("vol_root"),
            ),
            metadata_page(Vec::new(), None),
        ]);
        let reader = Arc::new(PagedMetadataAuthorityReader::new(port));

        let InventoryAbsence::DesiredVolumes(by_cat) = metadata_probe(&environment, reader)
            .prove_absent(&assigned_context(true))
            .unwrap()
        else {
            panic!("exact indexed candidate must form typed Desired volume evidence")
        };
        assert_eq!(
            by_cat[&Id::new("cat_01").unwrap()][0].observed.volume_id,
            record.volume_id
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].node_id, Id::new("node_a").unwrap());
        assert_eq!(calls[0].desired_read_position.get(), 12);
        assert_eq!(calls[0].snapshot_read_position, None);
        assert_eq!(calls[0].after_volume_id, None);
        assert_eq!(calls[0].limit, METADATA_AUTHORITY_PAGE_LIMIT);
        assert_eq!(
            calls[0].candidate_volume_ids.as_ref(),
            Some(&[record.volume_id].into_iter().collect())
        );
        assert_eq!(
            calls[1].snapshot_read_position,
            Some(Sequence::new(77).unwrap())
        );
        assert_eq!(calls[1].candidate_volume_ids, None);
        assert_eq!(calls[1].after_volume_id, Some(Id::new("vol_root").unwrap()));
    }

    #[test]
    fn paged_node_snapshot_empty_final_page_proves_node_absence() {
        let environment = TestEnvironment::new();
        let (port, calls) = scripted_metadata_inventory_port([metadata_page(Vec::new(), None)]);
        let reader = Arc::new(PagedMetadataAuthorityReader::new(port));
        assert_eq!(
            metadata_probe(&environment, reader)
                .prove_absent(&context())
                .unwrap(),
            InventoryAbsence::Empty
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn production_inventory_port_pages_one_immutable_authority_snapshot() {
        let calls = Arc::new(AtomicUsize::new(0));
        let records = (0..300)
            .map(|index| (unowned_record(&format!("volume-{index:04}"), 4_096), None))
            .collect::<Vec<_>>();
        let candidates = records
            .iter()
            .map(|(record, _)| record.volume_id.clone())
            .collect::<BTreeSet<_>>();
        let port =
            RuntimeVolumeInventoryPagePort::start(Arc::new(TestRuntimeVolumeInventoryAuthority {
                snapshot: inventory_snapshot(records),
                delay: Duration::ZERO,
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let reader = PagedMetadataAuthorityReader::new(Arc::new(port));
        let scan_context = context();

        let MetadataAuthorityCandidateInventory::Records(read) = reader
            .read_candidates(
                &Id::new("node_a").unwrap(),
                &candidates,
                scan_context.deadline(),
                &scan_context,
            )
            .unwrap()
        else {
            panic!("one complete target snapshot must survive local pagination")
        };
        assert_eq!(read.len(), candidates.len());
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn production_inventory_port_preserves_foreign_candidate_ownership() {
        let calls = Arc::new(AtomicUsize::new(0));
        let foreign = owned_record("vol_root", "att_root");
        let port =
            RuntimeVolumeInventoryPagePort::start(Arc::new(TestRuntimeVolumeInventoryAuthority {
                snapshot: inventory_snapshot(vec![(foreign.clone(), Some("node_b"))]),
                delay: Duration::ZERO,
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let reader = PagedMetadataAuthorityReader::new(Arc::new(port));
        let scan_context = context();

        assert_eq!(
            reader
                .read_candidates(
                    &Id::new("node_a").unwrap(),
                    &BTreeSet::from([foreign.volume_id]),
                    scan_context.deadline(),
                    &scan_context,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn production_inventory_port_rejects_unsorted_or_cross_bound_snapshots() {
        let mut unsorted = inventory_snapshot(vec![
            (unowned_record("volume-a", 4_096), None),
            (unowned_record("volume-b", 4_096), None),
        ]);
        unsorted.records.reverse();
        let owned = owned_record("volume-owned", "attachment-owned");
        let mut cross_bound = inventory_snapshot(vec![(owned, Some("node_a"))]);
        cross_bound.records[0]
            .binding
            .as_mut()
            .unwrap()
            .attachment_id = Id::new("attachment-other").unwrap();

        for snapshot in [unsorted, cross_bound] {
            let calls = Arc::new(AtomicUsize::new(0));
            let candidates = snapshot
                .records
                .iter()
                .map(|record| record.volume.volume_id.clone())
                .collect::<BTreeSet<_>>();
            let port = RuntimeVolumeInventoryPagePort::start(Arc::new(
                TestRuntimeVolumeInventoryAuthority {
                    snapshot,
                    delay: Duration::ZERO,
                    calls: Arc::clone(&calls),
                },
            ))
            .unwrap();
            let reader = PagedMetadataAuthorityReader::new(Arc::new(port));
            let scan_context = context();
            assert_eq!(
                reader
                    .read_candidates(
                        &Id::new("node_a").unwrap(),
                        &candidates,
                        scan_context.deadline(),
                        &scan_context,
                    )
                    .unwrap(),
                MetadataAuthorityCandidateInventory::Unavailable
            );
            assert_eq!(calls.load(Ordering::SeqCst), 1);
        }
    }

    #[test]
    fn timed_out_production_inventory_read_never_overlaps_a_successor() {
        let calls = Arc::new(AtomicUsize::new(0));
        let port =
            RuntimeVolumeInventoryPagePort::start(Arc::new(TestRuntimeVolumeInventoryAuthority {
                snapshot: inventory_snapshot(Vec::new()),
                delay: Duration::from_millis(200),
                calls: Arc::clone(&calls),
            }))
            .unwrap();
        let reader = PagedMetadataAuthorityReader::new(Arc::new(port));
        let first = context_until(Instant::now() + Duration::from_millis(50));
        match reader.read_candidates(
            &Id::new("node_a").unwrap(),
            &BTreeSet::new(),
            first.deadline(),
            &first,
        ) {
            Ok(MetadataAuthorityCandidateInventory::Unavailable) => {}
            Err(error) => assert!(
                error
                    .to_string()
                    .contains("runtime inventory scan deadline expired"),
                "first read failed for a reason other than its shared deadline: {error:#}"
            ),
            Ok(other) => panic!("timed-out first read unexpectedly completed: {other:?}"),
        }
        // The first backend call is still sleeping. A successor must fail
        // immediately at the operation guard rather than overlap it, so its
        // own shared scan deadline remains active and returns Unavailable.
        let second = context_until(Instant::now() + Duration::from_millis(50));
        assert_eq!(
            reader
                .read_candidates(
                    &Id::new("node_a").unwrap(),
                    &BTreeSet::new(),
                    second.deadline(),
                    &second,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn unknown_or_foreign_authority_only_owner_cannot_complete_the_node_snapshot() {
        for owner_node_id in [None, Some(Id::new("node_b").unwrap())] {
            let environment = TestEnvironment::new();
            let (port, _calls) = scripted_metadata_inventory_port([metadata_page(
                vec![
                    MetadataAuthorityIndexedRecord {
                        record: owned_record("vol_orphan", "att_orphan"),
                        owner_node_id,
                    },
                    MetadataAuthorityIndexedRecord {
                        record: unowned_record("vol_root", 4_294_967_296),
                        owner_node_id: None,
                    },
                ],
                None,
            )]);
            let reader = Arc::new(PagedMetadataAuthorityReader::new(port));
            assert_eq!(
                metadata_probe(&environment, reader)
                    .prove_absent(&assigned_context(true))
                    .unwrap(),
                InventoryAbsence::Unavailable
            );
        }
    }

    #[test]
    fn desired_candidate_owned_by_another_node_cannot_project_as_local_owned() {
        let environment = TestEnvironment::new();
        let (port, _calls) = scripted_metadata_inventory_port([metadata_page(
            vec![MetadataAuthorityIndexedRecord {
                record: owned_record("vol_root", "att_01"),
                owner_node_id: Some(Id::new("node_b").unwrap()),
            }],
            None,
        )]);
        let reader = Arc::new(PagedMetadataAuthorityReader::new(port));

        assert_eq!(
            metadata_probe(&environment, reader)
                .prove_absent(&assigned_context(true))
                .unwrap(),
            InventoryAbsence::Unavailable
        );
    }

    #[test]
    fn paged_snapshot_surfaces_node_owned_authority_only_volume() {
        let environment = TestEnvironment::new();
        let (port, calls) = scripted_metadata_inventory_port([
            metadata_page(
                vec![MetadataAuthorityIndexedRecord {
                    record: owned_record("vol_orphan", "att_orphan"),
                    owner_node_id: Some(Id::new("node_a").unwrap()),
                }],
                Some("vol_orphan"),
            ),
            metadata_page(
                vec![MetadataAuthorityIndexedRecord {
                    record: unowned_record("vol_root", 4_294_967_296),
                    owner_node_id: None,
                }],
                Some("vol_root"),
            ),
            metadata_page(Vec::new(), None),
        ]);
        let reader = Arc::new(PagedMetadataAuthorityReader::new(port));
        let error = metadata_probe(&environment, reader)
            .prove_absent(&assigned_context(true))
            .unwrap_err();
        assert!(format!("{error:#}").contains("Node-owned volume outside scan candidates"));

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[1].snapshot_read_position,
            Some(Sequence::new(77).unwrap())
        );
        assert_eq!(calls[1].candidate_volume_ids, None);
        assert_eq!(
            calls[1].after_volume_id,
            Some(Id::new("vol_orphan").unwrap())
        );
        assert_eq!(calls[2].after_volume_id, Some(Id::new("vol_root").unwrap()));
    }

    #[test]
    fn paged_snapshot_rejects_binding_cursor_and_order_mismatches() {
        let base_record = MetadataAuthorityIndexedRecord {
            record: unowned_record("vol_root", 4_294_967_296),
            owner_node_id: None,
        };
        // A provider must prove exhaustion with a separate empty page. A
        // short or truncated nonempty page cannot self-certify completeness.
        let nonempty_without_cursor = metadata_page(vec![base_record.clone()], None);
        let mut wrong_node = metadata_page(vec![base_record.clone()], None);
        let MetadataAuthorityPageRead::Page(page) = &mut wrong_node else {
            unreachable!()
        };
        page.node_id = Id::new("node_b").unwrap();

        let mut wrong_desired_position = metadata_page(vec![base_record.clone()], None);
        let MetadataAuthorityPageRead::Page(page) = &mut wrong_desired_position else {
            unreachable!()
        };
        page.desired_read_position = Sequence::new(13).unwrap();

        let bad_cursor = metadata_page(vec![base_record.clone()], Some("vol_other"));
        let missing_candidate = metadata_page(Vec::new(), None);

        let mut unowned_with_owner = metadata_page(vec![base_record.clone()], None);
        let MetadataAuthorityPageRead::Page(page) = &mut unowned_with_owner else {
            unreachable!()
        };
        page.records[0].owner_node_id = Some(Id::new("node_a").unwrap());

        let descending = metadata_page(
            vec![
                base_record,
                MetadataAuthorityIndexedRecord {
                    record: owned_record("vol_orphan", "att_orphan"),
                    owner_node_id: Some(Id::new("node_a").unwrap()),
                },
            ],
            None,
        );

        let first_page = metadata_page(
            vec![MetadataAuthorityIndexedRecord {
                record: owned_record("vol_orphan", "att_orphan"),
                owner_node_id: Some(Id::new("node_a").unwrap()),
            }],
            Some("vol_orphan"),
        );
        let mut drifted_second_page = metadata_page(
            vec![MetadataAuthorityIndexedRecord {
                record: unowned_record("vol_root", 4_294_967_296),
                owner_node_id: None,
            }],
            None,
        );
        let MetadataAuthorityPageRead::Page(page) = &mut drifted_second_page else {
            unreachable!()
        };
        page.snapshot_read_position = Sequence::new(78).unwrap();

        for (case, reads) in [
            ("nonempty_without_cursor", vec![nonempty_without_cursor]),
            ("wrong_node", vec![wrong_node]),
            ("wrong_desired_position", vec![wrong_desired_position]),
            ("bad_cursor", vec![bad_cursor]),
            ("missing_candidate", vec![missing_candidate]),
            ("unowned_with_owner", vec![unowned_with_owner]),
            ("descending", vec![descending]),
            (
                "snapshot_position_drift",
                vec![first_page, drifted_second_page],
            ),
        ] {
            let context = assigned_context(true);
            let candidates = [Id::new("vol_root").unwrap()].into_iter().collect();
            let (port, _calls) = scripted_metadata_inventory_port(reads);
            let reader = PagedMetadataAuthorityReader::new(port);
            assert_eq!(
                reader
                    .read_candidates(
                        &Id::new("node_a").unwrap(),
                        &candidates,
                        context.deadline(),
                        &context,
                    )
                    .unwrap(),
                MetadataAuthorityCandidateInventory::Unavailable,
                "{case}"
            );
        }
    }

    #[test]
    fn paged_node_snapshot_accepts_exact_maximum_record_count() {
        let context = context_until(Instant::now() + Duration::from_secs(30));
        let candidates = boundary_volume_ids(METADATA_AUTHORITY_MAX_RECORDS);
        let (port, calls) = boundary_metadata_inventory_port(METADATA_AUTHORITY_MAX_RECORDS);
        let reader = PagedMetadataAuthorityReader::new(port);

        let MetadataAuthorityCandidateInventory::Records(records) = reader
            .read_candidates(
                &Id::new("node_a").unwrap(),
                &candidates,
                context.deadline(),
                &context,
            )
            .unwrap()
        else {
            panic!("the exact frozen Node-owned volume bound must be accepted")
        };

        assert_eq!(records.len(), METADATA_AUTHORITY_MAX_RECORDS);
        assert!(records.keys().eq(candidates.iter()));
        assert_eq!(
            calls.load(Ordering::SeqCst),
            METADATA_AUTHORITY_MAX_RECORDS.div_ceil(METADATA_AUTHORITY_PAGE_LIMIT) + 1
        );
    }

    #[test]
    fn paged_node_snapshot_rejects_maximum_plus_one_before_reading_authority() {
        let context = context_until(Instant::now() + Duration::from_secs(30));
        let candidates = boundary_volume_ids(METADATA_AUTHORITY_MAX_RECORDS + 1);
        let (port, calls) = boundary_metadata_inventory_port(METADATA_AUTHORITY_MAX_RECORDS + 1);
        let reader = PagedMetadataAuthorityReader::new(port);

        assert_eq!(
            reader
                .read_candidates(
                    &Id::new("node_a").unwrap(),
                    &candidates,
                    context.deadline(),
                    &context,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn test_point_reader_cannot_close_a_clean_host() {
        let environment = TestEnvironment::new();
        let (authority, calls) = TestVolumeDataAuthority::missing();
        let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
        let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
        assert!(matches!(
            scanner.scan_complete(context()).unwrap(),
            RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                if unavailable_sources == [InventorySource::MetadataStore]
        ));
        assert!(calls.lock().unwrap().is_empty());
        assert!(!environment.state.join(LEGACY_LEDGER).exists());
        assert!(environment.state.is_dir());
        assert!(environment.socket_root.is_dir());
    }

    #[test]
    fn authoritative_empty_reader_is_the_only_complete_metadata_case() {
        let environment = TestEnvironment::new();
        let (reader, calls) = recording_metadata_reader(MetadataReaderBehavior::AuthoritativeEmpty);
        let scan_context = context();
        let deadline = scan_context.deadline();
        let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(scan_context).unwrap()
        else {
            panic!("healthy authoritative-empty metadata proof must permit completion")
        };
        assert!(inventory.runtimes().is_empty());
        assert!(inventory.residue().is_empty());

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].node_id, Id::new("node_a").unwrap());
        assert!(calls[0].candidate_volume_ids.is_empty());
        assert_eq!(calls[0].deadline, deadline);
    }

    #[test]
    fn test_point_reader_candidate_failure_makes_metadata_incomplete() {
        let environment = TestEnvironment::new();
        let (authority, calls) = TestVolumeDataAuthority::missing();
        let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
        let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
        assert!(matches!(
            scanner.scan_complete(assigned_context(true)).unwrap(),
            RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                if unavailable_sources == [InventorySource::MetadataStore]
        ));
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [Id::new("vol_root").unwrap()]
        );
    }

    #[test]
    fn test_point_reader_projects_an_exact_desired_unowned_root() {
        let environment = TestEnvironment::new();
        let record = cats_storage::authority::VolumeRecord {
            volume_id: Id::new("vol_root").unwrap(),
            size_bytes: 4_294_967_296,
            durability: Durability::Strict,
            admin_state: VolumeAdminState::Active,
            head: cats_storage::authority::RemoteHead {
                generation: cats_storage::authority::Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            lease_owner: None,
            lease_epoch: FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        let (authority, calls) = TestVolumeDataAuthority::exact(record.clone());
        let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
        let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();

        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(assigned_context(true)).unwrap()
        else {
            panic!("a Desired-bound authority root must admit the first full observation")
        };
        assert!(inventory.residue().is_empty());
        let [runtime] = inventory.runtimes() else {
            panic!("the assigned Cat must be represented exactly once")
        };
        assert!(matches!(
            &runtime.checkpoint,
            CheckpointEvidence::Missing { .. }
        ));
        assert!(matches!(
            &runtime.step,
            ReconcileStep::InspectInventory { .. }
        ));
        assert_eq!(runtime.lifecycle_admission, LifecycleAdmission::Closed);
        assert!(runtime.processes.is_empty());
        let [volume] = runtime.volumes.as_slice() else {
            panic!("the Desired root authority fact must be observed exactly once")
        };
        assert_eq!(volume.volume_id, record.volume_id);
        assert_eq!(volume.size_bytes, Some(record.size_bytes));
        assert_eq!(volume.durability, Some(record.durability));
        assert!(matches!(
            &volume.authority,
            VolumeAuthorityEvidence::Unowned {
                attachment_epoch,
                head,
            } if *attachment_epoch == record.lease_epoch && head == &record.head
        ));
        assert!(volume.local_lineages.is_empty());
        assert!(volume.devices.is_empty());
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [Id::new("vol_root").unwrap()]
        );
    }

    #[test]
    fn test_point_reader_projects_exact_acquire_response_loss() {
        let environment = TestEnvironment::new();
        let unowned = cats_storage::authority::VolumeRecord {
            volume_id: Id::new("vol_root").unwrap(),
            size_bytes: 4_294_967_296,
            durability: Durability::Strict,
            admin_state: VolumeAdminState::Active,
            head: cats_storage::authority::RemoteHead {
                generation: cats_storage::authority::Generation::new(0).unwrap(),
                root_hash: None,
                root_object_id: None,
            },
            lease_owner: None,
            lease_epoch: FenceEpoch::new(0).unwrap(),
            lease_expires_at: None,
            last_transition: None,
        };
        let request = cats_storage::authority::NormalAcquireRequest {
            volume_id: Id::new("vol_root").unwrap(),
            transition_id: RandomId128::new("11111111111111111111111111111111").unwrap(),
            attachment_id: Id::new("att_root").unwrap(),
            expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            placement_epoch: Epoch::new(1).unwrap(),
            lease_duration_ms: 5_000,
        };
        let (record, result) = cats_storage::authority::normal_acquire(
            &unowned,
            &request,
            cats_storage::authority::UnixMillis::new(10_000).unwrap(),
        )
        .unwrap();
        let (authority, _) = TestVolumeDataAuthority::exact(record.clone());
        let scanner = scanner_with_metadata_authority(
            environment.config(),
            Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
        )
        .unwrap();

        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(assigned_context(true)).unwrap()
        else {
            panic!("the exact acquire receipt must survive response loss")
        };
        let volume = &inventory.runtimes()[0].volumes[0];
        assert!(matches!(
            &volume.authority,
            VolumeAuthorityEvidence::Owned {
                attachment_id,
                attachment_epoch,
                head,
            } if attachment_id == &request.attachment_id
                && *attachment_epoch == result.resulting_epoch
                && head == &record.head
        ));
    }

    #[test]
    fn metadata_reader_receives_assigned_and_all_local_volume_candidates() {
        let environment = TestEnvironment::new();
        for (namespace, volume_id) in [
            (DATA_NAMESPACE, "vol_local"),
            (PENDING_PACK_NAMESPACE, "vol_pending"),
            (PENDING_PACK_NAMESPACE, "vol_root"),
        ] {
            std::fs::create_dir_all(environment.state.join(namespace).join(volume_id)).unwrap();
        }
        let (reader, calls) = recording_metadata_reader(MetadataReaderBehavior::Unavailable);
        let scan_context = assigned_context(true);
        let deadline = scan_context.deadline();
        assert_eq!(
            metadata_probe(&environment, reader)
                .prove_absent(&scan_context)
                .unwrap(),
            InventoryAbsence::Unavailable
        );

        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].deadline, deadline);
        assert_eq!(
            calls[0].candidate_volume_ids,
            ["vol_local", "vol_pending", "vol_root"]
                .into_iter()
                .map(|volume_id| Id::new(volume_id).unwrap())
                .collect()
        );
    }

    #[test]
    fn authority_record_for_a_local_only_volume_is_never_folded_into_desired() {
        let environment = TestEnvironment::new();
        std::fs::create_dir_all(environment.state.join(DATA_NAMESPACE).join("vol_orphan")).unwrap();
        let (authority, calls) = TestVolumeDataAuthority::present();
        let reader = Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap());
        let error = metadata_probe(&environment, reader)
            .prove_absent(&assigned_context(true))
            .unwrap_err();
        assert!(format!("{error:#}").contains("outside Desired"));
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            ["vol_orphan", "vol_root"]
                .into_iter()
                .map(|value| Id::new(value).unwrap())
                .collect()
        );
    }

    #[test]
    fn unsupported_target_persistent_or_multi_volume_remains_outside_the_first_slice() {
        for make_unsupported in ["cold", "persistent", "multi"] {
            let environment = TestEnvironment::new();
            let (reader, calls) =
                recording_metadata_reader(MetadataReaderBehavior::AuthoritativeEmpty);
            let mut scan_context = assigned_context(true);
            let desired = &mut scan_context.coordinates_mut().desired.desired_specs[0];
            match make_unsupported {
                "cold" => desired.target = RuntimeTarget::Cold,
                "persistent" => desired.volumes[0].disk_kind = DiskKind::Persistent,
                "multi" => {
                    desired.volumes.push(desired.volumes[0].clone());
                    desired.volumes[1].volume_intent_id = Id::new("vint_second").unwrap();
                    desired.volumes[1].disk_id = Id::new("disk_second").unwrap();
                    desired.volumes[1].volume_id = Id::new("vol_second").unwrap();
                    desired.volumes[1].attachment_id = Id::new("att_second").unwrap();
                }
                _ => unreachable!("closed test cases"),
            }
            assert_eq!(
                metadata_probe(&environment, reader)
                    .prove_absent(&scan_context)
                    .unwrap(),
                InventoryAbsence::Unavailable,
                "{make_unsupported}"
            );
            assert!(
                calls.lock().unwrap().is_empty(),
                "unsupported intent must fail before authority I/O"
            );
        }
    }

    #[test]
    fn typed_point_reader_cannot_prove_an_empty_candidate_set() {
        for (authority, calls) in [
            TestVolumeDataAuthority::missing(),
            TestVolumeDataAuthority::present(),
        ] {
            let reader = VolumeDataAuthorityMetadataReader::start(authority).unwrap();
            let scan_context = context();
            assert_eq!(
                reader
                    .read_candidates(
                        &scan_context.coordinates().session.node_id,
                        &BTreeSet::new(),
                        scan_context.deadline(),
                        &scan_context,
                    )
                    .unwrap(),
                MetadataAuthorityCandidateInventory::Unavailable
            );
            assert!(
                calls.lock().unwrap().is_empty(),
                "a point lookup cannot manufacture a global absence read"
            );
        }
    }

    #[test]
    fn typed_volume_authority_reader_strictly_reads_every_candidate() {
        let (authority, calls) = TestVolumeDataAuthority::missing();
        let reader = VolumeDataAuthorityMetadataReader::start(authority).unwrap();
        let scan_context = context();
        let candidates = ["vol_a", "vol_b", "vol_c"]
            .into_iter()
            .map(|value| Id::new(value).unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            reader
                .read_candidates(
                    &scan_context.coordinates().session.node_id,
                    &candidates,
                    scan_context.deadline(),
                    &scan_context,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .cloned()
                .collect::<BTreeSet<_>>(),
            candidates
        );
    }

    #[test]
    fn typed_volume_authority_reader_returns_every_complete_record() {
        let (authority, calls) = TestVolumeDataAuthority::present();
        let reader = VolumeDataAuthorityMetadataReader::start(authority).unwrap();
        let scan_context = context();
        let candidates = ["vol_a", "vol_b"]
            .into_iter()
            .map(|value| Id::new(value).unwrap())
            .collect::<BTreeSet<_>>();
        let records = reader
            .read_candidates(
                &scan_context.coordinates().session.node_id,
                &candidates,
                scan_context.deadline(),
                &scan_context,
            )
            .unwrap();
        let MetadataAuthorityCandidateInventory::Records(records) = records else {
            panic!("complete strict reads must return their typed records")
        };
        assert_eq!(records.keys().cloned().collect::<BTreeSet<_>>(), candidates);
        assert_eq!(calls.lock().unwrap().len(), candidates.len());
    }

    #[test]
    fn typed_volume_authority_reader_returns_before_an_uncooperative_read() {
        let (authority, _calls) = TestVolumeDataAuthority::delayed(Duration::from_millis(250));
        let reader = VolumeDataAuthorityMetadataReader::start(authority).unwrap();
        let scan_context = context_until(Instant::now() + Duration::from_millis(80));
        let candidates = [Id::new("vol_slow").unwrap()].into_iter().collect();
        let started = Instant::now();
        assert_eq!(
            reader
                .read_candidates(
                    &scan_context.coordinates().session.node_id,
                    &candidates,
                    scan_context.deadline(),
                    &scan_context,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
        assert!(started.elapsed() < Duration::from_millis(180));
    }

    #[test]
    fn authority_failure_matrix_is_unavailable_and_never_complete() {
        for behavior in [
            MetadataReaderBehavior::Unavailable,
            MetadataReaderBehavior::TimedOut,
            MetadataReaderBehavior::Cancelled,
            MetadataReaderBehavior::Orphan,
            MetadataReaderBehavior::WrongOwner,
        ] {
            let environment = TestEnvironment::new();
            let (reader, calls) = recording_metadata_reader(behavior);
            let scanner = scanner_with_metadata_authority(environment.config(), reader).unwrap();
            assert!(matches!(
                scanner.scan_complete(assigned_context(true)).unwrap(),
                RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                    if unavailable_sources == [InventorySource::MetadataStore]
            ));
            assert_eq!(calls.lock().unwrap().len(), 1, "{behavior:?}");
        }
    }

    #[test]
    fn authority_timeout_and_cancellation_cannot_become_empty() {
        for behavior in [
            MetadataReaderBehavior::ReturnAfterDeadline,
            MetadataReaderBehavior::CancelDuringRead,
        ] {
            let environment = TestEnvironment::new();
            let (reader, calls) = recording_metadata_reader(behavior);
            let probe = metadata_probe(&environment, reader);
            // Start the absolute deadline only after all fixture and probe
            // construction. Under the full parallel suite those operations
            // may be descheduled long enough to consume a deadline created in
            // the loop initializer, which would legitimately stop before the
            // reader and weaken this late-authority-result oracle.
            let deadline = Instant::now()
                + match behavior {
                    MetadataReaderBehavior::ReturnAfterDeadline => Duration::from_secs(2),
                    MetadataReaderBehavior::CancelDuringRead => Duration::from_secs(5),
                    _ => unreachable!("the test iterates only cancellation behaviors"),
                };
            let scan_context = context_until(deadline);
            let error = probe.prove_absent(&scan_context).unwrap_err();
            let error = format!("{error:#}");
            assert!(
                error.contains("deadline") || error.contains("cancelled"),
                "{behavior:?}: {error}"
            );
            assert_eq!(calls.lock().unwrap().len(), 1, "{behavior:?}");
        }
    }

    #[test]
    fn unparseable_local_candidate_keeps_metadata_unavailable() {
        let environment = TestEnvironment::new();
        std::fs::create_dir_all(environment.state.join(DATA_NAMESPACE)).unwrap();
        std::fs::write(
            environment
                .state
                .join(DATA_NAMESPACE)
                .join("not a volume id"),
            b"retained",
        )
        .unwrap();
        let (reader, calls) = recording_metadata_reader(MetadataReaderBehavior::AuthoritativeEmpty);
        assert!(matches!(
            metadata_probe(&environment, reader).prove_absent(&context()),
            Ok(InventoryAbsence::Unavailable)
        ));
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn every_concrete_source_can_report_unavailable_without_becoming_empty() {
        let environment = TestEnvironment::new();
        let missing_state = StateDirectory::unanchored(environment.state.join("missing"));
        let limits = ProbeLimits::default();
        let unavailable_process = ProcessPaths {
            root: environment.proc_root.clone(),
            binaries: vec![environment.guest_binary.clone()],
            supported: false,
            limits,
        };
        let probes: Vec<Box<dyn InventoryAbsenceProbe>> = vec![
            Box::new(StateNamespaceProbe {
                source: InventorySource::Checkpoint,
                state_directory: missing_state.clone(),
                namespace: CHECKPOINT_NAMESPACE,
                reject_legacy_root: true,
                limits,
            }),
            Box::new(SystemdProbe {
                systemd_root: environment.systemd_root.clone(),
                metering_root: None,
                supported: false,
                limits,
            }),
            Box::new(ProcessProbe {
                paths: unavailable_process.clone(),
            }),
            Box::new(ControlSocketProbe {
                state_directory: missing_state.clone(),
                legacy_socket_root: environment.socket_root.clone(),
                limits,
            }),
            Box::new(BlockFrontendProbe {
                state_directory: StateDirectory::unanchored(environment.state.clone()),
                block_class_root: environment.block_root.clone(),
                legacy_socket_root: environment.socket_root.clone(),
                supported: false,
                limits,
            }),
            Box::new(NetworkProbe {
                state_directory: StateDirectory::unanchored(environment.state.clone()),
                network_class_root: environment.network_root.clone(),
                supported: false,
                limits,
            }),
            Box::new(StateNamespaceProbe {
                source: InventorySource::DataDirectory,
                state_directory: missing_state.clone(),
                namespace: DATA_NAMESPACE,
                reject_legacy_root: true,
                limits,
            }),
            Box::new(StateNamespaceProbe {
                source: InventorySource::PendingPack,
                state_directory: missing_state.clone(),
                namespace: PENDING_PACK_NAMESPACE,
                reject_legacy_root: true,
                limits,
            }),
            Box::new(StateNamespaceProbe {
                source: InventorySource::WarmSnapshot,
                state_directory: missing_state.clone(),
                namespace: WARM_SNAPSHOT_NAMESPACE,
                reject_legacy_root: true,
                limits,
            }),
            Box::new(MetadataStoreProbe {
                state_directory: missing_state.clone(),
                authority: Arc::new(TestUnavailableMetadataReader),
                limits,
            }),
            Box::new(GuestMountProbe {
                state_directory: StateDirectory::unanchored(environment.state.clone()),
                legacy_socket_root: environment.socket_root.clone(),
                guest_process_paths: unavailable_process,
                limits,
            }),
        ];
        assert_eq!(probes.len(), 11);
        for probe in probes {
            assert_eq!(
                probe.prove_absent(&context()).unwrap(),
                InventoryAbsence::Unavailable,
                "{:?} must fail closed",
                probe.source()
            );
        }
    }

    #[test]
    fn every_legacy_state_residue_blocks_and_remains_untouched() {
        for relative_file in [
            LEGACY_LEDGER,
            "cats/cat-a/checkpoint.json",
            "cats/cat-a/ctl.sock",
            "cats/cat-a/vol-root/data.bin",
            "cats/cat-a/vol-root/pending/0001.pack",
            "cats/cat-a/snapshot/state.json",
            "cats/cat-a/warm-state.json",
        ] {
            let environment = TestEnvironment::new();
            let residue = environment.state.join(relative_file);
            std::fs::create_dir_all(residue.parent().unwrap()).unwrap();
            std::fs::write(&residue, b"legacy residue").unwrap();
            let scanner = scanner(environment.config()).unwrap();
            assert!(scanner.scan_complete(context()).is_err(), "{relative_file}");
            assert!(residue.exists(), "scanner removed {relative_file}");
        }

        let environment = TestEnvironment::new();
        let legacy_cats = environment.state.join(LEGACY_CATS_DIRECTORY);
        std::fs::create_dir(&legacy_cats).unwrap();
        assert!(scanner(environment.config())
            .unwrap()
            .scan_complete(context())
            .is_err());
        assert!(legacy_cats.is_dir());
    }

    #[test]
    fn every_new_state_namespace_and_partial_network_journal_blocks() {
        for namespace in [
            CHECKPOINT_NAMESPACE,
            CONTROL_SOCKET_NAMESPACE,
            VHOST_NAMESPACE,
            NETWORK_NAMESPACE,
            DATA_NAMESPACE,
            PENDING_PACK_NAMESPACE,
            WARM_SNAPSHOT_NAMESPACE,
            GUEST_MOUNT_NAMESPACE,
            RUNTIME_EFFECTS_NAMESPACE,
        ] {
            let environment = TestEnvironment::new();
            let directory = environment.state.join(namespace);
            std::fs::create_dir(&directory).unwrap();
            let residue = directory.join(if namespace == RUNTIME_EFFECTS_NAMESPACE {
                "cat-a.network.json"
            } else {
                "residue"
            });
            std::fs::write(&residue, b"partial").unwrap();
            assert!(scanner(environment.config())
                .unwrap()
                .scan_complete(context())
                .is_err());
            assert!(residue.exists());
        }
    }

    #[test]
    fn state_namespace_rejects_symlinks_and_entry_cap_overflow() {
        let environment = TestEnvironment::new();
        let outside = environment.state.parent().unwrap().join("outside");
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, environment.state.join(CHECKPOINT_NAMESPACE)).unwrap();
        let error = scanner(environment.config())
            .unwrap()
            .scan_complete(context())
            .unwrap_err();
        assert!(format!("{error:#}").contains("unsafe"));

        let environment = TestEnvironment::new();
        let checkpoints = environment.state.join(CHECKPOINT_NAMESPACE);
        std::fs::create_dir(&checkpoints).unwrap();
        for index in 0..3 {
            std::fs::write(checkpoints.join(index.to_string()), b"x").unwrap();
        }
        let mut config = environment.config();
        config.limits.state_entries = 2;
        let error = scanner(config)
            .unwrap()
            .scan_complete(context())
            .unwrap_err();
        assert!(format!("{error:#}").contains("entry cap"));
    }

    #[test]
    fn deadline_and_cancellation_stop_before_complete_coverage() {
        let environment = TestEnvironment::new();
        let scanner = scanner(environment.config()).unwrap();
        assert!(scanner
            .scan_complete(context_until(Instant::now()))
            .is_err());

        let cancelled = context();
        cancelled.cancel_for_test();
        assert!(scanner.scan_complete(cancelled).is_err());
    }

    #[test]
    fn linux_candidates_are_detected_without_running_external_commands() {
        let environment = TestEnvironment::new();
        let scope = environment.systemd_root.join("cats-orphan.scope");
        std::fs::create_dir(&scope).unwrap();
        let systemd = SystemdProbe {
            systemd_root: environment.systemd_root.clone(),
            metering_root: None,
            supported: true,
            limits: ProbeLimits::default(),
        };
        assert!(systemd.prove_absent(&context()).is_err());

        let pid = environment.proc_root.join("123");
        std::fs::create_dir(&pid).unwrap();
        std::os::unix::fs::symlink(&environment.ch_binary, pid.join("exe")).unwrap();
        std::fs::write(pid.join("cmdline"), b"unrelated\0").unwrap();
        let process = ProcessProbe {
            paths: ProcessPaths {
                root: environment.proc_root.clone(),
                binaries: vec![environment.ch_binary.clone()],
                supported: true,
                limits: ProbeLimits::default(),
            },
        };
        assert!(process.prove_absent(&context()).is_err());

        let interface = environment.network_root.join("cat00000000abc");
        std::fs::create_dir(&interface).unwrap();
        let network = NetworkProbe {
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            network_class_root: environment.network_root.clone(),
            supported: true,
            limits: ProbeLimits::default(),
        };
        assert!(network.prove_absent(&context()).is_err());
    }

    #[test]
    fn nbd_free_serving_leaked_and_malformed_states_are_distinct() {
        let cases = [
            (None, "0", ProbeFact::Empty),
            (Some("123"), "8", ProbeFact::Present),
            (None, "8", ProbeFact::Present),
        ];
        for (pid, size, expected) in cases {
            let environment = TestEnvironment::new();
            let nbd = environment.block_root.join("nbd0");
            std::fs::create_dir(&nbd).unwrap();
            if let Some(pid) = pid {
                std::fs::write(nbd.join("pid"), pid).unwrap();
            }
            std::fs::write(nbd.join("size"), size).unwrap();
            assert_eq!(
                scan_nbd(&environment.block_root, 16, &context()).unwrap(),
                expected
            );
        }

        let environment = TestEnvironment::new();
        let nbd = environment.block_root.join("nbd0");
        std::fs::create_dir(&nbd).unwrap();
        std::fs::write(nbd.join("size"), "not-a-number").unwrap();
        assert!(scan_nbd(&environment.block_root, 16, &context()).is_err());
    }

    #[test]
    fn installed_factory_derives_checkpoint_evidence_from_the_scanned_dirfd_child() {
        let environment = TestEnvironment::new();
        let state = StateDirectory::unanchored(environment.state.clone());
        let config = ProbeConfig::installed(InstalledCleanSlateProbeConfig {
            state_directory: state.clone(),
            cloud_hypervisor_binary: environment.ch_binary.clone(),
            blockd_binary: environment.blockd_binary.clone(),
            guest_agent_binary: environment.guest_binary.clone(),
            metering_cgroup_root: None,
            volume_inventory_authority: Arc::new(TestUnavailableRuntimeVolumeInventoryAuthority),
            blob_store: Arc::new(TestUnavailableBlobStore),
            root_provision_systemd: RootProvisionSystemdConfig::new(
                super::super::AuthorizedBlockdLaunchConfig {
                    blockd_binary: environment.blockd_binary.clone(),
                    metadata_store: AdapterSelection::new(
                        "postgres",
                        AdapterConfig::from_pairs([("url-file", "/run/cats/postgres.url")])
                            .unwrap(),
                    ),
                    object_store: AdapterSelection::new(
                        "aws-s3",
                        AdapterConfig::from_pairs([("bucket", "cats-test")]).unwrap(),
                    ),
                    max_staged_bytes: 1,
                    max_staged_packs: 1,
                    max_local_bytes: 4_194_304,
                },
            )
            .unwrap(),
        })
        .unwrap();
        assert_eq!(
            config.checkpoint_directory,
            state.path().join(CHECKPOINT_NAMESPACE)
        );
    }

    fn install_exact_process_fixture(
        environment: &TestEnvironment,
        expected: &RootProvisionProcessExpectation,
        process_id: u32,
    ) -> std::os::unix::net::UnixListener {
        std::fs::create_dir(environment.systemd_root.join(expected.scope_id.as_str())).unwrap();
        let proc = environment.proc_root.join(process_id.to_string());
        std::fs::create_dir(&proc).unwrap();
        std::os::unix::fs::symlink(expected.executable_path.as_str(), proc.join("exe")).unwrap();
        std::fs::write(
            proc.join("cmdline"),
            [expected.executable_path.as_str().as_bytes(), b"\0"].concat(),
        )
        .unwrap();
        let socket =
            std::os::unix::net::UnixListener::bind(expected.control_socket_path.as_str()).unwrap();
        std::fs::set_permissions(
            expected.control_socket_path.as_str(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        socket
    }

    #[test]
    fn root_process_bridge_projects_only_a_twice_verified_exact_process() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let process = exact_process_evidence(&expected, 41);
        let _socket = install_exact_process_fixture(&environment, &expected, process.process_id);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(process)),
            ],
        );
        let outcome = bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .unwrap();
        let RootProcessInventoryBridgeOutcome::Complete(mut processes) = outcome else {
            panic!("exact physical process must complete the three-source bridge")
        };
        let evidence = processes
            .remove(&Id::new("cat_01").unwrap())
            .unwrap()
            .into_process_evidence();
        assert_eq!(evidence.process_id, 41);
        assert!(matches!(
            evidence.control_handshake,
            cats_api::runtime_reconciliation::ControlHandshakeEvidence::Verified
        ));
    }

    struct FullRootScannerFixture {
        scan_context: RuntimeInventoryScanContext,
        config: ProbeConfig,
        record: VolumeRecord,
        blob: Arc<ExactManifestBlobStore>,
        expected: RootProvisionProcessExpectation,
        data_directory: PathBuf,
        stored_checkpoint: StoredCheckpoint,
        acquired: AuthorizedBlockdCheckpoint,
        authority: super::super::serving_handoff::ServingAuthorityTargetEvidence,
    }

    fn full_root_scanner_fixture(environment: &TestEnvironment) -> FullRootScannerFixture {
        let scan_context = assigned_context(true);
        let desired = scan_context.coordinates().desired.desired_specs[0].clone();
        let (mut record, attachment) = exact_owned_record_and_attachment(&desired);
        let data_directory = prepare_exact_lineage(environment, &desired, &attachment);
        let blob = Arc::new(ExactManifestBlobStore::for_desired(&desired));
        let ProvisionHeadRead::Ready { blank, target } = expected_provision_heads(
            blob.as_ref(),
            &desired,
            &desired.volumes[0],
            scan_context.deadline(),
        ) else {
            panic!("exact manifest must produce deterministic provision heads")
        };
        record.head = target.clone();
        let mut checkpoint = acquire_checkpoint(
            &desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: attachment.acquire_request.volume_id.clone(),
                    transition_id: attachment.acquire_request.transition_id.clone(),
                    attachment_id: attachment.acquire_request.attachment_id.clone(),
                    expected_unowned_epoch: attachment.acquire_request.expected_unowned_epoch,
                    desired_revision: attachment.acquire_request.desired_revision,
                    placement_epoch: attachment.acquire_request.placement_epoch,
                    lease_duration_ms: attachment.acquire_request.lease_duration_ms,
                },
            },
            cats_api::runtime_reconciliation::UnixMillis::new(9_000).unwrap(),
        );
        let token = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let scope_id = Id::new("cats-root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service").unwrap();
        let data = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
        checkpoint.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            scope_id,
            control_socket_path: HostPath::new(
                data_directory
                    .join("root-provision.sock")
                    .to_string_lossy()
                    .into_owned(),
            )
            .unwrap(),
            data_directory: data.clone(),
            process_identity_token: token,
            size_bytes: attachment.size_bytes,
            boot_image_digest: desired.runtime.boot_image_digest.clone(),
            expected_blank_head: blank,
            expected_provisioned_head: target,
        };
        checkpoint.volumes = vec![prepared_owned_observed_volume(
            &desired.volumes[0],
            &attachment,
            data,
        )];
        let stored_checkpoint = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap()
        .create(&checkpoint)
        .unwrap();
        let acquired: AuthorizedBlockdCheckpoint = serde_json::from_slice(
            &std::fs::read(data_directory.join(LAUNCH_CHECKPOINT_FILE)).unwrap(),
        )
        .unwrap();
        let ReconcileStep::ProvisionRootImage {
            provision_transition_id,
            ..
        } = &checkpoint.step
        else {
            unreachable!()
        };
        let authority = super::super::serving_handoff::ServingAuthorityTargetEvidence::new(
            provision_transition_id.clone(),
            record.clone(),
        );
        let expected = RootProvisionProcessExpectation::from_checkpoint(
            &checkpoint,
            super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                attachment,
                volume: &record,
            },
            HostPath::new(environment.blockd_binary.to_string_lossy().into_owned()).unwrap(),
        )
        .unwrap();
        FullRootScannerFixture {
            scan_context,
            config: environment.config(),
            record,
            blob,
            expected,
            data_directory,
            stored_checkpoint,
            acquired,
            authority,
        }
    }

    #[test]
    fn current_acquire_crash_retry_completes_without_root_process_or_blockd_lineage() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = scan_context.coordinates().desired.desired_specs[0].clone();
        let volume = &desired.volumes[0];
        let VolumeAcquire::Normal {
            transition_id,
            expected_unowned_epoch,
        } = &volume.acquire
        else {
            unreachable!()
        };
        let checkpoint = acquire_checkpoint(
            &desired,
            volume,
            RuntimeVolumeTransition::Acquire {
                request: VolumeAcquireRequest::Normal {
                    volume_id: volume.volume_id.clone(),
                    transition_id: transition_id.clone(),
                    attachment_id: volume.attachment_id.clone(),
                    expected_unowned_epoch: *expected_unowned_epoch,
                    desired_revision: desired.desired_revision,
                    placement_epoch: desired.placement.placement_epoch,
                    lease_duration_ms: 60_000,
                },
            },
            UnixMillis::new(9_000).unwrap(),
        );
        FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap()
        .create(&checkpoint)
        .unwrap();

        let mut config = environment.config();
        config.root_process_port = Some(Arc::new(FakeRootProcessPort {
            inspections: Mutex::new(VecDeque::new()),
        }));
        let (authority, _) = TestVolumeDataAuthority::exact(unowned_record(
            volume.volume_id.as_str(),
            volume.size_bytes,
        ));
        let scanner = scanner_with_metadata_authority_and_blob(
            config,
            Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
            None,
        )
        .unwrap();

        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(scan_context).unwrap()
        else {
            panic!("current Acquire retry must not require a root-process or blockd projection")
        };
        assert!(matches!(
            &inventory.runtimes()[0].checkpoint,
            CheckpointEvidence::Valid { step, .. }
                if matches!(step.as_ref(), ReconcileStep::AcquireVolume { .. })
        ));
        assert!(inventory.runtimes()[0].processes.is_empty());
        assert!(!environment.state.join(DATA_NAMESPACE).exists());
    }

    fn full_root_scanner(
        fixture: &FullRootScannerFixture,
        inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
    ) -> CleanSlateInventoryScanner {
        let mut config = fixture.config.clone();
        config.root_process_port = Some(Arc::new(FakeRootProcessPort {
            inspections: Mutex::new(inspections.into_iter().collect()),
        }));
        let (authority, _) = TestVolumeDataAuthority::exact(fixture.record.clone());
        let blob: Arc<dyn BlobStore> = fixture.blob.clone();
        scanner_with_metadata_authority_and_blob(
            config,
            Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
            Some(blob),
        )
        .unwrap()
    }

    fn prepare_device_successor(
        fixture: &FullRootScannerFixture,
        handoff: cats_api::runtime_reconciliation::RootServingHandoff,
    ) -> RuntimeCheckpoint {
        let mut checkpoint = fixture.stored_checkpoint.checkpoint().clone();
        let attachment = &fixture.acquired.attachment;
        let volume = &fixture.acquired.volume;
        let data_directory =
            HostPath::new(fixture.data_directory.to_string_lossy().into_owned()).unwrap();
        checkpoint.step = ReconcileStep::PrepareDevice {
            volume_id: volume.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            expected_head: fixture.record.head.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            guest_device: volume.guest_device.clone(),
            ownership_token: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            serving_authority: Box::new(ServingAuthorityProvenance::AfterRootProvision { handoff }),
            serving_process: ServingBlockdIdentity {
                scope_id: Id::new("cats-serving-dddddddddddddddddddddddddddddddd.service").unwrap(),
                control_socket_path: HostPath::new(
                    fixture
                        .data_directory
                        .join("serving-control.sock")
                        .to_string_lossy()
                        .into_owned(),
                )
                .unwrap(),
                data_directory,
                executable_path: fixture.expected.executable_path.clone(),
                process_identity_token: RandomId128::new("dddddddddddddddddddddddddddddddd")
                    .unwrap(),
            },
            frontend: PrepareDeviceFrontend::VhostUserBlk {
                socket_path: HostPath::new(
                    fixture
                        .data_directory
                        .join("serving-vhost.sock")
                        .to_string_lossy()
                        .into_owned(),
                )
                .unwrap(),
                queues: 2,
                queue_size: 256,
            },
        };
        let observed = checkpoint.volumes.first_mut().unwrap();
        observed.authority = VolumeAuthorityEvidence::Owned {
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            head: fixture.record.head.clone(),
        };
        for lineage in &mut observed.local_lineages {
            lineage.local_durable_generation = fixture.record.head.generation;
            lineage.remote_durable_generation = fixture.record.head.generation;
        }
        checkpoint.updated_at_unix_ms = UnixMillis::new(
            fixture
                .stored_checkpoint
                .checkpoint()
                .updated_at_unix_ms
                .get()
                + 1,
        )
        .unwrap();
        checkpoint
    }

    #[test]
    fn consumed_root_handoff_remains_complete_in_a_fresh_prepare_device_scan() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        install_exact_control_only_files(
            &fixture.data_directory,
            fixture.expected.attachment.size_bytes,
        );
        let proof = fixture
            .expected
            .clone()
            .prove_exact_process(exact_process_evidence(&fixture.expected, 79))
            .unwrap();
        let handoff_store = super::super::serving_handoff::ServingHandoffStore::new(
            StateDirectory::unanchored(environment.state.clone()),
        );
        let ready = handoff_store
            .seal_serving_ready(
                &fixture.stored_checkpoint,
                &fixture.acquired,
                &fixture.authority,
                &proof,
            )
            .unwrap();
        let checkpoint_store = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &fixture.expected.cat_id,
        )
        .unwrap();
        let successor = ready
            .consume_for_prepare_device(&fixture.stored_checkpoint, |handoff| {
                let successor = prepare_device_successor(&fixture, handoff);
                checkpoint_store
                    .replace(&fixture.stored_checkpoint, &successor)
                    .map(|_| successor)
                    .map_err(anyhow::Error::from)
            })
            .unwrap();

        let live_old_process = exact_process_evidence(&fixture.expected, 79);
        let _live_old_socket = install_exact_process_fixture(
            &environment,
            &fixture.expected,
            live_old_process.process_id,
        );
        let scanner = full_root_scanner(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
            ],
        );
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(fixture.scan_context.clone()).unwrap()
        else {
            panic!("live old target-control process must remain exact after PrepareDevice CAS")
        };
        assert_eq!(inventory.runtimes()[0].processes.len(), 1);
        assert_eq!(inventory.runtimes()[0].processes[0].process_id, 79);

        let mut physical_mismatches = Vec::new();
        let mut mismatch = live_old_process.clone();
        mismatch.process_id = 80;
        physical_mismatches.push(("process_id", mismatch));
        let mut mismatch = live_old_process.clone();
        mismatch.unit_main_process_id = 80;
        physical_mismatches.push(("unit_main_process_id", mismatch));
        let mut mismatch = live_old_process.clone();
        mismatch.process_start_time_ticks = WireU64::new(124).unwrap();
        physical_mismatches.push(("process_start_time_ticks", mismatch));
        let mut mismatch = live_old_process.clone();
        mismatch.cgroup_process_ids = vec![80];
        physical_mismatches.push(("cgroup_process_ids", mismatch));
        let mut mismatch = live_old_process.clone();
        mismatch.handshake.peer_process_id = 80;
        physical_mismatches.push(("handshake_peer_process_id", mismatch));
        for (field, mismatch) in physical_mismatches {
            assert!(
                full_root_scanner(
                    &fixture,
                    [RootProvisionProcessInspection::Exact(Box::new(mismatch))],
                )
                .scan_complete(fixture.scan_context.clone())
                .is_err(),
                "sealed old process {field} drift must conflict before an allowlist is formed"
            );
            assert!(
                environment
                    .systemd_root
                    .join(fixture.expected.scope_id.as_str())
                    .exists(),
                "conflict classification must not delete the retained unit"
            );
            assert!(
                environment.proc_root.join("79").exists(),
                "conflict classification must not delete the retained process"
            );
            assert!(
                Path::new(fixture.expected.control_socket_path.as_str()).exists(),
                "conflict classification must not delete the retained socket"
            );
        }

        let current = checkpoint_store.load().unwrap().unwrap();
        let mut drifted = successor.clone();
        let ReconcileStep::PrepareDevice {
            serving_process, ..
        } = &mut drifted.step
        else {
            unreachable!()
        };
        serving_process.data_directory = HostPath::new(
            fixture
                .data_directory
                .join("drifted")
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap();
        let drifted = checkpoint_store.replace(&current, &drifted).unwrap();
        assert!(full_root_scanner(&fixture, [])
            .scan_complete(assigned_context(true))
            .is_err());
        checkpoint_store.replace(&drifted, &successor).unwrap();

        let current = checkpoint_store.load().unwrap().unwrap();
        let mut direct = successor.clone();
        let authorization_path = fixture.data_directory.join(AUTHORIZED_SERVING_FILE);
        let authorization_bytes = std::fs::read(&authorization_path).unwrap();
        let metadata = std::fs::metadata(&authorization_path).unwrap();
        let ReconcileStep::PrepareDevice {
            serving_authority, ..
        } = &mut direct.step
        else {
            unreachable!()
        };
        **serving_authority = ServingAuthorityProvenance::DirectAuthorizedAttachment {
            authorization: DirectAuthorizedAttachmentIdentity {
                path: HostPath::new(authorization_path.to_string_lossy().into_owned()).unwrap(),
                device: WireU64::new(metadata.dev()).unwrap(),
                inode: WireU64::new(metadata.ino()).unwrap(),
                length: WireU64::new(metadata.len()).unwrap(),
                content_sha256: Sha256Digest::from_bytes(
                    Sha256::digest(authorization_bytes).into(),
                ),
            },
            purpose: DirectAuthorizedAttachmentPurpose::ExistingRoot,
        };
        let direct = checkpoint_store.replace(&current, &direct).unwrap();
        assert!(full_root_scanner(&fixture, [])
            .scan_complete(assigned_context(true))
            .is_err());
        checkpoint_store.replace(&direct, &successor).unwrap();

        for path in [
            fixture.data_directory.join(SERVING_HANDOFF_RECORD_FILE),
            fixture.data_directory.join(concat!(
                "authorized-target-control-",
                "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                ".json"
            )),
        ] {
            let bytes = std::fs::read(&path).unwrap();
            let mut drift = bytes.clone();
            drift.push(b' ');
            std::fs::write(&path, &drift).unwrap();
            assert!(full_root_scanner(&fixture, [])
                .scan_complete(assigned_context(true))
                .is_err());
            std::fs::write(&path, bytes).unwrap();
        }
        assert!(matches!(
            full_root_scanner(
                &fixture,
                [
                    RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(live_old_process)),
                ],
            )
            .scan_complete(assigned_context(true))
            .unwrap(),
            RuntimeInventoryScanOutcome::Complete(_)
        ));
    }

    #[test]
    fn production_pre_scan_recovers_each_safe_handoff_temp_then_requires_a_fresh_full_scan() {
        for kind in [
            ServingHandoffTempKind::TargetAuthorization,
            ServingHandoffTempKind::Record,
            ServingHandoffTempKind::RetirementReceipt,
        ] {
            let environment = TestEnvironment::new();
            let fixture = full_root_scanner_fixture(&environment);
            let handoff_store = super::super::serving_handoff::ServingHandoffStore::new(
                StateDirectory::unanchored(environment.state.clone()),
            );
            match kind {
                ServingHandoffTempKind::TargetAuthorization => {}
                ServingHandoffTempKind::Record => {
                    drop(
                        handoff_store
                            .seal_target_control_authorization(
                                &fixture.stored_checkpoint,
                                &fixture.acquired,
                                &fixture.authority,
                            )
                            .unwrap(),
                    );
                }
                ServingHandoffTempKind::RetirementReceipt => {
                    let proof = fixture
                        .expected
                        .clone()
                        .prove_exact_process(exact_process_evidence(&fixture.expected, 83))
                        .unwrap();
                    drop(
                        handoff_store
                            .seal_serving_ready(
                                &fixture.stored_checkpoint,
                                &fixture.acquired,
                                &fixture.authority,
                                &proof,
                            )
                            .unwrap(),
                    );
                }
            }
            let temp_name = match kind {
                ServingHandoffTempKind::TargetAuthorization => concat!(
                    ".authorized-target-control-",
                    "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    ".json.tmp"
                ),
                ServingHandoffTempKind::Record => ".serving-handoff.json.tmp",
                ServingHandoffTempKind::RetirementReceipt => ".serving-handoff-retirement.json.tmp",
            };
            let temp_path = fixture.data_directory.join(temp_name);
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            std::io::Write::write_all(&mut options.open(&temp_path).unwrap(), b"partial").unwrap();

            let (authority, _) = TestVolumeDataAuthority::exact(fixture.record.clone());
            let recovery = SignedRunningPublicationRecovery::new(authority);
            let recovery_context = RuntimePreScanRecoveryContext::for_test(
                StateDirectory::unanchored(environment.state.clone()),
                fixture.scan_context.coordinates().clone(),
                Instant::now() + Duration::from_secs(10),
            );
            assert!(matches!(
                recovery.recover_one(recovery_context).unwrap(),
                RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                    if cat_id == fixture.expected.cat_id
            ));
            assert!(!temp_path.exists());

            let scanner = full_root_scanner(
                &fixture,
                [
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ],
            );
            assert!(matches!(
                scanner.scan_complete(fixture.scan_context).unwrap(),
                RuntimeInventoryScanOutcome::Complete(_)
            ));
        }
    }

    #[test]
    fn handoff_checkpoint_join_is_linear_at_a_cap_scaled_cat_count() {
        const CAT_COUNT: usize = RUNTIME_V1_MAX_ASSIGNED_CATS / 16;
        let environment = TestEnvironment::new();
        let mut scan_context = context_until(Instant::now() + Duration::from_secs(60));
        let base = assigned_context(true).coordinates().desired.desired_specs[0].clone();
        let desired_specs = (0..CAT_COUNT)
            .map(|index| {
                let mut desired = base.clone();
                desired.cat_id = Id::new(format!("cat_{index:04}")).unwrap();
                desired.runtime.network_config.network_id =
                    Id::new(format!("net_{index:04}")).unwrap();
                let volume = desired.volumes.first_mut().unwrap();
                volume.volume_intent_id = Id::new(format!("vint_{index:04}")).unwrap();
                volume.disk_id = Id::new(format!("disk_{index:04}")).unwrap();
                volume.volume_id = Id::new(format!("vol_{index:04}")).unwrap();
                volume.attachment_id = Id::new(format!("att_{index:04}")).unwrap();
                volume.guest_device.serial = Id::new(format!("root-{index:04}")).unwrap();
                let VolumeAcquire::Normal { transition_id, .. } = &mut volume.acquire else {
                    unreachable!()
                };
                *transition_id = RandomId128::new(format!("{:032x}", index + 1)).unwrap();
                desired.spec_digest = spec_digest(&desired).unwrap();
                desired
            })
            .collect::<Vec<_>>();
        scan_context.coordinates_mut().desired.desired_specs = desired_specs.clone();

        let checkpoint_directory = environment.state.join(CHECKPOINT_NAMESPACE);
        let mut first_checkpoint_path = None;
        for (index, desired) in desired_specs.iter().enumerate() {
            let (mut record, attachment) = exact_owned_record_and_attachment(desired);
            let prepared =
                AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                    .prepare(desired, &desired.volumes[0], &attachment)
                    .unwrap();
            let data_directory = prepared.data_directory().to_path_buf();
            let acquired = prepared.checkpoint().clone();
            drop(prepared);
            let blob = ExactManifestBlobStore::for_desired(desired);
            let ProvisionHeadRead::Ready { blank, target } = expected_provision_heads(
                &blob,
                desired,
                &desired.volumes[0],
                scan_context.deadline(),
            ) else {
                panic!("cap-scaled fixture manifest must be exact")
            };
            let mut checkpoint = acquire_checkpoint(
                desired,
                &desired.volumes[0],
                RuntimeVolumeTransition::Acquire {
                    request: VolumeAcquireRequest::Normal {
                        volume_id: attachment.acquire_request.volume_id.clone(),
                        transition_id: attachment.acquire_request.transition_id.clone(),
                        attachment_id: attachment.acquire_request.attachment_id.clone(),
                        expected_unowned_epoch: attachment.acquire_request.expected_unowned_epoch,
                        desired_revision: attachment.acquire_request.desired_revision,
                        placement_epoch: attachment.acquire_request.placement_epoch,
                        lease_duration_ms: attachment.acquire_request.lease_duration_ms,
                    },
                },
                UnixMillis::new(10_000 + index as u64).unwrap(),
            );
            let provision_transition_id =
                RandomId128::new(format!("{:032x}", CAT_COUNT + index)).unwrap();
            let process_identity_token =
                RandomId128::new(format!("{:032x}", 2 * CAT_COUNT + index)).unwrap();
            let scope_id = Id::new(format!(
                "cats-root-{}.service",
                RandomId128::new(format!("{:032x}", 3 * CAT_COUNT + index))
                    .unwrap()
                    .as_str()
            ))
            .unwrap();
            let data = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
            checkpoint.step = ReconcileStep::ProvisionRootImage {
                provision_transition_id: provision_transition_id.clone(),
                volume_id: attachment.identity.volume_id.clone(),
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                scope_id,
                control_socket_path: HostPath::new(
                    data_directory
                        .join("root-provision.sock")
                        .to_string_lossy()
                        .into_owned(),
                )
                .unwrap(),
                data_directory: data.clone(),
                process_identity_token,
                size_bytes: attachment.size_bytes,
                boot_image_digest: desired.runtime.boot_image_digest.clone(),
                expected_blank_head: blank,
                expected_provisioned_head: target.clone(),
            };
            checkpoint.volumes = vec![prepared_owned_observed_volume(
                &desired.volumes[0],
                &attachment,
                data,
            )];
            let stored = FileCheckpointStore::open(&checkpoint_directory, &desired.cat_id)
                .unwrap()
                .create(&checkpoint)
                .unwrap();
            if index == 0 {
                record.head = target;
                let authority = super::super::serving_handoff::ServingAuthorityTargetEvidence::new(
                    provision_transition_id,
                    record,
                );
                drop(
                    super::super::serving_handoff::ServingHandoffStore::new(
                        StateDirectory::unanchored(environment.state.clone()),
                    )
                    .seal_target_control_authorization(&stored, &acquired, &authority)
                    .unwrap(),
                );
                first_checkpoint_path = Some(super::super::runtime_checkpoint_path(
                    &checkpoint_directory,
                    &desired.cat_id,
                ));
            }
        }

        // A stable, single-link rejection for another Cat is closed typed
        // checkpoint evidence. It must not hide the first Cat's handoff from
        // the one immutable namespace join.
        let rejection_desired = &desired_specs[1];
        let (_, rejection_attachment) = exact_owned_record_and_attachment(rejection_desired);
        let cleanup = CleanupRelease {
            target: CleanupTarget::Volume {
                volume_id: rejection_attachment.identity.volume_id.clone(),
                attachment_id: rejection_attachment.identity.attachment_id.clone(),
                attachment_epoch: rejection_attachment.identity.attachment_epoch,
            },
            inventory_session: SessionBinding {
                node_id: rejection_desired.placement.node_id.clone(),
                node_boot_id: NodeBootId::new("33333333333333333333333333333333").unwrap(),
                agent_instance_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
                agent_session_epoch: Epoch::new(2).unwrap(),
            },
            inventory_epoch: Epoch::new(3).unwrap(),
            inventory_read_position: Sequence::new(12).unwrap(),
            desired_read_position: Sequence::new(21).unwrap(),
            volume_release: Some(VolumeReleaseReplay {
                release_transition_id: RandomId128::new("55555555555555555555555555555555")
                    .unwrap(),
                generation: rejection_attachment.head.generation,
                disposition: rejection_desired.volumes[0].disposition.clone(),
            }),
        };
        let rejection_store =
            FileCheckpointStore::open(&checkpoint_directory, &rejection_desired.cat_id).unwrap();
        let current = rejection_store.load().unwrap().unwrap();
        let mut cleanup_checkpoint = current.checkpoint().clone();
        cleanup_checkpoint.step = ReconcileStep::CleanupRelease {
            cleanup: cleanup.clone(),
        };
        cleanup_checkpoint.updated_at_unix_ms =
            UnixMillis::new(cleanup_checkpoint.updated_at_unix_ms.get() + 1).unwrap();
        let cleanup_checkpoint = rejection_store
            .replace(&current, &cleanup_checkpoint)
            .unwrap();
        let release_request = RuntimeVolumeTransitionRequest {
            version: ContractVersion::V1,
            session: cleanup.inventory_session.clone(),
            cat_id: rejection_desired.cat_id.clone(),
            desired_revision: rejection_desired.desired_revision,
            spec_digest: rejection_desired.spec_digest.clone(),
            placement: rejection_desired.placement.clone(),
            transition: RuntimeVolumeTransition::Release { cleanup },
        };
        rejection_store
            .persist_definite_release_rejection(
                &cleanup_checkpoint,
                &release_request,
                RuntimeVolumeTransitionPreconditionProblem::CleanupEvidenceMismatch,
            )
            .unwrap();
        drop(rejection_store);

        let limits = ProbeLimits {
            // Enough for one checkpoint enumeration plus one linear data-tree
            // traversal, but far below the old 2*N^2 checkpoint cost.
            state_entries: 1_024,
            ..ProbeLimits::default()
        };
        let root = clone_state_root(&StateDirectory::unanchored(environment.state.clone()))
            .unwrap()
            .unwrap();
        let data =
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits).unwrap();
        assert!(data.complete);
        assert_eq!(data.evidence.len(), CAT_COUNT);

        let rejection_target = super::super::checkpoint::release_rejection_path(
            &checkpoint_directory,
            &rejection_desired.cat_id,
        );
        let rejection_temp = super::super::checkpoint::release_rejection_temporary_path(
            &checkpoint_directory,
            &rejection_desired.cat_id,
        );
        let rejection_bytes = std::fs::read(&rejection_target).unwrap();
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        std::io::Write::write_all(
            &mut options.open(&rejection_temp).unwrap(),
            &rejection_bytes,
        )
        .unwrap();
        let interrupted =
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits).unwrap();
        assert!(
            !interrupted.complete,
            "single-link rejection temp must fail closed"
        );
        assert_eq!(std::fs::read(&rejection_target).unwrap(), rejection_bytes);
        assert_eq!(std::fs::read(&rejection_temp).unwrap(), rejection_bytes);
        std::fs::remove_file(&rejection_temp).unwrap();

        std::fs::hard_link(&rejection_target, &rejection_temp).unwrap();
        let publishing =
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits).unwrap();
        assert!(
            !publishing.complete,
            "two-link rejection publication must fail closed"
        );
        assert_eq!(std::fs::metadata(&rejection_target).unwrap().nlink(), 2);
        assert_eq!(std::fs::metadata(&rejection_temp).unwrap().nlink(), 2);
        std::fs::remove_file(&rejection_temp).unwrap();
        assert!(
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits)
                .unwrap()
                .complete,
            "stable single-link rejection must rejoin the cross-Cat handoff"
        );

        let mut mismatched_marker =
            decode_definite_release_rejection(&rejection_bytes, &rejection_target).unwrap();
        mismatched_marker.checkpoint_content_digest = Sha256Digest::from_bytes([0xee; 32]);
        std::fs::write(
            &rejection_target,
            serde_json::to_vec(&mismatched_marker).unwrap(),
        )
        .unwrap();
        assert!(
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits).is_err(),
            "stable rejection must validate against its exact checkpoint"
        );
        std::fs::write(&rejection_target, &rejection_bytes).unwrap();

        let foreign_rejection = checkpoint_directory.join("cat-foreign.release-rejection.json");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        std::io::Write::write_all(
            &mut options.open(&foreign_rejection).unwrap(),
            &rejection_bytes,
        )
        .unwrap();
        assert!(
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits).is_err(),
            "foreign stable rejection must fail closed"
        );
        std::fs::remove_file(foreign_rejection).unwrap();

        let foreign = checkpoint_directory.join("foreign.checkpoint");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        std::io::Write::write_all(&mut options.open(&foreign).unwrap(), b"foreign").unwrap();
        assert!(
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits,).is_err()
        );
        std::fs::remove_file(foreign).unwrap();

        let first_bytes = std::fs::read(first_checkpoint_path.unwrap()).unwrap();
        let duplicate_path =
            super::super::runtime_checkpoint_path(&checkpoint_directory, &desired_specs[1].cat_id);
        std::fs::write(duplicate_path, first_bytes).unwrap();
        assert!(
            scan_authorized_blockd_data(&root, &environment.state, &scan_context, limits,).is_err()
        );
    }

    #[test]
    fn full_scanner_rejects_exact_process_without_exact_control_only_files() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        let exact = exact_process_evidence(&fixture.expected, 69);
        let _socket =
            install_exact_process_fixture(&environment, &fixture.expected, exact.process_id);
        let scanner = full_root_scanner(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                RootProvisionProcessInspection::Exact(Box::new(exact)),
            ],
        );

        assert!(matches!(
            scanner.scan_complete(fixture.scan_context).unwrap(),
            RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                if unavailable_sources.contains(&InventorySource::DataDirectory)
        ));
        for name in ["cache.data", "dirty.bitmap", "pending-packs"] {
            assert!(!fixture.data_directory.join(name).exists(), "{name}");
        }
    }

    #[test]
    fn full_scanner_accepts_absent_process_with_not_started_control_state() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        assert!(matches!(
            authorized_data_probe(&environment)
                .prove_absent(&fixture.scan_context)
                .unwrap(),
            InventoryAbsence::AuthorizedBlockd(evidence)
                if matches!(
                    evidence
                        .get(&fixture.expected.cat_id)
                        .map(|item| &item.control_state),
                    Some(AuthorizedBlockdControlState::NotStarted)
                )
        ));
        let scanner = full_root_scanner(
            &fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );

        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(fixture.scan_context).unwrap()
        else {
            panic!("absent process and not-started engine state must be complete")
        };
        assert!(inventory.runtimes()[0].processes.is_empty());
        for name in ["cache.data", "dirty.bitmap", "pending-packs"] {
            assert!(!fixture.data_directory.join(name).exists(), "{name}");
        }
    }

    #[test]
    fn full_scanner_projects_exact_root_process_from_all_three_raw_authorities() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        install_exact_control_only_files(
            &fixture.data_directory,
            fixture.expected.attachment.size_bytes,
        );
        let exact = exact_process_evidence(&fixture.expected, 71);
        let _socket =
            install_exact_process_fixture(&environment, &fixture.expected, exact.process_id);
        let scanner = full_root_scanner(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                RootProvisionProcessInspection::Exact(Box::new(exact)),
            ],
        );
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(fixture.scan_context).unwrap()
        else {
            panic!("all exact sources must complete the full scan")
        };
        assert_eq!(inventory.runtimes()[0].processes.len(), 1);
        assert_eq!(inventory.runtimes()[0].processes[0].process_id, 71);
    }

    #[test]
    fn root_process_bridge_absent_and_unavailable_are_distinct() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert!(matches!(
            bridge
                .inspect_all(
                    BTreeMap::from([(expected.cat_id.clone(), expected)]),
                    &assigned_context(true),
                )
                .unwrap(),
            RootProcessInventoryBridgeOutcome::Complete(processes) if processes.is_empty()
        ));

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let bridge =
            root_process_bridge(&environment, [RootProvisionProcessInspection::Unavailable]);
        assert!(matches!(
            bridge
                .inspect_all(
                    BTreeMap::from([(expected.cat_id.clone(), expected)]),
                    &assigned_context(true),
                )
                .unwrap(),
            RootProcessInventoryBridgeOutcome::Unavailable
        ));
    }

    #[test]
    fn root_process_bridge_fails_closed_on_conflict_foreign_and_partial_socket() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let bridge = root_process_bridge(
            &environment,
            [RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity,
            )],
        );
        assert!(bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .is_err());

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        std::fs::create_dir(environment.systemd_root.join("cats-foreign.service")).unwrap();
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert!(bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .is_err());

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let _partial =
            std::os::unix::net::UnixListener::bind(expected.control_socket_path.as_str()).unwrap();
        std::fs::set_permissions(
            expected.control_socket_path.as_str(),
            <std::fs::Permissions as std::os::unix::fs::PermissionsExt>::from_mode(0o700),
        )
        .unwrap();
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert!(bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .is_err());
    }

    #[test]
    fn production_retirement_adapter_reuses_the_sealed_node_global_sweep() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &assigned_context(true))
                .unwrap(),
            RootProvisionProcessInspection::Absent
        ));

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let foreign_unit = environment.systemd_root.join("cats-foreign.service");
        std::fs::create_dir(&foreign_unit).unwrap();
        let bridge = root_process_bridge(&environment, [RootProvisionProcessInspection::Absent]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &assigned_context(true))
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
        assert!(foreign_unit.exists(), "retirement sweep must be read-only");

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let foreign_pid = environment.proc_root.join("73");
        std::fs::create_dir(&foreign_pid).unwrap();
        std::os::unix::fs::symlink(expected.executable_path.as_str(), foreign_pid.join("exe"))
            .unwrap();
        std::fs::write(
            foreign_pid.join("cmdline"),
            [expected.executable_path.as_str().as_bytes(), b"\0"].concat(),
        )
        .unwrap();
        let bridge = root_process_bridge(&environment, [RootProvisionProcessInspection::Absent]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &assigned_context(true))
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
        assert!(foreign_pid.exists(), "retirement sweep must not kill a PID");

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let foreign_socket_path = environment
            .state
            .join(DATA_NAMESPACE)
            .join("foreign")
            .join("late.sock");
        std::fs::create_dir_all(foreign_socket_path.parent().unwrap()).unwrap();
        let _foreign_socket = std::os::unix::net::UnixListener::bind(&foreign_socket_path).unwrap();
        let bridge = root_process_bridge(&environment, [RootProvisionProcessInspection::Absent]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &assigned_context(true))
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
        assert!(foreign_socket_path.exists());
    }

    #[test]
    fn production_retirement_adapter_rejects_a_late_expected_identity() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let exact = exact_process_evidence(&expected, 75);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Exact(Box::new(exact)),
            ],
        );
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &assigned_context(true))
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch
            )
        ));
    }

    #[test]
    fn root_process_bridge_rejects_extra_managed_process_and_inspection_race() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let exact = exact_process_evidence(&expected, 51);
        let _socket = install_exact_process_fixture(&environment, &expected, exact.process_id);
        let extra = environment.proc_root.join("52");
        std::fs::create_dir(&extra).unwrap();
        std::os::unix::fs::symlink(expected.executable_path.as_str(), extra.join("exe")).unwrap();
        std::fs::write(extra.join("cmdline"), b"").unwrap();
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                RootProvisionProcessInspection::Exact(Box::new(exact)),
            ],
        );
        assert!(bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .is_err());

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let exact = exact_process_evidence(&expected, 61);
        let _socket = install_exact_process_fixture(&environment, &expected, exact.process_id);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(exact)),
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert!(bridge
            .inspect_all(
                BTreeMap::from([(expected.cat_id.clone(), expected)]),
                &assigned_context(true),
            )
            .is_err());
    }

    #[test]
    fn systemd_global_sweep_recognizes_transient_cats_services() {
        let environment = TestEnvironment::new();
        std::fs::create_dir(environment.systemd_root.join("cats-root-token.service")).unwrap();
        let mut budget = 16;
        assert_eq!(
            scan_cgroup_tree(
                &environment.systemd_root,
                CgroupKind::Systemd,
                0,
                &mut budget,
                4,
                &context(),
            )
            .unwrap(),
            ProbeFact::Present
        );
    }
}
