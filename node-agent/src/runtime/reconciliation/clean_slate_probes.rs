//! Read-only production probes for the first Running inventory vertical.
//!
//! These probes recognize an otherwise-empty Host; the typed test seam can
//! also compose a complete per-Node authority-index snapshot for a root-only
//! Running Desired. Production reads the schema-v11 owner index and the exact
//! Desired candidate set in one bounded repeatable-read snapshot, then pages
//! that immutable result locally. Finding any local Cats runtime fact is still an error, not an
//! invitation to infer an identity, adopt it, or clean it up. A source that
//! cannot be enumerated exhaustively reports `Unavailable`; it never turns an
//! I/O failure into absence.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsStr, OsString};
use std::fs::{File, OpenOptions};
use std::io::{self, Read as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::{OsStrExt as _, OsStringExt as _};
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{bail, Context as _};
use cats_api::runtime_reconciliation::{
    DesiredRuntimeSpec, DiskKind, Id, InventorySource, ObservedDiskKind, ObservedVolume, Sequence,
    VolumeAcquire, VolumeAdminState, VolumeAuthorityEvidence, VolumeIntent,
};
#[cfg(test)]
use cats_storage::authority::VolumeDataAuthority;
use cats_storage::authority::{
    validate_volume_owner_binding, validate_volume_record, NodeVolumeInventorySnapshot,
    RuntimeVolumeInventoryAuthority, VolumeRecord,
};

use crate::runtime_spine::{RuntimeInventoryScanContext, RuntimeInventoryScanner};
use crate::state_directory::StateDirectory;

use super::{CleanSlateInventoryScanner, InventoryAbsence, InventoryAbsenceProbe};

pub(crate) const CHECKPOINT_NAMESPACE: &str = "checkpoints";
const CONTROL_SOCKET_NAMESPACE: &str = "control-sockets";
const VHOST_NAMESPACE: &str = "vhost-user";
const NETWORK_NAMESPACE: &str = "network";
const RUNTIME_EFFECTS_NAMESPACE: &str = "runtime-effects";
const DATA_NAMESPACE: &str = "data";
const PENDING_PACK_NAMESPACE: &str = "pending-packs";
const WARM_SNAPSHOT_NAMESPACE: &str = "warm-snapshots";
const GUEST_MOUNT_NAMESPACE: &str = "guest-mounts";

const LEGACY_LEDGER: &str = "runtime-ledger";
const LEGACY_CATS_DIRECTORY: &str = "cats";
const DEFAULT_LEGACY_SOCKET_ROOT: &str = "/tmp/cats-sock";
const DEFAULT_SYSTEMD_CGROUP_ROOT: &str = "/sys/fs/cgroup/system.slice";
const DEFAULT_PROC_ROOT: &str = "/proc";
const DEFAULT_BLOCK_CLASS_ROOT: &str = "/sys/class/block";
const DEFAULT_NETWORK_CLASS_ROOT: &str = "/sys/class/net";

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
            state_entries: 4_096,
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
            .finish()
    }
}

#[derive(Debug, Clone)]
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
        })
    }
}

pub(crate) fn installed_clean_slate_scanner(
    config: InstalledCleanSlateProbeConfig,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    let metadata_authority = Arc::new(PagedMetadataAuthorityReader::new(Arc::new(
        RuntimeVolumeInventoryPagePort::start(Arc::clone(&config.volume_inventory_authority))?,
    )));
    let config = ProbeConfig::installed(config)?;
    let scanner = scanner_with_metadata_authority(config, metadata_authority)?;
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
    let checkpoint_directory = config.state_directory.path().join(CHECKPOINT_NAMESPACE);
    Ok(Arc::new(scanner_with_metadata_authority(
        ProbeConfig {
            state_directory: config.state_directory,
            checkpoint_directory,
            proc_root: config.proc_root,
            systemd_cgroup_root: config.systemd_cgroup_root,
            metering_cgroup_root: None,
            block_class_root: config.block_class_root,
            network_class_root: config.network_class_root,
            legacy_socket_root: config.legacy_socket_root,
            cloud_hypervisor_binary: config.cloud_hypervisor_binary,
            blockd_binary: config.blockd_binary,
            guest_agent_binary: config.guest_agent_binary,
            linux_sources_supported: true,
            limits: ProbeLimits::default(),
        },
        Arc::new(TestAuthoritativeEmptyMetadataReader),
    )?))
}

#[cfg(test)]
fn scanner(config: ProbeConfig) -> anyhow::Result<CleanSlateInventoryScanner> {
    scanner_with_metadata_authority(config, Arc::new(TestAuthoritativeEmptyMetadataReader))
}

fn scanner_with_metadata_authority(
    config: ProbeConfig,
    metadata_authority: Arc<dyn MetadataAuthorityAbsenceReader>,
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
        Arc::new(StateNamespaceProbe {
            source: InventorySource::Checkpoint,
            state_directory: state.clone(),
            namespace: CHECKPOINT_NAMESPACE,
            reject_legacy_root: true,
            limits: config.limits,
        }),
        Arc::new(SystemdProbe {
            systemd_root: config.systemd_cgroup_root,
            metering_root: config.metering_cgroup_root,
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
        Arc::new(StateNamespaceProbe {
            source: InventorySource::DataDirectory,
            state_directory: state.clone(),
            namespace: DATA_NAMESPACE,
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
            legacy_socket_root: config.legacy_socket_root,
            guest_process_paths: ProcessPaths {
                root: config.proc_root,
                binaries: vec![config.guest_agent_binary],
                supported: config.linux_sources_supported,
                limits: config.limits,
            },
            limits: config.limits,
        }),
    ];
    CleanSlateInventoryScanner::new(config.checkpoint_directory, probes)
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

struct StateNamespaceProbe {
    source: InventorySource,
    state_directory: StateDirectory,
    namespace: &'static str,
    reject_legacy_root: bool,
    limits: ProbeLimits,
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

        let mut local_candidates_complete = true;
        if let Some(root) = clone_state_root(&self.state_directory)? {
            for namespace in [DATA_NAMESPACE, PENDING_PACK_NAMESPACE] {
                let discovered = scan_state_volume_candidates(
                    &root,
                    namespace,
                    self.limits.state_entries,
                    context,
                )?;
                candidate_volume_ids.extend(discovered.volume_ids);
                local_candidates_complete &= discovered.complete;
            }
            local_candidates_complete &= matches!(
                state_entry_fact(&root, LEGACY_CATS_DIRECTORY, context)?,
                ProbeFact::Empty
            );
        } else {
            local_candidates_complete = false;
        }

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
                if let Some(local_only) =
                    candidate_volume_ids.difference(&desired_volume_ids).next()
                {
                    bail!(
                        "metadata authority/local namespaces retain volume outside Desired: {local_only}"
                    );
                }

                let mut by_cat: BTreeMap<Id, Vec<ObservedVolume>> = BTreeMap::new();
                for (volume_id, (desired, intent)) in desired_volumes {
                    let Some(record) = records.get(&volume_id) else {
                        return Ok(InventoryAbsence::Unavailable);
                    };
                    let observed = observe_desired_volume(desired, intent, record)?;
                    by_cat
                        .entry(desired.cat_id.clone())
                        .or_default()
                        .push(observed);
                }
                Ok(InventoryAbsence::DesiredVolumes(by_cat))
            }
        }
    }
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

    if record.lease_owner.as_ref() == Some(&intent.attachment_id) {
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
        anyhow::ensure!(
            request.volume_id == intent.volume_id
                && request.transition_id == *transition_id
                && request.attachment_id == intent.attachment_id
                && request.expected_unowned_epoch == *expected_unowned_epoch
                && request.desired_revision == desired.desired_revision
                && request.placement_epoch == desired.placement.placement_epoch
                && result.volume_id == intent.volume_id
                && result.transition_id == *transition_id
                && result.attachment_id == intent.attachment_id
                && result.resulting_epoch == record.lease_epoch,
            "Desired attachment owner does not bind the current Desired grant"
        );
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
    context: &RuntimeInventoryScanContext,
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
    context: &RuntimeInventoryScanContext,
) -> anyhow::Result<ProbeFact> {
    scan_managed_path_namespace_matching(path, cap, context, |_| true)
}

fn scan_managed_path_namespace_matching(
    path: &Path,
    cap: usize,
    context: &RuntimeInventoryScanContext,
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
    context: &RuntimeInventoryScanContext,
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
    context: &RuntimeInventoryScanContext,
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
    context: &RuntimeInventoryScanContext,
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
            CgroupKind::Systemd => is_cats_scope(&name),
            CgroupKind::DedicatedMeteringRoot => true,
        };
        if candidate {
            return Ok(ProbeFact::Present);
        }
        match scan_cgroup_tree(&entry.path(), kind, depth + 1, budget, depth_cap, context)? {
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

fn is_cats_scope(name: &OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };
    name.starts_with("cats-") && name.ends_with(".scope")
}

fn scan_processes(
    paths: &ProcessPaths,
    context: &RuntimeInventoryScanContext,
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
        let pid = entry.path();
        let exe = std::fs::read_link(pid.join("exe"));
        if exe
            .as_ref()
            .is_ok_and(|exe| paths.binaries.iter().any(|binary| binary == exe))
        {
            return Ok(ProbeFact::Present);
        }
        let cmdline = read_bounded_optional(
            &pid.join("cmdline"),
            paths.limits.process_cmdline_bytes,
            context,
        )?;
        if let OptionalBytes::Bytes(cmdline) = &cmdline {
            let first = cmdline.split(|byte| *byte == 0).next().unwrap_or_default();
            if paths
                .binaries
                .iter()
                .any(|binary| binary.as_os_str().as_bytes() == first)
            {
                return Ok(ProbeFact::Present);
            }
        }
        if let Err(source) = exe {
            unavailable |= source.kind() != io::ErrorKind::NotFound
                || (matches!(cmdline, OptionalBytes::Missing) && pid.exists());
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
    context: &RuntimeInventoryScanContext,
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
        decode_desired_read_snapshot, spec_digest, AssignedKind, AssignedPlacement,
        CheckpointEvidence, ContractVersion, DesiredRuntimeSpec, DiskKind, Durability, Epoch,
        FenceEpoch, GuestDeviceIdentity, Id, Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission,
        MacAddress, NetworkConfig, RandomId128, ReconcileStep, Revision, RuntimeConfig,
        RuntimeTarget, RuntimeTransition, SessionBinding, Sha256Digest, VolumeAccess,
        VolumeAcquire, VolumeDisposition, VolumeIntent,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::{
        RuntimeInventoryScanOutcome, RuntimeInventoryScanner, RuntimeSpineFullScan,
    };

    use super::*;

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

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
            let root = tempfile::tempdir().unwrap();
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
            by_cat[&Id::new("cat_01").unwrap()][0].volume_id,
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
        assert_eq!(
            reader
                .read_candidates(
                    &Id::new("node_a").unwrap(),
                    &BTreeSet::new(),
                    first.deadline(),
                    &first,
                )
                .unwrap(),
            MetadataAuthorityCandidateInventory::Unavailable
        );
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
        })
        .unwrap();
        assert_eq!(
            config.checkpoint_directory,
            state.path().join(CHECKPOINT_NAMESPACE)
        );
    }
}
