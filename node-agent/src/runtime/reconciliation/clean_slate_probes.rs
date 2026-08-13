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
use cats_api::blockd::PENDING_PACK_DIR;
use cats_api::chunk;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, decode_runtime_checkpoint, encode_desired_runtime_spec,
    DesiredRuntimeSpec, DiskKind, HostPath, Id, InventorySource, ObservedDiskKind, ObservedVolume,
    ProcessState, ReconcileStep, RuntimeCheckpoint, Sequence, Sha256Digest, VolumeAccess,
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
    RuntimeAssignedCatSet, RuntimeInventoryScanContext, RuntimeInventoryScanner,
    RuntimePhysicalReadContext, RuntimePreScanRecoveryContext,
};
use crate::state_directory::StateDirectory;

use super::authorized_blockd::{
    decode_root_provision_stop_receipt, validate_authorized_blockd_checkpoint,
    AUTHORIZED_SERVING_FILE, AUTHORIZED_SERVING_TEMP, IDENTITY_FILE, IDENTITY_TEMP,
    LAUNCH_CHECKPOINT_FILE, LAUNCH_CHECKPOINT_TEMP, MAX_AUTHORIZED_SERVING_BYTES,
    MAX_IDENTITY_BYTES, MAX_LAUNCH_CHECKPOINT_BYTES, ROOT_PROVISION_STOP_RECEIPT_FILE,
    ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES, ROOT_PROVISION_STOP_RECEIPT_TEMP,
};
#[cfg(target_os = "linux")]
use super::blockd_socket_namespace::ManagedBlockdSocketWholeRootSnapshot;
use super::blockd_socket_namespace::{
    serving_socket_owner_authority_digest, BlockdSocketIntentStore, BlockdSocketOwnershipIntentV1,
    CurrentBlockdSocketBoot, ExactManagedBlockdSocketOwnerStartAbsence,
    RetainedManagedBlockdSocketRoot,
};
use super::checkpoint::{
    decode_definite_release_rejection, validate_definite_release_rejection,
    DefiniteReleaseRejection, RELEASE_REJECTION_MAX_BYTES,
};
#[cfg(test)]
use super::inventory::serving_process_expectations;
use super::inventory::{
    checkpoint_prepared_volume_matches_blockd, AuthorityVolumeInventoryEvidence,
    AuthorizedBlockdControlState, AuthorizedBlockdInventoryEvidence, DesiredCheckpointBinding,
    RuntimeCheckpointInventoryEvidence,
};
use super::kernel_nbd::{KernelNbdInventoryConfig, KernelNbdInventoryPort};
use super::network::{
    prepare_device_checkpoint_view, prepared_device_inputs, NetworkAllocationPort,
};
use super::root_provision_process::inspect_exact_root_provision_process;
use super::root_provision_process::ManagedServingKey;
use super::root_provision_process::RootProvisionManagedStopInspection;
use super::root_provision_process::StopReceiptSocketAdmission;
use super::serving_blockd_process::{
    global_sealed as serving_global_sealed, process_sealed as serving_process_sealed,
    ServingBlockdExpectation, ServingBlockdProcessConflict, ServingBlockdProcessGlobalPort,
    ServingBlockdProcessInspection, ServingBlockdProcessPort,
};
use super::serving_handoff::{
    scanned_target_control_process_launch, validate_scanned_serving_handoff_artifacts,
    ScannedServingHandoffArtifact, ServingHandoffTempKind, SERVING_HANDOFF_RECORD_FILE,
    SERVING_HANDOFF_RECORD_MAX_BYTES, SERVING_HANDOFF_RETIREMENT_FILE,
    SERVING_HANDOFF_RETIREMENT_MAX_BYTES,
};
use super::signed_running::request_matches_volume;
use super::systemd_root_provision::platform_managed_blockd_listeners_absent;
use super::vmm_cid::{
    inventory_port_sealed as vmm_cid_inventory_sealed, ExactLiveVmmCid, VmmCidInventoryPort,
    VmmCidInventorySnapshot, VmmCidOwner,
};
use super::vmm_process::{
    global_sealed as vmm_global_sealed, sealed as vmm_process_sealed,
    PlatformSystemdVmmProcessPort, VmmGateSuccessorProof, VmmProcessConflict,
    VmmProcessExpectation, VmmProcessGlobalInspection, VmmProcessGlobalPort, VmmProcessInspection,
    VmmProcessPort,
};
#[cfg(target_os = "linux")]
use super::vmm_process::{
    stale_boot_recovery_global_sealed, StaleBootVmmProcessGlobalInspection,
    StaleBootVmmProcessGlobalPort,
};
#[cfg(all(test, target_os = "linux"))]
use super::vmm_runtime_paths::VMM_LAUNCH_FILE_NAMESPACE;
#[cfg(target_os = "linux")]
use super::vmm_runtime_paths::{
    scan_managed_vmm_launch_root, scan_managed_vmm_launch_root_for_stale_boot_recovery,
    ManagedVmmLaunchRootScan, RetainedManagedVmmLaunchRoot,
};
#[cfg(target_os = "linux")]
use super::vmm_socket_namespace::{
    current_kernel_node_boot_id, scan_managed_vmm_socket_root_for_stale_boot_recovery,
    scan_stale_boot_receipt_namespace_snapshot, ReceiptNamespaceSnapshot,
    StaleVmmSocketReceiptScan,
};
use super::vmm_socket_namespace::{
    scan_managed_vmm_socket_root, ManagedVmmSocketRootScan, RetainedManagedVmmSocketRoot,
    VmmSocketReceiptStore,
};
use super::{
    inventory::{
        root_process_inventory_bridge_sealed, ActiveRuntimeInventoryKeyRingReader,
        RootProcessInventoryBridge, RootProcessInventoryBridgeOutcome,
    },
    AdmissionCellRegistry, AuthorizedBlockdCheckpoint, CleanSlateInventoryScanner,
    InventoryAbsence, InventoryAbsenceProbe, PlatformSystemdRootProvisionProcessPort,
    PlatformSystemdServingBlockdProcessPort, RootProvisionProcessConflict,
    RootProvisionProcessExpectation, RootProvisionProcessGlobalPort,
    RootProvisionProcessInspection, RootProvisionProcessPort, RootProvisionProcessRetirementPort,
    RootProvisionSystemdConfig,
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
pub(super) const RUNTIME_V1_MAX_ASSIGNED_CATS: usize = 1_024;
const RUNTIME_STATE_ENTRIES_PER_ASSIGNED_CAT: usize = 32;
pub(crate) const RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT: usize =
    RUNTIME_V1_MAX_ASSIGNED_CATS * RUNTIME_STATE_ENTRIES_PER_ASSIGNED_CAT;

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
    /// The current Takeover target artifact is already the one exact extra
    /// member beyond the checkpoint's prepared set. The checkpoint CAS may
    /// have lost its response; pre-scan recovery may read fresh signed
    /// successor evidence, but must not rewrite or delete this immutable R0.
    AuthorizedBlockdTakeoverPublication {
        cat_id: Id,
    },
    RootProvisionStopReceipt {
        cat_id: Id,
    },
    RootProvisionStopReceiptPublication {
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

fn next_stop_receipt_recovery(
    stable: &[Id],
    recoverable: &[Id],
) -> Option<LocalPublicationRecoveryEvidence> {
    recoverable
        .first()
        .cloned()
        .map(
            |cat_id| LocalPublicationRecoveryEvidence::RootProvisionStopReceiptPublication {
                cat_id,
            },
        )
        .or_else(|| {
            stable
                .first()
                .cloned()
                .map(|cat_id| LocalPublicationRecoveryEvidence::RootProvisionStopReceipt { cat_id })
        })
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
            state_entries: RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
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
    pub ip_binary: PathBuf,
    pub kernel_nbd_inventory: Option<KernelNbdInventoryConfig>,
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
            .field("ip_binary", &self.ip_binary)
            .field("kernel_nbd_inventory", &self.kernel_nbd_inventory)
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
    serving_process_port: Option<Arc<dyn ServingBlockdProcessPort>>,
    root_provision_systemd: Option<RootProvisionSystemdConfig>,
    network_allocation_port: Option<NetworkAllocationPort>,
    kernel_nbd_inventory_port: Option<KernelNbdInventoryPort>,
    managed_blockd_socket_root: Option<Arc<RetainedManagedBlockdSocketRoot>>,
    blockd_socket_intents: Option<Arc<BlockdSocketIntentStore>>,
    managed_vmm_socket_root: Option<Arc<RetainedManagedVmmSocketRoot>>,
    #[cfg(target_os = "linux")]
    managed_vmm_launch_root: Option<Arc<RetainedManagedVmmLaunchRoot>>,
    vmm_socket_receipts: Option<Arc<VmmSocketReceiptStore>>,
    recovery_metadata_authority: Option<Arc<dyn MetadataAuthorityAbsenceReader>>,
    recovery_blob_store: Option<Arc<dyn BlobStore>>,
}

impl ProbeConfig {
    fn installed(config: InstalledCleanSlateProbeConfig) -> anyhow::Result<Self> {
        for (role, binary) in [
            ("Cloud Hypervisor", &config.cloud_hypervisor_binary),
            ("cats-blockd", &config.blockd_binary),
            ("cats-guest-agent", &config.guest_agent_binary),
            ("ip", &config.ip_binary),
        ] {
            anyhow::ensure!(
                binary.is_absolute(),
                "installed {role} binary path must be absolute: {}",
                binary.display()
            );
        }
        let checkpoint_directory = config.state_directory.path().join(CHECKPOINT_NAMESPACE);
        let managed_blockd_socket_root =
            Arc::new(RetainedManagedBlockdSocketRoot::open_installed()?);
        let blockd_socket_intents = Arc::new(BlockdSocketIntentStore::open_existing(
            config.state_directory.clone(),
        )?);
        if let Some(kernel_nbd) = &config.kernel_nbd_inventory {
            anyhow::ensure!(
                kernel_nbd.state_directory().path() == config.state_directory.path(),
                "installed kernel-NBD scanner uses another StateDirectory"
            );
        }
        #[cfg(target_os = "linux")]
        let (managed_vmm_socket_root, managed_vmm_launch_root, vmm_socket_receipts) = (
            Some(Arc::new(
                RetainedManagedVmmSocketRoot::open_installed()
                    .context("open installed managed VMM socket root")?,
            )),
            Some(Arc::new(
                RetainedManagedVmmLaunchRoot::open_existing(config.state_directory.clone())
                    .context("open installed VMM launch-file namespace")?,
            )),
            Some(Arc::new(
                VmmSocketReceiptStore::open_existing(config.state_directory.clone())
                    .context("open installed VMM socket receipt namespace")?,
            )),
        );
        #[cfg(not(target_os = "linux"))]
        let (managed_vmm_socket_root, vmm_socket_receipts) = (None, None);
        let recovery_metadata_authority = Arc::new(PagedMetadataAuthorityReader::new(Arc::new(
            RuntimeVolumeInventoryPagePort::start(Arc::clone(&config.volume_inventory_authority))?,
        ))) as Arc<dyn MetadataAuthorityAbsenceReader>;
        Ok(Self {
            state_directory: config.state_directory.clone(),
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
                config.root_provision_systemd.clone(),
                config.state_directory.clone(),
            ))),
            serving_process_port: Some(Arc::new(
                PlatformSystemdServingBlockdProcessPort::platform(
                    config.state_directory.clone(),
                    Arc::clone(&managed_blockd_socket_root),
                ),
            )),
            root_provision_systemd: Some(config.root_provision_systemd),
            network_allocation_port: Some(NetworkAllocationPort::new(
                config.state_directory,
                config.ip_binary,
            )?),
            kernel_nbd_inventory_port: config.kernel_nbd_inventory.map(KernelNbdInventoryPort::new),
            managed_blockd_socket_root: Some(managed_blockd_socket_root),
            blockd_socket_intents: Some(blockd_socket_intents),
            managed_vmm_socket_root,
            #[cfg(target_os = "linux")]
            managed_vmm_launch_root,
            vmm_socket_receipts,
            recovery_metadata_authority: Some(recovery_metadata_authority),
            recovery_blob_store: Some(config.blob_store),
        })
    }
}

pub(crate) fn installed_clean_slate_scanner(
    config: InstalledCleanSlateProbeConfig,
    admission_registry: Arc<AdmissionCellRegistry>,
    route_grant_verifier: Option<Arc<crate::route_grant_v2::RouteGrantV2Verifier>>,
) -> anyhow::Result<Arc<dyn RuntimeInventoryScanner>> {
    let metadata_authority = Arc::new(PagedMetadataAuthorityReader::new(Arc::new(
        RuntimeVolumeInventoryPagePort::start(Arc::clone(&config.volume_inventory_authority))?,
    )));
    let blob_store = Arc::clone(&config.blob_store);
    let config = ProbeConfig::installed(config)?;
    let scanner =
        scanner_with_metadata_authority_and_blob(config, metadata_authority, Some(blob_store))?
            .with_running_tail(admission_registry);
    let scanner = match route_grant_verifier {
        Some(verifier) => scanner
            .with_key_ring_reader(Arc::new(ActiveRuntimeInventoryKeyRingReader::new(verifier))),
        // A ring artifact is not an authorization fact when the machine
        // listener is disabled. Reporting unavailable prevents Control from
        // minting a Grant to an ingress that this process cannot serve.
        None => scanner,
    };
    Ok(Arc::new(scanner))
}

pub(crate) struct InstalledRootProcessEffectPorts {
    pub(crate) retirement: Arc<dyn RootProvisionProcessRetirementPort>,
    pub(crate) global: Arc<dyn RootProvisionProcessGlobalPort>,
    pub(crate) serving: Arc<dyn ServingBlockdProcessGlobalPort>,
    pub(crate) vmm: Arc<dyn VmmProcessGlobalPort>,
    pub(crate) vmm_cid: Arc<dyn VmmCidInventoryPort>,
    #[cfg(target_os = "linux")]
    pub(crate) stale_boot_vmm: InstalledStaleBootVmmRecoveryPorts,
}

#[cfg(target_os = "linux")]
#[derive(Clone)]
pub(crate) struct InstalledStaleBootVmmRecoveryPorts {
    pub(crate) global: Arc<dyn StaleBootVmmProcessGlobalPort>,
    pub(crate) socket_root: Arc<RetainedManagedVmmSocketRoot>,
    pub(crate) launch_root: Arc<RetainedManagedVmmLaunchRoot>,
    pub(crate) receipts: Arc<VmmSocketReceiptStore>,
}

pub(crate) fn installed_root_process_effect_ports(
    config: InstalledCleanSlateProbeConfig,
) -> anyhow::Result<InstalledRootProcessEffectPorts> {
    let config = ProbeConfig::installed(config)?;
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
    let bridge = platform_root_process_inventory_bridge(&config, process_paths)?;
    #[cfg(target_os = "linux")]
    let stale_boot_vmm = InstalledStaleBootVmmRecoveryPorts {
        global: Arc::clone(&bridge) as Arc<dyn StaleBootVmmProcessGlobalPort>,
        socket_root: config
            .managed_vmm_socket_root
            .clone()
            .context("installed bridge lacks the retained VMM socket root")?,
        launch_root: config
            .managed_vmm_launch_root
            .clone()
            .context("installed bridge lacks the retained VMM launch root")?,
        receipts: config
            .vmm_socket_receipts
            .clone()
            .context("installed bridge lacks the retained VMM receipt store")?,
    };
    Ok(InstalledRootProcessEffectPorts {
        retirement: Arc::clone(&bridge) as Arc<dyn RootProvisionProcessRetirementPort>,
        global: Arc::clone(&bridge) as Arc<dyn RootProvisionProcessGlobalPort>,
        serving: Arc::clone(&bridge) as Arc<dyn ServingBlockdProcessGlobalPort>,
        vmm: Arc::clone(&bridge) as Arc<dyn VmmProcessGlobalPort>,
        vmm_cid: bridge as Arc<dyn VmmCidInventoryPort>,
        #[cfg(target_os = "linux")]
        stale_boot_vmm,
    })
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
            serving_process_port: None,
            root_provision_systemd: None,
            network_allocation_port: None,
            kernel_nbd_inventory_port: None,
            managed_blockd_socket_root: None,
            blockd_socket_intents: None,
            managed_vmm_socket_root: None,
            #[cfg(target_os = "linux")]
            managed_vmm_launch_root: None,
            vmm_socket_receipts: None,
            recovery_metadata_authority: None,
            recovery_blob_store: None,
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
    let network_bridge = config.network_allocation_port.clone();
    let kernel_nbd_port = config.kernel_nbd_inventory_port.clone();
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
            block_class_root: config.block_class_root.clone(),
            legacy_socket_root: config.legacy_socket_root.clone(),
            supported: config.linux_sources_supported,
            managed_kernel_nbd_device_count: kernel_nbd_port
                .as_ref()
                .map(KernelNbdInventoryPort::device_count),
            limits: config.limits,
        }),
        Arc::new(NetworkProbe {
            state_directory: state.clone(),
            network_class_root: config.network_class_root.clone(),
            supported: config.linux_sources_supported,
            physical_inventory_owned_by_bridge: network_bridge.is_some(),
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
                root: config.proc_root.clone(),
                binaries: vec![config.guest_agent_binary.clone()],
                supported: config.linux_sources_supported,
                limits: config.limits,
            },
            limits: config.limits,
        }),
    ];
    let scanner = match blob_store {
        Some(blob_store) if config.root_process_port.is_some() => {
            let bridge = platform_root_process_inventory_bridge(&config, process_paths)?;
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
    .map_err(anyhow::Error::from)?;
    let scanner = match network_bridge {
        Some(bridge) => scanner.with_network_bridge(Arc::new(bridge)),
        None => scanner,
    };
    Ok(match kernel_nbd_port {
        Some(port) => scanner.with_kernel_nbd_pool(port),
        None => scanner,
    })
}

fn platform_root_process_inventory_bridge(
    config: &ProbeConfig,
    process_paths: ProcessPaths,
) -> anyhow::Result<Arc<PlatformRootProcessInventoryBridge>> {
    let executable_path = HostPath::new(config.blockd_binary.to_string_lossy().into_owned())
        .context("installed blockd binary is not a canonical HostPath")?;
    #[cfg(test)]
    let serving_port = config.serving_process_port.clone().unwrap_or_else(|| {
        Arc::new(TestAbsentServingProcessPort) as Arc<dyn ServingBlockdProcessPort>
    });
    #[cfg(not(test))]
    let serving_port = Arc::clone(
        config
            .serving_process_port
            .as_ref()
            .context("installed bridge lacks its exact serving-process port")?,
    );
    #[cfg(test)]
    let root_provision_systemd = config
        .root_provision_systemd
        .clone()
        .unwrap_or_else(|| test_systemd_config_for_path(&config.blockd_binary));
    #[cfg(not(test))]
    let root_provision_systemd = config
        .root_provision_systemd
        .clone()
        .context("installed bridge lacks validated systemd configuration")?;
    Ok(Arc::new(PlatformRootProcessInventoryBridge {
        port: Arc::clone(
            config
                .root_process_port
                .as_ref()
                .context("installed root-process bridge lacks its exact process port")?,
        ),
        serving_port,
        vmm_port: Arc::new(PlatformSystemdVmmProcessPort),
        root_provision_systemd,
        executable_path,
        state_directory: config.state_directory.clone(),
        process_paths,
        systemd_root: config.systemd_cgroup_root.clone(),
        metering_root: config.metering_cgroup_root.clone(),
        legacy_socket_root: config.legacy_socket_root.clone(),
        limits: config.limits,
        managed_blockd_socket_root: config.managed_blockd_socket_root.clone(),
        blockd_socket_intents: config.blockd_socket_intents.clone(),
        managed_vmm_socket_root: config.managed_vmm_socket_root.clone(),
        #[cfg(target_os = "linux")]
        managed_vmm_launch_root: config.managed_vmm_launch_root.clone(),
        vmm_socket_receipts: config.vmm_socket_receipts.clone(),
        recovery_metadata_authority: config.recovery_metadata_authority.clone(),
        recovery_blob_store: config.recovery_blob_store.clone(),
    }))
}

#[cfg(test)]
struct TestAbsentServingProcessPort;

#[cfg(test)]
impl serving_process_sealed::Sealed for TestAbsentServingProcessPort {}

#[cfg(test)]
impl ServingBlockdProcessPort for TestAbsentServingProcessPort {
    fn inspect(
        &self,
        _expected: &ServingBlockdExpectation,
        _context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ServingBlockdProcessInspection> {
        Ok(ServingBlockdProcessInspection::Absent)
    }

    fn start_checkpointed(
        &self,
        _checkpointed: super::serving_blockd_process::CheckpointedServingBlockdProcess<'_>,
        _context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<super::serving_blockd_process::ServingBlockdProcessStart> {
        unreachable!("inventory test port is read-only")
    }
}

#[cfg(test)]
fn test_systemd_config_for_path(blockd_binary: &Path) -> RootProvisionSystemdConfig {
    RootProvisionSystemdConfig::new(super::AuthorizedBlockdLaunchConfig {
        blockd_binary: blockd_binary.to_path_buf(),
        metadata_store: cats_storage::AdapterSelection::new(
            "postgres",
            cats_storage::AdapterConfig::from_pairs([("url-file", "/run/cats/postgres.url")])
                .unwrap(),
        ),
        object_store: cats_storage::AdapterSelection::new(
            "aws-s3",
            cats_storage::AdapterConfig::from_pairs([("bucket", "cats-test")]).unwrap(),
        ),
        max_staged_bytes: 1,
        max_staged_packs: 1,
        max_local_bytes: 4_194_304,
    })
    .unwrap()
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
        && data.evidence_count() + data.handoff_temps.len() == data.leaf_count
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
    if !data.recoverable_stop_receipts.is_empty() || !data.stable_stop_receipts.is_empty() {
        if data.evidence_count() != data.leaf_count {
            return Ok(LocalPublicationRecoveryEvidence::None);
        }
        return Ok(next_stop_receipt_recovery(
            &data.stable_stop_receipts,
            &data.recoverable_stop_receipts,
        )
        .expect("nonempty stop receipt evidence has one recovery candidate"));
    }
    let mut authorized_recovery = BTreeSet::new();
    let mut takeover_publications = BTreeSet::new();
    for desired in &context.coordinates().desired.desired_specs {
        let Some(checkpoint) = checkpoints.get(&desired.cat_id) else {
            continue;
        };
        let ReconcileStep::AcquireVolume { request } = &checkpoint.step else {
            continue;
        };
        let mut targets = desired
            .volumes
            .iter()
            .filter(|volume| request_matches_volume(request, desired, volume));
        let Some(target) = targets.next() else {
            continue;
        };
        if targets.next().is_some() {
            continue;
        }
        let expected_prepared = checkpoint
            .volumes
            .iter()
            .filter(|volume| !volume.local_lineages.is_empty())
            .map(|volume| volume.volume_id.clone())
            .collect::<BTreeSet<_>>();
        let actual_for_cat = data.evidence.get(&desired.cat_id);
        let actual_prepared = actual_for_cat
            .map(|volumes| volumes.keys().cloned().collect::<BTreeSet<_>>())
            .unwrap_or_default();
        let prepared_values_are_exact = expected_prepared.iter().all(|volume_id| {
            actual_for_cat
                .and_then(|volumes| volumes.get(volume_id))
                .is_some_and(|blockd| checkpoint_prepared_volume_matches_blockd(checkpoint, blockd))
        });
        if !prepared_values_are_exact
            || !data.recovery_incompleteness_is_scoped_to(checkpoint, target)
        {
            continue;
        }
        if !actual_prepared.contains(&target.volume_id) && actual_prepared == expected_prepared {
            authorized_recovery.insert(desired.cat_id.clone());
            continue;
        }
        if matches!(
            request,
            cats_api::runtime_reconciliation::VolumeAcquireRequest::Takeover { .. }
        ) && !expected_prepared.contains(&target.volume_id)
        {
            let mut exact_publication = expected_prepared;
            exact_publication.insert(target.volume_id.clone());
            if actual_prepared == exact_publication {
                takeover_publications.insert(desired.cat_id.clone());
            }
        }
    }
    if let Some(cat_id) = authorized_recovery.into_iter().next() {
        return Ok(LocalPublicationRecoveryEvidence::AuthorizedBlockd { cat_id });
    }
    if let Some(cat_id) = takeover_publications.into_iter().next() {
        return Ok(
            LocalPublicationRecoveryEvidence::AuthorizedBlockdTakeoverPublication { cat_id },
        );
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
    evidence: BTreeMap<Id, BTreeMap<Id, AuthorizedBlockdInventoryEvidence>>,
    candidate_volume_ids: BTreeSet<Id>,
    observed_volume_paths: BTreeSet<(Id, Id)>,
    recoverable_publication_prefixes: BTreeSet<RecoverableAuthorizedBlockdPrefix>,
    unattributed_incomplete: bool,
    leaf_count: usize,
    complete: bool,
    handoff_temps: Vec<(Id, ServingHandoffTempKind, AuthorizedBlockdCheckpoint)>,
    stable_stop_receipts: Vec<Id>,
    recoverable_stop_receipts: Vec<Id>,
}

impl AuthorizedBlockdDataScan {
    fn evidence_count(&self) -> usize {
        self.evidence.values().map(BTreeMap::len).sum()
    }

    fn recovery_incompleteness_is_scoped_to(
        &self,
        checkpoint: &RuntimeCheckpoint,
        target: &VolumeIntent,
    ) -> bool {
        if self.complete {
            return true;
        }
        let Some(observed) = checkpoint
            .volumes
            .iter()
            .find(|volume| volume.volume_id == target.volume_id)
        else {
            return false;
        };
        let predecessor_epoch = match observed.authority {
            VolumeAuthorityEvidence::Unowned {
                attachment_epoch, ..
            }
            | VolumeAuthorityEvidence::Owned {
                attachment_epoch, ..
            } => attachment_epoch,
            _ => return false,
        };
        let Some(expected_epoch) = predecessor_epoch.get().checked_add(1) else {
            return false;
        };
        let target_path = (checkpoint.cat_id.clone(), target.volume_id.clone());
        let prefix_is_exact = self.recoverable_publication_prefixes.len() == 1
            && self
                .recoverable_publication_prefixes
                .iter()
                .next()
                .is_some_and(|prefix| match prefix {
                    RecoverableAuthorizedBlockdPrefix::Cat { cat_id } => {
                        cat_id == &checkpoint.cat_id
                    }
                    RecoverableAuthorizedBlockdPrefix::Volume { cat_id, volume_id } => {
                        (cat_id, volume_id) == (&checkpoint.cat_id, &target.volume_id)
                    }
                    RecoverableAuthorizedBlockdPrefix::Attachment {
                        cat_id,
                        volume_id,
                        attachment_name,
                    } => {
                        (cat_id, volume_id) == (&checkpoint.cat_id, &target.volume_id)
                            && attachment_name == &format!("attachment-{}", target.attachment_id)
                    }
                    RecoverableAuthorizedBlockdPrefix::Epoch {
                        cat_id,
                        volume_id,
                        attachment_name,
                        epoch_name,
                    } => {
                        (cat_id, volume_id) == (&checkpoint.cat_id, &target.volume_id)
                            && attachment_name == &format!("attachment-{}", target.attachment_id)
                            && epoch_name == &format!("epoch-{expected_epoch}")
                    }
                });
        if self.unattributed_incomplete || !prefix_is_exact {
            return false;
        }
        self.observed_volume_paths.iter().all(|observed| {
            observed == &target_path
                || self
                    .evidence
                    .get(&observed.0)
                    .is_some_and(|volumes| volumes.contains_key(&observed.1))
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
enum RecoverableAuthorizedBlockdPrefix {
    Cat {
        cat_id: Id,
    },
    Volume {
        cat_id: Id,
        volume_id: Id,
    },
    Attachment {
        cat_id: Id,
        volume_id: Id,
        attachment_name: String,
    },
    Epoch {
        cat_id: Id,
        volume_id: Id,
        attachment_name: String,
        epoch_name: String,
    },
}

/// One immutable checkpoint-namespace join for the whole data-directory
/// scan. Re-enumerating this namespace once per Cat is both racy and
/// quadratic; this index validates every name and target exactly once, then
/// all handoff leaves use an in-memory Cat lookup from the same snapshot.
pub(crate) struct RuntimeCheckpointNamespaceSnapshot {
    directory: File,
    checkpoints: BTreeMap<Id, RuntimeCheckpoint>,
    // The coordinate is consumed only by Linux's restart-only VMM recovery.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    coordinate: RuntimeCheckpointNamespaceCoordinate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RuntimeCheckpointNamespaceCoordinate {
    directory: StrictFilesystemCoordinate,
    entries: BTreeMap<OsString, StrictFilesystemCoordinate>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StrictFilesystemCoordinate {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    user: u32,
    group: u32,
    length: u64,
}

impl StrictFilesystemCoordinate {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            mode: metadata.mode(),
            links: metadata.nlink(),
            user: metadata.uid(),
            group: metadata.gid(),
            length: metadata.len(),
        }
    }

    fn from_stat(metadata: &libc::stat) -> anyhow::Result<Self> {
        Ok(Self {
            device: raw_device_to_u64(metadata.st_dev)
                .context("checkpoint namespace entry has an invalid device")?,
            inode: metadata.st_ino,
            mode: u32::try_from(u64::from(metadata.st_mode))
                .context("checkpoint namespace entry has an invalid mode")?,
            links: raw_link_count_to_u64(metadata.st_nlink),
            user: metadata.st_uid,
            group: metadata.st_gid,
            length: u64::try_from(metadata.st_size)
                .context("checkpoint namespace entry has a negative length")?,
        })
    }
}

/// Stable, complete checkpoint collection admitted only for restart-only VMM
/// receipt recovery.  The private namespace coordinate prevents a provider
/// from presenting a hand-picked checkpoint subset as the Node-wide set.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(target_os = "linux")]
pub(crate) struct RuntimeCheckpointRecoverySet {
    checkpoints: BTreeMap<Id, RuntimeCheckpoint>,
    bindings: BTreeMap<Id, DesiredCheckpointBinding>,
    coordinate: RuntimeCheckpointNamespaceCoordinate,
}

#[cfg(target_os = "linux")]
impl RuntimeCheckpointRecoverySet {
    pub(crate) fn iter_checkpoints(&self) -> impl ExactSizeIterator<Item = &RuntimeCheckpoint> {
        self.checkpoints.values()
    }

    pub(crate) fn checkpoint(&self, cat_id: &Id) -> Option<&RuntimeCheckpoint> {
        self.checkpoints.get(cat_id)
    }

    fn binding(&self, cat_id: &Id) -> Option<DesiredCheckpointBinding> {
        self.bindings.get(cat_id).copied()
    }
}

impl RuntimeCheckpointNamespaceSnapshot {
    /// Every durable Runtime checkpoint from one complete, strictly validated
    /// checkpoint-namespace enumeration. Callers cannot construct this proof
    /// from a partial or per-Cat lookup.
    pub(crate) fn iter_checkpoints(&self) -> impl ExactSizeIterator<Item = &RuntimeCheckpoint> {
        self.checkpoints.values()
    }

    pub(crate) fn checkpoint(&self, cat_id: &Id) -> Option<&RuntimeCheckpoint> {
        self.checkpoints.get(cat_id)
    }

    pub(crate) fn retained_directory(&self) -> &File {
        &self.directory
    }

    fn get(&self, cat_id: &Id) -> Option<&RuntimeCheckpoint> {
        self.checkpoint(cat_id)
    }
}

pub(crate) fn snapshot_runtime_checkpoint_namespace(
    root: &File,
    context: &dyn RuntimePhysicalReadContext,
    assigned_cats: &RuntimeAssignedCatSet,
    limit: usize,
) -> anyhow::Result<Option<RuntimeCheckpointNamespaceSnapshot>> {
    let directory = match open_state_namespace(root, CHECKPOINT_NAMESPACE)? {
        ManagedDirectory::Open(directory) => directory,
        ManagedDirectory::Missing | ManagedDirectory::Unavailable => return Ok(None),
    };
    let mut budget = limit;
    let Some(entries) = strict_checkpoint_directory_entries(&directory, &mut budget, context)?
    else {
        return Ok(None);
    };
    let coordinate = RuntimeCheckpointNamespaceCoordinate {
        directory: StrictFilesystemCoordinate::from_metadata(&directory.metadata()?),
        entries: entries
            .iter()
            .map(|entry| {
                Ok((
                    entry.name.clone(),
                    StrictFilesystemCoordinate::from_stat(&entry.metadata)?,
                ))
            })
            .collect::<anyhow::Result<BTreeMap<_, _>>>()?,
    };
    let desired_by_target = assigned_cats
        .iter()
        .map(|cat_id| (format!("cat-{cat_id}.checkpoint.json"), cat_id))
        .collect::<BTreeMap<_, _>>();
    let desired_locks = assigned_cats
        .iter()
        .map(|cat_id| format!("cat-{cat_id}.checkpoint.lock"))
        .collect::<BTreeSet<_>>();
    let desired_checkpoint_temps = assigned_cats
        .iter()
        .map(|cat_id| format!(".cat-{cat_id}.checkpoint.tmp"))
        .collect::<BTreeSet<_>>();
    let desired_by_release_rejection = assigned_cats
        .iter()
        .map(|cat_id| (format!("cat-{cat_id}.release-rejection.json"), cat_id))
        .collect::<BTreeMap<_, _>>();
    let desired_by_release_rejection_temp = assigned_cats
        .iter()
        .map(|cat_id| (format!(".cat-{cat_id}.release-rejection.tmp"), cat_id))
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
        if let Some(cat_id) = desired_by_release_rejection.get(name) {
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
                &marker.cat_id == *cat_id,
                "handoff index release rejection filename and Cat identity disagree"
            );
            anyhow::ensure!(
                release_rejections
                    .insert((*cat_id).clone(), (marker, diagnostic_path))
                    .is_none(),
                "handoff index contains duplicate release rejections for one Cat"
            );
            continue;
        }
        let Some(cat_id) = desired_by_target.get(name) else {
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
            &checkpoint.cat_id == *cat_id,
            "handoff index checkpoint filename and Cat identity disagree"
        );
        anyhow::ensure!(
            checkpoints.insert((*cat_id).clone(), checkpoint).is_none(),
            "handoff index contains duplicate Runtime checkpoints for one Cat"
        );
    }
    for (cat_id, (marker, path)) in release_rejections {
        let checkpoint = checkpoints
            .get(&cat_id)
            .context("handoff index release rejection lacks its Runtime checkpoint")?;
        validate_definite_release_rejection(&marker, checkpoint, &path)?;
    }
    let snapshot = RuntimeCheckpointNamespaceSnapshot {
        directory,
        checkpoints,
        coordinate,
    };
    anyhow::ensure!(
        snapshot.iter_checkpoints().len() <= RUNTIME_V1_MAX_ASSIGNED_CATS,
        "handoff checkpoint index exceeds the assigned-Cat cap"
    );
    Ok(Some(snapshot))
}

/// Classify the complete checkpoint namespace twice before a stale-boot
/// receipt is selected. Every present checkpoint must be either exact-current
/// or a structurally exact retained phase which is legally superseded by the
/// current same-Node Desired. Corrupt, foreign, incomplete, conflicting or
/// racing namespaces yield no recovery authority.
#[cfg(target_os = "linux")]
pub(crate) fn runtime_checkpoint_recovery_set(
    context: &RuntimePreScanRecoveryContext,
    socket_root: &RetainedManagedVmmSocketRoot,
) -> anyhow::Result<Option<RuntimeCheckpointRecoverySet>> {
    context.check_active()?;
    let scan_context = context.inventory_context();
    let assigned = scan_context.assigned_cats()?;
    let Some(root) = clone_state_root(context.state_directory())? else {
        return Ok(None);
    };
    let Some(first) = snapshot_runtime_checkpoint_namespace(
        &root,
        &scan_context,
        &assigned,
        RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
    )?
    else {
        return Ok(None);
    };
    let Some(first_bindings) =
        checkpoint_set_recovery_bindings(&first.checkpoints, context, socket_root)
    else {
        return Ok(None);
    };
    let Some(second) = snapshot_runtime_checkpoint_namespace(
        &root,
        &scan_context,
        &assigned,
        RUNTIME_CHECKPOINT_NAMESPACE_ENTRY_LIMIT,
    )?
    else {
        return Ok(None);
    };
    let Some(second_bindings) =
        checkpoint_set_recovery_bindings(&second.checkpoints, context, socket_root)
    else {
        return Ok(None);
    };
    if first.coordinate != second.coordinate
        || first.checkpoints != second.checkpoints
        || first_bindings != second_bindings
    {
        return Ok(None);
    }
    context.check_active()?;
    Ok(Some(RuntimeCheckpointRecoverySet {
        checkpoints: second.checkpoints,
        bindings: second_bindings,
        coordinate: second.coordinate,
    }))
}

#[cfg(target_os = "linux")]
fn checkpoint_set_recovery_bindings(
    checkpoints: &BTreeMap<Id, RuntimeCheckpoint>,
    context: &RuntimePreScanRecoveryContext,
    socket_root: &RetainedManagedVmmSocketRoot,
) -> Option<BTreeMap<Id, DesiredCheckpointBinding>> {
    let desired = context
        .coordinates()
        .desired
        .desired_specs
        .iter()
        .map(|desired| (&desired.cat_id, desired))
        .collect::<BTreeMap<_, _>>();
    checkpoints
        .iter()
        .map(|(cat_id, checkpoint)| {
            let desired = *desired.get(cat_id)?;
            let binding = checkpoint_binding(desired, checkpoint).ok()?;
            super::inventory::validate_checkpoint_recovery_structure(
                desired,
                checkpoint,
                binding,
                context.state_directory(),
                socket_root.planner(),
            )
            .ok()?;
            Some((cat_id.clone(), binding))
        })
        .collect()
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
                observed_volume_paths: BTreeSet::new(),
                recoverable_publication_prefixes: BTreeSet::new(),
                unattributed_incomplete: false,
                leaf_count: 0,
                complete: true,
                handoff_temps: Vec::new(),
                stable_stop_receipts: Vec::new(),
                recoverable_stop_receipts: Vec::new(),
            })
        }
        ManagedDirectory::Unavailable => {
            return Ok(AuthorizedBlockdDataScan {
                evidence: BTreeMap::new(),
                candidate_volume_ids: BTreeSet::new(),
                observed_volume_paths: BTreeSet::new(),
                recoverable_publication_prefixes: BTreeSet::new(),
                unattributed_incomplete: true,
                leaf_count: 0,
                complete: false,
                handoff_temps: Vec::new(),
                stable_stop_receipts: Vec::new(),
                recoverable_stop_receipts: Vec::new(),
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
    let assigned_cats = context.assigned_cats()?;
    let checkpoint_snapshot =
        snapshot_runtime_checkpoint_namespace(root, context, &assigned_cats, limits.state_entries)?;
    let mut budget = limits.state_entries;
    let Some(cat_entries) = strict_directory_entries(&directory, &mut budget, context)? else {
        return Ok(AuthorizedBlockdDataScan {
            evidence: BTreeMap::new(),
            candidate_volume_ids: BTreeSet::new(),
            observed_volume_paths: BTreeSet::new(),
            recoverable_publication_prefixes: BTreeSet::new(),
            unattributed_incomplete: true,
            leaf_count: 0,
            complete: false,
            handoff_temps: Vec::new(),
            stable_stop_receipts: Vec::new(),
            recoverable_stop_receipts: Vec::new(),
        });
    };
    let mut scan = AuthorizedBlockdDataScan {
        evidence: BTreeMap::new(),
        candidate_volume_ids: BTreeSet::new(),
        observed_volume_paths: BTreeSet::new(),
        recoverable_publication_prefixes: BTreeSet::new(),
        unattributed_incomplete: false,
        leaf_count: 0,
        complete: true,
        handoff_temps: Vec::new(),
        stable_stop_receipts: Vec::new(),
        recoverable_stop_receipts: Vec::new(),
    };

    for cat_entry in cat_entries {
        let Some(cat_name) = cat_entry.name.to_str() else {
            bail!("authorized blockd data namespace contains non-UTF-8 Cat entry")
        };
        let Some(desired) = desired_by_directory.get(cat_name) else {
            bail!("authorized blockd data namespace retains foreign Cat {cat_name}")
        };
        let Some(cat_directory) =
            open_exact_only_child_directory(&directory, &cat_entry, root, context)?
        else {
            scan.complete = false;
            scan.unattributed_incomplete = true;
            continue;
        };
        let Some(volume_entries) = strict_directory_entries(&cat_directory, &mut budget, context)?
        else {
            scan.complete = false;
            scan.unattributed_incomplete = true;
            continue;
        };
        if volume_entries.is_empty() {
            scan.complete = false;
            scan.recoverable_publication_prefixes
                .insert(RecoverableAuthorizedBlockdPrefix::Cat {
                    cat_id: desired.cat_id.clone(),
                });
            continue;
        }
        for volume_entry in volume_entries {
            scan.leaf_count += 1;
            let volume_name = volume_entry
                .name
                .to_str()
                .context("authorized blockd volume path is not UTF-8")?
                .to_owned();
            let scanned_volume_id = desired
                .volumes
                .iter()
                .find(|volume| volume_name == format!("volume-{}", volume.volume_id))
                .map(|volume| volume.volume_id.clone());
            if let Some(volume_id) = &scanned_volume_id {
                scan.observed_volume_paths
                    .insert((desired.cat_id.clone(), volume_id.clone()));
            } else {
                scan.unattributed_incomplete = true;
            }
            let Some(volume_directory) =
                open_strict_child_directory(&cat_directory, &volume_entry, root)?
            else {
                scan.complete = false;
                continue;
            };
            let (attachment_name, attachment_directory) = match descend_only_directory(
                &volume_directory,
                root,
                &mut budget,
                context,
                "attachment",
            )? {
                OnlyDirectoryDescent::Open { name, directory } => (name, directory),
                OnlyDirectoryDescent::Empty => {
                    scan.complete = false;
                    if let Some(volume_id) = &scanned_volume_id {
                        scan.recoverable_publication_prefixes.insert(
                            RecoverableAuthorizedBlockdPrefix::Volume {
                                cat_id: desired.cat_id.clone(),
                                volume_id: volume_id.clone(),
                            },
                        );
                    }
                    continue;
                }
                OnlyDirectoryDescent::Unavailable => {
                    scan.complete = false;
                    continue;
                }
            };
            let (epoch_name, epoch_directory) = match descend_only_directory(
                &attachment_directory,
                root,
                &mut budget,
                context,
                "epoch",
            )? {
                OnlyDirectoryDescent::Open { name, directory } => (name, directory),
                OnlyDirectoryDescent::Empty => {
                    scan.complete = false;
                    if let Some(volume_id) = &scanned_volume_id {
                        scan.recoverable_publication_prefixes.insert(
                            RecoverableAuthorizedBlockdPrefix::Attachment {
                                cat_id: desired.cat_id.clone(),
                                volume_id: volume_id.clone(),
                                attachment_name: attachment_name.clone(),
                            },
                        );
                    }
                    continue;
                }
                OnlyDirectoryDescent::Unavailable => {
                    scan.complete = false;
                    continue;
                }
            };
            let Some(leaf_entries) =
                strict_directory_entries(&epoch_directory, &mut budget, context)?
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
                ROOT_PROVISION_STOP_RECEIPT_FILE,
                ROOT_PROVISION_STOP_RECEIPT_TEMP,
                "cache.data",
                ".cache.data.init",
                "dirty.bitmap",
                ".dirty.bitmap.init",
                PENDING_PACK_DIR,
            ];
            if let Some(foreign) = by_name.keys().find(|name| {
                !allowed.contains(&name.as_str()) && !is_serving_handoff_artifact_name(name)
            }) {
                bail!("authorized blockd leaf retains foreign entry {foreign}")
            }
            let recoverable_publication_window = matches!(
                (
                    by_name.contains_key(IDENTITY_FILE),
                    by_name.contains_key(IDENTITY_TEMP),
                    by_name.contains_key(AUTHORIZED_SERVING_FILE),
                    by_name.contains_key(AUTHORIZED_SERVING_TEMP),
                    by_name.contains_key(LAUNCH_CHECKPOINT_FILE),
                    by_name.contains_key(LAUNCH_CHECKPOINT_TEMP),
                    by_name.len(),
                ),
                (false, false, false, false, false, false, 0)
                    | (false, true, false, false, false, false, 1)
                    | (true, false, false, false, false, false, 1)
                    | (true, false, false, true, false, false, 2)
                    | (true, false, true, false, false, false, 2)
                    | (true, false, true, false, false, true, 3)
            );
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
                if recoverable_publication_window {
                    if let Some(volume_id) = &scanned_volume_id {
                        scan.recoverable_publication_prefixes.insert(
                            RecoverableAuthorizedBlockdPrefix::Epoch {
                                cat_id: desired.cat_id.clone(),
                                volume_id: volume_id.clone(),
                                attachment_name: attachment_name.clone(),
                                epoch_name: epoch_name.clone(),
                            },
                        );
                    } else {
                        scan.unattributed_incomplete = true;
                    }
                }
                continue;
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
            let stop_target = if let Some(entry) = by_name.get(ROOT_PROVISION_STOP_RECEIPT_FILE) {
                read_strict_regular_at(
                    &epoch_directory,
                    entry,
                    root,
                    ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES,
                    context,
                )?
            } else {
                None
            };
            let stop_temp = if let Some(entry) = by_name.get(ROOT_PROVISION_STOP_RECEIPT_TEMP) {
                read_strict_regular_at(
                    &epoch_directory,
                    entry,
                    root,
                    ROOT_PROVISION_STOP_RECEIPT_MAX_BYTES,
                    context,
                )?
            } else {
                None
            };
            if by_name.contains_key(ROOT_PROVISION_STOP_RECEIPT_FILE) && stop_target.is_none()
                || by_name.contains_key(ROOT_PROVISION_STOP_RECEIPT_TEMP) && stop_temp.is_none()
            {
                scan.complete = false;
                continue;
            }
            let mut stop_receipt_socket = None;
            if let Some(bytes) = stop_target.as_ref().or(stop_temp.as_ref()) {
                if let (Some(target), Some(temporary)) = (&stop_target, &stop_temp) {
                    anyhow::ensure!(
                        target == temporary,
                        "root-provision stop receipt target and temp conflict"
                    );
                }
                let receipt = decode_root_provision_stop_receipt(bytes)?;
                let Some(runtime_checkpoint) = checkpoint_snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.get(&desired.cat_id))
                else {
                    scan.complete = false;
                    continue;
                };
                anyhow::ensure!(
                checkpoint_content_digest(runtime_checkpoint)?
                    == *receipt.checkpoint_content_digest()
                    && runtime_checkpoint.cat_id == desired.cat_id
                    && !has_unvalidated_handoff_artifact,
                "root-provision stop receipt conflicts with its checkpoint, launch grant, or handoff"
            );
                receipt.binds_authorized_checkpoint(&checkpoint)?;
                stop_receipt_socket = Some(StopReceiptSocketAdmission::from_managed(
                    receipt.socket_owner().clone(),
                ));
                if stop_temp.is_some() {
                    scan.recoverable_stop_receipts.push(desired.cat_id.clone());
                    scan.complete = false;
                } else {
                    scan.stable_stop_receipts.push(desired.cat_id.clone());
                }
            }
            let control_files = ["cache.data", "dirty.bitmap", PENDING_PACK_DIR];
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
                let Some(pending) = open_strict_child_directory(
                    &epoch_directory,
                    &by_name[PENDING_PACK_DIR],
                    root,
                )?
                else {
                    scan.complete = false;
                    continue;
                };
                let Some(pending_entries) =
                    strict_directory_entries(&pending, &mut budget, context)?
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
            let mut target_control_launch = None;
            if !has_unvalidated_handoff_artifact {
                if let Some(runtime_checkpoint) = checkpoint_snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.get(&desired.cat_id))
                {
                    if matches!(
                        runtime_checkpoint.step,
                        ReconcileStep::PrepareDevice { .. }
                            | ReconcileStep::PrepareNetwork { .. }
                            | ReconcileStep::StartRuntime { .. }
                    ) || runtime_checkpoint.runtime_launch.identity().is_some()
                    {
                        let prepared = prepared_device_inputs(runtime_checkpoint)?
                        .into_iter()
                        .find(|device| device.volume_id == identity.volume_id)
                        .context(
                            "authorized blockd lineage lacks its prepared-device checkpoint entry",
                        )?;
                        anyhow::ensure!(
                        !matches!(
                            prepared.serving_authority.as_ref(),
                            cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
                        ),
                        "after-root-provision checkpoint lacks its durable handoff artifacts"
                    );
                    }
                }
            }
            if has_unvalidated_handoff_artifact {
                let Some(runtime_checkpoint) = checkpoint_snapshot
                    .as_ref()
                    .and_then(|snapshot| snapshot.get(&desired.cat_id))
                    .cloned()
                else {
                    scan.complete = false;
                    continue;
                };
                let prepared_checkpoint;
                let handoff_checkpoint =
                    if matches!(
                        runtime_checkpoint.step,
                        ReconcileStep::PrepareNetwork { .. } | ReconcileStep::StartRuntime { .. }
                    ) || runtime_checkpoint.runtime_launch.identity().is_some()
                    {
                        prepared_checkpoint = prepare_device_checkpoint_view(&runtime_checkpoint)?;
                        &prepared_checkpoint
                    } else {
                        &runtime_checkpoint
                    };
                let provision_transition_id = match &handoff_checkpoint.step {
                ReconcileStep::ProvisionRootImage {
                    provision_transition_id,
                    ..
                } => provision_transition_id.clone(),
                ReconcileStep::PrepareDevice { devices } => {
                    let mut roots = devices.iter().filter(|device| matches!(
                        device.serving_authority.as_ref(),
                        cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision { .. }
                    ));
                    let root_device = roots.next().context(
                        "PrepareDevice handoff artifacts lack their Root device",
                    )?;
                    anyhow::ensure!(
                        roots.next().is_none(),
                        "PrepareDevice handoff artifacts have duplicate Root devices"
                    );
                    let cats_api::runtime_reconciliation::ServingAuthorityProvenance::AfterRootProvision {
                        handoff,
                    } = root_device.serving_authority.as_ref()
                    else {
                        unreachable!("root filter selected after-root-provision authority")
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
                    "serving handoff artifacts require provision_root_image or an after-root-provision prepared-device phase"
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
                            scan.handoff_temps.push((
                                desired.cat_id.clone(),
                                kind,
                                checkpoint.clone(),
                            ));
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
                target_control_launch = Some(scanned_target_control_process_launch(
                    &runtime_checkpoint,
                    &checkpoint,
                    &target,
                )?);
            }
            scan.candidate_volume_ids.insert(identity.volume_id.clone());
            anyhow::ensure!(
                scan.evidence
                    .entry(desired.cat_id.clone())
                    .or_default()
                    .insert(
                        identity.volume_id.clone(),
                        AuthorizedBlockdInventoryEvidence {
                            data_directory,
                            checkpoint,
                            binding,
                            control_state,
                            retained_root_process,
                            target_control_launch,
                            stop_receipt_socket,
                        },
                    )
                    .is_none(),
                "authorized blockd inventory duplicated one Cat/Volume"
            );
        }
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

#[cfg(target_os = "linux")]
fn raw_device_to_u64(device: libc::dev_t) -> Option<u64> {
    Some(device)
}

#[cfg(not(target_os = "linux"))]
fn raw_device_to_u64(device: libc::dev_t) -> Option<u64> {
    u64::try_from(device).ok()
}

#[cfg(target_os = "linux")]
fn raw_link_count_to_u64(links: libc::nlink_t) -> u64 {
    links
}

#[cfg(not(target_os = "linux"))]
fn raw_link_count_to_u64(links: libc::nlink_t) -> u64 {
    u64::from(links)
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
    let device = raw_device_to_u64(entry.metadata.st_dev)
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

enum OnlyDirectoryDescent {
    Empty,
    Unavailable,
    Open { name: String, directory: File },
}

fn descend_only_directory(
    parent: &File,
    root: &File,
    budget: &mut usize,
    context: &RuntimeInventoryScanContext,
    label: &str,
) -> anyhow::Result<OnlyDirectoryDescent> {
    let Some(entries) = strict_directory_entries(parent, budget, context)? else {
        return Ok(OnlyDirectoryDescent::Unavailable);
    };
    if entries.is_empty() {
        return Ok(OnlyDirectoryDescent::Empty);
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
        return Ok(OnlyDirectoryDescent::Unavailable);
    };
    Ok(OnlyDirectoryDescent::Open { name, directory })
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
    serving_port: Arc<dyn ServingBlockdProcessPort>,
    vmm_port: Arc<dyn VmmProcessPort>,
    root_provision_systemd: RootProvisionSystemdConfig,
    executable_path: HostPath,
    state_directory: StateDirectory,
    process_paths: ProcessPaths,
    systemd_root: PathBuf,
    metering_root: Option<PathBuf>,
    legacy_socket_root: PathBuf,
    limits: ProbeLimits,
    managed_blockd_socket_root: Option<Arc<RetainedManagedBlockdSocketRoot>>,
    blockd_socket_intents: Option<Arc<BlockdSocketIntentStore>>,
    managed_vmm_socket_root: Option<Arc<RetainedManagedVmmSocketRoot>>,
    #[cfg(target_os = "linux")]
    managed_vmm_launch_root: Option<Arc<RetainedManagedVmmLaunchRoot>>,
    vmm_socket_receipts: Option<Arc<VmmSocketReceiptStore>>,
    // These sidecars are reached only by Linux's restart-only VMM recovery.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    recovery_metadata_authority: Option<Arc<dyn MetadataAuthorityAbsenceReader>>,
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    recovery_blob_store: Option<Arc<dyn BlobStore>>,
}

enum AdmittedManagedProcessInspection {
    Exact {
        root: BTreeMap<Id, RootProvisionProcessInspection>,
        serving: BTreeMap<ManagedServingKey, ServingBlockdProcessInspection>,
        vmm: BTreeMap<Id, VmmProcessInspection>,
    },
    Unavailable,
    IdentityMismatch,
    DuplicateIdentity,
}

enum AdmittedRootTargetPurpose {
    Ordinary,
    StopReceipt,
}

enum ManagedBlockdStartTarget<'a> {
    Root(&'a RootProvisionProcessExpectation),
    Serving(&'a ServingBlockdExpectation),
}

fn insert_exact_blockd_intent(
    intents: &mut BTreeMap<String, BlockdSocketOwnershipIntentV1>,
    intent: BlockdSocketOwnershipIntentV1,
) -> anyhow::Result<()> {
    let key = intent.control_socket_path().as_str().to_owned();
    if let Some(existing) = intents.insert(key, intent.clone()) {
        anyhow::ensure!(
            existing == intent,
            "managed blockd admission aliases one socket to different owner authority"
        );
    }
    Ok(())
}

#[cfg(target_os = "linux")]
struct StaleBootRecoveryManagedSet {
    root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
    serving_expected: BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
    vmm_expected: BTreeMap<Id, VmmProcessExpectation>,
    stale_vmm: BTreeSet<Id>,
    receipt_snapshot: ReceiptNamespaceSnapshot,
    stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
    blockd_boot: CurrentBlockdSocketBoot,
    blockd_root: Arc<RetainedManagedBlockdSocketRoot>,
    blockd_intents: Arc<BlockdSocketIntentStore>,
    blockd_expected: Vec<BlockdSocketOwnershipIntentV1>,
    blockd_snapshot: ManagedBlockdSocketWholeRootSnapshot,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
enum StaleBootRecoveryManagedInspection {
    Exact {
        root: BTreeMap<Id, RootProvisionProcessInspection>,
        serving: BTreeMap<ManagedServingKey, ServingBlockdProcessInspection>,
        vmm: BTreeMap<Id, VmmProcessInspection>,
    },
    Unavailable,
    Conflict,
}

impl PlatformRootProcessInventoryBridge {
    fn managed_blockd_intents(
        &self,
        root_expected: &BTreeMap<Id, RootProvisionProcessExpectation>,
        serving_expected: &BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
    ) -> anyhow::Result<Vec<BlockdSocketOwnershipIntentV1>> {
        let mut intents = BTreeMap::<String, BlockdSocketOwnershipIntentV1>::new();
        for expected in root_expected.values() {
            insert_exact_blockd_intent(
                &mut intents,
                BlockdSocketOwnershipIntentV1::root(
                    root,
                    current_boot,
                    expected.provision_transition_id.clone(),
                    expected.socket_owner_authority_digest.clone(),
                )?,
            )?;
        }
        for expected in serving_expected.values() {
            insert_exact_blockd_intent(
                &mut intents,
                BlockdSocketOwnershipIntentV1::serving(
                    root,
                    current_boot,
                    expected.device_ownership_token().clone(),
                    serving_socket_owner_authority_digest(expected.prepared_device())?,
                )?,
            )?;
        }
        Ok(intents.into_values().collect())
    }

    fn managed_blockd_intents_for_admission(
        &self,
        admission: &super::root_provision_process::NodeGlobalManagedProcessAdmission,
        root: &RetainedManagedBlockdSocketRoot,
        current_boot: &CurrentBlockdSocketBoot,
        extra: BlockdSocketOwnershipIntentV1,
    ) -> anyhow::Result<Vec<BlockdSocketOwnershipIntentV1>> {
        let (root_expected, _) = admission.root_control_state();
        let (serving_expected, _) = admission.serving_blockd_state();
        let mut intents = self
            .managed_blockd_intents(&root_expected, &serving_expected, root, current_boot)?
            .into_iter()
            .map(|intent| (intent.control_socket_path().as_str().to_owned(), intent))
            .collect::<BTreeMap<_, _>>();
        insert_exact_blockd_intent(&mut intents, extra)?;
        Ok(intents.into_values().collect())
    }

    fn retain_managed_blockd_start_absence(
        &self,
        expected_intent: BlockdSocketOwnershipIntentV1,
        target: ManagedBlockdStartTarget<'_>,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
        let node_global_effect = context.lock_node_global_effect()?;
        let admission = context.node_global_process()?;
        let current_boot = CurrentBlockdSocketBoot::read()?;
        anyhow::ensure!(
            admission.node_boot_id() == current_boot.node_boot_id(),
            "accepted Node-global scan names another kernel boot"
        );
        let admitted_absent = match target {
            ManagedBlockdStartTarget::Root(expected) => admission
                .root_control(&expected.cat_id)
                .is_some_and(|(admitted, exact)| admitted == expected && exact.is_none()),
            ManagedBlockdStartTarget::Serving(expected) => admission
                .serving_blockd(expected.cat_id(), expected.volume_id())
                .is_some_and(|(admitted, exact)| admitted == expected && exact.is_none()),
        };
        anyhow::ensure!(
            admitted_absent,
            "managed blockd start target is not the exact absent accepted expectation"
        );
        let root = Arc::new(RetainedManagedBlockdSocketRoot::open_installed()?);
        let intents = Arc::new(BlockdSocketIntentStore::open_existing(
            self.state_directory.clone(),
        )?);
        let all_intents = self.managed_blockd_intents_for_admission(
            admission,
            &root,
            &current_boot,
            expected_intent.clone(),
        )?;
        let capture = root.capture_start_absence(&intents, &expected_intent, &current_boot)?;
        let before = root.capture_closed_whole_root(&intents, &all_intents)?;
        let target_paths = std::iter::once(expected_intent.control_socket_path())
            .chain(expected_intent.io_socket_path());
        if !platform_managed_blockd_listeners_absent(target_paths, context)? {
            return Ok(None);
        }
        let inspected = self.inspect_admitted_managed_processes(admission, context)?;
        let absent = match (target, inspected) {
            (
                ManagedBlockdStartTarget::Root(expected),
                AdmittedManagedProcessInspection::Exact { root, .. },
            ) => match root.get(&expected.cat_id) {
                Some(RootProvisionProcessInspection::Absent) => true,
                None => admission.root_control(&expected.cat_id).is_none(),
                Some(_) => false,
            },
            (
                ManagedBlockdStartTarget::Serving(expected),
                AdmittedManagedProcessInspection::Exact { serving, .. },
            ) => matches!(
                serving.get(&ManagedServingKey::new(
                    expected.cat_id().clone(),
                    expected.volume_id().clone(),
                )),
                Some(ServingBlockdProcessInspection::Absent)
            ),
            (_, AdmittedManagedProcessInspection::Unavailable) => return Ok(None),
            (_, AdmittedManagedProcessInspection::IdentityMismatch)
            | (_, AdmittedManagedProcessInspection::DuplicateIdentity) => {
                anyhow::bail!("Node-global managed process set changed during start absence")
            }
        };
        if !absent
            || !platform_managed_blockd_listeners_absent(
                std::iter::once(expected_intent.control_socket_path())
                    .chain(expected_intent.io_socket_path()),
                context,
            )?
        {
            return Ok(None);
        }
        let after = root.capture_closed_whole_root(&intents, &all_intents)?;
        Ok(Some(
            ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
                capture,
                before,
                after,
                &current_boot,
                node_global_effect,
            )?,
        ))
    }

    #[cfg(target_os = "linux")]
    fn stale_boot_recovery_managed_set(
        &self,
        checkpoints: &RuntimeCheckpointRecoverySet,
        context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<Option<StaleBootRecoveryManagedSet>> {
        let physical = context.inventory_context();
        let Some(root) = clone_state_root(&self.state_directory)? else {
            return Ok(None);
        };
        let checkpoints_by_cat = match scan_runtime_checkpoints(&root, &physical, self.limits)? {
            InventoryAbsence::Empty if checkpoints.iter_checkpoints().len() == 0 => BTreeMap::new(),
            InventoryAbsence::RuntimeCheckpoints(checkpoints_by_cat) => checkpoints_by_cat,
            InventoryAbsence::Empty | InventoryAbsence::Unavailable => return Ok(None),
            _ => unreachable!("checkpoint probe returned another source kind"),
        };
        if checkpoints_by_cat.len() != checkpoints.iter_checkpoints().len()
            || checkpoints_by_cat.iter().any(|(cat_id, evidence)| {
                checkpoints.checkpoint(cat_id) != Some(&evidence.checkpoint)
                    || checkpoints.binding(cat_id) != Some(evidence.binding)
            })
        {
            return Ok(None);
        }

        let data = scan_authorized_blockd_data(
            &root,
            self.state_directory.path(),
            &physical,
            self.limits,
        )?;
        if !data.complete
            || !data.handoff_temps.is_empty()
            || !data.recoverable_stop_receipts.is_empty()
        {
            return Ok(None);
        }
        let blockd_by_cat = data.evidence;
        let metadata_authority = self
            .recovery_metadata_authority
            .as_ref()
            .context("stale-boot recovery lacks complete metadata inventory authority")?;
        let volumes_by_cat = match (MetadataStoreProbe {
            state_directory: self.state_directory.clone(),
            authority: Arc::clone(metadata_authority),
            limits: self.limits,
        })
        .prove_absent(&physical)?
        {
            InventoryAbsence::Empty => BTreeMap::new(),
            InventoryAbsence::DesiredVolumes(volumes) => volumes,
            InventoryAbsence::Unavailable => return Ok(None),
            _ => unreachable!("metadata probe returned another source kind"),
        };

        for desired in &context.coordinates().desired.desired_specs {
            let Some(evidence) = checkpoints_by_cat.get(&desired.cat_id) else {
                continue;
            };
            super::inventory::validate_scanned_checkpoint(
                desired,
                &evidence.checkpoint,
                evidence.binding,
                blockd_by_cat.get(&desired.cat_id),
                &self.state_directory.path().join(CHECKPOINT_NAMESPACE),
                self.recovery_blob_store.as_deref(),
                physical.deadline(),
            )?;
        }
        let checkpoint_directory = self.state_directory.path().join(CHECKPOINT_NAMESPACE);
        let root_expected = super::inventory::recovery_root_process_expectations(
            &physical,
            &checkpoint_directory,
            self.recovery_blob_store.as_deref(),
            &self.executable_path,
            &checkpoints_by_cat,
            &blockd_by_cat,
            &volumes_by_cat,
        )?;
        let serving_expected = super::inventory::recovery_serving_process_expectations(
            &physical,
            self,
            &checkpoints_by_cat,
            &blockd_by_cat,
            &volumes_by_cat,
        )?;
        let vmm_expected = super::inventory::recovery_vmm_process_expectations(
            &checkpoint_directory,
            &checkpoints_by_cat,
        )?;
        let socket_root = self
            .managed_vmm_socket_root
            .as_deref()
            .context("stale-boot recovery lacks the managed VMM socket root")?;
        let receipts = self
            .vmm_socket_receipts
            .as_deref()
            .context("stale-boot recovery lacks the VMM receipt store")?;
        let expected_checkpoints = vmm_expected
            .values()
            .map(VmmProcessExpectation::checkpoint)
            .collect::<Vec<_>>();
        let receipt_snapshot = scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            &expected_checkpoints,
            &physical,
        )?;
        if !matches!(receipt_snapshot, ReceiptNamespaceSnapshot::Exact(_)) {
            return Ok(None);
        }
        let current_boot_id = current_kernel_node_boot_id()?;
        let stale_vmm =
            vmm_expected
                .iter()
                .try_fold(BTreeSet::new(), |mut stale, (cat_id, expectation)| {
                    if receipt_snapshot
                        .stale_boot_receipt_for_checkpoint(expectation.checkpoint())?
                        .is_some_and(|receipt| receipt.node_boot_id() != &current_boot_id)
                    {
                        stale.insert(cat_id.clone());
                    }
                    Ok::<_, anyhow::Error>(stale)
                })?;
        let mut stop_receipt_sockets = blockd_by_cat.iter().try_fold(
            BTreeMap::new(),
            |mut sockets, (cat_id, by_volume)| {
                for evidence in by_volume.values() {
                    if let Some(socket) = evidence.stop_receipt_socket.clone() {
                        anyhow::ensure!(
                            sockets.insert(cat_id.clone(), socket).is_none(),
                            "stale-boot recovery found duplicate Root stop-receipt sockets"
                        );
                    }
                }
                Ok::<_, anyhow::Error>(sockets)
            },
        )?;
        let blockd_boot = CurrentBlockdSocketBoot::read()?;
        let blockd_root = Arc::clone(
            self.managed_blockd_socket_root
                .as_ref()
                .context("stale-boot recovery lacks the managed blockd socket root")?,
        );
        let blockd_intents = Arc::clone(
            self.blockd_socket_intents
                .as_ref()
                .context("stale-boot recovery lacks the managed blockd intent store")?,
        );
        let blockd_expected = self.managed_blockd_intents(
            &root_expected,
            &serving_expected,
            &blockd_root,
            &blockd_boot,
        )?;
        let blockd_snapshot =
            blockd_root.capture_closed_whole_root(&blockd_intents, &blockd_expected)?;
        for socket in stop_receipt_sockets.values_mut() {
            socket.bind_managed_snapshot(&blockd_snapshot)?;
        }
        Ok(Some(StaleBootRecoveryManagedSet {
            root_expected,
            serving_expected,
            vmm_expected,
            stale_vmm,
            receipt_snapshot,
            stop_receipt_sockets,
            blockd_boot,
            blockd_root,
            blockd_intents,
            blockd_expected,
            blockd_snapshot,
        }))
    }

    #[cfg(target_os = "linux")]
    fn inspect_stale_boot_recovery_managed_set(
        &self,
        expected: &StaleBootRecoveryManagedSet,
        selected: &VmmProcessExpectation,
        context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<StaleBootRecoveryManagedInspection> {
        let physical = context.inventory_context();
        let Some(root) =
            inspect_root_process_set(self.port.as_ref(), &expected.root_expected, &physical)?
        else {
            return Ok(StaleBootRecoveryManagedInspection::Unavailable);
        };
        let Some(serving) = inspect_serving_process_set(
            self.serving_port.as_ref(),
            &expected.serving_expected,
            &physical,
        )?
        else {
            return Ok(StaleBootRecoveryManagedInspection::Unavailable);
        };
        let Some(vmm) =
            inspect_vmm_process_set(self.vmm_port.as_ref(), &expected.vmm_expected, &physical)?
        else {
            return Ok(StaleBootRecoveryManagedInspection::Unavailable);
        };
        if expected
            .stale_vmm
            .iter()
            .any(|cat_id| !matches!(vmm.get(cat_id), Some(VmmProcessInspection::Absent)))
            || !matches!(
                vmm.get(selected.cat_id()),
                Some(VmmProcessInspection::Absent)
            )
        {
            return Ok(StaleBootRecoveryManagedInspection::Conflict);
        }
        Ok(StaleBootRecoveryManagedInspection::Exact { root, serving, vmm })
    }
    /// One shared sealed sweep for both full-inventory projection and
    /// retirement absence. Every managed service, Cats binary process, and
    /// managed socket must be accounted for by the exact identities supplied
    /// by the caller; an empty allowlist therefore proves Node-global absence.
    fn sweep_node_global_inventory(
        &self,
        allowed_units: &BTreeSet<Id>,
        allowed_pids: &BTreeSet<u32>,
        allowed_sockets: &BTreeSet<PathBuf>,
        expected_vmms: &BTreeMap<Id, VmmProcessExpectation>,
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
        let managed_vmm_sockets = match (
            self.managed_vmm_socket_root.as_deref(),
            self.vmm_socket_receipts.as_deref(),
        ) {
            (Some(root), Some(receipts)) => {
                let checkpoints = expected_vmms
                    .values()
                    .map(VmmProcessExpectation::checkpoint)
                    .collect::<Vec<_>>();
                match scan_managed_vmm_socket_root(root, receipts, &checkpoints, context)? {
                    ManagedVmmSocketRootScan::Accounted => ProbeFact::Empty,
                    ManagedVmmSocketRootScan::Residue => ProbeFact::Present,
                    ManagedVmmSocketRootScan::Unavailable => ProbeFact::Unavailable,
                }
            }
            (None, None) if !self.process_paths.supported => ProbeFact::Unavailable,
            (None, None) => ProbeFact::Empty,
            _ => ProbeFact::Unavailable,
        };
        #[cfg(target_os = "linux")]
        let managed_vmm_launch_files = match (
            self.managed_vmm_launch_root.as_deref(),
            self.managed_vmm_socket_root.as_deref(),
            self.vmm_socket_receipts.as_deref(),
        ) {
            (Some(launch_root), Some(socket_root), Some(receipts)) => {
                let checkpoints = expected_vmms
                    .values()
                    .map(VmmProcessExpectation::checkpoint)
                    .collect::<Vec<_>>();
                match scan_managed_vmm_launch_root(
                    launch_root,
                    socket_root,
                    receipts,
                    &checkpoints,
                    context,
                )? {
                    ManagedVmmLaunchRootScan::Accounted => ProbeFact::Empty,
                    ManagedVmmLaunchRootScan::Residue => ProbeFact::Present,
                    ManagedVmmLaunchRootScan::Unavailable => ProbeFact::Unavailable,
                }
            }
            (None, None, None) if !self.process_paths.supported => ProbeFact::Unavailable,
            (None, None, None) => ProbeFact::Empty,
            _ => ProbeFact::Unavailable,
        };
        #[cfg(not(target_os = "linux"))]
        let managed_vmm_launch_files = ProbeFact::Empty;
        Ok(
            if [
                systemd,
                metering,
                processes,
                sockets,
                managed_vmm_sockets,
                managed_vmm_launch_files,
            ]
            .contains(&ProbeFact::Present)
            {
                ProbeFact::Present
            } else if [
                systemd,
                metering,
                processes,
                sockets,
                managed_vmm_sockets,
                managed_vmm_launch_files,
            ]
            .contains(&ProbeFact::Unavailable)
            {
                ProbeFact::Unavailable
            } else {
                ProbeFact::Empty
            },
        )
    }

    #[cfg(target_os = "linux")]
    fn sweep_node_global_stale_boot_recovery(
        &self,
        expected: &StaleBootRecoveryManagedSet,
        inspected: &StaleBootRecoveryManagedInspection,
        context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<ProbeFact> {
        let StaleBootRecoveryManagedInspection::Exact { root, serving, vmm } = inspected else {
            return Ok(ProbeFact::Present);
        };
        if expected
            .stale_vmm
            .iter()
            .any(|cat_id| !matches!(vmm.get(cat_id), Some(VmmProcessInspection::Absent)))
        {
            return Ok(ProbeFact::Present);
        }
        let physical = context.inventory_context();
        let socket_root = self
            .managed_vmm_socket_root
            .as_deref()
            .context("stale-boot recovery lacks the managed VMM socket root")?;
        let receipts = self
            .vmm_socket_receipts
            .as_deref()
            .context("stale-boot recovery lacks the VMM receipt store")?;
        let checkpoints = expected
            .vmm_expected
            .values()
            .map(VmmProcessExpectation::checkpoint)
            .collect::<Vec<_>>();
        if scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            &checkpoints,
            &physical,
        )? != expected.receipt_snapshot
        {
            return Ok(ProbeFact::Present);
        }
        if CurrentBlockdSocketBoot::read()? != expected.blockd_boot
            || expected.blockd_snapshot.assert_current().is_err()
        {
            return Ok(ProbeFact::Present);
        }
        let mut budget = self.limits.os_entries;
        let mut allowed_units = BTreeSet::new();
        let mut allowed_pids = BTreeSet::new();
        let mut allowed_sockets = BTreeSet::new();
        for inspection in root.values() {
            if let RootProvisionProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.scope_id.clone())
                    || !allowed_pids.insert(evidence.process_id)
                    || !allowed_sockets.insert(PathBuf::from(evidence.control_socket_path.as_str()))
                {
                    return Ok(ProbeFact::Present);
                }
            }
        }
        for inspection in serving.values() {
            if let ServingBlockdProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.unit_id().clone())
                    || !allowed_pids.insert(evidence.process_id())
                    || !allowed_sockets
                        .insert(PathBuf::from(evidence.control_socket_path().as_str()))
                    || !allowed_sockets.insert(PathBuf::from(evidence.listener_path().as_str()))
                {
                    return Ok(ProbeFact::Present);
                }
            }
        }
        for inspection in vmm.values() {
            if let VmmProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.unit_id().clone())
                    || !allowed_pids.insert(evidence.process_id())
                {
                    return Ok(ProbeFact::Present);
                }
            }
        }
        for (cat_id, socket) in &expected.stop_receipt_sockets {
            let Some(root_expected) = expected.root_expected.get(cat_id) else {
                return Ok(ProbeFact::Present);
            };
            if &root_expected.control_socket_path != socket.receipt_socket() {
                return Ok(ProbeFact::Present);
            }
            match root.get(cat_id) {
                Some(RootProvisionProcessInspection::Absent) => {
                    for path in socket.physical_paths() {
                        if !allowed_sockets.insert(PathBuf::from(path.as_str())) {
                            return Ok(ProbeFact::Present);
                        }
                    }
                }
                Some(RootProvisionProcessInspection::Exact(evidence))
                    if &evidence.control_socket_path == socket.receipt_socket()
                        && socket.physical_paths()
                            == &BTreeSet::from([socket.receipt_socket().clone()]) => {}
                _ => return Ok(ProbeFact::Present),
            }
        }
        let managed_blockd_paths = expected
            .blockd_snapshot
            .socket_paths()
            .into_iter()
            .map(|path| PathBuf::from(path.as_str()))
            .collect::<BTreeSet<_>>();
        if !allowed_sockets.is_subset(&managed_blockd_paths) {
            return Ok(ProbeFact::Present);
        }
        let stale_blockd_paths = managed_blockd_paths
            .difference(&allowed_sockets)
            .map(|path| {
                HostPath::new(path.to_string_lossy().into_owned())
                    .context("managed blockd socket path is not canonical")
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        if !platform_managed_blockd_listeners_absent(stale_blockd_paths.iter(), &physical)? {
            return Ok(ProbeFact::Present);
        }
        let systemd = scan_cgroup_tree_allowing(
            &self.systemd_root,
            CgroupKind::Systemd,
            0,
            &mut budget,
            self.limits.recursion_depth,
            &allowed_units,
            &physical,
        )?;
        let metering = if let Some(root) = &self.metering_root {
            scan_cgroup_tree_allowing(
                root,
                CgroupKind::DedicatedMeteringRoot,
                0,
                &mut budget,
                self.limits.recursion_depth,
                &BTreeSet::new(),
                &physical,
            )?
        } else {
            ProbeFact::Empty
        };
        let processes = scan_processes_allowing(&self.process_paths, &allowed_pids, &physical)?;
        let sockets = scan_root_process_sockets(
            &self.state_directory,
            &self.legacy_socket_root,
            &allowed_sockets,
            self.limits,
            &physical,
        )?;
        let managed_vmm_sockets = match (
            self.managed_vmm_socket_root.as_deref(),
            self.vmm_socket_receipts.as_deref(),
        ) {
            (Some(root), Some(receipts)) => {
                match scan_managed_vmm_socket_root_for_stale_boot_recovery(
                    root,
                    receipts,
                    &checkpoints,
                    &physical,
                )? {
                    ManagedVmmSocketRootScan::Accounted => ProbeFact::Empty,
                    ManagedVmmSocketRootScan::Residue => ProbeFact::Present,
                    ManagedVmmSocketRootScan::Unavailable => ProbeFact::Unavailable,
                }
            }
            _ => ProbeFact::Unavailable,
        };
        let managed_vmm_launch_files = match (
            self.managed_vmm_launch_root.as_deref(),
            self.managed_vmm_socket_root.as_deref(),
            self.vmm_socket_receipts.as_deref(),
        ) {
            (Some(launch_root), Some(socket_root), Some(receipts)) => {
                match scan_managed_vmm_launch_root_for_stale_boot_recovery(
                    launch_root,
                    socket_root,
                    receipts,
                    &checkpoints,
                    &physical,
                )? {
                    ManagedVmmLaunchRootScan::Accounted => ProbeFact::Empty,
                    ManagedVmmLaunchRootScan::Residue => ProbeFact::Present,
                    ManagedVmmLaunchRootScan::Unavailable => ProbeFact::Unavailable,
                }
            }
            _ => ProbeFact::Unavailable,
        };
        let receipts_still_exact = if scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            &checkpoints,
            &physical,
        )? == expected.receipt_snapshot
        {
            ProbeFact::Empty
        } else {
            ProbeFact::Present
        };
        let blockd_still_exact = if CurrentBlockdSocketBoot::read()? == expected.blockd_boot
            && expected
                .blockd_root
                .capture_closed_whole_root(&expected.blockd_intents, &expected.blockd_expected)
                .is_ok_and(|after| expected.blockd_snapshot.same_coordinates(&after))
        {
            ProbeFact::Empty
        } else {
            ProbeFact::Present
        };
        Ok(
            if [
                systemd,
                metering,
                processes,
                sockets,
                managed_vmm_sockets,
                managed_vmm_launch_files,
                receipts_still_exact,
                blockd_still_exact,
            ]
            .contains(&ProbeFact::Present)
            {
                ProbeFact::Present
            } else if [
                systemd,
                metering,
                processes,
                sockets,
                managed_vmm_sockets,
                managed_vmm_launch_files,
                receipts_still_exact,
                blockd_still_exact,
            ]
            .contains(&ProbeFact::Unavailable)
            {
                ProbeFact::Unavailable
            } else {
                ProbeFact::Empty
            },
        )
    }

    /// Revalidate the complete admitted RootControl + ServingBlockd set around
    /// one Node-global residue sweep. Effects may project only their target
    /// role from the result, but no effect may shrink this shared allowlist:
    /// a legitimate serving process must not become foreign residue while a
    /// Root-control effect runs (or vice versa).
    fn inspect_admitted_managed_processes(
        &self,
        admission: &super::root_provision_process::NodeGlobalManagedProcessAdmission,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<AdmittedManagedProcessInspection> {
        self.inspect_admitted_managed_processes_with_vmm_successor(admission, None, context)
    }

    fn inspect_admitted_managed_processes_with_vmm_successor(
        &self,
        admission: &super::root_provision_process::NodeGlobalManagedProcessAdmission,
        vmm_successor: Option<&VmmGateSuccessorProof>,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<AdmittedManagedProcessInspection> {
        let (root_expected, root_admitted) = admission.root_control_state();
        let (serving_expected, serving_admitted) = admission.serving_blockd_state();
        let (mut vmm_expected, vmm_admitted) = admission.vmm_state();
        if let Some(successor_proof) = vmm_successor {
            let successor = successor_proof.successor();
            let Some((accepted, Some(admitted_exact))) = admission.vmm(successor.cat_id()) else {
                return Ok(AdmittedManagedProcessInspection::IdentityMismatch);
            };
            if accepted != admitted_exact.expectation()
                || successor_proof.validate_for(admitted_exact)? != successor
            {
                return Ok(AdmittedManagedProcessInspection::IdentityMismatch);
            }
            vmm_expected.insert(successor.cat_id().clone(), successor.clone());
        }
        let managed_blockd = match (
            self.managed_blockd_socket_root.as_ref(),
            self.blockd_socket_intents.as_ref(),
        ) {
            (Some(root), Some(intents)) => {
                let current_boot = CurrentBlockdSocketBoot::read()?;
                anyhow::ensure!(
                    admission.node_boot_id() == current_boot.node_boot_id(),
                    "accepted managed-process admission names another kernel boot"
                );
                let expected = self.managed_blockd_intents(
                    &root_expected,
                    &serving_expected,
                    root,
                    &current_boot,
                )?;
                let before = root.capture_closed_whole_root(intents, &expected)?;
                Some((Arc::clone(root), Arc::clone(intents), expected, before))
            }
            (None, None) if !self.process_paths.supported => {
                return Ok(AdmittedManagedProcessInspection::Unavailable)
            }
            #[cfg(test)]
            (None, None) => None,
            #[cfg(not(test))]
            (None, None) => anyhow::bail!("installed scanner lacks managed blockd namespace"),
            _ => anyhow::bail!("managed blockd root and intent store are not one composition"),
        };
        let Some(root_first) =
            inspect_root_process_set(self.port.as_ref(), &root_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        let Some(serving_first) =
            inspect_serving_process_set(self.serving_port.as_ref(), &serving_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        let Some(vmm_first) =
            inspect_vmm_process_set(self.vmm_port.as_ref(), &vmm_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        if root_first != root_admitted
            || serving_first != serving_admitted
            || vmm_first != vmm_admitted
        {
            return Ok(AdmittedManagedProcessInspection::IdentityMismatch);
        }

        let mut allowed_units = BTreeSet::new();
        let mut allowed_pids = BTreeSet::new();
        let mut allowed_sockets = BTreeSet::new();
        for inspection in root_first.values() {
            if let RootProvisionProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.scope_id.clone())
                    || !allowed_pids.insert(evidence.process_id)
                    || !allowed_sockets.insert(PathBuf::from(evidence.control_socket_path.as_str()))
                {
                    return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
                }
            }
        }
        for inspection in serving_first.values() {
            if let ServingBlockdProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.unit_id().clone())
                    || !allowed_pids.insert(evidence.process_id())
                    || !allowed_sockets
                        .insert(PathBuf::from(evidence.control_socket_path().as_str()))
                    || !allowed_sockets.insert(PathBuf::from(evidence.listener_path().as_str()))
                {
                    return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
                }
            }
        }
        for inspection in vmm_first.values() {
            if let VmmProcessInspection::Exact(evidence) = inspection {
                if !allowed_units.insert(evidence.unit_id().clone())
                    || !allowed_pids.insert(evidence.process_id())
                {
                    return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
                }
            }
        }
        allowed_sockets.extend(
            admission
                .stop_receipt_physical_paths()
                .iter()
                .map(|socket| PathBuf::from(socket.as_str())),
        );
        if let Some((_, _, _, before)) = managed_blockd.as_ref() {
            let managed_paths = before
                .socket_paths()
                .into_iter()
                .map(|path| PathBuf::from(path.as_str()))
                .collect::<BTreeSet<_>>();
            if !allowed_sockets.is_subset(&managed_paths) {
                return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
            }
            let stale_paths = managed_paths
                .difference(&allowed_sockets)
                .map(|path| {
                    HostPath::new(path.to_string_lossy().into_owned())
                        .context("managed blockd socket path is not canonical")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            if !platform_managed_blockd_listeners_absent(stale_paths.iter(), context)? {
                return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
            }
        }
        let sweep = match self.sweep_node_global_inventory(
            &allowed_units,
            &allowed_pids,
            &allowed_sockets,
            &vmm_expected,
            context,
        ) {
            Ok(sweep) => sweep,
            Err(_) => {
                context.check_active()?;
                return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
            }
        };
        match sweep {
            ProbeFact::Present => {
                return Ok(AdmittedManagedProcessInspection::DuplicateIdentity);
            }
            ProbeFact::Unavailable => {
                return Ok(AdmittedManagedProcessInspection::Unavailable);
            }
            ProbeFact::Empty => {}
        }

        if let Some((root, intents, expected, before)) = managed_blockd.as_ref() {
            let after = root.capture_closed_whole_root(intents, expected)?;
            if !before.same_coordinates(&after) {
                return Ok(AdmittedManagedProcessInspection::IdentityMismatch);
            }
        }

        let Some(root_second) =
            inspect_root_process_set(self.port.as_ref(), &root_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        let Some(serving_second) =
            inspect_serving_process_set(self.serving_port.as_ref(), &serving_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        let Some(vmm_second) =
            inspect_vmm_process_set(self.vmm_port.as_ref(), &vmm_expected, context)?
        else {
            return Ok(AdmittedManagedProcessInspection::Unavailable);
        };
        if root_first != root_second || serving_first != serving_second || vmm_first != vmm_second {
            return Ok(AdmittedManagedProcessInspection::IdentityMismatch);
        }
        Ok(AdmittedManagedProcessInspection::Exact {
            root: root_second,
            serving: serving_second,
            vmm: vmm_second,
        })
    }

    fn inspect_admitted_root_target(
        &self,
        expected: &RootProvisionProcessExpectation,
        purpose: AdmittedRootTargetPurpose,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        let _node_global_effect = context.lock_node_global_effect()?;
        let admission = context.node_global_process()?;
        let Some((admitted_target, admitted_exact)) = admission.root_control(&expected.cat_id)
        else {
            return Ok(RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch,
            ));
        };
        if admitted_target != expected {
            return Ok(RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch,
            ));
        }
        if matches!(purpose, AdmittedRootTargetPurpose::StopReceipt) {
            let Some(admitted_socket) = admission.stop_receipt_socket(&expected.cat_id) else {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ));
            };
            if admitted_exact.is_some()
                || admitted_socket.receipt_socket() != &expected.control_socket_path
            {
                return Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ));
            }
        }
        match self.inspect_admitted_managed_processes(admission, context)? {
            AdmittedManagedProcessInspection::Exact { root, .. } => Ok(root
                .get(&expected.cat_id)
                .expect("target expectation was retained in the closed set")
                .clone()),
            AdmittedManagedProcessInspection::Unavailable => {
                Ok(RootProvisionProcessInspection::Unavailable)
            }
            AdmittedManagedProcessInspection::IdentityMismatch => {
                Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::IdentityMismatch,
                ))
            }
            AdmittedManagedProcessInspection::DuplicateIdentity => {
                Ok(RootProvisionProcessInspection::Conflict(
                    RootProvisionProcessConflict::DuplicateIdentity,
                ))
            }
        }
    }
}

impl root_process_inventory_bridge_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl RootProcessInventoryBridge for PlatformRootProcessInventoryBridge {
    fn executable_path(&self) -> &HostPath {
        &self.executable_path
    }

    fn serving_expectation(
        &self,
        checkpoint: &RuntimeCheckpoint,
        physical_desired: &DesiredRuntimeSpec,
        gate_desired: &DesiredRuntimeSpec,
        prepared: &cats_api::runtime_reconciliation::PreparedDeviceInput,
        blockd: &AuthorizedBlockdInventoryEvidence,
        authority: &VolumeRecord,
    ) -> anyhow::Result<ServingBlockdExpectation> {
        ServingBlockdExpectation::from_inventory_running(
            &self.state_directory,
            &self.root_provision_systemd,
            checkpoint,
            physical_desired,
            gate_desired,
            prepared,
            blockd,
            authority,
        )
    }

    fn inspect_all(
        &self,
        root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
        serving_expected: BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
        vmm_expected: BTreeMap<Id, VmmProcessExpectation>,
        mut stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
        let unavailable =
            |exact_running_negative_cats| RootProcessInventoryBridgeOutcome::Unavailable {
                exact_running_negative_cats,
            };
        let managed_blockd = match (
            self.managed_blockd_socket_root.as_ref(),
            self.blockd_socket_intents.as_ref(),
        ) {
            (Some(root), Some(intents)) => {
                let current_boot = CurrentBlockdSocketBoot::read()?;
                let expected = self.managed_blockd_intents(
                    &root_expected,
                    &serving_expected,
                    root,
                    &current_boot,
                )?;
                let before = root.capture_closed_whole_root(intents, &expected)?;
                Some((Arc::clone(root), Arc::clone(intents), expected, before))
            }
            (None, None) if !self.process_paths.supported => {
                return Ok(unavailable(BTreeSet::new()))
            }
            #[cfg(test)]
            (None, None) => None,
            #[cfg(not(test))]
            (None, None) => anyhow::bail!("installed scanner lacks managed blockd namespace"),
            _ => anyhow::bail!("managed blockd root and intent store are not one composition"),
        };
        if let Some((_, _, _, before)) = managed_blockd.as_ref() {
            for socket in stop_receipt_sockets.values_mut() {
                socket.bind_managed_snapshot(before)?;
            }
        }
        let Some(root_first) =
            inspect_root_process_set(self.port.as_ref(), &root_expected, context)?
        else {
            return Ok(unavailable(BTreeSet::new()));
        };
        let Some(serving_first) =
            inspect_serving_process_set(self.serving_port.as_ref(), &serving_expected, context)?
        else {
            return Ok(unavailable(BTreeSet::new()));
        };
        let Some(vmm_first) =
            inspect_vmm_process_set(self.vmm_port.as_ref(), &vmm_expected, context)?
        else {
            return Ok(unavailable(BTreeSet::new()));
        };
        let exact_running_negative_cats = vmm_first
            .iter()
            .filter_map(|(cat_id, inspection)| match inspection {
                VmmProcessInspection::Absent => Some(cat_id.clone()),
                VmmProcessInspection::Exact(evidence)
                    if evidence.state() != ProcessState::Running =>
                {
                    Some(cat_id.clone())
                }
                VmmProcessInspection::Exact(_) => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();

        let mut allowed_units = root_first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => Some(evidence.scope_id.clone()),
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        let mut allowed_pids = root_first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => Some(evidence.process_id),
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        let mut allowed_sockets = root_first
            .values()
            .filter_map(|inspection| match inspection {
                RootProvisionProcessInspection::Exact(evidence) => {
                    Some(PathBuf::from(evidence.control_socket_path.as_str()))
                }
                RootProvisionProcessInspection::Absent => None,
                _ => unreachable!("inspection set contains only exact or absent"),
            })
            .collect::<BTreeSet<_>>();
        for inspection in serving_first.values() {
            if let ServingBlockdProcessInspection::Exact(evidence) = inspection {
                anyhow::ensure!(
                    allowed_units.insert(evidence.unit_id().clone())
                        && allowed_pids.insert(evidence.process_id())
                        && allowed_sockets
                            .insert(PathBuf::from(evidence.control_socket_path().as_str()))
                        && allowed_sockets.insert(PathBuf::from(evidence.listener_path().as_str())),
                    "managed-process inventory contains duplicate physical identity"
                );
            }
        }
        for inspection in vmm_first.values() {
            if let VmmProcessInspection::Exact(evidence) = inspection {
                anyhow::ensure!(
                    allowed_units.insert(evidence.unit_id().clone())
                        && allowed_pids.insert(evidence.process_id()),
                    "managed-process inventory contains duplicate VMM physical identity"
                );
            }
        }
        for (cat_id, socket) in &stop_receipt_sockets {
            let expected = root_expected
                .get(cat_id)
                .context("stop receipt socket lacks a RootControl expectation")?;
            anyhow::ensure!(
                &expected.control_socket_path == socket.receipt_socket(),
                "stop receipt socket changed from its RootControl expectation"
            );
            match root_first.get(cat_id) {
                Some(RootProvisionProcessInspection::Absent) => {
                    for path in socket.physical_paths() {
                        anyhow::ensure!(
                            allowed_sockets.insert(PathBuf::from(path.as_str())),
                            "stop receipt socket duplicates a managed physical identity"
                        );
                    }
                }
                Some(RootProvisionProcessInspection::Exact(evidence)) => {
                    anyhow::ensure!(
                        &evidence.control_socket_path == socket.receipt_socket()
                            && socket.physical_paths()
                                == &BTreeSet::from([socket.receipt_socket().clone()]),
                        "live receipted RootControl changed its socket"
                    );
                }
                _ => anyhow::bail!("stop receipt socket lacks a closed RootControl inspection"),
            }
        }
        anyhow::ensure!(
            allowed_units.len() == allowed_pids.len(),
            "managed-process inventory contains duplicate unit or PID identity"
        );

        if let Some((_, _, _, before)) = managed_blockd.as_ref() {
            let managed_paths = before
                .socket_paths()
                .into_iter()
                .map(|path| PathBuf::from(path.as_str()))
                .collect::<BTreeSet<_>>();
            anyhow::ensure!(
                allowed_sockets.is_subset(&managed_paths),
                "live or receipted blockd socket is outside the exact managed-root snapshot"
            );
            let stale_paths = managed_paths
                .difference(&allowed_sockets)
                .map(|path| {
                    HostPath::new(path.to_string_lossy().into_owned())
                        .context("managed blockd socket path is not canonical")
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            anyhow::ensure!(
                platform_managed_blockd_listeners_absent(stale_paths.iter(), context)?,
                "absent managed blockd owner retains a live Unix listener"
            );
        }

        let sweep = match self.sweep_node_global_inventory(
            &allowed_units,
            &allowed_pids,
            &allowed_sockets,
            &vmm_expected,
            context,
        ) {
            Ok(sweep) => sweep,
            Err(_problem) if context.check_active().is_err() => {
                return Ok(unavailable(exact_running_negative_cats));
            }
            Err(problem) => return Err(problem),
        };
        match sweep {
            ProbeFact::Present => {
                bail!("managed-process inventory found foreign or duplicate managed residue")
            }
            ProbeFact::Unavailable => {
                return Ok(unavailable(exact_running_negative_cats));
            }
            ProbeFact::Empty => {}
        }

        if let Some((root, intents, expected, before)) = managed_blockd.as_ref() {
            let after = root.capture_closed_whole_root(intents, expected)?;
            anyhow::ensure!(
                before.same_coordinates(&after),
                "managed blockd namespace changed across full Node-global inventory"
            );
        }

        let root_second =
            match inspect_root_process_set(self.port.as_ref(), &root_expected, context) {
                Ok(Some(inspected)) => inspected,
                Ok(None) => return Ok(unavailable(exact_running_negative_cats)),
                Err(_problem) if context.check_active().is_err() => {
                    return Ok(unavailable(exact_running_negative_cats));
                }
                Err(problem) => return Err(problem),
            };
        let serving_second = match inspect_serving_process_set(
            self.serving_port.as_ref(),
            &serving_expected,
            context,
        ) {
            Ok(Some(inspected)) => inspected,
            Ok(None) => return Ok(unavailable(exact_running_negative_cats)),
            Err(_problem) if context.check_active().is_err() => {
                return Ok(unavailable(exact_running_negative_cats));
            }
            Err(problem) => return Err(problem),
        };
        let vmm_second =
            match inspect_vmm_process_set(self.vmm_port.as_ref(), &vmm_expected, context) {
                Ok(Some(inspected)) => inspected,
                Ok(None) => return Ok(unavailable(exact_running_negative_cats)),
                Err(_problem) if context.check_active().is_err() => {
                    return Ok(unavailable(exact_running_negative_cats));
                }
                Err(problem) => return Err(problem),
            };
        anyhow::ensure!(
            root_first == root_second && serving_first == serving_second && vmm_first == vmm_second,
            "managed-process identity changed across the global inventory sweep"
        );
        let mut root_proofs = BTreeMap::new();
        for (cat_id, inspection) in root_second {
            if let RootProvisionProcessInspection::Exact(evidence) = inspection {
                let expectation = root_expected
                    .get(&cat_id)
                    .expect("inspection keys originate from expectations")
                    .clone();
                let proof = expectation.prove_exact_process(*evidence)?;
                root_proofs.insert(cat_id, proof);
            }
        }
        let mut serving_proofs = BTreeMap::new();
        for (key, inspection) in serving_second {
            if let ServingBlockdProcessInspection::Exact(evidence) = inspection {
                let expectation = serving_expected
                    .get(&key)
                    .expect("inspection keys originate from expectations")
                    .clone();
                serving_proofs.insert(key, expectation.prove_exact_process(*evidence)?);
            }
        }
        let mut vmm_proofs = BTreeMap::new();
        for (cat_id, inspection) in vmm_second {
            if let VmmProcessInspection::Exact(evidence) = inspection {
                let expectation = vmm_expected
                    .get(&cat_id)
                    .expect("inspection keys originate from expectations")
                    .clone();
                vmm_proofs.insert(cat_id, expectation.prove_exact_process(*evidence)?);
            }
        }
        Ok(RootProcessInventoryBridgeOutcome::Complete(
            super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
                root_expected, root_proofs,
            )?
            .with_serving_blockds(serving_expected, serving_proofs)?
            .with_vmms(vmm_expected, vmm_proofs)?
            .with_stop_receipt_sockets(stop_receipt_sockets)?,
        ))
    }
}

impl super::root_provision_process::retirement_sealed::Sealed
    for PlatformRootProcessInventoryBridge
{
}

impl super::root_provision_process::global_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl RootProvisionProcessGlobalPort for PlatformRootProcessInventoryBridge {
    fn inspect_exact_or_absent_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        self.inspect_admitted_root_target(expected, AdmittedRootTargetPurpose::Ordinary, context)
    }
}

impl serving_process_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl ServingBlockdProcessPort for PlatformRootProcessInventoryBridge {
    fn inspect(
        &self,
        expected: &ServingBlockdExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<ServingBlockdProcessInspection> {
        self.serving_port.inspect(expected, context)
    }

    fn start_checkpointed(
        &self,
        checkpointed: super::serving_blockd_process::CheckpointedServingBlockdProcess<'_>,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<super::serving_blockd_process::ServingBlockdProcessStart> {
        self.serving_port.start_checkpointed(checkpointed, context)
    }
}

impl serving_global_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl ServingBlockdProcessGlobalPort for PlatformRootProcessInventoryBridge {
    fn retain_start_socket_absence(
        &self,
        expected: &ServingBlockdExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
        let current_boot = CurrentBlockdSocketBoot::read()?;
        let root = RetainedManagedBlockdSocketRoot::open_installed()?;
        let intent = BlockdSocketOwnershipIntentV1::serving(
            &root,
            &current_boot,
            expected.device_ownership_token().clone(),
            serving_socket_owner_authority_digest(expected.prepared_device())?,
        )?;
        self.retain_managed_blockd_start_absence(
            intent,
            ManagedBlockdStartTarget::Serving(expected),
            context,
        )
    }

    fn inspect_serving_exact_or_absent_after_node_global_sweep(
        &self,
        expected: &ServingBlockdExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<ServingBlockdProcessInspection> {
        let _node_global_effect = context.lock_node_global_effect()?;
        let admission = context.node_global_process()?;
        let Some((admitted_target, _)) =
            admission.serving_blockd(expected.cat_id(), expected.volume_id())
        else {
            return Ok(ServingBlockdProcessInspection::Conflict(
                ServingBlockdProcessConflict::IdentityMismatch,
            ));
        };
        if admitted_target != expected {
            return Ok(ServingBlockdProcessInspection::Conflict(
                ServingBlockdProcessConflict::IdentityMismatch,
            ));
        }
        match self.inspect_admitted_managed_processes(admission, context)? {
            AdmittedManagedProcessInspection::Exact { serving, .. } => Ok(serving
                .get(&ManagedServingKey::new(
                    expected.cat_id().clone(),
                    expected.volume_id().clone(),
                ))
                .expect("target serving expectation was retained in the closed set")
                .clone()),
            AdmittedManagedProcessInspection::Unavailable => {
                Ok(ServingBlockdProcessInspection::Unavailable)
            }
            AdmittedManagedProcessInspection::IdentityMismatch => {
                Ok(ServingBlockdProcessInspection::Conflict(
                    ServingBlockdProcessConflict::IdentityMismatch,
                ))
            }
            AdmittedManagedProcessInspection::DuplicateIdentity => {
                Ok(ServingBlockdProcessInspection::Conflict(
                    ServingBlockdProcessConflict::DuplicateIdentity,
                ))
            }
        }
    }
}

impl vmm_process_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl VmmProcessPort for PlatformRootProcessInventoryBridge {
    fn inspect(
        &self,
        expected: &VmmProcessExpectation,
        context: &dyn RuntimePhysicalReadContext,
    ) -> anyhow::Result<VmmProcessInspection> {
        self.vmm_port.inspect(expected, context)
    }

    fn start_checkpointed(
        &self,
        checkpointed: super::vmm_process::CheckpointedVmmProcess<'_>,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<super::vmm_process::VmmProcessStart> {
        self.vmm_port.start_checkpointed(checkpointed, context)
    }
}

impl vmm_global_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl VmmProcessGlobalPort for PlatformRootProcessInventoryBridge {
    fn inspect_vmm_exact_or_absent_after_node_global_sweep(
        &self,
        expected: &VmmProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<VmmProcessGlobalInspection> {
        let _node_global_effect = context.lock_node_global_effect()?;
        let admission = context.node_global_process()?;
        let Some((admitted_target, _)) = admission.vmm(expected.cat_id()) else {
            return Ok(VmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if admitted_target != expected {
            return Ok(VmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        match self.inspect_admitted_managed_processes(admission, context)? {
            AdmittedManagedProcessInspection::Exact { mut vmm, .. } => {
                match vmm
                    .remove(expected.cat_id())
                    .expect("target VMM expectation was retained in the closed set")
                {
                    VmmProcessInspection::Absent => {
                        Ok(VmmProcessGlobalInspection::Absent(Box::new(
                            super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(
                                expected.clone(),
                            ),
                        )))
                    }
                    VmmProcessInspection::Exact(evidence) => Ok(VmmProcessGlobalInspection::Exact(
                        Box::new(expected.clone().prove_exact_process(*evidence)?),
                    )),
                    VmmProcessInspection::Conflict(problem) => {
                        Ok(VmmProcessGlobalInspection::Conflict(problem))
                    }
                    VmmProcessInspection::Unavailable => {
                        Ok(VmmProcessGlobalInspection::Unavailable)
                    }
                }
            }
            AdmittedManagedProcessInspection::Unavailable => {
                Ok(VmmProcessGlobalInspection::Unavailable)
            }
            AdmittedManagedProcessInspection::IdentityMismatch => Ok(
                VmmProcessGlobalInspection::Conflict(VmmProcessConflict::IdentityMismatch),
            ),
            AdmittedManagedProcessInspection::DuplicateIdentity => Ok(
                VmmProcessGlobalInspection::Conflict(VmmProcessConflict::DuplicateIdentity),
            ),
        }
    }

    fn inspect_vmm_gate_successor_exact_after_node_global_sweep(
        &self,
        admitted_predecessor: &super::vmm_process::ExactVmmProcessProof,
        successor_proof: &VmmGateSuccessorProof,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<VmmProcessGlobalInspection> {
        let _node_global_effect = context.lock_node_global_effect()?;
        let successor = successor_proof.validate_for(admitted_predecessor)?;
        let admission = context.node_global_process()?;
        let Some((admitted_target, admitted_exact)) =
            admission.vmm(admitted_predecessor.expectation().cat_id())
        else {
            return Ok(VmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if admitted_target != admitted_predecessor.expectation()
            || admitted_exact != Some(admitted_predecessor)
        {
            return Ok(VmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        match self.inspect_admitted_managed_processes_with_vmm_successor(
            admission,
            Some(successor_proof),
            context,
        )? {
            AdmittedManagedProcessInspection::Exact { mut vmm, .. } => match vmm
                .remove(successor.cat_id())
                .expect("successor VMM expectation was retained in the closed set")
            {
                VmmProcessInspection::Exact(evidence) => {
                    let proof = successor.clone().prove_exact_process(*evidence)?;
                    if proof.evidence() != admitted_predecessor.evidence() {
                        return Ok(VmmProcessGlobalInspection::Conflict(
                            VmmProcessConflict::IdentityMismatch,
                        ));
                    }
                    Ok(VmmProcessGlobalInspection::Exact(Box::new(proof)))
                }
                VmmProcessInspection::Absent => Ok(VmmProcessGlobalInspection::Absent(Box::new(
                    super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(
                        successor.clone(),
                    ),
                ))),
                VmmProcessInspection::Conflict(problem) => {
                    Ok(VmmProcessGlobalInspection::Conflict(problem))
                }
                VmmProcessInspection::Unavailable => Ok(VmmProcessGlobalInspection::Unavailable),
            },
            AdmittedManagedProcessInspection::Unavailable => {
                Ok(VmmProcessGlobalInspection::Unavailable)
            }
            AdmittedManagedProcessInspection::IdentityMismatch => Ok(
                VmmProcessGlobalInspection::Conflict(VmmProcessConflict::IdentityMismatch),
            ),
            AdmittedManagedProcessInspection::DuplicateIdentity => Ok(
                VmmProcessGlobalInspection::Conflict(VmmProcessConflict::DuplicateIdentity),
            ),
        }
    }
}

#[cfg(target_os = "linux")]
impl stale_boot_recovery_global_sealed::Sealed for PlatformRootProcessInventoryBridge {}

#[cfg(target_os = "linux")]
impl StaleBootVmmProcessGlobalPort for PlatformRootProcessInventoryBridge {
    fn inspect_stale_boot_absence_after_node_global_sweep(
        &self,
        selected: &VmmProcessExpectation,
        checkpoints: &RuntimeCheckpointRecoverySet,
        context: &RuntimePreScanRecoveryContext,
    ) -> anyhow::Result<StaleBootVmmProcessGlobalInspection> {
        context.check_active()?;
        let socket_root = self
            .managed_vmm_socket_root
            .as_deref()
            .context("stale-boot VMM recovery lacks the managed socket root")?;
        let Some(fresh_before) = runtime_checkpoint_recovery_set(context, socket_root)? else {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if &fresh_before != checkpoints {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }

        let Some(expected) = self.stale_boot_recovery_managed_set(checkpoints, context)? else {
            return Ok(StaleBootVmmProcessGlobalInspection::Unavailable);
        };
        if expected.vmm_expected.get(selected.cat_id()) != Some(selected) {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }

        let physical = context.inventory_context();
        let first = self.inspect_stale_boot_recovery_managed_set(&expected, selected, context)?;
        match &first {
            StaleBootRecoveryManagedInspection::Exact { .. } => {}
            StaleBootRecoveryManagedInspection::Unavailable => {
                return Ok(StaleBootVmmProcessGlobalInspection::Unavailable)
            }
            StaleBootRecoveryManagedInspection::Conflict => {
                return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                    VmmProcessConflict::IdentityMismatch,
                ))
            }
        }

        let receipts = self
            .vmm_socket_receipts
            .as_deref()
            .context("stale-boot VMM recovery lacks the receipt store")?;
        let expected_checkpoints = expected
            .vmm_expected
            .values()
            .map(VmmProcessExpectation::checkpoint)
            .collect::<Vec<_>>();
        let candidate = receipts.retain_one_stale_boot_receipt(
            socket_root,
            &expected_checkpoints,
            &physical,
        )?;
        let StaleVmmSocketReceiptScan::Candidate(candidate) = candidate else {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if candidate.cat_id() != selected.cat_id()
            || candidate.receipt().runtime_incarnation() != selected.runtime_incarnation()
        {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        candidate.assert_current(receipts)?;
        socket_root.assert_stale_boot_attempt_absent(candidate.receipt())?;

        match self.sweep_node_global_stale_boot_recovery(&expected, &first, context)? {
            ProbeFact::Present => {
                return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                    VmmProcessConflict::DuplicateIdentity,
                ))
            }
            ProbeFact::Unavailable => return Ok(StaleBootVmmProcessGlobalInspection::Unavailable),
            ProbeFact::Empty => {}
        }
        let second = self.inspect_stale_boot_recovery_managed_set(&expected, selected, context)?;
        match &second {
            StaleBootRecoveryManagedInspection::Exact { .. } if second == first => {}
            StaleBootRecoveryManagedInspection::Unavailable => {
                return Ok(StaleBootVmmProcessGlobalInspection::Unavailable)
            }
            StaleBootRecoveryManagedInspection::Exact { .. }
            | StaleBootRecoveryManagedInspection::Conflict => {
                return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                    VmmProcessConflict::IdentityMismatch,
                ))
            }
        }
        let Some(fresh_after) = runtime_checkpoint_recovery_set(context, socket_root)? else {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if &fresh_after != checkpoints {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        if scan_stale_boot_receipt_namespace_snapshot(
            socket_root,
            receipts,
            &expected_checkpoints,
            &physical,
        )? != expected.receipt_snapshot
        {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        let fresh_candidate = receipts.retain_one_stale_boot_receipt(
            socket_root,
            &expected_checkpoints,
            &physical,
        )?;
        let StaleVmmSocketReceiptScan::Candidate(fresh_candidate) = fresh_candidate else {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        };
        if fresh_candidate.cat_id() != selected.cat_id()
            || fresh_candidate.receipt().runtime_incarnation() != selected.runtime_incarnation()
        {
            return Ok(StaleBootVmmProcessGlobalInspection::Conflict(
                VmmProcessConflict::IdentityMismatch,
            ));
        }
        fresh_candidate.assert_current(receipts)?;
        socket_root.assert_stale_boot_attempt_absent(fresh_candidate.receipt())?;
        context.check_active()?;
        Ok(StaleBootVmmProcessGlobalInspection::Absent(Box::new(
            super::vmm_process::ExactVmmProcessAbsenceProof::for_expectation(selected.clone()),
        )))
    }
}

impl vmm_cid_inventory_sealed::Sealed for PlatformRootProcessInventoryBridge {}

impl VmmCidInventoryPort for PlatformRootProcessInventoryBridge {
    fn inspect(
        &self,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<VmmCidInventorySnapshot> {
        context.check_active()?;
        let _node_global_effect = context.lock_node_global_effect()?;
        let accepted = context.accepted_full()?;
        let admission = context.node_global_process()?;
        anyhow::ensure!(
            admission.matches_observation(accepted.observation()),
            "VMM CID inventory admission is not bound to the accepted full observation"
        );
        match self.inspect_admitted_managed_processes(admission, context)? {
            AdmittedManagedProcessInspection::Exact { .. } => {}
            AdmittedManagedProcessInspection::Unavailable => {
                anyhow::bail!("Node-global VMM CID inventory is unavailable")
            }
            AdmittedManagedProcessInspection::IdentityMismatch => {
                anyhow::bail!("Node-global VMM CID inventory changed from its admission")
            }
            AdmittedManagedProcessInspection::DuplicateIdentity => {
                anyhow::bail!("Node-global VMM CID inventory contains foreign or duplicate state")
            }
        }
        let exact = admission
            .exact_vmm_proofs()
            .map(|proof| {
                let (cat_id, runtime_incarnation, guest_cid) = proof.guest_cid_identity();
                ExactLiveVmmCid::new(
                    VmmCidOwner::new(cat_id.clone(), runtime_incarnation.clone()),
                    guest_cid,
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        context.check_active()?;
        VmmCidInventorySnapshot::try_new(exact)
    }
}

impl RootProvisionProcessRetirementPort for PlatformRootProcessInventoryBridge {
    fn inspect_exact_stop_owner_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionManagedStopInspection> {
        let current_boot = CurrentBlockdSocketBoot::read()?;
        let root = RetainedManagedBlockdSocketRoot::open_installed()?;
        let intents = BlockdSocketIntentStore::open_existing(self.state_directory.clone())?;
        let intent = BlockdSocketOwnershipIntentV1::root(
            &root,
            &current_boot,
            expected.provision_transition_id.clone(),
            expected.socket_owner_authority_digest.clone(),
        )?;
        let retain_owner = || -> anyhow::Result<_> {
            match root.retain_existing_intent(&intents, &intent, &current_boot)? {
                super::blockd_socket_namespace::ManagedBlockdSocketOwnerInspection::Current(
                    retained,
                ) => retained.retain_root_stop_owner_evidence(&current_boot).map(Some),
                super::blockd_socket_namespace::ManagedBlockdSocketOwnerInspection::Absent
                | super::blockd_socket_namespace::ManagedBlockdSocketOwnerInspection::StaleBootAbsent
                | super::blockd_socket_namespace::ManagedBlockdSocketOwnerInspection::RecoverableAbsent => {
                    Ok(None)
                }
            }
        };
        let Some(before) = retain_owner()? else {
            return Ok(RootProvisionManagedStopInspection::Absent);
        };
        let inspection = self.inspect_admitted_root_target(
            expected,
            AdmittedRootTargetPurpose::Ordinary,
            context,
        )?;
        match inspection {
            RootProvisionProcessInspection::Exact(process) => {
                let Some(after) = retain_owner()? else {
                    return Ok(RootProvisionManagedStopInspection::Conflict(
                        RootProvisionProcessConflict::IdentityMismatch,
                    ));
                };
                if before != after || !after.matches_expectation(expected) {
                    return Ok(RootProvisionManagedStopInspection::Conflict(
                        RootProvisionProcessConflict::IdentityMismatch,
                    ));
                }
                Ok(RootProvisionManagedStopInspection::Exact {
                    process,
                    owner: Box::new(after),
                })
            }
            RootProvisionProcessInspection::Absent => {
                Ok(RootProvisionManagedStopInspection::Absent)
            }
            RootProvisionProcessInspection::Conflict(problem) => {
                Ok(RootProvisionManagedStopInspection::Conflict(problem))
            }
            RootProvisionProcessInspection::Unavailable => {
                Ok(RootProvisionManagedStopInspection::Unavailable)
            }
        }
    }

    fn retire_absent_socket_owner(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<super::blockd_socket_namespace::ManagedBlockdSocketOwnerRetirement> {
        let absence = RootProvisionProcessRetirementPort::retain_start_socket_absence(
            self, expected, context,
        )?
        .context("Root socket-owner retirement lacks exact Node-global absence")?;
        let current_boot = CurrentBlockdSocketBoot::read()?;
        let root = RetainedManagedBlockdSocketRoot::open_installed()?;
        let intents = BlockdSocketIntentStore::open_existing(self.state_directory.clone())?;
        let intent = BlockdSocketOwnershipIntentV1::root(
            &root,
            &current_boot,
            expected.provision_transition_id.clone(),
            expected.socket_owner_authority_digest.clone(),
        )?;
        root.retire_absent_owner(&intents, &intent, &current_boot, absence)
    }

    fn retain_start_socket_absence(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<Option<ExactManagedBlockdSocketOwnerStartAbsence>> {
        let current_boot = CurrentBlockdSocketBoot::read()?;
        let root = RetainedManagedBlockdSocketRoot::open_installed()?;
        let intent = BlockdSocketOwnershipIntentV1::root(
            &root,
            &current_boot,
            expected.provision_transition_id.clone(),
            expected.socket_owner_authority_digest.clone(),
        )?;
        self.retain_managed_blockd_start_absence(
            intent,
            ManagedBlockdStartTarget::Root(expected),
            context,
        )
    }

    fn inspect_exact_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        self.inspect_admitted_root_target(expected, AdmittedRootTargetPurpose::Ordinary, context)
    }

    fn inspect_after_node_global_sweep(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        self.inspect_admitted_root_target(expected, AdmittedRootTargetPurpose::Ordinary, context)
    }

    fn inspect_absent_with_admitted_stop_receipt(
        &self,
        expected: &RootProvisionProcessExpectation,
        context: &crate::runtime_spine::RuntimeDesiredEffectContext,
    ) -> anyhow::Result<RootProvisionProcessInspection> {
        self.inspect_admitted_root_target(expected, AdmittedRootTargetPurpose::StopReceipt, context)
    }
}

fn inspect_root_process_set(
    port: &dyn RootProvisionProcessPort,
    expected: &BTreeMap<Id, RootProvisionProcessExpectation>,
    context: &dyn RuntimePhysicalReadContext,
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

fn inspect_serving_process_set(
    port: &dyn ServingBlockdProcessPort,
    expected: &BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<BTreeMap<ManagedServingKey, ServingBlockdProcessInspection>>> {
    let mut inspected = BTreeMap::new();
    for (key, expectation) in expected {
        let inspection = port.inspect(expectation, context)?;
        match inspection {
            ServingBlockdProcessInspection::Absent | ServingBlockdProcessInspection::Exact(_) => {}
            ServingBlockdProcessInspection::Unavailable => return Ok(None),
            ServingBlockdProcessInspection::Conflict(_) => {
                bail!(
                    "serving blockd process conflict for Cat {} Volume {}",
                    key.cat_id(),
                    key.volume_id()
                )
            }
        }
        inspected.insert(key.clone(), inspection);
    }
    Ok(Some(inspected))
}

fn inspect_vmm_process_set(
    port: &dyn VmmProcessPort,
    expected: &BTreeMap<Id, VmmProcessExpectation>,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<BTreeMap<Id, VmmProcessInspection>>> {
    let mut inspected = BTreeMap::new();
    for (cat_id, expectation) in expected {
        let inspection = port.inspect(expectation, context)?;
        match inspection {
            VmmProcessInspection::Absent | VmmProcessInspection::Exact(_) => {}
            VmmProcessInspection::Unavailable => return Ok(None),
            VmmProcessInspection::Conflict(problem) => {
                let problem = match problem {
                    VmmProcessConflict::DuplicateIdentity => "duplicate identity",
                    VmmProcessConflict::IdentityMismatch => "identity mismatch",
                };
                bail!("VMM process conflict for {cat_id}: {problem}")
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
    managed_kernel_nbd_device_count: Option<u32>,
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
            scan_nbd(
                &self.block_class_root,
                self.limits.os_entries,
                self.managed_kernel_nbd_device_count,
                context,
            )?
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
    physical_inventory_owned_by_bridge: bool,
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
        let interfaces = if self.physical_inventory_owned_by_bridge {
            ProbeFact::Empty
        } else if self.supported {
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
                    for (cat_id, by_volume) in &data.evidence {
                        for evidence in by_volume.values() {
                            let carries_superseded_receipt =
                                evidence.checkpoint.attachment.acquire_desired_revision()
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
                                    disk_kind: match volume.disk_kind {
                                        cats_api::runtime_reconciliation::DiskKind::Root => cats_api::runtime_reconciliation::ObservedDiskKind::Root,
                                        cats_api::runtime_reconciliation::DiskKind::Persistent => cats_api::runtime_reconciliation::ObservedDiskKind::Persistent,
                                    },
                                    size_bytes: Some(volume.size_bytes),
                                    durability: Some(volume.durability),
                                    authority: VolumeAuthorityEvidence::Unavailable,
                                    local_lineages: Vec::new(),
                                    devices: Vec::new(),
                                },
                                acquire_request: Some(
                                    evidence
                                        .checkpoint
                                        .attachment
                                        .checkpoint_acquire_request(),
                                ),
                            },
                        )?;
                        }
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
        // The frozen Desired wire already closes lifecycle target/disposition
        // compatibility: non-Deleted retains every volume, while Deleted
        // permits only explicit detach/delete dispositions and restricts
        // disposable delete to Root. Inventory is observation-only, so the
        // same complete authority read is valid for every lifecycle target.
        if encode_desired_runtime_spec(desired).is_err() {
            return Ok(None);
        }
        if desired.volumes.is_empty() || desired.volumes.len() > 64 {
            return Ok(None);
        }
        for (index, intent) in desired.volumes.iter().enumerate() {
            let shape_is_exact = usize::from(intent.guest_device.slot) == index
                && intent.access == VolumeAccess::ReadWriteOnce
                && match index {
                    0 => intent.disk_kind == DiskKind::Root && intent.mount.is_none(),
                    _ => intent.disk_kind == DiskKind::Persistent && intent.mount.is_some(),
                };
            if !shape_is_exact {
                return Ok(None);
            }
            anyhow::ensure!(
                volumes
                    .insert(intent.volume_id.clone(), (desired, intent))
                    .is_none(),
                "one authority Volume is referenced by multiple Desired Runtimes"
            );
        }
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
            let current_marker_matches = match (&intent.acquire, &record.last_transition) {
                (
                    VolumeAcquire::Normal {
                        transition_id,
                        expected_unowned_epoch,
                    },
                    Some(cats_api::runtime_reconciliation::LastVolumeTransition::NormalAcquire {
                        request,
                        result,
                    }),
                ) => {
                    request.volume_id == intent.volume_id
                        && request.transition_id == *transition_id
                        && request.attachment_id == intent.attachment_id
                        && request.expected_unowned_epoch == *expected_unowned_epoch
                        && request.desired_revision == desired.desired_revision
                        && request.placement_epoch == desired.placement.placement_epoch
                        && result.volume_id == intent.volume_id
                        && result.transition_id == *transition_id
                        && result.attachment_id == intent.attachment_id
                        && result.resulting_epoch == record.lease_epoch
                }
                (
                    VolumeAcquire::Takeover { authorization_id },
                    Some(cats_api::runtime_reconciliation::LastVolumeTransition::Takeover {
                        authorization_id: observed,
                    }),
                ) => observed == authorization_id,
                _ => false,
            };
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
        disk_kind: match intent.disk_kind {
            DiskKind::Root => ObservedDiskKind::Root,
            DiskKind::Persistent => ObservedDiskKind::Persistent,
        },
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
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<Vec<StrictDirectoryEntry>>> {
    strict_directory_entries_with_release_links(directory, budget, context, false)
}

fn strict_checkpoint_directory_entries(
    directory: &File,
    budget: &mut usize,
    context: &dyn RuntimePhysicalReadContext,
) -> anyhow::Result<Option<Vec<StrictDirectoryEntry>>> {
    strict_directory_entries_with_release_links(directory, budget, context, true)
}

fn strict_directory_entries_with_release_links(
    directory: &File,
    budget: &mut usize,
    context: &dyn RuntimePhysicalReadContext,
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
            && raw_device_to_u64(entry.metadata.st_dev) == Some(metadata.dev())
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
    context: &dyn RuntimePhysicalReadContext,
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
            && raw_device_to_u64(entry.metadata.st_dev) == Some(before.dev())
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
        && raw_device_to_u64(entry.metadata.st_dev) == Some(metadata.dev())
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
    context: &dyn RuntimePhysicalReadContext,
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
            && raw_device_to_u64(entry.metadata.st_dev) == Some(before.dev())
            && before.ino() == entry.metadata.st_ino
            && u128::from(before.nlink()) == u128::from(entry.metadata.st_nlink),
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
    managed_device_count: Option<u32>,
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
        let index = std::str::from_utf8(&name.as_bytes()[3..])
            .ok()
            .and_then(|value| value.parse::<u32>().ok())
            .context("kernel-NBD sysfs entry index is not a u32")?;
        if managed_device_count.is_some_and(|count| index < count) {
            // The allocation-flock-protected kernel pool bridge inspects this
            // configured slot and joins it to the complete checkpoint
            // namespace. This generic residue probe owns only slots outside
            // that closed pool.
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
    _managed_socket_paths: &BTreeSet<PathBuf>,
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
    // V1 lockstep cutover: every blockd socket is owned by the independent
    // `/run/cats/blockd-v1` scanner. Any socket below durable Cat data is an
    // old-layout or foreign residue, even if its lexical path appears in a
    // checkpoint or stop receipt.
    Ok(if discovered.is_empty() {
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
    use std::os::unix::ffi::OsStrExt as _;
    #[cfg(target_os = "linux")]
    use std::os::unix::fs::DirBuilderExt as _;
    use std::os::unix::fs::{FileTypeExt as _, MetadataExt as _, PermissionsExt as _};
    use std::os::unix::io::AsRawFd as _;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Mutex;
    use std::time::{Duration, Instant};

    use cats_api::guest::{
        FilesystemControlOperationV1, FilesystemControlOutcomeV1, FilesystemControlRequestV1,
        FilesystemControlResponseV1, FilesystemIdentityV1, PersistentFilesystemMountV1,
        PersistentFilesystemObservationV1, RuntimeReadyDeviceV1, RuntimeReadyMountV1,
        RuntimeReadyRequestV1, RuntimeReadyResponseV1,
    };
    #[cfg(target_os = "linux")]
    use cats_api::runtime_reconciliation::RuntimeLaunch;
    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, decode_runtime_checkpoint, inventory_digest, spec_digest,
        AcquireOrigin, AdmissionInventoryAttestation, AgentSession, AsciiText, AssignedKind,
        AssignedPlacement, CheckpointEvidence, CleanupRelease, CleanupTarget, ContractVersion,
        DesiredRuntimeSpec, DirectAuthorizedAttachmentIdentity, DirectAuthorizedAttachmentPurpose,
        DiskKind, Durability, Epoch, Ext4MountIntent, FenceEpoch, FilesystemInitialization,
        Generation, GuestBootId, GuestDeviceIdentity, GuestTransportEvidence, HostPath, Id,
        Ipv4Address, IsolatedIpv4Kind, LifecycleAdmission, MacAddress, MountAccess, NetworkConfig,
        NodeBootId, NodeObservation, NormalAcquireRequest, ObservedNetwork, OwnershipTokenEvidence,
        PersistentFilesystemBinding, PersistentInitializationReceipt, PrepareDeviceFrontend,
        PreparedDeviceInput, ProcessState, RandomId128, ReconcileStep, RemoteHead, Revision,
        RuntimeConfig, RuntimeNetworkIdentity, RuntimeTarget, RuntimeTransition,
        RuntimeVolumeTransition, RuntimeVolumeTransitionPreconditionProblem,
        RuntimeVolumeTransitionRequest, ServingAuthorityProvenance, ServingBlockdIdentity,
        SessionBinding, Sha256Digest, UnixMillis, VolumeAccess, VolumeAcquire,
        VolumeAcquireRequest, VolumeDisposition, VolumeIntent, VolumeReleaseReplay, WireU64,
    };
    use cats_storage::{
        encode_image_manifest, AdapterConfig, AdapterSelection, BlobError, ImageManifestV1,
        LowerHexSha256,
    };
    use tempfile::TempDir;

    use crate::runtime_spine::{
        RuntimeDesiredEffectAdmission, RuntimeDesiredEffectContext, RuntimeDesiredEffectOutcome,
        RuntimeInventoryScanOutcome, RuntimeInventoryScanner, RuntimePhysicalReadContext,
        RuntimePreScanRecovery, RuntimePreScanRecoveryContext, RuntimePreScanRecoveryOutcome,
        RuntimeSpineFullScan,
    };

    use super::super::inventory::{
        network_inventory_bridge_sealed, NetworkInventoryBridge, NetworkInventoryBridgeOutcome,
    };
    use super::super::serving_blockd_process::RetainedServingBlockdAuthority;
    use super::super::signed_running::{
        acquire_checkpoint, expected_provision_heads, prepared_owned_observed_volume,
        ProvisionHeadRead, SignedRunningPublicationRecovery,
    };
    use super::super::{
        runtime_checkpoint_path, AdmissionCell, AdmissionSnapshot, AuthorizedBlockdStore,
        FileCheckpointStore, NodeGlobalManagedProcessScanAdmission, NodeGlobalNetworkScanAdmission,
        StoredCheckpoint,
    };
    #[cfg(target_os = "linux")]
    use super::super::{ManagedVmmLaunchFilePaths, VmmSocketOwnershipReceiptV1};

    use super::*;

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    fn managed_root_control_socket(provision_transition_id: &RandomId128) -> HostPath {
        cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .root_paths(provision_transition_id)
            .unwrap()
            .control_socket()
            .clone()
    }

    fn managed_serving_sockets(device_ownership_token: &RandomId128) -> (HostPath, HostPath) {
        let paths = cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed()
            .serving_paths(device_ownership_token)
            .unwrap();
        (paths.control_socket().clone(), paths.io_socket().clone())
    }

    #[test]
    fn start_runtime_is_never_projected_without_an_exact_live_vmm() {
        let environment = TestEnvironment::new();
        let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let expected = VmmProcessExpectation::from_checkpoint(checkpoint)
            .unwrap()
            .with_checkpoint_path(
                HostPath::new("/var/lib/cats/checkpoints/cat-cat_01.checkpoint.json").unwrap(),
            )
            .unwrap();
        let cat_id = expected.cat_id().clone();
        let bridge = root_process_bridge_with_all_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeVmmProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let outcome = bridge
            .inspect_all(
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::from([(cat_id, expected)]),
                BTreeMap::new(),
                &assigned_context(true),
            )
            .unwrap();
        match outcome {
            // Non-Linux builds cannot perform the production VMM inspection.
            RootProcessInventoryBridgeOutcome::Unavailable { .. } => {}
            // Linux can prove the exact unit absent. Absence is sealed in the
            // private admission but must never become a public VMM process.
            RootProcessInventoryBridgeOutcome::Complete(admission) => {
                assert!(admission.process_projections().is_empty());
                assert!(admission.vmm_proofs().is_empty());
            }
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn stale_boot_global_sweep_preserves_current_live_cat_and_rejects_extra_unit() {
        let environment = TestEnvironment::new();
        std::fs::set_permissions(
            &environment.state,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let state_directory = StateDirectory::unanchored(environment.state.clone());
        let launch_namespace = environment.state.join(VMM_LAUNCH_FILE_NAMESPACE);
        std::fs::create_dir(&launch_namespace).unwrap();
        std::fs::set_permissions(
            &launch_namespace,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let launch_root =
            Arc::new(RetainedManagedVmmLaunchRoot::open_existing(state_directory.clone()).unwrap());
        let managed_socket_root = Arc::new(
            RetainedManagedVmmSocketRoot::provision_for_test(
                &environment.state.parent().unwrap().join("managed-vmm"),
            )
            .unwrap(),
        );
        let receipts =
            Arc::new(VmmSocketReceiptStore::provision_for_test(state_directory.clone()).unwrap());

        let mut current = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let current_incarnation = current.runtime_incarnation.as_ref().unwrap().clone();
        let current_sockets = managed_socket_root
            .planner()
            .paths_for(&current_incarnation)
            .unwrap();
        let current_files =
            ManagedVmmLaunchFilePaths::for_incarnation(&state_directory, &current_incarnation)
                .unwrap();
        let ReconcileStep::StartRuntime {
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut current.step
        else {
            unreachable!()
        };
        *api_socket_path = current_sockets.api_socket_path().clone();
        *vsock_socket_path = current_sockets.vsock_socket_path().clone();
        *memory_file_path = current_files.memory_file_path().clone();
        *serial_log_path = current_files.serial_log_path().clone();
        *vmm_log_path = current_files.vmm_log_path().clone();
        current.runtime_launch = RuntimeLaunch::Present(Box::new(
            current.step.start_runtime_launch_identity().unwrap(),
        ));
        let current_receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
            &current,
            &state_directory,
            &managed_socket_root,
            current_kernel_node_boot_id().unwrap(),
            RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap(),
        )
        .unwrap();
        receipts.publish(&current_receipt).unwrap();
        let current_attempt = match managed_socket_root
            .prepare_existing_receipt(&current, &receipts)
            .unwrap()
        {
            super::super::vmm_socket_namespace::ManagedVmmSocketPreparation::Prepared(attempt) => {
                *attempt
            }
            super::super::vmm_socket_namespace::ManagedVmmSocketPreparation::ExistingLive => {
                panic!("current Cat fixture unexpectedly pre-existed")
            }
        };
        let current_directory =
            std::fs::metadata(current_sockets.public_directory().as_str()).unwrap();
        let current_api = std::fs::metadata(current_sockets.api_socket_path().as_str()).unwrap();

        let mut stale = current.clone();
        stale.cat_id = Id::new("cat_02").unwrap();
        let stale_incarnation = RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap();
        stale.runtime_incarnation = Some(stale_incarnation.clone());
        let stale_sockets = managed_socket_root
            .planner()
            .paths_for(&stale_incarnation)
            .unwrap();
        let stale_files =
            ManagedVmmLaunchFilePaths::for_incarnation(&state_directory, &stale_incarnation)
                .unwrap();
        let ReconcileStep::StartRuntime {
            runtime_incarnation,
            scope_id,
            process_identity_token,
            api_socket_path,
            vsock_socket_path,
            memory_file_path,
            serial_log_path,
            vmm_log_path,
            ..
        } = &mut stale.step
        else {
            unreachable!()
        };
        *runtime_incarnation = stale_incarnation.clone();
        *scope_id = Id::new(format!("cats-vmm-{}.service", stale_incarnation.as_str())).unwrap();
        *process_identity_token = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        *api_socket_path = stale_sockets.api_socket_path().clone();
        *vsock_socket_path = stale_sockets.vsock_socket_path().clone();
        *memory_file_path = stale_files.memory_file_path().clone();
        *serial_log_path = stale_files.serial_log_path().clone();
        *vmm_log_path = stale_files.vmm_log_path().clone();
        stale.runtime_launch = RuntimeLaunch::Present(Box::new(
            stale.step.start_runtime_launch_identity().unwrap(),
        ));
        let mut stale_receipt = VmmSocketOwnershipReceiptV1::from_checkpoint(
            &stale,
            &state_directory,
            &managed_socket_root,
            current_kernel_node_boot_id().unwrap(),
            RandomId128::new("dddddddddddddddddddddddddddddddd").unwrap(),
        )
        .unwrap();
        let current_boot = current_kernel_node_boot_id().unwrap();
        let old_boot = ["e".repeat(32), "f".repeat(32)]
            .into_iter()
            .map(|value| NodeBootId::new(value).unwrap())
            .find(|value| value != &current_boot)
            .unwrap();
        stale_receipt.set_node_boot_id_for_test(old_boot);
        receipts.publish(&stale_receipt).unwrap();

        let current_expected = VmmProcessExpectation::from_checkpoint(current.clone())
            .unwrap()
            .with_checkpoint_path(
                HostPath::new(
                    environment
                        .state
                        .join("checkpoints/cat-cat_01.checkpoint.json")
                        .to_string_lossy()
                        .into_owned(),
                )
                .unwrap(),
            )
            .unwrap();
        let stale_expected = VmmProcessExpectation::from_checkpoint(stale.clone())
            .unwrap()
            .with_checkpoint_path(
                HostPath::new(
                    environment
                        .state
                        .join("checkpoints/cat-cat_02.checkpoint.json")
                        .to_string_lossy()
                        .into_owned(),
                )
                .unwrap(),
            )
            .unwrap();
        let expectations = BTreeMap::from([
            (current.cat_id.clone(), current_expected.clone()),
            (stale.cat_id.clone(), stale_expected),
        ]);
        let expected_checkpoints = expectations
            .values()
            .map(VmmProcessExpectation::checkpoint)
            .collect::<Vec<_>>();
        let scan = assigned_context(true);
        let recovery_context = RuntimePreScanRecoveryContext::for_test(
            state_directory,
            scan.coordinates().clone(),
            Instant::now() + Duration::from_secs(10),
        );
        let receipt_snapshot = scan_stale_boot_receipt_namespace_snapshot(
            &managed_socket_root,
            &receipts,
            &expected_checkpoints,
            &recovery_context.inventory_context(),
        )
        .unwrap();
        let blockd_root = Arc::new(
            RetainedManagedBlockdSocketRoot::provision_for_test(
                &environment._root.path().join("blockd-sockets"),
            )
            .unwrap(),
        );
        let blockd_intents = Arc::new(
            BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(
                environment.state.clone(),
            ))
            .unwrap(),
        );
        let blockd_boot = CurrentBlockdSocketBoot::read().unwrap();
        let blockd_expected = Vec::new();
        let blockd_snapshot = blockd_root
            .capture_closed_whole_root(&blockd_intents, &blockd_expected)
            .unwrap();
        let managed = StaleBootRecoveryManagedSet {
            root_expected: BTreeMap::new(),
            serving_expected: BTreeMap::new(),
            vmm_expected: expectations,
            stale_vmm: BTreeSet::from([stale.cat_id.clone()]),
            receipt_snapshot,
            stop_receipt_sockets: BTreeMap::new(),
            blockd_boot,
            blockd_root: Arc::clone(&blockd_root),
            blockd_intents: Arc::clone(&blockd_intents),
            blockd_expected,
            blockd_snapshot,
        };
        let process_id = 4_242;
        let inspected = StaleBootRecoveryManagedInspection::Exact {
            root: BTreeMap::new(),
            serving: BTreeMap::new(),
            vmm: BTreeMap::from([
                (
                    current.cat_id.clone(),
                    VmmProcessInspection::Exact(Box::new(
                        current_expected.exact_evidence_for_test(process_id),
                    )),
                ),
                (stale.cat_id.clone(), VmmProcessInspection::Absent),
            ]),
        };
        std::fs::create_dir(
            environment
                .systemd_root
                .join(current_expected.unit_id().as_str()),
        )
        .unwrap();
        let proc = environment.proc_root.join(process_id.to_string());
        std::fs::create_dir(&proc).unwrap();
        let vmm_binary = PathBuf::from(
            current_expected
                .launch_identity()
                .boot
                .vmm_executable
                .path
                .as_str(),
        );
        std::os::unix::fs::symlink(&vmm_binary, proc.join("exe")).unwrap();
        std::fs::write(
            proc.join("cmdline"),
            [vmm_binary.as_os_str().as_bytes(), b"\0"].concat(),
        )
        .unwrap();
        let mut bridge = root_process_bridge_with_all_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeVmmProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
        );
        bridge.process_paths.binaries = vec![vmm_binary];
        bridge.managed_vmm_socket_root = Some(Arc::clone(&managed_socket_root));
        bridge.managed_vmm_launch_root = Some(launch_root);
        bridge.vmm_socket_receipts = Some(Arc::clone(&receipts));
        bridge.managed_blockd_socket_root = Some(blockd_root);
        bridge.blockd_socket_intents = Some(blockd_intents);

        assert_eq!(
            bridge
                .sweep_node_global_stale_boot_recovery(&managed, &inspected, &recovery_context,)
                .unwrap(),
            ProbeFact::Empty
        );
        let current_directory_after =
            std::fs::metadata(current_sockets.public_directory().as_str()).unwrap();
        let current_api_after =
            std::fs::metadata(current_sockets.api_socket_path().as_str()).unwrap();
        assert_eq!(current_directory.ino(), current_directory_after.ino());
        assert_eq!(current_api.ino(), current_api_after.ino());

        let live_stale = StaleBootRecoveryManagedInspection::Exact {
            root: BTreeMap::new(),
            serving: BTreeMap::new(),
            vmm: BTreeMap::from([
                (
                    current.cat_id.clone(),
                    VmmProcessInspection::Exact(Box::new(
                        current_expected.exact_evidence_for_test(process_id),
                    )),
                ),
                (
                    stale.cat_id.clone(),
                    VmmProcessInspection::Exact(Box::new(
                        managed
                            .vmm_expected
                            .get(&stale.cat_id)
                            .unwrap()
                            .exact_evidence_for_test(5_252),
                    )),
                ),
            ]),
        };
        assert_eq!(
            bridge
                .sweep_node_global_stale_boot_recovery(&managed, &live_stale, &recovery_context,)
                .unwrap(),
            ProbeFact::Present
        );
        assert_eq!(
            receipts.load(stale_receipt.runtime_incarnation()).unwrap(),
            Some(stale_receipt.clone())
        );

        let foreign = environment.systemd_root.join("cats-foreign.scope");
        std::fs::create_dir(&foreign).unwrap();
        assert_eq!(
            bridge
                .sweep_node_global_stale_boot_recovery(&managed, &inspected, &recovery_context,)
                .unwrap(),
            ProbeFact::Present
        );
        assert!(foreign.is_dir());
        assert_eq!(
            receipts.load(stale_receipt.runtime_incarnation()).unwrap(),
            Some(stale_receipt)
        );
        drop(current_attempt);
    }

    #[test]
    fn platform_sweep_accepts_only_the_typed_second_endpoint_revision_successor() {
        let environment = TestEnvironment::new();
        let physical =
            cats_api::runtime_reconciliation::decode_desired_runtime_spec(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-desired.json"
            )))
            .unwrap();
        let launch_checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();

        let mut live_gate = physical.clone();
        live_gate.desired_revision = Revision::new(physical.desired_revision.get() + 1).unwrap();
        live_gate.endpoints[0].route_epoch =
            Epoch::new(physical.endpoints[0].route_epoch.get() + 1).unwrap();
        live_gate.spec_digest = spec_digest(&live_gate).unwrap();
        super::super::authorized_blockd::validate_running_physical_desired_successor(
            &physical, &live_gate,
        )
        .unwrap();
        let mut accepted_checkpoint = launch_checkpoint;
        accepted_checkpoint.desired_revision = live_gate.desired_revision;
        accepted_checkpoint.spec_digest = live_gate.spec_digest.clone();
        let accepted = VmmProcessExpectation::from_checkpoint(accepted_checkpoint.clone())
            .unwrap()
            .with_checkpoint_path(
                HostPath::new("/var/lib/cats/checkpoints/cat-cat_01.checkpoint.json").unwrap(),
            )
            .unwrap();
        let accepted_exact = accepted
            .clone()
            .prove_exact_process(accepted.exact_evidence_for_test(71))
            .unwrap();

        let mut successor_desired = live_gate.clone();
        successor_desired.desired_revision =
            Revision::new(live_gate.desired_revision.get() + 1).unwrap();
        successor_desired.endpoints[0].route_epoch =
            Epoch::new(live_gate.endpoints[0].route_epoch.get() + 1).unwrap();
        successor_desired.spec_digest = spec_digest(&successor_desired).unwrap();
        let mut successor_checkpoint = accepted_checkpoint;
        successor_checkpoint.desired_revision = successor_desired.desired_revision;
        successor_checkpoint.spec_digest = successor_desired.spec_digest.clone();
        successor_checkpoint.updated_at_unix_ms =
            UnixMillis::new(successor_checkpoint.updated_at_unix_ms.get() + 1).unwrap();
        let successor = VmmGateSuccessorProof::endpoint_only(
            &accepted_exact,
            &live_gate,
            &successor_desired,
            &successor_checkpoint,
        )
        .unwrap();

        let admission = NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(
            BTreeMap::from([(accepted.cat_id().clone(), accepted.clone())]),
            BTreeMap::from([(accepted.cat_id().clone(), accepted_exact.clone())]),
        )
        .unwrap()
        .into_admission_for_test();
        let context = RuntimeDesiredEffectContext::for_test_with_node_global_process(
            StateDirectory::unanchored(environment.state.clone()),
            Instant::now() + Duration::from_secs(5),
            admission,
        );
        let bridge = root_process_bridge_with_all_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeVmmProcessPort {
                process_ids: Mutex::new(VecDeque::from([Some(71), Some(71)])),
            }),
        );

        let VmmProcessGlobalInspection::Exact(current) = bridge
            .inspect_vmm_gate_successor_exact_after_node_global_sweep(
                &accepted_exact,
                &successor,
                &context,
            )
            .unwrap()
        else {
            panic!("typed Endpoint-only successor must retain the exact physical VMM")
        };
        assert_eq!(current.expectation(), successor.successor());
        assert_eq!(current.evidence(), accepted_exact.evidence());
    }

    #[test]
    fn cid_inventory_rejects_a_vmm_late_before_or_between_fresh_global_scans() {
        for process_ids in [vec![Some(4_242)], vec![None, Some(4_242)]] {
            let environment = TestEnvironment::new();
            let checkpoint = decode_runtime_checkpoint(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
            )))
            .unwrap();
            let expected = VmmProcessExpectation::from_checkpoint(checkpoint)
                .unwrap()
                .with_checkpoint_path(
                    HostPath::new("/var/lib/cats/checkpoints/cat-cat_01.checkpoint.json").unwrap(),
                )
                .unwrap();
            let context = effect_context_with_absent_vmm(&environment, expected);
            let bridge = root_process_bridge_with_all_ports(
                &environment,
                Arc::new(FakeRootProcessPort {
                    inspections: Mutex::new(VecDeque::new()),
                }),
                Arc::new(FakeServingProcessPort {
                    process_ids: Mutex::new(VecDeque::new()),
                }),
                Arc::new(FakeVmmProcessPort {
                    process_ids: Mutex::new(process_ids.into()),
                }),
            );

            let error = VmmCidInventoryPort::inspect(&bridge, &context).unwrap_err();

            assert!(error
                .to_string()
                .contains("VMM CID inventory changed from its admission"));
        }
    }

    #[test]
    fn recoverable_stop_receipt_publication_precedes_another_cats_stable_receipt() {
        let stable = Id::new("cat_a").unwrap();
        let recoverable = Id::new("cat_b").unwrap();
        assert!(matches!(
            next_stop_receipt_recovery(
                std::slice::from_ref(&stable),
                std::slice::from_ref(&recoverable),
            ),
            Some(LocalPublicationRecoveryEvidence::RootProvisionStopReceiptPublication {
                cat_id,
            }) if cat_id == recoverable
        ));
        assert!(matches!(
            next_stop_receipt_recovery(std::slice::from_ref(&stable), &[]),
            Some(LocalPublicationRecoveryEvidence::RootProvisionStopReceipt { cat_id })
                if cat_id == stable
        ));
    }

    #[cfg(target_os = "linux")]
    struct TestUnavailableBlobStore;

    #[cfg(target_os = "linux")]
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

    #[cfg(target_os = "linux")]
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

    struct ExactVolumeSetDataAuthority {
        records: BTreeMap<Id, VolumeRecord>,
    }

    struct SharedVolumeSetDataAuthority {
        records: Arc<Mutex<BTreeMap<Id, VolumeRecord>>>,
    }

    impl VolumeDataAuthority for ExactVolumeSetDataAuthority {
        fn load_volume(
            &self,
            volume_id: &Id,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeRecord> {
            self.records
                .get(volume_id)
                .cloned()
                .ok_or(cats_storage::authority::AuthorityError::NotFound)
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

    impl VolumeDataAuthority for SharedVolumeSetDataAuthority {
        fn load_volume(
            &self,
            volume_id: &Id,
        ) -> cats_storage::authority::Result<cats_storage::authority::VolumeRecord> {
            self.records
                .lock()
                .unwrap()
                .get(volume_id)
                .cloned()
                .ok_or(cats_storage::authority::AuthorityError::NotFound)
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

    #[cfg(target_os = "linux")]
    struct TestUnavailableRuntimeVolumeInventoryAuthority;

    #[cfg(target_os = "linux")]
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
    struct ExactSetMetadataAuthorityReader {
        records: BTreeMap<Id, VolumeRecord>,
    }

    impl metadata_authority_reader_sealed::Sealed for ExactSetMetadataAuthorityReader {}

    impl MetadataAuthorityAbsenceReader for ExactSetMetadataAuthorityReader {
        fn read_candidates(
            &self,
            _node_id: &Id,
            candidate_volume_ids: &BTreeSet<Id>,
            deadline: Instant,
            context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<MetadataAuthorityCandidateInventory> {
            assert_eq!(deadline, context.deadline());
            context.check_active()?;
            Ok(if self.records.keys().eq(candidate_volume_ids.iter()) {
                MetadataAuthorityCandidateInventory::Records(self.records.clone())
            } else {
                MetadataAuthorityCandidateInventory::Unavailable
            })
        }
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
        managed_blockd_socket_root: Arc<RetainedManagedBlockdSocketRoot>,
    }

    impl TestEnvironment {
        fn new() -> Self {
            // Several unrelated process/socket probes still bind temporary
            // Unix listeners. Keep the fixture under /tmp so those synthetic
            // paths remain compact on macOS; the one deliberately deep legacy
            // socket fixture binds a short name before moving the inode.
            // Production blockd paths always come from the installation-owned
            // namespace.
            let canonical_temp = std::fs::canonicalize("/tmp").unwrap();
            let root = tempfile::Builder::new()
                .prefix("c")
                .tempdir_in(canonical_temp)
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
            let managed_blockd_socket_root = Arc::new(
                RetainedManagedBlockdSocketRoot::provision_for_test(
                    &root.path().join("default-managed-blockd-sockets"),
                )
                .unwrap(),
            );
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
                managed_blockd_socket_root,
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
                serving_process_port: None,
                root_provision_systemd: None,
                network_allocation_port: None,
                kernel_nbd_inventory_port: None,
                managed_blockd_socket_root: None,
                blockd_socket_intents: None,
                managed_vmm_socket_root: None,
                #[cfg(target_os = "linux")]
                managed_vmm_launch_root: None,
                vmm_socket_receipts: None,
                recovery_metadata_authority: None,
                recovery_blob_store: None,
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

    fn assigned_context_with_root_and_persistent() -> RuntimeInventoryScanContext {
        let mut context = assigned_context(true);
        let desired = &mut context.coordinates_mut().desired.desired_specs[0];
        desired.volumes.push(VolumeIntent {
            volume_intent_id: Id::new("vint_z_persistent").unwrap(),
            disk_id: Id::new("disk_persistent").unwrap(),
            volume_id: Id::new("vol_persistent").unwrap(),
            attachment_id: Id::new("att_persistent").unwrap(),
            size_bytes: 8_589_934_592,
            disk_kind: DiskKind::Persistent,
            access: VolumeAccess::ReadWriteOnce,
            durability: Durability::Strict,
            guest_device: GuestDeviceIdentity {
                serial: Id::new("cats-persistent").unwrap(),
                slot: 1,
            },
            acquire: VolumeAcquire::Normal {
                transition_id: RandomId128::new("22222222222222222222222222222222").unwrap(),
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
            },
            disposition: VolumeDisposition::Retain,
            mount: Some(Ext4MountIntent {
                filesystem_uuid: RandomId128::new("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").unwrap(),
                mount_path: HostPath::new("/data").unwrap(),
                initialization: FilesystemInitialization::Existing,
            }),
        });
        desired.spec_digest = spec_digest(desired).unwrap();
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
        exact_owned_record_and_attachment_for(desired, 0)
    }

    fn exact_owned_record_and_attachment_for(
        desired: &DesiredRuntimeSpec,
        index: usize,
    ) -> (VolumeRecord, AuthorizedServingAttachment) {
        let volume = &desired.volumes[index];
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
        let mut predecessor = unowned_record(volume.volume_id.as_str(), volume.size_bytes);
        predecessor.durability = volume.durability;
        let (record, result) = cats_storage::authority::normal_acquire(
            &predecessor,
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
            acquire: cats_storage::authority::AuthorizedServingAcquire::Normal { request, result },
        };
        (record, attachment)
    }

    fn prepare_exact_lineage(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) -> PathBuf {
        prepare_exact_lineage_for(environment, desired, 0, attachment)
    }

    fn prepare_exact_lineage_for(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        index: usize,
        attachment: &AuthorizedServingAttachment,
    ) -> PathBuf {
        let prepared =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                .prepare(desired, &desired.volumes[index], attachment)
                .unwrap();
        prepared.data_directory().to_path_buf()
    }

    fn direct_vhost_prepared_device(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        index: usize,
        attachment: &AuthorizedServingAttachment,
        data_directory: &Path,
    ) -> PreparedDeviceInput {
        let volume = &desired.volumes[index];
        let authorization_path = data_directory.join(AUTHORIZED_SERVING_FILE);
        let authorization_bytes = std::fs::read(&authorization_path).unwrap();
        let authorization_metadata = std::fs::metadata(&authorization_path).unwrap();
        let suffix = volume.volume_id.as_str();
        let ownership_token = RandomId128::new(format!("{:032x}", index + 1)).unwrap();
        let (control_socket_path, io_socket_path) = managed_serving_sockets(&ownership_token);
        PreparedDeviceInput {
            volume_intent_id: volume.volume_intent_id.clone(),
            disk_id: volume.disk_id.clone(),
            volume_id: volume.volume_id.clone(),
            disk_kind: volume.disk_kind,
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            expected_head: attachment.head.clone(),
            size_bytes: attachment.size_bytes,
            durability: attachment.durability,
            guest_device: volume.guest_device.clone(),
            ownership_token,
            serving_authority: Box::new(ServingAuthorityProvenance::DirectAuthorizedAttachment {
                authorization: DirectAuthorizedAttachmentIdentity {
                    path: HostPath::new(authorization_path.to_string_lossy().into_owned()).unwrap(),
                    device: WireU64::new(authorization_metadata.dev()).unwrap(),
                    inode: WireU64::new(authorization_metadata.ino()).unwrap(),
                    length: WireU64::new(authorization_metadata.len()).unwrap(),
                    content_sha256: Sha256Digest::from_bytes(
                        Sha256::digest(authorization_bytes).into(),
                    ),
                },
                purpose: match volume.disk_kind {
                    DiskKind::Root => DirectAuthorizedAttachmentPurpose::ExistingRoot,
                    DiskKind::Persistent
                        if volume.mount.as_ref().is_some_and(|mount| {
                            matches!(
                                mount.initialization,
                                FilesystemInitialization::Initialize { .. }
                            )
                        }) =>
                    {
                        DirectAuthorizedAttachmentPurpose::PersistentUninitialized
                    }
                    DiskKind::Persistent => {
                        DirectAuthorizedAttachmentPurpose::PersistentInitialized
                    }
                },
            }),
            serving_process: ServingBlockdIdentity {
                scope_id: Id::new(format!("cats-blockd-{suffix}.service")).unwrap(),
                control_socket_path,
                data_directory: HostPath::new(data_directory.to_string_lossy().into_owned())
                    .unwrap(),
                executable_path: HostPath::new(
                    environment.blockd_binary.to_string_lossy().into_owned(),
                )
                .unwrap(),
                process_identity_token: RandomId128::new(format!("{:032x}", index + 101)).unwrap(),
            },
            frontend: PrepareDeviceFrontend::VhostUserBlk {
                socket_path: io_socket_path,
                queues: 1,
                queue_size: 256,
            },
        }
    }

    struct FakeRootProcessPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
    }

    struct FakeServingProcessPort {
        process_ids: Mutex<VecDeque<Option<u32>>>,
    }

    struct FakeVmmProcessPort {
        process_ids: Mutex<VecDeque<Option<u32>>>,
    }

    #[derive(Debug, Clone, Copy)]
    enum ScriptedVmmInspection {
        Absent,
        Exact(ProcessState),
        Unavailable,
    }

    struct ScriptedVmmProcessPort {
        inspections: Mutex<VecDeque<ScriptedVmmInspection>>,
        cancel_after_first: Option<RuntimeInventoryScanContext>,
        calls: AtomicUsize,
    }

    impl super::super::vmm_process::VmmProcessPortSealedForTest for FakeVmmProcessPort {}

    impl VmmProcessPort for FakeVmmProcessPort {
        fn inspect(
            &self,
            expected: &VmmProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<VmmProcessInspection> {
            Ok(
                match self
                    .process_ids
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("fake VMM inspection exhausted")
                {
                    Some(process_id) => VmmProcessInspection::Exact(Box::new(
                        expected.exact_evidence_for_test(process_id),
                    )),
                    None => VmmProcessInspection::Absent,
                },
            )
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::vmm_process::CheckpointedVmmProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessStart> {
            unreachable!("inventory fake is read-only")
        }
    }

    impl super::super::vmm_process::VmmProcessPortSealedForTest for ScriptedVmmProcessPort {}

    impl VmmProcessPort for ScriptedVmmProcessPort {
        fn inspect(
            &self,
            expected: &VmmProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<VmmProcessInspection> {
            let inspection = match self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .expect("scripted VMM inspection exhausted")
            {
                ScriptedVmmInspection::Absent => VmmProcessInspection::Absent,
                ScriptedVmmInspection::Exact(state) => VmmProcessInspection::Exact(Box::new(
                    expected.exact_evidence_with_state_for_test(101, state),
                )),
                ScriptedVmmInspection::Unavailable => VmmProcessInspection::Unavailable,
            };
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                if let Some(context) = &self.cancel_after_first {
                    context.cancel_for_test();
                }
            }
            Ok(inspection)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::vmm_process::CheckpointedVmmProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessStart> {
            unreachable!("inventory fake is read-only")
        }
    }

    struct ExactRunningProcessBridge {
        state_directory: StateDirectory,
        systemd: RootProvisionSystemdConfig,
        executable_path: HostPath,
        exact_vmm_state: Option<ProcessState>,
    }

    impl root_process_inventory_bridge_sealed::Sealed for ExactRunningProcessBridge {}

    impl RootProcessInventoryBridge for ExactRunningProcessBridge {
        fn executable_path(&self) -> &HostPath {
            &self.executable_path
        }

        fn serving_expectation(
            &self,
            checkpoint: &RuntimeCheckpoint,
            physical_desired: &DesiredRuntimeSpec,
            gate_desired: &DesiredRuntimeSpec,
            prepared: &PreparedDeviceInput,
            blockd: &AuthorizedBlockdInventoryEvidence,
            authority: &VolumeRecord,
        ) -> anyhow::Result<ServingBlockdExpectation> {
            ServingBlockdExpectation::from_inventory_running(
                &self.state_directory,
                &self.systemd,
                checkpoint,
                physical_desired,
                gate_desired,
                prepared,
                blockd,
                authority,
            )
        }

        fn inspect_all(
            &self,
            root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
            serving_expected: BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
            vmm_expected: BTreeMap<Id, VmmProcessExpectation>,
            stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
            let serving_exact = serving_expected
                .iter()
                .enumerate()
                .map(|(index, (key, expectation))| {
                    let process_id = u32::try_from(index)
                        .ok()
                        .and_then(|index| 81_u32.checked_add(index))
                        .context("test serving process ID overflow")?;
                    Ok((
                        key.clone(),
                        expectation
                            .clone()
                            .prove_exact_process(expectation.exact_evidence_for_test(process_id))?,
                    ))
                })
                .collect::<anyhow::Result<BTreeMap<_, _>>>()?;
            let vmm_exact = if let Some(state) = self.exact_vmm_state {
                vmm_expected
                    .iter()
                    .enumerate()
                    .map(|(index, (cat_id, expectation))| {
                        let process_id = u32::try_from(index)
                            .ok()
                            .and_then(|index| 101_u32.checked_add(index))
                            .context("test VMM process ID overflow")?;
                        Ok((
                            cat_id.clone(),
                            expectation.clone().prove_exact_process(
                                expectation.exact_evidence_with_state_for_test(process_id, state),
                            )?,
                        ))
                    })
                    .collect::<anyhow::Result<BTreeMap<_, _>>>()?
            } else {
                BTreeMap::new()
            };
            let admission = NodeGlobalManagedProcessScanAdmission::from_root_controls(
                root_expected,
                BTreeMap::new(),
            )?
            .with_serving_blockds(serving_expected, serving_exact)?
            .with_vmms(vmm_expected, vmm_exact)?
            .with_stop_receipt_sockets(stop_receipt_sockets)?;
            Ok(RootProcessInventoryBridgeOutcome::Complete(admission))
        }
    }

    struct PreservedNegativeUnavailableProcessBridge {
        inner: ExactRunningProcessBridge,
        exact_running_negative_cats: BTreeSet<Id>,
    }

    impl root_process_inventory_bridge_sealed::Sealed for PreservedNegativeUnavailableProcessBridge {}

    impl RootProcessInventoryBridge for PreservedNegativeUnavailableProcessBridge {
        fn executable_path(&self) -> &HostPath {
            self.inner.executable_path()
        }

        fn serving_expectation(
            &self,
            checkpoint: &RuntimeCheckpoint,
            physical_desired: &DesiredRuntimeSpec,
            gate_desired: &DesiredRuntimeSpec,
            prepared: &PreparedDeviceInput,
            blockd: &AuthorizedBlockdInventoryEvidence,
            authority: &VolumeRecord,
        ) -> anyhow::Result<ServingBlockdExpectation> {
            self.inner.serving_expectation(
                checkpoint,
                physical_desired,
                gate_desired,
                prepared,
                blockd,
                authority,
            )
        }

        fn inspect_all(
            &self,
            _root_expected: BTreeMap<Id, RootProvisionProcessExpectation>,
            _serving_expected: BTreeMap<ManagedServingKey, ServingBlockdExpectation>,
            _vmm_expected: BTreeMap<Id, VmmProcessExpectation>,
            _stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
            Ok(RootProcessInventoryBridgeOutcome::Unavailable {
                exact_running_negative_cats: self.exact_running_negative_cats.clone(),
            })
        }
    }

    /// Test provider that repeats the exact accepted process set through the
    /// production revalidation ports. It deliberately does not reconstruct
    /// evidence from public observation fields.
    struct AcceptedRunningProcessPort;

    impl super::super::serving_blockd_process::process_sealed::Sealed for AcceptedRunningProcessPort {}

    impl super::super::serving_blockd_process::global_sealed::Sealed for AcceptedRunningProcessPort {}

    impl super::super::serving_blockd_process::ServingBlockdProcessPort for AcceptedRunningProcessPort {
        fn inspect(
            &self,
            _expected: &ServingBlockdExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<super::super::serving_blockd_process::ServingBlockdProcessInspection>
        {
            anyhow::bail!("accepted-full test port only supports the global sweep")
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::serving_blockd_process::CheckpointedServingBlockdProcess<
                '_,
            >,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::serving_blockd_process::ServingBlockdProcessStart>
        {
            anyhow::bail!("accepted-full test port is read-only")
        }
    }

    impl super::super::serving_blockd_process::ServingBlockdProcessGlobalPort
        for AcceptedRunningProcessPort
    {
        fn inspect_serving_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &ServingBlockdExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::serving_blockd_process::ServingBlockdProcessInspection>
        {
            let (_, exact) = context
                .node_global_process()?
                .serving_blockd(expected.cat_id(), expected.volume_id())
                .context("accepted full set lacks the retained serving process")?;
            let exact = exact.context("accepted serving process is not exact")?;
            Ok(
                super::super::serving_blockd_process::ServingBlockdProcessInspection::Exact(
                    Box::new(exact.evidence().clone()),
                ),
            )
        }
    }

    impl super::super::vmm_process::sealed::Sealed for AcceptedRunningProcessPort {}
    impl super::super::vmm_process::global_sealed::Sealed for AcceptedRunningProcessPort {}

    impl super::super::vmm_process::VmmProcessPort for AcceptedRunningProcessPort {
        fn inspect(
            &self,
            _expected: &VmmProcessExpectation,
            _context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessInspection> {
            anyhow::bail!("accepted-full test port only supports the global sweep")
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::vmm_process::CheckpointedVmmProcess<'_>,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessStart> {
            anyhow::bail!("accepted-full test port is read-only")
        }
    }

    impl super::super::vmm_process::VmmProcessGlobalPort for AcceptedRunningProcessPort {
        fn inspect_vmm_exact_or_absent_after_node_global_sweep(
            &self,
            expected: &VmmProcessExpectation,
            context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessGlobalInspection> {
            let (_, exact) = context
                .node_global_process()?
                .vmm(expected.cat_id())
                .context("accepted full set lacks the retained VMM")?;
            let exact = exact.context("accepted VMM is not exact")?;
            Ok(
                super::super::vmm_process::VmmProcessGlobalInspection::Exact(Box::new(
                    exact.clone(),
                )),
            )
        }

        fn inspect_vmm_gate_successor_exact_after_node_global_sweep(
            &self,
            admitted_predecessor: &super::super::vmm_process::ExactVmmProcessProof,
            successor: &super::super::vmm_process::VmmGateSuccessorProof,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::vmm_process::VmmProcessGlobalInspection> {
            Ok(
                super::super::vmm_process::VmmProcessGlobalInspection::Exact(Box::new(
                    successor
                        .successor()
                        .clone()
                        .prove_exact_process(admitted_predecessor.evidence().clone())?,
                )),
            )
        }
    }

    struct ScriptedPersistentGuest {
        formatted: AtomicBool,
        lose_first_format_response: AtomicBool,
        operations: Arc<Mutex<Vec<(FilesystemControlOperationV1, Id, RemoteHead)>>>,
    }

    impl ScriptedPersistentGuest {
        fn response(
            request: FilesystemControlRequestV1,
            filesystem: FilesystemIdentityV1,
            mounted: bool,
        ) -> FilesystemControlResponseV1 {
            let mounts = mounted
                .then(|| PersistentFilesystemMountV1 {
                    device_major: 252,
                    device_minor: u32::from(request.filesystem.guest_device.slot),
                    source_path: HostPath::new("/dev/vdb").unwrap(),
                    mount_root: HostPath::new("/").unwrap(),
                    mount_path: request.filesystem.mount_path.clone(),
                    filesystem_type: Id::new("ext4").unwrap(),
                    access: MountAccess::ReadWrite,
                })
                .into_iter()
                .collect();
            FilesystemControlResponseV1 {
                version: request.version,
                request: Box::new(request.clone()),
                outcome: FilesystemControlOutcomeV1::Exact,
                observation: PersistentFilesystemObservationV1 {
                    guest_device: request.filesystem.guest_device.clone(),
                    device_path: HostPath::new("/dev/vdb").unwrap(),
                    device_major: 252,
                    device_minor: u32::from(request.filesystem.guest_device.slot),
                    size_bytes: request.filesystem.size_bytes,
                    filesystem,
                    mounts,
                },
            }
        }
    }

    impl super::super::persistent_filesystem::PersistentFilesystemGuestPort
        for ScriptedPersistentGuest
    {
        fn control(
            &self,
            _context: &dyn RuntimePhysicalReadContext,
            _launch: &cats_api::runtime_reconciliation::RuntimeLaunchIdentity,
            _vmm: &super::super::vmm_process::ExactVmmProcessProof,
            request: FilesystemControlRequestV1,
        ) -> anyhow::Result<FilesystemControlResponseV1> {
            self.operations.lock().unwrap().push((
                request.operation,
                request.filesystem.volume_id.clone(),
                request.expected_head.clone(),
            ));
            match request.operation {
                FilesystemControlOperationV1::Probe if !self.formatted.load(Ordering::SeqCst) => {
                    Ok(Self::response(request, FilesystemIdentityV1::Blank, false))
                }
                FilesystemControlOperationV1::FormatExt4 => {
                    self.formatted.store(true, Ordering::SeqCst);
                    if self
                        .lose_first_format_response
                        .swap(false, Ordering::SeqCst)
                    {
                        anyhow::bail!("injected mkfs response loss")
                    }
                    let filesystem_uuid = request.filesystem.filesystem_uuid.clone();
                    Ok(Self::response(
                        request,
                        FilesystemIdentityV1::Ext4 { filesystem_uuid },
                        false,
                    ))
                }
                FilesystemControlOperationV1::Probe | FilesystemControlOperationV1::FlushDevice => {
                    let filesystem_uuid = request.filesystem.filesystem_uuid.clone();
                    Ok(Self::response(
                        request,
                        FilesystemIdentityV1::Ext4 { filesystem_uuid },
                        false,
                    ))
                }
                FilesystemControlOperationV1::MountExt4 => {
                    let filesystem_uuid = request.filesystem.filesystem_uuid.clone();
                    Ok(Self::response(
                        request,
                        FilesystemIdentityV1::Ext4 { filesystem_uuid },
                        true,
                    ))
                }
            }
        }
    }

    struct AdvancingRelaxedBlockd {
        records: Arc<Mutex<BTreeMap<Id, VolumeRecord>>>,
        volume_id: Id,
        initialized_head: RemoteHead,
        drains: Arc<AtomicUsize>,
    }

    impl AdvancingRelaxedBlockd {
        fn status_for(
            &self,
            serving: &super::super::serving_blockd_process::ExactServingBlockdProcessProof,
        ) -> cats_api::blockd::DurabilityStatus {
            let current = self.records.lock().unwrap()[&self.volume_id].clone();
            let mut status = serving.durability_status().clone();
            let generation = i64::try_from(current.head.generation.get()).unwrap();
            status.remote_head = Some(current.head);
            status.remote_durable_generation = generation;
            if generation == 0 {
                status.local_durable_generation = 1;
                status.unpublished_generations = 1;
                status.unpublished_bytes = 4_096;
                status.oldest_unpublished_age_ms = 1;
            } else {
                status.local_durable_generation = generation;
                status.unpublished_generations = 0;
                status.unpublished_bytes = 0;
                status.oldest_unpublished_age_ms = 0;
            }
            status
        }
    }

    impl super::super::persistent_filesystem::PersistentBlockdControlPort for AdvancingRelaxedBlockd {
        fn status(
            &self,
            _context: &dyn RuntimePhysicalReadContext,
            serving: &super::super::serving_blockd_process::ExactServingBlockdProcessProof,
        ) -> anyhow::Result<cats_api::blockd::DurabilityStatus> {
            Ok(self.status_for(serving))
        }

        fn drain(
            &self,
            _context: &dyn RuntimePhysicalReadContext,
            serving: &super::super::serving_blockd_process::ExactServingBlockdProcessProof,
        ) -> anyhow::Result<cats_api::blockd::DurabilityStatus> {
            self.drains.fetch_add(1, Ordering::SeqCst);
            self.records
                .lock()
                .unwrap()
                .get_mut(&self.volume_id)
                .unwrap()
                .head = self.initialized_head.clone();
            Ok(self.status_for(serving))
        }
    }

    struct CommitInitializedPort {
        calls: Arc<AtomicUsize>,
    }

    impl super::super::signed_running::SignedNormalAcquirePort for CommitInitializedPort {
        fn acquire(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &super::super::NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<super::super::NormalAcquireAttempt, super::super::NormalAcquireClientError>
        {
            unreachable!("filesystem test never acquires a volume")
        }

        fn release(
            &self,
            _request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _expected_head: &RemoteHead,
            _accepted: &super::super::NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<super::super::NormalReleaseAttempt, super::super::NormalAcquireClientError>
        {
            unreachable!("filesystem test never releases a volume")
        }

        fn commit_initialized(
            &self,
            request: &RuntimeVolumeTransitionRequest,
            _volume: &VolumeIntent,
            _accepted: &super::super::NormalAcquireAcceptedContext,
            _deadline: Instant,
        ) -> Result<super::super::CommitInitializedAttempt, super::super::NormalAcquireClientError>
        {
            let RuntimeVolumeTransition::CommitInitialized {
                filesystem,
                new_remote_head,
            } = &request.transition
            else {
                return Err(super::super::NormalAcquireClientError::InvalidVolumeBinding);
            };
            let FilesystemInitialization::Initialize {
                initialization_token,
                expected_blank_head,
            } = &filesystem.initialization
            else {
                return Err(super::super::NormalAcquireClientError::InvalidVolumeBinding);
            };
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(super::super::CommitInitializedAttempt::Committed(Box::new(
                PersistentInitializationReceipt {
                    disk_id: filesystem.disk_id.clone(),
                    volume_id: filesystem.volume_id.clone(),
                    initialization_token: initialization_token.clone(),
                    filesystem_uuid: filesystem.filesystem_uuid.clone(),
                    expected_blank_head: expected_blank_head.clone(),
                    initialized_head: new_remote_head.clone(),
                    initialized_at: UnixMillis::new(20_000).unwrap(),
                },
            )))
        }
    }

    fn bind_inventory_for_running_effect(
        mut inventory: crate::runtime_spine::CompleteRuntimeInventory,
        scan_context: &RuntimeInventoryScanContext,
        state_directory: StateDirectory,
    ) -> RuntimeDesiredEffectContext {
        let process_scan = inventory
            .take_node_global_process_admission()
            .expect("filesystem scan lacks its sealed process authority");
        let network_scan = inventory
            .take_node_global_network_admission()
            .expect("filesystem scan lacks its sealed network authority");
        let kernel_nbd_scan = inventory.take_kernel_nbd_pool_admission();
        let coordinates = scan_context.coordinates().clone();
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("dadadadadadadadadadadadadadadada").unwrap(),
            node_id: coordinates.session.node_id.clone(),
            node_boot_id: coordinates.session.node_boot_id.clone(),
            agent_instance_id: coordinates.session.agent_instance_id.clone(),
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        let process = process_scan.bind(&observation).unwrap();
        let network = network_scan.bind(&observation).unwrap();
        let kernel_nbd = kernel_nbd_scan.map(|scan| scan.bind(&observation).unwrap());
        let desired = coordinates
            .desired
            .desired_specs
            .iter()
            .find(|desired| desired.cat_id == observation.runtimes[0].cat_id)
            .unwrap();
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            immutable_host_id: Id::new("host_test").unwrap(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            registration_attempt_id: RandomId128::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: UnixMillis::new(observation.observed_at_unix_ms.get() + 60_000)
                .unwrap(),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation.inventory_digest.clone().unwrap(),
            inventory_read_position: observation.inventory_read_position.unwrap(),
            accepted_at_unix_ms: UnixMillis::new(observation.observed_at_unix_ms.get() + 1)
                .unwrap(),
        };
        let admission = RuntimeDesiredEffectAdmission::for_test(session, observation, attestation)
            .bind_assigned_cats_for_test(&coordinates.desired);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            state_directory,
            Instant::now() + Duration::from_secs(5),
            admission,
        )
        .with_node_global_process_for_test(process)
        .with_node_global_network_for_test(network);
        match kernel_nbd {
            Some(kernel_nbd) => context.with_kernel_nbd_pool_for_test(kernel_nbd),
            None => context,
        }
    }

    fn exact_running_ip_binary(directory: &Path, checkpoint: &RuntimeCheckpoint) -> PathBuf {
        let launch = checkpoint
            .runtime_launch
            .identity()
            .expect("exact Running checkpoint retains a launch");
        let network = launch.network.as_ref();
        let alias = format!(
            "cats-network:{}:{}",
            network.network_config.network_id, network.ownership_token
        );
        let links = format!(
            r#"[{{"ifindex":17,"ifname":"{}","flags":["UP"],"ifalias":"{}","linkinfo":{{"info_kind":"tun","info_data":{{"type":"tap"}}}}}}]"#,
            network.tap_name, alias
        );
        let addresses = format!(
            r#"[{{"ifindex":17,"ifname":"{}","addr_info":[{{"family":"inet","local":"{}","prefixlen":{}}}]}}]"#,
            network.tap_name,
            network.network_config.gateway_ipv4,
            network.network_config.prefix_length
        );
        let path = directory.join("test-ip-running-exact");
        std::fs::write(
            &path,
            format!(
                "#!/bin/sh\nif [ \"$2\" = '-d' ]; then printf '%s' '{links}'; else printf '%s' '{addresses}'; fi\n"
            ),
        )
        .unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    struct ExactRunningNetworkBridge;

    struct UnavailableRunningNetworkBridge;

    impl network_inventory_bridge_sealed::Sealed for ExactRunningNetworkBridge {}
    impl network_inventory_bridge_sealed::Sealed for UnavailableRunningNetworkBridge {}

    impl NetworkInventoryBridge for ExactRunningNetworkBridge {
        fn inspect_all(
            &self,
            checkpoints: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<NetworkInventoryBridgeOutcome> {
            anyhow::ensure!(
                checkpoints.len() == 1,
                "test network bridge requires one checkpoint"
            );
            let checkpoint = checkpoints
                .values()
                .next()
                .context("test network bridge checkpoint disappeared")?;
            Ok(NetworkInventoryBridgeOutcome::Complete(
                NodeGlobalNetworkScanAdmission::exact_checkpoint_for_test(&checkpoint.checkpoint)?,
            ))
        }
    }

    impl NetworkInventoryBridge for UnavailableRunningNetworkBridge {
        fn inspect_all(
            &self,
            _checkpoints: &BTreeMap<Id, RuntimeCheckpointInventoryEvidence>,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<NetworkInventoryBridgeOutcome> {
            Ok(NetworkInventoryBridgeOutcome::Unavailable)
        }
    }

    struct ExactRunningGuestReadyPort {
        calls: Arc<AtomicUsize>,
        fault: RunningGuestReadyFault,
    }

    #[derive(Debug, Clone, Copy)]
    enum RunningGuestReadyFault {
        Exact,
        MissingPersistent,
        DuplicateRootMount,
        ForeignPersistentUuid,
    }

    impl super::super::GuestReadyTransportPort for ExactRunningGuestReadyPort {
        fn challenge(
            &self,
            _context: &dyn RuntimePhysicalReadContext,
            launch: &cats_api::runtime_reconciliation::RuntimeLaunchIdentity,
            request: RuntimeReadyRequestV1,
        ) -> anyhow::Result<RuntimeReadyResponseV1> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let devices = launch
                .devices
                .iter()
                .map(|prepared| {
                    let suffix =
                        char::from_u32(u32::from(b'a') + u32::from(prepared.guest_device.slot))
                            .context("test Guest slot does not form a device suffix")?;
                    Ok(RuntimeReadyDeviceV1 {
                        guest_device: prepared.guest_device.clone(),
                        device_path: HostPath::new(format!("/dev/vd{suffix}"))
                            .context("test Guest device path")?,
                        device_major: 252,
                        device_minor: u32::from(prepared.guest_device.slot),
                        size_bytes: prepared.size_bytes,
                        filesystem_uuid: RandomId128::new(match prepared.guest_device.slot {
                            0 => "dddddddddddddddddddddddddddddddd",
                            1 => "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
                            2 => "ffffffffffffffffffffffffffffffff",
                            _ => anyhow::bail!("test Guest fixture supports slots 0 through 2"),
                        })
                        .context("test filesystem UUID")?,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mounts = devices
                .iter()
                .map(|device| {
                    Ok(RuntimeReadyMountV1 {
                        device_major: device.device_major,
                        device_minor: device.device_minor,
                        source_path: device.device_path.clone(),
                        filesystem_uuid: device.filesystem_uuid.clone(),
                        mount_root: HostPath::new("/").expect("canonical mount root"),
                        mount_path: HostPath::new(match device.guest_device.slot {
                            0 => "/",
                            1 => "/data",
                            2 => "/logs",
                            _ => anyhow::bail!("test Guest fixture supports slots 0 through 2"),
                        })
                        .expect("canonical test mount path"),
                        filesystem_type: Id::new("ext4").expect("filesystem ID"),
                        access: MountAccess::ReadWrite,
                    })
                })
                .collect::<anyhow::Result<Vec<_>>>()?;
            let mut response = RuntimeReadyResponseV1 {
                version: request.version,
                challenge: request.challenge,
                runtime_incarnation: request.runtime_incarnation,
                expected_guest_cid: request.expected_guest_cid,
                expected_guest_port: request.expected_guest_port,
                expected_guest_agent_protocol_version: request
                    .expected_guest_agent_protocol_version,
                actual_guest_cid: launch.guest_cid,
                actual_guest_port: request.expected_guest_port,
                actual_guest_agent_protocol_version: request.expected_guest_agent_protocol_version,
                guest_boot_id: GuestBootId::new("11111111222233334444555555555555")
                    .context("test Guest boot ID")?,
                devices,
                mounts,
            };
            match self.fault {
                RunningGuestReadyFault::Exact => {}
                RunningGuestReadyFault::MissingPersistent => {
                    anyhow::ensure!(response.mounts.len() > 1, "fault needs Persistent mount");
                    response.mounts.pop();
                }
                RunningGuestReadyFault::DuplicateRootMount => {
                    anyhow::ensure!(response.mounts.len() > 1, "fault needs Persistent mount");
                    response.mounts[1] = response.mounts[0].clone();
                }
                RunningGuestReadyFault::ForeignPersistentUuid => {
                    anyhow::ensure!(response.mounts.len() > 1, "fault needs Persistent mount");
                    let foreign = RandomId128::new("cccccccccccccccccccccccccccccccc")
                        .context("foreign test filesystem UUID")?;
                    response.devices[1].filesystem_uuid = foreign.clone();
                    response.mounts[1].filesystem_uuid = foreign;
                }
            }
            Ok(response)
        }
    }

    struct LaunchOrderedGuestReadyPort {
        launch_revalidated: Arc<AtomicBool>,
        prepared_checkpoint_path: PathBuf,
        inner: ExactRunningGuestReadyPort,
    }

    impl super::super::GuestReadyTransportPort for LaunchOrderedGuestReadyPort {
        fn challenge(
            &self,
            context: &dyn RuntimePhysicalReadContext,
            launch: &cats_api::runtime_reconciliation::RuntimeLaunchIdentity,
            request: RuntimeReadyRequestV1,
        ) -> anyhow::Result<RuntimeReadyResponseV1> {
            anyhow::ensure!(
                self.launch_revalidated.load(Ordering::SeqCst),
                "Guest mounted-set challenge preceded Host authority revalidation"
            );
            let prepared = decode_runtime_checkpoint(
                &std::fs::read(&self.prepared_checkpoint_path)
                    .context("read prepared admission checkpoint")?,
            )
            .context("decode prepared admission checkpoint")?;
            anyhow::ensure!(
                matches!(
                    prepared.step,
                    ReconcileStep::Stable {
                        state: cats_api::runtime_reconciliation::StableState::Running
                    }
                ) && prepared.lifecycle_admission == LifecycleAdmission::Open,
                "Guest mounted-set challenge preceded the durable Stable/Open successor"
            );
            self.inner.challenge(context, launch, request)
        }
    }

    impl serving_process_sealed::Sealed for FakeServingProcessPort {}

    impl ServingBlockdProcessPort for FakeServingProcessPort {
        fn inspect(
            &self,
            expected: &ServingBlockdExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<ServingBlockdProcessInspection> {
            Ok(
                match self
                    .process_ids
                    .lock()
                    .unwrap()
                    .pop_front()
                    .expect("fake serving-process inspection exhausted")
                {
                    Some(process_id) => ServingBlockdProcessInspection::Exact(Box::new(
                        expected.exact_evidence_for_test(process_id),
                    )),
                    None => ServingBlockdProcessInspection::Absent,
                },
            )
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::serving_blockd_process::CheckpointedServingBlockdProcess<
                '_,
            >,
            _context: &crate::runtime_spine::RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::serving_blockd_process::ServingBlockdProcessStart>
        {
            unreachable!("inventory fake is read-only")
        }
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

    struct CancellingRootProcessPort {
        inspections: Mutex<VecDeque<RootProvisionProcessInspection>>,
        calls: AtomicUsize,
        cancel_after: usize,
        context: RuntimeDesiredEffectContext,
    }

    impl super::super::root_provision_process::sealed::Sealed for CancellingRootProcessPort {}

    impl RootProvisionProcessPort for CancellingRootProcessPort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            context: &dyn crate::runtime_spine::RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            context.check_active()?;
            let call = self.calls.fetch_add(1, Ordering::SeqCst) + 1;
            let inspection = self
                .inspections
                .lock()
                .unwrap()
                .pop_front()
                .context("cancelling root-process inspection exhausted")?;
            if call == self.cancel_after {
                self.context.cancel_for_test();
            }
            Ok(inspection)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::root_provision_process::CheckpointedRootProvisionProcess<
                '_,
            >,
            _context: &crate::runtime_spine::RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::root_provision_process::RootProvisionProcessStart>
        {
            unreachable!("global allowlist tests never start a process")
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
                request: attachment.checkpoint_acquire_request(),
            },
            cats_api::runtime_reconciliation::UnixMillis::new(9_000).unwrap(),
        );
        let token = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let provision_transition_id = RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let scope_id = Id::new("cats-root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service").unwrap();
        let data = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
        checkpoint.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: provision_transition_id.clone(),
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            scope_id,
            control_socket_path: managed_root_control_socket(&provision_transition_id),
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

    fn second_root_process_expectation(
        environment: &TestEnvironment,
        first: &RootProvisionProcessExpectation,
    ) -> RootProvisionProcessExpectation {
        let mut second = first.clone();
        second.cat_id = Id::new("cat_02").unwrap();
        second.scope_id = Id::new("cats-root-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.service").unwrap();
        second.cgroup_path = HostPath::new(
            environment
                .systemd_root
                .join(second.scope_id.as_str())
                .to_string_lossy()
                .into_owned(),
        )
        .unwrap();
        let data_directory = environment
            .state
            .join(DATA_NAMESPACE)
            .join("second-control");
        std::fs::create_dir_all(&data_directory).unwrap();
        second.data_directory =
            HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
        second.provision_transition_id =
            RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        second.control_socket_path = managed_root_control_socket(&second.provision_transition_id);
        second.process_identity_token =
            RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        second
    }

    fn root_process_bridge(
        environment: &TestEnvironment,
        inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
    ) -> PlatformRootProcessInventoryBridge {
        root_process_bridge_with_port(
            environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(inspections.into_iter().collect()),
            }),
        )
    }

    fn root_process_bridge_with_port(
        environment: &TestEnvironment,
        port: Arc<dyn RootProvisionProcessPort>,
    ) -> PlatformRootProcessInventoryBridge {
        root_process_bridge_with_ports(
            environment,
            port,
            Arc::new(PlatformSystemdServingBlockdProcessPort::platform(
                StateDirectory::unanchored(environment.state.clone()),
                Arc::clone(&environment.managed_blockd_socket_root),
            )),
        )
    }

    fn root_process_bridge_with_ports(
        environment: &TestEnvironment,
        port: Arc<dyn RootProvisionProcessPort>,
        serving_port: Arc<dyn ServingBlockdProcessPort>,
    ) -> PlatformRootProcessInventoryBridge {
        root_process_bridge_with_all_ports(
            environment,
            port,
            serving_port,
            Arc::new(PlatformSystemdVmmProcessPort),
        )
    }

    fn root_process_bridge_with_all_ports(
        environment: &TestEnvironment,
        port: Arc<dyn RootProvisionProcessPort>,
        serving_port: Arc<dyn ServingBlockdProcessPort>,
        vmm_port: Arc<dyn VmmProcessPort>,
    ) -> PlatformRootProcessInventoryBridge {
        PlatformRootProcessInventoryBridge {
            port,
            serving_port,
            vmm_port,
            root_provision_systemd: test_root_provision_systemd(&environment.blockd_binary),
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
            managed_blockd_socket_root: None,
            blockd_socket_intents: None,
            managed_vmm_socket_root: None,
            #[cfg(target_os = "linux")]
            managed_vmm_launch_root: None,
            vmm_socket_receipts: None,
            recovery_metadata_authority: None,
            recovery_blob_store: None,
        }
    }

    fn test_root_provision_systemd(blockd_binary: &Path) -> RootProvisionSystemdConfig {
        RootProvisionSystemdConfig::new(super::super::AuthorizedBlockdLaunchConfig {
            blockd_binary: blockd_binary.to_path_buf(),
            metadata_store: AdapterSelection::new(
                "postgres",
                AdapterConfig::from_pairs([("url-file", "/run/cats/postgres.url")]).unwrap(),
            ),
            object_store: AdapterSelection::new(
                "aws-s3",
                AdapterConfig::from_pairs([("bucket", "cats-test")]).unwrap(),
            ),
            max_staged_bytes: 1,
            max_staged_packs: 1,
            max_local_bytes: 4_194_304,
        })
        .unwrap()
    }

    fn effect_context_with_root_controls(
        environment: &TestEnvironment,
        entries: impl IntoIterator<
            Item = (
                RootProvisionProcessExpectation,
                Option<super::super::root_provision_process::RootProvisionProcessEvidence>,
            ),
        >,
    ) -> RuntimeDesiredEffectContext {
        let mut expected = BTreeMap::new();
        let mut exact = BTreeMap::new();
        for (expectation, evidence) in entries {
            let cat_id = expectation.cat_id.clone();
            if let Some(evidence) = evidence {
                exact.insert(
                    cat_id.clone(),
                    expectation.clone().prove_exact_process(evidence).unwrap(),
                );
            }
            expected.insert(cat_id, expectation);
        }
        let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(expected, exact)
            .unwrap()
            .into_admission_for_test();
        RuntimeDesiredEffectContext::for_test_with_node_global_process(
            StateDirectory::unanchored(environment.state.clone()),
            Instant::now() + Duration::from_secs(5),
            admission,
        )
    }

    fn effect_context_with_managed_processes(
        environment: &TestEnvironment,
        root_entries: impl IntoIterator<
            Item = (
                RootProvisionProcessExpectation,
                Option<super::super::root_provision_process::RootProvisionProcessEvidence>,
            ),
        >,
        serving_entries: impl IntoIterator<Item = (ServingBlockdExpectation, Option<u32>)>,
        stop_receipt_sockets: BTreeMap<Id, StopReceiptSocketAdmission>,
    ) -> RuntimeDesiredEffectContext {
        let mut root_expected = BTreeMap::new();
        let mut root_exact = BTreeMap::new();
        for (expectation, evidence) in root_entries {
            let cat_id = expectation.cat_id.clone();
            if let Some(evidence) = evidence {
                root_exact.insert(
                    cat_id.clone(),
                    expectation.clone().prove_exact_process(evidence).unwrap(),
                );
            }
            root_expected.insert(cat_id, expectation);
        }
        let mut serving_expected = BTreeMap::new();
        let mut serving_exact = BTreeMap::new();
        for (expectation, process_id) in serving_entries {
            let key = ManagedServingKey::new(
                expectation.cat_id().clone(),
                expectation.volume_id().clone(),
            );
            if let Some(process_id) = process_id {
                serving_exact.insert(
                    key.clone(),
                    expectation
                        .clone()
                        .prove_exact_process(expectation.exact_evidence_for_test(process_id))
                        .unwrap(),
                );
            }
            serving_expected.insert(key, expectation);
        }
        let admission = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            root_expected,
            root_exact,
        )
        .unwrap()
        .with_serving_blockds(serving_expected, serving_exact)
        .unwrap()
        .with_stop_receipt_sockets(stop_receipt_sockets)
        .unwrap()
        .into_admission_for_test();
        RuntimeDesiredEffectContext::for_test_with_node_global_process(
            StateDirectory::unanchored(environment.state.clone()),
            Instant::now() + Duration::from_secs(5),
            admission,
        )
    }

    fn effect_context_with_absent_vmm(
        environment: &TestEnvironment,
        expected: VmmProcessExpectation,
    ) -> RuntimeDesiredEffectContext {
        let cat_id = expected.cat_id().clone();
        let managed = super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::new(),
            BTreeMap::new(),
        )
        .unwrap()
        .with_vmms(BTreeMap::from([(cat_id, expected)]), BTreeMap::new())
        .unwrap()
        .into_admission_for_test();
        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: Id::new("node_test").unwrap(),
            immutable_host_id: Id::new("host_test").unwrap(),
            node_boot_id: NodeBootId::new("2".repeat(32)).unwrap(),
            agent_instance_id: RandomId128::new("3".repeat(32)).unwrap(),
            agent_session_epoch: Epoch::new(1).unwrap(),
            registration_attempt_id: RandomId128::new("4".repeat(32)).unwrap(),
            guest_config_digest: Sha256Digest::from_bytes([6; 32]),
            lease_deadline_unix_ms: UnixMillis::new(2_000).unwrap(),
        };
        let observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("1".repeat(32)).unwrap(),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(1).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: Some(Sha256Digest::from_bytes([4; 32])),
            inventory_read_position: Some(Sequence::new(1).unwrap()),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: Vec::new(),
            residue: Vec::new(),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: session.node_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation.inventory_digest.clone().unwrap(),
            inventory_read_position: observation.inventory_read_position.unwrap(),
            accepted_at_unix_ms: UnixMillis::new(1_100).unwrap(),
        };
        RuntimeDesiredEffectContext::for_test_with_admission(
            StateDirectory::unanchored(environment.state.clone()),
            Instant::now() + Duration::from_secs(5),
            RuntimeDesiredEffectAdmission::for_test(session, observation, attestation),
        )
        .with_node_global_process_for_test(managed)
    }

    fn persist_acquire_checkpoint(
        environment: &TestEnvironment,
        desired: &DesiredRuntimeSpec,
        attachment: &AuthorizedServingAttachment,
    ) {
        let checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: attachment.checkpoint_acquire_request(),
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
        std::fs::create_dir(data_directory.join(PENDING_PACK_DIR)).unwrap();
        std::fs::set_permissions(
            data_directory.join(PENDING_PACK_DIR),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }

    #[test]
    fn authorized_data_probe_accepts_exact_control_only_engine_files_without_a_legacy_socket() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (_record, attachment) = exact_owned_record_and_attachment(desired);
        let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
        install_exact_control_only_files(&data_directory, attachment.size_bytes);

        assert!(matches!(
            authorized_data_probe(&environment)
                .prove_absent(&scan_context)
                .unwrap(),
            InventoryAbsence::AuthorizedBlockd(evidence)
                if matches!(
                    evidence
                        .get(&desired.cat_id)
                        .and_then(|items| items.get(&desired.volumes[0].volume_id))
                        .map(|item| &item.control_state),
                    Some(AuthorizedBlockdControlState::ExactControlOnlyEmpty)
                )
        ));
    }

    #[test]
    fn authorized_data_probe_rejects_and_preserves_a_legacy_data_directory_socket() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context(true);
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (_record, attachment) = exact_owned_record_and_attachment(desired);
        let data_directory = prepare_exact_lineage(&environment, desired, &attachment);
        install_exact_control_only_files(&data_directory, attachment.size_bytes);
        let legacy_socket = data_directory.join("root-provision.sock");
        // Bind below SUN_LEN through a short pathname, then move the socket
        // inode into the deliberately long legacy data-directory location.
        // The probe only trusts the final descriptor-relative entry; keeping
        // the listener open preserves the socket inode without making
        // this fixture depend on the host's temporary-directory prefix.
        let short_socket = environment._root.path().join("legacy.sock");
        let listener = std::os::unix::net::UnixListener::bind(&short_socket).unwrap();
        std::fs::rename(&short_socket, &legacy_socket).unwrap();

        let error = authorized_data_probe(&environment)
            .prove_absent(&scan_context)
            .expect_err("the old data-directory socket is foreign residue");

        assert!(format!("{error:#}").contains("foreign entry root-provision.sock"));
        assert!(legacy_socket
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);
    }

    #[test]
    fn authorized_data_probe_enumerates_root_and_persistent_lineages_in_volume_order() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context_with_root_and_persistent();
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (_, root_attachment) = exact_owned_record_and_attachment_for(desired, 0);
        let (_, persistent_attachment) = exact_owned_record_and_attachment_for(desired, 1);
        prepare_exact_lineage_for(&environment, desired, 0, &root_attachment);
        prepare_exact_lineage_for(&environment, desired, 1, &persistent_attachment);

        let InventoryAbsence::AuthorizedBlockd(evidence) = authorized_data_probe(&environment)
            .prove_absent(&scan_context)
            .unwrap()
        else {
            panic!("two exact lineages must form one complete data inventory")
        };
        let by_volume = &evidence[&desired.cat_id];
        assert_eq!(by_volume.len(), 2);
        assert_eq!(
            by_volume.keys().cloned().collect::<Vec<_>>(),
            [
                desired.volumes[1].volume_id.clone(),
                desired.volumes[0].volume_id.clone(),
            ]
        );
        assert_eq!(
            by_volume[&desired.volumes[0].volume_id]
                .checkpoint
                .volume
                .disk_kind,
            DiskKind::Root
        );
        assert_eq!(
            by_volume[&desired.volumes[1].volume_id]
                .checkpoint
                .volume
                .disk_kind,
            DiskKind::Persistent
        );
    }

    #[test]
    fn serving_expectations_require_exact_root_and_persistent_direct_vhost_set() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context_with_root_and_persistent();
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (root_record, root_attachment) = exact_owned_record_and_attachment_for(desired, 0);
        let (persistent_record, persistent_attachment) =
            exact_owned_record_and_attachment_for(desired, 1);
        let root_data = prepare_exact_lineage_for(&environment, desired, 0, &root_attachment);
        let persistent_data =
            prepare_exact_lineage_for(&environment, desired, 1, &persistent_attachment);
        let root_device =
            direct_vhost_prepared_device(&environment, desired, 0, &root_attachment, &root_data);
        let persistent_device = direct_vhost_prepared_device(
            &environment,
            desired,
            1,
            &persistent_attachment,
            &persistent_data,
        );
        let mut checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: root_attachment.checkpoint_acquire_request(),
            },
            UnixMillis::new(9_000).unwrap(),
        );
        checkpoint.step = ReconcileStep::PrepareNetwork {
            network: RuntimeNetworkIdentity {
                network_config: desired.runtime.network_config.clone(),
                tap_name: Id::new("tap_multi").unwrap(),
                ownership_token: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            },
            devices: vec![root_device.clone(), persistent_device.clone()],
        };
        checkpoint.volumes = vec![
            prepared_owned_observed_volume(
                &desired.volumes[0],
                &root_attachment,
                root_device.serving_process.data_directory.clone(),
            ),
            prepared_owned_observed_volume(
                &desired.volumes[1],
                &persistent_attachment,
                persistent_device.serving_process.data_directory.clone(),
            ),
        ];
        let InventoryAbsence::AuthorizedBlockd(blockds) = authorized_data_probe(&environment)
            .prove_absent(&scan_context)
            .unwrap()
        else {
            panic!("direct vhost fixtures must produce exact authorized inventory")
        };
        let checkpoints = BTreeMap::from([(
            desired.cat_id.clone(),
            RuntimeCheckpointInventoryEvidence {
                checkpoint: checkpoint.clone(),
                binding: DesiredCheckpointBinding::Current,
                definite_release_rejected: false,
            },
        )]);
        let volumes = BTreeMap::from([(
            desired.cat_id.clone(),
            vec![
                AuthorityVolumeInventoryEvidence {
                    observed: checkpoint.volumes[0].clone(),
                    record: root_record,
                },
                AuthorityVolumeInventoryEvidence {
                    observed: checkpoint.volumes[1].clone(),
                    record: persistent_record,
                },
            ],
        )]);
        let bridge = root_process_bridge_with_all_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
            Arc::new(FakeVmmProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
        );
        let expected =
            serving_process_expectations(&scan_context, &bridge, &checkpoints, &blockds, &volumes)
                .unwrap();
        assert_eq!(expected.len(), 2);
        assert!(expected.contains_key(&ManagedServingKey::new(
            desired.cat_id.clone(),
            root_device.volume_id.clone(),
        )));
        assert!(expected.contains_key(&ManagedServingKey::new(
            desired.cat_id.clone(),
            persistent_device.volume_id.clone(),
        )));

        let mut missing = blockds.clone();
        missing
            .get_mut(&desired.cat_id)
            .unwrap()
            .remove(&persistent_device.volume_id);
        assert!(serving_process_expectations(
            &scan_context,
            &bridge,
            &checkpoints,
            &missing,
            &volumes,
        )
        .is_err());

        let mut extra = blockds.clone();
        let extra_evidence = extra[&desired.cat_id][&persistent_device.volume_id].clone();
        extra
            .get_mut(&desired.cat_id)
            .unwrap()
            .insert(Id::new("vol_extra").unwrap(), extra_evidence);
        assert!(serving_process_expectations(
            &scan_context,
            &bridge,
            &checkpoints,
            &extra,
            &volumes,
        )
        .is_err());

        let mut duplicate_checkpoint = checkpoints.clone();
        let entry = duplicate_checkpoint.get_mut(&desired.cat_id).unwrap();
        let ReconcileStep::PrepareNetwork { devices, .. } = &mut entry.checkpoint.step else {
            unreachable!()
        };
        devices[1] = devices[0].clone();
        assert!(serving_process_expectations(
            &scan_context,
            &bridge,
            &duplicate_checkpoint,
            &blockds,
            &volumes,
        )
        .is_err());
    }

    #[test]
    fn retained_direct_serving_authority_reopens_root_and_persistent_exactly() {
        let environment = TestEnvironment::new();
        let scan_context = assigned_context_with_root_and_persistent();
        let desired = &scan_context.coordinates().desired.desired_specs[0];
        let (root_record, root_attachment) = exact_owned_record_and_attachment_for(desired, 0);
        let (persistent_record, persistent_attachment) =
            exact_owned_record_and_attachment_for(desired, 1);
        let root_data = prepare_exact_lineage_for(&environment, desired, 0, &root_attachment);
        let persistent_data =
            prepare_exact_lineage_for(&environment, desired, 1, &persistent_attachment);
        let root =
            direct_vhost_prepared_device(&environment, desired, 0, &root_attachment, &root_data);
        let persistent = direct_vhost_prepared_device(
            &environment,
            desired,
            1,
            &persistent_attachment,
            &persistent_data,
        );
        let mut checkpoint = acquire_checkpoint(
            desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: root_attachment.checkpoint_acquire_request(),
            },
            UnixMillis::new(9_000).unwrap(),
        );
        checkpoint.step = ReconcileStep::PrepareNetwork {
            network: RuntimeNetworkIdentity {
                network_config: desired.runtime.network_config.clone(),
                tap_name: Id::new("tap_multi").unwrap(),
                ownership_token: RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap(),
            },
            devices: vec![root.clone(), persistent.clone()],
        };
        checkpoint.volumes = vec![
            prepared_owned_observed_volume(
                &desired.volumes[0],
                &root_attachment,
                root.serving_process.data_directory.clone(),
            ),
            prepared_owned_observed_volume(
                &desired.volumes[1],
                &persistent_attachment,
                persistent.serving_process.data_directory.clone(),
            ),
        ];
        checkpoint
            .volumes
            .sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
        let state = StateDirectory::unanchored(environment.state.clone());
        let systemd = test_systemd_config_for_path(&environment.blockd_binary);

        for (device, record) in [(&root, &root_record), (&persistent, &persistent_record)] {
            let retained = RetainedServingBlockdAuthority::reopen(
                &state,
                &checkpoint,
                desired,
                device,
                record,
            )
            .unwrap();
            let expected = retained.expectation(&systemd, desired, record).unwrap();
            assert!(expected.matches_device_contract(&desired.cat_id, device));
            retained
                .assert_current(&checkpoint, desired, record, &expected)
                .unwrap();
        }
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
            std::fs::create_dir(data_directory.join(PENDING_PACK_DIR)).unwrap();
            std::fs::set_permissions(
                data_directory.join(PENDING_PACK_DIR),
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
            assert_eq!(
                evidence[&desired.cat_id][&desired.volumes[0].volume_id]
                    .checkpoint
                    .attachment,
                attachment
            );
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
            AcquireMarker,
        }

        for drift in [Drift::Owner, Drift::Head, Drift::AcquireMarker] {
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
            RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
                ..
            }
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
            RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
                ..
            }
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
    fn full_scanner_covers_every_lifecycle_target_and_complete_volume_disposition_set() {
        for target in [
            RuntimeTarget::Running,
            RuntimeTarget::Suspended,
            RuntimeTarget::Warm,
            RuntimeTarget::Cold,
            RuntimeTarget::Deleted,
        ] {
            let environment = TestEnvironment::new();
            let mut scan_context = assigned_context_with_root_and_persistent();
            let desired = &mut scan_context.coordinates_mut().desired.desired_specs[0];
            desired.target = target;
            if target == RuntimeTarget::Deleted {
                desired.volumes[0].disposition = VolumeDisposition::DeleteDisposableRoot {
                    delete_id: Id::new("delete_root_lifecycle").unwrap(),
                };
                desired.volumes[1].disposition = VolumeDisposition::DetachRetained;
            }
            desired.spec_digest = spec_digest(desired).unwrap();
            let records = desired
                .volumes
                .iter()
                .map(|intent| {
                    (
                        intent.volume_id.clone(),
                        unowned_record(intent.volume_id.as_str(), intent.size_bytes),
                    )
                })
                .collect();
            let scanner = scanner_with_metadata_authority(
                environment.config(),
                Arc::new(ExactSetMetadataAuthorityReader { records }),
            )
            .unwrap();
            let RuntimeInventoryScanOutcome::Complete(inventory) =
                scanner.scan_complete(scan_context).unwrap()
            else {
                panic!("{target:?} complete multi-volume authority must form a full inventory")
            };
            let [runtime] = inventory.runtimes() else {
                panic!("{target:?} must project exactly one Runtime")
            };
            assert_eq!(runtime.volumes.len(), 2, "{target:?}");
            assert!(runtime
                .volumes
                .iter()
                .all(|volume| matches!(volume.authority, VolumeAuthorityEvidence::Unowned { .. })));
            assert_eq!(
                runtime
                    .volumes
                    .iter()
                    .map(|volume| volume.volume_id.clone())
                    .collect::<BTreeSet<_>>(),
                [
                    Id::new("vol_root").unwrap(),
                    Id::new("vol_persistent").unwrap()
                ]
                .into_iter()
                .collect(),
                "{target:?}"
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
                RuntimeInventoryScanOutcome::Incomplete {
                    unavailable_sources,
                    ..
                }
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
                managed_kernel_nbd_device_count: None,
                limits,
            }),
            Box::new(NetworkProbe {
                state_directory: StateDirectory::unanchored(environment.state.clone()),
                network_class_root: environment.network_root.clone(),
                supported: false,
                physical_inventory_owned_by_bridge: false,
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
            physical_inventory_owned_by_bridge: false,
            limits: ProbeLimits::default(),
        };
        assert!(network.prove_absent(&context()).is_err());
    }

    #[test]
    fn typed_network_bridge_does_not_turn_legacy_state_into_authority() {
        let environment = TestEnvironment::new();
        let network = NetworkProbe {
            state_directory: StateDirectory::unanchored(environment.state.clone()),
            network_class_root: environment.network_root.join("not-scanned-by-typed-bridge"),
            supported: true,
            physical_inventory_owned_by_bridge: true,
            limits: ProbeLimits::default(),
        };
        assert_eq!(
            network.prove_absent(&context()).unwrap(),
            InventoryAbsence::Empty
        );

        let legacy = environment.state.join(RUNTIME_EFFECTS_NAMESPACE);
        std::fs::create_dir(&legacy).unwrap();
        std::fs::write(legacy.join("old-network.json"), b"foreign").unwrap();
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
                scan_nbd(&environment.block_root, 16, None, &context()).unwrap(),
                expected
            );
        }

        let environment = TestEnvironment::new();
        let nbd = environment.block_root.join("nbd0");
        std::fs::create_dir(&nbd).unwrap();
        std::fs::write(nbd.join("size"), "not-a-number").unwrap();
        assert!(scan_nbd(&environment.block_root, 16, None, &context()).is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn installed_factory_derives_checkpoint_evidence_from_the_scanned_dirfd_child() {
        let environment = TestEnvironment::new();
        let state = StateDirectory::unanchored(environment.state.clone());
        #[cfg(target_os = "linux")]
        {
            std::fs::create_dir_all(
                Path::new(super::super::vmm_socket_namespace::INSTALLED_VMM_SOCKET_ROOT)
                    .parent()
                    .unwrap(),
            )
            .unwrap();
            let installed =
                Path::new(super::super::vmm_socket_namespace::INSTALLED_VMM_SOCKET_ROOT);
            if !installed.exists() {
                std::fs::create_dir(installed).unwrap();
            }
            std::fs::set_permissions(installed, std::fs::Permissions::from_mode(0o700)).unwrap();
            let blockd_socket_root =
                cats_blockd::runtime_socket_namespace::ManagedBlockdSocketRoot::installed();
            let blockd_installed = Path::new(blockd_socket_root.path().as_str());
            std::fs::create_dir_all(blockd_installed.parent().unwrap()).unwrap();
            let mut builder = std::fs::DirBuilder::new();
            builder.mode(0o700);
            match builder.create(blockd_installed) {
                Ok(()) => {}
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => panic!(
                    "create installed managed blockd socket root {}: {source}",
                    blockd_installed.display()
                ),
            }
            // `mkdir` is the only publication step. Whether this test or a
            // concurrent installed-composition test won the race, retain and
            // validate the exact installation-owned inode before proceeding.
            RetainedManagedBlockdSocketRoot::open_installed().unwrap();
            BlockdSocketIntentStore::provision_for_test(state.clone()).unwrap();
            VmmSocketReceiptStore::provision_for_test(state.clone()).unwrap();
            let launch_root = state.path().join(VMM_LAUNCH_FILE_NAMESPACE);
            std::fs::create_dir(&launch_root).unwrap();
            std::fs::set_permissions(&launch_root, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let config = ProbeConfig::installed(InstalledCleanSlateProbeConfig {
            state_directory: state.clone(),
            cloud_hypervisor_binary: environment.ch_binary.clone(),
            blockd_binary: environment.blockd_binary.clone(),
            guest_agent_binary: environment.guest_binary.clone(),
            ip_binary: PathBuf::from("/sbin/ip"),
            kernel_nbd_inventory: None,
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
        assert!(config.managed_blockd_socket_root.is_some());
        assert!(config.blockd_socket_intents.is_some());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn node_global_sweep_includes_the_bounded_managed_vmm_socket_root() {
        let environment = TestEnvironment::new();
        let mut bridge = root_process_bridge_with_port(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::new()),
            }),
        );
        let managed_root = Arc::new(
            RetainedManagedVmmSocketRoot::provision_for_test(
                &environment
                    .state
                    .parent()
                    .unwrap()
                    .join("managed-vmm-sockets"),
            )
            .unwrap(),
        );
        let receipts = Arc::new(
            VmmSocketReceiptStore::provision_for_test(StateDirectory::unanchored(
                environment.state.clone(),
            ))
            .unwrap(),
        );
        let launch_namespace = environment.state.join(VMM_LAUNCH_FILE_NAMESPACE);
        std::fs::create_dir(&launch_namespace).unwrap();
        std::fs::set_permissions(
            &launch_namespace,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let launch_root = Arc::new(
            RetainedManagedVmmLaunchRoot::open_existing(StateDirectory::unanchored(
                environment.state.clone(),
            ))
            .unwrap(),
        );
        bridge.managed_vmm_socket_root = Some(Arc::clone(&managed_root));
        bridge.managed_vmm_launch_root = Some(launch_root);
        bridge.vmm_socket_receipts = Some(receipts);
        let empty = BTreeSet::new();
        let expected_vmms = BTreeMap::new();
        assert_eq!(
            bridge
                .sweep_node_global_inventory(
                    &empty,
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    &expected_vmms,
                    &context(),
                )
                .unwrap(),
            ProbeFact::Empty
        );

        let foreign = Path::new(managed_root.planner().path().as_str()).join("foreign");
        std::fs::write(&foreign, b"foreign").unwrap();
        assert_eq!(
            bridge
                .sweep_node_global_inventory(
                    &empty,
                    &BTreeSet::new(),
                    &BTreeSet::new(),
                    &expected_vmms,
                    &context(),
                )
                .unwrap(),
            ProbeFact::Present
        );
        assert_eq!(std::fs::read(foreign).unwrap(), b"foreign");
    }

    struct SyntheticManagedListener;

    fn install_exact_process_fixture(
        environment: &TestEnvironment,
        expected: &RootProvisionProcessExpectation,
        process_id: u32,
    ) -> SyntheticManagedListener {
        std::fs::create_dir(environment.systemd_root.join(expected.scope_id.as_str())).unwrap();
        let proc = environment.proc_root.join(process_id.to_string());
        std::fs::create_dir(&proc).unwrap();
        std::os::unix::fs::symlink(expected.executable_path.as_str(), proc.join("exe")).unwrap();
        std::fs::write(
            proc.join("cmdline"),
            [expected.executable_path.as_str().as_bytes(), b"\0"].concat(),
        )
        .unwrap();
        // The fake process port below supplies the exact socket-peer proof.
        // Do not bind the production `/run/cats/blockd-v1` pathname from a
        // non-privileged unit test; whole-root listener coverage provisions a
        // retained temporary namespace in blockd_socket_namespace tests.
        SyntheticManagedListener
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                &assigned_context(true),
            )
            .unwrap();
        let RootProcessInventoryBridgeOutcome::Complete(admission) = outcome else {
            panic!("exact physical process must complete the three-source bridge")
        };
        let mut processes = admission.root_control_proofs();
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
        full_root_scanner_fixture_with_context(environment, assigned_context(true))
    }

    fn full_root_scanner_fixture_with_context(
        environment: &TestEnvironment,
        scan_context: RuntimeInventoryScanContext,
    ) -> FullRootScannerFixture {
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
                request: attachment.checkpoint_acquire_request(),
            },
            cats_api::runtime_reconciliation::UnixMillis::new(9_000).unwrap(),
        );
        let token = RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap();
        let provision_transition_id = RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        let scope_id = Id::new("cats-root-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.service").unwrap();
        let data = HostPath::new(data_directory.to_string_lossy().into_owned()).unwrap();
        checkpoint.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: provision_transition_id.clone(),
            volume_id: attachment.identity.volume_id.clone(),
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            scope_id,
            control_socket_path: managed_root_control_socket(&provision_transition_id),
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

    fn publish_test_stop_receipt(
        environment: &TestEnvironment,
        stored: &StoredCheckpoint,
        acquired: &AuthorizedBlockdCheckpoint,
        record: &VolumeRecord,
        expected: &RootProvisionProcessExpectation,
        process_id: u32,
        leave_temp: bool,
    ) {
        let mut retained =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                .retain_exact_runtime_checkpoint(stored.checkpoint())
                .unwrap();
        let node_boot_id = NodeBootId::new("33333333333333333333333333333333").unwrap();
        let socket_owner =
            super::super::blockd_socket_namespace::ManagedBlockdRootStopOwnerEvidence::for_test(
                expected,
                node_boot_id.clone(),
            )
            .unwrap();
        let receipt = super::super::authorized_blockd::RootProvisionStopReceipt::new(
            stored.checkpoint(),
            acquired,
            record.clone(),
            exact_process_evidence(expected, process_id),
            socket_owner,
            super::super::root_provision_process::RootProvisionRetirementAdmission {
                node_boot_id,
                agent_instance_id: RandomId128::new("44444444444444444444444444444444").unwrap(),
                agent_session_epoch: Epoch::new(2).unwrap(),
                inventory_epoch: Epoch::new(4).unwrap(),
                inventory_digest: Sha256Digest::from_bytes([9; 32]),
                inventory_read_position: Sequence::new(12).unwrap(),
            },
        )
        .unwrap();
        assert!(matches!(
            retained.persist_or_reopen_stop_receipt(&receipt).unwrap(),
            super::super::authorized_blockd::StopReceiptPublication::Published(_)
        ));
        if leave_temp {
            std::fs::rename(
                retained
                    .data_directory()
                    .join(ROOT_PROVISION_STOP_RECEIPT_FILE),
                retained
                    .data_directory()
                    .join(ROOT_PROVISION_STOP_RECEIPT_TEMP),
            )
            .unwrap();
        }
    }

    #[test]
    fn stable_managed_owner_receipt_cannot_starve_another_cats_temp_publication() {
        let environment = TestEnvironment::new();
        let first = full_root_scanner_fixture(&environment);
        let mut scan_context = first.scan_context.clone();
        let mut second_desired = scan_context.coordinates().desired.desired_specs[0].clone();
        second_desired.cat_id = Id::new("c2").unwrap();
        second_desired.runtime.network_config.network_id = Id::new("n2").unwrap();
        let second_volume = second_desired.volumes.first_mut().unwrap();
        second_volume.volume_intent_id = Id::new("vi2").unwrap();
        second_volume.disk_id = Id::new("d2").unwrap();
        second_volume.volume_id = Id::new("v2").unwrap();
        second_volume.attachment_id = Id::new("a2").unwrap();
        second_volume.guest_device.serial = Id::new("r2").unwrap();
        let VolumeAcquire::Normal { transition_id, .. } = &mut second_volume.acquire else {
            unreachable!()
        };
        *transition_id = RandomId128::new("22222222222222222222222222222222").unwrap();
        second_desired.spec_digest = spec_digest(&second_desired).unwrap();
        let (second_record, second_attachment) = exact_owned_record_and_attachment(&second_desired);
        let second_data = prepare_exact_lineage(&environment, &second_desired, &second_attachment);
        let second_blob = ExactManifestBlobStore::for_desired(&second_desired);
        let ProvisionHeadRead::Ready {
            blank: second_blank,
            target: second_target,
        } = expected_provision_heads(
            &second_blob,
            &second_desired,
            &second_desired.volumes[0],
            scan_context.deadline(),
        )
        else {
            unreachable!()
        };
        let mut second_checkpoint = acquire_checkpoint(
            &second_desired,
            &second_desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: second_attachment.checkpoint_acquire_request(),
            },
            UnixMillis::new(9_001).unwrap(),
        );
        let second_data_host = HostPath::new(second_data.to_str().unwrap().to_owned()).unwrap();
        let second_provision_transition_id =
            RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        second_checkpoint.step = ReconcileStep::ProvisionRootImage {
            provision_transition_id: second_provision_transition_id.clone(),
            volume_id: second_attachment.identity.volume_id.clone(),
            attachment_id: second_attachment.identity.attachment_id.clone(),
            attachment_epoch: second_attachment.identity.attachment_epoch,
            scope_id: Id::new("cats-root-dddddddddddddddddddddddddddddddd.service").unwrap(),
            control_socket_path: managed_root_control_socket(&second_provision_transition_id),
            data_directory: second_data_host.clone(),
            process_identity_token: RandomId128::new("dddddddddddddddddddddddddddddddd").unwrap(),
            size_bytes: second_attachment.size_bytes,
            boot_image_digest: second_desired.runtime.boot_image_digest.clone(),
            expected_blank_head: second_blank,
            expected_provisioned_head: second_target,
        };
        second_checkpoint.volumes = vec![prepared_owned_observed_volume(
            &second_desired.volumes[0],
            &second_attachment,
            second_data_host,
        )];
        let second_stored = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &second_desired.cat_id,
        )
        .unwrap()
        .create(&second_checkpoint)
        .unwrap();
        let second_acquired: AuthorizedBlockdCheckpoint = serde_json::from_slice(
            &std::fs::read(second_data.join(LAUNCH_CHECKPOINT_FILE)).unwrap(),
        )
        .unwrap();
        let second_expected = RootProvisionProcessExpectation::from_checkpoint(
            &second_checkpoint,
            super::super::root_provision_process::RootProvisionAuthoritySnapshot {
                attachment: second_attachment,
                volume: &second_record,
            },
            HostPath::new(environment.blockd_binary.to_str().unwrap().to_owned()).unwrap(),
        )
        .unwrap();

        publish_test_stop_receipt(
            &environment,
            &first.stored_checkpoint,
            &first.acquired,
            &first.record,
            &first.expected,
            81,
            false,
        );
        publish_test_stop_receipt(
            &environment,
            &second_stored,
            &second_acquired,
            &second_record,
            &second_expected,
            82,
            true,
        );
        scan_context
            .coordinates_mut()
            .desired
            .desired_specs
            .push(second_desired.clone());
        let recovery_context = RuntimePreScanRecoveryContext::for_test(
            StateDirectory::unanchored(environment.state.clone()),
            scan_context.coordinates().clone(),
            Instant::now() + Duration::from_secs(10),
        );
        let evidence = classify_local_publication_recovery(&recovery_context).unwrap();
        assert!(matches!(
            evidence,
            LocalPublicationRecoveryEvidence::RootProvisionStopReceiptPublication { cat_id }
                if cat_id == second_desired.cat_id
        ));
        let (authority, _) = TestVolumeDataAuthority::exact(first.record.clone());
        assert!(matches!(
            SignedRunningPublicationRecovery::new(authority)
                .recover_one(recovery_context)
                .unwrap(),
            RuntimePreScanRecoveryOutcome::Recovered { cat_id }
                if cat_id == second_desired.cat_id
        ));
        assert!(second_data.join(ROOT_PROVISION_STOP_RECEIPT_FILE).exists());
        assert!(!second_data.join(ROOT_PROVISION_STOP_RECEIPT_TEMP).exists());
        let InventoryAbsence::AuthorizedBlockd(evidence) = authorized_data_probe(&environment)
            .prove_absent(&scan_context)
            .unwrap()
        else {
            panic!("settling the second Cat temp must reopen a complete data scan")
        };
        assert_eq!(evidence.len(), 2);
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
        full_root_scanner_with_serving(fixture, inspections, [None, None])
    }

    fn full_root_scanner_with_serving(
        fixture: &FullRootScannerFixture,
        inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
        serving_process_ids: impl IntoIterator<Item = Option<u32>>,
    ) -> CleanSlateInventoryScanner {
        full_root_scanner_with_serving_and_network(fixture, inspections, serving_process_ids, None)
    }

    fn full_root_scanner_with_serving_and_network(
        fixture: &FullRootScannerFixture,
        inspections: impl IntoIterator<Item = RootProvisionProcessInspection>,
        serving_process_ids: impl IntoIterator<Item = Option<u32>>,
        network_allocation_port: Option<NetworkAllocationPort>,
    ) -> CleanSlateInventoryScanner {
        let mut config = fixture.config.clone();
        config.root_process_port = Some(Arc::new(FakeRootProcessPort {
            inspections: Mutex::new(inspections.into_iter().collect()),
        }));
        config.serving_process_port = Some(Arc::new(FakeServingProcessPort {
            process_ids: Mutex::new(serving_process_ids.into_iter().collect()),
        }));
        config.network_allocation_port = network_allocation_port;
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
        let ownership_token = RandomId128::new("cccccccccccccccccccccccccccccccc").unwrap();
        let (control_socket_path, io_socket_path) = managed_serving_sockets(&ownership_token);
        checkpoint.step = ReconcileStep::PrepareDevice {
            devices: vec![PreparedDeviceInput {
                volume_intent_id: volume.volume_intent_id.clone(),
                disk_id: volume.disk_id.clone(),
                volume_id: volume.volume_id.clone(),
                disk_kind: volume.disk_kind,
                attachment_id: attachment.identity.attachment_id.clone(),
                attachment_epoch: attachment.identity.attachment_epoch,
                acquire_origin: attachment.identity.acquire_origin.clone(),
                expected_head: fixture.record.head.clone(),
                size_bytes: attachment.size_bytes,
                durability: attachment.durability,
                guest_device: volume.guest_device.clone(),
                ownership_token,
                serving_authority: Box::new(ServingAuthorityProvenance::AfterRootProvision {
                    handoff,
                }),
                serving_process: ServingBlockdIdentity {
                    scope_id: Id::new("cats-serving-dddddddddddddddddddddddddddddddd.service")
                        .unwrap(),
                    control_socket_path,
                    data_directory,
                    executable_path: fixture.expected.executable_path.clone(),
                    process_identity_token: RandomId128::new("dddddddddddddddddddddddddddddddd")
                        .unwrap(),
                },
                frontend: PrepareDeviceFrontend::VhostUserBlk {
                    socket_path: io_socket_path,
                    queues: 2,
                    queue_size: 256,
                },
            }],
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

    struct LivePreparedScannerFixture {
        stored: StoredCheckpoint,
        old_process: super::super::root_provision_process::RootProvisionProcessEvidence,
        #[cfg(target_os = "linux")]
        retained_root_expected: RootProvisionProcessExpectation,
        #[cfg(target_os = "linux")]
        serving_expected: ServingBlockdExpectation,
        _listeners: Vec<SyntheticManagedListener>,
    }

    fn install_live_prepare_device_fixture(
        environment: &TestEnvironment,
        fixture: &FullRootScannerFixture,
    ) -> LivePreparedScannerFixture {
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
        let stored = ready
            .consume_for_prepare_device(&fixture.stored_checkpoint, |handoff| {
                let successor = prepare_device_successor(fixture, handoff);
                checkpoint_store
                    .replace(&fixture.stored_checkpoint, &successor)
                    .map_err(anyhow::Error::from)
            })
            .unwrap();
        drop(ready);

        let old_process = exact_process_evidence(&fixture.expected, 79);
        let old_socket =
            install_exact_process_fixture(environment, &fixture.expected, old_process.process_id);
        let retained =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                .retain_prepare_device_handoff(stored.checkpoint(), &fixture.acquired.desired)
                .unwrap();
        let serving_ready = handoff_store
            .reopen_prepare_device_handoff(
                stored.checkpoint(),
                &fixture.acquired.desired,
                &fixture.record,
                retained,
            )
            .unwrap();
        let serving_expected = ServingBlockdExpectation::from_handoff(
            &serving_ready,
            &test_root_provision_systemd(&environment.blockd_binary),
            stored.checkpoint(),
            &fixture.acquired.desired,
            &fixture.record,
        )
        .unwrap();
        #[cfg(target_os = "linux")]
        let retained_root_expected = RootProvisionProcessExpectation::from_retained_prepare_device(
            stored.checkpoint(),
            &fixture.acquired.desired,
            serving_ready.attempt(),
        )
        .unwrap();
        drop(serving_ready);
        std::fs::create_dir(
            environment
                .systemd_root
                .join(serving_expected.unit_id().as_str()),
        )
        .unwrap();
        let serving_proc = environment.proc_root.join("81");
        std::fs::create_dir(&serving_proc).unwrap();
        std::os::unix::fs::symlink(
            serving_expected.executable_path().as_str(),
            serving_proc.join("exe"),
        )
        .unwrap();
        let serving_cmdline = serving_expected
            .command_line()
            .iter()
            .flat_map(|argument| {
                argument
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(std::iter::once(0))
            })
            .collect::<Vec<_>>();
        std::fs::write(serving_proc.join("cmdline"), serving_cmdline).unwrap();
        LivePreparedScannerFixture {
            stored,
            old_process,
            #[cfg(target_os = "linux")]
            retained_root_expected,
            #[cfg(target_os = "linux")]
            serving_expected,
            _listeners: vec![
                old_socket,
                SyntheticManagedListener,
                SyntheticManagedListener,
            ],
        }
    }

    #[cfg(target_os = "linux")]
    struct ManagedInspectAllFixture {
        root: Arc<RetainedManagedBlockdSocketRoot>,
        intents: Arc<BlockdSocketIntentStore>,
        boot: CurrentBlockdSocketBoot,
        root_expected: RootProvisionProcessExpectation,
        serving_expected: ServingBlockdExpectation,
        root_intent: BlockdSocketOwnershipIntentV1,
        serving_intent: BlockdSocketOwnershipIntentV1,
    }

    #[cfg(target_os = "linux")]
    fn managed_inspect_all_fixture(environment: &TestEnvironment) -> ManagedInspectAllFixture {
        let fixture = full_root_scanner_fixture(environment);
        let mut live = install_live_prepare_device_fixture(environment, &fixture);
        let root = Arc::new(
            RetainedManagedBlockdSocketRoot::provision_for_test(
                &environment._root.path().join("managed-blockd-sockets"),
            )
            .unwrap(),
        );
        let intents = Arc::new(
            BlockdSocketIntentStore::provision_for_test(StateDirectory::unanchored(
                environment.state.clone(),
            ))
            .unwrap(),
        );
        let boot = CurrentBlockdSocketBoot::read().unwrap();

        let root_scope = live.retained_root_expected.scope_id.clone();
        let serving_scope = live.serving_expected.unit_id().clone();
        let serving_process_id = 81;
        live._listeners.clear();
        for path in [
            environment
                .proc_root
                .join(live.old_process.process_id.to_string()),
            environment.proc_root.join(serving_process_id.to_string()),
            environment.systemd_root.join(root_scope.as_str()),
            environment.systemd_root.join(serving_scope.as_str()),
        ] {
            std::fs::remove_dir_all(path).unwrap();
        }
        let mut root_expected = live.retained_root_expected;
        let installed_root_expected = root_expected.clone();
        root_expected.control_socket_path = root
            .planner()
            .root_paths(&root_expected.provision_transition_id)
            .unwrap()
            .control_socket()
            .clone();
        let mut restored_root_expected = root_expected.clone();
        restored_root_expected.control_socket_path =
            installed_root_expected.control_socket_path.clone();
        assert_eq!(restored_root_expected, installed_root_expected);

        let serving_expected = live
            .serving_expected
            .shadow_socket_root_for_test(root.planner())
            .unwrap();
        let root_intent = BlockdSocketOwnershipIntentV1::root(
            &root,
            &boot,
            root_expected.provision_transition_id.clone(),
            root_expected.socket_owner_authority_digest.clone(),
        )
        .unwrap();
        let serving_intent = BlockdSocketOwnershipIntentV1::serving(
            &root,
            &boot,
            serving_expected.device_ownership_token().clone(),
            serving_socket_owner_authority_digest(serving_expected.prepared_device()).unwrap(),
        )
        .unwrap();
        assert_eq!(
            root_expected.control_socket_path,
            *root_intent.control_socket_path()
        );
        assert_eq!(
            serving_expected.control_socket_path(),
            serving_intent.control_socket_path()
        );
        assert_eq!(
            Some(serving_expected.listener_path()),
            serving_intent.io_socket_path()
        );
        ManagedInspectAllFixture {
            root,
            intents,
            boot,
            root_expected,
            serving_expected,
            root_intent,
            serving_intent,
        }
    }

    #[cfg(target_os = "linux")]
    fn managed_inspect_all_bridge(
        environment: &TestEnvironment,
        managed: &ManagedInspectAllFixture,
        root_port: Arc<dyn RootProvisionProcessPort>,
        serving_port: Arc<dyn ServingBlockdProcessPort>,
    ) -> PlatformRootProcessInventoryBridge {
        let mut bridge = root_process_bridge_with_all_ports(
            environment,
            root_port,
            serving_port,
            Arc::new(FakeVmmProcessPort {
                process_ids: Mutex::new(VecDeque::new()),
            }),
        );
        bridge.managed_blockd_socket_root = Some(Arc::clone(&managed.root));
        bridge.blockd_socket_intents = Some(Arc::clone(&managed.intents));
        bridge
    }

    #[cfg(target_os = "linux")]
    fn managed_inspect_all(
        bridge: &PlatformRootProcessInventoryBridge,
        managed: &ManagedInspectAllFixture,
        stop_receipts: BTreeMap<Id, StopReceiptSocketAdmission>,
    ) -> anyhow::Result<RootProcessInventoryBridgeOutcome> {
        bridge.inspect_all(
            BTreeMap::from([(
                managed.root_expected.cat_id.clone(),
                managed.root_expected.clone(),
            )]),
            BTreeMap::from([(
                ManagedServingKey::new(
                    managed.serving_expected.cat_id().clone(),
                    managed.serving_expected.volume_id().clone(),
                ),
                managed.serving_expected.clone(),
            )]),
            BTreeMap::new(),
            stop_receipts,
            &assigned_context(true),
        )
    }

    #[cfg(target_os = "linux")]
    fn install_managed_process_fixture(
        environment: &TestEnvironment,
        scope_id: &Id,
        executable_path: &HostPath,
        command_line: impl IntoIterator<Item = OsString>,
        process_id: u32,
    ) {
        std::fs::create_dir(environment.systemd_root.join(scope_id.as_str())).unwrap();
        let proc = environment.proc_root.join(process_id.to_string());
        std::fs::create_dir(&proc).unwrap();
        std::os::unix::fs::symlink(executable_path.as_str(), proc.join("exe")).unwrap();
        let command_line = command_line
            .into_iter()
            .flat_map(|argument| {
                argument
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(std::iter::once(0))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        std::fs::write(proc.join("cmdline"), command_line).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn file_bytes_and_inode(path: &Path) -> (Vec<u8>, u64) {
        let metadata = std::fs::symlink_metadata(path).unwrap();
        (std::fs::read(path).unwrap(), metadata.ino())
    }

    #[cfg(target_os = "linux")]
    fn intent_receipt_path(
        environment: &TestEnvironment,
        intent: &BlockdSocketOwnershipIntentV1,
    ) -> PathBuf {
        let owner = match intent.owner() {
            super::super::blockd_socket_namespace::BlockdSocketOwnerV1::Root {
                provision_transition_id,
            } => format!("r-{provision_transition_id}.intent.v1.json"),
            super::super::blockd_socket_namespace::BlockdSocketOwnerV1::Serving {
                device_ownership_token,
            } => format!("d-{device_ownership_token}.intent.v1.json"),
        };
        environment
            .state
            .join(super::super::BLOCKD_SOCKET_INTENT_NAMESPACE)
            .join(owner)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_full_managed_root_composes_absent_then_exact_root_and_serving_owners() {
        let environment = TestEnvironment::new();
        let managed = managed_inspect_all_fixture(&environment);
        for intent in [&managed.root_intent, &managed.serving_intent] {
            managed
                .intents
                .publish(intent, &managed.root, &managed.boot)
                .unwrap();
            drop(
                managed
                    .root
                    .prepare_existing_intent(&managed.intents, intent, &managed.boot)
                    .unwrap(),
            );
        }

        let absent = managed_inspect_all_bridge(
            &environment,
            &managed,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::from([
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ])),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let RootProcessInventoryBridgeOutcome::Complete(absent) =
            managed_inspect_all(&absent, &managed, BTreeMap::new()).unwrap()
        else {
            panic!("closed marker-only managed owners must be an available normal full scan")
        };
        assert!(absent.root_control_proofs().is_empty());
        assert!(absent.serving_blockd_proofs().is_empty());

        let prepared_root = managed
            .root
            .prepare_existing_intent(&managed.intents, &managed.root_intent, &managed.boot)
            .unwrap();
        let root_listener =
            std::os::unix::net::UnixListener::bind(prepared_root.control_socket_path().as_str())
                .unwrap();
        prepared_root
            .assert_post_submit_owner_current(
                &managed.boot,
                super::super::blockd_socket_namespace::BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop(prepared_root);

        let prepared_serving = managed
            .root
            .prepare_existing_intent(&managed.intents, &managed.serving_intent, &managed.boot)
            .unwrap();
        let serving_control_listener =
            std::os::unix::net::UnixListener::bind(prepared_serving.control_socket_path().as_str())
                .unwrap();
        let serving_io_listener = std::os::unix::net::UnixListener::bind(
            prepared_serving.io_socket_path().unwrap().as_str(),
        )
        .unwrap();
        prepared_serving
            .assert_post_submit_owner_current(
                &managed.boot,
                super::super::blockd_socket_namespace::BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop(prepared_serving);

        let root_process = exact_process_evidence(&managed.root_expected, 79);
        install_managed_process_fixture(
            &environment,
            &managed.root_expected.scope_id,
            &managed.root_expected.executable_path,
            [OsString::from(
                managed.root_expected.executable_path.as_str(),
            )],
            root_process.process_id,
        );
        install_managed_process_fixture(
            &environment,
            managed.serving_expected.unit_id(),
            managed.serving_expected.executable_path(),
            managed.serving_expected.command_line().iter().cloned(),
            81,
        );
        let exact = managed_inspect_all_bridge(
            &environment,
            &managed,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::from([
                    RootProvisionProcessInspection::Exact(Box::new(root_process.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(root_process)),
                ])),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([Some(81), Some(81)])),
            }),
        );
        let RootProcessInventoryBridgeOutcome::Complete(exact) =
            managed_inspect_all(&exact, &managed, BTreeMap::new()).unwrap()
        else {
            panic!("one exact Root and Serving owner must complete the normal full scan")
        };
        assert_eq!(
            exact.root_control_proofs().keys().collect::<Vec<_>>(),
            [&managed.root_expected.cat_id]
        );
        assert_eq!(exact.serving_blockd_proofs().len(), 1);
        assert_eq!(exact.exact_process_count(&managed.root_expected.cat_id), 2);
        drop((root_listener, serving_control_listener, serving_io_listener));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_full_managed_root_rejects_live_listeners_for_processes_reported_absent() {
        let environment = TestEnvironment::new();
        let managed = managed_inspect_all_fixture(&environment);
        for intent in [&managed.root_intent, &managed.serving_intent] {
            managed
                .intents
                .publish(intent, &managed.root, &managed.boot)
                .unwrap();
        }
        let prepared_root = managed
            .root
            .prepare_existing_intent(&managed.intents, &managed.root_intent, &managed.boot)
            .unwrap();
        let root_listener =
            std::os::unix::net::UnixListener::bind(prepared_root.control_socket_path().as_str())
                .unwrap();
        prepared_root
            .assert_post_submit_owner_current(
                &managed.boot,
                super::super::blockd_socket_namespace::BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop(prepared_root);
        let prepared_serving = managed
            .root
            .prepare_existing_intent(&managed.intents, &managed.serving_intent, &managed.boot)
            .unwrap();
        let serving_control_listener =
            std::os::unix::net::UnixListener::bind(prepared_serving.control_socket_path().as_str())
                .unwrap();
        let serving_io_listener = std::os::unix::net::UnixListener::bind(
            prepared_serving.io_socket_path().unwrap().as_str(),
        )
        .unwrap();
        prepared_serving
            .assert_post_submit_owner_current(
                &managed.boot,
                super::super::blockd_socket_namespace::BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        drop(prepared_serving);

        for path in [
            managed.root_intent.control_socket_path(),
            managed.serving_intent.control_socket_path(),
            managed.serving_intent.io_socket_path().unwrap(),
        ] {
            std::os::unix::net::UnixStream::connect(path.as_str())
                .expect("known-positive managed listener must accept a connection");
        }
        let root_paths = managed
            .root
            .planner()
            .root_paths(&managed.root_expected.provision_transition_id)
            .unwrap();
        let serving_paths = managed
            .root
            .planner()
            .serving_paths(managed.serving_expected.device_ownership_token())
            .unwrap();
        let before = [
            file_bytes_and_inode(Path::new(root_paths.owner_marker().as_str())),
            file_bytes_and_inode(Path::new(serving_paths.owner_marker().as_str())),
            file_bytes_and_inode(&intent_receipt_path(&environment, &managed.root_intent)),
            file_bytes_and_inode(&intent_receipt_path(&environment, &managed.serving_intent)),
        ];
        let bridge = managed_inspect_all_bridge(
            &environment,
            &managed,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::from([
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ])),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let error = managed_inspect_all(&bridge, &managed, BTreeMap::new())
            .expect_err("live managed listeners were projected as absent");
        assert!(
            format!("{error:#}").contains("retains a live Unix listener"),
            "{error:#}"
        );
        assert_eq!(
            before,
            [
                file_bytes_and_inode(Path::new(root_paths.owner_marker().as_str())),
                file_bytes_and_inode(Path::new(serving_paths.owner_marker().as_str())),
                file_bytes_and_inode(&intent_receipt_path(&environment, &managed.root_intent)),
                file_bytes_and_inode(&intent_receipt_path(&environment, &managed.serving_intent)),
            ]
        );
        drop((root_listener, serving_control_listener, serving_io_listener));
    }

    #[cfg(target_os = "linux")]
    struct MutatingManagedRootProcessPort {
        mutation_path: PathBuf,
        calls: AtomicUsize,
    }

    #[cfg(target_os = "linux")]
    impl super::super::root_provision_process::sealed::Sealed for MutatingManagedRootProcessPort {}

    #[cfg(target_os = "linux")]
    impl RootProvisionProcessPort for MutatingManagedRootProcessPort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                std::fs::write(&self.mutation_path, b"foreign").unwrap();
            }
            Ok(RootProvisionProcessInspection::Absent)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::root_provision_process::CheckpointedRootProvisionProcess<
                '_,
            >,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::root_provision_process::RootProvisionProcessStart>
        {
            unreachable!("inventory mutation regression is read-only")
        }
    }

    #[cfg(target_os = "linux")]
    struct ReplacingManagedMarkerPort {
        marker_path: PathBuf,
        replacement_path: PathBuf,
        calls: AtomicUsize,
    }

    #[cfg(target_os = "linux")]
    impl super::super::root_provision_process::sealed::Sealed for ReplacingManagedMarkerPort {}

    #[cfg(target_os = "linux")]
    impl RootProvisionProcessPort for ReplacingManagedMarkerPort {
        fn inspect(
            &self,
            _expected: &RootProvisionProcessExpectation,
            _context: &dyn RuntimePhysicalReadContext,
        ) -> anyhow::Result<RootProvisionProcessInspection> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 0 {
                let bytes = std::fs::read(&self.marker_path).unwrap();
                std::fs::write(&self.replacement_path, bytes).unwrap();
                std::fs::set_permissions(
                    &self.replacement_path,
                    std::fs::Permissions::from_mode(0o600),
                )
                .unwrap();
                std::fs::rename(&self.replacement_path, &self.marker_path).unwrap();
            }
            Ok(RootProvisionProcessInspection::Absent)
        }

        fn start_checkpointed(
            &self,
            _checkpointed: super::super::root_provision_process::CheckpointedRootProvisionProcess<
                '_,
            >,
            _context: &RuntimeDesiredEffectContext,
        ) -> anyhow::Result<super::super::root_provision_process::RootProvisionProcessStart>
        {
            unreachable!("inventory marker-ABA regression is read-only")
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_full_managed_root_rejects_a_mid_scan_unknown_owner_without_cleanup() {
        let environment = TestEnvironment::new();
        let managed = managed_inspect_all_fixture(&environment);
        for intent in [&managed.root_intent, &managed.serving_intent] {
            managed
                .intents
                .publish(intent, &managed.root, &managed.boot)
                .unwrap();
            drop(
                managed
                    .root
                    .prepare_existing_intent(&managed.intents, intent, &managed.boot)
                    .unwrap(),
            );
        }
        let foreign = Path::new(managed.root.planner().path().as_str()).join("foreign");
        let root_port = Arc::new(MutatingManagedRootProcessPort {
            mutation_path: foreign.clone(),
            calls: AtomicUsize::new(0),
        });
        let bridge = managed_inspect_all_bridge(
            &environment,
            &managed,
            root_port.clone(),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let error = managed_inspect_all(&bridge, &managed, BTreeMap::new())
            .expect_err("mid-scan foreign managed owner entered a complete full inventory");
        assert!(
            format!("{error:#}").contains("unknown owner or recovery alias"),
            "{error:#}"
        );
        assert_eq!(root_port.calls.load(Ordering::SeqCst), 1);
        assert_eq!(std::fs::read(&foreign).unwrap(), b"foreign");
        assert!(Path::new(
            managed
                .root
                .planner()
                .root_paths(&managed.root_expected.provision_transition_id)
                .unwrap()
                .public_directory()
                .as_str()
        )
        .exists());
        assert!(Path::new(
            managed
                .root
                .planner()
                .serving_paths(managed.serving_expected.device_ownership_token())
                .unwrap()
                .public_directory()
                .as_str()
        )
        .exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_full_managed_root_rejects_same_name_marker_inode_aba_without_cleanup() {
        let environment = TestEnvironment::new();
        let managed = managed_inspect_all_fixture(&environment);
        for intent in [&managed.root_intent, &managed.serving_intent] {
            managed
                .intents
                .publish(intent, &managed.root, &managed.boot)
                .unwrap();
            drop(
                managed
                    .root
                    .prepare_existing_intent(&managed.intents, intent, &managed.boot)
                    .unwrap(),
            );
        }
        let root_paths = managed
            .root
            .planner()
            .root_paths(&managed.root_expected.provision_transition_id)
            .unwrap();
        let serving_paths = managed
            .root
            .planner()
            .serving_paths(managed.serving_expected.device_ownership_token())
            .unwrap();
        let marker = Path::new(root_paths.owner_marker().as_str()).to_path_buf();
        let replacement = environment._root.path().join("replacement-owner-marker");
        let marker_before = file_bytes_and_inode(&marker);
        let stable_before = [
            file_bytes_and_inode(Path::new(serving_paths.owner_marker().as_str())),
            file_bytes_and_inode(&intent_receipt_path(&environment, &managed.root_intent)),
            file_bytes_and_inode(&intent_receipt_path(&environment, &managed.serving_intent)),
        ];
        let root_port = Arc::new(ReplacingManagedMarkerPort {
            marker_path: marker.clone(),
            replacement_path: replacement,
            calls: AtomicUsize::new(0),
        });
        let bridge = managed_inspect_all_bridge(
            &environment,
            &managed,
            root_port.clone(),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let error = managed_inspect_all(&bridge, &managed, BTreeMap::new())
            .expect_err("same-name managed marker inode ABA entered a complete full inventory");
        assert!(
            format!("{error:#}").contains("changed across full Node-global inventory"),
            "{error:#}"
        );
        assert_eq!(root_port.calls.load(Ordering::SeqCst), 1);
        let marker_after = file_bytes_and_inode(&marker);
        assert_eq!(marker_after.0, marker_before.0);
        assert_ne!(marker_after.1, marker_before.1);
        assert_eq!(
            stable_before,
            [
                file_bytes_and_inode(Path::new(serving_paths.owner_marker().as_str())),
                file_bytes_and_inode(&intent_receipt_path(&environment, &managed.root_intent)),
                file_bytes_and_inode(&intent_receipt_path(&environment, &managed.serving_intent)),
            ]
        );
        assert!(Path::new(root_paths.public_directory().as_str()).exists());
        assert!(Path::new(serving_paths.public_directory().as_str()).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn normal_full_stop_journal_tracks_physical_socket_then_retired_empty_owner() {
        let environment = TestEnvironment::new();
        let managed = managed_inspect_all_fixture(&environment);
        managed
            .intents
            .publish(&managed.root_intent, &managed.root, &managed.boot)
            .unwrap();
        let prepared = managed
            .root
            .prepare_existing_intent(&managed.intents, &managed.root_intent, &managed.boot)
            .unwrap();
        let listener =
            std::os::unix::net::UnixListener::bind(prepared.control_socket_path().as_str())
                .unwrap();
        prepared
            .assert_post_submit_owner_current(
                &managed.boot,
                super::super::blockd_socket_namespace::BlockdSocketPostSubmitOutcome::HandshakeVerified,
            )
            .unwrap();
        let stop_owner = prepared
            .retain_root_stop_owner_evidence(&managed.boot)
            .unwrap();
        drop((prepared, listener));

        let first_bridge = managed_inspect_all_bridge(
            &environment,
            &managed,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::from([
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ])),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let RootProcessInventoryBridgeOutcome::Complete(first) = managed_inspect_all(
            &first_bridge,
            &managed,
            BTreeMap::from([(
                managed.root_expected.cat_id.clone(),
                StopReceiptSocketAdmission::from_managed(stop_owner.clone()),
            )]),
        )
        .unwrap() else {
            panic!("stopped Root owner must retain its exact journaled socket")
        };
        let first = first.into_admission_for_test();
        assert_eq!(
            first
                .stop_receipt_socket(&managed.root_expected.cat_id)
                .unwrap()
                .receipt_socket(),
            stop_owner.control_socket_path()
        );
        assert_eq!(
            first.stop_receipt_physical_paths(),
            BTreeSet::from([managed.root_intent.control_socket_path().clone()])
        );

        let effect_context = RuntimeDesiredEffectContext::for_test(
            StateDirectory::unanchored(environment.state.clone()),
            Instant::now() + Duration::from_secs(5),
        );
        let node_global = effect_context.lock_node_global_effect().unwrap();
        let capture = managed
            .root
            .capture_start_absence(&managed.intents, &managed.root_intent, &managed.boot)
            .unwrap();
        let expected = [managed.root_intent.clone(), managed.serving_intent.clone()];
        let before = managed
            .root
            .capture_closed_whole_root(&managed.intents, &expected)
            .unwrap();
        let after = managed
            .root
            .capture_closed_whole_root(&managed.intents, &expected)
            .unwrap();
        let absence = ExactManagedBlockdSocketOwnerStartAbsence::seal_after_node_global_sweep(
            capture,
            before,
            after,
            &managed.boot,
            node_global,
        )
        .unwrap();
        assert_eq!(
            managed
                .root
                .retire_absent_owner(
                    &managed.intents,
                    &managed.root_intent,
                    &managed.boot,
                    absence,
                )
                .unwrap(),
            super::super::blockd_socket_namespace::ManagedBlockdSocketOwnerRetirement::Retired
        );

        let second_bridge = managed_inspect_all_bridge(
            &environment,
            &managed,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(VecDeque::from([
                    RootProvisionProcessInspection::Absent,
                    RootProvisionProcessInspection::Absent,
                ])),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new(VecDeque::from([None, None])),
            }),
        );
        let expected_receipt_socket = stop_owner.control_socket_path().clone();
        let RootProcessInventoryBridgeOutcome::Complete(second) = managed_inspect_all(
            &second_bridge,
            &managed,
            BTreeMap::from([(
                managed.root_expected.cat_id.clone(),
                StopReceiptSocketAdmission::from_managed(stop_owner),
            )]),
        )
        .unwrap() else {
            panic!("retired owner with a surviving semantic journal must scan complete")
        };
        let second = second.into_admission_for_test();
        let retained_semantic_receipt = second
            .stop_receipt_socket(&managed.root_expected.cat_id)
            .expect("owner retirement must not erase the semantic stop receipt admission");
        assert_eq!(
            retained_semantic_receipt.receipt_socket(),
            &expected_receipt_socket
        );
        assert!(second.stop_receipt_physical_paths().is_empty());
        assert!(
            !Path::new(
                managed
                    .root
                    .planner()
                    .root_paths(&managed.root_expected.provision_transition_id)
                    .unwrap()
                    .public_directory()
                    .as_str()
            )
            .exists()
                && managed
                    .intents
                    .load(managed.root_intent.owner())
                    .unwrap()
                    .is_none()
        );
    }

    fn retire_old_process_fixture(
        environment: &TestEnvironment,
        fixture: &FullRootScannerFixture,
        live: &mut LivePreparedScannerFixture,
    ) {
        let _ = live._listeners.remove(0);
        std::fs::remove_dir_all(
            environment
                .proc_root
                .join(live.old_process.process_id.to_string()),
        )
        .unwrap();
        std::fs::remove_dir_all(
            environment
                .systemd_root
                .join(fixture.expected.scope_id.as_str()),
        )
        .unwrap();
    }

    #[test]
    fn fresh_full_scanner_rejects_paired_foreign_prepared_device_ids() {
        for field in ["volume_intent_id", "disk_id"] {
            let environment = TestEnvironment::new();
            let fixture = full_root_scanner_fixture(&environment);
            let live = install_live_prepare_device_fixture(&environment, &fixture);
            let mut poisoned = live.stored.checkpoint().clone();
            let observed = poisoned.volumes.first_mut().unwrap();
            match (&mut poisoned.step, field) {
                (ReconcileStep::PrepareDevice { devices }, "volume_intent_id") => {
                    let foreign = Id::new("vint_foreign").unwrap();
                    devices[0].volume_intent_id = foreign.clone();
                    observed.volume_intent_id = Some(foreign);
                }
                (ReconcileStep::PrepareDevice { devices }, "disk_id") => {
                    let foreign = Id::new("disk_foreign").unwrap();
                    devices[0].disk_id = foreign.clone();
                    observed.disk_id = Some(foreign);
                }
                _ => panic!("unexpected prepared-device fixture or mutation field"),
            }
            poisoned.updated_at_unix_ms =
                UnixMillis::new(live.stored.checkpoint().updated_at_unix_ms.get() + 1).unwrap();
            FileCheckpointStore::open(
                &environment.state.join(CHECKPOINT_NAMESPACE),
                &fixture.expected.cat_id,
            )
            .unwrap()
            .replace(&live.stored, &poisoned)
            .unwrap();

            let error = full_root_scanner_with_serving(
                &fixture,
                [
                    RootProvisionProcessInspection::Exact(Box::new(live.old_process.clone())),
                    RootProvisionProcessInspection::Exact(Box::new(live.old_process.clone())),
                ],
                [Some(81), Some(81)],
            )
            .scan_complete(fixture.scan_context.clone())
            .expect_err("paired foreign prepared-device IDs entered full inventory");
            assert!(
                format!("{error:#}").contains("prepared-device checkpoint"),
                "{field}: {error:#}"
            );
        }
    }

    #[test]
    fn fresh_full_prepare_network_scan_seals_absence_and_provisioned_head() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        let mut live = install_live_prepare_device_fixture(&environment, &fixture);
        retire_old_process_fixture(&environment, &fixture, &mut live);
        let desired = &fixture.acquired.desired;
        let planned = crate::ch::plan_network(&desired.runtime.network_config).unwrap();
        let identity = RuntimeNetworkIdentity {
            network_config: planned.config,
            tap_name: Id::new(planned.tap).unwrap(),
            ownership_token: planned.ownership_token,
        };
        let device =
            super::super::network::prepared_device_input(live.stored.checkpoint()).unwrap();
        assert_eq!(device.expected_head, fixture.record.head);
        let mut checkpoint = live.stored.checkpoint().clone();
        checkpoint.step = ReconcileStep::PrepareNetwork {
            network: identity.clone(),
            devices: vec![device.clone()],
        };
        checkpoint.updated_at_unix_ms =
            UnixMillis::new(live.stored.checkpoint().updated_at_unix_ms.get() + 1).unwrap();
        FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &fixture.expected.cat_id,
        )
        .unwrap()
        .replace(&live.stored, &checkpoint)
        .unwrap();

        let ip = environment.state.parent().unwrap().join("ip-empty");
        std::fs::write(
            &ip,
            "#!/bin/sh\nif [ \"$2\" = \"-d\" ] || [ \"$2\" = \"-4\" ]; then printf '[]'; exit 0; fi\nexit 97\n",
        )
        .unwrap();
        std::fs::set_permissions(&ip, std::fs::Permissions::from_mode(0o755)).unwrap();
        let network_port =
            NetworkAllocationPort::new(StateDirectory::unanchored(environment.state.clone()), ip)
                .unwrap();
        let coordinates = fixture.scan_context.coordinates().clone();
        let scanner = full_root_scanner_with_serving_and_network(
            &fixture,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
            [Some(81), Some(81)],
            Some(network_port),
        );
        let RuntimeInventoryScanOutcome::Complete(mut inventory) =
            scanner.scan_complete(fixture.scan_context.clone()).unwrap()
        else {
            panic!("fresh PrepareNetwork scan must be complete")
        };
        let runtime = &inventory.runtimes()[0];
        let ReconcileStep::PrepareNetwork { network, devices } = &runtime.step else {
            panic!("fresh scan did not retain PrepareNetwork")
        };
        assert_eq!(network, &identity);
        assert_eq!(devices, &[device]);
        let VolumeAuthorityEvidence::Owned { head, .. } = &runtime.volumes[0].authority else {
            panic!("fresh PrepareNetwork scan lost owned authority")
        };
        assert_eq!(head, &fixture.record.head);
        assert!(runtime.networks.is_empty());

        let process_scan = inventory
            .take_node_global_process_admission()
            .expect("fresh PrepareNetwork scan lacks sealed process admission");
        let network_scan = inventory
            .take_node_global_network_admission()
            .expect("fresh PrepareNetwork scan lacks sealed network admission");
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: coordinates.session.node_id.clone(),
            node_boot_id: coordinates.session.node_boot_id.clone(),
            agent_instance_id: coordinates.session.agent_instance_id.clone(),
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        let process_admission = process_scan.bind(&observation).unwrap();
        let network_admission = network_scan.bind(&observation).unwrap();
        assert!(process_admission.matches_observation(&observation));
        assert!(network_admission.matches_observation(&observation));
    }

    #[test]
    fn full_scanner_mints_running_tail_only_from_one_exact_physical_pass() {
        let environment = TestEnvironment::new();
        let template = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let ReconcileStep::StartRuntime {
            guest_config_digest,
            ..
        } = &template.step
        else {
            panic!("StartRuntime template")
        };
        let mut scan_context = assigned_context(true);
        let desired = &mut scan_context.coordinates_mut().desired.desired_specs[0];
        desired.runtime.guest_config_digest = guest_config_digest.clone();
        desired.spec_digest = spec_digest(desired).unwrap();
        let fixture = full_root_scanner_fixture_with_context(&environment, scan_context);
        let live = install_live_prepare_device_fixture(&environment, &fixture);
        let desired = &fixture.acquired.desired;
        let planned = crate::ch::plan_network(&desired.runtime.network_config).unwrap();
        let network = RuntimeNetworkIdentity {
            network_config: planned.config,
            tap_name: Id::new(planned.tap).unwrap(),
            ownership_token: planned.ownership_token,
        };
        let device = super::super::network::prepared_device_input(live.stored.checkpoint())
            .expect("retained prepared device");
        let mut predecessor = live.stored.checkpoint().clone();
        let PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } = &device.frontend else {
            panic!("Running scanner fixture uses the vhost frontend")
        };
        predecessor.volumes[0].devices = vec![
            cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk {
                guest_device: device.guest_device.clone(),
                socket_path: socket_path.clone(),
                ownership_token: OwnershipTokenEvidence::Valid {
                    ownership_token: device.ownership_token.clone(),
                },
            },
        ];
        predecessor.step = ReconcileStep::PrepareNetwork {
            network: network.clone(),
            devices: vec![device],
        };
        predecessor.updated_at_unix_ms =
            UnixMillis::new(live.stored.checkpoint().updated_at_unix_ms.get() + 1).unwrap();

        let ReconcileStep::StartRuntime {
            launcher_executable,
            boot,
            ..
        } = template.step
        else {
            panic!("StartRuntime template")
        };
        let runtime_incarnation = RandomId128::new("55555555555555555555555555555555").unwrap();
        let socket_paths = super::super::ManagedVmmSocketRoot::installed()
            .paths_for(&runtime_incarnation)
            .unwrap();
        let state_directory = StateDirectory::unanchored(environment.state.clone());
        let launch_file_paths = super::super::ManagedVmmLaunchFilePaths::for_incarnation(
            &state_directory,
            &runtime_incarnation,
        )
        .unwrap();
        let network_projection = ObservedNetwork {
            kind: network.network_config.kind,
            network_id: network.network_config.network_id.clone(),
            guest_mac: network.network_config.guest_mac.clone(),
            guest_ipv4: network.network_config.guest_ipv4.clone(),
            prefix_length: network.network_config.prefix_length,
            gateway_ipv4: network.network_config.gateway_ipv4.clone(),
            tap_name: network.tap_name.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: network.ownership_token.clone(),
            },
        };
        let start = super::super::vmm_start_runtime::build_start_runtime_successor(
            &predecessor,
            desired,
            runtime_incarnation,
            RandomId128::new("66666666666666666666666666666666").unwrap(),
            3,
            super::super::vmm_start_runtime::StartRuntimeCheckpointAuthority {
                launcher_executable: *launcher_executable,
                boot: *boot,
                network_projection,
                socket_paths: &socket_paths,
                launch_file_paths: &launch_file_paths,
            },
            UnixMillis::new(predecessor.updated_at_unix_ms.get() + 1).unwrap(),
        )
        .unwrap();
        let start_stored = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap()
        .replace(&live.stored, &start)
        .unwrap();

        let bridge = Arc::new(ExactRunningProcessBridge {
            state_directory: state_directory.clone(),
            systemd: test_root_provision_systemd(&environment.blockd_binary),
            executable_path: HostPath::new(
                environment.blockd_binary.to_string_lossy().into_owned(),
            )
            .unwrap(),
            exact_vmm_state: Some(ProcessState::Running),
        });
        let registry = AdmissionCellRegistry::for_state_directory(&state_directory);
        let guest_calls = Arc::new(AtomicUsize::new(0));
        let scanner = full_root_scanner(&fixture, [])
            .with_root_process_bridge_for_test(bridge)
            .with_network_bridge(Arc::new(ExactRunningNetworkBridge))
            .with_running_tail_transport_for_test(
                Arc::clone(&registry),
                Arc::new(ExactRunningGuestReadyPort {
                    calls: Arc::clone(&guest_calls),
                    fault: RunningGuestReadyFault::Exact,
                }),
            );
        let coordinates = fixture.scan_context.coordinates().clone();
        let RuntimeInventoryScanOutcome::Complete(mut inventory) =
            scanner.scan_complete(fixture.scan_context.clone()).unwrap()
        else {
            panic!("one exact Running physical pass must complete")
        };
        assert_eq!(guest_calls.load(Ordering::SeqCst), 1);
        let runtime = &inventory.runtimes()[0];
        assert!(matches!(
            runtime.guest_transport,
            cats_api::runtime_reconciliation::GuestTransportEvidence::VsockReady {
                guest_cid: 3,
                ..
            }
        ));
        assert_eq!(runtime.mounts.len(), 1);
        assert_eq!(runtime.mounts[0].mount_path.as_str(), "/");
        let process_scan = inventory
            .take_node_global_process_admission()
            .expect("exact scan must retain its complete process admission");
        let network_scan = inventory
            .take_node_global_network_admission()
            .expect("exact scan must retain its complete network admission");
        let tail = inventory
            .take_running_tail_admission()
            .expect("exact scan must retain a private Running-tail admission");

        let paused_registry = AdmissionCellRegistry::for_state_directory(&state_directory);
        let paused_cell = AdmissionCell::new(
            AdmissionSnapshot::from_checkpoint(start_stored.checkpoint()).unwrap(),
        )
        .unwrap();
        paused_registry
            .insert_cell_for_machine_test(desired.cat_id.clone(), paused_cell)
            .unwrap();
        let paused_guest_calls = Arc::new(AtomicUsize::new(0));
        let paused_bridge = Arc::new(ExactRunningProcessBridge {
            state_directory: state_directory.clone(),
            systemd: test_root_provision_systemd(&environment.blockd_binary),
            executable_path: HostPath::new(
                environment.blockd_binary.to_string_lossy().into_owned(),
            )
            .unwrap(),
            exact_vmm_state: Some(ProcessState::Paused),
        });
        let paused_scanner = full_root_scanner(&fixture, [])
            .with_root_process_bridge_for_test(paused_bridge)
            .with_network_bridge(Arc::new(ExactRunningNetworkBridge))
            .with_running_tail_transport_for_test(
                paused_registry,
                Arc::new(ExactRunningGuestReadyPort {
                    calls: Arc::clone(&paused_guest_calls),
                    fault: RunningGuestReadyFault::Exact,
                }),
            );
        let RuntimeInventoryScanOutcome::Complete(mut paused_inventory) = paused_scanner
            .scan_complete(fixture.scan_context.clone())
            .unwrap()
        else {
            panic!("a Paused VMM must remain a complete fail-closed observation")
        };
        drop(paused_scanner);
        assert_eq!(
            paused_guest_calls.load(Ordering::SeqCst),
            0,
            "Paused VMM must be rejected before a successful Guest-ready response can mint Ready"
        );
        assert!(matches!(
            paused_inventory.runtimes()[0].guest_transport,
            GuestTransportEvidence::Unavailable
        ));
        let paused_tail = paused_inventory
            .take_running_tail_admission()
            .expect("Paused VMM with an existing cell must mint close-only authority");
        assert!(!paused_tail.has_ready_for_test(&desired.cat_id));
        assert_eq!(
            paused_tail.route_retirement_mode_for_test(&desired.cat_id),
            Some(super::super::RouteRetirementMode::GlobalPhysicalNegative)
        );

        let hybrid_scanner = full_root_scanner(&fixture, [])
            .with_root_process_bridge_for_test(Arc::new(ExactRunningProcessBridge {
                state_directory: state_directory.clone(),
                systemd: test_root_provision_systemd(&environment.blockd_binary),
                executable_path: HostPath::new(
                    environment.blockd_binary.to_string_lossy().into_owned(),
                )
                .unwrap(),
                exact_vmm_state: Some(ProcessState::Paused),
            }))
            .with_network_bridge(Arc::new(UnavailableRunningNetworkBridge));
        let RuntimeInventoryScanOutcome::Incomplete {
            unavailable_sources,
            exact_physical_negative_cats,
        } = hybrid_scanner
            .scan_complete(fixture.scan_context.clone())
            .unwrap()
        else {
            panic!("a later unavailable source must retain the earlier exact Paused negative")
        };
        assert!(unavailable_sources.contains(&InventorySource::Network));
        assert_eq!(
            exact_physical_negative_cats,
            BTreeSet::from([desired.cat_id.clone()])
        );

        for (initial, label) in [
            (ScriptedVmmInspection::Exact(ProcessState::Paused), "paused"),
            (ScriptedVmmInspection::Absent, "absent"),
        ] {
            for later_unavailable in [
                "node-global-sweep",
                "node-global-cancellation",
                "second-vmm-sample",
            ] {
                let platform_scan_context = RuntimeInventoryScanContext::for_test(
                    fixture.scan_context.coordinates().clone(),
                    Instant::now() + Duration::from_secs(5),
                );
                let vmm_inspections = match later_unavailable {
                    "node-global-sweep" | "node-global-cancellation" => VecDeque::from([initial]),
                    "second-vmm-sample" => {
                        VecDeque::from([initial, ScriptedVmmInspection::Unavailable])
                    }
                    _ => unreachable!(),
                };
                let root_process = live.old_process.clone();
                let mut platform_bridge = root_process_bridge_with_all_ports(
                    &environment,
                    Arc::new(FakeRootProcessPort {
                        inspections: Mutex::new(VecDeque::from([
                            RootProvisionProcessInspection::Exact(Box::new(root_process.clone())),
                            RootProvisionProcessInspection::Exact(Box::new(root_process)),
                        ])),
                    }),
                    Arc::new(FakeServingProcessPort {
                        process_ids: Mutex::new(VecDeque::from([Some(81), Some(81)])),
                    }),
                    Arc::new(ScriptedVmmProcessPort {
                        inspections: Mutex::new(vmm_inspections),
                        cancel_after_first: (later_unavailable == "node-global-cancellation")
                            .then(|| platform_scan_context.clone()),
                        calls: AtomicUsize::new(0),
                    }),
                );
                let empty_os = TempDir::new().unwrap();
                platform_bridge.systemd_root = empty_os.path().join("systemd");
                platform_bridge.process_paths.root = empty_os.path().join("proc");
                platform_bridge.legacy_socket_root = empty_os.path().join("legacy-sockets");
                for path in [
                    &platform_bridge.systemd_root,
                    &platform_bridge.process_paths.root,
                    &platform_bridge.legacy_socket_root,
                ] {
                    std::fs::create_dir(path).unwrap();
                }
                if later_unavailable == "node-global-sweep" {
                    let unavailable_sweep_root = environment.state.parent().unwrap().join(format!(
                        "managed-vmm-unavailable-{label}-{later_unavailable}"
                    ));
                    platform_bridge.managed_vmm_socket_root = Some(Arc::new(
                        RetainedManagedVmmSocketRoot::provision_for_test(&unavailable_sweep_root)
                            .unwrap(),
                    ));
                }
                let platform_scanner = full_root_scanner(&fixture, [])
                    .with_root_process_bridge_for_test(Arc::new(platform_bridge))
                    .with_network_bridge(Arc::new(ExactRunningNetworkBridge));
                let RuntimeInventoryScanOutcome::Incomplete {
                    unavailable_sources,
                    exact_physical_negative_cats,
                } = platform_scanner
                    .scan_complete(platform_scan_context)
                    .unwrap()
                else {
                    panic!("production scanner lost {label} negative before {later_unavailable}")
                };
                assert!(unavailable_sources.contains(&InventorySource::Process));
                assert_eq!(
                    exact_physical_negative_cats,
                    BTreeSet::from([desired.cat_id.clone()]),
                    "production scanner lost {label} negative before {later_unavailable}"
                );
            }
        }
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: coordinates.session.node_id,
            node_boot_id: coordinates.session.node_boot_id,
            agent_instance_id: coordinates.session.agent_instance_id,
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        let process_admission = process_scan.bind(&observation).unwrap();
        let network_admission = network_scan.bind(&observation).unwrap();
        let tail_admission = tail.bind(&observation).unwrap();

        let absent_guest_calls = Arc::new(AtomicUsize::new(0));
        let absent_bridge = Arc::new(ExactRunningProcessBridge {
            state_directory: state_directory.clone(),
            systemd: test_root_provision_systemd(&environment.blockd_binary),
            executable_path: HostPath::new(
                environment.blockd_binary.to_string_lossy().into_owned(),
            )
            .unwrap(),
            exact_vmm_state: None,
        });
        let absent_registry = AdmissionCellRegistry::for_state_directory(&state_directory);
        let absent_scanner = full_root_scanner(&fixture, [])
            .with_root_process_bridge_for_test(absent_bridge)
            .with_network_bridge(Arc::new(ExactRunningNetworkBridge))
            .with_running_tail_transport_for_test(
                absent_registry,
                Arc::new(ExactRunningGuestReadyPort {
                    calls: Arc::clone(&absent_guest_calls),
                    fault: RunningGuestReadyFault::Exact,
                }),
            );
        let RuntimeInventoryScanOutcome::Complete(mut absent_inventory) = absent_scanner
            .scan_complete(fixture.scan_context.clone())
            .unwrap()
        else {
            panic!("an absent expected VMM is a complete Progressing observation")
        };
        assert_eq!(absent_guest_calls.load(Ordering::SeqCst), 0);
        assert!(matches!(
            absent_inventory.runtimes()[0].guest_transport,
            cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
        ));
        assert!(absent_inventory.take_running_tail_admission().is_none());

        let session = AgentSession {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            immutable_host_id: Id::new("host_test").unwrap(),
            node_boot_id: observation.node_boot_id.clone(),
            agent_instance_id: observation.agent_instance_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            registration_attempt_id: RandomId128::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd").unwrap(),
            guest_config_digest: desired.runtime.guest_config_digest.clone(),
            lease_deadline_unix_ms: UnixMillis::new(observation.observed_at_unix_ms.get() + 60_000)
                .unwrap(),
        };
        let attestation = AdmissionInventoryAttestation {
            version: ContractVersion::V1,
            node_id: observation.node_id.clone(),
            agent_session_epoch: observation.agent_session_epoch,
            inventory_epoch: observation.inventory_epoch,
            inventory_digest: observation.inventory_digest.clone().unwrap(),
            inventory_read_position: observation.inventory_read_position.unwrap(),
            accepted_at_unix_ms: UnixMillis::new(observation.observed_at_unix_ms.get() + 1)
                .unwrap(),
        };
        let admission =
            RuntimeDesiredEffectAdmission::for_test(session, observation.clone(), attestation)
                .bind_assigned_cats_for_test(&fixture.scan_context.coordinates().desired)
                .with_running_tail_for_test(tail_admission);
        let context = RuntimeDesiredEffectContext::for_test_with_admission(
            state_directory.clone(),
            Instant::now() + Duration::from_secs(5),
            admission,
        )
        .with_node_global_process_for_test(process_admission)
        .with_node_global_network_for_test(network_admission);
        let authority: Arc<dyn VolumeDataAuthority> = Arc::new(ExactVolumeSetDataAuthority {
            records: BTreeMap::from([(fixture.record.volume_id.clone(), fixture.record.clone())]),
        });
        let process_port = Arc::new(AcceptedRunningProcessPort);
        let network = Arc::new(
            super::super::network::PrepareNetworkReservationEffect::new(
                state_directory.clone(),
                exact_running_ip_binary(
                    environment.state.parent().unwrap(),
                    start_stored.checkpoint(),
                ),
                Arc::clone(&authority),
                Arc::clone(&process_port)
                    as Arc<
                        dyn super::super::serving_blockd_process::ServingBlockdProcessGlobalPort,
                    >,
            )
            .unwrap(),
        );
        let revalidator = Arc::new(
            super::super::RunningLaunchAuthorityRevalidator::platform_parts(
                state_directory,
                test_root_provision_systemd(&environment.blockd_binary),
                network,
                authority,
                Arc::clone(&process_port)
                    as Arc<
                        dyn super::super::serving_blockd_process::ServingBlockdProcessGlobalPort,
                    >,
                process_port as Arc<dyn super::super::vmm_process::VmmProcessGlobalPort>,
                None,
            ),
        );
        let effect_guest_calls = Arc::new(AtomicUsize::new(0));
        let effect = super::super::RunningAdmissionEffect::with_launch_authority(
            Arc::clone(&registry),
            revalidator,
        )
        .with_physical_revalidation_for_test(
            Arc::new(ExactRunningGuestReadyPort {
                calls: Arc::clone(&effect_guest_calls),
                fault: RunningGuestReadyFault::Exact,
            }),
            Arc::new(|_, _, _, _, _, _| {
                unreachable!("the real launch authority must replace the test hook")
            }),
        );
        let effect_desired = desired.clone();
        let (complete_tx, complete_rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let outcome = effect.try_apply(&context, &effect_desired);
            let _ = complete_tx.send(outcome);
        });
        let outcome = complete_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("production launch authority deadlocked on its checkpoint guard")
            .unwrap();
        assert_eq!(outcome, Some(RuntimeDesiredEffectOutcome::RefreshInventory));
        assert_eq!(effect_guest_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            registry
                .get(&desired.cat_id)
                .expect("production launch barrier opens the shared cell")
                .snapshot()
                .lifecycle_admission(),
            LifecycleAdmission::Open
        );
    }

    #[derive(Debug, Clone, Copy)]
    enum RunningFrontendFixture {
        VhostUserBlk,
        KernelNbd,
    }

    #[test]
    fn full_scanner_seals_exact_root_and_persistent_vhost_mount_set() {
        assert_full_scanner_seals_exact_root_and_persistent_mount_set(
            RunningFrontendFixture::VhostUserBlk,
        );
    }

    #[test]
    fn full_scanner_seals_exact_root_and_persistent_kernel_nbd_mount_set() {
        assert_full_scanner_seals_exact_root_and_persistent_mount_set(
            RunningFrontendFixture::KernelNbd,
        );
    }

    fn assert_full_scanner_seals_exact_root_and_persistent_mount_set(
        frontend_fixture: RunningFrontendFixture,
    ) {
        let environment = TestEnvironment::new();
        let template = decode_runtime_checkpoint(include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/runtime-reconciliation-v1-start-runtime-checkpoint.json"
        )))
        .unwrap();
        let ReconcileStep::StartRuntime {
            guest_config_digest,
            ..
        } = &template.step
        else {
            panic!("StartRuntime template")
        };
        let mut scan_context = assigned_context_with_root_and_persistent();
        let desired = &mut scan_context.coordinates_mut().desired.desired_specs[0];
        desired.cat_id = Id::new("c1").unwrap();
        let mut second_persistent = desired.volumes[1].clone();
        second_persistent.guest_device.slot = 2;
        second_persistent.acquire = VolumeAcquire::Normal {
            transition_id: RandomId128::new("33333333333333333333333333333333").unwrap(),
            expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
        };
        second_persistent.mount = Some(Ext4MountIntent {
            filesystem_uuid: RandomId128::new("ffffffffffffffffffffffffffffffff").unwrap(),
            mount_path: HostPath::new("/logs").unwrap(),
            initialization: FilesystemInitialization::Existing,
        });
        desired.volumes.push(second_persistent);
        let initialization_blank_head = RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        desired.volumes[1].mount.as_mut().unwrap().initialization =
            FilesystemInitialization::Initialize {
                initialization_token: RandomId128::new("abababababababababababababababab").unwrap(),
                expected_blank_head: initialization_blank_head.clone(),
            };
        desired.volumes[1].durability = Durability::Relaxed;
        for (volume, ids) in desired.volumes.iter_mut().zip([
            ("via", "dr", "vr", "ar", "root"),
            ("vib", "dp", "vp", "ap", "data"),
            ("vic", "dl", "vl", "al", "logs"),
        ]) {
            volume.volume_intent_id = Id::new(ids.0).unwrap();
            volume.disk_id = Id::new(ids.1).unwrap();
            volume.volume_id = Id::new(ids.2).unwrap();
            volume.attachment_id = Id::new(ids.3).unwrap();
            volume.guest_device.serial = Id::new(ids.4).unwrap();
        }
        desired.runtime.guest_config_digest = guest_config_digest.clone();
        desired.spec_digest = spec_digest(desired).unwrap();
        let desired = desired.clone();
        let kernel_nbd_client =
            matches!(frontend_fixture, RunningFrontendFixture::KernelNbd).then(|| {
                let path = environment.state.parent().unwrap().join("nbd-client");
                std::fs::write(&path, b"fixture").unwrap();
                std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
                let allocation_lock = environment.state.join("kernel-nbd-allocation.lock");
                std::fs::write(&allocation_lock, []).unwrap();
                std::fs::set_permissions(&allocation_lock, std::fs::Permissions::from_mode(0o600))
                    .unwrap();
                let allocation_lock_file = std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&allocation_lock)
                    .unwrap();
                // SAFETY: these calls only read the current process credentials.
                let effective_user_id = unsafe { libc::geteuid() };
                // SAFETY: these calls only read the current process credentials.
                let effective_group_id = unsafe { libc::getegid() };
                // SAFETY: the fixture owns this live descriptor and -1 keeps
                // its uid unchanged while aligning gid with this process.
                let chown_result = unsafe {
                    libc::fchown(
                        allocation_lock_file.as_raw_fd(),
                        libc::uid_t::MAX,
                        effective_group_id,
                    )
                };
                assert_eq!(chown_result, 0);
                let metadata = std::fs::metadata(&allocation_lock).unwrap();
                assert_eq!(
                    (
                        metadata.nlink(),
                        metadata.mode() & 0o7777,
                        metadata.uid(),
                        metadata.gid(),
                        metadata.len(),
                    ),
                    (1, 0o600, effective_user_id, effective_group_id, 0),
                    "kernel-NBD fixture allocation lock metadata",
                );
                path
            });

        let mut records = BTreeMap::new();
        let initialized_persistent_head = RemoteHead {
            generation: Generation::new(1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([2; 32])),
            root_object_id: Some(AsciiText::new("roots/vp").unwrap()),
        };
        let mut attachments = Vec::new();
        let mut devices = Vec::new();
        let mut listeners = Vec::new();
        for index in 0..desired.volumes.len() {
            let (mut record, mut attachment) =
                exact_owned_record_and_attachment_for(&desired, index);
            let head = RemoteHead {
                generation: Generation::new(1).unwrap(),
                root_hash: Some(Sha256Digest::from_bytes(
                    [u8::try_from(index + 1).unwrap(); 32],
                )),
                root_object_id: Some(
                    AsciiText::new(format!(
                        "roots/{}",
                        desired.volumes[index].volume_id.as_str()
                    ))
                    .unwrap(),
                ),
            };
            if index == 1 {
                assert_eq!(record.head, initialization_blank_head);
                assert_eq!(attachment.head, initialization_blank_head);
                assert_eq!(head, initialized_persistent_head);
            } else {
                record.head = head.clone();
                attachment.head = head;
            }
            let data = prepare_exact_lineage_for(&environment, &desired, index, &attachment);
            install_exact_control_only_files(&data, attachment.size_bytes);
            let mut device =
                direct_vhost_prepared_device(&environment, &desired, index, &attachment, &data);
            if matches!(frontend_fixture, RunningFrontendFixture::KernelNbd) {
                let (_, listener_socket_path) = managed_serving_sockets(&device.ownership_token);
                device.frontend = PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    device_path: HostPath::new(format!("/dev/nbd{index}")).unwrap(),
                    direct: false,
                };
            }
            let frontend_path = match &device.frontend {
                PrepareDeviceFrontend::VhostUserBlk { socket_path, .. } => socket_path,
                PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    ..
                } => listener_socket_path,
            };
            let (expected_control_socket, expected_io_socket) =
                managed_serving_sockets(&device.ownership_token);
            assert_eq!(
                device.serving_process.control_socket_path,
                expected_control_socket
            );
            assert_eq!(frontend_path, &expected_io_socket);
            if let (RunningFrontendFixture::KernelNbd, Some(client)) =
                (frontend_fixture, kernel_nbd_client.as_ref())
            {
                let pid = 201_u32 + u32::try_from(index).unwrap();
                let slot = environment.block_root.join(format!("nbd{index}"));
                std::fs::create_dir(&slot).unwrap();
                std::fs::write(slot.join("pid"), format!("{pid}\n")).unwrap();
                std::fs::write(
                    slot.join("size"),
                    format!("{}\n", attachment.size_bytes / 512),
                )
                .unwrap();
                let process = environment.proc_root.join(pid.to_string());
                std::fs::create_dir(&process).unwrap();
                let mut fields = vec!["S".to_owned()];
                fields.extend((0..18).map(|_| "0".to_owned()));
                fields.push((700_u64 + u64::from(pid)).to_string());
                fields.extend((0..4).map(|_| "0".to_owned()));
                std::fs::write(
                    process.join("stat"),
                    format!("{pid} (nbd-client) {}\n", fields.join(" ")),
                )
                .unwrap();
                std::os::unix::fs::symlink(client, process.join("exe")).unwrap();
                let PrepareDeviceFrontend::KernelNbd {
                    listener_socket_path,
                    device_path,
                    ..
                } = &device.frontend
                else {
                    unreachable!()
                };
                let arguments: [&[u8]; 9] = [
                    client.as_os_str().as_bytes(),
                    b"-nonetlink",
                    b"-unix",
                    listener_socket_path.as_str().as_bytes(),
                    device_path.as_str().as_bytes(),
                    b"-b",
                    b"512",
                    b"-N",
                    b"",
                ];
                let mut command_line = Vec::new();
                for argument in arguments {
                    command_line.extend_from_slice(argument);
                    command_line.push(0);
                }
                std::fs::write(process.join("cmdline"), command_line).unwrap();
            }
            records.insert(record.volume_id.clone(), record);
            attachments.push(attachment);
            devices.push(device);
            listeners.extend([SyntheticManagedListener, SyntheticManagedListener]);
        }

        let planned = crate::ch::plan_network(&desired.runtime.network_config).unwrap();
        let network = RuntimeNetworkIdentity {
            network_config: planned.config,
            tap_name: Id::new(planned.tap).unwrap(),
            ownership_token: planned.ownership_token,
        };
        let mut predecessor = acquire_checkpoint(
            &desired,
            &desired.volumes[0],
            RuntimeVolumeTransition::Acquire {
                request: attachments[0].checkpoint_acquire_request(),
            },
            UnixMillis::new(9_000).unwrap(),
        );
        predecessor.step = ReconcileStep::PrepareNetwork {
            network: network.clone(),
            devices: devices.clone(),
        };
        predecessor.volumes = devices
            .iter()
            .zip(&attachments)
            .enumerate()
            .map(|(index, (device, attachment))| {
                prepared_owned_observed_volume(
                    &desired.volumes[index],
                    attachment,
                    device.serving_process.data_directory.clone(),
                )
            })
            .collect();
        predecessor
            .volumes
            .sort_by(|left, right| left.volume_id.cmp(&right.volume_id));
        let checkpoint_store = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap();
        let stored_predecessor = checkpoint_store.create(&predecessor).unwrap();

        let ReconcileStep::StartRuntime {
            launcher_executable,
            boot,
            ..
        } = template.step
        else {
            panic!("StartRuntime template")
        };
        let runtime_incarnation = RandomId128::new("55555555555555555555555555555555").unwrap();
        let socket_paths = super::super::ManagedVmmSocketRoot::installed()
            .paths_for(&runtime_incarnation)
            .unwrap();
        let state_directory = StateDirectory::unanchored(environment.state.clone());
        let launch_file_paths = super::super::ManagedVmmLaunchFilePaths::for_incarnation(
            &state_directory,
            &runtime_incarnation,
        )
        .unwrap();
        let network_projection = ObservedNetwork {
            kind: network.network_config.kind,
            network_id: network.network_config.network_id.clone(),
            guest_mac: network.network_config.guest_mac.clone(),
            guest_ipv4: network.network_config.guest_ipv4.clone(),
            prefix_length: network.network_config.prefix_length,
            gateway_ipv4: network.network_config.gateway_ipv4.clone(),
            tap_name: network.tap_name.clone(),
            ownership_token: OwnershipTokenEvidence::Valid {
                ownership_token: network.ownership_token.clone(),
            },
        };
        let start = super::super::vmm_start_runtime::build_start_runtime_successor(
            &predecessor,
            &desired,
            runtime_incarnation,
            RandomId128::new("66666666666666666666666666666666").unwrap(),
            3,
            super::super::vmm_start_runtime::StartRuntimeCheckpointAuthority {
                launcher_executable: *launcher_executable,
                boot: *boot,
                network_projection,
                socket_paths: &socket_paths,
                launch_file_paths: &launch_file_paths,
            },
            UnixMillis::new(predecessor.updated_at_unix_ms.get() + 1).unwrap(),
        )
        .unwrap();
        checkpoint_store
            .replace(&stored_predecessor, &start)
            .unwrap();
        drop(checkpoint_store);

        let records = Arc::new(Mutex::new(records));
        let registry = AdmissionCellRegistry::for_state_directory(&state_directory);
        let guest_calls = Arc::new(AtomicUsize::new(0));
        let build_scanner = |fault, exact_vmms: bool| {
            let authority: Arc<dyn VolumeDataAuthority> = Arc::new(ExactVolumeSetDataAuthority {
                records: records.lock().unwrap().clone(),
            });
            let bridge = Arc::new(ExactRunningProcessBridge {
                state_directory: state_directory.clone(),
                systemd: test_root_provision_systemd(&environment.blockd_binary),
                executable_path: HostPath::new(
                    environment.blockd_binary.to_string_lossy().into_owned(),
                )
                .unwrap(),
                exact_vmm_state: exact_vmms.then_some(ProcessState::Running),
            });
            let mut config = environment.config();
            if let Some(client) = &kernel_nbd_client {
                config.kernel_nbd_inventory_port = Some(KernelNbdInventoryPort::new(
                    KernelNbdInventoryConfig::fixture(
                        state_directory.clone(),
                        environment.block_root.clone(),
                        environment.proc_root.clone(),
                        client.clone(),
                        u32::try_from(desired.volumes.len()).unwrap(),
                    ),
                ));
            }
            scanner_with_metadata_authority_and_blob(
                config,
                Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
                None,
            )
            .unwrap()
            .with_root_process_bridge_for_test(bridge)
            .with_network_bridge(Arc::new(ExactRunningNetworkBridge))
            .with_running_tail_transport_for_test(
                Arc::clone(&registry),
                Arc::new(ExactRunningGuestReadyPort {
                    calls: Arc::clone(&guest_calls),
                    fault,
                }),
            )
        };

        if let Some(client) = &kernel_nbd_client {
            let allocation_lock = environment.state.join("kernel-nbd-allocation.lock");
            let allocation_lock_file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&allocation_lock)
                .unwrap();
            // SAFETY: the fixture owns this descriptor and releases the
            // advisory lock below before dropping it.
            let lock_result =
                unsafe { libc::flock(allocation_lock_file.as_raw_fd(), libc::LOCK_EX) };
            assert_eq!(lock_result, 0);
            let authority: Arc<dyn VolumeDataAuthority> = Arc::new(ExactVolumeSetDataAuthority {
                records: records.lock().unwrap().clone(),
            });
            let mut config = environment.config();
            config.kernel_nbd_inventory_port = Some(KernelNbdInventoryPort::new(
                KernelNbdInventoryConfig::fixture(
                    state_directory.clone(),
                    environment.block_root.clone(),
                    environment.proc_root.clone(),
                    client.clone(),
                    u32::try_from(desired.volumes.len()).unwrap(),
                ),
            ));
            let scanner = scanner_with_metadata_authority_and_blob(
                config,
                Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
                None,
            )
            .unwrap()
            .with_root_process_bridge_for_test(Arc::new(
                PreservedNegativeUnavailableProcessBridge {
                    inner: ExactRunningProcessBridge {
                        state_directory: state_directory.clone(),
                        systemd: test_root_provision_systemd(&environment.blockd_binary),
                        executable_path: HostPath::new(
                            environment.blockd_binary.to_string_lossy().into_owned(),
                        )
                        .unwrap(),
                        exact_vmm_state: None,
                    },
                    exact_running_negative_cats: BTreeSet::from([desired.cat_id.clone()]),
                },
            ))
            .with_network_bridge(Arc::new(ExactRunningNetworkBridge));
            let RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
                exact_physical_negative_cats,
            } = scanner.scan_complete(scan_context.clone()).unwrap()
            else {
                panic!("missing process admission must skip the locked kernel-NBD pool")
            };
            assert!(unavailable_sources.contains(&InventorySource::Process));
            assert!(unavailable_sources.contains(&InventorySource::BlockFrontend));
            assert_eq!(
                exact_physical_negative_cats,
                BTreeSet::from([desired.cat_id.clone()])
            );
            // SAFETY: this unlock matches the successful fixture flock above.
            let unlock_result =
                unsafe { libc::flock(allocation_lock_file.as_raw_fd(), libc::LOCK_UN) };
            assert_eq!(unlock_result, 0);
        }

        let RuntimeInventoryScanOutcome::Complete(mut early_inventory) =
            build_scanner(RunningGuestReadyFault::Exact, true)
                .scan_complete(scan_context.clone())
                .unwrap()
        else {
            panic!("exact physical StartRuntime must remain a complete closed observation")
        };
        assert_eq!(guest_calls.load(Ordering::SeqCst), 0);
        assert!(
            early_inventory.take_running_tail_admission().is_none(),
            "Persistent StartRuntime must not mint Running-tail authority"
        );

        let checkpoint_store = FileCheckpointStore::open(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        )
        .unwrap();
        let mut phase_stored = checkpoint_store.load().unwrap().unwrap();
        let launch = phase_stored.checkpoint().runtime_launch.identity().unwrap();
        let mut persistent = launch
            .devices
            .iter()
            .filter(|device| device.disk_kind == DiskKind::Persistent)
            .map(|prepared| {
                let intent = desired
                    .volumes
                    .iter()
                    .find(|intent| intent.volume_id == prepared.volume_id)
                    .unwrap();
                let mount = intent.mount.as_ref().unwrap();
                (
                    PersistentFilesystemBinding {
                        runtime_incarnation: launch.runtime_incarnation.clone(),
                        volume_intent_id: prepared.volume_intent_id.clone(),
                        disk_id: prepared.disk_id.clone(),
                        volume_id: prepared.volume_id.clone(),
                        attachment_id: prepared.attachment_id.clone(),
                        attachment_epoch: prepared.attachment_epoch,
                        size_bytes: prepared.size_bytes,
                        guest_device: prepared.guest_device.clone(),
                        filesystem_uuid: mount.filesystem_uuid.clone(),
                        mount_path: mount.mount_path.clone(),
                        initialization: mount.initialization.clone(),
                    },
                    prepared.expected_head.clone(),
                )
            })
            .collect::<Vec<_>>();
        persistent.sort_by_key(|(filesystem, _)| filesystem.guest_device.slot);
        let first_filesystem = persistent[0].0.clone();
        let first_head = persistent[0].1.clone();
        let final_filesystem = persistent[1].0.clone();
        let final_head = persistent[1].1.clone();
        assert_eq!(first_head, initialization_blank_head);
        for step in [
            ReconcileStep::FormatFilesystem {
                filesystem: Box::new(first_filesystem.clone()),
            },
            ReconcileStep::DrainInitialization {
                filesystem: Box::new(first_filesystem.clone()),
                local_generation: Generation::new(1).unwrap(),
                remote_generation: Generation::new(0).unwrap(),
            },
            ReconcileStep::CommitInitialized {
                filesystem: Box::new(first_filesystem.clone()),
                new_remote_head: initialized_persistent_head.clone(),
            },
            ReconcileStep::MountFilesystem {
                filesystem: Box::new(first_filesystem.clone()),
                expected_head: initialized_persistent_head.clone(),
            },
        ] {
            let mut early = phase_stored.checkpoint().clone();
            early.step = step.clone();
            phase_stored = checkpoint_store.replace(&phase_stored, &early).unwrap();
            let RuntimeInventoryScanOutcome::Complete(mut inventory) =
                build_scanner(RunningGuestReadyFault::Exact, true)
                    .scan_complete(scan_context.clone())
                    .unwrap()
            else {
                panic!("exact early Persistent phase must remain a complete closed observation")
            };
            assert!(
                inventory.take_running_tail_admission().is_none(),
                "early Persistent phase {step:?} minted Running-tail authority"
            );
            assert_eq!(
                guest_calls.load(Ordering::SeqCst),
                0,
                "early Persistent phase challenged Guest Ready"
            );
        }
        let mut format = phase_stored.checkpoint().clone();
        format.step = ReconcileStep::FormatFilesystem {
            filesystem: Box::new(first_filesystem.clone()),
        };
        phase_stored = checkpoint_store.replace(&phase_stored, &format).unwrap();
        drop(checkpoint_store);

        let effect_authority: Arc<dyn VolumeDataAuthority> =
            Arc::new(SharedVolumeSetDataAuthority {
                records: Arc::clone(&records),
            });
        let process_port = Arc::new(AcceptedRunningProcessPort);
        let network = Arc::new(
            super::super::network::PrepareNetworkReservationEffect::new(
                state_directory.clone(),
                exact_running_ip_binary(
                    environment.state.parent().unwrap(),
                    phase_stored.checkpoint(),
                ),
                Arc::clone(&effect_authority),
                Arc::clone(&process_port)
                    as Arc<
                        dyn super::super::serving_blockd_process::ServingBlockdProcessGlobalPort,
                    >,
            )
            .unwrap(),
        );
        let kernel_nbd_revalidation = kernel_nbd_client.as_ref().map(|client| {
            KernelNbdInventoryConfig::fixture(
                state_directory.clone(),
                environment.block_root.clone(),
                environment.proc_root.clone(),
                client.clone(),
                u32::try_from(desired.volumes.len()).unwrap(),
            )
        });
        let revalidator = Arc::new(
            super::super::RunningLaunchAuthorityRevalidator::platform_parts(
                state_directory.clone(),
                test_root_provision_systemd(&environment.blockd_binary),
                network,
                Arc::clone(&effect_authority),
                Arc::clone(&process_port)
                    as Arc<
                        dyn super::super::serving_blockd_process::ServingBlockdProcessGlobalPort,
                    >,
                process_port as Arc<dyn super::super::vmm_process::VmmProcessGlobalPort>,
                kernel_nbd_revalidation,
            ),
        );
        let filesystem_operations = Arc::new(Mutex::new(Vec::new()));
        let filesystem_guest = Arc::new(ScriptedPersistentGuest {
            formatted: AtomicBool::new(false),
            lose_first_format_response: AtomicBool::new(true),
            operations: Arc::clone(&filesystem_operations),
        });
        let drains = Arc::new(AtomicUsize::new(0));
        let blockd = Arc::new(AdvancingRelaxedBlockd {
            records: Arc::clone(&records),
            volume_id: first_filesystem.volume_id.clone(),
            initialized_head: initialized_persistent_head.clone(),
            drains: Arc::clone(&drains),
        });
        let commits = Arc::new(AtomicUsize::new(0));
        let filesystem_effect = super::super::PersistentFilesystemEffect::for_test(
            effect_authority,
            Arc::new(CommitInitializedPort {
                calls: Arc::clone(&commits),
            }),
            filesystem_guest,
            blockd,
            revalidator,
        );
        let apply_filesystem_round = || {
            assert!(
                registry
                    .existing_session(&desired.cat_id)
                    .unwrap()
                    .is_none(),
                "an early filesystem scan created a Running admission session"
            );
            let RuntimeInventoryScanOutcome::Complete(inventory) =
                build_scanner(RunningGuestReadyFault::Exact, true)
                    .scan_complete(scan_context.clone())
                    .unwrap()
            else {
                panic!("filesystem phase must retain one complete physical inventory")
            };
            let context = bind_inventory_for_running_effect(
                inventory,
                &scan_context,
                state_directory.clone(),
            );
            assert_eq!(
                filesystem_effect.try_apply(&context, &desired).unwrap(),
                Some(RuntimeDesiredEffectOutcome::RefreshInventory)
            );
        };

        // mkfs succeeds but its first response is lost. The next accepted-full
        // round adopts the exact UUID and must not issue a second format.
        let load_filesystem_checkpoint = || {
            FileCheckpointStore::open(
                &environment.state.join(CHECKPOINT_NAMESPACE),
                &desired.cat_id,
            )
            .unwrap()
            .load()
            .unwrap()
            .unwrap()
        };
        apply_filesystem_round();
        assert!(matches!(
            load_filesystem_checkpoint().checkpoint().step,
            ReconcileStep::FormatFilesystem { .. }
        ));
        apply_filesystem_round();
        let after_format = load_filesystem_checkpoint();
        assert!(matches!(
            after_format.checkpoint().step,
            ReconcileStep::DrainInitialization {
                local_generation,
                remote_generation,
                ..
            } if local_generation.get() == 1 && remote_generation.get() == 0
        ));
        apply_filesystem_round();
        let after_drain = load_filesystem_checkpoint();
        assert!(matches!(
            &after_drain.checkpoint().step,
            ReconcileStep::CommitInitialized {
                new_remote_head,
                ..
            } if new_remote_head == &initialized_persistent_head
        ));
        apply_filesystem_round();
        let after_commit = load_filesystem_checkpoint();
        assert!(matches!(
            &after_commit.checkpoint().step,
            ReconcileStep::MountFilesystem {
                filesystem,
                expected_head,
            } if filesystem.volume_id == first_filesystem.volume_id
                && expected_head == &initialized_persistent_head
        ));
        apply_filesystem_round();
        let after_mount = load_filesystem_checkpoint();
        assert!(matches!(
            &after_mount.checkpoint().step,
            ReconcileStep::MountFilesystem {
                filesystem,
                expected_head,
            } if filesystem.as_ref() == &final_filesystem
                && expected_head == &final_head
        ));

        // The durable Mount checkpoint is only a lower bound on the current
        // attachment head. A write to an already mounted sibling may publish a
        // later head before this final volume is handled. Both the fresh Probe
        // and the post-launch-barrier Mount must bind that same current head;
        // replaying the checkpoint's older head would be stale authority.
        let advanced_final_head = RemoteHead {
            generation: Generation::new(final_head.generation.get() + 1).unwrap(),
            root_hash: Some(Sha256Digest::from_bytes([9; 32])),
            root_object_id: Some(AsciiText::new("roots/vl-advanced").unwrap()),
        };
        records
            .lock()
            .unwrap()
            .get_mut(&final_filesystem.volume_id)
            .unwrap()
            .head = advanced_final_head.clone();
        apply_filesystem_round();
        let after_final_mount = load_filesystem_checkpoint();
        assert!(matches!(
            &after_final_mount.checkpoint().step,
            ReconcileStep::MountFilesystem {
                filesystem,
                expected_head,
            } if filesystem.as_ref() == &final_filesystem
                && expected_head == &final_head
        ));
        assert_eq!(drains.load(Ordering::SeqCst), 1);
        assert_eq!(commits.load(Ordering::SeqCst), 1);
        let operations = filesystem_operations.lock().unwrap();
        assert_eq!(
            operations
                .iter()
                .filter(|(operation, _, _)| {
                    *operation == FilesystemControlOperationV1::FormatExt4
                })
                .count(),
            1,
            "an ambiguous mkfs response must be adopted by exact UUID probe"
        );
        let final_mount_operations = operations
            .iter()
            .filter(|(_, volume_id, _)| volume_id == &final_filesystem.volume_id)
            .collect::<Vec<_>>();
        assert_eq!(
            final_mount_operations.len(),
            2,
            "the final Existing volume needs one exact Probe and Mount"
        );
        assert!(final_mount_operations.iter().all(|(operation, _, head)| {
            matches!(
                operation,
                FilesystemControlOperationV1::Probe | FilesystemControlOperationV1::MountExt4
            ) && head == &advanced_final_head
        }));
        assert!(operations.iter().all(|(_, volume_id, head)| {
            if volume_id == &final_filesystem.volume_id {
                head == &advanced_final_head
            } else {
                head == &initialization_blank_head || head == &initialized_persistent_head
            }
        }));
        drop(operations);

        let RuntimeInventoryScanOutcome::Complete(mut inventory) =
            build_scanner(RunningGuestReadyFault::Exact, true)
                .scan_complete(scan_context.clone())
                .unwrap()
        else {
            panic!("exact Root + Persistent physical set must complete")
        };
        assert_eq!(
            guest_calls.load(Ordering::SeqCst),
            2,
            "the final-Mount effect scan and acceptance scan each challenge the exact mounted set"
        );
        assert_eq!(inventory.runtimes()[0].volumes.len(), 3);
        assert_eq!(inventory.runtimes()[0].mounts.len(), 3);
        assert_eq!(inventory.runtimes()[0].processes.len(), 4);
        let bind_inventory = |inventory: &mut crate::runtime_spine::CompleteRuntimeInventory| {
            let process_scan = inventory
                .take_node_global_process_admission()
                .expect("full Running scan process authority");
            let network_scan = inventory
                .take_node_global_network_admission()
                .expect("full Running scan network authority");
            let tail_scan = inventory
                .take_running_tail_admission()
                .expect("full Running scan mounted-set authority");
            let coordinates = scan_context.coordinates().clone();
            let mut observation = NodeObservation {
                version: ContractVersion::V1,
                observation_id: RandomId128::new("abababababababababababababababab").unwrap(),
                node_id: coordinates.session.node_id.clone(),
                node_boot_id: coordinates.session.node_boot_id.clone(),
                agent_instance_id: coordinates.session.agent_instance_id.clone(),
                agent_session_epoch: coordinates.session.agent_session_epoch,
                heartbeat_sequence: coordinates.heartbeat_sequence,
                observed_at_unix_ms: inventory.observed_at_unix_ms(),
                complete_inventory: true,
                inventory_epoch: coordinates.inventory_epoch,
                inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
                inventory_read_position: Some(coordinates.desired.read_position),
                key_ring_version: None,
                key_ring_digest: None,
                loaded_kids: Vec::new(),
                runtimes: inventory.runtimes().to_vec(),
                residue: inventory.residue().to_vec(),
            };
            observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
            let process = process_scan.bind(&observation).unwrap();
            let network = network_scan.bind(&observation).unwrap();
            let tail = tail_scan.bind(&observation).unwrap();
            let session = AgentSession {
                version: ContractVersion::V1,
                node_id: observation.node_id.clone(),
                immutable_host_id: Id::new("host_test").unwrap(),
                node_boot_id: observation.node_boot_id.clone(),
                agent_instance_id: observation.agent_instance_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
                registration_attempt_id: RandomId128::new("cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd")
                    .unwrap(),
                guest_config_digest: desired.runtime.guest_config_digest.clone(),
                lease_deadline_unix_ms: UnixMillis::new(
                    observation.observed_at_unix_ms.get() + 60_000,
                )
                .unwrap(),
            };
            let attestation = AdmissionInventoryAttestation {
                version: ContractVersion::V1,
                node_id: observation.node_id.clone(),
                agent_session_epoch: observation.agent_session_epoch,
                inventory_epoch: observation.inventory_epoch,
                inventory_digest: observation.inventory_digest.clone().unwrap(),
                inventory_read_position: observation.inventory_read_position.unwrap(),
                accepted_at_unix_ms: UnixMillis::new(observation.observed_at_unix_ms.get() + 1)
                    .unwrap(),
            };
            let admission =
                RuntimeDesiredEffectAdmission::for_test(session, observation.clone(), attestation)
                    .bind_assigned_cats_for_test(&coordinates.desired)
                    .with_running_tail_for_test(tail);
            RuntimeDesiredEffectContext::for_test_with_admission(
                state_directory.clone(),
                Instant::now() + Duration::from_secs(5),
                admission,
            )
            .with_node_global_process_for_test(process)
            .with_node_global_network_for_test(network)
        };
        if matches!(frontend_fixture, RunningFrontendFixture::VhostUserBlk) {
            let context = bind_inventory(&mut inventory);
            let launch_revalidated = Arc::new(AtomicBool::new(false));
            let launch_hook_flag = Arc::clone(&launch_revalidated);
            let fresh_guest_calls = Arc::new(AtomicUsize::new(0));
            let checkpoint_path = runtime_checkpoint_path(
                &environment.state.join(CHECKPOINT_NAMESPACE),
                &desired.cat_id,
            );
            let fresh_guest = Arc::new(LaunchOrderedGuestReadyPort {
                launch_revalidated: Arc::clone(&launch_revalidated),
                prepared_checkpoint_path: checkpoint_path.clone(),
                inner: ExactRunningGuestReadyPort {
                    calls: Arc::clone(&fresh_guest_calls),
                    fault: RunningGuestReadyFault::ForeignPersistentUuid,
                },
            });
            let before = std::fs::read(&checkpoint_path).unwrap();
            let effect = super::super::RunningAdmissionEffect::new(Arc::clone(&registry))
                .with_physical_revalidation_for_test(
                    fresh_guest,
                    Arc::new(move |_, _, _, _, _, _| {
                        launch_hook_flag.store(true, Ordering::SeqCst);
                        Ok(())
                    }),
                );
            let error = effect
                .try_apply(&context, &desired)
                .expect_err("changed Persistent UUID opened Running admission");
            let error_chain = format!("{error:#}");
            assert!(
                error_chain.contains("Persistent mount differs"),
                "{error_chain}"
            );
            assert_eq!(fresh_guest_calls.load(Ordering::SeqCst), 1);
            assert!(launch_revalidated.load(Ordering::SeqCst));
            assert_eq!(
                registry
                    .get(&desired.cat_id)
                    .expect("effect creates one fail-closed cell")
                    .snapshot()
                    .lifecycle_admission(),
                LifecycleAdmission::Closed,
            );
            let after = std::fs::read(&checkpoint_path).unwrap();
            assert_ne!(after, before);
            let prepared = decode_runtime_checkpoint(&after).unwrap();
            assert!(matches!(
                prepared.step,
                ReconcileStep::Stable {
                    state: cats_api::runtime_reconciliation::StableState::Running
                }
            ));
            assert_eq!(prepared.lifecycle_admission, LifecycleAdmission::Open);
        }

        let mut success_inventory =
            if matches!(frontend_fixture, RunningFrontendFixture::VhostUserBlk) {
                let RuntimeInventoryScanOutcome::Complete(inventory) =
                    build_scanner(RunningGuestReadyFault::Exact, true)
                        .scan_complete(scan_context.clone())
                        .unwrap()
                else {
                    panic!("prepared vhost admission did not rescan exactly")
                };
                inventory
            } else {
                inventory
            };
        let success_context = bind_inventory(&mut success_inventory);
        let success_launch_revalidated = Arc::new(AtomicBool::new(false));
        let success_launch_hook = Arc::clone(&success_launch_revalidated);
        let success_guest_calls = Arc::new(AtomicUsize::new(0));
        let checkpoint_path = runtime_checkpoint_path(
            &environment.state.join(CHECKPOINT_NAMESPACE),
            &desired.cat_id,
        );
        let success_guest = Arc::new(LaunchOrderedGuestReadyPort {
            launch_revalidated: Arc::clone(&success_launch_revalidated),
            prepared_checkpoint_path: checkpoint_path.clone(),
            inner: ExactRunningGuestReadyPort {
                calls: Arc::clone(&success_guest_calls),
                fault: RunningGuestReadyFault::Exact,
            },
        });
        let success_effect = super::super::RunningAdmissionEffect::new(Arc::clone(&registry))
            .with_physical_revalidation_for_test(
                success_guest,
                Arc::new(move |_, _, _, _, _, _| {
                    success_launch_hook.store(true, Ordering::SeqCst);
                    Ok(())
                }),
            );
        assert!(matches!(
            success_effect
                .try_apply(&success_context, &desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        ));
        assert_eq!(success_guest_calls.load(Ordering::SeqCst), 1);
        assert!(success_launch_revalidated.load(Ordering::SeqCst));
        assert_eq!(
            registry
                .get(&desired.cat_id)
                .expect("exact mounted set opens one admission cell")
                .snapshot()
                .lifecycle_admission(),
            LifecycleAdmission::Open,
        );
        let stable = decode_runtime_checkpoint(&std::fs::read(checkpoint_path).unwrap()).unwrap();
        assert!(matches!(
            stable.step,
            ReconcileStep::Stable {
                state: cats_api::runtime_reconciliation::StableState::Running
            }
        ));

        for fault in [
            RunningGuestReadyFault::MissingPersistent,
            RunningGuestReadyFault::DuplicateRootMount,
            RunningGuestReadyFault::ForeignPersistentUuid,
        ] {
            let RuntimeInventoryScanOutcome::Complete(mut inventory) = build_scanner(fault, true)
                .scan_complete(scan_context.clone())
                .unwrap()
            else {
                panic!("invalid Guest mount set is exact closed progress")
            };
            assert!(inventory.runtimes()[0].mounts.is_empty());
            assert_eq!(
                inventory.runtimes()[0].lifecycle_admission,
                LifecycleAdmission::Open,
                "the scanner must project the still-live shared cell"
            );
            assert!(
                inventory.take_running_tail_admission().is_some(),
                "Guest drift must mint a close-only retirement sidecar"
            );
        }

        let RuntimeInventoryScanOutcome::Complete(mut vmm_absent) =
            build_scanner(RunningGuestReadyFault::Exact, false)
                .scan_complete(scan_context.clone())
                .unwrap()
        else {
            panic!("an absent expected VMM is complete negative physical evidence")
        };
        assert_eq!(
            vmm_absent.runtimes()[0].lifecycle_admission,
            LifecycleAdmission::Open,
            "VMM absence must not hide a still-live shared cell"
        );
        assert!(matches!(
            vmm_absent.runtimes()[0].guest_transport,
            cats_api::runtime_reconciliation::GuestTransportEvidence::Unavailable
        ));
        let vmm_absent_context = bind_inventory(&mut vmm_absent);
        assert_eq!(
            success_effect
                .try_retire(&vmm_absent_context, &desired)
                .unwrap(),
            Some(RuntimeDesiredEffectOutcome::RefreshInventory)
        );
        assert_eq!(
            registry
                .get(&desired.cat_id)
                .expect("negative physical proof retains the cell until retirement")
                .snapshot()
                .lifecycle_admission(),
            LifecycleAdmission::Closed,
        );

        // The blockd artifacts deliberately remain bound to the immutable
        // launch Desired (R0). A later stable Endpoint-only Desired (R1) must
        // be rescannable from those Superseded artifacts without rewriting
        // storage launch provenance.
        let mut gate_desired = desired.clone();
        gate_desired.desired_revision = Revision::new(desired.desired_revision.get() + 1).unwrap();
        let endpoint_template =
            cats_api::runtime_reconciliation::decode_desired_runtime_spec(include_bytes!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/../testdata/runtime-reconciliation-v1-desired.json"
            )))
            .unwrap()
            .endpoints
            .remove(0);
        gate_desired.endpoints = vec![endpoint_template.clone()];
        gate_desired.spec_digest = spec_digest(&gate_desired).unwrap();
        let mut gate_stable = stable;
        gate_stable.desired_revision = gate_desired.desired_revision;
        gate_stable.spec_digest = gate_desired.spec_digest.clone();
        gate_stable.updated_at_unix_ms =
            UnixMillis::new(gate_stable.updated_at_unix_ms.get() + 1).unwrap();
        let runtime_incarnation = gate_stable
            .runtime_launch
            .identity()
            .unwrap()
            .runtime_incarnation
            .clone();
        gate_stable.route_gates = vec![cats_api::runtime_reconciliation::CheckpointRouteGate {
            binding: cats_api::runtime_reconciliation::RouteGateBinding {
                workspace_id: gate_desired.workspace_id.clone(),
                endpoint_id: endpoint_template.endpoint_id,
                hostname: endpoint_template.hostname,
                cat_id: gate_desired.cat_id.clone(),
                node_id: gate_desired.placement.node_id.clone(),
                runtime_incarnation,
                route_epoch: endpoint_template.route_epoch,
                protocol: endpoint_template.protocol,
                target_port: endpoint_template.target_port,
            },
            gate: cats_api::runtime_reconciliation::RouteGateState::Active,
        }];
        let active_session = registry
            .existing_session(&desired.cat_id)
            .unwrap()
            .expect("successful admission retains its checkpoint writer");
        let predecessor = active_session.checkpoint_store().load().unwrap().unwrap();
        active_session
            .checkpoint_store()
            .replace(&predecessor, &gate_stable)
            .unwrap();
        let mut gate_scan_context = scan_context.clone();
        gate_scan_context.coordinates_mut().desired.desired_specs[0] = gate_desired.clone();
        let authority: Arc<dyn VolumeDataAuthority> = Arc::new(ExactVolumeSetDataAuthority {
            records: records.lock().unwrap().clone(),
        });
        let bridge = Arc::new(ExactRunningProcessBridge {
            state_directory: state_directory.clone(),
            systemd: test_root_provision_systemd(&environment.blockd_binary),
            executable_path: HostPath::new(
                environment.blockd_binary.to_string_lossy().into_owned(),
            )
            .unwrap(),
            exact_vmm_state: Some(ProcessState::Running),
        });
        let mut config = environment.config();
        if let Some(client) = &kernel_nbd_client {
            config.kernel_nbd_inventory_port = Some(KernelNbdInventoryPort::new(
                KernelNbdInventoryConfig::fixture(
                    state_directory.clone(),
                    environment.block_root.clone(),
                    environment.proc_root.clone(),
                    client.clone(),
                    u32::try_from(gate_desired.volumes.len()).unwrap(),
                ),
            ));
        }
        let endpoint_registry = AdmissionCellRegistry::for_state_directory(&state_directory);
        let endpoint_scanner = scanner_with_metadata_authority_and_blob(
            config,
            Arc::new(VolumeDataAuthorityMetadataReader::start(authority).unwrap()),
            None,
        )
        .unwrap()
        .with_root_process_bridge_for_test(bridge)
        .with_network_bridge(Arc::new(ExactRunningNetworkBridge))
        .with_running_tail_transport_for_test(
            endpoint_registry,
            Arc::new(ExactRunningGuestReadyPort {
                calls: Arc::clone(&guest_calls),
                fault: RunningGuestReadyFault::Exact,
            }),
        );
        let RuntimeInventoryScanOutcome::Complete(mut gate_inventory) =
            endpoint_scanner.scan_complete(gate_scan_context).unwrap()
        else {
            panic!("R0 blockd artifacts plus current Stable/Open R1 must rescan exactly")
        };
        assert_eq!(
            gate_inventory.runtimes()[0].processes.len(),
            gate_desired.volumes.len() + 1,
        );
        assert!(gate_inventory.take_running_tail_admission().is_some());
        drop(listeners);
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
        drop(ready);

        let live_old_process = exact_process_evidence(&fixture.expected, 79);
        let _live_old_socket = install_exact_process_fixture(
            &environment,
            &fixture.expected,
            live_old_process.process_id,
        );
        let old_only_scanner = full_root_scanner(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
            ],
        );
        let RuntimeInventoryScanOutcome::Complete(mut old_only_inventory) = old_only_scanner
            .scan_complete(fixture.scan_context.clone())
            .unwrap()
        else {
            panic!("retained old exact plus serving absent must remain complete")
        };
        assert_eq!(old_only_inventory.runtimes()[0].processes.len(), 1);
        let old_only_admission = old_only_inventory
            .take_node_global_process_admission()
            .expect("old-only scan retains the same-Cat closed role set");
        assert!(old_only_admission
            .root_control_proofs()
            .contains_key(&fixture.acquired.desired.cat_id));
        assert!(old_only_admission.serving_blockd_proofs().is_empty());
        assert!(old_only_admission
            .into_admission_for_test()
            .serving_blockd(
                &fixture.acquired.desired.cat_id,
                &fixture.acquired.desired.volumes[0].volume_id,
            )
            .is_some());

        let retained =
            AuthorizedBlockdStore::new(StateDirectory::unanchored(environment.state.clone()))
                .retain_prepare_device_handoff(&successor, &fixture.acquired.desired)
                .unwrap();
        let serving_ready = handoff_store
            .reopen_prepare_device_handoff(
                &successor,
                &fixture.acquired.desired,
                &fixture.record,
                retained,
            )
            .unwrap();
        let serving_expected = ServingBlockdExpectation::from_handoff(
            &serving_ready,
            &test_root_provision_systemd(&environment.blockd_binary),
            &successor,
            &fixture.acquired.desired,
            &fixture.record,
        )
        .unwrap();
        drop(serving_ready);
        std::fs::create_dir(
            environment
                .systemd_root
                .join(serving_expected.unit_id().as_str()),
        )
        .unwrap();
        let serving_proc = environment.proc_root.join("81");
        std::fs::create_dir(&serving_proc).unwrap();
        std::os::unix::fs::symlink(
            serving_expected.executable_path().as_str(),
            serving_proc.join("exe"),
        )
        .unwrap();
        let serving_cmdline = serving_expected
            .command_line()
            .iter()
            .flat_map(|argument| {
                argument
                    .as_os_str()
                    .as_bytes()
                    .iter()
                    .copied()
                    .chain(std::iter::once(0))
            })
            .collect::<Vec<_>>();
        std::fs::write(serving_proc.join("cmdline"), serving_cmdline).unwrap();
        let _serving_control = SyntheticManagedListener;
        let _serving_frontend = SyntheticManagedListener;
        let scanner = full_root_scanner_with_serving(
            &fixture,
            [
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
            ],
            [Some(81), Some(81)],
        );
        let RuntimeInventoryScanOutcome::Complete(mut inventory) =
            scanner.scan_complete(fixture.scan_context.clone()).unwrap()
        else {
            panic!("live old target-control process must remain exact after PrepareDevice CAS")
        };
        assert_eq!(inventory.runtimes()[0].processes.len(), 2);
        assert_eq!(inventory.runtimes()[0].processes[0].process_id, 79);
        assert_eq!(inventory.runtimes()[0].processes[1].process_id, 81);
        assert!(matches!(
            inventory.runtimes()[0].volumes[0].devices.as_slice(),
            [cats_api::runtime_reconciliation::ObservedDevice::VhostUserBlk { .. }]
        ));
        let admission = inventory
            .take_node_global_process_admission()
            .expect("fresh PrepareDevice scan retains both process roles");
        assert!(admission
            .root_control_proofs()
            .contains_key(&fixture.acquired.desired.cat_id));
        assert!(admission
            .serving_blockd_proofs()
            .contains_key(&ManagedServingKey::new(
                fixture.acquired.desired.cat_id.clone(),
                fixture.acquired.desired.volumes[0].volume_id.clone(),
            )));

        // A Root-control effect must revalidate the same complete admitted
        // role set. The exact serving process is legitimate residue even when
        // the target belongs to another Cat, for both exact and absent Root
        // targets; a truly foreign third identity still closes the effect.
        let second_root = second_root_process_expectation(&environment, &fixture.expected);
        let second_process = exact_process_evidence(&second_root, 82);
        let second_socket =
            install_exact_process_fixture(&environment, &second_root, second_process.process_id);
        let exact_context = effect_context_with_managed_processes(
            &environment,
            [
                (fixture.expected.clone(), Some(live_old_process.clone())),
                (second_root.clone(), Some(second_process.clone())),
            ],
            [(serving_expected.clone(), Some(81))],
            BTreeMap::new(),
        );
        let exact_bridge = root_process_bridge_with_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(
                    [
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Exact(Box::new(second_process.clone())),
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Exact(Box::new(second_process.clone())),
                    ]
                    .into(),
                ),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new([Some(81), Some(81)].into()),
            }),
        );
        assert_eq!(
            exact_bridge
                .inspect_exact_after_node_global_sweep(&second_root, &exact_context)
                .unwrap(),
            RootProvisionProcessInspection::Exact(Box::new(second_process))
        );

        let _ = second_socket;
        std::fs::remove_dir_all(environment.systemd_root.join(second_root.scope_id.as_str()))
            .unwrap();
        std::fs::remove_dir_all(environment.proc_root.join("82")).unwrap();
        let absent_context = effect_context_with_managed_processes(
            &environment,
            [
                (fixture.expected.clone(), Some(live_old_process.clone())),
                (second_root.clone(), None),
            ],
            [(serving_expected.clone(), Some(81))],
            BTreeMap::from([
                (
                    fixture.expected.cat_id.clone(),
                    StopReceiptSocketAdmission::new(
                        fixture.expected.control_socket_path.clone(),
                        BTreeSet::from([fixture.expected.control_socket_path.clone()]),
                    )
                    .unwrap(),
                ),
                (
                    second_root.cat_id.clone(),
                    StopReceiptSocketAdmission::new(
                        second_root.control_socket_path.clone(),
                        BTreeSet::from([second_root.control_socket_path.clone()]),
                    )
                    .unwrap(),
                ),
            ]),
        );
        let absent_bridge = root_process_bridge_with_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(
                    [
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Absent,
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Absent,
                    ]
                    .into(),
                ),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new([Some(81), Some(81)].into()),
            }),
        );
        assert_eq!(
            absent_bridge
                .inspect_after_node_global_sweep(&second_root, &absent_context)
                .unwrap(),
            RootProvisionProcessInspection::Absent
        );

        let receipt_bridge = root_process_bridge_with_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(
                    [
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Absent,
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Absent,
                    ]
                    .into(),
                ),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new([Some(81), Some(81)].into()),
            }),
        );
        assert_eq!(
            receipt_bridge
                .inspect_absent_with_admitted_stop_receipt(&second_root, &absent_context)
                .unwrap(),
            RootProvisionProcessInspection::Absent
        );

        let foreign_unit = environment.systemd_root.join("cats-foreign.service");
        std::fs::create_dir(&foreign_unit).unwrap();
        let foreign_bridge = root_process_bridge_with_ports(
            &environment,
            Arc::new(FakeRootProcessPort {
                inspections: Mutex::new(
                    [
                        RootProvisionProcessInspection::Exact(Box::new(live_old_process.clone())),
                        RootProvisionProcessInspection::Absent,
                    ]
                    .into(),
                ),
            }),
            Arc::new(FakeServingProcessPort {
                process_ids: Mutex::new([Some(81)].into()),
            }),
        );
        assert!(matches!(
            foreign_bridge
                .inspect_after_node_global_sweep(&second_root, &absent_context)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
        std::fs::remove_dir(foreign_unit).unwrap();
        std::fs::remove_dir_all(second_root.data_directory.as_str()).unwrap();
        let _ = (_serving_control, _serving_frontend);
        std::fs::remove_dir_all(
            environment
                .systemd_root
                .join(serving_expected.unit_id().as_str()),
        )
        .unwrap();
        std::fs::remove_dir_all(serving_proc).unwrap();

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
            assert_eq!(
                fixture.expected.control_socket_path,
                managed_root_control_socket(&fixture.expected.provision_transition_id),
                "conflict classification must not rewrite the retained managed socket identity"
            );
            assert!(
                !fixture.data_directory.join("root-provision.sock").exists(),
                "a managed Root socket must never reappear in durable Cat data"
            );
        }

        let current = checkpoint_store.load().unwrap().unwrap();
        let mut drifted = successor.clone();
        let ReconcileStep::PrepareDevice { devices } = &mut drifted.step else {
            unreachable!()
        };
        devices[0].serving_process.data_directory = HostPath::new(
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
        let ReconcileStep::PrepareDevice { devices } = &mut direct.step else {
            unreachable!()
        };
        *devices[0].serving_authority = ServingAuthorityProvenance::DirectAuthorizedAttachment {
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
                    request: attachment.checkpoint_acquire_request(),
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
                control_socket_path: managed_root_control_socket(&provision_transition_id),
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
        let assigned_cats = scan_context.assigned_cats().unwrap();
        let checkpoint_snapshot = snapshot_runtime_checkpoint_namespace(
            &root,
            &scan_context,
            &assigned_cats,
            limits.state_entries,
        )
        .unwrap()
        .unwrap();
        assert_eq!(checkpoint_snapshot.iter_checkpoints().len(), CAT_COUNT);
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
            RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
                ..
            }
                if unavailable_sources.contains(&InventorySource::DataDirectory)
        ));
        for name in ["cache.data", "dirty.bitmap", PENDING_PACK_DIR] {
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
                        .and_then(|items| {
                            items.get(&fixture.acquired.desired.volumes[0].volume_id)
                        })
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
        for name in ["cache.data", "dirty.bitmap", PENDING_PACK_DIR] {
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
    fn scanner_private_process_admission_binds_exact_full_observation_coordinates() {
        let environment = TestEnvironment::new();
        let fixture = full_root_scanner_fixture(&environment);
        let coordinates = fixture.scan_context.coordinates().clone();
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
        let RuntimeInventoryScanOutcome::Complete(mut inventory) =
            scanner.scan_complete(fixture.scan_context).unwrap()
        else {
            panic!("all exact sources must complete the full scan")
        };
        let scan_admission = inventory
            .take_node_global_process_admission()
            .expect("full scanner must retain its private process admission");
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: coordinates.session.node_id.clone(),
            node_boot_id: coordinates.session.node_boot_id.clone(),
            agent_instance_id: coordinates.session.agent_instance_id.clone(),
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        let admission = scan_admission.bind(&observation).unwrap();
        assert!(admission.matches_observation(&observation));

        let mut changed = observation.clone();
        changed.observation_id = RandomId128::new("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb").unwrap();
        assert!(!admission.matches_observation(&changed));
        let mut changed = observation.clone();
        changed.inventory_digest = Some(Sha256Digest::from_bytes([9; 32]));
        assert!(!admission.matches_observation(&changed));
        let mut changed = observation.clone();
        changed.agent_session_epoch = Epoch::new(changed.agent_session_epoch.get() + 1).unwrap();
        assert!(!admission.matches_observation(&changed));
        let mut changed = observation;
        changed.inventory_read_position =
            Some(cats_api::runtime_reconciliation::Sequence::new(13).unwrap());
        assert!(!admission.matches_observation(&changed));
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                &assigned_context(true),
            )
                .unwrap(),
            RootProcessInventoryBridgeOutcome::Complete(admission)
                if admission.root_control_proofs().is_empty()
        ));

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let bridge =
            root_process_bridge(&environment, [RootProvisionProcessInspection::Unavailable]);
        assert!(matches!(
            bridge
                .inspect_all(
                    BTreeMap::from([(expected.cat_id.clone(), expected)]),
                    BTreeMap::new(),
                    BTreeMap::new(),
                    BTreeMap::new(),
                    &assigned_context(true),
                )
                .unwrap(),
            RootProcessInventoryBridgeOutcome::Unavailable { .. }
        ));
    }

    #[test]
    fn root_process_bridge_fails_closed_on_conflict_foreign_and_legacy_socket() {
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
                &assigned_context(true),
            )
            .is_err());

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let legacy_socket = environment.socket_root.join("legacy-root-provision.sock");
        let _partial = std::os::unix::net::UnixListener::bind(&legacy_socket).unwrap();
        std::fs::set_permissions(
            legacy_socket,
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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
        let context = effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &context)
                .unwrap(),
            RootProvisionProcessInspection::Absent
        ));

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let foreign_unit = environment.systemd_root.join("cats-foreign.service");
        std::fs::create_dir(&foreign_unit).unwrap();
        let bridge = root_process_bridge(&environment, [RootProvisionProcessInspection::Absent]);
        let context = effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &context)
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
        let context = effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &context)
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
        let context = effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &context)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
        assert!(foreign_socket_path.exists());
    }

    #[test]
    fn effect_global_port_brackets_exact_and_absent_and_rejects_late_duplicate() {
        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let effect_context =
            effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Absent,
                RootProvisionProcessInspection::Absent,
            ],
        );
        assert_eq!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&expected, &effect_context,)
                .unwrap(),
            RootProvisionProcessInspection::Absent
        );

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let exact = exact_process_evidence(&expected, 76);
        let effect_context = effect_context_with_root_controls(
            &environment,
            [(expected.clone(), Some(exact.clone()))],
        );
        let _socket = install_exact_process_fixture(&environment, &expected, exact.process_id);
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
                RootProvisionProcessInspection::Exact(Box::new(exact.clone())),
            ],
        );
        assert_eq!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&expected, &effect_context,)
                .unwrap(),
            RootProvisionProcessInspection::Exact(Box::new(exact))
        );

        // Even one allowed exact launch cannot hide a second managed
        // blank/wrapper incarnation elsewhere in the Node-global namespace.
        std::fs::create_dir(environment.systemd_root.join("cats-second.service")).unwrap();
        let exact = exact_process_evidence(&expected, 76);
        let effect_context = effect_context_with_root_controls(
            &environment,
            [(expected.clone(), Some(exact.clone()))],
        );
        let bridge = root_process_bridge(
            &environment,
            [RootProvisionProcessInspection::Exact(Box::new(exact))],
        );
        assert!(matches!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&expected, &effect_context,)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));

        let environment = TestEnvironment::new();
        let (expected, _) = root_process_expectation(&environment);
        let effect_context =
            effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        std::fs::create_dir(environment.systemd_root.join("cats-late.service")).unwrap();
        let bridge = root_process_bridge(&environment, [RootProvisionProcessInspection::Absent]);
        assert!(matches!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&expected, &effect_context,)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
    }

    #[test]
    fn effect_global_port_allows_two_exact_cats_but_rejects_a_third_foreign_identity() {
        let environment = TestEnvironment::new();
        let (first, _) = root_process_expectation(&environment);
        let second = second_root_process_expectation(&environment, &first);
        let first_process = exact_process_evidence(&first, 76);
        let second_process = exact_process_evidence(&second, 77);
        let _first_socket =
            install_exact_process_fixture(&environment, &first, first_process.process_id);
        let _second_socket =
            install_exact_process_fixture(&environment, &second, second_process.process_id);
        let context = effect_context_with_root_controls(
            &environment,
            [
                (first.clone(), Some(first_process.clone())),
                (second.clone(), Some(second_process.clone())),
            ],
        );
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(first_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(second_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(first_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(second_process.clone())),
            ],
        );
        assert_eq!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&first, &context)
                .unwrap(),
            RootProvisionProcessInspection::Exact(Box::new(first_process.clone()))
        );

        std::fs::create_dir(environment.systemd_root.join("cats-foreign.service")).unwrap();
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(first_process)),
                RootProvisionProcessInspection::Exact(Box::new(second_process)),
            ],
        );
        assert!(matches!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&first, &context)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::DuplicateIdentity
            )
        ));
    }

    #[test]
    fn node_global_admission_rejects_duplicate_exact_physical_identity() {
        let environment = TestEnvironment::new();
        let (first, _) = root_process_expectation(&environment);
        let mut duplicate = first.clone();
        duplicate.cat_id = Id::new("cat_02").unwrap();
        let first_process = exact_process_evidence(&first, 76);
        let duplicate_process = exact_process_evidence(&duplicate, 76);
        let first_proof = first.clone().prove_exact_process(first_process).unwrap();
        let duplicate_proof = duplicate
            .clone()
            .prove_exact_process(duplicate_process)
            .unwrap();

        assert!(super::super::root_provision_process::NodeGlobalManagedProcessScanAdmission::from_root_controls(
            BTreeMap::from([
                (first.cat_id.clone(), first),
                (duplicate.cat_id.clone(), duplicate),
            ]),
            BTreeMap::from([
                (first_proof.expectation().cat_id.clone(), first_proof),
                (duplicate_proof.expectation().cat_id.clone(), duplicate_proof),
            ]),
        )
        .is_err());
    }

    #[test]
    fn effect_global_port_rejects_other_cat_aba_and_honors_mid_sweep_cancellation() {
        let environment = TestEnvironment::new();
        let (first, _) = root_process_expectation(&environment);
        let second = second_root_process_expectation(&environment, &first);
        let first_process = exact_process_evidence(&first, 76);
        let second_process = exact_process_evidence(&second, 77);
        let _first_socket =
            install_exact_process_fixture(&environment, &first, first_process.process_id);
        let _second_socket =
            install_exact_process_fixture(&environment, &second, second_process.process_id);
        let context = effect_context_with_root_controls(
            &environment,
            [
                (first.clone(), Some(first_process.clone())),
                (second.clone(), Some(second_process.clone())),
            ],
        );
        let mut changed_second = second_process.clone();
        changed_second.process_start_time_ticks =
            WireU64::new(changed_second.process_start_time_ticks.get() + 1).unwrap();
        let bridge = root_process_bridge(
            &environment,
            [
                RootProvisionProcessInspection::Exact(Box::new(first_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(second_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(first_process.clone())),
                RootProvisionProcessInspection::Exact(Box::new(changed_second)),
            ],
        );
        assert!(matches!(
            bridge
                .inspect_exact_or_absent_after_node_global_sweep(&first, &context)
                .unwrap(),
            RootProvisionProcessInspection::Conflict(
                RootProvisionProcessConflict::IdentityMismatch
            )
        ));

        let environment = TestEnvironment::new();
        let (first, _) = root_process_expectation(&environment);
        let second = second_root_process_expectation(&environment, &first);
        let first_process = exact_process_evidence(&first, 76);
        let second_process = exact_process_evidence(&second, 77);
        let _first_socket =
            install_exact_process_fixture(&environment, &first, first_process.process_id);
        let _second_socket =
            install_exact_process_fixture(&environment, &second, second_process.process_id);
        let context = effect_context_with_root_controls(
            &environment,
            [
                (first.clone(), Some(first_process.clone())),
                (second, Some(second_process.clone())),
            ],
        );
        let bridge = root_process_bridge_with_port(
            &environment,
            Arc::new(CancellingRootProcessPort {
                inspections: Mutex::new(
                    [
                        RootProvisionProcessInspection::Exact(Box::new(first_process)),
                        RootProvisionProcessInspection::Exact(Box::new(second_process)),
                    ]
                    .into(),
                ),
                calls: AtomicUsize::new(0),
                cancel_after: 2,
                context: context.clone(),
            }),
        );
        assert!(bridge
            .inspect_exact_or_absent_after_node_global_sweep(&first, &context)
            .is_err());
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
        let context = effect_context_with_root_controls(&environment, [(expected.clone(), None)]);
        assert!(matches!(
            bridge
                .inspect_after_node_global_sweep(&expected, &context)
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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
                BTreeMap::new(),
                BTreeMap::new(),
                BTreeMap::new(),
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
