//! Provider-neutral, claim-gated garbage collection for one volume.
//!
//! The serving `ChunkEngine` is intentionally not a GC authority. Local
//! flush/publish locks cannot exclude a writer on another Host during the
//! bounded dual-run window. The caller must first reserve GC in the global
//! Volume Authority, freezing one current head plus every retained product
//! snapshot head and excluding acquire/publish/snapshot mutations. This module
//! then traces the immutable graphs and executes only a plan bound to that
//! explicit claim.

use std::collections::{HashMap, HashSet};
use std::time::Instant;

use cats_api::chunk::{self, keys, CHUNKS_PER_LEAF, CHUNK_SIZE, DIRTY_PAGE_SIZE, MAX_VOLUME_BYTES};
use cats_api::runtime_reconciliation::{Id, RemoteHead};
use cats_storage::{validate_list_page, BlobError, BlobStore, BLOB_LIST_PAGE_MAX_KEYS};

use crate::engine::MAX_DELTA_LAYERS;
use crate::format::{self, BaseRef, ChunkRef, DeltaRef, LeafRef};

/// Canonical nodes are much smaller: the 1 TiB Root has 1024 fixed-size refs
/// and a Leaf has at most 256 refs with at most four fixed-size Delta refs.
/// This conservative cap rejects corrupt length fields before an adapter can
/// allocate without bound.
const MAX_MAP_NODE_BYTES: usize = 1 << 20;

/// Authority-owned reason why a Root must survive this collection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RetainedRootSource {
    Current,
    Snapshot { snapshot_id: Id },
}

/// One exact immutable Root retained by an authority-consistent view.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RetainedRoot {
    pub source: RetainedRootSource,
    pub head: RemoteHead,
}

/// A caller-provided carrier proving root discovery and writer exclusion
/// happened outside blockd.
///
/// There is deliberately no `Default` and every destructive API requires this
/// type. An empty snapshot set is therefore an explicit authority decision next
/// to the one mandatory current Root, never a data-plane fallback.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollectionClaim {
    claim_id: Id,
    volume_id: Id,
    size_bytes: u64,
    retained_roots: Vec<RetainedRoot>,
}

impl GarbageCollectionClaim {
    /// Construct the carrier returned by the global GC-claim transition.
    ///
    /// This validates only self-contained fields. The transaction owner must
    /// additionally bind `claim_id`, the exact current head and snapshot set to
    /// its persisted `GarbageCollecting` state before calling blockd.
    pub fn new(
        claim_id: Id,
        volume_id: Id,
        size_bytes: u64,
        retained_roots: Vec<RetainedRoot>,
    ) -> Result<Self, GcError> {
        validate_trace_input(size_bytes, &retained_roots)?;
        let current_count = retained_roots
            .iter()
            .filter(|root| matches!(root.source, RetainedRootSource::Current))
            .count();
        if current_count != 1 {
            return Err(GcError::InvalidClaim(
                "exactly one current Root is required".into(),
            ));
        }
        let mut snapshots = HashSet::new();
        for retained in &retained_roots {
            if let RetainedRootSource::Snapshot { snapshot_id } = &retained.source {
                if !snapshots.insert(snapshot_id.clone()) {
                    return Err(GcError::InvalidClaim(format!(
                        "duplicate snapshot Root {snapshot_id}"
                    )));
                }
            }
        }
        Ok(Self {
            claim_id,
            volume_id,
            size_bytes,
            retained_roots,
        })
    }

    pub fn claim_id(&self) -> &Id {
        &self.claim_id
    }

    pub fn volume_id(&self) -> &Id {
        &self.volume_id
    }

    pub fn size_bytes(&self) -> u64 {
        self.size_bytes
    }

    pub fn retained_roots(&self) -> &[RetainedRoot] {
        &self.retained_roots
    }
}

/// Fully verified volume-owned objects reachable from a retained Root set.
///
/// Image Base objects are read and verified while tracing because restore must
/// reject an incomplete graph, but they are deliberately absent from these
/// sets: per-volume GC never lists or deletes `images/`. Commit records are not
/// graph members and are never read, listed or deleted here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LiveObjectGraph {
    volume_id: Id,
    data_objects: HashSet<String>,
    map_nodes: HashSet<String>,
}

impl LiveObjectGraph {
    pub fn volume_id(&self) -> &Id {
        &self.volume_id
    }

    pub fn data_objects(&self) -> &HashSet<String> {
        &self.data_objects
    }

    pub fn map_nodes(&self) -> &HashSet<String> {
        &self.map_nodes
    }
}

/// A complete, non-destructive scan bound to one exact authority claim.
///
/// Fields are private so a caller cannot fabricate an executor input that
/// skipped multi-root tracing. The plan may be safely discarded. Executing it
/// still requires the same explicit claim carrier.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GarbageCollectionPlan {
    claim: GarbageCollectionClaim,
    live: LiveObjectGraph,
    data_objects_live: usize,
    map_objects_live: usize,
    data_objects_candidates: usize,
    map_objects_candidates: usize,
}

impl GarbageCollectionPlan {
    pub fn claim_id(&self) -> &Id {
        self.claim.claim_id()
    }

    pub fn data_objects_live(&self) -> usize {
        self.data_objects_live
    }

    pub fn map_objects_live(&self) -> usize {
        self.map_objects_live
    }

    pub fn data_objects_candidates(&self) -> usize {
        self.data_objects_candidates
    }

    pub fn map_objects_candidates(&self) -> usize {
        self.map_objects_candidates
    }

    pub fn keeps_data_object(&self, key: &str) -> bool {
        self.live.data_objects().contains(key)
    }

    pub fn keeps_map_node(&self, key: &str) -> bool {
        self.live.map_nodes().contains(key)
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GcStats {
    pub data_objects_live: usize,
    pub data_objects_deleted: usize,
    pub map_objects_live: usize,
    pub map_objects_deleted: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum GcError {
    #[error("invalid garbage-collection claim: {0}")]
    InvalidClaim(String),
    #[error("retained object graph is corrupt: {0}")]
    Corrupt(String),
    #[error("garbage-collection plan does not match the authority claim")]
    ClaimMismatch,
    #[error("garbage-collection deadline elapsed")]
    Deadline,
    #[error(transparent)]
    Blob(#[from] BlobError),
}

/// Trace and verify the complete union of arbitrary retained Roots.
///
/// This reusable, non-destructive helper is also the restore preflight: every
/// Root and Leaf must be canonical and match its hash and geometry; every Base
/// and Delta, including shared image Bases, must match its declared length and
/// SHA-256. Any missing, malformed or conflicting reference returns an error.
pub fn trace_live_objects(
    blob: &dyn BlobStore,
    volume_id: &Id,
    size_bytes: u64,
    retained_roots: &[RetainedRoot],
    deadline: Instant,
) -> Result<LiveObjectGraph, GcError> {
    validate_trace_input(size_bytes, retained_roots)?;
    ensure_deadline(deadline)?;
    let mut tracer = Tracer {
        blob,
        volume_id,
        size_bytes,
        deadline,
        live_data: HashSet::new(),
        live_maps: HashSet::new(),
        verified_data: HashMap::new(),
    };
    for retained in retained_roots {
        tracer.trace_root(retained)?;
    }
    Ok(LiveObjectGraph {
        volume_id: volume_id.clone(),
        data_objects: tracer.live_data,
        map_nodes: tracer.live_maps,
    })
}

/// Build a complete deletion plan without deleting any object.
///
/// Both prefixes are fully cursor-scanned only after the complete graph union
/// passes validation. This fixes the selective-pagination failure where one
/// page containing only live keys could hide garbage on later pages.
pub fn plan_garbage(
    blob: &dyn BlobStore,
    claim: &GarbageCollectionClaim,
    page_size: usize,
    deadline: Instant,
) -> Result<GarbageCollectionPlan, GcError> {
    validate_page_size(page_size)?;
    let graph = trace_live_objects(
        blob,
        claim.volume_id(),
        claim.size_bytes(),
        claim.retained_roots(),
        deadline,
    )?;
    let data_objects_candidates = count_candidates(
        blob,
        &format!("volumes/{}/data/", claim.volume_id()),
        graph.data_objects(),
        page_size,
        deadline,
    )?;
    let map_objects_candidates = count_candidates(
        blob,
        &format!("volumes/{}/maps/", claim.volume_id()),
        graph.map_nodes(),
        page_size,
        deadline,
    )?;
    Ok(GarbageCollectionPlan {
        claim: claim.clone(),
        data_objects_live: graph.data_objects().len(),
        map_objects_live: graph.map_nodes().len(),
        data_objects_candidates,
        map_objects_candidates,
        live: graph,
    })
}

/// Delete one previously verified plan while the same global claim remains
/// active. A failure may leave a prefix partially swept; the claim must remain
/// persisted and a later pass can build a fresh plan and retry idempotently.
pub fn execute_garbage_plan(
    blob: &dyn BlobStore,
    claim: &GarbageCollectionClaim,
    plan: GarbageCollectionPlan,
    deadline: Instant,
) -> Result<GcStats, GcError> {
    if &plan.claim != claim {
        return Err(GcError::ClaimMismatch);
    }
    let mut stats = GcStats {
        data_objects_live: plan.data_objects_live,
        map_objects_live: plan.map_objects_live,
        ..GcStats::default()
    };
    stats.data_objects_deleted = sweep_prefix(
        blob,
        &format!("volumes/{}/data/", claim.volume_id()),
        plan.live.data_objects(),
        plan.data_objects_candidates,
        deadline,
    )?;
    stats.map_objects_deleted = sweep_prefix(
        blob,
        &format!("volumes/{}/maps/", claim.volume_id()),
        plan.live.map_nodes(),
        plan.map_objects_candidates,
        deadline,
    )?;
    Ok(stats)
}

/// Convenience composition of plan and execute. It still requires the global
/// claim explicitly; there is no serving-engine or empty-root entry point.
pub fn collect_garbage(
    blob: &dyn BlobStore,
    claim: &GarbageCollectionClaim,
    page_size: usize,
    deadline: Instant,
) -> Result<GcStats, GcError> {
    let plan = plan_garbage(blob, claim, page_size, deadline)?;
    execute_garbage_plan(blob, claim, plan, deadline)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DataObjectIdentity {
    len: u32,
    sha256: [u8; 32],
}

struct Tracer<'a> {
    blob: &'a dyn BlobStore,
    volume_id: &'a Id,
    size_bytes: u64,
    deadline: Instant,
    live_data: HashSet<String>,
    live_maps: HashSet<String>,
    verified_data: HashMap<String, DataObjectIdentity>,
}

impl Tracer<'_> {
    fn trace_root(&mut self, retained: &RetainedRoot) -> Result<(), GcError> {
        if retained.head.generation.get() == 0 {
            return Ok(());
        }
        let expected_hash = retained.head.root_hash.as_ref().expect("validated head");
        let object_id = retained
            .head
            .root_object_id
            .as_ref()
            .expect("validated head")
            .as_str();
        validate_map_id(object_id, expected_hash.as_bytes(), "Root")?;
        let key = keys::map_node(
            self.volume_id.as_str(),
            &hex::encode(expected_hash.as_bytes()),
        );
        if key.rsplit('/').next() != Some(object_id) {
            return corrupt(format!("Root key {object_id:?} is not canonical"));
        }
        let bytes = self.read_map(&key, expected_hash.as_bytes(), "Root")?;
        let expected_leaf_count = usize::try_from(chunk::leaf_count(self.size_bytes))
            .map_err(|_| GcError::Corrupt("leaf count does not fit memory".into()))?;
        preflight_node_count(&bytes, expected_leaf_count, "Root")?;
        let (size, leaves) = format::decode_root(&bytes)
            .map_err(|error| GcError::Corrupt(format!("Root {object_id}: {error}")))?;
        if size != self.size_bytes || leaves.len() != expected_leaf_count {
            return corrupt(format!("Root {object_id} has inconsistent volume geometry"));
        }
        if format::encode_root(size, &leaves) != bytes {
            return corrupt(format!("Root {object_id} is not canonically encoded"));
        }
        self.live_maps.insert(key);
        for (leaf_index, leaf) in leaves.iter().enumerate() {
            if let LeafRef::Present { hash, object_id } = leaf {
                self.trace_leaf(leaf_index, hash, object_id)?;
            }
        }
        Ok(())
    }

    fn trace_leaf(
        &mut self,
        leaf_index: usize,
        expected_hash: &[u8; 32],
        object_id: &str,
    ) -> Result<(), GcError> {
        validate_map_id(object_id, expected_hash, "Leaf")?;
        let key = keys::map_node(self.volume_id.as_str(), &hex::encode(expected_hash));
        if key.rsplit('/').next() != Some(object_id) {
            return corrupt(format!("Leaf key {object_id:?} is not canonical"));
        }
        let bytes = self.read_map(&key, expected_hash, "Leaf")?;
        let first_chunk = (leaf_index as u64)
            .checked_mul(CHUNKS_PER_LEAF as u64)
            .ok_or_else(|| GcError::Corrupt("Leaf geometry overflow".into()))?;
        let remaining = chunk::chunk_count(self.size_bytes)
            .checked_sub(first_chunk)
            .ok_or_else(|| GcError::Corrupt("Leaf lies beyond the volume".into()))?;
        let expected_entries = remaining.min(CHUNKS_PER_LEAF as u64) as usize;
        preflight_leaf_geometry(&bytes, first_chunk, expected_entries)?;
        let (decoded_first, entries) = format::decode_leaf(&bytes)
            .map_err(|error| GcError::Corrupt(format!("Leaf {object_id}: {error}")))?;
        if decoded_first != first_chunk || entries.len() != expected_entries {
            return corrupt(format!("Leaf {object_id} has inconsistent geometry"));
        }
        if format::encode_leaf(decoded_first, &entries) != bytes {
            return corrupt(format!("Leaf {object_id} is not canonically encoded"));
        }
        self.live_maps.insert(key);
        for (offset, entry) in entries.iter().enumerate() {
            self.trace_chunk(first_chunk + offset as u64, entry)?;
        }
        Ok(())
    }

    fn trace_chunk(&mut self, chunk_index: u64, entry: &ChunkRef) -> Result<(), GcError> {
        match entry {
            ChunkRef::Hole => Ok(()),
            ChunkRef::Base(base) => self.trace_base(chunk_index, base),
            ChunkRef::Layered { base, deltas } => {
                if deltas.is_empty() || deltas.len() > MAX_DELTA_LAYERS {
                    return corrupt(format!(
                        "chunk {chunk_index} delta depth {} is outside 1..={MAX_DELTA_LAYERS}",
                        deltas.len()
                    ));
                }
                if let Some(base) = base {
                    self.trace_base(chunk_index, base)?;
                }
                let mut ids = HashSet::new();
                for delta in deltas {
                    if !ids.insert(delta.object_id.as_str()) {
                        return corrupt(format!("chunk {chunk_index} repeats a Delta object"));
                    }
                    self.trace_delta(chunk_index, delta)?;
                }
                Ok(())
            }
        }
    }

    fn trace_base(&mut self, chunk_index: u64, base: &BaseRef) -> Result<(), GcError> {
        if base.len != CHUNK_SIZE {
            return corrupt(format!(
                "chunk {chunk_index} Base has invalid length {}",
                base.len
            ));
        }
        let key = if let Some(image_id) = &base.image {
            validate_lower_hex(image_id, 64, "image id")?;
            validate_lower_hex(&base.object_id, 64, "image Base object id")?;
            if base.object_id != hex::encode(base.sha256) {
                return corrupt(format!("chunk {chunk_index} image Base key/hash mismatch"));
            }
            keys::image_data(image_id, &base.object_id)
        } else {
            validate_local_object_id(&base.object_id, chunk_index, false)?;
            let key = keys::data(self.volume_id.as_str(), &base.object_id);
            self.live_data.insert(key.clone());
            key
        };
        self.verify_data(&key, base.len, base.sha256)
    }

    fn trace_delta(&mut self, chunk_index: u64, delta: &DeltaRef) -> Result<(), GcError> {
        validate_local_object_id(&delta.object_id, chunk_index, true)?;
        if delta.page_mask == 0 || delta.page_mask == u64::MAX {
            return corrupt(format!(
                "chunk {chunk_index} Delta has an invalid page mask"
            ));
        }
        let expected_len = delta
            .page_mask
            .count_ones()
            .checked_mul(DIRTY_PAGE_SIZE)
            .ok_or_else(|| GcError::Corrupt("Delta length overflow".into()))?;
        if delta.len != expected_len {
            return corrupt(format!(
                "chunk {chunk_index} Delta has invalid length {}",
                delta.len
            ));
        }
        let key = keys::data(self.volume_id.as_str(), &delta.object_id);
        self.live_data.insert(key.clone());
        self.verify_data(&key, delta.len, delta.sha256)
    }

    fn read_map(
        &self,
        key: &str,
        expected_hash: &[u8; 32],
        kind: &str,
    ) -> Result<Vec<u8>, GcError> {
        ensure_deadline(self.deadline)?;
        let bytes = self
            .blob
            .get_bounded_until(key, MAX_MAP_NODE_BYTES, self.deadline)?;
        if &format::sha256(&bytes) != expected_hash {
            return corrupt(format!("{kind} {key} content hash mismatch"));
        }
        Ok(bytes)
    }

    fn verify_data(&mut self, key: &str, len: u32, sha256: [u8; 32]) -> Result<(), GcError> {
        let identity = DataObjectIdentity { len, sha256 };
        if let Some(previous) = self.verified_data.get(key) {
            if previous != &identity {
                return corrupt(format!(
                    "live object {key} has conflicting immutable identities"
                ));
            }
            return Ok(());
        }
        ensure_deadline(self.deadline)?;
        let bytes = self
            .blob
            .get_bounded_until(key, len as usize, self.deadline)?;
        if bytes.len() != len as usize || format::sha256(&bytes) != sha256 {
            return corrupt(format!("data object {key} length/hash mismatch"));
        }
        self.verified_data.insert(key.to_string(), identity);
        Ok(())
    }
}

fn count_candidates(
    blob: &dyn BlobStore,
    prefix: &str,
    live: &HashSet<String>,
    page_size: usize,
    deadline: Instant,
) -> Result<usize, GcError> {
    let mut candidates = 0usize;
    let mut cursor: Option<String> = None;
    loop {
        ensure_deadline(deadline)?;
        let page = blob.list_after_bounded(prefix, cursor.as_deref(), page_size)?;
        validate_list_page(prefix, cursor.as_deref(), page_size, &page)?;
        ensure_deadline(deadline)?;
        let next = page.keys.last().cloned();
        candidates = candidates
            .checked_add(page.keys.iter().filter(|key| !live.contains(*key)).count())
            .ok_or_else(|| GcError::Corrupt("garbage candidate count overflow".into()))?;
        if !page.is_truncated {
            return Ok(candidates);
        }
        cursor = next;
    }
}

fn sweep_prefix(
    blob: &dyn BlobStore,
    prefix: &str,
    live: &HashSet<String>,
    expected_candidates: usize,
    deadline: Instant,
) -> Result<usize, GcError> {
    let mut deleted = 0usize;
    let mut cursor: Option<String> = None;
    loop {
        ensure_deadline(deadline)?;
        // The port bounds the returned page. It cannot cancel an adapter call
        // in flight yet, so the deadline is checked on both sides and a late
        // response fails closed before any key from that page is deleted.
        let page = blob.list_after_bounded(prefix, cursor.as_deref(), BLOB_LIST_PAGE_MAX_KEYS)?;
        validate_list_page(prefix, cursor.as_deref(), BLOB_LIST_PAGE_MAX_KEYS, &page)?;
        ensure_deadline(deadline)?;
        let next = page.keys.last().cloned();
        for key in page.keys {
            if live.contains(&key) {
                continue;
            }
            blob.delete_until(&key, deadline)?;
            deleted = deleted
                .checked_add(1)
                .ok_or_else(|| GcError::Corrupt("garbage delete count overflow".into()))?;
        }
        if !page.is_truncated {
            if deleted != expected_candidates {
                return Err(GcError::Corrupt(format!(
                    "garbage candidate set changed under claim: planned {expected_candidates}, deleted {deleted}"
                )));
            }
            return Ok(deleted);
        }
        cursor = next;
    }
}

fn validate_trace_input(size_bytes: u64, retained_roots: &[RetainedRoot]) -> Result<(), GcError> {
    if size_bytes == 0
        || size_bytes > MAX_VOLUME_BYTES
        || !size_bytes.is_multiple_of(CHUNK_SIZE as u64)
    {
        return Err(GcError::InvalidClaim(format!(
            "volume size must be a non-zero chunk multiple no larger than {MAX_VOLUME_BYTES}"
        )));
    }
    if retained_roots.is_empty() {
        return Err(GcError::InvalidClaim(
            "at least one retained Root is required".into(),
        ));
    }
    for retained in retained_roots {
        validate_head_shape(&retained.head)?;
    }
    Ok(())
}

fn validate_page_size(page_size: usize) -> Result<(), GcError> {
    if !(1..=BLOB_LIST_PAGE_MAX_KEYS).contains(&page_size) {
        return Err(GcError::InvalidClaim(format!(
            "page_size must be in 1..={BLOB_LIST_PAGE_MAX_KEYS}"
        )));
    }
    Ok(())
}

fn validate_head_shape(head: &RemoteHead) -> Result<(), GcError> {
    match (
        head.generation.get(),
        head.root_hash.is_some(),
        head.root_object_id.is_some(),
    ) {
        (0, false, false) | (1.., true, true) => Ok(()),
        _ => Err(GcError::InvalidClaim(
            "generation zero must have no Root; later generations require hash and object id"
                .into(),
        )),
    }
}

fn validate_map_id(id: &str, hash: &[u8; 32], kind: &str) -> Result<(), GcError> {
    let expected = format!("{}.node", hex::encode(hash));
    if id != expected {
        return corrupt(format!("{kind} object id {id:?} does not match its hash"));
    }
    Ok(())
}

fn validate_local_object_id(id: &str, chunk_index: u64, delta: bool) -> Result<(), GcError> {
    let suffix = format!("-c{chunk_index}{}", if delta { "-d" } else { "" });
    let Some(txn) = id.strip_suffix(&suffix) else {
        return corrupt(format!(
            "data object id {id:?} has the wrong chunk/type suffix"
        ));
    };
    validate_lower_hex(txn, 32, "data transaction id")
}

fn validate_lower_hex(value: &str, length: usize, what: &str) -> Result<(), GcError> {
    if value.len() != length
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return corrupt(format!("{what} {value:?} is not canonical lowercase hex"));
    }
    Ok(())
}

fn preflight_node_count(bytes: &[u8], expected: usize, kind: &str) -> Result<(), GcError> {
    let Some(raw) = bytes.get(18..22) else {
        return corrupt(format!("truncated {kind}"));
    };
    let count = u32::from_le_bytes(raw.try_into().expect("four-byte slice")) as usize;
    if count != expected {
        return corrupt(format!(
            "{kind} entry count {count} does not match {expected}"
        ));
    }
    Ok(())
}

fn preflight_leaf_geometry(
    bytes: &[u8],
    expected_first: u64,
    expected_count: usize,
) -> Result<(), GcError> {
    let Some(raw_first) = bytes.get(10..18) else {
        return corrupt("truncated Leaf".into());
    };
    let first = u64::from_le_bytes(raw_first.try_into().expect("eight-byte slice"));
    if first != expected_first {
        return corrupt(format!(
            "Leaf first chunk {first} does not match {expected_first}"
        ));
    }
    preflight_node_count(bytes, expected_count, "Leaf")
}

fn ensure_deadline(deadline: Instant) -> Result<(), GcError> {
    if Instant::now() >= deadline {
        Err(GcError::Deadline)
    } else {
        Ok(())
    }
}

fn corrupt<T>(message: String) -> Result<T, GcError> {
    Err(GcError::Corrupt(message))
}

#[cfg(test)]
mod tests;
