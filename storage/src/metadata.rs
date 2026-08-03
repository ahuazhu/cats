//! Contract for authoritative volume roots and single-writer fencing.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VolumeHead {
    pub volume_id: String,
    pub size_bytes: u64,
    pub generation: i64,
    pub root_hash: Option<[u8; 32]>,
    pub root_object_id: Option<String>,
    /// Current fencing identity. A caller reconciling an ambiguous root CAS
    /// must validate these fields together with the root before treating the
    /// operation as committed.
    pub lease_owner: Option<String>,
    pub lease_epoch: i64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotRow {
    pub snapshot_id: String,
    pub volume_id: String,
    pub generation: i64,
    pub root_hash: Option<[u8; 32]>,
    pub root_object_id: Option<String>,
}

#[derive(Debug, thiserror::Error)]
pub enum MetaError {
    #[error("volume not found: {0}")]
    NotFound(String),
    #[error("volume already exists: {0}")]
    AlreadyExists(String),
    #[error("lease is held by another attachment")]
    LeaseHeld,
    #[error("lease owner or epoch is stale (fenced)")]
    Fenced,
    #[error("root CAS conflict: expected generation {expected}")]
    CasConflict { expected: i64 },
    #[error("invalid metadata operation: {0}")]
    InvalidArgument(String),
    #[error("metadata backend error: {0}")]
    Backend(String),
}

pub type Result<T> = std::result::Result<T, MetaError>;

/// Authoritative metadata operations.
///
/// Implementations must be safe for concurrent callers and must preserve the
/// single-statement generation/owner/epoch CAS required before a FLUSH may be
/// acknowledged. Expiry controls when another attachment may acquire the
/// lease; acquisition bumps the epoch. A bare expiry lapse must not fence the
/// unchanged owner, because owner + epoch remain the authoritative fencing
/// token until a revoke or competing acquire changes them.
pub trait MetadataStore: Send + Sync {
    fn create_volume(&self, volume_id: &str, size_bytes: u64) -> Result<()>;
    fn load_head(&self, volume_id: &str) -> Result<VolumeHead>;
    fn delete_volume(&self, volume_id: &str) -> Result<()>;
    /// Grow-only resize; V1 rejects resize while a live lease exists.
    fn resize_volume(&self, volume_id: &str, new_size_bytes: u64) -> Result<()>;

    /// Acquire the sole writer lease and return a newly incremented epoch.
    fn acquire_lease(&self, volume_id: &str, attachment_id: &str, ttl_ms: i64) -> Result<i64>;
    /// Extend the lease. Succeeds while the row still names this attachment
    /// and epoch: an expiry lapse alone stays renewable, because everything
    /// that must fence — a revoke, a competing acquire — bumps the epoch.
    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> Result<()>;
    fn release_lease(&self, volume_id: &str, attachment_id: &str, epoch: i64) -> Result<()>;
    /// Expire the current lease immediately and bump the epoch, so the old
    /// holder fails closed and cannot renew back in.
    fn revoke_lease(&self, volume_id: &str) -> Result<()>;

    /// Atomically publish a new root and return the new generation.
    ///
    /// `new_generation` must be greater than `expected_generation`; a batched
    /// commit publishes several packs under one swap by jumping more than one
    /// step (ADR-0021 follow-up). The compare stays on `expected_generation`,
    /// so the fencing and lineage semantics are unchanged. The CAS checks
    /// owner + epoch, not wall-clock expiry: if another attachment acquired an
    /// expired lease it necessarily bumped the epoch first.
    #[allow(clippy::too_many_arguments)]
    fn cas_head(
        &self,
        volume_id: &str,
        expected_generation: i64,
        new_generation: i64,
        new_root_hash: [u8; 32],
        new_root_object_id: &str,
        attachment_id: &str,
        epoch: i64,
    ) -> Result<i64>;

    fn create_snapshot(&self, snapshot_id: &str, volume_id: &str) -> Result<SnapshotRow>;
    fn list_snapshots(&self, volume_id: &str) -> Result<Vec<SnapshotRow>>;
}
