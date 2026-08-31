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

/// Data-plane metadata fixture operations.
///
/// Ownership transitions are intentionally absent. The Runtime/Volume
/// Authority transaction path owns attachment transitions and immutable
/// capacity. New blockd composition uses
/// `VolumeDataAuthority`; this narrower port remains for SQLite-backed engine
/// tests and local storage experiments and is not a production authority.
pub trait MetadataStore: Send + Sync {
    fn create_volume(&self, volume_id: &str, size_bytes: u64) -> Result<()>;
    fn load_head(&self, volume_id: &str) -> Result<VolumeHead>;
    fn delete_volume(&self, volume_id: &str) -> Result<()>;

    /// Extend the lease. Succeeds while the row still names this attachment
    /// and epoch. The grant itself must have come from the Volume Authority.
    fn renew_lease(
        &self,
        volume_id: &str,
        attachment_id: &str,
        epoch: i64,
        ttl_ms: i64,
    ) -> Result<()>;
    fn release_lease(&self, volume_id: &str, attachment_id: &str, epoch: i64) -> Result<()>;

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

#[cfg(test)]
mod tests {
    #[test]
    fn fixture_port_exposes_no_ownership_or_capacity_mutations() {
        let source = include_str!("metadata.rs");
        let trait_source = source
            .split_once("pub trait MetadataStore")
            .and_then(|(_, tail)| tail.split_once("#[cfg(test)]"))
            .map(|(trait_source, _)| trait_source)
            .expect("MetadataStore trait source boundary");
        assert!(
            trait_source.contains("fn renew_lease"),
            "calibration failed: fixture data-plane method is not visible"
        );
        for retired in [
            concat!("fn acquire", "_lease"),
            concat!("fn revoke", "_lease"),
            concat!("fn resize", "_volume"),
        ] {
            assert!(
                !trait_source.contains(retired),
                "fixture metadata port still exposes {retired}"
            );
        }
    }
}
