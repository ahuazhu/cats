//! ChunkStore protocol constants (ADR-0003, frozen at P0).
//!
//! The binary encodings (map nodes, pending packs, object headers) are
//! implemented in `cats-blockd::format`; this module fixes the numeric
//! contract shared by every component and by `docs/specs/blockd-protocol.md`.

/// Logical block size advertised to the guest block frontend.
pub const LOGICAL_BLOCK_SIZE: u32 = 512;

/// Base chunk size: the unit of remote objects and of the volume map (V1
/// full-chunk commit; 64 KiB delta records are a later optimization).
pub const CHUNK_SIZE: u32 = 4 * 1024 * 1024;

/// Dirty-tracking page size inside a chunk.
pub const DIRTY_PAGE_SIZE: u32 = 64 * 1024;

/// Pages per chunk (64 pages -> one u64 bitmap word per chunk).
pub const PAGES_PER_CHUNK: u32 = CHUNK_SIZE / DIRTY_PAGE_SIZE;

/// Chunks covered by one map leaf (256 chunks = 1 GiB of logical space).
pub const CHUNKS_PER_LEAF: u32 = 256;

/// Maximum volume size representable with the two-level map (V1 limit).
pub const MAX_VOLUME_BYTES: u64 = 1024 * 1024 * 1024 * 1024; // 1 TiB

/// Default root disk size when the caller does not specify one.
pub const DEFAULT_ROOT_DISK_BYTES: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB

/// Volume sizes must be a multiple of the chunk size (control plane rounds
/// user requests up before creating the volume).
pub fn round_up_to_chunk(size_bytes: u64) -> u64 {
    let c = CHUNK_SIZE as u64;
    size_bytes.div_ceil(c) * c
}

pub fn chunk_count(size_bytes: u64) -> u64 {
    size_bytes.div_ceil(CHUNK_SIZE as u64)
}

pub fn leaf_count(size_bytes: u64) -> u64 {
    chunk_count(size_bytes).div_ceil(CHUNKS_PER_LEAF as u64)
}

/// Remote object key layout under a volume prefix.
pub mod keys {
    /// `volumes/<volume-id>/data/<object-id>`
    pub fn data(volume_id: &str, object_id: &str) -> String {
        format!("volumes/{volume_id}/data/{object_id}")
    }
    /// `volumes/<volume-id>/maps/<hex-sha256>.node`
    pub fn map_node(volume_id: &str, node_hash_hex: &str) -> String {
        format!("volumes/{volume_id}/maps/{node_hash_hex}.node")
    }
    /// `volumes/<volume-id>/commits/<generation>-<txn>.json`
    pub fn commit_record(volume_id: &str, generation: i64, txn: &str) -> String {
        format!("volumes/{volume_id}/commits/{generation}-{txn}.json")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn geometry_constants_are_consistent() {
        assert_eq!(CHUNK_SIZE % DIRTY_PAGE_SIZE, 0);
        assert_eq!(PAGES_PER_CHUNK, 64);
        assert_eq!(CHUNK_SIZE % LOGICAL_BLOCK_SIZE, 0);
        assert_eq!(round_up_to_chunk(1), CHUNK_SIZE as u64);
        assert_eq!(round_up_to_chunk(CHUNK_SIZE as u64), CHUNK_SIZE as u64);
        assert_eq!(chunk_count(100 * 1024 * 1024 * 1024), 25_600);
        assert_eq!(leaf_count(100 * 1024 * 1024 * 1024), 100);
    }
}
