//! Binary encodings frozen by docs/specs/blockd-protocol.md §3/§5.
//!
//! All multi-byte integers are little-endian. Map node hashes are
//! SHA-256 over the complete encoded byte string.

use sha2::{Digest, Sha256};

use cats_api::chunk::{CHUNK_SIZE, PAGES_PER_CHUNK};

pub const LEAF_MAGIC: &[u8; 8] = b"CATSLEAF";
pub const ROOT_MAGIC: &[u8; 8] = b"CATSROOT";
pub const PACK_MAGIC: &[u8; 8] = b"CATSPACK";
pub const BITMAP_MAGIC: &[u8; 8] = b"CATSDRTY";
pub const FORMAT_VERSION: u16 = 1;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Reference of one logical chunk in the committed map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRef {
    Hole,
    Base { object_id: String, len: u32, sha256: [u8; 32] },
}

impl ChunkRef {
    pub fn is_hole(&self) -> bool {
        matches!(self, ChunkRef::Hole)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("bad magic or truncated {0} encoding")]
    Malformed(&'static str),
    #[error("unsupported {0} version {1}")]
    Version(&'static str, u16),
    #[error("hash mismatch for {0} node")]
    HashMismatch(&'static str),
}

fn take<'a>(buf: &mut &'a [u8], n: usize, what: &'static str) -> Result<&'a [u8], FormatError> {
    if buf.len() < n {
        return Err(FormatError::Malformed(what));
    }
    let (head, rest) = buf.split_at(n);
    *buf = rest;
    Ok(head)
}

fn take_u8(buf: &mut &[u8], what: &'static str) -> Result<u8, FormatError> {
    Ok(take(buf, 1, what)?[0])
}
fn take_u16(buf: &mut &[u8], what: &'static str) -> Result<u16, FormatError> {
    Ok(u16::from_le_bytes(take(buf, 2, what)?.try_into().unwrap()))
}
fn take_u32(buf: &mut &[u8], what: &'static str) -> Result<u32, FormatError> {
    Ok(u32::from_le_bytes(take(buf, 4, what)?.try_into().unwrap()))
}
fn take_u64(buf: &mut &[u8], what: &'static str) -> Result<u64, FormatError> {
    Ok(u64::from_le_bytes(take(buf, 8, what)?.try_into().unwrap()))
}

// ---------------------------------------------------------------------------
// Leaf nodes
// ---------------------------------------------------------------------------

pub fn encode_leaf(first_chunk: u64, entries: &[ChunkRef]) -> Vec<u8> {
    let mut out = Vec::with_capacity(16 + entries.len() * 64);
    out.extend_from_slice(LEAF_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&first_chunk.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for e in entries {
        match e {
            ChunkRef::Hole => out.push(0),
            ChunkRef::Base { object_id, len, sha256 } => {
                out.push(1);
                let id = object_id.as_bytes();
                out.extend_from_slice(&(id.len() as u16).to_le_bytes());
                out.extend_from_slice(id);
                out.extend_from_slice(&len.to_le_bytes());
                out.extend_from_slice(sha256);
            }
        }
    }
    out
}

pub fn decode_leaf(mut buf: &[u8]) -> Result<(u64, Vec<ChunkRef>), FormatError> {
    let b = &mut buf;
    if take(b, 8, "leaf")? != LEAF_MAGIC {
        return Err(FormatError::Malformed("leaf"));
    }
    let ver = take_u16(b, "leaf")?;
    if ver != FORMAT_VERSION {
        return Err(FormatError::Version("leaf", ver));
    }
    let first_chunk = take_u64(b, "leaf")?;
    let count = take_u32(b, "leaf")? as usize;
    let mut entries = Vec::with_capacity(count);
    for _ in 0..count {
        match take_u8(b, "leaf")? {
            0 => entries.push(ChunkRef::Hole),
            1 => {
                let id_len = take_u16(b, "leaf")? as usize;
                let id = std::str::from_utf8(take(b, id_len, "leaf")?)
                    .map_err(|_| FormatError::Malformed("leaf"))?
                    .to_string();
                let len = take_u32(b, "leaf")?;
                let sha: [u8; 32] = take(b, 32, "leaf")?.try_into().unwrap();
                entries.push(ChunkRef::Base { object_id: id, len, sha256: sha });
            }
            _ => return Err(FormatError::Malformed("leaf")),
        }
    }
    if !b.is_empty() {
        return Err(FormatError::Malformed("leaf"));
    }
    Ok((first_chunk, entries))
}

// ---------------------------------------------------------------------------
// Root nodes
// ---------------------------------------------------------------------------

/// Reference of one leaf in the root node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LeafRef {
    Empty,
    Present { hash: [u8; 32], object_id: String },
}

pub fn encode_root(volume_size: u64, leaves: &[LeafRef]) -> Vec<u8> {
    let mut out = Vec::with_capacity(24 + leaves.len() * 80);
    out.extend_from_slice(ROOT_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&volume_size.to_le_bytes());
    out.extend_from_slice(&(leaves.len() as u32).to_le_bytes());
    for l in leaves {
        match l {
            LeafRef::Empty => out.push(0),
            LeafRef::Present { hash, object_id } => {
                out.push(1);
                out.extend_from_slice(hash);
                let id = object_id.as_bytes();
                out.extend_from_slice(&(id.len() as u16).to_le_bytes());
                out.extend_from_slice(id);
            }
        }
    }
    out
}

pub fn decode_root(mut buf: &[u8]) -> Result<(u64, Vec<LeafRef>), FormatError> {
    let b = &mut buf;
    if take(b, 8, "root")? != ROOT_MAGIC {
        return Err(FormatError::Malformed("root"));
    }
    let ver = take_u16(b, "root")?;
    if ver != FORMAT_VERSION {
        return Err(FormatError::Version("root", ver));
    }
    let volume_size = take_u64(b, "root")?;
    let count = take_u32(b, "root")? as usize;
    let mut leaves = Vec::with_capacity(count);
    for _ in 0..count {
        match take_u8(b, "root")? {
            0 => leaves.push(LeafRef::Empty),
            1 => {
                let hash: [u8; 32] = take(b, 32, "root")?.try_into().unwrap();
                let id_len = take_u16(b, "root")? as usize;
                let id = std::str::from_utf8(take(b, id_len, "root")?)
                    .map_err(|_| FormatError::Malformed("root"))?
                    .to_string();
                leaves.push(LeafRef::Present { hash, object_id: id });
            }
            _ => return Err(FormatError::Malformed("root")),
        }
    }
    if !b.is_empty() {
        return Err(FormatError::Malformed("root"));
    }
    Ok((volume_size, leaves))
}

// ---------------------------------------------------------------------------
// Pending commit pack (spec §5.2): header JSON + frozen chunk payloads.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackHeader {
    pub txn: String,
    pub volume_id: String,
    pub base_generation: i64,
    pub lease_epoch: i64,
    pub entries: Vec<PackEntry>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackEntry {
    pub chunk_idx: u64,
    pub payload_offset: u64,
    pub len: u32,
    pub sha256_hex: String,
}

pub fn encode_pack(header: &PackHeader, payload: &[u8]) -> Vec<u8> {
    let hdr = serde_json::to_vec(header).expect("pack header serializes");
    let mut out = Vec::with_capacity(16 + hdr.len() + payload.len());
    out.extend_from_slice(PACK_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&(hdr.len() as u32).to_le_bytes());
    out.extend_from_slice(&hdr);
    out.extend_from_slice(payload);
    out
}

pub fn decode_pack(mut buf: &[u8]) -> Result<(PackHeader, Vec<u8>), FormatError> {
    let b = &mut buf;
    if take(b, 8, "pack")? != PACK_MAGIC {
        return Err(FormatError::Malformed("pack"));
    }
    let ver = take_u16(b, "pack")?;
    if ver != FORMAT_VERSION {
        return Err(FormatError::Version("pack", ver));
    }
    let hdr_len = take_u32(b, "pack")? as usize;
    let hdr = take(b, hdr_len, "pack")?;
    let header: PackHeader =
        serde_json::from_slice(hdr).map_err(|_| FormatError::Malformed("pack"))?;
    Ok((header, b.to_vec()))
}

// ---------------------------------------------------------------------------
// Persistent dirty bitmap file (spec §5.1)
// ---------------------------------------------------------------------------

pub const BITMAP_HEADER_LEN: u64 = 8 + 2 + 8; // magic + version + chunk_count

pub fn encode_bitmap_header(chunk_count: u64) -> Vec<u8> {
    let mut out = Vec::with_capacity(BITMAP_HEADER_LEN as usize);
    out.extend_from_slice(BITMAP_MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_le_bytes());
    out.extend_from_slice(&chunk_count.to_le_bytes());
    out
}

pub fn decode_bitmap_header(mut buf: &[u8]) -> Result<u64, FormatError> {
    let b = &mut buf;
    if take(b, 8, "bitmap")? != BITMAP_MAGIC {
        return Err(FormatError::Malformed("bitmap"));
    }
    let ver = take_u16(b, "bitmap")?;
    if ver != FORMAT_VERSION {
        return Err(FormatError::Version("bitmap", ver));
    }
    take_u64(b, "bitmap")
}

/// Bit mask of the dirty pages a byte range touches inside one chunk.
pub fn page_mask(offset_in_chunk: u32, len: u32) -> u64 {
    assert!(offset_in_chunk + len <= CHUNK_SIZE);
    if len == 0 {
        return 0;
    }
    let page = cats_api::chunk::DIRTY_PAGE_SIZE;
    let first = offset_in_chunk / page;
    let last = (offset_in_chunk + len - 1) / page;
    debug_assert!(last < PAGES_PER_CHUNK);
    let mut mask = 0u64;
    for p in first..=last {
        mask |= 1u64 << p;
    }
    mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leaf_roundtrip_and_hash_stability() {
        let entries = vec![
            ChunkRef::Hole,
            ChunkRef::Base { object_id: "txn1-c1".into(), len: CHUNK_SIZE, sha256: [7u8; 32] },
            ChunkRef::Hole,
        ];
        let enc = encode_leaf(0, &entries);
        let (first, dec) = decode_leaf(&enc).unwrap();
        assert_eq!(first, 0);
        assert_eq!(dec, entries);
        // Deterministic encoding => stable hash.
        assert_eq!(sha256(&enc), sha256(&encode_leaf(0, &entries)));
    }

    #[test]
    fn root_roundtrip() {
        let leaves = vec![
            LeafRef::Empty,
            LeafRef::Present { hash: [9u8; 32], object_id: "abc.node".into() },
        ];
        let enc = encode_root(1 << 30, &leaves);
        let (size, dec) = decode_root(&enc).unwrap();
        assert_eq!(size, 1 << 30);
        assert_eq!(dec, leaves);
    }

    #[test]
    fn pack_roundtrip() {
        let header = PackHeader {
            txn: "t1".into(),
            volume_id: "vol_x".into(),
            base_generation: 3,
            lease_epoch: 5,
            entries: vec![PackEntry {
                chunk_idx: 2,
                payload_offset: 0,
                len: 4,
                sha256_hex: hex::encode(sha256(b"data")),
            }],
        };
        let enc = encode_pack(&header, b"data");
        let (h, payload) = decode_pack(&enc).unwrap();
        assert_eq!(h.txn, "t1");
        assert_eq!(payload, b"data");
    }

    #[test]
    fn truncated_inputs_are_rejected() {
        let entries = vec![ChunkRef::Hole];
        let enc = encode_leaf(0, &entries);
        assert!(decode_leaf(&enc[..enc.len() - 1]).is_err());
        assert!(decode_root(b"junk").is_err());
        assert!(decode_pack(b"short").is_err());
    }

    #[test]
    fn page_mask_covers_ranges() {
        assert_eq!(page_mask(0, 1), 1);
        assert_eq!(page_mask(0, 65536), 1);
        assert_eq!(page_mask(0, 65537), 0b11);
        assert_eq!(page_mask(65536, 65536), 0b10);
        assert_eq!(page_mask(0, CHUNK_SIZE), u64::MAX);
        assert_eq!(page_mask(CHUNK_SIZE - 1, 1), 1u64 << 63);
    }
}
