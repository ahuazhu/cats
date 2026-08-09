//! Binary encodings frozen by docs/specs/blockd-protocol.md §3/§5.
//!
//! All multi-byte integers are little-endian. Map node hashes are
//! SHA-256 over the complete encoded byte string.

use sha2::{Digest, Sha256};

use cats_api::chunk::{CHUNK_SIZE, PAGES_PER_CHUNK};

pub const LEAF_MAGIC: &[u8; 8] = b"CATSLEAF";
pub const ROOT_MAGIC: &[u8; 8] = b"CATSROOT";
pub const PACK_MAGIC: &[u8; 8] = b"CATSPACK";
pub(crate) const ENCODED_PACK_PREFIX_LEN: usize = 8 + 2 + 4;
pub const BITMAP_MAGIC: &[u8; 8] = b"CATSDRTY";
pub const FORMAT_VERSION: u16 = 1;
/// Leaf encoding version that can carry layered (base + delta) chunk refs.
///
/// A leaf is encoded at version 1 unless it actually contains a layered ref, so
/// volumes that never take a delta keep byte-identical map nodes (and therefore
/// the same object ids) as before delta packs existed.
pub const LEAF_VERSION_LAYERED: u16 = 2;
/// Leaf encoding version whose base refs carry the image they came from.
///
/// Same rule: only used when some base actually names an image, so a volume that
/// was never provisioned from a shared image keeps the older encoding.
pub const LEAF_VERSION_IMAGE_BASE: u16 = 3;

pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// A full-chunk image object.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BaseRef {
    pub object_id: String,
    pub len: u32,
    pub sha256: [u8; 32],
    /// Set when the object belongs to a shared, system-owned base image instead
    /// of this volume. Deltas are always written by the volume itself, so only a
    /// base can come from somewhere else.
    pub image: Option<String>,
}

impl BaseRef {
    pub fn local(object_id: String, len: u32, sha256: [u8; 32]) -> Self {
        Self {
            object_id,
            len,
            sha256,
            image: None,
        }
    }
}

/// A delta object: the dirty 64 KiB pages of one chunk, concatenated in page
/// order. `page_mask` says which pages, so `len` is `popcount(page_mask)` pages.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeltaRef {
    pub object_id: String,
    pub page_mask: u64,
    pub len: u32,
    pub sha256: [u8; 32],
}

/// Reference of one logical chunk in the committed map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChunkRef {
    Hole,
    Base(BaseRef),
    /// A base image — or a hole, when `base` is `None` — with deltas applied in
    /// order. Later deltas win on any page they both carry.
    Layered {
        base: Option<BaseRef>,
        deltas: Vec<DeltaRef>,
    },
}

impl ChunkRef {
    pub fn is_hole(&self) -> bool {
        matches!(self, ChunkRef::Hole)
    }

    /// Delta objects a cold read of this chunk has to fetch on top of its base.
    pub fn layer_count(&self) -> usize {
        match self {
            Self::Hole | Self::Base(_) => 0,
            Self::Layered { deltas, .. } => deltas.len(),
        }
    }

    /// The chunk's base image, if it has one.
    pub fn base(&self) -> Option<BaseRef> {
        match self {
            Self::Hole => None,
            Self::Base(base) => Some(base.clone()),
            Self::Layered { base, .. } => base.clone(),
        }
    }

    /// Objects a cold read of this chunk fetches, base first. GC must treat every
    /// one of them as live while this map is referenced by a Root.
    pub fn object_ids(&self) -> Vec<&str> {
        match self {
            Self::Hole => Vec::new(),
            Self::Base(base) => vec![base.object_id.as_str()],
            Self::Layered { base, deltas } => base
                .iter()
                .map(|b| b.object_id.as_str())
                .chain(deltas.iter().map(|d| d.object_id.as_str()))
                .collect(),
        }
    }

    /// Append a delta, turning a hole or a plain base into a layered ref.
    ///
    /// A base that came from a shared image stays the base: a Guest writing one
    /// page of a provisioned chunk publishes that page, not a private copy of the
    /// whole 4 MiB, which is what keeps image sharing from eroding as Cats write.
    pub fn with_delta(self, delta: DeltaRef) -> Self {
        match self {
            Self::Hole => Self::Layered {
                base: None,
                deltas: vec![delta],
            },
            Self::Base(base) => Self::Layered {
                base: Some(base),
                deltas: vec![delta],
            },
            Self::Layered { base, mut deltas } => {
                // An older delta whose pages this one fully rewrites contributes
                // nothing: hydration would fetch it and then overwrite every byte
                // of it. Dropping it shortens the chain (so a cold read fetches
                // fewer objects and the base rewrite triggers later) and stops GC
                // from having to keep a fully shadowed object alive. Rewriting the
                // same hot page over and over is the common case for this.
                deltas.retain(|existing| existing.page_mask & !delta.page_mask != 0);
                deltas.push(delta);
                Self::Layered { base, deltas }
            }
        }
    }

    /// Just the delta objects, which are always written by the volume itself even
    /// when the base underneath them belongs to a shared image.
    pub fn delta_object_ids(&self) -> Vec<&str> {
        match self {
            Self::Hole | Self::Base(_) => Vec::new(),
            Self::Layered { deltas, .. } => deltas.iter().map(|d| d.object_id.as_str()).collect(),
        }
    }

    /// The shared image this chunk's base came from, if any.
    pub fn image(&self) -> Option<&str> {
        match self {
            Self::Hole => None,
            Self::Base(base) => base.image.as_deref(),
            Self::Layered { base, .. } => base.as_ref().and_then(|b| b.image.as_deref()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FormatError {
    #[error("bad magic or truncated {0} encoding")]
    Malformed(&'static str),
    #[error("unsupported {0} version {1}")]
    Version(&'static str, u16),
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
fn take_id(buf: &mut &[u8]) -> Result<String, FormatError> {
    let len = take_u16(buf, "leaf")? as usize;
    Ok(std::str::from_utf8(take(buf, len, "leaf")?)
        .map_err(|_| FormatError::Malformed("leaf"))?
        .to_string())
}

// ---------------------------------------------------------------------------
// Leaf nodes
// ---------------------------------------------------------------------------

fn push_id(out: &mut Vec<u8>, id: &str) {
    let bytes = id.as_bytes();
    out.extend_from_slice(&(bytes.len() as u16).to_le_bytes());
    out.extend_from_slice(bytes);
}

/// The lowest leaf version that can express these entries.
///
/// Versions are opt-in per node so that adding a feature to the format does not
/// rewrite volumes that do not use it: a volume that never takes a delta keeps
/// producing version-1 nodes with the same hashes, and therefore the same object
/// ids, as it did before delta packs and shared images existed.
fn leaf_version(entries: &[ChunkRef]) -> u16 {
    if entries.iter().any(|e| e.image().is_some()) {
        LEAF_VERSION_IMAGE_BASE
    } else if entries
        .iter()
        .any(|e| matches!(e, ChunkRef::Layered { .. }))
    {
        LEAF_VERSION_LAYERED
    } else {
        FORMAT_VERSION
    }
}

pub fn encode_leaf(first_chunk: u64, entries: &[ChunkRef]) -> Vec<u8> {
    let version = leaf_version(entries);
    let mut out = Vec::with_capacity(16 + entries.len() * 64);
    out.extend_from_slice(LEAF_MAGIC);
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(&first_chunk.to_le_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    // At version 3 every base carries a trailing image id, empty for a local
    // object. One rule for both the plain and the layered base.
    let push_base = |out: &mut Vec<u8>, base: &BaseRef| {
        push_id(out, &base.object_id);
        out.extend_from_slice(&base.len.to_le_bytes());
        out.extend_from_slice(&base.sha256);
        if version >= LEAF_VERSION_IMAGE_BASE {
            push_id(out, base.image.as_deref().unwrap_or(""));
        }
    };
    for e in entries {
        match e {
            ChunkRef::Hole => out.push(0),
            ChunkRef::Base(base) => {
                out.push(1);
                push_base(&mut out, base);
            }
            ChunkRef::Layered { base, deltas } => {
                out.push(2);
                match base {
                    None => out.push(0),
                    Some(base) => {
                        out.push(1);
                        push_base(&mut out, base);
                    }
                }
                out.extend_from_slice(&(deltas.len() as u16).to_le_bytes());
                for delta in deltas {
                    push_id(&mut out, &delta.object_id);
                    out.extend_from_slice(&delta.page_mask.to_le_bytes());
                    out.extend_from_slice(&delta.len.to_le_bytes());
                    out.extend_from_slice(&delta.sha256);
                }
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
    if ver != FORMAT_VERSION && ver != LEAF_VERSION_LAYERED && ver != LEAF_VERSION_IMAGE_BASE {
        return Err(FormatError::Version("leaf", ver));
    }
    let first_chunk = take_u64(b, "leaf")?;
    let count = take_u32(b, "leaf")? as usize;
    let mut entries = Vec::with_capacity(count);
    let take_base = |b: &mut &[u8]| -> Result<BaseRef, FormatError> {
        let object_id = take_id(b)?;
        let len = take_u32(b, "leaf")?;
        let sha256: [u8; 32] = take(b, 32, "leaf")?.try_into().unwrap();
        let image = if ver >= LEAF_VERSION_IMAGE_BASE {
            Some(take_id(b)?).filter(|id| !id.is_empty())
        } else {
            None
        };
        Ok(BaseRef {
            object_id,
            len,
            sha256,
            image,
        })
    };
    for _ in 0..count {
        match take_u8(b, "leaf")? {
            0 => entries.push(ChunkRef::Hole),
            1 => entries.push(ChunkRef::Base(take_base(b)?)),
            2 if ver >= LEAF_VERSION_LAYERED => {
                let base = match take_u8(b, "leaf")? {
                    0 => None,
                    1 => Some(take_base(b)?),
                    _ => return Err(FormatError::Malformed("leaf")),
                };
                let count = take_u16(b, "leaf")? as usize;
                if count == 0 {
                    // A layered ref with no deltas would be a plain base or a
                    // hole; refuse it so there is exactly one encoding per state.
                    return Err(FormatError::Malformed("leaf"));
                }
                let mut deltas = Vec::with_capacity(count);
                for _ in 0..count {
                    deltas.push(DeltaRef {
                        object_id: take_id(b)?,
                        page_mask: take_u64(b, "leaf")?,
                        len: take_u32(b, "leaf")?,
                        sha256: take(b, 32, "leaf")?.try_into().unwrap(),
                    });
                }
                entries.push(ChunkRef::Layered { base, deltas });
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
                leaves.push(LeafRef::Present {
                    hash,
                    object_id: id,
                });
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

/// `page_mask` of a full-chunk base image. Deltas always carry fewer pages, so
/// this value distinguishes the two without a second field — and it is the serde
/// default, which keeps packs written before delta packs replayable.
pub fn full_page_mask() -> u64 {
    u64::MAX
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackEntry {
    pub chunk_idx: u64,
    pub payload_offset: u64,
    pub len: u32,
    pub sha256_hex: String,
    /// Which of the chunk's 64 pages this entry carries.
    #[serde(default = "full_page_mask")]
    pub page_mask: u64,
    /// Relaxed local-first packs may carry only the exact byte ranges written
    /// by the Guest. The background publisher materializes those ranges into
    /// the complete 64 KiB pages named by `page_mask` before uploading. Empty
    /// means the payload is already a publishable base/delta (the V1 format).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub byte_ranges: Vec<PackByteRange>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PackByteRange {
    /// Offset within the 4 MiB chunk.
    pub chunk_offset: u32,
    /// Offset within the pack's shared payload.
    pub payload_offset: u64,
    pub len: u32,
}

impl PackEntry {
    /// A full-chunk image rather than a delta.
    pub fn is_base(&self) -> bool {
        self.page_mask == full_page_mask()
    }

    /// A discard: the chunk carries no pages and publishes no object, and the
    /// commit turns its map entry into a Hole. Distinguishable from every other
    /// entry because a delta always carries at least one page.
    pub fn is_discard(&self) -> bool {
        self.page_mask == 0
    }

    pub fn is_byte_overlay(&self) -> bool {
        !self.byte_ranges.is_empty()
    }
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

pub fn encoded_pack_len(header: &PackHeader, payload_len: usize) -> Option<usize> {
    let header_len = serde_json::to_vec(header)
        .expect("pack header serializes")
        .len();
    8usize
        .checked_add(2)?
        .checked_add(4)?
        .checked_add(header_len)?
        .checked_add(payload_len)
}

pub(crate) fn encoded_pack_header_len(prefix: &[u8]) -> Result<usize, FormatError> {
    let mut remaining = prefix;
    if take(&mut remaining, 8, "pack")? != PACK_MAGIC {
        return Err(FormatError::Malformed("pack"));
    }
    let ver = take_u16(&mut remaining, "pack")?;
    if ver != FORMAT_VERSION {
        return Err(FormatError::Version("pack", ver));
    }
    let header_len = take_u32(&mut remaining, "pack")? as usize;
    ENCODED_PACK_PREFIX_LEN
        .checked_add(header_len)
        .ok_or(FormatError::Malformed("pack"))
}

pub(crate) fn decode_pack_header(buf: &[u8]) -> Result<(PackHeader, usize), FormatError> {
    let mut remaining = buf;
    let encoded_header_len = encoded_pack_header_len(buf)?;
    let _prefix = take(&mut remaining, ENCODED_PACK_PREFIX_LEN, "pack")?;
    let hdr_len = encoded_header_len - ENCODED_PACK_PREFIX_LEN;
    let hdr = take(&mut remaining, hdr_len, "pack")?;
    let header: PackHeader =
        serde_json::from_slice(hdr).map_err(|_| FormatError::Malformed("pack"))?;
    let payload_offset = buf
        .len()
        .checked_sub(remaining.len())
        .ok_or(FormatError::Malformed("pack"))?;
    Ok((header, payload_offset))
}

pub fn decode_pack(buf: &[u8]) -> Result<(PackHeader, Vec<u8>), FormatError> {
    let (header, payload_offset) = decode_pack_header(buf)?;
    Ok((header, buf[payload_offset..].to_vec()))
}

/// Decode an owned pack without cloning its payload. The prefix is removed
/// in-place, so publisher memory stays bounded by the encoded buffer it
/// admitted before reading the file.
pub fn decode_pack_owned(mut buf: Vec<u8>) -> Result<(PackHeader, Vec<u8>), FormatError> {
    let (header, payload_offset) = decode_pack_header(&buf)?;
    buf.drain(..payload_offset);
    Ok((header, buf))
}

// ---------------------------------------------------------------------------
// Shared base image manifest (spec §6.3, ADR-0017)
// ---------------------------------------------------------------------------

/// What a volume needs to reference an image's chunks without reading them.
///
/// JSON, like the commit record: an image is published once and read once per
/// provisioning, so the encoding costs nothing and stays inspectable.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageManifest {
    pub version: u16,
    /// sha256 of the raw image file. Also the namespace it was published under,
    /// which is what makes publishing idempotent across nodes.
    pub image_id: String,
    /// Logical length of the image. A volume may be larger — the chunks past the
    /// image are holes — but never smaller.
    pub size_bytes: u64,
    /// Non-hole chunks only, ascending by `chunk_idx`. An all-zero chunk is left
    /// out rather than stored, so a sparse image publishes only what it uses.
    pub chunks: Vec<ImageChunk>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImageChunk {
    pub chunk_idx: u64,
    /// Content-addressed: the sha256 of the chunk's bytes. Identical chunks
    /// within an image therefore share one object.
    pub object_id: String,
    pub len: u32,
}

impl ImageManifest {
    /// The map a freshly provisioned volume of `volume_bytes` starts from.
    ///
    /// Every entry is a base ref into the image namespace, so building this
    /// uploads nothing: provisioning becomes a metadata operation.
    pub fn base_map(&self, volume_bytes: u64) -> Result<Vec<ChunkRef>, FormatError> {
        if volume_bytes < self.size_bytes {
            return Err(FormatError::Malformed("image manifest"));
        }
        let count = volume_bytes.div_ceil(CHUNK_SIZE as u64) as usize;
        let mut map = vec![ChunkRef::Hole; count];
        for chunk in &self.chunks {
            let slot = map
                .get_mut(chunk.chunk_idx as usize)
                .ok_or(FormatError::Malformed("image manifest"))?;
            let sha256 = decode_sha256_hex(&chunk.object_id)
                .ok_or(FormatError::Malformed("image manifest"))?;
            *slot = ChunkRef::Base(BaseRef {
                object_id: chunk.object_id.clone(),
                len: chunk.len,
                sha256,
                image: Some(self.image_id.clone()),
            });
        }
        Ok(map)
    }
}

/// Image object ids are their own sha256, so a reference into an image carries no
/// separate digest — decoding the id is what verifies the object on read.
pub fn decode_sha256_hex(hex: &str) -> Option<[u8; 32]> {
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(hex.get(i * 2..i * 2 + 2)?, 16).ok()?;
    }
    Some(out)
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
            ChunkRef::Base(BaseRef::local("txn1-c1".into(), CHUNK_SIZE, [7u8; 32])),
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
            LeafRef::Present {
                hash: [9u8; 32],
                object_id: "abc.node".into(),
            },
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
                page_mask: full_page_mask(),
                byte_ranges: Vec::new(),
            }],
        };
        let enc = encode_pack(&header, b"data");
        assert_eq!(encoded_pack_len(&header, 4), Some(enc.len()));
        let encoded_header_len = encoded_pack_header_len(&enc[..ENCODED_PACK_PREFIX_LEN]).unwrap();
        let (prefix_header, payload_offset) =
            decode_pack_header(&enc[..encoded_header_len]).unwrap();
        assert_eq!(prefix_header.txn, "t1");
        assert_eq!(payload_offset, encoded_header_len);
        let (h, payload) = decode_pack(&enc).unwrap();
        assert_eq!(h.txn, "t1");
        assert_eq!(payload, b"data");
        let (owned_header, owned_payload) = decode_pack_owned(enc).unwrap();
        assert_eq!(owned_header.txn, "t1");
        assert_eq!(owned_payload, b"data");
    }

    #[test]
    fn layered_leaf_roundtrip_and_version_only_bumps_when_needed() {
        let plain = vec![
            ChunkRef::Hole,
            ChunkRef::Base(BaseRef::local("txn1-c1".into(), CHUNK_SIZE, [7u8; 32])),
        ];
        // A leaf with no layered ref keeps the version it always had, so volumes
        // that never take a delta keep byte-identical map nodes.
        assert_eq!(
            u16::from_le_bytes(encode_leaf(0, &plain)[8..10].try_into().unwrap()),
            FORMAT_VERSION
        );

        let layered = vec![
            ChunkRef::Layered {
                base: None,
                deltas: vec![DeltaRef {
                    object_id: "txn2-c0-d".into(),
                    page_mask: 0b101,
                    len: 2 * cats_api::chunk::DIRTY_PAGE_SIZE,
                    sha256: [1u8; 32],
                }],
            },
            ChunkRef::Layered {
                base: Some(BaseRef::local("txn1-c1".into(), CHUNK_SIZE, [7u8; 32])),
                deltas: vec![
                    DeltaRef {
                        object_id: "txn2-c1-d".into(),
                        page_mask: 1,
                        len: cats_api::chunk::DIRTY_PAGE_SIZE,
                        sha256: [2u8; 32],
                    },
                    DeltaRef {
                        object_id: "txn3-c1-d".into(),
                        page_mask: 1 << 63,
                        len: cats_api::chunk::DIRTY_PAGE_SIZE,
                        sha256: [3u8; 32],
                    },
                ],
            },
        ];
        let encoded = encode_leaf(64, &layered);
        assert_eq!(
            u16::from_le_bytes(encoded[8..10].try_into().unwrap()),
            LEAF_VERSION_LAYERED
        );
        let (first, decoded) = decode_leaf(&encoded).unwrap();
        assert_eq!(first, 64);
        assert_eq!(decoded, layered);
        assert_eq!(sha256(&encoded), sha256(&encode_leaf(64, &layered)));

        assert_eq!(layered[0].layer_count(), 1);
        assert_eq!(layered[1].layer_count(), 2);
        assert_eq!(
            layered[1].object_ids(),
            vec!["txn1-c1", "txn2-c1-d", "txn3-c1-d"]
        );
        assert_eq!(layered[0].base(), None);
    }

    #[test]
    fn a_delta_that_fully_rewrites_an_older_one_replaces_it() {
        let page = |mask: u64, tag: u8| DeltaRef {
            object_id: format!("d{tag}"),
            page_mask: mask,
            len: cats_api::chunk::DIRTY_PAGE_SIZE * mask.count_ones(),
            sha256: [tag; 32],
        };
        let base = BaseRef::local("b".into(), CHUNK_SIZE, [1u8; 32]);
        let chunk = ChunkRef::Base(base.clone());

        // Writing the same page again: the older delta would be fetched and then
        // completely overwritten, so it is dropped rather than kept in the chain.
        let once = chunk.clone().with_delta(page(0b001, 1));
        let twice = once.clone().with_delta(page(0b001, 2));
        assert_eq!(twice.layer_count(), 1);
        assert_eq!(twice.object_ids(), vec!["b", "d2"]);

        // A delta covering a superset of two older ones replaces both.
        let spread = chunk
            .clone()
            .with_delta(page(0b001, 1))
            .with_delta(page(0b010, 2))
            .with_delta(page(0b011, 3));
        assert_eq!(spread.layer_count(), 1);
        assert_eq!(spread.object_ids(), vec!["b", "d3"]);

        // A partial overlap keeps the older delta: it still owns a page.
        let overlap = chunk.with_delta(page(0b011, 1)).with_delta(page(0b001, 2));
        assert_eq!(overlap.layer_count(), 2);
        assert_eq!(overlap.object_ids(), vec!["b", "d1", "d2"]);
    }

    #[test]
    fn a_layered_ref_with_no_deltas_is_not_a_valid_encoding() {
        // Every state has exactly one encoding: no deltas means Hole or Base.
        let mut encoded = encode_leaf(
            0,
            &[ChunkRef::Layered {
                base: None,
                deltas: vec![DeltaRef {
                    object_id: "d".into(),
                    page_mask: 1,
                    len: cats_api::chunk::DIRTY_PAGE_SIZE,
                    sha256: [0u8; 32],
                }],
            }],
        );
        // Rewrite the delta count to zero and drop the delta body.
        let count_at = encoded.len() - (1 + 2 + 8 + 4 + 32);
        encoded[count_at] = 0;
        encoded[count_at + 1] = 0;
        encoded.truncate(count_at + 2);
        assert!(decode_leaf(&encoded).is_err());
    }

    #[test]
    fn an_image_base_survives_a_leaf_roundtrip_and_only_it_bumps_to_version_3() {
        let image = "a".repeat(64);
        let object = "b".repeat(64);
        let sha = decode_sha256_hex(&object).unwrap();
        let entries = vec![
            ChunkRef::Base(BaseRef {
                object_id: object.clone(),
                len: CHUNK_SIZE,
                sha256: sha,
                image: Some(image.clone()),
            }),
            // A Guest write onto a shared image chunk: the image stays the base
            // and only the written page becomes a private object.
            ChunkRef::Layered {
                base: Some(BaseRef {
                    object_id: object.clone(),
                    len: CHUNK_SIZE,
                    sha256: sha,
                    image: Some(image.clone()),
                }),
                deltas: vec![DeltaRef {
                    object_id: "txn2-c1-d".into(),
                    page_mask: 1,
                    len: cats_api::chunk::DIRTY_PAGE_SIZE,
                    sha256: [3u8; 32],
                }],
            },
            ChunkRef::Base(BaseRef::local("txn1-c2".into(), CHUNK_SIZE, [7u8; 32])),
        ];
        let encoded = encode_leaf(0, &entries);
        assert_eq!(
            u16::from_le_bytes(encoded[8..10].try_into().unwrap()),
            LEAF_VERSION_IMAGE_BASE
        );
        let (first, decoded) = decode_leaf(&encoded).unwrap();
        assert_eq!(first, 0);
        assert_eq!(decoded, entries);
        assert_eq!(decoded[0].image(), Some(image.as_str()));
        assert_eq!(decoded[1].image(), Some(image.as_str()));
        // A local base in the same leaf is still local: the empty image id is not
        // the same thing as an image named "".
        assert_eq!(decoded[2].image(), None);

        // Dropping the image origin drops the version back, so a leaf whose image
        // chunks have all been overwritten stops paying for the field.
        let no_image = vec![ChunkRef::Base(BaseRef::local(
            "txn1-c2".into(),
            CHUNK_SIZE,
            [7u8; 32],
        ))];
        assert_eq!(
            u16::from_le_bytes(encode_leaf(0, &no_image)[8..10].try_into().unwrap()),
            FORMAT_VERSION
        );
    }

    #[test]
    fn a_manifest_becomes_a_map_that_points_into_the_image_namespace() {
        let object = "c".repeat(64);
        let manifest = ImageManifest {
            version: FORMAT_VERSION,
            image_id: "d".repeat(64),
            size_bytes: 2 * CHUNK_SIZE as u64,
            // Chunk 1 is all zeros, so the image never stored it.
            chunks: vec![ImageChunk {
                chunk_idx: 0,
                object_id: object.clone(),
                len: CHUNK_SIZE,
            }],
        };

        // A volume bigger than the image: the tail is holes, not an error.
        let map = manifest.base_map(4 * CHUNK_SIZE as u64).unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map[0].image(), Some(manifest.image_id.as_str()));
        assert_eq!(map[0].base().unwrap().object_id, object);
        assert_eq!(
            map[0].base().unwrap().sha256,
            decode_sha256_hex(&object).unwrap()
        );
        assert!(matches!(map[1], ChunkRef::Hole));
        assert!(matches!(map[3], ChunkRef::Hole));

        // A volume smaller than the image would silently truncate the rootfs.
        assert!(manifest.base_map(CHUNK_SIZE as u64).is_err());

        // A chunk index past the volume is a corrupt manifest, not a hole.
        let mut bad = manifest.clone();
        bad.chunks[0].chunk_idx = 99;
        assert!(bad.base_map(2 * CHUNK_SIZE as u64).is_err());

        // Object ids are content hashes; anything else cannot be verified on read.
        let mut unhashed = manifest.clone();
        unhashed.chunks[0].object_id = "not-a-digest".into();
        assert!(unhashed.base_map(2 * CHUNK_SIZE as u64).is_err());
    }

    #[test]
    fn a_pack_written_before_delta_packs_still_decodes_as_full_chunks() {
        // Recovery has to replay a pending pack written by an older binary, which
        // had no page_mask field at all.
        let legacy = serde_json::json!({
            "txn": "t1",
            "volume_id": "vol_x",
            "base_generation": 1,
            "lease_epoch": 2,
            "entries": [{
                "chunk_idx": 0,
                "payload_offset": 0,
                "len": CHUNK_SIZE,
                "sha256_hex": hex::encode([0u8; 32]),
            }]
        });
        let header: PackHeader = serde_json::from_value(legacy).unwrap();
        assert!(header.entries[0].is_base());
        assert_eq!(header.entries[0].page_mask, full_page_mask());
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
