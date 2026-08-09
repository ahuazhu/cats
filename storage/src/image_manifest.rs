//! Canonical, provider-neutral golden-image manifest boundary.

use std::cell::Cell;
use std::fmt;
use std::time::Instant;

use cats_api::chunk::{CHUNK_SIZE, MAX_VOLUME_BYTES};
use cats_api::runtime_reconciliation::Sha256Digest;
use serde::de::{DeserializeSeed, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};

use crate::{BlobError, BlobStore};

pub const IMAGE_MANIFEST_MAX_BYTES: usize = 32 * 1024 * 1024;
pub const IMAGE_MANIFEST_VERSION: u16 = 1;
const IMAGE_MANIFEST_MAX_CHUNKS: usize = (MAX_VOLUME_BYTES / CHUNK_SIZE as u64) as usize;

/// A SHA-256 digest without the wire-level `sha256:` prefix.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LowerHexSha256(String);

impl LowerHexSha256 {
    pub fn new(value: impl Into<String>) -> Option<Self> {
        let value = value.into();
        (value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
        .then_some(Self(value))
    }

    pub fn from_digest(value: &Sha256Digest) -> Self {
        // Sha256Digest construction proves the exact `sha256:<lowerhex>` wire
        // shape, so removing its fixed prefix preserves this newtype invariant.
        Self(value.as_str()["sha256:".len()..].to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for LowerHexSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for LowerHexSha256 {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl std::ops::Deref for LowerHexSha256 {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageManifestChunkV1 {
    pub chunk_idx: u64,
    pub len: u32,
    pub object_id: LowerHexSha256,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImageManifestV1 {
    pub version: u16,
    pub image_id: LowerHexSha256,
    pub size_bytes: u64,
    pub chunks: Vec<ImageManifestChunkV1>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ImageManifestProblem {
    InvalidUtf8OrJson,
    NonCanonicalBytes,
    UnsupportedVersion,
    IdentityMismatch,
    InvalidSize,
    InvalidChunks,
}

impl fmt::Display for ImageManifestProblem {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::InvalidUtf8OrJson => "invalid_utf8_or_json",
            Self::NonCanonicalBytes => "non_canonical_bytes",
            Self::UnsupportedVersion => "unsupported_version",
            Self::IdentityMismatch => "identity_mismatch",
            Self::InvalidSize => "invalid_size",
            Self::InvalidChunks => "invalid_chunks",
        })
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ImageManifestReadError {
    #[error("image manifest not found at {key}")]
    NotFound { key: String },
    #[error(
        "image manifest exceeds the {maximum}-byte limit (observed at least {observed_at_least})"
    )]
    TooLarge {
        maximum: usize,
        observed_at_least: usize,
    },
    #[error("image manifest at {key} is corrupt: {problem}")]
    Corrupt {
        key: String,
        problem: ImageManifestProblem,
    },
    #[error("image manifest backend is unavailable for {key}")]
    BackendUnavailable { key: String },
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireManifest {
    // Declaration order is the canonical JSON object member order.
    #[serde(deserialize_with = "deserialize_bounded_chunks")]
    chunks: Vec<WireChunk>,
    image_id: String,
    size_bytes: u64,
    version: u16,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireChunk {
    // Declaration order is the canonical JSON object member order.
    chunk_idx: u64,
    len: u32,
    object_id: String,
}

fn deserialize_bounded_chunks<'de, D>(deserializer: D) -> Result<Vec<WireChunk>, D::Error>
where
    D: Deserializer<'de>,
{
    struct BoundedChunksVisitor;

    impl<'de> Visitor<'de> for BoundedChunksVisitor {
        type Value = Vec<WireChunk>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {IMAGE_MANIFEST_MAX_CHUNKS} image manifest chunks"
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: SeqAccess<'de>,
        {
            // Never trust an input-provided size hint as an allocation size.
            // A maximum-size valid image has exactly this many chunks, so any
            // 262145th entry is invalid independent of size_bytes and must be
            // rejected while streaming the sequence rather than after a large
            // untrusted Vec has already been built.
            let mut chunks = Vec::with_capacity(
                sequence
                    .size_hint()
                    .unwrap_or(0)
                    .min(IMAGE_MANIFEST_MAX_CHUNKS),
            );
            while let Some(chunk) = sequence.next_element()? {
                if chunks.len() == IMAGE_MANIFEST_MAX_CHUNKS {
                    return Err(serde::de::Error::invalid_length(
                        IMAGE_MANIFEST_MAX_CHUNKS + 1,
                        &self,
                    ));
                }
                chunks.push(chunk);
            }
            Ok(chunks)
        }
    }

    deserializer.deserialize_seq(BoundedChunksVisitor)
}

pub fn image_manifest_key(boot_image_digest: &Sha256Digest) -> String {
    format!(
        "images/{}/manifest.json",
        &boot_image_digest.as_str()["sha256:".len()..]
    )
}

/// Encode the one accepted manifest artifact representation.
pub fn encode_image_manifest(manifest: &ImageManifestV1) -> Result<Vec<u8>, ImageManifestProblem> {
    validate_manifest(manifest, Some(&manifest.image_id))?;
    serde_json::to_vec(&WireManifest::from(manifest))
        .map_err(|_| ImageManifestProblem::InvalidUtf8OrJson)
}

/// Decode exact canonical bytes and validate every context-free invariant.
pub fn decode_image_manifest(
    bytes: &[u8],
    boot_image_digest: &Sha256Digest,
) -> Result<ImageManifestV1, ImageManifestProblem> {
    reject_canonical_chunk_overflow(bytes)?;
    let wire: WireManifest =
        serde_json::from_slice(bytes).map_err(|_| ImageManifestProblem::InvalidUtf8OrJson)?;
    let canonical =
        serde_json::to_vec(&wire).map_err(|_| ImageManifestProblem::InvalidUtf8OrJson)?;
    if canonical != bytes {
        return Err(ImageManifestProblem::NonCanonicalBytes);
    }

    if wire.version != IMAGE_MANIFEST_VERSION {
        return Err(ImageManifestProblem::UnsupportedVersion);
    }
    let image_id =
        LowerHexSha256::new(wire.image_id).ok_or(ImageManifestProblem::IdentityMismatch)?;
    if image_id != LowerHexSha256::from_digest(boot_image_digest) {
        return Err(ImageManifestProblem::IdentityMismatch);
    }
    if wire.size_bytes == 0
        || wire.size_bytes > MAX_VOLUME_BYTES
        || !wire.size_bytes.is_multiple_of(u64::from(CHUNK_SIZE))
    {
        return Err(ImageManifestProblem::InvalidSize);
    }
    if u64::try_from(wire.chunks.len()).ok() > Some(wire.size_bytes / u64::from(CHUNK_SIZE)) {
        return Err(ImageManifestProblem::InvalidChunks);
    }

    let mut chunks = Vec::with_capacity(wire.chunks.len());
    let mut previous = None;
    let chunk_count = wire.size_bytes / u64::from(CHUNK_SIZE);
    for chunk in wire.chunks {
        if previous.is_some_and(|value| chunk.chunk_idx <= value)
            || chunk.chunk_idx >= chunk_count
            || chunk.len != CHUNK_SIZE
        {
            return Err(ImageManifestProblem::InvalidChunks);
        }
        let object_id =
            LowerHexSha256::new(chunk.object_id).ok_or(ImageManifestProblem::InvalidChunks)?;
        previous = Some(chunk.chunk_idx);
        chunks.push(ImageManifestChunkV1 {
            chunk_idx: chunk.chunk_idx,
            len: chunk.len,
            object_id,
        });
    }
    Ok(ImageManifestV1 {
        version: wire.version,
        image_id,
        size_bytes: wire.size_bytes,
        chunks,
    })
}

fn reject_canonical_chunk_overflow(bytes: &[u8]) -> Result<(), ImageManifestProblem> {
    const CANONICAL_CHUNKS_PREFIX: &[u8] = b"{\"chunks\":";
    let Some(chunks) = bytes.strip_prefix(CANONICAL_CHUNKS_PREFIX) else {
        return Ok(());
    };
    let overflowed = Cell::new(false);
    let mut deserializer = serde_json::Deserializer::from_slice(chunks);
    let _ = ChunkCountSeed {
        overflowed: &overflowed,
    }
    .deserialize(&mut deserializer);
    if overflowed.get() {
        Err(ImageManifestProblem::InvalidChunks)
    } else {
        Ok(())
    }
}

struct ChunkCountSeed<'a> {
    overflowed: &'a Cell<bool>,
}

impl<'de> DeserializeSeed<'de> for ChunkCountSeed<'_> {
    type Value = ();

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_seq(ChunkCountVisitor {
            overflowed: self.overflowed,
        })
    }
}

struct ChunkCountVisitor<'a> {
    overflowed: &'a Cell<bool>,
}

impl<'de> Visitor<'de> for ChunkCountVisitor<'_> {
    type Value = ();

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("the canonical image manifest chunks array")
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        for _ in 0..IMAGE_MANIFEST_MAX_CHUNKS {
            if sequence.next_element::<WireChunk>()?.is_none() {
                return Ok(());
            }
        }
        if sequence.next_element::<WireChunk>()?.is_some() {
            self.overflowed.set(true);
            return Err(serde::de::Error::invalid_length(
                IMAGE_MANIFEST_MAX_CHUNKS + 1,
                &self,
            ));
        }
        Ok(())
    }
}

pub fn read_image_manifest(
    blob: &dyn BlobStore,
    boot_image_digest: &Sha256Digest,
) -> Result<ImageManifestV1, ImageManifestReadError> {
    read_with(blob, boot_image_digest, None)
}

pub fn read_image_manifest_until(
    blob: &dyn BlobStore,
    boot_image_digest: &Sha256Digest,
    deadline: Instant,
) -> Result<ImageManifestV1, ImageManifestReadError> {
    read_with(blob, boot_image_digest, Some(deadline))
}

fn read_with(
    blob: &dyn BlobStore,
    boot_image_digest: &Sha256Digest,
    deadline: Option<Instant>,
) -> Result<ImageManifestV1, ImageManifestReadError> {
    let key = image_manifest_key(boot_image_digest);
    let result = match deadline {
        Some(deadline) => blob.get_bounded_until(&key, IMAGE_MANIFEST_MAX_BYTES, deadline),
        None => blob.get_bounded(&key, IMAGE_MANIFEST_MAX_BYTES),
    };
    let bytes = result.map_err(|error| match error {
        BlobError::NotFound(_) => ImageManifestReadError::NotFound { key: key.clone() },
        BlobError::TooLarge {
            maximum,
            observed_at_least,
            ..
        } => ImageManifestReadError::TooLarge {
            maximum,
            observed_at_least,
        },
        BlobError::InvalidKey { .. } | BlobError::Io { .. } | BlobError::Backend { .. } => {
            ImageManifestReadError::BackendUnavailable { key: key.clone() }
        }
    })?;
    decode_image_manifest(&bytes, boot_image_digest).map_err(|problem| {
        ImageManifestReadError::Corrupt {
            key: key.clone(),
            problem,
        }
    })
}

fn validate_manifest(
    manifest: &ImageManifestV1,
    expected_image_id: Option<&LowerHexSha256>,
) -> Result<(), ImageManifestProblem> {
    if manifest.version != IMAGE_MANIFEST_VERSION {
        return Err(ImageManifestProblem::UnsupportedVersion);
    }
    if expected_image_id.is_some_and(|expected| expected != &manifest.image_id) {
        return Err(ImageManifestProblem::IdentityMismatch);
    }
    if manifest.size_bytes == 0
        || manifest.size_bytes > MAX_VOLUME_BYTES
        || !manifest.size_bytes.is_multiple_of(u64::from(CHUNK_SIZE))
    {
        return Err(ImageManifestProblem::InvalidSize);
    }
    if u64::try_from(manifest.chunks.len()).ok() > Some(manifest.size_bytes / u64::from(CHUNK_SIZE))
    {
        return Err(ImageManifestProblem::InvalidChunks);
    }
    let mut previous = None;
    let chunk_count = manifest.size_bytes / u64::from(CHUNK_SIZE);
    for chunk in &manifest.chunks {
        if previous.is_some_and(|value| chunk.chunk_idx <= value)
            || chunk.chunk_idx >= chunk_count
            || chunk.len != CHUNK_SIZE
        {
            return Err(ImageManifestProblem::InvalidChunks);
        }
        previous = Some(chunk.chunk_idx);
    }
    Ok(())
}

impl From<&ImageManifestV1> for WireManifest {
    fn from(manifest: &ImageManifestV1) -> Self {
        Self {
            chunks: manifest
                .chunks
                .iter()
                .map(|chunk| WireChunk {
                    chunk_idx: chunk.chunk_idx,
                    len: chunk.len,
                    object_id: chunk.object_id.as_str().to_string(),
                })
                .collect(),
            image_id: manifest.image_id.as_str().to_string(),
            size_bytes: manifest.size_bytes,
            version: manifest.version,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use sha2::{Digest, Sha256};

    use super::*;

    const DIGEST: &str = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const FIXED: &[u8] = b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}";

    fn digest() -> Sha256Digest {
        Sha256Digest::new(DIGEST).unwrap()
    }

    fn canonical_value(value: serde_json::Value) -> Vec<u8> {
        // serde_json's map representation emits the same lexicographic member
        // order frozen by A21 for these field names.
        serde_json::to_vec(&value).unwrap()
    }

    #[test]
    fn fixed_vector_is_exact_and_round_trips() {
        assert_eq!(FIXED.len(), 124);
        assert_eq!(
            format!("{:x}", Sha256::digest(FIXED)),
            "e250eb35ef5804002b6afebcc410cba2df75f38c1761c5bf2d5d00a57e8c7d02"
        );
        let manifest = decode_image_manifest(FIXED, &digest()).unwrap();
        assert_eq!(encode_image_manifest(&manifest).unwrap(), FIXED);
        assert_eq!(
            image_manifest_key(&digest()),
            "images/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/manifest.json"
        );
    }

    #[test]
    fn legacy_order_and_whitespace_are_not_accepted() {
        let legacy = b"{\"version\":1,\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"chunks\":[]}";
        assert_eq!(
            decode_image_manifest(legacy, &digest()),
            Err(ImageManifestProblem::NonCanonicalBytes)
        );
        let newline = [FIXED, b"\n"].concat();
        assert_eq!(
            decode_image_manifest(&newline, &digest()),
            Err(ImageManifestProblem::NonCanonicalBytes)
        );
        let spaced = String::from_utf8(FIXED.to_vec())
            .unwrap()
            .replacen(":[]", ": []", 1);
        assert_eq!(
            decode_image_manifest(spaced.as_bytes(), &digest()),
            Err(ImageManifestProblem::NonCanonicalBytes)
        );
    }

    #[test]
    fn schema_identity_size_and_chunk_failures_are_closed() {
        let base = serde_json::json!({
            "chunks": [],
            "image_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "size_bytes": 4194304,
            "version": 1
        });
        let cases = [
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 4194304,
                    "version": 2
                }),
                ImageManifestProblem::UnsupportedVersion,
            ),
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 4194304,
                    "version": 1
                }),
                ImageManifestProblem::IdentityMismatch,
            ),
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 4194304,
                    "version": 1
                }),
                ImageManifestProblem::IdentityMismatch,
            ),
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 0,
                    "version": 1
                }),
                ImageManifestProblem::InvalidSize,
            ),
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 4194305,
                    "version": 1
                }),
                ImageManifestProblem::InvalidSize,
            ),
            (
                serde_json::json!({
                    "chunks": [],
                    "image_id": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
                    "size_bytes": 1099515822080_u64,
                    "version": 1
                }),
                ImageManifestProblem::InvalidSize,
            ),
        ];
        for (value, expected) in cases {
            assert_eq!(
                decode_image_manifest(&canonical_value(value), &digest()),
                Err(expected)
            );
        }

        let object = "1".repeat(64);
        for chunks in [
            serde_json::json!([
                {"chunk_idx":0,"len":4194304,"object_id":object},
                {"chunk_idx":0,"len":4194304,"object_id":object}
            ]),
            serde_json::json!([
                {"chunk_idx":1,"len":4194304,"object_id":object},
                {"chunk_idx":0,"len":4194304,"object_id":object}
            ]),
            serde_json::json!([
                {"chunk_idx":1,"len":4194304,"object_id":object}
            ]),
            serde_json::json!([
                {"chunk_idx":0,"len":1,"object_id":object}
            ]),
            serde_json::json!([
                {"chunk_idx":0,"len":4194304,"object_id":"ABCDEF"}
            ]),
        ] {
            let mut value = base.clone();
            value["chunks"] = chunks;
            assert_eq!(
                decode_image_manifest(&canonical_value(value), &digest()),
                Err(ImageManifestProblem::InvalidChunks)
            );
        }
    }

    #[test]
    fn malformed_fields_and_noncanonical_numbers_never_enter_the_dto() {
        for bytes in [
            b"{\"chunks\":[],\"extra\":1,\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".as_slice(),
            b"{\"chunks\":[],\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".as_slice(),
            b"{\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".as_slice(),
            b"{\"chunks\":{},\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".as_slice(),
            b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":\"1\"}".as_slice(),
            b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4.194304e6,\"version\":1}".as_slice(),
            b"{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":-0,\"version\":1}".as_slice(),
            b"\xef\xbb\xbf{\"chunks\":[],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}".as_slice(),
        ] {
            assert!(decode_image_manifest(bytes, &digest()).is_err());
        }

        let escaped = b"{\"chunks\":[],\"image_id\":\"\\u0030123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}";
        assert_eq!(
            decode_image_manifest(escaped, &digest()),
            Err(ImageManifestProblem::NonCanonicalBytes)
        );
        let reordered_chunk = b"{\"chunks\":[{\"object_id\":\"1111111111111111111111111111111111111111111111111111111111111111\",\"len\":4194304,\"chunk_idx\":0}],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":4194304,\"version\":1}";
        assert_eq!(
            decode_image_manifest(reordered_chunk, &digest()),
            Err(ImageManifestProblem::NonCanonicalBytes)
        );
    }

    #[test]
    fn maximum_dense_manifest_fits_under_the_reader_cap() {
        let object_id = LowerHexSha256::new("1".repeat(64)).unwrap();
        let chunks = (0..262_144)
            .map(|chunk_idx| ImageManifestChunkV1 {
                chunk_idx,
                len: CHUNK_SIZE,
                object_id: object_id.clone(),
            })
            .collect();
        let manifest = ImageManifestV1 {
            version: IMAGE_MANIFEST_VERSION,
            image_id: LowerHexSha256::from_digest(&digest()),
            size_bytes: MAX_VOLUME_BYTES,
            chunks,
        };
        let encoded = encode_image_manifest(&manifest).unwrap();
        assert_eq!(encoded.len(), 29_773_435);
        assert!(encoded.len() < IMAGE_MANIFEST_MAX_BYTES);
        let decoded = decode_image_manifest(&encoded, &digest()).unwrap();
        assert_eq!(decoded.chunks.len(), 262_144);
    }

    #[test]
    fn chunk_sequence_is_rejected_at_the_first_entry_above_the_volume_limit() {
        let entry = "{\"chunk_idx\":0,\"len\":0,\"object_id\":\"\"}";
        let mut bytes = String::with_capacity(entry.len() * (IMAGE_MANIFEST_MAX_CHUNKS + 1));
        bytes.push_str("{\"chunks\":[");
        for index in 0..=IMAGE_MANIFEST_MAX_CHUNKS {
            if index != 0 {
                bytes.push(',');
            }
            bytes.push_str(entry);
        }
        bytes.push_str(
            "],\"image_id\":\"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\",\"size_bytes\":1099511627776,\"version\":1}",
        );

        assert!(bytes.len() < IMAGE_MANIFEST_MAX_BYTES);
        assert_eq!(
            decode_image_manifest(bytes.as_bytes(), &digest()),
            Err(ImageManifestProblem::InvalidChunks)
        );
    }

    struct RecordingBlob {
        bytes: Vec<u8>,
        keys: Mutex<Vec<String>>,
        maximums: Mutex<Vec<usize>>,
    }

    impl BlobStore for RecordingBlob {
        fn put_immutable(&self, _key: &str, _data: &[u8]) -> crate::blob::Result<()> {
            unreachable!()
        }

        fn get(&self, key: &str) -> crate::blob::Result<Vec<u8>> {
            self.keys.lock().unwrap().push(key.to_string());
            Ok(self.bytes.clone())
        }

        fn get_bounded(&self, key: &str, maximum: usize) -> crate::blob::Result<Vec<u8>> {
            self.keys.lock().unwrap().push(key.to_string());
            self.maximums.lock().unwrap().push(maximum);
            if self.bytes.len() > maximum {
                return Err(BlobError::TooLarge {
                    key: key.to_string(),
                    maximum,
                    observed_at_least: maximum.saturating_add(1),
                });
            }
            Ok(self.bytes.clone())
        }

        fn exists(&self, _key: &str) -> crate::blob::Result<bool> {
            unreachable!()
        }

        fn delete(&self, _key: &str) -> crate::blob::Result<()> {
            unreachable!()
        }

        fn list(&self, _prefix: &str) -> crate::blob::Result<Vec<String>> {
            unreachable!()
        }
    }

    #[test]
    fn reader_fetches_only_the_exact_manifest_key() {
        let blob = RecordingBlob {
            bytes: FIXED.to_vec(),
            keys: Mutex::new(Vec::new()),
            maximums: Mutex::new(Vec::new()),
        };
        read_image_manifest(&blob, &digest()).unwrap();
        assert_eq!(
            *blob.keys.lock().unwrap(),
            vec![image_manifest_key(&digest())]
        );
        assert_eq!(
            *blob.maximums.lock().unwrap(),
            vec![IMAGE_MANIFEST_MAX_BYTES]
        );
    }

    #[test]
    fn reader_accepts_exactly_the_cap_for_decode_and_rejects_the_next_byte() {
        let at_cap = RecordingBlob {
            bytes: vec![b' '; IMAGE_MANIFEST_MAX_BYTES],
            keys: Mutex::new(Vec::new()),
            maximums: Mutex::new(Vec::new()),
        };
        assert!(matches!(
            read_image_manifest(&at_cap, &digest()),
            Err(ImageManifestReadError::Corrupt { .. })
        ));

        let above_cap = RecordingBlob {
            bytes: vec![b' '; IMAGE_MANIFEST_MAX_BYTES + 1],
            keys: Mutex::new(Vec::new()),
            maximums: Mutex::new(Vec::new()),
        };
        assert_eq!(
            read_image_manifest(&above_cap, &digest()),
            Err(ImageManifestReadError::TooLarge {
                maximum: IMAGE_MANIFEST_MAX_BYTES,
                observed_at_least: IMAGE_MANIFEST_MAX_BYTES + 1,
            })
        );
    }
}
