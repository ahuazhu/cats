//! Recovery of the closed ObjectWrite key class from a ChunkStore key.
//!
//! [`cats_api::object_write_gateway::object_write_key`] renders one
//! [`ObjectWriteImmutableKey`] into the flat key the blob port uses. This
//! module inverts that rendering so an existing `BlobStore` caller keeps its
//! string key, and then re-renders the recovered class and requires it to
//! reproduce the caller's key byte for byte. Anything the closed contract
//! cannot express — image objects, metadata heads, arbitrary prefixes, a key
//! belonging to another volume, a map key whose digest is not the body's
//! digest — fails before any request is signed or sent.

use cats_api::object_write_gateway::{
    object_write_key, ObjectWriteImmutableKey, VolumeDataObjectKind,
};
use cats_api::runtime_reconciliation::{Generation, Id, RandomId128, Sha256Digest, WireU64};

use crate::ObjectWriteError;

const VOLUME_PREFIX: &str = "volumes/";
const MAP_SUFFIX: &str = ".node";
const COMMIT_SUFFIX: &str = ".json";
const DELTA_SUFFIX: &str = "-d";
const CHUNK_SEPARATOR: &str = "-c";

/// Recover the signed key class for `key`, or explain why this attachment
/// credential may not write it.
///
/// `content_sha256` is the digest of the exact bytes being published. It is
/// required here rather than derived later because a volume map key *is* its
/// content digest: a caller that offers a map key for different bytes is
/// asking for an object the gateway would refuse, and the mismatch must be
/// caught locally instead of turning into a remote rejection.
pub(crate) fn immutable_key_for(
    volume_id: &Id,
    key: &str,
    content_sha256: &Sha256Digest,
) -> Result<ObjectWriteImmutableKey, ObjectWriteError> {
    cats_storage::validate_key(key).map_err(|error| ObjectWriteError::UnrepresentableKey {
        key: key.to_owned(),
        reason: error.to_string(),
    })?;
    let recovered = recover(volume_id, key)?;
    let rendered = object_write_key(volume_id, &recovered, content_sha256).map_err(|source| {
        ObjectWriteError::Contract {
            key: key.to_owned(),
            source,
        }
    })?;
    if rendered != key {
        return Err(ObjectWriteError::UnrepresentableKey {
            key: key.to_owned(),
            reason: format!("the signed key class renders as {rendered:?} instead"),
        });
    }
    Ok(recovered)
}

fn recover(volume_id: &Id, key: &str) -> Result<ObjectWriteImmutableKey, ObjectWriteError> {
    let unprefixed = key
        .strip_prefix(VOLUME_PREFIX)
        .ok_or_else(|| unrepresentable(key, "only volume objects are writable"))?;
    let (found_volume, rest) = unprefixed
        .split_once('/')
        .ok_or_else(|| unrepresentable(key, "expected volumes/<volume-id>/<class>/<object>"))?;
    if found_volume != volume_id.as_str() {
        return Err(ObjectWriteError::VolumeMismatch {
            key: key.to_owned(),
            expected: volume_id.as_str().to_owned(),
            found: found_volume.to_owned(),
        });
    }
    let (class, object) = rest
        .split_once('/')
        .ok_or_else(|| unrepresentable(key, "expected volumes/<volume-id>/<class>/<object>"))?;
    match class {
        "data" => data_key(key, object),
        "maps" => map_key(key, object),
        "commits" => commit_key(key, object),
        _ => Err(unrepresentable(
            key,
            "only data, map and commit objects are writable",
        )),
    }
}

fn data_key(key: &str, object: &str) -> Result<ObjectWriteImmutableKey, ObjectWriteError> {
    let (body, object_kind) = match object.strip_suffix(DELTA_SUFFIX) {
        Some(body) => (body, VolumeDataObjectKind::Delta),
        None => (object, VolumeDataObjectKind::Base),
    };
    let (transaction, chunk_index) = body
        .rsplit_once(CHUNK_SEPARATOR)
        .ok_or_else(|| unrepresentable(key, "expected <transaction>-c<chunk-index>"))?;
    let transaction_id = RandomId128::new(transaction)
        .ok_or_else(|| unrepresentable(key, "the transaction is not a 128-bit random id"))?;
    let chunk_index = chunk_index
        .parse::<u64>()
        .ok()
        .and_then(WireU64::new)
        .ok_or_else(|| unrepresentable(key, "the chunk index is not a wire integer"))?;
    Ok(ObjectWriteImmutableKey::VolumeData {
        transaction_id,
        chunk_index,
        object_kind,
    })
}

fn map_key(key: &str, object: &str) -> Result<ObjectWriteImmutableKey, ObjectWriteError> {
    if !object.ends_with(MAP_SUFFIX) {
        return Err(unrepresentable(key, "a map object must end in .node"));
    }
    // The digest inside the key is checked by re-rendering against the body's
    // own digest, so nothing further is recoverable here.
    Ok(ObjectWriteImmutableKey::VolumeMap)
}

fn commit_key(key: &str, object: &str) -> Result<ObjectWriteImmutableKey, ObjectWriteError> {
    let body = object
        .strip_suffix(COMMIT_SUFFIX)
        .ok_or_else(|| unrepresentable(key, "a commit record must end in .json"))?;
    let (generation, transaction) = body
        .split_once('-')
        .ok_or_else(|| unrepresentable(key, "expected <generation>-<transaction>.json"))?;
    // Generation zero is representable as a wire integer but the signed
    // contract refuses it: there is no commit before the first one.
    let generation = generation
        .parse::<u64>()
        .ok()
        .filter(|generation| *generation > 0)
        .and_then(Generation::new)
        .ok_or_else(|| unrepresentable(key, "the generation is not a committed generation"))?;
    let transaction_id = RandomId128::new(transaction)
        .ok_or_else(|| unrepresentable(key, "the transaction is not a 128-bit random id"))?;
    Ok(ObjectWriteImmutableKey::VolumeCommit {
        generation,
        transaction_id,
    })
}

fn unrepresentable(key: &str, reason: &str) -> ObjectWriteError {
    ObjectWriteError::UnrepresentableKey {
        key: key.to_owned(),
        reason: reason.to_owned(),
    }
}
