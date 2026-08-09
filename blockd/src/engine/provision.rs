use std::collections::HashSet;
use std::fs;
use std::sync::atomic::Ordering;

use cats_api::chunk::{self, CHUNK_SIZE};
use cats_api::runtime_reconciliation::{
    AsciiText, Generation, ProvisionRootImageDefiniteConflictProblem, ProvisionRootImageError,
    ProvisionRootImageRequest, ProvisionRootImageResult, ProvisionRootImageRetryableProblem,
    RemoteHead, Sha256Digest,
};
use cats_storage::{BlobError, MetaError, VolumeHead};

use crate::crashpoint;
use crate::format::{self, ImageManifest, LeafRef};
use crate::image::ImageError;

use super::publish::{encode_commit_record, PreparedMapPublication};
use super::*;

/// An effect response is deliberately narrower than [`EngineError`].
///
/// `Closed` is the complete A14 ERR vocabulary. `ResultUnknown` is never put
/// on the wire: fencing, an authority identity change, or an unclassifiable
/// transport outcome makes the control server close the connection so the
/// Node must reread the authoritative volume head.
#[derive(Debug, thiserror::Error)]
pub enum ProvisionRootImageEffectError {
    #[error("root image provision returned a closed error: {0:?}")]
    Closed(ProvisionRootImageError),
    #[error("root image provision result is unknown: {0}")]
    ResultUnknown(&'static str),
}

type EffectResult<T> = std::result::Result<T, ProvisionRootImageEffectError>;

impl ChunkEngine {
    /// Publish the deterministic generation-one image root under an already
    /// granted owner/epoch, with every Guest data path disabled.
    ///
    /// The transition id is both the durable commit transaction and its object
    /// key. All request, manifest, local-state, and computed-target checks run
    /// before the first immutable PUT. The only successful predecessors are
    /// the exact blank head and an idempotent replay of the exact target.
    pub fn provision_root_image(
        &self,
        request: &ProvisionRootImageRequest,
    ) -> EffectResult<ProvisionRootImageResult> {
        self.validate_request_binding(request)?;
        if self.is_fenced() {
            return Err(ProvisionRootImageEffectError::ResultUnknown(
                "attachment is fenced",
            ));
        }

        let _flush = self
            .flush_lock
            .lock()
            .map_err(|_| ProvisionRootImageEffectError::ResultUnknown("flush lock was poisoned"))?;
        let _publish = self.publish_lock.lock().map_err(|_| {
            ProvisionRootImageEffectError::ResultUnknown("publish lock was poisoned")
        })?;
        let _gate = self
            .io_gate
            .write()
            .map_err(|_| ProvisionRootImageEffectError::ResultUnknown("I/O gate was poisoned"))?;

        self.validate_local_state(request)?;
        let manifest = self.load_and_validate_manifest(request)?;
        let (new_map, prepared, chunks) = self.compute_target(request, &manifest)?;

        let head = self.load_authority(request)?;
        if same_target(&head, &request.expected_provisioned_head) {
            self.reload_target_map(request)?;
            return Ok(effect_result(request));
        }
        if !is_blank(&head) {
            return Err(ProvisionRootImageEffectError::ResultUnknown(
                "authoritative head is neither blank nor the requested target",
            ));
        }

        let volume_id = request.volume_id.as_str();
        for (hash, bytes) in &prepared.leaf_nodes {
            let key = chunk::keys::map_node(volume_id, &hex::encode(hash));
            self.put_provision_object(request, &key, bytes)?;
            crashpoint::maybe_crash(crashpoint::AFTER_PROVISION_LEAF_PUT);
        }

        let root_hex = hex::encode(prepared.root_hash);
        let root_key = chunk::keys::map_node(volume_id, &root_hex);
        self.put_provision_object(request, &root_key, &prepared.root_bytes)?;
        crashpoint::maybe_crash(crashpoint::AFTER_PROVISION_ROOT_PUT);

        let transition = request.provision_transition_id.as_str();
        let record = encode_commit_record(transition, 1, self.epoch, &root_hex, &chunks);
        let commit_key = chunk::keys::commit_record(volume_id, 1, transition);
        self.put_provision_object(request, &commit_key, &record)?;
        crashpoint::maybe_crash(crashpoint::AFTER_PROVISION_COMMIT_PUT);
        crashpoint::maybe_crash(crashpoint::BEFORE_CAS);

        let cas = self.authority.compare_and_swap_head(
            volume_id,
            self.size,
            &request.expected_blank_head,
            &request.expected_provisioned_head,
            request.attachment_id.as_str(),
            self.epoch,
        );
        match cas {
            Ok(1) => {}
            Ok(_) => {
                return Err(ProvisionRootImageEffectError::ResultUnknown(
                    "authority returned an unexpected generation",
                ));
            }
            Err(MetaError::Backend(_) | MetaError::CasConflict { .. }) => {
                let observed = self.load_authority(request)?;
                if same_target(&observed, &request.expected_provisioned_head) {
                    // A lost CAS response is an idempotent success.
                } else if is_blank(&observed) {
                    return Err(retryable(
                        request,
                        ProvisionRootImageRetryableProblem::AuthorityUnavailable,
                    ));
                } else {
                    return Err(ProvisionRootImageEffectError::ResultUnknown(
                        "ambiguous CAS observed a different authoritative head",
                    ));
                }
            }
            Err(MetaError::Fenced | MetaError::LeaseHeld) => {
                self.fenced.store(true, Ordering::SeqCst);
                return Err(ProvisionRootImageEffectError::ResultUnknown(
                    "authority rejected the owner or epoch",
                ));
            }
            Err(_) => {
                return Err(ProvisionRootImageEffectError::ResultUnknown(
                    "authority rejected the generation-one CAS",
                ));
            }
        }
        crashpoint::maybe_crash(crashpoint::AFTER_CAS);

        // The head is the authority, but this process must also load the exact
        // committed map before it can truthfully report the control effect. It
        // still cannot expose Guest I/O; the later reconciler phase restarts a
        // serving frontend under the same grant.
        {
            let mut state = self.state.lock().map_err(|_| {
                ProvisionRootImageEffectError::ResultUnknown("engine state lock was poisoned")
            })?;
            state.map = new_map;
            state.leaf_refs = prepared.leaves;
            state.generation = 1;
            state.hydrated.fill(false);
        }
        self.staged
            .lock()
            .map_err(|_| {
                ProvisionRootImageEffectError::ResultUnknown("staged queue lock was poisoned")
            })?
            .next_base = 1;

        // Close the response race as far as a hint can: a later owner change
        // never becomes a closed blockd error. The Node rereads authority after
        // every response regardless.
        let observed = self.load_authority(request)?;
        if !same_target(&observed, &request.expected_provisioned_head) {
            return Err(ProvisionRootImageEffectError::ResultUnknown(
                "authority changed after the generation-one CAS",
            ));
        }
        Ok(effect_result(request))
    }

    fn validate_request_binding(&self, request: &ProvisionRootImageRequest) -> EffectResult<()> {
        let epoch = i64::try_from(request.attachment_epoch.get()).ok();
        if self.guest_io_enabled
            || request.volume_id.as_str() != self.cfg.volume_id
            || request.attachment_id.as_str() != self.cfg.attachment_id
            || epoch != Some(self.epoch)
            || request.size_bytes != self.size
        {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::RequestBinding,
            ));
        }
        if request.expected_blank_head.generation.get() != 0
            || request.expected_blank_head.root_hash.is_some()
            || request.expected_blank_head.root_object_id.is_some()
            || request.expected_provisioned_head.generation.get() != 1
            || request.expected_provisioned_head.root_hash.is_none()
            || request.expected_provisioned_head.root_object_id.is_none()
        {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::TargetMismatch,
            ));
        }
        Ok(())
    }

    fn validate_local_state(&self, request: &ProvisionRootImageRequest) -> EffectResult<()> {
        if self.inflight_staging_bytes.load(Ordering::SeqCst) != 0 {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::LocalState,
            ));
        }
        let staged = self.staged.lock().map_err(|_| {
            ProvisionRootImageEffectError::ResultUnknown("staged queue lock was poisoned")
        })?;
        if !staged.packs.is_empty() || staged.bytes != 0 {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::LocalState,
            ));
        }
        drop(staged);

        let state = self.state.lock().map_err(|_| {
            ProvisionRootImageEffectError::ResultUnknown("engine state lock was poisoned")
        })?;
        if !matches!(state.generation, 0 | 1)
            || state.dirty.iter().any(|word| *word != 0)
            || state.dirty_ranges.iter().any(|ranges| !ranges.is_empty())
            || !state.discarded.is_empty()
            || !state.freezing.is_empty()
        {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::LocalState,
            ));
        }
        drop(state);

        let pending = self.cfg.data_dir.join(PENDING_PACK_DIR);
        let mut entries = fs::read_dir(&pending).map_err(|_| {
            retryable(
                request,
                ProvisionRootImageRetryableProblem::LocalIoUnavailable,
            )
        })?;
        match entries.next() {
            Some(Ok(_)) => Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::LocalState,
            )),
            Some(Err(_)) => Err(retryable(
                request,
                ProvisionRootImageRetryableProblem::LocalIoUnavailable,
            )),
            None => Ok(()),
        }
    }

    fn load_and_validate_manifest(
        &self,
        request: &ProvisionRootImageRequest,
    ) -> EffectResult<ImageManifest> {
        let image_id = &request.boot_image_digest.as_str()["sha256:".len()..];
        let manifest =
            crate::image::load(self.blob.as_ref(), image_id).map_err(|error| match error {
                ImageError::Blob(BlobError::NotFound(_)) => retryable(
                    request,
                    ProvisionRootImageRetryableProblem::ImageUnavailable,
                ),
                ImageError::Blob(_) => retryable(
                    request,
                    ProvisionRootImageRetryableProblem::ObjectStoreUnavailable,
                ),
                ImageError::Corrupt(_) | ImageError::Invalid { .. } | ImageError::Empty(_) => {
                    definite(
                        request,
                        ProvisionRootImageDefiniteConflictProblem::ImageManifest,
                    )
                }
                ImageError::Io(_) => retryable(
                    request,
                    ProvisionRootImageRetryableProblem::LocalIoUnavailable,
                ),
            })?;

        // The cats-storage reader has already completed the shared canonical
        // and structural pass. This request-local fit check is the only
        // manifest shape condition owned by blockd.
        if manifest.size_bytes > request.size_bytes {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::ImageManifest,
            ));
        }

        // Only after the shared structural pass succeeds may availability of an
        // individual object affect the outcome.
        let mut verified_objects = HashSet::new();
        for entry in &manifest.chunks {
            if !verified_objects.insert(entry.object_id.as_str()) {
                continue;
            }
            let key = chunk::keys::image_data(image_id, entry.object_id.as_str());
            let bytes = self.blob.get(&key).map_err(|error| match error {
                BlobError::NotFound(_) => retryable(
                    request,
                    ProvisionRootImageRetryableProblem::ImageUnavailable,
                ),
                _ => retryable(
                    request,
                    ProvisionRootImageRetryableProblem::ObjectStoreUnavailable,
                ),
            })?;
            let expected_digest = format::decode_sha256_hex(entry.object_id.as_str());
            if bytes.len() != CHUNK_SIZE as usize
                || expected_digest.is_none_or(|digest| format::sha256(&bytes) != digest)
            {
                return Err(definite(
                    request,
                    ProvisionRootImageDefiniteConflictProblem::ImageManifest,
                ));
            }
        }
        Ok(manifest)
    }

    fn compute_target(
        &self,
        request: &ProvisionRootImageRequest,
        manifest: &ImageManifest,
    ) -> EffectResult<(Vec<format::ChunkRef>, PreparedMapPublication, Vec<u64>)> {
        let new_map = format::image_base_map(manifest, request.size_bytes).map_err(|_| {
            definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::ImageManifest,
            )
        })?;
        let chunks: Vec<u64> = manifest
            .chunks
            .iter()
            .map(|entry| entry.chunk_idx)
            .collect();
        let leaves = vec![LeafRef::Empty; chunk::leaf_count(request.size_bytes) as usize];
        let prepared = self.prepare_map_publication(0, &new_map, &leaves, &chunks);
        let computed = RemoteHead {
            generation: Generation::new(1).expect("one is a valid generation"),
            root_hash: Some(Sha256Digest::from_bytes(prepared.root_hash)),
            root_object_id: Some(
                AsciiText::new(prepared.root_object_id.clone())
                    .expect("sha256 map object id is printable ASCII"),
            ),
        };
        if computed != request.expected_provisioned_head {
            return Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::TargetMismatch,
            ));
        }
        Ok((new_map, prepared, chunks))
    }

    fn load_authority(&self, request: &ProvisionRootImageRequest) -> EffectResult<VolumeHead> {
        let head = self
            .authority
            .load_head(request.volume_id.as_str())
            .map_err(|error| {
                if matches!(error, MetaError::Backend(_)) {
                    retryable(
                        request,
                        ProvisionRootImageRetryableProblem::AuthorityUnavailable,
                    )
                } else {
                    ProvisionRootImageEffectError::ResultUnknown(
                        "authoritative volume head could not be classified",
                    )
                }
            })?;
        if head.volume_id != request.volume_id.as_str()
            || head.size_bytes != request.size_bytes
            || head.lease_owner.as_deref() != Some(request.attachment_id.as_str())
            || u64::try_from(head.lease_epoch).ok() != Some(request.attachment_epoch.get())
        {
            self.fenced.store(true, Ordering::SeqCst);
            return Err(ProvisionRootImageEffectError::ResultUnknown(
                "authoritative owner, epoch, or immutable binding changed",
            ));
        }
        Ok(head)
    }

    fn put_provision_object(
        &self,
        request: &ProvisionRootImageRequest,
        key: &str,
        bytes: &[u8],
    ) -> EffectResult<()> {
        if self.blob.put_immutable(key, bytes).is_ok() {
            return Ok(());
        }
        match self.blob.get(key) {
            Ok(existing) if existing == bytes => Ok(()),
            Ok(_) => Err(definite(
                request,
                ProvisionRootImageDefiniteConflictProblem::ImmutableObject,
            )),
            Err(_) => Err(retryable(
                request,
                ProvisionRootImageRetryableProblem::ObjectStoreUnavailable,
            )),
        }
    }

    fn reload_target_map(&self, request: &ProvisionRootImageRequest) -> EffectResult<()> {
        self.load_committed_map().map_err(|error| match error {
            EngineError::Blob(_) => retryable(
                request,
                ProvisionRootImageRetryableProblem::ObjectStoreUnavailable,
            ),
            EngineError::Io(_) => retryable(
                request,
                ProvisionRootImageRetryableProblem::LocalIoUnavailable,
            ),
            _ => ProvisionRootImageEffectError::ResultUnknown(
                "committed target could not be loaded into the control process",
            ),
        })
    }
}

fn effect_result(request: &ProvisionRootImageRequest) -> ProvisionRootImageResult {
    ProvisionRootImageResult {
        provision_transition_id: request.provision_transition_id.clone(),
        volume_id: request.volume_id.clone(),
        attachment_id: request.attachment_id.clone(),
        attachment_epoch: request.attachment_epoch,
        resulting_head: request.expected_provisioned_head.clone(),
    }
}

fn retryable(
    request: &ProvisionRootImageRequest,
    problem: ProvisionRootImageRetryableProblem,
) -> ProvisionRootImageEffectError {
    ProvisionRootImageEffectError::Closed(ProvisionRootImageError::Retryable {
        provision_transition_id: request.provision_transition_id.clone(),
        volume_id: request.volume_id.clone(),
        attachment_id: request.attachment_id.clone(),
        attachment_epoch: request.attachment_epoch,
        problem,
    })
}

fn definite(
    request: &ProvisionRootImageRequest,
    problem: ProvisionRootImageDefiniteConflictProblem,
) -> ProvisionRootImageEffectError {
    ProvisionRootImageEffectError::Closed(ProvisionRootImageError::DefiniteConflict {
        provision_transition_id: request.provision_transition_id.clone(),
        volume_id: request.volume_id.clone(),
        attachment_id: request.attachment_id.clone(),
        attachment_epoch: request.attachment_epoch,
        problem,
    })
}

fn is_blank(head: &VolumeHead) -> bool {
    head.generation == 0 && head.root_hash.is_none() && head.root_object_id.is_none()
}

fn same_target(head: &VolumeHead, expected: &RemoteHead) -> bool {
    u64::try_from(head.generation).ok() == Some(expected.generation.get())
        && head.root_hash.as_ref() == expected.root_hash.as_ref().map(Sha256Digest::as_bytes)
        && head.root_object_id.as_deref() == expected.root_object_id.as_ref().map(AsciiText::as_str)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::format::{BaseRef, ChunkRef};

    const FIXED_MANIFEST: &str = r#"{"chunks":[{"chunk_idx":0,"len":4194304,"object_id":"1111111111111111111111111111111111111111111111111111111111111111"},{"chunk_idx":256,"len":4194304,"object_id":"2222222222222222222222222222222222222222222222222222222222222222"}],"image_id":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef","size_bytes":1077936128,"version":1}"#;

    #[test]
    fn root_provision_fixed_vector_crosses_the_leaf_boundary() {
        let digest = Sha256Digest::new(
            "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        )
        .unwrap();
        let manifest =
            cats_storage::decode_image_manifest(FIXED_MANIFEST.as_bytes(), &digest).unwrap();
        let chunk_count = manifest.size_bytes / CHUNK_SIZE as u64;
        assert_eq!(chunk_count, 257);
        let mut map = vec![ChunkRef::Hole; chunk_count as usize];
        for entry in &manifest.chunks {
            let sha256 = format::decode_sha256_hex(entry.object_id.as_str()).unwrap();
            map[entry.chunk_idx as usize] = ChunkRef::Base(BaseRef {
                object_id: entry.object_id.as_str().to_string(),
                len: entry.len,
                sha256,
                image: Some(manifest.image_id.as_str().to_string()),
            });
        }

        let leaf_zero = format::encode_leaf(0, &map[..256]);
        let leaf_one = format::encode_leaf(256, &map[256..]);
        assert_eq!(leaf_zero.len(), 446);
        assert_eq!(leaf_one.len(), 191);
        assert_eq!(
            hex::encode(format::sha256(&leaf_zero)),
            "21853df0366ecb382ed81d8ec0162d84531567a835b9b16438ffddad46f2ff33"
        );
        assert_eq!(
            hex::encode(format::sha256(&leaf_one)),
            "a353861b0cb2e42e281738da932e357017545c3fe4e8c6718239a5de82f07be4"
        );

        let leaves = vec![
            LeafRef::Present {
                hash: format::sha256(&leaf_zero),
                object_id: "21853df0366ecb382ed81d8ec0162d84531567a835b9b16438ffddad46f2ff33.node"
                    .into(),
            },
            LeafRef::Present {
                hash: format::sha256(&leaf_one),
                object_id: "a353861b0cb2e42e281738da932e357017545c3fe4e8c6718239a5de82f07be4.node"
                    .into(),
            },
        ];
        let root = format::encode_root(manifest.size_bytes, &leaves);
        assert_eq!(root.len(), 230);
        let root_hash = hex::encode(format::sha256(&root));
        assert_eq!(
            root_hash,
            "a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753"
        );

        let transition = "13579bdf2468ace013579bdf2468ace0";
        let record = encode_commit_record(transition, 1, 7, &root_hash, &[0, 256]);
        let literal = br#"{"chunks":[0,256],"generation":1,"lease_epoch":7,"root_hash":"a3a4782016a5ec8ef71c9efd06c5e899beeab070982397c294b578fc4e341753","txn":"13579bdf2468ace013579bdf2468ace0"}"#;
        assert_eq!(record.as_slice(), literal);
        assert_eq!(record.len(), 169);
        assert_eq!(
            hex::encode(format::sha256(&record)),
            "b15b76d3cad36765db54f421200124ff27e4ffea8bf7dbd8016743069a593720"
        );
        assert_eq!(
            chunk::keys::commit_record("vol_golden", 1, transition),
            "volumes/vol_golden/commits/1-13579bdf2468ace013579bdf2468ace0.json"
        );
    }
}
