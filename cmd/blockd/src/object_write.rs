//! Selects the object-write publish path for the attachment blockd adopts.
//!
//! Production bare-metal workers are denied direct ChunkStore mutation by IAM
//! (`DenyDirectChunkStoreMutation`), so an attachment that binds an
//! object-write credential may publish only through the ObjectWrite Gateway.
//! This module turns the public [`ObjectWriteCredentialReference`] carried by
//! that attachment into a ready signer and wraps the object store blockd
//! already opened as the Gateway's read delegate. An attachment that binds no
//! credential keeps exactly the store it had before this module existed.
//!
//! Two properties are load bearing:
//!
//! * **Nothing guesses a path.** The registered artifact is located by the
//!   credential ID the attachment names, and the private key is located by a
//!   `private_artifact_id` this module *re-derives* from the artifact's own
//!   session scope with the frozen contract helpers. A tampered artifact
//!   therefore cannot steer the private-key read at another file.
//! * **The private key never escapes.** It is read into one bounded buffer,
//!   handed to [`Ed25519RequestSigner`] (whose `Debug` is redacted) and then
//!   zeroed. It reaches no log line, no error message, no argv entry and no
//!   environment variable; every refusal below quotes only public identifiers
//!   and the exact check that failed.
//!
//! This module deliberately takes no lock on the credential namespace. The
//! Node publishes both files by rename, so a reader cannot observe a torn one,
//! and every refusal here is fail-closed: a credential blockd cannot load is a
//! refusal to start, never a fallback to a direct write.

use std::ffi::CString;
use std::fs::File;
use std::io::Read as _;
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use cats_api::agent_registration::Ed25519RequestSigner;
use cats_api::object_write_gateway::{
    decode_object_write_credential_registered_artifact, object_write_credential_id,
    object_write_private_artifact_id, object_write_private_key_file_name,
    object_write_registered_artifact_file_name, ObjectWriteCredentialReference,
    OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME, OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES,
};
use cats_object_store_gateway::ObjectWriteGatewayBlobStore;
use cats_storage::authority::AuthorizedServingAttachment;
use cats_storage::blob::BlobStore;

use crate::{effective_uid, open_at};

/// A PKCS#8 v2 Ed25519 PEM is roughly 120 bytes. Anything near this bound is
/// not a key the Node wrote, so the read is bounded rather than trusting the
/// file's own length.
const PRIVATE_KEY_MAX_BYTES: usize = 4 * 1024;

/// The exact mode the Node publishes both credential files with.
const CREDENTIAL_FILE_MODE: u32 = 0o600;

/// The Gateway-backed store for `attachment`, or `None` when the attachment
/// binds no object-write credential and publishing is unchanged.
///
/// `reads` is the object store blockd opened from its own adapter flags; the
/// Gateway serves every non-mutating method from it unchanged.
pub(crate) fn gateway_publish_store(
    gateway_url: Option<&str>,
    credential_directory: Option<&Path>,
    attachment: &AuthorizedServingAttachment,
    reads: &Arc<dyn BlobStore>,
) -> Result<Option<ObjectWriteGatewayBlobStore>> {
    let Some(reference) = attachment.object_write_credential.as_ref() else {
        return Ok(None);
    };
    let attachment_id = &attachment.identity.attachment_id;
    let credential_id = &reference.credential_id;
    let gateway_url = gateway_url.with_context(|| {
        format!(
            "attachment {attachment_id} binds object-write credential {credential_id}, so \
             --object-write-gateway-url is required: this worker may not mutate the ChunkStore \
             directly"
        )
    })?;
    let directory = credential_directory.with_context(|| {
        format!(
            "attachment {attachment_id} binds object-write credential {credential_id}, so \
             --object-write-credential-directory is required to load its attachment-scoped \
             signing key"
        )
    })?;
    let signer = load_attachment_signer(directory, attachment, reference)?;
    let store = ObjectWriteGatewayBlobStore::new(
        gateway_url,
        attachment.identity.volume_id.clone(),
        signer,
        Arc::clone(reads),
    )
    .with_context(|| {
        format!("bind object-write credential {credential_id} to the ObjectWrite Gateway")
    })?;
    tracing::info!(
        volume = %attachment.identity.volume_id,
        attachment = %attachment_id,
        credential = %credential_id,
        "publishing immutable objects through the ObjectWrite Gateway"
    );
    Ok(Some(store))
}

/// Recovers the attachment-scoped signer for exactly the credential the
/// attachment names, or reports the first check that failed.
fn load_attachment_signer(
    directory_path: &Path,
    attachment: &AuthorizedServingAttachment,
    reference: &ObjectWriteCredentialReference,
) -> Result<Ed25519RequestSigner> {
    let directory = open_credential_directory(directory_path)?;

    let artifact_file = object_write_registered_artifact_file_name(&reference.credential_id);
    let artifact_path = directory_path.join(&artifact_file);
    let artifact_bytes = read_credential_file(
        &directory,
        &artifact_path,
        &artifact_file,
        OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES,
        "registered object-write credential artifact",
    )?
    .with_context(|| {
        format!(
            "registered object-write credential artifact {} is absent for credential {}",
            artifact_path.display(),
            reference.credential_id
        )
    })?;
    let artifact =
        decode_object_write_credential_registered_artifact(&artifact_bytes).map_err(|_| {
            anyhow::anyhow!(
                "registered object-write credential artifact {} is malformed or noncanonical",
                artifact_path.display()
            )
        })?;
    let registration = &artifact.registration;

    if registration.credential.credential_id != reference.credential_id {
        bail!(
            "registered object-write credential artifact {} names credential {}, not the {} bound \
             to this attachment",
            artifact_path.display(),
            registration.credential.credential_id,
            reference.credential_id
        );
    }
    if registration.credential.public_key_spki_sha256 != reference.public_key_spki_sha256 {
        bail!(
            "registered object-write credential artifact {} publishes public key {}, not the {} \
             bound to this attachment",
            artifact_path.display(),
            registration.credential.public_key_spki_sha256,
            reference.public_key_spki_sha256
        );
    }
    let identity = &attachment.identity;
    if registration.volume_id != identity.volume_id
        || registration.attachment_id != identity.attachment_id
        || registration.attachment_epoch != identity.attachment_epoch
    {
        bail!(
            "registered object-write credential artifact {} is scoped to volume {} attachment {} \
             epoch {}, not this attachment's volume {} attachment {} epoch {}",
            artifact_path.display(),
            registration.volume_id,
            registration.attachment_id,
            registration.attachment_epoch.get(),
            identity.volume_id,
            identity.attachment_id,
            identity.attachment_epoch.get()
        );
    }

    // Re-derive both identifiers from the artifact's own session scope. The
    // private key file name below comes from the derived value, so a tampered
    // artifact can only fail this check, never redirect the read.
    let derived_credential_id = object_write_credential_id(
        &registration.session,
        &registration.volume_id,
        &registration.attachment_id,
        registration.attachment_epoch,
    );
    let private_artifact_id = object_write_private_artifact_id(
        &registration.session,
        &registration.volume_id,
        &registration.attachment_id,
        registration.attachment_epoch,
    );
    if derived_credential_id != registration.credential.credential_id
        || private_artifact_id != registration.private_artifact_id
    {
        bail!(
            "registered object-write credential artifact {} claims identifiers its own session \
             scope does not derive",
            artifact_path.display()
        );
    }

    let key_file = object_write_private_key_file_name(&private_artifact_id);
    let key_path = directory_path.join(&key_file);
    let mut pem = read_credential_file(
        &directory,
        &key_path,
        &key_file,
        PRIVATE_KEY_MAX_BYTES,
        "object-write private key",
    )?
    .with_context(|| {
        format!(
            "object-write private key {} is absent for credential {}",
            key_path.display(),
            reference.credential_id
        )
    })?;
    let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(reference.credential_id.clone(), &pem);
    pem.fill(0);
    // The parse error is deliberately dropped rather than chained: no failure
    // detail about key material may reach an operator's terminal or log.
    let signer = signer.map_err(|_| {
        anyhow::anyhow!(
            "object-write private key {} is not a canonical PKCS#8 v2 Ed25519 key",
            key_path.display()
        )
    })?;
    if signer.public_key_spki_sha256() != reference.public_key_spki_sha256 {
        bail!(
            "object-write private key {} does not match the public key registered for credential \
             {}",
            key_path.display(),
            reference.credential_id
        );
    }
    Ok(signer)
}

/// Opens the Node's `object-write-credentials` namespace itself, not a parent
/// of it: the flag names the exact contract directory so a misconfigured
/// deployment cannot point blockd at an arbitrary readable tree.
fn open_credential_directory(path: &Path) -> Result<File> {
    if !path.is_absolute() {
        bail!(
            "--object-write-credential-directory {} must be an absolute path",
            path.display()
        );
    }
    if path.file_name().and_then(|name| name.to_str())
        != Some(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME)
    {
        bail!(
            "--object-write-credential-directory {} is not the contract credential namespace; its \
             final component must be {OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME}",
            path.display()
        );
    }
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let directory = options
        .open(path)
        .with_context(|| format!("open object-write credential directory {}", path.display()))?;
    let metadata = directory.metadata().with_context(|| {
        format!(
            "inspect object-write credential directory {}",
            path.display()
        )
    })?;
    if !metadata.file_type().is_dir() {
        bail!(
            "object-write credential directory {} is not a directory",
            path.display()
        );
    }
    if metadata.uid() != effective_uid() {
        bail!(
            "object-write credential directory {} is owned by another user",
            path.display()
        );
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        bail!(
            "object-write credential directory {} is group or world accessible (mode {mode:04o})",
            path.display()
        );
    }
    Ok(directory)
}

/// Reads one bounded root-only credential file by name relative to the already
/// opened namespace descriptor. `Ok(None)` means the file is absent; every
/// other unsafe property is a refusal naming the exact check.
fn read_credential_file(
    directory: &File,
    path: &Path,
    name: &str,
    maximum: usize,
    label: &str,
) -> Result<Option<Vec<u8>>> {
    let component = CString::new(name).with_context(|| format!("{label} basename contains NUL"))?;
    let mut file = match open_at(
        directory,
        &component,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
    ) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| format!("open {label} {}", path.display()))
        }
    };
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label} {}", path.display()))?;
    if !metadata.file_type().is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    if metadata.nlink() != 1 {
        bail!("{label} {} is hard-linked", path.display());
    }
    if metadata.uid() != effective_uid() {
        bail!("{label} {} is owned by another user", path.display());
    }
    let mode = metadata.mode() & 0o7777;
    if mode & 0o077 != 0 {
        bail!(
            "{label} {} is group or world accessible (mode {mode:04o})",
            path.display()
        );
    }
    if mode != CREDENTIAL_FILE_MODE {
        bail!(
            "{label} {} is not root-only 0600 (mode {mode:04o})",
            path.display()
        );
    }
    if metadata.len() > maximum as u64 {
        bail!("{label} {} exceeds {maximum} bytes", path.display());
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.by_ref()
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label} {}", path.display()))?;
    if bytes.len() > maximum {
        bail!("{label} {} exceeds {maximum} bytes", path.display());
    }
    Ok(Some(bytes))
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;
    use std::path::PathBuf;

    use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
    use base64::Engine as _;
    use cats_api::object_write_gateway::{
        encode_object_write_credential_registered_artifact,
        object_write_private_directory_fsync_receipt_id,
        object_write_private_file_fsync_receipt_id, ObjectWriteCredentialRegisteredArtifact,
        ObjectWriteCredentialRegistration, ObjectWriteCredentialRegistrationReceipt,
    };
    use cats_api::runtime_reconciliation::{
        canonical_ed25519_spki_sha256, AcquireOrigin, Base64UrlNoPad, ContractVersion, Epoch,
        FenceEpoch, Generation, Id, NodeBootId, NormalAcquireRequest, NormalAcquireResult,
        RandomId128, RemoteHead, Revision, SessionBinding, Sha256Digest, UnixMillis,
    };
    use cats_object_store_file::FileBlobStoreFactory;
    use cats_storage::authority::{
        AttachmentLineageIdentity, AuthorizedServingAcquire, VolumeDurability,
    };
    use cats_storage::{open_blob_store, AdapterConfig, BlobStoreFactory};
    use ring::signature::{Ed25519KeyPair, KeyPair as _};

    use super::*;

    const GATEWAY_URL: &str = "https://object-write-gateway.invalid:8443";
    const VOLUME_ID: &str = "vol_owgateway";
    const ATTACHMENT_ID: &str = "att_owgateway";
    const ATTACHMENT_EPOCH: u64 = 9;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn session() -> SessionBinding {
        SessionBinding {
            node_id: id("node_owgateway"),
            node_boot_id: NodeBootId::new("1".repeat(32)).unwrap(),
            agent_instance_id: RandomId128::new("2".repeat(32)).unwrap(),
            agent_session_epoch: Epoch::new(4).unwrap(),
        }
    }

    /// One real Ed25519 key in exactly the canonical PKCS#8 v2 PEM the Node
    /// writes, with the public half in the contract's SPKI encoding.
    struct GeneratedKey {
        pem: Vec<u8>,
        spki: Base64UrlNoPad,
    }

    impl GeneratedKey {
        fn digest(&self) -> Sha256Digest {
            canonical_ed25519_spki_sha256(&self.spki).expect("canonical Ed25519 SPKI")
        }
    }

    fn generate_key() -> GeneratedKey {
        let document = Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new()).unwrap();
        let encoded = STANDARD.encode(document.as_ref());
        let mut pem = Vec::with_capacity(encoded.len() + 80);
        pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
        for chunk in encoded.as_bytes().chunks(64) {
            pem.extend_from_slice(chunk);
            pem.push(b'\n');
        }
        pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
        let pair = Ed25519KeyPair::from_pkcs8(document.as_ref()).unwrap();
        let mut spki_der = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki_der.extend_from_slice(pair.public_key().as_ref());
        GeneratedKey {
            pem,
            spki: Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(&spki_der)).unwrap(),
        }
    }

    struct Fixture {
        _root: tempfile::TempDir,
        directory: PathBuf,
        attachment: AuthorizedServingAttachment,
        registration: ObjectWriteCredentialRegistration,
        reads: Arc<dyn BlobStore>,
    }

    impl Fixture {
        fn key_path(&self) -> PathBuf {
            self.directory.join(object_write_private_key_file_name(
                &self.registration.private_artifact_id,
            ))
        }

        fn artifact_path(&self) -> PathBuf {
            self.directory
                .join(object_write_registered_artifact_file_name(
                    &self.registration.credential.credential_id,
                ))
        }

        fn write_artifact(&self, registration: ObjectWriteCredentialRegistration) {
            let artifact = registered_artifact(registration);
            let path = self
                .directory
                .join(object_write_registered_artifact_file_name(
                    &artifact.registration.credential.credential_id,
                ));
            write_private(
                &path,
                &encode_object_write_credential_registered_artifact(&artifact).unwrap(),
            );
        }

        fn resolve(&self) -> Result<Option<ObjectWriteGatewayBlobStore>> {
            gateway_publish_store(
                Some(GATEWAY_URL),
                Some(self.directory.as_path()),
                &self.attachment,
                &self.reads,
            )
        }
    }

    fn write_private(path: &Path, bytes: &[u8]) {
        std::fs::write(path, bytes).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn registered_artifact(
        registration: ObjectWriteCredentialRegistration,
    ) -> ObjectWriteCredentialRegisteredArtifact {
        let receipt = ObjectWriteCredentialRegistrationReceipt {
            version: ContractVersion::V1,
            writer_authority_id: registration.writer_authority_id.clone(),
            volume_id: registration.volume_id.clone(),
            attachment_id: registration.attachment_id.clone(),
            attachment_epoch: registration.attachment_epoch,
            credential: registration.credential.clone(),
            registered_at_unix_ms: UnixMillis::new(1_900_000_000_000).unwrap(),
        };
        ObjectWriteCredentialRegisteredArtifact {
            version: ContractVersion::V1,
            registration,
            receipt,
        }
    }

    fn attachment_with(
        credential: Option<ObjectWriteCredentialReference>,
    ) -> AuthorizedServingAttachment {
        let transition = RandomId128::new("3".repeat(32)).unwrap();
        let head = RemoteHead {
            generation: Generation::new(0).unwrap(),
            root_hash: None,
            root_object_id: None,
        };
        let request = NormalAcquireRequest {
            volume_id: id(VOLUME_ID),
            transition_id: transition.clone(),
            attachment_id: id(ATTACHMENT_ID),
            expected_unowned_epoch: FenceEpoch::new(ATTACHMENT_EPOCH - 1).unwrap(),
            desired_revision: Revision::new(5).unwrap(),
            placement_epoch: Epoch::new(2).unwrap(),
            lease_duration_ms: 5_000,
        };
        let result = NormalAcquireResult {
            volume_id: request.volume_id.clone(),
            transition_id: transition.clone(),
            attachment_id: request.attachment_id.clone(),
            resulting_epoch: FenceEpoch::new(ATTACHMENT_EPOCH).unwrap(),
            resulting_head: head.clone(),
            lease_expires_at: UnixMillis::new(1_900_000_005_000).unwrap(),
        };
        AuthorizedServingAttachment {
            identity: AttachmentLineageIdentity {
                volume_id: request.volume_id.clone(),
                attachment_id: request.attachment_id.clone(),
                attachment_epoch: result.resulting_epoch,
                acquire_origin: AcquireOrigin::Normal {
                    transition_id: transition,
                },
                node_id: id("node_owgateway"),
                placement_epoch: request.placement_epoch,
            },
            object_write_credential: credential,
            size_bytes: 4 * 1024 * 1024,
            durability: VolumeDurability::Strict,
            head,
            lease_expires_at: result.lease_expires_at,
            acquire: AuthorizedServingAcquire::Normal { request, result },
        }
    }

    /// One registered credential exactly as the Node publishes it: a 0700
    /// `object-write-credentials` namespace holding the 0600 registered
    /// artifact and the 0600 private key.
    fn fixture() -> Fixture {
        let root = tempfile::tempdir().unwrap();
        let state = root.path().canonicalize().unwrap();
        let directory = state.join(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME);
        std::fs::create_dir(&directory).unwrap();
        std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();

        let session = session();
        let volume_id = id(VOLUME_ID);
        let attachment_id = id(ATTACHMENT_ID);
        let attachment_epoch = FenceEpoch::new(ATTACHMENT_EPOCH).unwrap();
        let key = generate_key();
        let credential = ObjectWriteCredentialReference {
            credential_id: object_write_credential_id(
                &session,
                &volume_id,
                &attachment_id,
                attachment_epoch,
            ),
            public_key_spki_sha256: key.digest(),
        };
        let private_artifact_id = object_write_private_artifact_id(
            &session,
            &volume_id,
            &attachment_id,
            attachment_epoch,
        );
        let file_receipt =
            object_write_private_file_fsync_receipt_id(&private_artifact_id, &credential);
        let registration = ObjectWriteCredentialRegistration {
            version: ContractVersion::V1,
            session,
            writer_authority_id: id("writer_owgateway"),
            volume_id,
            attachment_id,
            attachment_epoch,
            credential: credential.clone(),
            public_key_spki: key.spki.clone(),
            private_artifact_id: private_artifact_id.clone(),
            private_directory_fsync_receipt_id: object_write_private_directory_fsync_receipt_id(
                &private_artifact_id,
                &file_receipt,
            ),
            private_file_fsync_receipt_id: file_receipt,
        };

        write_private(
            &directory.join(object_write_private_key_file_name(&private_artifact_id)),
            &key.pem,
        );
        write_private(
            &directory.join(object_write_registered_artifact_file_name(
                &credential.credential_id,
            )),
            &encode_object_write_credential_registered_artifact(&registered_artifact(
                registration.clone(),
            ))
            .unwrap(),
        );

        let object_root = state.join("objects");
        std::fs::create_dir(&object_root).unwrap();
        let config =
            AdapterConfig::from_cli(vec![format!("root={}", object_root.display())]).unwrap();
        let factories: [&dyn BlobStoreFactory; 1] = [&FileBlobStoreFactory];
        let reads = open_blob_store("file", &config, &factories).unwrap();

        Fixture {
            _root: root,
            directory,
            attachment: attachment_with(Some(credential)),
            registration,
            reads,
        }
    }

    fn refusal(result: Result<Option<ObjectWriteGatewayBlobStore>>) -> String {
        match result {
            Ok(Some(_)) => panic!("a Gateway store was built where the input had to be refused"),
            Ok(None) => {
                panic!("the direct object store was kept where the input had to be refused")
            }
            Err(error) => format!("{error:#}"),
        }
    }

    /// Proves the wiring this change exists for: a credential-bearing
    /// attachment publishes through the Gateway, bound to exactly the
    /// credential the attachment names and to the volume it serves.
    #[test]
    fn a_credential_bearing_attachment_selects_the_gateway_store() {
        let fixture = fixture();
        let store = fixture.resolve().unwrap().expect("Gateway store");
        let rendered = format!("{store:?}");
        assert!(
            rendered.contains("ObjectWriteGatewayBlobStore"),
            "unexpected store: {rendered}"
        );
        assert!(
            rendered.contains(GATEWAY_URL),
            "store is not bound to the requested gateway: {rendered}"
        );
        assert!(
            rendered.contains(VOLUME_ID),
            "store is not bound to the served volume: {rendered}"
        );
        assert!(
            rendered.contains(
                fixture
                    .attachment
                    .object_write_credential
                    .as_ref()
                    .unwrap()
                    .credential_id
                    .as_str()
            ),
            "store is not bound to the attachment credential: {rendered}"
        );
    }

    /// The private key must not be recoverable from anything the process can
    /// print. `Debug` is the widest surface the store has.
    #[test]
    fn the_gateway_store_never_renders_private_key_material() {
        let fixture = fixture();
        let pem = std::fs::read(fixture.key_path()).unwrap();
        let body: String = String::from_utf8(pem)
            .unwrap()
            .lines()
            .filter(|line| !line.starts_with("-----"))
            .collect();
        let store = fixture.resolve().unwrap().expect("Gateway store");
        let rendered = format!("{store:?}");
        assert!(!rendered.contains("PRIVATE KEY"), "{rendered}");
        assert!(!rendered.contains(&body), "{rendered}");
        assert!(
            !rendered.contains(&body[..32]),
            "a private key prefix reached Debug: {rendered}"
        );
    }

    /// The no-credential path is unchanged: blockd keeps the object store it
    /// opened, even when both Gateway flags happen to be present.
    #[test]
    fn an_attachment_without_a_credential_keeps_the_direct_object_store() {
        let fixture = fixture();
        let attachment = attachment_with(None);
        assert!(gateway_publish_store(
            Some(GATEWAY_URL),
            Some(fixture.directory.as_path()),
            &attachment,
            &fixture.reads,
        )
        .unwrap()
        .is_none());
        assert!(
            gateway_publish_store(None, None, &attachment, &fixture.reads)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn a_missing_gateway_url_refuses_a_credential_bearing_attachment() {
        let fixture = fixture();
        let message = refusal(gateway_publish_store(
            None,
            Some(fixture.directory.as_path()),
            &fixture.attachment,
            &fixture.reads,
        ));
        assert!(
            message.contains("--object-write-gateway-url is required"),
            "{message}"
        );
    }

    #[test]
    fn a_missing_credential_directory_refuses_a_credential_bearing_attachment() {
        let fixture = fixture();
        let message = refusal(gateway_publish_store(
            Some(GATEWAY_URL),
            None,
            &fixture.attachment,
            &fixture.reads,
        ));
        assert!(
            message.contains("--object-write-credential-directory is required"),
            "{message}"
        );
    }

    /// The attachment names a public key the registered artifact does not
    /// publish: the credential on disk is not the one authority bound.
    #[test]
    fn a_mismatched_credential_reference_refuses() {
        let mut fixture = fixture();
        fixture
            .attachment
            .object_write_credential
            .as_mut()
            .unwrap()
            .public_key_spki_sha256 = Sha256Digest::from_bytes([0x5c; 32]);
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("publishes public key")
                && message.contains("bound to this attachment"),
            "{message}"
        );
    }

    /// A credential ID with no artifact of its own must refuse rather than
    /// fall back to any other credential present in the namespace.
    #[test]
    fn a_credential_reference_with_no_registered_artifact_refuses() {
        let mut fixture = fixture();
        fixture
            .attachment
            .object_write_credential
            .as_mut()
            .unwrap()
            .credential_id = id("owcred1_absent");
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("registered object-write credential artifact")
                && message.contains("is absent"),
            "{message}"
        );
    }

    #[test]
    fn a_group_readable_private_key_refuses() {
        let fixture = fixture();
        std::fs::set_permissions(fixture.key_path(), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("object-write private key")
                && message.contains("group or world accessible"),
            "{message}"
        );
    }

    #[test]
    fn an_absent_private_key_refuses() {
        let fixture = fixture();
        std::fs::remove_file(fixture.key_path()).unwrap();
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("object-write private key") && message.contains("is absent"),
            "{message}"
        );
    }

    /// `O_NOFOLLOW`: a key replaced by a symlink is never read through.
    #[test]
    fn a_symlinked_private_key_refuses() {
        let fixture = fixture();
        let key_path = fixture.key_path();
        let elsewhere = fixture.directory.parent().unwrap().join("stolen.pk8");
        std::fs::rename(&key_path, &elsewhere).unwrap();
        std::os::unix::fs::symlink(&elsewhere, &key_path).unwrap();
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("open object-write private key"),
            "{message}"
        );
    }

    /// The registered public half and the local private half must be the same
    /// keypair; otherwise every signature would be refused by the gateway.
    #[test]
    fn a_private_key_that_does_not_match_the_registration_refuses() {
        let fixture = fixture();
        write_private(&fixture.key_path(), &generate_key().pem);
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("does not match the public key registered for credential"),
            "{message}"
        );
    }

    #[test]
    fn a_malformed_private_key_refuses() {
        let fixture = fixture();
        write_private(&fixture.key_path(), b"-----BEGIN PRIVATE KEY-----\n");
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("is not a canonical PKCS#8 v2 Ed25519 key"),
            "{message}"
        );
    }

    /// A credential minted for another attachment epoch cannot serve this one.
    #[test]
    fn an_artifact_scoped_to_another_attachment_refuses() {
        let mut fixture = fixture();
        fixture.attachment.identity.attachment_epoch =
            FenceEpoch::new(ATTACHMENT_EPOCH + 1).unwrap();
        let message = refusal(fixture.resolve());
        assert!(message.contains("is scoped to volume"), "{message}");
    }

    /// The private key file name is re-derived, so a tampered sidecar cannot
    /// steer the read at another artifact's key.
    #[test]
    fn an_artifact_claiming_underived_identifiers_refuses() {
        let fixture = fixture();
        let mut registration = fixture.registration.clone();
        let victim = object_write_private_artifact_id(
            &registration.session,
            &registration.volume_id,
            &registration.attachment_id,
            FenceEpoch::new(ATTACHMENT_EPOCH + 3).unwrap(),
        );
        registration.private_artifact_id = victim;
        fixture.write_artifact(registration);
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("claims identifiers its own session scope does not derive"),
            "{message}"
        );
    }

    #[test]
    fn a_malformed_registered_artifact_refuses() {
        let fixture = fixture();
        write_private(&fixture.artifact_path(), b"{\"version\":\"v1\"}");
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("is malformed or noncanonical"),
            "{message}"
        );
    }

    /// The flag names the contract namespace itself, so pointing it one level
    /// up is a refusal rather than a silent search.
    #[test]
    fn a_directory_outside_the_contract_namespace_refuses() {
        let fixture = fixture();
        let parent = fixture.directory.parent().unwrap().to_path_buf();
        let message = refusal(gateway_publish_store(
            Some(GATEWAY_URL),
            Some(parent.as_path()),
            &fixture.attachment,
            &fixture.reads,
        ));
        assert!(
            message.contains("is not the contract credential namespace"),
            "{message}"
        );
    }

    #[test]
    fn a_relative_credential_directory_refuses() {
        let fixture = fixture();
        let message = refusal(gateway_publish_store(
            Some(GATEWAY_URL),
            Some(Path::new("object-write-credentials")),
            &fixture.attachment,
            &fixture.reads,
        ));
        assert!(message.contains("must be an absolute path"), "{message}");
    }

    #[test]
    fn a_group_accessible_credential_directory_refuses() {
        let fixture = fixture();
        std::fs::set_permissions(&fixture.directory, std::fs::Permissions::from_mode(0o750))
            .unwrap();
        let message = refusal(fixture.resolve());
        assert!(
            message.contains("object-write credential directory")
                && message.contains("group or world accessible"),
            "{message}"
        );
    }

    /// An origin the adapter refuses must fail startup, not silently publish
    /// volume bytes in the clear.
    #[test]
    fn a_plaintext_non_loopback_gateway_origin_refuses() {
        let fixture = fixture();
        let message = refusal(gateway_publish_store(
            Some("http://object-write-gateway.invalid"),
            Some(fixture.directory.as_path()),
            &fixture.attachment,
            &fixture.reads,
        ));
        assert!(
            message.contains("bind object-write credential"),
            "{message}"
        );
        assert!(message.contains("loopback"), "{message}");
    }
}
