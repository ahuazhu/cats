//! Node-owned lifecycle of one attachment-scoped object-write credential.
//!
//! The Node mints one Ed25519 keypair per `(volume, attachment, attachment
//! epoch)`, persists it durably before anything can register it, registers only
//! the public half against Control with its A19 key, and finally publishes the
//! returned public artifact. Loading that credential later returns a signer and
//! the public [`ObjectWriteCredentialReference`]; retiring it destroys the
//! private half.
//!
//! Three properties are load bearing:
//!
//! * The private key never leaves this module. It is written to one root-only
//!   `0600` file, read back into an [`Ed25519RequestSigner`] whose `Debug` is
//!   redacted, and never placed in an error, log or wire field.
//! * Every identifier that selects a file is *derived* from the exact scope by
//!   the frozen contract helpers. A tampered sidecar can therefore never steer
//!   a read or an unlink at another path.
//! * Each step is idempotent and its predecessor is durable before it starts,
//!   so a crash between any two steps converges on the next attempt. The
//!   credential ID is scope derived and a private key is never regenerated
//!   while one already exists, so a retry re-registers the *same* public key
//!   rather than minting a second live credential for the same epoch.
//!
//! Deliberately not wired into the attachment lifecycle yet: this module owns
//! the credential, not the decision to create or retire one.

// Scoped to this module for exactly as long as the attachment lifecycle has not
// called into it. Every item below is exercised by this module's tests; drop
// this attribute in the change that makes the reconciler establish, load and
// retire these credentials, so an item that is genuinely unreachable then still
// gets reported.
#![allow(dead_code)]

use std::ffi::{CStr, CString};
use std::fs::{DirBuilder, File, OpenOptions};
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::fs::{
    DirBuilderExt as _, MetadataExt as _, OpenOptionsExt as _, PermissionsExt,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine as _;
use cats_api::agent_registration::{
    Ed25519RequestSigner, NODE_CREDENTIAL_ID_HEADER, NODE_PUBLIC_KEY_SPKI_HEADER,
    NODE_SIGNATURE_HEADER,
};
use cats_api::object_write_gateway::{
    decode_object_write_credential_registered_artifact,
    decode_object_write_credential_registration,
    decode_object_write_credential_registration_receipt, decode_object_write_writer_authority_view,
    encode_object_write_credential_registered_artifact, encode_object_write_writer_authority_read,
    object_write_credential_id, object_write_prepared_registration_file_name,
    object_write_private_artifact_id, object_write_private_directory_fsync_receipt_id,
    object_write_private_file_fsync_receipt_id, object_write_private_key_file_name,
    object_write_registered_artifact_file_name, sign_object_write_credential_registration,
    ObjectWriteCredentialReference, ObjectWriteCredentialRegisteredArtifact,
    ObjectWriteCredentialRegistration, ObjectWriteCredentialRegistrationProof,
    ObjectWriteCredentialRegistrationReceipt, ObjectWriteWriterAuthorityRead,
    ObjectWriteWriterAuthorityStateV1, OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME,
    OBJECT_WRITE_CREDENTIAL_ID_HEADER, OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
    OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH, OBJECT_WRITE_GATEWAY_METHOD,
    OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER, OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES,
    OBJECT_WRITE_SIGNATURE_HEADER, OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
    OBJECT_WRITE_WRITER_AUTHORITY_VIEW_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    Base64UrlNoPad, ContractVersion, FenceEpoch, Id, SessionBinding,
};
use ring::rand::SystemRandom;
use ring::signature::Ed25519KeyPair;
use thiserror::Error;

/// Control caps one registration request at 16 KiB; the canonical body is far
/// smaller, so a larger prepared sidecar is corruption rather than growth.
const PREPARED_REGISTRATION_MAX_BYTES: usize = 16 * 1024;
/// A PKCS#8 v2 Ed25519 PEM is ~120 bytes. Anything near this bound is not a
/// key this module wrote.
const PRIVATE_KEY_MAX_BYTES: usize = 4 * 1024;
/// Only the process that owns the Node state directory may hold this material.
const PRIVATE_FILE_MODE: u32 = 0o600;
const CREDENTIAL_DIRECTORY_MODE: u32 = 0o700;
/// The gateway contract fixes one method for both of its routes; the registrar
/// below hard-codes `post`, so a contract change must break the build here.
const _: () = assert!(matches!(OBJECT_WRITE_GATEWAY_METHOD.as_bytes(), b"POST"));

/// The exact attachment epoch one credential belongs to.
///
/// `session` is part of the credential identity: Control accepts a registration
/// only while that Agent session is current, and a new session therefore mints
/// a different credential rather than reusing an inherited key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ObjectWriteCredentialScope {
    pub(crate) session: SessionBinding,
    pub(crate) writer_authority_id: Id,
    pub(crate) volume_id: Id,
    pub(crate) attachment_id: Id,
    pub(crate) attachment_epoch: FenceEpoch,
}

/// A credential whose private half is present locally and whose public half
/// Control has registered.
///
/// This is the value the object-write data path consumes: it can sign, and it
/// carries the only credential material a descriptor may quote.
#[derive(Debug, Clone)]
pub(crate) struct LoadedObjectWriteCredential {
    signer: Ed25519RequestSigner,
    artifact: ObjectWriteCredentialRegisteredArtifact,
}

impl LoadedObjectWriteCredential {
    /// Signs object-write requests with the attachment-scoped private key.
    pub(crate) fn signer(&self) -> &Ed25519RequestSigner {
        &self.signer
    }

    /// The only credential material allowed in a descriptor or checkpoint.
    pub(crate) fn credential(&self) -> &ObjectWriteCredentialReference {
        &self.artifact.registration.credential
    }

    /// The registered public artifact, including Control's receipt.
    pub(crate) fn registered_artifact(&self) -> &ObjectWriteCredentialRegisteredArtifact {
        &self.artifact
    }
}

#[derive(Debug, Error)]
pub(crate) enum ObjectWriteCredentialError {
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe object-write credential entry at {path}: {reason}")]
    UnsafeEntry { path: PathBuf, reason: &'static str },
    #[error("another object-write credential writer already owns {path}")]
    WriterAlreadyActive { path: PathBuf },
    #[error("object-write credential state at {path} is corrupt: {reason}")]
    Corrupt { path: PathBuf, reason: &'static str },
    #[error("no registered object-write credential for this attachment epoch")]
    NotRegistered,
    #[error("object-write credential registration was rejected: {0}")]
    Rejected(String),
    #[error("object-write credential registration outcome is unknown: {0}")]
    RegistrationAmbiguous(String),
    #[error("generate object-write attachment key")]
    KeyGeneration,
    #[error(
        "Control reports no object-write writer authority for this Node; an operator must run \
         `cats admin runtime-node object-write-authority provision` for this Host"
    )]
    WriterAuthorityAbsent,
    #[error(
        "the Node's object-write writer authority is {state}, so no attachment credential may be \
         registered under it"
    )]
    WriterAuthorityClosed { state: &'static str },
    #[error("the object-write writer authority read did not settle: {0}")]
    WriterAuthorityUnresolved(ObjectWriteWriterAuthorityReadFailure),
    #[cfg(test)]
    #[error("injected object-write credential crash")]
    InjectedCrash,
}

/// Why one writer-authority read did not produce an answer.
///
/// Every variant fails the credential path closed. None of them may be
/// substituted with a configured, cached-from-another-session or locally
/// derived authority ID: the Node has no authority to name one, and Control's
/// derivation is the only source.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ObjectWriteWriterAuthorityReadFailure {
    #[error("object-write writer authority read timed out")]
    Timeout,
    #[error("object-write writer authority read transport failed")]
    Connection,
    #[error("Control closed the object-write writer authority read with status {status}")]
    Closed { status: u16 },
    #[error("Control returned a malformed object-write writer authority view")]
    MalformedResponse,
    #[error("Control answered an object-write writer authority read for another session")]
    SessionMismatch,
}

/// The one Control read that tells this Node which writer authority its
/// attachment credentials belong to.
///
/// A trait keeps the once-per-session resolution testable without a Control
/// Plane; production uses the A19-signed HTTP reader below. Both
/// implementations are real; neither is a stub for the other.
pub(crate) trait ObjectWriteWriterAuthorityResolver: Send + Sync {
    fn read(
        &self,
        session: &SessionBinding,
        deadline: Instant,
    ) -> Result<ObjectWriteWriterAuthorityStateV1, ObjectWriteWriterAuthorityReadFailure>;
}

/// Why one registration attempt did not return a receipt.
///
/// `Timeout` and `Connection` are ambiguous: Control may already hold the
/// credential. Callers must retry the byte-identical body rather than mint a
/// second key, which is why this module never discards local state for them.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ObjectWriteCredentialRegistrationFailure {
    #[error("object-write credential registration timed out")]
    Timeout,
    #[error("object-write credential registration transport failed")]
    Connection,
    #[error("Control closed object-write credential registration with status {status}")]
    Closed { status: u16 },
    #[error("Control returned a malformed object-write credential receipt")]
    MalformedResponse,
}

impl ObjectWriteCredentialRegistrationFailure {
    /// A closed status is a decision; anything else leaves the postcondition
    /// undiscovered and must be retried rather than rolled back.
    fn is_ambiguous(&self) -> bool {
        match self {
            Self::Timeout | Self::Connection | Self::MalformedResponse => true,
            Self::Closed { .. } => false,
        }
    }
}

/// The single Control call this module performs.
///
/// A trait keeps the credential state machine testable at its crash points
/// without a Control Plane, while production uses the A19-signed HTTP client
/// below. Both implementations are real; neither is a stub for the other.
pub(crate) trait ObjectWriteCredentialRegistrar: Send + Sync {
    fn register(
        &self,
        proof: &ObjectWriteCredentialRegistrationProof,
        deadline: Instant,
    ) -> Result<ObjectWriteCredentialRegistrationReceipt, ObjectWriteCredentialRegistrationFailure>;
}

/// Loads the already-registered credential for one attachment epoch.
///
/// This is the seam the object-write data path consumes. It takes a shared
/// directory lock, so it does not contend with another reader and cannot
/// observe a half-published sidecar; a concurrent mutating operation on the same
/// Node yields [`ObjectWriteCredentialError::WriterAlreadyActive`], which the
/// caller retries. It returns [`ObjectWriteCredentialError::NotRegistered`] when
/// the attachment has no credential, when the credential has been retired, and
/// when only a pre-registration sidecar survived a crash.
pub(crate) fn load(
    state_directory: &Path,
    volume_id: &Id,
    attachment_id: &Id,
    attachment_epoch: FenceEpoch,
) -> Result<LoadedObjectWriteCredential, ObjectWriteCredentialError> {
    ObjectWriteCredentialStore::open_shared(state_directory)?.load(
        volume_id,
        attachment_id,
        attachment_epoch,
    )
}

/// The `object-write-credentials` namespace under one Node state directory,
/// held with a whole-directory `flock` for the operation's duration.
///
/// The lock is taken on the directory descriptor itself rather than a sidecar
/// lock file so the namespace contains only the three basenames the frozen
/// contract declares. Credential operations happen once per attachment epoch,
/// so serializing the namespace costs nothing and makes "one live credential
/// per attachment epoch" independent of how many workers race.
pub(crate) struct ObjectWriteCredentialStore {
    directory: File,
    directory_path: PathBuf,
    #[cfg(test)]
    faults: std::sync::Mutex<TestFaults>,
}

impl std::fmt::Debug for ObjectWriteCredentialStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectWriteCredentialStore")
            .field("directory_path", &self.directory_path)
            .finish_non_exhaustive()
    }
}

impl Drop for ObjectWriteCredentialStore {
    fn drop(&mut self) {
        loop {
            // SAFETY: `self.directory` owns a live descriptor for the whole
            // call and `flock` retains neither it nor any Rust memory.
            let result = unsafe { libc::flock(self.directory.as_raw_fd(), libc::LOCK_UN) };
            if result == 0 {
                return;
            }
            if io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }
}

impl ObjectWriteCredentialStore {
    /// Opens the namespace for a mutating operation, creating it `0700` when
    /// absent, and excludes every other writer on this Host.
    pub(crate) fn open(state_directory: &Path) -> Result<Self, ObjectWriteCredentialError> {
        Self::open_locked(state_directory, libc::LOCK_EX)
    }

    /// Opens the namespace for reading only.
    fn open_shared(state_directory: &Path) -> Result<Self, ObjectWriteCredentialError> {
        Self::open_locked(state_directory, libc::LOCK_SH)
    }

    fn open_locked(
        state_directory: &Path,
        lock_mode: i32,
    ) -> Result<Self, ObjectWriteCredentialError> {
        let directory_path = state_directory.join(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME);
        let mut builder = DirBuilder::new();
        builder.recursive(true).mode(CREDENTIAL_DIRECTORY_MODE);
        builder.create(&directory_path).map_err(|source| {
            io_error(
                "create object-write credential directory",
                &directory_path,
                source,
            )
        })?;
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let directory = options.open(&directory_path).map_err(|source| {
            map_open_error(
                "open object-write credential directory",
                &directory_path,
                source,
            )
        })?;
        let metadata = directory.metadata().map_err(|source| {
            io_error(
                "inspect object-write credential directory",
                &directory_path,
                source,
            )
        })?;
        if !metadata.is_dir() {
            return Err(ObjectWriteCredentialError::UnsafeEntry {
                path: directory_path,
                reason: "not a directory",
            });
        }
        if metadata.uid() != effective_uid() {
            return Err(ObjectWriteCredentialError::UnsafeEntry {
                path: directory_path,
                reason: "directory is owned by another user",
            });
        }
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(ObjectWriteCredentialError::UnsafeEntry {
                path: directory_path,
                reason: "directory is group or world accessible",
            });
        }
        lock_directory(&directory, lock_mode, &directory_path)?;
        Ok(Self {
            directory,
            directory_path,
            #[cfg(test)]
            faults: std::sync::Mutex::new(TestFaults::default()),
        })
    }

    /// Converges one attachment epoch on exactly one registered credential.
    ///
    /// Ordered so each step's predecessor is already durable:
    ///
    /// 1. return the credential when its registered artifact already exists;
    /// 2. destroy a superseded credential left by an earlier scope at this
    ///    same attachment locator;
    /// 3. reuse the durable private key when one exists, otherwise generate
    ///    and durably publish one;
    /// 4. durably publish the exact canonical registration body;
    /// 5. register that body with Control, replaying it byte for byte after an
    ///    ambiguous attempt so Control's idempotent replay returns the original
    ///    receipt instead of a second credential;
    /// 6. durably publish the registered artifact.
    pub(crate) fn establish(
        &self,
        scope: &ObjectWriteCredentialScope,
        node_signer: &Ed25519RequestSigner,
        registrar: &dyn ObjectWriteCredentialRegistrar,
        deadline: Instant,
    ) -> Result<LoadedObjectWriteCredential, ObjectWriteCredentialError> {
        let names = CredentialNames::derive(
            &scope.session,
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
        )?;

        if let Some(artifact) = self.read_registered_artifact(&names)? {
            let signer = self.require_private_key(&names, &artifact.registration)?;
            // `load` needs the session-independent sidecar to find this
            // credential at all, so a registered artifact whose sidecar was
            // lost or superseded is republished rather than left unloadable.
            if self.read_prepared_registration(&names)?.as_ref() != Some(&artifact.registration) {
                self.publish_prepared_registration(&names, &artifact.registration)?;
            }
            return Ok(LoadedObjectWriteCredential { signer, artifact });
        }

        let prepared = match self.read_prepared_registration(&names)? {
            Some(prepared) if prepared.credential.credential_id == names.credential_id => {
                Some(prepared)
            }
            // A different scope owned this attachment locator. Its private key
            // is unusable for this epoch and must not survive as residue.
            Some(superseded) => {
                self.destroy_superseded(scope, &names, &superseded)?;
                None
            }
            None => None,
        };

        let (signer, registration) = match prepared {
            Some(registration) => {
                let signer = self.require_private_key(&names, &registration)?;
                (signer, registration)
            }
            None => {
                let signer = self.establish_private_key(&names)?;
                self.maybe_crash(EstablishStage::PrivateKeyDurable)?;
                let registration = build_registration(scope, &names, &signer)?;
                self.publish_prepared_registration(&names, &registration)?;
                self.maybe_crash(EstablishStage::PreparedRegistrationDurable)?;
                (signer, registration)
            }
        };

        let proof = sign_object_write_credential_registration(node_signer, &signer, &registration)
            .map_err(|_| ObjectWriteCredentialError::Corrupt {
                path: names.prepared_path(&self.directory_path),
                reason: "prepared registration does not match its private key",
            })?;
        let receipt = registrar
            .register(&proof, deadline)
            .map_err(|failure| self.classify_registration_failure(failure))?;
        self.maybe_crash(EstablishStage::ControlRegistered)?;

        // The frozen artifact validation below cross-checks volume, attachment,
        // epoch and credential but not the writer authority, and that authority
        // is what admits the writes this credential will sign.
        if receipt.writer_authority_id != registration.writer_authority_id {
            return Err(ObjectWriteCredentialError::Rejected(
                "Control receipt names another writer authority".to_owned(),
            ));
        }
        let artifact = ObjectWriteCredentialRegisteredArtifact {
            version: ContractVersion::V1,
            registration,
            receipt,
        };
        // `encode` re-runs the frozen cross-field validation, so a receipt that
        // rebinds the volume, attachment, epoch or credential cannot become a
        // durable artifact.
        let bytes =
            encode_object_write_credential_registered_artifact(&artifact).map_err(|_| {
                ObjectWriteCredentialError::Rejected(
                    "Control receipt does not bind the registered credential".to_owned(),
                )
            })?;
        self.publish(
            &names.registered_temporary_name,
            &names.registered_name,
            &names.registered_path(&self.directory_path),
            &bytes,
        )?;
        Ok(LoadedObjectWriteCredential { signer, artifact })
    }

    /// Loads the registered credential for one attachment epoch.
    ///
    /// The Agent session is recovered from the prepared sidecar, then every
    /// identifier it claims is re-derived and compared, so only a self
    /// consistent triple of files can produce a signer.
    pub(crate) fn load(
        &self,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<LoadedObjectWriteCredential, ObjectWriteCredentialError> {
        let locator = PreparedLocator::derive(volume_id, attachment_id, attachment_epoch)?;
        let Some(prepared) = self.read_prepared_at(&locator)? else {
            return Err(ObjectWriteCredentialError::NotRegistered);
        };
        if prepared.volume_id != *volume_id
            || prepared.attachment_id != *attachment_id
            || prepared.attachment_epoch != attachment_epoch
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: locator.path(&self.directory_path),
                reason: "prepared registration names another attachment",
            });
        }
        let names = CredentialNames::derive(
            &prepared.session,
            volume_id,
            attachment_id,
            attachment_epoch,
        )?;
        if names.credential_id != prepared.credential.credential_id
            || names.private_artifact_id != prepared.private_artifact_id
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: locator.path(&self.directory_path),
                reason: "prepared registration claims underived identifiers",
            });
        }
        let Some(artifact) = self.read_registered_artifact(&names)? else {
            return Err(ObjectWriteCredentialError::NotRegistered);
        };
        if artifact.registration != prepared {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: names.registered_path(&self.directory_path),
                reason: "registered artifact disagrees with its prepared registration",
            });
        }
        let signer = self.load_private_key(&names, &artifact.registration)?;
        Ok(LoadedObjectWriteCredential { signer, artifact })
    }

    /// Retires the credential for one attachment epoch on release or takeover.
    ///
    /// The private key is destroyed first, so any interrupted retirement still
    /// leaves a state in which [`Self::load`] cannot produce a signer. The
    /// public sidecars follow. Retiring an attachment with no credential, or
    /// one already retired, succeeds.
    ///
    /// A corrupt sidecar makes the credential unidentifiable, so retirement
    /// reports that rather than unlinking a file it cannot attribute. That
    /// still denies a signer, because [`Self::load`] rejects the same sidecar.
    pub(crate) fn retire(
        &self,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<(), ObjectWriteCredentialError> {
        let locator = PreparedLocator::derive(volume_id, attachment_id, attachment_epoch)?;
        let Some(prepared) = self.read_prepared_at(&locator)? else {
            return Ok(());
        };
        let names = CredentialNames::derive(
            &prepared.session,
            volume_id,
            attachment_id,
            attachment_epoch,
        )?;
        if names.credential_id != prepared.credential.credential_id
            || names.private_artifact_id != prepared.private_artifact_id
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: locator.path(&self.directory_path),
                reason: "prepared registration claims underived identifiers",
            });
        }
        self.destroy_private_key(&names)?;
        self.maybe_crash(RetireStage::PrivateKeyDestroyed)?;
        self.remove(&locator.name, &locator.path(&self.directory_path))?;
        self.remove(
            &names.registered_name,
            &names.registered_path(&self.directory_path),
        )?;
        Ok(())
    }

    /// Removes an earlier Agent session's credential that still owns this
    /// attachment locator. Same ordering as retirement: private key first.
    ///
    /// Only the Agent session may differ. A sidecar that claims another volume,
    /// attachment or epoch fails closed instead of authorizing this unlink,
    /// because those identifiers select which credential gets destroyed.
    fn destroy_superseded(
        &self,
        scope: &ObjectWriteCredentialScope,
        names: &CredentialNames,
        superseded: &ObjectWriteCredentialRegistration,
    ) -> Result<(), ObjectWriteCredentialError> {
        if superseded.volume_id != scope.volume_id
            || superseded.attachment_id != scope.attachment_id
            || superseded.attachment_epoch != scope.attachment_epoch
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: names.prepared_path(&self.directory_path),
                reason: "superseded registration names another attachment",
            });
        }
        let superseded_names = CredentialNames::derive(
            &superseded.session,
            &superseded.volume_id,
            &superseded.attachment_id,
            superseded.attachment_epoch,
        )?;
        if superseded_names.credential_id != superseded.credential.credential_id
            || superseded_names.private_artifact_id != superseded.private_artifact_id
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: names.prepared_path(&self.directory_path),
                reason: "superseded registration claims underived identifiers",
            });
        }
        self.destroy_private_key(&superseded_names)?;
        self.remove(
            &names.prepared_name,
            &names.prepared_path(&self.directory_path),
        )?;
        self.remove(
            &superseded_names.registered_name,
            &superseded_names.registered_path(&self.directory_path),
        )?;
        Ok(())
    }

    /// Returns the durable private key when one exists, otherwise generates and
    /// publishes one.
    ///
    /// Reusing an existing key is what keeps a crash between the key barrier
    /// and the prepared-registration barrier from minting a second key for a
    /// credential ID Control may already know.
    fn establish_private_key(
        &self,
        names: &CredentialNames,
    ) -> Result<Ed25519RequestSigner, ObjectWriteCredentialError> {
        let private_key_path = names.private_key_path(&self.directory_path);
        if let Some(mut pem) = self.read_private_file(
            &names.private_key_name,
            &private_key_path,
            PRIVATE_KEY_MAX_BYTES,
        )? {
            let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(names.credential_id.clone(), &pem);
            pem.fill(0);
            return signer.map_err(|_| ObjectWriteCredentialError::Corrupt {
                path: private_key_path,
                reason: "private key is not a canonical PKCS#8 v2 Ed25519 key",
            });
        }
        let mut pem = generate_pkcs8_v2_pem()?;
        let result = (|| {
            let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(names.credential_id.clone(), &pem)
                .map_err(|_| ObjectWriteCredentialError::KeyGeneration)?;
            self.publish(
                &names.private_key_temporary_name,
                &names.private_key_name,
                &private_key_path,
                &pem,
            )?;
            Ok(signer)
        })();
        pem.fill(0);
        result
    }

    /// Same as [`Self::load_private_key`] but for a credential that is already
    /// durable: an absent key is then unrecoverable corruption for this epoch,
    /// not simply an unregistered attachment.
    fn require_private_key(
        &self,
        names: &CredentialNames,
        registration: &ObjectWriteCredentialRegistration,
    ) -> Result<Ed25519RequestSigner, ObjectWriteCredentialError> {
        self.load_private_key(names, registration)
            .map_err(|error| match error {
                ObjectWriteCredentialError::NotRegistered => ObjectWriteCredentialError::Corrupt {
                    path: names.private_key_path(&self.directory_path),
                    reason: "durable registration has no private key",
                },
                other => other,
            })
    }

    fn load_private_key(
        &self,
        names: &CredentialNames,
        registration: &ObjectWriteCredentialRegistration,
    ) -> Result<Ed25519RequestSigner, ObjectWriteCredentialError> {
        let private_key_path = names.private_key_path(&self.directory_path);
        let Some(mut pem) = self.read_private_file(
            &names.private_key_name,
            &private_key_path,
            PRIVATE_KEY_MAX_BYTES,
        )?
        else {
            return Err(ObjectWriteCredentialError::NotRegistered);
        };
        let signer = Ed25519RequestSigner::from_pkcs8_v2_pem(names.credential_id.clone(), &pem);
        pem.fill(0);
        let signer = signer.map_err(|_| ObjectWriteCredentialError::Corrupt {
            path: private_key_path.clone(),
            reason: "private key is not a canonical PKCS#8 v2 Ed25519 key",
        })?;
        if signer.public_key_spki_sha256() != registration.credential.public_key_spki_sha256
            || URL_SAFE_NO_PAD.encode(signer.public_key_spki_der())
                != registration.public_key_spki.as_str()
        {
            return Err(ObjectWriteCredentialError::Corrupt {
                path: private_key_path,
                reason: "private key does not match the registered public key",
            });
        }
        Ok(signer)
    }

    /// Overwrites and unlinks the private key.
    ///
    /// The overwrite is a best-effort scrub: a journaling or copy-on-write
    /// filesystem may retain the old blocks. The unlink plus directory barrier
    /// is the property this module actually relies on, because every path to a
    /// signer goes through [`Self::load_private_key`].
    fn destroy_private_key(
        &self,
        names: &CredentialNames,
    ) -> Result<(), ObjectWriteCredentialError> {
        let path = names.private_key_path(&self.directory_path);
        let mut file = match open_at(
            &self.directory,
            &names.private_key_name,
            libc::O_WRONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(source) => return Err(map_open_error("open retired private key", &path, source)),
        };
        verify_private_file(&file, &path)?;
        let length = file
            .metadata()
            .map_err(|source| io_error("inspect retired private key", &path, source))?
            .len();
        let zeroes = vec![0_u8; usize::try_from(length).unwrap_or(PRIVATE_KEY_MAX_BYTES)];
        file.write_all(&zeroes)
            .map_err(|source| io_error("scrub retired private key", &path, source))?;
        file.sync_all()
            .map_err(|source| io_error("sync retired private key", &path, source))?;
        drop(file);
        self.remove(&names.private_key_name, &path)
    }

    fn read_registered_artifact(
        &self,
        names: &CredentialNames,
    ) -> Result<Option<ObjectWriteCredentialRegisteredArtifact>, ObjectWriteCredentialError> {
        let path = names.registered_path(&self.directory_path);
        let Some(bytes) = self.read_private_file(
            &names.registered_name,
            &path,
            OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES,
        )?
        else {
            return Ok(None);
        };
        let artifact =
            decode_object_write_credential_registered_artifact(&bytes).map_err(|_| {
                ObjectWriteCredentialError::Corrupt {
                    path: path.clone(),
                    reason: "registered artifact is malformed or noncanonical",
                }
            })?;
        if artifact.registration.credential.credential_id != names.credential_id {
            return Err(ObjectWriteCredentialError::Corrupt {
                path,
                reason: "registered artifact names another credential",
            });
        }
        Ok(Some(artifact))
    }

    fn read_prepared_registration(
        &self,
        names: &CredentialNames,
    ) -> Result<Option<ObjectWriteCredentialRegistration>, ObjectWriteCredentialError> {
        self.read_prepared(
            &names.prepared_name,
            &names.prepared_path(&self.directory_path),
        )
    }

    fn read_prepared_at(
        &self,
        locator: &PreparedLocator,
    ) -> Result<Option<ObjectWriteCredentialRegistration>, ObjectWriteCredentialError> {
        self.read_prepared(&locator.name, &locator.path(&self.directory_path))
    }

    fn read_prepared(
        &self,
        name: &CStr,
        path: &Path,
    ) -> Result<Option<ObjectWriteCredentialRegistration>, ObjectWriteCredentialError> {
        let Some(bytes) = self.read_private_file(name, path, PREPARED_REGISTRATION_MAX_BYTES)?
        else {
            return Ok(None);
        };
        decode_object_write_credential_registration(&bytes)
            .map(Some)
            .map_err(|_| ObjectWriteCredentialError::Corrupt {
                path: path.to_path_buf(),
                reason: "prepared registration is malformed or noncanonical",
            })
    }

    fn publish_prepared_registration(
        &self,
        names: &CredentialNames,
        registration: &ObjectWriteCredentialRegistration,
    ) -> Result<(), ObjectWriteCredentialError> {
        let path = names.prepared_path(&self.directory_path);
        let bytes = cats_api::object_write_gateway::encode_object_write_credential_registration(
            registration,
        )
        .map_err(|_| ObjectWriteCredentialError::Corrupt {
            path: path.clone(),
            reason: "registration does not satisfy the frozen contract",
        })?;
        if bytes.len() > PREPARED_REGISTRATION_MAX_BYTES {
            return Err(ObjectWriteCredentialError::Corrupt {
                path,
                reason: "registration exceeds the Control request bound",
            });
        }
        self.publish(
            &names.prepared_temporary_name,
            &names.prepared_name,
            &path,
            &bytes,
        )
    }

    /// Writes `bytes` to a deterministic temp basename, makes the content
    /// durable, renames it onto the target and makes the target link durable.
    ///
    /// A crash before the rename leaves only the temp, which the next attempt
    /// removes; a crash after it leaves a complete target.
    fn publish(
        &self,
        temporary_name: &CStr,
        target_name: &CStr,
        target_path: &Path,
        bytes: &[u8],
    ) -> Result<(), ObjectWriteCredentialError> {
        let temporary_path = temporary_path(target_path);
        unlink_at_if_exists(&self.directory, temporary_name).map_err(|source| {
            io_error(
                "remove stale object-write credential temp",
                &temporary_path,
                source,
            )
        })?;
        let mut file = open_at(
            &self.directory,
            temporary_name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            PRIVATE_FILE_MODE,
        )
        .map_err(|source| {
            map_open_error(
                "create object-write credential temp",
                &temporary_path,
                source,
            )
        })?;
        verify_private_file(&file, &temporary_path)?;
        file.write_all(bytes).map_err(|source| {
            io_error(
                "write object-write credential temp",
                &temporary_path,
                source,
            )
        })?;
        file.sync_all().map_err(|source| {
            io_error("sync object-write credential temp", &temporary_path, source)
        })?;
        drop(file);
        rename_at(
            &self.directory,
            temporary_name,
            &self.directory,
            target_name,
        )
        .map_err(|source| io_error("publish object-write credential", target_path, source))?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync object-write credential directory",
                &self.directory_path,
                source,
            )
        })
    }

    fn remove(&self, name: &CStr, path: &Path) -> Result<(), ObjectWriteCredentialError> {
        unlink_at_if_exists(&self.directory, name)
            .map_err(|source| io_error("remove object-write credential file", path, source))?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync object-write credential directory",
                &self.directory_path,
                source,
            )
        })
    }

    /// Reads one root-only `0600` regular file, rejecting a symlink, a hard
    /// link, foreign ownership, loosened permissions and an over-long body.
    fn read_private_file(
        &self,
        name: &CStr,
        path: &Path,
        maximum: usize,
    ) -> Result<Option<Vec<u8>>, ObjectWriteCredentialError> {
        let file = match open_at(
            &self.directory,
            name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(map_open_error(
                    "open object-write credential file",
                    path,
                    source,
                ))
            }
        };
        verify_private_file(&file, path)?;
        let mut bytes = Vec::new();
        file.take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read object-write credential file", path, source))?;
        if bytes.len() > maximum {
            return Err(ObjectWriteCredentialError::UnsafeEntry {
                path: path.to_path_buf(),
                reason: "file exceeds its bound",
            });
        }
        Ok(Some(bytes))
    }

    /// An ambiguous attempt keeps every local artifact so the byte-identical
    /// body can be replayed; a closed status is a decision.
    fn classify_registration_failure(
        &self,
        failure: ObjectWriteCredentialRegistrationFailure,
    ) -> ObjectWriteCredentialError {
        if failure.is_ambiguous() {
            ObjectWriteCredentialError::RegistrationAmbiguous(failure.to_string())
        } else {
            ObjectWriteCredentialError::Rejected(failure.to_string())
        }
    }

    #[cfg(not(test))]
    fn maybe_crash(&self, _stage: impl Into<CrashStage>) -> Result<(), ObjectWriteCredentialError> {
        Ok(())
    }

    #[cfg(test)]
    fn maybe_crash(&self, stage: impl Into<CrashStage>) -> Result<(), ObjectWriteCredentialError> {
        let stage = stage.into();
        let mut faults = self.faults.lock().expect("test fault lock");
        if faults.crash_once == Some(stage) {
            faults.crash_once = None;
            return Err(ObjectWriteCredentialError::InjectedCrash);
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject_crash_once(&self, stage: impl Into<CrashStage>) {
        self.faults.lock().expect("test fault lock").crash_once = Some(stage.into());
    }
}

/// Every basename one credential owns, derived only from its exact scope.
#[derive(Debug)]
struct CredentialNames {
    credential_id: Id,
    private_artifact_id: Id,
    private_key_name: CString,
    private_key_temporary_name: CString,
    prepared_name: CString,
    prepared_temporary_name: CString,
    registered_name: CString,
    registered_temporary_name: CString,
    private_key_file: String,
    prepared_file: String,
    registered_file: String,
}

impl CredentialNames {
    fn derive(
        session: &SessionBinding,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<Self, ObjectWriteCredentialError> {
        let credential_id =
            object_write_credential_id(session, volume_id, attachment_id, attachment_epoch);
        let private_artifact_id =
            object_write_private_artifact_id(session, volume_id, attachment_id, attachment_epoch);
        let private_key_file = object_write_private_key_file_name(&private_artifact_id);
        let prepared_file = object_write_prepared_registration_file_name(
            volume_id,
            attachment_id,
            attachment_epoch,
        );
        let registered_file = object_write_registered_artifact_file_name(&credential_id);
        Ok(Self {
            credential_id,
            private_artifact_id,
            private_key_name: basename(&private_key_file)?,
            private_key_temporary_name: temporary_basename(&private_key_file)?,
            prepared_name: basename(&prepared_file)?,
            prepared_temporary_name: temporary_basename(&prepared_file)?,
            registered_name: basename(&registered_file)?,
            registered_temporary_name: temporary_basename(&registered_file)?,
            private_key_file,
            prepared_file,
            registered_file,
        })
    }

    fn private_key_path(&self, directory: &Path) -> PathBuf {
        directory.join(&self.private_key_file)
    }

    fn prepared_path(&self, directory: &Path) -> PathBuf {
        directory.join(&self.prepared_file)
    }

    fn registered_path(&self, directory: &Path) -> PathBuf {
        directory.join(&self.registered_file)
    }
}

/// The session-independent sidecar locator, which is all a later reader or a
/// replacement Agent knows about an attachment epoch.
#[derive(Debug)]
struct PreparedLocator {
    name: CString,
    file: String,
}

impl PreparedLocator {
    fn derive(
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<Self, ObjectWriteCredentialError> {
        let file = object_write_prepared_registration_file_name(
            volume_id,
            attachment_id,
            attachment_epoch,
        );
        Ok(Self {
            name: basename(&file)?,
            file,
        })
    }

    fn path(&self, directory: &Path) -> PathBuf {
        directory.join(&self.file)
    }
}

fn build_registration(
    scope: &ObjectWriteCredentialScope,
    names: &CredentialNames,
    signer: &Ed25519RequestSigner,
) -> Result<ObjectWriteCredentialRegistration, ObjectWriteCredentialError> {
    let credential = ObjectWriteCredentialReference {
        credential_id: names.credential_id.clone(),
        public_key_spki_sha256: signer.public_key_spki_sha256(),
    };
    let public_key_spki = Base64UrlNoPad::new(URL_SAFE_NO_PAD.encode(signer.public_key_spki_der()))
        .ok_or(ObjectWriteCredentialError::KeyGeneration)?;
    // Both receipt identities are derived, not measured: they name the exact
    // barriers this module has already performed for this artifact and key.
    let private_file_fsync_receipt_id =
        object_write_private_file_fsync_receipt_id(&names.private_artifact_id, &credential);
    let private_directory_fsync_receipt_id = object_write_private_directory_fsync_receipt_id(
        &names.private_artifact_id,
        &private_file_fsync_receipt_id,
    );
    Ok(ObjectWriteCredentialRegistration {
        version: ContractVersion::V1,
        session: scope.session.clone(),
        writer_authority_id: scope.writer_authority_id.clone(),
        volume_id: scope.volume_id.clone(),
        attachment_id: scope.attachment_id.clone(),
        attachment_epoch: scope.attachment_epoch,
        credential,
        public_key_spki,
        private_artifact_id: names.private_artifact_id.clone(),
        private_file_fsync_receipt_id,
        private_directory_fsync_receipt_id,
    })
}

/// The A19-authenticated production registration transport.
#[derive(Clone)]
pub(crate) struct ObjectWriteCredentialHttpRegistrar {
    origin: reqwest::Url,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for ObjectWriteCredentialHttpRegistrar {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectWriteCredentialHttpRegistrar")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

impl ObjectWriteCredentialHttpRegistrar {
    /// `server_ca_bundle_pem` are the PEM roots that issue server certificates
    /// in this deployment's Route v2 revision. The gateway is a fixed internal
    /// origin whose certificate no public trust store contains, so the roots
    /// are mandatory and they *replace* the built-in set rather than extending
    /// it: leaving the public roots installed would let any publicly issued
    /// certificate for the gateway host stand in for the gateway.
    pub(crate) fn for_production(
        gateway_origin: &str,
        server_ca_bundle_pem: &[u8],
    ) -> anyhow::Result<Self> {
        Self::new(
            gateway_origin,
            TransportMode::ProductionHttps,
            Some(server_ca_bundle_pem),
        )
    }

    /// Same real registrar against a loopback HTTP peer. `pub(crate)` so the
    /// crate's object-write end-to-end acceptance test can point it at the
    /// running gateway; the transport rule it relaxes is only the origin
    /// scheme, and it is compiled out of every non-test build.
    #[cfg(test)]
    pub(crate) fn for_loopback_test(gateway_origin: &str) -> anyhow::Result<Self> {
        Self::new(gateway_origin, TransportMode::LoopbackTest, None)
    }

    fn new(
        gateway_origin: &str,
        mode: TransportMode,
        server_ca_bundle_pem: Option<&[u8]>,
    ) -> anyhow::Result<Self> {
        let origin = validate_origin(gateway_origin, "object-write gateway", mode)?;
        let mut client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd();
        if let Some(pem) = server_ca_bundle_pem {
            let roots = reqwest::tls::Certificate::from_pem_bundle(pem).map_err(|error| {
                anyhow::anyhow!(
                    "object-write gateway server CA bundle is not a readable PEM bundle: {error}"
                )
            })?;
            if roots.is_empty() {
                anyhow::bail!("object-write gateway server CA bundle contains no certificate");
            }
            client = client.https_only(true).tls_built_in_root_certs(false);
            for root in roots {
                client = client.add_root_certificate(root);
            }
        }
        let client = client.build()?;
        Ok(Self { origin, client })
    }
}

impl ObjectWriteCredentialRegistrar for ObjectWriteCredentialHttpRegistrar {
    fn register(
        &self,
        proof: &ObjectWriteCredentialRegistrationProof,
        deadline: Instant,
    ) -> Result<ObjectWriteCredentialRegistrationReceipt, ObjectWriteCredentialRegistrationFailure>
    {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ObjectWriteCredentialRegistrationFailure::Timeout)?;
        let url = self
            .origin
            .join(OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH)
            .expect("a validated origin accepts the fixed registration path");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .header(
                reqwest::header::CONTENT_TYPE,
                OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
            )
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(NODE_CREDENTIAL_ID_HEADER, proof.node.credential_id.clone())
            .header(
                NODE_PUBLIC_KEY_SPKI_HEADER,
                proof.node.public_key_spki.clone(),
            )
            .header(NODE_SIGNATURE_HEADER, proof.node.signature.clone())
            .header(
                OBJECT_WRITE_CREDENTIAL_ID_HEADER,
                proof.attachment_key.credential_id.clone(),
            )
            .header(
                OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER,
                proof.attachment_key.public_key_spki.clone(),
            )
            .header(
                OBJECT_WRITE_SIGNATURE_HEADER,
                proof.attachment_key.signature.clone(),
            )
            .body(proof.body.clone())
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) if error.is_timeout() => {
                return Err(ObjectWriteCredentialRegistrationFailure::Timeout)
            }
            Err(_) => return Err(ObjectWriteCredentialRegistrationFailure::Connection),
        };
        let status = response.status().as_u16();
        if status != 200 {
            return Err(ObjectWriteCredentialRegistrationFailure::Closed { status });
        }
        let body = response
            .bytes()
            .map_err(|_| ObjectWriteCredentialRegistrationFailure::Connection)?;
        if body.len() > OBJECT_WRITE_REGISTERED_ARTIFACT_MAX_BYTES {
            return Err(ObjectWriteCredentialRegistrationFailure::MalformedResponse);
        }
        decode_object_write_credential_registration_receipt(&body)
            .map_err(|_| ObjectWriteCredentialRegistrationFailure::MalformedResponse)
    }
}

/// A19-signed reader for this Node's own writer authority.
///
/// It targets the *Control* management origin, not the ObjectWrite Gateway:
/// the `object_write_authorities` row and the `owa1_` derivation both live in
/// Control, and the Node authenticates here with the same per-Node credential
/// it uses for every other `/v1/internal/runtime/...` call.
pub(crate) struct ObjectWriteWriterAuthorityHttpReader {
    origin: reqwest::Url,
    signer: Ed25519RequestSigner,
    client: reqwest::blocking::Client,
}

impl std::fmt::Debug for ObjectWriteWriterAuthorityHttpReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ObjectWriteWriterAuthorityHttpReader")
            .field("origin", &self.origin)
            .field("signer", &self.signer)
            .finish_non_exhaustive()
    }
}

impl ObjectWriteWriterAuthorityHttpReader {
    pub(crate) fn for_production(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
    ) -> anyhow::Result<Self> {
        Self::new(control_plane_origin, signer, TransportMode::ProductionHttps)
    }

    #[cfg(test)]
    fn for_loopback_test(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
    ) -> anyhow::Result<Self> {
        Self::new(control_plane_origin, signer, TransportMode::LoopbackTest)
    }

    fn new(
        control_plane_origin: &str,
        signer: Ed25519RequestSigner,
        mode: TransportMode,
    ) -> anyhow::Result<Self> {
        let origin = validate_origin(control_plane_origin, "Control", mode)?;
        let client = reqwest::blocking::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .no_zstd()
            .build()?;
        Ok(Self {
            origin,
            signer,
            client,
        })
    }
}

impl ObjectWriteWriterAuthorityResolver for ObjectWriteWriterAuthorityHttpReader {
    fn read(
        &self,
        session: &SessionBinding,
        deadline: Instant,
    ) -> Result<ObjectWriteWriterAuthorityStateV1, ObjectWriteWriterAuthorityReadFailure> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(ObjectWriteWriterAuthorityReadFailure::Timeout)?;
        let request = ObjectWriteWriterAuthorityRead {
            version: ContractVersion::V1,
            session: session.clone(),
        };
        let body = encode_object_write_writer_authority_read(&request)
            .map_err(|_| ObjectWriteWriterAuthorityReadFailure::MalformedResponse)?;
        let proof = self.signer.sign(
            OBJECT_WRITE_GATEWAY_METHOD,
            OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
            &body,
        );
        let url = self
            .origin
            .join(OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH)
            .expect("a validated origin accepts the fixed authority read path");
        let response = self
            .client
            .post(url)
            .timeout(remaining)
            .header(
                reqwest::header::CONTENT_TYPE,
                OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
            )
            .header(
                reqwest::header::ACCEPT,
                OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE,
            )
            .header(reqwest::header::ACCEPT_ENCODING, "identity")
            .header(NODE_CREDENTIAL_ID_HEADER, proof.credential_id)
            .header(NODE_PUBLIC_KEY_SPKI_HEADER, proof.public_key_spki)
            .header(NODE_SIGNATURE_HEADER, proof.signature)
            .body(body)
            .send();
        let response = match response {
            Ok(response) => response,
            Err(error) if error.is_timeout() => {
                return Err(ObjectWriteWriterAuthorityReadFailure::Timeout)
            }
            Err(_) => return Err(ObjectWriteWriterAuthorityReadFailure::Connection),
        };
        let status = response.status().as_u16();
        if status != 200 {
            return Err(ObjectWriteWriterAuthorityReadFailure::Closed { status });
        }
        let body = response
            .bytes()
            .map_err(|_| ObjectWriteWriterAuthorityReadFailure::Connection)?;
        if body.len() > OBJECT_WRITE_WRITER_AUTHORITY_VIEW_MAX_WIRE_BYTES {
            return Err(ObjectWriteWriterAuthorityReadFailure::MalformedResponse);
        }
        let view = decode_object_write_writer_authority_view(&body)
            .map_err(|_| ObjectWriteWriterAuthorityReadFailure::MalformedResponse)?;
        if view.session != *session {
            return Err(ObjectWriteWriterAuthorityReadFailure::SessionMismatch);
        }
        Ok(view.authority)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransportMode {
    ProductionHttps,
    LoopbackTest,
}

fn validate_origin(
    input: &str,
    subject: &'static str,
    mode: TransportMode,
) -> anyhow::Result<reqwest::Url> {
    let url = reqwest::Url::parse(input)?;
    anyhow::ensure!(
        url.username().is_empty() && url.password().is_none(),
        "{subject} origin has userinfo"
    );
    anyhow::ensure!(url.query().is_none(), "{subject} origin has a query");
    anyhow::ensure!(url.fragment().is_none(), "{subject} origin has a fragment");
    anyhow::ensure!(url.path() == "/", "{subject} origin has a path");
    match mode {
        TransportMode::ProductionHttps => anyhow::ensure!(
            url.scheme() == "https",
            "production {subject} origin must use HTTPS"
        ),
        TransportMode::LoopbackTest => anyhow::ensure!(
            url.scheme() == "http"
                && url
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "::1" | "localhost")),
            "test {subject} origin must be loopback HTTP"
        ),
    }
    Ok(url)
}

fn generate_pkcs8_v2_pem() -> Result<Vec<u8>, ObjectWriteCredentialError> {
    let document = Ed25519KeyPair::generate_pkcs8(&SystemRandom::new())
        .map_err(|_| ObjectWriteCredentialError::KeyGeneration)?;
    let mut encoded = STANDARD.encode(document.as_ref());
    let mut pem = Vec::with_capacity(encoded.len() + 80);
    pem.extend_from_slice(b"-----BEGIN PRIVATE KEY-----\n");
    for chunk in encoded.as_bytes().chunks(64) {
        pem.extend_from_slice(chunk);
        pem.push(b'\n');
    }
    pem.extend_from_slice(b"-----END PRIVATE KEY-----\n");
    // Drop the intermediate base64 copy of the private key.
    // SAFETY: NUL is valid UTF-8, so overwriting the ASCII base64 body with
    // zeroes keeps the `String` well formed for its remaining lifetime.
    unsafe { encoded.as_bytes_mut() }.fill(0);
    Ok(pem)
}

fn temporary_path(target: &Path) -> PathBuf {
    let (directory, file) = (target.parent(), target.file_name());
    match (directory, file.and_then(|name| name.to_str())) {
        (Some(directory), Some(file)) => directory.join(format!(".{file}.incomplete")),
        _ => target.to_path_buf(),
    }
}

fn basename(value: &str) -> Result<CString, ObjectWriteCredentialError> {
    ensure_plain_basename(value)?;
    CString::new(value).map_err(|_| ObjectWriteCredentialError::UnsafeEntry {
        path: PathBuf::from(value),
        reason: "NUL byte in credential basename",
    })
}

fn temporary_basename(value: &str) -> Result<CString, ObjectWriteCredentialError> {
    ensure_plain_basename(value)?;
    CString::new(format!(".{value}.incomplete")).map_err(|_| {
        ObjectWriteCredentialError::UnsafeEntry {
            path: PathBuf::from(value),
            reason: "NUL byte in credential basename",
        }
    })
}

/// Every basename this module uses comes from a frozen contract helper, so this
/// is a defence in depth assertion rather than a parser.
fn ensure_plain_basename(value: &str) -> Result<(), ObjectWriteCredentialError> {
    let plain = !value.is_empty()
        && value != "."
        && value != ".."
        && !value.starts_with('.')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if plain {
        Ok(())
    } else {
        Err(ObjectWriteCredentialError::UnsafeEntry {
            path: PathBuf::from(value),
            reason: "credential basename is not a plain component",
        })
    }
}

fn verify_private_file(file: &File, path: &Path) -> Result<(), ObjectWriteCredentialError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect object-write credential file", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(ObjectWriteCredentialError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "not a regular file",
        });
    }
    if metadata.nlink() != 1 {
        return Err(ObjectWriteCredentialError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "hard-linked file",
        });
    }
    if metadata.uid() != effective_uid() {
        return Err(ObjectWriteCredentialError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "file is owned by another user",
        });
    }
    if metadata.permissions().mode() & 0o7777 != PRIVATE_FILE_MODE {
        return Err(ObjectWriteCredentialError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "file is not root-only 0600",
        });
    }
    Ok(())
}

fn effective_uid() -> u32 {
    // SAFETY: `geteuid` takes no arguments, cannot fail and retains no memory.
    unsafe { libc::geteuid() }
}

fn lock_directory(
    directory: &File,
    mode: i32,
    path: &Path,
) -> Result<(), ObjectWriteCredentialError> {
    loop {
        // SAFETY: `directory` owns a live descriptor for the whole call and
        // `flock` neither takes ownership of it nor retains a pointer.
        let result = unsafe { libc::flock(directory.as_raw_fd(), mode | libc::LOCK_NB) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::Interrupted {
            continue;
        }
        if source.kind() == io::ErrorKind::WouldBlock {
            return Err(ObjectWriteCredentialError::WriterAlreadyActive {
                path: path.to_path_buf(),
            });
        }
        return Err(io_error(
            "lock object-write credential directory",
            path,
            source,
        ));
    }
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: `directory` remains open for the call, `name` is
        // NUL-terminated, and a successful descriptor is transferred exactly
        // once into `File`. `openat` retains neither pointer.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::mode_t as libc::c_uint,
            )
        };
        if descriptor >= 0 {
            // SAFETY: `openat` returned one fresh owned descriptor.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    loop {
        // SAFETY: both descriptors remain live for the call and both names are
        // NUL-terminated. `renameat` retains neither pointer.
        let result = unsafe {
            libc::renameat(
                old_directory.as_raw_fd(),
                old_name.as_ptr(),
                new_directory.as_raw_fd(),
                new_name.as_ptr(),
            )
        };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn unlink_at_if_exists(directory: &File, name: &CStr) -> io::Result<()> {
    loop {
        // SAFETY: `directory` and `name` remain live for the call. The name is
        // directory-relative and NUL-terminated; `unlinkat` retains no pointer.
        let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
        if result == 0 {
            return Ok(());
        }
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            return Ok(());
        }
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn map_open_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> ObjectWriteCredentialError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        ObjectWriteCredentialError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "symbolic link",
        }
    } else {
        io_error(operation, path, source)
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> ObjectWriteCredentialError {
    ObjectWriteCredentialError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

/// The durable barriers `establish` crosses, in order. Tests inject a crash at
/// one of them; production builds only name them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EstablishStage {
    PrivateKeyDurable,
    PreparedRegistrationDurable,
    ControlRegistered,
}

/// The one durable barrier `retire` crosses before it removes public sidecars.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RetireStage {
    PrivateKeyDestroyed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CrashStage {
    Establish(EstablishStage),
    Retire(RetireStage),
}

impl From<EstablishStage> for CrashStage {
    fn from(stage: EstablishStage) -> Self {
        Self::Establish(stage)
    }
}

impl From<RetireStage> for CrashStage {
    fn from(stage: RetireStage) -> Self {
        Self::Retire(stage)
    }
}

/// Why one attachment epoch has no usable object-write credential.
///
/// The exact attachment is named so an operator can find the grant that failed.
/// `reason` renders only this module's own error, which describes a path, a
/// derived identifier or Control's decision; no private key byte, and no value
/// derived from one, can reach it.
#[derive(Debug, Error)]
#[error(
    "no usable object-write credential for volume {volume_id} attachment {attachment_id} epoch {attachment_epoch}: {reason}"
)]
pub struct ObjectWriteCredentialUnavailable {
    volume_id: Id,
    attachment_id: Id,
    attachment_epoch: u64,
    reason: String,
}

impl ObjectWriteCredentialUnavailable {
    fn new(
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
        source: &ObjectWriteCredentialError,
    ) -> Self {
        Self {
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch: attachment_epoch.get(),
            reason: source.to_string(),
        }
    }
}

/// The Node's authority to mint and destroy the attachment-scoped object-write
/// credential one serving grant needs before it may publish.
///
/// The reconciler holds this instead of an [`ObjectWriteCredentialStore`] so a
/// grant path never learns the state-directory layout, the A19 Node signer or
/// the registration transport, and so the private half of a credential cannot
/// escape this module: `establish` returns only the public reference a
/// descriptor may quote.
pub trait ObjectWriteCredentialPort: std::fmt::Debug + Send + Sync {
    /// Converges one attachment epoch on exactly one registered credential and
    /// returns its public binding. Idempotent: a repeat for the same epoch
    /// re-registers the same key rather than minting a second credential.
    fn establish(
        &self,
        session: &SessionBinding,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
        deadline: Instant,
    ) -> Result<ObjectWriteCredentialReference, ObjectWriteCredentialUnavailable>;

    /// Destroys the credential of one ended attachment epoch, private half
    /// first. Retiring an epoch that has no credential succeeds.
    fn retire(
        &self,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<(), ObjectWriteCredentialUnavailable>;

    /// Absolute directory the serving process loads the private half from. It
    /// is the credential namespace itself, not the Node state root.
    fn credential_directory(&self) -> PathBuf;

    /// The origin the serving process publishes objects through.
    fn gateway_origin(&self) -> &str;

    /// PEM roots the serving process must authenticate that origin against.
    fn server_ca_bundle_file(&self) -> &Path;
}

/// A recording [`ObjectWriteCredentialPort`] for the reconciler's own tests.
///
/// It is deliberately not a stub of the production port: it performs no I/O and
/// exists only so a reconciliation test can observe *which* attachment epoch
/// was credentialed or retired, and inject the two failures the grant paths
/// must fail closed on.
#[cfg(test)]
#[derive(Debug, Default)]
pub(crate) struct RecordingObjectWriteCredentials {
    establish_fails: bool,
    retire_fails: bool,
    established: std::sync::Mutex<Vec<(Id, Id, FenceEpoch)>>,
    retired: std::sync::Mutex<Vec<(Id, Id, FenceEpoch)>>,
}

#[cfg(test)]
impl RecordingObjectWriteCredentials {
    pub(crate) fn failing_establish() -> Self {
        Self {
            establish_fails: true,
            ..Self::default()
        }
    }

    pub(crate) fn failing_retire() -> Self {
        Self {
            retire_fails: true,
            ..Self::default()
        }
    }

    pub(crate) fn established(&self) -> Vec<(Id, Id, FenceEpoch)> {
        self.established.lock().unwrap().clone()
    }

    pub(crate) fn retired(&self) -> Vec<(Id, Id, FenceEpoch)> {
        self.retired.lock().unwrap().clone()
    }

    /// The public reference this port hands back for one scope. It is derived
    /// exactly the way the production port derives it, so a test asserting the
    /// bound value is asserting the real binding rule.
    pub(crate) fn expected_credential(
        session: &SessionBinding,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> ObjectWriteCredentialReference {
        ObjectWriteCredentialReference {
            credential_id: object_write_credential_id(
                session,
                volume_id,
                attachment_id,
                attachment_epoch,
            ),
            public_key_spki_sha256: cats_api::runtime_reconciliation::Sha256Digest::from_bytes(
                [7; 32],
            ),
        }
    }
}

#[cfg(test)]
impl ObjectWriteCredentialPort for RecordingObjectWriteCredentials {
    fn establish(
        &self,
        session: &SessionBinding,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
        _deadline: Instant,
    ) -> Result<ObjectWriteCredentialReference, ObjectWriteCredentialUnavailable> {
        if self.establish_fails {
            return Err(ObjectWriteCredentialUnavailable::new(
                volume_id,
                attachment_id,
                attachment_epoch,
                &ObjectWriteCredentialError::Rejected("injected".to_owned()),
            ));
        }
        self.established.lock().unwrap().push((
            volume_id.clone(),
            attachment_id.clone(),
            attachment_epoch,
        ));
        Ok(Self::expected_credential(
            session,
            volume_id,
            attachment_id,
            attachment_epoch,
        ))
    }

    fn retire(
        &self,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<(), ObjectWriteCredentialUnavailable> {
        if self.retire_fails {
            return Err(ObjectWriteCredentialUnavailable::new(
                volume_id,
                attachment_id,
                attachment_epoch,
                &ObjectWriteCredentialError::Rejected("injected".to_owned()),
            ));
        }
        self.retired.lock().unwrap().push((
            volume_id.clone(),
            attachment_id.clone(),
            attachment_epoch,
        ));
        Ok(())
    }

    fn credential_directory(&self) -> PathBuf {
        PathBuf::from("/var/lib/cats/node/test").join(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME)
    }

    fn gateway_origin(&self) -> &str {
        "https://gateway.invalid"
    }

    fn server_ca_bundle_file(&self) -> &Path {
        Path::new("/etc/cats/route-v2/node-server-ca-bundle.pem")
    }
}

/// Production [`ObjectWriteCredentialPort`]: one Node state directory, the
/// installed A19 Node signer, the Control writer-authority read and the
/// ObjectWrite Gateway registration route.
///
/// The writer authority ID is never configuration. Control derives it from the
/// Node ID, the fleet deployment writes one shared worker environment, and a
/// local re-derivation would duplicate Control's rule and could drift, so this
/// port asks Control for it and treats the answer as the only authority.
pub struct NodeObjectWriteCredentials {
    state_directory: PathBuf,
    gateway_origin: String,
    server_ca_bundle_file: PathBuf,
    node_signer: Ed25519RequestSigner,
    registrar: Arc<dyn ObjectWriteCredentialRegistrar>,
    authority_reader: Arc<dyn ObjectWriteWriterAuthorityResolver>,
    /// The one authority resolved for the current Agent session. A different
    /// session re-reads, because a credential is session bound and a
    /// replacement Agent must not inherit a stale answer.
    resolved_authority: std::sync::Mutex<Option<(SessionBinding, Id)>>,
}

impl std::fmt::Debug for NodeObjectWriteCredentials {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NodeObjectWriteCredentials")
            .field("state_directory", &self.state_directory)
            .field("gateway_origin", &self.gateway_origin)
            .field("resolved_authority", &self.resolved_authority)
            .finish_non_exhaustive()
    }
}

impl NodeObjectWriteCredentials {
    /// Composes the production path. `gateway_origin` and `control_plane_origin`
    /// must both be bare HTTPS origins; they are validated here so a
    /// misconfigured Node fails at startup rather than at its first grant.
    pub fn for_production(
        state_directory: PathBuf,
        gateway_origin: &str,
        server_ca_bundle_file: &Path,
        control_plane_origin: &str,
        node_signer: Ed25519RequestSigner,
    ) -> anyhow::Result<Self> {
        anyhow::ensure!(
            state_directory.is_absolute(),
            "object-write credential state directory must be absolute"
        );
        anyhow::ensure!(
            server_ca_bundle_file.is_absolute(),
            "object-write gateway server CA bundle path must be absolute"
        );
        let server_ca_bundle_pem = std::fs::read(server_ca_bundle_file).map_err(|error| {
            anyhow::anyhow!(
                "read object-write gateway server CA bundle {}: {error}",
                server_ca_bundle_file.display()
            )
        })?;
        let registrar = ObjectWriteCredentialHttpRegistrar::for_production(
            gateway_origin,
            &server_ca_bundle_pem,
        )?;
        let authority_reader = ObjectWriteWriterAuthorityHttpReader::for_production(
            control_plane_origin,
            node_signer.clone(),
        )?;
        Ok(Self {
            state_directory,
            // Keep the exact configured origin: the serving process must be
            // told the same one this Node registered against.
            gateway_origin: gateway_origin.to_owned(),
            server_ca_bundle_file: server_ca_bundle_file.to_path_buf(),
            node_signer,
            registrar: Arc::new(registrar),
            authority_reader: Arc::new(authority_reader),
            resolved_authority: std::sync::Mutex::new(None),
        })
    }

    /// Same composition against an in-test Control. The registrar and the
    /// authority reader are real; only the peer they talk to is supplied by the
    /// caller.
    #[cfg(test)]
    pub(crate) fn with_registrar_for_test(
        state_directory: PathBuf,
        gateway_origin: &str,
        node_signer: Ed25519RequestSigner,
        registrar: Arc<dyn ObjectWriteCredentialRegistrar>,
        authority_reader: Arc<dyn ObjectWriteWriterAuthorityResolver>,
    ) -> Self {
        Self {
            state_directory,
            gateway_origin: gateway_origin.to_owned(),
            server_ca_bundle_file: PathBuf::from(
                cats_api::route_grant_v2::NODE_ROUTE_V2_SERVER_CA_BUNDLE_PATH,
            ),
            node_signer,
            registrar,
            authority_reader,
            resolved_authority: std::sync::Mutex::new(None),
        }
    }

    /// The writer authority this Agent session's credentials belong to, read
    /// from Control once per session.
    ///
    /// Every non-`Open` answer and every unsettled read fails closed. There is
    /// deliberately no fallback: a configured, derived or previous-session ID
    /// would either duplicate Control's derivation or publish under a writer
    /// Control has already cut off.
    fn session_writer_authority_id(
        &self,
        session: &SessionBinding,
        deadline: Instant,
    ) -> Result<Id, ObjectWriteCredentialError> {
        // A plain blocking mutex in blocking code: no `.await` crosses it. It
        // is held across the read so exactly one read happens per session even
        // when two attachments converge at once; `establish` is already
        // serialized per Node by the credential-directory `flock`, so this adds
        // no new contention.
        let mut resolved = self
            .resolved_authority
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((cached_session, writer_authority_id)) = resolved.as_ref() {
            if cached_session == session {
                return Ok(writer_authority_id.clone());
            }
        }
        let state = self
            .authority_reader
            .read(session, deadline)
            .map_err(ObjectWriteCredentialError::WriterAuthorityUnresolved)?;
        let writer_authority_id = match &state {
            ObjectWriteWriterAuthorityStateV1::Open {
                writer_authority_id,
            } => writer_authority_id.clone(),
            ObjectWriteWriterAuthorityStateV1::Absent => {
                return Err(ObjectWriteCredentialError::WriterAuthorityAbsent)
            }
            ObjectWriteWriterAuthorityStateV1::CutoffPending { .. }
            | ObjectWriteWriterAuthorityStateV1::CutoffComplete { .. } => {
                return Err(ObjectWriteCredentialError::WriterAuthorityClosed {
                    state: state.state_name(),
                })
            }
        };
        *resolved = Some((session.clone(), writer_authority_id.clone()));
        Ok(writer_authority_id)
    }
}

impl ObjectWriteCredentialPort for NodeObjectWriteCredentials {
    fn establish(
        &self,
        session: &SessionBinding,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
        deadline: Instant,
    ) -> Result<ObjectWriteCredentialReference, ObjectWriteCredentialUnavailable> {
        // Every grant path collapses this failure into a bare retry of the same
        // exact transition, so this is the only place the reason exists. An
        // unlogged refusal here reads on the Node as an effect that retries
        // forever with no stated cause.
        let failed = |error: &ObjectWriteCredentialError| {
            let unavailable = ObjectWriteCredentialUnavailable::new(
                volume_id,
                attachment_id,
                attachment_epoch,
                error,
            );
            tracing::warn!(gateway = %self.gateway_origin, refusal = %unavailable,
                "object-write credential establish failed");
            unavailable
        };
        let scope = ObjectWriteCredentialScope {
            session: session.clone(),
            writer_authority_id: self
                .session_writer_authority_id(session, deadline)
                .map_err(|error| failed(&error))?,
            volume_id: volume_id.clone(),
            attachment_id: attachment_id.clone(),
            attachment_epoch,
        };
        let store = ObjectWriteCredentialStore::open(&self.state_directory)
            .map_err(|error| failed(&error))?;
        let loaded = store
            .establish(&scope, &self.node_signer, self.registrar.as_ref(), deadline)
            .map_err(|error| failed(&error))?;
        // Only the public half leaves this call. `loaded` owns the signer and
        // is dropped here.
        Ok(loaded.credential().clone())
    }

    fn retire(
        &self,
        volume_id: &Id,
        attachment_id: &Id,
        attachment_epoch: FenceEpoch,
    ) -> Result<(), ObjectWriteCredentialUnavailable> {
        let failed = |error: &ObjectWriteCredentialError| {
            let unavailable = ObjectWriteCredentialUnavailable::new(
                volume_id,
                attachment_id,
                attachment_epoch,
                error,
            );
            tracing::warn!(gateway = %self.gateway_origin, refusal = %unavailable,
                "object-write credential retire failed");
            unavailable
        };
        let store = ObjectWriteCredentialStore::open(&self.state_directory)
            .map_err(|error| failed(&error))?;
        store
            .retire(volume_id, attachment_id, attachment_epoch)
            .map_err(|error| failed(&error))
    }

    fn credential_directory(&self) -> PathBuf {
        self.state_directory
            .join(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME)
    }

    fn gateway_origin(&self) -> &str {
        &self.gateway_origin
    }

    fn server_ca_bundle_file(&self) -> &Path {
        &self.server_ca_bundle_file
    }
}

#[cfg(test)]
#[derive(Default)]
struct TestFaults {
    crash_once: Option<CrashStage>,
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{BufRead as _, BufReader, Read as _, Write as _};
    use std::net::TcpListener;
    use std::sync::Mutex;
    use std::time::Duration;

    use cats_api::agent_registration::verify_request_proof;
    use cats_api::object_write_gateway::{
        verify_object_write_credential_registration, ObjectWriteCredentialRegistrationReceipt,
    };
    use cats_api::runtime_reconciliation::{Epoch, NodeBootId, RandomId128, UnixMillis};
    use tempfile::TempDir;

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).unwrap()
    }

    fn session(epoch: u64) -> SessionBinding {
        SessionBinding {
            node_id: id("node_a"),
            node_boot_id: NodeBootId::new("1".repeat(32)).unwrap(),
            agent_instance_id: RandomId128::new("2".repeat(32)).unwrap(),
            agent_session_epoch: Epoch::new(epoch).unwrap(),
        }
    }

    fn scope() -> ObjectWriteCredentialScope {
        scope_for_session(session(7))
    }

    fn scope_for_session(session: SessionBinding) -> ObjectWriteCredentialScope {
        ObjectWriteCredentialScope {
            session,
            writer_authority_id: id("writer_a"),
            volume_id: id("volume_a"),
            attachment_id: id("attachment_a"),
            attachment_epoch: FenceEpoch::new(9).unwrap(),
        }
    }

    fn node_signer() -> Ed25519RequestSigner {
        let mut private_key = vec![
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20,
        ];
        private_key.extend(std::iter::repeat_n(0x11_u8, 32));
        Ed25519RequestSigner::from_pkcs8_der(id("node_credential_a"), &private_key).unwrap()
    }

    /// Control's real replay rule: the exact same registration returns the
    /// original receipt, and a different key under the same credential ID is a
    /// conflict rather than a second credential.
    #[derive(Default)]
    struct ReplayingControl {
        registered: Mutex<HashMap<String, ObjectWriteCredentialRegistration>>,
        bodies: Mutex<Vec<Vec<u8>>>,
        fail_next: Mutex<Option<ObjectWriteCredentialRegistrationFailure>>,
    }

    impl ReplayingControl {
        fn fail_next(&self, failure: ObjectWriteCredentialRegistrationFailure) {
            *self.fail_next.lock().unwrap() = Some(failure);
        }

        fn accepted_bodies(&self) -> Vec<Vec<u8>> {
            self.bodies.lock().unwrap().clone()
        }

        fn registered_public_keys(&self) -> Vec<String> {
            self.registered
                .lock()
                .unwrap()
                .values()
                .map(|registration| registration.public_key_spki.as_str().to_owned())
                .collect()
        }
    }

    impl ObjectWriteCredentialRegistrar for ReplayingControl {
        fn register(
            &self,
            proof: &ObjectWriteCredentialRegistrationProof,
            _deadline: Instant,
        ) -> Result<
            ObjectWriteCredentialRegistrationReceipt,
            ObjectWriteCredentialRegistrationFailure,
        > {
            if let Some(failure) = self.fail_next.lock().unwrap().take() {
                return Err(failure);
            }
            let (_node, _attachment, registration) = verify_object_write_credential_registration(
                &proof.body,
                &proof.node,
                &proof.attachment_key,
            )
            .expect("Control verifies both proofs");
            self.bodies.lock().unwrap().push(proof.body.clone());
            let mut registered = self.registered.lock().unwrap();
            let key = registration.credential.credential_id.as_str().to_owned();
            match registered.get(&key) {
                Some(existing) if *existing == registration => {}
                Some(_) => {
                    return Err(ObjectWriteCredentialRegistrationFailure::Closed { status: 409 })
                }
                None => {
                    registered.insert(key, registration.clone());
                }
            }
            Ok(ObjectWriteCredentialRegistrationReceipt {
                version: ContractVersion::V1,
                writer_authority_id: registration.writer_authority_id.clone(),
                volume_id: registration.volume_id.clone(),
                attachment_id: registration.attachment_id.clone(),
                attachment_epoch: registration.attachment_epoch,
                credential: registration.credential.clone(),
                registered_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
            })
        }
    }

    /// One assigned writer authority in the exact shape Control derives:
    /// the `owa1_` prefix plus 64 lowercase hex digits.
    fn assigned_writer_authority_id() -> Id {
        id(&format!("owa1_{}", "5b".repeat(32)))
    }

    /// Control's writer-authority answer for one Node, with a read log so a
    /// test can prove resolution is once per Agent session rather than once per
    /// attachment.
    struct RecordingAuthorityReader {
        answer: Result<ObjectWriteWriterAuthorityStateV1, ObjectWriteWriterAuthorityReadFailure>,
        reads: Mutex<Vec<SessionBinding>>,
    }

    impl RecordingAuthorityReader {
        fn answering(
            answer: Result<
                ObjectWriteWriterAuthorityStateV1,
                ObjectWriteWriterAuthorityReadFailure,
            >,
        ) -> Arc<Self> {
            Arc::new(Self {
                answer,
                reads: Mutex::new(Vec::new()),
            })
        }

        fn open() -> Arc<Self> {
            Self::answering(Ok(ObjectWriteWriterAuthorityStateV1::Open {
                writer_authority_id: assigned_writer_authority_id(),
            }))
        }

        fn reads(&self) -> Vec<SessionBinding> {
            self.reads.lock().unwrap().clone()
        }
    }

    impl ObjectWriteWriterAuthorityResolver for RecordingAuthorityReader {
        fn read(
            &self,
            session: &SessionBinding,
            _deadline: Instant,
        ) -> Result<ObjectWriteWriterAuthorityStateV1, ObjectWriteWriterAuthorityReadFailure>
        {
            self.reads.lock().unwrap().push(session.clone());
            self.answer.clone()
        }
    }

    fn deadline() -> Instant {
        Instant::now() + Duration::from_secs(30)
    }

    fn establish(
        root: &Path,
        control: &ReplayingControl,
    ) -> Result<LoadedObjectWriteCredential, ObjectWriteCredentialError> {
        let store = ObjectWriteCredentialStore::open(root).unwrap();
        store.establish(&scope(), &node_signer(), control, deadline())
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    /// A 16-byte slice of the encoded private key, calibrated against a known
    /// positive so an absent match cannot be an artefact of a broken search.
    fn key_material_probe(private_key: &[u8]) -> &[u8] {
        let middle = private_key.len() / 2;
        let probe = &private_key[middle..middle + 16];
        assert!(
            contains(private_key, probe),
            "the key-material probe must find itself in the key file it came from"
        );
        assert!(
            !contains(b"-----BEGIN PRIVATE KEY-----\n", probe),
            "the probe must be key bytes, not the shared PEM envelope"
        );
        probe
    }

    fn credential_directory(root: &Path) -> PathBuf {
        root.join(OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME)
    }

    fn directory_entries(root: &Path) -> Vec<String> {
        let mut names: Vec<String> = std::fs::read_dir(credential_directory(root))
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        names.sort();
        names
    }

    #[test]
    fn establish_publishes_root_only_artifacts_and_loads_a_matching_signer() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        let established = establish(root.path(), &control).unwrap();

        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let directory = credential_directory(root.path());
        assert_eq!(
            directory_entries(root.path()),
            {
                let mut expected = vec![
                    names.private_key_file.clone(),
                    names.prepared_file.clone(),
                    names.registered_file.clone(),
                ];
                expected.sort();
                expected
            },
            "only the three contract-declared basenames survive a successful establish"
        );
        for file in [
            &names.private_key_file,
            &names.prepared_file,
            &names.registered_file,
        ] {
            let metadata = std::fs::metadata(directory.join(file)).unwrap();
            assert_eq!(
                metadata.permissions().mode() & 0o7777,
                0o600,
                "{file} must be root-only 0600"
            );
            assert_eq!(metadata.uid(), effective_uid(), "{file} must be root owned");
        }
        assert_eq!(
            std::fs::metadata(&directory).unwrap().permissions().mode() & 0o7777,
            0o700,
            "the credential namespace must not be group or world accessible"
        );

        let loaded = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        assert_eq!(loaded.credential(), established.credential());
        assert_eq!(
            loaded.credential().credential_id,
            names.credential_id,
            "the credential ID is derived from the exact scope"
        );
        assert_eq!(
            loaded.signer().public_key_spki_sha256(),
            loaded.credential().public_key_spki_sha256,
            "the loaded signer holds the registered public key"
        );
        assert_eq!(
            loaded.registered_artifact().receipt.attachment_epoch,
            scope().attachment_epoch
        );
    }

    #[test]
    fn registration_body_carries_the_derived_durability_receipts_and_no_private_key() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        let loaded = establish(root.path(), &control).unwrap();
        let registration = &loaded.registered_artifact().registration;
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();

        assert_eq!(registration.private_artifact_id, names.private_artifact_id);
        let file_receipt = object_write_private_file_fsync_receipt_id(
            &names.private_artifact_id,
            &registration.credential,
        );
        assert_eq!(registration.private_file_fsync_receipt_id, file_receipt);
        assert_eq!(
            registration.private_directory_fsync_receipt_id,
            object_write_private_directory_fsync_receipt_id(
                &names.private_artifact_id,
                &file_receipt
            )
        );

        let private_key =
            std::fs::read(credential_directory(root.path()).join(&names.private_key_file)).unwrap();
        let seed = key_material_probe(&private_key);
        let bodies = control.accepted_bodies();
        assert_eq!(bodies.len(), 1);
        for body in bodies {
            assert!(
                !contains(&body, seed),
                "no private key material may reach the registration wire"
            );
        }
    }

    #[test]
    fn crash_after_the_private_key_barrier_reuses_that_key_instead_of_minting_a_second() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store.inject_crash_once(EstablishStage::PrivateKeyDurable);
        let crashed = store.establish(&scope(), &node_signer(), &control, deadline());
        assert!(matches!(
            crashed,
            Err(ObjectWriteCredentialError::InjectedCrash)
        ));
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let directory = credential_directory(root.path());
        let key_after_crash = std::fs::read(directory.join(&names.private_key_file)).unwrap();
        assert!(
            !directory.join(&names.prepared_file).exists(),
            "the prepared registration must not exist before its private key barrier"
        );
        drop(store);

        let recovered = establish(root.path(), &control).unwrap();
        assert_eq!(
            std::fs::read(directory.join(&names.private_key_file)).unwrap(),
            key_after_crash,
            "recovery must reuse the durable key, never generate a second one"
        );
        assert_eq!(
            control.registered_public_keys().len(),
            1,
            "exactly one public key is ever registered for this attachment epoch"
        );
        assert_eq!(
            recovered.signer().public_key_spki_sha256(),
            recovered.credential().public_key_spki_sha256
        );
    }

    #[test]
    fn crash_after_the_prepared_barrier_replays_the_identical_body() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store.inject_crash_once(EstablishStage::PreparedRegistrationDurable);
        assert!(matches!(
            store.establish(&scope(), &node_signer(), &control, deadline()),
            Err(ObjectWriteCredentialError::InjectedCrash)
        ));
        assert!(
            control.accepted_bodies().is_empty(),
            "no registration is sent before the prepared barrier"
        );
        drop(store);

        assert!(establish(root.path(), &control).is_ok());
        assert_eq!(control.accepted_bodies().len(), 1);
        assert_eq!(control.registered_public_keys().len(), 1);
    }

    #[test]
    fn crash_after_control_registration_replays_and_converges_on_the_same_credential() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store.inject_crash_once(EstablishStage::ControlRegistered);
        assert!(matches!(
            store.establish(&scope(), &node_signer(), &control, deadline()),
            Err(ObjectWriteCredentialError::InjectedCrash)
        ));
        assert_eq!(
            control.accepted_bodies().len(),
            1,
            "Control committed the registration the Node never observed"
        );
        drop(store);
        assert!(
            matches!(
                load(
                    root.path(),
                    &scope().volume_id,
                    &scope().attachment_id,
                    scope().attachment_epoch
                ),
                Err(ObjectWriteCredentialError::NotRegistered)
            ),
            "a credential Control holds but the Node never published is not loadable"
        );

        let recovered = establish(root.path(), &control).unwrap();
        let bodies = control.accepted_bodies();
        assert_eq!(bodies.len(), 2, "recovery replays the registration");
        assert_eq!(
            bodies[0], bodies[1],
            "the replayed body is byte identical, so Control returns the original receipt"
        );
        assert_eq!(control.registered_public_keys().len(), 1);
        let loaded = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        assert_eq!(loaded.credential(), recovered.credential());
    }

    #[test]
    fn an_ambiguous_registration_keeps_local_state_for_the_replay() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        control.fail_next(ObjectWriteCredentialRegistrationFailure::Timeout);

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let error = store
            .establish(&scope(), &node_signer(), &control, deadline())
            .unwrap_err();
        assert!(
            matches!(error, ObjectWriteCredentialError::RegistrationAmbiguous(_)),
            "a timeout is undiscovered, not a decision: {error}"
        );
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let directory = credential_directory(root.path());
        assert!(directory.join(&names.private_key_file).exists());
        assert!(
            directory.join(&names.prepared_file).exists(),
            "an ambiguous attempt must not discard the body it has to replay"
        );
        drop(store);

        let recovered = establish(root.path(), &control).unwrap();
        assert_eq!(control.registered_public_keys().len(), 1);
        assert_eq!(
            recovered.credential().credential_id,
            names.credential_id,
            "the same credential converges after the ambiguity"
        );
    }

    #[test]
    fn retirement_makes_the_private_key_unusable_and_is_idempotent() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store
            .retire(
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch,
            )
            .unwrap();
        drop(store);

        assert!(
            directory_entries(root.path()).is_empty(),
            "retirement leaves no credential residue"
        );
        assert!(matches!(
            load(
                root.path(),
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch
            ),
            Err(ObjectWriteCredentialError::NotRegistered)
        ));

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store
            .retire(
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch,
            )
            .expect("retiring an already retired attachment succeeds");
    }

    #[test]
    fn a_crash_during_retirement_still_leaves_the_private_key_gone() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let directory = credential_directory(root.path());

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store.inject_crash_once(RetireStage::PrivateKeyDestroyed);
        assert!(matches!(
            store.retire(
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch
            ),
            Err(ObjectWriteCredentialError::InjectedCrash)
        ));
        drop(store);

        assert!(!directory.join(&names.private_key_file).exists());
        assert!(
            directory.join(&names.prepared_file).exists(),
            "the interrupted retirement is mid-flight, not undone"
        );
        assert!(matches!(
            load(
                root.path(),
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch
            ),
            Err(ObjectWriteCredentialError::NotRegistered)
        ));

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store
            .retire(
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch,
            )
            .unwrap();
        drop(store);
        assert!(directory_entries(root.path()).is_empty());
    }

    #[test]
    fn a_replacement_agent_session_destroys_the_superseded_credential() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        let first = establish(root.path(), &control).unwrap();
        let first_names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();

        let replacement = scope_for_session(session(8));
        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let second = store
            .establish(&replacement, &node_signer(), &control, deadline())
            .unwrap();
        drop(store);

        assert_ne!(
            second.credential().credential_id,
            first.credential().credential_id,
            "a new Agent session mints a new credential identity"
        );
        let directory = credential_directory(root.path());
        assert!(
            !directory.join(&first_names.private_key_file).exists(),
            "the superseded private key must not survive as residue"
        );
        assert!(
            !directory.join(&first_names.registered_file).exists(),
            "the superseded registered artifact must not survive"
        );
        let loaded = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        assert_eq!(loaded.credential(), second.credential());
    }

    #[test]
    fn a_sidecar_claiming_another_attachment_cannot_destroy_that_credential() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();

        // Establish a credential for a neighbouring attachment, then forge this
        // attachment's sidecar so it names the neighbour.
        let victim = ObjectWriteCredentialScope {
            attachment_id: id("attachment_b"),
            ..scope()
        };
        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        store
            .establish(&victim, &node_signer(), &control, deadline())
            .unwrap();
        drop(store);
        let victim_names = CredentialNames::derive(
            &victim.session,
            &victim.volume_id,
            &victim.attachment_id,
            victim.attachment_epoch,
        )
        .unwrap();
        let directory = credential_directory(root.path());
        let forged = std::fs::read(directory.join(&victim_names.prepared_file)).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let forged_path = directory.join(&names.prepared_file);
        std::fs::write(&forged_path, forged).unwrap();
        // The forgery has to clear the ownership and mode gate to reach the
        // attachment check this test is about.
        std::fs::set_permissions(&forged_path, std::fs::Permissions::from_mode(0o600)).unwrap();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let error = store
            .establish(&scope(), &node_signer(), &control, deadline())
            .unwrap_err();
        assert!(
            matches!(
                error,
                ObjectWriteCredentialError::Corrupt {
                    reason: "superseded registration names another attachment",
                    ..
                }
            ),
            "a forged sidecar may not authorize destroying another attachment: {error}"
        );
        drop(store);
        assert!(
            directory.join(&victim_names.private_key_file).exists(),
            "the neighbouring attachment keeps its private key"
        );
        assert!(directory.join(&victim_names.registered_file).exists());
        load(
            root.path(),
            &victim.volume_id,
            &victim.attachment_id,
            victim.attachment_epoch,
        )
        .expect("the neighbouring credential is still usable");
    }

    #[test]
    fn load_fails_closed_on_a_tampered_prepared_registration() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let prepared_path = credential_directory(root.path()).join(&names.prepared_file);

        let mut registration =
            decode_object_write_credential_registration(&std::fs::read(&prepared_path).unwrap())
                .unwrap();
        registration.private_artifact_id = id("owpriv1_forged");
        std::fs::write(
            &prepared_path,
            cats_api::object_write_gateway::encode_object_write_credential_registration(
                &registration,
            )
            .unwrap(),
        )
        .unwrap();

        let error = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ObjectWriteCredentialError::Corrupt {
                    reason: "prepared registration claims underived identifiers",
                    ..
                }
            ),
            "a sidecar may never steer a read at an underived path: {error}"
        );
    }

    #[test]
    fn load_fails_closed_when_the_registered_artifact_is_absent() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        std::fs::remove_file(credential_directory(root.path()).join(&names.registered_file))
            .unwrap();

        assert!(matches!(
            load(
                root.path(),
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch
            ),
            Err(ObjectWriteCredentialError::NotRegistered)
        ));
    }

    #[test]
    fn establish_republishes_a_lost_sidecar_so_the_seam_can_still_load() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        std::fs::remove_file(credential_directory(root.path()).join(&names.prepared_file)).unwrap();
        assert!(
            matches!(
                load(
                    root.path(),
                    &scope().volume_id,
                    &scope().attachment_id,
                    scope().attachment_epoch
                ),
                Err(ObjectWriteCredentialError::NotRegistered)
            ),
            "without its sidecar the credential is not reachable by attachment locator"
        );

        let recovered = establish(root.path(), &control).unwrap();
        assert_eq!(
            control.accepted_bodies().len(),
            1,
            "an already registered credential needs no second Control call"
        );
        let loaded = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .expect("establish must leave the seam able to load");
        assert_eq!(loaded.credential(), recovered.credential());
    }

    #[test]
    fn a_group_readable_private_key_is_rejected() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let key_path = credential_directory(root.path()).join(&names.private_key_file);
        std::fs::set_permissions(&key_path, std::fs::Permissions::from_mode(0o640)).unwrap();

        let error = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap_err();
        assert!(
            matches!(
                error,
                ObjectWriteCredentialError::UnsafeEntry {
                    reason: "file is not root-only 0600",
                    ..
                }
            ),
            "a widened private key must not produce a signer: {error}"
        );
    }

    #[test]
    fn a_receipt_that_rebinds_the_writer_authority_is_rejected() {
        struct RebindingControl;

        impl ObjectWriteCredentialRegistrar for RebindingControl {
            fn register(
                &self,
                proof: &ObjectWriteCredentialRegistrationProof,
                _deadline: Instant,
            ) -> Result<
                ObjectWriteCredentialRegistrationReceipt,
                ObjectWriteCredentialRegistrationFailure,
            > {
                let registration =
                    decode_object_write_credential_registration(&proof.body).unwrap();
                Ok(ObjectWriteCredentialRegistrationReceipt {
                    version: ContractVersion::V1,
                    writer_authority_id: id("writer_b"),
                    volume_id: registration.volume_id,
                    attachment_id: registration.attachment_id,
                    attachment_epoch: registration.attachment_epoch,
                    credential: registration.credential,
                    registered_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
                })
            }
        }

        let root = TempDir::new().unwrap();
        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let error = store
            .establish(&scope(), &node_signer(), &RebindingControl, deadline())
            .unwrap_err();
        assert!(
            matches!(error, ObjectWriteCredentialError::Rejected(ref message)
                if message.contains("writer authority")),
            "a receipt may not move the credential to another writer authority: {error}"
        );
        drop(store);
        assert!(matches!(
            load(
                root.path(),
                &scope().volume_id,
                &scope().attachment_id,
                scope().attachment_epoch
            ),
            Err(ObjectWriteCredentialError::NotRegistered)
        ));
    }

    #[test]
    fn a_durable_registration_without_its_private_key_fails_closed() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        std::fs::remove_file(credential_directory(root.path()).join(&names.private_key_file))
            .unwrap();

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let error = store
            .establish(&scope(), &node_signer(), &control, deadline())
            .unwrap_err();
        assert!(
            matches!(
                error,
                ObjectWriteCredentialError::Corrupt {
                    reason: "durable registration has no private key",
                    ..
                }
            ),
            "a registered credential with no key must not be re-minted: {error}"
        );
        assert_eq!(
            control.accepted_bodies().len(),
            1,
            "the failure must not register a replacement key for this epoch"
        );
    }

    #[test]
    fn a_second_writer_cannot_open_the_namespace() {
        let root = TempDir::new().unwrap();
        let held = ObjectWriteCredentialStore::open(root.path()).unwrap();
        let error = ObjectWriteCredentialStore::open(root.path()).unwrap_err();
        assert!(
            matches!(
                error,
                ObjectWriteCredentialError::WriterAlreadyActive { .. }
            ),
            "two credential writers may never run at once: {error}"
        );
        drop(held);
        ObjectWriteCredentialStore::open(root.path()).expect("the lock is released with the store");
    }

    #[test]
    fn the_http_registrar_sends_both_proofs_and_never_the_private_key() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        let loaded = establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let private_key =
            std::fs::read(credential_directory(root.path()).join(&names.private_key_file)).unwrap();

        let node = node_signer();
        let proof = sign_object_write_credential_registration(
            &node,
            loaded.signer(),
            &loaded.registered_artifact().registration,
        )
        .unwrap();
        let receipt_body =
            cats_api::object_write_gateway::encode_object_write_credential_registration_receipt(
                &ObjectWriteCredentialRegistrationReceipt {
                    version: ContractVersion::V1,
                    writer_authority_id: scope().writer_authority_id,
                    volume_id: scope().volume_id,
                    attachment_id: scope().attachment_id,
                    attachment_epoch: scope().attachment_epoch,
                    credential: loaded.credential().clone(),
                    registered_at_unix_ms: UnixMillis::new(1_720_000_000_000).unwrap(),
                },
            )
            .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = HashMap::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                let name = name.to_ascii_lowercase();
                if name == "content-length" {
                    content_length = value.trim().parse().unwrap();
                }
                headers.insert(name, value.trim().to_owned());
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = reader.into_inner();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                        receipt_body.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.write_all(&receipt_body).unwrap();
            (request_line, headers, body)
        });

        let registrar =
            ObjectWriteCredentialHttpRegistrar::for_loopback_test(&format!("http://{address}/"))
                .unwrap();
        let receipt = registrar.register(&proof, deadline()).unwrap();
        let (request_line, headers, body) = server.join().unwrap();

        assert_eq!(receipt.credential, *loaded.credential());
        assert!(request_line.starts_with(&format!(
            "POST {OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH} "
        )));
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some(OBJECT_WRITE_CREDENTIAL_REGISTRATION_CONTENT_TYPE)
        );
        assert_eq!(body, proof.body);
        verify_request_proof(
            OBJECT_WRITE_GATEWAY_METHOD,
            OBJECT_WRITE_CREDENTIAL_REGISTRATION_PATH,
            &body,
            headers.get(NODE_CREDENTIAL_ID_HEADER).unwrap(),
            headers.get(NODE_PUBLIC_KEY_SPKI_HEADER).unwrap(),
            headers.get(NODE_SIGNATURE_HEADER).unwrap(),
        )
        .expect("the A19 node proof travels in the frozen headers");
        verify_object_write_credential_registration(
            &body,
            &cats_api::agent_registration::NodeRequestProof {
                credential_id: headers.get(NODE_CREDENTIAL_ID_HEADER).unwrap().clone(),
                public_key_spki: headers.get(NODE_PUBLIC_KEY_SPKI_HEADER).unwrap().clone(),
                signature: headers.get(NODE_SIGNATURE_HEADER).unwrap().clone(),
            },
            &cats_api::agent_registration::NodeRequestProof {
                credential_id: headers
                    .get(OBJECT_WRITE_CREDENTIAL_ID_HEADER)
                    .unwrap()
                    .clone(),
                public_key_spki: headers
                    .get(OBJECT_WRITE_PUBLIC_KEY_SPKI_HEADER)
                    .unwrap()
                    .clone(),
                signature: headers.get(OBJECT_WRITE_SIGNATURE_HEADER).unwrap().clone(),
            },
        )
        .expect("Control's own verifier accepts what the Node sent");

        let seed = key_material_probe(&private_key);
        assert!(!contains(&body, seed));
        for value in headers.values() {
            assert!(!contains(value.as_bytes(), seed));
        }
    }

    /// A fixed self-signed root, standing in for the deployment's Route v2 root.
    const TEST_SERVER_ROOT_PEM: &str = "\
-----BEGIN CERTIFICATE-----\n\
MIIBYzCCARWgAwIBAgIULICwc/RLnF4bSmGzzr94Ux2eOTIwBQYDK2VwMCYxJDAi\n\
BgNVBAMMG0NhdHMgb2JqZWN0LXdyaXRlIHRlc3Qgcm9vdDAgFw0yNjA4MTgxMTAx\n\
NTZaGA8yMTI2MDcyNTExMDE1NlowJjEkMCIGA1UEAwwbQ2F0cyBvYmplY3Qtd3Jp\n\
dGUgdGVzdCByb290MCowBQYDK2VwAyEA1NilIB8rScb67W7/kKsQ7WB/zvZaT1BG\n\
f2zFVOq+kZOjUzBRMB0GA1UdDgQWBBQkQswCbzxcDl5pz/rGPiUdFSpISDAfBgNV\n\
HSMEGDAWgBQkQswCbzxcDl5pz/rGPiUdFSpISDAPBgNVHRMBAf8EBTADAQH/MAUG\n\
AytlcANBAD1/4EhOQ+aymAJVDBlUSZR9rfAwzGDkp3HohSGR+goWZV++BRdaMN/a\n\
AOyU0kuaUva+bGyoQ8A95rEzSQMTmw4=\n\
-----END CERTIFICATE-----\n";

    #[test]
    fn a_production_registrar_refuses_a_plaintext_origin() {
        let roots = TEST_SERVER_ROOT_PEM.as_bytes();
        assert!(
            ObjectWriteCredentialHttpRegistrar::for_production("http://127.0.0.1:9/", roots)
                .is_err()
        );
        assert!(ObjectWriteCredentialHttpRegistrar::for_production(
            "https://control.example/v1/internal/",
            roots
        )
        .is_err());
        assert!(ObjectWriteCredentialHttpRegistrar::for_production(
            "https://control.example/",
            roots
        )
        .is_ok());
    }

    /// The gateway is certified by the deployment's own root, so a registrar
    /// built without a usable one is a startup refusal. Without this the client
    /// silently keeps the public trust store and can never reach the gateway,
    /// which the grant path then reports only as an endless exact retry.
    #[test]
    fn a_production_registrar_requires_usable_server_roots() {
        for unusable in [
            b"".as_slice(),
            b"-----BEGIN CERTIFICATE-----\nnot base64\n-----END CERTIFICATE-----\n".as_slice(),
        ] {
            assert!(
                ObjectWriteCredentialHttpRegistrar::for_production(
                    "https://gateway.example/",
                    unusable
                )
                .is_err(),
                "an unusable PEM bundle must fail closed"
            );
        }
    }

    #[test]
    fn errors_never_render_private_key_material() {
        let root = TempDir::new().unwrap();
        let control = ReplayingControl::default();
        establish(root.path(), &control).unwrap();
        let names = CredentialNames::derive(
            &scope().session,
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap();
        let key_path = credential_directory(root.path()).join(&names.private_key_file);
        let private_key = std::fs::read(&key_path).unwrap();
        std::fs::write(&key_path, b"-----BEGIN PRIVATE KEY-----\nbroken\n").unwrap();

        let error = load(
            root.path(),
            &scope().volume_id,
            &scope().attachment_id,
            scope().attachment_epoch,
        )
        .unwrap_err();
        let rendered = format!("{error} {error:?}");
        assert!(!contains(
            rendered.as_bytes(),
            key_material_probe(&private_key)
        ));
        assert!(matches!(
            error,
            ObjectWriteCredentialError::Corrupt {
                reason: "private key is not a canonical PKCS#8 v2 Ed25519 key",
                ..
            }
        ));

        let store = ObjectWriteCredentialStore::open(root.path()).unwrap();
        assert!(format!("{store:?}").find("PRIVATE KEY").is_none());
    }

    fn port_for_test(root: &Path, control: Arc<ReplayingControl>) -> NodeObjectWriteCredentials {
        port_with_authority(root, control, RecordingAuthorityReader::open())
    }

    fn port_with_authority(
        root: &Path,
        control: Arc<ReplayingControl>,
        authority: Arc<RecordingAuthorityReader>,
    ) -> NodeObjectWriteCredentials {
        NodeObjectWriteCredentials::with_registrar_for_test(
            root.to_path_buf(),
            "https://gateway.invalid",
            node_signer(),
            control,
            authority,
        )
    }

    /// Private-key files under the credential namespace. A namespace that was
    /// never created counts as none: it is the stronger form of "no key was
    /// minted", so a fail-closed assertion must accept it.
    fn private_key_files(root: &Path) -> Vec<String> {
        if !credential_directory(root).exists() {
            return Vec::new();
        }
        directory_entries(root)
            .into_iter()
            .filter(|name| {
                name.ends_with(cats_api::object_write_gateway::OBJECT_WRITE_PRIVATE_KEY_FILE_SUFFIX)
            })
            .collect()
    }

    /// Crash point 1: the Node registered a credential but died before the
    /// grant that would have bound it. The next attempt for the same epoch
    /// must adopt that same credential, not mint a second live one.
    #[test]
    fn re_establishing_after_a_crash_before_binding_adopts_the_same_credential() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        let port = port_for_test(root.path(), Arc::clone(&control));
        let scope = scope();

        let first = port
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        // The crash is between `establish` and the caller binding `first`.
        let second = port
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();

        assert_eq!(first, second);
        assert_eq!(
            private_key_files(root.path()).len(),
            1,
            "one attachment epoch may never hold two live credentials"
        );
        assert_eq!(
            control.registered_public_keys().len(),
            1,
            "Control must hold exactly one credential for this epoch"
        );
    }

    /// Crash point 2: the attachment was dropped but the credential outlived
    /// it. Retiring converges, denies a signer and stays idempotent.
    #[test]
    fn retiring_a_dropped_attachment_denies_a_signer_and_repeats_cleanly() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        let port = port_for_test(root.path(), Arc::clone(&control));
        let scope = scope();
        port.establish(
            &scope.session,
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
            Instant::now() + Duration::from_secs(5),
        )
        .unwrap();
        // Calibration: before retirement this exact load succeeds, so the
        // failure asserted below cannot be an artefact of a broken lookup.
        load(
            root.path(),
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
        )
        .expect("a live credential must load before it is retired");

        port.retire(
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
        )
        .unwrap();

        assert!(matches!(
            load(
                root.path(),
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
            ),
            Err(ObjectWriteCredentialError::NotRegistered)
        ));
        assert!(private_key_files(root.path()).is_empty());
        port.retire(
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
        )
        .expect("retiring an already retired epoch succeeds");
    }

    /// blockd validates that the final path component is the credential
    /// namespace basename and refuses to start otherwise.
    #[test]
    fn credential_directory_names_the_namespace_not_the_state_root() {
        let root = TempDir::new().unwrap();
        let port = port_for_test(root.path(), Arc::new(ReplayingControl::default()));
        let directory = port.credential_directory();
        assert_eq!(
            directory.file_name().unwrap(),
            OBJECT_WRITE_CREDENTIAL_DIRECTORY_BASENAME
        );
        assert_eq!(directory.parent().unwrap(), root.path());
        assert!(directory.is_absolute());
    }

    /// The value the reconciler binds into an attachment, and the value it
    /// would log on failure, must never carry key material.
    #[test]
    fn the_port_publishes_no_private_key_material() {
        let root = TempDir::new().unwrap();
        let port = port_for_test(root.path(), Arc::new(ReplayingControl::default()));
        let scope = scope();
        let credential = port
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap();
        let key_path = credential_directory(root.path()).join(
            private_key_files(root.path())
                .first()
                .expect("one private key exists"),
        );
        let private_key = std::fs::read(&key_path).unwrap();
        let probe = key_material_probe(&private_key);

        let published = format!(
            "{credential:?} {:?} {}",
            port,
            port.retire(
                &scope.volume_id,
                &scope.attachment_id,
                FenceEpoch::new(1).unwrap()
            )
            .err()
            .map(|error| error.to_string())
            .unwrap_or_default()
        );
        assert!(!contains(published.as_bytes(), probe));
        assert!(!contains(
            serde_json::to_vec(&credential).unwrap().as_slice(),
            probe
        ));
    }

    /// An unusable Control decision is never downgraded into "no credential".
    #[test]
    fn a_refused_registration_yields_no_credential_at_all() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        control.fail_next(ObjectWriteCredentialRegistrationFailure::Closed { status: 403 });
        let port = port_for_test(root.path(), Arc::clone(&control));
        let scope = scope();
        let error = port
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                Instant::now() + Duration::from_secs(5),
            )
            .unwrap_err();
        assert!(error.to_string().contains("volume_a"));
        // Calibration: the same port with the same scope succeeds once Control
        // stops refusing, so the error above is the refusal and not the setup.
        port.establish(
            &scope.session,
            &scope.volume_id,
            &scope.attachment_id,
            scope.attachment_epoch,
            Instant::now() + Duration::from_secs(5),
        )
        .expect("the identical scope registers once Control accepts");
    }

    /// The authority ID is derived from the Node ID, so it cannot travel in the
    /// fleet-shared worker environment. It is read from Control once for the
    /// Agent session, not once per attachment: two attachments in one session
    /// must produce exactly one read, and a replacement session must re-read
    /// rather than inherit the previous answer.
    #[test]
    fn the_writer_authority_is_read_once_per_agent_session_not_per_attachment() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        let authority = RecordingAuthorityReader::open();
        let port = port_with_authority(root.path(), control, Arc::clone(&authority));
        let first_session = session(7);
        let replacement_session = session(8);

        for attachment in ["attachment_a", "attachment_b"] {
            port.establish(
                &first_session,
                &id("volume_a"),
                &id(attachment),
                FenceEpoch::new(9).unwrap(),
                deadline(),
            )
            .expect("an open writer authority credentials every attachment of its session");
        }
        assert_eq!(
            authority.reads(),
            vec![first_session.clone()],
            "two attachments of one session must not each ask Control",
        );

        port.establish(
            &replacement_session,
            &id("volume_a"),
            &id("attachment_a"),
            FenceEpoch::new(10).unwrap(),
            deadline(),
        )
        .expect("a replacement session resolves its own authority");
        assert_eq!(
            authority.reads(),
            vec![first_session, replacement_session],
            "a replacement Agent session must re-read rather than inherit",
        );
    }

    /// An operator has not opened this Host's authority yet. There is nothing to
    /// register under and nothing to fall back to, so no key may be minted and
    /// no registration may be attempted.
    #[test]
    fn an_absent_writer_authority_fails_the_credential_path_closed() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        let absent =
            RecordingAuthorityReader::answering(Ok(ObjectWriteWriterAuthorityStateV1::Absent));
        let port = port_with_authority(root.path(), Arc::clone(&control), absent);
        let scope = scope();

        let error = port
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                deadline(),
            )
            .unwrap_err();
        let rendered = error.to_string();
        assert!(
            rendered.contains("no object-write writer authority"),
            "an absent authority must name the missing provisioning step: {rendered}"
        );
        assert!(
            control.accepted_bodies().is_empty(),
            "an absent authority must not reach Control's registration route"
        );
        assert!(
            private_key_files(root.path()).is_empty(),
            "an absent authority must not mint an attachment key"
        );

        // Calibration: the same root, control and attachment succeed as soon as
        // Control reports an open authority, so the refusal above is the
        // authority state and not a broken establish path.
        let opened = port_with_authority(
            root.path(),
            Arc::clone(&control),
            RecordingAuthorityReader::open(),
        );
        opened
            .establish(
                &scope.session,
                &scope.volume_id,
                &scope.attachment_id,
                scope.attachment_epoch,
                deadline(),
            )
            .expect("an open authority credentials this exact attachment");
        assert_eq!(control.accepted_bodies().len(), 1);
    }

    /// A cut-off writer may never take a new credential: its accepted-sequence
    /// prefix is being sealed, and publishing under it after the cutoff is
    /// exactly the fence this authority exists to enforce.
    #[test]
    fn a_cut_off_writer_authority_fails_the_credential_path_closed() {
        for state in [
            ObjectWriteWriterAuthorityStateV1::CutoffPending {
                writer_authority_id: assigned_writer_authority_id(),
            },
            ObjectWriteWriterAuthorityStateV1::CutoffComplete {
                writer_authority_id: assigned_writer_authority_id(),
            },
        ] {
            let expected = state.state_name();
            let root = TempDir::new().unwrap();
            let control = Arc::new(ReplayingControl::default());
            let port = port_with_authority(
                root.path(),
                Arc::clone(&control),
                RecordingAuthorityReader::answering(Ok(state)),
            );
            let scope = scope();

            let error = port
                .establish(
                    &scope.session,
                    &scope.volume_id,
                    &scope.attachment_id,
                    scope.attachment_epoch,
                    deadline(),
                )
                .unwrap_err();
            let rendered = error.to_string();
            assert!(
                rendered.contains(expected),
                "a {expected} authority must say so: {rendered}"
            );
            assert!(
                control.accepted_bodies().is_empty(),
                "a {expected} authority must not reach Control's registration route"
            );
            assert!(
                private_key_files(root.path()).is_empty(),
                "a {expected} authority must not mint an attachment key"
            );
        }
    }

    /// An unsettled read is not an answer. It must not be cached, guessed or
    /// replaced by a locally derived ID, and it must leave no local residue.
    #[test]
    fn an_unsettled_writer_authority_read_leaves_no_credential_and_no_cached_answer() {
        let root = TempDir::new().unwrap();
        let control = Arc::new(ReplayingControl::default());
        let refusing = RecordingAuthorityReader::answering(Err(
            ObjectWriteWriterAuthorityReadFailure::Closed { status: 403 },
        ));
        let port = port_with_authority(root.path(), Arc::clone(&control), Arc::clone(&refusing));
        let scope = scope();

        for _ in 0..2 {
            let error = port
                .establish(
                    &scope.session,
                    &scope.volume_id,
                    &scope.attachment_id,
                    scope.attachment_epoch,
                    deadline(),
                )
                .unwrap_err();
            assert!(
                error.to_string().contains("status 403"),
                "the closed status must reach the operator: {error}"
            );
        }
        assert_eq!(
            refusing.reads().len(),
            2,
            "a failed read may not be cached as an answer"
        );
        assert!(control.accepted_bodies().is_empty());
        assert!(private_key_files(root.path()).is_empty());
    }

    /// The production reader signs the exact method, path and canonical body
    /// with the A19 Node credential, and refuses a view bound to any other
    /// session.
    #[test]
    fn the_http_authority_reader_signs_its_exact_request_and_refuses_another_session() {
        let served_session = session(7);
        let other_session = session(8);
        let view_body = cats_api::object_write_gateway::encode_object_write_writer_authority_view(
            &cats_api::object_write_gateway::ObjectWriteWriterAuthorityView {
                version: ContractVersion::V1,
                session: other_session,
                authority: ObjectWriteWriterAuthorityStateV1::Open {
                    writer_authority_id: assigned_writer_authority_id(),
                },
            },
        )
        .unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let served = view_body.clone();
        let server = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream);
            let mut request_line = String::new();
            reader.read_line(&mut request_line).unwrap();
            let mut headers = HashMap::new();
            let mut content_length = 0;
            loop {
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                if line == "\r\n" {
                    break;
                }
                let (name, value) = line.trim_end().split_once(':').unwrap();
                let name = name.to_ascii_lowercase();
                if name == "content-length" {
                    content_length = value.trim().parse().unwrap();
                }
                headers.insert(name, value.trim().to_owned());
            }
            let mut body = vec![0; content_length];
            reader.read_exact(&mut body).unwrap();
            let mut stream = reader.into_inner();
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\ncontent-length: {}\r\n\r\n",
                        served.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
            stream.write_all(&served).unwrap();
            (request_line, headers, body)
        });

        let reader = ObjectWriteWriterAuthorityHttpReader::for_loopback_test(
            &format!("http://{address}/"),
            node_signer(),
        )
        .unwrap();
        let failure = reader.read(&served_session, deadline()).unwrap_err();
        let (request_line, headers, body) = server.join().unwrap();

        assert_eq!(
            failure,
            ObjectWriteWriterAuthorityReadFailure::SessionMismatch,
            "a view for another session is never this Node's answer"
        );
        assert!(
            request_line.starts_with(&format!("POST {OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH} "))
        );
        assert_eq!(
            body,
            encode_object_write_writer_authority_read(&ObjectWriteWriterAuthorityRead {
                version: ContractVersion::V1,
                session: served_session,
            })
            .unwrap(),
            "the request body is the canonical read for this Node's own session"
        );
        verify_request_proof(
            OBJECT_WRITE_GATEWAY_METHOD,
            OBJECT_WRITE_WRITER_AUTHORITY_READ_PATH,
            &body,
            headers.get(NODE_CREDENTIAL_ID_HEADER).unwrap(),
            headers.get(NODE_PUBLIC_KEY_SPKI_HEADER).unwrap(),
            headers.get(NODE_SIGNATURE_HEADER).unwrap(),
        )
        .expect("the A19 node proof covers the exact authority-read path and body");
    }

    #[test]
    fn a_production_authority_reader_refuses_a_plaintext_origin() {
        assert!(ObjectWriteWriterAuthorityHttpReader::for_production(
            "http://127.0.0.1:9/",
            node_signer()
        )
        .is_err());
        assert!(ObjectWriteWriterAuthorityHttpReader::for_production(
            "https://control.example/v1",
            node_signer()
        )
        .is_err());
        assert!(ObjectWriteWriterAuthorityHttpReader::for_production(
            "https://control.example/",
            node_signer()
        )
        .is_ok());
    }
}
