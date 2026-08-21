//! One bounded, atomic lifecycle-command journal per Cat.
//!
//! This store is intentionally not an append ledger.  The single current
//! record contains the accepted command, its resumable execution step (and
//! optional embedded Stop fence), or its exact terminal result.  A successful
//! Delete replaces that executable record with one minimal, non-executable
//! completed receipt.  An exact Control acknowledgement is the only operation
//! which may unlink that receipt.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cats_api::runtime_inventory::{
    ObservedArtifactClassification, ObservedCatRuntimeTelemetry,
    RUNTIME_INVENTORY_MAX_ARTIFACTS_PER_CAT, RUNTIME_INVENTORY_MAX_CATS,
    RUNTIME_INVENTORY_MAX_CONDITIONS_PER_CAT, RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS,
    RUNTIME_INVENTORY_MAX_VOLUMES_PER_CAT,
};
pub use cats_api::runtime_lifecycle::LifecycleCommandKind;
use cats_api::runtime_lifecycle::{
    decode_lifecycle_command_envelope, decode_lifecycle_command_response,
    encode_lifecycle_command_envelope, encode_lifecycle_command_response,
    lifecycle_terminal_result_digest, validate_completed_command_receipt,
    validate_lifecycle_command_query, validate_lifecycle_command_response_for_command,
    validate_lifecycle_initial_target_admission, validate_lifecycle_result_stored_ack_for_response,
    validate_lifecycle_successor_with_predecessor_command, CompletedCommandReceipt,
    LifecycleCommandEnvelope, LifecycleCommandQuery, LifecycleCommandResponse,
    LifecyclePredecessor, LifecycleResultStoredAck, LifecycleTerminalResult, NodeResult,
    LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES, LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{Id, RandomId128, Sha256Digest, UnixMillis};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::state_directory::StateDirectory;

const JOURNAL_VERSION: u64 = 1;
// The shared command/response may itself be 1 MiB. It is retained as
// base64url inside the atomic outer record together with bounded recovery
// state, so the file cap must cover that deterministic expansion without
// narrowing the protocol.
// A terminal successor can simultaneously retain one canonical command, its
// own canonical result, and the immediately preceding canonical result. Each
// shared value is at most 1 MiB and ExactBytes expands as base64url in this
// JSON document, so 6 MiB covers that closed three-value shape plus metadata.
const JOURNAL_MAX_BYTES: usize = 6 * 1024 * 1024;
const COMMAND_PAYLOAD_MAX_BYTES: usize = LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES;
const EXECUTION_PAYLOAD_MAX_BYTES: usize = 512 * 1024;
const RESULT_MAX_BYTES: usize = LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES;
const CHECKPOINT_CONTENT_DIGEST_DOMAIN: &[u8] = b"cats.atomic-lifecycle.checkpoint.v1";

const TARGET_SUFFIX: &str = ".lifecycle-command.json";
const LOCK_SUFFIX: &str = ".lifecycle-command.lock";
const TEMP_SUFFIX: &str = ".lifecycle-command.tmp";
pub const LIFECYCLE_JOURNAL_DIRECTORY_NAME: &str = "lifecycle-command-journal";

/// Exact opaque bytes retained without JSON normalization.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExactBytes(Vec<u8>);

impl ExactBytes {
    pub fn new(bytes: impl Into<Vec<u8>>) -> Self {
        Self(bytes.into())
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0
    }
}

impl Serialize for ExactBytes {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&URL_SAFE_NO_PAD.encode(&self.0))
    }
}

impl<'de> Deserialize<'de> for ExactBytes {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        let decoded = URL_SAFE_NO_PAD
            .decode(&encoded)
            .map_err(serde::de::Error::custom)?;
        if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
            return Err(serde::de::Error::custom(
                "exact bytes are not canonical base64url without padding",
            ));
        }
        Ok(Self(decoded))
    }
}

/// Bounded local projection of the canonical API predecessor. It exists only
/// to compare the current local terminal high-watermark without teaching the
/// journal the protocol's typed predecessor state machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(crate) enum ExpectedLifecyclePredecessor {
    Genesis,
    Terminal {
        operation_id: Id,
        result_digest: Sha256Digest,
    },
}

/// One canonical command admitted by Control. The opaque request bytes bind
/// placement and typed predecessor details which this storage layer does not
/// interpret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JournalCommandProjection {
    pub(crate) cat_id: Id,
    pub(crate) operation_id: Id,
    pub(crate) request_fingerprint: Sha256Digest,
    pub(crate) command_kind: LifecycleCommandKind,
    pub(crate) expected_predecessor: ExpectedLifecyclePredecessor,
    pub(crate) canonical_request: ExactBytes,
}

impl JournalCommandProjection {
    /// Losslessly retain the shared canonical request. All identity fields in
    /// this storage projection are derived from that already-validated API
    /// value and checked again whenever the journal is decoded.
    pub fn from_api(request: &LifecycleCommandEnvelope) -> Result<Self, LifecycleJournalError> {
        let canonical_request = encode_lifecycle_command_envelope(request).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-request>"),
                format!("canonical API request rejected: {source}"),
            )
        })?;
        Ok(Self {
            cat_id: request.cat_id.clone(),
            operation_id: request.operation_id.clone(),
            request_fingerprint: request.request_fingerprint.clone(),
            command_kind: request.command_kind(),
            expected_predecessor: api_predecessor_high_watermark(&request.predecessor),
            canonical_request: ExactBytes::new(canonical_request),
        })
    }

    pub fn decode_api(&self) -> Result<LifecycleCommandEnvelope, LifecycleJournalError> {
        decode_lifecycle_command_envelope(self.canonical_request.as_slice()).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-request>"),
                format!("decode canonical API request: {source}"),
            )
        })
    }

    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn operation_id(&self) -> &Id {
        &self.operation_id
    }

    pub fn request_fingerprint(&self) -> &Sha256Digest {
        &self.request_fingerprint
    }

    pub const fn command_kind(&self) -> LifecycleCommandKind {
        self.command_kind
    }
}

/// Opaque, command-private recovery state for one bounded execution step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecutionStep {
    pub name: Id,
    pub recovery_payload: ExactBytes,
}

/// The strong Stop barrier is part of the same atomic record. It is never a
/// second file or a separately advancing authority.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EmbeddedStopFence {
    fence_payload: ExactBytes,
    state: EmbeddedStopFenceState,
}

/// Durable lifecycle of the embedded negative-execution barrier. Same-node
/// Start clears it only while atomically accepting the exact successor;
/// successful Cold preserves it as a non-executable source tombstone.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EmbeddedStopFenceState {
    Installed,
    ConvertedToColdTombstone,
}

/// Unforgeable in-process capability returned only after an embedded Stop
/// fence is durably current. Its private binding prevents physical Stop ports
/// from accepting an arbitrary caller-constructed payload as authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableStopFence {
    cat_id: Id,
    operation_id: Id,
    record_content_digest: Sha256Digest,
    fence_digest: Sha256Digest,
}

impl DurableStopFence {
    pub fn cat_id(&self) -> &Id {
        &self.cat_id
    }

    pub fn operation_id(&self) -> &Id {
        &self.operation_id
    }
}

/// Exact canonical terminal response bytes plus the shared protocol's
/// domain-separated digest over `LifecycleTerminalResult`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactCommandResult {
    result_bytes: ExactBytes,
    result_digest: Sha256Digest,
}

impl ExactCommandResult {
    /// Losslessly retain the shared canonical result envelope and its
    /// protocol-defined domain-separated digest.
    pub fn from_api(result: &LifecycleCommandResponse) -> Result<Self, LifecycleJournalError> {
        let result_bytes = encode_lifecycle_command_response(result).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-response>"),
                format!("canonical API result rejected: {source}"),
            )
        })?;
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(result.clone()),
        };
        let result_digest = lifecycle_terminal_result_digest(&terminal).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-response>"),
                format!("canonical API terminal digest rejected: {source}"),
            )
        })?;
        Ok(Self {
            result_bytes: ExactBytes::new(result_bytes),
            result_digest,
        })
    }

    pub fn decode_api(&self) -> Result<LifecycleCommandResponse, LifecycleJournalError> {
        let result =
            decode_lifecycle_command_response(self.result_bytes.as_slice()).map_err(|source| {
                invalid_record(
                    Path::new("<lifecycle-command-response>"),
                    format!("decode canonical API result: {source}"),
                )
            })?;
        let terminal = LifecycleTerminalResult::NodeResult {
            response: Box::new(result.clone()),
        };
        let expected_digest = lifecycle_terminal_result_digest(&terminal).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-response>"),
                format!("validate canonical API terminal digest: {source}"),
            )
        })?;
        if expected_digest != self.result_digest {
            return Err(invalid_record(
                Path::new("<lifecycle-command-response>"),
                "stored result digest differs from shared canonical terminal digest",
            ));
        }
        Ok(result)
    }

    pub fn result_digest(&self) -> &Sha256Digest {
        &self.result_digest
    }

    pub fn result_bytes(&self) -> &[u8] {
        self.result_bytes.as_slice()
    }
}

/// The only mutable command states. A terminal state is immutable; accepting
/// its exact successor atomically replaces the whole record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case", deny_unknown_fields)]
pub enum CommandJournalState {
    Accepted {
        stop_fence: Option<EmbeddedStopFence>,
    },
    Executing {
        step: ExecutionStep,
        stop_fence: Option<EmbeddedStopFence>,
    },
    Terminal {
        result: ExactCommandResult,
        stop_fence: Option<EmbeddedStopFence>,
    },
}

/// The immediately superseded terminal retained by the current command.
/// Exact bytes preserve typed retry/effect authority while the single bounded
/// generation remains enough to reject a delayed predecessor replay without
/// becoming an append history.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SupersededPredecessor {
    pub operation_id: Id,
    pub request_fingerprint: Sha256Digest,
    /// Exact canonical command which produced `terminal_result`. Failed
    /// SameNodeRetry admission needs its absent slots' original
    /// `NormalUnowned` transition; a response-only carrier cannot recover it.
    canonical_command: Box<JournalCommandProjection>,
    terminal_result: ExactCommandResult,
}

impl SupersededPredecessor {
    pub fn terminal_result_digest(&self) -> &Sha256Digest {
        self.terminal_result.result_digest()
    }

    pub fn terminal_response(&self) -> Result<LifecycleCommandResponse, LifecycleJournalError> {
        self.terminal_result.decode_api()
    }

    pub fn command(&self) -> Result<LifecycleCommandEnvelope, LifecycleJournalError> {
        self.canonical_command.decode_api()
    }
}

/// The sole record stored at the deterministic per-Cat target pathname.
#[expect(
    clippy::large_enum_variant,
    reason = "the executable variant deliberately owns one small bounded in-memory projection of the sole atomic record; both wire variants are independently capped"
)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "record_kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum LifecycleJournalRecord {
    Command {
        version: u64,
        command: Box<JournalCommandProjection>,
        superseded_predecessor: Option<SupersededPredecessor>,
        state: CommandJournalState,
    },
    CompletedDeleteReceipt {
        version: u64,
        receipt: Box<CompletedCommandReceipt>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LifecycleJournalDocument {
    checkpoint: LifecycleJournalRecord,
    checkpoint_content_digest: Sha256Digest,
}

impl LifecycleJournalRecord {
    pub fn cat_id(&self) -> &Id {
        match self {
            Self::Command { command, .. } => &command.cat_id,
            Self::CompletedDeleteReceipt { receipt, .. } => &receipt.cat_id,
        }
    }

    pub fn operation_id(&self) -> &Id {
        match self {
            Self::Command { command, .. } => &command.operation_id,
            Self::CompletedDeleteReceipt { receipt, .. } => &receipt.operation_id,
        }
    }

    pub fn request_fingerprint(&self) -> &Sha256Digest {
        match self {
            Self::Command { command, .. } => &command.request_fingerprint,
            Self::CompletedDeleteReceipt { receipt, .. } => &receipt.request_fingerprint,
        }
    }

    /// Decode the one exact local SameNode predecessor response retained for
    /// the current command. Cross-node/HostFence initial target anchors do
    /// not have (and must not synthesize) a local predecessor response.
    pub fn decode_predecessor_response(
        &self,
    ) -> Result<Option<LifecycleCommandResponse>, LifecycleJournalError> {
        match self {
            Self::Command {
                superseded_predecessor: Some(predecessor),
                ..
            } => predecessor.terminal_response().map(Some),
            Self::Command {
                superseded_predecessor: None,
                ..
            }
            | Self::CompletedDeleteReceipt { .. } => Ok(None),
        }
    }
}

/// A decoded record tied to the exact file identity and bytes observed while
/// reading it. Callers must present it for every state transition.
#[derive(Debug, Clone)]
pub struct StoredLifecycleJournal {
    record: LifecycleJournalRecord,
    content_digest: Sha256Digest,
    file_identity: FileIdentity,
}

/// Held proof that one exact embedded Stop fence is still current. The guard
/// is acquired inside the owned blocking worker and remains there across one
/// bounded synchronous physical effect; it is never held across async await.
pub struct CurrentStopFenceGuard<'a> {
    store: &'a FileLifecycleCommandJournal,
    expected: &'a StoredLifecycleJournal,
    token: &'a DurableStopFence,
    _writer: MutexGuard<'a, ()>,
    descriptor: File,
}

impl CurrentStopFenceGuard<'_> {
    pub fn cat_id(&self) -> &Id {
        &self.token.cat_id
    }

    pub fn operation_id(&self) -> &Id {
        &self.token.operation_id
    }

    /// Digest of the exact durable Executing journal generation which owns
    /// this retained fence. Same-scan physical postconditions bind this value
    /// instead of reconstructing journal identity from a pathname or a later
    /// enumeration.
    pub fn journal_content_digest(&self) -> &Sha256Digest {
        self.expected.content_digest()
    }

    pub fn fence_payload(&self) -> &[u8] {
        match self.expected.record() {
            LifecycleJournalRecord::Command {
                state:
                    CommandJournalState::Accepted {
                        stop_fence: Some(fence),
                    }
                    | CommandJournalState::Executing {
                        stop_fence: Some(fence),
                        ..
                    }
                    | CommandJournalState::Terminal {
                        stop_fence: Some(fence),
                        ..
                    },
                ..
            } => fence.fence_payload.as_slice(),
            _ => unreachable!("validated Stop fence guard lost its embedded fence"),
        }
    }

    pub fn assert_current(&self) -> Result<(), LifecycleJournalError> {
        let metadata = self.descriptor.metadata().map_err(|source| {
            io_error(
                "reinspect retained lifecycle Stop fence journal",
                &self.store.target_path,
                source,
            )
        })?;
        verify_regular_single_link(&self.descriptor, &self.store.target_path)?;
        if FileIdentity::from_metadata(&metadata) != self.expected.file_identity {
            return Err(LifecycleJournalError::ConcurrentUpdate {
                path: self.store.target_path.clone(),
            });
        }
        self.store
            .verify_expected(ExpectedTarget::Exact(self.expected))?;
        validate_stop_fence_token(self.expected, self.token, &self.store.target_path)
    }
}

impl StoredLifecycleJournal {
    pub fn record(&self) -> &LifecycleJournalRecord {
        &self.record
    }

    /// Exact immediately preceding SameNode terminal response retained by an
    /// accepted/executing/terminal successor. Initial target anchors and
    /// completed Delete receipts have no local predecessor response.
    pub fn predecessor_terminal_response(
        &self,
    ) -> Result<Option<LifecycleCommandResponse>, LifecycleJournalError> {
        self.record.decode_predecessor_response()
    }

    /// Exact canonical command paired with the immediately preceding
    /// SameNode terminal. It is retained in the same atomic journal record so
    /// failed retry admission remains reproducible after Agent restart.
    pub fn predecessor_command(
        &self,
    ) -> Result<Option<LifecycleCommandEnvelope>, LifecycleJournalError> {
        match &self.record {
            LifecycleJournalRecord::Command {
                superseded_predecessor: Some(predecessor),
                ..
            } => predecessor.command().map(Some),
            LifecycleJournalRecord::Command {
                superseded_predecessor: None,
                ..
            }
            | LifecycleJournalRecord::CompletedDeleteReceipt { .. } => Ok(None),
        }
    }

    /// Exact canonical bytes and shared digest for the bounded immediately
    /// preceding SameNode result. Executors use this when a retry's physical
    /// authority depends on the predecessor's typed receipts.
    pub fn predecessor_terminal_result(&self) -> Option<&ExactCommandResult> {
        match &self.record {
            LifecycleJournalRecord::Command {
                superseded_predecessor: Some(predecessor),
                ..
            } => Some(&predecessor.terminal_result),
            LifecycleJournalRecord::Command {
                superseded_predecessor: None,
                ..
            }
            | LifecycleJournalRecord::CompletedDeleteReceipt { .. } => None,
        }
    }

    pub fn content_digest(&self) -> &Sha256Digest {
        &self.content_digest
    }
}

/// Explicit complete-inventory assertion required before a journal-less
/// Genesis can be accepted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GenesisLocalInventory {
    ConfirmedEmpty,
    PhysicalResidue { description: String },
}

#[derive(Debug, Clone)]
pub enum AdmitCommandOutcome {
    Accepted(StoredLifecycleJournal),
    Replay(StoredLifecycleJournal),
    Superseded {
        current_operation_id: Id,
        current_record_digest: Sha256Digest,
    },
}

#[derive(Debug, Clone)]
pub enum QueryCommandOutcome {
    Current(Box<StoredLifecycleJournal>),
    Superseded {
        current_operation_id: Id,
        current_record_digest: Sha256Digest,
    },
    NotFound,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeleteReceiptAckOutcome {
    Removed,
}

#[derive(Debug, Error)]
pub enum LifecycleJournalError {
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe lifecycle journal entry at {path}: {reason}")]
    UnsafeEntry { path: PathBuf, reason: String },
    #[error("invalid lifecycle journal at {path}: {reason}")]
    InvalidRecord { path: PathBuf, reason: String },
    #[error("lifecycle journal target changed after it was read: {path}")]
    ConcurrentUpdate { path: PathBuf },
    #[error("another lifecycle journal writer already owns {path}")]
    WriterAlreadyActive { path: PathBuf },
    #[error("lifecycle journal writer serialization lock is poisoned: {path}")]
    WriterSerializationPoisoned { path: PathBuf },
    #[error("command belongs to Cat {presented}, expected {expected}")]
    WrongCat { expected: Id, presented: Id },
    #[error("command belongs to Node {presented}, expected {expected}")]
    WrongNode { expected: Id, presented: Id },
    #[error("operation {operation_id} reused with a different request fingerprint")]
    OperationFingerprintConflict { operation_id: Id },
    #[error("operation {current_operation_id} is still unresolved")]
    CommandInProgress { current_operation_id: Id },
    #[error("operation {operation_id} does not match the exact terminal predecessor")]
    PredecessorMismatch { operation_id: Id },
    #[error("Cat {cat_id} has physical residue but no accepted lifecycle command: {description}")]
    PhysicalResidueWithoutJournal { cat_id: Id, description: String },
    #[error(
        "Cat {cat_id} has a completed Delete receipt and cannot accept another lifecycle command"
    )]
    ResourceDeleted { cat_id: Id },
    #[error("illegal lifecycle journal transition: {reason}")]
    IllegalTransition { reason: &'static str },
    #[error("Delete result-stored acknowledgement does not match the exact completed receipt")]
    DeleteAckMismatch,
    #[error("completed Delete receipt is missing")]
    DeleteReceiptMissing,
    #[error("complete physical inventory is required before lifecycle journal recovery: {reason}")]
    IncompletePhysicalInventory { reason: String },
    #[cfg(test)]
    #[error("injected lifecycle journal crash")]
    InjectedCrash,
}

/// Concrete descriptor-relative store for one Cat.
pub struct FileLifecycleCommandJournal {
    directory: File,
    namespace_anchor: Option<JournalNamespaceAnchor>,
    _writer_lock: JournalWriterLock,
    directory_path: PathBuf,
    target_name: CString,
    target_path: PathBuf,
    temporary_name: CString,
    temporary_path: PathBuf,
    cat_id: Id,
    writer_serialization: Mutex<()>,
    #[cfg(test)]
    faults: Mutex<TestFaults>,
}

struct JournalNamespaceAnchor {
    state_directory: StateDirectory,
    state_root: File,
    namespace_name: CString,
}

struct JournalWriterLock {
    file: File,
}

impl JournalWriterLock {
    fn acquire(file: File, path: &Path) -> Result<Self, LifecycleJournalError> {
        loop {
            // SAFETY: `file` is live for this call and flock retains no Rust
            // pointer or ownership of the descriptor.
            let result = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
            if result == 0 {
                return Ok(Self { file });
            }
            let source = io::Error::last_os_error();
            if source.kind() == io::ErrorKind::Interrupted {
                continue;
            }
            if source.raw_os_error() == Some(libc::EWOULDBLOCK)
                || source.raw_os_error() == Some(libc::EAGAIN)
            {
                return Err(LifecycleJournalError::WriterAlreadyActive {
                    path: path.to_path_buf(),
                });
            }
            return Err(io_error("lock lifecycle journal writer", path, source));
        }
    }
}

impl Drop for JournalWriterLock {
    fn drop(&mut self) {
        loop {
            // SAFETY: the owned lock descriptor remains live for this call.
            let result = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
            if result == 0 || io::Error::last_os_error().kind() != io::ErrorKind::Interrupted {
                return;
            }
        }
    }
}

impl FileLifecycleCommandJournal {
    /// Open the protected journal namespace and acquire its per-Cat writer
    /// lock. A stale deterministic temp is never adopted: rename removes the
    /// temp name, so a surviving temp proves publication did not linearize.
    pub fn open(directory: &Path, cat_id: &Id) -> Result<Self, LifecycleJournalError> {
        let directory_file = open_or_create_directory(directory)?;
        Self::open_from_directory(directory, directory_file, None, cat_id)
    }

    /// Production entry point anchored to the identity-selected Node state
    /// directory. Namespace creation, every leaf operation, and every lexical
    /// revalidation are relative to retained descriptors; a renamed or
    /// replaced ancestor cannot redirect an acknowledged journal publish.
    pub fn open_in_state_directory(
        state_directory: &StateDirectory,
        cat_id: &Id,
    ) -> Result<Self, LifecycleJournalError> {
        let directory = state_directory
            .path()
            .join(LIFECYCLE_JOURNAL_DIRECTORY_NAME);
        let state_root = state_directory.try_clone_directory().map_err(|source| {
            io_error(
                "retain lifecycle journal state directory",
                state_directory.path(),
                source,
            )
        })?;
        let namespace_name = c_string(LIFECYCLE_JOURNAL_DIRECTORY_NAME, &directory)?;
        let directory_file = open_or_create_directory_at(
            &state_root,
            namespace_name.as_c_str(),
            &directory,
            state_directory.path(),
        )?;
        revalidate_journal_namespace(
            state_directory,
            &state_root,
            namespace_name.as_c_str(),
            &directory_file,
            &directory,
        )?;
        let anchor = JournalNamespaceAnchor {
            state_directory: state_directory.clone(),
            state_root,
            namespace_name,
        };
        Self::open_from_directory(&directory, directory_file, Some(anchor), cat_id)
    }

    fn open_from_directory(
        directory: &Path,
        directory_file: File,
        namespace_anchor: Option<JournalNamespaceAnchor>,
        cat_id: &Id,
    ) -> Result<Self, LifecycleJournalError> {
        let target_file_name = target_file_name(cat_id);
        let lock_file_name = lock_file_name(cat_id);
        let temporary_file_name = temporary_file_name(cat_id);
        let target_name = c_string(&target_file_name, directory)?;
        let lock_name = c_string(&lock_file_name, directory)?;
        let temporary_name = c_string(&temporary_file_name, directory)?;
        let lock_path = directory.join(&lock_file_name);
        let target_path = directory.join(&target_file_name);
        let temporary_path = directory.join(&temporary_file_name);

        let lock_file = open_at(
            &directory_file,
            &lock_name,
            libc::O_RDWR | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|source| {
            map_open_error("open lifecycle journal writer lock", &lock_path, source)
        })?;
        verify_regular_single_link(&lock_file, &lock_path)?;
        let writer_lock = JournalWriterLock::acquire(lock_file, &lock_path)?;

        // No physical effect may begin before the target rename and directory
        // fsync have returned. Therefore a regular, single-link temp is
        // pre-linearization debris and cannot carry command authority. An
        // unsafe type or extra link is not a valid crash prefix: preserve it
        // verbatim and fail closed instead of hiding foreign residue.
        match open_at(
            &directory_file,
            &temporary_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(temporary) => {
                verify_regular_single_link(&temporary, &temporary_path)?;
                unlink_temporary_if_current(&directory_file, &temporary_name, &temporary).map_err(
                    |source| {
                        io_error(
                            "remove exact stale lifecycle journal temp",
                            &temporary_path,
                            source,
                        )
                    },
                )?;
            }
            Err(source) if source.kind() == io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(map_open_error(
                    "open stale lifecycle journal temp",
                    &temporary_path,
                    source,
                ))
            }
        }

        // A prior process may have exited after rename made the target
        // visible but before its directory-fsync acknowledgement returned.
        // Confirm the visible namespace now, before any recovered record can
        // authorize a physical effect or terminal repost. This also makes a
        // stale-temp removal and newly-created lock entry durable.
        directory_file.sync_all().map_err(|source| {
            io_error(
                "confirm lifecycle journal directory durability",
                directory,
                source,
            )
        })?;

        let store = Self {
            directory: directory_file,
            namespace_anchor,
            _writer_lock: writer_lock,
            directory_path: directory.to_path_buf(),
            target_name,
            target_path,
            temporary_name,
            temporary_path,
            cat_id: cat_id.clone(),
            writer_serialization: Mutex::new(()),
            #[cfg(test)]
            faults: Mutex::new(TestFaults::default()),
        };
        store.revalidate_directory_namespace()?;
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.target_path
    }

    pub fn load(&self) -> Result<Option<StoredLifecycleJournal>, LifecycleJournalError> {
        self.load_target()
    }

    /// Query one exact command identity without joining or starting physical
    /// work. An immediately superseded predecessor returns only the current
    /// high-watermark identity; historical response replay belongs to Control.
    pub fn query(
        &self,
        query: &LifecycleCommandQuery,
    ) -> Result<QueryCommandOutcome, LifecycleJournalError> {
        validate_lifecycle_command_query(query).map_err(|source| {
            invalid_record(
                Path::new("<lifecycle-command-query>"),
                format!("canonical API query rejected: {source}"),
            )
        })?;
        if query.cat_id != self.cat_id {
            return Err(LifecycleJournalError::WrongCat {
                expected: self.cat_id.clone(),
                presented: query.cat_id.clone(),
            });
        }
        let _writer = self.lock_writer()?;
        let Some(current) = self.load_target()? else {
            return Ok(QueryCommandOutcome::NotFound);
        };
        let current_node_id = match current.record() {
            LifecycleJournalRecord::Command { command, .. } => command.decode_api()?.node_id,
            LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
                receipt.node_id.clone()
            }
        };
        if query.node_id != current_node_id {
            return Err(LifecycleJournalError::WrongNode {
                expected: current_node_id,
                presented: query.node_id.clone(),
            });
        }
        if current.record.operation_id() == &query.operation_id {
            if current.record.request_fingerprint() != &query.request_fingerprint {
                return Err(LifecycleJournalError::OperationFingerprintConflict {
                    operation_id: query.operation_id.clone(),
                });
            }
            return Ok(QueryCommandOutcome::Current(Box::new(current)));
        }
        if let LifecycleJournalRecord::Command {
            command,
            superseded_predecessor: Some(predecessor),
            ..
        } = &current.record
        {
            if predecessor.operation_id == query.operation_id {
                if predecessor.request_fingerprint != query.request_fingerprint {
                    return Err(LifecycleJournalError::OperationFingerprintConflict {
                        operation_id: query.operation_id.clone(),
                    });
                }
                return Ok(QueryCommandOutcome::Superseded {
                    current_operation_id: command.operation_id.clone(),
                    current_record_digest: current.content_digest.clone(),
                });
            }
        }
        Ok(QueryCommandOutcome::NotFound)
    }

    /// Lossless shared-protocol entry point. Callers do not construct a second
    /// Node command DTO; the journal projection is derived from the canonical
    /// API request and discarded after this admission call.
    pub fn admit_api(
        &self,
        request: &LifecycleCommandEnvelope,
        genesis_inventory: GenesisLocalInventory,
    ) -> Result<AdmitCommandOutcome, LifecycleJournalError> {
        let command = JournalCommandProjection::from_api(request)?;
        self.admit(&command, genesis_inventory)
    }

    /// Admit, replay, or reject one exact command. A different command can
    /// replace only the current terminal record and only when it names that
    /// exact operation/result digest as predecessor.
    pub(crate) fn admit(
        &self,
        command: &JournalCommandProjection,
        genesis_inventory: GenesisLocalInventory,
    ) -> Result<AdmitCommandOutcome, LifecycleJournalError> {
        validate_command(command, &self.target_path)?;
        if command.cat_id != self.cat_id {
            return Err(LifecycleJournalError::WrongCat {
                expected: self.cat_id.clone(),
                presented: command.cat_id.clone(),
            });
        }
        let _writer = self.lock_writer()?;
        let current = self.load_target()?;
        let Some(current) = current else {
            let initial = command.decode_api()?;
            validate_lifecycle_initial_target_admission(&initial).map_err(|_| {
                LifecycleJournalError::PredecessorMismatch {
                    operation_id: command.operation_id.clone(),
                }
            })?;
            if let GenesisLocalInventory::PhysicalResidue { description } = genesis_inventory {
                return Err(LifecycleJournalError::PhysicalResidueWithoutJournal {
                    cat_id: self.cat_id.clone(),
                    description,
                });
            }
            let record = LifecycleJournalRecord::Command {
                version: JOURNAL_VERSION,
                command: Box::new(command.clone()),
                superseded_predecessor: None,
                state: CommandJournalState::Accepted { stop_fence: None },
            };
            return self
                .persist_locked(ExpectedTarget::Missing, &record)
                .map(AdmitCommandOutcome::Accepted);
        };

        if current.record.operation_id() == &command.operation_id {
            if current.record.request_fingerprint() != &command.request_fingerprint {
                return Err(LifecycleJournalError::OperationFingerprintConflict {
                    operation_id: command.operation_id.clone(),
                });
            }
            return Ok(AdmitCommandOutcome::Replay(current));
        }

        match &current.record {
            LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
                Err(LifecycleJournalError::ResourceDeleted {
                    cat_id: receipt.cat_id.clone(),
                })
            }
            LifecycleJournalRecord::Command {
                command: current_command,
                superseded_predecessor,
                state,
                ..
            } => {
                if let Some(predecessor) = superseded_predecessor {
                    if predecessor.operation_id == command.operation_id {
                        if predecessor.request_fingerprint != command.request_fingerprint {
                            return Err(LifecycleJournalError::OperationFingerprintConflict {
                                operation_id: command.operation_id.clone(),
                            });
                        }
                        return Ok(AdmitCommandOutcome::Superseded {
                            current_operation_id: current_command.operation_id.clone(),
                            current_record_digest: current.content_digest.clone(),
                        });
                    }
                }

                let CommandJournalState::Terminal { result, .. } = state else {
                    return Err(LifecycleJournalError::CommandInProgress {
                        current_operation_id: current_command.operation_id.clone(),
                    });
                };
                let ExpectedLifecyclePredecessor::Terminal {
                    operation_id,
                    result_digest,
                } = &command.expected_predecessor
                else {
                    return Err(LifecycleJournalError::PredecessorMismatch {
                        operation_id: command.operation_id.clone(),
                    });
                };
                if operation_id != &current_command.operation_id
                    || result_digest != &result.result_digest
                {
                    return Err(LifecycleJournalError::PredecessorMismatch {
                        operation_id: command.operation_id.clone(),
                    });
                }
                let current_response = result.decode_api()?;
                let current_terminal = LifecycleTerminalResult::NodeResult {
                    response: Box::new(current_response),
                };
                let successor_envelope = command.decode_api()?;
                // A local record can advance only along its exact SameNode
                // lane. Cross-node handoff and Host-fenced recovery are
                // initial anchors on the clean target Node; replacing the
                // source record here would discard its negative-execution
                // fence and give the old Node authority over a target command.
                if !matches!(
                    &successor_envelope.predecessor,
                    LifecyclePredecessor::SameNode { .. }
                ) {
                    return Err(LifecycleJournalError::PredecessorMismatch {
                        operation_id: command.operation_id.clone(),
                    });
                }
                let predecessor_envelope = current_command.decode_api()?;
                validate_lifecycle_successor_with_predecessor_command(
                    Some(&current_terminal),
                    Some(&predecessor_envelope),
                    &successor_envelope,
                )
                .map_err(|_| LifecycleJournalError::PredecessorMismatch {
                    operation_id: command.operation_id.clone(),
                })?;
                let inherited_stop_fence = if command.command_kind == LifecycleCommandKind::Start {
                    None
                } else {
                    match state {
                        CommandJournalState::Terminal { stop_fence, .. } => stop_fence.clone(),
                        _ => unreachable!("terminal state was matched above"),
                    }
                };
                let successor = LifecycleJournalRecord::Command {
                    version: JOURNAL_VERSION,
                    command: Box::new(command.clone()),
                    superseded_predecessor: Some(SupersededPredecessor {
                        operation_id: current_command.operation_id.clone(),
                        request_fingerprint: current_command.request_fingerprint.clone(),
                        canonical_command: current_command.clone(),
                        terminal_result: result.clone(),
                    }),
                    state: CommandJournalState::Accepted {
                        stop_fence: inherited_stop_fence,
                    },
                };
                self.persist_locked(ExpectedTarget::Exact(&current), &successor)
                    .map(AdmitCommandOutcome::Accepted)
            }
        }
    }

    /// Durably publish a resumable execution step. Once installed, an embedded
    /// Stop fence may not be removed or changed by a later step.
    pub fn record_execution(
        &self,
        expected: &StoredLifecycleJournal,
        step: ExecutionStep,
        stop_fence: Option<EmbeddedStopFence>,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        if step.recovery_payload.as_slice().len() > EXECUTION_PAYLOAD_MAX_BYTES {
            return Err(invalid_record(
                &self.target_path,
                "execution recovery payload exceeds its byte cap",
            ));
        }
        if stop_fence.as_ref().is_some_and(|fence| {
            fence.fence_payload.as_slice().is_empty()
                || fence.fence_payload.as_slice().len() > EXECUTION_PAYLOAD_MAX_BYTES
        }) {
            return Err(invalid_record(
                &self.target_path,
                "invalid embedded Stop fence",
            ));
        }
        let replacement = match &expected.record {
            LifecycleJournalRecord::Command {
                version,
                command,
                superseded_predecessor,
                state,
            } => {
                if matches!(state, CommandJournalState::Terminal { .. }) {
                    return Err(LifecycleJournalError::IllegalTransition {
                        reason: "a terminal command cannot resume execution",
                    });
                }
                if let Some(existing) = command_state_stop_fence(state) {
                    if stop_fence.as_ref() != Some(existing) {
                        return Err(LifecycleJournalError::IllegalTransition {
                            reason: "an embedded Stop fence cannot be removed or replaced",
                        });
                    }
                }
                LifecycleJournalRecord::Command {
                    version: *version,
                    command: command.clone(),
                    superseded_predecessor: superseded_predecessor.clone(),
                    state: CommandJournalState::Executing { step, stop_fence },
                }
            }
            LifecycleJournalRecord::CompletedDeleteReceipt { .. } => {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "a completed Delete receipt is non-executable",
                })
            }
        };
        self.replace(expected, &replacement)
    }

    /// Atomically embed a Stop fence and return its unforgeable capability only
    /// after the new record and directory entry are durable.
    pub fn record_stop_fence(
        &self,
        expected: &StoredLifecycleJournal,
        step: ExecutionStep,
        fence_payload: ExactBytes,
    ) -> Result<(StoredLifecycleJournal, DurableStopFence), LifecycleJournalError> {
        let existing = match expected.record() {
            LifecycleJournalRecord::Command { state, .. } => command_state_stop_fence(state),
            LifecycleJournalRecord::CompletedDeleteReceipt { .. } => None,
        };
        let stop_fence = match existing {
            Some(existing) if existing.fence_payload != fence_payload => {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "an embedded Stop fence cannot be replaced",
                })
            }
            Some(existing) => existing.clone(),
            None => EmbeddedStopFence {
                fence_payload,
                state: EmbeddedStopFenceState::Installed,
            },
        };
        let stored = self.record_execution(expected, step, Some(stop_fence))?;
        let token = durable_stop_fence(&stored, &self.target_path)?;
        Ok((stored, token))
    }

    /// Advance recovery state while preserving one exact durable Stop fence.
    /// The returned capability binds the replacement record; the predecessor
    /// capability becomes stale immediately after publication.
    pub fn advance_stop_fenced_execution(
        &self,
        expected: &StoredLifecycleJournal,
        token: &DurableStopFence,
        step: ExecutionStep,
    ) -> Result<(StoredLifecycleJournal, DurableStopFence), LifecycleJournalError> {
        if step.recovery_payload.as_slice().len() > EXECUTION_PAYLOAD_MAX_BYTES {
            return Err(invalid_record(
                &self.target_path,
                "execution recovery payload exceeds its byte cap",
            ));
        }
        let _writer = self.lock_writer()?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        validate_stop_fence_token(expected, token, &self.target_path)?;
        let LifecycleJournalRecord::Command {
            version,
            command,
            superseded_predecessor,
            state:
                CommandJournalState::Executing {
                    stop_fence: Some(fence),
                    ..
                },
        } = expected.record()
        else {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "Stop-fenced execution is not current",
            });
        };
        let replacement = LifecycleJournalRecord::Command {
            version: *version,
            command: command.clone(),
            superseded_predecessor: superseded_predecessor.clone(),
            state: CommandJournalState::Executing {
                step,
                stop_fence: Some(fence.clone()),
            },
        };
        let stored = self.persist_locked(ExpectedTarget::Exact(expected), &replacement)?;
        let token = durable_stop_fence(&stored, &self.target_path)?;
        Ok((stored, token))
    }

    /// Retain the exact current leaf and writer serialization for one bounded
    /// synchronous strong-Stop effect.
    pub fn retain_current_stop_fence<'a>(
        &'a self,
        expected: &'a StoredLifecycleJournal,
        token: &'a DurableStopFence,
    ) -> Result<CurrentStopFenceGuard<'a>, LifecycleJournalError> {
        let writer = self.lock_writer()?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        validate_stop_fence_token(expected, token, &self.target_path)?;
        let descriptor = open_at(
            &self.directory,
            &self.target_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        )
        .map_err(|source| {
            map_open_error(
                "retain current lifecycle Stop fence journal",
                &self.target_path,
                source,
            )
        })?;
        verify_regular_single_link(&descriptor, &self.target_path)?;
        let identity = FileIdentity::from_metadata(&descriptor.metadata().map_err(|source| {
            io_error(
                "inspect retained lifecycle Stop fence journal",
                &self.target_path,
                source,
            )
        })?);
        if identity != expected.file_identity {
            return Err(LifecycleJournalError::ConcurrentUpdate {
                path: self.target_path.clone(),
            });
        }
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        Ok(CurrentStopFenceGuard {
            store: self,
            expected,
            token,
            _writer: writer,
            descriptor,
        })
    }

    /// Reissue an in-process capability after Agent restart for an exact
    /// current Executing or Terminal record which still embeds its Stop fence.
    /// This does not create or advance durable authority.
    pub fn recover_current_stop_fence(
        &self,
        expected: &StoredLifecycleJournal,
    ) -> Result<DurableStopFence, LifecycleJournalError> {
        let _writer = self.lock_writer()?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        durable_stop_fence(expected, &self.target_path)
    }

    /// Durably publish an immutable exact terminal result before returning it.
    pub fn complete(
        &self,
        expected: &StoredLifecycleJournal,
        result: ExactCommandResult,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        validate_result_for_stored_command(expected, &result, &self.target_path)?;
        let response = result.decode_api()?;
        if terminal_result_requires_stop_fence(&response.result) {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "not-running terminal result requires a durable Stop fence",
            });
        }
        if matches!(response.result, NodeResult::Deleted(_)) {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "successful Delete requires a completed command receipt",
            });
        }
        let replacement = match &expected.record {
            LifecycleJournalRecord::Command {
                version,
                command,
                superseded_predecessor,
                state,
            } => {
                if let CommandJournalState::Terminal {
                    result: existing, ..
                } = state
                {
                    if existing == &result {
                        let _writer = self.lock_writer()?;
                        self.verify_expected(ExpectedTarget::Exact(expected))?;
                        return self.load_target()?.ok_or_else(|| {
                            LifecycleJournalError::ConcurrentUpdate {
                                path: self.target_path.clone(),
                            }
                        });
                    }
                    return Err(LifecycleJournalError::IllegalTransition {
                        reason: "a terminal result is immutable",
                    });
                }
                if command_state_stop_fence(state).is_some() {
                    return Err(LifecycleJournalError::IllegalTransition {
                        reason: "a Stop-fenced result requires DurableStopFence validation",
                    });
                }
                LifecycleJournalRecord::Command {
                    version: *version,
                    command: command.clone(),
                    superseded_predecessor: superseded_predecessor.clone(),
                    state: CommandJournalState::Terminal {
                        result,
                        stop_fence: None,
                    },
                }
            }
            LifecycleJournalRecord::CompletedDeleteReceipt { .. } => {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "a completed Delete receipt is already terminal",
                })
            }
        };
        self.replace(expected, &replacement)
    }

    /// Publish a terminal result whose postcondition depends on strong Stop.
    /// Token validation and atomic replacement share one writer critical
    /// section, so a stale or caller-fabricated fence cannot settle a result.
    pub fn complete_after_stop(
        &self,
        expected: &StoredLifecycleJournal,
        token: &DurableStopFence,
        result: ExactCommandResult,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        validate_result_for_stored_command(expected, &result, &self.target_path)?;
        let response = result.decode_api()?;
        if !terminal_result_requires_stop_fence(&response.result) {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "running or Suspended terminal result cannot retain a Stop fence",
            });
        }
        if matches!(response.result, NodeResult::Deleted(_)) {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "successful Delete requires a completed command receipt",
            });
        }
        let _writer = self.lock_writer()?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        validate_stop_fence_token(expected, token, &self.target_path)?;
        let replacement = terminal_replacement(expected, result)?;
        self.persist_locked(ExpectedTarget::Exact(expected), &replacement)
    }

    /// Replace a successful Delete's executable journal with the minimal
    /// non-executable response-loss receipt. Callers invoke this only after all
    /// destructive local cleanup and restart-source removal have completed.
    pub fn complete_delete(
        &self,
        expected: &StoredLifecycleJournal,
        token: &DurableStopFence,
        result: ExactCommandResult,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        validate_result_for_stored_command(expected, &result, &self.target_path)?;
        let LifecycleJournalRecord::Command { command, state, .. } = &expected.record else {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "a completed Delete receipt cannot be completed twice",
            });
        };
        if command.command_kind != LifecycleCommandKind::Delete {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "only Delete can produce a completed Delete receipt",
            });
        }
        let response = result.decode_api()?;
        if !matches!(response.result, NodeResult::Deleted(_)) {
            return Err(LifecycleJournalError::IllegalTransition {
                reason: "completed Delete receipt requires the successful Deleted result",
            });
        }
        match state {
            CommandJournalState::Executing {
                stop_fence: Some(_),
                ..
            } => {}
            CommandJournalState::Accepted { .. } | CommandJournalState::Executing { .. } => {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "Delete success requires a durable embedded Stop fence",
                })
            }
            CommandJournalState::Terminal { .. } => {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "a generic terminal result cannot become Delete success",
                })
            }
        }
        let completed = CompletedCommandReceipt::new(response).map_err(|source| {
            invalid_record(
                &self.target_path,
                format!("construct canonical completed Delete receipt: {source}"),
            )
        })?;
        if completed.terminal_result_digest != result.result_digest {
            return Err(invalid_record(
                &self.target_path,
                "completed receipt digest differs from exact terminal result",
            ));
        }
        let receipt = LifecycleJournalRecord::CompletedDeleteReceipt {
            version: JOURNAL_VERSION,
            receipt: Box::new(completed),
        };
        let _writer = self.lock_writer()?;
        self.verify_expected(ExpectedTarget::Exact(expected))?;
        validate_stop_fence_token(expected, token, &self.target_path)?;
        self.persist_locked(ExpectedTarget::Exact(expected), &receipt)
    }

    /// Descriptor-safe unlink of only the exact acknowledged completed Delete
    /// receipt, followed by a directory durability barrier.
    pub fn acknowledge_delete(
        &self,
        acknowledgement: &LifecycleResultStoredAck,
    ) -> Result<DeleteReceiptAckOutcome, LifecycleJournalError> {
        let _writer = self.lock_writer()?;
        let Some(current) = self.load_target()? else {
            return Err(LifecycleJournalError::DeleteReceiptMissing);
        };
        let LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } = &current.record else {
            return Err(LifecycleJournalError::DeleteAckMismatch);
        };
        if validate_lifecycle_result_stored_ack_for_response(
            acknowledgement,
            &receipt.terminal_response,
        )
        .is_err()
            || receipt.terminal_result_digest != acknowledgement.terminal_result_digest
        {
            return Err(LifecycleJournalError::DeleteAckMismatch);
        }
        self.verify_expected(ExpectedTarget::Exact(&current))?;
        self.revalidate_directory_namespace()?;
        self.maybe_crash(WriteStage::BeforeDeleteUnlink)?;
        unlink_at_if_exists(&self.directory, &self.target_name).map_err(|source| {
            io_error("unlink completed Delete receipt", &self.target_path, source)
        })?;
        self.maybe_crash(WriteStage::DeleteUnlinked)?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync lifecycle journal directory after Delete acknowledgement",
                &self.directory_path,
                source,
            )
        })?;
        self.maybe_crash(WriteStage::DeleteDirectorySynced)?;
        self.revalidate_directory_namespace()?;
        Ok(DeleteReceiptAckOutcome::Removed)
    }

    fn replace(
        &self,
        expected: &StoredLifecycleJournal,
        replacement: &LifecycleJournalRecord,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        let _writer = self.lock_writer()?;
        self.persist_locked(ExpectedTarget::Exact(expected), replacement)
    }

    fn lock_writer(&self) -> Result<MutexGuard<'_, ()>, LifecycleJournalError> {
        self.writer_serialization.lock().map_err(|_| {
            LifecycleJournalError::WriterSerializationPoisoned {
                path: self.target_path.clone(),
            }
        })
    }

    fn persist_locked(
        &self,
        expected: ExpectedTarget<'_>,
        record: &LifecycleJournalRecord,
    ) -> Result<StoredLifecycleJournal, LifecycleJournalError> {
        validate_record(record, &self.cat_id, &self.target_path)?;
        let bytes = encode_record(record, &self.target_path)?;
        self.verify_expected(expected)?;
        self.revalidate_directory_namespace()?;
        let mut temporary = self.create_temporary()?;
        self.maybe_crash(WriteStage::BeforeTempWrite)?;
        temporary.file.write_all(&bytes).map_err(|source| {
            io_error("write lifecycle journal temp", &self.temporary_path, source)
        })?;
        self.maybe_crash(WriteStage::TempWritten)?;
        temporary.file.sync_all().map_err(|source| {
            io_error("sync lifecycle journal temp", &self.temporary_path, source)
        })?;
        self.maybe_crash(WriteStage::TempSynced)?;
        self.verify_expected(expected)?;
        self.revalidate_directory_namespace()?;
        rename_at(
            &self.directory,
            &self.temporary_name,
            &self.directory,
            &self.target_name,
        )
        .map_err(|source| io_error("publish lifecycle journal", &self.target_path, source))?;
        temporary.disarm();
        self.maybe_crash(WriteStage::Renamed)?;
        self.directory.sync_all().map_err(|source| {
            io_error(
                "sync lifecycle journal directory",
                &self.directory_path,
                source,
            )
        })?;
        self.maybe_crash(WriteStage::DirectorySynced)?;
        self.revalidate_directory_namespace()?;

        let stored =
            self.load_target()?
                .ok_or_else(|| LifecycleJournalError::ConcurrentUpdate {
                    path: self.target_path.clone(),
                })?;
        if stored.record != *record
            || stored.content_digest != checkpoint_content_digest(record, &self.target_path)?
        {
            return Err(LifecycleJournalError::ConcurrentUpdate {
                path: self.target_path.clone(),
            });
        }
        Ok(stored)
    }

    fn verify_expected(&self, expected: ExpectedTarget<'_>) -> Result<(), LifecycleJournalError> {
        let current = self.load_target()?;
        match (expected, current) {
            (ExpectedTarget::Missing, None) => Ok(()),
            (ExpectedTarget::Exact(expected), Some(current))
                if current.file_identity == expected.file_identity
                    && current.content_digest == expected.content_digest
                    && current.record == expected.record =>
            {
                Ok(())
            }
            _ => Err(LifecycleJournalError::ConcurrentUpdate {
                path: self.target_path.clone(),
            }),
        }
    }

    fn load_target(&self) -> Result<Option<StoredLifecycleJournal>, LifecycleJournalError> {
        self.revalidate_directory_namespace()?;
        let file = match open_at(
            &self.directory,
            &self.target_name,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
            0,
        ) {
            Ok(file) => file,
            Err(source) if source.kind() == io::ErrorKind::NotFound => {
                self.revalidate_directory_namespace()?;
                return Ok(None);
            }
            Err(source) => {
                return Err(map_open_error(
                    "open lifecycle journal",
                    &self.target_path,
                    source,
                ))
            }
        };
        verify_regular_single_link(&file, &self.target_path)?;
        let before =
            FileIdentity::from_metadata(&file.metadata().map_err(|source| {
                io_error("inspect lifecycle journal", &self.target_path, source)
            })?);
        let mut bytes = Vec::with_capacity(
            usize::try_from(before.len)
                .unwrap_or(usize::MAX)
                .min(JOURNAL_MAX_BYTES.saturating_add(1)),
        );
        let mut bounded = Read::take(&file, (JOURNAL_MAX_BYTES as u64).saturating_add(1));
        bounded
            .read_to_end(&mut bytes)
            .map_err(|source| io_error("read lifecycle journal", &self.target_path, source))?;
        let after = FileIdentity::from_metadata(&file.metadata().map_err(|source| {
            io_error("reinspect lifecycle journal", &self.target_path, source)
        })?);
        if before != after {
            return Err(LifecycleJournalError::ConcurrentUpdate {
                path: self.target_path.clone(),
            });
        }
        let record = decode_record(&bytes, &self.cat_id, &self.target_path)?;
        let content_digest = checkpoint_content_digest(&record, &self.target_path)?;
        self.revalidate_directory_namespace()?;
        Ok(Some(StoredLifecycleJournal {
            record,
            content_digest,
            file_identity: before,
        }))
    }

    fn create_temporary(&self) -> Result<TemporaryJournal<'_>, LifecycleJournalError> {
        let file = open_at(
            &self.directory,
            &self.temporary_name,
            libc::O_WRONLY
                | libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | libc::O_NONBLOCK,
            0o600,
        )
        .map_err(|source| {
            map_open_error(
                "create lifecycle journal temp",
                &self.temporary_path,
                source,
            )
        })?;
        let temporary = TemporaryJournal {
            directory: &self.directory,
            name: &self.temporary_name,
            file,
            armed: true,
        };
        verify_regular_single_link(&temporary.file, &self.temporary_path)?;
        Ok(temporary)
    }

    fn revalidate_directory_namespace(&self) -> Result<(), LifecycleJournalError> {
        if let Some(anchor) = &self.namespace_anchor {
            return revalidate_journal_namespace(
                &anchor.state_directory,
                &anchor.state_root,
                anchor.namespace_name.as_c_str(),
                &self.directory,
                &self.directory_path,
            );
        }
        let mut options = OpenOptions::new();
        options.read(true).custom_flags(
            libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        );
        let current = options.open(&self.directory_path).map_err(|source| {
            map_open_error(
                "reopen current lifecycle journal directory",
                &self.directory_path,
                source,
            )
        })?;
        let retained = self.directory.metadata().map_err(|source| {
            io_error(
                "inspect retained lifecycle journal directory",
                &self.directory_path,
                source,
            )
        })?;
        let current = current.metadata().map_err(|source| {
            io_error(
                "inspect current lifecycle journal directory",
                &self.directory_path,
                source,
            )
        })?;
        verify_directory_metadata(
            &retained,
            &current,
            &self.directory_path,
            "retained directory is no longer the current lexical namespace",
        )
    }

    #[cfg(not(test))]
    fn maybe_crash(&self, _stage: WriteStage) -> Result<(), LifecycleJournalError> {
        Ok(())
    }

    #[cfg(test)]
    fn maybe_crash(&self, stage: WriteStage) -> Result<(), LifecycleJournalError> {
        let mut faults = self.faults.lock().expect("journal test fault lock");
        if faults.exit_once == Some(stage) {
            // SAFETY: test-only process-crash injection intentionally skips
            // every Rust destructor to characterize an actual crash prefix.
            unsafe { libc::_exit(TEST_PROCESS_EXIT_CODE) }
        }
        if faults.crash_once == Some(stage) {
            faults.crash_once = None;
            return Err(LifecycleJournalError::InjectedCrash);
        }
        Ok(())
    }

    #[cfg(test)]
    fn inject_crash_once(&self, stage: WriteStage) {
        self.faults
            .lock()
            .expect("journal test fault lock")
            .crash_once = Some(stage);
    }

    #[cfg(test)]
    fn inject_process_exit_once(&self, stage: WriteStage) {
        self.faults
            .lock()
            .expect("journal test fault lock")
            .exit_once = Some(stage);
    }
}

/// One startup entry recoverable by a per-Cat worker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartupJournalEntry {
    pub cat_id: Id,
    pub record: LifecycleJournalRecord,
    pub journal_digest: Sha256Digest,
}

/// A Cat-local startup failure. Other Cats remain enumerable and recoverable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockedStartupCat {
    pub cat_id: Id,
    pub reason: String,
}

/// A valid durable terminal journal whose physical evidence is contradictory.
/// It remains recoverable only for exact result settlement; no physical
/// effect or startup admission recovery may use it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedTerminalStartupCat {
    pub cat_id: Id,
    pub reason: String,
}

/// A valid non-terminal journal whose same-scan physical evidence is missing
/// or contradictory. The exact journal remains observable, but the Cat may
/// execute no effect and is not included in terminal settlement recovery.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QuarantinedStartupJournalEntry {
    pub entry: StartupJournalEntry,
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LifecycleJournalStartupInventory {
    /// Exact journals eligible for either effect recovery or terminal-only
    /// settlement, strictly sorted and unique by Cat.
    pub recoverable: Vec<StartupJournalEntry>,
    /// Cats whose journal/physical state grants neither effects nor result
    /// settlement, strictly sorted and disjoint from `recoverable`.
    pub blocked: Vec<BlockedStartupCat>,
    /// Exact non-terminal journals barred from physical recovery. These are
    /// strictly sorted and disjoint from both `recoverable` and `blocked`.
    pub quarantined_commands: Vec<QuarantinedStartupJournalEntry>,
    /// Subset of `recoverable` that may settle an already-durable terminal but
    /// may not reopen admission. Strictly sorted and unique by Cat.
    pub quarantined_terminals: Vec<QuarantinedTerminalStartupCat>,
}

/// Session-bound result of the Host's complete union inventory. Partial
/// heartbeat members or an interrupted scan cannot be passed as an empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartupPhysicalInventory {
    Complete {
        scan_id: RandomId128,
        collected_at_unix_ms: UnixMillis,
        /// Complete physical Cat projections, strictly sorted and unique by
        /// Cat ID. The physical scanner must leave every command-journal
        /// projection `None`; the sole descriptor-safe journal enumeration
        /// overlays it after this scan.
        cats: Vec<ObservedCatRuntimeTelemetry>,
        /// Physical artifacts which could not be safely attributed to a Cat,
        /// strictly sorted and unique by artifact ID.
        unattributed_artifacts: Vec<ObservedArtifactClassification>,
    },
    Incomplete {
        reason: String,
    },
}

impl StartupPhysicalInventory {
    pub fn physical_cat_ids(&self) -> Result<BTreeSet<Id>, LifecycleJournalError> {
        match self {
            Self::Complete {
                cats,
                unattributed_artifacts,
                ..
            } => {
                validate_physical_inventory_order(cats, unattributed_artifacts)?;
                Ok(cats.iter().map(|cat| cat.cat_id.clone()).collect())
            }
            Self::Incomplete { reason } => {
                Err(LifecycleJournalError::IncompletePhysicalInventory {
                    reason: reason.clone(),
                })
            }
        }
    }

    pub fn has_unattributed_artifacts(&self) -> bool {
        matches!(
            self,
            Self::Complete {
                unattributed_artifacts,
                ..
            } if !unattributed_artifacts.is_empty()
        )
    }
}

fn validate_physical_inventory_order(
    cats: &[ObservedCatRuntimeTelemetry],
    unattributed_artifacts: &[ObservedArtifactClassification],
) -> Result<(), LifecycleJournalError> {
    if cats.len() > RUNTIME_INVENTORY_MAX_CATS
        || unattributed_artifacts.len() > RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS
    {
        return Err(invalid_physical_inventory(
            "complete physical inventory exceeds its bounded collection limits",
        ));
    }
    if cats
        .windows(2)
        .any(|pair| pair[0].cat_id.as_str() >= pair[1].cat_id.as_str())
    {
        return Err(invalid_physical_inventory(
            "physical Cat projections are not strictly sorted and unique",
        ));
    }
    for cat in cats {
        if cat.observed_command_journal.is_some() {
            return Err(invalid_physical_inventory(
                "physical scan attempted to supply a command-journal projection",
            ));
        }
        if cat.observed_artifact_classifications.len() > RUNTIME_INVENTORY_MAX_ARTIFACTS_PER_CAT
            || cat.observed_volumes.len() > RUNTIME_INVENTORY_MAX_VOLUMES_PER_CAT
            || cat.observed_conditions.len() > RUNTIME_INVENTORY_MAX_CONDITIONS_PER_CAT
        {
            return Err(invalid_physical_inventory(
                "physical Cat projection exceeds its bounded collection limits",
            ));
        }
        if cat
            .observed_artifact_classifications
            .windows(2)
            .any(|pair| pair[0].artifact_id() >= pair[1].artifact_id())
        {
            return Err(invalid_physical_inventory(
                "Cat artifact projections are not strictly sorted and unique",
            ));
        }
        if cat
            .observed_volumes
            .windows(2)
            .any(|pair| pair[0].volume_id.as_str() >= pair[1].volume_id.as_str())
        {
            return Err(invalid_physical_inventory(
                "Cat volume projections are not strictly sorted and unique",
            ));
        }
        if cat
            .observed_conditions
            .windows(2)
            .any(|pair| pair[0].kind >= pair[1].kind)
        {
            return Err(invalid_physical_inventory(
                "Cat condition projections are not strictly sorted and unique",
            ));
        }
    }
    if unattributed_artifacts
        .windows(2)
        .any(|pair| pair[0].artifact_id() >= pair[1].artifact_id())
    {
        return Err(invalid_physical_inventory(
            "unattributed artifacts are not strictly sorted and unique",
        ));
    }
    Ok(())
}

fn invalid_physical_inventory(reason: impl Into<String>) -> LifecycleJournalError {
    LifecycleJournalError::IncompletePhysicalInventory {
        reason: reason.into(),
    }
}

/// Enumerate the bounded per-Cat high-watermarks at Agent startup and join
/// them with complete physical-inventory Cat IDs. A corrupt Cat or a Cat with
/// physical residue but no journal is blocked locally rather than guessed
/// Cold or allowed to affect a sibling Cat.
pub fn enumerate_startup(
    directory: &Path,
    physical_inventory: &StartupPhysicalInventory,
) -> Result<LifecycleJournalStartupInventory, LifecycleJournalError> {
    let directory_file = open_or_create_directory(directory)?;
    enumerate_startup_from_directory(directory, &directory_file, physical_inventory, |cat_id| {
        FileLifecycleCommandJournal::open(directory, cat_id)
    })
}

/// Production startup enumeration rooted in the retained, identity-selected
/// Node state directory. The exact namespace descriptor used for `readdir`
/// is cloned into every per-Cat store and revalidated before and after the
/// scan, so an ancestor or journal-directory replacement cannot turn an empty
/// lexical path into authority.
pub fn enumerate_startup_in_state_directory(
    state_directory: &StateDirectory,
    physical_inventory: &StartupPhysicalInventory,
) -> Result<LifecycleJournalStartupInventory, LifecycleJournalError> {
    let directory = state_directory
        .path()
        .join(LIFECYCLE_JOURNAL_DIRECTORY_NAME);
    let state_root = state_directory.try_clone_directory().map_err(|source| {
        io_error(
            "retain lifecycle journal state directory for startup enumeration",
            state_directory.path(),
            source,
        )
    })?;
    let namespace_name = c_string(LIFECYCLE_JOURNAL_DIRECTORY_NAME, &directory)?;
    let directory_file = open_or_create_directory_at(
        &state_root,
        namespace_name.as_c_str(),
        &directory,
        state_directory.path(),
    )?;
    revalidate_journal_namespace(
        state_directory,
        &state_root,
        namespace_name.as_c_str(),
        &directory_file,
        &directory,
    )?;

    let inventory = enumerate_startup_from_directory(
        &directory,
        &directory_file,
        physical_inventory,
        |cat_id| {
            let store_directory = directory_file.try_clone().map_err(|source| {
                io_error(
                    "clone lifecycle journal directory for startup Cat",
                    &directory,
                    source,
                )
            })?;
            let store_state_root = state_root.try_clone().map_err(|source| {
                io_error(
                    "clone retained lifecycle state directory for startup Cat",
                    state_directory.path(),
                    source,
                )
            })?;
            FileLifecycleCommandJournal::open_from_directory(
                &directory,
                store_directory,
                Some(JournalNamespaceAnchor {
                    state_directory: state_directory.clone(),
                    state_root: store_state_root,
                    namespace_name: namespace_name.clone(),
                }),
                cat_id,
            )
        },
    )?;

    revalidate_journal_namespace(
        state_directory,
        &state_root,
        namespace_name.as_c_str(),
        &directory_file,
        &directory,
    )?;
    Ok(inventory)
}

fn enumerate_startup_from_directory(
    directory: &Path,
    directory_file: &File,
    physical_inventory: &StartupPhysicalInventory,
    mut open_store: impl FnMut(&Id) -> Result<FileLifecycleCommandJournal, LifecycleJournalError>,
) -> Result<LifecycleJournalStartupInventory, LifecycleJournalError> {
    let physical_residue = physical_inventory.physical_cat_ids()?;
    let names = directory_entry_names(directory_file)
        .map_err(|source| io_error("enumerate lifecycle journal directory", directory, source))?;
    let mut target_cats = BTreeSet::new();
    let mut temp_cats = BTreeSet::new();
    for name in names {
        if name == b"." || name == b".." {
            continue;
        }
        let name = std::str::from_utf8(&name).map_err(|_| LifecycleJournalError::UnsafeEntry {
            path: directory.to_path_buf(),
            reason: "non-UTF-8 entry in lifecycle journal namespace".into(),
        })?;
        if let Some(cat) = parse_artifact_cat(name, TARGET_SUFFIX)? {
            target_cats.insert(cat);
        } else if let Some(cat) = parse_artifact_cat(name, TEMP_SUFFIX)? {
            temp_cats.insert(cat);
        } else if parse_artifact_cat(name, LOCK_SUFFIX)?.is_none() {
            return Err(LifecycleJournalError::UnsafeEntry {
                path: directory.join(name),
                reason: "unclassified entry in lifecycle journal namespace".into(),
            });
        }
    }

    let mut all_cats = target_cats.clone();
    all_cats.extend(temp_cats);
    all_cats.extend(physical_residue.iter().cloned());
    let mut inventory = LifecycleJournalStartupInventory::default();
    for cat_id in all_cats {
        let store = match open_store(&cat_id) {
            Ok(store) => store,
            Err(error) => {
                inventory.blocked.push(BlockedStartupCat {
                    cat_id,
                    reason: error.to_string(),
                });
                continue;
            }
        };
        match store.load() {
            Ok(Some(stored)) => {
                if physical_residue.contains(&cat_id)
                    && matches!(
                        &stored.record,
                        LifecycleJournalRecord::CompletedDeleteReceipt { .. }
                    )
                {
                    inventory
                        .quarantined_terminals
                        .push(QuarantinedTerminalStartupCat {
                            cat_id: cat_id.clone(),
                            reason: "physical residue contradicts completed Delete receipt".into(),
                        });
                }
                inventory.recoverable.push(StartupJournalEntry {
                    cat_id,
                    record: stored.record,
                    journal_digest: stored.content_digest,
                });
            }
            Ok(None) if physical_residue.contains(&cat_id) => {
                inventory.blocked.push(BlockedStartupCat {
                    cat_id,
                    reason: "physical residue exists without a lifecycle journal".into(),
                });
            }
            Ok(None) => {}
            Err(error) => inventory.blocked.push(BlockedStartupCat {
                cat_id,
                reason: error.to_string(),
            }),
        }
    }
    inventory
        .recoverable
        .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    inventory
        .blocked
        .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    inventory
        .quarantined_terminals
        .sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
    Ok(inventory)
}

fn command_state_stop_fence(state: &CommandJournalState) -> Option<&EmbeddedStopFence> {
    match state {
        CommandJournalState::Accepted { stop_fence }
        | CommandJournalState::Executing { stop_fence, .. }
        | CommandJournalState::Terminal { stop_fence, .. } => stop_fence.as_ref(),
    }
}

fn durable_stop_fence(
    stored: &StoredLifecycleJournal,
    path: &Path,
) -> Result<DurableStopFence, LifecycleJournalError> {
    let LifecycleJournalRecord::Command { command, state, .. } = stored.record() else {
        return Err(LifecycleJournalError::IllegalTransition {
            reason: "a completed Delete receipt cannot grant Stop authority",
        });
    };
    let fence =
        command_state_stop_fence(state).ok_or(LifecycleJournalError::IllegalTransition {
            reason: "the current command has no embedded Stop fence",
        })?;
    if fence.fence_payload.as_slice().is_empty() {
        return Err(invalid_record(path, "embedded Stop fence is empty"));
    }
    Ok(DurableStopFence {
        cat_id: command.cat_id.clone(),
        operation_id: command.operation_id.clone(),
        record_content_digest: stored.content_digest.clone(),
        fence_digest: digest(fence.fence_payload.as_slice()),
    })
}

fn validate_stop_fence_token(
    stored: &StoredLifecycleJournal,
    token: &DurableStopFence,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    let expected = durable_stop_fence(stored, path)?;
    if &expected != token {
        return Err(LifecycleJournalError::IllegalTransition {
            reason: "Durable Stop fence does not bind the exact current journal",
        });
    }
    Ok(())
}

fn terminal_replacement(
    expected: &StoredLifecycleJournal,
    result: ExactCommandResult,
) -> Result<LifecycleJournalRecord, LifecycleJournalError> {
    match expected.record() {
        LifecycleJournalRecord::Command {
            version,
            command,
            superseded_predecessor,
            state,
        } => {
            if matches!(state, CommandJournalState::Terminal { .. }) {
                return Err(LifecycleJournalError::IllegalTransition {
                    reason: "a terminal result is immutable",
                });
            }
            let mut stop_fence = command_state_stop_fence(state).cloned().ok_or(
                LifecycleJournalError::IllegalTransition {
                    reason: "strong-Stop terminal publication lost its embedded fence",
                },
            )?;
            if command.command_kind == LifecycleCommandKind::Cold
                && matches!(result.decode_api()?.result, NodeResult::Cold(_))
            {
                stop_fence.state = EmbeddedStopFenceState::ConvertedToColdTombstone;
            }
            Ok(LifecycleJournalRecord::Command {
                version: *version,
                command: command.clone(),
                superseded_predecessor: superseded_predecessor.clone(),
                state: CommandJournalState::Terminal {
                    result,
                    stop_fence: Some(stop_fence),
                },
            })
        }
        LifecycleJournalRecord::CompletedDeleteReceipt { .. } => {
            Err(LifecycleJournalError::IllegalTransition {
                reason: "a completed Delete receipt is already terminal",
            })
        }
    }
}

fn api_predecessor_high_watermark(
    predecessor: &LifecyclePredecessor,
) -> ExpectedLifecyclePredecessor {
    match predecessor {
        LifecyclePredecessor::Genesis { .. } => ExpectedLifecyclePredecessor::Genesis,
        LifecyclePredecessor::SameNode {
            operation_id,
            terminal_result_digest,
            ..
        } => ExpectedLifecyclePredecessor::Terminal {
            operation_id: operation_id.clone(),
            result_digest: terminal_result_digest.clone(),
        },
        LifecyclePredecessor::CrossNodeColdHandoff {
            cold_operation_id,
            cold_result_digest,
            ..
        } => ExpectedLifecyclePredecessor::Terminal {
            operation_id: cold_operation_id.clone(),
            result_digest: cold_result_digest.clone(),
        },
        LifecyclePredecessor::HostFenceRecovery {
            interrupted_operation_id,
            host_lost_result_digest,
            ..
        } => ExpectedLifecyclePredecessor::Terminal {
            operation_id: interrupted_operation_id.clone(),
            result_digest: host_lost_result_digest.clone(),
        },
    }
}

fn validate_command(
    command: &JournalCommandProjection,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    if command.canonical_request.as_slice().is_empty() {
        return Err(invalid_record(path, "canonical request is empty"));
    }
    if command.canonical_request.as_slice().len() > COMMAND_PAYLOAD_MAX_BYTES {
        return Err(invalid_record(
            path,
            "canonical request exceeds its byte cap",
        ));
    }
    if let ExpectedLifecyclePredecessor::Terminal { operation_id, .. } =
        &command.expected_predecessor
    {
        if operation_id == &command.operation_id {
            return Err(invalid_record(
                path,
                "operation cannot name itself as predecessor",
            ));
        }
    }
    match decode_lifecycle_command_envelope(command.canonical_request.as_slice()) {
        Ok(request)
            if request.cat_id == command.cat_id
                && request.operation_id == command.operation_id
                && request.request_fingerprint == command.request_fingerprint
                && request.command_kind() == command.command_kind
                && api_predecessor_high_watermark(&request.predecessor)
                    == command.expected_predecessor =>
        {
            Ok(())
        }
        Ok(_) => Err(invalid_record(
            path,
            "journal command projection differs from canonical API request",
        )),
        Err(source) => Err(invalid_record(
            path,
            format!("canonical lifecycle API request rejected: {source}"),
        )),
    }
}

fn validate_result(result: &ExactCommandResult, path: &Path) -> Result<(), LifecycleJournalError> {
    if result.result_bytes.as_slice().is_empty() {
        return Err(invalid_record(path, "terminal result is empty"));
    }
    if result.result_bytes.as_slice().len() > RESULT_MAX_BYTES {
        return Err(invalid_record(path, "terminal result exceeds its byte cap"));
    }
    result.decode_api().map(|_| ()).map_err(|source| {
        invalid_record(
            path,
            format!("canonical lifecycle API result rejected: {source}"),
        )
    })
}

fn validate_result_for_stored_command(
    stored: &StoredLifecycleJournal,
    result: &ExactCommandResult,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    let LifecycleJournalRecord::Command { command, .. } = stored.record() else {
        return Err(LifecycleJournalError::IllegalTransition {
            reason: "a completed Delete receipt is already terminal",
        });
    };
    validate_result_for_command(command, result, path)
}

fn terminal_result_requires_stop_fence(result: &NodeResult) -> bool {
    !matches!(
        result,
        NodeResult::RuntimeReady(_) | NodeResult::Suspended(_) | NodeResult::SuspendDeclined(_)
    )
}

fn validate_result_for_command(
    command: &JournalCommandProjection,
    result: &ExactCommandResult,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    validate_result(result, path)?;
    let request = command.decode_api()?;
    let response = result.decode_api()?;
    validate_lifecycle_command_response_for_command(&response, &request).map_err(|source| {
        invalid_record(
            path,
            format!("terminal API result does not bind journal command: {source}"),
        )
    })
}

fn validate_embedded_stop_fence(
    stop_fence: Option<&EmbeddedStopFence>,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    if stop_fence.is_some_and(|fence| {
        fence.fence_payload.as_slice().is_empty()
            || fence.fence_payload.as_slice().len() > EXECUTION_PAYLOAD_MAX_BYTES
    }) {
        return Err(invalid_record(path, "invalid embedded Stop fence"));
    }
    Ok(())
}

fn validate_command_state_stop_fence(
    state: &CommandJournalState,
    inherits_stop_fence: bool,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    let stop_fence = command_state_stop_fence(state);
    validate_embedded_stop_fence(stop_fence, path)?;

    match state {
        CommandJournalState::Accepted { .. } => {
            if stop_fence.is_some() != inherits_stop_fence {
                return Err(invalid_record(
                    path,
                    "Accepted state does not exactly preserve its predecessor Stop fence",
                ));
            }
        }
        CommandJournalState::Executing { .. } => {
            if inherits_stop_fence && stop_fence.is_none() {
                return Err(invalid_record(
                    path,
                    "Executing state removed its inherited Stop fence",
                ));
            }
            if !inherits_stop_fence
                && stop_fence.is_some_and(|fence| fence.state != EmbeddedStopFenceState::Installed)
            {
                return Err(invalid_record(
                    path,
                    "Executing state manufactured a Cold source tombstone",
                ));
            }
        }
        CommandJournalState::Terminal { result, .. } => {
            let response = result.decode_api()?;
            let requires_stop_fence = terminal_result_requires_stop_fence(&response.result);
            if stop_fence.is_some() != requires_stop_fence {
                return Err(invalid_record(
                    path,
                    "terminal result and durable Stop-fence presence disagree",
                ));
            }
            if matches!(response.result, NodeResult::Cold(_))
                && stop_fence.is_some_and(|fence| {
                    fence.state != EmbeddedStopFenceState::ConvertedToColdTombstone
                })
            {
                return Err(invalid_record(
                    path,
                    "successful Cold terminal did not convert its Stop fence to a tombstone",
                ));
            }
            if requires_stop_fence
                && !inherits_stop_fence
                && !matches!(response.result, NodeResult::Cold(_))
                && stop_fence.is_some_and(|fence| fence.state != EmbeddedStopFenceState::Installed)
            {
                return Err(invalid_record(
                    path,
                    "terminal result manufactured a Cold source tombstone",
                ));
            }
        }
    }
    Ok(())
}

fn validate_record(
    record: &LifecycleJournalRecord,
    expected_cat: &Id,
    path: &Path,
) -> Result<(), LifecycleJournalError> {
    let version = match record {
        LifecycleJournalRecord::Command {
            version,
            command,
            superseded_predecessor,
            state,
        } => {
            validate_command(command, path)?;
            let request = command.decode_api()?;
            let mut inherits_stop_fence = false;
            if let Some(predecessor) = superseded_predecessor {
                if predecessor.operation_id == command.operation_id {
                    return Err(invalid_record(
                        path,
                        "superseded predecessor equals current operation",
                    ));
                }
                match &command.expected_predecessor {
                    ExpectedLifecyclePredecessor::Terminal {
                        operation_id,
                        result_digest,
                    } if operation_id == &predecessor.operation_id
                        && result_digest == predecessor.terminal_result.result_digest() => {}
                    _ => {
                        return Err(invalid_record(
                            path,
                            "superseded predecessor does not match command predecessor",
                        ))
                    }
                }
                validate_result(&predecessor.terminal_result, path)?;
                validate_command(&predecessor.canonical_command, path)?;
                let predecessor_command = predecessor.command()?;
                let predecessor_response = predecessor.terminal_result.decode_api()?;
                if predecessor_response.operation_id != predecessor.operation_id
                    || predecessor_response.request_fingerprint != predecessor.request_fingerprint
                    || predecessor_response.cat_id != command.cat_id
                    || predecessor_command.operation_id != predecessor.operation_id
                    || predecessor_command.request_fingerprint != predecessor.request_fingerprint
                    || predecessor_command.workspace_id != predecessor_response.workspace_id
                    || predecessor_command.cat_id != predecessor_response.cat_id
                    || predecessor_command.node_id != predecessor_response.node_id
                    || predecessor_command.placement_identity
                        != predecessor_response.placement_identity
                {
                    return Err(invalid_record(
                        path,
                        "bounded predecessor command, metadata, and terminal response differ",
                    ));
                }
                if !matches!(&request.predecessor, LifecyclePredecessor::SameNode { .. }) {
                    return Err(invalid_record(
                        path,
                        "only SameNode successors retain a local predecessor response",
                    ));
                }
                let predecessor_terminal = LifecycleTerminalResult::NodeResult {
                    response: Box::new(predecessor_response.clone()),
                };
                validate_lifecycle_successor_with_predecessor_command(
                    Some(&predecessor_terminal),
                    Some(&predecessor_command),
                    &request,
                )
                .map_err(|source| {
                    invalid_record(
                        path,
                        format!("bounded predecessor does not authorize successor: {source}"),
                    )
                })?;
                inherits_stop_fence = command.command_kind != LifecycleCommandKind::Start
                    && terminal_result_requires_stop_fence(&predecessor_response.result);
            } else {
                validate_lifecycle_initial_target_admission(&request).map_err(|source| {
                    invalid_record(
                        path,
                        format!("command lacks a valid initial target anchor: {source}"),
                    )
                })?;
            }
            match state {
                CommandJournalState::Accepted { .. } => {
                    validate_command_state_stop_fence(state, inherits_stop_fence, path)?;
                }
                CommandJournalState::Executing { step, .. } => {
                    if step.recovery_payload.as_slice().len() > EXECUTION_PAYLOAD_MAX_BYTES {
                        return Err(invalid_record(
                            path,
                            "execution recovery payload exceeds its byte cap",
                        ));
                    }
                    validate_command_state_stop_fence(state, inherits_stop_fence, path)?;
                }
                CommandJournalState::Terminal { result, .. } => {
                    validate_result_for_command(command, result, path)?;
                    validate_command_state_stop_fence(state, inherits_stop_fence, path)?;
                }
            }
            *version
        }
        LifecycleJournalRecord::CompletedDeleteReceipt { version, receipt } => {
            validate_completed_command_receipt(receipt).map_err(|source| {
                invalid_record(
                    path,
                    format!("invalid canonical completed Delete receipt: {source}"),
                )
            })?;
            *version
        }
    };
    if version != JOURNAL_VERSION {
        return Err(invalid_record(path, "unsupported journal version"));
    }
    if record.cat_id() != expected_cat {
        return Err(LifecycleJournalError::WrongCat {
            expected: expected_cat.clone(),
            presented: record.cat_id().clone(),
        });
    }
    Ok(())
}

fn encode_record(
    record: &LifecycleJournalRecord,
    path: &Path,
) -> Result<Vec<u8>, LifecycleJournalError> {
    let document = LifecycleJournalDocument {
        checkpoint: record.clone(),
        checkpoint_content_digest: checkpoint_content_digest(record, path)?,
    };
    let bytes = canonical_json_bytes(&document, path)?;
    if bytes.len() > JOURNAL_MAX_BYTES {
        return Err(invalid_record(path, "journal exceeds its byte cap"));
    }
    Ok(bytes)
}

fn decode_record(
    bytes: &[u8],
    expected_cat: &Id,
    path: &Path,
) -> Result<LifecycleJournalRecord, LifecycleJournalError> {
    if bytes.len() > JOURNAL_MAX_BYTES {
        return Err(invalid_record(path, "journal exceeds its byte cap"));
    }
    let document: LifecycleJournalDocument = serde_json::from_slice(bytes)
        .map_err(|source| invalid_record(path, format!("JSON decode failed: {source}")))?;
    validate_record(&document.checkpoint, expected_cat, path)?;
    if checkpoint_content_digest(&document.checkpoint, path)? != document.checkpoint_content_digest
    {
        return Err(invalid_record(
            path,
            "checkpoint content digest does not match its durable record",
        ));
    }
    let canonical = encode_record(&document.checkpoint, path)?;
    if canonical != bytes {
        return Err(invalid_record(path, "journal JSON is not canonical"));
    }
    Ok(document.checkpoint)
}

fn checkpoint_content_digest(
    record: &LifecycleJournalRecord,
    path: &Path,
) -> Result<Sha256Digest, LifecycleJournalError> {
    let canonical = canonical_json_bytes(record, path)?;
    let mut hasher = Sha256::new();
    hasher.update(CHECKPOINT_CONTENT_DIGEST_DOMAIN);
    hasher.update([0]);
    hasher.update(canonical);
    Ok(Sha256Digest::from_bytes(hasher.finalize().into()))
}

fn canonical_json_bytes<T: Serialize>(
    value: &T,
    path: &Path,
) -> Result<Vec<u8>, LifecycleJournalError> {
    let value = serde_json::to_value(value)
        .map_err(|source| invalid_record(path, format!("JSON value encode failed: {source}")))?;
    serde_json::to_vec(&value)
        .map_err(|source| invalid_record(path, format!("JSON encode failed: {source}")))
}

fn digest(bytes: &[u8]) -> Sha256Digest {
    Sha256Digest::from_bytes(Sha256::digest(bytes).into())
}

fn target_file_name(cat_id: &Id) -> String {
    format!("cat-{}{TARGET_SUFFIX}", cat_id.as_str())
}

fn lock_file_name(cat_id: &Id) -> String {
    format!("cat-{}{LOCK_SUFFIX}", cat_id.as_str())
}

fn temporary_file_name(cat_id: &Id) -> String {
    format!(".cat-{}{TEMP_SUFFIX}", cat_id.as_str())
}

fn parse_artifact_cat(name: &str, suffix: &str) -> Result<Option<Id>, LifecycleJournalError> {
    let prefix = if suffix == TEMP_SUFFIX {
        ".cat-"
    } else {
        "cat-"
    };
    let Some(value) = name
        .strip_prefix(prefix)
        .and_then(|value| value.strip_suffix(suffix))
    else {
        return Ok(None);
    };
    Id::new(value)
        .map(Some)
        .ok_or_else(|| LifecycleJournalError::UnsafeEntry {
            path: PathBuf::from(name),
            reason: "invalid Cat identifier in lifecycle journal artifact".into(),
        })
}

fn open_or_create_directory(directory: &Path) -> Result<File, LifecycleJournalError> {
    let Some(leaf) = directory.file_name() else {
        return open_existing_directory(directory);
    };
    let parent_path = directory
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let parent = open_directory_descriptor(parent_path)?;
    let leaf = CString::new(leaf.as_bytes()).map_err(|_| LifecycleJournalError::UnsafeEntry {
        path: directory.to_path_buf(),
        reason: "directory leaf contains NUL".into(),
    })?;
    let mut created = false;
    let file = match open_at(
        &parent,
        &leaf,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            match mkdir_at(&parent, &leaf, 0o700) {
                Ok(()) => created = true,
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(io_error(
                        "create lifecycle journal directory",
                        directory,
                        source,
                    ))
                }
            }
            open_at(
                &parent,
                &leaf,
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0,
            )
            .map_err(|source| {
                map_open_error(
                    "open created lifecycle journal directory",
                    directory,
                    source,
                )
            })?
        }
        Err(source) => {
            return Err(map_open_error(
                "open lifecycle journal directory",
                directory,
                source,
            ))
        }
    };
    verify_safe_directory(&file, directory)?;
    if created {
        file.sync_all().map_err(|source| {
            io_error(
                "sync created lifecycle journal directory",
                directory,
                source,
            )
        })?;
    }
    // Also closes the crash window from a previous creator which returned
    // after mkdir but before making the parent entry durable.
    parent.sync_all().map_err(|source| {
        io_error(
            "sync lifecycle journal directory parent",
            parent_path,
            source,
        )
    })?;
    Ok(file)
}

fn open_or_create_directory_at(
    parent: &File,
    leaf: &CStr,
    directory: &Path,
    parent_path: &Path,
) -> Result<File, LifecycleJournalError> {
    let mut created = false;
    let file = match open_at(
        parent,
        leaf,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => {
            match mkdir_at(parent, leaf, 0o700) {
                Ok(()) => created = true,
                Err(source) if source.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(io_error(
                        "create lifecycle journal directory from retained state directory",
                        directory,
                        source,
                    ))
                }
            }
            open_at(
                parent,
                leaf,
                libc::O_RDONLY
                    | libc::O_DIRECTORY
                    | libc::O_NOFOLLOW
                    | libc::O_CLOEXEC
                    | libc::O_NONBLOCK,
                0,
            )
            .map_err(|source| {
                map_open_error(
                    "open lifecycle journal directory from retained state directory",
                    directory,
                    source,
                )
            })?
        }
        Err(source) => {
            return Err(map_open_error(
                "open lifecycle journal directory from retained state directory",
                directory,
                source,
            ))
        }
    };
    verify_safe_directory(&file, directory)?;
    if created {
        file.sync_all().map_err(|source| {
            io_error(
                "sync created lifecycle journal directory",
                directory,
                source,
            )
        })?;
    }
    parent.sync_all().map_err(|source| {
        io_error(
            "sync retained lifecycle journal state directory",
            parent_path,
            source,
        )
    })?;
    Ok(file)
}

fn open_existing_directory(directory: &Path) -> Result<File, LifecycleJournalError> {
    let file = open_directory_descriptor(directory)?;
    verify_safe_directory(&file, directory)?;
    Ok(file)
}

fn open_directory_descriptor(directory: &Path) -> Result<File, LifecycleJournalError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(directory)
        .map_err(|source| map_open_error("open lifecycle journal directory", directory, source))?;
    Ok(file)
}

fn verify_safe_directory(file: &File, directory: &Path) -> Result<(), LifecycleJournalError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect lifecycle journal directory", directory, source))?;
    if !metadata.is_dir() {
        return Err(LifecycleJournalError::UnsafeEntry {
            path: directory.to_path_buf(),
            reason: "not a directory".into(),
        });
    }
    // SAFETY: geteuid reads process credentials and retains no pointer.
    let effective_uid = unsafe { libc::geteuid() };
    if metadata.uid() != effective_uid || metadata.mode() & 0o022 != 0 {
        return Err(LifecycleJournalError::UnsafeEntry {
            path: directory.to_path_buf(),
            reason: "directory has unsafe owner or writable group/other mode".into(),
        });
    }
    Ok(())
}

fn verify_same_directory(
    retained: &File,
    current: &File,
    path: &Path,
    reason: &'static str,
) -> Result<(), LifecycleJournalError> {
    let retained = retained
        .metadata()
        .map_err(|source| io_error("inspect retained lifecycle directory", path, source))?;
    let current = current
        .metadata()
        .map_err(|source| io_error("inspect current lifecycle directory", path, source))?;
    verify_directory_metadata(&retained, &current, path, reason)
}

fn revalidate_journal_namespace(
    state_directory: &StateDirectory,
    retained_state_root: &File,
    namespace_name: &CStr,
    retained_namespace: &File,
    namespace_path: &Path,
) -> Result<(), LifecycleJournalError> {
    let lexical_root = state_directory.try_reopen_directory().map_err(|source| {
        io_error(
            "reopen current lifecycle journal state directory",
            state_directory.path(),
            source,
        )
    })?;
    verify_same_directory(
        retained_state_root,
        &lexical_root,
        state_directory.path(),
        "retained Node state directory is no longer the current lexical namespace",
    )?;
    let current_namespace = open_at(
        retained_state_root,
        namespace_name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    )
    .map_err(|source| {
        map_open_error(
            "reopen current lifecycle journal namespace from retained state directory",
            namespace_path,
            source,
        )
    })?;
    verify_same_directory(
        retained_namespace,
        &current_namespace,
        namespace_path,
        "retained journal directory is no longer the current state-directory child",
    )
}

fn verify_directory_metadata(
    retained: &Metadata,
    current: &Metadata,
    path: &Path,
    reason: &'static str,
) -> Result<(), LifecycleJournalError> {
    if !retained.is_dir()
        || !current.is_dir()
        || retained.dev() != current.dev()
        || retained.ino() != current.ino()
        || retained.uid() != current.uid()
        || retained.mode() != current.mode()
    {
        return Err(LifecycleJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: reason.into(),
        });
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum ExpectedTarget<'a> {
    Missing,
    Exact(&'a StoredLifecycleJournal),
}

struct TemporaryJournal<'a> {
    directory: &'a File,
    name: &'a CStr,
    file: File,
    armed: bool,
}

impl TemporaryJournal<'_> {
    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for TemporaryJournal<'_> {
    fn drop(&mut self) {
        if self.armed {
            let _ = unlink_temporary_if_current(self.directory, self.name, &self.file);
        }
    }
}

fn unlink_temporary_if_current(directory: &File, name: &CStr, retained: &File) -> io::Result<()> {
    let current = match open_at(
        directory,
        name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(current) => current,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(source) => return Err(source),
    };
    let retained = retained.metadata()?;
    let current = current.metadata()?;
    if !retained.is_file()
        || !current.is_file()
        || retained.nlink() != 1
        || current.nlink() != 1
        || retained.dev() != current.dev()
        || retained.ino() != current.ino()
    {
        return Err(io::Error::other(
            "lifecycle journal temp name no longer identifies the retained file",
        ));
    }
    unlink_at_if_exists(directory, name)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WriteStage {
    BeforeTempWrite,
    TempWritten,
    TempSynced,
    Renamed,
    DirectorySynced,
    BeforeDeleteUnlink,
    DeleteUnlinked,
    DeleteDirectorySynced,
}

#[cfg(test)]
#[derive(Default)]
struct TestFaults {
    crash_once: Option<WriteStage>,
    exit_once: Option<WriteStage>,
}

#[cfg(test)]
const TEST_PROCESS_EXIT_CODE: i32 = 87;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileIdentity {
    device: u64,
    inode: u64,
    len: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

impl FileIdentity {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            len: metadata.size(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

fn verify_regular_single_link(file: &File, path: &Path) -> Result<(), LifecycleJournalError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect lifecycle journal entry", path, source))?;
    if !metadata.file_type().is_file() {
        return Err(LifecycleJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "not a regular file".into(),
        });
    }
    if metadata.nlink() != 1 {
        return Err(LifecycleJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "hard-linked file".into(),
        });
    }
    Ok(())
}

fn c_string(value: &str, path: &Path) -> Result<CString, LifecycleJournalError> {
    CString::new(value).map_err(|_| LifecycleJournalError::UnsafeEntry {
        path: path.to_path_buf(),
        reason: "NUL byte in lifecycle journal path".into(),
    })
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    loop {
        // SAFETY: the directory descriptor and NUL-terminated name are live
        // for the call. A successful fresh descriptor is transferred once.
        let descriptor = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name.as_ptr(),
                flags,
                mode as libc::mode_t as libc::c_uint,
            )
        };
        if descriptor >= 0 {
            // SAFETY: `descriptor` is freshly owned from openat.
            return Ok(unsafe { File::from_raw_fd(descriptor) });
        }
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::Interrupted {
            return Err(source);
        }
    }
}

fn mkdir_at(directory: &File, name: &CStr, mode: libc::mode_t) -> io::Result<()> {
    loop {
        // SAFETY: `directory` and `name` remain live for this call; mkdirat
        // retains neither pointer nor descriptor ownership.
        let result = unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode) };
        if result == 0 {
            return Ok(());
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
        // SAFETY: both live directory descriptors and NUL-terminated names
        // are borrowed only for this call.
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
        // SAFETY: the directory descriptor and relative NUL-terminated name
        // remain live; unlinkat retains neither.
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

fn directory_entry_names(directory: &File) -> io::Result<Vec<Vec<u8>>> {
    let duplicate = directory.try_clone()?.into_raw_fd();
    // SAFETY: ownership of the duplicated descriptor transfers to fdopendir;
    // DirectoryStream closes it exactly once through closedir.
    let stream = unsafe { libc::fdopendir(duplicate) };
    if stream.is_null() {
        let source = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(duplicate) };
        return Err(source);
    }
    struct DirectoryStream(*mut libc::DIR);
    impl Drop for DirectoryStream {
        fn drop(&mut self) {
            // SAFETY: this wrapper uniquely owns the live DIR pointer.
            unsafe { libc::closedir(self.0) };
        }
    }
    let stream = DirectoryStream(stream);
    let mut names = Vec::new();
    loop {
        clear_errno();
        // SAFETY: the DIR remains exclusively owned and live for this call.
        let entry = unsafe { libc::readdir(stream.0) };
        if entry.is_null() {
            let source = io::Error::last_os_error();
            if source.raw_os_error() != Some(0) {
                return Err(source);
            }
            break;
        }
        // SAFETY: POSIX readdir returns a NUL-terminated d_name valid until
        // the next call on this DIR. We copy it immediately.
        let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
        names.push(name.to_bytes().to_vec());
    }
    Ok(names)
}

#[cfg(target_os = "linux")]
fn clear_errno() {
    // SAFETY: libc exposes this thread's errno slot; writing zero affects only
    // error detection for the immediately following readdir call.
    unsafe { *libc::__errno_location() = 0 }
}

#[cfg(target_os = "macos")]
fn clear_errno() {
    // SAFETY: libc exposes this thread's errno slot; writing zero affects only
    // error detection for the immediately following readdir call.
    unsafe { *libc::__error() = 0 }
}

fn map_open_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> LifecycleJournalError {
    if source.raw_os_error() == Some(libc::ELOOP) {
        LifecycleJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "symbolic link".into(),
        }
    } else {
        io_error(operation, path, source)
    }
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> LifecycleJournalError {
    LifecycleJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

fn invalid_record(path: &Path, reason: impl Into<String>) -> LifecycleJournalError {
    LifecycleJournalError::InvalidRecord {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::fs::{symlink, PermissionsExt as _};

    use cats_api::runtime_inventory::ObservedRuntimePhysicalState;
    use cats_api::runtime_lifecycle::{
        ColdResult, ColdSpec, ColdVolumeDisposition, ColdVolumeDispositionDigest,
        CommandFailedResult, CommandFailureReason, CompletedVolumeDisposition, DeleteSpec,
        DeletedResult, DiskRole, ExecutionAbsenceProof, ImmutableRuntimeConfig, KilledResult,
        LifecycleCommand, LifecyclePredecessor, PlacementIdentity, RequestedVolumeDisposition,
        RetainedEvidence, RuntimeNetworkConfig, RuntimeVolumeAuthorityInput, RuntimeVolumeConfig,
        RuntimeVolumeGuestBinding, StartSource, StartSpec, StartVolumeAuthority, StopSpec,
        TerminalResultKind, VolumeTerminalReceipt,
    };
    use cats_api::runtime_reconciliation::{
        ContractVersion, Durability, Epoch, FenceEpoch, Generation, Ipv4Address, MacAddress,
        RandomId128, UnixMillis,
    };

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn fingerprint(byte: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([byte; 32])
    }

    fn random(byte: u8) -> RandomId128 {
        RandomId128::new(format!("{byte:02x}").repeat(16)).unwrap()
    }

    fn placement() -> PlacementIdentity {
        PlacementIdentity {
            node_id: id("node_a"),
            placement_epoch: Epoch::new(1).unwrap(),
        }
    }

    fn runtime_config() -> ImmutableRuntimeConfig {
        ImmutableRuntimeConfig::new(
            id("config_a"),
            fingerprint(1),
            2,
            512 * 1024 * 1024,
            fingerprint(2),
            RuntimeNetworkConfig::IsolatedIpv4 {
                network_id: id("network_a"),
                guest_mac: MacAddress::new("02:00:00:00:00:01").unwrap(),
                guest_ipv4: Ipv4Address::new("10.0.0.2").unwrap(),
                prefix_length: 30,
                gateway_ipv4: Ipv4Address::new("10.0.0.1").unwrap(),
            },
            vec![RuntimeVolumeConfig {
                volume_id: id("volume_root"),
                disk_id: id("disk_root"),
                disk_role: DiskRole::Root,
                size_bytes: 1024 * 1024,
                durability: Durability::Strict,
                guest_device_serial: id("root_serial"),
                guest_device_slot: 0,
                guest_binding: RuntimeVolumeGuestBinding::RootBoot,
            }],
        )
        .unwrap()
    }

    fn complete_physical_inventory(
        cat_ids: impl IntoIterator<Item = Id>,
    ) -> StartupPhysicalInventory {
        let mut cats = cat_ids
            .into_iter()
            .map(|cat_id| ObservedCatRuntimeTelemetry {
                cat_id,
                observed_placement: placement(),
                observed_command_journal: None,
                observed_physical_state: ObservedRuntimePhysicalState::StoppedRetained,
                observed_runtime_incarnation: None,
                observed_artifact_manifest_digest: fingerprint(60),
                observed_artifact_classifications: Vec::new(),
                observed_volumes: Vec::new(),
                observed_conditions: Vec::new(),
            })
            .collect::<Vec<_>>();
        cats.sort_by(|left, right| left.cat_id.cmp(&right.cat_id));
        StartupPhysicalInventory::Complete {
            scan_id: random(61),
            collected_at_unix_ms: UnixMillis::new(1_000).unwrap(),
            cats,
            unattributed_artifacts: Vec::new(),
        }
    }

    fn start_spec(source: StartSource, deadline: u64) -> StartSpec {
        let authority = match source {
            StartSource::SameNodeSuspended
            | StartSource::SameNodeWarm
            | StartSource::SameNodeStopped => RuntimeVolumeAuthorityInput::SameNodeOwned {
                attachment_id: id("attachment_root"),
                attachment_epoch: FenceEpoch::new(1).unwrap(),
            },
            StartSource::HostFenceRecovery => RuntimeVolumeAuthorityInput::Takeover {
                authorization_id: id("takeover_root"),
            },
            StartSource::Genesis
            | StartSource::SameNodeCold
            | StartSource::SameNodeRetry
            | StartSource::ColdHandoff => RuntimeVolumeAuthorityInput::NormalUnowned {
                expected_unowned_epoch: FenceEpoch::new(0).unwrap(),
                transition_id: random(3),
            },
        };
        StartSpec {
            volume_authorities: vec![StartVolumeAuthority {
                volume_id: id("volume_root"),
                disk_id: id("disk_root"),
                authority,
            }],
            source,
            effect_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
        }
    }

    fn api_request(operation: &str, deadline: u64) -> LifecycleCommandEnvelope {
        let target = placement();
        LifecycleCommandEnvelope::new(
            id(operation),
            id("workspace_a"),
            id("cat_api"),
            target.node_id.clone(),
            target.clone(),
            runtime_config(),
            None,
            LifecyclePredecessor::Genesis {
                cat_creation_id: id("creation-api-adapter"),
                target_placement: target,
            },
            LifecycleCommand::Start(Box::new(start_spec(StartSource::Genesis, deadline))),
        )
        .unwrap()
    }

    fn cross_node_initial_request(cat: &str, operation: &str) -> LifecycleCommandEnvelope {
        let source = PlacementIdentity {
            node_id: id("node_source"),
            placement_epoch: Epoch::new(1).unwrap(),
        };
        let target = placement();
        let config = runtime_config();
        let cold_operation_id = id("operation_source_cold");
        LifecycleCommandEnvelope::new(
            id(operation),
            id("workspace_a"),
            id(cat),
            target.node_id.clone(),
            target.clone(),
            config,
            Some(cold_operation_id.clone()),
            LifecyclePredecessor::CrossNodeColdHandoff {
                cold_operation_id,
                cold_result_digest: fingerprint(41),
                source_node_id: source.node_id.clone(),
                source_placement: source,
                volume_disposition_receipts: vec![ColdVolumeDispositionDigest::NormallyReleased {
                    volume_id: id("volume_root"),
                    normal_release_receipt_digest: fingerprint(42),
                }],
                target_placement: target,
            },
            LifecycleCommand::Start(Box::new(start_spec(StartSource::ColdHandoff, 30_000))),
        )
        .unwrap()
    }

    fn absence() -> ExecutionAbsenceProof {
        ExecutionAbsenceProof {
            stop_fence_receipt_digest: fingerprint(10),
            admission_closed_receipt_digest: fingerprint(11),
            dedicated_scope_absence_receipt_digest: fingerprint(12),
            frontend_absence_receipt_digest: fingerprint(13),
            restart_source_absence_receipt_digest: fingerprint(14),
        }
    }

    fn retained_evidence() -> RetainedEvidence {
        RetainedEvidence {
            artifact_manifest_digest: fingerprint(15),
            adoptable_count: 0,
            gc_candidate_count: 0,
            retained_authority_or_data_count: 0,
            quarantined_count: 0,
        }
    }

    fn volume_receipt(
        remote_durable: bool,
        authority_receipt_digest: Sha256Digest,
    ) -> VolumeTerminalReceipt {
        VolumeTerminalReceipt {
            volume_id: id("volume_root"),
            disk_id: id("disk_root"),
            disk_role: DiskRole::Root,
            attachment_id: id("attachment_root"),
            attachment_epoch: FenceEpoch::new(1).unwrap(),
            local_durable_generation: Generation::new(2).unwrap(),
            remote_durable_generation: Generation::new(if remote_durable { 2 } else { 1 }).unwrap(),
            authority_receipt_digest: Some(authority_receipt_digest),
        }
    }

    fn response_for(request: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        let result = match request.command_kind() {
            LifecycleCommandKind::Start => NodeResult::StartFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::VmmFailed,
                not_running: absence(),
                retained_evidence: retained_evidence(),
                retained_volume_receipts: Vec::new(),
            })),
            LifecycleCommandKind::Stop => NodeResult::Killed(Box::new(KilledResult {
                stopped_runtime_incarnation: Some(random(17)),
                execution_absence: absence(),
                stop_fence_receipt_digest: fingerprint(18),
                retained_volume_receipts: vec![volume_receipt(false, fingerprint(16))],
                retained_evidence: RetainedEvidence {
                    retained_authority_or_data_count: 1,
                    ..retained_evidence()
                },
            })),
            LifecycleCommandKind::Cold => NodeResult::Cold(Box::new(ColdResult {
                runtime_config_digest: runtime_config().config_digest,
                execution_absence: absence(),
                volume_dispositions: vec![ColdVolumeDisposition::NormallyReleased {
                    volume: Box::new(volume_receipt(true, fingerprint(23))),
                    normal_release_receipt_digest: fingerprint(23),
                }],
                local_recovery_dependency_absent_digest: fingerprint(19),
            })),
            LifecycleCommandKind::Delete => NodeResult::Deleted(Box::new(DeletedResult {
                execution_absence: absence(),
                volume_dispositions: vec![CompletedVolumeDisposition::RootDisposableTailDeleted {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    previous_attachment_id: id("attachment_root"),
                    previous_attachment_epoch: FenceEpoch::new(1).unwrap(),
                    disposable_authorization_id: id("delete_authorization"),
                    authorization_consumed_receipt_digest: fingerprint(20),
                    delete_completion_receipt_digest: fingerprint(23),
                    local_lineage_absence_digest: fingerprint(21),
                }],
                destructive_cleanup_absent_digest: fingerprint(22),
            })),
            LifecycleCommandKind::Suspend => {
                NodeResult::SuspendFailed(Box::new(CommandFailedResult {
                    reason: CommandFailureReason::StoredEvidenceConflict,
                    not_running: absence(),
                    retained_evidence: retained_evidence(),
                    retained_volume_receipts: vec![volume_receipt(false, fingerprint(16))],
                }))
            }
            LifecycleCommandKind::Warm => NodeResult::WarmFailed(Box::new(CommandFailedResult {
                reason: CommandFailureReason::StoredEvidenceConflict,
                not_running: absence(),
                retained_evidence: retained_evidence(),
                retained_volume_receipts: vec![volume_receipt(false, fingerprint(16))],
            })),
        };
        LifecycleCommandResponse::new(request, result).unwrap()
    }

    fn api_terminal_result(request: &LifecycleCommandEnvelope) -> LifecycleCommandResponse {
        response_for(request)
    }

    fn command(
        cat: &str,
        operation: &str,
        command_kind: LifecycleCommandKind,
        expected_predecessor: ExpectedLifecyclePredecessor,
        request_byte: u8,
    ) -> JournalCommandProjection {
        let placement = placement();
        let (expected_operation, predecessor, command_kind) = match expected_predecessor {
            ExpectedLifecyclePredecessor::Genesis => (
                None,
                LifecyclePredecessor::Genesis {
                    cat_creation_id: id("creation_a"),
                    target_placement: placement.clone(),
                },
                LifecycleCommandKind::Start,
            ),
            ExpectedLifecyclePredecessor::Terminal {
                operation_id,
                result_digest,
            } => (
                Some(operation_id.clone()),
                LifecyclePredecessor::SameNode {
                    operation_id,
                    terminal_result_kind: TerminalResultKind::StartFailed,
                    terminal_result_digest: result_digest,
                    node_id: placement.node_id.clone(),
                    placement_identity: placement.clone(),
                },
                command_kind,
            ),
        };
        let deadline = 10_000 + u64::from(request_byte);
        let command = match command_kind {
            LifecycleCommandKind::Start => LifecycleCommand::Start(Box::new(start_spec(
                if expected_operation.is_none() {
                    StartSource::Genesis
                } else {
                    StartSource::SameNodeRetry
                },
                deadline,
            ))),
            LifecycleCommandKind::Stop => LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
            }),
            LifecycleCommandKind::Cold => LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(deadline + 1).unwrap(),
            }),
            LifecycleCommandKind::Delete => LifecycleCommand::Delete(DeleteSpec {
                delete_id: id("delete_a"),
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(deadline + 1).unwrap(),
                volume_dispositions: vec![RequestedVolumeDisposition::DiscardWithCat {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    disk_role: DiskRole::Root,
                }],
            }),
            other => panic!("unused journal test command kind: {other:?}"),
        };
        let request = LifecycleCommandEnvelope::new(
            id(operation),
            id("workspace_a"),
            id(cat),
            placement.node_id.clone(),
            placement,
            runtime_config(),
            expected_operation,
            predecessor,
            command,
        )
        .unwrap();
        JournalCommandProjection::from_api(&request).unwrap()
    }

    fn admit(
        store: &FileLifecycleCommandJournal,
        command: &JournalCommandProjection,
    ) -> StoredLifecycleJournal {
        match store
            .admit(command, GenesisLocalInventory::ConfirmedEmpty)
            .expect("admit command")
        {
            AdmitCommandOutcome::Accepted(stored) => stored,
            other => panic!("unexpected admission outcome: {other:?}"),
        }
    }

    fn execute(
        store: &FileLifecycleCommandJournal,
        stored: &StoredLifecycleJournal,
        with_stop_fence: bool,
    ) -> StoredLifecycleJournal {
        store
            .record_execution(
                stored,
                ExecutionStep {
                    name: id("effect_01"),
                    recovery_payload: ExactBytes::new(b"recover-exact-effect".to_vec()),
                },
                with_stop_fence.then(|| EmbeddedStopFence {
                    fence_payload: ExactBytes::new(b"stop-fence-operation-bound".to_vec()),
                    state: EmbeddedStopFenceState::Installed,
                }),
            )
            .expect("record execution")
    }

    fn complete(
        store: &FileLifecycleCommandJournal,
        stored: &StoredLifecycleJournal,
        _result_label: &[u8],
    ) -> StoredLifecycleJournal {
        let result = result_for_stored(stored);
        match durable_stop_fence(stored, store.path()) {
            Ok(token) => store
                .complete_after_stop(stored, &token, result)
                .expect("complete Stop-fenced command"),
            Err(_) => store.complete(stored, result).expect("complete command"),
        }
    }

    fn result_for_stored(stored: &StoredLifecycleJournal) -> ExactCommandResult {
        let LifecycleJournalRecord::Command { command, .. } = stored.record() else {
            panic!("completed receipt is not executable")
        };
        ExactCommandResult::from_api(&response_for(&command.decode_api().unwrap()))
            .expect("canonical result")
    }

    fn terminal_result(stored: &StoredLifecycleJournal) -> &ExactCommandResult {
        match stored.record() {
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal { result, .. },
                ..
            } => result,
            other => panic!("expected terminal record, got {other:?}"),
        }
    }

    fn successor_of(
        cat: &str,
        operation: &str,
        predecessor: &StoredLifecycleJournal,
        request_byte: u8,
    ) -> JournalCommandProjection {
        successor_command(
            cat,
            operation,
            predecessor,
            LifecycleCommandKind::Start,
            request_byte,
        )
    }

    fn successor_command(
        cat: &str,
        operation: &str,
        predecessor: &StoredLifecycleJournal,
        command_kind: LifecycleCommandKind,
        request_byte: u8,
    ) -> JournalCommandProjection {
        let response = terminal_result(predecessor).decode_api().unwrap();
        let source = match response.result.kind() {
            TerminalResultKind::Killed => StartSource::SameNodeStopped,
            TerminalResultKind::Cold => StartSource::SameNodeCold,
            _ => StartSource::SameNodeRetry,
        };
        let placement = response.placement_identity.clone();
        let deadline = 20_000 + u64::from(request_byte);
        let command = match command_kind {
            LifecycleCommandKind::Start => {
                LifecycleCommand::Start(Box::new(start_spec(source, deadline)))
            }
            LifecycleCommandKind::Stop => LifecycleCommand::Stop(StopSpec {
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
            }),
            LifecycleCommandKind::Cold => LifecycleCommand::Cold(ColdSpec {
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(deadline + 1).unwrap(),
            }),
            LifecycleCommandKind::Delete => LifecycleCommand::Delete(DeleteSpec {
                delete_id: id("delete_successor"),
                grace_deadline_unix_ms: UnixMillis::new(deadline).unwrap(),
                convergence_deadline_unix_ms: UnixMillis::new(deadline + 1).unwrap(),
                volume_dispositions: vec![RequestedVolumeDisposition::DiscardWithCat {
                    volume_id: id("volume_root"),
                    disk_id: id("disk_root"),
                    disk_role: DiskRole::Root,
                }],
            }),
            other => panic!("unused successor kind: {other:?}"),
        };
        let request = LifecycleCommandEnvelope::new(
            id(operation),
            response.workspace_id.clone(),
            id(cat),
            response.node_id.clone(),
            placement.clone(),
            runtime_config(),
            Some(response.operation_id.clone()),
            LifecyclePredecessor::SameNode {
                operation_id: response.operation_id.clone(),
                terminal_result_kind: response.result.kind(),
                terminal_result_digest: terminal_result(predecessor).result_digest.clone(),
                node_id: response.node_id,
                placement_identity: placement,
            },
            command,
        )
        .unwrap();
        JournalCommandProjection::from_api(&request).unwrap()
    }

    #[test]
    fn accepted_is_durable_before_admission_returns_and_exact_retry_replays_disk() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_replay");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let original = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &original);
        assert!(store.path().is_file());

        let AdmitCommandOutcome::Replay(replayed) = store
            .admit(&original, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap()
        else {
            panic!("exact operation/fingerprint was not replayed")
        };
        assert_eq!(replayed.record(), accepted.record());
        assert_eq!(
            replayed.content_digest(),
            accepted.content_digest(),
            "replay must not rewrite the journal"
        );
    }

    #[test]
    fn shared_api_request_and_result_adapters_are_lossless_and_command_bound() {
        assert_eq!(
            COMMAND_PAYLOAD_MAX_BYTES,
            LIFECYCLE_COMMAND_ENVELOPE_MAX_WIRE_BYTES
        );
        assert_eq!(RESULT_MAX_BYTES, LIFECYCLE_COMMAND_RESPONSE_MAX_WIRE_BYTES);

        let request = api_request("operation_api", 10_000);
        let projected = JournalCommandProjection::from_api(&request).unwrap();
        assert_eq!(projected.decode_api().unwrap(), request);
        assert_eq!(
            projected.canonical_request.as_slice(),
            encode_lifecycle_command_envelope(&request).unwrap()
        );
        let envelope = api_terminal_result(&request);
        let exact_result = ExactCommandResult::from_api(&envelope).unwrap();
        assert_eq!(exact_result.decode_api().unwrap(), envelope);
        assert_eq!(
            exact_result.result_bytes.as_slice(),
            encode_lifecycle_command_response(&envelope).unwrap()
        );

        let root = tempfile::tempdir().unwrap();
        let store = FileLifecycleCommandJournal::open(root.path(), &request.cat_id).unwrap();
        let accepted = admit(&store, &projected);
        let (fenced, token) = store
            .record_stop_fence(
                &accepted,
                ExecutionStep {
                    name: id("strong_stop"),
                    recovery_payload: ExactBytes::new(b"scope-stopped".to_vec()),
                },
                ExactBytes::new(b"api-stop-fence".to_vec()),
            )
            .unwrap();
        let terminal = store
            .complete_after_stop(&fenced, &token, exact_result)
            .unwrap();
        assert_eq!(terminal_result(&terminal).decode_api().unwrap(), envelope);

        let other_request = api_request("operation_other", 20_000);
        let other_result =
            ExactCommandResult::from_api(&api_terminal_result(&other_request)).unwrap();
        let other_root = tempfile::tempdir().unwrap();
        let other_store =
            FileLifecycleCommandJournal::open(other_root.path(), &request.cat_id).unwrap();
        let accepted = admit(&other_store, &projected);
        let (fenced, token) = other_store
            .record_stop_fence(
                &accepted,
                ExecutionStep {
                    name: id("strong_stop"),
                    recovery_payload: ExactBytes::new(b"scope-stopped".to_vec()),
                },
                ExactBytes::new(b"api-stop-fence".to_vec()),
            )
            .unwrap();
        assert!(matches!(
            other_store.complete_after_stop(&fenced, &token, other_result),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn file_cap_covers_two_commands_and_two_maximum_canonical_results() {
        let predecessor_operation = id("operation_predecessor");
        let record = LifecycleJournalRecord::Command {
            version: JOURNAL_VERSION,
            command: Box::new(JournalCommandProjection {
                cat_id: id("cat_maximum_record"),
                operation_id: id("operation_current"),
                request_fingerprint: fingerprint(51),
                command_kind: LifecycleCommandKind::Start,
                expected_predecessor: ExpectedLifecyclePredecessor::Terminal {
                    operation_id: predecessor_operation.clone(),
                    result_digest: fingerprint(52),
                },
                canonical_request: ExactBytes::new(vec![0; COMMAND_PAYLOAD_MAX_BYTES]),
            }),
            superseded_predecessor: Some(SupersededPredecessor {
                operation_id: predecessor_operation,
                request_fingerprint: fingerprint(53),
                canonical_command: Box::new(JournalCommandProjection {
                    cat_id: id("cat_maximum_record"),
                    operation_id: id("operation_predecessor"),
                    request_fingerprint: fingerprint(53),
                    command_kind: LifecycleCommandKind::Start,
                    expected_predecessor: ExpectedLifecyclePredecessor::Genesis,
                    canonical_request: ExactBytes::new(vec![0; COMMAND_PAYLOAD_MAX_BYTES]),
                }),
                terminal_result: ExactCommandResult {
                    result_bytes: ExactBytes::new(vec![0; RESULT_MAX_BYTES]),
                    result_digest: fingerprint(52),
                },
            }),
            state: CommandJournalState::Terminal {
                result: ExactCommandResult {
                    result_bytes: ExactBytes::new(vec![0; RESULT_MAX_BYTES]),
                    result_digest: fingerprint(54),
                },
                stop_fence: None,
            },
        };
        let document = LifecycleJournalDocument {
            checkpoint: record,
            checkpoint_content_digest: fingerprint(55),
        };
        let encoded = serde_json::to_vec(&document).unwrap();
        assert!(
            encoded.len() <= JOURNAL_MAX_BYTES,
            "maximum closed record encoded to {} bytes above the {} byte cap",
            encoded.len(),
            JOURNAL_MAX_BYTES,
        );
    }

    #[test]
    fn operation_id_reuse_with_a_different_fingerprint_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_conflict");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let original = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &original);
        let conflict = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            2,
        );

        assert!(matches!(
            store.admit(&conflict, GenesisLocalInventory::ConfirmedEmpty),
            Err(LifecycleJournalError::OperationFingerprintConflict { .. })
        ));
        assert_eq!(store.load().unwrap().unwrap().record(), accepted.record());
    }

    #[test]
    fn genesis_with_physical_residue_and_missing_journal_has_zero_acceptance() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_residue");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );

        assert!(matches!(
            store.admit(
                &start,
                GenesisLocalInventory::PhysicalResidue {
                    description: "foreign VMM scope".into(),
                }
            ),
            Err(LifecycleJournalError::PhysicalResidueWithoutJournal { .. })
        ));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn cross_node_initial_target_is_accepted_only_with_confirmed_local_absence() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_handoff_target");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let request = cross_node_initial_request(cat.as_str(), "operation_handoff_start");

        let accepted = store
            .admit_api(&request, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap();
        let AdmitCommandOutcome::Accepted(accepted) = accepted else {
            panic!("clean cross-node target was not accepted")
        };
        assert!(accepted.predecessor_terminal_result().is_none());
    }

    #[test]
    fn cross_node_initial_target_with_physical_residue_has_zero_acceptance() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_handoff_residue");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let request = cross_node_initial_request(cat.as_str(), "operation_handoff_start");

        assert!(matches!(
            store.admit_api(
                &request,
                GenesisLocalInventory::PhysicalResidue {
                    description: "unattributed target VMM".into(),
                },
            ),
            Err(LifecycleJournalError::PhysicalResidueWithoutJournal { .. })
        ));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn cross_node_initial_target_with_forged_start_source_is_rejected_before_write() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_handoff_forged");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let mut request = cross_node_initial_request(cat.as_str(), "operation_handoff_start");
        let LifecycleCommand::Start(spec) = &mut request.command else {
            unreachable!()
        };
        spec.source = StartSource::Genesis;

        assert!(matches!(
            store.admit_api(&request, GenesisLocalInventory::ConfirmedEmpty),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn successor_requires_the_exact_terminal_predecessor() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_chain");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let first = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Stop,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &first);
        let premature = command(
            cat.as_str(),
            "operation_b",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Terminal {
                operation_id: first.operation_id.clone(),
                result_digest: fingerprint(9),
            },
            2,
        );
        assert!(matches!(
            store.admit(&premature, GenesisLocalInventory::ConfirmedEmpty),
            Err(LifecycleJournalError::CommandInProgress { .. })
        ));

        let executing = execute(&store, &accepted, true);
        let terminal = complete(&store, &executing, b"killed-exact-result");
        let wrong = command(
            cat.as_str(),
            "operation_b",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Terminal {
                operation_id: first.operation_id.clone(),
                result_digest: fingerprint(8),
            },
            2,
        );
        assert!(matches!(
            store.admit(&wrong, GenesisLocalInventory::ConfirmedEmpty),
            Err(LifecycleJournalError::PredecessorMismatch { .. })
        ));

        let exact = successor_of(cat.as_str(), "operation_b", &terminal, 2);
        let AdmitCommandOutcome::Accepted(successor) = store
            .admit(&exact, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap()
        else {
            panic!("exact successor was not accepted")
        };
        assert_eq!(successor.record().operation_id(), &exact.operation_id);
        let expected_predecessor_command = first.decode_api().unwrap();
        assert_eq!(
            successor.predecessor_command().unwrap(),
            Some(expected_predecessor_command.clone()),
        );
        assert_eq!(
            successor.predecessor_terminal_response().unwrap(),
            Some(terminal_result(&terminal).decode_api().unwrap()),
        );
        assert_eq!(
            successor
                .predecessor_terminal_result()
                .unwrap()
                .result_bytes(),
            terminal_result(&terminal).result_bytes(),
        );
        drop(store);

        let reopened = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let recovered = reopened
            .load()
            .unwrap()
            .expect("accepted failed Start retry journal");
        assert_eq!(
            recovered.predecessor_command().unwrap(),
            Some(expected_predecessor_command),
            "failed retry lost its exact canonical predecessor across restart",
        );
    }

    #[test]
    fn recovery_rejects_a_predecessor_response_with_a_recomputed_outer_digest() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_predecessor_corrupt");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let first = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &first);
        let executing = execute(&store, &accepted, true);
        let terminal = complete(&store, &executing, b"start-failed");
        let successor = successor_of(cat.as_str(), "operation_b", &terminal, 2);
        let accepted = match store
            .admit(&successor, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap()
        {
            AdmitCommandOutcome::Accepted(stored) => stored,
            other => panic!("unexpected successor outcome: {other:?}"),
        };
        let mut corrupted = accepted.record().clone();
        let LifecycleJournalRecord::Command {
            superseded_predecessor: Some(predecessor),
            ..
        } = &mut corrupted
        else {
            panic!("successor lost its bounded predecessor")
        };
        predecessor.terminal_result.result_digest = fingerprint(99);
        let document = LifecycleJournalDocument {
            checkpoint_content_digest: checkpoint_content_digest(&corrupted, store.path()).unwrap(),
            checkpoint: corrupted,
        };
        fs::write(
            store.path(),
            canonical_json_bytes(&document, store.path()).unwrap(),
        )
        .unwrap();

        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn successor_validates_shared_terminal_kind_node_and_placement_before_write() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_successor_binding");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let genesis = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let terminal = complete(
            &store,
            &execute(&store, &admit(&store, &genesis), true),
            b"start-failed",
        );
        let response = terminal_result(&terminal).decode_api().unwrap();
        let digest_before = terminal.content_digest().clone();

        for (declared_kind, node_id, placement_epoch) in [
            (TerminalResultKind::RuntimeReady, id("node_a"), 1),
            (TerminalResultKind::StartFailed, id("node_b"), 1),
            (TerminalResultKind::StartFailed, id("node_a"), 2),
        ] {
            let target = PlacementIdentity {
                node_id: node_id.clone(),
                placement_epoch: Epoch::new(placement_epoch).unwrap(),
            };
            let forged = LifecycleCommandEnvelope::new(
                id("operation_b"),
                response.workspace_id.clone(),
                cat.clone(),
                node_id.clone(),
                target.clone(),
                runtime_config(),
                Some(response.operation_id.clone()),
                LifecyclePredecessor::SameNode {
                    operation_id: response.operation_id.clone(),
                    terminal_result_kind: declared_kind,
                    terminal_result_digest: terminal_result(&terminal).result_digest.clone(),
                    node_id,
                    placement_identity: target,
                },
                LifecycleCommand::Stop(StopSpec {
                    grace_deadline_unix_ms: UnixMillis::new(30_000).unwrap(),
                }),
            )
            .unwrap();
            let forged = JournalCommandProjection::from_api(&forged).unwrap();
            assert!(matches!(
                store.admit(&forged, GenesisLocalInventory::ConfirmedEmpty),
                Err(LifecycleJournalError::PredecessorMismatch { .. })
            ));
            assert_eq!(
                store.load().unwrap().unwrap().content_digest(),
                &digest_before
            );
        }
    }

    #[test]
    fn stop_fence_is_replaced_only_by_start_and_inherited_by_stop_or_delete() {
        for successor_kind in [
            LifecycleCommandKind::Start,
            LifecycleCommandKind::Stop,
            LifecycleCommandKind::Delete,
        ] {
            let root = tempfile::tempdir().unwrap();
            let cat = id("cat_failure_successor");
            let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
            let genesis = command(
                cat.as_str(),
                "operation_a",
                LifecycleCommandKind::Start,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            );
            let terminal = complete(
                &store,
                &execute(&store, &admit(&store, &genesis), true),
                b"start-failed",
            );
            let successor =
                successor_command(cat.as_str(), "operation_b", &terminal, successor_kind, 2);
            let accepted = admit(&store, &successor);
            let LifecycleJournalRecord::Command {
                state: CommandJournalState::Accepted { stop_fence },
                ..
            } = accepted.record()
            else {
                panic!("successor was not durably Accepted")
            };
            assert_eq!(
                stop_fence.is_some(),
                successor_kind != LifecycleCommandKind::Start
            );
            let digest = accepted.content_digest().clone();
            assert!(matches!(
                store
                    .admit(&genesis, GenesisLocalInventory::ConfirmedEmpty)
                    .unwrap(),
                AdmitCommandOutcome::Superseded { .. }
            ));
            assert_eq!(store.load().unwrap().unwrap().content_digest(), &digest);
        }
    }

    #[test]
    fn killed_fence_survives_cold_or_delete_and_cold_converts_to_tombstone() {
        for successor_kind in [LifecycleCommandKind::Cold, LifecycleCommandKind::Delete] {
            let root = tempfile::tempdir().unwrap();
            let cat = id("cat_killed_successor");
            let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
            let genesis = command(
                cat.as_str(),
                "operation_genesis",
                LifecycleCommandKind::Start,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            );
            let start_failed = complete(
                &store,
                &execute(&store, &admit(&store, &genesis), true),
                b"start-failed",
            );
            let stop = successor_command(
                cat.as_str(),
                "operation_stop",
                &start_failed,
                LifecycleCommandKind::Stop,
                2,
            );
            let killed = complete(
                &store,
                &execute(&store, &admit(&store, &stop), true),
                b"killed",
            );
            assert_eq!(
                terminal_result(&killed).decode_api().unwrap().result.kind(),
                TerminalResultKind::Killed
            );
            let successor = successor_command(
                cat.as_str(),
                "operation_after_killed",
                &killed,
                successor_kind,
                3,
            );
            let accepted = admit(&store, &successor);
            assert!(command_state_stop_fence(match accepted.record() {
                LifecycleJournalRecord::Command { state, .. } => state,
                _ => unreachable!(),
            })
            .is_some());
            let executing = execute(&store, &accepted, true);
            let token = durable_stop_fence(&executing, store.path()).unwrap();
            if successor_kind == LifecycleCommandKind::Cold {
                let cold = store
                    .complete_after_stop(&executing, &token, result_for_stored(&executing))
                    .unwrap();
                let fence = command_state_stop_fence(match cold.record() {
                    LifecycleJournalRecord::Command { state, .. } => state,
                    _ => unreachable!(),
                })
                .unwrap();
                assert_eq!(
                    fence.state,
                    EmbeddedStopFenceState::ConvertedToColdTombstone
                );
            } else {
                let deleted = store
                    .complete_delete(&executing, &token, result_for_stored(&executing))
                    .unwrap();
                assert!(matches!(
                    deleted.record(),
                    LifecycleJournalRecord::CompletedDeleteReceipt { .. }
                ));
            }
        }
    }

    #[test]
    fn same_node_stopped_successor_retains_exact_typed_killed_evidence_across_restart() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_stopped_retry_evidence");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let genesis = command(
            cat.as_str(),
            "operation_stopped_retry_genesis",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let start_failed = complete(
            &store,
            &execute(&store, &admit(&store, &genesis), true),
            b"start-failed",
        );
        let stop = successor_command(
            cat.as_str(),
            "operation_stopped_retry_stop",
            &start_failed,
            LifecycleCommandKind::Stop,
            2,
        );
        let killed = complete(
            &store,
            &execute(&store, &admit(&store, &stop), true),
            b"killed",
        );
        let expected_exact = terminal_result(&killed).clone();
        let expected = expected_exact.decode_api().unwrap();
        let NodeResult::Killed(expected_killed) = &expected.result else {
            panic!("Stop fixture did not produce Killed")
        };
        assert_eq!(expected_killed.retained_volume_receipts.len(), 1);
        assert!(expected_killed.retained_volume_receipts[0]
            .authority_receipt_digest
            .is_some());
        assert_eq!(
            expected_killed
                .retained_evidence
                .retained_authority_or_data_count,
            1
        );

        let successor = successor_command(
            cat.as_str(),
            "operation_stopped_retry_start",
            &killed,
            LifecycleCommandKind::Start,
            3,
        );
        let accepted = admit(&store, &successor);
        assert_eq!(
            accepted.predecessor_terminal_response().unwrap(),
            Some(expected.clone())
        );
        assert_eq!(
            accepted.predecessor_terminal_result(),
            Some(&expected_exact)
        );
        drop(store);

        let reopened = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let recovered = reopened.load().unwrap().expect("accepted Start journal");
        assert_eq!(
            recovered.predecessor_terminal_response().unwrap(),
            Some(expected)
        );
        assert_eq!(
            recovered.predecessor_terminal_result(),
            Some(&expected_exact)
        );
    }

    #[test]
    fn old_operation_is_superseded_without_mutating_the_successor() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_superseded");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let old = command(
            cat.as_str(),
            "operation_old",
            LifecycleCommandKind::Stop,
            ExpectedLifecyclePredecessor::Genesis,
            3,
        );
        let old_terminal = complete(
            &store,
            &execute(&store, &admit(&store, &old), true),
            b"killed",
        );
        let new = successor_of(cat.as_str(), "operation_new", &old_terminal, 4);
        let successor = admit(&store, &new);
        let successor = execute(&store, &successor, false);
        let digest_before = successor.content_digest().clone();

        let AdmitCommandOutcome::Superseded {
            current_operation_id,
            current_record_digest,
        } = store
            .admit(&old, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap()
        else {
            panic!("old operation did not return Superseded")
        };
        assert_eq!(current_operation_id, new.operation_id);
        assert_eq!(current_record_digest, digest_before);
        assert_eq!(
            store.load().unwrap().unwrap().content_digest(),
            &digest_before
        );
        assert!(matches!(
            store
                .query(&LifecycleCommandQuery {
                    version: ContractVersion::V1,
                    node_id: id("node_a"),
                    cat_id: cat.clone(),
                    operation_id: old.operation_id.clone(),
                    request_fingerprint: old.request_fingerprint.clone(),
                })
                .unwrap(),
            QueryCommandOutcome::Superseded {
                current_operation_id,
                ..
            } if current_operation_id == new.operation_id
        ));
        assert!(matches!(
            store.query(&LifecycleCommandQuery {
                version: ContractVersion::V1,
                node_id: id("node_a"),
                cat_id: cat,
                operation_id: old.operation_id,
                request_fingerprint: fingerprint(99),
            }),
            Err(LifecycleJournalError::OperationFingerprintConflict { .. })
        ));
    }

    #[test]
    fn embedded_stop_fence_cannot_be_removed_or_replaced() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_fence");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let stop = command(
            cat.as_str(),
            "operation_stop",
            LifecycleCommandKind::Stop,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let fenced = execute(&store, &admit(&store, &stop), true);
        let next_step = ExecutionStep {
            name: id("effect_02"),
            recovery_payload: ExactBytes::new(b"next".to_vec()),
        };
        assert!(matches!(
            store.record_execution(&fenced, next_step.clone(), None),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert!(matches!(
            store.record_execution(
                &fenced,
                next_step,
                Some(EmbeddedStopFence {
                    fence_payload: ExactBytes::new(b"different-fence".to_vec()),
                    state: EmbeddedStopFenceState::Installed,
                })
            ),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert!(matches!(
            store.record_stop_fence(
                &fenced,
                ExecutionStep {
                    name: id("effect_03"),
                    recovery_payload: ExactBytes::new(b"next".to_vec()),
                },
                ExactBytes::new(b"different-fence".to_vec()),
            ),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        let names = fs::read_dir(root.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
            .collect::<Vec<_>>();
        assert!(names.iter().all(|name| !name.contains("stop-fence")));
        assert_eq!(
            names.iter().filter(|name| name.ends_with(".json")).count(),
            1
        );
    }

    #[test]
    fn durable_stop_capability_is_current_record_bound_and_store_is_worker_safe() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FileLifecycleCommandJournal>();
        assert_send_sync::<StoredLifecycleJournal>();
        assert_send_sync::<DurableStopFence>();

        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_stop_capability");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let stop = command(
            cat.as_str(),
            "operation_stop",
            LifecycleCommandKind::Stop,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let (fenced, token) = store
            .record_stop_fence(
                &admit(&store, &stop),
                ExecutionStep {
                    name: id("close_admission"),
                    recovery_payload: ExactBytes::new(b"closed".to_vec()),
                },
                ExactBytes::new(b"durable-stop-fence".to_vec()),
            )
            .unwrap();
        {
            let guard = store.retain_current_stop_fence(&fenced, &token).unwrap();
            assert_eq!(guard.cat_id(), &cat);
            assert_eq!(guard.operation_id(), &stop.operation_id);
            assert_eq!(guard.fence_payload(), b"durable-stop-fence");
            guard.assert_current().unwrap();
        }

        let (advanced, advanced_token) = store
            .advance_stop_fenced_execution(
                &fenced,
                &token,
                ExecutionStep {
                    name: id("kill_scope"),
                    recovery_payload: ExactBytes::new(b"scope-absent".to_vec()),
                },
            )
            .unwrap();
        assert!(matches!(
            store.retain_current_stop_fence(&advanced, &token),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert!(matches!(
            store.complete(&advanced, result_for_stored(&advanced)),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        let terminal = store
            .complete_after_stop(&advanced, &advanced_token, result_for_stored(&advanced))
            .unwrap();
        assert!(matches!(
            terminal.record(),
            LifecycleJournalRecord::Command {
                state: CommandJournalState::Terminal {
                    stop_fence: Some(_),
                    ..
                },
                ..
            }
        ));
        let recovered = store.recover_current_stop_fence(&terminal).unwrap();
        let guard = store
            .retain_current_stop_fence(&terminal, &recovered)
            .unwrap();
        guard.assert_current().unwrap();
    }

    #[test]
    fn not_running_terminal_cannot_bypass_durable_stop_fence() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_no_fence_bypass");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_start",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &start);
        let accepted_digest = accepted.content_digest().clone();
        assert!(matches!(
            store.complete(&accepted, result_for_stored(&accepted)),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert_eq!(
            store.load().unwrap().unwrap().content_digest(),
            &accepted_digest
        );

        let executing = execute(&store, &accepted, false);
        let executing_digest = executing.content_digest().clone();
        assert!(matches!(
            store.complete(&executing, result_for_stored(&executing)),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert_eq!(
            store.load().unwrap().unwrap().content_digest(),
            &executing_digest
        );

        let (fenced, token) = store
            .record_stop_fence(
                &executing,
                ExecutionStep {
                    name: id("prove_absence"),
                    recovery_payload: ExactBytes::new(b"absent".to_vec()),
                },
                ExactBytes::new(b"exact-fence".to_vec()),
            )
            .unwrap();
        store
            .complete_after_stop(&fenced, &token, result_for_stored(&fenced))
            .unwrap();
    }

    #[test]
    fn recovery_rejects_missing_terminal_or_inherited_fence_after_outer_digest_recompute() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_missing_recovered_fence");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_start",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let terminal = complete(
            &store,
            &execute(&store, &admit(&store, &start), true),
            b"failed",
        );

        let mut missing_terminal_fence = terminal.record().clone();
        let LifecycleJournalRecord::Command {
            state: CommandJournalState::Terminal { stop_fence, .. },
            ..
        } = &mut missing_terminal_fence
        else {
            panic!("fixture must be a command terminal")
        };
        *stop_fence = None;
        let document = LifecycleJournalDocument {
            checkpoint_content_digest: checkpoint_content_digest(
                &missing_terminal_fence,
                store.path(),
            )
            .unwrap(),
            checkpoint: missing_terminal_fence,
        };
        fs::write(
            store.path(),
            canonical_json_bytes(&document, store.path()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));

        let replacement = encode_record(terminal.record(), store.path()).unwrap();
        fs::write(store.path(), replacement).unwrap();
        let terminal = store.load().unwrap().unwrap();
        let stop = successor_command(
            cat.as_str(),
            "operation_stop",
            &terminal,
            LifecycleCommandKind::Stop,
            2,
        );
        let accepted = match store
            .admit(&stop, GenesisLocalInventory::ConfirmedEmpty)
            .unwrap()
        {
            AdmitCommandOutcome::Accepted(stored) => stored,
            other => panic!("unexpected successor outcome: {other:?}"),
        };
        let mut missing_inherited_fence = accepted.record().clone();
        let LifecycleJournalRecord::Command {
            state: CommandJournalState::Accepted { stop_fence },
            ..
        } = &mut missing_inherited_fence
        else {
            panic!("fixture must be an accepted command")
        };
        *stop_fence = None;
        let document = LifecycleJournalDocument {
            checkpoint_content_digest: checkpoint_content_digest(
                &missing_inherited_fence,
                store.path(),
            )
            .unwrap(),
            checkpoint: missing_inherited_fence,
        };
        fs::write(
            store.path(),
            canonical_json_bytes(&document, store.path()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn accepted_publication_crash_prefix_is_either_absent_or_exactly_replayable() {
        for stage in [
            WriteStage::BeforeTempWrite,
            WriteStage::TempWritten,
            WriteStage::TempSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let root = tempfile::tempdir().unwrap();
            let cat = id("cat_accept_crash");
            let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
            let start = command(
                cat.as_str(),
                "operation_a",
                LifecycleCommandKind::Start,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            );
            store.inject_crash_once(stage);
            assert!(matches!(
                store.admit(&start, GenesisLocalInventory::ConfirmedEmpty),
                Err(LifecycleJournalError::InjectedCrash)
            ));
            let visible = store.load().unwrap();
            if matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced) {
                let visible = visible.expect("post-rename command must be visible");
                assert_eq!(visible.record().operation_id(), &start.operation_id);
                assert!(matches!(
                    store
                        .admit(&start, GenesisLocalInventory::ConfirmedEmpty)
                        .unwrap(),
                    AdmitCommandOutcome::Replay(_)
                ));
            } else {
                assert!(
                    visible.is_none(),
                    "pre-rename command became visible at {stage:?}"
                );
            }
        }
    }

    #[test]
    fn successor_publication_crash_never_creates_a_mixed_chain() {
        for stage in [
            WriteStage::BeforeTempWrite,
            WriteStage::TempWritten,
            WriteStage::TempSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let root = tempfile::tempdir().unwrap();
            let cat = id("cat_successor_crash");
            let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
            let old = command(
                cat.as_str(),
                "operation_old",
                LifecycleCommandKind::Stop,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            );
            let old_terminal = complete(
                &store,
                &execute(&store, &admit(&store, &old), true),
                b"killed",
            );
            let new = successor_of(cat.as_str(), "operation_new", &old_terminal, 2);
            store.inject_crash_once(stage);
            assert!(matches!(
                store.admit(&new, GenesisLocalInventory::ConfirmedEmpty),
                Err(LifecycleJournalError::InjectedCrash)
            ));
            let visible = store.load().unwrap().unwrap();
            if matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced) {
                assert_eq!(visible.record().operation_id(), &new.operation_id);
                assert!(matches!(
                    store
                        .admit(&old, GenesisLocalInventory::ConfirmedEmpty)
                        .unwrap(),
                    AdmitCommandOutcome::Superseded { .. }
                ));
            } else {
                assert_eq!(visible.record().operation_id(), &old.operation_id);
                assert!(matches!(
                    store
                        .admit(&old, GenesisLocalInventory::ConfirmedEmpty)
                        .unwrap(),
                    AdmitCommandOutcome::Replay(_)
                ));
            }
        }
    }

    #[test]
    fn terminal_publication_crash_replays_only_a_whole_result() {
        for stage in [
            WriteStage::BeforeTempWrite,
            WriteStage::TempWritten,
            WriteStage::TempSynced,
            WriteStage::Renamed,
            WriteStage::DirectorySynced,
        ] {
            let root = tempfile::tempdir().unwrap();
            let cat = id("cat_terminal_crash");
            let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
            let start = command(
                cat.as_str(),
                "operation_a",
                LifecycleCommandKind::Start,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            );
            let executing = execute(&store, &admit(&store, &start), true);
            let token = durable_stop_fence(&executing, store.path()).unwrap();
            store.inject_crash_once(stage);
            assert!(matches!(
                store.complete_after_stop(&executing, &token, result_for_stored(&executing)),
                Err(LifecycleJournalError::InjectedCrash)
            ));
            let visible = store.load().unwrap().unwrap();
            assert_eq!(visible.record().operation_id(), &start.operation_id);
            assert_eq!(
                matches!(
                    visible.record(),
                    LifecycleJournalRecord::Command {
                        state: CommandJournalState::Terminal { .. },
                        ..
                    }
                ),
                matches!(stage, WriteStage::Renamed | WriteStage::DirectorySynced)
            );
        }
    }

    #[test]
    fn real_process_exit_after_temp_fsync_leaves_no_accepted_authority() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_real_crash");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );

        // SAFETY: the child performs only this test's bounded journal write
        // and then intentionally exits without destructors.
        let child = unsafe { libc::fork() };
        assert!(child >= 0, "fork failed: {}", io::Error::last_os_error());
        if child == 0 {
            store.inject_process_exit_once(WriteStage::TempSynced);
            let _ = store.admit(&start, GenesisLocalInventory::ConfirmedEmpty);
            // SAFETY: reaching here means the intended injection failed.
            unsafe { libc::_exit(99) }
        }
        let mut status = 0;
        // SAFETY: `child` is the live child PID returned by fork.
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), TEST_PROCESS_EXIT_CODE);
        assert!(!store.path().exists());
        assert!(root.path().join(temporary_file_name(&cat)).exists());

        drop(store);
        let recovered = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        assert!(!root.path().join(temporary_file_name(&cat)).exists());
        assert!(recovered.load().unwrap().is_none());
        assert!(matches!(
            recovered
                .admit(&start, GenesisLocalInventory::ConfirmedEmpty)
                .unwrap(),
            AdmitCommandOutcome::Accepted(_)
        ));
    }

    #[test]
    fn stale_temp_is_removed_but_never_adopted() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_stale_temp");
        let temporary = root.path().join(temporary_file_name(&cat));
        fs::write(&temporary, b"uncommitted accepted command").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();

        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        assert!(!temporary.exists());
        assert!(store.load().unwrap().is_none());
    }

    #[test]
    fn unsafe_stale_temp_residue_is_preserved_and_fails_closed() {
        for kind in ["symlink", "fifo", "hardlink"] {
            let root = tempfile::tempdir().unwrap();
            let cat = id(&format!("cat_unsafe_temp_{kind}"));
            let temporary = root.path().join(temporary_file_name(&cat));
            match kind {
                "symlink" => {
                    let outside = root.path().join("outside");
                    fs::write(&outside, b"foreign").unwrap();
                    symlink(&outside, &temporary).unwrap();
                }
                "fifo" => {
                    let temporary = CString::new(temporary.as_os_str().as_bytes()).unwrap();
                    // SAFETY: the C string is NUL-terminated and names a path
                    // owned by this temporary test directory.
                    assert_eq!(unsafe { libc::mkfifo(temporary.as_ptr(), 0o600) }, 0);
                }
                "hardlink" => {
                    let outside = root.path().join("outside");
                    fs::write(&outside, b"foreign").unwrap();
                    fs::hard_link(&outside, &temporary).unwrap();
                }
                _ => unreachable!(),
            }

            assert!(FileLifecycleCommandJournal::open(root.path(), &cat).is_err());
            assert!(
                fs::symlink_metadata(&temporary).is_ok(),
                "unsafe {kind} temp was silently removed"
            );
        }
    }

    #[test]
    fn publish_time_temp_substitution_is_preserved_without_command_authority() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_publish_temp_substitution");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let outside = root.path().join("outside");
        fs::write(&outside, b"foreign").unwrap();
        let temporary = root.path().join(temporary_file_name(&cat));
        symlink(&outside, &temporary).unwrap();

        let start = command(
            cat.as_str(),
            "operation_start",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        assert!(store
            .admit(&start, GenesisLocalInventory::ConfirmedEmpty)
            .is_err());
        assert!(fs::symlink_metadata(&temporary)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(!store.path().exists());
        assert_eq!(fs::read(&outside).unwrap(), b"foreign");
    }

    #[test]
    fn final_directory_leaf_is_created_descriptor_relatively_and_symlink_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let namespace = root.path().join("journal");
        let cat = id("cat_directory_create");
        let store = FileLifecycleCommandJournal::open(&namespace, &cat).unwrap();
        assert!(namespace.is_dir());
        assert_eq!(
            fs::metadata(&namespace).unwrap().permissions().mode() & 0o077,
            0
        );
        drop(store);

        let symlink_root = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let namespace = symlink_root.path().join("journal");
        symlink(outside.path(), &namespace).unwrap();
        assert!(FileLifecycleCommandJournal::open(&namespace, &cat).is_err());
    }

    #[test]
    fn per_cat_flock_excludes_a_second_writer() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_lock");
        let first = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        assert!(matches!(
            FileLifecycleCommandJournal::open(root.path(), &cat),
            Err(LifecycleJournalError::WriterAlreadyActive { .. })
        ));
        drop(first);
        FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
    }

    #[test]
    fn symlink_and_hard_link_targets_fail_closed() {
        let symlink_root = tempfile::tempdir().unwrap();
        let cat = id("cat_symlink");
        let store = FileLifecycleCommandJournal::open(symlink_root.path(), &cat).unwrap();
        let outside = symlink_root.path().join("outside");
        fs::write(&outside, b"outside").unwrap();
        symlink(&outside, store.path()).unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::UnsafeEntry { .. })
        ));

        let hard_root = tempfile::tempdir().unwrap();
        let cat = id("cat_hardlink");
        let store = FileLifecycleCommandJournal::open(hard_root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        admit(&store, &start);
        fs::hard_link(store.path(), hard_root.path().join("alias")).unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::UnsafeEntry { .. })
        ));
    }

    #[test]
    fn semantic_aba_and_renamed_namespace_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let namespace = root.path().join("journal");
        let cat = id("cat_aba");
        let store = FileLifecycleCommandJournal::open(&namespace, &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let accepted = admit(&store, &start);
        let moved_leaf = root.path().join("old-record");
        fs::rename(store.path(), &moved_leaf).unwrap();
        fs::copy(&moved_leaf, store.path()).unwrap();
        assert!(matches!(
            store.record_execution(
                &accepted,
                ExecutionStep {
                    name: id("effect_01"),
                    recovery_payload: ExactBytes::new(b"state".to_vec()),
                },
                None
            ),
            Err(LifecycleJournalError::ConcurrentUpdate { .. })
        ));

        let fresh = store.load().unwrap().unwrap();
        let moved_namespace = root.path().join("moved-journal");
        fs::rename(&namespace, &moved_namespace).unwrap();
        fs::create_dir(&namespace).unwrap();
        fs::set_permissions(&namespace, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            store.record_execution(
                &fresh,
                ExecutionStep {
                    name: id("effect_01"),
                    recovery_payload: ExactBytes::new(b"state".to_vec()),
                },
                None
            ),
            Err(LifecycleJournalError::UnsafeEntry { .. })
        ));
    }

    #[test]
    fn retained_state_directory_rejects_ancestor_rename_recreate() {
        let parent = tempfile::tempdir().unwrap();
        let state_path = parent.path().join("state");
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();
        let state_directory = StateDirectory::unanchored(state_path.clone());
        let cat = id("cat_state_namespace_replaced");
        let store =
            FileLifecycleCommandJournal::open_in_state_directory(&state_directory, &cat).unwrap();
        let accepted = admit(
            &store,
            &command(
                cat.as_str(),
                "operation_start",
                LifecycleCommandKind::Start,
                ExpectedLifecyclePredecessor::Genesis,
                1,
            ),
        );

        let detached_state = parent.path().join("detached-state");
        fs::rename(&state_path, &detached_state).unwrap();
        fs::create_dir(&state_path).unwrap();
        fs::set_permissions(&state_path, fs::Permissions::from_mode(0o700)).unwrap();

        assert!(matches!(
            store.record_execution(
                &accepted,
                ExecutionStep {
                    name: id("effect_01"),
                    recovery_payload: ExactBytes::new(b"state".to_vec()),
                },
                None,
            ),
            Err(LifecycleJournalError::UnsafeEntry { .. })
        ));
        assert!(!state_path
            .join(LIFECYCLE_JOURNAL_DIRECTORY_NAME)
            .join(target_file_name(&cat))
            .exists());
    }

    #[test]
    fn delete_success_becomes_minimal_non_executable_receipt() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_delete");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let (delete, executing) = accepted_delete(&store, cat.as_str(), 7);
        let canonical_request = delete.canonical_request.as_slice().to_vec();
        let result = result_for_stored(&executing);
        let token = durable_stop_fence(&executing, store.path()).unwrap();
        let receipt = store
            .complete_delete(&executing, &token, result.clone())
            .unwrap();

        assert!(matches!(
            receipt.record(),
            LifecycleJournalRecord::CompletedDeleteReceipt {
                receipt: stored_receipt,
                ..
            } if stored_receipt.operation_id == delete.operation_id
                && stored_receipt.terminal_response.as_ref() == &result.decode_api().unwrap()
        ));
        let bytes = fs::read(store.path()).unwrap();
        let encoded_request = URL_SAFE_NO_PAD.encode(canonical_request);
        assert!(!bytes
            .windows(encoded_request.len())
            .any(|window| window == encoded_request.as_bytes()));
        assert!(matches!(
            store.record_execution(
                &receipt,
                ExecutionStep {
                    name: id("forbidden"),
                    recovery_payload: ExactBytes::new(Vec::new()),
                },
                None
            ),
            Err(LifecycleJournalError::IllegalTransition { .. })
        ));
        assert!(matches!(
            store
                .admit(&delete, GenesisLocalInventory::ConfirmedEmpty)
                .unwrap(),
            AdmitCommandOutcome::Replay(_)
        ));
    }

    fn accepted_delete(
        store: &FileLifecycleCommandJournal,
        cat_name: &str,
        seed: u8,
    ) -> (JournalCommandProjection, StoredLifecycleJournal) {
        let genesis = command(
            cat_name,
            "operation_genesis",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            seed,
        );
        let genesis_terminal = complete(
            store,
            &execute(store, &admit(store, &genesis), true),
            b"start-failed",
        );
        let delete = command(
            cat_name,
            "operation_delete",
            LifecycleCommandKind::Delete,
            ExpectedLifecyclePredecessor::Terminal {
                operation_id: genesis.operation_id,
                result_digest: terminal_result(&genesis_terminal).result_digest.clone(),
            },
            seed.saturating_add(1),
        );
        let executing = execute(store, &admit(store, &delete), true);
        (delete, executing)
    }

    fn completed_delete_fixture(
        root: &Path,
        cat_name: &str,
    ) -> (
        FileLifecycleCommandJournal,
        JournalCommandProjection,
        ExactCommandResult,
    ) {
        let cat = id(cat_name);
        let store = FileLifecycleCommandJournal::open(root, &cat).unwrap();
        let (delete, executing) = accepted_delete(&store, cat.as_str(), 9);
        let result = result_for_stored(&executing);
        let token = durable_stop_fence(&executing, store.path()).unwrap();
        store
            .complete_delete(&executing, &token, result.clone())
            .unwrap();
        (store, delete, result)
    }

    #[test]
    fn only_exact_result_stored_ack_can_unlink_delete_receipt() {
        let root = tempfile::tempdir().unwrap();
        let (store, delete, result) = completed_delete_fixture(root.path(), "cat_delete_ack");
        let exact = LifecycleResultStoredAck {
            version: ContractVersion::V1,
            node_id: id("node_a"),
            cat_id: delete.cat_id.clone(),
            operation_id: delete.operation_id.clone(),
            request_fingerprint: delete.request_fingerprint.clone(),
            terminal_result_digest: result.result_digest.clone(),
        };
        let mut wrong = exact.clone();
        wrong.terminal_result_digest = fingerprint(1);
        assert!(matches!(
            store.acknowledge_delete(&wrong),
            Err(LifecycleJournalError::DeleteAckMismatch)
        ));
        assert!(store.path().is_file());
        let mut wrong_node = exact.clone();
        wrong_node.node_id = id("node_b");
        assert!(matches!(
            store.acknowledge_delete(&wrong_node),
            Err(LifecycleJournalError::DeleteAckMismatch)
        ));
        assert!(store.path().is_file());
        assert_eq!(
            store.acknowledge_delete(&exact).unwrap(),
            DeleteReceiptAckOutcome::Removed
        );
        assert!(!store.path().exists());
    }

    #[test]
    fn delete_ack_crash_prefix_never_unlinks_before_exact_validation() {
        for stage in [
            WriteStage::BeforeDeleteUnlink,
            WriteStage::DeleteUnlinked,
            WriteStage::DeleteDirectorySynced,
        ] {
            let root = tempfile::tempdir().unwrap();
            let (store, delete, result) =
                completed_delete_fixture(root.path(), "cat_delete_ack_crash");
            let exact = LifecycleResultStoredAck {
                version: ContractVersion::V1,
                node_id: id("node_a"),
                cat_id: delete.cat_id,
                operation_id: delete.operation_id,
                request_fingerprint: delete.request_fingerprint,
                terminal_result_digest: result.result_digest,
            };
            store.inject_crash_once(stage);
            assert!(matches!(
                store.acknowledge_delete(&exact),
                Err(LifecycleJournalError::InjectedCrash)
            ));
            assert_eq!(
                store.path().exists(),
                stage == WriteStage::BeforeDeleteUnlink,
                "unexpected Delete receipt visibility at {stage:?}"
            );
        }
    }

    #[test]
    fn startup_enumeration_is_per_cat_and_missing_with_residue_fails_closed() {
        let root = tempfile::tempdir().unwrap();
        let good_cat = id("cat_good");
        let good_store = FileLifecycleCommandJournal::open(root.path(), &good_cat).unwrap();
        let good = command(
            good_cat.as_str(),
            "operation_good",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        admit(&good_store, &good);
        drop(good_store);

        let bad_cat = id("cat_bad");
        let bad_path = root.path().join(target_file_name(&bad_cat));
        fs::write(&bad_path, b"{not-json").unwrap();
        fs::set_permissions(&bad_path, fs::Permissions::from_mode(0o600)).unwrap();
        let missing_cat = id("cat_missing");
        let physical = complete_physical_inventory([missing_cat.clone()]);

        let inventory = enumerate_startup(root.path(), &physical).unwrap();
        assert_eq!(inventory.recoverable.len(), 1);
        assert_eq!(inventory.recoverable[0].cat_id, good_cat);
        assert_eq!(
            inventory
                .blocked
                .iter()
                .map(|blocked| blocked.cat_id.clone())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([bad_cat, missing_cat])
        );
    }

    #[test]
    fn startup_quarantines_delete_residue_but_keeps_exact_receipt_settleable() {
        let root = tempfile::tempdir().unwrap();
        let (store, delete, _) = completed_delete_fixture(root.path(), "cat_deleted_residue");
        drop(store);
        let inventory = enumerate_startup(
            root.path(),
            &complete_physical_inventory([delete.cat_id.clone()]),
        )
        .unwrap();
        assert_eq!(inventory.recoverable.len(), 1);
        assert_eq!(inventory.recoverable[0].cat_id, delete.cat_id);
        assert!(matches!(
            &inventory.recoverable[0].record,
            LifecycleJournalRecord::CompletedDeleteReceipt { .. }
        ));
        assert!(inventory.blocked.is_empty());
        assert_eq!(inventory.quarantined_terminals.len(), 1);
        assert_eq!(inventory.quarantined_terminals[0].cat_id, delete.cat_id);
        assert!(inventory.quarantined_terminals[0]
            .reason
            .contains("contradicts"));
    }

    #[test]
    fn incomplete_startup_inventory_cannot_be_treated_as_empty() {
        let root = tempfile::tempdir().unwrap();
        assert!(matches!(
            enumerate_startup(
                root.path(),
                &StartupPhysicalInventory::Incomplete {
                    reason: "scope scan timed out".into(),
                }
            ),
            Err(LifecycleJournalError::IncompletePhysicalInventory { .. })
        ));
    }

    #[test]
    fn corrupt_result_digest_and_noncanonical_json_fail_closed() {
        let root = tempfile::tempdir().unwrap();
        let cat = id("cat_corrupt");
        let store = FileLifecycleCommandJournal::open(root.path(), &cat).unwrap();
        let start = command(
            cat.as_str(),
            "operation_a",
            LifecycleCommandKind::Start,
            ExpectedLifecyclePredecessor::Genesis,
            1,
        );
        let executing = execute(&store, &admit(&store, &start), true);
        let terminal = complete(&store, &executing, b"failed-not-running");
        let canonical = encode_record(terminal.record(), store.path()).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["checkpoint"]["state"]["result"]["result_digest"] =
            serde_json::Value::String(fingerprint(4).to_string());
        fs::write(
            store.path(),
            canonical_json_bytes(&value, store.path()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));

        let mut value: serde_json::Value = serde_json::from_slice(&canonical).unwrap();
        value["checkpoint"]["state"]["stop_fence"]["fence_payload"] =
            serde_json::Value::String(URL_SAFE_NO_PAD.encode(b"valid-but-tampered-fence"));
        fs::write(
            store.path(),
            canonical_json_bytes(&value, store.path()).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));

        let mut whitespace = b" ".to_vec();
        whitespace.extend(&canonical);
        fs::write(store.path(), whitespace).unwrap();
        assert!(matches!(
            store.load(),
            Err(LifecycleJournalError::InvalidRecord { .. })
        ));
    }
}
