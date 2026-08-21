//! Crash-safe exact-report journal for runtime inventory telemetry.

use std::collections::BTreeSet;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use cats_api::runtime_inventory::{
    decode_runtime_inventory_acceptance, decode_runtime_inventory_report,
    encode_runtime_inventory_acceptance, encode_runtime_inventory_report, full_inventory_digest,
    RuntimeInventoryAcceptance, RuntimeInventoryAcceptanceKind, RuntimeInventoryAttestation,
    RuntimeInventoryBody, RuntimeInventoryReport, RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES,
    RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES,
};
use cats_api::runtime_reconciliation::{
    encode_agent_session, AgentSession, ContractVersion, Epoch, Id, RandomId128, Sequence,
    SessionBinding, UnixMillis,
};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

use crate::state_directory::StateDirectory;

const JOURNAL_VERSION: u64 = 1;
const DIRECTORY_NAME: &str = "runtime-inventory-journal";
const STATE_FILE: &str = "state.json";
const TEMPORARY_FILE: &str = ".state.json.tmp";
// One accepted Full report plus one pending report dominate this bound after
// base64url expansion. Acceptance records are independently capped at 16 KiB.
const JOURNAL_MAX_BYTES: usize = 24 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
struct ExactBytes(Vec<u8>);

impl ExactBytes {
    fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    fn as_slice(&self) -> &[u8] {
        &self.0
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
                "runtime inventory journal bytes are not canonical base64url",
            ));
        }
        Ok(Self(decoded))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedFullRecord {
    report: ExactBytes,
    acceptance: ExactBytes,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeInventoryJournalDocument {
    journal_version: u64,
    session: SessionBinding,
    pending_report: Option<ExactBytes>,
    last_acceptance: Option<ExactBytes>,
    accepted_full: Option<AcceptedFullRecord>,
}

/// One process-owned exact-report journal. All mutation methods replace one
/// canonical file and fsync the containing descriptor before returning.
pub struct RuntimeInventoryJournal {
    directory: File,
    directory_path: PathBuf,
    document: RuntimeInventoryJournalDocument,
}

impl std::fmt::Debug for RuntimeInventoryJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeInventoryJournal")
            .field("directory_path", &self.directory_path)
            .field("session", &self.document.session)
            .field("pending", &self.document.pending_report.is_some())
            .field("accepted_full", &self.document.accepted_full.is_some())
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
pub enum RuntimeInventoryJournalError {
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("unsafe runtime inventory journal at {path}: {reason}")]
    UnsafeEntry { path: PathBuf, reason: String },
    #[error("corrupt runtime inventory journal at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("runtime inventory journal contract failed: {context}")]
    InvalidContract { context: &'static str },
    #[error("runtime inventory sequence or epoch exhausted")]
    SequenceExhausted,
    #[error("runtime inventory journal belongs to another Node")]
    WrongNode,
    #[error("runtime inventory journal contains a newer AgentSession")]
    NewerSession,
    #[error("runtime inventory journal reused one session epoch with another binding")]
    SessionBindingConflict,
    #[error("runtime inventory already has one unresolved exact report")]
    PendingReport,
    #[error("runtime inventory acceptance has no pending exact report")]
    MissingPendingReport,
    #[error("runtime inventory acceptance does not match the pending exact report")]
    AcceptanceMismatch,
    #[error("Partial runtime inventory has no accepted Full attestation")]
    MissingFullInventory,
    #[error("Partial runtime inventory introduced Cat {cat_id} outside the accepted Full")]
    PartialCatNotInFull { cat_id: Id },
}

impl RuntimeInventoryJournal {
    pub fn open(
        state_directory: &StateDirectory,
        session: &AgentSession,
    ) -> Result<Self, RuntimeInventoryJournalError> {
        encode_agent_session(session).map_err(|_| {
            RuntimeInventoryJournalError::InvalidContract {
                context: "validate AgentSession",
            }
        })?;
        let parent = state_directory.try_clone_directory().map_err(|source| {
            io_error(
                "open identity-selected Node state directory",
                state_directory.path(),
                source,
            )
        })?;
        let directory_path = state_directory.path().join(DIRECTORY_NAME);
        let directory = ensure_directory(&parent, &directory_path)?;
        let expected_session = session_binding(session);
        let document = match read_document(&directory, &directory_path)? {
            None => RuntimeInventoryJournalDocument::empty(expected_session),
            Some(document) if document.session == expected_session => document,
            Some(document) => {
                if document.session.node_id != expected_session.node_id {
                    return Err(RuntimeInventoryJournalError::WrongNode);
                }
                if document.session.agent_session_epoch > expected_session.agent_session_epoch {
                    return Err(RuntimeInventoryJournalError::NewerSession);
                }
                if document.session.agent_session_epoch == expected_session.agent_session_epoch {
                    return Err(RuntimeInventoryJournalError::SessionBindingConflict);
                }
                RuntimeInventoryJournalDocument::empty(expected_session)
            }
        };
        validate_document(&document, &directory_path)?;
        let journal = Self {
            directory,
            directory_path,
            document,
        };
        // Persist both first initialization and an exact newer-session reset
        // before any physical scan or network request can begin.
        journal.persist()?;
        Ok(journal)
    }

    pub fn session(&self) -> &SessionBinding {
        &self.document.session
    }

    pub fn pending_report(
        &self,
    ) -> Result<Option<(RuntimeInventoryReport, Vec<u8>)>, RuntimeInventoryJournalError> {
        self.document
            .pending_report
            .as_ref()
            .map(|bytes| {
                let report = decode_canonical_report(bytes, "decode pending report")?;
                Ok((report, bytes.0.clone()))
            })
            .transpose()
    }

    pub fn accepted_full(
        &self,
    ) -> Result<
        Option<(RuntimeInventoryReport, RuntimeInventoryAcceptance)>,
        RuntimeInventoryJournalError,
    > {
        self.document
            .accepted_full
            .as_ref()
            .map(decode_full_record)
            .transpose()
    }

    pub fn accepted_full_attestation(
        &self,
    ) -> Result<Option<RuntimeInventoryAttestation>, RuntimeInventoryJournalError> {
        let Some((_, acceptance)) = self.accepted_full()? else {
            return Ok(None);
        };
        let RuntimeInventoryAcceptanceKind::Full { attestation } = acceptance.inventory else {
            return Err(corrupt(
                &self.directory_path,
                "accepted Full record contains a Partial acceptance",
            ));
        };
        Ok(Some(*attestation))
    }

    pub fn full_cat_ids(&self) -> Result<Vec<Id>, RuntimeInventoryJournalError> {
        let Some((report, _)) = self.accepted_full()? else {
            return Ok(Vec::new());
        };
        Ok(report
            .inventory
            .cats()
            .iter()
            .map(|cat| cat.cat_id.clone())
            .collect())
    }

    pub fn next_sequence(&self) -> Result<Sequence, RuntimeInventoryJournalError> {
        match self.last_acceptance()? {
            None => Sequence::new(1).ok_or(RuntimeInventoryJournalError::SequenceExhausted),
            Some(acceptance) => checked_next_sequence(acceptance.sequence),
        }
    }

    pub fn next_full_epoch(&self) -> Result<Epoch, RuntimeInventoryJournalError> {
        match self.accepted_full_attestation()? {
            None => Epoch::new(1).ok_or(RuntimeInventoryJournalError::SequenceExhausted),
            Some(attestation) => checked_next_epoch(attestation.inventory_epoch),
        }
    }

    pub fn current_full_epoch(&self) -> Result<Option<Epoch>, RuntimeInventoryJournalError> {
        Ok(self
            .accepted_full_attestation()?
            .map(|attestation| attestation.inventory_epoch))
    }

    pub fn prepare_report(
        &mut self,
        report: RuntimeInventoryReport,
    ) -> Result<Vec<u8>, RuntimeInventoryJournalError> {
        if self.document.pending_report.is_some() {
            return Err(RuntimeInventoryJournalError::PendingReport);
        }
        if report.session != self.document.session || report.sequence != self.next_sequence()? {
            return Err(RuntimeInventoryJournalError::InvalidContract {
                context: "report session or sequence",
            });
        }
        match &report.inventory {
            RuntimeInventoryBody::Full {
                inventory_epoch, ..
            } if *inventory_epoch != self.next_full_epoch()? => {
                return Err(RuntimeInventoryJournalError::InvalidContract {
                    context: "Full inventory epoch",
                })
            }
            RuntimeInventoryBody::Partial {
                inventory_epoch,
                cats,
            } => {
                let Some(current_epoch) = self.current_full_epoch()? else {
                    return Err(RuntimeInventoryJournalError::MissingFullInventory);
                };
                if *inventory_epoch != current_epoch {
                    return Err(RuntimeInventoryJournalError::InvalidContract {
                        context: "Partial inventory epoch",
                    });
                }
                let full_members: BTreeSet<Id> = self.full_cat_ids()?.into_iter().collect();
                if let Some(cat) = cats.iter().find(|cat| !full_members.contains(&cat.cat_id)) {
                    return Err(RuntimeInventoryJournalError::PartialCatNotInFull {
                        cat_id: cat.cat_id.clone(),
                    });
                }
            }
            RuntimeInventoryBody::Full { .. } => {}
        }
        let bytes = encode_runtime_inventory_report(&report).map_err(|_| {
            RuntimeInventoryJournalError::InvalidContract {
                context: "encode report",
            }
        })?;
        self.document.pending_report = Some(ExactBytes::new(bytes.clone()));
        self.persist()?;
        Ok(bytes)
    }

    pub fn accept_pending(
        &mut self,
        exact_acceptance: Vec<u8>,
    ) -> Result<RuntimeInventoryAcceptance, RuntimeInventoryJournalError> {
        let acceptance = decode_canonical_acceptance(
            &ExactBytes::new(exact_acceptance.clone()),
            "decode pending acceptance",
        )?;
        let pending = self
            .document
            .pending_report
            .as_ref()
            .ok_or(RuntimeInventoryJournalError::MissingPendingReport)?;
        let report = decode_canonical_report(pending, "decode pending report")?;
        if !acceptance_matches_report(&acceptance, &report) {
            return Err(RuntimeInventoryJournalError::AcceptanceMismatch);
        }
        if matches!(report.inventory, RuntimeInventoryBody::Full { .. }) {
            self.document.accepted_full = Some(AcceptedFullRecord {
                report: pending.clone(),
                acceptance: ExactBytes::new(exact_acceptance.clone()),
            });
        }
        self.document.last_acceptance = Some(ExactBytes::new(exact_acceptance));
        self.document.pending_report = None;
        validate_document(&self.document, &self.directory_path)?;
        self.persist()?;
        Ok(acceptance)
    }

    fn last_acceptance(
        &self,
    ) -> Result<Option<RuntimeInventoryAcceptance>, RuntimeInventoryJournalError> {
        self.document
            .last_acceptance
            .as_ref()
            .map(|bytes| decode_canonical_acceptance(bytes, "decode last acceptance"))
            .transpose()
    }

    fn persist(&self) -> Result<(), RuntimeInventoryJournalError> {
        let bytes = encode_document(&self.document)?;
        replace_file(
            &self.directory,
            &self.directory_path,
            STATE_FILE,
            TEMPORARY_FILE,
            &bytes,
        )
    }
}

impl RuntimeInventoryJournalDocument {
    fn empty(session: SessionBinding) -> Self {
        Self {
            journal_version: JOURNAL_VERSION,
            session,
            pending_report: None,
            last_acceptance: None,
            accepted_full: None,
        }
    }
}

fn validate_document(
    document: &RuntimeInventoryJournalDocument,
    path: &Path,
) -> Result<(), RuntimeInventoryJournalError> {
    if document.journal_version != JOURNAL_VERSION {
        return Err(corrupt(path, "unsupported journal version"));
    }
    let full = document
        .accepted_full
        .as_ref()
        .map(decode_full_record)
        .transpose()?;
    let last = document
        .last_acceptance
        .as_ref()
        .map(|bytes| decode_canonical_acceptance(bytes, "decode last acceptance"))
        .transpose()?;
    if let Some((report, acceptance)) = &full {
        if report.session != document.session || acceptance.session != document.session {
            return Err(corrupt(path, "accepted Full belongs to another session"));
        }
    }
    match (&full, &last) {
        (None, Some(_)) => return Err(corrupt(path, "last acceptance exists without a Full")),
        (Some((_, full_acceptance)), Some(last_acceptance))
            if last_acceptance.sequence < full_acceptance.sequence =>
        {
            return Err(corrupt(path, "last acceptance predates accepted Full"))
        }
        (Some((_, full_acceptance)), Some(last_acceptance))
            if matches!(
                &last_acceptance.inventory,
                RuntimeInventoryAcceptanceKind::Full { .. }
            ) && last_acceptance != full_acceptance =>
        {
            return Err(corrupt(
                path,
                "last Full acceptance differs from retained Full",
            ))
        }
        (Some((_, full_acceptance)), Some(last_acceptance)) => {
            let full_epoch = full_acceptance.inventory_epoch();
            if last_acceptance.session != document.session
                || last_acceptance.sequence < full_acceptance.sequence
                || last_acceptance.inventory_epoch() != full_epoch
            {
                return Err(corrupt(path, "last acceptance projection is inconsistent"));
            }
        }
        (Some(_), None) => return Err(corrupt(path, "accepted Full has no last acceptance")),
        (None, None) => {}
    }
    if let Some(pending) = &document.pending_report {
        let report = decode_canonical_report(pending, "decode pending report")?;
        if report.session != document.session {
            return Err(corrupt(path, "pending report belongs to another session"));
        }
        let expected_sequence = match &last {
            None => Sequence::new(1).ok_or(RuntimeInventoryJournalError::SequenceExhausted)?,
            Some(last) => checked_next_sequence(last.sequence)?,
        };
        if report.sequence != expected_sequence {
            return Err(corrupt(path, "pending report is not the next sequence"));
        }
        match (&report.inventory, &full) {
            (
                RuntimeInventoryBody::Full {
                    inventory_epoch, ..
                },
                None,
            ) if inventory_epoch.get() == 1 => {}
            (
                RuntimeInventoryBody::Full {
                    inventory_epoch, ..
                },
                Some((_, full_acceptance)),
            ) if *inventory_epoch == checked_next_epoch(full_acceptance.inventory_epoch())? => {}
            (
                RuntimeInventoryBody::Partial {
                    inventory_epoch,
                    cats,
                },
                Some((full_report, _)),
            ) if *inventory_epoch == full_report.inventory.inventory_epoch() => {
                let members: BTreeSet<&Id> = full_report
                    .inventory
                    .cats()
                    .iter()
                    .map(|cat| &cat.cat_id)
                    .collect();
                if let Some(cat) = cats.iter().find(|cat| !members.contains(&cat.cat_id)) {
                    return Err(RuntimeInventoryJournalError::PartialCatNotInFull {
                        cat_id: cat.cat_id.clone(),
                    });
                }
            }
            (RuntimeInventoryBody::Partial { .. }, None) => {
                return Err(RuntimeInventoryJournalError::MissingFullInventory)
            }
            _ => {
                return Err(corrupt(
                    path,
                    "pending report uses the wrong inventory epoch",
                ))
            }
        }
    }
    Ok(())
}

trait AcceptanceInventoryEpoch {
    fn inventory_epoch(&self) -> Epoch;
}

impl AcceptanceInventoryEpoch for RuntimeInventoryAcceptance {
    fn inventory_epoch(&self) -> Epoch {
        match &self.inventory {
            RuntimeInventoryAcceptanceKind::Full { attestation } => attestation.inventory_epoch,
            RuntimeInventoryAcceptanceKind::Partial { inventory_epoch } => *inventory_epoch,
        }
    }
}

fn decode_full_record(
    record: &AcceptedFullRecord,
) -> Result<(RuntimeInventoryReport, RuntimeInventoryAcceptance), RuntimeInventoryJournalError> {
    let report = decode_canonical_report(&record.report, "decode accepted Full report")?;
    let acceptance =
        decode_canonical_acceptance(&record.acceptance, "decode accepted Full acceptance")?;
    if !matches!(&report.inventory, RuntimeInventoryBody::Full { .. })
        || !matches!(
            &acceptance.inventory,
            RuntimeInventoryAcceptanceKind::Full { .. }
        )
        || !acceptance_matches_report(&acceptance, &report)
    {
        return Err(RuntimeInventoryJournalError::AcceptanceMismatch);
    }
    Ok((report, acceptance))
}

fn acceptance_matches_report(
    acceptance: &RuntimeInventoryAcceptance,
    report: &RuntimeInventoryReport,
) -> bool {
    if acceptance.version != ContractVersion::V1
        || acceptance.session != report.session
        || acceptance.report_id != report.report_id
        || acceptance.sequence != report.sequence
    {
        return false;
    }
    match (&report.inventory, &acceptance.inventory) {
        (
            RuntimeInventoryBody::Full {
                inventory_epoch,
                scan_id,
                inventory_digest,
                ..
            },
            RuntimeInventoryAcceptanceKind::Full { attestation },
        ) => {
            attestation.version == ContractVersion::V1
                && attestation.session == report.session
                && attestation.inventory_epoch == *inventory_epoch
                && attestation.scan_id == *scan_id
                && attestation.inventory_digest == *inventory_digest
                && attestation.source_report_id == report.report_id
                && attestation.source_sequence == report.sequence
                && attestation.accepted_at_unix_ms == acceptance.accepted_at_unix_ms
        }
        (
            RuntimeInventoryBody::Partial {
                inventory_epoch, ..
            },
            RuntimeInventoryAcceptanceKind::Partial {
                inventory_epoch: accepted_epoch,
            },
        ) => inventory_epoch == accepted_epoch,
        _ => false,
    }
}

fn decode_canonical_report(
    bytes: &ExactBytes,
    context: &'static str,
) -> Result<RuntimeInventoryReport, RuntimeInventoryJournalError> {
    if bytes.0.len() > RUNTIME_INVENTORY_REPORT_MAX_WIRE_BYTES {
        return Err(RuntimeInventoryJournalError::InvalidContract { context });
    }
    let report = decode_runtime_inventory_report(bytes.as_slice())
        .map_err(|_| RuntimeInventoryJournalError::InvalidContract { context })?;
    let canonical = encode_runtime_inventory_report(&report)
        .map_err(|_| RuntimeInventoryJournalError::InvalidContract { context })?;
    if canonical != bytes.0 {
        return Err(RuntimeInventoryJournalError::InvalidContract { context });
    }
    Ok(report)
}

fn decode_canonical_acceptance(
    bytes: &ExactBytes,
    context: &'static str,
) -> Result<RuntimeInventoryAcceptance, RuntimeInventoryJournalError> {
    if bytes.0.len() > RUNTIME_INVENTORY_ACCEPTANCE_MAX_WIRE_BYTES {
        return Err(RuntimeInventoryJournalError::InvalidContract { context });
    }
    let acceptance = decode_runtime_inventory_acceptance(bytes.as_slice())
        .map_err(|_| RuntimeInventoryJournalError::InvalidContract { context })?;
    let canonical = encode_runtime_inventory_acceptance(&acceptance)
        .map_err(|_| RuntimeInventoryJournalError::InvalidContract { context })?;
    if canonical != bytes.0 {
        return Err(RuntimeInventoryJournalError::InvalidContract { context });
    }
    Ok(acceptance)
}

fn checked_next_sequence(value: Sequence) -> Result<Sequence, RuntimeInventoryJournalError> {
    value
        .get()
        .checked_add(1)
        .and_then(Sequence::new)
        .ok_or(RuntimeInventoryJournalError::SequenceExhausted)
}

fn checked_next_epoch(value: Epoch) -> Result<Epoch, RuntimeInventoryJournalError> {
    value
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or(RuntimeInventoryJournalError::SequenceExhausted)
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn encode_document(
    document: &RuntimeInventoryJournalDocument,
) -> Result<Vec<u8>, RuntimeInventoryJournalError> {
    let value =
        serde_json::to_value(document).map_err(|_| RuntimeInventoryJournalError::Corrupt {
            path: PathBuf::from("<runtime-inventory-journal>"),
            reason: "journal cannot be serialized".into(),
        })?;
    let bytes = cats_api::runtime_reconciliation::canonical_json_value_bytes(&value);
    if bytes.len() > JOURNAL_MAX_BYTES {
        return Err(RuntimeInventoryJournalError::Corrupt {
            path: PathBuf::from("<runtime-inventory-journal>"),
            reason: "journal exceeds its bounded size".into(),
        });
    }
    Ok(bytes)
}

fn read_document(
    directory: &File,
    directory_path: &Path,
) -> Result<Option<RuntimeInventoryJournalDocument>, RuntimeInventoryJournalError> {
    let Some(bytes) = read_file(directory, directory_path, STATE_FILE, JOURNAL_MAX_BYTES)? else {
        return Ok(None);
    };
    let document: RuntimeInventoryJournalDocument = serde_json::from_slice(&bytes)
        .map_err(|_| corrupt(directory_path, "journal JSON is malformed"))?;
    if encode_document(&document)? != bytes {
        return Err(corrupt(directory_path, "journal JSON is not canonical"));
    }
    validate_document(&document, directory_path)?;
    Ok(Some(document))
}

fn ensure_directory(parent: &File, path: &Path) -> Result<File, RuntimeInventoryJournalError> {
    let name = c_string(DIRECTORY_NAME, path)?;
    // SAFETY: `parent` is a live directory descriptor and `name` remains a
    // stable NUL-terminated basename for this call.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        parent
            .sync_all()
            .map_err(|source| io_error("sync Node state directory", path, source))?;
    } else {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(io_error("create runtime inventory directory", path, source));
        }
    }
    let directory = open_at(
        parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .map_err(|source| io_error("open runtime inventory directory", path, source))?;
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect runtime inventory directory", path, source))?;
    // SAFETY: geteuid takes no pointers and has no failure mode.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != euid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(RuntimeInventoryJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "directory must be an owned mode-0700 directory".into(),
        });
    }
    Ok(directory)
}

fn read_file(
    directory: &File,
    directory_path: &Path,
    name: &'static str,
    cap: usize,
) -> Result<Option<Vec<u8>>, RuntimeInventoryJournalError> {
    let path = directory_path.join(name);
    let name = c_string(name, &path)?;
    let mut file = match open_at(
        directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open runtime inventory journal", &path, source)),
    };
    verify_file(&file, &path)?;
    let mut bytes = Vec::new();
    Read::by_ref(&mut file)
        .take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read runtime inventory journal", &path, source))?;
    if bytes.len() > cap {
        return Err(corrupt(directory_path, "journal exceeds its bounded size"));
    }
    Ok(Some(bytes))
}

fn replace_file(
    directory: &File,
    directory_path: &Path,
    target_name: &'static str,
    temporary_name: &'static str,
    bytes: &[u8],
) -> Result<(), RuntimeInventoryJournalError> {
    let target_path = directory_path.join(target_name);
    let temporary_path = directory_path.join(temporary_name);
    let target = c_string(target_name, &target_path)?;
    let temporary = c_string(temporary_name, &temporary_path)?;
    unlink_if_exists(directory, &temporary).map_err(|source| {
        io_error(
            "remove stale runtime inventory temp",
            &temporary_path,
            source,
        )
    })?;
    let mut file = open_at(
        directory,
        &temporary,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .map_err(|source| io_error("create runtime inventory temp", &temporary_path, source))?;
    verify_file(&file, &temporary_path)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write runtime inventory temp", &temporary_path, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync runtime inventory temp", &temporary_path, source))?;
    rename_at(directory, &temporary, directory, &target)
        .map_err(|source| io_error("publish runtime inventory journal", &target_path, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync runtime inventory directory", directory_path, source))
}

fn verify_file(file: &File, path: &Path) -> Result<(), RuntimeInventoryJournalError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect runtime inventory state", path, source))?;
    // SAFETY: geteuid takes no pointers and has no failure mode.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != euid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(RuntimeInventoryJournalError::UnsafeEntry {
            path: path.to_path_buf(),
            reason: "state must be one owned mode-0600 regular file".into(),
        });
    }
    Ok(())
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: directory is live, name is stable for the call, and a successful
    // descriptor is transferred exactly once into `File`.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned one fresh owned descriptor.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors are live and both names remain valid for this
    // call.
    let result = unsafe {
        libc::renameat(
            old_directory.as_raw_fd(),
            old_name.as_ptr(),
            new_directory.as_raw_fd(),
            new_name.as_ptr(),
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

fn unlink_if_exists(directory: &File, name: &CStr) -> io::Result<bool> {
    // SAFETY: directory is live and name remains valid for the call.
    let result = unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), 0) };
    if result == 0 {
        Ok(true)
    } else {
        let source = io::Error::last_os_error();
        if source.kind() == io::ErrorKind::NotFound {
            Ok(false)
        } else {
            Err(source)
        }
    }
}

fn c_string(value: &str, path: &Path) -> Result<CString, RuntimeInventoryJournalError> {
    CString::new(value.as_bytes()).map_err(|_| RuntimeInventoryJournalError::UnsafeEntry {
        path: path.to_path_buf(),
        reason: "journal basename contains NUL".into(),
    })
}

fn corrupt(path: &Path, reason: impl Into<String>) -> RuntimeInventoryJournalError {
    RuntimeInventoryJournalError::Corrupt {
        path: path.to_path_buf(),
        reason: reason.into(),
    }
}

fn io_error(
    operation: &'static str,
    path: &Path,
    source: io::Error,
) -> RuntimeInventoryJournalError {
    RuntimeInventoryJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

pub(super) struct FullReportInput {
    pub(super) session: SessionBinding,
    pub(super) report_id: RandomId128,
    pub(super) sequence: Sequence,
    pub(super) collected_at_unix_ms: UnixMillis,
    pub(super) inventory_epoch: Epoch,
    pub(super) scan_id: RandomId128,
    pub(super) cats: Vec<cats_api::runtime_inventory::ObservedCatRuntimeTelemetry>,
    pub(super) unattributed_artifacts:
        Vec<cats_api::runtime_inventory::ObservedArtifactClassification>,
}

pub(super) fn new_full_report(
    input: FullReportInput,
) -> Result<RuntimeInventoryReport, RuntimeInventoryJournalError> {
    let mut report = RuntimeInventoryReport {
        version: ContractVersion::V1,
        session: input.session,
        report_id: input.report_id,
        sequence: input.sequence,
        collected_at_unix_ms: input.collected_at_unix_ms,
        inventory: RuntimeInventoryBody::Full {
            inventory_epoch: input.inventory_epoch,
            scan_id: input.scan_id,
            inventory_digest: cats_api::runtime_reconciliation::Sha256Digest::from_bytes([0; 32]),
            cats: input.cats,
            unattributed_artifacts: input.unattributed_artifacts,
        },
    };
    let digest = full_inventory_digest(&report).map_err(|_| {
        RuntimeInventoryJournalError::InvalidContract {
            context: "compute Full inventory digest",
        }
    })?;
    let RuntimeInventoryBody::Full {
        inventory_digest, ..
    } = &mut report.inventory
    else {
        unreachable!("constructed report is Full")
    };
    *inventory_digest = digest;
    Ok(report)
}

pub(super) fn new_partial_report(
    session: SessionBinding,
    report_id: RandomId128,
    sequence: Sequence,
    collected_at_unix_ms: UnixMillis,
    inventory_epoch: Epoch,
    cats: Vec<cats_api::runtime_inventory::ObservedCatRuntimeTelemetry>,
) -> RuntimeInventoryReport {
    RuntimeInventoryReport {
        version: ContractVersion::V1,
        session,
        report_id,
        sequence,
        collected_at_unix_ms,
        inventory: RuntimeInventoryBody::Partial {
            inventory_epoch,
            cats,
        },
    }
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_inventory::{
        encode_runtime_inventory_acceptance, ObservedCatRuntimeTelemetry,
        ObservedRuntimePhysicalState,
    };
    use cats_api::runtime_lifecycle::PlacementIdentity;
    use cats_api::runtime_reconciliation::{NodeBootId, Sha256Digest};
    use tempfile::TempDir;

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("valid test random ID")
    }

    fn digest(value: u8) -> Sha256Digest {
        Sha256Digest::from_bytes([value; 32])
    }

    fn session(epoch: u64, instance: u128) -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: id("node_inventory"),
            immutable_host_id: id("host_inventory"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111")
                .expect("valid boot ID"),
            agent_instance_id: random(instance),
            agent_session_epoch: Epoch::new(epoch).expect("positive session epoch"),
            registration_attempt_id: random(instance + 100),
            guest_config_digest: digest(1),
            lease_deadline_unix_ms: UnixMillis::new(9_000_000).expect("positive lease deadline"),
        }
    }

    fn state_directory(root: &TempDir) -> StateDirectory {
        StateDirectory::unanchored(root.path().to_path_buf())
    }

    fn observed_cat(name: &str) -> ObservedCatRuntimeTelemetry {
        ObservedCatRuntimeTelemetry {
            cat_id: id(name),
            observed_placement: PlacementIdentity {
                node_id: id("node_inventory"),
                placement_epoch: Epoch::new(1).expect("positive placement epoch"),
            },
            observed_command_journal: None,
            observed_physical_state: ObservedRuntimePhysicalState::Absent,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: digest(2),
            observed_artifact_classifications: Vec::new(),
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        }
    }

    fn full_report(
        journal: &RuntimeInventoryJournal,
        report_id: u128,
        cats: Vec<ObservedCatRuntimeTelemetry>,
    ) -> RuntimeInventoryReport {
        new_full_report(FullReportInput {
            session: journal.session().clone(),
            report_id: random(report_id),
            sequence: journal.next_sequence().expect("next sequence"),
            collected_at_unix_ms: UnixMillis::new(1_000 + report_id as u64)
                .expect("positive collection time"),
            inventory_epoch: journal.next_full_epoch().expect("next Full epoch"),
            scan_id: random(report_id + 1_000),
            cats,
            unattributed_artifacts: Vec::new(),
        })
        .expect("valid Full report")
    }

    fn acceptance(report: &RuntimeInventoryReport) -> RuntimeInventoryAcceptance {
        let accepted_at_unix_ms =
            UnixMillis::new(5_000 + report.sequence.get()).expect("positive acceptance time");
        let inventory = match &report.inventory {
            RuntimeInventoryBody::Full {
                inventory_epoch,
                scan_id,
                inventory_digest,
                ..
            } => RuntimeInventoryAcceptanceKind::Full {
                attestation: Box::new(RuntimeInventoryAttestation {
                    version: ContractVersion::V1,
                    session: report.session.clone(),
                    inventory_epoch: *inventory_epoch,
                    scan_id: scan_id.clone(),
                    inventory_digest: inventory_digest.clone(),
                    source_report_id: report.report_id.clone(),
                    source_sequence: report.sequence,
                    accepted_at_unix_ms,
                }),
            },
            RuntimeInventoryBody::Partial {
                inventory_epoch, ..
            } => RuntimeInventoryAcceptanceKind::Partial {
                inventory_epoch: *inventory_epoch,
            },
        };
        RuntimeInventoryAcceptance {
            version: ContractVersion::V1,
            session: report.session.clone(),
            report_id: report.report_id.clone(),
            sequence: report.sequence,
            accepted_at_unix_ms,
            lease_deadline_unix_ms: UnixMillis::new(10_000).expect("positive lease deadline"),
            inventory,
        }
    }

    fn accept(
        journal: &mut RuntimeInventoryJournal,
        report: &RuntimeInventoryReport,
    ) -> RuntimeInventoryAcceptance {
        let expected = acceptance(report);
        let bytes = encode_runtime_inventory_acceptance(&expected).expect("encode acceptance");
        assert_eq!(
            journal
                .accept_pending(bytes)
                .expect("accept pending report"),
            expected
        );
        expected
    }

    #[test]
    fn pending_full_survives_reopen_as_exact_bytes() {
        let root = TempDir::new().expect("temporary directory");
        let state = state_directory(&root);
        let registered = session(1, 1);
        let mut journal = RuntimeInventoryJournal::open(&state, &registered).expect("open journal");
        let report = full_report(&journal, 10, vec![observed_cat("cat_a")]);
        let exact = journal
            .prepare_report(report.clone())
            .expect("prepare Full report");
        drop(journal);

        let mut reopened =
            RuntimeInventoryJournal::open(&state, &registered).expect("reopen journal");
        let (recovered, recovered_exact) = reopened
            .pending_report()
            .expect("decode pending")
            .expect("pending exists");
        assert_eq!(recovered, report);
        assert_eq!(recovered_exact, exact);
        let accepted = accept(&mut reopened, &report);
        drop(reopened);

        let recovered = RuntimeInventoryJournal::open(&state, &registered).expect("recover Full");
        assert!(recovered.pending_report().expect("read pending").is_none());
        assert_eq!(
            recovered
                .accepted_full()
                .expect("decode accepted Full")
                .expect("accepted Full exists"),
            (report, accepted)
        );
        assert_eq!(recovered.next_sequence().expect("next sequence").get(), 2);
    }

    #[test]
    fn wrong_acceptance_keeps_exact_pending_report() {
        let root = TempDir::new().expect("temporary directory");
        let state = state_directory(&root);
        let registered = session(1, 1);
        let mut journal = RuntimeInventoryJournal::open(&state, &registered).expect("open journal");
        let report = full_report(&journal, 20, Vec::new());
        let exact = journal
            .prepare_report(report.clone())
            .expect("prepare Full report");
        let mut wrong = acceptance(&report);
        wrong.report_id = random(999);
        let RuntimeInventoryAcceptanceKind::Full { attestation } = &mut wrong.inventory else {
            unreachable!("acceptance for Full is Full")
        };
        attestation.source_report_id = wrong.report_id.clone();
        let bytes = encode_runtime_inventory_acceptance(&wrong).expect("encode wrong acceptance");
        assert!(matches!(
            journal.accept_pending(bytes),
            Err(RuntimeInventoryJournalError::AcceptanceMismatch)
        ));
        assert_eq!(
            journal
                .pending_report()
                .expect("read pending")
                .expect("pending exists")
                .1,
            exact
        );
    }

    #[test]
    fn partial_cannot_expand_or_replace_the_accepted_full() {
        let root = TempDir::new().expect("temporary directory");
        let state = state_directory(&root);
        let registered = session(1, 1);
        let mut journal = RuntimeInventoryJournal::open(&state, &registered).expect("open journal");
        let full = full_report(&journal, 30, vec![observed_cat("cat_a")]);
        journal
            .prepare_report(full.clone())
            .expect("prepare Full report");
        let full_acceptance = accept(&mut journal, &full);

        let foreign = new_partial_report(
            journal.session().clone(),
            random(31),
            journal.next_sequence().expect("next sequence"),
            UnixMillis::new(2_000).expect("positive collection time"),
            journal
                .current_full_epoch()
                .expect("decode epoch")
                .expect("Full epoch exists"),
            vec![observed_cat("cat_b")],
        );
        assert!(matches!(
            journal.prepare_report(foreign),
            Err(RuntimeInventoryJournalError::PartialCatNotInFull { cat_id })
                if cat_id == id("cat_b")
        ));

        let partial = new_partial_report(
            journal.session().clone(),
            random(32),
            journal.next_sequence().expect("next sequence"),
            UnixMillis::new(2_001).expect("positive collection time"),
            journal
                .current_full_epoch()
                .expect("decode epoch")
                .expect("Full epoch exists"),
            vec![observed_cat("cat_a")],
        );
        journal
            .prepare_report(partial.clone())
            .expect("prepare Partial report");
        let partial_acceptance = accept(&mut journal, &partial);
        assert!(matches!(
            partial_acceptance.inventory,
            RuntimeInventoryAcceptanceKind::Partial { .. }
        ));
        assert_eq!(
            journal
                .accepted_full()
                .expect("decode Full")
                .expect("accepted Full exists"),
            (full, full_acceptance)
        );
        assert_eq!(journal.next_sequence().expect("next sequence").get(), 3);
    }

    #[test]
    fn newer_session_atomically_resets_sequence_and_old_session_cannot_return() {
        let root = TempDir::new().expect("temporary directory");
        let state = state_directory(&root);
        let original_session = session(1, 1);
        let mut original =
            RuntimeInventoryJournal::open(&state, &original_session).expect("open journal");
        let full = full_report(&original, 40, Vec::new());
        original
            .prepare_report(full.clone())
            .expect("prepare Full report");
        accept(&mut original, &full);
        drop(original);

        let conflicting_session = session(1, 2);
        assert!(matches!(
            RuntimeInventoryJournal::open(&state, &conflicting_session),
            Err(RuntimeInventoryJournalError::SessionBindingConflict)
        ));
        let replacement_session = session(2, 2);
        let replacement = RuntimeInventoryJournal::open(&state, &replacement_session)
            .expect("replace journal session");
        assert_eq!(replacement.next_sequence().expect("next sequence").get(), 1);
        assert!(replacement.accepted_full().expect("decode Full").is_none());
        drop(replacement);
        assert!(matches!(
            RuntimeInventoryJournal::open(&state, &original_session),
            Err(RuntimeInventoryJournalError::NewerSession)
        ));
    }
}
