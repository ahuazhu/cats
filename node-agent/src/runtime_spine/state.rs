//! Crash-safe, descriptor-relative local A20 replay state.

use std::ffi::{CStr, CString, OsStr};
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::os::fd::{AsRawFd as _, FromRawFd as _};
use std::os::unix::ffi::OsStrExt as _;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};

use cats_api::runtime_reconciliation::{
    decode_agent_session, decode_desired_read_request, decode_desired_read_snapshot,
    decode_node_observation, decode_observation_acceptance, encode_agent_session,
    encode_desired_read_request, encode_desired_read_snapshot, encode_node_observation,
    encode_observation_acceptance, AgentSession, AppliedDesiredEvidence, ContractError,
    ContractVersion, DesiredReadRequest, DesiredReadSnapshot, Epoch, NodeObservation,
    ObservationAcceptance, ObservationInventoryAcceptance, Sequence, SessionBinding,
    AGENT_SESSION_MAX_WIRE_BYTES, DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
    DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES, NODE_OBSERVATION_MAX_WIRE_BYTES,
    OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::state_directory::StateDirectory;

use super::acceptance_matches_observation;

const DIRECTORY_NAME: &str = "runtime-spine";
const SESSION_FILE: &str = "session.json";
const RESET_FILE: &str = "session-reset.json";
const DESIRED_PENDING_FILE: &str = "desired-pending.json";
const DESIRED_ACCEPTED_FILE: &str = "desired-accepted.json";
const DESIRED_INVALIDATED_FILE: &str = "desired-invalidated.json";
const OBSERVATION_PENDING_FILE: &str = "observation-pending.json";
const OBSERVATION_LAST_FILE: &str = "observation-last.json";
const OBSERVATION_FULL_FILE: &str = "observation-full.json";
const RECORD_OVERHEAD_MAX_BYTES: usize = 1_024;
const OBSERVATION_RECORD_MAX_BYTES: usize = NODE_OBSERVATION_MAX_WIRE_BYTES
    + OBSERVATION_ACCEPTANCE_MAX_WIRE_BYTES
    + RECORD_OVERHEAD_MAX_BYTES;

const SESSION_FILES: &[&str] = &[
    DESIRED_PENDING_FILE,
    DESIRED_ACCEPTED_FILE,
    DESIRED_INVALIDATED_FILE,
    OBSERVATION_PENDING_FILE,
    OBSERVATION_LAST_FILE,
    OBSERVATION_FULL_FILE,
];

#[derive(Debug, Error)]
pub enum RuntimeSpineJournalError {
    #[error("{operation} {path}: {source}")]
    Io {
        operation: &'static str,
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("runtime-spine {record} violates its shared contract: {source}")]
    Contract {
        record: &'static str,
        #[source]
        source: ContractError,
    },
    #[error("runtime-spine local state is corrupt: {0}")]
    Corrupt(&'static str),
    #[error("runtime-spine sequence space is exhausted")]
    SequenceExhausted,
    #[error("runtime-spine local transition is out of order: {0}")]
    Transition(&'static str),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurableRuntimeSpineRequest<T> {
    value: T,
    bytes: Vec<u8>,
}

impl<T> DurableRuntimeSpineRequest<T> {
    pub fn value(&self) -> &T {
        &self.value
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RuntimeSpineDesiredWork {
    Request(DurableRuntimeSpineRequest<DesiredReadRequest>),
    Scan(DesiredReadSnapshot),
}

/// Exact local coordinates a complete physical scan must bind before it can
/// become a durable `NodeObservation` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeSpineFullScan {
    pub session: SessionBinding,
    pub heartbeat_sequence: Sequence,
    pub inventory_epoch: Epoch,
    pub desired: DesiredReadSnapshot,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AcceptedObservationRecord {
    version: ContractVersion,
    observation: NodeObservation,
    acceptance: ObservationAcceptance,
}

/// The bounded current A20 protocol state for one exact AgentSession.
pub(crate) struct RuntimeSpineJournal {
    directory: File,
    path: PathBuf,
    registered_lease_deadline_unix_ms: cats_api::runtime_reconciliation::UnixMillis,
    session: AgentSession,
    pending_desired: Option<DurableRuntimeSpineRequest<DesiredReadRequest>>,
    desired_snapshot: Option<DesiredReadSnapshot>,
    invalidated_desired: Option<DesiredReadSnapshot>,
    pending_observation: Option<DurableRuntimeSpineRequest<NodeObservation>>,
    last_observation: Option<AcceptedObservationRecord>,
    full_observation: Option<AcceptedObservationRecord>,
}

impl std::fmt::Debug for RuntimeSpineJournal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RuntimeSpineJournal")
            .field("path", &self.path)
            .field("session", &session_binding(&self.session))
            .field("pending_desired", &self.pending_desired.is_some())
            .field("desired_snapshot", &self.desired_snapshot.is_some())
            .field("invalidated_desired", &self.invalidated_desired.is_some())
            .field("pending_observation", &self.pending_observation.is_some())
            .field("last_observation", &self.last_observation.is_some())
            .field("full_observation", &self.full_observation.is_some())
            .finish()
    }
}

impl RuntimeSpineJournal {
    #[cfg(test)]
    pub(super) fn open_for_test(
        state_directory: &StateDirectory,
        registered_session: AgentSession,
    ) -> Result<Self, RuntimeSpineJournalError> {
        Self::open_inner(state_directory, registered_session, false)
    }

    /// Opens a command-scoped view while the journal lane's separate
    /// exclusive guard descriptor is held. This is intentionally unavailable
    /// outside the runtime-spine module so production callers cannot mutate
    /// the journal without owning its flock.
    pub(super) fn open_under_lane_lock(
        state_directory: &StateDirectory,
        registered_session: AgentSession,
    ) -> Result<Self, RuntimeSpineJournalError> {
        Self::open_inner(state_directory, registered_session, false)
    }

    pub(super) fn open_exclusive(
        state_directory: &StateDirectory,
        registered_session: AgentSession,
    ) -> Result<Self, RuntimeSpineJournalError> {
        Self::open_inner(state_directory, registered_session, true)
    }

    fn open_inner(
        state_directory: &StateDirectory,
        registered_session: AgentSession,
        exclusive: bool,
    ) -> Result<Self, RuntimeSpineJournalError> {
        validate_session(&registered_session, "registered session")?;
        let parent = state_directory.try_clone_directory().map_err(|source| {
            io_error("clone Node state directory", state_directory.path(), source)
        })?;
        let path = state_directory.path().join(DIRECTORY_NAME);
        let directory = ensure_directory(&parent, &path)?;
        if exclusive {
            lock_directory(&directory, &path)?;
        }
        let mut journal = Self {
            directory,
            path,
            registered_lease_deadline_unix_ms: registered_session.lease_deadline_unix_ms,
            session: registered_session,
            pending_desired: None,
            desired_snapshot: None,
            invalidated_desired: None,
            pending_observation: None,
            last_observation: None,
            full_observation: None,
        };
        journal.recover_session()?;
        journal.load_records()?;
        Ok(journal)
    }

    #[cfg(test)]
    pub(super) fn session(&self) -> &AgentSession {
        &self.session
    }

    #[cfg(test)]
    pub(super) fn desired_snapshot(&self) -> Option<&DesiredReadSnapshot> {
        self.desired_snapshot.as_ref()
    }

    #[cfg(test)]
    pub(super) fn full_observation(&self) -> Option<(&NodeObservation, &ObservationAcceptance)> {
        self.full_observation
            .as_ref()
            .map(|record| (&record.observation, &record.acceptance))
    }

    pub(crate) fn pending_observation(
        &self,
    ) -> Option<DurableRuntimeSpineRequest<NodeObservation>> {
        self.pending_observation.clone()
    }

    pub(crate) fn full_scan(&self) -> Result<RuntimeSpineFullScan, RuntimeSpineJournalError> {
        if self.pending_observation.is_some() {
            return Err(RuntimeSpineJournalError::Transition(
                "a physical scan cannot replace a pending observation",
            ));
        }
        let desired =
            self.desired_snapshot
                .as_ref()
                .ok_or(RuntimeSpineJournalError::Transition(
                    "a physical scan has no Desired snapshot",
                ))?;
        if self.desired_is_consumed(desired) || self.desired_is_invalidated(desired) {
            return Err(RuntimeSpineJournalError::Transition(
                "a physical scan cannot reuse a consumed or invalidated Desired snapshot",
            ));
        }
        let heartbeat_sequence = match &self.last_observation {
            Some(last) => checked_next(last.acceptance.heartbeat_sequence)?,
            None => Sequence::new(1).expect("one is a valid Sequence"),
        };
        let inventory_epoch = match &self.full_observation {
            Some(full) => checked_next_epoch(full.observation.inventory_epoch)?,
            None => Epoch::new(1).expect("one is a valid Epoch"),
        };
        Ok(RuntimeSpineFullScan {
            session: session_binding(&self.session),
            heartbeat_sequence,
            inventory_epoch,
            desired: desired.clone(),
        })
    }

    /// Returns the exact pending request, the unconsumed snapshot to scan, or
    /// durably creates the next request before exposing its bytes.
    pub(crate) fn desired_work(
        &mut self,
    ) -> Result<RuntimeSpineDesiredWork, RuntimeSpineJournalError> {
        if let Some(pending) = &self.pending_desired {
            return Ok(RuntimeSpineDesiredWork::Request(pending.clone()));
        }
        if let Some(snapshot) = &self.desired_snapshot {
            if !self.desired_is_consumed(snapshot) && !self.desired_is_invalidated(snapshot) {
                return Ok(RuntimeSpineDesiredWork::Scan(snapshot.clone()));
            }
        }
        let next = match &self.desired_snapshot {
            Some(snapshot) => checked_next(snapshot.request_sequence)?,
            None => Sequence::new(1).expect("one is a valid Sequence"),
        };
        let request = DesiredReadRequest {
            version: ContractVersion::V1,
            session: session_binding(&self.session),
            request_sequence: next,
        };
        let bytes = encode_desired_read_request(&request).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "DesiredReadRequest",
                source,
            }
        })?;
        replace_file(&self.directory, &self.path, DESIRED_PENDING_FILE, &bytes)?;
        let pending = DurableRuntimeSpineRequest {
            value: request,
            bytes,
        };
        self.pending_desired = Some(pending.clone());
        Ok(RuntimeSpineDesiredWork::Request(pending))
    }

    pub(crate) fn accept_desired(
        &mut self,
        snapshot: DesiredReadSnapshot,
        exact_bytes: &[u8],
    ) -> Result<(), RuntimeSpineJournalError> {
        let pending = self
            .pending_desired
            .as_ref()
            .ok_or(RuntimeSpineJournalError::Transition(
                "Desired success has no pending request",
            ))?;
        let decoded = decode_desired_read_snapshot(exact_bytes).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "DesiredReadSnapshot",
                source,
            }
        })?;
        if decoded != snapshot
            || snapshot.version != pending.value.version
            || snapshot.session != pending.value.session
            || snapshot.request_sequence != pending.value.request_sequence
        {
            return Err(RuntimeSpineJournalError::Transition(
                "Desired success does not match the pending request",
            ));
        }
        replace_file(
            &self.directory,
            &self.path,
            DESIRED_ACCEPTED_FILE,
            exact_bytes,
        )?;
        remove_file(&self.directory, &self.path, DESIRED_PENDING_FILE)?;
        remove_file(&self.directory, &self.path, DESIRED_INVALIDATED_FILE)?;
        self.desired_snapshot = Some(snapshot);
        self.invalidated_desired = None;
        self.pending_desired = None;
        Ok(())
    }

    /// Records a definite Control rejection that makes the current Desired
    /// cursor unusable, then forgets the rejected observation. The marker is
    /// durable before the exact pending body is removed, so a crash cannot
    /// strand the Node replaying a request the server has already rejected.
    pub(crate) fn invalidate_desired_after_observation_rejection(
        &mut self,
    ) -> Result<(), RuntimeSpineJournalError> {
        if self.pending_observation.is_none() {
            return Err(RuntimeSpineJournalError::Transition(
                "Desired invalidation has no definitely rejected observation",
            ));
        }
        let snapshot =
            self.desired_snapshot
                .as_ref()
                .ok_or(RuntimeSpineJournalError::Transition(
                    "Desired invalidation has no accepted snapshot",
                ))?;
        let bytes = encode_desired_read_snapshot(snapshot).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "DesiredReadSnapshot invalidation marker",
                source,
            }
        })?;
        replace_file(
            &self.directory,
            &self.path,
            DESIRED_INVALIDATED_FILE,
            &bytes,
        )?;
        remove_file(&self.directory, &self.path, OBSERVATION_PENDING_FILE)?;
        self.invalidated_desired = Some(snapshot.clone());
        self.pending_observation = None;
        Ok(())
    }

    /// Durably stores a complete, already-physically-scanned candidate before
    /// any network send. A retained pending request always wins over a newly
    /// supplied candidate.
    pub(crate) fn prepare_observation(
        &mut self,
        candidate: NodeObservation,
    ) -> Result<DurableRuntimeSpineRequest<NodeObservation>, RuntimeSpineJournalError> {
        if let Some(pending) = &self.pending_observation {
            return Ok(pending.clone());
        }
        let bytes = encode_node_observation(&candidate).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "NodeObservation",
                source,
            }
        })?;
        self.validate_observation_candidate(&candidate)?;
        replace_file(
            &self.directory,
            &self.path,
            OBSERVATION_PENDING_FILE,
            &bytes,
        )?;
        let pending = DurableRuntimeSpineRequest {
            value: candidate,
            bytes,
        };
        self.pending_observation = Some(pending.clone());
        Ok(pending)
    }

    pub(crate) fn accept_observation(
        &mut self,
        acceptance: ObservationAcceptance,
        exact_bytes: &[u8],
    ) -> Result<(), RuntimeSpineJournalError> {
        let pending =
            self.pending_observation
                .as_ref()
                .ok_or(RuntimeSpineJournalError::Transition(
                    "observation success has no pending request",
                ))?;
        let decoded = decode_observation_acceptance(exact_bytes).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "ObservationAcceptance",
                source,
            }
        })?;
        if decoded != acceptance || !acceptance_matches_observation(&acceptance, &pending.value) {
            return Err(RuntimeSpineJournalError::Transition(
                "observation success does not match the pending request",
            ));
        }
        if acceptance.lease_deadline_unix_ms < self.session.lease_deadline_unix_ms {
            return Err(RuntimeSpineJournalError::Corrupt(
                "accepted observation regressed the AgentSession deadline",
            ));
        }
        let record = AcceptedObservationRecord {
            version: ContractVersion::V1,
            observation: pending.value.clone(),
            acceptance: acceptance.clone(),
        };
        let record_bytes = encode_observation_record(&record)?;
        replace_file(
            &self.directory,
            &self.path,
            OBSERVATION_LAST_FILE,
            &record_bytes,
        )?;
        if record.observation.complete_inventory {
            replace_file(
                &self.directory,
                &self.path,
                OBSERVATION_FULL_FILE,
                &record_bytes,
            )?;
            self.full_observation = Some(record.clone());
        }
        self.session.lease_deadline_unix_ms = acceptance.lease_deadline_unix_ms;
        let session_bytes = encode_agent_session(&self.session).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "AgentSession",
                source,
            }
        })?;
        replace_file(&self.directory, &self.path, SESSION_FILE, &session_bytes)?;
        remove_file(&self.directory, &self.path, OBSERVATION_PENDING_FILE)?;
        self.last_observation = Some(record);
        self.pending_observation = None;
        Ok(())
    }

    fn recover_session(&mut self) -> Result<(), RuntimeSpineJournalError> {
        if let Some(reset_bytes) = read_file(
            &self.directory,
            &self.path,
            RESET_FILE,
            AGENT_SESSION_MAX_WIRE_BYTES,
        )? {
            let reset = decode_agent_session(&reset_bytes).map_err(|source| {
                RuntimeSpineJournalError::Contract {
                    record: "session reset marker",
                    source,
                }
            })?;
            if !same_session_without_deadline(&reset, &self.session) {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "session reset marker belongs to another AgentSession",
                ));
            }
            self.finish_session_reset()?;
            return Ok(());
        }

        let stored = read_file(
            &self.directory,
            &self.path,
            SESSION_FILE,
            AGENT_SESSION_MAX_WIRE_BYTES,
        )?
        .map(|bytes| {
            decode_agent_session(&bytes).map_err(|source| RuntimeSpineJournalError::Contract {
                record: "AgentSession",
                source,
            })
        })
        .transpose()?;
        match stored {
            Some(stored) if same_session_without_deadline(&stored, &self.session) => {
                if stored.lease_deadline_unix_ms > self.session.lease_deadline_unix_ms {
                    self.session.lease_deadline_unix_ms = stored.lease_deadline_unix_ms;
                } else if stored.lease_deadline_unix_ms < self.session.lease_deadline_unix_ms {
                    let bytes = encode_agent_session(&self.session).map_err(|source| {
                        RuntimeSpineJournalError::Contract {
                            record: "AgentSession",
                            source,
                        }
                    })?;
                    replace_file(&self.directory, &self.path, SESSION_FILE, &bytes)?;
                }
            }
            _ => {
                let bytes = encode_agent_session(&self.session).map_err(|source| {
                    RuntimeSpineJournalError::Contract {
                        record: "AgentSession",
                        source,
                    }
                })?;
                replace_file(&self.directory, &self.path, RESET_FILE, &bytes)?;
                self.finish_session_reset()?;
            }
        }
        Ok(())
    }

    fn finish_session_reset(&self) -> Result<(), RuntimeSpineJournalError> {
        for name in SESSION_FILES {
            remove_file(&self.directory, &self.path, name)?;
        }
        let bytes = encode_agent_session(&self.session).map_err(|source| {
            RuntimeSpineJournalError::Contract {
                record: "AgentSession",
                source,
            }
        })?;
        replace_file(&self.directory, &self.path, SESSION_FILE, &bytes)?;
        remove_file(&self.directory, &self.path, RESET_FILE)
    }

    fn load_records(&mut self) -> Result<(), RuntimeSpineJournalError> {
        self.pending_desired = read_file(
            &self.directory,
            &self.path,
            DESIRED_PENDING_FILE,
            DESIRED_READ_REQUEST_MAX_WIRE_BYTES,
        )?
        .map(|bytes| {
            let value = decode_desired_read_request(&bytes).map_err(|source| {
                RuntimeSpineJournalError::Contract {
                    record: "pending DesiredReadRequest",
                    source,
                }
            })?;
            Ok(DurableRuntimeSpineRequest { value, bytes })
        })
        .transpose()?;
        self.desired_snapshot = read_file(
            &self.directory,
            &self.path,
            DESIRED_ACCEPTED_FILE,
            DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES,
        )?
        .map(|bytes| {
            decode_desired_read_snapshot(&bytes).map_err(|source| {
                RuntimeSpineJournalError::Contract {
                    record: "accepted DesiredReadSnapshot",
                    source,
                }
            })
        })
        .transpose()?;
        self.invalidated_desired = read_file(
            &self.directory,
            &self.path,
            DESIRED_INVALIDATED_FILE,
            DESIRED_READ_SNAPSHOT_MAX_WIRE_BYTES,
        )?
        .map(|bytes| {
            decode_desired_read_snapshot(&bytes).map_err(|source| {
                RuntimeSpineJournalError::Contract {
                    record: "DesiredReadSnapshot invalidation marker",
                    source,
                }
            })
        })
        .transpose()?;
        self.pending_observation = read_file(
            &self.directory,
            &self.path,
            OBSERVATION_PENDING_FILE,
            NODE_OBSERVATION_MAX_WIRE_BYTES,
        )?
        .map(|bytes| {
            let value = decode_node_observation(&bytes).map_err(|source| {
                RuntimeSpineJournalError::Contract {
                    record: "pending NodeObservation",
                    source,
                }
            })?;
            Ok(DurableRuntimeSpineRequest { value, bytes })
        })
        .transpose()?;
        self.last_observation =
            read_observation_record(&self.directory, &self.path, OBSERVATION_LAST_FILE)?;
        self.full_observation =
            read_observation_record(&self.directory, &self.path, OBSERVATION_FULL_FILE)?;
        self.validate_loaded_records()?;
        self.repair_completed_writes()
    }

    fn validate_loaded_records(&self) -> Result<(), RuntimeSpineJournalError> {
        let binding = session_binding(&self.session);
        if self
            .pending_desired
            .as_ref()
            .is_some_and(|pending| pending.value.session != binding)
            || self
                .desired_snapshot
                .as_ref()
                .is_some_and(|snapshot| snapshot.session != binding)
            || self
                .invalidated_desired
                .as_ref()
                .is_some_and(|snapshot| snapshot.session != binding)
            || self
                .pending_observation
                .as_ref()
                .is_some_and(|pending| observation_binding(&pending.value) != binding)
            || self
                .last_observation
                .as_ref()
                .is_some_and(|record| record.acceptance.session != binding)
            || self
                .full_observation
                .as_ref()
                .is_some_and(|record| record.acceptance.session != binding)
        {
            return Err(RuntimeSpineJournalError::Corrupt(
                "a retained record belongs to another AgentSession",
            ));
        }
        match (&self.invalidated_desired, &self.desired_snapshot) {
            (Some(invalidated), Some(current))
                if invalidated.request_sequence > current.request_sequence =>
            {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "Desired invalidation marker is newer than the accepted snapshot",
                ));
            }
            (Some(_), None) => {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "Desired invalidation marker has no accepted snapshot",
                ));
            }
            _ => {}
        }
        if let Some(record) = &self.last_observation {
            validate_observation_record(record)?;
        }
        if let Some(record) = &self.full_observation {
            validate_observation_record(record)?;
            if !record.observation.complete_inventory {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "the retained full observation is partial",
                ));
            }
        }
        if self.full_observation.is_some() && self.last_observation.is_none() {
            return Err(RuntimeSpineJournalError::Corrupt(
                "the full inventory receipt exists without a latest acceptance",
            ));
        }
        if let (Some(last), Some(full)) = (&self.last_observation, &self.full_observation) {
            if last.observation.complete_inventory
                && last != full
                && !is_next_full_receipt(last, full)
            {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "latest full observation is not the successor of the full receipt",
                ));
            }
            if last.acceptance.heartbeat_sequence < full.acceptance.heartbeat_sequence {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "full receipt is newer than the latest observation",
                ));
            }
        }
        if self.full_observation.is_none()
            && self.last_observation.as_ref().is_some_and(|last| {
                !last.observation.complete_inventory || last.observation.inventory_epoch.get() != 1
            })
        {
            return Err(RuntimeSpineJournalError::Corrupt(
                "the first accepted observation is not a full epoch one inventory",
            ));
        }
        let expected_deadline = self
            .last_observation
            .as_ref()
            .map(|last| last.acceptance.lease_deadline_unix_ms)
            .unwrap_or(self.registered_lease_deadline_unix_ms)
            .max(self.registered_lease_deadline_unix_ms);
        if self.session.lease_deadline_unix_ms > expected_deadline {
            return Err(RuntimeSpineJournalError::Corrupt(
                "the local AgentSession deadline has no accepted observation receipt",
            ));
        }
        Ok(())
    }

    fn repair_completed_writes(&mut self) -> Result<(), RuntimeSpineJournalError> {
        if let (Some(pending), Some(snapshot)) = (&self.pending_desired, &self.desired_snapshot) {
            if pending.value.session == snapshot.session
                && pending.value.request_sequence == snapshot.request_sequence
            {
                remove_file(&self.directory, &self.path, DESIRED_PENDING_FILE)?;
                self.pending_desired = None;
            }
        }
        if let (Some(invalidated), Some(snapshot)) =
            (&self.invalidated_desired, &self.desired_snapshot)
        {
            if invalidated.request_sequence < snapshot.request_sequence {
                remove_file(&self.directory, &self.path, DESIRED_INVALIDATED_FILE)?;
                self.invalidated_desired = None;
            } else if invalidated != snapshot {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "Desired invalidation marker differs from its accepted snapshot",
                ));
            }
        }
        if self.invalidated_desired.is_some() && self.pending_observation.is_some() {
            remove_file(&self.directory, &self.path, OBSERVATION_PENDING_FILE)?;
            self.pending_observation = None;
        }
        if let (Some(pending), Some(last)) = (&self.pending_observation, &self.last_observation) {
            if pending.value == last.observation {
                remove_file(&self.directory, &self.path, OBSERVATION_PENDING_FILE)?;
                self.pending_observation = None;
            }
        }
        if let Some(last) = self.last_observation.clone() {
            if last.observation.complete_inventory && self.full_observation.as_ref() != Some(&last)
            {
                let bytes = encode_observation_record(&last)?;
                replace_file(&self.directory, &self.path, OBSERVATION_FULL_FILE, &bytes)?;
                self.full_observation = Some(last.clone());
            }
            if last.acceptance.lease_deadline_unix_ms > self.session.lease_deadline_unix_ms {
                self.session.lease_deadline_unix_ms = last.acceptance.lease_deadline_unix_ms;
                let bytes = encode_agent_session(&self.session).map_err(|source| {
                    RuntimeSpineJournalError::Contract {
                        record: "AgentSession",
                        source,
                    }
                })?;
                replace_file(&self.directory, &self.path, SESSION_FILE, &bytes)?;
            }
        }
        if let Some(pending) = &self.pending_desired {
            let expected = match &self.desired_snapshot {
                Some(snapshot)
                    if self.desired_is_consumed(snapshot)
                        || self.desired_is_invalidated(snapshot) =>
                {
                    checked_next(snapshot.request_sequence)?
                }
                None => Sequence::new(1).expect("one is a valid Sequence"),
                Some(_) => {
                    return Err(RuntimeSpineJournalError::Corrupt(
                        "a new Desired request exists before the prior snapshot was consumed",
                    ));
                }
            };
            if pending.value.session != session_binding(&self.session)
                || pending.value.request_sequence != expected
            {
                return Err(RuntimeSpineJournalError::Corrupt(
                    "pending Desired request has the wrong local sequence",
                ));
            }
        }
        if let Some(pending) = &self.pending_observation {
            self.validate_observation_candidate(&pending.value)?;
        }
        Ok(())
    }

    fn validate_observation_candidate(
        &self,
        candidate: &NodeObservation,
    ) -> Result<(), RuntimeSpineJournalError> {
        if observation_binding(candidate) != session_binding(&self.session) {
            return Err(RuntimeSpineJournalError::Transition(
                "observation does not match the current AgentSession",
            ));
        }
        let expected_sequence = match &self.last_observation {
            Some(last) => checked_next(last.acceptance.heartbeat_sequence)?,
            None => Sequence::new(1).expect("one is a valid Sequence"),
        };
        if candidate.heartbeat_sequence != expected_sequence {
            return Err(RuntimeSpineJournalError::Transition(
                "observation is not the next local heartbeat sequence",
            ));
        }
        let snapshot =
            self.desired_snapshot
                .as_ref()
                .ok_or(RuntimeSpineJournalError::Transition(
                    "observation has no Desired snapshot",
                ))?;
        if self.desired_is_invalidated(snapshot) {
            return Err(RuntimeSpineJournalError::Transition(
                "observation uses a definitely invalidated Desired snapshot",
            ));
        }
        if candidate.complete_inventory {
            if self.desired_is_consumed(snapshot) {
                return Err(RuntimeSpineJournalError::Transition(
                    "full observation does not have an unconsumed Desired snapshot",
                ));
            }
            if candidate.inventory_read_position != Some(snapshot.read_position) {
                return Err(RuntimeSpineJournalError::Transition(
                    "full observation uses the wrong Desired read position",
                ));
            }
            let expected_epoch = match &self.full_observation {
                Some(full) => checked_next_epoch(full.observation.inventory_epoch)?,
                None => Epoch::new(1).expect("one is a valid Epoch"),
            };
            if candidate.inventory_epoch != expected_epoch {
                return Err(RuntimeSpineJournalError::Transition(
                    "full observation uses the wrong inventory epoch",
                ));
            }
            validate_assigned_coverage(snapshot, candidate)?;
        } else {
            let full =
                self.full_observation
                    .as_ref()
                    .ok_or(RuntimeSpineJournalError::Transition(
                        "partial observation has no accepted full inventory",
                    ))?;
            if !self.desired_is_consumed(snapshot) {
                return Err(RuntimeSpineJournalError::Transition(
                    "partial observation cannot consume a new Desired snapshot",
                ));
            }
            if candidate.inventory_epoch != full.observation.inventory_epoch {
                return Err(RuntimeSpineJournalError::Transition(
                    "partial observation uses the wrong inventory epoch",
                ));
            }
            if candidate.runtimes.iter().any(|runtime| {
                !full
                    .observation
                    .runtimes
                    .iter()
                    .any(|present| present.cat_id == runtime.cat_id)
            }) {
                return Err(RuntimeSpineJournalError::Transition(
                    "partial observation introduces a Cat absent from the full inventory",
                ));
            }
        }
        Ok(())
    }

    fn desired_is_consumed(&self, snapshot: &DesiredReadSnapshot) -> bool {
        self.full_observation.as_ref().is_some_and(|record| {
            matches!(
                &record.acceptance.inventory,
                ObservationInventoryAcceptance::Full { attestation }
                    if attestation.inventory_read_position == snapshot.read_position
            )
        })
    }

    fn desired_is_invalidated(&self, snapshot: &DesiredReadSnapshot) -> bool {
        self.invalidated_desired.as_ref() == Some(snapshot)
    }
}

fn lock_directory(directory: &File, path: &Path) -> Result<(), RuntimeSpineJournalError> {
    // SAFETY: the directory owns a live descriptor and `flock` neither keeps
    // a pointer nor transfers descriptor ownership. The lock follows this
    // open file description and is released when the lane guard is dropped.
    let result = unsafe { libc::flock(directory.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if result == 0 {
        Ok(())
    } else {
        Err(io_error(
            "lock runtime-spine journal",
            path,
            io::Error::last_os_error(),
        ))
    }
}

fn validate_assigned_coverage(
    snapshot: &DesiredReadSnapshot,
    observation: &NodeObservation,
) -> Result<(), RuntimeSpineJournalError> {
    for desired in &snapshot.desired_specs {
        let Some(runtime) = observation
            .runtimes
            .iter()
            .find(|runtime| runtime.cat_id == desired.cat_id)
        else {
            return Err(RuntimeSpineJournalError::Transition(
                "full observation omits an assigned Cat",
            ));
        };
        let expected = AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        };
        if runtime.applied_desired.as_ref() != Some(&expected) {
            return Err(RuntimeSpineJournalError::Transition(
                "full observation has the wrong applied Desired binding",
            ));
        }
    }
    Ok(())
}

fn encode_observation_record(
    record: &AcceptedObservationRecord,
) -> Result<Vec<u8>, RuntimeSpineJournalError> {
    validate_observation_record(record)?;
    let bytes = serde_json::to_vec(record)
        .map_err(|_| RuntimeSpineJournalError::Corrupt("cannot encode observation receipt"))?;
    if bytes.len() > OBSERVATION_RECORD_MAX_BYTES {
        return Err(RuntimeSpineJournalError::Corrupt(
            "observation receipt exceeds its local bound",
        ));
    }
    Ok(bytes)
}

fn validate_observation_record(
    record: &AcceptedObservationRecord,
) -> Result<(), RuntimeSpineJournalError> {
    if record.version != ContractVersion::V1
        || !acceptance_matches_observation(&record.acceptance, &record.observation)
    {
        return Err(RuntimeSpineJournalError::Corrupt(
            "observation receipt request/result binding is invalid",
        ));
    }
    encode_node_observation(&record.observation).map_err(|source| {
        RuntimeSpineJournalError::Contract {
            record: "accepted NodeObservation",
            source,
        }
    })?;
    encode_observation_acceptance(&record.acceptance).map_err(|source| {
        RuntimeSpineJournalError::Contract {
            record: "ObservationAcceptance",
            source,
        }
    })?;
    Ok(())
}

fn is_next_full_receipt(
    last: &AcceptedObservationRecord,
    full: &AcceptedObservationRecord,
) -> bool {
    last.acceptance.heartbeat_sequence > full.acceptance.heartbeat_sequence
        && checked_next_epoch(full.observation.inventory_epoch)
            .is_ok_and(|expected| last.observation.inventory_epoch == expected)
}

fn read_observation_record(
    directory: &File,
    path: &Path,
    name: &'static str,
) -> Result<Option<AcceptedObservationRecord>, RuntimeSpineJournalError> {
    let Some(bytes) = read_file(directory, path, name, OBSERVATION_RECORD_MAX_BYTES)? else {
        return Ok(None);
    };
    let record: AcceptedObservationRecord = serde_json::from_slice(&bytes)
        .map_err(|_| RuntimeSpineJournalError::Corrupt("observation receipt JSON is malformed"))?;
    let canonical = encode_observation_record(&record)?;
    if canonical != bytes {
        return Err(RuntimeSpineJournalError::Corrupt(
            "observation receipt JSON is not canonical",
        ));
    }
    Ok(Some(record))
}

fn validate_session(
    session: &AgentSession,
    record: &'static str,
) -> Result<(), RuntimeSpineJournalError> {
    encode_agent_session(session)
        .map(|_| ())
        .map_err(|source| RuntimeSpineJournalError::Contract { record, source })
}

fn same_session_without_deadline(left: &AgentSession, right: &AgentSession) -> bool {
    left.version == right.version
        && left.node_id == right.node_id
        && left.immutable_host_id == right.immutable_host_id
        && left.node_boot_id == right.node_boot_id
        && left.agent_instance_id == right.agent_instance_id
        && left.agent_session_epoch == right.agent_session_epoch
        && left.registration_attempt_id == right.registration_attempt_id
        && left.guest_config_digest == right.guest_config_digest
}

fn session_binding(session: &AgentSession) -> SessionBinding {
    SessionBinding {
        node_id: session.node_id.clone(),
        node_boot_id: session.node_boot_id.clone(),
        agent_instance_id: session.agent_instance_id.clone(),
        agent_session_epoch: session.agent_session_epoch,
    }
}

fn observation_binding(observation: &NodeObservation) -> SessionBinding {
    SessionBinding {
        node_id: observation.node_id.clone(),
        node_boot_id: observation.node_boot_id.clone(),
        agent_instance_id: observation.agent_instance_id.clone(),
        agent_session_epoch: observation.agent_session_epoch,
    }
}

fn checked_next(value: Sequence) -> Result<Sequence, RuntimeSpineJournalError> {
    value
        .get()
        .checked_add(1)
        .and_then(Sequence::new)
        .ok_or(RuntimeSpineJournalError::SequenceExhausted)
}

fn checked_next_epoch(value: Epoch) -> Result<Epoch, RuntimeSpineJournalError> {
    value
        .get()
        .checked_add(1)
        .and_then(Epoch::new)
        .ok_or(RuntimeSpineJournalError::SequenceExhausted)
}

fn ensure_directory(parent: &File, path: &Path) -> Result<File, RuntimeSpineJournalError> {
    let name = c_string(DIRECTORY_NAME, path)?;
    // SAFETY: parent is a live directory descriptor; `name` is NUL-terminated
    // and remains alive for the call.
    let result = unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) };
    if result == 0 {
        parent
            .sync_all()
            .map_err(|source| io_error("sync Node state directory", path, source))?;
    } else {
        let source = io::Error::last_os_error();
        if source.kind() != io::ErrorKind::AlreadyExists {
            return Err(io_error("create runtime-spine directory", path, source));
        }
    }
    let directory = open_at(
        parent,
        &name,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0,
    )
    .map_err(|source| io_error("open runtime-spine directory", path, source))?;
    let metadata = directory
        .metadata()
        .map_err(|source| io_error("inspect runtime-spine directory", path, source))?;
    // SAFETY: geteuid takes no pointers and has no failure mode.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_dir()
        || metadata.uid() != euid
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        return Err(RuntimeSpineJournalError::Corrupt(
            "runtime-spine directory has unsafe metadata",
        ));
    }
    Ok(directory)
}

fn read_file(
    directory: &File,
    path: &Path,
    name: &'static str,
    cap: usize,
) -> Result<Option<Vec<u8>>, RuntimeSpineJournalError> {
    let target = path.join(name);
    let name = c_string(name, &target)?;
    let mut file = match open_at(
        directory,
        &name,
        libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
        0,
    ) {
        Ok(file) => file,
        Err(source) if source.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(source) => return Err(io_error("open runtime-spine state", &target, source)),
    };
    verify_file(&file, &target)?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take(u64::try_from(cap).unwrap_or(u64::MAX) + 1)
        .read_to_end(&mut bytes)
        .map_err(|source| io_error("read runtime-spine state", &target, source))?;
    if bytes.len() > cap {
        return Err(RuntimeSpineJournalError::Corrupt(
            "runtime-spine state exceeds its bounded size",
        ));
    }
    Ok(Some(bytes))
}

fn replace_file(
    directory: &File,
    path: &Path,
    name: &'static str,
    bytes: &[u8],
) -> Result<(), RuntimeSpineJournalError> {
    let target = path.join(name);
    let temporary_name = format!(".{name}.tmp");
    let temporary = path.join(&temporary_name);
    let name = c_string(name, &target)?;
    let temporary_name = c_string(&temporary_name, &temporary)?;
    unlink_if_exists(directory, &temporary_name)
        .map_err(|source| io_error("remove stale runtime-spine temp", &temporary, source))?;
    let mut file = open_at(
        directory,
        &temporary_name,
        libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        0o600,
    )
    .map_err(|source| io_error("create runtime-spine temp", &temporary, source))?;
    verify_file(&file, &temporary)?;
    file.write_all(bytes)
        .map_err(|source| io_error("write runtime-spine temp", &temporary, source))?;
    file.sync_all()
        .map_err(|source| io_error("sync runtime-spine temp", &temporary, source))?;
    rename_at(directory, &temporary_name, directory, &name)
        .map_err(|source| io_error("publish runtime-spine state", &target, source))?;
    directory
        .sync_all()
        .map_err(|source| io_error("sync runtime-spine directory", path, source))
}

fn remove_file(
    directory: &File,
    path: &Path,
    name: &'static str,
) -> Result<(), RuntimeSpineJournalError> {
    let target = path.join(name);
    let name = c_string(name, &target)?;
    if unlink_if_exists(directory, &name)
        .map_err(|source| io_error("remove runtime-spine state", &target, source))?
    {
        directory
            .sync_all()
            .map_err(|source| io_error("sync runtime-spine directory", path, source))?;
    }
    Ok(())
}

fn verify_file(file: &File, path: &Path) -> Result<(), RuntimeSpineJournalError> {
    let metadata = file
        .metadata()
        .map_err(|source| io_error("inspect runtime-spine state", path, source))?;
    // SAFETY: geteuid takes no pointers and has no failure mode.
    let euid = unsafe { libc::geteuid() };
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != euid
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(RuntimeSpineJournalError::Corrupt(
            "runtime-spine state file has unsafe metadata",
        ));
    }
    Ok(())
}

fn open_at(directory: &File, name: &CStr, flags: i32, mode: u32) -> io::Result<File> {
    // SAFETY: directory is a live descriptor; name is a stable C string; a
    // successful new descriptor is transferred exactly once into File.
    let descriptor = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags, mode) };
    if descriptor < 0 {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: openat returned a fresh descriptor owned by this call.
        Ok(unsafe { File::from_raw_fd(descriptor) })
    }
}

fn rename_at(
    old_directory: &File,
    old_name: &CStr,
    new_directory: &File,
    new_name: &CStr,
) -> io::Result<()> {
    // SAFETY: both descriptors are live and both names remain valid for the
    // duration of the call.
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

fn c_string(value: &str, _path: &Path) -> Result<CString, RuntimeSpineJournalError> {
    CString::new(OsStr::new(value).as_bytes())
        .map_err(|_| RuntimeSpineJournalError::Corrupt("runtime-spine basename contains NUL"))
}

fn io_error(operation: &'static str, path: &Path, source: io::Error) -> RuntimeSpineJournalError {
    RuntimeSpineJournalError::Io {
        operation,
        path: path.to_path_buf(),
        source,
    }
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        decode_agent_session, decode_desired_read_snapshot, encode_desired_read_snapshot,
        encode_observation_acceptance, inventory_digest, AdmissionInventoryAttestation,
        RandomId128, Sha256Digest, UnixMillis,
    };

    use super::*;

    const SESSION: &[u8] = br#"{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"guest_config_digest":"sha256:78215611e8c3bd683eb542b5696a6316156365a94624c7521446ab5660d067e2","immutable_host_id":"host_a","lease_deadline_unix_ms":1720000060000,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a","registration_attempt_id":"55555555555555555555555555555555","version":1}"#;
    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    fn session() -> AgentSession {
        decode_agent_session(SESSION).unwrap()
    }

    fn snapshot() -> DesiredReadSnapshot {
        decode_desired_read_snapshot(SNAPSHOT).unwrap()
    }

    fn state_directory(root: &tempfile::TempDir) -> StateDirectory {
        StateDirectory::unanchored(root.path().to_path_buf())
    }

    fn full_observation(session: &AgentSession, snapshot: &DesiredReadSnapshot) -> NodeObservation {
        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: session.node_id.clone(),
            node_boot_id: session.node_boot_id.clone(),
            agent_instance_id: session.agent_instance_id.clone(),
            agent_session_epoch: session.agent_session_epoch,
            heartbeat_sequence: Sequence::new(1).unwrap(),
            observed_at_unix_ms: UnixMillis::new(1_720_000_004_000).unwrap(),
            complete_inventory: true,
            inventory_epoch: Epoch::new(1).unwrap(),
            inventory_digest: Some(Sha256Digest::from_bytes([1; 32])),
            inventory_read_position: Some(snapshot.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: Vec::new(),
            residue: Vec::new(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        observation
    }

    fn acceptance(session: &AgentSession, observation: &NodeObservation) -> ObservationAcceptance {
        let accepted_at_unix_ms = UnixMillis::new(1_720_000_005_000).unwrap();
        ObservationAcceptance {
            version: ContractVersion::V1,
            session: session_binding(session),
            observation_id: observation.observation_id.clone(),
            heartbeat_sequence: observation.heartbeat_sequence,
            accepted_at_unix_ms,
            lease_deadline_unix_ms: UnixMillis::new(1_720_000_065_000).unwrap(),
            inventory: ObservationInventoryAcceptance::Full {
                attestation: AdmissionInventoryAttestation {
                    version: ContractVersion::V1,
                    node_id: session.node_id.clone(),
                    agent_session_epoch: session.agent_session_epoch,
                    inventory_epoch: observation.inventory_epoch,
                    inventory_digest: observation.inventory_digest.clone().unwrap(),
                    inventory_read_position: observation.inventory_read_position.unwrap(),
                    accepted_at_unix_ms,
                },
            },
        }
    }

    #[test]
    fn desired_request_and_snapshot_survive_response_loss_exactly() {
        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let registered = session();

        let mut journal = RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        let RuntimeSpineDesiredWork::Request(first) = journal.desired_work().unwrap() else {
            panic!("first work must be a request")
        };
        drop(journal);

        let mut journal = RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        let RuntimeSpineDesiredWork::Request(replayed) = journal.desired_work().unwrap() else {
            panic!("pending work must replay")
        };
        assert_eq!(replayed.bytes(), first.bytes());
        assert_eq!(replayed.value(), first.value());

        let snapshot = snapshot();
        replace_file(
            &journal.directory,
            &journal.path,
            DESIRED_ACCEPTED_FILE,
            SNAPSHOT,
        )
        .unwrap();
        drop(journal);

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        assert_eq!(recovered.desired_snapshot(), Some(&snapshot));
        assert!(matches!(
            recovered.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Scan(found) if found == snapshot
        ));
    }

    #[test]
    fn accepted_full_crash_windows_repair_receipt_deadline_and_pending_request() {
        for completed_writes in 1..=4 {
            let root = tempfile::tempdir().unwrap();
            let state = state_directory(&root);
            let registered = session();
            let mut journal =
                RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
            assert!(matches!(
                journal.desired_work().unwrap(),
                RuntimeSpineDesiredWork::Request(_)
            ));
            let desired = snapshot();
            journal.accept_desired(desired.clone(), SNAPSHOT).unwrap();
            let observation = full_observation(&registered, &desired);
            journal.prepare_observation(observation.clone()).unwrap();
            let accepted = acceptance(&registered, &observation);
            let record = AcceptedObservationRecord {
                version: ContractVersion::V1,
                observation: observation.clone(),
                acceptance: accepted.clone(),
            };
            let record_bytes = encode_observation_record(&record).unwrap();

            // Mirror accept_observation's durable write order and crash after
            // each boundary: latest receipt, full receipt, renewed session,
            // then pending-request removal.
            replace_file(
                &journal.directory,
                &journal.path,
                OBSERVATION_LAST_FILE,
                &record_bytes,
            )
            .unwrap();
            if completed_writes >= 2 {
                replace_file(
                    &journal.directory,
                    &journal.path,
                    OBSERVATION_FULL_FILE,
                    &record_bytes,
                )
                .unwrap();
            }
            if completed_writes >= 3 {
                let mut renewed = registered.clone();
                renewed.lease_deadline_unix_ms = accepted.lease_deadline_unix_ms;
                replace_file(
                    &journal.directory,
                    &journal.path,
                    SESSION_FILE,
                    &encode_agent_session(&renewed).unwrap(),
                )
                .unwrap();
            }
            if completed_writes >= 4 {
                remove_file(&journal.directory, &journal.path, OBSERVATION_PENDING_FILE).unwrap();
            }
            drop(journal);

            let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
            assert_eq!(
                recovered.session().lease_deadline_unix_ms,
                accepted.lease_deadline_unix_ms,
                "crash after write {completed_writes} did not repair the session deadline"
            );
            assert_eq!(
                recovered.full_observation(),
                Some((&observation, &accepted)),
                "crash after write {completed_writes} did not repair the full receipt"
            );
            assert!(
                !root
                    .path()
                    .join(DIRECTORY_NAME)
                    .join(OBSERVATION_PENDING_FILE)
                    .exists(),
                "crash after write {completed_writes} left the accepted request pending"
            );
            let RuntimeSpineDesiredWork::Request(next) = recovered.desired_work().unwrap() else {
                panic!("the accepted full inventory must consume the Desired snapshot")
            };
            assert_eq!(next.value().request_sequence.get(), 2);

            drop(recovered);
            let mut replayed = RuntimeSpineJournal::open_for_test(&state, session()).unwrap();
            let RuntimeSpineDesiredWork::Request(exact) = replayed.desired_work().unwrap() else {
                panic!("the next Desired request must remain pending")
            };
            assert_eq!(exact.bytes(), next.bytes());
        }
    }

    #[test]
    fn normal_acceptance_and_session_replacement_are_durable() {
        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let registered = session();
        let mut journal = RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        assert!(matches!(
            journal.desired_work().unwrap(),
            RuntimeSpineDesiredWork::Request(_)
        ));
        let desired = snapshot();
        journal.accept_desired(desired.clone(), SNAPSHOT).unwrap();
        let observation = full_observation(&registered, &desired);
        journal.prepare_observation(observation.clone()).unwrap();
        let accepted = acceptance(&registered, &observation);
        let response = encode_observation_acceptance(&accepted).unwrap();
        journal.accept_observation(accepted, &response).unwrap();
        drop(journal);

        let mut replacement = registered;
        replacement.agent_instance_id =
            RandomId128::new("66666666666666666666666666666666").unwrap();
        replacement.registration_attempt_id =
            RandomId128::new("77777777777777777777777777777777").unwrap();
        replacement.agent_session_epoch = Epoch::new(3).unwrap();
        replacement.lease_deadline_unix_ms = UnixMillis::new(1_720_000_070_000).unwrap();
        let mut replaced = RuntimeSpineJournal::open_for_test(&state, replacement.clone()).unwrap();
        assert!(replaced.desired_snapshot().is_none());
        assert!(replaced.full_observation().is_none());
        let RuntimeSpineDesiredWork::Request(first) = replaced.desired_work().unwrap() else {
            panic!("a replacement session must restart its local request sequence")
        };
        assert_eq!(first.value().request_sequence.get(), 1);
        assert_eq!(first.value().session, session_binding(&replacement));
    }

    #[test]
    fn unsafe_or_noncanonical_local_files_fail_closed() {
        use std::os::unix::fs::symlink;

        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let journal = RuntimeSpineJournal::open_for_test(&state, session()).unwrap();
        drop(journal);
        let directory = root.path().join(DIRECTORY_NAME);
        symlink(SESSION_FILE, directory.join(DESIRED_PENDING_FILE)).unwrap();
        assert!(RuntimeSpineJournal::open_for_test(&state, session()).is_err());

        std::fs::remove_file(directory.join(DESIRED_PENDING_FILE)).unwrap();
        std::fs::write(directory.join(DESIRED_PENDING_FILE), b"{}\n").unwrap();
        assert!(RuntimeSpineJournal::open_for_test(&state, session()).is_err());
    }

    #[test]
    fn accepted_desired_uses_the_exact_canonical_response() {
        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let mut journal = RuntimeSpineJournal::open_for_test(&state, session()).unwrap();
        journal.desired_work().unwrap();
        let desired = snapshot();
        let canonical = encode_desired_read_snapshot(&desired).unwrap();
        assert_eq!(canonical, SNAPSHOT);
        journal.accept_desired(desired, &canonical).unwrap();
    }

    #[test]
    fn full_scan_coordinates_are_successors_and_pending_observation_wins() {
        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let registered = session();
        let mut journal = RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        journal.desired_work().unwrap();
        let first_desired = snapshot();
        journal
            .accept_desired(first_desired.clone(), SNAPSHOT)
            .unwrap();

        let first_scan = journal.full_scan().unwrap();
        assert_eq!(first_scan.session, session_binding(&registered));
        assert_eq!(first_scan.heartbeat_sequence.get(), 1);
        assert_eq!(first_scan.inventory_epoch.get(), 1);
        assert_eq!(first_scan.desired, first_desired);

        let first_observation = full_observation(&registered, &first_scan.desired);
        journal
            .prepare_observation(first_observation.clone())
            .unwrap();
        assert!(matches!(
            journal.full_scan(),
            Err(RuntimeSpineJournalError::Transition(
                "a physical scan cannot replace a pending observation"
            ))
        ));
        let first_acceptance = acceptance(&registered, &first_observation);
        let first_response = encode_observation_acceptance(&first_acceptance).unwrap();
        journal
            .accept_observation(first_acceptance, &first_response)
            .unwrap();

        let RuntimeSpineDesiredWork::Request(request) = journal.desired_work().unwrap() else {
            panic!("an accepted full scan must consume its Desired snapshot")
        };
        let mut next_desired = first_scan.desired;
        next_desired.request_sequence = request.value().request_sequence;
        next_desired.read_position = Sequence::new(13).unwrap();
        next_desired.issued_at_unix_ms = UnixMillis::new(1_720_000_010_000).unwrap();
        next_desired.expires_at_unix_ms = UnixMillis::new(1_720_000_040_000).unwrap();
        let next_bytes = encode_desired_read_snapshot(&next_desired).unwrap();
        journal
            .accept_desired(next_desired.clone(), &next_bytes)
            .unwrap();

        let next_scan = journal.full_scan().unwrap();
        assert_eq!(next_scan.heartbeat_sequence.get(), 2);
        assert_eq!(next_scan.inventory_epoch.get(), 2);
        assert_eq!(next_scan.desired, next_desired);
    }

    #[test]
    fn definite_observation_rejection_durably_advances_to_a_new_desired_cursor() {
        let root = tempfile::tempdir().unwrap();
        let state = state_directory(&root);
        let registered = session();
        let mut journal = RuntimeSpineJournal::open_for_test(&state, registered.clone()).unwrap();
        journal.desired_work().unwrap();
        let first_snapshot = snapshot();
        journal
            .accept_desired(first_snapshot.clone(), SNAPSHOT)
            .unwrap();
        let observation = full_observation(&registered, &first_snapshot);
        let pending = journal.prepare_observation(observation).unwrap();

        let marker = encode_desired_read_snapshot(&first_snapshot).unwrap();
        replace_file(
            &journal.directory,
            &journal.path,
            DESIRED_INVALIDATED_FILE,
            &marker,
        )
        .unwrap();
        drop(journal);

        let mut recovered = RuntimeSpineJournal::open_for_test(&state, registered).unwrap();
        let RuntimeSpineDesiredWork::Request(next) = recovered.desired_work().unwrap() else {
            panic!("the rejected observation must make the next Desired request eligible")
        };
        assert_eq!(next.value().request_sequence.get(), 2);
        assert_ne!(next.bytes(), pending.bytes());
        drop(recovered);

        let mut replayed = RuntimeSpineJournal::open_for_test(&state, session()).unwrap();
        let RuntimeSpineDesiredWork::Request(exact) = replayed.desired_work().unwrap() else {
            panic!("the replacement Desired request must replay exactly")
        };
        assert_eq!(exact.bytes(), next.bytes());

        let mut second = first_snapshot;
        second.request_sequence = Sequence::new(2).unwrap();
        second.read_position = Sequence::new(13).unwrap();
        second.issued_at_unix_ms = UnixMillis::new(1_720_000_010_000).unwrap();
        second.expires_at_unix_ms = UnixMillis::new(1_720_000_040_000).unwrap();
        let second_bytes = encode_desired_read_snapshot(&second).unwrap();
        replayed
            .accept_desired(second.clone(), &second_bytes)
            .unwrap();
        drop(replayed);

        let reopened = RuntimeSpineJournal::open_for_test(&state, session()).unwrap();
        assert_eq!(reopened.desired_snapshot(), Some(&second));
        assert!(reopened.invalidated_desired.is_none());
    }
}
