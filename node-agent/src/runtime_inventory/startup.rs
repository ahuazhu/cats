//! One-shot handoff from lifecycle startup discovery to telemetry startup.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};

use cats_api::runtime_inventory::{
    validate_observed_cat_runtime_telemetry, ObservedCatRuntimeTelemetry, ObservedRuntimeCondition,
    ObservedRuntimeConditionKind, ObservedRuntimePhysicalState, RUNTIME_INVENTORY_MAX_CATS,
    RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS,
};
use cats_api::runtime_lifecycle::PlacementIdentity;
use cats_api::runtime_reconciliation::{AgentSession, Id, Sha256Digest};
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::lifecycle_command::journal::{
    LifecycleJournalRecord, LifecycleJournalStartupInventory, StartupJournalEntry,
    StartupPhysicalInventory,
};

use super::runner::observed_command_journal_record;
use super::RuntimeFullInventoryScan;

const EMPTY_PHYSICAL_MANIFEST_DOMAIN: &[u8] = b"cats.runtime-inventory.empty-physical-manifest.v1";
const BLOCKED_JOURNAL_EVIDENCE_DOMAIN: &[u8] = b"cats.runtime-inventory.blocked-journal.v1";

#[derive(Debug, Error)]
pub enum StartupInventoryCacheError {
    #[error("startup inventory cache mutex is unavailable")]
    Unavailable,
    #[error("startup physical inventory is incomplete: {reason}")]
    IncompletePhysical { reason: String },
    #[error("startup physical inventory is invalid: {reason}")]
    InvalidPhysical { reason: &'static str },
    #[error("startup inventory cache was initialized with conflicting physical evidence")]
    PhysicalConflict,
    #[error("startup inventory journal join was attempted before the physical scan")]
    PhysicalNotInitialized,
    #[error("startup inventory journal join was replayed with conflicting evidence")]
    JoinedConflict,
    #[error("startup inventory seed was requested before the journal join")]
    JoinedSeedNotReady,
    #[error("startup inventory seed was consumed more than once")]
    JoinedSeedConsumed,
    #[error("startup journal Cat {cat_id} is duplicated")]
    DuplicateJournalCat { cat_id: Id },
    #[error("startup journal Cat {cat_id} belongs to another placement")]
    WrongJournalPlacement { cat_id: Id },
    #[error("blocked startup journal Cat {cat_id} has no attributable physical projection")]
    UnattributedBlockedJournal { cat_id: Id },
    #[error("quarantined terminal Cat {cat_id} is not an exact recoverable journal")]
    QuarantinedTerminalNotRecoverable { cat_id: Id },
    #[error("decode startup lifecycle journal for Cat {cat_id}: {reason}")]
    InvalidJournal { cat_id: Id, reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum StartupInventoryCacheState {
    Empty,
    Physical(RuntimeFullInventoryScan),
    Joined {
        physical: RuntimeFullInventoryScan,
        joined: RuntimeFullInventoryScan,
    },
    Consumed {
        physical: RuntimeFullInventoryScan,
        joined: RuntimeFullInventoryScan,
    },
}

/// Caller-owned one-shot cache shared by lifecycle startup and telemetry.
///
/// The lifecycle runner initializes it from its sole physical scan, performs
/// the sole descriptor-safe journal enumeration, and then publishes one
/// joined seed. The telemetry runner may take that exact seed once. No cache
/// transition can trigger a scan, execute an effect, or open admission.
#[derive(Debug)]
pub struct StartupInventoryCache {
    state: Mutex<StartupInventoryCacheState>,
}

impl StartupInventoryCache {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(StartupInventoryCacheState::Empty),
        })
    }

    /// Retains the exact rich physical scan. Every journal projection must be
    /// absent because the next transition owns the only journal enumeration.
    pub fn initialize_physical(
        &self,
        session: &AgentSession,
        physical: &StartupPhysicalInventory,
    ) -> Result<(), StartupInventoryCacheError> {
        let scan = match physical {
            StartupPhysicalInventory::Complete {
                scan_id,
                collected_at_unix_ms,
                cats,
                unattributed_artifacts,
            } => RuntimeFullInventoryScan {
                scan_id: scan_id.clone(),
                collected_at_unix_ms: *collected_at_unix_ms,
                cats: cats.clone(),
                unattributed_artifacts: unattributed_artifacts.clone(),
            },
            StartupPhysicalInventory::Incomplete { reason } => {
                return Err(StartupInventoryCacheError::IncompletePhysical {
                    reason: reason.clone(),
                })
            }
        };
        validate_physical_scan(&scan, &session.node_id)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| StartupInventoryCacheError::Unavailable)?;
        match &*state {
            StartupInventoryCacheState::Empty => {
                *state = StartupInventoryCacheState::Physical(scan);
                Ok(())
            }
            StartupInventoryCacheState::Physical(existing)
            | StartupInventoryCacheState::Joined {
                physical: existing, ..
            }
            | StartupInventoryCacheState::Consumed {
                physical: existing, ..
            } if existing == &scan => Ok(()),
            StartupInventoryCacheState::Physical(_)
            | StartupInventoryCacheState::Joined { .. }
            | StartupInventoryCacheState::Consumed { .. } => {
                Err(StartupInventoryCacheError::PhysicalConflict)
            }
        }
    }

    /// Overlays the exact lifecycle high-watermarks and publishes one sorted
    /// union. Journal-only Cats are observable as physically absent; a corrupt
    /// journal without attributable placement fails closed instead of being
    /// guessed into the inventory.
    pub fn join_and_publish_once(
        &self,
        session: &AgentSession,
        startup: &LifecycleJournalStartupInventory,
    ) -> Result<(), StartupInventoryCacheError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StartupInventoryCacheError::Unavailable)?;
        let physical = match &*state {
            StartupInventoryCacheState::Empty => {
                return Err(StartupInventoryCacheError::PhysicalNotInitialized)
            }
            StartupInventoryCacheState::Physical(physical)
            | StartupInventoryCacheState::Joined { physical, .. }
            | StartupInventoryCacheState::Consumed { physical, .. } => physical.clone(),
        };
        let mut joined = physical.clone();
        join_journals(&mut joined, session, startup)?;
        match &*state {
            StartupInventoryCacheState::Physical(_) => {
                *state = StartupInventoryCacheState::Joined { physical, joined };
                Ok(())
            }
            StartupInventoryCacheState::Joined {
                joined: existing, ..
            }
            | StartupInventoryCacheState::Consumed {
                joined: existing, ..
            } if existing == &joined => Ok(()),
            StartupInventoryCacheState::Joined { .. }
            | StartupInventoryCacheState::Consumed { .. } => {
                Err(StartupInventoryCacheError::JoinedConflict)
            }
            StartupInventoryCacheState::Empty => unreachable!("physical state was matched above"),
        }
    }

    /// Takes the joined seed exactly once. `ProductionRuntimeInventorySource`
    /// calls this for its first Full; later Fulls call the installed collector.
    pub fn take_joined(&self) -> Result<RuntimeFullInventoryScan, StartupInventoryCacheError> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| StartupInventoryCacheError::Unavailable)?;
        let current = std::mem::replace(&mut *state, StartupInventoryCacheState::Empty);
        match current {
            StartupInventoryCacheState::Joined { physical, joined } => {
                let seed = joined.clone();
                *state = StartupInventoryCacheState::Consumed { physical, joined };
                Ok(seed)
            }
            current @ (StartupInventoryCacheState::Empty
            | StartupInventoryCacheState::Physical(_)) => {
                *state = current;
                Err(StartupInventoryCacheError::JoinedSeedNotReady)
            }
            current @ StartupInventoryCacheState::Consumed { .. } => {
                *state = current;
                Err(StartupInventoryCacheError::JoinedSeedConsumed)
            }
        }
    }
}

fn validate_physical_scan(
    scan: &RuntimeFullInventoryScan,
    node_id: &Id,
) -> Result<(), StartupInventoryCacheError> {
    if scan.cats.len() > RUNTIME_INVENTORY_MAX_CATS
        || scan.unattributed_artifacts.len() > RUNTIME_INVENTORY_MAX_UNATTRIBUTED_ARTIFACTS
    {
        return Err(StartupInventoryCacheError::InvalidPhysical {
            reason: "physical collection exceeds its bounded limits",
        });
    }
    if scan
        .cats
        .windows(2)
        .any(|pair| pair[0].cat_id >= pair[1].cat_id)
        || scan
            .unattributed_artifacts
            .windows(2)
            .any(|pair| pair[0].artifact_id() >= pair[1].artifact_id())
    {
        return Err(StartupInventoryCacheError::InvalidPhysical {
            reason: "physical vectors are not strictly sorted and unique",
        });
    }
    for cat in &scan.cats {
        if cat.observed_command_journal.is_some()
            || validate_observed_cat_runtime_telemetry(cat, node_id).is_err()
        {
            return Err(StartupInventoryCacheError::InvalidPhysical {
                reason: "physical Cat projection is invalid or contains a journal",
            });
        }
    }
    Ok(())
}

fn join_journals(
    scan: &mut RuntimeFullInventoryScan,
    session: &AgentSession,
    startup: &LifecycleJournalStartupInventory,
) -> Result<(), StartupInventoryCacheError> {
    let mut cats: BTreeMap<Id, ObservedCatRuntimeTelemetry> = std::mem::take(&mut scan.cats)
        .into_iter()
        .map(|cat| (cat.cat_id.clone(), cat))
        .collect();
    let mut seen = BTreeSet::new();
    for entry in &startup.recoverable {
        if entry.record.cat_id() != &entry.cat_id || !seen.insert(entry.cat_id.clone()) {
            return Err(StartupInventoryCacheError::DuplicateJournalCat {
                cat_id: entry.cat_id.clone(),
            });
        }
        join_exact_journal(&mut cats, session, entry)?;
    }
    let recoverable_cats = startup
        .recoverable
        .iter()
        .map(|entry| entry.cat_id.clone())
        .collect::<BTreeSet<_>>();
    for quarantined in &startup.quarantined_commands {
        let entry = &quarantined.entry;
        if entry.record.cat_id() != &entry.cat_id || !seen.insert(entry.cat_id.clone()) {
            return Err(StartupInventoryCacheError::DuplicateJournalCat {
                cat_id: entry.cat_id.clone(),
            });
        }
        join_exact_journal(&mut cats, session, entry)?;
        let cat = cats.get_mut(&entry.cat_id).ok_or_else(|| {
            StartupInventoryCacheError::InvalidJournal {
                cat_id: entry.cat_id.clone(),
                reason: "joined quarantined journal lost its Cat projection".into(),
            }
        })?;
        quarantine_cat(cat, &quarantined.reason);
    }
    for blocked in &startup.blocked {
        if !seen.insert(blocked.cat_id.clone()) {
            return Err(StartupInventoryCacheError::DuplicateJournalCat {
                cat_id: blocked.cat_id.clone(),
            });
        }
        let Some(cat) = cats.get_mut(&blocked.cat_id) else {
            return Err(StartupInventoryCacheError::UnattributedBlockedJournal {
                cat_id: blocked.cat_id.clone(),
            });
        };
        quarantine_cat(cat, &blocked.reason);
    }
    let mut quarantined = BTreeSet::new();
    for terminal in &startup.quarantined_terminals {
        if !recoverable_cats.contains(&terminal.cat_id)
            || !quarantined.insert(terminal.cat_id.clone())
        {
            return Err(
                StartupInventoryCacheError::QuarantinedTerminalNotRecoverable {
                    cat_id: terminal.cat_id.clone(),
                },
            );
        }
        let cat = cats.get_mut(&terminal.cat_id).ok_or_else(|| {
            StartupInventoryCacheError::QuarantinedTerminalNotRecoverable {
                cat_id: terminal.cat_id.clone(),
            }
        })?;
        quarantine_cat(cat, &terminal.reason);
    }
    scan.cats = cats.into_values().collect();
    if scan.cats.len() > RUNTIME_INVENTORY_MAX_CATS {
        return Err(StartupInventoryCacheError::InvalidPhysical {
            reason: "joined Cat collection exceeds its bounded limit",
        });
    }
    for cat in &scan.cats {
        validate_observed_cat_runtime_telemetry(cat, &session.node_id).map_err(|_| {
            StartupInventoryCacheError::InvalidPhysical {
                reason: "joined Cat projection is invalid",
            }
        })?;
    }
    Ok(())
}

fn join_exact_journal(
    cats: &mut BTreeMap<Id, ObservedCatRuntimeTelemetry>,
    session: &AgentSession,
    entry: &StartupJournalEntry,
) -> Result<(), StartupInventoryCacheError> {
    let journal =
        observed_command_journal_record(&entry.record, &entry.journal_digest).map_err(|error| {
            StartupInventoryCacheError::InvalidJournal {
                cat_id: entry.cat_id.clone(),
                reason: error.to_string(),
            }
        })?;
    if let Some(cat) = cats.get_mut(&entry.cat_id) {
        cat.observed_command_journal = Some(journal);
        return Ok(());
    }
    let placement = journal_placement(&entry.record).map_err(|reason| {
        StartupInventoryCacheError::InvalidJournal {
            cat_id: entry.cat_id.clone(),
            reason,
        }
    })?;
    if placement.node_id != session.node_id {
        return Err(StartupInventoryCacheError::WrongJournalPlacement {
            cat_id: entry.cat_id.clone(),
        });
    }
    cats.insert(
        entry.cat_id.clone(),
        ObservedCatRuntimeTelemetry {
            cat_id: entry.cat_id.clone(),
            observed_placement: placement,
            observed_command_journal: Some(journal),
            observed_physical_state: ObservedRuntimePhysicalState::Absent,
            observed_runtime_incarnation: None,
            observed_artifact_manifest_digest: empty_physical_manifest_digest(),
            observed_artifact_classifications: Vec::new(),
            observed_volumes: Vec::new(),
            observed_conditions: Vec::new(),
        },
    );
    Ok(())
}

fn quarantine_cat(cat: &mut ObservedCatRuntimeTelemetry, reason: &str) {
    let condition = ObservedRuntimeCondition {
        kind: ObservedRuntimeConditionKind::Quarantined,
        evidence_digest: blocked_journal_evidence_digest(&cat.cat_id, reason),
    };
    match cat
        .observed_conditions
        .binary_search_by_key(&condition.kind, |existing| existing.kind)
    {
        Ok(index) => cat.observed_conditions[index] = condition,
        Err(index) => cat.observed_conditions.insert(index, condition),
    }
}

fn journal_placement(record: &LifecycleJournalRecord) -> Result<PlacementIdentity, String> {
    match record {
        LifecycleJournalRecord::Command { command, .. } => command
            .decode_api()
            .map(|command| command.placement_identity)
            .map_err(|error| error.to_string()),
        LifecycleJournalRecord::CompletedDeleteReceipt { receipt, .. } => {
            Ok(receipt.placement_identity.clone())
        }
    }
}

fn empty_physical_manifest_digest() -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(EMPTY_PHYSICAL_MANIFEST_DOMAIN);
    hasher.update([0]);
    hasher.update(b"[]");
    Sha256Digest::from_bytes(hasher.finalize().into())
}

fn blocked_journal_evidence_digest(cat_id: &Id, reason: &str) -> Sha256Digest {
    let mut hasher = Sha256::new();
    hasher.update(BLOCKED_JOURNAL_EVIDENCE_DOMAIN);
    hasher.update([0]);
    hasher.update(cat_id.as_str().as_bytes());
    hasher.update([0]);
    hasher.update(reason.as_bytes());
    Sha256Digest::from_bytes(hasher.finalize().into())
}

#[cfg(test)]
mod tests {
    use cats_api::runtime_reconciliation::{
        ContractVersion, Epoch, NodeBootId, RandomId128, UnixMillis,
    };

    use crate::lifecycle_command::journal::BlockedStartupCat;

    use super::*;

    fn id(value: &str) -> Id {
        Id::new(value).expect("valid test ID")
    }

    fn random(value: u128) -> RandomId128 {
        RandomId128::new(format!("{value:032x}")).expect("valid test random ID")
    }

    fn session() -> AgentSession {
        AgentSession {
            version: ContractVersion::V1,
            node_id: id("node_startup_cache"),
            immutable_host_id: id("host_startup_cache"),
            node_boot_id: NodeBootId::new("11111111111111111111111111111111")
                .expect("valid boot ID"),
            agent_instance_id: random(1),
            agent_session_epoch: Epoch::new(1).expect("positive session epoch"),
            registration_attempt_id: random(2),
            guest_config_digest: Sha256Digest::from_bytes([3; 32]),
            lease_deadline_unix_ms: UnixMillis::new(10_000).expect("positive deadline"),
        }
    }

    fn physical(scan_id: u128) -> StartupPhysicalInventory {
        StartupPhysicalInventory::Complete {
            scan_id: random(scan_id),
            collected_at_unix_ms: UnixMillis::new(1_000).expect("positive collection time"),
            cats: Vec::new(),
            unattributed_artifacts: Vec::new(),
        }
    }

    #[test]
    fn exact_initialize_and_join_replay_but_conflicts_fail_closed() {
        let cache = StartupInventoryCache::new();
        let registered = session();
        let scan = physical(10);
        cache
            .initialize_physical(&registered, &scan)
            .expect("initialize physical scan");
        cache
            .initialize_physical(&registered, &scan)
            .expect("exact physical replay");
        assert!(matches!(
            cache.initialize_physical(&registered, &physical(11)),
            Err(StartupInventoryCacheError::PhysicalConflict)
        ));

        let startup = LifecycleJournalStartupInventory::default();
        cache
            .join_and_publish_once(&registered, &startup)
            .expect("join startup inventory");
        cache
            .join_and_publish_once(&registered, &startup)
            .expect("exact join replay");
        let seed = cache.take_joined().expect("take joined seed");
        assert_eq!(seed.scan_id, random(10));
        assert!(seed.cats.is_empty());
        cache
            .join_and_publish_once(&registered, &startup)
            .expect("exact join remains idempotent after take");
        assert!(matches!(
            cache.take_joined(),
            Err(StartupInventoryCacheError::JoinedSeedConsumed)
        ));
    }

    #[test]
    fn join_before_scan_and_unattributed_blocked_journal_fail_closed() {
        let cache = StartupInventoryCache::new();
        let registered = session();
        assert!(matches!(
            cache.join_and_publish_once(&registered, &LifecycleJournalStartupInventory::default()),
            Err(StartupInventoryCacheError::PhysicalNotInitialized)
        ));
        cache
            .initialize_physical(&registered, &physical(20))
            .expect("initialize physical scan");
        let startup = LifecycleJournalStartupInventory {
            recoverable: Vec::new(),
            blocked: vec![BlockedStartupCat {
                cat_id: id("cat_corrupt"),
                reason: "corrupt exact journal".into(),
            }],
            quarantined_commands: Vec::new(),
            quarantined_terminals: Vec::new(),
        };
        assert!(matches!(
            cache.join_and_publish_once(&registered, &startup),
            Err(StartupInventoryCacheError::UnattributedBlockedJournal { cat_id })
                if cat_id == id("cat_corrupt")
        ));
    }
}
