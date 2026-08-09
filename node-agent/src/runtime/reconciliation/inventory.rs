//! Clean-slate full inventory boundary.
//!
//! This is deliberately stricter than the future non-empty scanner. It can
//! establish the first A20 attestation only after every Runtime §6 physical
//! source independently proves that its managed namespace is empty. It never
//! adopts or translates the legacy runtime ledger.

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    AppliedDesiredEvidence, CheckpointEvidence, Condition, GuestTransportEvidence, InventorySource,
    LifecycleAdmission, ObservedRuntimeStatus, ProgressingReason, ReconcileStep, UnixMillis,
    WarmSnapshotEvidence,
};
use thiserror::Error;

use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
};

use super::runtime_checkpoint_path;

const REQUIRED_SOURCES: [InventorySource; 11] = [
    InventorySource::Checkpoint,
    InventorySource::Systemd,
    InventorySource::Process,
    InventorySource::ControlSocket,
    InventorySource::BlockFrontend,
    InventorySource::Network,
    InventorySource::DataDirectory,
    InventorySource::PendingPack,
    InventorySource::WarmSnapshot,
    InventorySource::MetadataStore,
    InventorySource::GuestMount,
];

/// Explicit cutover placeholder used until the production composition root
/// supplies all eleven concrete absence probes. It can never manufacture a
/// complete scan or let local readiness open.
pub(crate) struct UnavailableCleanSlateScanner;

impl crate::runtime_spine::inventory_scanner_sealed::Sealed for UnavailableCleanSlateScanner {}

impl RuntimeInventoryScanner for UnavailableCleanSlateScanner {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
        context.check_active()?;
        Ok(RuntimeInventoryScanOutcome::Incomplete {
            unavailable_sources: REQUIRED_SOURCES.to_vec(),
        })
    }
}

pub(crate) fn unavailable_clean_slate_scanner() -> Arc<dyn RuntimeInventoryScanner> {
    Arc::new(UnavailableCleanSlateScanner)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InventoryAbsence {
    Empty,
    Unavailable,
}

/// One read-only proof for exactly one member of the Runtime inventory-source
/// closed set. `Err` means detected residue/collision/corruption, not ordinary
/// source downtime; implementations use `Unavailable` for the latter. Every
/// concrete probe must pass `context.deadline()` to its filesystem, socket,
/// process or metadata I/O and return promptly after cancellation.
pub trait InventoryAbsenceProbe:
    super::inventory_probe_sealed::Sealed + Send + Sync + 'static
{
    fn source(&self) -> InventorySource;
    fn prove_absent(
        &self,
        context: &RuntimeInventoryScanContext,
    ) -> anyhow::Result<InventoryAbsence>;
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InventoryProbeSetError {
    #[error("inventory absence probe is duplicated for {0:?}")]
    Duplicate(InventorySource),
    #[error("inventory absence probe is missing for {0:?}")]
    Missing(InventorySource),
}

pub struct CleanSlateInventoryScanner {
    checkpoint_directory: PathBuf,
    probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
}

impl crate::runtime_spine::inventory_scanner_sealed::Sealed for CleanSlateInventoryScanner {}

impl std::fmt::Debug for CleanSlateInventoryScanner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CleanSlateInventoryScanner")
            .field("checkpoint_directory", &self.checkpoint_directory)
            .field(
                "sources",
                &self
                    .probes
                    .iter()
                    .map(|probe| probe.source())
                    .collect::<Vec<_>>(),
            )
            .finish()
    }
}

impl CleanSlateInventoryScanner {
    pub fn new(
        checkpoint_directory: PathBuf,
        mut probes: Vec<Arc<dyn InventoryAbsenceProbe>>,
    ) -> Result<Self, InventoryProbeSetError> {
        probes.sort_by_key(|probe| probe.source());
        let mut found = BTreeSet::new();
        for probe in &probes {
            if !found.insert(probe.source()) {
                return Err(InventoryProbeSetError::Duplicate(probe.source()));
            }
        }
        for source in REQUIRED_SOURCES {
            if !found.contains(&source) {
                return Err(InventoryProbeSetError::Missing(source));
            }
        }
        Ok(Self {
            checkpoint_directory,
            probes,
        })
    }
}

impl RuntimeInventoryScanner for CleanSlateInventoryScanner {
    fn scan_complete(
        &self,
        context: RuntimeInventoryScanContext,
    ) -> anyhow::Result<RuntimeInventoryScanOutcome> {
        let mut unavailable_sources = Vec::new();
        let mut coverage = InventoryCoverageAggregator::new();
        for probe in &self.probes {
            context.remaining().with_context(|| {
                format!("clean-slate inventory stopped before {:?}", probe.source())
            })?;
            match probe
                .prove_absent(&context)
                .with_context(|| format!("prove {:?} inventory is absent", probe.source()))?
            {
                InventoryAbsence::Empty => {}
                InventoryAbsence::Unavailable => unavailable_sources.push(probe.source()),
            }
            // A probe may return only after its underlying I/O consumed the
            // deadline. Never count that late result as complete coverage.
            context.remaining().with_context(|| {
                format!("clean-slate inventory stopped after {:?}", probe.source())
            })?;
            coverage.record(probe.source())?;
        }
        if !unavailable_sources.is_empty() {
            return Ok(RuntimeInventoryScanOutcome::Incomplete {
                unavailable_sources,
            });
        }

        let observed_at_unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system time precedes the Unix epoch")?
            .as_millis();
        let observed_at_unix_ms = u64::try_from(observed_at_unix_ms)
            .ok()
            .and_then(UnixMillis::new)
            .context("system time does not fit UnixMillis")?;
        let coverage = coverage.finish()?;
        let inventory_epoch = context.coordinates().inventory_epoch;
        let runtimes = context
            .coordinates()
            .desired
            .desired_specs
            .iter()
            .map(|desired| {
                let step = ReconcileStep::InspectInventory { inventory_epoch };
                Ok(ObservedRuntimeStatus {
                    cat_id: desired.cat_id.clone(),
                    applied_desired: Some(AppliedDesiredEvidence {
                        desired_revision: desired.desired_revision,
                        spec_digest: desired.spec_digest.clone(),
                        placement: desired.placement.clone(),
                        target: desired.target,
                    }),
                    runtime_incarnation: None,
                    stable_state: None,
                    step: step.clone(),
                    checkpoint: CheckpointEvidence::Missing {
                        checkpoint_path: cats_api::runtime_reconciliation::HostPath::new(
                            runtime_checkpoint_path(&self.checkpoint_directory, &desired.cat_id)
                                .to_string_lossy()
                                .into_owned(),
                        )
                        .ok_or_else(|| {
                            anyhow::anyhow!("checkpoint path is not a valid HostPath")
                        })?,
                    },
                    processes: Vec::new(),
                    volumes: Vec::new(),
                    mounts: Vec::new(),
                    networks: Vec::new(),
                    guest_transport: GuestTransportEvidence::Unavailable,
                    warm_snapshot: WarmSnapshotEvidence::Absent,
                    lifecycle_admission: LifecycleAdmission::Closed,
                    routes: Vec::new(),
                    platform_guards: 0,
                    conditions: vec![Condition::Progressing {
                        reason: ProgressingReason::ReconcileStep { step },
                    }],
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;

        Ok(RuntimeInventoryScanOutcome::Complete(
            CompleteRuntimeInventory::from_validated_coverage(
                coverage,
                observed_at_unix_ms,
                RuntimeInventoryKeyRing::Unavailable,
                runtimes,
                Vec::new(),
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Instant;

    use cats_api::runtime_reconciliation::{
        decode_desired_read_snapshot, encode_node_observation, inventory_digest, spec_digest,
        AssignedKind, AssignedPlacement, ContractVersion, DesiredRuntimeSpec, Epoch, Id,
        InventorySource, Ipv4Address, IsolatedIpv4Kind, MacAddress, NetworkConfig, NodeObservation,
        RandomId128, Revision, RuntimeConfig, RuntimeTarget, RuntimeTransition, SessionBinding,
        Sha256Digest,
    };

    use super::*;

    const SNAPSHOT: &[u8] = br#"{"desired_specs":[],"expires_at_unix_ms":1720000030000,"issued_at_unix_ms":1720000000000,"read_position":12,"request_sequence":1,"session":{"agent_instance_id":"44444444444444444444444444444444","agent_session_epoch":2,"node_boot_id":"33333333333333333333333333333333","node_id":"node_a"},"version":1}"#;

    struct Probe {
        source: InventorySource,
        result: InventoryAbsence,
        calls: Arc<AtomicUsize>,
    }

    impl super::super::inventory_probe_sealed::Sealed for Probe {}

    impl InventoryAbsenceProbe for Probe {
        fn source(&self) -> InventorySource {
            self.source
        }

        fn prove_absent(
            &self,
            _context: &RuntimeInventoryScanContext,
        ) -> anyhow::Result<InventoryAbsence> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.result)
        }
    }

    fn context() -> RuntimeInventoryScanContext {
        let desired = decode_desired_read_snapshot(SNAPSHOT).unwrap();
        RuntimeInventoryScanContext::for_test(
            crate::runtime_spine::RuntimeSpineFullScan {
                session: SessionBinding {
                    node_id: desired.session.node_id.clone(),
                    node_boot_id: desired.session.node_boot_id.clone(),
                    agent_instance_id: desired.session.agent_instance_id.clone(),
                    agent_session_epoch: desired.session.agent_session_epoch,
                },
                heartbeat_sequence: cats_api::runtime_reconciliation::Sequence::new(1).unwrap(),
                inventory_epoch: Epoch::new(1).unwrap(),
                desired,
            },
            Instant::now() + std::time::Duration::from_secs(5),
        )
    }

    fn assigned_context() -> RuntimeInventoryScanContext {
        let mut context = context();
        let mut desired = DesiredRuntimeSpec {
            version: ContractVersion::V1,
            workspace_id: Id::new("ws_01").unwrap(),
            cat_id: Id::new("cat_01").unwrap(),
            desired_revision: Revision::new(1).unwrap(),
            target: RuntimeTarget::Running,
            placement: AssignedPlacement {
                kind: AssignedKind::Assigned,
                node_id: Id::new("node_a").unwrap(),
                placement_epoch: Epoch::new(1).unwrap(),
            },
            runtime: RuntimeConfig {
                vcpus: 2,
                memory_bytes: 2_147_483_648,
                boot_image_digest: Sha256Digest::from_bytes([1; 32]),
                guest_config_digest: Sha256Digest::from_bytes([2; 32]),
                network_config: NetworkConfig {
                    kind: IsolatedIpv4Kind::IsolatedIpv4,
                    network_id: Id::new("net_01").unwrap(),
                    guest_mac: MacAddress::new("02:ca:0a:f0:00:06").unwrap(),
                    guest_ipv4: Ipv4Address::new("10.240.0.6").unwrap(),
                    prefix_length: 30,
                    gateway_ipv4: Ipv4Address::new("10.240.0.5").unwrap(),
                },
            },
            volumes: Vec::new(),
            endpoints: Vec::new(),
            transition: RuntimeTransition::CancelAndDrain,
            spec_digest: Sha256Digest::from_bytes([0; 32]),
        };
        desired.spec_digest = spec_digest(&desired).unwrap();
        context
            .coordinates_mut()
            .desired
            .desired_specs
            .push(desired);
        context
    }

    fn probes(
        unavailable: Option<InventorySource>,
        calls: &Arc<AtomicUsize>,
    ) -> Vec<Arc<dyn InventoryAbsenceProbe>> {
        REQUIRED_SOURCES
            .into_iter()
            .map(|source| {
                Arc::new(Probe {
                    source,
                    result: if unavailable == Some(source) {
                        InventoryAbsence::Unavailable
                    } else {
                        InventoryAbsence::Empty
                    },
                    calls: Arc::clone(calls),
                }) as Arc<dyn InventoryAbsenceProbe>
            })
            .collect()
    }

    #[test]
    fn every_closed_source_is_required_and_empty_scan_is_complete() {
        let calls = Arc::new(AtomicUsize::new(0));
        let mut missing = probes(None, &calls);
        missing.pop();
        assert_eq!(
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), missing).unwrap_err(),
            InventoryProbeSetError::Missing(InventorySource::GuestMount)
        );
        let mut duplicate = probes(None, &calls);
        duplicate.push(Arc::new(Probe {
            source: InventorySource::Checkpoint,
            result: InventoryAbsence::Empty,
            calls: Arc::clone(&calls),
        }));
        assert_eq!(
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), duplicate).unwrap_err(),
            InventoryProbeSetError::Duplicate(InventorySource::Checkpoint)
        );

        let scanner =
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), probes(None, &calls))
                .unwrap();
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context()).unwrap()
        else {
            panic!("all empty sources must produce a complete scan")
        };
        assert!(inventory.runtimes().is_empty());
        assert!(inventory.residue().is_empty());
        assert_eq!(calls.load(Ordering::SeqCst), REQUIRED_SOURCES.len());
    }

    #[test]
    fn one_unavailable_source_never_becomes_empty_success() {
        let calls = Arc::new(AtomicUsize::new(0));
        let scanner = CleanSlateInventoryScanner::new(
            PathBuf::from("/checkpoints"),
            probes(Some(InventorySource::MetadataStore), &calls),
        )
        .unwrap();
        assert!(matches!(
            scanner.scan_complete(context()).unwrap(),
            RuntimeInventoryScanOutcome::Incomplete { unavailable_sources }
                if unavailable_sources == [InventorySource::MetadataStore]
        ));
    }

    #[test]
    fn assigned_but_physically_empty_cat_is_closed_and_progressing() {
        let calls = Arc::new(AtomicUsize::new(0));
        let scanner =
            CleanSlateInventoryScanner::new(PathBuf::from("/checkpoints"), probes(None, &calls))
                .unwrap();
        let context = assigned_context();
        let coordinates = context.coordinates().clone();
        let RuntimeInventoryScanOutcome::Complete(inventory) =
            scanner.scan_complete(context).unwrap()
        else {
            panic!("all empty sources must produce a complete assigned scan")
        };
        assert_eq!(inventory.runtimes().len(), 1);
        let runtime = &inventory.runtimes()[0];
        assert_eq!(runtime.cat_id.as_str(), "cat_01");
        assert!(runtime.applied_desired.is_some());
        assert!(matches!(
            runtime.checkpoint,
            CheckpointEvidence::Missing { .. }
        ));
        assert_eq!(runtime.lifecycle_admission, LifecycleAdmission::Closed);
        assert!(matches!(
            runtime.conditions.as_slice(),
            [Condition::Progressing {
                reason: ProgressingReason::ReconcileStep {
                    step: ReconcileStep::InspectInventory { .. }
                }
            }]
        ));

        let mut observation = NodeObservation {
            version: ContractVersion::V1,
            observation_id: RandomId128::new("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa").unwrap(),
            node_id: coordinates.session.node_id,
            node_boot_id: coordinates.session.node_boot_id,
            agent_instance_id: coordinates.session.agent_instance_id,
            agent_session_epoch: coordinates.session.agent_session_epoch,
            heartbeat_sequence: coordinates.heartbeat_sequence,
            observed_at_unix_ms: inventory.observed_at_unix_ms(),
            complete_inventory: true,
            inventory_epoch: coordinates.inventory_epoch,
            inventory_digest: Some(Sha256Digest::from_bytes([0; 32])),
            inventory_read_position: Some(coordinates.desired.read_position),
            key_ring_version: None,
            key_ring_digest: None,
            loaded_kids: Vec::new(),
            runtimes: inventory.runtimes().to_vec(),
            residue: inventory.residue().to_vec(),
        };
        observation.inventory_digest = Some(inventory_digest(&observation).unwrap());
        encode_node_observation(&observation).unwrap();
    }
}
