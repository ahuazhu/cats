//! First-slice full inventory boundary.
//!
//! This can establish the first A20 attestation only after every Runtime §6
//! physical source proves that its managed namespace is empty, while the
//! metadata source may return exact authority facts for Desired-bound root
//! Volumes. It never adopts or translates the legacy runtime ledger.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Context as _;
use cats_api::runtime_reconciliation::{
    checkpoint_content_digest, AppliedDesiredEvidence, CheckpointEvidence, Condition,
    DesiredRuntimeSpec, GuestTransportEvidence, HostPath, Id, InventorySource, LifecycleAdmission,
    LocalLineageState, LocalVolumeLineage, ObservedRuntimeStatus, ObservedVolume,
    ProgressingReason, ReconcileStep, RequireIdleCheckpoint, RuntimeCheckpoint, UnixMillis,
    VolumeAuthorityEvidence, WarmSnapshotEvidence, WireU64,
};
use thiserror::Error;

use crate::runtime_spine::{
    CompleteRuntimeInventory, InventoryCoverageAggregator, RuntimeInventoryKeyRing,
    RuntimeInventoryScanContext, RuntimeInventoryScanOutcome, RuntimeInventoryScanner,
};

use super::{
    runtime_checkpoint_path,
    signed_running::{
        prepared_owned_observed_volume, request_matches_volume, unowned_observed_volume,
    },
    AuthorizedBlockdCheckpoint,
};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InventoryAbsence {
    Empty,
    RuntimeCheckpoints(BTreeMap<Id, RuntimeCheckpoint>),
    AuthorizedBlockd(BTreeMap<Id, AuthorizedBlockdInventoryEvidence>),
    /// The metadata source contains exactly the Desired-bound volume facts
    /// supplied here and no discovered local-only candidate. These are not
    /// physical residue: a newly assigned Cat must be able to report its
    /// authoritative root before its first local effect exists.
    DesiredVolumes(BTreeMap<Id, Vec<ObservedVolume>>),
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedBlockdInventoryEvidence {
    pub data_directory: HostPath,
    pub checkpoint: AuthorizedBlockdCheckpoint,
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
        let mut volumes_by_cat = BTreeMap::new();
        let mut checkpoints_by_cat = BTreeMap::new();
        let mut blockd_by_cat = BTreeMap::new();
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
                InventoryAbsence::RuntimeCheckpoints(checkpoints) => {
                    anyhow::ensure!(
                        probe.source() == InventorySource::Checkpoint,
                        "only the checkpoint source may report Runtime checkpoints"
                    );
                    for (cat_id, checkpoint) in checkpoints {
                        anyhow::ensure!(
                            checkpoints_by_cat.insert(cat_id, checkpoint).is_none(),
                            "checkpoint inventory duplicated one Cat"
                        );
                    }
                }
                InventoryAbsence::AuthorizedBlockd(blockds) => {
                    anyhow::ensure!(
                        probe.source() == InventorySource::DataDirectory,
                        "only the data-directory source may report authorized blockd lineage"
                    );
                    for (cat_id, blockd) in blockds {
                        anyhow::ensure!(
                            blockd_by_cat.insert(cat_id, blockd).is_none(),
                            "data-directory inventory duplicated one Cat"
                        );
                    }
                }
                InventoryAbsence::DesiredVolumes(observed) => {
                    anyhow::ensure!(
                        probe.source() == InventorySource::MetadataStore,
                        "only the metadata source may report Desired volume facts"
                    );
                    for (cat_id, volumes) in observed {
                        anyhow::ensure!(
                            volumes_by_cat.insert(cat_id, volumes).is_none(),
                            "metadata inventory duplicated one Cat"
                        );
                    }
                }
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
                runtime_from_inventory(
                    desired,
                    inventory_epoch,
                    &self.checkpoint_directory,
                    volumes_by_cat.remove(&desired.cat_id).unwrap_or_default(),
                    checkpoints_by_cat.remove(&desired.cat_id),
                    blockd_by_cat.remove(&desired.cat_id),
                )
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        anyhow::ensure!(
            volumes_by_cat.is_empty() && checkpoints_by_cat.is_empty() && blockd_by_cat.is_empty(),
            "inventory named a Cat outside Desired"
        );

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

fn runtime_from_inventory(
    desired: &DesiredRuntimeSpec,
    inventory_epoch: cats_api::runtime_reconciliation::Epoch,
    checkpoint_directory: &std::path::Path,
    mut volumes: Vec<ObservedVolume>,
    checkpoint: Option<RuntimeCheckpoint>,
    blockd: Option<AuthorizedBlockdInventoryEvidence>,
) -> anyhow::Result<ObservedRuntimeStatus> {
    let checkpoint_path = runtime_checkpoint_path(checkpoint_directory, &desired.cat_id);
    let checkpoint_path = HostPath::new(
        checkpoint_path
            .to_str()
            .context("checkpoint path is not UTF-8")?
            .to_owned(),
    )
    .ok_or_else(|| anyhow::anyhow!("checkpoint path is not a valid HostPath"))?;

    if let Some(blockd) = &blockd {
        let [intent] = desired.volumes.as_slice() else {
            anyhow::bail!("authorized blockd lineage requires one Desired root")
        };
        anyhow::ensure!(
            checkpoint.is_some(),
            "authorized blockd lineage lacks its Runtime checkpoint"
        );
        anyhow::ensure!(
            blockd.checkpoint.desired == *desired && blockd.checkpoint.volume == *intent,
            "authorized blockd lineage does not bind current Desired"
        );
        let [volume] = volumes.as_mut_slice() else {
            anyhow::bail!("authorized blockd lineage lacks one authority Volume")
        };
        let attachment = &blockd.checkpoint.attachment;
        anyhow::ensure!(
            volume.volume_id == attachment.identity.volume_id
                && matches!(
                    &volume.authority,
                    VolumeAuthorityEvidence::Owned {
                        attachment_id,
                        attachment_epoch,
                        head,
                    } if attachment_id == &attachment.identity.attachment_id
                        && *attachment_epoch == attachment.identity.attachment_epoch
                        && head == &attachment.head
                )
                && volume.local_lineages.is_empty(),
            "authorized blockd lineage conflicts with Volume authority"
        );
        volume.local_lineages.push(LocalVolumeLineage {
            attachment_id: attachment.identity.attachment_id.clone(),
            attachment_epoch: attachment.identity.attachment_epoch,
            acquire_origin: attachment.identity.acquire_origin.clone(),
            node_id: attachment.identity.node_id.clone(),
            placement_epoch: attachment.identity.placement_epoch,
            local_durable_generation: attachment.head.generation,
            remote_durable_generation: attachment.head.generation,
            data_directory: blockd.data_directory.clone(),
            pending_pack_count: WireU64::new(0).expect("zero fits WireU64"),
            fenced: false,
            state: LocalLineageState::Active,
        });
    }

    let (step, checkpoint_evidence, runtime_incarnation, stable_state, lifecycle_admission) =
        match checkpoint {
            Some(checkpoint) => {
                validate_scanned_checkpoint(desired, &checkpoint, blockd.as_ref())?;
                let evidence = CheckpointEvidence::Valid {
                    checkpoint_path,
                    content_digest: checkpoint_content_digest(&checkpoint)
                        .context("digest scanned Runtime checkpoint")?,
                    version: checkpoint.version,
                    cat_id: checkpoint.cat_id.clone(),
                    node_id: checkpoint.node_id.clone(),
                    desired_revision: checkpoint.desired_revision,
                    spec_digest: checkpoint.spec_digest.clone(),
                    placement_epoch: checkpoint.placement_epoch,
                    runtime_incarnation: checkpoint.runtime_incarnation.clone(),
                    stable_state: checkpoint.stable_state,
                    step: Box::new(checkpoint.step.clone()),
                    require_idle: Box::new(checkpoint.require_idle.clone()),
                    updated_at_unix_ms: checkpoint.updated_at_unix_ms,
                };
                (
                    checkpoint.step,
                    evidence,
                    checkpoint.runtime_incarnation,
                    checkpoint.stable_state,
                    checkpoint.lifecycle_admission,
                )
            }
            None => {
                anyhow::ensure!(
                    blockd.is_none(),
                    "local lineage cannot exist without a Runtime checkpoint"
                );
                let step = ReconcileStep::InspectInventory { inventory_epoch };
                (
                    step,
                    CheckpointEvidence::Missing { checkpoint_path },
                    None,
                    None,
                    LifecycleAdmission::Closed,
                )
            }
        };

    Ok(ObservedRuntimeStatus {
        cat_id: desired.cat_id.clone(),
        applied_desired: Some(AppliedDesiredEvidence {
            desired_revision: desired.desired_revision,
            spec_digest: desired.spec_digest.clone(),
            placement: desired.placement.clone(),
            target: desired.target,
        }),
        runtime_incarnation,
        stable_state,
        step: step.clone(),
        checkpoint: checkpoint_evidence,
        processes: Vec::new(),
        volumes,
        mounts: Vec::new(),
        networks: Vec::new(),
        guest_transport: GuestTransportEvidence::Unavailable,
        warm_snapshot: WarmSnapshotEvidence::Absent,
        lifecycle_admission,
        routes: Vec::new(),
        platform_guards: 0,
        conditions: vec![Condition::Progressing {
            reason: ProgressingReason::ReconcileStep { step },
        }],
    })
}

fn validate_scanned_checkpoint(
    desired: &DesiredRuntimeSpec,
    checkpoint: &RuntimeCheckpoint,
    blockd: Option<&AuthorizedBlockdInventoryEvidence>,
) -> anyhow::Result<()> {
    anyhow::ensure!(
        checkpoint.version == cats_api::runtime_reconciliation::ContractVersion::V1
            && checkpoint.cat_id == desired.cat_id
            && checkpoint.node_id == desired.placement.node_id
            && checkpoint.placement_epoch == desired.placement.placement_epoch
            && checkpoint.desired_revision == desired.desired_revision
            && checkpoint.spec_digest == desired.spec_digest
            && checkpoint.runtime_incarnation.is_none()
            && checkpoint.stable_state.is_none()
            && checkpoint.processes.is_empty()
            && checkpoint.mounts.is_empty()
            && checkpoint.networks.is_empty()
            && matches!(
                checkpoint.guest_transport,
                GuestTransportEvidence::Unavailable
            )
            && matches!(checkpoint.warm_snapshot, WarmSnapshotEvidence::Absent)
            && checkpoint.lifecycle_admission == LifecycleAdmission::Closed
            && checkpoint.route_gates.is_empty()
            && matches!(
                checkpoint.require_idle,
                RequireIdleCheckpoint::NotApplicable
            ),
        "Runtime checkpoint does not bind the current pre-launch Desired"
    );
    let [intent] = desired.volumes.as_slice() else {
        anyhow::bail!("scanned signed Running checkpoint requires one root Volume")
    };
    match &checkpoint.step {
        ReconcileStep::AcquireVolume { request } => {
            anyhow::ensure!(
                request_matches_volume(request, desired, intent)
                    && checkpoint.volumes == [unowned_observed_volume(intent)],
                "Acquire checkpoint does not bind the exact Desired root"
            );
        }
        ReconcileStep::ProvisionRootImage {
            volume_id,
            attachment_id,
            attachment_epoch,
            data_directory,
            size_bytes,
            boot_image_digest,
            expected_blank_head,
            ..
        } => {
            let Some(blockd) = blockd else {
                anyhow::bail!("provision checkpoint lacks authorized blockd lineage")
            };
            let attachment = &blockd.checkpoint.attachment;
            anyhow::ensure!(
                volume_id == &intent.volume_id
                    && attachment_id == &attachment.identity.attachment_id
                    && *attachment_epoch == attachment.identity.attachment_epoch
                    && data_directory == &blockd.data_directory
                    && *size_bytes == intent.size_bytes
                    && boot_image_digest == &desired.runtime.boot_image_digest
                    && expected_blank_head == &attachment.head
                    && checkpoint.volumes
                        == [prepared_owned_observed_volume(
                            intent,
                            attachment,
                            blockd.data_directory.clone(),
                        )],
                "provision checkpoint does not bind authorized blockd lineage"
            );
        }
        _ => anyhow::bail!("pre-launch scanner encountered an unsupported Runtime step"),
    }
    Ok(())
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
            Ok(self.result.clone())
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
